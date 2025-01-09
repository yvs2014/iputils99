/*
 * Copyright (c) 1989 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Mike Muuss.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "common.h"
#include "iputils_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <locale.h>
#include <limits.h>
#include <signal.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <poll.h>
#include <math.h>
#include <assert.h>
#include <err.h>

#ifndef HZ
#define HZ sysconf(_SC_CLK_TCK)
#endif

#ifdef HAVE_LIBCAP
# include <sys/prctl.h>
#else
static uid_t euid;
#endif

#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <linux/sockios.h>

#define MIN_USER_MS		10	// Minimal interval for non-root users, in milliseconds
#define MIN_GAP_MS		10	// Minimal interpacket gap, in milliseconds
#define SCHINT(a)	(((a) < MIN_GAP_MS) ? MIN_GAP_MS : (a))

#define	BITMAP_ARR(bit)	(rts->rcvd_tbl.bitmap[(bit) >> BITMAP_SHIFT])		// Identify word in array
#define	BITMAP_BIT(bit)	(((bitmap_t)1) << ((bit) & ((1 << BITMAP_SHIFT) - 1)))	// Identify bit in word

static inline bitmap_t rcvd_test(const state_t *rts, uint16_t seq) {
	unsigned bit = seq % MAX_DUP_CHK;
	return BITMAP_ARR(bit) & BITMAP_BIT(bit);
}
static inline void rcvd_set(state_t *rts, uint16_t seq) {
	unsigned bit = seq % MAX_DUP_CHK;
	BITMAP_ARR(bit) |= BITMAP_BIT(bit);
}

static inline void rcvd_clear(state_t *rts, uint16_t seq) {
	unsigned bit = seq % MAX_DUP_CHK;
	BITMAP_ARR(bit) &= ~BITMAP_BIT(bit);
}

void usage(int rc) {
	const char *options =
"  -a                 use audible ping\n"
"  -A                 use adaptive ping\n"
"  -B                 sticky source address\n"
"  -c <count>         stop after <count> replies\n"
"  -C                 call connect() syscall on socket creation\n"
"  -D                 print timestamps\n"
"  -d                 use SO_DEBUG socket option\n"
"  -e <identifier>    define identifier for ping session, default is random for\n"
"                     SOCK_RAW and kernel defined for SOCK_DGRAM\n"
"                     Imply using SOCK_RAW (for IPv4 only for identifier 0)\n"
"  -f                 flood ping\n"
"  -h                 print help and exit\n"
"  -H                 force reverse DNS name resolution (useful for numeric\n"
"                     destinations or for -f), override -n\n"
"  -I <interface>     either interface name or address\n"
"  -i <interval>      seconds between sending each packet\n"
"  -L                 suppress loopback of multicast packets\n"
"  -l <preload>       send <preload> number of packages while waiting replies\n"
"  -m <mark>          tag the packets going out\n"
"  -M <pmtud opt>     define path MTU discovery, can be one of <do|dont|want|probe>\n"
"  -n                 no reverse DNS name resolution, override -H\n"
"  -O                 report outstanding replies\n"
"  -p <pattern>       contents of padding byte\n"
"  -q                 quiet output\n"
"  -Q <tclass>        use quality of service <tclass> bits\n"
"  -s <size>          use <size> as number of data bytes to be sent\n"
"  -S <size>          use <size> as SO_SNDBUF socket option value\n"
"  -t <ttl>           define time to live\n"
"  -U                 print user-to-user latency\n"
"  -v                 verbose output\n"
"  -V                 print version and exit\n"
"  -w <deadline>      reply wait <deadline> in seconds\n"
"  -W <timeout>       time to wait for response\n"
"\n"
"IPv4 options:\n"
"  -4                 use IPv4\n"
"  -b                 allow pinging broadcast\n"
"  -R                 record route\n"
"  -T <timestamp>     define timestamp, can be one of <tsonly|tsandaddr|tsprespec>\n"
"\n"
"IPv6 options:\n"
"  -6                 use IPv6\n"
"  -F <flowlabel>     define flow label, default is random\n"
"  -N <nodeinfo opt>  use IPv6 node info query, try <help> as argument\n"
;
	usage_common(rc, options, false);
}

uid_t limit_capabilities(const state_t *rts) {
#ifdef HAVE_LIBCAP
	// set proc
	cap_t proc = cap_get_proc();
	if (!proc)
		err(errno, "cap_get_proc");
	// set caps
	cap_t cap = cap_init();
	if (!cap)
		err(errno, "cap_init");
	// set flags
	cap_flag_value_t flag = CAP_CLEAR;
	cap_get_flag(proc, CAP_NET_ADMIN, CAP_PERMITTED, &flag);
	if (flag != CAP_CLEAR)
		cap_set_flag(cap, CAP_PERMITTED, 1, &rts->cap_admin, CAP_SET);
	flag = CAP_CLEAR;
	cap_get_flag(proc, CAP_NET_RAW, CAP_PERMITTED, &flag);
	if (flag != CAP_CLEAR)
		cap_set_flag(cap, CAP_PERMITTED, 1, &rts->cap_raw,   CAP_SET);
	if (cap_set_proc(cap) < 0)
		err(errno, "cap_set_proc");
	cap_free(cap);
	cap_free(proc);
	// set state
	if (prctl(PR_SET_KEEPCAPS, 1) < 0)
		err(errno, "prctl");
	if (setuid(getuid()) < 0)
		err(errno, "setuid");
	if (prctl(PR_SET_KEEPCAPS, 0) < 0)
		err(errno, "prctl");
#else
	euid = geteuid();
#endif
	uid_t uid = getuid();
#ifndef HAVE_LIBCAP
	if (seteuid(uid))
		err(errno, "setuid");
#endif
	return uid;
}

#ifdef HAVE_LIBCAP
int modify_capability(cap_value_t cap, cap_flag_value_t on) {
	int rc = -1;
	cap_t cap_p = cap_get_proc();
	if (cap_p) {
		cap_flag_value_t cap_ok = CAP_CLEAR;
		cap_get_flag(cap_p, cap, CAP_PERMITTED, &cap_ok);
		if (cap_ok != CAP_CLEAR) {
			cap_set_flag(cap_p, CAP_EFFECTIVE, 1, &cap, on);
			if (cap_set_proc(cap_p) < 0)
				warn("cap_set_proc");
			else
				rc = 0;
		} else
			rc = on ? -1 : 0;
		cap_free(cap_p);
	} else
		warn("cap_get_proc");
	return rc;
}
#else
int modify_capability(int on) {
	int rc = seteuid(on ? euid : getuid());
	if (rc)
		err(errno, "seteuid");
	return rc;
}
#endif

void drop_capabilities(void) {
#ifdef HAVE_LIBCAP
	cap_t cap = cap_init();
	if (cap_set_proc(cap) < 0)
		err(errno, "cap_set_proc");
	cap_free(cap);
#else
	if (setuid(getuid()) < 0)
		err(errno, "setuid");
#endif
}

// Fill payload area (supposed to be without timestamp area) with supplied pattern
void fill_payload(int quiet, const char *str, uint8_t *payload, size_t len) {
	for (const char *cp = str; *cp; cp++)
		if (!isxdigit(*cp))
			errx(EINVAL, "%s: %s", _("Pattern must be specified as hex digits"), cp);
#define PAD_BYTES	16
	unsigned pad[PAD_BYTES];
	errno = 0;
	int items = sscanf(str,
		"%2x%2x%2x%2x"
		"%2x%2x%2x%2x"
		"%2x%2x%2x%2x"
		"%2x%2x%2x%2x",
		&pad[0],  &pad[1],  &pad[2],  &pad[3],
		&pad[4],  &pad[5],  &pad[6],  &pad[7],
		&pad[8],  &pad[9],  &pad[10], &pad[11],
		&pad[12], &pad[13], &pad[14], &pad[15]);
	if (errno)
		errx(errno, "sscanf()");
	if (items <= 0)
		errx(EINVAL, "%s", _("Blank pattern"));
	size_t max = (items > PAD_BYTES) ? PAD_BYTES : items;
	for (size_t i = 0; i <= len; i++)
		payload[i] = pad[i % max];
	if (!quiet) {
		printf("%s: 0x", _("PATTERN"));
		for (size_t i = 0; i < max; i++)
			printf("%02x", pad[i]);
		if (max > len) { // if it's known already (-s before -p)
			printf(", %s: 0x", _("PAYLOAD"));
			for (size_t i = 0; i < len; i++)
				printf("%02x", payload[i]);
		}
		printf("\n");
	}
}

/* a bit clearer, but in fact it's the same as with global_rts */
static volatile bool exiting;
static volatile bool snapshot;
static volatile bool in_print_addr;
static jmp_buf label_in_print_addr;

static void sig_handler(int signo) {
	switch (signo) {
		case SIGINT:
		case SIGALRM:
			if (!exiting)
				exiting = true;
			if (in_print_addr)
				longjmp(label_in_print_addr, 0);
			break;
		case SIGQUIT:
			if (!snapshot)
				snapshot = true;
			break;
		default: break;
	}
}

static int schedule_exit(const state_t *rts, int next) {
	static unsigned long long waittime;
	if (waittime)
		return next;
	if (rts->nreceived) {
		waittime = 2 * rts->tmax;
		unsigned long long minwait = rts->interval * 1000ull;
		if (waittime < minwait)
			waittime = minwait;
	} else {
		waittime = rts->lingertime * 1000ull;
	}
	time_t msec = waittime / 1000;
	if ((next < 0) || (next < msec))
		next = msec;
	struct itimerval it = { .it_value = {
		.tv_sec  = waittime / 1000000,
		.tv_usec = waittime % 1000000,
	}};
	setitimer(ITIMER_REAL, &it, NULL);
	return next;
}

static inline int get_interval(const state_t *rts) {
	int interval = rts->interval;
	int est = rts->rtt ? (rts->rtt / 8) : (interval * 1000);
	interval = (est + rts->rtt_addend + 500) / 1000;
	if (rts->uid && (interval < MIN_USER_MS))
		interval = MIN_USER_MS;
	return interval;
}

/* Print timestamp */
void print_timestamp(void) {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	printf("[%lu.%06lu] ",
	       (unsigned long)tv.tv_sec, (unsigned long)tv.tv_usec);
}

static inline int in_flight(const state_t *rts) {
	uint16_t diff = rts->ntransmitted - rts->acked;
	return (diff <= 0x7FFF) ? diff : (rts->ntransmitted - rts->nreceived - rts->nerrors);
}

static inline void advance_ntransmitted(state_t *rts) {
	rts->ntransmitted++;
	/* Invalidate acked, if 16 bit seq overflows */
	if (((uint16_t)rts->ntransmitted - rts->acked) > 0x7FFF)
	rts->acked = (uint16_t)rts->ntransmitted + 1;
}

/*
 * pinger --
 * 	Compose and transmit an ICMP ECHO REQUEST packet.  The IP packet
 * will be added on by the kernel.  The ID field is our UNIX process ID,
 * and the sequence number is an ascending integer.  The first several bytes
 * of the data portion are used to hold a UNIX "timeval" struct in VAX
 * byte-order, to compute the round-trip time.
 */
static int pinger(state_t *rts, const fnset_t *fnset, const sock_t *sock) {
	static int oom_count;
	static int tokens;

	/* Have we already sent enough? If we have, return an arbitrary positive value */
	if (exiting || (rts->npackets && (rts->ntransmitted >= rts->npackets) && !rts->deadline))
		return 1000;

	/* Check that packets < rate*time + preload */
	if ((rts->cur_time.tv_sec == 0) && (rts->cur_time.tv_nsec == 0)) {
		clock_gettime(CLOCK_MONOTONIC_RAW, &rts->cur_time);
		tokens = rts->interval * (rts->preload - 1);
	} else {
		struct timespec tv = {0};
		clock_gettime(CLOCK_MONOTONIC_RAW, &tv);
		long ntokens = (tv.tv_sec - rts->cur_time.tv_sec) * 1000 +
			  (tv.tv_nsec - rts->cur_time.tv_nsec) / 1000000;
		if (!rts->interval) {
			/* Case of unlimited flood is special;
			 * if we see no reply, they are limited to 100pps */
			long rest = MIN_GAP_MS - ntokens;
			if ((rest > 0) && (in_flight(rts) >= rts->preload))
				return rest;
		}
		ntokens += tokens;
		long tmp = (long)rts->interval * rts->preload;
		if (tmp < ntokens)
			ntokens = tmp;
		if (ntokens < rts->interval)
			return rts->interval - ntokens;

		rts->cur_time = tv;
		tokens = ntokens - rts->interval;
	}

	if (rts->opt.outstanding) {
		if ((rts->ntransmitted > 0) && !rcvd_test(rts, rts->ntransmitted)) {
			PRINT_TIMESTAMP;
			printf("%s (%s=%lu)\n", _("No answer yet"), _("icmp_seq"), rts->ntransmitted % MAX_DUP_CHK);
			fflush(stdout);
		}
	}

	int rc;
	int hard_local_error = 0;
	do {
		rcvd_clear(rts, rts->ntransmitted + 1);
		rc = fnset->send_probe(rts, sock->fd, rts->outpack);
		if (rc == 0) {	// No error
			oom_count = 0;
			advance_ntransmitted(rts);
			if (!rts->opt.quiet && rts->opt.flood) {
				/* Very silly, but without this output with
				 * high preload or pipe size is very confusing */
#define PRELOAD_OKAY  (rts->preload   < rts->screen_width)
#define PIPESIZE_OKAY (rts->pipesize  < rts->screen_width)
#define INFLIGHT_OKAY (in_flight(rts) < rts->screen_width)
				if ((PRELOAD_OKAY && PIPESIZE_OKAY) || INFLIGHT_OKAY)
					if (write(STDOUT_FILENO, ".", 1)) {};
			}
			return (rts->interval - tokens);
		}
		if (rc > 0)	// Apparently, it is some fatal bug
			abort();
		// rc < 0
		switch (errno) {
		case ENOBUFS:
		case ENOMEM: {
			/* Device queue overflow or OOM. Packet is not sent */
			tokens = 0;
			/* Slowdown. This works only in adaptive mode (option -A) */
			rts->rtt_addend += (rts->rtt < (8 * 50000)) ?
				(rts->rtt / 8) : 50000;
			if (rts->opt.adaptive)
				rts->interval = get_interval(rts);
			int nores_interval = SCHINT(rts->interval / 2);
			if (nores_interval > 500)
				nores_interval = 500;
			oom_count++;
			if ((oom_count * nores_interval) < rts->lingertime)
				return nores_interval;
			rc = 0;
			/* Fall to hard error. It is to avoid complete deadlock
			 * on stuck output device even when dealine was not requested.
			 * Expected timings are screwed up in any case, but we will
			 * exit some day. :-) */
			hard_local_error = 1;
		}
			break;
		case EAGAIN:
			/* Socket buffer is full */
			tokens += rts->interval;
			return MIN_GAP_MS;
			break;
		default:
			/* Proceed a received error */
			rc = fnset->receive_error(rts, sock);
			if (rc > 0) {
				/* An ICMP error arrived. In this case, we've received
				 * an error from sendto(), but we've also received an
				 * ICMP message, which means the packet did in fact
				 * send in some capacity. So, in this odd case, report
				 * the more specific errno as the error, and treat this
				 * as a hard local error. */
				rc = 0;
				hard_local_error = 1;
			} else if ((rc == 0) && rts->confirm_flag && (errno == EINVAL)) {
				/* Compatibility with old linuces */
				rts->confirm_flag = 0;
				errno = 0;
			}
			break;
		}
	} while (!errno && !hard_local_error);

	/* Pretend we sent packet */
	advance_ntransmitted(rts);
	if (!rc && !rts->opt.quiet) {
		if (rts->opt.flood) {
			if (write(STDOUT_FILENO, "E", 1)) {};
		} else
			warn("sendmsg");
	}
	tokens = 0;
	return SCHINT(rts->interval);
}

void sock_setmark(state_t *rts, int fd) {
#ifdef SO_MARK
	if (!rts->opt.mark)
		return;
	ENABLE_CAPABILITY_ADMIN;
	int rc = setsockopt(fd, SOL_SOCKET, SO_MARK, &rts->mark, sizeof(rts->mark));
	int keep = errno;
	DISABLE_CAPABILITY_ADMIN;
	if (rc < 0) {
		errno = keep;
		warn("%s: %s: %u", _WARN, _("failed to set mark"), rts->mark);
		errno = keep;
		if (errno == EPERM)
			warnx("%s", _("=> missing cap_net_admin+p capability"));
		rts->opt.mark = false;
	}
#else
	warnx("%s: %s", _WARN, _("SO_MARK not supported"));
#endif
}

inline void sock_settos(int fd, int qos, bool ip6) {
	if (qos && (setsockopt(fd, ip6 ? IPPROTO_IPV6 : IPPROTO_IP,
	    ip6 ? IPV6_TCLASS : IP_TOS, &qos, sizeof(qos)) < 0))
		err(errno, "setsockopt(QoS)");
}

void print_headline(const state_t *rts, size_t nodatalen) {
	// called once at ping setup
	socklen_t len = rts->ip6 ?
		sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
	const char *target = sprint_addr(&rts->whereto, len, false);
	printf("%s %s (%s)", _("PING"), rts->hostname, target);
	if (rts->ip6 && rts->flowlabel)
		printf(", %s 0x%05x", _("flow"), ntohl(rts->flowlabel));
	if (rts->device || rts->opt.strictsource) {
		const char *from = sprint_addr(&rts->source, len, false);
		printf("%s %s %s:", _(" from"), from, rts->device ? rts->device : "");
	}
	printf(" %zu(%zu) %s\n", rts->datalen, rts->datalen + nodatalen, _("data bytes"));
}

/* Protocol independent setup and parameter checks */
static void ping_setup(state_t *rts, const sock_t *sock) {
	if (rts->opt.flood && !rts->opt.interval)
		rts->interval = 0;

	// interval restrictions
	if (rts->uid && (rts->interval < MIN_USER_MS))
		errx(EINVAL, "%s: %s %u %s, %s", _("Cannot flood"),
			_("Minimal user interval must be >="), MIN_USER_MS, _("ms"),
			_("see -i option for details"));
	if (rts->interval >= (INT_MAX / rts->preload))
		errx(EINVAL, "%s: %d", _("Illegal preload and/or interval"), rts->interval);

	// socket options
	if (rts->opt.so_debug) {
		int opt = 1;
		setsockopt(sock->fd, SOL_SOCKET, SO_DEBUG, &opt, sizeof(opt));
	}
	if (rts->opt.so_dontroute) {
		int opt = 1;
		setsockopt(sock->fd, SOL_SOCKET, SO_DONTROUTE, &opt, sizeof(opt));
	}
#ifdef SO_TIMESTAMP
	if (!rts->opt.latency) {
		int opt = 1;
		if (setsockopt(sock->fd, SOL_SOCKET, SO_TIMESTAMP, &opt, sizeof(opt)) < 0)
			warnx("%s: %s", _WARN, _("no SO_TIMESTAMP support, falling back to SIOCGSTAMP"));
	}
#endif
	sock_setmark(rts, sock->fd);

	/* Set some SNDTIMEO to prevent blocking forever
	 * on sends, when device is too slow or stalls. Just put limit
	 * of one second, or "interval", if it is less.
	 */
	{ struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
	  if (rts->interval < 1000) {
		tv.tv_sec  = 0;
		tv.tv_usec = 1000 * SCHINT(rts->interval);
	  }
	  setsockopt(sock->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	}

	/* Set RCVTIMEO to "interval"
	 * Note, it is just an optimization allowing to avoid redundant poll() */
	{ struct timeval tv = {
		.tv_sec  = SCHINT(rts->interval) / 1000,
		.tv_usec = 1000 * (SCHINT(rts->interval) % 1000),
	  };
	  if (setsockopt(sock->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)))
		rts->opt.flood_poll = true;
	}

	if (!rts->opt.pingfilled) {
		unsigned char *p = rts->outpack + sizeof(struct icmphdr);
		/* Do not forget about case of small datalen, fill timestamp area too! */
		for (size_t i = 0; i < rts->datalen; ++i)
			*p++ = i;
	}

	{ // signals
	  struct sigaction sa = { .sa_handler = sig_handler, .sa_flags = SA_RESTART };
	  sigaction(SIGINT,  &sa, NULL);
	  sigaction(SIGQUIT, &sa, NULL);
	  sigaction(SIGALRM, &sa, NULL);
	  sigset_t set;
	  sigemptyset(&set);
	  sigprocmask(SIG_SETMASK, &set, NULL);
	}

	clock_gettime(CLOCK_MONOTONIC_RAW, &rts->start_time);

	if (rts->deadline) {
		struct itimerval it = { .it_value = { .tv_sec = rts->deadline }};
		setitimer(ITIMER_REAL, &it, NULL);
	}

	if (isatty(STDOUT_FILENO)) {
		struct winsize w = {0};
		if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) != -1) {
			if (w.ws_col > 0)
				rts->screen_width = w.ws_col;
		}
	}
}


/* Print out statistics, and give up */
static bool finish(const state_t *rts) {
	struct timespec tv = {0};
	timespecsub(&rts->cur_time, &rts->start_time, &tv);

	putchar('\n');
	fflush(stdout);
	printf("--- %s%s ---\n", rts->hostname, _(" ping statistics"));
	printf("%ld %s", rts->ntransmitted, _("packets transmitted"));
	printf(", %ld %s",  rts->nreceived, _("received"));
	if (rts->nrepeats)
		printf(", +%ld %s", rts->nrepeats,  _("duplicates"));
	if (rts->nchecksum)
		printf(", +%ld %s", rts->nchecksum, _("corrupted"));
	if (rts->nerrors)
		printf(", +%ld %s", rts->nerrors,   _("errors"));

	if (rts->ntransmitted) {
		printf(", %g%% %s",
			((rts->ntransmitted - rts->nreceived) * 100.) / rts->ntransmitted,
			_("packet loss"));
		printf(", %s %ld %s", _("time"),
			1000 * tv.tv_sec + (tv.tv_nsec + 500000) / 1000000, _("ms"));
	}
	putchar('\n');

	char comma = ',';
	if (rts->nreceived && rts->timing) {
		long total = rts->nreceived + rts->nrepeats;
		long tmavg = rts->tsum / total;
		long long tmvar = (rts->tsum < INT_MAX) ?
			/* This slightly clumsy computation order is important to avoid
			 * integer rounding errors for small ping times */
			(rts->tsum2 - ((rts->tsum * rts->tsum) / total)) / total :
			(rts->tsum2 / total) - tmavg * tmavg;
		double tmdev = sqrt((tmvar < 0) ? -tmvar : tmvar);
		printf("%s = %ld.%03ld/%lu.%03ld/%ld.%03ld/%ld.%03ld %s",
			_("rtt min/avg/max/mdev"),
			rts->tmin             / 1000,   rts->tmin % 1000,
			(unsigned long)(tmavg / 1000),      tmavg % 1000,
			rts->tmax             / 1000,   rts->tmax % 1000,
			(long)tmdev           / 1000, (long)tmdev % 1000,
			_("ms"));
		comma = ',';
	}
	if (rts->pipesize > 1) {
		if (comma)
			printf("%c ", comma);
		printf("%s %d", _("pipe"), rts->pipesize);
		comma = ',';
	}

	if ((!rts->interval || rts->opt.flood || rts->opt.adaptive)
			&& rts->nreceived && (rts->ntransmitted > 1)) {
		if (comma)
			printf("%c ", comma);
		int ipg = (1000000 * (long long)tv.tv_sec + tv.tv_nsec / 1000) / (rts->ntransmitted - 1);
		printf("%s = %d.%03d/%d.%03d %s", _("ipg/ewma"),
		       ipg      / 1000,            ipg % 1000,
		       rts->rtt / 8000, (rts->rtt / 8) % 1000,
		       _("ms"));
	}
	putchar('\n');
	return (!rts->nreceived || (rts->deadline && (rts->nreceived < rts->npackets)));
}


static void fin_status(const state_t *rts) {
	static bool in_fin_status;
	if (in_fin_status)
		return;
	in_fin_status = true;
	int loss = rts->ntransmitted ?
		(100ll * (rts->ntransmitted - rts->nreceived)) / rts->ntransmitted
		: 0;
	// stderr due to signals
	fprintf(stderr, "%ld/%ld %s", rts->nreceived, rts->ntransmitted, _("packets"));
	fprintf(stderr, ", %d%% %s", loss, _("loss"));
	if (rts->nreceived && rts->timing) {
		long tavg = rts->tsum / (rts->nreceived + rts->nrepeats);
		fprintf(stderr, ", %s = %ld.%03ld/%lu.%03ld/%d.%03d/%ld.%03ld %s",
			_("min/avg/ewma/max"),
			rts->tmin / 1000, rts->tmin      % 1000,
			tavg      / 1000, tavg           % 1000,
			rts->rtt  / 8000, (rts->rtt / 8) % 1000,
			rts->tmax / 1000, rts->tmax      % 1000,
			_("ms"));
	}
	putc('\n', stderr);
	in_fin_status = false;
}

#ifdef SO_TIMESTAMP
static inline struct timeval *msghdr_timeval(struct msghdr *msg) {
	struct timeval *tv = NULL;
	for (struct cmsghdr *c = CMSG_FIRSTHDR(msg); c; c = CMSG_NXTHDR(msg, c))
		if ((c->cmsg_level == SOL_SOCKET) && (c->cmsg_type == SO_TIMESTAMP))
			if (c->cmsg_len >= CMSG_LEN(sizeof(struct timeval)))
				tv = (struct timeval *)CMSG_DATA(c);
	return tv;
}
#endif

static bool main_loop(state_t *rts, const fnset_t *fnset, const sock_t *sock,
		uint8_t *packet, size_t packlen)
{
	struct iovec iov = { .iov_base = packet };
	char addrbuf[128];
	char ans_data[4096];

	for (;;) {
		/* Check exit conditions. */
		if (exiting) // SIGINT, SIGALRM
			break;
		if (rts->npackets && rts->nreceived + rts->nerrors >= rts->npackets)
			break;
		if (rts->deadline && rts->nerrors)
			break;
		/* Check for and do special actions */
		if (snapshot) { // SIGQUIT
			fin_status(rts);
			snapshot = false;
		}

		/* Send probes scheduled to this time */
		int next;
		do {
			next = pinger(rts, fnset, sock);
			if (rts->npackets && (rts->ntransmitted >= rts->npackets) && !rts->deadline)
				next = schedule_exit(rts, next);
		} while (next <= 0);

		/* "next" is time to send next probe, if positive.
		 * If next<=0 send now or as soon as possible. */

		/* Technical part. Looks wicked. Could be dropped,
		 * if everyone used the newest kernel. :-)
		 * Its purpose is:
		 * 1. Provide intervals less than resolution of scheduler.
		 *    Solution: spinning.
		 * 2. Avoid use of poll(), when recvmsg() can provide
		 *    timed waiting (SO_RCVTIMEO). */
		int polling = 0;
		int recv_error = 0;
		if (rts->opt.adaptive || rts->opt.flood_poll || (next <= SCHINT(rts->interval))) {
			int recv_expected = in_flight(rts);

			/* If we are here, recvmsg() is unable to wait for
			 * required timeout. */
			if (1000 % HZ == 0 ? next <= 1000 / HZ : (next < INT_MAX / HZ && next * HZ <= 1000)) {
				/* Very short timeout... So, if we wait for
				 * something, we sleep for MIN_INTERVAL_MS.
				 * Otherwise, spin! */
				if (recv_expected) {
					next = MIN_GAP_MS;
				} else {
					next = 0;
					/* When spinning, no reasons to poll.
					 * Use nonblocking recvmsg() instead. */
					polling = MSG_DONTWAIT;
					/* But yield yet. */
					sched_yield();
				}
			}

			if (!polling &&
			    (rts->opt.adaptive || rts->opt.flood_poll || rts->interval)) {
				struct pollfd pset;
				pset.fd = sock->fd;
				pset.events = POLLIN;
				pset.revents = 0;
				if (poll(&pset, 1, next) < 1 ||
				    !(pset.revents & (POLLIN | POLLERR)))
					continue;
				polling = MSG_DONTWAIT;
				recv_error = pset.revents & POLLERR;
			}
		}

		for (;;) {
			/* Raw socket can receive messages destined to other running pings */
			bool not_ours = false;

			iov.iov_len = packlen;
			struct msghdr msg = {
				.msg_name       = addrbuf,
				.msg_namelen    = sizeof(addrbuf),
				.msg_iov        = &iov,
				.msg_iovlen     = 1,
				.msg_control    = ans_data,
				.msg_controllen = sizeof(ans_data),
			};

			ssize_t received = recvmsg(sock->fd, &msg, polling);
			polling = MSG_DONTWAIT;

			if (received < 0) {
				/* If there was a POLLERR and there is no packet
				 * on the socket, try to read the error queue.
				 * Otherwise, give up.
				 */
				if (((errno == EAGAIN) && !recv_error)
				    || (errno == EINTR))
					break;
				int keep = errno;
				recv_error = 0;
				if (!fnset->receive_error(rts, sock)) {
					errno = keep;
					if (errno) {
						warn("recvmsg");
						break;
					}
					not_ours = true;
				}
			} else {
				struct timeval *recv_tv =
#ifdef SO_TIMESTAMP
					msghdr_timeval(&msg);
#else
					NULL;
#endif
				struct timeval timeval;
				if (rts->opt.latency || !recv_tv) {
					if (rts->opt.latency || ioctl(sock->fd, SIOCGSTAMP, &timeval)) {
						if (gettimeofday(&timeval, NULL) < 0) // no way
							memset(&timeval, 0, sizeof(timeval));
					}
					recv_tv = &timeval;
				}
				assert(received >= 0); // be sure in ssize_t to size_t conversion at one place
				not_ours = fnset->parse_reply(rts, sock->raw, &msg, received, addrbuf, recv_tv);
			}

			{ /* Lack of packet filtration: report once */
			static bool reported_about_bpf;
			if (not_ours && sock->raw && !reported_about_bpf) {
				warnx("%s: %s", _WARN, _("Lack of packet filtration"));
				reported_about_bpf = true;
			}}

			/* If nothing is in flight, "break" returns us to pinger */
			if (!in_flight(rts))
				break;

			/* Otherwise, try to recvmsg() again. recvmsg()
			 * is nonblocking after the first iteration, so that
			 * if nothing is queued, it will receive EAGAIN
			 * and return to pinger. */
		}
	}
	return finish(rts);
}


int setup_n_loop(state_t *rts, size_t hlen, const sock_t *sock,
		const fnset_t* fnset)
{
	/* can we time transfer */
	rts->timing = (rts->datalen >= sizeof(struct timeval));
#ifdef ENABLE_NI6
	if (rts->ip6 && rts->ni && rts->timing)
		rts->timing = (rts->ni->query < 0);
#endif
	//
	size_t packlen = hlen + rts->datalen;
	uint8_t *packet = malloc(packlen);
	if (packet) {
		ping_setup(rts, sock);
		drop_capabilities();
		int rc = main_loop(rts, fnset, sock, packet, packlen);
		free(packet);
		return rc;
	}
	if (errno)
		err(errno, "malloc(%zu)", packlen);
	errx(EXIT_FAILURE, "malloc(%zu)", packlen);
}

bool stats_noflush(state_t *rts, const uint8_t *icmp, int icmplen,
	size_t received, uint16_t seq, int hops, const struct timeval *at,
	void (*print)(bool ip6, const uint8_t *hdr, size_t len),
	const char *from, bool ack, bool wrong)
{
// note: do not use inet_ntoa() and sprint_addr() inside, it requires a static buffer
	++rts->nreceived;
	if (ack)
		acknowledge(rts, seq);

	const uint8_t *ptr = icmp + icmplen;
	long triptime = 0;

	if (rts->timing && (received >= (sizeof(struct icmphdr) + sizeof(struct timeval)))) {
		struct timeval peer;
		memcpy(&peer, ptr, sizeof(peer));
		struct timeval tv;
		memcpy(&tv,    at, sizeof(tv));
		do {
			timersub(&tv, &peer, &tv);
			triptime = tv.tv_sec * 1000000 + tv.tv_usec;
			if (triptime >= 0)
				break;
			warnx("%s: %s: %ldus", _WARN,
				_("Time of day goes back, taking countermeasures"),
				triptime);
			if (rts->opt.latency) {
				triptime = 0;
				break;
			}
			rts->opt.latency = true;
			gettimeofday(&tv, NULL);
		} while (1);
		if (triptime > (MAXWAIT * 1000000))
			triptime = MAXWAIT * 1000000;
		if (ack) {
			rts->tsum  += triptime;
			rts->tsum2 += (double)((long long)triptime * (long long)triptime);
			if (triptime < rts->tmin)
				rts->tmin = triptime;
			if (triptime > rts->tmax)
				rts->tmax = triptime;
			if (!rts->rtt)
				rts->rtt = triptime * 8;
			else
				rts->rtt += triptime - rts->rtt / 8;
			if (rts->opt.adaptive)
				rts->interval = get_interval(rts);
		}
	}

	bool dup = false;
	if (!ack) {
		++rts->nchecksum;
		--rts->nreceived;
	} else if (rcvd_test(rts, seq)) {
		++rts->nrepeats;
		--rts->nreceived;
		dup = true;
	} else
		rcvd_set(rts, seq);
	rts->confirm = rts->confirm_flag;

	if (rts->opt.quiet)
		return true;
	if (rts->opt.flood) {
		if (ack) {
			if (write(STDOUT_FILENO, "\b \b", 3)) {};
		} else {
			if (write(STDOUT_FILENO, "\bC", 2)) {};
		}
		return true;
	}

	PRINT_TIMESTAMP;
	printf("%zd %s%s %s: ", received, _("bytes"), _(" from"), from);
	if (print) /* seq */
		print(rts->ip6, icmp, received);
	else
		printf("%s=%u", _("icmp_seq"), seq);
	if (rts->opt.verbose)
		printf(" %s=%u", _("ident"), ntohs(rts->ident16));
	if (hops >= 0)
		printf(" %s=%d", _("ttl"), hops);
	if (received < (sizeof(struct icmphdr) + rts->datalen)) {
		printf(" (%s)\n", _("truncated"));
		return true;
	}

	if (rts->timing) {
		printf(" %s=", _("time"));
		if      (triptime >= (100000 - 50))
			printf("%ld", (triptime + 500) / 1000);
		else if (triptime >= (10000 - 5))
			printf("%ld.%01ld", (triptime + 50) / 1000,
			       ((triptime + 50) % 1000) / 100);
		else if (triptime >= 1000)
			printf("%ld.%02ld", (triptime + 5) / 1000,
			       ((triptime + 5) % 1000) / 10);
		else
			printf("%ld.%03ld", triptime / 1000, triptime % 1000);
		printf(" %s", _("ms"));
	}
	char* exclame[3] = {
		(dup && (!rts->multicast || rts->opt.verbose)) ? "DUP" : NULL,
		ack ? NULL : "BAD CHECKSUM",
		wrong ? "DIFFERENT ADDRESS" : NULL,
	};
	for (int i = 0; i < 3; i++)
		if (exclame[i])
			printf(" (%s!)", exclame[i]);

	/* check the data */
	const uint8_t *cp = ptr + sizeof(struct timeval);
	const uint8_t *dp = &rts->outpack[sizeof(struct icmphdr) + sizeof(struct timeval)];
	for (size_t i = sizeof(struct timeval); i < rts->datalen; ++i, ++cp, ++dp) {
		if (*cp == *dp)
			continue;
		putchar('\n');
		printf("\n%s %zu (%s%02x, %s%02x) ",
			_("wrong byte #"),  i,
			_("expected 0x"), *dp,
			_("got 0x"),      *cp);
		cp = ptr + sizeof(struct timeval);
		for (i = sizeof(struct timeval); i < rts->datalen; ++i, ++cp) {
			if ((i % 32) == sizeof(struct timeval))
				printf("\n#%zu\t", i);
			printf("%x ", *cp);
		}
	}

	return false;
}

inline bool gather_stats(state_t *rts, const void *icmp, int icmplen,
	size_t received, uint16_t seq, int hops, const struct timeval *at,
	void (*print)(bool ip6, const uint8_t *hdr, size_t len),
	const char *from, bool ack, bool wrong)
{
	bool finished = stats_noflush(rts, icmp, icmplen, received, seq, hops,
		at, print, from, ack, wrong);
	if (finished)
		fflush(stdout);
	return finished;
}

double strtod_or_err(const char *str, const char *errmesg,
	double min, double max)
{
	errno = (str && *str) ? 0 : EINVAL;
	if (!errno) {
		char *end = NULL;
/* Here we always use "C" LC_NUMERIC to have dots as decimal separators */
		setlocale(LC_NUMERIC, "C");
		double num = strtod(str, &end);
		int keep = errno;
		setlocale(LC_NUMERIC, "");
		errno = keep;
		if (!(errno || (str == end) || (end && *end))) {
			if (isgreaterequal(num, min) && islessequal(num, max))
				return num;
			errno = ERANGE;
			err(errno, "%s: %s: %g-%g", errmesg, str, min, max);
		}
	}
	if (errno)
		err(errno, "%s: %s", errmesg, str);
	errx(EXIT_FAILURE, "%s: %s", errmesg, str);
}

/* Return a host address optionally with a hostname */
const char *sprint_addr(const void *sa, socklen_t salen, bool resolve) {
	static char buffer[2 * NI_MAXHOST + 4] = ""; // "NI_MAXHOST (NI_MAXHOST)"
	static struct sockaddr_storage last_sa = {0};
	static socklen_t last_salen = 0;
	if ((salen == last_salen) && !memcmp(sa, &last_sa, salen))
		return buffer;
	memcpy(&last_sa, sa, salen);
	last_salen = salen;
	in_print_addr = !setjmp(label_in_print_addr);
	char address[NI_MAXHOST] = "";
	getnameinfo(sa, salen, address, sizeof(address), NULL, 0, NI_FLAGS | NI_NUMERICHOST);
	//
	char name[NI_MAXHOST] = "";
	if (resolve && !exiting)
		getnameinfo(sa, salen, name, sizeof(name), NULL, 0, NI_FLAGS);
	//
	int rc = -1;
	if (*name && strncmp(name, address, NI_MAXHOST))
		rc = snprintf(buffer, sizeof(buffer), "%s (%s)", name, address);
	else
		rc = snprintf(buffer, sizeof(buffer), "%s", address);
	if (rc < 0)
		buffer[0] = 0;
	//
	in_print_addr = false;
	return buffer;
}

inline void acknowledge(state_t *rts, uint16_t seq) {
	uint16_t diff = (uint16_t)rts->ntransmitted - seq;
	if (diff <= 0x7FFF) {
		if ((int)diff + 1 > rts->pipesize)
			rts->pipesize = (int)diff + 1;
		if ((int16_t)(seq - rts->acked) > 0 ||
		    (uint16_t)rts->ntransmitted - rts->acked > 0x7FFF)
			rts->acked = seq;
	}
}

