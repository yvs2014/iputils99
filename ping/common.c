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

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <setjmp.h>
#include <sched.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#ifndef SIOCGSTAMP
#include <linux/sockios.h>
#endif

#include "common.h"

#include "iputils.h"
#include "stats.h"
#include "setsock.h"
#include "sock_pa.h"
#include "sock_pt.h"
#ifdef HAVE_LIBCAP
#include "caps.h"
#else
#include "perm.h"
#endif

#ifndef HZ
#define HZ sysconf(_SC_CLK_TCK)
#endif

#define MIN_USER_MS	10	// Minimal interval for non-root users, in milliseconds

#ifndef NI_MAXADDR
#define NI_MAXADDR	40	// Enough for the longest ip6addr in chars (39 + \0)
#endif
#ifndef NI_MAXNAME
#define NI_MAXNAME	NI_MAXHOST
#endif

// Identify word in array
#define BITMAP_ARR(bit)	((map)[(bit) >> BITMAP_SHIFT])
// Identify bit in word
#define BITMAP_BIT(bit)	(((bitmap_t)1) << ((bit) & ((1 << BITMAP_SHIFT) - 1)))

inline bitmap_t rcvd_test(uint16_t seq, const bitmap_t *map) {
	uint bit = seq % MAX_DUP_CHK;
	return BITMAP_ARR(bit) & BITMAP_BIT(bit);
}
inline void rcvd_set(uint16_t seq, bitmap_t *map) {
	uint bit = seq % MAX_DUP_CHK;
	BITMAP_ARR(bit) |= BITMAP_BIT(bit);
}

inline void rcvd_clear(uint16_t seq, bitmap_t *map) {
	uint bit = seq % MAX_DUP_CHK;
	BITMAP_ARR(bit) &= ~BITMAP_BIT(bit);
}

static const char *usestr =
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
#ifdef SO_MARK
"  -m <mark>          tag the packets going out\n"
#endif
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
"  -T <timestamp>     define timestamp, can be one of TSONLY|TSANDADDR|TSPRESPEC\n"
"\n"
"IPv6 options:\n"
"  -6                 use IPv6\n"
"  -F <flowlabel>     define flow label, default is random\n"
#ifdef ENABLE_RFC4620
"  -N <nodeinfo opt>  use IPv6 node info query, try <help> as argument\n"
#endif
;

NORETURN void usage(int rc) {
	drop_priv();
	usage_data_t use = {
		.usestr = usestr,
		.target = "TARGET",
		.more   = !MORE,
	};
	usage_common(rc, &use);
}

// Fill payload area (supposed to be without timestamp area) with supplied pattern
void fill_payload(int quiet, const char *str, uint8_t *payload, size_t len) {
	for (const char *cp = str; *cp; cp++)
		if (!isxdigit(*cp))
			errx(EINVAL, "%s: %s", _("Pattern must be specified as hex digits"), cp);
#define PAD_BYTES	16
	uint pad[PAD_BYTES];
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

static inline int schedule_exit(int next, long nreceived, long tmax, int interval, int lingertime) {
	static uint64_t waittime;
	if (!waittime) {
		if (nreceived) {
			waittime = 2 * tmax;
			uint64_t minwait = interval * (uint64_t)1000;
			if (waittime < minwait)
				waittime = minwait;
		} else
			waittime = lingertime * (uint64_t)1000;
		time_t msec = waittime / 1000;
		if ((next < 0) || (next < msec))
			next = msec;
		struct itimerval it = { .it_value = {
			.tv_sec  = waittime / MLN,
			.tv_usec = waittime % MLN,
		}};
		setitimer(ITIMER_REAL, &it, NULL);
	}
	return next;
}

int get_interval(const state_t *rts) {
	int dt = rts->interval;
	int est = rts->rtt ? (rts->rtt / 8) : (dt * 1000);
	dt = (est + rts->rtt_addend + 500) / 1000;
	if (rts->uid && (dt < MIN_USER_MS))
		dt = MIN_USER_MS;
	return dt;
}

inline int in_flight(const state_t *rts) {
	uint16_t diff = (uint16_t)rts->ntransmitted - rts->acked;
	return (diff <= INT16_MAX) ? diff : (rts->ntransmitted - rts->nreceived - rts->nerrors);
}

static inline void advance_ntransmitted(state_t *rts) {
	rts->ntransmitted++;
	/* Invalidate acked, if 16 bit seq overflows */
	if (((uint16_t)rts->ntransmitted - rts->acked) > INT16_MAX)
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
			  (tv.tv_nsec - rts->cur_time.tv_nsec) / MLN;
		if (!rts->interval) {
			/* Case of unlimited flood is special;
			 * if we see no reply, they are limited to 100pps */
			long rest = MIN_GAP_MS - ntokens;
			if ((rest > 0) && (in_flight(rts) >= rts->preload))
				return rest;
		}
		ntokens += tokens;
		long maxtokens = (long)rts->interval * rts->preload;
		if (ntokens > maxtokens)
			ntokens = maxtokens;
		if (ntokens < rts->interval)
			return rts->interval - ntokens;

		rts->cur_time = tv;
		tokens = ntokens - rts->interval;
	}

	if (rts->opt.outstanding && (rts->ntransmitted > 0)) {
		if(!rcvd_test(rts->ntransmitted, rts->bitmap)) {
			PRINT_TIMESTAMP;
			printf("%s: %s=%lu\n", _("No answer yet"), _("icmp_seq"), rts->ntransmitted % MAX_DUP_CHK);
			fflush(stdout);
		}
	}

	int rc;
	int hard_local_error = 0;
	do {
		rcvd_clear(rts->ntransmitted + 1, rts->bitmap);
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
					SUPPRESS_UNUSED_RESULT_WARN(write(STDOUT_FILENO, ".", 1));
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
		if (rts->opt.flood)
			SUPPRESS_UNUSED_RESULT_WARN(write(STDOUT_FILENO, "E", 1));
		else
			warn("sendmsg");
	}
	tokens = 0;
	return SCHINT(rts->interval);
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
	if (rts->opt.so_debug)
		setsock_debug(sock->fd); // privileged action
	if (rts->opt.so_dontroute)
		setsock_dontroute(sock->fd);
#ifdef SO_TIMESTAMP
	if (!rts->opt.latency)
		setsock_timestamp(sock->fd);
#endif
#ifdef SO_MARK
	if (rts->so.mark >= 0)
		setsock_mark(sock->fd, rts->so.mark); // privileged action
#endif
	setsock_sndtime(sock->fd, rts->interval);
	if (setsock_rcvtime(sock->fd, rts->interval))
		rts->opt.flood_poll = true;
	if (!rts->opt.pingfilled) {
		uint8_t *p = rts->outpack + sizeof(struct icmphdr);
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

static bool main_loop(state_t *rts, const fnset_t *fnset, const sock_t *sock, uint8_t *packet, size_t packlen) {
	struct iovec iov = { .iov_base = packet };
	uint8_t addrbuf[128] = {0};
	uint8_t ans_data[4096] = {0};

	for (;;) {
		if (exiting) // SIGINT, SIGALRM
			break;
		if (rts->npackets && rts->nreceived + rts->nerrors >= rts->npackets)
			break;
		if (rts->deadline && rts->nerrors)
			break;
		/* Check for and do special actions */
		if (snapshot) { // SIGQUIT
			print_status(rts);
			snapshot = false;
		}

		/* Send probes scheduled to this time */
		int next;
		do {
			next = pinger(rts, fnset, sock);
			if (rts->npackets && (rts->ntransmitted >= rts->npackets) && !rts->deadline)
				next = schedule_exit(next, rts->nreceived, rts->tmax, rts->interval, rts->lingertime);
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
			// If we are here, recvmsg() is unable to wait for required timeout
			if (1000 % HZ == 0 ? next <= 1000 / HZ : (next < INT_MAX / HZ && next * HZ <= 1000)) {
						     // Very short timeout ...
				if (in_flight(rts))  // If we wait for something, sleep for MIN_GAP_MS
					next = MIN_GAP_MS;
				else {               // otherwise spin
					next = 0;
					polling = MSG_DONTWAIT; // No reason to poll at spinning,
								// instead use nonblocking recvmsg().
					sched_yield();          // But yield yet.
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
				recv_error = 0;
				if (!fnset->receive_error(rts, sock)) {
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
				struct timeval timeval = {0};
				if (rts->opt.latency || !recv_tv) {
					if (rts->opt.latency || ioctl(sock->fd, SIOCGSTAMP, &timeval)) {
						if (gettimeofday(&timeval, NULL) < 0)
							memset(&timeval, 0, sizeof(timeval));
					}
					recv_tv = &timeval;
				}
				not_ours = fnset->parse_reply(rts, sock->raw, &msg, received, addrbuf, recv_tv);
			}

			if (not_ours && sock->raw) {
				if (rts->unidentified) {
					if (rts->opt.verbose)
warnx("id=0x%04x: %s: %u", rts->ident16, _("non-filtered out"), rts->unidentified);
				} else if (fnset->bpf_filter)
					fnset->bpf_filter(rts, sock);
				rts->unidentified++;
				if (!rts->unidentified)
					rts->unidentified++;
			}

			/* If nothing is in flight, "break" returns us to pinger */
			if (!in_flight(rts))
				break;

			/* Otherwise, try to recvmsg() again. recvmsg()
			 * is nonblocking after the first iteration, so that
			 * if nothing is queued, it will receive EAGAIN
			 * and return to pinger. */
		}
	}
	return resume(rts);
}

int setup_n_loop(state_t *rts, size_t iph_len, size_t icmph_len, size_t opt_len, size_t extra,
	const sock_t *sock, const fnset_t* fnset) // NONNULL((1, 5, 6)
{
	if (!rts->sndbuf)
		rts->sndbuf = estimate_packlen(iph_len + opt_len, icmph_len, rts->datalen);
	size_t dlen = rts->datalen;
#ifdef ENABLE_RFC4620
	ssize_t l = (rts->ni && niquery_is_enabled(rts->ni)) ?
		sizeof(struct ni_hdr) + rts->ni->subject_len - sizeof(struct icmp6_hdr) : 0;
	dlen = (l > 0) ? l : 0;
#endif
	setsock_buffer(sock->fd, rts->sndbuf, rts->preload);
	headline(rts, iph_len + opt_len + icmph_len, dlen);
	//
	size_t hlen = iph_len + icmph_len + extra;
	if (rts->ip6)
		hlen += icmph_len;
	else
		hlen *= 2;
	//
	rts->timing = (rts->datalen >= sizeof(struct timeval)); // can we transfer timestamp
#ifdef ENABLE_RFC4620
	if (rts->ip6 && rts->ni && rts->timing)
		rts->timing = (rts->ni->query < 0);
#endif
	//
	size_t packlen = hlen + rts->datalen;
	uint8_t *packet = calloc(1, packlen);
	if (!packet)
		err(errno, "calloc(%zu)", packlen);
	ping_setup(rts, sock);
	errno = 0; // postsetup cleanup
	drop_priv();
	int rc = main_loop(rts, fnset, sock, packet, packlen);
	free(packet);
	return rc;
}

/* Return hostaddr and hostname (optionally), note: last request is cached */
const char *sprint_addr(const void *sa, socklen_t salen, bool resolve) {
	// "NI_MAXNAME (NI_MAXADDR)"
	static char nicached[NI_MAXNAME + 2 + NI_MAXADDR + 1];
	static struct sockaddr_storage last_sa = {0};
	static socklen_t last_salen = 0;
	if ((salen == last_salen) && !memcmp(sa, &last_sa, salen))
		return nicached;
	memcpy(&last_sa, sa, salen);
	last_salen = salen;
	in_print_addr = !setjmp(label_in_print_addr);
	char addr[NI_MAXADDR] = {0};
	getnameinfo(sa, salen, addr, sizeof(addr), NULL, 0, NI_FLAGS | NI_NUMERICHOST);
	//
	char name[NI_MAXNAME] = {0};
	if (resolve && !exiting)
		getnameinfo(sa, salen, name, sizeof(name), NULL, 0, NI_FLAGS);
	//
	int rc = (*name && strncmp(name, addr, NI_MAXADDR)) ?
		snprintf(nicached, sizeof(nicached), "%s (%s)", name, addr) :
		snprintf(nicached, sizeof(nicached), "%s", addr);
	if (rc < 0)
		nicached[0] = 0;
	//
	in_print_addr = false;
	return nicached;
}

inline const char *sprint_addr4(in_addr_t addr, bool resolve) {
	struct sockaddr_in sin = {.sin_family = AF_INET, .sin_addr.s_addr = addr};
	return sprint_addr(&sin, sizeof(sin), resolve);
}

inline void acknowledge(state_t *rts, uint16_t seq) {
	uint16_t diff = (uint16_t)rts->ntransmitted - seq;
	if (diff <= INT16_MAX) {
		int piped = (int)diff + 1;
		if (piped > rts->pipesize)
			rts->pipesize = piped;
		if ((int16_t)(seq - rts->acked) > 0 ||
		    (uint16_t)rts->ntransmitted - rts->acked > INT16_MAX)
			rts->acked = seq;
	}
}

size_t estimate_packlen(size_t ip, size_t icmp, size_t data) {
	// "alloc" is an estimate of memory taken by single packet
	return ((icmp + data + 511) / 512) * (ip + 2 * icmp + DEFIPPAYLOAD + 160);
}

void bind_by_need(int fd, uint16_t port, bool strict, struct sockaddr *src, bool ip6)  { // NONNULL(4)
	if (port) {
		if (ip6)
			SA6(src)->sin6_port = port;
		else
			SA4(src)->sin_port  = port;
	}
	if (strict || port)
		if (bind(fd, src, ip6 ? SA6_LEN : SA4_LEN) < 0)
			err(errno, "bind(%s)", "icmp-socket");
}

void pmtu_interval(state_t *rts) { // NONNULL(1)
	rts->multicast = true;
#if IPV6_PMTUDISC_DO == IPV6_PMTUDISC_DO
#define	PMTUDISCDO IP_PMTUDISC_DO
#else
	int pmtudo = rts->ip6 ? IPV6_PMTUDISC_DO : IP_PMTUDISC_DO;
#define	PMTUDISCDO pmtudo
#endif
	if (rts->uid) {
		if (rts->interval < MIN_MCAST_MS) {
			errx(EINVAL, "%s %u %s, %s", _(rts->ip6 ?
				"Minimal user interval for multicast ping must be >=" :
				"Minimal user interval for broadcast ping must be >="),
				MIN_MCAST_MS, _("ms"), _("see -i option for details"));
		}
		if ((rts->so.mtudisc >= 0) && (rts->so.mtudisc != PMTUDISCDO))
			errx(EINVAL, "%s %s", _(rts->ip6 ?
				"Multicast ping" : "Broadcast ping"), _("does not fragment"));
	}
	if (rts->so.mtudisc < 0)
		rts->so.mtudisc = PMTUDISCDO;
}
#undef PMTUDISCDO


//
// Common setsock_xxx call sets
void setsock_set46(int fd, sockopt_t *so, bool ip6) { // NONNULL(2)
	if (so->noloop)
		setsock_noloop(fd, ip6);
	if (so->tos >= 0)
		setsock_tos(fd, so->tos, ip6);
	if (so->ttl >= 0)
		setsock_ttl(fd, so->ttl, MULTICAST_TOO, ip6);
	if (so->mtudisc >= 0)
		setsock_mtudisc(fd, so->mtudisc, ip6);
	setsock_recverr(fd, ip6);
}

