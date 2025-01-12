/*-
 * Copyright (c) 1985, 1993
 *	The Regents of the University of California.  All rights reserved.
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

/*
 * Clockdiff computes the difference between the time of the machine on which it is
 * called and the time of the machines given as argument.  The time differences measured
 * by clockdiff are obtained using a sequence of ICMP TSTAMP messages which are returned
 * to the sender by the IP module in the remote machine.
 *
 * In order to compare clocks of machines in different time zones, the time is
 * transmitted (as a 32-bit value) in milliseconds since midnight UT.  If a hosts uses a
 * different time format, it should set the high order bit of the 32-bit quantity it
 * transmits.
 *
 * However, VMS apparently transmits the time in milliseconds since midnight local time
 * (rather than GMT) without setting the high order bit.  Furthermore, it does not
 * understand daylight-saving time.  This makes clockdiff behaving inconsistently with
 * hosts running VMS.
 *
 * In order to reduce the sensitivity to the variance of message transmission time,
 * clockdiff sends a sequence of messages.  Yet, measures between two `distant' hosts can
 * be affected by a small error.  The error can, however, be reduced by increasing the
 * number of messages sent in each measurement.
 */

#include "iputils_common.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <getopt.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/timex.h>
#include <sys/types.h>
#include <time.h>
#include <err.h>
#include <errno.h>

#ifdef HAVE_LIBCAP
#include <sys/capability.h>
#endif
#ifdef USE_NLS
#include <locale.h>
#endif

enum {
	RANGE   =  1,		/* best expected round-trip time, ms */
	MSGS    = 50,
	TRIALS  = 10,
	//
	GOOD        = 0,
	UNREACHABLE = 2,
	NONSTDTIME  = 3,
	BREAK       = 4,
	CONTINUE    = 5,
	HOSTDOWN    = 0x7fffffff,
	//
	BIASP  =  43199999,
	BIASN  = -43200000,
	MODULO =  86400000,
	PROCESSING_TIME	= 0,	/* ms. to reduce error in measurement */
};

static const char* ts_format[] = {"%FT%T%z" /*iso*/, "%c" /*local*/};

typedef struct run_state {
	uint16_t id;
	int sock;
	struct sockaddr_in server;
	int ip_opt_len;
	int delta1;
	int delta2;
	uint16_t seqno;
	uint16_t seqno0;
	uint16_t acked;
	long rtt;
	long min_rtt;
	long sigma;
	char *host;
	const char *time_format;
	bool interactive;
} state_t;

struct measure_vars {
	struct timespec ts1;
	struct timespec tout;
	int msgcount;
	long min1;
	long min2;
	struct iphdr   *ip;
	struct icmphdr *icmp;
	uint8_t packet[1024];
};

/*
 * All includes, definitions, struct declarations, and global variables are above.  After
 * this comment all you can find is functions.
 */

/*
 * addcarry() - checksum routine for Internet Protocol family headers.
 *
 * This routine is very heavily used in the network code and should be modified for each
 * CPU to be as fast as possible.
 *
 * This implementation is TAHOE version.
 */
static inline int addcarry(int sum) {
	if (sum & 0xffff0000) {
		sum &= 0xffff;
		sum++;
	}
	return sum;
}

static int clockdiff_in_cksum(const unsigned short *addr, int len) {
	union word {
		char c[2];
		unsigned short s;
	} u;
	int sum = 0;

	while (len > 0) {
		/* add by words */
		while ((len -= 2) >= 0) {
			if ((unsigned long)addr & 0x1) {
				/* word is not aligned */
				u.c[0] = *(char *)addr;
				u.c[1] = *((char *)addr + 1);
				sum += u.s;
				addr++;
			} else
				sum += *addr++;
			sum = addcarry(sum);
		}
		if (len == -1)
			/* odd number of bytes */
			u.c[0] = *(unsigned char *)addr;
	}
	if (len == -1) {
		/*
		 * The last mbuf has odd # of bytes.  Follow the standard (the odd byte
		 * is shifted left by 8 bits)
		 */
		u.c[1] = 0;
		sum += u.s;
		sum = addcarry(sum);
	}
	return (~sum & 0xffff);
}

static int measure_inner_loop(state_t *rts, struct measure_vars *mv) {
	{ long tmo = MAX(rts->rtt + rts->sigma, 1);
	  mv->tout.tv_sec  = tmo / 1000;
	  mv->tout.tv_nsec = (tmo - (tmo / 1000) * 1000) * 1000000; }

	struct pollfd p = { .fd = rts->sock, .events = POLLIN | POLLHUP };
	if (ppoll(&p, 1, &mv->tout, NULL) <= 0)
		return BREAK;

	clock_gettime(CLOCK_REALTIME, &mv->ts1);

	socklen_t len = sizeof(struct sockaddr_in);
	if (recvfrom(rts->sock, mv->packet, sizeof(mv->packet),
			0, NULL, &len) < 0)
		return -1;

	mv->icmp = (struct icmphdr *)(mv->packet + (mv->ip->ihl << 2));

	long recvtime, sendtime;
	long peer_time1 = 0;
	long peer_time2 = 0;
	bool reply_with_ts = (mv->icmp->type == ICMP_TIMESTAMPREPLY) ||
		(rts->ip_opt_len                    &&
		 (mv->icmp->type == ICMP_ECHOREPLY) &&
		 (mv->packet[20] == IPOPT_TIMESTAMP));

	if (reply_with_ts
	    && (mv->icmp->un.echo.id       == rts->id)
	    && (mv->icmp->un.echo.sequence >= rts->seqno0)
	    && (mv->icmp->un.echo.sequence <= rts->seqno))
	{
		if (rts->acked < mv->icmp->un.echo.sequence)
			rts->acked = mv->icmp->un.echo.sequence;
		if (rts->ip_opt_len) {
			uint8_t *opt = mv->packet + sizeof(struct iphdr);
			if ((opt[3] & 0xF) != IPOPT_TS_PRESPEC) {
				warnx("%s: %d", _("Wrong timestamp"), opt[3] & 0xF);
				return NONSTDTIME;
			}
			if (opt[3] >> 4) {
				if (((opt[3] >> 4)   != 1) ||
				    (rts->ip_opt_len != (4 + 3 * 8)))
					 warnx("%s: %d", _("Overflow hops"), opt[3] >> 4);
			}
			sendtime = recvtime = peer_time1 = peer_time2 = 0;
			for (int i = 0; i < (opt[2] - 5) / 8; i++) {
				uint32_t *timep = (uint32_t *)(opt + 4 + i * 8 + 4);
				uint32_t t = ntohl(*timep);

				if (t & 0x80000000)
					return NONSTDTIME;

				if (i == 0)
					sendtime = t;
				if (i == 1)
					peer_time1 = peer_time2 = t;
				if (i == 2) {
					if (rts->ip_opt_len == (4 + 4 * 8))
						peer_time2 = t;
					else
						recvtime = t;
				}
				if (i == 3)
					recvtime = t;
			}

			if (!(sendtime && recvtime && peer_time1 && peer_time2)) {
				warnx("%s", _("Wrong timestamp"));
				return -1;
			}
		} else {
			recvtime = (mv->ts1.tv_sec % (24 * 60 * 60)) * 1000 +
					mv->ts1.tv_nsec / 1000000;
			sendtime = ntohl(*(uint32_t *)(mv->icmp + 1));
		}

		long diff = recvtime - sendtime;
		if (diff < 0) /* diff can be less than 0 around midnight */
			return CONTINUE;
		rts->rtt   = (rts->rtt   * 3 + diff)                  / 4;
		rts->sigma = (rts->sigma * 3 + labs(diff - rts->rtt)) / 4;
		mv->msgcount++;
		if (!rts->ip_opt_len) {
			peer_time1 = ntohl(((uint32_t *)(mv->icmp + 1))[1]);
			/*
			 * a hosts using a time format different from ms.  since midnight
			 * UT (as per RFC792) should set the high order bit of the 32-bit
			 * time value it transmits.
			 */
			if ((peer_time1 & 0x80000000) != 0)
				return NONSTDTIME;
		}
		if (rts->interactive) {
			printf(".");
			fflush(stdout);
		}

		long delta1 = peer_time1 - sendtime;
		/*
		 * Handles wrap-around to avoid that around midnight small time
		 * differences appear enormous.  However, the two machine's clocks must
		 * be within 12 hours from each other.
		 */
		if      (delta1 < BIASN)
			delta1 += MODULO;
		else if (delta1 > BIASP)
			delta1 -= MODULO;

		long delta2 = recvtime;
		delta2 -= rts->ip_opt_len ? peer_time2 : peer_time1;
		if      (delta2 < BIASN)
			delta2 += MODULO;
		else if (delta2 > BIASP)
			delta2 -= MODULO;

		if (delta1 < mv->min1)
			mv->min1 = delta1;
		if (delta2 < mv->min2)
			mv->min2 = delta2;
		int rtt = delta1 + delta2;
		if (rtt < rts->min_rtt) {
			rts->min_rtt = rtt;
			rts->delta2  = (delta1 - delta2) / 2 + PROCESSING_TIME;
		}
		if (diff < RANGE) {
			mv->min1 = delta1;
			mv->min2 = delta2;
			return BREAK;
		}
	}
	return CONTINUE;
}

/*
 * Measures the differences between machines' clocks using ICMP timestamp messages
 */
static int measure(state_t *rts) {
	struct measure_vars mv = {
		.min1 = LONG_MAX,
		.min2 = LONG_MAX,
	};
	mv.ip = (struct iphdr *)mv.packet;

	rts->min_rtt = LONG_MAX;
	rts->delta1  = HOSTDOWN;
	rts->delta2  = HOSTDOWN;

	/* empties the icmp input queue */
	struct pollfd p = { .fd = rts->sock, .events = POLLIN | POLLHUP };
	while (ppoll(&p, 1, &mv.tout, NULL)) {
		socklen_t len = sizeof(struct sockaddr_in);
		if (recvfrom(rts->sock, mv.packet, sizeof(mv.packet),
				0, NULL, &len) < 0)
			return -1;
	}

	/*
	 * To measure the difference, select MSGS messages whose round-trip time is
	 * smaller than RANGE if ckrange is 1, otherwise simply select MSGS messages
	 * regardless of round-trip transmission time.  Choose the smallest transmission
	 * time in each of the two directions.  Use these two latter quantities to
	 * compute the delta between the two clocks.
	 */

	unsigned char opacket[64] = {0};
	struct icmphdr *oicp = (struct icmphdr *)opacket;

	oicp->type       = rts->ip_opt_len ? ICMP_ECHO : ICMP_TIMESTAMP;
	oicp->code       = 0;
	oicp->checksum   = 0;
	oicp->un.echo.id = rts->id;
	((uint32_t *)(oicp + 1))[0] = 0;
	((uint32_t *)(oicp + 1))[1] = 0;
	((uint32_t *)(oicp + 1))[2] = 0;

	rts->acked = rts->seqno = rts->seqno0 = 0;

	for (mv.msgcount = 0; mv.msgcount < MSGS;) {
		char escape = 0;

		/*
		 * If no answer is received for TRIALS consecutive times, the machine is
		 * assumed to be down
		 */
		if ((rts->seqno - rts->acked) > TRIALS) {
			errno = EHOSTDOWN;
			return -1;
		}

		oicp->un.echo.sequence = ++rts->seqno;
		oicp->checksum = 0;

		clock_gettime(CLOCK_REALTIME, &mv.ts1);
		*(uint32_t *) (oicp + 1) =
		    htonl((mv.ts1.tv_sec % (24 * 60 * 60)) * 1000 + mv.ts1.tv_nsec / 1000000);
		oicp->checksum = clockdiff_in_cksum((unsigned short *)oicp, sizeof(*oicp) + 12);

		if (sendto(rts->sock, opacket, sizeof(*oicp) + 12, 0,
		       (struct sockaddr *)&rts->server, sizeof(struct sockaddr_in)) < 0)
		{
			errno = EHOSTUNREACH;
			return -1;
		}

		while (!escape) {
			int ret = measure_inner_loop(rts, &mv);
			switch (ret) {
				case BREAK:
					escape = 1;
					break;
				case CONTINUE:
					continue;
				default:
					return ret;
			}
		}
	}
	rts->delta1 = (mv.min1 - mv.min2) / 2 + PROCESSING_TIME;
	return GOOD;
}

static void drop_rights(void) {
#ifdef HAVE_LIBCAP
	cap_t caps = cap_init();
	if (cap_set_proc(caps))
		err(errno, "cap_set_proc");
	cap_free(caps);
#endif
	if (setuid(getuid()))
		err(errno, "setuid");
}

NORETURN static void usage(int rc) {
	drop_rights();
	const char *options =
"                without -o, use icmp timestamp only\n"
"                (see RFC792, page 16)\n"
"  -o            use IP timestamp and icmp echo\n"
"  -o1           use three-term IP timestamp and icmp echo\n"
"  -T, --time-format <ctime|iso>\n"
"                specify display time format, ctime is the default\n"
"  -I            alias of --time-format=iso\n"
"  -h, --help    display this help\n"
"  -V, --version print version and exit\n"
;
	usage_common(rc, options, "HOST", !MORE);
}

static void parse_opts(state_t *rts, int argc, char **argv) {
	const struct option longopts[] = {
		{ "time-format", required_argument, NULL, 'T' },
		{ "version",     no_argument,       NULL, 'V' },
		{ "help",        no_argument,       NULL, 'h' },
		{ NULL,          0,                 NULL, 0   },
	};
	int ch;
	while ((ch = getopt_long(argc, argv, "o1T:IVh", longopts, NULL)) != -1)
		switch (ch) {
		case 'o':
			rts->ip_opt_len = 4 + 4 * 8;
			break;
		case '1':
			rts->ip_opt_len = 4 + 3 * 8;
			break;
		case 'T':
			if      (!strcmp(optarg, "iso"))
				rts->time_format = ts_format[0];
			else if (!strcmp(optarg, "ctime"))
				rts->time_format = ts_format[1];
			else
				errx(EXIT_FAILURE,
					"Invalid time-format argument: %s",
					optarg);
			break;
		case 'I':
			rts->time_format = ts_format[0];
			break;
		case 'V':
			version_n_exit(EXIT_SUCCESS, FEAT_CAP | FEAT_IDN | FEAT_NLS);
		case 'h':
			usage(EXIT_SUCCESS);
		default:
			usage(EXIT_FAILURE);
		}
}

int main(int argc, char **argv) {
	setmyname(argv[0]);
	SET_NLS;
	atexit(close_stdout);

	state_t rts = {.rtt = 1000, .time_format = ts_format[1]};
	parse_opts(&rts, argc, argv);
	argc -= optind;
	argv += optind;
	if (argc <= 0) {
		errno = EDESTADDRREQ;
		warn("%s", _("No goal"));
		usage(EDESTADDRREQ);
	} else if (argc != 1)
		usage(EINVAL);

	rts.sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (rts.sock < 0)
		err(errno, "socket(%s, %s)", "AF_INET", "SOCK_RAW");
	{ int inc = -16;
	  if (nice(inc) == -1)
		err(errno, "nice(%d)", inc);
	}

	drop_rights();

	if (isatty(fileno(stdin)) && isatty(fileno(stdout)))
		rts.interactive = true;

	rts.id = getpid();

	{ // resolv
	  const struct addrinfo hints = {
		.ai_family   = AF_INET,
		.ai_socktype = SOCK_RAW,
		.ai_flags    = AI_CANONNAME
	  };
	  struct addrinfo *res = NULL;
	  int rc = GAI_WRAPPER(argv[0], NULL, &hints, &res);
	  if (rc) {
		if (rc == EAI_SYSTEM)
			err(errno, "%s", "getaddrinfo()");
		errx(rc, "%s", gai_strerror(rc));
	  }
	  if (!res)
		errx(EXIT_FAILURE, "%s", "getaddrinfo()");
	  rts.host = strdup(res->ai_canonname);
	  memcpy(&rts.server, res->ai_addr, sizeof(rts.server));
	  freeaddrinfo(res);
	}

	if (connect(rts.sock, (struct sockaddr *)&rts.server, sizeof(rts.server)) < 0)
		err(errno, "%s", "connect()");
	if (rts.ip_opt_len) {
		struct sockaddr_in myaddr = { 0 };
		socklen_t addrlen = sizeof(myaddr);
		uint8_t *rspace = calloc(1, rts.ip_opt_len);
		if (!rspace)
			err(errno, "calloc(%d)", rts.ip_opt_len);
		rspace[0] = IPOPT_TIMESTAMP;
		rspace[1] = rts.ip_opt_len;
		rspace[2] = 5;
		rspace[3] = IPOPT_TS_PRESPEC;
		if (getsockname(rts.sock, (struct sockaddr *)&myaddr, &addrlen) < 0)
			err(errno, "getsockname");
		((uint32_t *) (rspace + 4))[0 * 2] = myaddr.sin_addr.s_addr;
		((uint32_t *) (rspace + 4))[1 * 2] = rts.server.sin_addr.s_addr;
		((uint32_t *) (rspace + 4))[2 * 2] = myaddr.sin_addr.s_addr;
		if (rts.ip_opt_len == (4 + 4 * 8)) {
			((uint32_t *) (rspace + 4))[2 * 2] = rts.server.sin_addr.s_addr;
			((uint32_t *) (rspace + 4))[3 * 2] = myaddr.sin_addr.s_addr;
		}

		if (setsockopt(rts.sock, IPPROTO_IP, IP_OPTIONS, rspace, rts.ip_opt_len) < 0) {
			warn("IP_OPTIONS (fallback to icmp tstamps)");
			rts.ip_opt_len = 0;
		}
		free(rspace);
	}

	{ const char *name = rts.host ? rts.host : "";
	  int status = measure(&rts);
	  if (status < 0) {
		if (errno)
			err(errno, "%s(%s)", _("measure"), name);
		errx(EXIT_FAILURE, "%s(%s): %s", _("measure"), name, _("Unknown failure"));
	  }
	  switch (status) {
	  case NONSTDTIME:
		errx(EXIT_FAILURE, "%s(%s): %s", _("measure"), name, _("Non-standard time format"));
		break;
	  }
	}

	{ time_t now = time(NULL);
	  if (rts.interactive) {
		struct tm tm = {0};
		localtime_r(&now, &tm);
		char ts[64];
		if (!strftime(ts, sizeof(ts), rts.time_format, &tm))
			ts[0] = 0;
		const char *ms = _("ms");
		putchar('\n');
		printf("%s=%s ", _("host"), rts.host);
		printf("%s=%ld(%ld)%s/%ld%s ", _("rtt"),
			rts.rtt, rts.sigma, ms, rts.min_rtt, ms);
		printf("%s=%d%s/%d%s ", _("delta"),
			rts.delta1, ms, rts.delta2, ms);
		printf("[%s]", ts);
	  } else
		printf("%ld %d %d", now, rts.delta1, rts.delta2);
	  putchar('\n');
	}
	exit(EXIT_SUCCESS);
}

