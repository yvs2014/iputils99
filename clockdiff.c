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

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
//
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <poll.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/timex.h>
#include <sys/types.h>
#include <time.h>
#include <err.h>
#include <errno.h>

#include "iputils.h"

#ifdef HAVE_LIBCAP
#include "caps.h"
#else
#include "perm.h"
#endif

#define TODAY_MSEC(tv) (((tv).tv_sec % DAY_IN_SEC) * 1000 + (tv).tv_nsec / 1000000)

typedef enum {
	DT_GOOD    =  0,
	DT_UNREACH =  2,
	DT_NONSTD  =  3,
	DT_BREAK   =  4,
	DT_CONT    =  5,
	DT_ERROR   = -1,
} timediff_e;

#define _OPTLEN(n) (4 + (n) * (sizeof(struct in_addr) * 2))
#define OPTLEN(n) (_OPTLEN(n) + 4)
enum {
	RANGE   =  1,         // the best expected RTT, in msec
	MSGS    = 50,
	TRIALS  = 10,
	//
	HOSTDOWN = INT32_MAX,
//	PROCESSING_TIME	= 0,  // to reduce error in measurement, in msec
	//
	DAY_IN_SEC  = 24 * 3600,
	DAY_IN_MSEC = DAY_IN_SEC * 1000,
	HALFDAY_BEFORE = -DAY_IN_MSEC / 2,     // in msec
	HALFDAY_AFTER  =  DAY_IN_MSEC / 2 - 1, // in msec
	//
	OPTLEN_2 = _OPTLEN(4),
	OPTLEN_3 = _OPTLEN(3),
};

typedef struct run_state {
	uint16_t id16;
	int sock;
	uint8_t optlen;
	int delta1;
	int delta2;
	uint16_t seqno;
	uint16_t seqno0;
	uint16_t acked;
	long rtt;
	long min_rtt;
	long sigma;
	const char *ts_format;
	bool interactive;
} state_t;

typedef struct measurement_data {
	struct timespec ts;
	struct timespec tout;
	int msgcount;
	long min1;
	long min2;
	struct iphdr   *ip;
	struct icmphdr *icmp;
	uint8_t packet[1024];
} measurement_data_t;

typedef struct delta_timing {
	long send, recv, peer1, peer2;
} delta_timing_t;

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

static inline timediff_e opt_measure(state_t *rts, measurement_data_t *m, delta_timing_t *dt) {
	uint8_t *opt = m->packet + sizeof(struct iphdr);
	{ // low 4bits
	  uint8_t low = opt[3] & 0xf;
	  if (low != IPOPT_TS_PRESPEC) {
		warnx("%s: %u", _("Wrong timestamp"), low);
		return DT_NONSTD;
	  }
	}
	{ // high 4bits
	  uint8_t high = opt[3] >> 4;
	  if (high && ((high != 1) || (rts->optlen != OPTLEN_3)))
		 warnx("%s: %u", _("Overflow hops"), high);
	}
	for (int i = 0; i < (opt[2] - 5) / 8; i++) {
		uint32_t *timep = (uint32_t *)(opt + OPTLEN(i));
		uint32_t t = ntohl(*timep);
		if (IS_BIT31_SET(t))
			return DT_NONSTD;
		switch (i) {
		case 0:
			dt->send = t;
			break;
		case 1:
			dt->peer1 = dt->peer2 = t;
			break;
		case 2:
			if (rts->optlen == OPTLEN_2)
				dt->peer2 = t;
			else
				dt->recv  = t;
			break;
		case 3:
			dt->recv = t;
			break;
		default: break;
		}
	}
	if (!(dt->send && dt->recv && dt->peer1 && dt->peer2)) {
		warnx("%s", _("Wrong timestamp"));
		return DT_ERROR;
	}
	return DT_GOOD;
}

static inline timediff_e measure_msg(state_t *rts, measurement_data_t *m) {
	{ long tmo = MAX(rts->rtt + rts->sigma, 1);
	  m->tout.tv_sec  = tmo / 1000;
	  m->tout.tv_nsec = (tmo - (tmo / 1000) * 1000) * 1000000; }

	{ struct pollfd p = { .fd = rts->sock, .events = POLLIN | POLLHUP };
	  if (ppoll(&p, 1, &m->tout, NULL) <= 0)
		return DT_BREAK; }
	{ if (clock_gettime(CLOCK_REALTIME, &m->ts) < 0)
		return DT_ERROR; }
	{ socklen_t len = SA4_LEN;
	  if (recvfrom(rts->sock, m->packet, sizeof(m->packet), 0, NULL, &len) < 0)
		return DT_ERROR; }

	m->icmp = (struct icmphdr *)(m->packet + (m->ip->ihl << 2));

#define REPLY_WITH_TS ((m->icmp->type == ICMP_TIMESTAMPREPLY) || \
  (rts->optlen && (m->icmp->type == ICMP_ECHOREPLY) && (m->packet[20] == IPOPT_TIMESTAMP)))
//
#define ICMP_ECHO_OKAY ((m->icmp->un.echo.id       == rts->id16  ) && \
                        (m->icmp->un.echo.sequence >= rts->seqno0) && \
	                (m->icmp->un.echo.sequence <= rts->seqno ))
	delta_timing_t dt = {0};
	if (REPLY_WITH_TS && ICMP_ECHO_OKAY) {
		if (rts->acked < m->icmp->un.echo.sequence)
			rts->acked = m->icmp->un.echo.sequence;
		if (rts->optlen) {
			timediff_e status = opt_measure(rts, m, &dt);
			if (status != DT_GOOD)
				return status;
		} else {
			dt.send = ntohl(*(uint32_t *)(m->icmp + 1));
			dt.recv = TODAY_MSEC(m->ts);
		}

		long diff = dt.recv - dt.send;
		if (diff < 0) // probably around midnight
			return DT_CONT;
		rts->rtt   = (rts->rtt   * 3 + diff)                  / 4;
		rts->sigma = (rts->sigma * 3 + labs(diff - rts->rtt)) / 4;
		m->msgcount++;
		if (!rts->optlen) {
			dt.peer1 = ntohl(((uint32_t *)(m->icmp + 1))[1]);
			/*
			 * a hosts using a time format different from ms.  since midnight
			 * UT (as per RFC792) should set the high order bit of the 32-bit
			 * time value it transmits.
			 */
			if (IS_BIT31_SET(dt.peer1))
				return DT_NONSTD;
		}
		if (rts->interactive) {
			printf(".");
			fflush(stdout);
		}

// Handles wrap-around to avoid that around midnight small time differences appear enormous.
// However, the two machine's clocks must be within 12 hours from each other.
#define SET_DELTA(delta, keep, value) long delta = (value);    \
	if      (delta < HALFDAY_BEFORE) delta += DAY_IN_MSEC; \
	else if (delta > HALFDAY_AFTER)  delta -= DAY_IN_MSEC; \
	if (delta < keep) keep = delta;
//
		SET_DELTA(delta1, m->min1, dt.peer1 - dt.send)
		SET_DELTA(delta2, m->min2, dt.recv - (rts->optlen ? dt.peer2 : dt.peer1))
//
		int rtt = delta1 + delta2;
		if (rtt < rts->min_rtt) {
			rts->min_rtt = rtt;
			rts->delta2  = (delta1 - delta2) / 2;
//			rts->delta2 += PROCESSING_TIME;
		}
		if (diff < RANGE) {
			m->min1 = delta1;
			m->min2 = delta2;
			return DT_BREAK;
		}
	}
	return DT_CONT;
}

// Measure the differences between machines' clocks using ICMP timestamp messages
static timediff_e measure(state_t *rts, const struct sockaddr_in *sa, socklen_t salen) {
	measurement_data_t m = {.min1 = LONG_MAX, .min2 = LONG_MAX};
	m.ip = (struct iphdr *)m.packet;

	rts->min_rtt = LONG_MAX;
	rts->delta1  = HOSTDOWN;
	rts->delta2  = HOSTDOWN;

	/* empties the icmp input queue */
	struct pollfd p = {.fd = rts->sock, .events = POLLIN | POLLHUP};
	while (ppoll(&p, 1, &m.tout, NULL)) {
		socklen_t len = SA4_LEN;
		if (recvfrom(rts->sock, m.packet, sizeof(m.packet), 0, NULL, &len) < 0)
			return DT_ERROR;
	}

	/*
	 * To measure the difference, select MSGS messages whose round-trip time is
	 * smaller than RANGE if ckrange is 1, otherwise simply select MSGS messages
	 * regardless of round-trip transmission time.  Choose the smallest transmission
	 * time in each of the two directions.  Use these two latter quantities to
	 * compute the delta between the two clocks.
	 */
	uint8_t opacket[64] = {0};
	struct icmphdr *icmp = (struct icmphdr *)opacket;
	icmp->type       = rts->optlen ? ICMP_ECHO : ICMP_TIMESTAMP;
	icmp->code       = 0;
	icmp->checksum   = 0;
	icmp->un.echo.id = rts->id16;
	((uint32_t *)(icmp + 1))[0] = 0;
	((uint32_t *)(icmp + 1))[1] = 0;
	((uint32_t *)(icmp + 1))[2] = 0;

	rts->acked = rts->seqno = rts->seqno0 = 0;
	for (m.msgcount = 0; m.msgcount < MSGS;) {
		// If no answer is received for TRIALS consecutive times,
		// the machine is assumed to be down
		if ((rts->seqno - rts->acked) > TRIALS) {
			errno = EHOSTDOWN;
			return DT_ERROR;
		}
		//
		icmp->un.echo.sequence = ++rts->seqno;
		icmp->checksum = 0;
		//
		clock_gettime(CLOCK_REALTIME, &m.ts);
		*(uint32_t *)(icmp + 1) = htonl(TODAY_MSEC(m.ts));
		icmp->checksum = clockdiff_in_cksum((unsigned short *)icmp, sizeof(*icmp) + 12);
		//
		if (sendto(rts->sock, opacket, sizeof(*icmp) + 12, 0, sa, salen) < 0) {
			errno = EHOSTUNREACH;
			return DT_ERROR;
		}
		//
		while (true) {
			timediff_e status = measure_msg(rts, &m); // with recvfrom()
			if (status == DT_BREAK) break;
			if (status != DT_CONT ) return status;
		}
	}
	rts->delta1  = (m.min1 - m.min2) / 2;
//	rts->delta1 += PROCESSING_TIME;
	return DT_GOOD;
}

NORETURN static void usage(int rc) {
	drop_priv();
	const char *options =
"      by default, ICMP timestamps are only used (see RFC792, page 16)\n"
"  -2  use IP timestamp and ICMP echo\n"
"  -3  use three-term IP timestamp and ICMP echo\n"
"\n"
"      by default, 'ctime' format is used\n"
"  -I  use ISO time format\n"
"\n"
"  -h  print help and exit\n"
"  -V  print version and exit\n"
;
	usage_common(rc, options, "HOST", !MORE);
}

static void parse_options(state_t *rts, int argc, char **argv) {
	int ch;
	while ((ch = getopt(argc, argv, "hIV23")) != EOF)
		switch (ch) {
		case '2':
		case '3': {
			bool both = (ch == '2');
			uint8_t incompat = both ? OPTLEN_3 : OPTLEN_2;
			if (rts->optlen == incompat)
				OPTEXCL('2', '3');
			rts->optlen = both ? OPTLEN_2 : OPTLEN_3;
			} break;
		case 'I':
			rts->ts_format = "%FT%T%z"; /*iso*/
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
#ifdef HAVE_LIBCAP
	// limit caps to net_raw|sys_nice
	{ cap_value_t caps[] = {CAP_NET_RAW, CAP_SYS_NICE};
	  limit_cap(caps, ARRAY_LEN(caps)); }
	NET_RAW_OFF;
	SYS_NICE_OFF;
#else
	keep_euid();
#endif

	setmyname(argv[0]);
	BIND_NLS;
	atexit(close_stdout);

	state_t rts = {.rtt = 1000, .ts_format = "%c" /*local*/};
	parse_options(&rts, argc, argv);
	argc -= optind;
	argv += optind;
	if (argc <= 0) {
		errno = EDESTADDRREQ;
		warn("%s", _("No goal"));
		usage(EDESTADDRREQ);
	} else if (argc != 1)
		usage(EINVAL);

	{
	  NET_RAW_ON;
	  rts.sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	  int keep = errno;
	  NET_RAW_OFF;
	  if (rts.sock < 0) {
		errno = keep;
		err(errno, "socket(%s, %s)", "AF_INET", "SOCK_RAW");
	  }
	}
	{ int inc = -16;
	  SYS_NICE_ON;
	  int rc = nice(inc);
	  int keep = errno;
	  SYS_NICE_OFF;
	  if (rc == -1) {
		errno = keep;
		err(errno, "nice(%d)", inc);
	  }
	}

	drop_priv();

	if (isatty(fileno(stdin)) && isatty(fileno(stdout)))
		rts.interactive = true;
	validate_hostlen(argv[0], true);

#ifdef HAVE_ARC4RANDOM_UNIFORM
	rts.id16 = arc4random_uniform(USHRT_MAX) + 1;
#else
	rts.id16 = htons(getpid() & USHRT_MAX);
#endif

#define PEERNAME (canonname ? canonname : target)
	const char *target = argv[0];
	char *canonname = NULL;

	struct sockaddr_in to = {0};
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
		errx(rc, TARGET_FMT ": %s", argv[0], gai_strerror(rc));
	  }
	  if (!res)
		errx(EXIT_FAILURE, "%s", "getaddrinfo()");
	  canonname = strdup(res->ai_canonname);
	  memcpy(&to, res->ai_addr, SA4_LEN);
	  freeaddrinfo(res);
	}
	if (connect(rts.sock, &to, SA4_LEN) < 0)
		err(errno, "%s", "connect()");
	if (rts.optlen) {
		struct sockaddr_in my = {0};
		uint8_t *rspace = calloc(1, rts.optlen);
		if (!rspace)
			err(errno, "calloc(%d)", rts.optlen);
		rspace[0] = IPOPT_TIMESTAMP;
		rspace[1] = rts.optlen;
		rspace[2] = 5;
		rspace[3] = IPOPT_TS_PRESPEC;
		{ socklen_t len = SA4_LEN;
		  if (getsockname(rts.sock, &my, &len) < 0)
			err(errno, "getsockname"); }
		((uint32_t *) (rspace + 4))[0 * 2] = my.sin_addr.s_addr;
		((uint32_t *) (rspace + 4))[1 * 2] = to.sin_addr.s_addr;
		((uint32_t *) (rspace + 4))[2 * 2] = my.sin_addr.s_addr;
		if (rts.optlen == OPTLEN_2) {
			((uint32_t *) (rspace + 4))[2 * 2] = to.sin_addr.s_addr;
			((uint32_t *) (rspace + 4))[3 * 2] = my.sin_addr.s_addr;
		}

		if (setsockopt(rts.sock, IPPROTO_IP, IP_OPTIONS, rspace, rts.optlen) < 0) {
			warn("IP_OPTIONS: fallback to ICMP timestamp");
			rts.optlen = 0;
		}
		free(rspace);
	}

	switch (measure(&rts, &to, SA4_LEN)) {
	case DT_ERROR:
		if (errno) err(errno, "%s(%s)", _("measure"), PEERNAME);
		errx(EXIT_FAILURE, "%s(%s): %s", _("measure"), PEERNAME, _("Unknown failure"));
	case DT_NONSTD:
		errx(EXIT_FAILURE, "%s(%s): %s", _("measure"), PEERNAME, _("Non-standard time format"));
	default: break;
	}

	{ time_t now = time(NULL);
	  if (rts.interactive) {
		struct tm tm = {0};
		localtime_r(&now, &tm);
		char ts[64];
		if (!strftime(ts, sizeof(ts), rts.ts_format, &tm))
			ts[0] = 0;
		const char *ms = _("ms");
		putchar('\n');
		printf("%s=%s ", _("host"), PEERNAME);
		printf("%s=%ld(%ld)%s/%ld%s ", _("rtt"),
			rts.rtt, rts.sigma, ms, rts.min_rtt, ms);
		printf("%s=%d%s/%d%s ", _("delta"),
			rts.delta1, ms, rts.delta2, ms);
		printf("[%s]", ts);
	  } else
		printf("%lld %d %d", (long long)now, rts.delta1, rts.delta2);
	  putchar('\n');
	}
	if (canonname)
		free(canonname);
	exit(EXIT_SUCCESS);
}

