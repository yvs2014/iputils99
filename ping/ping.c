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
/*
 *			P I N G . C
 *
 * Using the InterNet Control Message Protocol (ICMP) "ECHO" facility,
 * measure round-trip-delays and packet loss across network paths.
 *
 * Author -
 *	Mike Muuss
 *	U. S. Army Ballistic Research Laboratory
 *	December, 1983
 *
 * Status -
 *	Public Domain.  Distribution Unlimited.
 * Bugs -
 *	More statistics could always be gathered.
 *	If kernel does not support ICMP datagram sockets,
 *	this program has to run SUID to ROOT or with
 *	net_cap_raw enabled.
 */

// local changes by yvs@

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <assert.h>
#include <errno.h>
#include <err.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <linux/in6.h>

#include "iputils.h"
#include "str2num.h"
#include "common.h"
#include "setsock.h"
#include "ping4.h"
#include "ping6.h"
#include "extra.h"
#ifdef HAVE_LIBCAP
#include "caps.h"
#else
#include "perm.h"
#endif
#ifdef ENABLE_RFC4620
#include "node_info.h"
#endif

#ifndef MSG_CONFIRM
/* defined via netinet/in.h */
#define MSG_CONFIRM 0
#endif

#define PACKHDRLEN	(sizeof(struct icmphdr) + sizeof(struct timeval))
#define	DEFDATALEN	(DEFIPPAYLOAD - sizeof(struct icmphdr))	// default data length
#define MAXPAYLOAD	(USHRT_MAX - PACKHDRLEN)		// largest payload
#define V4IN6_WARNING	"Embedded IPv4 Address"
#define PINGTYPE(raw)	((raw) ? "raw" : "datagram")

#define AFTYPE(af)	(af == AF_UNSPEC ? "unspec" : \
			 af == AF_INET   ? "ip4"    : \
			 af == AF_INET6  ? "ip6"    : "")
#define PING_FEATURES (FEAT_CAP | FEAT_IDN | FEAT_NLS | FEAT_ALTNAME | FEAT_RFC4620)

/* This may not be needed if both protocol versions always had the same value,
 * but since I don't know that, it's better to be safe than sorry */
#define MTUDISC6(disc6)	{ \
	(disc6) = (disc6) == IP_PMTUDISC_DO    ? IPV6_PMTUDISC_DO   : \
		  (disc6) == IP_PMTUDISC_DONT  ? IPV6_PMTUDISC_DONT : \
		  (disc6) == IP_PMTUDISC_WANT  ? IPV6_PMTUDISC_WANT : \
		  (disc6) == IP_PMTUDISC_PROBE ? IPV6_PMTUDISC_PROBE: \
		  (disc6); }

typedef int (*run_fn)(state_t *rts, int argc, char **argv,
        struct addrinfo *ai, const sock_t *sock);

static void open_socket(sock_t *sock, int af, int proto, bool verbose) {
	assert((af == AF_INET) || (af == AF_INET6));
	/* Attempt to create a ping socket if requested. Attempt to create a raw
	 * socket otherwise or as a fallback. Well known errno values follow.
	 *
	 * 1) EACCES
	 * Kernel returns EACCES for all ping socket creation attempts when the
	 * user isn't allowed to use ping socket. A range of group ids is
	 * configured using the `net.ipv4.ping_group_range` sysctl. Fallback
	 * to raw socket is necessary.
	 *
	 * Kernel returns EACCES for all raw socket creation attempts when the
	 * process doesn't have the `CAP_NET_RAW` capability.
	 *
	 * 2) EAFNOSUPPORT
	 * Kernel returns EAFNOSUPPORT for IPv6 ping or raw socket creation
	 * attempts when run with IPv6 support disabled (e.g. via `ipv6.disable=1`
	 * kernel command-line option.
	 *
	 * https://github.com/iputils/iputils/issues/32
	 *
	 * OpenVZ 2.6.32-042stab113.11 and possibly other older kernels return
	 * EAFNOSUPPORT for all IPv4 ping socket creation attempts due to lack
	 * of support in the kernel. Fallback to raw socket is necessary.
	 *
	 * https://github.com/iputils/iputils/issues/54
	 *
	 * 3) EPROTONOSUPPORT
	 * OpenVZ 2.6.32-042stab113.11 and possibly other older kernels return
	 * EPROTONOSUPPORT for all IPv6 ping socket creation attempts due to lack
	 * of support in the kernel [1]. Debian 9.5 based container with kernel 4.10
	 * returns EPROTONOSUPPORT also for IPv4 [2]. Fallback to raw socket is
	 * necessary.
	 *
	 * [1] https://github.com/iputils/iputils/issues/54
	 * [2] https://github.com/iputils/iputils/issues/129
	 */
	errno = 0;
	int num = 0;
	if (!sock->raw) {
		sock->fd = socket(af, SOCK_DGRAM, proto);
		num = errno;
	}
	if (sock->fd < 0) { // kernel doesn't support ping sockets
		switch (errno) {
		case EAFNOSUPPORT:
			sock->raw = (af == AF_INET);
			break;
		case EPROTONOSUPPORT:
		case EACCES: // EACCES: not allowed to use ping sockets
			sock->raw = true;
			break;
		default: break;
		}
	}
	errno = 0; // cleanup errno
	if (sock->raw) {
		NET_RAW_ON;
		sock->fd = socket(af, SOCK_RAW, proto);
		num = errno;
		NET_RAW_OFF;
	}
	if (verbose)
		warnx("%s %s socket", PINGTYPE(sock->raw), AFTYPE(af));
	errno = 0; // cleanup errno
	if (sock->fd >= 0)
		return;
	// failed
	if (sock->raw && geteuid()) {
		errno = num;
		if (errno)
			warn("%s: %s", _("=> missing capability"), "cap_net_raw+p");
		else
			warnx("%s: %s", _("=> missing capability"), "cap_net_raw+p");
	}
	errno = num;
	if (errno)
		err(errno, "%s", __func__);
	else
		errx(EXIT_FAILURE, "%s", __func__);
}

static inline void opt_I(state_t *rts, const char *str) {
	if (strchr(str, ':')) {
		char *addr = strdup(str);
		if (!addr)
			err(errno, "%s: %s", _("Cannot copy"), str);
		char *scope = strchr(addr, SCOPE_DELIMITER);
		if (scope) {
			*scope++ = 0;
			rts->device = str + (scope - addr);
		}
		if (inet_pton(AF_INET6, addr, &SA6_IN(&rts->source)) <= 0)
			errx(EINVAL, "%s: %s", _("Invalid source address"), str);
		rts->opt.strictsource = true;
		free(addr);
	} else {
		int rc = inet_pton(AF_INET, str, &SA4_IN(&rts->source));
		if (rc < 0)
			errx(EINVAL, "%s: %s", _("Invalid source"), str);
		if (rc)
			rts->opt.strictsource = true;
		else
			rts->device = str;
	}
}

#ifdef ENABLE_RFC4620
static inline void opt_N(state_t *rts, const char *str, struct addrinfo *hints) {
	if (rts->datalen != DEFDATALEN) // '-s' indication
		errx(EINVAL, "%s: %s", _WARN,
			_("NodeInfo packet can only have a header"));
	if (hints->ai_family == AF_INET) // '-4' indiacation
		errx(EINVAL, "%s: %s", _WARN,
			_("NodeInfo client is for IPv6 only"));
	if (!rts->ni) {
		rts->ni = calloc(1, sizeof(struct ping_ni));
		if (!rts->ni)
			err(errno, "calloc(%zu)", sizeof(struct ping_ni));
		rts->ni->query        = -1;
		rts->ni->subject_type = -1;
		if (niquery_option_handler(rts->ni, str) < 0)
			errx(EINVAL, "%s: %s",
				_("Cannot set NodeInfo option"), str);
		hints->ai_socktype = SOCK_RAW;
		rts->datalen = 0;
	}
}
#endif

static inline void opt_s(state_t *rts) {
#ifdef ENABLE_RFC4620
	if (rts->ni)
		errx(EXIT_FAILURE, "%s: %s", _WARN,
			_("NodeInfo packet can only have a header"));
#endif
	uint len = VALID_INTSTR(0, MAXPAYLOAD);
	uint8_t *pack = calloc(1, PACKHDRLEN + len);
	if (!pack)
		err(errno, "calloc(%zu)", PACKHDRLEN + len);
	if (rts->outpack)
		free(rts->outpack);
	rts->outpack = pack;
	rts->datalen = len;
}

static char *optstr =
	"aAbBc:CdDe:fF:hHi:I:l:L"
#ifdef SO_MARK
	"m:"
#endif
	"M:n"
#ifdef ENABLE_RFC4620
	"N:"
#endif
	"Op:qQ:rRs:S:t:T:UvVw:W:46";

static void switch_opt(char c, void *data) { // NONNULL(1, 2)
#define RTS_DATA ((state_t *)data)
#define RTS_HINT ((struct addrinfo *)(RTS_DATA->auxdata))
	switch (c) {
	case '4':
	case '6': if (RTS_HINT) {
		bool ip4 = (c == '4');
#ifdef ENABLE_RFC4620
		if (RTS_DATA->ni && ip4) // '-N' indication
			errx(EINVAL, "%s: %s", _WARN,
				_("NodeInfo client is for IPv6 only"));
#endif
		int incompat = ip4 ? AF_INET6 : AF_INET;
		if (RTS_HINT->ai_family == incompat)
			OPTEXCL('4', '6');
		RTS_HINT->ai_family = ip4 ? AF_INET : AF_INET6;
	}	break;
	case 'a':
	// 'a' -> audible, 'aa' -> colored, 'aaa' -> audible and colored
		if (RTS_DATA->opt.audible) {
			if (!RTS_DATA->red) {
				RTS_DATA->red    = RED_COLOR;
				RTS_DATA->yellow = YELLOW_COLOR;
				RTS_DATA->opt.audible = false;
			}
		} else
			RTS_DATA->opt.audible = true;
		break;
	case 'A':
		RTS_DATA->opt.adaptive = true;
		break;
	case 'b':
		RTS_DATA->opt.broadcast = true;
		break;
	case 'B':
		RTS_DATA->opt.strictsource = true;
		break;
	case 'c':
		RTS_DATA->npackets = VALID_INTSTR(1, LONG_MAX);
		break;
	case 'C':
		RTS_DATA->opt.connect_sk = true;
		break;
	case 'd':
		RTS_DATA->opt.so_debug = true;
		break;
	case 'D':
		RTS_DATA->opt.ptimeofday = true;
		break;
	case 'e':
		RTS_DATA->ident16   = htons(VALID_INTSTR(0, USHRT_MAX));
		RTS_DATA->opt.ident = true;
		break;
	case 'f':
		RTS_DATA->opt.flood   = true;
		RTS_DATA->opt.resolve = false;         // disable resolve
		setvbuf(stdout, NULL, _IONBF, 0); // turn off buffers
		break;
	case 'F':
		RTS_DATA->flow = VALID_INTSTR(0, IPV6_FLOWINFO_FLOWLABEL);
		break;
	case 'H':
		if (RTS_DATA->opt.flood)
			OPTEXCL('f', 'H');
		RTS_DATA->opt.resolve = true;
		break;
	case 'i': {
		double value = str2dbl(optarg, 0, (double)INT_MAX / 1000,
			_("Bad timing interval"));
		RTS_DATA->interval = (int)(value * 1000);
		RTS_DATA->opt.interval = true;
	}	break;
	case 'I':
		opt_I(RTS_DATA, optarg);
		break;
	case 'l':
		RTS_DATA->preload = VALID_INTSTR(1, MAX_DUP_CHK);
		if (RTS_DATA->uid && (RTS_DATA->preload > 3))
			errx(EINVAL, "%s: %d",
_("Cannot set preload to value greater than 3"), RTS_DATA->preload);
		break;
	case 'L':
		RTS_DATA->opt.noloop = true;
		break;
#ifdef SO_MARK
	case 'm':
		RTS_DATA->mark = VALID_INTSTR(0, UINT_MAX);
		break;
#endif
	case 'M':
		if (strcmp(optarg, "do") == 0)
			RTS_DATA->mtudisc = IP_PMTUDISC_DO;
		else if (strcmp(optarg, "dont") == 0)
			RTS_DATA->mtudisc = IP_PMTUDISC_DONT;
		else if (strcmp(optarg, "want") == 0)
			RTS_DATA->mtudisc = IP_PMTUDISC_WANT;
		else if (strcmp(optarg, "probe") == 0)
			RTS_DATA->mtudisc = IP_PMTUDISC_PROBE;
		else {
			errno = EINVAL;
			err(errno, "-%c %s", c, optarg);
		}
		break;
	case 'n':
		RTS_DATA->opt.resolve = false;
		break;
#ifdef ENABLE_RFC4620
	case 'N':
		if (RTS_HINT)
			opt_N(RTS_DATA, optarg, RTS_HINT);
		break;
#endif
	case 'O':
		RTS_DATA->opt.outstanding = true;
		break;
	case 'p':
		if (RTS_DATA->outpack && (RTS_DATA->datalen > 0) && optarg) {
			uint8_t *data_offset = RTS_DATA->outpack + sizeof(struct icmphdr);
			if (RTS_DATA->datalen > sizeof(struct timeval))
				data_offset += sizeof(struct timeval);
			fill_payload(RTS_DATA->opt.quiet, optarg,
				data_offset, RTS_DATA->datalen);
			RTS_DATA->opt.pingfilled = true;
		}
		break;
	case 'q':
		RTS_DATA->opt.quiet = true;
		break;
	case 'Q':
		RTS_DATA->tos = VALID_INTSTR(0, UINT8_MAX);
		break;
	case 'r':
		RTS_DATA->opt.so_dontroute = true;
		break;
	case 'R':
		if (RTS_DATA->ts_opt >= 0)
			OPTEXCL('T', 'R');
		RTS_DATA->opt.rroute = true;
		break;
	case 's':
		opt_s(RTS_DATA);
		break;
	case 'S':
		RTS_DATA->sndbuf = VALID_INTSTR(1, INT_MAX);
		break;
	case 't':
		RTS_DATA->ttl = VALID_INTSTR(0, UCHAR_MAX);
		break;
	case 'T':
#define TSSTREQ(lit) (!strncasecmp(optarg, lit, sizeof(lit)))
		if (RTS_DATA->opt.rroute)
			OPTEXCL('R', 'T');
		if      TSSTREQ("tsonly")
			RTS_DATA->ts_opt = IPOPT_TS_TSONLY;
		else if TSSTREQ("tsandaddr")
			RTS_DATA->ts_opt = IPOPT_TS_TSANDADDR;
		else if (TSSTREQ("tsprespec") || TSSTREQ("prespec"))
			RTS_DATA->ts_opt = IPOPT_TS_PRESPEC;
		else { // 0(TSONLY) 1(TSANDADDR) 3(PRESPEC)
			RTS_DATA->ts_opt = str2ll(optarg, 0, 3, _("Invalid timestamp type"));
			if (RTS_DATA->ts_opt == 2) // 2: reserved
				errx(EINVAL, "%s: %s", _("Invalid timestamp type"), optarg);
		}
#undef TSSTREQ
		break;
	case 'U':
		RTS_DATA->opt.latency = true;
		break;
	case 'v':
		RTS_DATA->opt.verbose = true;
		break;
	case 'w':
		RTS_DATA->deadline = VALID_INTSTR(0, INT_MAX);
		break;
	case 'W': {
		double value = str2dbl(optarg, 0, (double)INT_MAX / 1000,
			_("Bad linger time"));
		/* lingertime will be converted to usec later */
		RTS_DATA->lingertime = (int)(value * 1000);
	}	break;
	}
#undef RTS_DATA
#undef RTS_HINT
}

int main(int argc, char **argv) {
	run_fn ping_run[2] = { ping4_run, ping6_run };
	//
	state_t rts = {
		.datalen      = DEFDATALEN,
		.interval     = 1000,		/* in ms */
		.preload      =  1,
		.lingertime   = MAXWAIT * 1000,	/* in ms */
		.confirm_flag = MSG_CONFIRM,
		.mtudisc      = -1,
		.mark         = -1,
		.flow         = -1,
		.ttl          = -1,
		.min_away     = -1,
		.max_away     = -1,
		.tmin         = LONG_MAX,
		.pipesize     = -1,
		.ts_opt       = -1,
		.screen_width = USHRT_MAX,
		.opt.resolve  = true,
	};

#ifdef HAVE_LIBCAP
	// limit capabilities
	limit_caps((cap_value_t[]){CAP_NET_RAW, CAP_NET_ADMIN, -1});
	NET_RAW_OFF;
	NET_ADMIN_OFF;
#else
	keep_euid();
#endif
	rts.uid = getuid();

	setmyname(argv[0]);
	BIND_NLS;
	atexit(close_stdout);

	rts.outpack = calloc(1, PACKHDRLEN + rts.datalen);
	if (!rts.outpack)
		err(errno, "calloc(%zu)", PACKHDRLEN + rts.datalen);

	struct addrinfo hints = {
		.ai_family   = AF_UNSPEC,
		.ai_socktype = SOCK_DGRAM,
		.ai_flags    = AI_FLAGS,
	};
	rts.auxdata = &hints;

	/* Support being called using `ping4` or `ping6` symlinks */
	if (argv[0][strlen(argv[0]) - 1] == '4')
		hints.ai_family = AF_INET;
	else if (argv[0][strlen(argv[0]) - 1] == '6')
		hints.ai_family = AF_INET6;

	common_getopt(argc, argv, optstr, PING_FEATURES, usage, switch_opt, &rts);
	argc -= optind;
	argv += optind;
	if (argc <= 0) {
		errno = EDESTADDRREQ;
		warn("%s", _("No goal"));
		usage(EDESTADDRREQ);
	}
	const char *target = argv[argc - 1];
	validate_hostlen(target, true);

	if (!rts.opt.ident) {
#ifdef HAVE_ARC4RANDOM_UNIFORM
		rts.ident16 = arc4random_uniform(USHRT_MAX) + 1;
#else
		rts.ident16 = htons(getpid() & USHRT_MAX);
#endif
	} else if (!rts.ident16) {
		/* Current Linux kernel 6.0 doesn't support on SOCK_DGRAM setting ident == 0 */
		if (rts.opt.verbose)
			warnx("%s", _("ident 0 => forcing raw socket"));
		hints.ai_socktype = SOCK_RAW;
	}

	struct addrinfo *res = NULL;
	int rcode = GAI_WRAPPER(target, NULL, &hints, &res);
	if (rcode) {
		if (rcode == EAI_SYSTEM)
			err(errno, "%s", "getaddrinfo()");
		errx(rcode, TARGET_FMT ": %s", target, gai_strerror(rcode));
	}

	for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
		if (rts.opt.verbose) {
			if (ai->ai_canonname)
				warnx("ai_family %s, ai_canonname %s",
					AFTYPE(ai->ai_family), ai->ai_canonname);
			else
				warnx("ai_family %s", AFTYPE(ai->ai_family));
		}

		// ip4-in-ip6-space workaround
		if ((ai->ai_family == AF_INET6) &&
		    IN6_IS_ADDR_V4MAPPED(&SA6_IN(ai->ai_addr)))
			switch (hints.ai_family) {
			case AF_INET6:
				errno = ENETUNREACH;
				err(errno, _(V4IN6_WARN));
				break;
			case AF_UNSPEC:
				unmap_ai_sa4(ai);
				warnx("%s: %s", WARN, _(V4IN6_WARN));
				break;
			default: break;
			}

		switch (ai->ai_family) {
		case AF_INET:
		case AF_INET6: {
			rts.ip6 = (ai->ai_family == AF_INET6);
			if (rts.ip6) { // linklocal scopeid workaround
				if (IN6_IS_ADDR_LINKLOCAL(&SA6_IN(ai->ai_addr)) &&
				    !SA6(ai->ai_addr)->sin6_scope_id)
					ping6_unspec(target, &SA6_IN(ai->ai_addr), &hints);
			}
			sock_t sock = {.fd = -1, .raw = (hints.ai_socktype == SOCK_RAW)};
			open_socket(&sock, rts.ip6 ? AF_INET6 : AF_INET,
				rts.ip6 ? IPPROTO_ICMPV6 : IPPROTO_ICMP, rts.opt.verbose);
			if (rts.ip6) // be sure in pathmtu disc6 constants
				MTUDISC6(rts.mtudisc);
			if (sock.fd >= 0) {
				if (rts.tos)
					setsock_tos(sock.fd, rts.tos, rts.ip6);
				rcode = ping_run[rts.ip6](&rts, argc, argv, ai, &sock);
				close(sock.fd);
			}
		} break;
		default:
			errno = EAFNOSUPPORT;
			err(errno, "%d", ai->ai_family);
		}

		if (rcode >= 0)
			break;
		/* rcode < 0 means next, there better be that next */
		assert(ai->ai_next);
	}

	if (res)
		freeaddrinfo(res);
	if (rts.outpack)
		free(rts.outpack);
#ifdef ENABLE_RFC4620
	if (rts.ni)
		free(rts.ni);
#endif
	return rcode;
}

