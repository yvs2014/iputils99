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

#include "iputils_common.h"
#include "common.h"
#include "ping4.h"
#include "extra.h"

#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <ifaddrs.h>
#include <math.h>
#include <locale.h>

/* FIXME: global_rts will be removed in future */
struct ping_rts *global_rts;

#define V4IN6_WARNING "Embedded IPv4 Address"

#define CASE_TYPE(x) case x: return #x;

static char *str_family(int family)
{
	switch (family) {
		CASE_TYPE(AF_UNSPEC)
		CASE_TYPE(AF_INET)
		CASE_TYPE(AF_INET6)
	default:
		error(2, 0, _("unknown protocol family: %d"), family);
	}

	return "";
}

static char *str_socktype(int socktype)
{
	if (!socktype)
		return "0";

	switch (socktype) {
		CASE_TYPE(SOCK_DGRAM)
		CASE_TYPE(SOCK_RAW)
	default:
		error(2, 0, _("unknown sock type: %d"), socktype);
	}

	return "";
}

static void create_socket(struct ping_rts *rts, socket_st *sock, int family,
			  int socktype, int protocol, int requisite)
{
	int do_fallback = 0;

	errno = 0;

	assert(sock->fd == -1);
	assert(socktype == SOCK_DGRAM || socktype == SOCK_RAW);

	/* Attempt to create a ping socket if requested. Attempt to create a raw
	 * socket otherwise or as a fallback. Well known errno values follow.
	 *
	 * 1) EACCES
	 *
	 * Kernel returns EACCES for all ping socket creation attempts when the
	 * user isn't allowed to use ping socket. A range of group ids is
	 * configured using the `net.ipv4.ping_group_range` sysctl. Fallback
	 * to raw socket is necessary.
	 *
	 * Kernel returns EACCES for all raw socket creation attempts when the
	 * process doesn't have the `CAP_NET_RAW` capability.
	 *
	 * 2) EAFNOSUPPORT
	 *
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
	 *
	 * OpenVZ 2.6.32-042stab113.11 and possibly other older kernels return
	 * EPROTONOSUPPORT for all IPv6 ping socket creation attempts due to lack
	 * of support in the kernel [1]. Debian 9.5 based container with kernel 4.10
	 * returns EPROTONOSUPPORT also for IPv4 [2]. Fallback to raw socket is
	 * necessary.
	 *
	 * [1] https://github.com/iputils/iputils/issues/54
	 * [2] https://github.com/iputils/iputils/issues/129
	 */
	if (socktype == SOCK_DGRAM)
		sock->fd = socket(family, socktype, protocol);

	/* Kernel doesn't support ping sockets. */
	if (sock->fd == -1 && errno == EAFNOSUPPORT && family == AF_INET)
		do_fallback = 1;
	if (sock->fd == -1 && errno == EPROTONOSUPPORT)
		do_fallback = 1;

	/* User is not allowed to use ping sockets. */
	if (sock->fd == -1 && errno == EACCES)
		do_fallback = 1;

	if (socktype == SOCK_RAW || do_fallback) {
		socktype = SOCK_RAW;
		sock->fd = socket(family, SOCK_RAW, protocol);
	}

	sock->socktype = socktype;

	/* valid socket */
	if (sock->fd != -1)
		return;

	/* failed to create socket */

	if (requisite || rts->opt_verbose) {
		error(0, 0, "socktype: %s", str_socktype(socktype));
		error(0, errno, "socket");
	}

	if (requisite) {
		if (socktype == SOCK_RAW && geteuid() != 0)
			error(0, 0, _("=> missing cap_net_raw+p capability or setuid?"));

		exit(2);
	}
}

static void set_socket_option(socket_st *sock, int level, int optname,
			      const void *optval, socklen_t olen)
{
	if (sock->fd == -1)
		return;
	if (setsockopt(sock->fd, level, optname, optval, olen) == -1)
		error(2, errno, "setsockopt");
}

/* Much like strtod(3), but will fails if str is not valid number. */
static double ping_strtod(const char *str, const char *err_msg)
{
	double num;
	char *end = NULL;
	int strtod_errno = 0;

	if (str == NULL || *str == '\0')
		goto err;
	errno = 0;

	/*
	 * Here we always want to use locale regardless USE_IDN or ENABLE_NLS,
	 * because it handles decimal point of -i/-W input options.
	 */
	setlocale(LC_ALL, "C");
	num = strtod(str, &end);
	strtod_errno = errno;
	setlocale(LC_ALL, "");
	/* Ignore setlocale() errno (e.g. invalid locale in env). */
	errno = strtod_errno;

	if (errno || str == end || (end && *end)) {
		error(0, 0, _("option argument contains garbage: %s"), end);
		error(0, 0, _("this will become fatal error in the future"));
	}
	switch (fpclassify(num)) {
	case FP_NORMAL:
	case FP_ZERO:
		break;
	default:
		errno = ERANGE;
		goto err;
	}
	return num;
 err:
	error(2, errno, "%s: %s", err_msg, str);
	abort();	/* cannot be reached, above error() will exit */

	return 0.0;
}

static int parseflow(char *str)
{
	const char *cp;
	unsigned long val;
	char *ep;

	/* handle both hex and decimal values */
	if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
		cp = str + 2;
		val = (int)strtoul(cp, &ep, 16);
	} else {
		val = (int)strtoul(str, &ep, 10);
	}

	/* doesn't look like decimal or hex, eh? */
	if (*ep != '\0')
		error(2, 0, _("bad value for flowinfo: %s"), str);

	if (val & ~IPV6_FLOWINFO_FLOWLABEL)
		error(2, 0, _("flow value is greater than 20 bits: %s"), str);

	return (val);
}

/* Set Type of Service (TOS) and other Quality of Service relating bits */
static int parsetos(char *str)
{
	const char *cp;
	int tos;
	char *ep;

	/* handle both hex and decimal values */
	if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
		cp = str + 2;
		tos = (int)strtol(cp, &ep, 16);
	} else {
		tos = (int)strtol(str, &ep, 10);
	}

	/* doesn't look like decimal or hex, eh? */
	if (*ep != '\0')
		error(2, 0, _("bad TOS value: %s"), str);

	if (tos > UINT8_MAX)
		error(2, 0, _("the decimal value of TOS bits must be in range 0-255: %d"), tos);
	return (tos);
}

int main(int argc, char **argv) {
	struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_protocol = IPPROTO_UDP,
		.ai_socktype = SOCK_DGRAM,
		.ai_flags = AI_FLAGS,
	};
	struct addrinfo *result, *ai;
	int ret_val;
	int ch;
	socket_st sock4 = { .fd = -1 };
	socket_st sock6 = { .fd = -1 };
	char *target;
	char *outpack_fill = NULL;
	static struct ping_rts rts = {
		.interval = 1000,
		.preload = 1,
		.lingertime = MAXWAIT * 1000,
		.confirm_flag = MSG_CONFIRM,
		.tmin = LONG_MAX,
		.pipesize = -1,
		.datalen = DEFDATALEN,
		.ident = -1,
		.screen_width = INT_MAX,
#ifdef HAVE_LIBCAP
		.cap_raw = CAP_NET_RAW,
		.cap_admin = CAP_NET_ADMIN,
#endif
		.pmtudisc = -1,
		.source.sin_family = AF_INET,
		.source6.sin6_family = AF_INET6,
		.ni.query = -1,
		.ni.subject_type = -1,
	};
	/* FIXME: global_rts will be removed in future */
	global_rts = &rts;

	atexit(close_stdout);
	limit_capabilities(&rts);

#if defined(USE_IDN) || defined(ENABLE_NLS)
	setlocale(LC_ALL, "");
#if defined(USE_IDN) && defined(AI_CANONIDN)
	if (!strcmp(setlocale(LC_ALL, NULL), "C"))
		hints.ai_flags &= ~ AI_CANONIDN;
#endif
#ifdef ENABLE_NLS
	bindtextdomain (PACKAGE_NAME, LOCALEDIR);
	textdomain (PACKAGE_NAME);
#endif
#endif

	/* Support being called using `ping4` or `ping6` symlinks */
	if (argv[0][strlen(argv[0]) - 1] == '4')
		hints.ai_family = AF_INET;
	else if (argv[0][strlen(argv[0]) - 1] == '6')
		hints.ai_family = AF_INET6;

	/* Parse command line options */
	while ((ch = getopt(argc, argv, "h?" "4bRT:" "6F:N:" "aABc:CdDe:fHi:I:l:Lm:M:nOp:qQ:rs:S:t:UvVw:W:")) != EOF) {
		switch(ch) {
		/* IPv4 specific options */
		case '4':
			if (hints.ai_family == AF_INET6)
				error(2, 0, _("only one -4 or -6 option may be specified"));
			hints.ai_family = AF_INET;
			break;
		case 'b':
			rts.broadcast_pings = 1;
			break;
		case 'e':
			rts.ident = htons(strtoul_or_err(optarg, _("invalid argument"),
							 0, IDENTIFIER_MAX));
			break;
		case 'R':
			if (rts.opt_timestamp)
				error(2, 0, _("only one of -T or -R may be used"));
			rts.opt_rroute = 1;
			break;
		case 'T':
			if (rts.opt_rroute)
				error(2, 0, _("only one of -T or -R may be used"));
			rts.opt_timestamp = 1;
			if (strcmp(optarg, "tsonly") == 0)
				rts.ts_type = IPOPT_TS_TSONLY;
			else if (strcmp(optarg, "tsandaddr") == 0)
				rts.ts_type = IPOPT_TS_TSANDADDR;
			else if (strcmp(optarg, "tsprespec") == 0)
				rts.ts_type = IPOPT_TS_PRESPEC;
			else
				error(2, 0, _("invalid timestamp type: %s"), optarg);
			break;
		/* IPv6 specific options */
		case '6':
			if (hints.ai_family == AF_INET)
				error(2, 0, _("only one -4 or -6 option may be specified"));
			hints.ai_family = AF_INET6;
			break;
		case 'F':
			rts.flowlabel = parseflow(optarg);
			rts.opt_flowinfo = 1;
			break;
		case 'N':
			if (niquery_option_handler(&rts.ni, optarg) < 0)
				usage();
			hints.ai_socktype = SOCK_RAW;
			break;
		/* Common options */
		case 'a':
			rts.opt_audible = 1;
			break;
		case 'A':
			rts.opt_adaptive = 1;
			break;
		case 'B':
			rts.opt_strictsource = 1;
			break;
		case 'c':
			rts.npackets = strtol_or_err(optarg, _("invalid argument"), 1, LONG_MAX);
			break;
		case 'C':
			rts.opt_connect_sk = 1;
			break;
		case 'd':
			rts.opt_so_debug = 1;
			break;
		case 'D':
			rts.opt_ptimeofday = 1;
			break;
		case 'H':
			rts.opt_force_lookup = 1;
			break;
		case 'i':
		{
			double optval;

			optval = ping_strtod(optarg, _("bad timing interval"));
			if (isless(optval, 0) || isgreater(optval, (double)INT_MAX / 1000))
				error(2, 0, _("bad timing interval: %s"), optarg);
			rts.interval = (int)(optval * 1000);
			rts.opt_interval = 1;
		}
			break;
		case 'I':
			/* IPv6 */
			if (strchr(optarg, ':')) {
				char *p, *addr = strdup(optarg);

				if (!addr)
					error(2, errno, _("cannot copy: %s"), optarg);

				p = strchr(addr, SCOPE_DELIMITER);
				if (p) {
					*p = '\0';
					rts.device = optarg + (p - addr) + 1;
				}

				if (inet_pton(AF_INET6, addr, (char *)&rts.source6.sin6_addr) <= 0)
					error(2, 0, _("invalid source address: %s"), optarg);

				rts.opt_strictsource = 1;

				free(addr);
			} else if (inet_pton(AF_INET, optarg, &rts.source.sin_addr) > 0) {
				rts.opt_strictsource = 1;
			} else {
				rts.device = optarg;
			}
			break;
		case 'l':
			rts.preload = strtol_or_err(optarg, _("invalid argument"), 1, MAX_DUP_CHK);
			if (rts.uid && rts.preload > 3)
				error(2, 0, _("cannot set preload to value greater than 3: %d"), rts.preload);
			break;
		case 'L':
			rts.opt_noloop = 1;
			break;
		case 'm':
			rts.mark = strtoul_or_err(optarg, _("invalid argument"), 0, UINT_MAX);
			rts.opt_mark = 1;
			break;
		case 'M':
			if (strcmp(optarg, "do") == 0)
				rts.pmtudisc = IP_PMTUDISC_DO;
			else if (strcmp(optarg, "dont") == 0)
				rts.pmtudisc = IP_PMTUDISC_DONT;
			else if (strcmp(optarg, "want") == 0)
				rts.pmtudisc = IP_PMTUDISC_WANT;
			else if (strcmp(optarg, "probe") == 0)
				rts.pmtudisc = IP_PMTUDISC_PROBE;
			else
				error(2, 0, _("invalid -M argument: %s"), optarg);
			break;
		case 'n':
			rts.opt_numeric = 1;
			rts.opt_force_lookup = 0;
			break;
		case 'O':
			rts.opt_outstanding = 1;
			break;
		case 'f':
			rts.opt_flood = 1;
			/* avoid `getaddrinfo()` during flood */
			rts.opt_numeric = 1;
			setvbuf(stdout, NULL, _IONBF, 0);
			break;
		case 'p':
			rts.opt_pingfilled = 1;
			free(outpack_fill);
			outpack_fill = strdup(optarg);
			if (!outpack_fill)
				error(2, errno, _("memory allocation failed"));
			break;
		case 'q':
			rts.opt_quiet = 1;
			break;
		case 'Q':
			rts.settos = parsetos(optarg); /* IPv4 */
			rts.tclass = rts.settos; /* IPv6 */
			break;
		case 'r':
			rts.opt_so_dontroute = 1;
			break;
		case 's':
			rts.datalen = strtol_or_err(optarg, _("invalid argument"), 0, INT_MAX);
			break;
		case 'S':
			rts.sndbuf = strtol_or_err(optarg, _("invalid argument"), 1, INT_MAX);
			break;
		case 't':
			rts.ttl = strtol_or_err(optarg, _("invalid argument"), 0, 255);
			rts.opt_ttl = 1;
			break;
		case 'U':
			rts.opt_latency = 1;
			break;
		case 'v':
			rts.opt_verbose = 1;
			break;
		case 'V':
			printf(IPUTILS_VERSION("ping"));
			print_config();
			exit(0);
		case 'w':
			rts.deadline = strtol_or_err(optarg, _("invalid argument"), 0, INT_MAX);
			break;
		case 'W':
		{
			double optval;

			optval = ping_strtod(optarg, _("bad linger time"));
			if (isless(optval, 0) || isgreater(optval, (double)INT_MAX / 1000))
				error(2, 0, _("bad linger time: %s"), optarg);
			/* lingertime will be converted to usec later */
			rts.lingertime = (int)(optval * 1000);
		}
			break;
		default:
			usage();
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (!argc)
		error(1, EDESTADDRREQ, "usage error");

	target = argv[argc - 1];

	rts.outpack = malloc(rts.datalen + 28);
	if (!rts.outpack)
		error(2, errno, _("memory allocation failed"));
	if (outpack_fill) {
		fill_packet(&rts, outpack_fill, rts.outpack, rts.datalen);
		free(outpack_fill);
	}

	/* Current Linux kernel 6.0 doesn't support on SOCK_DGRAM setting ident == 0 */
	if (!rts.ident) {
		if (rts.opt_verbose)
			error(0, 0, _("WARNING: ident 0 => forcing raw socket"));
		hints.ai_socktype = SOCK_RAW;
	}

	/* Create sockets */
	ENABLE_CAPABILITY_RAW;
	if (hints.ai_family != AF_INET6) {
		create_socket(&rts, &sock4, AF_INET, hints.ai_socktype, IPPROTO_ICMP,
			      hints.ai_family == AF_INET);
	}
	if (hints.ai_family != AF_INET) {
		create_socket(&rts, &sock6, AF_INET6, hints.ai_socktype, IPPROTO_ICMPV6, sock4.fd == -1);
		/* This may not be needed if both protocol versions always had the same value,
		 * but since I don't know that, it's better to be safe than sorry */
		rts.pmtudisc = rts.pmtudisc == IP_PMTUDISC_DO	? IPV6_PMTUDISC_DO   :
			       rts.pmtudisc == IP_PMTUDISC_DONT ? IPV6_PMTUDISC_DONT :
			       rts.pmtudisc == IP_PMTUDISC_WANT ? IPV6_PMTUDISC_WANT :
			       rts.pmtudisc == IP_PMTUDISC_PROBE? IPV6_PMTUDISC_PROBE: rts.pmtudisc;
	}
	DISABLE_CAPABILITY_RAW;

	/* Limit address family on single-protocol systems */
	if (hints.ai_family == AF_UNSPEC) {
		if (sock4.fd == -1)
			hints.ai_family = AF_INET6;
		else if (sock6.fd == -1)
			hints.ai_family = AF_INET;
	}

	if (rts.opt_verbose)
		error(0, 0, "sock4.fd: %d (socktype: %s), sock6.fd: %d (socktype: %s),"
			   " hints.ai_family: %s\n",
			   sock4.fd, str_socktype(sock4.socktype),
			   sock6.fd, str_socktype(sock6.socktype),
			   str_family(hints.ai_family));

	/* Set socket options */
	if (rts.settos)
		set_socket_option(&sock4, IPPROTO_IP, IP_TOS, &rts.settos, sizeof(rts.settos));
	if (rts.tclass)
		set_socket_option(&sock6, IPPROTO_IPV6, IPV6_TCLASS, &rts.tclass, sizeof(rts.tclass));

	unsigned char buf[sizeof(struct in6_addr)];
	if (!strchr(target, '%') && sock6.socktype == SOCK_DGRAM &&
		inet_pton(AF_INET6, target, buf) > 0 &&
		(IN6_IS_ADDR_LINKLOCAL(buf) || IN6_IS_ADDR_MC_LINKLOCAL(buf))) {
			error(0, 0, _(
				"Warning: IPv6 link-local address on ICMP datagram socket may require ifname or scope-id"
				" => use: address%%<ifname|scope-id>"));
	}

	ret_val = getaddrinfo(target, NULL, &hints, &result);
	if (ret_val)
		error(2, 0, "%s: %s", target, gai_strerror(ret_val));

	for (ai = result; ai; ai = ai->ai_next) {
		if (rts.opt_verbose)
			printf("ai->ai_family: %s, ai->ai_canonname: '%s'\n",
				   str_family(ai->ai_family),
				   ai->ai_canonname ? ai->ai_canonname : "");
		if ((ai->ai_family == AF_INET6) &&
		    IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr))
			switch (hints.ai_family) {
			case AF_INET6:
				error(1, ENETUNREACH, _(V4IN6_WARNING));
				break;
			case AF_UNSPEC:
				unmap_ai_sa4(ai);
				error(0, 0, _("Warning: " V4IN6_WARNING));
				break;
			default: break;
			}

		switch (ai->ai_family) {
		case AF_INET:
			ret_val = ping4_run(&rts, argc, argv, ai, &sock4);
			break;
		case AF_INET6: {
			int done = 0;
			struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)ai->ai_addr;
			if (sa6 && IN6_IS_ADDR_LINKLOCAL(&sa6->sin6_addr) && !sa6->sin6_scope_id) {
				// getaddrinfo() workaround
				ret_val = ping6_unspec(target, &sa6->sin6_addr, &hints, &rts, argc, argv, &sock6);
				if (ret_val >= 0)
					done = 1;
			}
			if (!done)
				ret_val = ping6_run(&rts, argc, argv, ai, &sock6);
			} break;
		default:
			error(2, 0, _("unknown protocol family: %d"), ai->ai_family);
		}

		if (ret_val >= 0)
			break;
		/* ret_val < 0 means to go on to next addrinfo result, there
		 * better be one. */
		assert(ai->ai_next);
	}

	freeaddrinfo(result);
	free(rts.outpack);
	return ret_val;
}

