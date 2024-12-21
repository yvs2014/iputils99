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
// ping.c auxiliary functions

#include "iputils_common.h"
#include "common.h"
#include "ping_aux.h"
#include "ping4_aux.h"
#include "ping6_aux.h"

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <math.h>
#include <locale.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <linux/in6.h>
#include <linux/errqueue.h>

unsigned long strtoul_or_err(const char *str, const char *errmesg,
	unsigned long min, unsigned long max)
{
	errno = (str && *str) ? 0 : EINVAL;
	if (!errno) {
		char *end = NULL;
		unsigned long num = strtoul(str, &end, 10);
		if (!(errno || (str == end) || (end && *end))) {
			if ((min <= num) && (num <= max))
				return num;
			error(ERANGE, 0, _("%s: '%s': out of range %lu-%lu"),
			      errmesg, str, min, max);
		}
	}
	error(errno, errno, "%s: '%s'", errmesg, str);
	_exit(errno ? errno : EXIT_FAILURE);
}

double strtod_or_err(const char *str, const char *errmesg,
	double min, double max)
{
	errno = (str && *str) ? 0 : EINVAL;
	if (!errno) {
		/*
		 * Here we always want to use locale regardless USE_IDN or ENABLE_NLS,
		 * because it handles decimal point of -i/-W input options
		 */
		char *end = NULL;
		setlocale(LC_ALL, "C");
		double num = strtod(str, &end);
		int keep = errno;
		setlocale(LC_ALL, "");
		errno = keep;
		if (!(errno || (str == end) || (end && *end))) {
			if (isgreaterequal(num, min) && islessequal(num, max))
				return num;
			error(ERANGE, 0, _("%s: '%s': out of range %g - %g"),
			      errmesg, str, min, max);
		}
	}
	error(errno, errno, "%s: %s", errmesg, str);
	_exit(errno ? errno : EXIT_FAILURE);
}

#define DX_SHIFT(str) (((str)[0] == '0') && (((str)[1] == 'x') || ((str)[1] == 'X')) ? 2 : 0)
unsigned parse_flow(const char *str) {
	/* handle both hex and decimal values */
	char *ep = NULL;
	int dx = DX_SHIFT(str);
	unsigned val = strtoul(str + dx, &ep, dx ? 16 : 10);
	/* doesn't look like decimal or hex, eh? */
	if (ep && *ep)
		error(2, 0, _("bad value for flowinfo: %s"), str);
	if (val & ~IPV6_FLOWINFO_FLOWLABEL)
		error(2, 0, _("flow value is greater than 20 bits: %s"), str);
	return val;
}

/* Set Type of Service (TOS) and other QOS relating bits */
unsigned char parse_tos(const char *str) {
	/* handle both hex and decimal values */
	char *ep = NULL;
	int dx = DX_SHIFT(str);
	unsigned long tos = strtoul(str + dx, &ep, dx ? 16 : 10);
	/* doesn't look like decimal or hex, eh? */
	if (ep && *ep)
		error(2, 0, _("bad TOS value: %s"), str);
	if (tos > UCHAR_MAX)
		error(2, 0, _("the decimal value of TOS bits must be in range 0-255: %lu"), tos);
	return tos;
}
#undef DX_SHIFT

inline unsigned if_name2index(const char *ifname) {
	unsigned rc = if_nametoindex(ifname);
	if (!rc)
		error(2, 0, _("unknown iface: %s"), ifname);
	return rc;
}

// return setsockopt's return_code and keep its errno
int setsock_bindopt(int fd, const char *device, socklen_t slen, unsigned mcast_face) {
	ENABLE_CAPABILITY_RAW;
	int rc = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, device, slen);
	int keep = errno;
	DISABLE_CAPABILITY_RAW;
	errno = keep;
	if ((rc < 0) && mcast_face) {
		struct ip_mreqn imr = { .imr_ifindex = mcast_face };
		rc = setsockopt(fd, SOL_IP, IP_MULTICAST_IF, &imr, sizeof(imr));
	}
	return rc;
}

#if defined(IP_PKTINFO) || defined(IPV6_PKTINFO)
static void set_pktinfo(int level, int name, const void *val, socklen_t len, int fd1, int fd2) {
	ENABLE_CAPABILITY_RAW;
	if ((setsockopt(fd1, level, name, val, len) < 0) ||
	    (setsockopt(fd2, level, name, val, len) < 0))
		error(2, errno, "setsockopt(PKTINFO)");
	DISABLE_CAPABILITY_RAW;
}
#endif

void set_device(bool ip6, const char *device, socklen_t len,
	unsigned pkt_face, unsigned mcast_face, int fd1, int fd2)
{
#if defined(IP_PKTINFO) || defined(IPV6_PKTINFO)
	if (ip6) {
#ifdef IPV6_PKTINFO
		struct in6_pktinfo ipi = { .ipi6_ifindex = pkt_face };
		set_pktinfo(IPPROTO_IPV6, IPV6_PKTINFO, &ipi, sizeof(ipi), fd1, fd2);
#endif
	} else {
#ifdef IP_PKTINFO
		struct in_pktinfo  ipi = { .ipi_ifindex  = pkt_face };
		set_pktinfo(IPPROTO_IP,   IP_PKTINFO,   &ipi, sizeof(ipi), fd1, fd2);
#endif
	}
#endif
	if ((setsock_bindopt(fd1, device, len, mcast_face) < 0) ||
	    (setsock_bindopt(fd2, device, len, mcast_face) < 0))
		error(2, errno, "setsockopt(BINDIFACE=%s)", device);
}

// func_set:receive_error:print_local_ee
inline void print_local_ee(const struct ping_rts *rts, const struct sock_extended_err *ee) {
	if (rts->opt.flood)
		write(STDOUT_FILENO, "E", 1);
	else if (ee->ee_errno != EMSGSIZE)
		error(0, ee->ee_errno, _("local error"));
	else
		error(0, 0, _("local error: message too long, mtu: %u"), ee->ee_info);
}

void mtudisc_n_bind(struct ping_rts *rts, const struct socket_st *sock) {
	// called once at setup
	if (rts->pmtudisc >= 0) {
		int level = rts->ip6 ? IPPROTO_IPV6      : SOL_IP;
		int name  = rts->ip6 ? IPV6_MTU_DISCOVER : IP_MTU_DISCOVER;
		if (setsockopt(sock->fd, level, name,
				&rts->pmtudisc, sizeof(rts->pmtudisc)) < 0)
			error(2, errno, "MTU_DISCOVER");
	}
	bool set_ident = (rts->custom_ident > 0) && !sock->raw;
	if (set_ident) {
		in_port_t *port = rts->ip6 ?
			&((struct sockaddr_in6 *)&rts->source)->sin6_port :
			&((struct sockaddr_in  *)&rts->source)->sin_port;
		*port = rts->ident16;
	}
	if (rts->opt.strictsource || set_ident) {
		socklen_t socklen = rts->ip6 ?
			sizeof(struct sockaddr_in6) :
			sizeof(struct sockaddr_in);
		if (bind(sock->fd, (struct sockaddr *)&rts->source, socklen) < 0)
			error(2, errno, "bind icmp socket");
	}
}

// func_set:receive_error:print_addr_seq
void print_addr_seq(const struct ping_rts *rts, uint16_t seq,
	const struct sock_extended_err *ee, socklen_t salen)
{
	if (rts->opt.quiet)
		return;
	if (rts->opt.flood)
		write(STDOUT_FILENO, "\bE", 2);
	else {
		PRINT_TIMESTAMP;
		const void *sa = ee + 1;
		printf(_("From %s icmp_seq=%u "), sprint_addr(rts, sa, salen), seq);
		if (rts->ip6) {
			print6_icmp(ee->ee_type, ee->ee_code, ee->ee_info);
			putchar('\n');
		} else
			print4_icmph(rts, ee->ee_type, ee->ee_code, ee->ee_info, NULL);
		fflush(stdout);
	}
}

void cmp_srcdev(const struct ping_rts *rts) {
	// called once before loop
	struct ifaddrs *list = NULL;
	if (getifaddrs(&list))
		error(2, errno, _("getifaddrs failed"));
	uint16_t af = rts->ip6 ? AF_INET6 : AF_INET;
	size_t len  = rts->ip6 ? 16 : 4;
	size_t off  = rts->ip6 ?
		offsetof(struct sockaddr_in6, sin6_addr) :
		offsetof(struct sockaddr_in,  sin_addr);
	const uint8_t *addr = (uint8_t *)&rts->source + off;
	struct ifaddrs *ifa = list;
	for (; ifa; ifa = ifa->ifa_next) {
		if (ifa->ifa_name && ifa->ifa_addr && (ifa->ifa_addr->sa_family == af))
			if (!strcmp(ifa->ifa_name, rts->device) &&
			    !memcmp((uint8_t *)ifa->ifa_addr + off, addr, len))
			break;
	}
	if (!ifa)
		error(0, 0, _("Warning: source address might be selected on device other than: %s"), rts->device);
	if (list)
		freeifaddrs(list);
}

