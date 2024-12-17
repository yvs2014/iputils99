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
#include <net/if.h>
#include <linux/in6.h>
#include <linux/errqueue.h>

#define CASE_TYPE(x)	case x: return #x;

char *str_family(int family) {
	switch (family) {
		CASE_TYPE(AF_UNSPEC)
		CASE_TYPE(AF_INET)
		CASE_TYPE(AF_INET6)
	default:
		error(2, 0, _("unknown protocol family: %d"), family);
	}
	return "";
}

/* Much like strtod(3), but will fails if str is not valid number */
double ping_strtod(const char *str, const char *err_msg) {
	errno = (str && *str) ? 0 : EINVAL;
	if (!errno) {
		/*
		 * Here we always want to use locale regardless USE_IDN or ENABLE_NLS,
		 * because it handles decimal point of -i/-W input options
		 */
		setlocale(LC_ALL, "C");
		char *end = NULL;
		double num = strtod(str, &end);
		int strtod_errno = errno;
		setlocale(LC_ALL, "");
		/* Ignore setlocale() errno (e.g. invalid locale in env) */
		errno = strtod_errno;
		if (errno || (str == end) || (end && *end)) {
			error(0, 0, _("option argument contains garbage: %s"), end);
			error(0, 0, _("this will become fatal error in the future"));
		}
		int fp = fpclassify(num);
		if ((fp == FP_NORMAL) || (fp == FP_ZERO))
			return num;
		errno = ERANGE;
	}
	error(2, errno, "%s: %s", err_msg, str);
	abort();	/* cannot be reached, above error() will exit */
	return 0.;
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
int setsock_bindopt(int fd, const char *device, socklen_t slen, unsigned ifindex) {
	ENABLE_CAPABILITY_RAW;
	int rc = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, device, slen);
	int bind_errno = errno;
	DISABLE_CAPABILITY_RAW;
	errno = bind_errno;
	if ((rc < 0) && ifindex) {
		struct ip_mreqn imr = { .imr_ifindex = ifindex };
		rc = setsockopt(fd, SOL_IP, IP_MULTICAST_IF, &imr, sizeof(imr));
	}
	return rc;
}

// func_set:receive_error:print_local_ee
inline void print_local_ee(struct ping_rts *rts, const struct sock_extended_err *ee) {
	if (rts->opt.flood)
		write(STDOUT_FILENO, "E", 1);
	else if (ee->ee_errno != EMSGSIZE)
		error(0, ee->ee_errno, _("local error"));
	else
		error(0, 0, _("local error: message too long, mtu: %u"), ee->ee_info);
	rts->nerrors++;
}

struct ip46_consts {
	socklen_t socklen;
	size_t icmpsize;
	size_t off_port;
        size_t off_seq;
	int mtu_level;
	int mtu_name;
};

static const struct ip46_consts ip4c = {
	.socklen   = sizeof(struct sockaddr_in),
	.icmpsize  = sizeof(struct icmphdr),
	.off_port  = offsetof(struct sockaddr_in, sin_port),
	.off_seq   = offsetof(struct icmphdr, un.echo.sequence),
	.mtu_level = SOL_IP,
	.mtu_name  = IP_MTU_DISCOVER,
};
static const struct ip46_consts ip6c = {
	.socklen   = sizeof(struct sockaddr_in6),
	.icmpsize  = sizeof(struct icmp6_hdr),
	.off_port  = offsetof(struct sockaddr_in6, sin6_port),
	.off_seq   = offsetof(struct icmp6_hdr, icmp6_seq),
	.mtu_level = IPPROTO_IPV6,
	.mtu_name  = IPV6_MTU_DISCOVER,
};

void mtudisc_n_bind(struct ping_rts *rts, const struct socket_st *sock) {
	const struct ip46_consts *ipc = rts->ip6 ? &ip6c : &ip4c;
	if (rts->pmtudisc >= 0)
		if (setsockopt(sock->fd, ipc->mtu_level, ipc->mtu_name,
				&rts->pmtudisc, sizeof(rts->pmtudisc)) < 0)
			error(2, errno, "MTU_DISCOVER");
	bool set_ident = (rts->custom_ident > 0) && !sock->raw;
	if (set_ident) {
		in_port_t *port = (in_port_t *)((char *)&rts->source + ipc->off_port);
		*port = rts->ident16;
	}
	if (rts->opt.strictsource || set_ident)
		if (bind(sock->fd, (struct sockaddr *)&rts->source, ipc->socklen) < 0)
			error(2, errno, "bind icmp socket");
}

void print_echo_reply(bool ip6, const uint8_t *hdr, size_t len) {
	const struct ip46_consts *ipc = ip6 ? &ip6c : &ip4c;
	if (len >= ipc->icmpsize) {
		uint16_t *seq = (uint16_t *)(hdr + ipc->off_seq);
		printf(_(" icmp_seq=%u"), ntohs(*seq));
	}
}

// func_set:receive_error:print_addr_seq
inline void print_addr_seq(struct ping_rts *rts, uint16_t seq,
	const struct sock_extended_err *ee, socklen_t salen)
{
	rts->nerrors++;
	if (rts->opt.quiet)
		return;
	if (rts->opt.flood)
		write(STDOUT_FILENO, "\bE", 2);
	else {
		PRINT_TIMESTAMP;
		const void *sa = ee + 1;
		printf(_("From %s icmp_seq=%u "), SPRINT_RES_ADDR(rts, sa, salen), seq);
		if (rts->ip6) {
			print6_icmp(ee->ee_type, ee->ee_code, ee->ee_info);
			putchar('\n');
		} else
			print4_icmph(rts, ee->ee_type, ee->ee_code, ee->ee_info, NULL);
		fflush(stdout);
	}
}

