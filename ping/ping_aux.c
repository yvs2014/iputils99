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

#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <math.h>
#include <locale.h>
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

// TMP
unsigned if_name2index(const char *ifname) {
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

void ping_bind(struct ping_rts *rts, const struct socket_st *sock) {
	bool set_ident = (rts->custom_ident > 0) && !sock->raw;
	if (set_ident) {
		if (rts->ip6)
			((struct sockaddr_in6 *)&rts->source)->sin6_port = rts->ident16;
		else
			((struct sockaddr_in  *)&rts->source)->sin_port  = rts->ident16;
	}
	if (rts->opt.strictsource || set_ident) {
		socklen_t socklen = rts->ip6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
		if (bind(sock->fd, (struct sockaddr *)&rts->source, socklen) < 0)
			error(2, errno, "bind icmp socket");
	}
}

