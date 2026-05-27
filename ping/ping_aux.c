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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <sys/types.h>
#include <linux/in6.h>

#include "ping_aux.h"

#include "iputils.h"
#include "common.h"
#include "stats.h"
#include "ping4_aux.h"
#include "ping6_aux.h"

// common IPv4/IPv6 ICMP header
typedef struct icmp46h {
	uint8_t type;
	uint8_t code;
	uint16_t sum;
	uint16_t id;
	uint16_t seq;
} icmp46h_t;

#define DX_SHIFT(str) (((str)[0] == '0') && (((str)[1] == 'x') || ((str)[1] == 'X')) ? 2 : 0)
unsigned parse_flow(const char *str) {
	/* handle both hex and decimal values */
	char *ep = NULL;
	int dx = DX_SHIFT(str);
	unsigned val = strtoul(str + dx, &ep, dx ? 16 : 10);
	/* doesn't look like decimal or hex, eh? */
	if (ep && *ep)
		errx(EINVAL, "%s: %s", _("Bad value for flowinfo"), str);
	if (val & ~IPV6_FLOWINFO_FLOWLABEL)
		errx(EINVAL, "%s: %s", _("Flow value is greater than 20 bits"), str);
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
		errx(EINVAL, "%s: %s", _("Bad TOS value"), str);
	if (tos > UCHAR_MAX)
		errx(EINVAL, "%s: %lu",
			_("Decimal value of TOS bits must be in range 0-255"),
			tos);
	return tos;
}
#undef DX_SHIFT

void setsock_bpf(const state_t *rts,
	const sock_t *sock, const struct sock_fprog *prog)
{
	if (rts->opt.verbose)
		warnx("bpf%c socket=%d ident=0x%04x",
			rts->ip6 ? '6' : '4', sock->fd, rts->ident16);
	if (setsockopt(sock->fd, SOL_SOCKET, SO_ATTACH_FILTER, prog, sizeof(*prog)) < 0)
		err(errno, "setsockopt(%s)", "SO_ATTACH_FILTER");
#ifdef SO_LOCK_FILTER
	int on = 1;
	if (setsockopt(sock->fd, SOL_SOCKET, SO_LOCK_FILTER, &on, sizeof(on)) < 0)
		warn("setsockopt(%s)", "SO_LOCK_FILTER");
#endif
}

inline void setsock_recverr(int fd, bool ip6) {
	int on = 1;
	if (setsockopt(fd, ip6 ? IPPROTO_IPV6 : IPPROTO_IP,
		ip6 ? IPV6_RECVERR : IP_RECVERR, &on, sizeof(on)) < 0)
			warn("%s: setsockopt(%s)", _WARN,
		ip6 ? "IPV6_RECVERR" : "IP_RECVERR");
}

inline void setsock_noloop(int fd, bool ip6) {
	int off = 0;
	if (setsockopt(fd, ip6 ? IPPROTO_IPV6 : IPPROTO_IP,
		ip6 ? IPV6_MULTICAST_LOOP : IP_MULTICAST_LOOP,
		&off, sizeof(off)) < 0)
			err(errno, "%s", _("Cannot disable multicast loopback"));
}

void setsock_ttl(int fd, bool ip6, int ttl) {
	int level = ip6 ? IPPROTO_IPV6 : IPPROTO_IP;
	if (setsockopt(fd, level, ip6 ? IPV6_MULTICAST_HOPS : IP_MULTICAST_TTL,
		&ttl, sizeof(ttl)) < 0)
			err(errno, "setsockopt(%s)", "MULTICAST_TTL");
	if (setsockopt(fd, level, ip6 ? IPV6_UNICAST_HOPS : IP_TTL,
		&ttl, sizeof(ttl)) < 0)
			err(errno, "setsockopt(%s)", "UNICAST_TTL");
}

void pmtu_interval(state_t *rts) {
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
		if ((rts->pmtudisc >= 0) && (rts->pmtudisc != PMTUDISCDO))
			errx(EINVAL, "%s %s", _(rts->ip6 ?
				"Multicast ping" : "Broadcast ping"),
				_("does not fragment"));
	}
	if (rts->pmtudisc < 0)
		rts->pmtudisc = PMTUDISCDO;
}
#undef PMTUDISCDO

void mtudisc_n_bind(state_t *rts, const sock_t *sock) {
	// called once at setup
	if (rts->pmtudisc >= 0) {
		int level = rts->ip6 ? IPPROTO_IPV6      : IPPROTO_IP;
		int name  = rts->ip6 ? IPV6_MTU_DISCOVER : IP_MTU_DISCOVER;
		if (setsockopt(sock->fd, level, name,
				&rts->pmtudisc, sizeof(rts->pmtudisc)) < 0)
			err(errno, "setsockopt(%s)", "MTU_DISCOVER");
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
			err(errno, "bind(%s)", "icmp-socket");
	}
}

/* Estimate memory eaten by single packet. It is rough estimate.
 * Actually, for small datalen's it depends on kernel side a lot. */
void set_estimate_buf(state_t *rts, int fd,
	size_t iplen, size_t extra, size_t icmplen)
{
	if (!rts->sndbuf)
/* Set socket buffers, "alloc" is an estimate of memory taken by single packet */
		rts->sndbuf = ((icmplen + rts->datalen + 511) / 512) *
			(iplen + extra + 2 * icmplen + DEFIPPAYLOAD + 160);
	if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &rts->sndbuf, sizeof(rts->sndbuf)) < 0)
		warn("setsockopt(%s)", "SO_SNDBUF");
	//
	int hold = rts->sndbuf * rts->preload;
	socklen_t size = sizeof(hold);
	if (hold < (IP_MAXPACKET + 1))
		hold = (IP_MAXPACKET + 1);
	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &hold, size) < 0)
		warn("setsockopt(%s)", "SO_RCVBUF");
	//
	int rcvbuf = hold;
	if (!getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &hold, &size))
		if (hold < rcvbuf)
			warnx("%s: %s", _WARN,
				_("Probably, rcvbuf is not enough to hold preload"));
}

// func_set:receive_error:print_addr_seq
static void print_addr_seq(const state_t *rts, uint16_t seq,
  const struct sock_extended_err *ee, socklen_t salen) {
	if (rts->opt.quiet)
		return;
	if (rts->opt.flood) {
		if (write(STDOUT_FILENO, "\bE", 2)) {};
	} else {
		PRINT_TIMESTAMP;
		const void *sa = ee + 1;
		printf("%s %s: %s=%u ",
			_("From"), sprint_addr(sa, salen, rts->opt.resolve),
			_("icmp_seq"), seq);
		if (rts->ip6)
			print_icmp6msg(ee->ee_type, ee->ee_code, ee->ee_info, rts->red);
		else
			print_icmp4msg(ee->ee_type, ee->ee_code, ee->ee_info,
				NULL, rts->opt.resolve, rts->red);
		putchar('\n');
		fflush(stdout);
	}
}

// func_set:receive_error:print_local_ee
inline void print_local_ee(const state_t *rts, const struct sock_extended_err *ee) {
	if (rts->opt.flood) {
		if (write(STDOUT_FILENO, "E", 1)) {};
	} else if (ee->ee_errno != EMSGSIZE)
		warnx("%s", _("Local error"));
	else
		warnx("%s: %s: mtu=%u", _("Local error"), _("Message too long"), ee->ee_info);
}


// extended error functions
//

static const struct sock_extended_err *cmsg_sock_ext_err(struct msghdr *msg, int level, int type) {
	const struct sock_extended_err *e = NULL;
	for (struct cmsghdr *c = CMSG_FIRSTHDR(msg); c; c = CMSG_NXTHDR(msg, c))
		if ((c->cmsg_level == level) && (c->cmsg_type == type))
			e = (struct sock_extended_err *)CMSG_DATA(c);
	if (e) return e;
	errx(EXIT_FAILURE, "%s() abort: no suitable extended error for level=%d and type=%d", __func__, level, type);
	abort();
}

static bool print_ee_reply(state_t *rts, size_t n,
  const sock_t *sock, const struct sock_extended_err *e,
  const icmp46h_t *icmp, size_t icmplen,
  const struct sockaddr *sa, socklen_t salen) {
	bool our = (n >= icmplen) &&
	  rts->ee_aux.addr_equal(sa, &rts->whereto) &&
	  (rts->ee_aux.echo_value = icmp->type) &&
	  IS_OURS(rts, sock->raw, icmp->id);
	if (our) {
		rts->nerrors++;
		uint16_t seq = ntohs(icmp->seq);
		if (rts->ee_aux.eerr_extra)
			rts->ee_aux.eerr_extra(rts, sock, seq);
		print_addr_seq(rts, seq, e, salen);
	}
	return our;
}

int get_errmsg(state_t *rts, const sock_t *sock, struct msghdr *msg) {
	int keep_errno = errno, net_errors = 0, local_errors = 0;
	ssize_t n = recvmsg(sock->fd, msg, MSG_ERRQUEUE | MSG_DONTWAIT);
	if (n < 0) {
		if (errno == EAGAIN || errno == EINTR)
			local_errors++;
	} else {
		const struct sock_extended_err *ee = cmsg_sock_ext_err(msg, rts->ee_aux.ee_level, rts->ee_aux.ee_type);
		if (ee->ee_origin == SO_EE_ORIGIN_LOCAL) {
			local_errors++;
			rts->nerrors++;
			if (!rts->opt.quiet)
				print_local_ee(rts, ee);
		} else if (ee->ee_origin == rts->ee_aux.ee_origin) {
			if (print_ee_reply(rts, n, sock, ee,
			  msg->msg_iov->iov_base, msg->msg_iov->iov_len,
			  msg->msg_name, msg->msg_namelen))
				net_errors++;
			else // not our error, clear
				keep_errno = 0;
		}
	}
	errno = keep_errno;
	return net_errors ? net_errors : -local_errors;
}

