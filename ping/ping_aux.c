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

#include "ping_aux.h"
#include "iputils.h"
#include "common.h"
#include "stats.h"
#include "ping4_aux.h"
#include "ping6_aux.h"
#include "setsock.h"

// common IPv4/IPv6 ICMP header
typedef struct icmp46h {
	uint8_t type;
	uint8_t code;
	uint16_t sum;
	uint16_t id;
	uint16_t seq;
} icmp46h_t;

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
		if ((rts->mtudisc >= 0) && (rts->mtudisc != PMTUDISCDO))
			errx(EINVAL, "%s %s", _(rts->ip6 ?
				"Multicast ping" : "Broadcast ping"),
				_("does not fragment"));
	}
	if (rts->mtudisc < 0)
		rts->mtudisc = PMTUDISCDO;
}
#undef PMTUDISCDO

// Called once at setup
void mtudisc_n_bind(state_t *rts, const sock_t *sock) {
	if (rts->mtudisc >= 0)
		setsock_mtudisc(sock->fd, rts->ip6, &rts->mtudisc);
	bool set_ident = (rts->custom_ident > 0) && !sock->raw;
	if (set_ident) {
		if (rts->ip6)
			SA6(&rts->source)->sin6_port = rts->ident16;
		else
			SA4(&rts->source)->sin_port  = rts->ident16;
	}
	if (rts->opt.strictsource || set_ident) {
		socklen_t socklen = rts->ip6 ? SA6_LEN : SA4_LEN;
		if (bind(sock->fd, SA(&rts->source), socklen) < 0)
			err(errno, "bind(%s)", "icmp-socket");
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

static inline const struct sock_extended_err *cmsg_sock_ext_err(struct msghdr *msg, int level, int type) {
	const struct sock_extended_err *e = NULL;
	for (struct cmsghdr *c = CMSG_FIRSTHDR(msg); c; c = CMSG_NXTHDR(msg, c))
		if ((c->cmsg_level == level) && (c->cmsg_type == type))
			e = (struct sock_extended_err *)CMSG_DATA(c);
	if (e) return e;
	errx(EXIT_FAILURE, "%s() abort: no suitable extended error for level=%d and type=%d", __func__, level, type);
	abort();
}

static bool print_ee_reply(state_t *rts, size_t n,
	const sock_t *sock, const struct sock_extended_err *ee,
	const icmp46h_t *icmp, size_t icmplen,
	const struct sockaddr *sa, socklen_t salen)
{
	bool our = (n >= icmplen) &&
		rts->ee_aux.addr_equal(sa, &rts->whereto) &&
		(rts->ee_aux.echo_value = icmp->type) &&
		IS_OURS(rts, sock->raw, icmp->id);
	if (our) {
		rts->nerrors++;
		uint16_t seq = ntohs(icmp->seq);
		if (rts->ee_aux.eerr_extra)
			rts->ee_aux.eerr_extra(rts, sock, seq);
		if (!rts->opt.quiet) {
			if (rts->opt.flood)
				write(STDOUT_FILENO, "\bE", 2);
			else {
				PRINT_TIMESTAMP;
				printf("%s %s: %s=%u ",
					_("From"), sprint_addr(ee + 1, salen, rts->opt.resolve),
					_("icmp_seq"), seq);
				if (rts->ip6)
					print_icmp6msg(ee->ee_type, ee->ee_code, ee->ee_info, rts->red);
				else
					print_icmp4msg(ee->ee_type, ee->ee_code, ee->ee_info, 0,
						rts->opt.resolve, rts->red);
				putchar('\n');
				fflush(stdout);
			}
		}
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

