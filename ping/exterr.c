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
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <linux/errqueue.h>

#include "exterr.h"
#include "iputils.h"
#include "stats.h"
#include "aux4.h"
#include "aux6.h"

// common IPv4/IPv6 ICMP header
typedef struct icmp46h {
	uint8_t type;
	uint8_t code;
	uint16_t sum;
	uint16_t id;
	uint16_t seq;
} icmp46h_t;


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

// returns seq<0 if not-our
static int ee_our_seq(state_t *rts, size_t n, const sock_t *sock, // NONNULL(1, 3, 4, 6)
	const icmp46h_t *icmp, size_t icmplen, const struct sockaddr *sa)
{
	int seq = -1;
	bool our = (n >= icmplen) &&
		rts->ee_aux.addr_equal(sa, &rts->whereto) &&
		(rts->ee_aux.echo_value == icmp->type) &&
		IS_OURS(rts, sock->raw, icmp->id);
	if (our) {
		rts->nerrors++;
		seq = ntohs(icmp->seq);
		if (rts->ee_aux.eerr_extra)
			rts->ee_aux.eerr_extra(rts, sock, seq);
	}
	return seq;
}

static void print_ee_reply(const state_t *rts, uint16_t seq,
	const struct sock_extended_err *ee, socklen_t salen) // NONNULL(1, 3)
{
	if (rts->opt.flood)
		(void)write(STDOUT_FILENO, "\bE", 2);
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

static inline void print_local_ee(bool flood, uint32_t ee_errno, uint32_t ee_info) {
	if (flood)
		(void)write(STDOUT_FILENO, "E", 1);
	else if (ee_errno != EMSGSIZE)
		warnx("%s", _("Local error"));
	else
		warnx("%s: %s: mtu=%u", _("Local error"), _("Message too long"), ee_info);
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
				print_local_ee(rts->opt.flood, ee->ee_errno, ee->ee_info);
		} else if (ee->ee_origin == rts->ee_aux.ee_origin) {
			int seq = ee_our_seq(rts, n, sock,
				msg->msg_iov->iov_base, msg->msg_iov->iov_len, msg->msg_name);
			if (seq >= 0) { // our error
				if (!rts->opt.quiet)
					print_ee_reply(rts, seq, ee, msg->msg_namelen);
				net_errors++;
			} else // otherwise clear errno
				keep_errno = 0;
		}
	}
	errno = keep_errno;
	return net_errors ? net_errors : -local_errors;
}

