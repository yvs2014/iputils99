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
// ping setsock-option functions depended on 'linux/in6' header

#include <err.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>

#include <linux/libc-compat.h>
#include <linux/in6.h>
#include <linux/in.h>

#include "sockopt_sys_flow6.h"

extern uint32_t htonl(uint32_t);

void setsock_flow6(int fd, int flow, size_t size, struct sockaddr *sa, socklen_t salen) { // NONNULL(4)
	if (salen == sizeof(struct sockaddr_in6)) {
		char buff[CMSG_ALIGN(sizeof(struct in6_flowlabel_req)) + size];
		memset(buff, 0, sizeof(buff));
		struct in6_flowlabel_req *flr = (struct in6_flowlabel_req *)buff;
		flr->flr_label  = htonl(flow);
		flr->flr_action = IPV6_FL_A_GET;
		flr->flr_flags  = IPV6_FL_F_CREATE;
		flr->flr_share  = IPV6_FL_S_EXCL;
		struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)sa;
		memcpy(&flr->flr_dst, &sa6->sin6_addr, sizeof(sa6->sin6_addr));
		if (setsockopt(fd, IPPROTO_IPV6, IPV6_FLOWLABEL_MGR, flr, sizeof(*flr)) < 0)
			err(errno, "setsockopt(%s)", "IPV6_FLOWLABEL_MGR");
		sa6->sin6_flowinfo = flow = flr->flr_label;
		int on = 1;
		if (setsockopt(fd, IPPROTO_IPV6, IPV6_FLOWINFO_SEND, &on, sizeof(on)) < 0)
			err(errno, "setsockopt(%s)", "IPV6_FLOWINFO_SEND");
	} else
		warn("IPV6_FLOW: wrong salen=%u", salen);
}

