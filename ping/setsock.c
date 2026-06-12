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
// ping.c setsock option functions

#include <err.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include "iputils.h"
#include "setsock.h"
#ifdef HAVE_LIBCAP
#include "caps.h"
#else
#include "perm.h"
#endif

#ifdef SO_MARK
void setsock_mark(int fd, int mark) {
	NET_RAW_ON;  // linux4.x: NET_ADMIN
	int rc = setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
	int keep = errno;
	NET_RAW_OFF; // linux4.x: NET_ADMIN
	errno = keep;
	//
	if (rc < 0) {
		warn("%s: %s: %d", _WARN, _("failed to set mark"), mark);
		if (errno == EPERM)
			err(errno, "%s: %s", _("=> missing capability"), "cap_net_raw+p");
		err(errno, "setsock(%s)", "MARK");
	}
}
#endif

void setsock_tos(int fd, int tos, bool ip6) {
	if (setsockopt(fd, ip6 ? IPPROTO_IPV6 : IPPROTO_IP,
	    ip6 ? IPV6_TCLASS : IP_TOS, &tos, sizeof(tos)) < 0)
		err(errno, "setsockopt(%s)", ip6 ? "TCLASS" : "TOS");
}

void setsock_ttl(int fd, bool ip6, int ttl) {
	int level = ip6 ? IPPROTO_IPV6 : IPPROTO_IP;
	if (setsockopt(fd, level, ip6 ? IPV6_MULTICAST_HOPS : IP_MULTICAST_TTL,
		&ttl, sizeof(ttl)) < 0)
			err(errno, "setsockopt(%s)", ip6 ? "MULTICAST_HOPS" : "MULTICAST_TTL");
	if (setsockopt(fd, level, ip6 ? IPV6_UNICAST_HOPS : IP_TTL,
		&ttl, sizeof(ttl)) < 0)
			err(errno, "setsockopt(%s)", ip6 ? "UNICAST_HOPS" : "TTL");
}

// TODO: common setsock_onoff(fd, level, name, bool onoff)
void setsock_recverr(int fd, bool ip6) {
	int on = 1;
	if (setsockopt(fd, ip6 ? IPPROTO_IPV6 : IPPROTO_IP,
	    ip6 ? IPV6_RECVERR : IP_RECVERR, &on, sizeof(on)) < 0)
		err(errno, "%s: setsockopt(%s)", _WARN, "RECVERR");
}

void setsock_noloop(int fd, bool ip6) {
	int off = 0;
	if (setsockopt(fd, ip6 ? IPPROTO_IPV6 : IPPROTO_IP,
	    ip6 ? IPV6_MULTICAST_LOOP : IP_MULTICAST_LOOP, &off, sizeof(off)) < 0)
		err(errno, "%s", _("Cannot disable multicast loopback"));
}

void setsock_mtudisc(int fd, bool ip6, int *mtudisc) { // NONNULL(3)
	int level = ip6 ? IPPROTO_IPV6      : IPPROTO_IP;
	int name  = ip6 ? IPV6_MTU_DISCOVER : IP_MTU_DISCOVER;
	if (setsockopt(fd, level, name,
	    mtudisc, sizeof(*mtudisc)) < 0)
		err(errno, "setsockopt(%s)", "MTU_DISCOVER");
}

void setsock_filter(int fd, const struct sock_fprog *prog, // NONNUL(2)
	bool verbose, char ip46, uint16_t id)
{
	if (verbose)
		warnx("bpf%c socket=%d ident=0x%04x", ip46, fd, id);
	if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, prog, sizeof(*prog)) < 0)
		err(errno, "setsockopt(%s)", "ATTACH_FILTER");
#ifdef SO_LOCK_FILTER
	int on = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_LOCK_FILTER, &on, sizeof(on)) < 0)
		warn("setsockopt(%s)", "LOCK_FILTER");
#endif
}

// Estimate memory eaten by single packet. It is rough estimate.
// Actually, for small datalen's it depends on kernel side a lot.
void setsock_buffer(int fd, int sndbuf, int preload) {
	if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) < 0)
		warn("setsockopt(%s)", "SNDBUF");
	//
	int hold = sndbuf * preload;
	socklen_t size = sizeof(hold);
	if (hold < (IP_MAXPACKET + 1))
		hold = (IP_MAXPACKET + 1);
	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &hold, size) < 0)
		warn("setsockopt(%s)", "RCVBUF");
	//
	int rcvbuf = hold;
#define SMALL_RCV_BUF _("Probably, rcvbuf is not enough to hold preload")
	if (!getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &hold, &size))
		if (hold < rcvbuf)
			warnx("%s: %s", _WARN, SMALL_RCV_BUF);
}

