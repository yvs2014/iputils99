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
// ping setsock-option functions

#include <err.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/icmp6.h>

#include "iputils.h"
#include "setsock.h"
#include "sock_pa.h"
#ifdef HAVE_LIBCAP
#include "caps.h"
#else
#include "perm.h"
#endif

#ifndef IPPROTO46
#define	IPPROTO46 (ip6 ? IPPROTO_IPV6 : IPPROTO_IP)
#endif

void setsock_tos(int fd, int tos, bool ip6) {
	if (setsockopt(fd, IPPROTO46, ip6 ? IPV6_TCLASS : IP_TOS, &tos, sizeof(tos)) < 0)
		err(errno, "setsockopt(%s)", ip6 ? _STR(IPV6_TCLASS) : _STR(IP_TOS));
}

void setsock_noloop(int fd, bool ip6) {
	int off = 0;
	if (setsockopt(fd, IPPROTO46, ip6 ? IPV6_MULTICAST_LOOP : IP_MULTICAST_LOOP, &off, sizeof(off)) < 0)
		err(errno, "%s", _("Cannot disable multicast loopback"));
}

#ifdef SO_MARK
void setsock_mark(int fd, int mark) {
	NET_RAW_ON;  // NET_RAW since linux-4.x (was NET_ADMIN)
	int rc = setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
	int keep = errno;
	NET_RAW_OFF;
	errno = keep;
	if (rc < 0) {
		warn("%s: %s: %d", _WARN, _("failed to set mark"), mark);
		warn_if_missing_cap(CAP_NET_RAW);
		err(errno, "setsockopt(%s)", _STR(SO_MARK));
	}
}
#endif

void setsock_icmp6_filter(int fd, uint8_t pass) {
	// select icmp echo reply as icmp type to receive
	struct icmp6_filter filter = {0};
	ICMP6_FILTER_SETBLOCKALL(&filter);
	if (pass)
		ICMP6_FILTER_SETPASS(pass, &filter);
	if (setsockopt(fd, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter)) < 0)
		err(errno, "setsockopt(%s)", _STR(ICMP6_FILTER));
}

void setsock_cksum6(int fd) {
	// checksum should be enabled by default and setting this option might fail anyway
	int csum_offset = 2;
	if (setsockopt(fd, SOL_RAW, IPV6_CHECKSUM, &csum_offset, sizeof(csum_offset)) < 0)
		warn("setsockopt(%s)", _STR(IPV6_CHECKSUM));
}

// Estimate memory eaten by single packet. It is rough estimate.
// Actually, for small datalen's it depends on kernel side a lot.
void setsock_buffer(int fd, int sndbuf, int preload) {
	if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) < 0)
		warn("setsockopt(%s)", _STR(SO_SNDBUF));
	//
	int hold = sndbuf * preload;
	socklen_t size = sizeof(hold);
	if (hold < (IP_MAXPACKET + 1))
		hold = (IP_MAXPACKET + 1);
	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &hold, size) < 0)
		warn("setsockopt(%s)", _STR(SO_RCVBUF));
	//
	int rcvbuf = hold;
#define SMALL_RCV_BUF _("Probably, rcvbuf is not enough to hold preload")
	if (!getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &hold, &size))
		if (hold < rcvbuf)
			warnx("%s: %s", _WARN, SMALL_RCV_BUF);
}

void setsock_debug(int fd) {
	int on = 1;
	NET_ADMIN_ON;
	int rc = setsockopt(fd, SOL_SOCKET, SO_DEBUG, &on, sizeof(on));
	int keep = errno;
	NET_ADMIN_OFF;
	errno = keep;
	if (rc < 0) {
		warn_if_missing_cap(CAP_NET_ADMIN);
		warn("setsockopt(%s)", _STR(SO_DEBUG));
	}
}

inline void setsock_binddev(int fd, const char dev[]) { // NONNULL(2)
	if (bindtodev(fd, dev) < 0) // privileged action
		err_nodev(dev);
}

#ifdef SO_TIMESTAMP
void setsock_timestamp(int fd) {
	int on = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_TIMESTAMP, &on, sizeof(on)) < 0)
		warnx("%s", _("no SO_TIMESTAMP support, falling back to SIOCGSTAMP"));
}
#endif

void setsock_sndtime(int fd, int interval) {
	/* Set some SNDTIMEO to prevent blocking forever
	 * on sends, when device is too slow or stalls. Just put limit
	 * of one second, or "interval", if it is less.
	 */
	bool ge_ms = interval >= 1000;
	struct timeval tv = {
		.tv_sec  = ge_ms ? 1 : 0,
		.tv_usec = ge_ms ? 0 : 1000 * SCHINT(interval),
	};
	if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0)
		warn("setsockopt(%s)", _STR(SO_SNDTIMEO));
}

bool setsock_rcvtime(int fd, int interval) {
	/* Set RCVTIMEO to "interval"
	 * Note, it is just an optimization allowing to avoid redundant poll() */
	struct timeval tv = {
		.tv_sec  = SCHINT(interval) / 1000,
		.tv_usec = 1000 * (SCHINT(interval) % 1000),
	  };
	int rc = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	if (rc < 0)
		warn("setsockopt(%s)", _STR(SO_RCVTIMEO));
	// for setting `flood_poll'
	return !!rc;
}

void setsock_ipopt_rr(int fd, ipopt_noped_t *opt) {
	opt->nop = IPOPT_NOP;
	opt->val = IPOPT_RR;
	opt->len = sizeof(ipopt_noped_t) - sizeof(((ipopt_noped_t*)0)->nop); /*39*/
	opt->off = IPOPT_MINOFF;
	if (setsockopt(fd, IPPROTO_IP, IP_OPTIONS, opt, sizeof(*opt)) < 0)
		err(errno, _("record route"));
}

void setsock_ipopt_xrr(int fd, ipopt_noped_t *opt, uint8_t val, uint8_t len) {
	opt->nop = IPOPT_NOP;
	opt->val = val;
	opt->len = len;
	opt->off = IPOPT_MINOFF;
	if (setsockopt(fd, IPPROTO_IP, IP_OPTIONS, opt, len + 1) < 0) {
		// restricted since 2026-06, so try fallback with 'cap_net_raw'
		NET_RAW_ON;
		int rc = setsockopt(fd, IPPROTO_IP, IP_OPTIONS, opt, len + 1);
		int keep = errno;
		NET_RAW_OFF;
		errno = keep;
		if (rc < 0) {
			warn_if_missing_cap(CAP_NET_RAW);
			err(errno, "%s: %s(%d)", _("record route"),
				IPOPT_SSRR ? _STR(IPOPT_SSRR) :
				IPOPT_LSRR ? _STR(IPOPT_LSRR) :
				"?", val);
		}
	}
}

void setsock_retopts(int fd) {
	int on = 1;
	if (setsockopt(fd, IPPROTO_IP, IP_RETOPTS, &on, sizeof(on)) < 0)
		warn("setsockopt(%s)", _STR(IP_RETOPTS));
}

void setsock_broadcast(int fd) {
	int on = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) < 0)
		err(errno, "setsockopt(%s)", _STR(SO_BROADCAST));
}

/*
void setsock_pktinfo(int fd, uint iface, const char dev[], bool ip6) { // NONNULL(3)
	union {
		struct in_pktinfo  ipi4;
		struct in6_pktinfo ipi6;
	} ipi = {0};
	if (ip6)
		ipi.ipi6.ipi6_ifindex = iface;
	else
		ipi.ipi4.ipi_ifindex  = iface;
	socklen_t len = ip6 ? sizeof(struct in6_pktinfo) : sizeof(struct in_pktinfo);
	if (setsockopt(fd1, IPPROTO_IP, IP_PKTINFO, &ipi, len) < 0)
		err(errno, "setsockopt(%s, %s)", _STR(IP_PKTINFO), dev);
}
*/

