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
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#include "iputils.h"
#include "setsock.h"
#include "sock_pa.h"
#ifdef HAVE_LIBCAP
#include "caps.h"
#else
#include "perm.h"
#endif

#if !defined(__GLIBC__) && !defined(__UCLIBC__)
// workaround for musl: IPV6_FLOWLABEL_MGR, IPV6_FLOWINFO_SEND
#define __UAPI_DEF_IPV6_OPTIONS 1
#endif
#include <linux/in6.h>

#ifndef IPPROTO46
#define	IPPROTO46 (ip6 ? IPPROTO_IPV6 : IPPROTO_IP)
#endif

// ICMP_FILTER is defined in <linux/icmp.h>,
// and <linux/icmp.h> has conflicts with <netinet/ip_icmp.h>
#ifndef ICMP_FILTER
#define ICMP_FILTER 1
struct icmp_filter {
	uint32_t data;
};
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
	if (setsockopt(fd, IPPROTO46, ip6 ? IPV6_TCLASS : IP_TOS, &tos, sizeof(tos)) < 0)
		err(errno, "setsockopt(%s)", ip6 ? "TCLASS" : "TOS");
}

void setsock_noloop(int fd, bool ip6) {
	int off = 0;
	if (setsockopt(fd, IPPROTO46, ip6 ? IPV6_MULTICAST_LOOP : IP_MULTICAST_LOOP,
	    &off, sizeof(off)) < 0)
		err(errno, "%s", _("Cannot disable multicast loopback"));
}

void setsock_filter(int fd, const struct sock_fprog *prog, // NONNULL(2)
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

void setsock_icmp4_filter(int fd, const int32_t flag[]) { // NONNULL(2)
	uint32_t u = 0;
	for (; *flag >= 0; flag++)
		u |= (1 << *flag);
	struct icmp_filter filt = {.data = ~u};
	if (setsockopt(fd, SOL_RAW, ICMP_FILTER, &filt, sizeof(filt)) < 0)
		err(errno, "setsockopt(%s: %04X)", "ICMP_FILTER", filt.data);
}

void setsock_icmp6_filter(int fd) {
	/* select icmp echo reply as icmp type to receive */
	struct icmp6_filter filter = {0};
	ICMP6_FILTER_SETBLOCKALL(&filter);
#ifdef ENABLE_RFC4620
	if (rts->ni && niquery_is_enabled(rts->ni))
	{	ICMP6_FILTER_SETPASS(IPUTILS_NI_ICMP6_REPLY, &filter); }
	else
#endif
	{	ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &filter); }
	if (setsockopt(fd, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter)) < 0)
		err(errno, "setsockopt(%s)", "ICMP6_FILTER");
}

void setsock_cksum6(int fd) {
	int csum_offset = 2;
	if (setsockopt(fd, SOL_RAW, IPV6_CHECKSUM, &csum_offset, sizeof(csum_offset)) < 0)
	/* checksum should be enabled by default and setting this option might fail anyway */
		warn("setsockopt(%s)", "RAW_CHECKSUM");
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

void setsock_debug(int fd) {
	int on = 1;
	NET_ADMIN_ON;
	int rc = setsockopt(fd, SOL_SOCKET, SO_DEBUG, &on, sizeof(on));
	int keep = errno;
	NET_ADMIN_OFF;
	errno = keep;
	if (rc < 0)
		warn("setsockopt(%s)", "DEBUG");
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
		warn("setsockopt(%s)", "SNDTIMEO");
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
		warn("setsockopt(%s)", "SNDTIMEO");
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
			const char *valstr = IPOPT_SSRR ? "IPOPT_SSRR" :
			                     IPOPT_LSRR ? "IPOPT_LSRR" : "?";
			if (errno == EPERM)
				warnx("%s: %s", _("=> missing capability"), "cap_net_raw+p");
			err(errno, "%s: %s(%d)", _("record route"), valstr, val);
		}
	}
}

void setsock_retopts(int fd) {
	int on = 1;
	if (setsockopt(fd, IPPROTO_IP, IP_RETOPTS, &on, sizeof(on)) < 0)
		warn("setsockopt(%s)", "RETOPTS");
}

void setsock_broadcast(int fd) {
	int on = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) < 0)
		err(errno, "setsockopt(%s)", "BROADCAST");
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
		err(errno, "setsockopt(%s, %s)", "PKTINFO", dev);
}
*/

void setsock_flow6(int fd, int flow, size_t clen, struct sockaddr_in6 *sa) { // NONNULL(4)
	char buf[CMSG_ALIGN(sizeof(struct in6_flowlabel_req)) + clen];
	memset(buf, 0, sizeof(buf));
	struct in6_flowlabel_req *freq = (struct in6_flowlabel_req *)buf;
	freq->flr_label  = htonl(flow);
	freq->flr_action = IPV6_FL_A_GET;
	freq->flr_flags  = IPV6_FL_F_CREATE;
	freq->flr_share  = IPV6_FL_S_EXCL;
	memcpy(&freq->flr_dst, &sa->sin6_addr, sizeof(sa->sin6_addr));
	if (setsockopt(fd, IPPROTO_IPV6, IPV6_FLOWLABEL_MGR, freq, sizeof(*freq)) < 0)
		err(errno, "setsockopt(%s)", "IPV6_FLOWLABEL");
	sa->sin6_flowinfo = flow = freq->flr_label;
	int on = 1;
	if (setsockopt(fd, IPPROTO_IPV6, IPV6_FLOWINFO_SEND, &on, sizeof(on)) < 0)
		err(errno, "setsockopt(%s)", "IPV6_FLOWINFO");
}

