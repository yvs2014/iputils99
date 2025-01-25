/*
 *
 *	Modified for AF_INET6 by Pedro Roque
 *
 *	<roque@di.fc.ul.pt>
 *
 *	Original copyright notice included below
 */

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
 *	If kernel does not support ICMP datagram sockets or
 *	if -N option is used, this program has to run SUID to ROOT or
 *	with net_cap_raw enabled.
 */

// local changes by yvs@
// part of ping.c

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <linux/in6.h>
#include <linux/errqueue.h>
#include <linux/filter.h>

#include "ping6.h"

#include "iputils.h"
#include "common.h"
#include "stats.h"
#include "ping_aux.h"
#include "ping6_aux.h"
#ifdef ENABLE_RFC4620
#include "node_info.h"
#include "ni_defs.h"
#endif

#ifndef IPV6_FLOWLABEL_MGR
# define IPV6_FLOWLABEL_MGR 32
#endif
#ifndef IPV6_FLOWINFO_SEND
# define IPV6_FLOWINFO_SEND 33
#endif

// func_set:send_probe
static ssize_t ping6_send_probe(state_t *rts, int fd, uint8_t *packet) {
	ssize_t len =
#ifdef ENABLE_RFC4620
	(rts->ni && niquery_is_enabled(rts->ni)) ?
		build_ni_hdr(rts->ni, rts->ntransmitted, packet) :
#endif
		build_echo_hdr(rts, packet);
	len += rts->datalen;
	//
	ssize_t rc = 0;
	if (rts->cmsg->len == 0) {
		rc = sendto(fd, packet, len, rts->confirm,
			    (struct sockaddr *)&rts->whereto,
			    sizeof(struct sockaddr_in6));
	} else {
		struct iovec iov = { .iov_len = len, .iov_base = packet };
		struct msghdr msg = {
			.msg_name       = &rts->whereto,
			.msg_namelen    = sizeof(struct sockaddr_in6),
			.msg_iov        = &iov,
			.msg_iovlen     = 1,
			.msg_control    = rts->cmsg->data,
			.msg_controllen = rts->cmsg->len,
		};
		rc = sendmsg(fd, &msg, rts->confirm);
	}
	rts->confirm = 0;
	return (rc == len) ? 0 : rc;
}

// func_set:receive_error
static int ping6_receive_error(state_t *rts, const sock_t *sock) {
	int saved_errno = errno;
	//
	char cbuf[512];
	struct icmp6_hdr icmp = {0};
	struct iovec iov = { .iov_base = &icmp, .iov_len = sizeof(icmp) };
	struct sockaddr_in6 target = {0};
	struct msghdr msg = {
		.msg_name       = &target,
		.msg_namelen    = sizeof(target),
		.msg_iov        = &iov,
		.msg_iovlen     = 1,
		.msg_control    = cbuf,
		.msg_controllen = sizeof(cbuf),
	};
	//
	int net_errors = 0;
	int local_errors = 0;
	ssize_t res = recvmsg(sock->fd, &msg, MSG_ERRQUEUE | MSG_DONTWAIT);
	if (res < 0) {
		if (errno == EAGAIN || errno == EINTR)
			local_errors++;
	} else {
		struct sock_extended_err *ee = NULL;
		for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c))
			if ((c->cmsg_level == IPPROTO_IPV6) && (c->cmsg_type == IPV6_RECVERR))
				ee = (struct sock_extended_err *)CMSG_DATA(c);
		if (!ee)
			abort();
		if (ee->ee_origin == SO_EE_ORIGIN_LOCAL) {
			local_errors++;
			rts->nerrors++;
			if (!rts->opt.quiet)
				print_local_ee(rts, ee);
		} else if (ee->ee_origin == SO_EE_ORIGIN_ICMP6) {
			struct sockaddr_in6 *to = (struct sockaddr_in6 *)&rts->whereto;
			if ((res < (ssize_t)sizeof(icmp))                 ||
			    memcmp(&target.sin6_addr, &to->sin6_addr, 16) ||
			    (icmp.icmp6_type != ICMP6_ECHO_REQUEST)       ||
			    !IS_OURS(rts, sock->raw, icmp.icmp6_id)) {
				/* Not our error, not an error at all, clear */
				saved_errno = 0;
			} else {
				net_errors++;
				rts->nerrors++;
				print_addr_seq(rts, ntohs(icmp.icmp6_seq), ee,
					sizeof(struct sockaddr_in6));
			}
		}
	}
	errno = saved_errno;
	return net_errors ? net_errors : -local_errors;
}


// func_set:parse_reply:fin
static inline void ping6_parse_reply_fin(bool audible, bool flood) {
	if (audible) {
		putchar('\a');
		if (flood)
			fflush(stdout);
	}
	if (!flood) {
		putchar('\n');
		fflush(stdout);
	}
}

static inline int ping6_icmp_extra_type(state_t *rts,
		const struct icmp6_hdr *icmp, size_t received, bool raw,
		const struct sockaddr_in6 *from, const struct sockaddr_in6 *to)
{
	const struct ip6_hdr   *iph  = (struct ip6_hdr   *)(icmp + 1);
	const struct icmp6_hdr *orig = (struct icmp6_hdr *)(iph  + 1);
	if (received < (sizeof(struct ip6_hdr) + 2 * sizeof(struct icmp6_hdr)))
		return true;
	if (memcmp(&iph->ip6_dst, &to->sin6_addr, sizeof(to->sin6_addr)))
		return true;
	//
	uint8_t next = iph->ip6_nxt;
	if (next == IPPROTO_FRAGMENT) {
		next = *(uint8_t *)orig;
		orig++;
	}
	if (next == IPPROTO_ICMPV6) {
		if (orig->icmp6_type != ICMP6_ECHO_REQUEST ||
		    !IS_OURS(rts, raw, orig->icmp6_id))
			return true;
		acknowledge(rts, ntohs(orig->icmp6_seq));
		return false;
	}
	//
	/* We've got something other than an ECHOREPLY */
	if (!rts->opt.verbose || rts->uid)
		return true;
	PRINT_TIMESTAMP;
	printf("%s %s: ", _("From"), sprint_addr(from, sizeof(*from), rts->opt.resolve));
	print6_icmp(icmp->icmp6_type, icmp->icmp6_code, ntohl(icmp->icmp6_mtu));
	return -1;
}

/*
 *	Print out the packet, if it came from us.  This logic is necessary
 * because ALL readers of the ICMP socket get a copy of ALL ICMP packets
 * which arrive ('tis only fair).  This permits multiple copies of this
 * program to be run without having intermingled output (or statistics!).
 */
// func_set:parse_reply
static bool ping6_parse_reply(state_t *rts, bool raw,
	struct msghdr *msg, size_t received, void *addr, const struct timeval *at)
{
	struct sockaddr_in6 *from = addr;
	uint8_t *base = msg->msg_iov->iov_base;

	int away = -1;
	for (struct cmsghdr *c = CMSG_FIRSTHDR(msg); c; c = CMSG_NXTHDR(msg, c)) {
		if (c->cmsg_level == IPPROTO_IPV6)
			switch (c->cmsg_type) {
			case IPV6_HOPLIMIT:
#ifdef IPV6_2292HOPLIMIT
			case IPV6_2292HOPLIMIT:
#endif
				if (c->cmsg_len >= CMSG_LEN(sizeof(int)))
					memcpy(&away, CMSG_DATA(c), sizeof(away));
				break;
			default: break;
			}
	}

	RETURN_IF_TOO_SHORT(received, sizeof(struct icmp6_hdr));

	/* Now the ICMP part */
	struct icmp6_hdr *icmp = (struct icmp6_hdr *)base;
	struct sockaddr_in6 *whereto = (struct sockaddr_in6 *)&rts->whereto;

	if (icmp->icmp6_type == ICMP6_ECHO_REPLY) {
		if (!IS_OURS(rts, raw, icmp->icmp6_id))
			return true;
		stat_aux_t stat = {
			.from = sprint_addr(from, sizeof(*from), rts->opt.resolve),
			.seq  = ntohs(icmp->icmp6_seq),
			.rcvd = received,
			.tv   = at,
			.icmp = (const uint8_t *)icmp,
			.data = (const uint8_t *)(icmp + 1),
			.ack  = true,
			.okay = !memcmp(&from->sin6_addr.s6_addr, &whereto->sin6_addr.s6_addr, 16)
				|| rts->multicast || rts->subnet_router_anycast,
			.away = away,
		};
		if (statistics(rts, &stat))
				return false;
	}
#ifdef ENABLE_RFC4620
	else if (icmp->icmp6_type == IPUTILS_NI_ICMP6_REPLY) {
		if (!rts->ni)
			return true;
		struct ni_hdr *nih = (struct ni_hdr *)icmp;
		int seq = niquery_check_nonce(rts->ni, nih->ni_nonce);
		if (seq < 0)
			return true;
		stat_aux_t stat = {
			.from  = sprint_addr(from, sizeof(*from), rts->opt.resolve),
			.seq   = ntohs(icmp->icmp6_seq),
			.rcvd  = received,
			.tv    = at,
			.icmp  = (const uint8_t *)icmp,
			.data  = (const uint8_t *)(icmp + 1),
			.ack   = true,
			.okay  = true,
			.away  = away,
			.print = print6_ni_reply,
		};
		if (statistics(rts, &stat))
				return false;
	}
#endif
	else {
		/* We must not ever fall here. All the messages but
		 * echo reply are blocked by filter and error are
		 * received with IPV6_RECVERR. Ugly code is preserved
		 * however, just to remember what crap we avoided
		 * using RECVRERR. :-)
		 */
		int rc = ping6_icmp_extra_type(rts, icmp, received, raw, from, whereto);
		if (rc >= 0)
			return rc;
	}
	ping6_parse_reply_fin(rts->opt.audible, rts->opt.flood);
	return false;
}

static inline bool get_subnet_anycast(const struct sockaddr_in6 *whereto) {
	/* detect Subnet-Router anycast at least for the default prefix 64 */
	for (size_t i = 8; i < sizeof(struct in6_addr); i++)
		if (whereto->sin6_addr.s6_addr[i])
			return false;
	return true;
}

static void ping6_bpf_filter(const state_t *rts, const sock_t *sock) {
	struct sock_filter filter[] = { // no need to be static?
		BPF_STMT(BPF_LD	 | BPF_H   | BPF_ABS, 4),	/* Load ident */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
			htons(rts->ident16), 			/* Compare ident */
			0, 1),
		BPF_STMT(BPF_RET | BPF_K, ~0U),			/* Okay, it's ours */
		BPF_STMT(BPF_LD  | BPF_B   | BPF_ABS, 0),	/* Load type */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
			ICMP6_ECHO_REPLY, 			/* Compare type */
			1, 0),
		BPF_STMT(BPF_RET | BPF_K, ~0U),			/* Okay, pass it down */
		BPF_STMT(BPF_RET | BPF_K, 0), 			/* Reject not our echo replies */
	};
	const struct sock_fprog fprog = {
		.len    = ARRAY_SIZE(filter),
		.filter = filter,
	};
	setsock_bpf(rts, sock, &fprog);
}

/* Return >= 0: exit with this code, < 0: go on to next addrinfo result */
int ping6_run(state_t *rts, int argc, char **argv,
		struct addrinfo *ai, const sock_t *sock)
{
	fnset_t ping6_func_set = {
		.bpf_filter	= ping6_bpf_filter,
		.send_probe     = ping6_send_probe,
		.receive_error  = ping6_receive_error,
		.parse_reply    = ping6_parse_reply,
	};

	rts->ip6 = true;
	cmsg_t cmsg6 = {0};
	rts->cmsg = &cmsg6;

	struct sockaddr_in6 *source   = (struct sockaddr_in6 *)&rts->source;
	struct sockaddr_in6 *firsthop = (struct sockaddr_in6 *)&rts->firsthop;
	struct sockaddr_in6 *whereto  = (struct sockaddr_in6 *)&rts->whereto;
	source->sin6_family = AF_INET6;

#ifdef ENABLE_RFC4620
	if (rts->ni && niquery_is_enabled(rts->ni)) {
		niquery_init_nonce(rts->ni);
		if (!niquery_is_subject_valid(rts->ni)) {
			rts->ni->subject      = &whereto->sin6_addr;
			rts->ni->subject_len  = sizeof(whereto->sin6_addr);
			rts->ni->subject_type = IPUTILS_NI_ICMP6_SUBJ_IPV6;
		}
	}
#endif

	char *target = NULL;
	if (argc > 1) {
		usage(EINVAL);
	} else if (argc == 1) {
		target = *argv;
	}
#ifdef ENABLE_RFC4620
	else if (rts->ni) {
		if ((rts->ni->query < 0) && (rts->ni->subject_type != IPUTILS_NI_ICMP6_SUBJ_FQDN))
			usage(EINVAL);
		target = rts->ni->group;
	}
#endif

	memcpy(whereto, ai->ai_addr, sizeof(*whereto));
	whereto->sin6_port = htons(IPPROTO_ICMPV6);

	if (target && memchr(target, ':', strlen(target)))
		rts->opt.resolve = false;

	if (IN6_IS_ADDR_UNSPECIFIED(&firsthop->sin6_addr)) {
		memcpy(&firsthop->sin6_addr, &whereto->sin6_addr, sizeof(firsthop->sin6_addr));
		firsthop->sin6_scope_id = whereto->sin6_scope_id;
		/* Verify scope_id is the same as intermediate nodes */
		static uint32_t scope_id;
		if (!scope_id)
			scope_id = firsthop->sin6_scope_id;
		else if (firsthop->sin6_scope_id && (firsthop->sin6_scope_id != scope_id))
			errx(EINVAL, "%s", _("Scope discrepancy among the nodes"));
	}

	rts->hostname = target;

	if (IN6_IS_ADDR_UNSPECIFIED(&source->sin6_addr)) {
		int probe_fd = socket(AF_INET6, SOCK_DGRAM, 0);
		if (probe_fd < 0)
			err(errno, "socket");

		bool scoped = IN6_IS_ADDR_LINKLOCAL(&firsthop->sin6_addr) ||
			      IN6_IS_ADDR_MC_LINKLOCAL(&firsthop->sin6_addr);
		if (rts->device) {
			unsigned iface = if_name2index(rts->device);
			struct in6_pktinfo ipi = { .ipi6_ifindex = iface };
			if ((setsockopt(probe_fd, IPPROTO_IPV6, IPV6_PKTINFO, &ipi, sizeof(ipi)) < 0) ||
			    (setsockopt(sock->fd, IPPROTO_IPV6, IPV6_PKTINFO, &ipi, sizeof(ipi)) < 0))
				err(errno, "setsockopt(%s, %s)", "IPV6_PKTINFO", rts->device);
			if (scoped)
				firsthop->sin6_scope_id = iface;
		}
		if (!scoped)
			firsthop->sin6_family = AF_INET6;
		sock_settos(probe_fd, rts->qos, rts->ip6);
		sock_setmark(rts, probe_fd);

		firsthop->sin6_port = htons(1025);
		if (connect(probe_fd, (struct sockaddr *)firsthop, sizeof(*firsthop)) < 0) {
			if ((errno == EHOSTUNREACH || errno == ENETUNREACH) && ai->ai_next) {
				close(probe_fd);
				return -1;
			}
			err(errno, "connect");
		}
		socklen_t socklen = sizeof(struct sockaddr_in6);
		if (getsockname(probe_fd, (struct sockaddr *)source, &socklen) < 0)
			err(errno, "getsockname");
		source->sin6_port = 0;
		close(probe_fd);

		if (rts->device)
			cmp_srcdev(rts);

	} else if (rts->device && (IN6_IS_ADDR_LINKLOCAL(&source->sin6_addr) ||
			      IN6_IS_ADDR_MC_LINKLOCAL(&source->sin6_addr)))
		source->sin6_scope_id = if_name2index(rts->device);

	if (rts->device && rts->cmsg) {
		struct cmsghdr *cmsg = (struct cmsghdr *)(rts->cmsg->data + rts->cmsg->len);
		cmsg->cmsg_len   = CMSG_LEN(sizeof(struct in6_pktinfo));
		cmsg->cmsg_level = IPPROTO_IPV6;
		cmsg->cmsg_type  = IPV6_PKTINFO;
		rts->cmsg->len  += CMSG_SPACE(sizeof(struct in6_pktinfo));

		struct in6_pktinfo *ipi = (struct in6_pktinfo *)CMSG_DATA(cmsg);
		memset(ipi, 0, sizeof(*ipi));
		ipi->ipi6_ifindex = if_name2index(rts->device);

		if (rts->opt.strictsource) {
			unsigned iface = if_name2index(rts->device);
			struct in6_pktinfo ipi = { .ipi6_ifindex = iface };
			if (setsockopt(sock->fd, IPPROTO_IPV6, IPV6_PKTINFO, &ipi, sizeof(ipi)) < 0)
				err(errno, "setsockopt(%s, %s)", "IPV6_PKTINFO", rts->device);
//			NET_RAW_ON;
//			int rc = setsockopt(sock->fd, SOL_SOCKET, SO_BINDTODEVICE,
//					rts->device, strlen(rts->device) + 1);
//			int keep = errno;
//			NET_RAW_OFF;
//			if (rc < 0) {
//				errno = keep;
//				err(errno, "setsockopt(%s): %s", "SO_BINDTODEVICE", rts->device);
//			}
		}
	}

	if (IN6_IS_ADDR_MULTICAST(&whereto->sin6_addr))
		pmtu_interval(rts);

	if (sock->raw) {
		int csum_offset = 2;
		if (setsockopt(sock->fd, SOL_RAW, IPV6_CHECKSUM, &csum_offset, sizeof(csum_offset)) < 0)
		/* checksum should be enabled by default and setting this option might fail anyway */
			warn("setsockopt(%s)", "RAW_CHECKSUM");
		/* select icmp echo reply as icmp type to receive */
		struct icmp6_filter filter = {0};
		ICMP6_FILTER_SETBLOCKALL(&filter);
#ifdef ENABLE_RFC4620
		if (rts->ni && niquery_is_enabled(rts->ni))
			ICMP6_FILTER_SETPASS(IPUTILS_NI_ICMP6_REPLY, &filter);
		else
#endif
			ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &filter);
		if (setsockopt(sock->fd, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter)) < 0)
			err(errno, "setsockopt(%s)", "ICMP6_FILTER");
	}

	if (rts->opt.noloop)
		setsock_noloop(sock->fd, rts->ip6);
	if (rts->ttl >= 0)
		setsock_ttl(sock->fd, rts->ip6, rts->ttl);

	{ int on = 1;
	  if (
#ifdef IPV6_RECVHOPLIMIT
	(setsockopt(sock->fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &on, sizeof(on)) < 0) &&
	(setsockopt(sock->fd, IPPROTO_IPV6, IPV6_2292HOPLIMIT, &on, sizeof(on)) < 0)
#else
	(setsockopt(sock->fd, IPPROTO_IPV6, IPV6_HOPLIMIT,     &on, sizeof(on)) < 0)
#endif
	  ) err(errno, "setsockopt(%s)", "IPV6_RECVHOPLIMIT, enable");
	}

	if (rts->opt.flowinfo) {
		char buf[CMSG_ALIGN(sizeof(struct in6_flowlabel_req)) + rts->cmsg->len];
		memset(buf, 0, sizeof(buf));
		struct in6_flowlabel_req *freq = (struct in6_flowlabel_req *)buf;
		freq->flr_label  = htonl(rts->flowlabel & IPV6_FLOWINFO_FLOWLABEL);
		freq->flr_action = IPV6_FL_A_GET;
		freq->flr_flags  = IPV6_FL_F_CREATE;
		freq->flr_share  = IPV6_FL_S_EXCL;
		memcpy(&freq->flr_dst, &whereto->sin6_addr, sizeof(whereto->sin6_addr));
		if (setsockopt(sock->fd, IPPROTO_IPV6, IPV6_FLOWLABEL_MGR, freq, sizeof(*freq)) < 0)
			err(errno, "setsockopt(%s)", "IPV6_FLOWLABEL");
		whereto->sin6_flowinfo = rts->flowlabel = freq->flr_label;
		int on = 1;
		if (setsockopt(sock->fd, IPPROTO_IPV6, IPV6_FLOWINFO_SEND, &on, sizeof(on)) < 0)
			err(errno, "setsockopt(%s)", "IPV6_FLOWINFO");
	}

	rts->subnet_router_anycast = get_subnet_anycast(whereto);
	mtudisc_n_bind(rts, sock);
	setsock_recverr(sock->fd, rts->ip6);
	set_estimate_buf(rts, sock->fd, sizeof(struct ip6_hdr), 0, sizeof(struct icmp6_hdr));

	size_t hlen = sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr);
	headline(rts, hlen);
	hlen += MAX_CMSG_SIZE + sizeof(struct icmp6_hdr); // ip + cmsg + icmp*2
	return setup_n_loop(rts, hlen, sock, &ping6_func_set);
}

