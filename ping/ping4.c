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
// part of ping.c

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
//#include <linux/icmp.h> /* conflicted with <netinet/ip_icmp.h> */

#include "ping4.h"
#include "iputils.h"
#include "common.h"
#include "stats.h"
#include "ping_aux.h"
#include "ping4_aux.h"
#include "ping4_opt.h"
#include "setsock.h"
#include "nbind.h"
#include "nlink.h"

// ICMP_FILTER is defined in <linux/icmp.h>
#ifndef ICMP_FILTER
#define ICMP_FILTER	1
struct icmp_filter {
	uint32_t data;
};
#endif

/*
 * 	Compose and transmit an ICMP ECHO REQUEST packet.  The IP packet
 * will be added on by the kernel.  The ID field is our UNIX process ID,
 * and the sequence number is an ascending integer.  The first several bytes
 * of the data portion are used to hold a UNIX "timeval" struct in VAX
 * byte-order, to compute the round-trip time.
 */
// func_set:send_probe
static ssize_t ping4_send_probe(state_t *rts, int fd, uint8_t *packet) {
	struct icmphdr *icmp = (struct icmphdr *)packet;
	icmp->type             = ICMP_ECHO;
	icmp->code             = 0;
	icmp->checksum         = 0;
	icmp->un.echo.sequence = htons(rts->ntransmitted + 1);
	icmp->un.echo.id       = rts->ident16;
	if (rts->timing) {
		bool lat = rts->opt.latency;
		if (lat) {
			struct timeval tv;
			lat = !gettimeofday(&tv, NULL);
			if (lat)
				memcpy(icmp + 1, &tv, sizeof(tv));
		}
		if (!lat)
			memset(icmp + 1, 0, sizeof(struct timeval));
	}
	// note: timestamp is accounted in data area
	ssize_t len = sizeof(struct icmphdr) + rts->datalen;

	/* compute ICMP checksum here */
	icmp->checksum = in_cksum((uint16_t *)icmp, len, 0);
	if (rts->timing && !rts->opt.latency) {
		struct timeval tv = {0};
		gettimeofday(&tv, NULL);
		memcpy(icmp + 1, &tv, sizeof(tv));
		icmp->checksum = in_cksum((uint16_t *)&tv, sizeof(tv), ~icmp->checksum);
	}

	ssize_t rc = sendto(fd, packet, len, 0, SA(&rts->whereto), SA4_LEN);
	return (rc == len) ? 0 : rc;
}


// func_set:receive_error:...
static inline void setsock4_icmp_filter(int fd) {
	struct icmp_filter filt = { .data = ~(
		(1 << ICMP_SOURCE_QUENCH) |
		(1 << ICMP_REDIRECT)      |
		(1 << ICMP_ECHOREPLY)
	)};
	if (setsockopt(fd, SOL_RAW, ICMP_FILTER, &filt, sizeof(filt)) < 0)
		err(errno, "setsockopt(%s)", "ICMP_FILTER");
}

// aux_fn:addr_equal
static bool addr4equal(const struct sockaddr *a, const struct sockaddr_storage *b) {
	return !memcmp(&SA4_IN(a), &SA4_IN(b), sizeof(struct in_addr));
}
// aux_fn:eerr_extra
static void icmp4_ee_extra(state_t *rts, const sock_t *sock, uint16_t seq) {
	acknowledge(rts, seq);
	static bool icmp4_filter_applied;
	if (sock->raw && !icmp4_filter_applied) {
		/* Set additional filter */
		setsock4_icmp_filter(sock->fd);
		icmp4_filter_applied = true;
	}
}

// func_set:receive_error
static int ping4_receive_error(state_t *rts, const sock_t *sock) {
	char cbuf[512] = {0};
	struct icmphdr icmp = {0};
	struct iovec iov = { .iov_base = &icmp, .iov_len = sizeof(icmp) };
	struct sockaddr_in sa = {0};
	struct msghdr msg = {
		.msg_name       = &sa,
		.msg_namelen    = sizeof(sa),
		.msg_iov        = &iov,
		.msg_iovlen     = 1,
		.msg_control    = cbuf,
		.msg_controllen = sizeof(cbuf),
	};
	return get_errmsg(rts, sock, &msg);
}

static inline void print_ipicmp4hdr(const struct icmphdr *icmp, const struct iphdr *ip,
	const bool_opt_t *opt, uint8_t color)
{
	uint32_t gw = ntohl(icmp->un.gateway);
	if (print_icmp4msg(icmp->type, icmp->code, gw, gw, opt, color))
		if (opt->verbose)
			print_ip4hdr(ip, opt->resolve, opt->flood);
}

static inline bool ping4_icmp_extra_type(state_t *rts,
	const struct icmphdr *icmp, size_t received,
	const struct sockaddr_in *from, bool raw, bool bad, uint8_t color)
{
	const struct iphdr *iph = (struct iphdr *)(icmp + 1);
	uint8_t ihl = iph->ihl * 4;
	const struct icmphdr *orig = (struct icmphdr *)((unsigned char *)iph + ihl);
	if ((received < (sizeof(struct iphdr) + 2 * sizeof(struct icmphdr))) ||
	    (received < (ihl                  + 2 * sizeof(struct icmphdr))))
			return true;
	if ((orig->type != ICMP_ECHO)              ||
	    (iph->daddr != SA4ADDR(&rts->whereto)) ||
	    !IS_OURS(rts, raw, orig->un.echo.id))
		return true;
	if ((icmp->type != ICMP_REDIRECT) && (icmp->type != ICMP_SOURCE_QUENCH)) {
		acknowledge(rts, ntohs(orig->un.echo.sequence));
		return false;
	}
	if (rts->opt.quiet || rts->opt.flood)
		return true;
	PRINT_TIMESTAMP;
	printf("%s %s: %s=%u ",
		_("From"), sprint_addr(from, sizeof(*from), rts->opt.resolve),
		_("icmp_seq"), ntohs(orig->un.echo.sequence));
	if (bad)
		printf("(%s!)", _("BAD CHECKSUM"));
	print_ipicmp4hdr(icmp, iph, &rts->opt, color);
	putchar('\n');
	return true;
}

/*
 *	Print out the packet, if it came from us.  This logic is necessary
 * because ALL readers of the ICMP socket get a copy of ALL ICMP packets
 * which arrive ('tis only fair).  This permits multiple copies of this
 * program to be run without having intermingled output (or statistics!).
 */
// func_set:parse_reply
static bool ping4_parse_reply(state_t *rts, bool raw, struct msghdr *msg,
	size_t received, void *addr, const struct timeval *at)
{
	uint8_t *base = msg->msg_iov->iov_base;
	/* Check the IP header */
	struct iphdr *ip = (struct iphdr *)base;
	uint8_t *opts = base;
	ssize_t olen  =  0;
	size_t  hlen  =  0;
	int away      = -1;
	if (raw) {
		hlen = ip->ihl * 4;
		if ((received < (hlen + sizeof(struct icmphdr))) || (ip->ihl < 5)) {
			if (rts->opt.verbose)
				warnx("%s: %s (%zd %s)",
					sprint_addr(SA4(addr), SA4_LEN, rts->opt.resolve),
					_("Packet too short"), received, BYTES(received));
			return true;
		}
		away  = ip->ttl;
		// options (without header)
		opts += sizeof(struct iphdr);
		olen  = (ssize_t)hlen - sizeof(struct iphdr);
	} else for (struct cmsghdr *c = CMSG_FIRSTHDR(msg); c; c = CMSG_NXTHDR(msg, c)) {
		if (c->cmsg_level == IPPROTO_IP) switch (c->cmsg_type) {
			case IP_TTL:
				CMSG_INT(c, &away);
				break;
			case IP_RETOPTS:
				// options (without header)
				opts = (uint8_t *)CMSG_DATA(c);
				olen = (ssize_t)c->cmsg_len - CMSG_LEN(0);
				break;
			default: break;
		}
	}

	RETURN_IF_TOO_SHORT(received, hlen + sizeof(struct icmphdr));
	received -= hlen;

	/* Now the ICMP part */
	struct icmphdr *icmp = (struct icmphdr *)(base + hlen);

	if (icmp->type == ICMP_ECHOREPLY) {
		if (!IS_OURS(rts, raw, icmp->un.echo.id))
			return true;	// 'Twas not our ECHO
		stat_aux_t stat = {
			.from = sprint_addr(SA4(addr), SA4_LEN, rts->opt.resolve),
			.seq  = ntohs(icmp->un.echo.sequence),
			.rcvd = received,
			.tv   = at,
			.icmp = (const uint8_t *)icmp,
			.data = (const uint8_t *)(icmp + 1),
			.ack  = !in_cksum((uint16_t *)icmp, received, 0),
			.okay = rts->multicast || rts->opt.broadcast ||
			        addr4equal(addr, &rts->whereto),
			.away = away,
		};
		if (statistics(rts, &stat))
			return false;
	} else {
		/* We fall here when a redirect or source quench arrived */
		bool bad = (in_cksum((uint16_t *)icmp, received, 0) != 0);
		switch (icmp->type) {
		case ICMP_ECHO:
			/* MUST NOT */
			return true;
		case ICMP_SOURCE_QUENCH:
		case ICMP_REDIRECT:
		case ICMP_DEST_UNREACH:
		case ICMP_TIME_EXCEEDED:
		case ICMP_PARAMETERPROB:
			return ping4_icmp_extra_type(rts, icmp, received, SA4(addr), raw, bad, rts->yellow);
		default: /* MUST NOT */
			break;
		}
		if (rts->opt.flood && !(rts->opt.verbose || rts->opt.quiet)) {
			if (write(STDOUT_FILENO, "!EC", bad ? 3 : 2)) {};
//			otherwise: (void)!write
			return false;
		}
		if (!rts->opt.verbose || rts->uid)
			return false;
		if (rts->opt.ptimeofday) {
			struct timeval tm;
			if (!gettimeofday(&tm, NULL))
				printf("%lu.%06lu ", (unsigned long)tm.tv_sec, (unsigned long)tm.tv_usec);
		}
		printf("%s %s: ", _("From"), sprint_addr(SA4(addr), SA4_LEN, rts->opt.resolve));
		if (bad) {
			printf("(%s!)\n", _("BAD CHECKSUM"));
			return false;
		}
		print_ipicmp4hdr(icmp, (struct iphdr *)(icmp + 1), &rts->opt, rts->red);
		putchar('\n');
		fflush(stdout);
		return false;
	}
	if (rts->opt.audible) {
		putchar('\a');
		if (rts->opt.flood)
			fflush(stdout);
	}
	if (!rts->opt.flood) {
		print4_ip_opts(opts, olen, rts->opt.resolve, rts->opt.flood);
		putchar('\n');
		fflush(stdout);
	}
	return false;
}

static inline void set_opt_ts(int fd, struct ip_timestamp *opt, uint8_t flg, uint8_t len) {
	if (len % 4)
		err(EINVAL, _("timestamp length is not a multiple of 4"));
	opt->ipt_code = IPOPT_TIMESTAMP,
	opt->ipt_len  = len;
	opt->ipt_ptr  = 5;
	opt->ipt_flg  = flg;
	if (setsockopt(fd, IPPROTO_IP, IP_OPTIONS, opt, opt->ipt_len) < 0) {
//		opt->ipt_flg = 2; // ???
//		if (setsockopt(fd, IPPROTO_IP, IP_OPTIONS, opt, opt->ipt_len) < 0)
		err(errno, _("timestamp option"));
	}
}

static inline void set_opt_rr(int fd, pre_noped_ipopt_t *opt) {
	opt->nop = IPOPT_NOP;
	opt->val = IPOPT_RR;
	opt->len = sizeof(pre_noped_ipopt_t) - sizeof(((pre_noped_ipopt_t*)0)->nop); /*39*/
	opt->off = IPOPT_MINOFF;
	if (setsockopt(fd, IPPROTO_IP, IP_OPTIONS, opt, sizeof(*opt)) < 0)
		err(errno, _("record route"));
}

static inline void set_opt_xrr(int fd, pre_noped_ipopt_t *opt, uint8_t val, uint8_t len) {
	opt->nop = IPOPT_NOP;
	opt->val = val;
	opt->len = len;
	opt->off = IPOPT_MINOFF;
	if (setsockopt(fd, IPPROTO_IP, IP_OPTIONS, opt, len + 1) < 0)
		err(errno, "%s: %s(%d)", _("record route"),
			val == IPOPT_SSRR ? "IPOPT_SSRR" :
			val == IPOPT_LSRR ? "IPOPT_LSRR" :
			"?", val);
}

static void ping4_bpf_filter(const state_t *rts, const sock_t *sock) {
	struct sock_filter filter[] = { // no need to be static?
		BPF_STMT(BPF_LDX | BPF_B   | BPF_MSH, 0),	/* Skip IP header due BSD */
		BPF_STMT(BPF_LD  | BPF_H   | BPF_IND, 4),	/* Load ident */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
			htons(rts->ident16),			/* Compare ident */
			0, 1),
		BPF_STMT(BPF_RET | BPF_K, ~0U),			/* Okay, it's ours */
		BPF_STMT(BPF_LD  | BPF_B   | BPF_IND, 0),	/* Load type */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
			ICMP_ECHOREPLY,				/* Compare type */
			1, 0),
		BPF_STMT(BPF_RET | BPF_K, ~0U),			/* Okay, pass it down */
		BPF_STMT(BPF_RET | BPF_K, 0),			/* Reject not our echo replies */
	};
	const struct sock_fprog fprog = {
		.len    = ARRAY_LEN(filter),
		.filter = filter,
	};
	setsock_filter(sock->fd, &fprog, rts->opt.verbose, '4', rts->ident16);
}

static inline const char *ping4_run_args(const char *target, bool hops, struct addrinfo *ai,
	char *hname, size_t hlen, struct sockaddr_in *to, struct ip_timestamp *ipt)
{
	const char *hostname = NULL; // return ref
	memset(to, 0, SA4_LEN);
	to->sin_family = AF_INET;
	if (inet_aton(target, &to->sin_addr) == 1)
		hostname = target;
	else {
		struct addrinfo *res = ai;
		if (hops) {
			const struct addrinfo hints = {
				.ai_family = AF_INET,
				.ai_flags  = AI_FLAGS,
			};
			int rc = GAI_WRAPPER(target, NULL, &hints, &res);
			if (rc) {
				if (rc == EAI_SYSTEM)
					err(errno, "%s", "getaddrinfo()");
				errx(rc, TARGET_FMT ": %s", target, gai_strerror(rc));
			}
		}
		if (!res)
			errx(EXIT_FAILURE, "%s", "getaddrinfo()");
		memcpy(to, res->ai_addr, SA4_LEN);
		/*
		 * On certain network setup getaddrinfo() can return empty
		 * ai_canonname. Instead of printing nothing in "PING"
		 * line use the target.
		 */
		strncpy(hname, res->ai_canonname ? res->ai_canonname : target, hlen - 1);
		hostname = hname;
		if (hops)
			freeaddrinfo(res);
	}
	if (hops && ipt) {
		if ((ipt->ipt_len * 2) < (ARRAY_LEN(ipt->data) - 1)) {
			ipt->data[ipt->ipt_len * 2] = to->sin_addr.s_addr;
			ipt->ipt_len++;
		} else
			errx(EINVAL, "%s, %s=%zd", _("Too many intermediate hops"),
				_("max"), ARRAY_LEN(ipt->data) / 2);
	}
	return hostname;
}

static int probe_dst4(state_t *rts, struct sockaddr_in dst, int sock_fd, bool next) {
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		err(errno, "socket");
	if (rts->device) {
//		struct in_pktinfo ipi = { .ipi_ifindex = if_name2index(rts->device) };
//		if ((setsockopt(fd,      IPPROTO_IP, IP_PKTINFO, &ipi, sizeof(ipi)) < 0) ||
//		    (setsockopt(sock_fd, IPPROTO_IP, IP_PKTINFO, &ipi, sizeof(ipi)) < 0))
//			err(errno, "setsockopt(%s, %s)", "IP_PKTINFO", rts->device);
		if ((bindtodev(fd, rts->device) < 0) || (bindtodev(sock_fd, rts->device) < 0))
			err(errno, "%s", rts->device);
	}
	if (rts->tos)
		setsock_tos(fd, rts->tos, rts->ip6);
#ifdef SO_MARK
	if (rts->mark >= 0)
		setsock_mark(fd, rts->mark); // privileged action
#endif
	dst.sin_port = htons(1025);
	if (rts->ipopt.ipt && rts->ipopt.ipt->ipt_len)
		dst.sin_addr.s_addr = rts->ipopt.ipt->data[0]; // note: `dst' is a copy
	if (connect(fd, SA(&dst), SA4_LEN) >= 0)
		return fd;
	//
	switch (errno) {
	case EACCES: {
#define WANT_BRD _("Do you want to ping broadcast? Then -b. If not, check your local firewall rules")
		if (!rts->opt.broadcast)
			errx(EINVAL, WANT_BRD);
		warnx("%s: %s", _WARN, _("Pinging broadcast address"));
		int opt = rts->opt.broadcast;
		if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt)) < 0)
			err(errno, "%s", _("Cannot set broadcasting"));
		if (connect(fd, SA(&dst), SA4_LEN) >= 0)
			return fd;
	}	break;
	case EHOSTUNREACH:
	case ENETUNREACH:
		if (next) {
			close(fd);
			return -1;
		}
		break;
	}
	//
	err(errno, "connect");
}

// take next addrinfo if `rc' < 0, otherwise exit with `rc'
int ping4_run(state_t *rts, int argc, char **argv, struct addrinfo *ai, const sock_t *sock) {
	fnset_t ping4_func_set = {
		.bpf_filter     = ping4_bpf_filter,
		.send_probe     = ping4_send_probe,
		.parse_reply    = ping4_parse_reply,
		.receive_error  = ping4_receive_error,
	};
	rts->ee_aux = (struct ee_aux){
		.echo_value  = ICMP_ECHO,
		.ee_origin   = SO_EE_ORIGIN_ICMP,
		.ee_level    = IPPROTO_IP,
		.ee_type     = IP_RECVERR,
		.addr_equal  = addr4equal,
		.eerr_extra  = icmp4_ee_extra,
	};
	uint8_t ipopt_space[MAX_IPOPTLEN] = {0};
	rts->ipopt.u8 = ipopt_space;
	rts->ip6 = false;
	SA4(&rts->source)->sin_family = AF_INET;
	//
	char hnamebuf[NI_MAXHOST] = {0};
	int arg_cnt = 0;
	for (; argc > 0; argc--, argv++) {
		if (validate_hostlen(*argv, false))
			errno = 0;
		else {
			const char *target = ping4_run_args(*argv, argc > 1, ai, hnamebuf, sizeof(hnamebuf),
				(struct sockaddr_in *)&rts->whereto, rts->ipopt.ipt);
			if (target)
				rts->hostname = target;
			if ((argc == 1) && (target == *argv))
				rts->opt.resolve = false;
			arg_cnt++;
		}
	}
	if (rts->ipopt.ipt->ipt_len) { // counter -> size (header + data)
		rts->ipopt.ipt->ipt_len *= 2 * sizeof(rts->ipopt.ipt->data[0]); // *= 8
		rts->ipopt.ipt->ipt_len += 4;
	}
	if (arg_cnt > 1) {
		if (rts->opt.rroute)
			usage(EINVAL);
		else if (rts->ts_opt < 0)
			rts->opt.sourceroute = true;
		else if (rts->ts_opt != IPOPT_TS_PRESPEC)
			errx(EINVAL, "%s", _("Only TSPRESPEC is allowed with intermediate hops"));
		else if ((size_t)argc > ARRAY_LEN(((struct ip_timestamp *)0)->data))
			errx(EINVAL, "%s: %d (%s=%zd)", _("Too many intermediate TS hops"), argc,
				_("max"), ARRAY_LEN(((struct ip_timestamp *)0)->data) - 1);
	} else if (rts->ts_opt == IPOPT_TS_PRESPEC)
		errx(EINVAL, "%s", _("No intermediate hops for TSPRESPEC"));

	if (!SA4ADDR(&rts->source)) {
		int fd = probe_dst4(rts, *SA4(&rts->whereto), sock->fd, ai->ai_next);
		if (fd < 0)
			return -1;
		GETSOCKNAME(fd, SA(&rts->source), SA4_LEN);
		SA4(&rts->source)->sin_port = 0;
		close(fd);
		if (rts->device && !nl_name2ndx(rts->device)) {
			warnx("%s: %s: %s", _WARN, rts->device, WARN_NOSRCDEV);
			rts->unreldev = true;
		}
	} else if (rts->device && (bindtodev(sock->fd, rts->device) < 0)) {
		if (!errno) errno = ENODEV;
			err(errno, NETDEV_FMT, rts->device);
	}

	if (!SA4ADDR(&rts->whereto))
		SA4ADDR(&rts->whereto) = SA4ADDR(&rts->source);

	if (rts->opt.broadcast || IN_MULTICAST(ntohl(SA4ADDR(&rts->whereto))))
		pmtu_interval(rts);

	if (sock->raw) {
		struct icmp_filter filt = { .data = ~(
			(1 << ICMP_SOURCE_QUENCH) |
			(1 << ICMP_DEST_UNREACH)  |
			(1 << ICMP_TIME_EXCEEDED) |
			(1 << ICMP_PARAMETERPROB) |
			(1 << ICMP_REDIRECT)      |
			(1 << ICMP_ECHOREPLY)
		)};
		if (setsockopt(sock->fd, SOL_RAW, ICMP_FILTER, &filt, sizeof(filt)) < 0)
			warn("%s: setsockopt(%s)", _WARN, "ICMP_FILTER");
	} else {
		int on = 1;
		if (setsockopt(sock->fd, IPPROTO_IP, IP_RECVTTL, &on, sizeof(on)) < 0)
			warn("%s: setsockopt(%s)", _WARN, "IP_RECVTTL");
		if (setsockopt(sock->fd, IPPROTO_IP, IP_RETOPTS, &on, sizeof(on)) < 0)
			warn("%s: setsockopt(%s)", _WARN, "IP_RETOPTS");
	}

	if (rts->opt.broadcast) {
		int opt = 1;
		if (setsockopt(sock->fd, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt)) < 0)
			err(errno, "%s", _("Cannot set broadcasting"));
	}

	if (rts->opt.noloop)
		setsock_noloop(sock->fd, rts->ip6);
	if (rts->ttl >= 0)
		setsock_ttl(sock->fd, rts->ip6, rts->ttl);
	if (rts->opt.connect_sk)
		if (connect(sock->fd, SA(&rts->whereto), SA4_LEN) < 0)
			err(errno, "%s", "connect()");

	mtudisc_n_bind(rts, sock);
	setsock_recverr(sock->fd, rts->ip6);
	//
	int optlen = ((rts->ts_opt >= 0) || rts->opt.rroute || rts->opt.sourceroute) ?
		MAX_IPOPTLEN : 0;
	if (optlen) { // rr, ts, etc. - exclusive?
		if (rts->ts_opt >= 0)
			set_opt_ts(sock->fd, rts->ipopt.ipt, rts->ts_opt,
				(rts->ts_opt == IPOPT_TS_PRESPEC) ? rts->ipopt.ipt->ipt_len :
				(rts->ts_opt == IPOPT_TS_TSONLY)  ? MAX_IPOPTLEN            :
				(MAX_IPOPTLEN - 4));
		else if (rts->opt.rroute)
			set_opt_rr(sock->fd, rts->ipopt.ipo);
		else if (rts->opt.sourceroute)
			set_opt_xrr(sock->fd, rts->ipopt.ipo,
				rts->opt.so_dontroute ? IPOPT_SSRR : IPOPT_LSRR,
				rts->ipopt.ipt->ipt_len - 4 - 1);
	}
	//
	if (!rts->sndbuf)
		rts->sndbuf = estimate_packlen(sizeof(struct iphdr) + optlen,
			sizeof(struct icmphdr), rts->datalen);
	setsock_buffer(sock->fd, rts->sndbuf, rts->preload);

	size_t hlen = sizeof(struct iphdr) + sizeof(struct icmphdr);
	headline(rts, hlen + optlen);
	hlen = (hlen + MAX_IPOPTLEN) * 2; // (ip+optlen+icmp)*2
	return setup_n_loop(rts, hlen, sock, &ping4_func_set);
}

