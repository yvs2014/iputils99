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

#include "iputils_common.h"
#include "common.h"
#include "ping_aux.h"
#include "ping4_aux.h"
#include "ping4.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

//#include <linux/icmp.h> /* conflicted with <netinet/ip_icmp.h> */
#include <linux/errqueue.h>

#ifndef ICMP_FILTER
#define ICMP_FILTER	1
struct icmp_filter {
	uint32_t data;
};
#endif

#define	MAXIPLEN	60
#define	MAXICMPLEN	76
#define	NROUTES		9		/* number of record route slots */

/*
 * 	Compose and transmit an ICMP ECHO REQUEST packet.  The IP packet
 * will be added on by the kernel.  The ID field is our UNIX process ID,
 * and the sequence number is an ascending integer.  The first several bytes
 * of the data portion are used to hold a UNIX "timeval" struct in VAX
 * byte-order, to compute the round-trip time.
 */
// func_set:send_probe
static ssize_t ping4_send_probe(struct ping_rts *rts, int sockfd,
		void *packet, unsigned packet_size __attribute__((__unused__)))
{
	struct icmphdr *icp = (struct icmphdr *)packet;
	icp->type = ICMP_ECHO;
	icp->code = 0;
	icp->checksum = 0;
	icp->un.echo.sequence = htons(rts->ntransmitted + 1);
	icp->un.echo.id = rts->ident16;

	if (rts->timing) {
		if (rts->opt.latency) {
			struct timeval tmp_tv;
			gettimeofday(&tmp_tv, NULL);
			memcpy(icp + 1, &tmp_tv, sizeof(tmp_tv));
		} else {
			memset(icp + 1, 0, sizeof(struct timeval));
		}
	}

	ssize_t len = rts->datalen + 8;	/* skips ICMP portion */
	/* compute ICMP checksum here */
	icp->checksum = in_cksum((unsigned short *)icp, len, 0);

	if (rts->timing && !rts->opt.latency) {
		struct timeval tmp_tv;
		gettimeofday(&tmp_tv, NULL);
		memcpy(icp + 1, &tmp_tv, sizeof(tmp_tv));
		icp->checksum = in_cksum((unsigned short *)&tmp_tv, sizeof(tmp_tv), ~icp->checksum);
	}

	ssize_t rc = sendto(sockfd, icp, len, 0, (struct sockaddr *)&rts->whereto, sizeof(struct sockaddr_in));
	return (rc == len) ? 0 : rc;
}


// func_set:receive_error:set_filter
static inline void ping4_raw_ack(int sockfd) {
	struct icmp_filter filt = { .data = ~(
		(1 << ICMP_SOURCE_QUENCH) |
		(1 << ICMP_REDIRECT)      |
		(1 << ICMP_ECHOREPLY)
	)};
	if (setsockopt(sockfd, SOL_RAW, ICMP_FILTER, &filt, sizeof(filt)) < 0)
		error(2, errno, "setsockopt(ICMP_FILTER)");
}

// func_set:receive_error
static int ping4_receive_error(struct ping_rts *rts, const socket_st *sock) {
	int saved_errno = errno;
	//
	char cbuf[512];
	struct icmphdr icmph = {0};
	struct iovec iov = { .iov_base = &icmph, .iov_len = sizeof(icmph) };
	struct sockaddr_in target = {0};
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
		for (struct cmsghdr *m = CMSG_FIRSTHDR(&msg); m; m = CMSG_NXTHDR(&msg, m))
			if ((m->cmsg_level == SOL_IP) && (m->cmsg_type == IP_RECVERR))
				ee = (struct sock_extended_err *)CMSG_DATA(m);
		if (!ee)
			abort();
		if (ee->ee_origin == SO_EE_ORIGIN_LOCAL) {
			local_errors++;
			if (!rts->opt.quiet)
				print_local_ee(rts, ee);
		} else if (ee->ee_origin == SO_EE_ORIGIN_ICMP) {
			struct sockaddr_in *sin = (struct sockaddr_in *)&rts->whereto;
			if ((res < (ssize_t)sizeof(icmph))                   ||
			    (target.sin_addr.s_addr != sin->sin_addr.s_addr) ||
			    (icmph.type != ICMP_ECHO)                        ||
			    !IS_OURS(rts, sock->raw, icmph.un.echo.id))
				/* Not our error, not an error at all, clear */
				saved_errno = 0;
			else {
				net_errors++;
				uint16_t seq = ntohs(icmph.un.echo.sequence);
				acknowledge(rts, seq);
				if (sock->raw)
					ping4_raw_ack(sock->fd);
				print_addr_seq(rts, seq, ee, sizeof(struct sockaddr_in));
			}
		}
	}
	errno = saved_errno;
	return net_errors ? net_errors : -local_errors;
}

static inline bool ping4_icmp_extra_type(struct ping_rts *rts,
		const struct icmphdr *icmp, size_t received,
		const struct sockaddr_in *from, bool raw, bool bad)
{
	const struct iphdr *iph = (struct iphdr *)(icmp + 1);
	const struct icmphdr *orig = (struct icmphdr *)((unsigned char *)iph + iph->ihl * 4);
	size_t minhl = 8 + iph->ihl * 4 + 8;
	if ((received < (8 + sizeof(struct iphdr) + 8)) || (received < minhl))
		return true;
	const struct sockaddr_in *sin = (struct sockaddr_in *)&rts->whereto;
	if ((orig->type != ICMP_ECHO)            ||
	    (iph->daddr != sin->sin_addr.s_addr) ||
	    !IS_OURS(rts, raw, orig->un.echo.id))
		return true;
	if ((icmp->type != ICMP_REDIRECT) && (icmp->type != ICMP_SOURCE_QUENCH)) {
		acknowledge(rts, ntohs(orig->un.echo.sequence));
		return false;
	}
	if (rts->opt.quiet || rts->opt.flood)
		return true;
	PRINT_TIMESTAMP;
	printf(_("From %s: icmp_seq=%u "),
	SPRINT_RES_ADDR(rts, from, sizeof(*from)), ntohs(orig->un.echo.sequence));
	if (bad)
		printf(_(" (BAD CHECKSUM!)"));
	print4_icmph(rts, icmp->type, icmp->code, ntohl(icmp->un.gateway), icmp);
	return true;
}

/*
 *	Print out the packet, if it came from us.  This logic is necessary
 * because ALL readers of the ICMP socket get a copy of ALL ICMP packets
 * which arrive ('tis only fair).  This permits multiple copies of this
 * program to be run without having intermingled output (or statistics!).
 */
// func_set:parse_reply
static bool ping4_parse_reply(struct ping_rts *rts, bool raw,
	struct msghdr *msg, size_t received, void *addr, const struct timeval *at)
{
	struct sockaddr_in *from = addr;
	uint8_t *base = msg->msg_iov->iov_base;

	/* Check the IP header */
	struct iphdr *ip = (struct iphdr *)base;
	size_t hlen   = 0;
	int reply_ttl = 0;
	uint8_t *opts = base;
	ssize_t olen  = 0;
	if (raw) {
		hlen = ip->ihl * 4;
		if ((received < (hlen + 8)) || (ip->ihl < 5)) {
			if (rts->opt.verbose)
				error(0, 0, _("packet too short (%zd bytes) from %s"), received,
					SPRINT_RES_ADDR(rts, from, sizeof(*from)));
			return true;
		}
		reply_ttl = ip->ttl;
		opts += sizeof(struct iphdr);
		olen = (ssize_t)hlen - sizeof(struct iphdr);
	} else for (struct cmsghdr *c = CMSG_FIRSTHDR(msg); c; c = CMSG_NXTHDR(msg, c)) {
		if (c->cmsg_level == SOL_IP)
			switch (c->cmsg_type) {
			case IP_TTL:
				if (c->cmsg_len >= sizeof(int)) {
					uint8_t *ttl = CMSG_DATA(c);
					reply_ttl = (int)*ttl;
				}
				break;
			case IP_RETOPTS:
				opts = (uint8_t *)CMSG_DATA(c);
				olen = c->cmsg_len;
				break;
			default: break;
			}
	}

	if (received < (hlen + 8)) {
		if (rts->opt.verbose)
			error(0, 0, _("packet too short: %zd bytes"), received);
		return true;
	}
	received -= hlen;

	/* Now the ICMP part */
	struct icmphdr *icmp = (struct icmphdr *)(base + hlen);

	if (icmp->type == ICMP_ECHOREPLY) {
		if (!IS_OURS(rts, raw, icmp->un.echo.id))
			return true;	/* 'Twas not our ECHO */
		struct sockaddr_in *sin = (struct sockaddr_in *)&rts->whereto;
		bool ack  = in_cksum((unsigned short *)icmp, received, 0) == 0;
		bool okay = (from->sin_addr.s_addr == sin->sin_addr.s_addr)
			|| rts->multicast || rts->opt.broadcast;
		if (gather_stats(rts, (uint8_t *)icmp, sizeof(*icmp), received,
			ntohs(icmp->un.echo.sequence), reply_ttl, at, NULL,
			SPRINT_RES_ADDR(rts, from, sizeof(*from)), ack, !okay))
				return false;
	} else {
		/* We fall here when a redirect or source quench arrived */
		bool bad = in_cksum((unsigned short *)icmp, received, 0) != 0;
		switch (icmp->type) {
		case ICMP_ECHO:
			/* MUST NOT */
			return true;
		case ICMP_SOURCE_QUENCH:
		case ICMP_REDIRECT:
		case ICMP_DEST_UNREACH:
		case ICMP_TIME_EXCEEDED:
		case ICMP_PARAMETERPROB:
			return ping4_icmp_extra_type(rts, icmp, received, from, raw, bad);
		default: /* MUST NOT */
			break;
		}
		if (rts->opt.flood && !(rts->opt.verbose || rts->opt.quiet)) {
			write(STDOUT_FILENO, "!EC", bad ? 3 : 2);
			return false;
		}
		if (!rts->opt.verbose || rts->uid)
			return false;
		if (rts->opt.ptimeofday) {
			struct timeval recv_time;
			gettimeofday(&recv_time, NULL);
			printf("%lu.%06lu ", (unsigned long)recv_time.tv_sec, (unsigned long)recv_time.tv_usec);
		}
		printf(_("From %s: "), SPRINT_RES_ADDR(rts, from, sizeof(*from)));
		if (bad) {
			printf(_(" (BAD CHECKSUM!)"));
			putchar('\n');
			return false;
		}
		print4_icmph(rts, icmp->type, icmp->code, ntohl(icmp->un.gateway), icmp);
		fflush(stdout);
		return false;
	}
	if (rts->opt.audible) {
		putchar('\a');
		if (rts->opt.flood)
			fflush(stdout);
	}
	if (!rts->opt.flood) {
		print4_ip_options(rts, opts, olen + sizeof(struct iphdr));
		putchar('\n');
		fflush(stdout);
	}
	return false;
}


/* return >= 0: exit with this code, < 0: go on to next addrinfo result */
int ping4_run(struct ping_rts *rts, int argc, char **argv,
		struct addrinfo *ai, const socket_st *sock)
{
	static ping_func_set_st ping4_func_set = {
		.send_probe     = ping4_send_probe,
		.receive_error  = ping4_receive_error,
		.parse_reply    = ping4_parse_reply,
	};
	static const struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_protocol = IPPROTO_UDP,
		.ai_flags = AI_FLAGS,
	};

	rts->ip6 = false;
	struct sockaddr_in *source  = (struct sockaddr_in *)&rts->source;
	struct sockaddr_in *whereto = (struct sockaddr_in *)&rts->whereto;
	source->sin_family = AF_INET;

	if (argc > 1) {
		if (rts->opt.rroute)
			usage();
		else if (rts->opt.timestamp) {
			if (rts->ipt_flg != IPOPT_TS_PRESPEC)
				usage();
			if (argc > 5)
				usage();
		} else {
			if (argc > 10)
				usage();
			rts->opt.sourceroute = true;
		}
	}

	char hnamebuf[NI_MAXHOST] = "";
	while (argc > 0) {
		char *target = *argv;
		memset(whereto, 0, sizeof(*whereto));
		whereto->sin_family = AF_INET;
		if (inet_aton(target, &whereto->sin_addr) == 1) {
			rts->hostname = target;
			if (argc == 1)
				rts->opt.numeric = true;
		} else {
			struct addrinfo *result = ai;
			if (argc > 1) {
				int rc = getaddrinfo(target, NULL, &hints, &result);
				if (rc)
					error(2, 0, "%s: %s", target, gai_strerror(rc));
			}
			memcpy(whereto, result->ai_addr, sizeof(*whereto));
			/*
			 * On certain network setup getaddrinfo() can return empty
			 * ai_canonname. Instead of printing nothing in "PING"
			 * line use the target.
			 */
			strncpy(hnamebuf, result->ai_canonname ? result->ai_canonname : target,
				sizeof(hnamebuf) - 1);
			rts->hostname = hnamebuf;
			if (argc > 1)
				freeaddrinfo(result);
		}
		if (argc > 1)
			rts->route[rts->nroute++] = whereto->sin_addr.s_addr;
		argc--;
		argv++;
	}

	socklen_t slen = 0;
	unsigned iface = 0;
	unsigned mcast = 0;
	if (rts->device) {
		slen  = strlen(rts->device) + 1;
		iface = if_name2index(rts->device);
		if (iface && IN_MULTICAST(ntohl(whereto->sin_addr.s_addr)))
			mcast = iface;
	}

	struct sockaddr_in dst = *whereto;
	if (!source->sin_addr.s_addr) {
		int probe_fd = socket(AF_INET, SOCK_DGRAM, 0);
		if (probe_fd < 0)
			error(2, errno, "socket");

		if (rts->device)
			set_device(false, rts->device, slen, iface, mcast, probe_fd, sock->fd);
		if (rts->qos) {
			int opt = rts->qos;
			if (setsockopt(probe_fd, IPPROTO_IP, IP_TOS, &opt, sizeof(opt)) < 0)
				error(0, errno, _("warning: QOS sockopts"));
		}
		sock_setmark(rts, probe_fd);

		dst.sin_port = htons(1025);
		if (rts->nroute)
			dst.sin_addr.s_addr = rts->route[0];
		if (connect(probe_fd, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
			switch (errno) {
			case EACCES:
				if (!rts->opt.broadcast)
					error(2, 0,
_("Do you want to ping broadcast? Then -b. If not, check your local firewall rules"));
				fprintf(stderr, _("WARNING: pinging broadcast address\n"));
				int opt = rts->opt.broadcast;
				if (setsockopt(probe_fd, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt)) < 0)
					error(2, errno, _("cannot set broadcasting"));
				if (connect(probe_fd, (struct sockaddr *)&dst, sizeof(dst)) < 0)
					error(2, errno, "connect");
				break;
			case EHOSTUNREACH:
			case ENETUNREACH:
				if (ai->ai_next) {
					close(probe_fd);
					return -1;
				}
				error(2, errno, "connect");
				break;
			default:
				error(2, errno, "connect");
				break;
			}
		}
		socklen_t socklen = sizeof(struct sockaddr_in);
		if (getsockname(probe_fd, (struct sockaddr *)source, &socklen) < 0)
			error(2, errno, "getsockname");
		source->sin_port = 0;
		close(probe_fd);

		if (rts->device)
			cmp_srcdev(rts);

	} else if (rts->device) {
		if (setsock_bindopt(sock->fd, rts->device, slen, mcast) < 0)
			error(2, errno, "setsock_bindopt(%s)", rts->device);
	}

	if (!whereto->sin_addr.s_addr)
		whereto->sin_addr.s_addr = source->sin_addr.s_addr;

	if (rts->opt.broadcast || IN_MULTICAST(ntohl(whereto->sin_addr.s_addr))) {
		rts->multicast = true;
		if (rts->uid) {
			if (rts->interval < MIN_MCAST_INTERVAL_MS)
				error(2, 0,
_("minimal interval for broadcast ping for user must be >= %d ms, use -i %s (or higher)"),
					  MIN_MCAST_INTERVAL_MS,
					  str_interval(MIN_MCAST_INTERVAL_MS));
			if ((rts->pmtudisc >= 0) && (rts->pmtudisc != IP_PMTUDISC_DO))
				error(2, 0, _("broadcast ping does not fragment"));
		}
		if (rts->pmtudisc < 0)
			rts->pmtudisc = IP_PMTUDISC_DO;
	}

	mtudisc_n_bind(rts, sock);

	if (sock->raw) {
		struct icmp_filter filt;
		filt.data = ~((1 << ICMP_SOURCE_QUENCH) |
			      (1 << ICMP_DEST_UNREACH)	|
			      (1 << ICMP_TIME_EXCEEDED) |
			      (1 << ICMP_PARAMETERPROB) |
			      (1 << ICMP_REDIRECT)	|
			      (1 << ICMP_ECHOREPLY));
		if (setsockopt(sock->fd, SOL_RAW, ICMP_FILTER, &filt, sizeof filt) < 0)
			error(0, errno, _("WARNING: setsockopt(ICMP_FILTER)"));
	}

	{ int hold = 1;
	  if (setsockopt(sock->fd, SOL_IP, IP_RECVERR, &hold, sizeof(hold)) < 0)
		error(0, 0, _("WARNING: your kernel is veeery old. No problems."));

	  if (!sock->raw) {
		if (setsockopt(sock->fd, SOL_IP, IP_RECVTTL, &hold, sizeof(hold)) < 0)
			error(0, errno, _("WARNING: setsockopt(IP_RECVTTL)"));
		if (setsockopt(sock->fd, SOL_IP, IP_RETOPTS, &hold, sizeof(hold)) < 0)
			error(0, errno, _("WARNING: setsockopt(IP_RETOPTS)"));
	  }
	}

	/* record route option */
	if (rts->opt.rroute) {
		unsigned char rspace[3 + 4 * NROUTES + 1] = {0};	/* record route space */
		rspace[0]                = IPOPT_NOP;
		rspace[1 + IPOPT_OPTVAL] = IPOPT_RR;
		rspace[1 + IPOPT_OLEN]   = sizeof(rspace) - 1;
		rspace[1 + IPOPT_OFFSET] = IPOPT_MINOFF;
		rts->optlen = 40;
		if (setsockopt(sock->fd, IPPROTO_IP, IP_OPTIONS, rspace, sizeof rspace) < 0)
			error(2, errno, "record route");
	}
	if (rts->opt.timestamp) {
		unsigned char rspace[3 + 4 * NROUTES + 1] = {0};	/* record route space */
		rspace[0] = IPOPT_TIMESTAMP;
		rspace[1] = (rts->ipt_flg == IPOPT_TS_TSONLY) ? 40 : 36;
		rspace[2] = 5;
		rspace[3] = rts->ipt_flg;
		if (rts->ipt_flg == IPOPT_TS_PRESPEC) {
			rspace[1] = 4 + rts->nroute * 8;
			for (int i = 0; i < rts->nroute; i++) {
				uint32_t *tmp = (uint32_t *)&rspace[4 + i * 8];
				*tmp = rts->route[i];
			}
		}
		if (setsockopt(sock->fd, IPPROTO_IP, IP_OPTIONS, rspace, rspace[1]) < 0) {
			rspace[3] = 2;
			if (setsockopt(sock->fd, IPPROTO_IP, IP_OPTIONS, rspace, rspace[1]) < 0)
				error(2, errno, "ts option");
		}
		rts->optlen = 40;
	}
	if (rts->opt.sourceroute) {
		unsigned char rspace[3 + 4 * NROUTES + 1] = {0};	/* record route space */
		rspace[0]                = IPOPT_NOOP;
		rspace[1 + IPOPT_OPTVAL] = rts->opt.so_dontroute ? IPOPT_SSRR : IPOPT_LSRR;
		rspace[1 + IPOPT_OLEN]   = 3 + rts->nroute * 4;
		rspace[1 + IPOPT_OFFSET] = IPOPT_MINOFF;
		for (int i = 0; i < rts->nroute; i++) {
			uint32_t *tmp = (uint32_t *)&rspace[4 + i * 4];
			*tmp = rts->route[i];
		}
		if (setsockopt(sock->fd, IPPROTO_IP, IP_OPTIONS, rspace, 4 + rts->nroute * 4) < 0)
			error(2, errno, "record route");
		rts->optlen = 40;
	}

	/* Estimate memory eaten by single packet. It is rough estimate.
	 * Actually, for small datalen's it depends on kernel side a lot. */
	{ int hold = rts->datalen + 8;
	  hold += ((hold + 511) / 512) * (rts->optlen + 20 + 16 + 64 + 160);
	  sock_setbufs(rts, sock->fd, hold);
	}

	if (rts->opt.broadcast) {
		int opt = 1;
		if (setsockopt(sock->fd, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt)) < 0)
			error(2, errno, _("cannot set broadcasting"));
	}

	if (rts->opt.noloop) {
		int opt = 0;
		if (setsockopt(sock->fd, IPPROTO_IP, IP_MULTICAST_LOOP, &opt, sizeof(opt)) < 0)
			error(2, errno, _("cannot disable multicast loopback"));
	}
	if (rts->opt.ttl) {
		if (setsockopt(sock->fd, IPPROTO_IP, IP_MULTICAST_TTL, &rts->ttl, sizeof(rts->ttl)) < 0)
			error(2, errno, _("cannot set multicast time-to-live"));
		int opt = 1;
		if (setsockopt(sock->fd, IPPROTO_IP, IP_TTL, &opt, sizeof(opt)) < 0)
			error(2, errno, _("cannot set unicast time-to-live"));
	}

	if (rts->datalen >= sizeof(struct timeval))	/* can we time transfer */
		rts->timing = true;
	int packlen = rts->datalen + MAXIPLEN + MAXICMPLEN;
	unsigned char *packet = malloc(packlen);
	if (!packet)
		error(2, errno, _("memory allocation failed"));

	printf(_("PING %s (%s) "), rts->hostname, inet_ntoa(whereto->sin_addr));
	if (rts->device || rts->opt.strictsource)
		printf(_("from %s %s: "), inet_ntoa(source->sin_addr), rts->device ? rts->device : "");
	printf(_("%zu(%zu) bytes of data.\n"), rts->datalen, rts->datalen + 8 + rts->optlen + 20);

	ping_setup(rts, sock);

	if (rts->opt.connect_sk)
		if (connect(sock->fd, (struct sockaddr *)&dst, sizeof(dst)) < 0)
			error(2, errno, "connect");
	drop_capabilities();

	int rc = main_loop(rts, &ping4_func_set, sock, packet, packlen);
	free(packet);
	return rc;
}

