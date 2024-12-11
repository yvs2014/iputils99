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
#include "ping4.h"
#include "ping4_aux.h"

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
#include <ifaddrs.h>
#include <netinet/ip_icmp.h>

#include <linux/filter.h>
#include <linux/errqueue.h>

#ifndef ICMP_FILTER
#define ICMP_FILTER	1
struct icmp_filter {
	uint32_t	data;
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
static int ping4_send_probe(struct ping_rts *rts, socket_st *sock, void *packet,
		unsigned packet_size __attribute__((__unused__)))
{
	struct icmphdr *icp;
	int cc;
	int i;

	icp = (struct icmphdr *)packet;
	icp->type = ICMP_ECHO;
	icp->code = 0;
	icp->checksum = 0;
	icp->un.echo.sequence = htons(rts->ntransmitted + 1);
	icp->un.echo.id = rts->ident;			/* ID */

	rcvd_clear(rts, rts->ntransmitted + 1);

	if (rts->timing) {
		if (rts->opt_latency) {
			struct timeval tmp_tv;
			gettimeofday(&tmp_tv, NULL);
			memcpy(icp + 1, &tmp_tv, sizeof(tmp_tv));
		} else {
			memset(icp + 1, 0, sizeof(struct timeval));
		}
	}

	cc = rts->datalen + 8;			/* skips ICMP portion */

	/* compute ICMP checksum here */
	icp->checksum = in_cksum((unsigned short *)icp, cc, 0);

	if (rts->timing && !rts->opt_latency) {
		struct timeval tmp_tv;
		gettimeofday(&tmp_tv, NULL);
		memcpy(icp + 1, &tmp_tv, sizeof(tmp_tv));
		icp->checksum = in_cksum((unsigned short *)&tmp_tv, sizeof(tmp_tv), ~icp->checksum);
	}

	i = sendto(sock->fd, icp, cc, 0, (struct sockaddr *)&rts->whereto, sizeof(rts->whereto));

	return (cc == i ? 0 : i);
}


// func_set:receive_error
static int ping4_receive_error(struct ping_rts *rts, socket_st *sock) {
	ssize_t res;
	char cbuf[512];
	struct iovec iov;
	struct msghdr msg;
	struct cmsghdr *cmsgh;
	struct sock_extended_err *e;
	struct icmphdr icmph;
	struct sockaddr_in target;
	int net_errors = 0;
	int local_errors = 0;
	int saved_errno = errno;

	iov.iov_base = &icmph;
	iov.iov_len = sizeof(icmph);
	msg.msg_name = (void *)&target;
	msg.msg_namelen = sizeof(target);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);

	res = recvmsg(sock->fd, &msg, MSG_ERRQUEUE | MSG_DONTWAIT);
	if (res < 0) {
		if (errno == EAGAIN || errno == EINTR)
			local_errors++;
		goto out;
	}

	e = NULL;
	for (cmsgh = CMSG_FIRSTHDR(&msg); cmsgh; cmsgh = CMSG_NXTHDR(&msg, cmsgh)) {
		if (cmsgh->cmsg_level == SOL_IP) {
			if (cmsgh->cmsg_type == IP_RECVERR)
				e = (struct sock_extended_err *)CMSG_DATA(cmsgh);
		}
	}
	if (e == NULL)
		abort();

	if (e->ee_origin == SO_EE_ORIGIN_LOCAL) {
		local_errors++;
		if (rts->opt_quiet)
			goto out;
		if (rts->opt_flood)
			write(STDOUT_FILENO, "E", 1);
		else if (e->ee_errno != EMSGSIZE)
			error(0, 0, _("local error: %s"), strerror(e->ee_errno));
		else
			error(0, 0, _("local error: message too long, mtu=%u"), e->ee_info);
		rts->nerrors++;
	} else if (e->ee_origin == SO_EE_ORIGIN_ICMP) {
		struct sockaddr_in *sin = (struct sockaddr_in *)(e + 1);

		if (res < (ssize_t) sizeof(icmph) ||
		    target.sin_addr.s_addr != rts->whereto.sin_addr.s_addr ||
		    icmph.type != ICMP_ECHO ||
		    !is_ours(rts, sock, icmph.un.echo.id)) {
			/* Not our error, not an error at all. Clear. */
			saved_errno = 0;
			goto out;
		}

		acknowledge(rts, ntohs(icmph.un.echo.sequence));

		if (sock->socktype == SOCK_RAW) {
			struct icmp_filter filt;

			filt.data = ~((1 << ICMP_SOURCE_QUENCH) |
				      (1 << ICMP_REDIRECT) |
				      (1 << ICMP_ECHOREPLY));
			if (setsockopt(sock->fd, SOL_RAW, ICMP_FILTER, (const void *)&filt,
				       sizeof(filt)) == -1)
				error(2, errno, "setsockopt(ICMP_FILTER)");
		}
		net_errors++;
		rts->nerrors++;
		if (rts->opt_quiet)
			goto out;
		if (rts->opt_flood) {
			write(STDOUT_FILENO, "\bE", 2);
		} else {
			print_timestamp(rts);
			printf(_("From %s icmp_seq=%u "), SPRINT_RES_ADDR(rts, sin, sizeof(*sin)),
				ntohs(icmph.un.echo.sequence));
			print4_icmph(rts, e->ee_type, e->ee_code, e->ee_info, NULL);
			fflush(stdout);
		}
	}

out:
	errno = saved_errno;
	return net_errors ? net_errors : -local_errors;
}

/*
 *	Print out the packet, if it came from us.  This logic is necessary
 * because ALL readers of the ICMP socket get a copy of ALL ICMP packets
 * which arrive ('tis only fair).  This permits multiple copies of this
 * program to be run without having intermingled output (or statistics!).
 */
// func_set:parse_reply
static int ping4_parse_reply(struct ping_rts *rts, struct socket_st *sock,
	struct msghdr *msg, int cc, void *addr, struct timeval *tv)
{
	struct sockaddr_in *from = addr;
	uint8_t *buf = msg->msg_iov->iov_base;
	struct icmphdr *icp;
	struct iphdr *ip;
	int hlen;
	int csfailed;
	struct cmsghdr *cmsgh;
	int reply_ttl;
	uint8_t *opts, *tmp_ttl;
	int olen;
	int wrong_source = 0;

	/* Check the IP header */
	ip = (struct iphdr *)buf;
	if (sock->socktype == SOCK_RAW) {
		hlen = ip->ihl * 4;
		if (cc < hlen + 8 || ip->ihl < 5) {
			if (rts->opt_verbose)
				error(0, 0, _("packet too short (%d bytes) from %s"), cc,
					SPRINT_RES_ADDR(rts, from, sizeof(*from)));
			return 1;
		}
		reply_ttl = ip->ttl;
		opts = buf + sizeof(struct iphdr);
		olen = hlen - sizeof(struct iphdr);
	} else {
		hlen = 0;
		reply_ttl = 0;
		opts = buf;
		olen = 0;
		for (cmsgh = CMSG_FIRSTHDR(msg); cmsgh; cmsgh = CMSG_NXTHDR(msg, cmsgh)) {
			if (cmsgh->cmsg_level != SOL_IP)
				continue;
			if (cmsgh->cmsg_type == IP_TTL) {
				if (cmsgh->cmsg_len < sizeof(int))
					continue;
				tmp_ttl = (uint8_t *)CMSG_DATA(cmsgh);
				reply_ttl = (int)*tmp_ttl;
			} else if (cmsgh->cmsg_type == IP_RETOPTS) {
				opts = (uint8_t *)CMSG_DATA(cmsgh);
				olen = cmsgh->cmsg_len;
			}
		}
	}

	/* Now the ICMP part */
	cc -= hlen;
	icp = (struct icmphdr *)(buf + hlen);
	csfailed = in_cksum((unsigned short *)icp, cc, 0);

	if (icp->type == ICMP_ECHOREPLY) {
		if (!is_ours(rts, sock, icp->un.echo.id))
			return 1;			/* 'Twas not our ECHO */

		if (!rts->broadcast_pings && !rts->multicast &&
		    from->sin_addr.s_addr != rts->whereto.sin_addr.s_addr)
			wrong_source = 1;
		if (gather_stats(rts, (uint8_t *)icp, sizeof(*icp), cc,
			ntohs(icp->un.echo.sequence), reply_ttl, 0, tv,
			SPRINT_RES_ADDR(rts, from, sizeof(*from)),
			print4_echo_reply, rts->multicast, wrong_source))
		{
			fflush(stdout);
			return 0;
		}
	} else {
		/* We fall here when a redirect or source quench arrived. */

		switch (icp->type) {
		case ICMP_ECHO:
			/* MUST NOT */
			return 1;
		case ICMP_SOURCE_QUENCH:
		case ICMP_REDIRECT:
		case ICMP_DEST_UNREACH:
		case ICMP_TIME_EXCEEDED:
		case ICMP_PARAMETERPROB:
			{
				struct iphdr *iph = (struct iphdr *)(&icp[1]);
				struct icmphdr *icp1 = (struct icmphdr *)
						((unsigned char *)iph + iph->ihl * 4);
				int error_pkt;
				if (cc < (int)(8 + sizeof(struct iphdr) + 8) ||
				    cc < 8 + iph->ihl * 4 + 8)
					return 1;
				if (icp1->type != ICMP_ECHO ||
				    iph->daddr != rts->whereto.sin_addr.s_addr ||
				    !is_ours(rts, sock, icp1->un.echo.id))
					return 1;
				error_pkt = (icp->type != ICMP_REDIRECT &&
					     icp->type != ICMP_SOURCE_QUENCH);
				if (error_pkt) {
					acknowledge(rts, ntohs(icp1->un.echo.sequence));
					return 0;
				}
				if (rts->opt_quiet || rts->opt_flood)
					return 1;
				print_timestamp(rts);
				printf(_("From %s: icmp_seq=%u "),
					SPRINT_RES_ADDR(rts, from, sizeof(*from)),
					ntohs(icp1->un.echo.sequence));
				if (csfailed)
					printf(_("(BAD CHECKSUM)"));
				print4_icmph(rts, icp->type, icp->code, ntohl(icp->un.gateway), icp);
				return 1;
			}
		default:
			/* MUST NOT */
			break;
		}
		if (rts->opt_flood && !(rts->opt_verbose || rts->opt_quiet)) {
			write(STDOUT_FILENO, "!EC", csfailed ? 3 : 2);
			return 0;
		}
		if (!rts->opt_verbose || rts->uid)
			return 0;
		if (rts->opt_ptimeofday) {
			struct timeval recv_time;
			gettimeofday(&recv_time, NULL);
			printf("%lu.%06lu ", (unsigned long)recv_time.tv_sec, (unsigned long)recv_time.tv_usec);
		}
		printf(_("From %s: "), SPRINT_RES_ADDR(rts, from, sizeof(*from)));
		if (csfailed) {
			printf(_("(BAD CHECKSUM)\n"));
			return 0;
		}
		print4_icmph(rts, icp->type, icp->code, ntohl(icp->un.gateway), icp);
		return 0;
	}

	if (rts->opt_audible) {
		putchar('\a');
		if (rts->opt_flood)
			fflush(stdout);
	}
	if (!rts->opt_flood) {
		print4_ip_options(rts, opts, olen + sizeof(struct iphdr));
		putchar('\n');
		fflush(stdout);
	}
	return 0;
}


// func_set:install_filter
static void ping4_install_filter(struct ping_rts *rts, socket_st *sock) {
	static int once;
	static struct sock_filter insns[] = {
		BPF_STMT(BPF_LDX | BPF_B   | BPF_MSH, 0),	/* Skip IP header due BSD, see ping6. */
		BPF_STMT(BPF_LD  | BPF_H   | BPF_IND, 4),	/* Load icmp echo ident */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0xAAAA, 0, 1), /* Ours? */
		BPF_STMT(BPF_RET | BPF_K, ~0U),			/* Yes, it passes. */
		BPF_STMT(BPF_LD  | BPF_B   | BPF_IND, 0),	/* Load icmp type */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ICMP_ECHOREPLY, 1, 0), /* Echo? */
		BPF_STMT(BPF_RET | BPF_K, 0xFFFFFFF),		/* No. It passes. */
		BPF_STMT(BPF_RET | BPF_K, 0)			/* Echo with wrong ident. Reject. */
	};
	static struct sock_fprog filter = {
		sizeof insns / sizeof(insns[0]),
		insns
	};

	if (once)
		return;
	once = 1;

	/* Patch bpflet for current identifier. */
	insns[2] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, htons(rts->ident), 0, 1);

	if (setsockopt(sock->fd, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter)))
		error(0, errno, _("WARNING: failed to install socket filter"));
}


/* return >= 0: exit with this code, < 0: go on to next addrinfo result */
int ping4_run(struct ping_rts *rts, int argc, char **argv, struct addrinfo *ai, socket_st *sock) {
	static ping_func_set_st ping4_func_set = {
		.send_probe     = ping4_send_probe,
		.receive_error  = ping4_receive_error,
		.parse_reply    = ping4_parse_reply,
		.install_filter = ping4_install_filter,
	};
	static const struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_protocol = IPPROTO_UDP,
		.ai_flags = AI_FLAGS,
	};
	int hold, packlen;
	unsigned char *packet;
	char *target;
	char hnamebuf[NI_MAXHOST];
	unsigned char rspace[3 + 4 * NROUTES + 1];	/* record route space */
	uint32_t *tmp_rspace;
	struct sockaddr_in dst;

	if (argc > 1) {
		if (rts->opt_rroute)
			usage();
		else if (rts->opt_timestamp) {
			if (rts->ts_type != IPOPT_TS_PRESPEC)
				usage();
			if (argc > 5)
				usage();
		} else {
			if (argc > 10)
				usage();
			rts->opt_sourceroute = 1;
		}
	}
	while (argc > 0) {
		target = *argv;

		memset((char *)&rts->whereto, 0, sizeof(rts->whereto));
		rts->whereto.sin_family = AF_INET;
		if (inet_aton(target, &rts->whereto.sin_addr) == 1) {
			rts->hostname = target;
			if (argc == 1)
				rts->opt_numeric = 1;
		} else {
			struct addrinfo *result = ai;
			int ret_val;

			if (argc > 1) {
				ret_val = getaddrinfo(target, NULL, &hints, &result);
				if (ret_val)
					error(2, 0, "%s: %s", target, gai_strerror(ret_val));
			}

			memcpy(&rts->whereto, result->ai_addr, sizeof rts->whereto);
			memset(hnamebuf, 0, sizeof hnamebuf);

			/*
			 * On certain network setup getaddrinfo() can return empty
			 * ai_canonname. Instead of printing nothing in "PING"
			 * line use the target.
			 */
			if (result->ai_canonname)
				strncpy(hnamebuf, result->ai_canonname, sizeof hnamebuf - 1);
			else
				strncpy(hnamebuf, target, sizeof hnamebuf - 1);

			rts->hostname = hnamebuf;

			if (argc > 1)
				freeaddrinfo(result);
		}
		if (argc > 1)
			rts->route[rts->nroute++] = rts->whereto.sin_addr.s_addr;
		argc--;
		argv++;
	}

	if (rts->source.sin_addr.s_addr == 0) {
		socklen_t alen;
		int probe_fd = socket(AF_INET, SOCK_DGRAM, 0);
		dst = rts->whereto;

		if (probe_fd < 0)
			error(2, errno, "socket");

		if (rts->device) {
			bind_to_device(rts, probe_fd, dst.sin_addr.s_addr);
			bind_to_device(rts, sock->fd, dst.sin_addr.s_addr);
		}

		if (rts->settos &&
		    setsockopt(probe_fd, IPPROTO_IP, IP_TOS, (char *)&rts->settos, sizeof(int)) < 0)
			error(0, errno, _("warning: QOS sockopts"));

		sock_setmark(rts, probe_fd);

		dst.sin_port = htons(1025);
		if (rts->nroute)
			dst.sin_addr.s_addr = rts->route[0];
		if (connect(probe_fd, (struct sockaddr *)&dst, sizeof(dst)) == -1) {
			if (errno == EACCES) {
				if (rts->broadcast_pings == 0)
					error(2, 0,
						_("Do you want to ping broadcast? Then -b. If not, check your local firewall rules"));
				fprintf(stderr, _("WARNING: pinging broadcast address\n"));
				if (setsockopt(probe_fd, SOL_SOCKET, SO_BROADCAST,
					       &rts->broadcast_pings, sizeof(rts->broadcast_pings)) < 0)
					error(2, errno, _("cannot set broadcasting"));
				if (connect(probe_fd, (struct sockaddr *)&dst, sizeof(dst)) == -1)
					error(2, errno, "connect");
			} else if ((errno == EHOSTUNREACH || errno == ENETUNREACH) && ai->ai_next) {
				close(probe_fd);
				return -1;
			} else {
				error(2, errno, "connect");
			}
		}
		alen = sizeof(rts->source);
		if (getsockname(probe_fd, (struct sockaddr *)&rts->source, &alen) == -1)
			error(2, errno, "getsockname");
		rts->source.sin_port = 0;

		if (rts->device) {
			struct ifaddrs *ifa0, *ifa;
			int ret;

			ret = getifaddrs(&ifa0);
			if (ret)
				error(2, errno, _("gatifaddrs failed"));
			for (ifa = ifa0; ifa; ifa = ifa->ifa_next) {
				if (!ifa->ifa_name || !ifa->ifa_addr ||
				    ifa->ifa_addr->sa_family != AF_INET)
					continue;
				if (!strcmp(ifa->ifa_name, rts->device) &&
				    !memcmp(&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr,
					    &rts->source.sin_addr, sizeof(rts->source.sin_addr)))
					break;
			}
			freeifaddrs(ifa0);
			if (!ifa)
				error(0, 0, _("Warning: source address might be selected on device other than: %s"), rts->device);
		}
		close(probe_fd);

	} else if (rts->device) {
		bind_to_device(rts, sock->fd, rts->whereto.sin_addr.s_addr);
	}

	if (rts->whereto.sin_addr.s_addr == 0)
		rts->whereto.sin_addr.s_addr = rts->source.sin_addr.s_addr;

	if (rts->broadcast_pings || IN_MULTICAST(ntohl(rts->whereto.sin_addr.s_addr))) {
		rts->multicast = 1;

		if (rts->uid) {
			if (rts->interval < MIN_MCAST_INTERVAL_MS)
				error(2, 0, _("minimal interval for broadcast ping for user must be >= %d ms, use -i %s (or higher)"),
					  MIN_MCAST_INTERVAL_MS,
					  str_interval(MIN_MCAST_INTERVAL_MS));
			if (rts->pmtudisc >= 0 && rts->pmtudisc != IP_PMTUDISC_DO)
				error(2, 0, _("broadcast ping does not fragment"));
		}

		if (rts->pmtudisc < 0)
			rts->pmtudisc = IP_PMTUDISC_DO;
	}

	if (rts->pmtudisc >= 0) {
		if (setsockopt(sock->fd, SOL_IP, IP_MTU_DISCOVER, &rts->pmtudisc, sizeof rts->pmtudisc) == -1)
			error(2, errno, "IP_MTU_DISCOVER");
	}

	int set_ident = rts->ident > 0 && sock->socktype == SOCK_DGRAM;
	if (set_ident)
		rts->source.sin_port = rts->ident;

	if (rts->opt_strictsource || set_ident) {
		if (bind(sock->fd, (struct sockaddr *)&rts->source, sizeof rts->source) == -1)
			error(2, errno, "bind");
	}

	if (sock->socktype == SOCK_RAW) {
		struct icmp_filter filt;
		filt.data = ~((1 << ICMP_SOURCE_QUENCH) |
			      (1 << ICMP_DEST_UNREACH)	|
			      (1 << ICMP_TIME_EXCEEDED) |
			      (1 << ICMP_PARAMETERPROB) |
			      (1 << ICMP_REDIRECT)	|
			      (1 << ICMP_ECHOREPLY));
		if (setsockopt(sock->fd, SOL_RAW, ICMP_FILTER, &filt, sizeof filt) == -1)
			error(0, errno, _("WARNING: setsockopt(ICMP_FILTER)"));
	}

	hold = 1;
	if (setsockopt(sock->fd, SOL_IP, IP_RECVERR, &hold, sizeof hold))
		error(0, 0, _("WARNING: your kernel is veeery old. No problems."));

	if (sock->socktype == SOCK_DGRAM) {
		if (setsockopt(sock->fd, SOL_IP, IP_RECVTTL, &hold, sizeof hold))
			error(0, errno, _("WARNING: setsockopt(IP_RECVTTL)"));
		if (setsockopt(sock->fd, SOL_IP, IP_RETOPTS, &hold, sizeof hold))
			error(0, errno, _("WARNING: setsockopt(IP_RETOPTS)"));
	}

	/* record route option */
	if (rts->opt_rroute) {
		memset(rspace, 0, sizeof(rspace));
		rspace[0] = IPOPT_NOP;
		rspace[1 + IPOPT_OPTVAL] = IPOPT_RR;
		rspace[1 + IPOPT_OLEN] = sizeof(rspace) - 1;
		rspace[1 + IPOPT_OFFSET] = IPOPT_MINOFF;
		rts->optlen = 40;
		if (setsockopt(sock->fd, IPPROTO_IP, IP_OPTIONS, rspace, sizeof rspace) < 0)
			error(2, errno, "record route");
	}
	if (rts->opt_timestamp) {
		memset(rspace, 0, sizeof(rspace));
		rspace[0] = IPOPT_TIMESTAMP;
		rspace[1] = (rts->ts_type == IPOPT_TS_TSONLY ? 40 : 36);
		rspace[2] = 5;
		rspace[3] = rts->ts_type;
		if (rts->ts_type == IPOPT_TS_PRESPEC) {
			int i;
			rspace[1] = 4 + rts->nroute * 8;
			for (i = 0; i < rts->nroute; i++) {
				tmp_rspace = (uint32_t *)&rspace[4 + i * 8];
				*tmp_rspace = rts->route[i];
			}
		}
		if (setsockopt(sock->fd, IPPROTO_IP, IP_OPTIONS, rspace, rspace[1]) < 0) {
			rspace[3] = 2;
			if (setsockopt(sock->fd, IPPROTO_IP, IP_OPTIONS, rspace, rspace[1]) < 0)
				error(2, errno, "ts option");
		}
		rts->optlen = 40;
	}
	if (rts->opt_sourceroute) {
		int i;
		memset(rspace, 0, sizeof(rspace));
		rspace[0] = IPOPT_NOOP;
		rspace[1 + IPOPT_OPTVAL] = rts->opt_so_dontroute ? IPOPT_SSRR : IPOPT_LSRR;
		rspace[1 + IPOPT_OLEN] = 3 + rts->nroute * 4;
		rspace[1 + IPOPT_OFFSET] = IPOPT_MINOFF;
		for (i = 0; i < rts->nroute; i++) {
			tmp_rspace = (uint32_t *)&rspace[4 + i * 4];
			*tmp_rspace = rts->route[i];
		}

		if (setsockopt(sock->fd, IPPROTO_IP, IP_OPTIONS, rspace, 4 + rts->nroute * 4) < 0)
			error(2, errno, "record route");
		rts->optlen = 40;
	}

	/* Estimate memory eaten by single packet. It is rough estimate.
	 * Actually, for small datalen's it depends on kernel side a lot. */
	hold = rts->datalen + 8;
	hold += ((hold + 511) / 512) * (rts->optlen + 20 + 16 + 64 + 160);
	sock_setbufs(rts, sock, hold);

	if (rts->broadcast_pings) {
		if (setsockopt(sock->fd, SOL_SOCKET, SO_BROADCAST, &rts->broadcast_pings,
			       sizeof rts->broadcast_pings) < 0)
			error(2, errno, _("cannot set broadcasting"));
	}

	if (rts->opt_noloop) {
		int loop = 0;
		if (setsockopt(sock->fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof loop) == -1)
			error(2, errno, _("cannot disable multicast loopback"));
	}
	if (rts->opt_ttl) {
		int ittl = rts->ttl;
		if (setsockopt(sock->fd, IPPROTO_IP, IP_MULTICAST_TTL, &rts->ttl, sizeof rts->ttl) == -1)
			error(2, errno, _("cannot set multicast time-to-live"));
		if (setsockopt(sock->fd, IPPROTO_IP, IP_TTL, &ittl, sizeof ittl) == -1)
			error(2, errno, _("cannot set unicast time-to-live"));
	}

	if (rts->datalen >= (int)sizeof(struct timeval))	/* can we time transfer */
		rts->timing = 1;
	packlen = rts->datalen + MAXIPLEN + MAXICMPLEN;
	packet = malloc(packlen);
	if (!packet)
		error(2, errno, _("memory allocation failed"));

	printf(_("PING %s (%s) "), rts->hostname, inet_ntoa(rts->whereto.sin_addr));
	if (rts->device || rts->opt_strictsource)
		printf(_("from %s %s: "), inet_ntoa(rts->source.sin_addr), rts->device ? rts->device : "");
	printf(_("%zu(%zu) bytes of data.\n"), rts->datalen, rts->datalen + 8 + rts->optlen + 20);

	ping_setup(rts, sock);
	if (rts->opt_connect_sk &&
	    connect(sock->fd, (struct sockaddr *)&dst, sizeof(dst)) == -1)
		error(2, errno, "connect failed");

	drop_capabilities();

	hold = main_loop(rts, &ping4_func_set, sock, packet, packlen);
	free(packet);

	return hold;
}

