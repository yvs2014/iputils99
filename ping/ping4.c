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
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
//#include <linux/icmp.h> /* conflicted with <netinet/ip_icmp.h> */
#include <linux/errqueue.h>
#include <linux/filter.h>

#include "ping4.h"

#include "iputils.h"
#include "common.h"
#include "stats.h"
#include "ping_aux.h"
#include "ping4_aux.h"
#include "nbind.h"

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
		if (rts->opt.latency) {
			struct timeval tv;
			gettimeofday(&tv, NULL);
			memcpy(icmp + 1, &tv, sizeof(tv));
		} else {
			memset(icmp + 1, 0, sizeof(struct timeval));
		}
	}
	// note: timestamp is accounted in data area
	ssize_t len = sizeof(struct icmphdr) + rts->datalen;

	/* compute ICMP checksum here */
	icmp->checksum = in_cksum((uint16_t *)icmp, len, 0);
	if (rts->timing && !rts->opt.latency) {
		struct timeval tv;
		gettimeofday(&tv, NULL);
		memcpy(icmp + 1, &tv, sizeof(tv));
		icmp->checksum = in_cksum((uint16_t *)&tv, sizeof(tv), ~icmp->checksum);
	}

	ssize_t rc = sendto(fd, icmp, len, 0,
		(struct sockaddr *)&rts->whereto, sizeof(struct sockaddr_in));
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

// func_set:receive_error
static int ping4_receive_error(state_t *rts, const sock_t *sock) {
	int saved_errno = errno;
	//
	char cbuf[512];
	struct icmphdr icmp = {0};
	struct iovec iov = { .iov_base = &icmp, .iov_len = sizeof(icmp) };
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
			if ((m->cmsg_level == IPPROTO_IP) && (m->cmsg_type == IP_RECVERR))
				ee = (struct sock_extended_err *)CMSG_DATA(m);
		if (!ee)
			abort();
		if (ee->ee_origin == SO_EE_ORIGIN_LOCAL) {
			local_errors++;
			rts->nerrors++;
			if (!rts->opt.quiet)
				print_local_ee(rts, ee);
		} else if (ee->ee_origin == SO_EE_ORIGIN_ICMP) {
			struct sockaddr_in *to = (struct sockaddr_in *)&rts->whereto;
			if ((res < (ssize_t)sizeof(icmp))                   ||
			    (target.sin_addr.s_addr != to->sin_addr.s_addr) ||
			    (icmp.type != ICMP_ECHO)                        ||
			    !IS_OURS(rts, sock->raw, icmp.un.echo.id)) {
				/* Not our error, not an error at all, clear */
				saved_errno = 0;
			} else {
				net_errors++;
				rts->nerrors++;
				uint16_t seq = ntohs(icmp.un.echo.sequence);
				acknowledge(rts, seq);
				static bool icmp4_filter_applied;
				if (sock->raw && !icmp4_filter_applied) {
					/* Set additional filter */
					setsock4_icmp_filter(sock->fd);
					icmp4_filter_applied = true;
				}
				print_addr_seq(rts, seq, ee, sizeof(struct sockaddr_in));
			}
		}
	}
	errno = saved_errno;
	return net_errors ? net_errors : -local_errors;
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
	printf("%s %s: %s=%u ",
		_("From"), sprint_addr(from, sizeof(*from), rts->opt.resolve),
		_("icmp_seq"), ntohs(orig->un.echo.sequence));
	if (bad)
		printf("(%s!)", _("BAD CHECKSUM"));
	if (print4_icmph(icmp->type, icmp->code, ntohl(icmp->un.gateway), icmp,
			rts->opt.resolve, color))
		if (rts->opt.verbose)
			print4_iph(iph, rts->opt.resolve, rts->opt.flood);
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
	struct sockaddr_in *from = addr;
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
					sprint_addr(from, sizeof(*from), rts->opt.resolve),
					_("Packet too short"), received, BYTES(received));
			return true;
		}
		away = ip->ttl;
		opts += sizeof(struct iphdr);
		olen = (ssize_t)hlen - sizeof(struct iphdr);
	} else for (struct cmsghdr *c = CMSG_FIRSTHDR(msg); c; c = CMSG_NXTHDR(msg, c)) {
		if (c->cmsg_level == IPPROTO_IP)
			switch (c->cmsg_type) {
			case IP_TTL:
				if (c->cmsg_len >= sizeof(int)) {
					uint8_t *ttl = CMSG_DATA(c);
					away = (int)*ttl;
				}
				break;
			case IP_RETOPTS:
				opts = (uint8_t *)CMSG_DATA(c);
				olen = c->cmsg_len;
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
			return true;	/* 'Twas not our ECHO */
		struct sockaddr_in *sin = (struct sockaddr_in *)&rts->whereto;
		stat_aux_t stat = {
			.from = sprint_addr(from, sizeof(*from), rts->opt.resolve),
			.seq  = ntohs(icmp->un.echo.sequence),
			.rcvd = received,
			.tv   = at,
			.icmp = (const uint8_t *)icmp,
			.data = (const uint8_t *)(icmp + 1),
			.ack  = !in_cksum((uint16_t *)icmp, received, 0),
			.okay = (from->sin_addr.s_addr == sin->sin_addr.s_addr)
				|| rts->multicast || rts->opt.broadcast,
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
			return ping4_icmp_extra_type(rts, icmp, received, from, raw, bad, rts->yellow);
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
			struct timeval recv_time;
			gettimeofday(&recv_time, NULL);
			printf("%lu.%06lu ", (unsigned long)recv_time.tv_sec, (unsigned long)recv_time.tv_usec);
		}

		printf("%s %s: ", _("From"), sprint_addr(from, sizeof(*from), rts->opt.resolve));
		if (bad) {
			printf("(%s!)\n", _("BAD CHECKSUM"));
			return false;
		}
		bool add_iph = print4_icmph(icmp->type, icmp->code, ntohl(icmp->un.gateway), icmp,
			rts->opt.resolve, rts->red);
		if (add_iph && rts->opt.verbose)
			print4_iph((struct iphdr *)(icmp + 1), rts->opt.resolve, rts->opt.flood);
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
		print4_ip_opts(opts, olen + sizeof(struct iphdr), rts->opt.resolve, rts->opt.flood);
		putchar('\n');
		fflush(stdout);
	}
	return false;
}

static inline void set_route_space(int fd) {
	uint8_t space[3 + 4 * MAX_ROUTES + 1] = {0};	/* record route space */
	space[0]                = IPOPT_NOP;
	space[1 + IPOPT_OPTVAL] = IPOPT_RR;
	space[1 + IPOPT_OLEN]   = sizeof(space) - 1;
	space[1 + IPOPT_OFFSET] = IPOPT_MINOFF;
	if (setsockopt(fd, IPPROTO_IP, IP_OPTIONS, space, sizeof(space)) < 0)
		err(errno, "record route");
}

static inline void set_ts_space(int fd, const route_t *route, uint8_t ipt_flg) {
	uint8_t space[3 + 4 * MAX_ROUTES + 1] = {0};	/* record route space */
	space[0] = IPOPT_TIMESTAMP;
	space[1] = (ipt_flg == IPOPT_TS_TSONLY) ? MAX_IPOPTLEN : 36;
	space[2] = 5;
	space[3] = ipt_flg;
	if (ipt_flg == IPOPT_TS_PRESPEC) {
		space[1] = 4 + route->n * 8;
		for (unsigned i = 0; i < route->n; i++) {
			uint32_t *data = (uint32_t *)&space[4 + i * 8];
			*data = route->data[i];
		}
	}
	if (setsockopt(fd, IPPROTO_IP, IP_OPTIONS, space, space[1]) < 0) {
		space[3] = 2;
		if (setsockopt(fd, IPPROTO_IP, IP_OPTIONS, space, space[1]) < 0)
			err(errno, "ts option");
	}
}

static inline void set_src_space(int fd, const route_t *route, bool dontroute) {
	uint8_t space[3 + 4 * MAX_ROUTES + 1] = {0};	/* record route space */
	space[0]                = IPOPT_NOOP;
	space[1 + IPOPT_OPTVAL] = dontroute ? IPOPT_SSRR : IPOPT_LSRR;
	space[1 + IPOPT_OLEN]   = 3 + route->n * 4;
	space[1 + IPOPT_OFFSET] = IPOPT_MINOFF;
	for (unsigned i = 0; i < route->n; i++) {
		uint32_t *data = (uint32_t *)&space[4 + i * 4];
		*data = route->data[i];
	}
	if (setsockopt(fd, IPPROTO_IP, IP_OPTIONS, space, 4 + route->n * 4) < 0)
		err(errno, "record route");
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
		.len    = ARRAY_SIZE(filter),
		.filter = filter,
	};
	setsock_bpf(rts, sock, &fprog);
}

/* Return >= 0: exit with this code, < 0: go on to next addrinfo result */
int ping4_run(state_t *rts, int argc, char **argv,
		struct addrinfo *ai, const sock_t *sock)
{
	fnset_t ping4_func_set = {
		.bpf_filter     = ping4_bpf_filter,
		.send_probe     = ping4_send_probe,
		.receive_error  = ping4_receive_error,
		.parse_reply    = ping4_parse_reply,
	};

	rts->ip6 = false;
	route_t route4 = {0};
	rts->route = &route4;

	struct sockaddr_in *source  = (struct sockaddr_in *)&rts->source;
	struct sockaddr_in *whereto = (struct sockaddr_in *)&rts->whereto;
	source->sin_family = AF_INET;

	if (argc > 1) {
		if (rts->opt.rroute)
			usage(EINVAL);
		else if (rts->opt.timestamp) {
			if (rts->ipt_flg != IPOPT_TS_PRESPEC)
				errx(EINVAL, "%s", _("Only 'tsprespec' is allowed with intermediate hops"));
#define MAX_TS_ROUTES ((MAX_ROUTES + 1) / 2) /* 5 */
			if (argc > MAX_TS_ROUTES)
				errx(EINVAL, "%s, %s=%d", _("Too many intermediate TS hops"),
					_("max"), MAX_TS_ROUTES - 1);
		} else
			rts->opt.sourceroute = true;
	}

	char hnamebuf[NI_MAXHOST] = "";
	while (argc > 0) {
		char *target = *argv;
		memset(whereto, 0, sizeof(*whereto));
		whereto->sin_family = AF_INET;
		if (inet_aton(target, &whereto->sin_addr) == 1) {
			rts->hostname = target;
			if (argc == 1)
				rts->opt.resolve = false;
		} else {
			struct addrinfo *res = ai;
			if (argc > 1) {
				const struct addrinfo hints = {
					.ai_family = AF_INET,
					.ai_flags  = AI_FLAGS,
				};
				int rc = GAI_WRAPPER(target, NULL, &hints, &res);
				if (rc) {
					if (rc == EAI_SYSTEM)
						err(errno, "%s", "getaddrinfo()");
					errx(rc, "%s", gai_strerror(rc));
				}
			}
			if (!res)
				errx(EXIT_FAILURE, "%s", "getaddrinfo()");
			memcpy(whereto, res->ai_addr, sizeof(*whereto));
			/*
			 * On certain network setup getaddrinfo() can return empty
			 * ai_canonname. Instead of printing nothing in "PING"
			 * line use the target.
			 */
			strncpy(hnamebuf, res->ai_canonname ? res->ai_canonname : target,
				sizeof(hnamebuf) - 1);
			rts->hostname = hnamebuf;
			if (argc > 1)
				freeaddrinfo(res);
		}
		if (argc > 1) {
			if (rts->route->n < MAX_ROUTES)
				rts->route->data[rts->route->n++] = whereto->sin_addr.s_addr;
			else
				errx(EINVAL, "%s, %s=%d", _("Too many intermediate hops"),
					_("max"), MAX_ROUTES);
		}
		argc--;
		argv++;
	}

	if (!source->sin_addr.s_addr) {
		int probe_fd = socket(AF_INET, SOCK_DGRAM, 0);
		if (probe_fd < 0)
			err(errno, "socket");
		if (rts->device) {
//			struct in_pktinfo ipi = { .ipi_ifindex = if_name2index(rts->device) };
//			if ((setsockopt(probe_fd, IPPROTO_IP, IP_PKTINFO, &ipi, sizeof(ipi)) < 0) ||
//			    (setsockopt(sock->fd, IPPROTO_IP, IP_PKTINFO, &ipi, sizeof(ipi)) < 0))
//				err(errno, "setsockopt(%s, %s)", "IP_PKTINFO", rts->device);
			if ((bindtodev(probe_fd, rts->device) < 0) ||
			    (bindtodev(sock->fd, rts->device) < 0))
				err(errno, "setsockopt(%s, %s)", "SO_BINDTODEVICE", rts->device);
		}
		sock_settos(probe_fd, rts->qos, rts->ip6);
		sock_setmark(rts, probe_fd);

		whereto->sin_port = htons(1025);
		if (rts->route->n)
			whereto->sin_addr.s_addr = rts->route->data[0];
		if (connect(probe_fd, (struct sockaddr *)whereto, sizeof(*whereto)) < 0) {
			switch (errno) {
			case EACCES:
				if (!rts->opt.broadcast)
					errx(EINVAL,
_("Do you want to ping broadcast? Then -b. If not, check your local firewall rules"));
				warnx("%s: %s", _WARN, _("Pinging broadcast address"));
				int opt = rts->opt.broadcast;
				if (setsockopt(probe_fd, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt)) < 0)
					err(errno, "%s", _("Cannot set broadcasting"));
				if (connect(probe_fd, (struct sockaddr *)whereto, sizeof(*whereto)) < 0)
					err(errno, "connect");
				break;
			case EHOSTUNREACH:
			case ENETUNREACH:
				if (ai->ai_next) {
					close(probe_fd);
					return -1;
				}
				err(errno, "connect");
				break;
			default:
				err(errno, "connect");
				break;
			}
		}
		socklen_t socklen = sizeof(struct sockaddr_in);
		if (getsockname(probe_fd, (struct sockaddr *)source, &socklen) < 0)
			err(errno, "getsockname");
		source->sin_port = 0;
		close(probe_fd);

		if (rts->device)
			cmp_srcdev(rts);

	} else if (rts->device) {
		struct in_pktinfo ipi = { .ipi_ifindex = if_name2index(rts->device) };
		if (setsockopt(sock->fd, IPPROTO_IP, IP_PKTINFO, &ipi, sizeof(ipi)) < 0)
			err(errno, "setsockopt(%s, %s)", "IP_PKTINFO", rts->device);
	}

	if (!whereto->sin_addr.s_addr)
		whereto->sin_addr.s_addr = source->sin_addr.s_addr;

	if (rts->opt.broadcast || IN_MULTICAST(ntohl(whereto->sin_addr.s_addr)))
		pmtu_interval(rts);

	if (sock->raw) {
		struct icmp_filter filt;
		filt.data = ~((1 << ICMP_SOURCE_QUENCH) |
			      (1 << ICMP_DEST_UNREACH)	|
			      (1 << ICMP_TIME_EXCEEDED) |
			      (1 << ICMP_PARAMETERPROB) |
			      (1 << ICMP_REDIRECT)	|
			      (1 << ICMP_ECHOREPLY));
		if (setsockopt(sock->fd, SOL_RAW, ICMP_FILTER, &filt, sizeof filt) < 0)
			warn("%s: setsockopt(%s)", _WARN, "ICMP_FILTER");
	} else {
		int on = 1;
		if (setsockopt(sock->fd, IPPROTO_IP, IP_RECVTTL, &on, sizeof(on)) < 0)
			warn("%s: setsockopt(%s)", _WARN, "IP_RECVTTL");
		if (setsockopt(sock->fd, IPPROTO_IP, IP_RETOPTS, &on, sizeof(on)) < 0)
			warn("%s: setsockopt(%s)", _WARN, "IP_RETOPTS");
	}

	int optlen = (rts->opt.rroute || rts->opt.timestamp || rts->opt.sourceroute) ?
		MAX_IPOPTLEN : 0;
	if (optlen) {
		if (rts->opt.rroute)
			set_route_space(sock->fd);
		if (rts->opt.timestamp)
			set_ts_space(sock->fd, rts->route, rts->ipt_flg);
		if (rts->opt.sourceroute)
			set_src_space(sock->fd, rts->route, rts->opt.so_dontroute);
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
		if (connect(sock->fd, (struct sockaddr *)whereto, sizeof(*whereto)) < 0)
			err(errno, "%s", "connect()");

	mtudisc_n_bind(rts, sock);
	setsock_recverr(sock->fd, rts->ip6);
	set_estimate_buf(rts, sock->fd, sizeof(struct iphdr), optlen, sizeof(struct icmphdr));

	size_t hlen = sizeof(struct iphdr) + sizeof(struct icmphdr);
	headline(rts, hlen + optlen);
	hlen = (hlen + MAX_IPOPTLEN) * 2; // (ip+optlen+icmp)*2
	return setup_n_loop(rts, hlen, sock, &ping4_func_set);
}

