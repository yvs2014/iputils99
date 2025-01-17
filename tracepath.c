/*
 * tracepath.c
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 */

// local changes: yvs, 2025

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <sys/socket.h>
#include <sys/uio.h>

/*
 * Keep linux/ includes after standard headers.
 * https://github.com/iputils/iputils/issues/168
 */
#include <linux/errqueue.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/types.h>

#ifdef USE_NLS
#include <locale.h>
#endif

#include "iputils.h"
#include "str2num.h"

#if defined(USE_IDN) && defined(NI_IDN)
#define NI_FLAGS	NI_IDN
#else
#define NI_FLAGS	0
#endif

#ifndef UNKN
#define UNKN	"???"
#endif

enum {
	MAX_PROBES   =    10,
	HOST_LEN     =    52,      // for printing
	HIS_ELEMS    =    64,      // in 'his' list
	CMSG_LEN     =   512,
	DEFAULT_MTU  = UINT16_MAX,
	DEFAULT_IPH4 =    28,      // sizeof(iphdr)   + sizeof(udphdr)
	DEFAULT_IPH6 =    48,      // sizeof(ip6_hdr) + sizeof(udphdr)
	DEFAULT_HOPS =    30,      // enough for today's internet
	BASEPORT     = 33433,      // firewall friendly
};

struct hhistory {
	int hops;
	struct timespec sendtime;
};

struct probehdr {
	uint32_t ttl;
	struct timespec ts;
};

typedef struct run_state {
	int       af; // address family
	struct sockaddr_storage addr;
	socklen_t               addrlen;
	int       sock;
	uint16_t  port;
	uint8_t   ttl;
	uint8_t   max_hops;
	void     *pktbuf;
	uint16_t  pktsize;
	uint16_t  hdrsize;
	//
	int hisptr;
	struct hhistory his[HIS_ELEMS];
	int hops_to;
	int hops_from;
	//
	int ni_flags;
	bool dns;
	bool verbose;
	bool show_both;
} state_t;

/*
 * All includes, definitions, struct declarations, and global variables are
 * above.  After this comment all you can find is functions.
 */

static void data_wait(int fd) {
	fd_set fds;
	FD_ZERO(&fds);
	FD_SET(fd, &fds);
	struct timeval tv = {.tv_sec = 1};
	select(fd + 1, &fds, NULL, NULL, &tv);
}

static inline void print_host(const char *host, const char *addr) {
	int len = printf("%s", host);
	if (addr)
		len += printf(" (%s)", addr);
	if (len >= HOST_LEN)
		len = HOST_LEN - 1;
	printf("%*s", HOST_LEN - len, "");
}

// return codes: <0 (-1) | 0 | >0 (mtu)
static int recverr(state_t *rts) {
	struct sockaddr_storage addr;
	struct probehdr rcvbuf;
	struct iovec iov = {
		.iov_base = &rcvbuf,
		.iov_len = sizeof(rcvbuf)
	};
	char cbuf[CMSG_LEN];
	const struct msghdr reset = {
		.msg_name = (uint8_t *)&addr,
		.msg_namelen = sizeof(addr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = cbuf,
		.msg_controllen = sizeof(cbuf),
	};

	int progress       = -1;
	ssize_t recv_size  = 0;
	struct msghdr msg  = {0};
	struct timespec ts = {0};

do { // was 'restart:'
	do {
		msg = reset;
		memset(&rcvbuf, -1, sizeof(rcvbuf));
		clock_gettime(CLOCK_MONOTONIC, &ts);
		recv_size = recvmsg(rts->sock, &msg, MSG_ERRQUEUE);
		if ((recv_size < 0) && (errno == EAGAIN))
			return progress;
	} while (recv_size < 0);

	progress = rts->pktsize;

	int slot = -rts->port;
	switch (rts->af) {
	case AF_INET6:
		slot += ntohs(((struct sockaddr_in6 *)&addr)->sin6_port);
		break;
	case AF_INET:
		slot += ntohs(((struct sockaddr_in *)&addr)->sin_port);
		break;
	default:
		assert("Unknown IP address family");
	}

	int sndhops = -1;
	struct timespec *retts = NULL;
	if ((slot >= 0) && (slot < (HIS_ELEMS - 1)) && rts->his[slot].hops) {
		sndhops = rts->his[slot].hops;
		retts  = &rts->his[slot].sendtime;
		rts->his[slot].hops = 0;
	}

	bool broken_router = false;
	if (recv_size == sizeof(rcvbuf)) {
		if (!(rcvbuf.ttl && (rcvbuf.ts.tv_sec || rcvbuf.ts.tv_nsec)))
			broken_router = true;
		else {
			sndhops = rcvbuf.ttl;
			retts = &rcvbuf.ts;
		}
	}

	int rethops = -1;
	struct sock_extended_err *e = NULL;
	for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg;
		cmsg = CMSG_NXTHDR(&msg, cmsg))
	{
		switch (cmsg->cmsg_level) {
		case IPPROTO_IPV6:
			switch (cmsg->cmsg_type) {
			case IPV6_RECVERR:
				e = (struct sock_extended_err *)CMSG_DATA(cmsg);
				break;
			case IPV6_HOPLIMIT:
#ifdef IPV6_2292HOPLIMIT
			case IPV6_2292HOPLIMIT:
#endif
				memcpy(&rethops, CMSG_DATA(cmsg), sizeof(rethops));
				break;
			default:
				printf("cmsg6:%d\n ", cmsg->cmsg_type);
			}
			break;
		case IPPROTO_IP:
			switch (cmsg->cmsg_type) {
			case IP_RECVERR:
				e = (struct sock_extended_err *)CMSG_DATA(cmsg);
				break;
			case IP_TTL:
				rethops = *(uint8_t *)CMSG_DATA(cmsg);
				break;
			default:
				printf("cmsg4:%d\n ", cmsg->cmsg_type);
			}
		}
	}

	if (e == NULL) {
		puts(_("No info"));
		return 0;
	}

	if (e->ee_origin == SO_EE_ORIGIN_LOCAL)
		printf("%2d?: [%s] ", rts->ttl, _("LOCALHOST"));
	else if (e->ee_origin == SO_EE_ORIGIN_ICMP6 ||
		 e->ee_origin == SO_EE_ORIGIN_ICMP) {
		struct sockaddr *sa = (struct sockaddr *)(e + 1);
		socklen_t salen;

		if (sndhops > 0)
			printf("%2d:  ", sndhops);
		else
			printf("%2d?: ", rts->ttl);

		switch (sa->sa_family) {
		case AF_INET6:
			salen = sizeof(struct sockaddr_in6);
			break;
		case AF_INET:
			salen = sizeof(struct sockaddr_in);
			break;
		default:
			salen = 0;
			break;
		}

		// print "host (addr)"
		char hostbuf[NI_MAXHOST] = "";
		char addrbuf[NI_MAXHOST] = "";
		if (getnameinfo(sa, salen, hostbuf, sizeof(hostbuf), NULL, 0, rts->ni_flags))
			strcpy(hostbuf, UNKN);
		if (rts->show_both &&
		    getnameinfo(sa, salen, addrbuf, sizeof(addrbuf), NULL, 0, NI_NUMERICHOST))
			strcpy(addrbuf, UNKN);
		print_host(hostbuf, *addrbuf ? addrbuf : NULL);
		fflush(stdout);
	}

	if (retts) {
		struct timespec res;
		timespecsub(&ts, retts, &res);
		printf("%3ld.%03ld %s",
			res.tv_sec * 1000 + res.tv_nsec / 1000000,
			(res.tv_nsec % 1000000) / 1000,
			_("ms"));
		if (broken_router)
			fputs(_("(This broken router returned corrupted payload)"), stdout);
		putchar(' ');
	}

	if      (rethops <= 64)
		rethops = 65 - rethops;
	else if (rethops <= 128)
		rethops = 129 - rethops;
	else
		rethops = 256 - rethops;

	switch (e->ee_errno) {
	case ETIMEDOUT:
		putchar('\n');
		break;
	case EMSGSIZE:
		rts->pktsize = e->ee_info;
		progress     = rts->pktsize;
		printf("%s %u\n", _("pmtu"), rts->pktsize);
		break;
	case ECONNREFUSED:
		puts(_("reached"));
		rts->hops_to   = (sndhops < 0) ? rts->ttl : sndhops;
		rts->hops_from = rethops;
		return 0;
	case EPROTO:
		printf("!P\n");
		return 0;
	case EHOSTUNREACH:
		if ((e->ee_origin == SO_EE_ORIGIN_ICMP &&
		     e->ee_type == ICMP_TIME_EXCEEDED &&
		     e->ee_code == ICMP_EXC_TTL) ||
		    (e->ee_origin == SO_EE_ORIGIN_ICMP6 &&
		     e->ee_type == ICMPV6_TIME_EXCEED &&
		     e->ee_code == ICMPV6_EXC_HOPLIMIT)) {
			if (rethops >= 0) {
				bool sent = (sndhops >= 0);
				if (( sent && (rethops != sndhops )) ||
				    (!sent && (rethops != rts->ttl)))
					printf("(%s %d)", _("asymm"), rethops);
			}
			putchar('\n');
			break;
		}
		printf("!H\n");
		return 0;
	case ENETUNREACH:
		printf("!N\n");
		return 0;
	case EACCES:
		printf("!A\n");
		return 0;
	default:
		putchar('\n');
		warnx("%s", _("NET ERROR"));
		return 0;
	}
} while (true); // was 'goto restart'

	return 0;
}

static inline void setsock4_opts(int sock, bool verbose) {
	if (verbose)
		warnx("set sock%c options: %s", '4',
			"MTU_DISCOVER, RECVERR, RECVTTL");
	// PMTU
	int opt = IP_PMTUDISC_PROBE;
	if (setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER, &opt, sizeof(opt)) < 0)
		err(errno, "setsockopt(%s)", "IP_MTU_DISCOVER");
	// receive errors
	opt = 1;
	if (setsockopt(sock, IPPROTO_IP, IP_RECVERR, &opt, sizeof(opt)) < 0)
		err(errno, "setsockopt(%s)", "IP_RECVERR");
	// receive TTL
	opt = 1;
	if (setsockopt(sock, IPPROTO_IP, IP_RECVTTL, &opt, sizeof(opt)) < 0)
		err(errno, "setsockopt(%s)", "IP_RECVTTL");
}

static inline void setsock6_opts(int sock, bool verbose) {
	if (verbose)
		warnx("set sock%c options: %s", '6', "MTU_DISCOVER, RECVERR"
#ifdef IPV6_RECVHOPLIMIT
			", RECVHOPLIMIT, 2292HOPLIMIT"
#else
			", HOPLIMIT"
#endif
		);
	// PMTU
	int opt = IPV6_PMTUDISC_PROBE;
	if (setsockopt(sock, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &opt, sizeof(opt)) < 0) {
		opt = IPV6_PMTUDISC_DO;
		if (setsockopt(sock, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &opt, sizeof(opt)) < 0)
			err(errno, "setsockopt(%s)", "IPV6_MTU_DISCOVER");
	}
	// receive errors
	opt = 1;
	if (setsockopt(sock, IPPROTO_IPV6, IPV6_RECVERR, &opt, sizeof(opt)) < 0)
		err(errno, "setsockopt(%s)", "IPV6_RECVERR");
	// receive TTL
	opt = 1;
	if (
#ifdef IPV6_RECVHOPLIMIT
	(setsockopt(sock, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &opt, sizeof(opt)) < 0) &&
	(setsockopt(sock, IPPROTO_IPV6, IPV6_2292HOPLIMIT, &opt, sizeof(opt)) < 0)
#else
	 setsockopt(sock, IPPROTO_IPV6, IPV6_HOPLIMIT, &opt, sizeof(opt)) < 0
#endif
	)
		err(errno, "setsockopt(%s)", "IPV6_RECVHOPLIMIT, enable");
}

static void setsock_ttl(int sock, int level, int name, uint8_t ttl) {
	int opt = ttl;
	if (setsockopt(sock, level, name, &opt, sizeof(opt)) < 0)
		err(errno, "setsockopt(ttl=%d)", opt);
}

// return codes: <0 (-1) | 0 | >0 (mtu)
static int probe_ttl(state_t *rts) {
	int  probe = MAX_PROBES;
	bool again;
	do {
		again = false;
		memset(rts->pktbuf, 0, rts->pktsize);
		struct probehdr *hdr = rts->pktbuf;
		for (probe = 0; probe < MAX_PROBES; probe++) {
			hdr->ttl = rts->ttl;
			switch (rts->af) {
			case AF_INET6:
				((struct sockaddr_in6 *)&rts->addr)->sin6_port =
				    htons(rts->port + rts->hisptr);
				break;
			case AF_INET:
				((struct sockaddr_in *)&rts->addr)->sin_port =
				    htons(rts->port + rts->hisptr);
				break;
			}
			clock_gettime(CLOCK_MONOTONIC, &hdr->ts);
			rts->his[rts->hisptr].hops     = rts->ttl;
			rts->his[rts->hisptr].sendtime = hdr->ts;
			ssize_t size = rts->pktsize - rts->hdrsize;
			if (size < 0)
				return -1;
			if (sendto(rts->sock, rts->pktbuf, size, 0,
				   (struct sockaddr *)&rts->addr, rts->addrlen) > 0)
				break;
			int rc = recverr(rts);
			rts->his[rts->hisptr].hops = 0;
			if (rc == 0)
				return 0;
			if (rc > 0) {
				again = true;
				break;
			}
		}
	} while (again);

	rts->hisptr = (rts->hisptr + 1) & (HIS_ELEMS - 1);

	if (probe < MAX_PROBES) {
		data_wait(rts->sock);
		ssize_t got = recv(rts->sock, rts->pktbuf, rts->pktsize, MSG_DONTWAIT);
		if (got > 0) { // was print("reply received 8")
			printf("%2d?: %s: %zd %s\n", rts->ttl,
				_("reply received"), got, _("bytes"));
			return 0;
		}
		return recverr(rts);
	}

	printf("%2d:  %s\n", rts->ttl, _("send fail"));
	return 0;
}

NORETURN static void usage(int rc) {
	const char *options =
"  -4             use IPv4\n"
"  -6             use IPv6\n"
"  -b             print both name and IP\n"
"  -l <length>    use packet <length>\n"
"  -m <hops>      use maximum <hops>\n"
"  -n             no reverse DNS name resolution\n"
"  -p <port>      use destination <port>\n"
"  -v             verbose output\n"
"  -V             print version and exit\n"
;
	usage_common(rc, options, "TARGET", !MORE);
}

static inline int resolve(const char *target, state_t *rts, const struct addrinfo *hints) {
	if (rts->verbose)
		warnx("resolve(%s, port=%u)", target, rts->port);
	char service[NI_MAXSERV];
	sprintf(service, "%u", rts->port);
	//
	struct addrinfo *res = NULL;
	int rc = GAI_WRAPPER(target, service, hints, &res);
	if (rc) {
		if (rc == EAI_SYSTEM)
			err(errno, "%s", "getaddrinfo()");
		errx(rc, "%s", gai_strerror(rc));
	}
	if (!res)
		errx(EXIT_FAILURE, "%s", "getaddrinfo()");
	//
	int sock = -1;
	for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
		// ip4-in-ip6-space workaround
		if ((ai->ai_family == AF_INET6) &&
                    IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr))
                        switch (hints->ai_family) {
                        case AF_INET6:
                                err(ENETUNREACH, _(V4IN6_WARN));
                                break;
                        case AF_UNSPEC: {
                                // like ping:unmap_ai_sa4(ai);
				if (!ai->ai_addr)
					break;
			        struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)ai->ai_addr;
			        struct sockaddr_in sa4 = {
					.sin_family = AF_INET,
					.sin_addr.s_addr = ((uint32_t*)&sa6->sin6_addr)[3],
				};
				memcpy(ai->ai_addr, &sa4, sizeof(sa4));
				ai->ai_addrlen = sizeof(sa4);
				ai->ai_family  = AF_INET;
				warnx("%s: %s", WARN, _(V4IN6_WARN));
			}	break;
                        default:
				break;
                        }
		// open socket
		switch (ai->ai_family) {
		case AF_INET:
		case AF_INET6:
			sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
			if (rts->verbose)
				warnx("socket(af=%d, type=%d, proto=%d)",
					ai->ai_family, ai->ai_socktype, ai->ai_protocol);
			if (sock < 0)
				warn("socket(af=%d)", ai->ai_family);
			else { // success
				memcpy(&rts->addr, ai->ai_addr, ai->ai_addrlen);
				rts->addrlen = ai->ai_addrlen;
				rts->af      = ai->ai_family;
			}
			break;
		}
		if (sock >= 0)
			break;
	}
	//
	if (res)
		freeaddrinfo(res);
	return sock;
}

static inline void parse_opts(int argc, char **argv, struct addrinfo *hints, state_t *rts) {
	int ch;
	while ((ch = getopt(argc, argv, "bhl:m:np:vV46?")) != EOF) {
		switch (ch) {
		case '4':
		case '6': {
			bool ip6 = (ch == '6');
			int not = ip6 ? AF_INET : AF_INET6;
			if (hints->ai_family == not)
				OPTEXCL('4', '6');
			hints->ai_family = ip6 ? AF_INET6 : AF_INET;
			rts->hdrsize = ip6 ? DEFAULT_IPH6 : DEFAULT_IPH4;
		}
			break;
		case 'n':
			rts->dns      = false;
			rts->ni_flags = NI_NUMERICHOST;
			break;
		case 'b':
			rts->show_both = true;
			break;
		case 'l':
			rts->pktsize = VALID_INTSTR(0, UINT16_MAX);
			break;
		case 'm':
			rts->max_hops = VALID_INTSTR(0, UINT8_MAX);
			break;
		case 'p':
			rts->port = VALID_INTSTR(0, UINT16_MAX);
			break;
		case 'v':
			rts->verbose = true;
			break;
		case 'V':
			version_n_exit(EXIT_SUCCESS, FEAT_IDN | FEAT_NLS);
		case 'h':
		case '?':
			usage(EXIT_SUCCESS);
		default:
			usage(EXIT_FAILURE);
		}
	}
}

static void resume(const state_t *rts) {
	printf("     %s: %s=%d", _("Resume"), _("pmtu"), rts->pktsize);
	if (rts->hops_to >= 0)
		printf(" %s=%d", _("hops"), rts->hops_to);
	if (rts->hops_from >= 0)
		printf(" %s=%d", _("back"), rts->hops_from);
	printf("\n");
}


int main(int argc, char **argv) {
	setmyname(argv[0]);
	SET_NLS;
	atexit(close_stdout);

	state_t rts = {
		.sock      = -1,
		.port      = BASEPORT,
		.max_hops  = DEFAULT_HOPS,
		.hops_to   = -1,
		.hops_from = -1,
		.ni_flags  = NI_FLAGS,
		.dns       = true,
	};

	struct addrinfo hints = {
		.ai_family   = AF_UNSPEC,
		.ai_socktype = SOCK_DGRAM,
		.ai_protocol = IPPROTO_UDP,
		.ai_flags    = AI_FLAGS,
	};
	// Support tracepath[46] tool names */
	if (argv[0][strlen(argv[0]) - 1] == '4')
		hints.ai_family = AF_INET;
	else if (argv[0][strlen(argv[0]) - 1] == '6')
		hints.ai_family = AF_INET6;

	// Parse options
	parse_opts(argc, argv, &hints, &rts);
	argc -= optind;
	argv += optind;
	if (argc <= 0) {
		errno = EDESTADDRREQ;
		warn("%s", _("No goal"));
		usage(EDESTADDRREQ);
	} else if (argc != 1)
		usage(EINVAL);

	//
	rts.sock = resolve(argv[0], &rts, &hints);
	if ((rts.sock < 0) || !rts.af)
		err(EXIT_FAILURE, "resolve(%s)", argv[0]);

	switch (rts.af) {
	case AF_INET6:
		setsock6_opts(rts.sock, rts.verbose);
		rts.hdrsize = DEFAULT_IPH6;
		if (!rts.pktsize)
			rts.pktsize = DEFAULT_MTU;
		break;
	case AF_INET:
		setsock4_opts(rts.sock, rts.verbose);
		rts.hdrsize = DEFAULT_IPH4;
		if (!rts.pktsize)
			rts.pktsize = DEFAULT_MTU;
		break;
	default:
		errno = EAFNOSUPPORT;
		err(errno, "%d", rts.af);
	}

	if (rts.pktsize <= rts.hdrsize) {
		errno = ERANGE;
		err(errno, "%s: %u-%u", _("Packet length"), rts.hdrsize, UINT16_MAX);
	}

	rts.pktbuf = malloc(rts.pktsize);
	if (!rts.pktbuf)
		err(errno, "malloc(%d)", rts.pktsize);

	if (rts.verbose)
		warnx("run upto %u hops", rts.max_hops);
	for (int ttl = 1; ttl <= rts.max_hops; ttl++) {
		rts.ttl = ttl;
		// set sock TTL
		switch (rts.af) {
		case AF_INET6:
			setsock_ttl(rts.sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, ttl);
			break;
		case AF_INET:
			setsock_ttl(rts.sock, IPPROTO_IP, IP_TTL, ttl);
			break;
		default:
			continue;
		}
		int rc = -1;
		bool again;
		do {
			again = false;
			for (int i = 0; i < 3; i++) {
				uint16_t size = rts.pktsize;
				// possible get: <0 (-1) | 0 | >0 (mtu)
				rc = probe_ttl(&rts);
				if (rts.pktsize != size) {
					again = true;
					break;
				}
				if (rc == 0) {
					resume(&rts);
					return 0;
				}
				if (rc > 0)
					break;
			}
		} while (again);
		if (rc < 0)
			printf("%2d:  %s\n", rts.ttl, _("no reply"));
	}
	printf("     %s: %s=%d\n", _("Too many hops"), _("pmtu"), rts.pktsize);

	resume(&rts);
	return 0;
}

