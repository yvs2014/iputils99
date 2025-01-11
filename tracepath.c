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

#include "iputils_common.h"

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <time.h>
#include <err.h>

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

#if defined(USE_IDN) && defined(NI_IDN)
# define NI_FLAGS	NI_IDN
#else
# define NI_FLAGS	0
#endif

enum {
	MAX_PROBES = 10,

	MAX_HOPS_DEFAULT = 30,
	MAX_HOPS_LIMIT = 255,

	HOST_COLUMN_SIZE = 52,

	HIS_ARRAY_SIZE = 64,

	DEFAULT_OVERHEAD_IPV4 = 28,
	DEFAULT_OVERHEAD_IPV6 = 48,

	DEFAULT_MTU_IPV4 = 65535,
	DEFAULT_MTU_IPV6 = 128000,

	DEFAULT_BASEPORT = 44444,

	ANCILLARY_DATA_LEN = 512,
};

struct hhistory {
	int hops;
	struct timespec sendtime;
};

struct probehdr {
	uint32_t ttl;
	struct timespec ts;
};

typedef struct tracepath_flags {
	bool no_resolve;
	bool show_both;
	bool mapped;
} tracepath_flags;

typedef struct run_state {
	struct hhistory his[HIS_ARRAY_SIZE];
	int hisptr;
	struct sockaddr_storage target;
	struct addrinfo *ai;
	int socket_fd;
	socklen_t targetlen;
	uint16_t base_port;
	uint8_t ttl;
	int max_hops;
	int overhead;
	int mtu;
	void *pktbuf;
	int hops_to;
	int hops_from;
	tracepath_flags opt;
} run_state;

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

static void print_host(const char *a, const char *b, bool show_both) {
	int plen = printf("%s", a);
	if (show_both)
		plen += printf(" (%s)", b);
	if (plen >= HOST_COLUMN_SIZE)
		plen = HOST_COLUMN_SIZE - 1;
	printf("%*s", HOST_COLUMN_SIZE - plen, "");
}

// return codes: <0 (-1) | 0 | >0 (mtu)
static int recverr(run_state *rts) {
	struct sockaddr_storage addr;
	struct probehdr rcvbuf;
	struct iovec iov = {
		.iov_base = &rcvbuf,
		.iov_len = sizeof(rcvbuf)
	};
	char cbuf[ANCILLARY_DATA_LEN];
	const struct msghdr reset = {
		.msg_name = (uint8_t *)&addr,
		.msg_namelen = sizeof(addr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = cbuf,
		.msg_controllen = sizeof(cbuf),
	};

	int progress = -1;
restart:
	memset(&rcvbuf, -1, sizeof(rcvbuf));
	struct msghdr msg = reset;

	struct timespec ts = {0};
	clock_gettime(CLOCK_MONOTONIC, &ts);
	ssize_t recv_size = recvmsg(rts->socket_fd, &msg, MSG_ERRQUEUE);
	if (recv_size < 0) {
		if (errno == EAGAIN)
			return progress;
		goto restart;
	}

	progress = rts->mtu;

	int slot = -rts->base_port;
	switch (rts->ai->ai_family) {
	case AF_INET6:
		slot += ntohs(((struct sockaddr_in6 *)&addr)->sin6_port);
		break;
	case AF_INET:
		slot += ntohs(((struct sockaddr_in *)&addr)->sin_port);
		break;
	}

	int sndhops = -1;
	struct timespec *retts = NULL;
	if ((slot >= 0) && (slot < (HIS_ARRAY_SIZE - 1)) && rts->his[slot].hops) {
		sndhops = rts->his[slot].hops;
		retts = &rts->his[slot].sendtime;
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

	char hnamebuf[NI_MAXHOST] = "";
	if (e->ee_origin == SO_EE_ORIGIN_LOCAL)
		printf("%2d?: [%s] ", rts->ttl, _("LOCALHOST"));
	else if (e->ee_origin == SO_EE_ORIGIN_ICMP6 ||
		 e->ee_origin == SO_EE_ORIGIN_ICMP) {
		char abuf[NI_MAXHOST];
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

		if (rts->opt.no_resolve || rts->opt.show_both) {
			if (getnameinfo(sa, salen, abuf, sizeof(abuf), NULL, 0, NI_NUMERICHOST))
				strcpy(abuf, "???");
		} else
			abuf[0] = 0;

		if (!rts->opt.no_resolve || rts->opt.show_both) {
			fflush(stdout);
			if (getnameinfo(sa, salen, hnamebuf, sizeof(hnamebuf), NULL, 0, NI_FLAGS))
				strcpy(hnamebuf, "???");
		} else
			hnamebuf[0] = 0;

		{ bool no = rts->opt.no_resolve;
		  print_host(no ? abuf : hnamebuf, no ? hnamebuf : abuf, rts->opt.show_both); }
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
		printf("%s %d\n", _("pmtu"), e->ee_info);
		rts->mtu = e->ee_info;
		progress = rts->mtu;
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
	goto restart;
}

// return codes: <0 (-1) | 0 | >0 (mtu)
static int probe_ttl(run_state *rts) {
	struct probehdr *hdr = rts->pktbuf;
	memset(rts->pktbuf, 0, rts->mtu);
restart:
	{ int i;
	  for (i = 0; i < MAX_PROBES; i++) {
		hdr->ttl = rts->ttl;
		switch (rts->ai->ai_family) {
		case AF_INET6:
			((struct sockaddr_in6 *)&rts->target)->sin6_port =
			    htons(rts->base_port + rts->hisptr);
			break;
		case AF_INET:
			((struct sockaddr_in *)&rts->target)->sin_port =
			    htons(rts->base_port + rts->hisptr);
			break;
		}
		clock_gettime(CLOCK_MONOTONIC, &hdr->ts);
		rts->his[rts->hisptr].hops     = rts->ttl;
		rts->his[rts->hisptr].sendtime = hdr->ts;
		if (sendto(rts->socket_fd, rts->pktbuf, rts->mtu - rts->overhead, 0,
			   (struct sockaddr *)&rts->target, rts->targetlen) > 0)
			break;
		int rc = recverr(rts);
		rts->his[rts->hisptr].hops = 0;
		if (rc == 0)
			return 0;
		if (rc > 0)
			goto restart;
	  }
	  rts->hisptr = (rts->hisptr + 1) & (HIS_ARRAY_SIZE - 1);

	  if (i < MAX_PROBES) {
		data_wait(rts->socket_fd);
		ssize_t got = recv(rts->socket_fd, rts->pktbuf, rts->mtu, MSG_DONTWAIT);
		if (got > 0) { // was print("reply received 8")
			printf("%2d?: %s: %zd %s\n", rts->ttl,
				_("reply received"), got, _("bytes"));
			return 0;
		}
		return recverr(rts);
	  }
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
"  -V             print version and exit\n"
;
	usage_common(rc, options, false);
}

int main(int argc, char **argv) {
	setmyname(argv[0]);
	SET_NLS;
	atexit(close_stdout);

	run_state rts = {
		.socket_fd = -1,
		.max_hops  = MAX_HOPS_DEFAULT,
		.hops_to   = -1,
		.hops_from = -1,
	};

	struct addrinfo hints = {
		.ai_family   = AF_UNSPEC,
		.ai_socktype = SOCK_DGRAM,
		.ai_protocol = IPPROTO_UDP,
		.ai_flags    = AI_FLAGS,
	};
	/* Support being called using `tracepath4` or `tracepath6` symlinks */
	if (argv[0][strlen(argv[0]) - 1] == '4')
		hints.ai_family = AF_INET;
	else if (argv[0][strlen(argv[0]) - 1] == '6')
		hints.ai_family = AF_INET6;

	int ch;
	while ((ch = getopt(argc, argv, "46nbh?l:m:p:V")) != EOF) {
		switch (ch) {
		case '4':
		case '6': {
			bool ip6 = (ch == '6');
			int not = ip6 ? AF_INET : AF_INET6;
			if (hints.ai_family == not)
				OPTEXCL('4', '6');
			hints.ai_family = ip6 ? AF_INET6 : AF_INET;
		}
			break;
		case 'n':
			rts.opt.no_resolve = true;
			break;
		case 'b':
			rts.opt.show_both = true;
			break;
		case 'l':
			rts.mtu = strtoll_or_err(optarg, _("Invalid argument"), rts.overhead, INT_MAX);
			break;
		case 'm':
			rts.max_hops = strtoll_or_err(optarg, _("Invalid argument"), 0, MAX_HOPS_LIMIT);
			break;
		case 'p':
			rts.base_port = strtoll_or_err(optarg, _("Invalid argument"), 0, UINT16_MAX);
			break;
		case 'V':
			version_n_exit(EXIT_SUCCESS);
		case 'h':
		case '?':
			usage(EXIT_SUCCESS);
		default:
			usage(EXIT_FAILURE);
		}
	}

	argc -= optind;
	argv += optind;
	if (argc <= 0) {
		errno = EDESTADDRREQ;
		warn("%s", _("No goal"));
		usage(EDESTADDRREQ);
	} else if (argc != 1)
		usage(EINVAL);

	/* Backward compatibility */
	if (!rts.base_port) {
		char *p = strchr(argv[0], '/');
		if (p) {
			*p = 0;
			rts.base_port = strtoll_or_err(p + 1, _("Invalid argument"), 0, UINT16_MAX);
		} else
			rts.base_port = DEFAULT_BASEPORT;
	}
	char pbuf[NI_MAXSERV];
	sprintf(pbuf, "%u", rts.base_port);

	struct addrinfo *res = NULL;
	{ // resolver
	  int rc = GAI_WRAPPER(argv[0], pbuf, &hints, &res);
	  if (rc) {
		if (rc == EAI_SYSTEM)
			err(errno, "%s", "getaddrinfo()");
		errx(rc, "%s", gai_strerror(rc));
	  }
	}
	if (!res)
		errx(EXIT_FAILURE, "%s", "getaddrinfo()");

	int af = 0;
	for (rts.ai = res; rts.ai; rts.ai = rts.ai->ai_next) {
		af = rts.ai->ai_family;
		if ((af == AF_INET) || (af == AF_INET6)) {
			rts.socket_fd = socket(af, rts.ai->ai_socktype, rts.ai->ai_protocol);
			if (rts.socket_fd >= 0) {
				memcpy(&rts.target, rts.ai->ai_addr, rts.ai->ai_addrlen);
				rts.targetlen = rts.ai->ai_addrlen;
				break; // success
			}
		}
	}
	if ((rts.socket_fd < 0) || !rts.ai)
		err(EXIT_FAILURE, "socket/ai");

	switch (af) {
	case AF_INET6:
		rts.overhead = DEFAULT_OVERHEAD_IPV6;
		if (!rts.mtu)
			rts.mtu = DEFAULT_MTU_IPV6;
		if (rts.mtu <= rts.overhead)
			goto pktlen_error;

		{ // path mtu
		  int opt = IPV6_PMTUDISC_PROBE;
		  if (setsockopt(rts.socket_fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER,
				&opt, sizeof(opt)) < 0) {
			opt = IPV6_PMTUDISC_DO;
			if (setsockopt(rts.socket_fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER,
					&opt, sizeof(opt)) < 0)
				err(errno, "setsockopt(%s)", "IPV6_MTU_DISCOVER");
		  }
		}
		{ // recv error
		  int on = 1;
		  if (setsockopt(rts.socket_fd, IPPROTO_IPV6, IPV6_RECVERR, &on, sizeof(on)) < 0)
			err(errno, "setsockopt(%s)", "IPV6_RECVERR");
		}
		{ // hop limit
		  int on = 1;
		  if (
#ifdef IPV6_RECVHOPLIMIT
			(setsockopt(rts.socket_fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT,
				&on, sizeof(on)) < 0) &&
			(setsockopt(rts.socket_fd, IPPROTO_IPV6, IPV6_2292HOPLIMIT,
				&on, sizeof(on)) < 0)
#else
			(setsockopt(rts.socket_fd, IPPROTO_IPV6, IPV6_HOPLIMIT,
				&on, sizeof(on)) < 0)
#endif
		  ) err(errno, "setsockopt(%s)", "IPV6_RECVHOPLIMIT, enable");
		}
		if (!IN6_IS_ADDR_V4MAPPED(&(((struct sockaddr_in6 *)&rts.target)->sin6_addr)))
			break;
		rts.opt.mapped = true;
		/*FALLTHROUGH*/
	case AF_INET:
		rts.overhead = DEFAULT_OVERHEAD_IPV4;
		if (!rts.mtu)
			rts.mtu = DEFAULT_MTU_IPV4;
		if (rts.mtu <= rts.overhead)
			goto pktlen_error;

		{ // path mtu
		  int opt = IP_PMTUDISC_PROBE;
		  if (setsockopt(rts.socket_fd, IPPROTO_IP, IP_MTU_DISCOVER, &opt, sizeof(opt)) < 0)
			err(errno, "setsockopt(%s)", "IP_MTU_DISCOVER");
		}
		{ // recv error
		  int on = 1;
		  if (setsockopt(rts.socket_fd, IPPROTO_IP, IP_RECVERR, &on, sizeof(on)) < 0)
			err(errno, "setsockopt(%s)", "IP_RECVERR");
		}
		{ // ttl
		  int on = 1;
		  if (setsockopt(rts.socket_fd, IPPROTO_IP, IP_RECVTTL, &on, sizeof(on)) < 0)
			err(errno, "setsockopt(%s)", "IP_RECVTTL");
		}
	}

	rts.pktbuf = malloc(rts.mtu);
	if (!rts.pktbuf)
		err(errno, "malloc(%d)", rts.mtu);

	for (rts.ttl = 1; rts.ttl <= rts.max_hops; rts.ttl++) {
		int ttl = rts.ttl;
		switch (af) {
		case AF_INET6:
			if (setsockopt(rts.socket_fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
					&ttl, sizeof(ttl)) < 0)
				err(errno, "setsockopt(%s)", "IPV6_UNICAST_HOPS");
			if (!rts.opt.mapped)
				break;
			/*FALLTHROUGH*/
		case AF_INET:
			if (setsockopt(rts.socket_fd, IPPROTO_IP, IP_TTL,
					&ttl, sizeof(ttl)) < 0)
				err(errno, "setsockopt(%s)", "IP_TTL");
		}

		int rc = -1;
restart:
		for (int i = 0; i < 3; i++) {
			int old_mtu = rts.mtu;
			// possible get: <0 (-1) | 0 | >0 (mtu)
			rc = probe_ttl(&rts);
			if (rts.mtu != old_mtu)
				goto restart;
			if (rc == 0)
				goto done;
			if (rc > 0)
				break;
		}
		if (rc < 0)
			printf("%2d:  %s\n", rts.ttl, _("no reply"));
	}
	printf("     %s: %s=%d\n", _("Too many hops"), _("pmtu"), rts.mtu);

done:
	if (res)
		freeaddrinfo(res);
	printf("     %s: %s=%d", _("Resume"), _("pmtu"), rts.mtu);
	if (rts.hops_to >= 0)
		printf(" %s=%d", _("hops"), rts.hops_to);
	if (rts.hops_from >= 0)
		printf(" %s=%d", _("back"), rts.hops_from);
	printf("\n");
	exit(EXIT_SUCCESS);

pktlen_error:
	errno = ERANGE;
	err(errno, "%s: %d - %d", _("Packet length"), rts.overhead, INT_MAX);
}

