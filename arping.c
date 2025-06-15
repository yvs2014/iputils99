/*
 * arping.c
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 * 		YOSHIFUJI Hideaki <yoshfuji@linux-ipv6.org>
 */

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/rtnetlink.h>
#include <netdb.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <limits.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <err.h>
#include <errno.h>
#include <assert.h>

#include "iputils.h"
#include "str2num.h"
#include "nbind.h"
#ifdef HAVE_LIBCAP
#include "caps.h"
#else
#include "perm.h"
#endif

/*
 * As of July 2021 AX.25 PID values are not currently defined in any
 * userspace headers.
 */
#ifndef AX25_P_IP
# define AX25_P_IP	0xcc	/* ARPA Internet Protocol     */
#endif

#define FINAL_PACKS	2

#define NETLINK		"NETLINK"
#define NL_WRONG_TYPE	"%s: got type=%u, expected=%u"

#define NLSTREQ(a, b) (!strncmp((a), (b), IF_NAMESIZE))


typedef struct arpdev {
	int ndx; // valid: >0
	char name[IF_NAMESIZE];
	struct ifaddrs *ifa, *ifa_list;
} arpdev_t;

typedef struct arping_opt_s {
	bool dad;
	bool quiet;
	bool advert;
	bool quit; // on reply
	bool unicast;
	bool broadcast;
	bool unsolicited;
} arpopt_t;

typedef struct run_state {
	arpdev_t dev;
	char *source;
	struct in_addr src, dst;
	int af; // ai_family
	char *target;
	int count;
	int timeout;
	unsigned interval;
	int sock;
	struct sockaddr_storage me;
	struct sockaddr_storage he;
	struct timespec start;
	struct timespec last;
	int sent;
	int brd_sent;
	int received;
	int brd_recv;
	int req_recv;
	arpopt_t opt;
} state_t;


/*
 * All includes, definitions, struct declarations, and global variables are
 * above.  After this comment all you can find is functions.
 */

static inline size_t sll_len(size_t halen) {
	size_t len = offsetof(struct sockaddr_ll, sll_addr) + halen;
	return (len < sizeof(struct sockaddr_ll)) ?
		sizeof(struct sockaddr_ll) : len;
}

NORETURN static void usage(int rc) {
	drop_priv();
	const char *options =
"  -f            quit on first reply\n"
"  -q            be quiet\n"
"  -b            keep on broadcasting, do not unicast\n"
"  -D            duplicate address detection mode\n"
"  -U            unsolicited ARP mode, update your neighbours\n"
"  -A            ARP answer mode, update your neighbours\n"
"  -V            print version and exit\n"
"  -c <count>    how many packets to send\n"
"  -w <timeout>  how long to wait for a reply\n"
"  -i <interval> set interval between packets (default: 1 second)\n"
"  -I <device>   which ethernet device to use\n"
"  -s <source>   source IP address\n"
;
	usage_common(rc, options, "TARGET", !MORE);
}

static int send_pack(state_t *ctl) {
	unsigned char buf[256];
	struct arphdr *ah = (struct arphdr *)buf;
	struct sockaddr_ll *ME = (struct sockaddr_ll *)&(ctl->me);
	struct sockaddr_ll *HE = (struct sockaddr_ll *)&(ctl->he);

	ah->ar_hrd = htons(ME->sll_hatype);
	if (ah->ar_hrd == htons(ARPHRD_FDDI))
		ah->ar_hrd = htons(ARPHRD_ETHER);

	/*
	 * Exceptions everywhere. AX.25 uses the AX.25 PID value not the
	 * DIX code for the protocol. Make these device structure fields.
	 */
	if (ah->ar_hrd == htons(ARPHRD_AX25) ||
	    ah->ar_hrd == htons(ARPHRD_NETROM))
		ah->ar_pro = htons(AX25_P_IP);
	else
		ah->ar_pro = htons(ETH_P_IP);

	ah->ar_hln = ME->sll_halen;
	ah->ar_pln = 4;
	ah->ar_op  = ctl->opt.advert ? htons(ARPOP_REPLY) : htons(ARPOP_REQUEST);

	unsigned char *p = (unsigned char *)(ah + 1);
	memcpy(p, &ME->sll_addr, ah->ar_hln);
	p += ME->sll_halen;

	memcpy(p, &ctl->src, 4);
	p += 4;

	memcpy(p, ctl->opt.advert ? &ME->sll_addr : &HE->sll_addr, ah->ar_hln);
	p += ah->ar_hln;

	memcpy(p, &ctl->dst, 4);
	p += 4;

	struct timespec now = {0};
	clock_gettime(CLOCK_MONOTONIC, &now);
	int err = sendto(ctl->sock, buf, p - buf, 0, (struct sockaddr *)HE, sll_len(ah->ar_hln));
	if (err == (p - buf)) {
		ctl->last = now;
		ctl->sent++;
		if (!ctl->opt.unicast)
			ctl->brd_sent++;
	}
	return err;
}

static void resume(const state_t *rts) {
	printf("%s: %d", _("Sent probes"), rts->sent);
	printf(" (%d %s)\n", rts->brd_sent,
		_n("broadcast", "broadcasts", rts->brd_sent));
	printf("%s: %d", _("Received responses"), rts->received);
	if (rts->brd_recv || rts->req_recv) {
		printf(" (");
		if (rts->req_recv)
			printf("%d %s", rts->req_recv,
				_n("request", "requests", rts->req_recv));
		if (rts->brd_recv)
			printf("%s%d %s",
				rts->req_recv ? ", " : "", rts->brd_recv,
				_n("broadcast", "broadcasts", rts->brd_recv));
		printf(")");
	}
	printf("\n");
	fflush(stdout);
}

static void print_hex(unsigned char *p, int len) {
	for (int i = 0; i < len; i++) {
		printf("%02X", p[i]);
		if (i != (len - 1))
			printf(":");
	}
}

static inline int print_pack(state_t *rts,
	unsigned char *buf, ssize_t len, bool broadcast, uint16_t sll_hatype)
{
	struct timespec ts = {0};
	clock_gettime(CLOCK_MONOTONIC, &ts);

	struct arphdr *ah = (struct arphdr *)buf;
	/* Only these types are recognised */
	if (ah->ar_op != htons(ARPOP_REQUEST) &&
	    ah->ar_op != htons(ARPOP_REPLY))
		return 0;

	/* ARPHRD check and this darned FDDI hack here :-( */
	if ((ah->ar_hrd != htons(sll_hatype)) &&
	   ((sll_hatype != ARPHRD_FDDI) || (ah->ar_hrd != htons(ARPHRD_ETHER))))
		return 0;

	/*
	 * Protocol must be IP - but exceptions everywhere. AX.25 and NETROM
	 * use the AX.25 PID value not the DIX code for the protocol.
	 */
	if ((ah->ar_hrd == htons(ARPHRD_AX25)) ||
	    (ah->ar_hrd == htons(ARPHRD_NETROM))) {
		if (ah->ar_pro != htons(AX25_P_IP))
			return 0;
	} else if (ah->ar_pro != htons(ETH_P_IP))
		return 0;

	if (ah->ar_pln != 4)
		return 0;
	if (ah->ar_hln != ((struct sockaddr_ll *)&rts->me)->sll_halen)
		return 0;
	if (len < (ssize_t) sizeof(*ah) + 2 * (4 + ah->ar_hln))
		return 0;

	unsigned char *p = (unsigned char *)(ah + 1);
	struct in_addr src_ip;
	memcpy(&src_ip, p + ah->ar_hln, 4);
	struct in_addr dst_ip;
	memcpy(&dst_ip, p + ah->ar_hln + 4 + ah->ar_hln, 4);

	if (!rts->opt.dad) {
		if (src_ip.s_addr != rts->dst.s_addr)
			return 0;
		if (rts->src.s_addr != dst_ip.s_addr)
			return 0;
		if (memcmp(p + ah->ar_hln + 4,
				((struct sockaddr_ll *)&rts->me)->sll_addr,
				ah->ar_hln))
			return 0;
	} else {
		/*
		 * DAD packet was:
		 * src_ip = 0 (or some src)
		 * src_hw = ME
		 * dst_ip = tested address
		 * dst_hw = <unspec>
		 *
		 * We fail, if receive request/reply with:
		 * src_ip = tested_address
		 * src_hw != ME
		 * if src_ip in request was not zero, check
		 * also that it matches to dst_ip, otherwise
		 * dst_ip/dst_hw do not matter.
		 */
		if (src_ip.s_addr != rts->dst.s_addr)
			return 0;
		struct sockaddr_ll *sll = (struct sockaddr_ll *)&rts->me;
		if (!memcmp(p, sll->sll_addr, sll->sll_halen))
			return 0;
		if (rts->src.s_addr && (rts->src.s_addr != dst_ip.s_addr))
			return 0;
	}
	if (!rts->opt.quiet) {
		bool printed = false;
		printf("%s %s %s", broadcast ? _("Broadcast") : _("Unicast"),
			_("from"), inet_ntoa(src_ip));
		printf(" [");
		print_hex(p, ah->ar_hln);
		printf("]");
		if (dst_ip.s_addr != rts->src.s_addr) {
			printf(" %s %s", _("for"), inet_ntoa(dst_ip));
			printed = true;
		}
		if (memcmp(p + ah->ar_hln + 4,
			((struct sockaddr_ll *)&rts->me)->sll_addr,
			ah->ar_hln))
		{
			if (!printed)
				printf(" %s", _("for"));
			printf(" [");
			print_hex(p + ah->ar_hln + 4, ah->ar_hln);
			printf("]");
		}
		if (rts->last.tv_sec) {
			struct timespec sub = {0};
			timespecsub(&ts, &rts->last, &sub);
			double ms = sub.tv_sec * 1000 + sub.tv_nsec / 1000000.;
			printf(" " TMMS, ms, _("ms"));
		} else
			printf(" %s?", _("UNSOLICITED"));
		putchar('\n');
		fflush(stdout);
	}
	rts->received++;
	if (rts->timeout && (rts->received == rts->count))
		return FINAL_PACKS;
	if (broadcast)
		rts->brd_recv++;
	if (ah->ar_op == htons(ARPOP_REQUEST))
		rts->req_recv++;
	if (rts->opt.quit || (!rts->count && (rts->received == rts->sent)))
		return FINAL_PACKS;
	if (!rts->opt.broadcast) {
		memcpy(((struct sockaddr_ll *)&rts->he)->sll_addr, p,
		       ((struct sockaddr_ll *)&rts->me)->sll_halen);
		rts->opt.unicast = true;
	}
	return 1;
}

static int outgoing_device(struct nlmsghdr *nh, arpdev_t *dev) {
	if (nh->nlmsg_type != RTM_NEWROUTE) {
		warnx(NL_WRONG_TYPE, NETLINK, nh->nlmsg_type, RTM_NEWROUTE);
		return 1;
	}
	struct rtmsg *rm = NLMSG_DATA(nh);
	size_t len = RTM_PAYLOAD(nh);
	for (struct rtattr *ra = RTM_RTA(rm); RTA_OK(ra, (unsigned short)len);
	     ra = RTA_NEXT(ra, len))
		if (ra->rta_type == RTA_OIF) {
			int *oif = RTA_DATA(ra);
			dev->ndx = *oif;
			if (!if_indextoname(dev->ndx, dev->name)) {
				warn("if_indextoname(%u)", dev->ndx);
				return 1;
			}
		}
	return 0;
}

static void netlink_query(arpdev_t *dev, int flags, int type,
	const void *arg, size_t len)
{
	static uint32_t seq;

	struct sockaddr_nl sa = {.nl_family = AF_NETLINK};
	struct iovec iov = {0};
	struct msghdr mh = {
		.msg_name = (void *)&sa,
		.msg_namelen = sizeof(sa),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};

	const size_t buffer_size = 4096;
	struct nlmsghdr *unmodified_nh = calloc(1, buffer_size);
	struct nlmsghdr *nh = unmodified_nh;
	if (!nh)
		err(errno, "calloc(%zu)", buffer_size);

	nh->nlmsg_len = NLMSG_LENGTH(len);
	nh->nlmsg_flags = flags;
	nh->nlmsg_type = type;
	nh->nlmsg_seq = ++seq;
	memcpy(NLMSG_DATA(nh), arg, len);

	iov.iov_base = nh;
	iov.iov_len = buffer_size;

	int ret = 1;
	int fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (fd < 0) {
		warn("socket(%s)", NETLINK);
		goto fail;
	}
	if (sendmsg(fd, &mh, 0) < 0) {
		warn("sendmsg(%s)", NETLINK);
		goto fail;
	}

	ssize_t msg_len = 0;
	do {
		msg_len = recvmsg(fd, &mh, 0);
	} while ((msg_len < 0) && (errno == EINTR));

	for (nh = iov.iov_base; NLMSG_OK(nh, msg_len); nh = NLMSG_NEXT(nh, msg_len)) {
		if (nh->nlmsg_seq == seq) switch (nh->nlmsg_type) {
		case NLMSG_ERROR:
			errno = abs(((struct nlmsgerr *)NLMSG_DATA(nh))->error);
			if (!errno) errno = EIO;
			warn("%s", NETLINK);
			break;
		case NLMSG_OVERRUN:
			errno = EOVERFLOW;
			warn("%s: iov", NETLINK);
			goto fail;
		case NLMSG_DONE:
			ret = 0;
			break;
		default:
			ret = outgoing_device(nh, dev);
			break;
		}
	}
 fail:
	free(unmodified_nh);
	if (0 <= fd)
		close(fd);
	if (ret)
		exit(EXIT_FAILURE);
}

static void guess_device(int af, struct in_addr dst, arpdev_t *dev) {
	struct {
		struct rtmsg  rm;
		struct rtattr ra;
		struct in_addr addr;
	} query = {
		.rm.rtm_family = af,
		.ra = {
			.rta_len  = RTA_LENGTH(sizeof(query.addr)),
			.rta_type = RTA_DST,
		},
		.addr = dst,
	};
	size_t len = NLMSG_ALIGN(sizeof(struct rtmsg)) + RTA_LENGTH(sizeof(query.addr));
	netlink_query(dev, NLM_F_REQUEST, RTM_GETROUTE, &query, len);
}

/* Common check for ifa->ifa_flags */
static bool valid_flags(unsigned flags, const char *name, bool quiet, bool dad) {
	if (!(flags & IFF_UP)) {
		if (name && name[0]) {
			if (!quiet)
				warnx("%s: %s", name, _("Interface is down"));
			exit(EINVAL);
		}
		return false;
	}
	if (flags & (IFF_NOARP | IFF_LOOPBACK)) {
		if (name && name[0]) {
			if (!quiet)
				warnx("%s: %s", name, _("Interface is not ARPable"));
			exit(dad ? EXIT_SUCCESS : EINVAL);
		}
		return false;
	}
	return true;
}

static bool valid_ifa(const struct ifaddrs *ifa,
		const arpdev_t *dev, const arpopt_t *opt) {
	return
	ifa->ifa_name && ifa->ifa_broadaddr && ifa->ifa_addr &&
	(ifa->ifa_addr->sa_family == AF_PACKET) &&
	valid_flags(ifa->ifa_flags, dev->name, opt->quiet, opt->dad) &&
	((struct sockaddr_ll *)ifa->ifa_addr)->sll_halen;
}

/*
 * check_device()
 *
 * This function checks 1) if the device (if given) is okay for ARP,
 * or 2) find fist appropriate device on the system.
 *
 * Return value:
 *	>0	: Succeeded, and appropriate device not found.
 *		  dev.ndx remains 0.
 *	0	: Succeeded, and appropriate device found.
 *		  dev.ndx is set.
 *	<0	: Failed.  Support not found, or other
 *		: system error.
 *
 * If an appropriate device found, it is recorded inside the
 * "device" variable for later reference.
 *
 */
static int check_device(state_t *rts) {
	assert(rts->dev.name[0]);
	//
	if (getifaddrs(&rts->dev.ifa_list)) {
		warn("%s", "getifaddrs()");
		return -1;
	}
	if (!rts->dev.ifa_list) {
		warnx("%s", strerror(ENODATA));
		return 1;
	}

	for (struct ifaddrs *ifa = rts->dev.ifa_list; ifa; ifa = ifa->ifa_next) {
		if (NLSTREQ(ifa->ifa_name, rts->dev.name))
			if (valid_ifa(ifa, &rts->dev, &rts->opt)) {
				rts->dev.ifa = ifa;
				break;
			}
	}

	int rc = 0;
	if (rts->dev.ifa) { // interface found
		rts->dev.ndx = if_nametoindex(rts->dev.ifa->ifa_name);
		if (!rts->dev.ndx) {
			warn("if_nametoindex(%s)", rts->dev.ifa->ifa_name);
			rc = -1;
		}
	}

	if (((rc < 0) || !rts->dev.ifa) && rts->dev.ifa_list) {
		freeifaddrs(rts->dev.ifa_list);
		rts->dev.ifa_list = NULL;
	}
	return (rc < 0) ? rc : !rts->dev.ndx;
}

/*
 * This fills the device "broadcast address"
 * based on information found by check_device() function.
 */
static void find_brd_addr(arpdev_t *dev, struct sockaddr_ll *he, bool quiet) {
	struct sockaddr_ll *ll = dev->ifa ?
		(struct sockaddr_ll *)dev->ifa->ifa_broadaddr :
		NULL;
	if (ll && (ll->sll_halen == he->sll_halen))
		memcpy(he->sll_addr, ll->sll_addr, he->sll_halen);
	else {
		if (!quiet)
			warnx("%s: %s", _WARN, _("Using default broadcast address"));
		memset(he->sll_addr, -1, he->sll_halen);
	}
	if (dev->ifa_list) { // no need more
		freeifaddrs(dev->ifa_list);
		dev->ifa = dev->ifa_list = NULL;
	}
}

static int event_loop(state_t *ctl) {
	enum {
		POLLFD_SIGNAL = 0,
		POLLFD_TIMER,
		POLLFD_TIMEOUT,
		POLLFD_SOCKET,
		POLLFD_COUNT
	};

	/* signalfd */
	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGQUIT);
	sigaddset(&mask, SIGTERM);
	if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
		warn("%s", "sigprocmask()");
		return 1;
	}
	int sfd = signalfd(-1, &mask, 0);
	if (sfd < 0) {
		warn("%s", "signalfd()");
		return 1;
	}
	struct pollfd pfds[POLLFD_COUNT];
	pfds[POLLFD_SIGNAL].fd     = sfd;
	pfds[POLLFD_SIGNAL].events = POLLIN | POLLERR | POLLHUP;

	/* interval timerfd */
	int tfd = timerfd_create(CLOCK_MONOTONIC, 0);
	if (tfd < 0) {
		warn("%s", "timerfd_create()");
		return 1;
	}
	struct itimerspec timerfd_vals = {
		.it_interval.tv_sec  = ctl->interval,
		.it_value.tv_sec     = ctl->interval,
	};
	if (timerfd_settime(tfd, 0, &timerfd_vals, NULL)) {
		warn("%s", "timerfd_settime()");
		return 1;
	}
	pfds[POLLFD_TIMER].fd     = tfd;
	pfds[POLLFD_TIMER].events = POLLIN | POLLERR | POLLHUP;

	/* timeout timerfd */
	int timeoutfd = timerfd_create(CLOCK_MONOTONIC, 0);
	if (timeoutfd < 0) {
		warn("%s", "timerfd_create()");
		return 1;
	}
	struct itimerspec timeoutfd_vals = {
		.it_interval.tv_sec = ctl->timeout,
		.it_value.tv_sec    = ctl->timeout,
	};
	if (timerfd_settime(timeoutfd, 0, &timeoutfd_vals, NULL)) {
		warn("%s", "timerfd_settime()");
		return 1;
	}
	pfds[POLLFD_TIMEOUT].fd     = timeoutfd;
	pfds[POLLFD_TIMEOUT].events = POLLIN | POLLERR | POLLHUP;

	/* socket */
	pfds[POLLFD_SOCKET].fd     = ctl->sock;
	pfds[POLLFD_SOCKET].events = POLLIN | POLLERR | POLLHUP;
	send_pack(ctl);

	unsigned char packet[4096];
	uint64_t total_expires = 1;
	int exit_loop = 0, rc = 0;
	while (!exit_loop) {
		if (poll(pfds, POLLFD_COUNT, -1) <= 0) {
			if (errno == EAGAIN)
				continue;
			if (errno)
				warn("%s", "poll()");
			exit_loop = 1;
			continue;
		}

		for (size_t i = 0; i < POLLFD_COUNT; i++) {
			if (!pfds[i].revents)
				continue;
			switch (i) {
			case POLLFD_SIGNAL: {
				struct signalfd_siginfo sigval = {0};
				if (read(sfd, &sigval, sizeof(sigval)) != sizeof(sigval))
				{
					if (errno)
						warn("read(%s)", "signalfd");
					else
						warnx("read(%s)", "signalfd");
					continue;
				}
				if ((sigval.ssi_signo == SIGINT ) ||
				    (sigval.ssi_signo == SIGQUIT) ||
				    (sigval.ssi_signo == SIGTERM))
					exit_loop = 1;
				else
					warn("unexpected signal: %d", sigval.ssi_signo);
			}	break;
			case POLLFD_TIMER: {
				uint64_t exp = 0;
				if (read(tfd, &exp, sizeof(exp)) != sizeof(exp))
				{
					if (errno)
						warn("read(%s)", "timerfd");
					else
						warnx("read(%s)", "timerfd");
					continue;
				}
				total_expires += exp;
				if ((0 < ctl->count) && ((uint64_t)ctl->count < total_expires)) {
					exit_loop = 1;
					continue;
				}
				send_pack(ctl);
			}	break;
			case POLLFD_TIMEOUT:
				exit_loop = 1;
				break;
			case POLLFD_SOCKET: {
				struct sockaddr_storage from;
				socklen_t socklen = sizeof(from);
				memset(&from, 0, socklen);
				ssize_t size = recvfrom(ctl->sock, packet, sizeof(packet), 0,
					      (struct sockaddr *)&from, &socklen);
				if (size < 0) {
					warn("%s", "recvfrom()");
					if (errno == ENETDOWN)
						rc = 2;
					continue;
				}
				struct sockaddr_ll *sll = (struct sockaddr_ll *)&from;
				bool broadcast = false;
				switch (sll->sll_pkttype) {
					case PACKET_HOST:
						break;
					case PACKET_BROADCAST:
					case PACKET_MULTICAST:
						broadcast = true;
						break;
					default: /* Filter out wild packets */
						continue;
				}
				if (print_pack(ctl, packet, size, broadcast, sll->sll_hatype)
						== FINAL_PACKS)
					exit_loop = 1;
			}	break;
			default:
				abort();
			}
		}
	}
	close(sfd);
	close(tfd);
	if (!ctl->opt.quiet)
		resume(ctl);
	bool got = (ctl->received > 0) ? true : false;
	rc |= ctl->opt.dad         ? got   :
	      ctl->opt.unsolicited ? false :
	      !got;
	if (!ctl->opt.unsolicited) {
		bool all_uni = (ctl->received == ctl->sent);
		bool all_brd = (ctl->received == ctl->brd_sent);
		rc |=
			/* dad: Duplicate Address Detection mode */
			(ctl->opt.dad && ctl->opt.quit)     ? all_brd :
			(ctl->timeout && (ctl->count <= 0)) ? !got    :
			!all_uni;
	}
	return rc;
}

static inline void bind_sock(state_t *rts) {
	struct sockaddr_ll *sll = (struct sockaddr_ll *)&rts->me;
	sll->sll_family   = AF_PACKET;
	sll->sll_ifindex  = rts->dev.ndx;
	sll->sll_protocol = htons(ETH_P_ARP);
	if (bind(rts->sock, (struct sockaddr *)&rts->me, sizeof(rts->me)) < 0)
		err(errno, "bind()");
	socklen_t alen = sizeof(rts->me);
	if (getsockname(rts->sock, (struct sockaddr *)&rts->me, &alen) < 0)
		err(errno, "%s", "getsockname()");
	if (((struct sockaddr_ll *)&rts->me)->sll_halen == 0) {
		if (!rts->opt.quiet)
			warnx("%s: %s (%s)", rts->dev.name,
_("Interface is not ARPable"), _("no ll address"));
		exit(rts->opt.dad ? EXIT_SUCCESS : EXIT_FAILURE);
	}
	rts->he = rts->me;
}

static inline int arping_sock(void) {
	NET_RAW_ON;
	int sock = socket(AF_PACKET, SOCK_DGRAM, 0);
	int keep = errno;
	NET_RAW_OFF;
	if (sock < 0) {
		errno = keep;
		err(errno, "socket(%s, %s)", "PACKET", "DGRAM");
	}
	return sock;
}

static inline void arping_setup(state_t *rts) {
	if (inet_aton(rts->target, &rts->dst))
		rts->af = AF_INET;
	else {
		const struct addrinfo hints = {
			.ai_family   = AF_INET,
			.ai_socktype = SOCK_RAW,
			.ai_flags    = AI_FLAGS,
		};
		struct addrinfo *res = NULL;
		int rc = GAI_WRAPPER(rts->target, NULL, &hints, &res);
		if (rc) {
			if (rc == EAI_SYSTEM)
				err(errno, "%s", "getaddrinfo()");
			errx(rc, "%s af=%d: %s", rts->target, hints.ai_family, gai_strerror(rc));
		}
		if (!res)
			errx(EXIT_FAILURE, "%s", "getaddrinfo()");
		memcpy(&rts->dst, &((struct sockaddr_in *)res->ai_addr)->sin_addr, sizeof(rts->dst));
		rts->af = res->ai_family;
		freeaddrinfo(res);
	}

	// address family: to be sure
	if (rts->af != AF_INET)
		errx(EAFNOSUPPORT, "%s: %s", rts->target, strerror(ENODEV));

	// only target: guess device
	if (!rts->dev.name[0])
		guess_device(rts->af, rts->dst, &rts->dev);

	// known at this point: either dev.name or dev.name+dev.ndx
	if (check_device(rts) < 0)
		exit(errno ? errno : EINVAL); // sys error

	if (!rts->dev.ndx) { // no suitable device?
		errno = ENODEV;
		if (rts->dev.name[0])
			err(errno, "%s", rts->dev.name);
		warn("%s", rts->target);
	}

	if (rts->source && inet_aton(rts->source, &rts->src) != 1) {
		errno = EADDRNOTAVAIL;
		err(errno, "%s", rts->source);
	}

	if (!rts->opt.dad && rts->opt.unsolicited && !rts->source)
		rts->src = rts->dst;

	if (!rts->opt.dad || rts->source) {
		int probe_fd = socket(AF_INET, SOCK_DGRAM, 0);
		if (probe_fd < 0)
			err(errno, "socket(%s, %s)", "INET", "DGRAM");
		if (rts->dev.name[0] && (bindtodev(probe_fd, rts->dev.name) < 0))
			warn("%s: %s: %s", _WARN, rts->dev.name,
				_("Interface is ignored"));
		struct sockaddr_in saddr = { .sin_family = AF_INET };
		if (rts->source || rts->src.s_addr) {
			saddr.sin_addr = rts->src;
			if (bind(probe_fd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0)
				err(errno, "%s", "bind()");
		} else if (!rts->opt.dad) {
			saddr.sin_port = htons(1025);
			saddr.sin_addr = rts->dst;
			if (!rts->opt.unsolicited) {
				int on = 1;
				if (setsockopt(probe_fd, SOL_SOCKET, SO_DONTROUTE, &on, sizeof(on)) < 0)
					warn("%s: setsockopt(%s)", _WARN, "SO_DONTROUTE");
				if (connect(probe_fd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0)
					err(errno, "%s", "connect()");
				socklen_t alen = sizeof(saddr);
				if (getsockname(probe_fd, (struct sockaddr *)&saddr, &alen) < 0)
					err(errno, "%s", "getsockname()");
			}
			rts->src = saddr.sin_addr;
		}
		close(probe_fd);
	};
}


static inline void print_header(struct in_addr src, struct in_addr dst,
	const char *device)
{
	printf("%s %s", _("ARPING"), inet_ntoa(dst));
	printf(" %s %s", _("from"), inet_ntoa(src));
	if (device)
		printf("%%%s", device);
	putchar('\n');
}

static inline void parse_options(state_t *rts, int argc, char **argv) {
	int ch;
	while ((ch = getopt(argc, argv, "Abc:Dfhi:I:qs:UVw:?")) != EOF) {
		switch (ch) {
		case 'b':
			rts->opt.broadcast = true;
			break;
		case 'D':
			rts->opt.dad  = true;
			rts->opt.quit = true;
			break;
		case 'U':
			rts->opt.unsolicited = true;
			break;
		case 'A':
			rts->opt.advert      = true;
			rts->opt.unsolicited = true;
			break;
		case 'q':
			rts->opt.quiet = true;
			break;
		case 'c':
			rts->count = VALID_INTSTR(1, INT_MAX);
			break;
		case 'w':
			rts->timeout = VALID_INTSTR(0, INT_MAX);
			break;
		case 'i':
			rts->interval = VALID_INTSTR(0, INT_MAX);
			break;
		case 'I':
			strncpy(rts->dev.name, optarg, sizeof(rts->dev.name) - 1);
			break;
		case 'f':
			rts->opt.quit = true;
			break;
		case 's':
			rts->source = optarg;
			break;
		case 'V':
			version_n_exit(EXIT_SUCCESS, FEAT_CAP | FEAT_IDN | FEAT_NLS);
		case 'h':
		case '?':
			usage(EXIT_SUCCESS);
		default:
			usage(EXIT_FAILURE);
		}
	}
}

int main(int argc, char **argv) {
#ifdef HAVE_LIBCAP
	// limit caps to net_raw
	{ cap_value_t caps[] = {CAP_NET_RAW};
	  limit_cap(caps, ARRAY_SIZE(caps)); }
	NET_RAW_OFF;
#else
	keep_euid();
#endif

	setmyname(argv[0]);
	BIND_NLS;
	atexit(close_stdout);

	struct run_state rts = { .count = -1, .interval = 1 };
#ifdef DEFAULT_DEVICE
	strncpy(rts.dev.name, DEFAULT_DEVICE, sizeof(rts.dev.name) - 1);
#endif

	parse_options(&rts, argc, argv);
	argc -= optind;
	argv += optind;
	if (argc <= 0) {
		errno = EDESTADDRREQ;
		warn("%s", _("No goal"));
		usage(EDESTADDRREQ);
	} else if (argc != 1)
		usage(EINVAL);

	rts.target = *argv;
	rts.sock   = arping_sock();
	arping_setup(&rts);
	drop_priv();
	//

	bind_sock(&rts);
	find_brd_addr(&rts.dev, (struct sockaddr_ll *)&rts.he, rts.opt.quiet);
	if (!rts.opt.quiet)
		print_header(rts.src, rts.dst, rts.dev.name);
	if (!rts.source && !rts.src.s_addr && !rts.opt.dad)
		errx(EINVAL, "%s", _("No source address in not-DAD mode"));

	return event_loop(&rts);
}

