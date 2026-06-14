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

// local changes by yvs@

#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <err.h>
#include <errno.h>
#include <assert.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#include "processing.h"
#include "iputils.h"
#include "str2num.h"
#include "sock_pa.h"
#include "nlink.h"
#ifdef HAVE_LIBCAP
#include "caps.h"
#else
#include "perm.h"
#endif

#define ARPING_FEATURES	(FEAT_CAP | FEAT_IDN | FEAT_NLS | FEAT_ALTNAME)

#define SLL(sa) ((struct sockaddr_ll *)(sa))

typedef struct arpdev {
	char name[IF_NAMESIZE];
	const char *req; // requested with -I
	int ndx;         // valid: >0
	struct ifaddrs *ifa_list;
	const struct ifaddrs *ifa;
} arpdev_t;

typedef struct run_state {
	char *source;
	char *target;
	arpdev_t dev;
	int sock;
	int af; // ai_family
	struct in_addr src, dst;
	struct sockaddr_storage from, to;
	struct timespec start, last;
	uint interval;
	counter_t stat;
	arpopt_t opt;
} state_t;

//

static const char *usestr =
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

NORETURN static void usage(int rc) {
	usage_data_t use = {
		.usestr = usestr,
		.target = "TARGET",
		.more   = !MORE,
	};
	usage_common(rc, &use);
}

static inline void update_stat(struct timespec *last, int *sent, int *brd_sent) {
	if (last)
		clock_gettime(CLOCK_MONOTONIC, last);
	if (sent)
		(*sent)++;
	if (brd_sent)
		(*brd_sent)++;
}

static inline void send_n_stat(state_t *rts) {
	if (send_pack(SLL(&rts->from), SLL(&rts->to), rts->src, rts->dst, rts->sock, rts->opt.advert))
		update_stat(&rts->last, &rts->stat.sent, rts->opt.unicast ? NULL : &rts->stat.brd_sent);
}

static void resume(const counter_t *stat) {
	printf("%s: %d (%d %s)\n", _("Sent probes"), stat->sent,
		stat->brd_sent, _n("broadcast", "broadcasts", stat->brd_sent));
	printf("%s: %d", _("Received responses"), stat->recv);
	if (stat->brd_recv || stat->req_recv) {
		printf(" (");
		if (stat->req_recv)
			printf("%d %s", stat->req_recv,
				_n("request", "requests", stat->req_recv));
		if (stat->req_recv && stat->brd_recv)
			printf(", ");
		if (stat->brd_recv)
			printf("%d %s", stat->brd_recv,
				_n("broadcast", "broadcasts", stat->brd_recv));
		printf(")");
	}
	putchar('\n');
	fflush(stdout);
}

static int oif2ndx(const struct nlmsghdr *nh, const char *data UNUSED) {
	const struct rtmsg *rm = NLMSG_DATA(nh);
	size_t len = RTM_PAYLOAD(nh);
	for (const struct rtattr *ra = RTM_RTA(rm); RTA_OK(ra, (ushort)len);
	     ra = RTA_NEXT(ra, len))
		if (ra->rta_type == RTA_OIF) {
			int *oif = RTA_DATA(ra);
			return oif ? *oif : 0;
		}
	return 0;
}

static void guess_device(int af, struct in_addr dst, arpdev_t *dev) {
	struct {
		struct rtmsg  rm;
		struct rtattr ra;
		struct in_addr addr;
	} q = {
		.rm.rtm_family = af,
		.ra = {
			.rta_len  = RTA_LENGTH(sizeof(q.addr)),
			.rta_type = RTA_DST,
		},
		.addr = dst,
	};
	int ndx = nl_query(dev->name, NLM_F_REQUEST, RTM_GETROUTE, &q, sizeof(q),
		RTM_NEWROUTE, NLMSG_HDRLEN + sizeof(struct rtmsg), oif2ndx);
	if (ndx < 0)
		errx(EXIT_FAILURE, "%s() failed", __func__);
	if (if_indextoname(ndx, dev->name))
		dev->ndx = ndx;
	else
		err(errno ? errno : EXIT_FAILURE, "if_indextoname(%d)", ndx);
}

// common checks for `ifa_flags'
static bool valid_flags(uint flags, const char *name, bool quiet, bool dad) {
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

#define VALID_IFA(ifa, dev, opt) (                                      \
	ifa->ifa_name && ifa->ifa_broadaddr && ifa->ifa_addr &&         \
	(ifa->ifa_addr->sa_family == AF_PACKET) &&                      \
	valid_flags(ifa->ifa_flags, dev->name, opt->quiet, opt->dad) && \
	SLL(ifa->ifa_addr)->sll_halen                                   \
)

static const struct ifaddrs* ifa_by_name(const struct ifaddrs* list,
	const arpdev_t *dev, const arpopt_t *opt)
{
	const struct ifaddrs *ifa = list;
	for (; ifa; ifa = ifa->ifa_next)
		if (NL_STREQ(ifa->ifa_name, dev->name) && VALID_IFA(ifa, dev, opt))
			break;
	return ifa;
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
	//
	rts->dev.ifa = ifa_by_name(rts->dev.ifa_list, &rts->dev, &rts->opt);
#ifdef USE_ALTNAMES
	// could be 'altname' too
	if (!rts->dev.ifa) {
		uint ndx = nl_nametoindex(rts->dev.name, rts->dev.ifa_list);
		if ((ndx > 0) && if_indextoname(ndx, rts->dev.name))
			rts->dev.ifa = ifa_by_name(rts->dev.ifa_list, &rts->dev, &rts->opt);
	}
#endif
	int rc = 0;
	if (rts->dev.ifa) { // interface found
		rts->dev.ndx = if_nametoindex(rts->dev.ifa->ifa_name);
		if (!rts->dev.ndx) {
			warn("if_nametoindex(%s)", rts->dev.ifa->ifa_name);
			rc = -1;
		}
	}
	//
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
	const struct sockaddr_ll *ll = dev->ifa ? SLL(dev->ifa->ifa_broadaddr) : NULL;
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

#define SET_PFD(typ, nam, val) {     \
	fds[typ].fd = (val);         \
	if (fds[typ].fd < 0) {       \
		warn("%s", (nam));   \
		return EXIT_FAILURE; \
	}                            \
}
#define SET_TFD(typ, var, val)                              \
	struct itimerspec var = {                           \
		.it_interval.tv_sec  = (val),               \
		.it_value.tv_sec     = (val),               \
	};                                                  \
	if (timerfd_settime(fds[typ].fd, 0, &var, NULL)) {  \
		warn("%s", "timerfd_settime()");            \
		return EXIT_FAILURE;                        \
	}                                                   \
	fds[typ].events = ev_mask;                          \

static inline bool rc_unsol(const counter_t *stat, const arpopt_t *opt, bool got) {
	bool all_uni = (stat->recv == stat->sent);
	bool all_brd = (stat->recv == stat->brd_sent);
	return // note: DAD stands for Duplicate Address Detection
		(opt->dad && opt->quit)               ? all_brd :
		(stat->timeout && (stat->count <= 0)) ? !got    :
		!all_uni;
}

static int main_loop(state_t *rts) {
	enum {
		POLLFD_SIGNAL = 0,
		POLLFD_TIMER,
		POLLFD_TIMEOUT,
		POLLFD_SOCKET,
		POLLFD_COUNT
	};
	struct pollfd fds[POLLFD_COUNT] = {0};
	const short ev_mask = POLLIN | POLLERR | POLLHUP;
	//
	// signal
	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGQUIT);
	sigaddset(&mask, SIGTERM);
	if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
		warn("%s", "sigprocmask()");
		return EXIT_FAILURE;
	}
	SET_PFD(POLLFD_SIGNAL, "signalfd()", signalfd(-1, &mask, 0));
	fds[POLLFD_SIGNAL].events = ev_mask;
	//
	// interval
	SET_PFD(POLLFD_TIMER, "timerfd_create()", timerfd_create(CLOCK_MONOTONIC, 0));
	SET_TFD(POLLFD_TIMER, it_interval, rts->interval);
	//
	// timeout
	SET_PFD(POLLFD_TIMEOUT, "timerfd_create()", timerfd_create(CLOCK_MONOTONIC, 0));
	SET_TFD(POLLFD_TIMEOUT, it_timeout, rts->stat.timeout);
	//
	// socket
	SET_PFD(POLLFD_SOCKET, "SOCKET", rts->sock);
	fds[POLLFD_SOCKET].events = ev_mask;
	//

	send_n_stat(rts);

	uint8_t packet[4096] = {0};
	uint64_t total_expires = 1;
	int rc = 0;
	for (continue_t run = CONTINUE; run;) {
		// error
		if (poll(fds, ARRAY_LEN(fds), -1) <= 0) {
			if (errno == EAGAIN)
				continue;
			if (errno)
				warn("%s", "poll()");
			break;
		}
		// okay
		for (size_t i = 0; i < ARRAY_LEN(fds); i++) {
			if (!fds[i].revents)
				continue; // internal loop
			switch (i) {
			case POLLFD_SIGNAL: {
				struct signalfd_siginfo sigval = {0};
				if (read(fds[i].fd, &sigval, sizeof(sigval)) != sizeof(sigval)) {
					if (errno)
						warn("read(%s)", "signalfd");
					else
						warnx("read(%s)", "signalfd");
					continue; // internal loop
				}
				if ((sigval.ssi_signo == SIGINT ) ||
				    (sigval.ssi_signo == SIGQUIT) ||
				    (sigval.ssi_signo == SIGTERM))
					run = QUIT;
				else
					warn("unexpected signal: %d", sigval.ssi_signo);
			}	break;
			case POLLFD_TIMER: {
				uint64_t exp = 0;
				if (read(fds[i].fd, &exp, sizeof(exp)) != sizeof(exp)) {
					if (errno)
						warn("read(%s)", "timerfd");
					else
						warnx("read(%s)", "timerfd");
					continue; // internal loop
				}
				total_expires += exp;
				if ((0 < rts->stat.count) && ((uint64_t)rts->stat.count < total_expires)) {
					run = QUIT;
					continue; // internal loop
				}
				send_n_stat(rts);
			}	break;
			case POLLFD_TIMEOUT:
				run = QUIT;
				break;
			case POLLFD_SOCKET: {
				struct sockaddr_storage got = {0};
				socklen_t socklen = sizeof(got);
				ssize_t size = recvfrom(fds[i].fd, packet, sizeof(packet),
					0, SA(&got), &socklen);
				if (size < 0) {
					warn("%s", "recvfrom()");
					if (errno == ENETDOWN)
						rc = errno;
					continue; // internal loop
				}
				bool broadcasted = false;
				switch (SLL(&got)->sll_pkttype) {
					case PACKET_HOST:
						break;
					case PACKET_BROADCAST:
					case PACKET_MULTICAST:
						broadcasted = true;
						break;
					default: // Filter out wild packets
						continue; // internal loop
				}
				const struct arphdr *ar = (struct arphdr *)packet;
				bool ok2in = arp_attr_okay(ar, size, SLL(&got)->sll_hatype, SLL(&rts->from)->sll_halen);
				run = ok2in ? checkin_print(ar, rts->src, rts->dst,
					SLL(&rts->from), SLL(&rts->to)->sll_addr,
					&rts->opt, &rts->stat, broadcasted, &rts->last)
					: CONTINUE;
			}	break;
			default:
				abort();
			}
		} // internal loop
	}
	//
	for (size_t i = 0; i < ARRAY_LEN(fds); i++)
		close(fds[i].fd);
	if (!rts->opt.quiet)
		resume(&rts->stat);
	if (!rc) {
		bool got = (rts->stat.recv > 0);
		rc = rts->opt.dad         ? got   :
		     rts->opt.unsolicited ? false :
		     !got;
	}
	if (!rc && rts->opt.unsolicited)
		rc = rc_unsol(&rts->stat, &rts->opt, rts->stat.recv > 0);
	return rc;
}

static inline void bind_sock(struct sockaddr_ll *from, struct sockaddr_ll *to,
	int ifndx, const char *ifname, int sock, bool quiet, bool dad)
{
	from->sll_family   = AF_PACKET;
	from->sll_ifindex  = ifndx;
	from->sll_protocol = htons(ETH_P_ARP);
	if (bind(sock, SA(from), SLL_LEN) < 0)
		err(errno, "bind()");
	GETSOCKNAME(sock, SA(from), SLL_LEN);
	if (!from->sll_halen) {
		if (!quiet)
			warnx("%s: %s (%s)", ifname,
_("Interface is not ARPable"), _("no ll address"));
		exit(dad ? EXIT_SUCCESS : EXIT_FAILURE);
	}
	*to = *from;
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
			errx(rc, "af=%d: " TARGET_FMT ": %s", hints.ai_family, rts->target, gai_strerror(rc));
		}
		if (!res)
			errx(EXIT_FAILURE, "%s", "getaddrinfo()");
		memcpy(&rts->dst, &SA4_IN(res->ai_addr), sizeof(struct in_addr));
		rts->af = res->ai_family;
		freeaddrinfo(res);
	}

	// address family: to be sure
	if (rts->af != AF_INET)
		errx(EAFNOSUPPORT, TARGET_FMT ": %s", rts->target,
			strerror(rts->af ? ENODEV : ENXIO));

	// only target: guess device
	if (!rts->dev.name[0])
		guess_device(rts->af, rts->dst, &rts->dev);

	// known at this point: either dev.name or dev.name+dev.ndx
	if (check_device(rts) < 0)
		exit(errno ? errno : EINVAL); // sys error

	if (!rts->dev.ndx) { // no suitable device?
		errno = ENODEV;
		if (rts->dev.name[0])
			err_nodev(rts->dev.req ? rts->dev.req : rts->dev.name);
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
		if (rts->dev.name[0] &&
		    (bindtodev(probe_fd, rts->dev.name)/*privileged action*/ < 0))
			warn("%s: %s: %s", _WARN, rts->dev.name, _("Interface is ignored"));
		//
		struct sockaddr_in addr = {.sin_family = AF_INET};
		if (rts->source || rts->src.s_addr) {
			addr.sin_addr = rts->src;
			if (bind(probe_fd, SA(&addr), SA4_LEN) < 0)
				err(errno, "%s", "bind()");
		} else if (!rts->opt.dad) {
			addr.sin_port = htons(1025);
			addr.sin_addr = rts->dst;
			if (!rts->opt.unsolicited) {
				setsock_dontroute(probe_fd);
				if (connect(probe_fd, SA(&addr), SA4_LEN) < 0)
					err(errno, "%s", "connect()");
				GETSOCKNAME(probe_fd, SA(&addr), SA4_LEN);
			}
			rts->src = addr.sin_addr;
		}
		close(probe_fd);
	};
}


static inline void print_header(const char *name,
	const struct in_addr src, const struct in_addr dst)
{
	printf("%s %s", _("ARPING"), inet_ntoa(dst));
	printf(" %s %s", _("from"), inet_ntoa(src));
	if (name && name[0])
		printf("%%%s", name);
	putchar('\n');
}

static char *optstr = "Abc:Dfhi:I:qs:UVw:";
static void switch_opt(char c, void *data) { // NONNULL(1, 2)
#define RTS_DATA ((state_t *)data)
	switch (c) {
	case 'A':
		RTS_DATA->opt.advert      = true;
		RTS_DATA->opt.unsolicited = true;
		break;
	case 'b':
		RTS_DATA->opt.broadcast = true;
		break;
	case 'c':
		RTS_DATA->stat.count = VALID_INTSTR(1, INT_MAX);
		break;
	case 'D':
		RTS_DATA->opt.dad  = true;
		RTS_DATA->opt.quit = true;
		break;
	case 'f':
		RTS_DATA->opt.quit = true;
		break;
	case 'i':
		RTS_DATA->interval = VALID_INTSTR(0, INT_MAX);
		break;
	case 'I':
		strncpy(RTS_DATA->dev.name, optarg, sizeof(RTS_DATA->dev.name) - 1);
		RTS_DATA->dev.req = optarg;
		break;
	case 'q':
		RTS_DATA->opt.quiet = true;
		break;
	case 's':
		RTS_DATA->source = optarg;
		break;
	case 'U':
		RTS_DATA->opt.unsolicited = true;
		break;
	case 'w':
		RTS_DATA->stat.timeout = VALID_INTSTR(0, INT_MAX);
		break;
	}
#undef RTS_DATA
}

int main(int argc, char **argv) {
#ifdef HAVE_LIBCAP
	// limit capabilities
	limit_caps((cap_value_t[]){CAP_NET_RAW, -1});
	NET_RAW_OFF;
#else
	keep_euid();
#endif
	// execute actions with elevated privileges
	int sock = arping_sock();
	// and drop privileges ASAP
	drop_priv();

	setmyname(argv[0]);
	BIND_NLS;
	atexit(close_stdout);

	struct run_state rts = {.sock = sock, .stat.count = -1, .interval = 1};
#ifdef DEFAULT_DEVICE
	strncpy(rts.dev.name, DEFAULT_DEVICE, sizeof(rts.dev.name) - 1);
#endif

	common_getopt(argc, argv, optstr, ARPING_FEATURES, usage, switch_opt, &rts);
	argc -= optind;
	argv += optind;
	if (argc != 1) {
		int rc = (argc > 0) ? EINVAL : EDESTADDRREQ;
		if (argc <= 0) {
			errno = rc;
			warn("%s", _("No goal"));
		}
		usage(rc);
	}

	rts.target = *argv;
	validate_hostlen(rts.target, true);
	arping_setup(&rts);
	//
	//
	bind_sock(SLL(&rts.from), SLL(&rts.to), rts.dev.ndx, rts.dev.name, rts.sock,
		rts.opt.quiet, rts.opt.dad);
	find_brd_addr(&rts.dev, SLL(&rts.to), rts.opt.quiet);
	if (!rts.opt.quiet) {
		const char *ifname =
			rts.dev.req && (strlen(rts.dev.req) < IF_NAMESIZE) ?
			rts.dev.req : rts.dev.name;
		print_header(ifname, rts.src, rts.dst);
	}
	if (!rts.source && !rts.src.s_addr && !rts.opt.dad)
		errx(EINVAL, "%s", _("No source address in not-DAD mode"));

	return main_loop(&rts);
}

