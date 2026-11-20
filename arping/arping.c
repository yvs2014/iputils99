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
#include "usage.h"
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
	struct in_addr saddr, daddr;      // src+dst address
	struct sockaddr_storage ssa, dsa; // src+dst sockaddr
	struct timespec start, last;
	uint interval;
	counter_t stat;
	arpopt_t opt;
} state_t;

static inline void update_stat(struct timespec *last, int *sent, int *brd_sent) {
	if (last)
		clock_gettime(CLOCK_MONOTONIC, last);
	if (sent)
		(*sent)++;
	if (brd_sent)
		(*brd_sent)++;
}

static inline void send_n_stat(state_t *rts) {
	if (send_pack(SLL(&rts->ssa), SLL(&rts->dsa), rts->saddr, rts->daddr, rts->sock, rts->opt.advert))
		update_stat(&rts->last, &rts->stat.sent, rts->opt.unicast ? NULL : &rts->stat.brd_sent);
}

static void resume(const counter_t *stat) {
	if (itistty)
		fputs(COLOR_BOLD, stdout);
	printf("%s: %d (%d %s)\n", _SENT_PROB, stat->sent, stat->brd_sent, _N_BRD(stat->brd_sent));
	printf("%s: %d", _RECV_RESP, stat->recv);
	if (stat->brd_recv || stat->req_recv) {
		printf(" (");
		if (stat->req_recv)
			printf("%d %s", stat->req_recv, _N_REQUEST(stat->req_recv));
		if (stat->req_recv && stat->brd_recv)
			printf(", ");
		if (stat->brd_recv)
			printf("%d %s", stat->brd_recv, _N_BRD(stat->brd_recv));
		putchar(')');
	}
	putchar('\n');
	if (itistty)
		fputs(COLOR_NORMAL, stdout);
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

static void guess_device(struct in_addr addr, arpdev_t *dev) {
	struct {
		struct rtmsg  rm;
		struct rtattr ra;
		struct in_addr addr;
	} q = {
		.rm.rtm_family = AF_INET,
		.ra = {
			.rta_len  = RTA_LENGTH(sizeof(q.addr)),
			.rta_type = RTA_DST,
		},
		.addr = addr,
	};
	int ndx = nl_query(dev->name, NLM_F_REQUEST, RTM_GETROUTE, &q, sizeof(q),
		RTM_NEWROUTE, NLMSG_HDRLEN + sizeof(struct rtmsg), oif2ndx);
	if (ndx < 0)
		errxt(EXIT_FAILURE, "%s() failed", __func__);
	if (if_indextoname(ndx, dev->name))
		dev->ndx = ndx;
	else
		errt(errno ? errno : EXIT_FAILURE, "if_indextoname(%d)", ndx);
}

// common checks for `ifa_flags'
static bool valid_flags(uint flags, const char *name, bool quiet, bool dad) {
	if (!(flags & IFF_UP)) {
		if (name && name[0]) {
			if (!quiet)
				warnxt("%s: %s", name, _IFACE_DOWN);
			exit(EINVAL);
		}
		return false;
	}
	if (flags & (IFF_NOARP | IFF_LOOPBACK)) {
		if (name && name[0]) {
			if (!quiet)
				warnxt("%s: %s", name, _NO_ARP_IFACE);
			exit(dad ? EXIT_SUCCESS : EINVAL);
		}
		return false;
	}
	return true;
}

#define VALID_IFA(ifa, dev, opt) (                                              \
	(ifa)->ifa_name && (ifa)->ifa_broadaddr && (ifa)->ifa_addr &&           \
	((ifa)->ifa_addr->sa_family == AF_PACKET) &&                            \
	valid_flags((ifa)->ifa_flags, (dev)->name, (opt)->quiet, (opt)->dad) && \
	SLL((ifa)->ifa_addr)->sll_halen                                         \
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
		warnt("%s", "getifaddrs()");
		return -1;
	}
	if (!rts->dev.ifa_list) {
		warnxt("%s", strerror(ENODATA));
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
			warnt("if_nametoindex(%s)", rts->dev.ifa->ifa_name);
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
			warnxt("%s: %s", _WARN, _USING_BRD);
		memset(he->sll_addr, -1, he->sll_halen);
	}
	if (dev->ifa_list) { // no need more
		freeifaddrs(dev->ifa_list);
		dev->ifa = dev->ifa_list = NULL;
	}
}

static inline bool rc_unsol(const counter_t *stat, const arpopt_t *opt, bool got) {
	bool all_uni = (stat->recv == stat->sent);
	bool all_brd = (stat->recv == stat->brd_sent);
	return // note: DAD stands for Duplicate Address Detection
		(opt->dad && opt->quit)               ? all_brd :
		(stat->timeout && (stat->count <= 0)) ? !got    :
		!all_uni;
}

//
typedef struct estate {
	state_t *rts;
	bool failed;
	uint64_t total;
} estate_t;
//
static continue_t fd_signal(struct pollfd *pollfd) { // NONNULL(1)
	struct signalfd_siginfo sigval = {0};
	if (read(pollfd->fd, &sigval, sizeof(sigval)) == sizeof(sigval)) {
		if ((sigval.ssi_signo == SIGINT ) ||
		    (sigval.ssi_signo == SIGQUIT) ||
		    (sigval.ssi_signo == SIGTERM))
			return QUIT;
		warnt("unexpected signal: %d", sigval.ssi_signo);
	} else {
		errno ? warnt("read(%s)", "signalfd") :
		       warnxt("read(%s)", "signalfd");
	}
	return CONTINUE;
}
//
static continue_t fd_timer(struct pollfd *pollfd, estate_t *erts) { // NONNULL(1, 2)
	state_t *rts = erts->rts; // NONNULL
	uint64_t exp = 0;
	if (read(pollfd->fd, &exp, sizeof(exp)) == sizeof(exp)) {
		erts->total += exp;
		if ((0 < rts->stat.count) && ((uint64_t)rts->stat.count < erts->total))
			return QUIT;
		send_n_stat(rts);
	} else {
		errno ? warnt("read(%s)", "timerfd") :
		       warnxt("read(%s)", "timerfd");
	}
	return CONTINUE;
}
//
static continue_t fd_socket(struct pollfd *pollfd, estate_t *erts) { // NONNULL(1, 2)
	state_t *rts = erts->rts; // NONNULL
	struct sockaddr_ll sll = {.sll_pkttype = PACKET_OTHERHOST};
	socklen_t socklen = sizeof(sll);
	uint8_t packet[4096] = {0};
	ssize_t size = recvfrom(pollfd->fd, packet, sizeof(packet), 0, SA(&sll), &socklen);
	if (size < 0) {
		warnt("%s", "recvfrom()");
		if ((errno == ENETDOWN) && !erts->failed)
			erts->failed = true;
		return CONTINUE;
	}
	if (socklen > sizeof(sll)) {
		warnxt("recvfrom(): %s", "sockaddr was truncated");
		return CONTINUE;
	}
	bool cast = false;
	switch (sll.sll_pkttype) {
		case PACKET_HOST:
			break;
		case PACKET_BROADCAST:
		case PACKET_MULTICAST:
			cast = true;
			break;
		default: // filter out wild packets
			return CONTINUE;
	}
	const struct arphdr *ar = (struct arphdr *)packet;
	const struct sockaddr_ll *my_sll = SLL(&rts->ssa);
	continue_t run = CONTINUE;
	if (arp_attr_okay(ar, size, sll.sll_hatype, my_sll->sll_halen))
		run = checkin_print(ar, rts->saddr, rts->daddr, my_sll,
			SLL(&rts->dsa)->sll_addr, &rts->opt, &rts->stat,
			cast, &rts->last);
	return run;
}
//
enum {
	POLLFD_SIGNAL = 0,
	POLLFD_TIMER,
	POLLFD_TIMEOUT,
	POLLFD_SOCKET,
	POLLFD_COUNT
};
//
static continue_t fd_loop(uint len, struct pollfd fds[len], estate_t *erts) { // NONNULL(2, 3)
	continue_t run = CONTINUE;
	struct pollfd *fd = fds;
	for (uint i = 0; i < len; i++, fd++) if (fd && fd->revents) switch (i) {
		case POLLFD_SIGNAL:
			if (fd_signal(fd) == QUIT)
				run = QUIT;
			break;
		case POLLFD_TIMER:
			if (fd_timer(fd, erts) == QUIT)
				run = QUIT;
			break;
		case POLLFD_TIMEOUT:
			run = QUIT;
			break;
		case POLLFD_SOCKET:
			if (fd_socket(fd, erts) == QUIT)
				run = QUIT;
			break;
		default:
			abort();
	}
	return run;
}

#define SET_PFD(typ, nam, val) do {  \
	fds[typ].fd = (val);         \
	if (fds[typ].fd < 0) {       \
		warnt("%s", (nam));  \
		return EXIT_FAILURE; \
	}                            \
} while(0)
#define SET_TFD(typ, var, val) \
	struct itimerspec (var) = {                           \
		.it_interval.tv_sec  = (val),                 \
		.it_value.tv_sec     = (val),                 \
	};                                                    \
	if (timerfd_settime(fds[typ].fd, 0, &(var), NULL)) {  \
		warnt("%s", "timerfd_settime()");             \
		return EXIT_FAILURE;                          \
	}                                                     \
	fds[typ].events = ev_mask;


static bool main_loop(state_t *rts) {
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
		warnt("%s", "sigprocmask()");
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
	//
	estate_t state = {.rts = rts, .total = 1};
	while (true) {
		if (poll(fds, ARRAY_LEN(fds), -1) > 0) {
			if (fd_loop(ARRAY_LEN(fds), fds, &state) == QUIT)
				break;
		} else if (errno != EAGAIN) {
			if (errno)
				warnt("%s", "poll()");
			break;
		}
	}
	//
	for (size_t i = 0; i < ARRAY_LEN(fds); i++)
		close(fds[i].fd);
	if (!rts->opt.quiet)
		resume(&rts->stat);
	if (!state.failed) {
		bool got = (rts->stat.recv > 0);
		state.failed = rts->opt.dad         ? got   :
		               rts->opt.unsolicited ? false :
		               !got;
	}
	if (!state.failed && rts->opt.unsolicited)
		state.failed = rc_unsol(&rts->stat, &rts->opt, rts->stat.recv > 0);
	return state.failed;
}

static inline void bind_sock(struct sockaddr_ll *from, struct sockaddr_ll *to,
	int ifndx, const char *ifname, int sock, bool quiet, bool dad)
{
	from->sll_family   = AF_PACKET;
	from->sll_ifindex  = ifndx;
	from->sll_protocol = htons(ETH_P_ARP);
	if (bind(sock, SA(from), SLL_LEN) < 0)
		errt(errno, "bind()");
	GETSOCKNAME(sock, SA(from), SLL_LEN);
	if (!from->sll_halen) {
		if (!quiet)
			warnxt("%s: %s (%s)", ifname, _NO_ARP_IFACE, _NO_LL_ADDR);
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
		warn_if_missing_cap(CAP_NET_RAW);
		err(errno, "socket(%s, %s)", "PACKET", "DGRAM");
	}
	return sock;
}

static void arping_resolv(state_t *rts) {
	const struct addrinfo hints = {
		.ai_family   = AF_INET,
		.ai_socktype = SOCK_RAW,
		.ai_flags    = AI_FLAGS,
	};
	struct addrinfo *res = NULL;
	int rc = GAI_WRAPPER(rts->target, NULL, &hints, &res);
	if (rc) {
		if (rc == EAI_SYSTEM)
			errt(errno, "%s", "getaddrinfo()");
		errxt(rc, TARGET_FMT ": %s", rts->target, gai_strerror(rc));
	}
	if (!res)
		errxt(EXIT_FAILURE, "%s", "getaddrinfo()");
	sa_family_t af = res->ai_family;
	if (af == AF_INET)
		memcpy(&rts->daddr, &SA4_IN(res->ai_addr), sizeof(struct in_addr));
	freeaddrinfo(res);
	// be sure: IP4 only
	if (af != AF_INET)
		errxt(EAFNOSUPPORT, TARGET_FMT ": %s", rts->target,
			strerror(af ? ENODEV : ENXIO));
}

static void setup(state_t *rts) {
	if (!inet_aton(rts->target, &rts->daddr))
		arping_resolv(rts);
	// only target: guess device
	if (!rts->dev.name[0])
		guess_device(rts->daddr, &rts->dev);
	// known at this point: either dev.name or dev.name+dev.ndx
	if (check_device(rts) < 0)
		exit(errno ? errno : EINVAL); // sys error
	//
	if (!rts->dev.ndx) { // no suitable device?
		errno = ENODEV;
		if (rts->dev.name[0])
			err_nodev(rts->dev.req ? rts->dev.req : rts->dev.name);
		warnt("%s", rts->target);
	}
	//
	if (rts->source && inet_aton(rts->source, &rts->saddr) != 1) {
		errno = EADDRNOTAVAIL;
		errt(errno, "%s", rts->source);
	}
	//
	if (!rts->opt.dad && rts->opt.unsolicited && !rts->source)
		rts->saddr = rts->daddr;
	//
	if (!rts->opt.dad || rts->source) {
		int probe_fd = socket(AF_INET, SOCK_DGRAM, 0);
		if (probe_fd < 0)
			errt(errno, "socket(%s, %s)", "INET", "DGRAM");
		if (rts->dev.name[0] &&
		    (bindtodev(probe_fd, rts->dev.name)/*privileged action*/ < 0))
			warnt("%s: %s: %s", _WARN, rts->dev.name, _IFACE_IGN);
		//
		struct sockaddr_in addr = {.sin_family = AF_INET};
		if (rts->source || rts->saddr.s_addr) {
			addr.sin_addr = rts->saddr;
			if (bind(probe_fd, SA(&addr), SA4_LEN) < 0)
				errt(errno, "%s", "bind()");
		} else if (!rts->opt.dad) {
			addr.sin_port = htons(1025);
			addr.sin_addr = rts->daddr;
			if (!rts->opt.unsolicited) {
				setsock_dontroute(probe_fd);
				if (connect(probe_fd, SA(&addr), SA4_LEN) < 0)
					errt(errno, "%s", "connect()");
				GETSOCKNAME(probe_fd, SA(&addr), SA4_LEN);
			}
			rts->saddr = addr.sin_addr;
		}
		close(probe_fd);
	};
}


static inline void print_header(const char *name,
	const struct in_addr src, const struct in_addr dst)
{
	if (itistty)
		fputs(COLOR_BOLD, stdout);
	printf("%s %s", _ARPING, inet_ntoa(dst));
	printf(" %s %s", _FROM,  inet_ntoa(src));
	if (name && name[0])
		printf("%%%s", name);
	putchar('\n');
	if (itistty)
		fputs(COLOR_NORMAL, stdout);
}

//

static const char *optstr = "Abc:Dfhi:I:qs:UVw:";

static const usage_opt_t uopts[] = { // null-terminated
	{.opt = 'A', .desc = {__ARPING_OPT_A}},
	{.opt = 'b', .desc = {__ARPING_OPT_b}},
	{.opt = 'c', .arg  = __COUNT,    .desc = {__ARPING_OPT_c}},
	{.opt = 'D', .desc = {__ARPING_OPT_D}},
	{.opt = 'f', .desc = {__ARPING_OPT_f}},
	{.opt = 'i', .arg  = __INTERVAL, .desc = {__ARPING_OPT_i}},
	{.opt = 'I', .arg  = __DEVICE,   .desc = {__ARPING_OPT_I}},
	{.opt = 'q', .desc = {__OPT_q}},
	{.opt = 's', .arg  = __SOURCE,   .desc = {__ARPING_OPT_s}},
	{.opt = 'U', .desc = {__ARPING_OPT_U}},
	{.opt = 'w', .arg  = __TIMEOUT,  .desc = {__ARPING_OPT_w}},
	{.opt = 'h', .desc = {__OPT_h}},
	{.opt = 'V', .desc = {__OPT_V}},
	{0},
};

NORETURN static void usage(int rc) {
	usage_data_t use = {
		.indent = 9,
		.uopt   = uopts,
		.optstr = optstr,
		.target = _TARGET,
		.more   = !MORE,
	};
	usage_common(rc, &use);
}

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
	default: break;
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
	//
	setmyname(argv[0]);
	BIND_NLS;
	atexit(close_stdout);
	//
	struct run_state rts = {.sock = sock, .stat.count = -1, .interval = 1};
	common_getopt(argc, argv, optstr, ARPING_FEATURES, usage, switch_opt, &rts);
	argc -= optind;
	argv += optind;
	if (argc != 1) {
		int rc = (argc > 0) ? EINVAL : EDESTADDRREQ;
		if (argc <= 0) {
			errno = rc;
			warnt("%s", _NO_GOAL);
		}
		usage(rc);
	}
	//
	rts.target = *argv;
	validate_hostlen(rts.target, true);
	setup(&rts);
	//
	bind_sock(SLL(&rts.ssa), SLL(&rts.dsa), rts.dev.ndx, rts.dev.name, rts.sock,
		rts.opt.quiet, rts.opt.dad);
	find_brd_addr(&rts.dev, SLL(&rts.dsa), rts.opt.quiet);
	if (!rts.opt.quiet) {
		const char *ifname =
			rts.dev.req && (strlen(rts.dev.req) < IF_NAMESIZE) ?
			rts.dev.req : rts.dev.name;
		print_header(ifname, rts.saddr, rts.daddr);
	}
	if (!rts.source && !rts.saddr.s_addr && !rts.opt.dad)
		errxt(EINVAL, "%s", _NOSRC_IN_DAD);
	//
	return main_loop(&rts) ? EXIT_FAILURE : EXIT_SUCCESS;
}

