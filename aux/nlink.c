// Iputils Project
//
// netlink aux functions:
//   initially 'arping' nl-queries rewritten
//   to get 'altname' netdev functionality

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <err.h>
#include <net/if.h>
#include <net/if_arp.h>

#include "nlink.h"

#define NETLINK		"NETLINK"
#define NL_WRONG_TYPE	"%s: got type=%u, expected=%u"
#define NL_TOO_SHORT	"%s: message too short (len=%u, expected=%zu)"

#ifdef USE_ALTNAMES
static int cmp_raname(const struct rtattr *ra, const char *name) {
	int len = RTA_PAYLOAD(ra);
	char *data = ra ? (char*)RTA_DATA(ra) : NULL;
	return (data && (len > 0) && (len <= NL_ALTSIZE)) ? NL_STREQ(name, data) : 0;
}

static int is_altname(const struct nlmsghdr *nh, const char *name) {
	const struct ifinfomsg *ifi = NLMSG_DATA(nh);
	int len = IFLA_PAYLOAD(nh);
	int found = 0;
	for (const struct rtattr *ra = IFLA_RTA(ifi); RTA_OK(ra, (ushort)len);
		ra = RTA_NEXT(ra, len))
	{
		int16_t type = ra->rta_type & INT16_MAX;
		switch (type) {
		case IFLA_ALT_IFNAME:
			found = cmp_raname(ra, name);
			break;
		case IFLA_PROP_LIST: {
			int llen = RTA_PAYLOAD(ra);
			for (const struct rtattr *lra = RTA_DATA(ra);
			     RTA_OK(lra, llen); lra = RTA_NEXT(lra, llen))
				if (lra->rta_type == IFLA_ALT_IFNAME) {
					found = cmp_raname(lra, name);
					break;
				}
			} break;
		default: break;
		}
	}
	return found;
}

static bool nl_altname(unsigned ndx, const char *name) {
	struct {
		struct ifinfomsg ifi;
		struct rtattr attr_mask;
		uint32_t mask;
	} q = {
		.ifi = {
			.ifi_type   = ARPHRD_NETROM,
			.ifi_index  = ndx,
			.ifi_change = UINT_MAX,
		},
		.attr_mask = { .rta_len = RTA_LENGTH(sizeof(uint32_t)), .rta_type = IFLA_EXT_MASK },
		.mask = RTEXT_FILTER_VF | RTEXT_FILTER_SKIP_STATS,
	};
	int rc = nl_query(name, NLM_F_REQUEST, RTM_GETLINK, &q, sizeof(q),
		RTM_NEWLINK, NLMSG_HDRLEN + sizeof(struct ifinfomsg), is_altname);
	return (rc < 0) ? false : rc;
}
#endif

//
// pub

#ifdef USE_ALTNAMES
unsigned nl_nametoindex(const char *name, struct ifaddrs *ifas) {
	if (!(name || name[0]))
		return 0;
	struct ifaddrs *list = ifas;
	if (!ifas && getifaddrs(&list)) {
		warn("getifaddrs()");
		return 0;
	}
	//
	unsigned ndx = 0;
	if (list) {
		for (const struct ifaddrs *ifa = list; ifa;
		     ifa = ifa->ifa_next, ndx = 0)
		{
			ndx = if_nametoindex(ifa->ifa_name);
			if (ndx && (ndx <= INT_MAX))
				if (nl_altname(ndx, name))
					break;
		}
	} else
		warnx("%s", strerror(ENODATA));
	//
	if (!ifas && list)
		freeifaddrs(list);
	return ndx;
}
#endif

unsigned nl_name2ndx(const char *name) {
	unsigned ndx = 0;
	if (name && name[0]) {
		ndx = if_nametoindex(name);
#ifdef USE_ALTNAMES
		if (!ndx)
			ndx = nl_nametoindex(name, NULL);
#endif
	}
	return ndx;
}

// Return codes:
//   <0: failed
//    0: not done
//   >0: done/data
int nl_query(const char *name, int flags, int type,
	const void *data, size_t len, int expected, size_t minlen,
	int (*handler)(const struct nlmsghdr *nh, const char *userdata))
{
	if (!data || !name)
		return 0;
// prepare query
	static uint32_t seq;
	uint8_t buff[4096] = {0};
	struct nlmsghdr *nh = (struct nlmsghdr *)buff;
	nh->nlmsg_len   = NLMSG_LENGTH(len);
	nh->nlmsg_flags = flags;
	nh->nlmsg_type  = type;
	nh->nlmsg_seq   = ++seq;
	memcpy(NLMSG_DATA(nh), data, len);
	//
	struct sockaddr_nl sa = {.nl_family = AF_NETLINK};
	struct iovec iov = {
		.iov_base = nh,
		.iov_len  = NLMSG_ALIGN(nh->nlmsg_len),
	};
	struct msghdr mh = {
		.msg_name    = &sa,
		.msg_namelen = sizeof(sa),
		.msg_iov     = &iov,
		.msg_iovlen  = 1,
	};
// send query
	int fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (fd < 0) {
		warn("socket(%s)", NETLINK);
		return -1;
	}
	if (sendmsg(fd, &mh, 0) < 0) {
		warn("sendmsg(%s)", NETLINK);
		return -1;
	}
// get response
	iov.iov_len = sizeof(buff);
	ssize_t msg_len;
	do msg_len = recvmsg(fd, &mh, 0);
	while ((msg_len < 0) && (errno == EINTR));
// parse response
	int rc = 0;
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
			break;
		case NLMSG_DONE:
			break;
		default:
			if (handler) {
				if (nh->nlmsg_type == expected) {
					if (nh->nlmsg_len > minlen)
						rc = handler(nh, name);
					else
						warnx(NL_TOO_SHORT, NETLINK,
							nh->nlmsg_len, minlen);
				} else
					warnx(NL_WRONG_TYPE, NETLINK,
						nh->nlmsg_type, expected);
			}
			break;
		}
	}
// fin
	close(fd);
	return rc;
}

