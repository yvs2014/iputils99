#ifndef NLINK_H
#define NLINK_H

#include <ifaddrs.h>
#include <linux/rtnetlink.h>

int nl_query(const char *name, int flags, int type,
	const void *data, size_t len, int expected, size_t minlen,
	int (*handler)(const struct nlmsghdr *nh, const char *userdata));

// with if_nametoindex()
unsigned nl_name2ndx(const char *name);
// without if_nametoindex()
unsigned nl_nametoindex(const char *name, struct ifaddrs *ifas);

#define NLALTSIZE     128
#define NLSTREQ(a, b) (!strncmp((a), (b), NLALTSIZE/*IF_NAMESIZE*/))

#endif
