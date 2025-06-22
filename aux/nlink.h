#ifndef NLINK_H
#define NLINK_H

#include <ifaddrs.h>
#include <linux/rtnetlink.h>

int nl_query(const char *name, int flags, int type,
	const void *data, size_t len, int expected, size_t minlen,
	int (*handler)(const struct nlmsghdr *nh, const char *userdata));

// with if_nametoindex()
unsigned nl_name2ndx(const char *name);

#ifdef USE_ALTNAMES
// without if_nametoindex()
unsigned nl_nametoindex(const char *name, struct ifaddrs *ifas);
#define NL_ALTSIZE 128
#else
#define NL_ALTSIZE IF_NAMESIZE
#endif

#define NL_STREQ(a, b) (!strncmp((a), (b), NL_ALTSIZE))

#endif
