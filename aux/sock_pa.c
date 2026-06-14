// Iputils Project
//
// setsockopt() stuff: ping, arping

#include <string.h>
#include <errno.h>
#include <err.h>
#include <sys/socket.h>
#include <net/if.h>
#ifdef USE_ALTNAMES
#include <linux/if.h>
#define MAXDEVNAME ALTIFNAMSIZ
#else
#define MAXDEVNAME IF_NAMESIZE
#endif

#include "sock_pa.h"
#ifdef HAVE_LIBCAP
#include "caps.h"
#else
#include "perm.h"
#endif

int bindtodev(int fd, const char dev[]) { // NONNULL(2)
	NET_RAW_ON;
	int rc = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, dev, strnlen(dev, MAXDEVNAME - 1) + 1);
	int keep = errno;
	NET_RAW_OFF;
	errno = keep;
	return rc;
}

NORETURN void err_nodev(const char dev[]) { // NONNULL(1)
	if (!errno)
		errno = ENODEV;
	err(errno, "%.*s", MAXDEVNAME, dev);
}

void setsock_binddev(int fd, const char dev[]) { // NONNULL(2)
	if (bindtodev(fd, dev) < 0)
		err_nodev(dev);
}

void setsock_dontroute(int fd) {
	int on = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_DONTROUTE, &on, sizeof(on)) < 0)
		warn("setsockopt(%s)", "DONTROUTE");
}

