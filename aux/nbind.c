// Iputils Project
//
// setsockopt(SO_BINDTODEVICE): ping/arping

#include <string.h>
#include <errno.h>
#include <sys/socket.h>

#include "nbind.h"

#ifdef HAVE_LIBCAP
#include "caps.h"
#else
#include "perm.h"
#endif

int bindtodev(int fd, const char *name) {
	NET_RAW_ON;
	int rc = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name) + 1);
	int keep = errno;
	NET_RAW_OFF;
	if (rc < 0)
		errno = keep;
	return rc;
}

