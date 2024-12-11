// part of iputils_common.c is used in node_info.c only

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#ifdef HAVE_GETRANDOM
#include <sys/random.h>
#endif

static unsigned srand_fallback(void) {
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	return ((getpid() << 16) ^ getuid() ^ ts.tv_sec ^ ts.tv_nsec);
}

void iputils_srand(void) {
	unsigned int i;
#if HAVE_GETRANDOM
	ssize_t ret;
	do {
		errno = 0;
		ret = getrandom(&i, sizeof(i), GRND_NONBLOCK);
		switch (errno) {
		case 0:
			break;
		case EINTR:
			continue;
		default:
			i = srand_fallback();
			goto done;
		}
	} while (ret != sizeof(i));
 done:
#else
	i = srand_fallback();
#endif
	srand(i);
	/* Consume up to 31 random numbers */
	i = rand() & 0x1F;
	while (0 < i) {
		rand();
		i--;
	}
}

