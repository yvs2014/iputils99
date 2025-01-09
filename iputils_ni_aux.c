// part of iputils_common.c that used in node_info.c only

#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#ifdef NI6_NONCE_MEMORY
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#endif
#ifdef HAVE_GETRANDOM
#include <sys/random.h>
#endif

#include "iputils_ni_aux.h"

#ifdef NI6_NONCE_MEMORY
static unsigned srand_fallback(void) {
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	return ((getpid() << 16) ^ getuid() ^ ts.tv_sec ^ ts.tv_nsec);
}

void iputils_srand(void) {
	unsigned i;
#if HAVE_GETRANDOM
	ssize_t ret;
	do {
		errno = 0;
		ret = getrandom(&i, sizeof(i), GRND_NONBLOCK);
		if (errno) {
			if (errno == EINTR)
				continue;
			i = srand_fallback();
			break;
		}
	} while (ret != sizeof(i));
#else
	i = srand_fallback();
#endif
	srand(i);
	/* Consume up to 31 random numbers */
	i = rand() & 0x1F;
	while (i > 0) {
		rand();
		i--;
	}
}
#endif

int ntohsp(const uint16_t *p) {
	uint16_t v;
	memcpy(&v, p, sizeof(v));
	return ntohs(v);
}

