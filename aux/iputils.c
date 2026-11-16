
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <err.h>

#if defined(USE_IDN) && !defined(USE_NLS)
#include <locale.h>
#endif
#ifdef USE_LIBIDN2
#include <idn2.h>
#endif
#ifdef HAVE_LIBCAP
#include <sys/capability.h>
#endif

#include "iputils.h"
#include "usage.h"

void close_stdout(void) {
	if (fclose(stdout) && (errno != EBADF) && (errno != EPIPE))
		errt(errno, "stdout");
	if (fclose(stderr) && (errno != EBADF) && (errno != EPIPE))
		errt(errno, "stderr");
}

#ifndef timespecsub
/* Subtract timespec structs:  res = a - b */
void timespecsub(const struct timespec *a, const struct timespec *b, struct timespec *res) {
	res->tv_sec  = a->tv_sec   - b->tv_sec;
	res->tv_nsec = a->tv_nsec  - b->tv_nsec;
	if (res->tv_nsec < 0) {
		res->tv_sec--;
		res->tv_nsec += 1000000000L;
	}
}
#endif

#ifndef timersub
/* Subtract timeval structs:  res = a - b */
void timersub(struct timeval *a, struct timeval *b, struct timeval *res) {
	res->tv_sec  = a->tv_sec  - b->tv_sec;
	res->tv_usec = a->tv_usec - b->tv_usec;
	if (res->tv_usec < 0) {
		res->tv_sec--;
		res->tv_usec += 1000000;
	}
}
#endif

inline int gai_wrapper(const char *restrict node, const char *restrict service,
	const struct addrinfo *restrict hints, struct addrinfo **restrict res)
{	// if USE_NLS is defined, assume that some locale is already set
#if defined(USE_IDN) && !defined(USE_NLS)
	setlocale(LC_ALL, "");
#endif
	int rc = getaddrinfo(node, service, hints, res);
#if defined(USE_IDN) && !defined(USE_NLS)
	int keep = errno;
	setlocale(LC_ALL, "C");
	errno = keep;
#endif
	return rc;
}

#ifdef USE_LIBIDN2
static inline char *idn2_decode(const char *restrict node) {
	char *decoded = NULL;
	int rc = idn2_to_ascii_lz(node, &decoded, 0);
	if (rc != IDN2_OK) { // first attempt failed
		if (decoded) {
			free(decoded);
			decoded = NULL;
		}
		// second attempt
		rc = idn2_to_ascii_8z(node, &decoded, 0);
	}
	if (rc != IDN2_OK) {
		warnt("%s: %s", node, idn2_strerror(rc));
		if (decoded) {
			free(decoded);
			decoded = NULL;
		}
	}
	return decoded;
}

// gai_wrapper2():
// IDN resolve using directly libidn2 for non-glibc libcs
int gai_wrapper2(const char *restrict node, const char *restrict service,
	const struct addrinfo *restrict hints, struct addrinfo **restrict res)
{
	int rc = gai_wrapper(node, service, hints, res);
	if (rc) {
		int keep = errno; // preserve errno
		char *decoded = idn2_decode(node);
		if (decoded) {
			errno = 0;
			rc = getaddrinfo(decoded, service, hints, res);
			free(decoded); // free() preserves errno
		} else
			errno = keep;
	}
	return rc;
}
#endif

#ifdef NI_MAXHOST
#define HOSTNAME_MAXLEN NI_MAXHOST
#else
#define HOSTNAME_MAXLEN 1025
#endif

// err() if 'fail' is true, otherwise warn()
// return 'errno' unless 'fail'
int validate_hostlen(const char *host, bool fail) {
	int re = 0;
	if (!host || !host[0]) {
		re = errno = EDESTADDRREQ;
		fail ? errt(errno, NULL) : warnt(NULL);
	} else if (strnlen(host, HOSTNAME_MAXLEN) >= HOSTNAME_MAXLEN) {
		re = errno = EOVERFLOW;
		fail ? errt(errno, "%.*s", HOSTNAME_MAXLEN, host) :
		       warnt("%.*s", HOSTNAME_MAXLEN, host);
	}
	return re;
}

void common_getopt(int argc, char **argv, const char *optstr, int features, // NONNULL(2, 3)
	void (*usage_fn)(int), void (*switch_fn)(char, void*), void *data)
{
	opterr = 0;
	int c;
	while ((c = getopt(argc, argv, optstr)) != EOF) switch (c) {
	case '?':
		if (optopt) {
			errno = EINVAL;
			warnt("-%c", optopt);
		}
		if (usage_fn)
			usage_fn(optopt ? EXIT_FAILURE : EXIT_SUCCESS);
		break;
	case 'h':
		if (usage_fn)
			usage_fn(EXIT_SUCCESS);
		break;
	case 'V':
		version_n_exit(features);
		break;
	default:
		if (switch_fn && c && data)
			switch_fn(c, data);
		break;
	}
}

#ifdef HAVE_LIBCAP
void warn_if_missing_cap(int cap) {
	if ((errno == EPERM) || (errno == EACCES)) {
		const char *capname =
			cap == CAP_NET_RAW   ? _STR(CAP_NET_RAW)   :
			cap == CAP_NET_ADMIN ? _STR(CAP_NET_ADMIN) :
			cap == CAP_SYS_NICE  ? _STR(CAP_SYS_NICE)  :
			NULL;
		if (capname)
			warnx("%s: %s", _MISS_CAP, capname);
		else
			warnx("%s: %d", _MISS_CAP, cap);
	}
}
#endif

