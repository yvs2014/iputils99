
#include "iputils_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <err.h>
#include <errno.h>
#include <locale.h>

#ifdef HAVE_GETRANDOM
# include <sys/random.h>
#endif

#ifdef USE_LIBIDN2
#include <idn2.h>
#endif

void close_stdout(void) {
	if (fclose(stdout))
		if ((errno != EBADF) && (errno != EPIPE))
			err(errno, "stdout");
	if (fclose(stderr))
		if ((errno != EBADF) && (errno != EPIPE))
			err(errno, "stderr");
}

long long strtoll_or_err(const char *str, const char *errmesg,
		long long min, long long max)
{
	errno = (str && *str) ? 0 : EINVAL;
	if (!errno) {
		char *end = NULL;
		long long num = strtoll(str, &end, 10);
		if (errno || (str == end) || (end && *end)) {
			errno = 0;
			num = strtoll(str, &end, 16);
		}
		if (!(errno || (str == end) || (end && *end))) {
			if ((min <= num) && (num <= max))
				return num;
			errno = ERANGE;
			err(errno, "%s: %s: %lld - %lld", errmesg, str, min, max);
		}
	}
	if (errno)
		err(errno, "%s: %s", errmesg, str);
	errx(EXIT_FAILURE, "%s: %s", errmesg, str);
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

static const char *myname;

void setmyname(const char *argv0) {
	myname =
#ifdef HAVE_GETPROGNAME
	getprogname();
#elif  HAVE_PROGRAM_INVOCATION_SHORT_NAME
	program_invocation_short_name;
#else
	NULL;
#endif
	if (!myname)
		myname = argv0 ? argv0 : "";
}

void version_n_exit(int rc) {
	if (!myname)
		setmyname(NULL);
	printf("%s %s%s: %cCAP %cIDN %cNLS %cNI6\n",
		myname,
#ifdef PACKAGE_NAME
		PACKAGE_NAME,
#else
		"iputils",
#endif
#ifdef PACKAGE_VERSION
		"_" PACKAGE_VERSION,
#else
		"",
#endif
#ifdef HAVE_LIBCAP
		'+',
#else
		'-',
#endif
#ifdef USE_IDN
		'+',
#else
		'-',
#endif
#ifdef USE_NLS
		'+',
#else
		'-',
#endif
#ifdef ENABLE_NI6
		'+'
#else
		'-'
#endif
	);
	exit(rc);
}

void usage_common(int rc, const char *options, bool more) {
	printf("\n%s:\n  %s", _("Usage"), myname);
	if (options)
		printf(" [%s]", _("options"));
	printf(" %s%s\n", _("TARGET"), more ? " ..." : "");
	if (options)
		printf("\n%s:\n%s", _("Options"), _(options));
	printf("\n%s %s(8)\n", _("For more details see"), myname);
	exit(rc);
}

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
		warn("%s: %s", node, idn2_strerror(rc));
		if (decoded) {
			free(decoded);
			decoded = NULL;
		}
	}
	return decoded;
}

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

