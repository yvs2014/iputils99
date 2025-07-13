
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <err.h>
#include <errno.h>
#if defined(USE_IDN) && !defined(USE_NLS)
#include <locale.h>
#endif
#ifdef USE_LIBIDN2
#include <idn2.h>
#endif

#include "iputils.h"

// gai_wrapper2():
// IDN resolve using directly libidn2 for non-glibc libcs

void close_stdout(void) {
	if (fclose(stdout))
		if ((errno != EBADF) && (errno != EPIPE))
			err(errno, "stdout");
	if (fclose(stderr))
		if ((errno != EBADF) && (errno != EPIPE))
			err(errno, "stderr");
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

#ifdef HAVE_LIBCAP
#define CAP_FEATURE	'+'
#else
#define CAP_FEATURE	'-'
#endif
#ifdef USE_IDN
#define IDN_FEATURE	'+'
#else
#define IDN_FEATURE	'-'
#endif
#ifdef USE_NLS
#define NLS_FEATURE	'+'
#else
#define NLS_FEATURE	'-'
#endif
#ifdef USE_ALTNAMES
#define ALTNAME_FEATURE	'+'
#else
#define ALTNAME_FEATURE	'-'
#endif
#ifdef ENABLE_RFC4620
#define RFC4620_FEATURE	'+'
#else
#define RFC4620_FEATURE	'-'
#endif

void version_n_exit(int rc, int features) {
	if (!myname)
		setmyname(NULL);
	printf("%s %s%s",
		myname,
#ifdef PACKAGE_NAME
		PACKAGE_NAME,
#else
		"iputils",
#endif
#ifdef PACKAGE_VERSION
		"_" PACKAGE_VERSION
#else
		""
#endif
	);
	if (features) {
		putchar(':');
		if (features & FEAT_CAP)
			printf(" %cCAP",     CAP_FEATURE);
		if (features & FEAT_IDN)
			printf(" %cIDN",     IDN_FEATURE);
		if (features & FEAT_NLS)
			printf(" %cNLS",     NLS_FEATURE);
		if (features & FEAT_ALTNAME)
			printf(" %cALTNAME", ALTNAME_FEATURE);
		if (features & FEAT_RFC4620)
			printf(" %cRFC4620", RFC4620_FEATURE);
	}
	putchar('\n');
	exit(rc);
}

void usage_common(int rc, const char *options, const char *target, bool more) {
	printf("\n%s:\n  %s", _("Usage"), myname);
	if (options)
		printf(" [%s]", _("options"));
	printf(" %s%s\n", _(target), more ? " ..." : "");
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

#ifdef NI_MAXHOST
#define HOSTNAME_MAXLEN NI_MAXHOST
#else
#define HOSTNAME_MAXLEN 1025
#endif

// err() if 'fail' is true, otherwise warn()
// return 'errno' unless 'fail'
int validate_hostlen(const char *host, bool fail) {
	if (!host || !host[0]) {
		errno = EDESTADDRREQ;
		if (fail) err(errno, NULL);
		else { warn(NULL); return errno; }
	}
	if (strnlen(host, HOSTNAME_MAXLEN) >= HOSTNAME_MAXLEN) {
		errno = EOVERFLOW;
		if (fail) err(errno, "%.*s", HOSTNAME_MAXLEN, host);
		else { warn("%.*s", HOSTNAME_MAXLEN, host); return errno; }
	}
	return 0;
}

