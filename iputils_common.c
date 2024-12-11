
#include "iputils_common.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio_ext.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#if HAVE_GETRANDOM
# include <sys/random.h>
#endif

#ifdef HAVE_ERROR_H
# include <error.h>
#else
void error(int status, int errnum, const char *format, ...) {
	va_list ap;
	fprintf(stderr, "%s: ",
#ifdef HAVE_GETPROGNAME
		getprogname()
#elif  HAVE_PROGRAM_INVOCATION_SHORT_NAME
		program_invocation_short_name
#endif
	);
	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
	if (errnum)
		fprintf(stderr, ": %s\n", strerror(errnum));
	else
		fprintf(stderr, "\n");
	if (status)
		exit(status);
}
#endif

static int close_stream(FILE *stream) {
	const int flush_status = fflush(stream);
#ifdef HAVE___FPENDING
	const int some_pending = (__fpending(stream) != 0);
#endif
	const int prev_fail = (ferror(stream) != 0);
	const int fclose_fail = (fclose(stream) != 0);
	if (flush_status ||
	    prev_fail || (fclose_fail && (
#ifdef HAVE___FPENDING
					  some_pending ||
#endif
					  errno != EBADF))) {
		if (!fclose_fail && !(errno == EPIPE))
			errno = 0;
		return EOF;
	}
	return 0;
}

void close_stdout(void) {
	if (close_stream(stdout) && (errno != EPIPE)) {
		error(0, errno, "write error");
		_exit(EXIT_FAILURE);
	}
	if (close_stream(stderr))
		_exit(EXIT_FAILURE);
}

long strtol_or_err(char const *const str, char const *const errmesg,
		const long min, const long max)
{
	long num;
	char *end = NULL;

	errno = 0;
	if (str == NULL || *str == '\0')
		goto err;
	num = strtol(str, &end, 10);
	if (errno || str == end || (end && *end))
		goto err;
	if (num < min || max < num)
		error(EXIT_FAILURE, 0, "%s: '%s': out of range: %ld <= value <= %ld",
		      errmesg, str,  min, max);
	return num;
 err:
	error(EXIT_FAILURE, errno, "%s: '%s'", errmesg, str);
	abort();
}

unsigned long strtoul_or_err(char const *const str, char const *const errmesg,
		const unsigned long min, const unsigned long max)
{
	unsigned long num;
	char *end = NULL;

	errno = 0;
	if (str == NULL || *str == '\0')
		goto err;
	num = strtoul(str, &end, 10);
	if (errno || str == end || (end && *end))
		goto err;
	if (num < min || max < num)
		error(EXIT_FAILURE, 0, "%s: '%s': out of range: %lu <= value <= %lu",
		      errmesg, str, min, max);
	return num;
 err:
	error(EXIT_FAILURE, errno, "%s: '%s'", errmesg, str);
	abort();
}

#ifndef timespecsub
/* Subtract timespec structs:  res = a - b */
void timespecsub(struct timespec *a, struct timespec *b, struct timespec *res) {
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

void print_config(void) {
	printf(
	"libcap: "
#ifdef HAVE_LIBCAP
	"yes"
#else
	"no"
#endif
	", IDN: "
#ifdef USE_IDN
	"yes"
#else
	"no"
#endif
	", NLS: "
#ifdef ENABLE_NLS
	"yes"
#else
	"no"
#endif
	", error.h: "
#ifdef HAVE_ERROR_H
	"yes"
#else
	"no"
#endif
	", getrandom(): "
#ifdef HAVE_GETRANDOM
	"yes"
#else
	"no"
#endif
	", __fpending(): "
#ifdef HAVE___FPENDING
	"yes"
#else
	"no"
#endif
	"\n");
}

