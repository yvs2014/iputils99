
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

long strtol_or_err(const char *str, const char *errmesg, long min, long max) {
	errno = (str && *str) ? 0 : EINVAL;
	if (!errno) {
		char *end = NULL;
		long num = strtol(str, &end, 10);
		if (!(errno || (str == end) || (end && *end))) {
			if ((min <= num) && (num <= max))
				return num;
			error(ERANGE, 0, _("%s: '%s': out of range %ld - %ld"),
				errmesg, str, min, max);
		}
	}
	error(errno, errno, "%s: '%s'", errmesg, str);
	_exit(errno ? errno : EXIT_FAILURE);
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

inline void print_config(void) {
	printf("%cCAP %cIDN %cNLS\n",
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
#ifdef ENABLE_NLS
	'+'
#else
	'-'
#endif
	);
}

