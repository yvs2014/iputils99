
// Iputils Project
//
// String to number conversion wrappers

#include <stdlib.h>
#include <math.h>
#include <errno.h>
#include <locale.h>

#include "attr.h"
#include "warnerr.h"

NORETURN static void str2num_fail(const char *msg, const char *str) {
	if (!(errno || msg))
		errno = EINVAL;
	if (errno) {
		msg ? errt(errno, "%s: %s", msg, str)
		    : errt(errno, "%s", str);
	}
	msg ? errxt(EXIT_FAILURE, "%s: %s", msg, str)
	    : errxt(EXIT_FAILURE, "%s", str);
}

long long str2ll(const char *str, long long min, long long max, const char *msg) {
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
			msg ? errt(errno, "%s: %s: %lld - %lld", msg, str, min, max)
			    : errt(errno, "%s: %lld - %lld", str, min, max);
		}
	}
	str2num_fail(msg, str);
}

double str2dbl(const char *str, double min, double max, const char *msg) {
	errno = (str && *str) ? 0 : EINVAL;
	if (!errno) {
		char *end = NULL;
		/* "C" locale to have dots as decimal separators */
		setlocale(LC_NUMERIC, "C");
		double num = strtod(str, &end);
		int keep = errno;
		setlocale(LC_NUMERIC, "");
		errno = keep;
		if (!(errno || (str == end) || (end && *end))) {
			if (isgreaterequal(num, min) && islessequal(num, max))
				return num;
			errno = ERANGE;
			msg ? errt(errno, "%s: %s: %g-%g", msg, str, min, max)
			    : errt(errno, "%s: %g-%g", str, min, max);
		}
	}
	str2num_fail(msg, str);
}

