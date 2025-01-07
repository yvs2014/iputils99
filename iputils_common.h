#ifndef IPUTILS_COMMON_H
#define IPUTILS_COMMON_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdbool.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netdb.h>

#ifdef USE_NLS
#include <libintl.h>
#define _(Text) gettext (Text)
#else
#define _(Text) Text
#endif

#ifndef SOL_IPV6
# define SOL_IPV6 IPPROTO_IPV6
#endif
#ifndef IP_PMTUDISC_DO
# define IP_PMTUDISC_DO		2
#endif
#ifndef IPV6_PMTUDISC_DO
# define IPV6_PMTUDISC_DO	2
#endif
#ifndef IP_PMTUDISC_PROBE
# define IP_PMTUDISC_PROBE	3
#endif
#ifndef IPV6_PMTUDISC_PROBE
# define IPV6_PMTUDISC_PROBE	3
#endif

#if defined(USE_IDN) && defined(AI_IDN)
# define AI_FLAGS (AI_CANONNAME | AI_IDN | AI_CANONIDN)
#else
# define AI_FLAGS AI_CANONNAME
#endif /* AI_IDN */
#if defined(USE_IDN) && defined(NI_IDN)
# define NI_FLAGS NI_IDN
#else
# define NI_FLAGS 0
#endif /* NI_IDN */

#ifndef NOOP
#define NOOP ((void)0)
#endif

#ifdef USE_NLS
#define SET_NLS do { \
	setlocale(LC_ALL, ""); \
	bindtextdomain(PACKAGE_NAME, LOCALEDIR); \
	textdomain(PACKAGE_NAME); \
} while (0)
#else
#define SET_NLS NOOP
#endif

#define INFO	"INFO"		// verbose output prefix
#define WARN	"WARNING"	// warning prefix
#define _INFO	_(INFO)
#define _WARN	_(WARN)

#define OPTEXCL(optA, optB) do { errx(EINVAL, "%s: -%c -%c", \
	_("Mutually exclusive options"), (optA), (optB)); } \
	while (0)

// wrapper: __has_attribute
#ifndef __has_attribute
#define __has_attribute(attr) 0
#endif
// attribute: noreturn
#if __has_attribute(__noreturn__)
#define NORETURN __attribute__((__noreturn__))
#else
#define NORETURN
#endif

long strtol_or_err(const char *str, const char *errmesg, long min, long max);
void close_stdout(void);
void setmyname(const char *argv0);
NORETURN void version_n_exit(int rc);
NORETURN void usage_common(int rc, const char *options, bool more);

int gai_wrapper(const char *restrict node, const char *restrict service,
	const struct addrinfo *restrict hints, struct addrinfo **restrict res);

#ifndef timespecsub
void timespecsub(const struct timespec *a, const struct timespec *b, struct timespec *res);
#endif
#ifndef timersub
void timersub(const struct timeval *a, const struct timeval *b, struct timeval *res);
#endif

#endif
