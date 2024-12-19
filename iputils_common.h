#ifndef IPUTILS_COMMON_H
#define IPUTILS_COMMON_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netdb.h>

#ifdef ENABLE_NLS
# include <libintl.h>
# define _(Text) gettext (Text)
#else
# undef bindtextdomain
# define bindtextdomain(Domain, Directory) /* empty */
# undef textdomain
# define textdomain(Domain) /* empty */
# define _(Text) Text
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

#ifdef USE_IDN
#ifdef AI_IDN
# define AI_FLAGS (AI_CANONNAME | AI_IDN | AI_CANONIDN)
#else
# define AI_FLAGS AI_CANONNAME
#endif /* AI_IDN */
#ifdef NI_IDN
# define NI_FLAGS NI_IDN
#else
# define NI_FLAGS 0
#endif /* NI_IDN */
#endif /* USE_IDN */

#ifdef HAVE_ERROR_H
# include <error.h>
#else
void error(int status, int errnum, const char *format, ...);
#endif

long strtol_or_err(const char *str, const char *errmesg, long min, long max);
void close_stdout(void);
void print_config(void);

#ifndef timespecsub
void timespecsub(const struct timespec *a, const struct timespec *b, struct timespec *res);
#endif
#ifndef timersub
void timersub(const struct timeval *a, const struct timeval *b, struct timeval *res);
#endif

#endif
