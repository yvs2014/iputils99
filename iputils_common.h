#ifndef IPUTILS_COMMON_H
#define IPUTILS_COMMON_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <time.h>
#include <sys/time.h>

#define ARRAY_SIZE(arr) \
  (sizeof(arr) / sizeof((arr)[0]) + \
   sizeof(__typeof__(int[1 - 2 * \
	  !!__builtin_types_compatible_p(__typeof__(arr), \
					 __typeof__(&arr[0]))])) * 0)

#ifdef __GNUC__
# define iputils_attribute_format(t, n, m) __attribute__((__format__ (t, n, m)))
#else
# define iputils_attribute_format(t, n, m)
#endif

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

#ifdef HAVE_ERROR_H
# include <error.h>
#else
extern void error(int status, int errnum, const char *format, ...);
#endif

extern int close_stream(FILE *stream);
extern void close_stdout(void);
extern long strtol_or_err(char const *const str, char const *const errmesg,
			  const long min, const long max);
extern unsigned long strtoul_or_err(char const *const str, char const *const errmesg,
			  const unsigned long min, const unsigned long max);
extern void iputils_srand(void);
void print_config(void);

#ifndef timespecsub
void timespecsub(struct timespec *a, struct timespec *b, struct timespec *res);
#endif
#ifndef timersub
void timersub(struct timeval *a, struct timeval *b, struct timeval *res);
#endif

#endif
