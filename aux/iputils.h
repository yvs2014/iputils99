#ifndef IPUTILS_H
#define IPUTILS_H

#include <stdbool.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netdb.h>

#include "cc_attr.h"

#ifndef NOOP
#define NOOP ((void)0)
#endif

#ifdef USE_NLS
#include <locale.h>
#include <libintl.h>
#define BIND_NLS do { \
	setlocale(LC_ALL, ""); \
	bindtextdomain(PACKAGE_NAME, LOCALEDIR); \
	textdomain(PACKAGE_NAME); \
} while (0)
#define _(text) gettext(text)
#define _n(singular, plural, number) ngettext((singular), (plural), (number))
#else
#define BIND_NLS NOOP
#define _(text) text
#define _n(singular, plural, number) plural
#endif

#define BYTES(nbytes) _n("byte", "bytes", (nbytes))

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

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

#define WARN	"WARNING"	// warning prefix
#define _WARN	_(WARN)
#define V4IN6_WARN	"Embedded IPv4 Address"

#define OPTEXCL(optA, optB) do { errx(EINVAL, "%s: -%c -%c", \
	_("Mutually exclusive options"), (optA), (optB)); } \
	while (0)

#define MSFMT "%.3f"		// common timing format in milliseconds
#define TMMS  MSFMT "%s"	// ".3fms"
#define TM_MS MSFMT " %s"	// ".3f ms"
#ifndef TARGET_FMT
#define TARGET_FMT "%.64s"	// limit to 64 characters
#endif
#ifndef NETDEV_FMT
#define NETDEV_FMT "%.128s"	// limit to 128 characters
#endif


void close_stdout(void);
void setmyname(const char *argv0);

NORETURN void usage_common(int rc, const char *options, const char *target, bool more);
#ifndef MORE
#define MORE true
#endif

NORETURN void version_n_exit(int rc, int features);
enum {
	FEAT_CAP     = 0x1,
	FEAT_IDN     = 0x2,
	FEAT_NLS     = 0x4,
	FEAT_RFC4620 = 0x8,
};

int gai_wrapper(const char *restrict node, const char *restrict service,
	const struct addrinfo *restrict hints, struct addrinfo **restrict res);
#ifdef USE_LIBIDN2
int gai_wrapper2(const char *restrict node, const char *restrict service,
	const struct addrinfo *restrict hints, struct addrinfo **restrict res);
#define GAI_WRAPPER gai_wrapper2
#else
#define GAI_WRAPPER gai_wrapper
#endif

#ifndef timespecsub
void timespecsub(const struct timespec *a, const struct timespec *b, struct timespec *res);
#endif
#ifndef timersub
void timersub(const struct timeval *a, const struct timeval *b, struct timeval *res);
#endif

#endif
