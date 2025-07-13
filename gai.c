
// Written to test getaddrinfo() flags with non-glibc libcs
// (mostly for IDN)

// yvs, 2025

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <err.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "iputils.h"
#include "str2num.h"

typedef struct gai_opts {
	int af;
	int flags;
	bool verbose;
#ifdef USE_LIBIDN2
	bool idn2;
#endif
} gai_opt_s;

NORETURN static void gai_usage(int rc) {
	const char *options =
"  -4        IPv4 family\n"
"  -6        IPv6 family\n"
"  -f value  ai_flags decimal or hex value\n"
"            use -f multiple times to combine flags\n"
"  -F macro  ai_flags macro like AI_IDN\n"
"            use -F multiple times to combine flags\n"
"  -i        convert IDN names using libidn2\n"
"            (available if IDN is not transparently supported)\n"
"  -h        print help and exit\n"
"  -v        verbose output\n"
"  -V        print version and exit\n"
;
	usage_common(rc, options, "HOST", MORE);
}

/* known AI_xxx: 16 is long enough */
#define STREQ(a, b) (!strncmp((a), (b), 16))

static inline unsigned ai_macro2value(char opt, const char *arg) {
#ifdef AI_PASSIVE
	if (STREQ(arg, "AI_PASSIVE"))
		return AI_PASSIVE;
#endif
#ifdef AI_CANONNAME
	if (STREQ(arg, "AI_CANONNAME"))
		return AI_CANONNAME;
#endif
#ifdef AI_NUMERICHOST
	if (STREQ(arg, "AI_NUMERICHOST"))
		return AI_NUMERICHOST;
#endif
#ifdef AI_V4MAPPED
	if (STREQ(arg, "AI_V4MAPPED"))
		return AI_V4MAPPED;
#endif
#ifdef AI_ALL
	if (STREQ(arg, "AI_ALL"))
		return AI_ALL;
#endif
#ifdef AI_ADDRCONFIG
	if (STREQ(arg, "AI_ADDRCONFIG"))
		return AI_ADDRCONFIG;
#endif
#ifdef AI_IDN
	if (STREQ(arg, "AI_IDN"))
		return AI_IDN;
#endif
#ifdef AI_CANONIDN
	if (STREQ(arg, "AI_CANONIDN"))
		return AI_CANONIDN;
#endif
#ifdef AI_NUMERICSERV
	if (STREQ(arg, "AI_NUMERICSERV"))
		return AI_NUMERICSERV;
#endif
	errno = EINVAL;
	err(errno, "-%c %s", opt, arg);
}

static void parse_opt(int argc, char **argv, gai_opt_s *gai_opt) {
	if (argc <= 0)
		return;
	const char *optstr = "hf:F:ivV46";
	int opt;
	while ((opt = getopt(argc, argv, optstr)) != EOF) {
		switch (opt) {
		case '4':
		case '6': {
			bool ip4 = (opt == '4');
			int incompat = ip4 ? AF_INET6 : AF_INET;
			if (gai_opt->af == incompat)
				OPTEXCL('4', '6');
			gai_opt->af = ip4 ? AF_INET : AF_INET6;
		}	break;
		case 'i':
#ifdef USE_LIBIDN2
			if (!gai_opt->idn2)
				gai_opt->idn2 = true;
#else
			warnx(_("no need in -i, IDN is transparently supported"));
#endif
			break;
		case 'h':
			gai_usage(EXIT_SUCCESS);
		case 'f':
		case 'F':
			if (!optarg || !*optarg)
				break;
			if (gai_opt->flags < 0)
				gai_opt->flags = 0;
			gai_opt->flags |= (opt == 'f') ?
				VALID_INTSTR(0, USHRT_MAX) :
				ai_macro2value(opt, optarg);
			break;
		case 'v':
			gai_opt->verbose = true;
			break;
		case 'V':
			version_n_exit(EXIT_SUCCESS, FEAT_IDN | FEAT_NLS);
		default:
			gai_usage(EXIT_FAILURE);
                }
	}
}

static void println_gni(const void *sa, socklen_t salen) {
	char addr[NI_MAXHOST] = {0};
	getnameinfo(sa, salen, addr, sizeof(addr), NULL, 0, NI_FLAGS | NI_NUMERICHOST);
	char name[NI_MAXHOST] = {0};
	getnameinfo(sa, salen, name, sizeof(name), NULL, 0, NI_FLAGS);
	if (*name && strncmp(name, addr, NI_MAXHOST))
		printf("%s (%s)\n", name, addr);
	else
		puts(addr);
}

int main(int argc, char **argv) {
	setmyname(argv[0]);
	BIND_NLS;

	gai_opt_s gai_opt = {.af = -1, .flags = -1};
	parse_opt(argc, argv, &gai_opt);
	argc -= optind;
	argv += optind;
	if (argc < 1)
		gai_usage(EXIT_FAILURE);

	const struct addrinfo hints = {
		.ai_family   = (gai_opt.af >= 0) ? gai_opt.af : AF_UNSPEC,
		.ai_socktype = SOCK_DGRAM,
		.ai_flags    = (gai_opt.flags >= 0) ? gai_opt.flags : AI_FLAGS,
	};
	if (gai_opt.verbose)
		printf("hints: af=%d type=%d flags=%u(0x%04x)\n",
			hints.ai_family, hints.ai_socktype,
			hints.ai_flags, hints.ai_flags);

	int re = EXIT_SUCCESS;

	for (int i = 0; i < argc; i++) {
		const char *name = argv[i];
		errno = validate_hostlen(name, false);
		if (errno) {
			re = EXIT_FAILURE;
			continue;
		}
		struct addrinfo *res = NULL;

		int rc =
#ifdef USE_LIBIDN2
			gai_opt.idn2 ? gai_wrapper2(name, NULL, &hints, &res) :
#endif
			gai_wrapper(name, NULL, &hints, &res);
		if (rc) {
			if (rc == EAI_SYSTEM)
				warn("%s", name);
			else
				warnx(TARGET_FMT ": %s", name, gai_strerror(rc));
			re = EXIT_FAILURE;
			continue;
		}

		for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
			int af = ai->ai_family;
			socklen_t len =	(af == AF_INET)  ? sizeof(struct sockaddr_in)  :
					(af == AF_INET6) ? sizeof(struct sockaddr_in6) : 0;
			if (!len) {
				errno = EAFNOSUPPORT;
				warn("%s: ai_family=%d", name, af);
				re = EXIT_FAILURE;
				continue;
			}
			printf("%s ip%c: ", name, (af == AF_INET) ? '4' : '6');
			println_gni(ai->ai_addr, len);
		}
	}

	return re;
}

