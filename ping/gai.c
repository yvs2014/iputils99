
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <locale.h>

#include "iputils_common.h"
#include "common.h"

typedef struct gai_opts {
	int af;
	int flags;
	bool verbose;
} gai_opt_s;

NORETURN static void gai_usage(int rc) {
	const char *options =
"  -4        IPv4 family\n"
"  -6        IPv6 family\n"
"  -f value  ai_flags decimal or hex value\n"
"            use -f multiple times to combine flags\n"
"  -F macro  ai_flags macro like AI_IDN\n"
"            use -F multiple times to combine flags\n"
"  -h        print help and exit\n"
"  -v        verbose output\n"
"  -V        print version and exit\n"
;
	usage_common(rc, options, true);
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
	const char *optstr = "hf:F:vV46";
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
		case 'h':
			gai_usage(EXIT_SUCCESS);
		case 'f':
		case 'F':
			if (!optarg || !*optarg)
				break;
			if (gai_opt->flags < 0)
				gai_opt->flags = 0;
			gai_opt->flags |= (opt == 'f') ?
				strtoul_or_err(optarg, _("Invalid argument"), 0, USHRT_MAX) :
				ai_macro2value(opt, optarg);
			break;
		case 'v':
			gai_opt->verbose = true;
			break;
		case 'V':
			version_n_exit(EXIT_SUCCESS);
		default:
			gai_usage(EXIT_FAILURE);
                }
	}
}

int main(int argc, char **argv) {
	setmyname(argv[0]);
	SET_NLS;

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
		errno = 0;
		const char *name = argv[i];
		struct addrinfo *res = NULL;

		int rc = gai_wrapper(name, NULL, &hints, &res);
		if (rc) {
			if (rc == EAI_SYSTEM)
				warn("%s", name);
			else
				warnx("%s: %s", name, gai_strerror(rc));
			re = EXIT_FAILURE;
			continue;
		}

		for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
			int af = ai->ai_family;
			socklen_t len =	(af == AF_INET)  ? sizeof(struct sockaddr_in)  :
					(af == AF_INET6) ? sizeof(struct sockaddr_in6) : 0;
			if (!len) {
				warnx("%s: unsupported af: %d", name, af);
				re = EXIT_FAILURE;
				continue;
			}
			printf("%s ip%c: %s\n", name, (af == AF_INET) ? '4' : '6',
				sprint_addr(ai->ai_addr, len, true));
		}
	}

	exit(re);
}
