
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

#define AI_FMTLEN 16

typedef struct gai_opts {
	int  af;
	int  flags;
	bool verbose;
#ifdef USE_LIBIDN2
	bool idn2;
#endif
} gaiopt_s;

typedef struct valstr {
	int  val;
	const char *str;
	const char *dsc;
} valstr_s;


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
"  -l        list AI_xxx constants\n"
"  -h        print help\n"
"  -v        verbose output\n"
"  -V        print version\n"
;
	usage_common(rc, options, "HOST", MORE);
}

#define STREQ(a, b) (!strncmp((a), (b), AI_FMTLEN * 2))

#define IF_AI_MACRO(macro) { if (STREQ((arg), (#macro))) return (macro); }

static inline unsigned ai_macro2value(char opt, const char *arg) {
#ifdef AI_PASSIVE
	IF_AI_MACRO(AI_PASSIVE);
#endif
#ifdef AI_CANONNAME
	IF_AI_MACRO(AI_CANONNAME);
#endif
#ifdef AI_NUMERICHOST
	IF_AI_MACRO(AI_NUMERICHOST);
#endif
#ifdef AI_V4MAPPED
	IF_AI_MACRO(AI_V4MAPPED);
#endif
#ifdef AI_ALL
	IF_AI_MACRO(AI_ALL);
#endif
#ifdef AI_ADDRCONFIG
	IF_AI_MACRO(AI_ADDRCONFIG);
#endif
#ifdef AI_IDN
	IF_AI_MACRO(AI_IDN);
#endif
#ifdef AI_CANONIDN
	IF_AI_MACRO(AI_CANONIDN);
#endif
	// deprecated
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunknown-pragmas"
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-W#pragma-messages"
#ifdef AI_IDN_ALLOW_UNASSIGNED
	IF_AI_MACRO(AI_IDN_ALLOW_UNASSIGNED);
#endif
#ifdef AI_IDN_USE_STD3_ASCII_RULES
	IF_AI_MACRO(AI_IDN_USE_STD3_ASCII_RULES);
#endif
#pragma clang diagnostic pop
#pragma GCC diagnostic pop
	//
#ifdef AI_NUMERICSERV
	IF_AI_MACRO(AI_NUMERICSERV);
#endif
	//
	errno = EINVAL;
	err(errno, "-%c %s", opt, arg);
}


#define VALSTR_M(macro, desc) {.val = (macro), .str = #macro, .dsc = (desc)}

NORETURN static inline void list_ai_consts(void) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunknown-pragmas"
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-W#pragma-messages"
#ifdef AI_IDN_ALLOW_UNASSIGNED
	valstr_s ai0100 = VALSTR_M(AI_IDN_ALLOW_UNASSIGNED, _("deprecated"));
#endif
#ifdef AI_IDN_USE_STD3_ASCII_RULES
	valstr_s ai0200 = VALSTR_M(AI_IDN_USE_STD3_ASCII_RULES, _("deprecated"));
#endif
#pragma clang diagnostic pop
#pragma GCC diagnostic pop
	//
	valstr_s ai[] = {
#ifdef AI_PASSIVE
		VALSTR_M(AI_PASSIVE,
	_("Socket address for bind()")),
#endif
#ifdef AI_CANONNAME
		VALSTR_M(AI_CANONNAME,
	_("Request for canonical name")),
#endif
#ifdef AI_NUMERICHOST
		VALSTR_M(AI_NUMERICHOST,
	_("Don't use host resolution")),
#endif
#ifdef AI_V4MAPPED
		VALSTR_M(AI_V4MAPPED,
	_("IPv4 mapped addresses are acceptable")),
#endif
#ifdef AI_ALL
		VALSTR_M(AI_ALL,
	_("IPv4 mapped and IPv6 addresses")),
#endif
#ifdef AI_ADDRCONFIG
		VALSTR_M(AI_ADDRCONFIG,
	_("Use host configuration to choose address type")),
#endif
#ifdef AI_IDN
		VALSTR_M(AI_IDN,
	_("Convert to IDN format if necessary")),
#endif
#ifdef AI_CANONIDN
		VALSTR_M(AI_CANONIDN,
	_("Translate canonical name from IDN format")),
#endif
	// deprecated
#ifdef AI_IDN_ALLOW_UNASSIGNED
		ai0100,
#endif
#ifdef AI_IDN_USE_STD3_ASCII_RULES
		ai0200,
#endif
	//
#ifdef AI_NUMERICSERV
		VALSTR_M(AI_NUMERICSERV,
	_("Don't use service resolution")),
#endif
	};
	for (uint i = 0; i < ARRAY_LEN(ai); i++)
		printf("%-*s 0x%04x %s\n", AI_FMTLEN, ai[i].str,
			ai[i].val, *ai[i].dsc ? ai[i].dsc : "");
	exit(EXIT_SUCCESS);
}

static inline void parse_opt(int argc, char **argv, gaiopt_s *gai_opt) {
	if (argc <= 0)
		return;
	const char *optstr = "hf:F:ilvV46";
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
		case 'i':
#ifdef USE_LIBIDN2
			if (!gai_opt->idn2)
				gai_opt->idn2 = true;
#else
			warnx(_("no need in -i, IDN is transparently supported"));
#endif
			break;
		case 'l':
			list_ai_consts();
		case 'v':
			gai_opt->verbose = true;
			break;
		case 'V':
			version_n_exit(EXIT_SUCCESS, FEAT_IDN | FEAT_NLS);
		case 'h':
			gai_usage(EXIT_SUCCESS);
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

	gaiopt_s gai_opt = {.af = -1, .flags = -1};
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
			hints.ai_flags,  hints.ai_flags);

	int re = EXIT_SUCCESS;

	for (int i = 0; i < argc; i++) {
		const char *name = argv[i];
		errno = validate_hostlen(name, false);
		if (errno) {
			re = errno;
			continue;
		}
		struct addrinfo *res = NULL;

		int rc =
#ifdef USE_LIBIDN2
			gai_opt.idn2 ? gai_wrapper2(name, NULL, &hints, &res) :
#endif
			gai_wrapper(name, NULL, &hints, &res);
		if (rc) {
			(rc == EAI_SYSTEM) ? warn("%s", name) :
				warnx(TARGET_FMT ": %s", name, gai_strerror(rc));
			re = rc;
		} else for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
			int af = ai->ai_family;
			char c = (af == AF_INET) ? '4' : (af == AF_INET6) ? '6' : 0;
			if (c) {
				printf("%s ip%c: ", name, c);
				println_gni(ai->ai_addr, ai->ai_addrlen);
			} else {
				re = errno = EAFNOSUPPORT;
				warn("%s: ai_family=%d", name, af);
			}
		}
		if (res) freeaddrinfo(res);
	}

	return re;
}

