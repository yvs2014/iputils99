
// Written to test getaddrinfo() flags with non-glibc libcs
// (mostly for IDN)

// yvs, 2025

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <sys/types.h>
#include <netdb.h>

#include "iputils.h"
#include "str2num.h"
#include "usage.h"

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


#define STREQ(a, b) (!strncmp((a), (b), AI_FMTLEN * (size_t)2))

#define IF_AI_MACRO(macro) { if (STREQ(arg, (#macro))) return (macro); }
#define IF_AI_MACRONAME(macro, name) { if (STREQ(arg, (name))) return (macro); }

static inline uint ai_macro2value(char opt, const char *arg) {
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
	// optional: deprecated AI flags
#ifdef _AI_IDN_ALLOW_UNASSIGNED
	IF_AI_MACRONAME(_AI_IDN_ALLOW_UNASSIGNED, "AI_IDN_ALLOW_UNASSIGNED")
#endif
#ifdef _AI_IDN_USE_STD3_ASCII_RULES
	IF_AI_MACRONAME(_AI_IDN_USE_STD3_ASCII_RULES, "AI_IDN_USE_STD3_ASCII_RULES");
#endif
	// end-of-optional
#ifdef AI_NUMERICSERV
	IF_AI_MACRO(AI_NUMERICSERV);
#endif
	//
	errno = EINVAL;
	errt(errno, "-%c %s", opt, arg);
}


#define AIF_VALSTR(macro, desc) {.val = (macro), .str = #macro, .dsc = (desc)}
#define AIF_DEPRECATED_VALSTR(macro, name, desc) {.val = (macro), .str = (name), .dsc = (desc)}

NORETURN static inline void list_ai_consts(void) {
	valstr_s ai[] = {
#ifdef AI_PASSIVE
		AIF_VALSTR(AI_PASSIVE, _BIND_SOCKADDR),
#endif
#ifdef AI_CANONNAME
		AIF_VALSTR(AI_CANONNAME, _CANONNAME_Q),
#endif
#ifdef AI_NUMERICHOST
		AIF_VALSTR(AI_NUMERICHOST, _DONT_USE_RRES),
#endif
#ifdef AI_V4MAPPED
		AIF_VALSTR(AI_V4MAPPED, _IP4MAP_ACCEPT),
#endif
#ifdef AI_ALL
		AIF_VALSTR(AI_ALL, _IP46MAP),
#endif
#ifdef AI_ADDRCONFIG
		AIF_VALSTR(AI_ADDRCONFIG, _USE_HOSTCONF),
#endif
#ifdef AI_IDN
		AIF_VALSTR(AI_IDN, _IDN_IF_NEEDED),
#endif
#ifdef AI_CANONIDN
		AIF_VALSTR(AI_CANONIDN, _IDN2CANON),
#endif
	// optional: deprecated AI flags
#ifdef _AI_IDN_ALLOW_UNASSIGNED
		AIF_DEPRECATED_VALSTR(_AI_IDN_ALLOW_UNASSIGNED,
	"AI_IDN_ALLOW_UNASSIGNED", _DEPRECATED),
#endif
#ifdef _AI_IDN_USE_STD3_ASCII_RULES
		AIF_DEPRECATED_VALSTR(_AI_IDN_USE_STD3_ASCII_RULES,
	"AI_IDN_USE_STD3_ASCII_RULES", _DEPRECATED),
#endif
	// end-of-optional
#ifdef AI_NUMERICSERV
		AIF_VALSTR(AI_NUMERICSERV, _DONT_USE_SRES),
#endif
	};
	for (uint i = 0; i < ARRAY_LEN(ai); i++)
		printf("%-*s 0x%04x %s\n", AI_FMTLEN, ai[i].str,
			ai[i].val, *ai[i].dsc ? ai[i].dsc : "");
	exit(EXIT_SUCCESS);
}

static char *optstr = "hf:F:ilvV46";

static const usage_opt_t uopts[] = { // null-terminated
	{.opt = '4', .desc = {__OPT_4}},
	{.opt = '6', .desc = {__OPT_6}},
	{.opt = 'f', .arg  = __VALUE, .desc = {__GAI_OPT_f0, __GAI_OPT_f1}},
	{.opt = 'F', .arg  = __MACRO, .desc = {__GAI_OPT_F0, __GAI_OPT_F1}},
	{.opt = 'i', .desc = {__GAI_OPT_i0, __GAI_OPT_i1}},
	{.opt = 'l', .desc = {__GAI_OPT_l}},
	{.opt = 'h', .desc = {__OPT_h}},
	{.opt = 'v', .desc = {__OPT_v}},
	{.opt = 'V', .desc = {__OPT_V}},
	{0},
};

NORETURN static void usage(int rc) {
	const usage_data_t use = {
		.indent  = 6,
		.options = uopts,
		.optstr  = optstr,
		.target  = _HOST,
		.more    = MORE,
	};
	usage_common(rc, &use);
}

static void switch_opt(char c, void *data) { // NONNULL(1, 2)
#define GAI_OPT ((gaiopt_s *)data)
	switch (c) {
	case '4':
	case '6': {
		bool ip4 = (c == '4');
		int incompat = ip4 ? AF_INET6 : AF_INET;
		if (GAI_OPT->af == incompat)
			OPTEXCL('4', '6');
		GAI_OPT->af = ip4 ? AF_INET : AF_INET6;
	}	break;
	case 'f':
	case 'F':
		if (optarg && *optarg) {
			if (GAI_OPT->flags < 0)
				GAI_OPT->flags = 0;
			GAI_OPT->flags |= (c == 'f') ?
				VALID_INTSTR(0, USHRT_MAX) :
				ai_macro2value(c, optarg);
		}
		break;
	case 'i':
#ifdef USE_LIBIDN2
		if (!GAI_OPT->idn2)
			GAI_OPT->idn2 = true;
#else
		warnxt(_NO_NEED_OPT_I);
#endif
		break;
	case 'l':
		list_ai_consts();
	case 'v':
		GAI_OPT->verbose = true;
		break;
	default:
		break;
	}
#undef GAI_OPT
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
	common_getopt(argc, argv, optstr, FEAT_IDN | FEAT_NLS, usage, switch_opt, &gai_opt);
	argc -= optind;
	argv += optind;
	if (argc < 1)
		usage(EXIT_FAILURE);

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
			(rc == EAI_SYSTEM) ? warnt("%s", name) :
				warnxt(TARGET_FMT ": %s", name, gai_strerror(rc));
			re = rc;
		} else for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
			int af = ai->ai_family;
			char c = (af == AF_INET) ? '4' : (af == AF_INET6) ? '6' : 0;
			if (c) {
				printf("%s ip%c: ", name, c);
				println_gni(ai->ai_addr, ai->ai_addrlen);
			} else {
				re = errno = EAFNOSUPPORT;
				warnt("%s: ai_family=%d", name, af);
			}
		}
		if (res) freeaddrinfo(res);
	}

	return re;
}

