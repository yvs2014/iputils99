
// part of iputils
//
// common display usage and colored error messages

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <stdarg.h>

#include "usage.h"
#include "warnerr.h"
#include "po.h"

static const char *myname;
bool itistty; // = isatty(STDOUT_FILENO)

#define REDIT true

//

void setmyname(const char *argv0) {
	myname =
#ifdef HAVE_GETPROGNAME
	getprogname();
#elif  HAVE_PROGRAM_INVOCATION_SHORT_NAME
	program_invocation_short_name;
#else
	NULL;
#endif
	if (!myname)
		myname = argv0 ? argv0 : "";
	itistty = isatty(STDOUT_FILENO);
	if (!itistty)
		errno = 0;
}

#ifdef HAVE_LIBCAP
#define CAP_FEATURE	'+'
#else
#define CAP_FEATURE	'-'
#endif
#ifdef USE_IDN
#define IDN_FEATURE	'+'
#else
#define IDN_FEATURE	'-'
#endif
#ifdef USE_NLS
#define NLS_FEATURE	'+'
#else
#define NLS_FEATURE	'-'
#endif
#ifdef USE_ALTNAMES
#define ALTNAME_FEATURE	'+'
#else
#define ALTNAME_FEATURE	'-'
#endif
#ifdef ENABLE_RFC4620
#define RFC4620_FEATURE	'+'
#else
#define RFC4620_FEATURE	'-'
#endif

NORETURN void version_n_exit(int features) {
	if (!myname)
		setmyname(NULL);
	printf("%s %s%s",
		myname,
#ifdef PACKAGE_NAME
		PACKAGE_NAME,
#else
		"iputils",
#endif
#ifdef PACKAGE_VERSION
		"_" PACKAGE_VERSION
#else
		""
#endif
	);
	if (features) {
		putchar(':');
		if (features & FEAT_CAP)
			printf(" %cCAP",     CAP_FEATURE);
		if (features & FEAT_IDN)
			printf(" %cIDN",     IDN_FEATURE);
		if (features & FEAT_NLS)
			printf(" %cNLS",     NLS_FEATURE);
		if (features & FEAT_ALTNAME)
			printf(" %cALTNAME", ALTNAME_FEATURE);
		if (features & FEAT_RFC4620)
			printf(" %cRFC4620", RFC4620_FEATURE);
	}
	putchar('\n');
	exit(EXIT_SUCCESS);
}

// print unicode string like ("%-*s", width, string)
static void uprintn(uint8_t w, const char *s) {
  if (s) {
    fputs(s, stdout);
    for (; *s && w; s++)
      if ((*s & 0xc0) != 0x80)
        w--;
  }
  if (w)
    printf("%*s", w, "");
}

#define MAXOPTS   50
#define OPTINDENT "  "

void usage_common(int rc, const usage_data_t *udata) { // NONNULL(2)
	const char *bold = itistty ? COLOR_BOLD   : "";
	const char *norm = itistty ? COLOR_NORMAL : "";
	const char *yell = itistty ? COLOR_YELLOW : "";
	printf("\n%s%s%s:\n", bold, _USAGE, norm);
	printf(OPTINDENT "%s", myname);
	const usage_opt_t *uopt = udata->options;
	if (udata->usestr)
		printf(" [%s%s%s]", yell, _OPTIONS, norm);
	if (udata->optstr)
		printf(" [%s%s%s]", yell, udata->optstr, norm);
	printf(" %s%s\n", udata->target, udata->more ? " ..." : "");
	if (udata->usestr || uopt)
		printf("\n%s%s%s:\n", bold, _OPTIONS_H, norm);
	for (uint i = 0; (i < MAXOPTS) && uopt && uopt->opt; i++, uopt++) {
		if (uopt->pre)
			printf(OPTINDENT "   %-*s %s\n", udata->indent, "", _(uopt->pre));
		printf(OPTINDENT "-%s%c ", yell, uopt->opt);
		if (uopt->arg)
			uprintn(udata->indent, _(uopt->arg));
		else
			printf("%*s", udata->indent, "");
		fputs(norm, stdout);
		if (uopt->desc[0])
			printf(" %s", _(uopt->desc[0]));
		putchar('\n');
		if (uopt->desc[0]) for (uint j = 1;
		   (j < ARRAY_LEN(uopt->desc)) && uopt->desc[j]; j++)
			printf(OPTINDENT "   %-*s %s\n", udata->indent, "", _(uopt->desc[j]));
	}
	if (udata->usestr && !uopt)
		printf("\n%s%s%s:\n%s", bold, _OPTIONS_H, norm, udata->usestr);
	printf("\n%s%s %s(8)%s\n", bold, _FOR_MORE, myname, norm);
	exit(rc);
}

//

static void warnerrt(const char *fmt, va_list args, bool red, const char *msg) {
	if (myname)
		fprintf(stderr, "%s%s%s: ", COLOR_BOLD, myname, COLOR_NORMAL);
	if (itistty)
		fputs(red ? COLOR_RED : COLOR_YELLOW, stderr);
	vfprintf(stderr, fmt, args);
	if (msg)
		fprintf(stderr, ": %s", msg);
	if (itistty)
		fputs(COLOR_NORMAL, stderr);
	putc('\n', stderr);
}

void warnt(const char *fmt, ...) {
	va_list args;
	va_start(args, fmt);
	warnerrt(fmt, args, !REDIT, strerror(errno));
	va_end(args);
}

void warnxt(const char *fmt, ...) {
	va_list args;
	va_start(args, fmt);
	warnerrt(fmt, args, !REDIT, NULL);
	va_end(args);
}

NORETURN void errt(int eval, const char *fmt, ...) {
	va_list args;
	va_start(args, fmt);
	warnerrt(fmt, args, REDIT, strerror(errno));
	va_end(args);
	exit(eval);
}

NORETURN void errxt(int eval, const char *fmt, ...) {
	va_list args;
	va_start(args, fmt);
	warnerrt(fmt, args, !REDIT, NULL);
	va_end(args);
	exit(eval);
}

