#ifndef WARNERR_H
#define WARNERR_H

#include <stdbool.h>
#include "cc_attr.h"

#define COLOR_NORMAL "\033[0m"
#define COLOR_BOLD   "\033[1m"
#define COLOR_RED    "\033[31m"
#define COLOR_YELLOW "\033[33m"

// colored (if it's a tty) formatted error messages
void warnt(const char *fmt, ...);
void warnxt(const char *fmt, ...);
NORETURN void errt(int eval, const char *fmt, ...);
NORETURN void errxt(int eval, const char *fmt, ...);

extern bool itistty;

#endif
