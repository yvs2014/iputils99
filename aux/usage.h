#ifndef USAGE_H
#define USAGE_H

#include <stdint.h>
#include <stdbool.h>
#include "attr.h"

enum {
	FEAT_CAP     = 0x1,
	FEAT_IDN     = 0x2,
	FEAT_NLS     = 0x4,
	FEAT_ALTNAME = 0x8,
	FEAT_RFC4620 = 0x10,
};

#define MAXOPTDESC 5
typedef struct usage_opt {
	char opt; // use '_' for extra headers
	const char *arg, *desc[MAXOPTDESC], *pre;
} usage_opt_t;

#define MORE true
typedef struct usage_data {
	uint8_t indent;
	const usage_opt_t *uopt; // uopt[] null-terminated array
	const char *optstr, *target;
	bool more;
} usage_data_t;

void setmyname(const char *argv0);
NORETURN void version_n_exit(int features);
NORETURN void usage_common(int rc, const usage_data_t *udata); // NONNULL(2)

#endif
