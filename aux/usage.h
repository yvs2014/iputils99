#ifndef USAGE_H
#define USAGE_H

#include <stdbool.h>
#include "cc_attr.h"

enum {
	FEAT_CAP     = 0x1,
	FEAT_IDN     = 0x2,
	FEAT_NLS     = 0x4,
	FEAT_ALTNAME = 0x8,
	FEAT_RFC4620 = 0x10,
};

typedef struct usage_data {
	const char *usestr, *target;
	bool more;
} usage_data_t;

void setmyname(const char *argv0);
NORETURN void version_n_exit(int features);
NORETURN void usage_common(int rc, const usage_data_t *udata); // NONNULL(2)

#endif
