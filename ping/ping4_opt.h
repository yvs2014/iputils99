#ifndef PING4_OPT_H
#define PING4_OPT_H

#include <stdint.h>
#include <stdbool.h>

void print4_ip_opts(const uint8_t *opt, int len, bool resolve, bool flood);

#endif
