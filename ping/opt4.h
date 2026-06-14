#ifndef OPT4_H
#define OPT4_H

#include <stdint.h>
#include <stdbool.h>

void print4_ip_opts(const uint8_t *opt, int len, bool resolve, bool flood);

#endif
