#ifndef PING4_AUX_H
#define PING4_AUX_H

#include "common.h"

void bind_to_device(struct ping_rts *rts, int fd, in_addr_t addr);

#endif
