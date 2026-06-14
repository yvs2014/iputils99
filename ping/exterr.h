#ifndef EXTERR_H
#define EXTERR_H

#include "common.h"

int get_errmsg(state_t *rts, const sock_t *sock, struct msghdr *msg);

#endif
