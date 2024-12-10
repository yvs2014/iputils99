#ifndef PING4_H
#define PING4_H

#include "common.h"

int ping4_run(struct ping_rts *rts, int argc, char **argv, struct addrinfo *ai, socket_st *sock);

#endif
