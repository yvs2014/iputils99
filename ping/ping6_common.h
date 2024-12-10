#ifndef PING6_COMMON_H
#define PING6_COMMON_H

#include "common.h"

int ping6_run(struct ping_rts *rts, int argc, char **argv,
	struct addrinfo *ai, struct socket_st *sock);

#endif
