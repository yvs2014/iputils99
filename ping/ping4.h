#ifndef PING4_H
#define PING4_H

#include "common.h"

int ping4_run(state_t *rts, int argc, char **argv,
	struct addrinfo *ai, const sock_t *sock);

#endif
