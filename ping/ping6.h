#ifndef PING6_H
#define PING6_H

#include "common.h"

int ping6_run(state_t *rts, int argc, char **argv,
	struct addrinfo *ai, const sock_t *sock);

#endif
