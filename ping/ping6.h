#ifndef PING6_H
#define PING6_H

#include "common.h"

int ping6_run(struct ping_rts *rts, int argc, char **argv,
	struct addrinfo *ai, socket_st *sock);

#endif
