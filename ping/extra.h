#ifndef PING_EXTRA_H
#define PING_EXTRA_H

#include "common.h"

void unmap_ai_sa4(struct addrinfo *ai);
int ping6_unspec(const char *target, struct in6_addr *addr, struct addrinfo *hints,
	struct ping_rts *rts, int argc, char **argv, struct socket_st *sock);

#endif
