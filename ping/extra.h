#ifndef PING_EXTRA_H
#define PING_EXTRA_H

#include "common.h"

#include <netdb.h>

void unmap_ai_sa4(struct addrinfo *ai);
int ping6_unspec(const char *target, const struct in6_addr *addr, const struct addrinfo *hints,
	struct ping_rts *rts, int argc, char **argv, const struct socket_st *sock);

#endif
