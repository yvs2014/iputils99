#ifndef PING_EXTRA_H
#define PING_EXTRA_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

void unmap_ai_sa4(struct addrinfo *ai);
void ping6_unspec(const char *target, const struct in6_addr *addr,
	const struct addrinfo *hints);

#endif
