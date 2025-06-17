
// local additions by yvs@
// -- fixups: ip4-in-ip6-space, ip6-link-local-scope

#include <string.h>
#include <err.h>
#include <errno.h>

#include "extra.h"

void unmap_ai_sa4(struct addrinfo *ai) {
	if (!ai || !ai->ai_addr)
		return;
	struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)ai->ai_addr;
	struct sockaddr_in sa4 = { .sin_family = AF_INET,
	  .sin_addr.s_addr = ((uint32_t*)&sa6->sin6_addr)[3] };
	memcpy(ai->ai_addr, &sa4, sizeof(sa4));
	ai->ai_addrlen = sizeof(sa4);
	ai->ai_family = AF_INET;
}

void ping6_unspec(const char *target, const struct in6_addr *addr,
	const struct addrinfo *hints)
{
	if (!target || !addr || !hints)
		return;
	struct addrinfo *res = NULL, unspec = *hints;
	unspec.ai_family = AF_UNSPEC;
	int rc = getaddrinfo(target, NULL, &unspec, &res);
	if (rc) {
		if (rc == EAI_SYSTEM)
			err(errno, "%s", "getaddrinfo()");
		errx(rc, TARGET_FMT ": %s", target, gai_strerror(rc));
	}
	for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
		if (ai->ai_family != AF_INET6)
			continue;
		struct sockaddr_in6 *sa = (struct sockaddr_in6 *)ai->ai_addr;
		if (sa && sa->sin6_scope_id)
			if (!memcmp(addr, &sa->sin6_addr, sizeof(struct in6_addr)))
				break;
	}
	if (res)
		freeaddrinfo(res);
}

