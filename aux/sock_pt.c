// Iputils Project
//
// setsockopt() stuff: ping, tracepath

#include <err.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/ip6.h>

#include "iputils.h"
#include "sock_pt.h"

#ifndef IPPROTO46
#define IPPROTO46 (ip6 ? IPPROTO_IPV6 : IPPROTO_IP)
#endif

#if IPV6_PMTUDISC_DO == IP_PMTUDISC_DO
#define PMTUDISCDO IP_PMTUDISC_DO
#else
#define PMTUDISCDO (ip6 ? IPV6_PMTUDISC_DO : IP_PMTUDISC_DO)
#endif

#define IPMTU46_VAL   (ip6 ?      IPV6_MTU_DISCOVER    :      IP_MTU_DISCOVER)
#define IPMTU46_STR   (ip6 ? _STR(IPV6_MTU_DISCOVER)   : _STR(IP_MTU_DISCOVER))
#define IPTTL46_VAL   (ip6 ?      IPV6_UNICAST_HOPS    :      IP_TTL)
#define IPTTL46_STR   (ip6 ? _STR(IPV6_UNICAST_HOPS)   : _STR(IP_TTL))
#define MCTTL46_VAL   (ip6 ?      IPV6_MULTICAST_HOPS  :      IP_MULTICAST_TTL)
#define MCTTL46_STR   (ip6 ? _STR(IPV6_MULTICAST_HOPS) : _STR(IP_MULTICAST_TTL))
#define RECVERR46_VAL (ip6 ?      IPV6_RECVERR         :      IP_RECVERR)
#define RECVERR46_STR (ip6 ? _STR(IPV6_RECVERR)        : _STR(IP_RECVERR))

void setsock_mtudisc(int fd, int mtu, bool ip6) {
	if (setsockopt(fd, IPPROTO_IPV6, IPMTU46_VAL, &mtu, sizeof(mtu)) < 0)
		err(errno, "setsockopt(%s)", IPMTU46_STR);
}

void setsock_mtudisc_probedo(int fd, bool ip6) {
	int mtu = ip6 ? IPV6_PMTUDISC_PROBE : IP_PMTUDISC_PROBE;
	if (setsockopt(fd, IPPROTO46, IPMTU46_VAL, &mtu, sizeof(mtu)) < 0)
		setsock_mtudisc(fd, PMTUDISCDO, ip6); // fallback
}

void setsock_ttl(int fd, int ttl, bool multicast_too, bool ip6) {
	if (setsockopt(fd, IPPROTO46, IPTTL46_VAL, &ttl, sizeof(ttl)) < 0)
		err(errno, "setsockopt(%s)", IPTTL46_STR);
	if (multicast_too && setsockopt(fd, IPPROTO46, MCTTL46_VAL, &ttl, sizeof(ttl)) < 0)
		err(errno, "setsockopt(%s)", MCTTL46_STR);
}

void setsock_recvttl(int fd, bool ip6) {
	int on = 1;
	if (ip6) {
		if (
#ifdef IPV6_RECVHOPLIMIT
(setsockopt(fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &on, sizeof(on)) < 0) &&
(setsockopt(fd, IPPROTO_IPV6, IPV6_2292HOPLIMIT, &on, sizeof(on)) < 0)
#else
(setsockopt(fd, IPPROTO_IPV6, IPV6_HOPLIMIT,     &on, sizeof(on)) < 0)
#endif
	)
			err(errno, "setsockopt(%s)", "IPV6_*HOPLIMIT");
	} else
		if (setsockopt(fd, IPPROTO_IP, IP_RECVTTL, &on, sizeof(on)) < 0)
			err(errno, "setsockopt(%s)", _STR(IP_RECVTTL));
}

void setsock_recverr(int fd, bool ip6) {
	int on = 1;
	if (setsockopt(fd, IPPROTO46, RECVERR46_VAL, &on, sizeof(on)) < 0)
		err(errno, "setsockopt(%s)", RECVERR46_STR);
}

