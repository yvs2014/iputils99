#ifndef PING_SETSOCK_H
#define PING_SETSOCK_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <linux/filter.h>

#define MIN_GAP_MS	10 // Minimal interpacket gap, in milliseconds
#define SCHINT(a)	(((a) < MIN_GAP_MS) ? MIN_GAP_MS : (a))

typedef struct ipopt_noped {
	uint8_t nop;
	uint8_t val, len, off;
	uint32_t data[9];
} ipopt_noped_t;

void setsock_mark(int fd, int mark);
void setsock_tos(int fd, int tos, bool ip6);
void setsock_noloop(int fd, bool ip6);
void setsock_filter(int fd, const struct sock_fprog *prog, // NONNULL(2)
	bool verbose, char ip46, uint16_t id);
void setsock_icmp4_filter(int fd, const int32_t flag[]); // NONNULL(2)
void setsock_icmp6_filter(int fd);
void setsock_cksum6(int fd);
void setsock_buffer(int fd, int sndbuf, int preload);
void setsock_debug(int fd);
void setsock_dontroute(int fd);
#ifdef SO_TIMESTAMP
void setsock_timestamp(int fd);
#endif
void setsock_sndtime(int fd, int interval);
bool setsock_rcvtime(int fd, int interval);

void setsock_ipopt_rr(int fd, ipopt_noped_t *opt);
void setsock_ipopt_xrr(int fd, ipopt_noped_t *opt, uint8_t val, uint8_t len);

void setsock_retopts(int fd);
void setsock_broadcast(int fd);
//void setsock_pktinfo(int fd, uint iface, const char *device, bool ip6);
void setsock_flow6(int fd, int flow, size_t clen, struct sockaddr_in6 *sa); // NONNULL(4)

#endif
