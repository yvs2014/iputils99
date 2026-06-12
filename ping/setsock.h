#ifndef PING_SETSOCK_H
#define PING_SETSOCK_H

#include <stdint.h>
#include <stddef.h>
#include <linux/filter.h>

void setsock_mark(int fd, int mark);
void setsock_tos(int fd, int tos, bool ip6);
void setsock_ttl(int fd, bool ip6, int ttl);
void setsock_recverr(int fd, bool ip6);
void setsock_noloop(int fd, bool ip6);
void setsock_mtudisc(int fd, bool ip6, int *mtudisc); // NONNULL(3)
void setsock_filter(int fd, const struct sock_fprog *prog, // NONNUL(2)
	bool verbose, char ip46, uint16_t id);
void setsock_buffer(int fd, int sndbuf, int preload);

#endif
