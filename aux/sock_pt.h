#ifndef SOCK_PT_H
#define SOCK_PT_H

#include <stdbool.h>

#define IP6           true
#define MULTICAST_TOO true

void setsock_mtudisc(int fd, int mtu, bool ip6);
void setsock_mtudisc_probedo(int fd, bool ip6);
void setsock_ttl(int fd, int ttl, bool multicast_too, bool ip6);
void setsock_recvttl(int fd, bool ip6);
void setsock_recverr(int fd, bool ip6);

#endif
