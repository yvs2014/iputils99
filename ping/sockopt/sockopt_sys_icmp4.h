#ifndef PING_SOCKOPT_SYS_ICMP4_H
#define PING_SOCKOPT_SYS_ICMP4_H

#include <stdint.h>

void setsock_icmp4_filter(int fd, const int32_t flag[]); // NONNULL(2)

#endif
