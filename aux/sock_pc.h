#ifndef SOCK_PC_H
#define SOCK_PC_H

#include <netinet/ip.h>

int setsock_ipopt_ts(int fd, struct ip_timestamp *opt, uint8_t flg, uint8_t len); // NONNULL(2)

#endif
