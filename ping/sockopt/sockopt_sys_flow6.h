#ifndef PING_SOCKOPT_SYS_FLOW6_H
#define PING_SOCKOPT_SYS_FLOW6_H

#include <stddef.h>
#include <sys/socket.h>

void setsock_flow6(int fd, int flow, size_t size, struct sockaddr *sa, socklen_t salen); // NONNULL(4)

#endif
