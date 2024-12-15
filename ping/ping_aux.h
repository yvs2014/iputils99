#ifndef PING_AUX_H
#define PING_AUX_H

#include "common.h"
#include <linux/errqueue.h>

char *str_family(int family);
double ping_strtod(const char *str, const char *err_msg);
unsigned parse_flow(const char *str);
unsigned char parse_tos(const char *str);
unsigned if_name2index(const char *ifname);
int setsock_bindopt(int fd, const char *device, socklen_t slen, unsigned ifindex);
void print_local_ee(struct ping_rts *rts, const struct sock_extended_err *ee);
void ping_bind(struct ping_rts *rts, const struct socket_st *sock);

#endif
