#ifndef PING_AUX_H
#define PING_AUX_H

#include "common.h"
#include <linux/errqueue.h>

//#define IP6 true
//#define IP4 false

char *str_family(int family);
double ping_strtod(const char *str, const char *err_msg);
unsigned parse_flow(const char *str);
unsigned char parse_tos(const char *str);
unsigned if_name2index(const char *ifname);
int setsock_bindopt(int fd, const char *device, socklen_t slen, unsigned ifindex);
void print_local_ee(struct ping_rts *rts, const struct sock_extended_err *ee);
void mtudisc_n_bind(struct ping_rts *rts, const struct socket_st *sock);
void print_echo_reply(bool ip6, const uint8_t *hdr, size_t len);
void print_addr_seq(struct ping_rts *rts, uint16_t seq,
	const struct sock_extended_err *ee, socklen_t salen);

#endif
