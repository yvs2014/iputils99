#ifndef PING_AUX_H
#define PING_AUX_H

#include "common.h"
#include <linux/errqueue.h>

unsigned long strtoul_or_err(const char *str, const char *errmesg,
	unsigned long min, unsigned long max);
double strtod_or_err(const char *str, const char *errmesg,
	double min, double max);
unsigned parse_flow(const char *str);
unsigned char parse_tos(const char *str);
unsigned if_name2index(const char *ifname);
int setsock_bindopt(int fd, const char *device, socklen_t slen, unsigned mcast_face);
void set_device(bool ip6, const char *device, socklen_t len,
	unsigned pkt_face, unsigned mcast_face, int fd1, int fd2);
void cmp_srcdev(const struct ping_rts *rts);
void mtudisc_n_bind(struct ping_rts *rts, const struct socket_st *sock);
void print_local_ee(const struct ping_rts *rts, const struct sock_extended_err *ee);
void print_addr_seq(const struct ping_rts *rts, uint16_t seq,
	const struct sock_extended_err *ee, socklen_t salen);

#endif
