#ifndef PING4_AUX_H
#define PING4_AUX_H

#include "common.h"
#include <netinet/ip_icmp.h>

unsigned short in_cksum(const unsigned short *addr, int len, unsigned short csum);
void bind_to_device(struct ping_rts *rts, int fd, in_addr_t addr);

void print4_icmph(struct ping_rts *rts, uint8_t type, uint8_t code,
	uint32_t info, struct icmphdr *icp);
void print4_ip_options(struct ping_rts *rts, unsigned char *cp, int hlen);
void print4_echo_reply(const uint8_t *hdr, size_t len);

#endif
