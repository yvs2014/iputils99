#ifndef PING4_AUX_H
#define PING4_AUX_H

#include "common.h"
#include <netinet/ip_icmp.h>

unsigned short in_cksum(const unsigned short *addr, int len, unsigned short csum);

void print4_icmph(const struct ping_rts *rts, uint8_t type, uint8_t code,
	uint32_t info, const struct icmphdr *icp);
void print4_ip_options(const struct ping_rts *rts, const unsigned char *cp, int hlen);

#endif
