#ifndef PING4_AUX_H
#define PING4_AUX_H

#include "common.h"
#include <netinet/ip_icmp.h>

uint16_t in_cksum(const uint16_t *addr, int len, uint16_t csum);

void print4_icmph(const state_t *rts, uint8_t type, uint8_t code, uint32_t info,
	const struct icmphdr *icmp);
void print4_ip_options(const state_t *rts, const uint8_t *cp, int hlen);

#endif
