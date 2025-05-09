#ifndef PING4_AUX_H
#define PING4_AUX_H

#include <stdbool.h>
#include <netinet/ip_icmp.h>

uint16_t in_cksum(const uint16_t *addr, int len, uint16_t csum);

bool print4_icmph(uint8_t type, uint8_t code, uint32_t info,
	const struct icmphdr *icmp, bool resolve, uint8_t color);
void print4_iph(const struct iphdr *ip, bool resolve, bool flood);
void print4_ip_opts(const uint8_t *cp, int hlen, bool resolve, bool flood);

#endif
