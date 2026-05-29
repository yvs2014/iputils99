#ifndef PING4_AUX_H
#define PING4_AUX_H

#include <stdbool.h>
#include <netinet/ip_icmp.h>

uint16_t in_cksum(const uint16_t *addr, int len, uint16_t csum);

bool print_icmp4msg(uint8_t type, uint8_t code, uint32_t info, uint32_t gateway,
	bool resolve, uint8_t color);
void print_ip4hdr(const struct iphdr *ip, bool resolve, bool flood);

#endif
