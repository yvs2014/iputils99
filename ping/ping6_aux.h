#ifndef PING6_AUX_H
#define PING6_AUX_H

#include "common.h"
#include "stdint.h"

ssize_t build_niquery(struct ping_rts *rts, uint8_t *_nih,
	unsigned packet_size __attribute__((__unused__)));
ssize_t build_echo(const struct ping_rts *rts, uint8_t *hdr);

void print6_icmp(uint8_t type, uint8_t code, uint32_t info);
void print6_ni_reply(bool ip6, const uint8_t *hdr, size_t len);

#endif
