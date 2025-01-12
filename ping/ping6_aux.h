#ifndef PING6_AUX_H
#define PING6_AUX_H

#include <stdint.h>
#include "common.h"

ssize_t build_echo_hdr(const state_t *rts, uint8_t *hdr);
void print6_icmp(uint8_t type, uint8_t code, uint32_t info);

#ifdef ENABLE_RFC4620
ssize_t build_ni_hdr(struct ping_ni *ni, long ntransmitted, uint8_t *hdr);
void print6_ni_reply(bool ip6, const uint8_t *hdr, size_t len);
#endif

#endif
