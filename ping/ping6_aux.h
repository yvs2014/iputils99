#ifndef PING6_AUX_H
#define PING6_AUX_H

#include "common.h"

unsigned int if_name2index(const char *ifname);

int build_niquery(struct ping_rts *rts, uint8_t *_nih,
	unsigned packet_size __attribute__((__unused__)));
int build_echo(struct ping_rts *rts, uint8_t *_icmph,
	unsigned packet_size __attribute__((__unused__)));

#endif
