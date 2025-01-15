#ifndef STATS_H
#define STATS_H

#include <stddef.h>
#include "common.h"

typedef struct stat_aux_s {
	const char *from;
	uint16_t seq;
	size_t rcvd;
	const struct timeval *tv;
	const uint8_t *icmp, *data;
	bool ack, okay, dup;
	int away;
	void (*print)(bool ip6, const uint8_t *hdr, size_t len);
	long triptime;
} stat_aux_t;

bool statistics(state_t *rts, stat_aux_t *stat);

void headline(const state_t *rts, size_t nodatalen);
bool resume(const state_t *rts);

void print_status(const state_t *rts);
void print_timestamp(void);
#define PRINT_TIMESTAMP do { if (rts->opt.ptimeofday) print_timestamp(); } while(0)


#endif
