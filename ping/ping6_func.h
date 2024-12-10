#ifndef PING6_FUNC_H
#define PING6_FUNC_H

//#include "common.h"
#include "stdint.h"

int print6_icmp(uint8_t type, uint8_t code, uint32_t info);
void print6_echo_reply(uint8_t *_icmph, int cc __attribute__((__unused__)));
void pr_niquery_reply(uint8_t *_nih, int len);

#endif
