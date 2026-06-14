#ifndef ARPING_PROCESSING_H
#define ARPING_PROCESSING_H

#include <stdint.h>
#include <stdbool.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <netpacket/packet.h>

#define SLL_LEN (sizeof(struct sockaddr_ll))

typedef struct counter {
	int count;
	int timeout;
	//
	int sent;
	int recv;
	int brd_sent;
	int brd_recv;
	int req_recv;
} counter_t;

typedef struct arpopt {
	bool dad;
	bool quiet;
	bool advert;
	bool quit; // on reply
	bool unicast;
	bool broadcast;
	bool unsolicited;
} arpopt_t;

typedef enum {QUIT = 0, CONTINUE} continue_t;

bool arp_attr_okay(const struct arphdr *ar, ssize_t len, uint16_t type, uint8_t halen); // NONNUL(1)

continue_t checkin_print(const struct arphdr *got,
	struct in_addr sent_src, struct in_addr sent_dst,
	const struct sockaddr_ll *my, uint8_t slladdr_to[8],
	arpopt_t *opt, counter_t *stat, bool broadcasted, const struct timespec *last);

bool send_pack(const struct sockaddr_ll *from, const struct sockaddr_ll *to,
	struct in_addr src, struct in_addr dst, int sock, bool advert);

#endif
