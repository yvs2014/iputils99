/*
 * arping.c
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 * 		YOSHIFUJI Hideaki <yoshfuji@linux-ipv6.org>
 */

// local changes by yvs@

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

#include "processing.h"
#include "iputils.h"

#ifndef AX25_P_IP
#define AX25_P_IP	0xcc	// ARPA Internet Protocol
#endif

// Only these types are recognised
#define ARP_OP_OK(ar) \
	(((ar)->ar_op == htons(ARPOP_REQUEST)) || \
	 ((ar)->ar_op == htons(ARPOP_REPLY  )))

// ARPHRD check and this darned FDDI hack here :-(
#define FDDI_HACK_OK(hrd, type) (((type) == ARPHRD_FDDI) && ((hrd) == htons(ARPHRD_ETHER)))
#define ARP_HRD_OK(hrd, type) (((hrd) == htons(type)) || FDDI_HACK_OK((hrd), (type)))

// Protocol must be IP - but exceptions everywhere.
// AX.25 and NETROM use the AX.25 PID value not the DIX code for the protocol.
#define IS_AX25NETROM(hrd) (((hrd) == htons(ARPHRD_AX25)) || ((hrd) == htons(ARPHRD_NETROM)))
#define ARP_PRO_OK(pro, req) ((pro) == htons(req))

#define ARP_PLN_OK(pln) ((pln) == 4)
#define	HLN_SLL_OK(hln, sll) ((hln) == (sll))
#define ARP_LEN_OK(hln, len) ((len) >= ((ssize_t)sizeof(struct arphdr) + 2 * (4 + (hln))))

#define GOT_IP_OK(orig) ((got_src.s_addr == sent_dst.s_addr) && \
	(!(orig) || (sent_src.s_addr == got_dst.s_addr)))

#define SLL_ADDR_OK(got, addr, len) (!memcmp((got), (addr), (len)))

#define PRINT_ARP_ADDR(data, len) print_hex((data), (len), " [:]")

static void print_hex(const uint8_t *data, uint8_t len, const char scope[4]) {
	putchar(scope[0]);
	putchar(scope[1]);
	for (;len > 0; data++) {
		printf("%02X", *data);
		len--;
		if (len) putchar(scope[2]); else break;
	}
	putchar(scope[3]);
}

static void print_packet_info(const struct arphdr *ar, const uint8_t *data,
	struct in_addr sent_from, struct in_addr got_from, struct in_addr got_to,
	const struct sockaddr_ll *my, const struct timespec *last, bool broadcasted)
{
	printf("%s %s %s", broadcasted ? _("Broadcast") : _("Unicast"), _("from"), inet_ntoa(got_from));
	PRINT_ARP_ADDR(data, ar->ar_hln);
	bool printed = (got_to.s_addr != sent_from.s_addr);
	if (printed)
		printf(" %s %s", _("for"), inet_ntoa(got_to));
	const uint8_t *got_for = data + ar->ar_hln + 4;
	if (memcmp(got_for, &my, ar->ar_hln)) {
		if (!printed)
			printf(" %s", _("for"));
		PRINT_ARP_ADDR(got_for, ar->ar_hln);
	}
	if (last->tv_sec) {
		struct timespec ts = {0}, sub = {0};
		if (!clock_gettime(CLOCK_MONOTONIC, &ts)) {
			timespecsub(&ts, last, &sub);
			double ms = sub.tv_sec * 1000 + sub.tv_nsec / 1000000.;
			printf(" " TMMS, ms, _("ms"));
		}
	} else
		printf(" %s?", _("UNSOLICITED"));
	putchar('\n');
	fflush(stdout);
}

static inline bool arp_pro_okay(const struct arphdr *ar) {
	bool ax25nr = IS_AX25NETROM(ar->ar_hrd);
	return ARP_PRO_OK(ar->ar_pro, ax25nr ? AX25_P_IP : ETH_P_IP);
}

bool arp_attr_okay(const struct arphdr *ar, // NONNULL(1)
	ssize_t len, uint16_t type, uint8_t halen)
{
	bool okay = ARP_OP_OK(ar) && ARP_HRD_OK(ar->ar_hrd, type) && arp_pro_okay(ar);
	if (okay)
		okay = ARP_PLN_OK(ar->ar_pln) && HLN_SLL_OK(ar->ar_hln, halen) && ARP_LEN_OK(ar->ar_hln, len);
	return okay;
}

static inline continue_t gather_stats(counter_t *stat, bool broadcasted, bool request, bool quit) {
	stat->recv++;
	if (stat->timeout && (stat->recv == stat->count))
		return QUIT;
	if (broadcasted)
		stat->brd_recv++;
	if (request)
		stat->req_recv++;
	return (quit || (!stat->count && (stat->recv == stat->sent))) ? QUIT : CONTINUE;
}

// return true to continue
continue_t checkin_print(const struct arphdr *got,
	struct in_addr sent_src, struct in_addr sent_dst,
	const struct sockaddr_ll *my, uint8_t slladdr_to[8],
	arpopt_t *opt, counter_t *stat, bool broadcasted, const struct timespec *last)
{
	continue_t next = CONTINUE;
	const uint8_t *data = (const uint8_t *)(got + 1);
	const uint8_t *p = data + got->ar_hln;
	struct in_addr got_src = {0}, got_dst = {0};
	memcpy(&got_src, p, sizeof(struct in_addr));
	p += sizeof(struct in_addr) + got->ar_hln;
	memcpy(&got_dst, p, sizeof(struct in_addr));
	//
	if (GOT_IP_OK(opt->dad ? sent_src.s_addr : true)) {
		int okay = SLL_ADDR_OK(opt->dad ? data : data + got->ar_hln + 4,
				my->sll_addr,
				opt->dad ? my->sll_halen : got->ar_hln);
		if (opt->dad)
			okay = !okay;
		if (okay) {
			if (!opt->quiet)
				print_packet_info(got, data, sent_src,
					got_src, got_dst, my, last, broadcasted);
			next = gather_stats(stat, broadcasted,
				got->ar_op == htons(ARPOP_REQUEST), opt->quit);
			if ((next != QUIT) && !opt->broadcast) {
				memcpy(slladdr_to, data, my->sll_halen);
				opt->unicast = true;
			}
		}
	}
	return next;
}

static inline size_t sll_len(size_t halen) {
	size_t len = offsetof(struct sockaddr_ll, sll_addr) + halen;
	return (len < SLL_LEN) ? SLL_LEN : len;
}

//

#define ARPHDR ((struct arphdr *)buf)

#define ARPDATAINC(ptr, size) do {   \
	memcpy(data, (ptr), (size)); \
	data += (size);              \
} while (0)

bool send_pack(const struct sockaddr_ll *from, const struct sockaddr_ll *to,
	struct in_addr src, struct in_addr dst, int sock, bool advert)
{
	uint8_t buf[256] = {0};
	ARPHDR->ar_hrd = htons(from->sll_hatype);
	if (ARPHDR->ar_hrd == htons(ARPHRD_FDDI))
		ARPHDR->ar_hrd = htons(ARPHRD_ETHER);
	/*
	 * Exceptions everywhere. AX.25 uses the AX.25 PID value not the
	 * DIX code for the protocol. Make these device structure fields.
	 */
	ARPHDR->ar_pro = IS_AX25NETROM(ARPHDR->ar_hrd) ? htons(AX25_P_IP) : htons(ETH_P_IP);
	ARPHDR->ar_hln = from->sll_halen;
	ARPHDR->ar_pln = 4;
	ARPHDR->ar_op  = advert ? htons(ARPOP_REPLY) : htons(ARPOP_REQUEST);
	//
	uint8_t *data = (uint8_t *)(ARPHDR + 1);
	memcpy(data, &from->sll_addr, ARPHDR->ar_hln);
	data += from->sll_halen;
	ARPDATAINC(&src, sizeof(src));
	ARPDATAINC(advert ? &from->sll_addr : &to->sll_addr, ARPHDR->ar_hln);
	ARPDATAINC(&dst, sizeof(dst));
	ssize_t size = data - buf;
	ssize_t sent = sendto(sock, buf, size, 0, SA(to), sll_len(ARPHDR->ar_hln));
	return ((sent > 0) && (sent == size));
}

