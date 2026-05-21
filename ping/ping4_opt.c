/*
 * Copyright (c) 1989 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Mike Muuss.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 *			P I N G . C
 *
 * Using the InterNet Control Message Protocol (ICMP) "ECHO" facility,
 * measure round-trip-delays and packet loss across network paths.
 *
 * Author -
 *	Mike Muuss
 *	U. S. Army Ballistic Research Laboratory
 *	December, 1983
 *
 * Status -
 *	Public Domain.  Distribution Unlimited.
 * Bugs -
 *	More statistics could always be gathered.
 *	If kernel does not support ICMP datagram sockets,
 *	this program has to run SUID to ROOT or with
 *	net_cap_raw enabled.
 */

// local changes by yvs@
// ping4.c IP options's functions

#include <stdio.h>
#include <string.h>
#include <netinet/ip.h>
#include <byteswap.h>

#include "iputils.h"
#include "common.h"


static inline void puts_addr(in_addr_t addr, bool resolve) {
	putchar('\t');
	fputs(addr ? sprint_addr4(addr, resolve) : "0.0.0.0", stdout);
}

static inline void puts_addrln(in_addr_t addr, bool resolve) {
	putchar('\t');
	puts(addr ? sprint_addr4(addr, resolve) : "0.0.0.0");
}

//
// NOTE: ipopt_xxx() functions: data behind TYPE-LENGTH
static void ipopt_sr(const uint8_t *data, int len, bool resolve, char kind) {
	if (len > IPOPT_MINOFF) {
		printf("\n%cSRR: ", kind);
		for (; len > IPOPT_MINOFF; len -= 4, data += 4)
			puts_addrln(*(in_addr_t*)data, resolve);
	}
}

// first two bytes: LENGTH, POINTER
#define VALIDATE_OPT_LP(min) do {   \
	int size = *data++;         \
	if (size > len) size = len; \
	size -= (min);              \
	if (size <= 0) return;      \
	/* note: `len' is reused */ \
	len = size;                 \
} while (0)

static void ipopt_rr(const uint8_t *data, int len, bool resolve, bool flood) {
	VALIDATE_OPT_LP(IPOPT_MINOFF);
	static int rr_tab_len;
	static char rr_tab[MAX_IPOPTLEN];
	uint limsz = (uint)len > sizeof(rr_tab) ? sizeof(rr_tab) : (uint)len;
	if ((len != rr_tab_len) || memcmp(data, rr_tab, limsz) || flood) {
		rr_tab_len = len;
		memcpy(rr_tab, data, limsz);
		printf("\nRR: ");
		for (; len > 0; len -= 4, data += 4)
			puts_addrln(*(in_addr_t*)data, resolve);
	} else
		printf("\t%s", _("(same route)"));
}
//
static void print_ipopt_ts(uint32_t ts, uint32_t* xtime, const char *rel, const char *abs) {
	uint32_t x = *xtime;
	*xtime = ts;
	printf("\t%ld", x ? ((int64_t)ts - x) : ts);
	const char *comment = x ? rel : abs;
	if (comment)
		printf(" %s", comment);
	putchar('\n');
}
//
static void ipopt_ts(const uint8_t *data, int len, bool resolve) {
	VALIDATE_OPT_LP(5);
	uint8_t flags = *data++;
	bool not_tsonly = ((flags & 0xF) != IPOPT_TS_TSONLY);
	uint32_t stdtime = 0, nonstdtime = 0;
	printf("\nTS: ");
	for (; len > 0; len -= 4, data += 4) {
		if (not_tsonly) {
			puts_addr(*(in_addr_t*)data, resolve);
			len  -= 4;
			data += 4;
			if (len <= 0)
				break;
		}
		uint32_t ts = bswap_32(*(uint32_t*)data);
		if (IS_BIT31_SET(ts))
			print_ipopt_ts(ts & INT32_MAX, &nonstdtime, _("not-standard"), _("absolute not-standard"));
		else
			print_ipopt_ts(ts, &stdtime, NULL, _("absolute"));
	}
	uint8_t unrec = flags >> 4;
	if (unrec)
		printf("%s: %u\n", _("Unrecorded hops"), unrec);
}
//

void print4_ip_opts(const uint8_t *opt, int len, bool resolve, bool flood) {
	if (opt && (len <= MAX_IPOPTLEN)) for (int l;
	     (len > 0) && (*opt != IPOPT_EOL);
	     len -= l, opt += l)
	{
		uint8_t t = *opt++;
		bool nop = t == IPOPT_NOP;
		if (nop) {
			l = 1;
			fputs("\nNOP\n", stdout);
		} else {
			l = *opt++;
			int rest = l - 2;
			if ((l > len) || (rest <= 0))
				break;
			switch (t) {
			case IPOPT_SSRR:
			case IPOPT_LSRR:
				ipopt_sr(opt, rest, resolve, (t == IPOPT_SSRR) ? 'S' : 'L');
				break;
			case IPOPT_RR:
				ipopt_rr(opt, rest, resolve, flood);
				break;
			case IPOPT_TS:
				ipopt_ts(opt, rest, resolve);
				break;
			default:
				printf("\n%s %u (0x%02x)", _("Unknown option"), t, t);
				break;
			}
		}
	}
}


