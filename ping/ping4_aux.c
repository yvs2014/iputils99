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
// ping4.c auxiliary functions

#include "iputils_common.h"
#include "ping4_aux.h"

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#if BYTE_ORDER == LITTLE_ENDIAN
# define ODDBYTE(v)	(v)
#elif BYTE_ORDER == BIG_ENDIAN
# define ODDBYTE(v)	((unsigned short)(v) << 8)
#else
# define ODDBYTE(v)	htons((unsigned short)(v) << 8)
#endif

/*
 *  Our algorithm is simple, using a 32 bit accumulator (sum),
 *  we add sequential 16 bit words to it, and at the end, fold
 *  back all the carry bits from the top 16 bits into the lower
 *  16 bits
 */
uint16_t in_cksum(const uint16_t *addr, int len, uint16_t csum) {
	const uint16_t *w = addr;
	int nleft = len;
	int sum   = csum;
	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}
	/* mop up an odd byte, if necessary */
	if (nleft == 1)
		sum += ODDBYTE(*(uint8_t *)w);	/* le16toh() may be unavailable on old systems */
	/* add back carry outs from top 16 bits to low 16 bits */
	sum  = (sum >> 16) + (sum & USHRT_MAX);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	uint16_t answer = ~sum;			/* truncate to 16 bits */
	return answer;
}

static inline void puts_addr(in_addr_t addr, bool resolve) {
	putchar('\t');
	if (addr) {
		struct sockaddr_in sin = { .sin_family = AF_INET,
			.sin_addr.s_addr = addr };
		fputs(sprint_addr(&sin, sizeof(sin), resolve), stdout);
	} else
		fputs("0.0.0.0", stdout);
}

void print4_ip_options(const state_t *rts, const uint8_t *cp, int hlen) {
	static int old_rrlen;
	static char old_rr[MAX_IPOPTLEN];

	int totlen = hlen - sizeof(struct iphdr);
	const unsigned char *optptr = cp;

	while (totlen > 0) {
		if (*optptr == IPOPT_EOL)
			break;
		if (*optptr == IPOPT_NOP) {
			totlen--;
			optptr++;
			printf(_("\nNOP"));
			continue;
		}
		cp = optptr;
		int olen = optptr[1];
		if ((olen < 2) || (olen > totlen))
			break;

		switch (*cp) {
		case IPOPT_SSRR:
		case IPOPT_LSRR: {
			printf("\n%cSRR: ", (*cp == IPOPT_SSRR) ? 'S' : 'L');
			int j = *++cp;
			cp++;
			for (; j > IPOPT_MINOFF; j -= 4, cp += 4) {
				puts_addr(*(in_addr_t *)cp, rts->opt.resolve);
				putchar('\n');
			}
		}
			break;
		case IPOPT_RR: {
			int j = *++cp;		/* get length */
			int i = *++cp;		/* and pointer */
			if (i > j)
				i = j;
			i -= IPOPT_MINOFF;
			if (i <= 0)
				break;
			if (i == old_rrlen
			    && !memcmp(cp, old_rr, i)
			    && !rts->opt.flood) {
				putchar('\t');
				fputs(_("(same route)"), stdout);
				break;
			}
			old_rrlen = i;
			memcpy(old_rr, (char *)cp, i);
			printf("\nRR: ");
			cp++;
			for (; i > 0; i -= 4, cp += 4) {
				puts_addr(*(in_addr_t *)cp, rts->opt.resolve);
				putchar('\n');
			}
		}
			break;
		case IPOPT_TS: {
			int j = *++cp;		/* get length */
			int i = *++cp;		/* and pointer */
			if (i > j)
				i = j;
			i -= 5;
			if (i <= 0)
				break;
			printf("\nTS: ");
			uint8_t flags = *++cp;
			cp++;
			int stdtime = 0, nonstdtime = 0;
			for (; i > 0; i -= 4) {
				if ((flags & 0xF) != IPOPT_TS_TSONLY) {
					puts_addr(*(in_addr_t *)cp, rts->opt.resolve);
					cp += 4;
					i  -= 4;
					if (i <= 0)
						break;
				}
				long l = *cp++;
				l = (l << 8) + *cp++;
				l = (l << 8) + *cp++;
				l = (l << 8) + *cp++;
				long ld = l;
				const char *comment = NULL;
				if (l & 0x80000000) {
					comment = _(nonstdtime ? "not-standard" : "absolute not-standard");
					ld &= 0x7fffffff;
					nonstdtime = ld;
					ld -= nonstdtime;
				} else {
					comment = stdtime ? "" : _("absolute");
					stdtime = ld;
					ld -= stdtime;
				}
				printf("\t%ld %s\n", ld, comment);
			}
			if (flags >> 4)
				printf("%s: %d\n", _("Unrecorded hops"), flags >> 4);
			break;
		}
		default:
			printf("\n%s %x", _("Unknown option"), *cp);
			break;
		}
		totlen -= olen;
		optptr += olen;
	}
}


/* Print an IP header with options */
static void print4_iph(const state_t *rts, const struct iphdr *ip) {
	printf("Vr HL TOS  Len   ID Flg  off TTL Pro  cks      Src      Dst Data\n");
	printf(" %1x  %1x  %02x %04x %04x", ip->version, ip->ihl, ip->tos, ip->tot_len, ip->id);
	printf("   %1x %04x", ((ip->frag_off) & 0xe000) >> 13, (ip->frag_off) & 0x1fff);
	printf("  %02x  %02x %04x", ip->ttl, ip->protocol, ip->check);
	printf(" %s ", inet_ntoa(*(struct in_addr *)&ip->saddr));
	printf(" %s ", inet_ntoa(*(struct in_addr *)&ip->daddr));
	printf("\n");
	int hlen = ip->ihl << 2;
	const uint8_t *cp = (uint8_t *)ip + 20;	/* point to options */
	print4_ip_options(rts, cp, hlen);
}


/* Print a descriptive string about an ICMP header */
void print4_icmph(const state_t *rts, uint8_t type, uint8_t code, uint32_t info,
		const struct icmphdr *icmp)
{
	switch (type) {
	case ICMP_ECHOREPLY:
		printf(_("Echo Reply"));
		/* XXX ID + Seq + Data */
		break;
	case ICMP_DEST_UNREACH:
		switch (code) {
		case ICMP_NET_UNREACH:
			printf(_("Destination Net Unreachable"));
			break;
		case ICMP_HOST_UNREACH:
			printf(_("Destination Host Unreachable"));
			break;
		case ICMP_PROT_UNREACH:
			printf(_("Destination Protocol Unreachable"));
			break;
		case ICMP_PORT_UNREACH:
			printf(_("Destination Port Unreachable"));
			break;
		case ICMP_FRAG_NEEDED:
			printf(_("Frag needed and DF set (mtu = %u)"), info);
			break;
		case ICMP_SR_FAILED:
			printf(_("Source Route Failed"));
			break;
		case ICMP_NET_UNKNOWN:
			printf(_("Destination Net Unknown"));
			break;
		case ICMP_HOST_UNKNOWN:
			printf(_("Destination Host Unknown"));
			break;
		case ICMP_HOST_ISOLATED:
			printf(_("Source Host Isolated"));
			break;
		case ICMP_NET_ANO:
			printf(_("Destination Net Prohibited"));
			break;
		case ICMP_HOST_ANO:
			printf(_("Destination Host Prohibited"));
			break;
		case ICMP_NET_UNR_TOS:
			printf(_("Destination Net Unreachable for Type of Service"));
			break;
		case ICMP_HOST_UNR_TOS:
			printf(_("Destination Host Unreachable for Type of Service"));
			break;
		case ICMP_PKT_FILTERED:
			printf(_("Packet filtered"));
			break;
		case ICMP_PREC_VIOLATION:
			printf(_("Precedence Violation"));
			break;
		case ICMP_PREC_CUTOFF:
			printf(_("Precedence Cutoff"));
			break;
		default:
			printf(_("Dest Unreachable, Bad Code: %d"), code);
			break;
		}
		if (icmp && rts->opt.verbose)
			print4_iph(rts, (struct iphdr *)(icmp + 1));
		break;
	case ICMP_SOURCE_QUENCH:
		printf(_("Source Quench\n"));
		if (icmp && rts->opt.verbose)
			print4_iph(rts, (struct iphdr *)(icmp + 1));
		break;
	case ICMP_REDIRECT:
		switch (code) {
		case ICMP_REDIR_NET:
			printf(_("Redirect Network"));
			break;
		case ICMP_REDIR_HOST:
			printf(_("Redirect Host"));
			break;
		case ICMP_REDIR_NETTOS:
			printf(_("Redirect Type of Service and Network"));
			break;
		case ICMP_REDIR_HOSTTOS:
			printf(_("Redirect Type of Service and Host"));
			break;
		default:
			printf(_("Redirect, Bad Code: %d"), code);
			break;
		}
		{ struct sockaddr_in sin = {
			.sin_family = AF_INET,
			.sin_addr.s_addr = icmp ? htonl(icmp->un.gateway) : htonl(info),
		  };
		  printf("(%s: %s)", _("New nexthop"),
			sprint_addr(&sin, sizeof(sin), rts->opt.resolve));
		}
		if (icmp && rts->opt.verbose)
			print4_iph(rts, (struct iphdr *)(icmp + 1));
		break;
	case ICMP_ECHO:
		printf(_("Echo Request"));
		/* XXX ID + Seq + Data */
		break;
	case ICMP_TIME_EXCEEDED:
		switch(code) {
		case ICMP_EXC_TTL:
			printf(_("Time to live exceeded"));
			break;
		case ICMP_EXC_FRAGTIME:
			printf(_("Frag reassembly time exceeded"));
			break;
		default:
			printf(_("Time exceeded, Bad Code: %d"), code);
			break;
		}
		if (icmp && rts->opt.verbose)
			print4_iph(rts, (struct iphdr *)(icmp + 1));
		break;
	case ICMP_PARAMETERPROB:
		printf(_("Parameter problem: pointer = %u"),
			icmp ? (ntohl(icmp->un.gateway) >> 24) : info);
		if (icmp && rts->opt.verbose)
			print4_iph(rts, (struct iphdr *)(icmp + 1));
		break;
	case ICMP_TIMESTAMP:
		printf(_("Timestamp"));
		/* XXX ID + Seq + 3 timestamps */
		break;
	case ICMP_TIMESTAMPREPLY:
		printf(_("Timestamp Reply"));
		/* XXX ID + Seq + 3 timestamps */
		break;
	case ICMP_INFO_REQUEST:
		printf(_("Information Request"));
		/* XXX ID + Seq */
		break;
	case ICMP_INFO_REPLY:
		printf(_("Information Reply"));
		/* XXX ID + Seq */
		break;
#ifdef ICMP_MASKREQ
	case ICMP_MASKREQ:
		printf(_("Address Mask Request"));
		break;
#endif
#ifdef ICMP_MASKREPLY
	case ICMP_MASKREPLY:
		printf(_("Address Mask Reply"));
		break;
#endif
	default:
		printf(_("Bad ICMP type: %d"), type);
	}
	putchar('\n');
}

