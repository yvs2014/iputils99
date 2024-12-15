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
#include <net/if.h>
#include <arpa/inet.h>

#if BYTE_ORDER == LITTLE_ENDIAN
# define ODDBYTE(v)	(v)
#elif BYTE_ORDER == BIG_ENDIAN
# define ODDBYTE(v)	((unsigned short)(v) << 8)
#else
# define ODDBYTE(v)	htons((unsigned short)(v) << 8)
#endif

unsigned short in_cksum(const unsigned short *addr, int len, unsigned short csum) {
	/*
	 *  Our algorithm is simple, using a 32 bit accumulator (sum),
	 *  we add sequential 16 bit words to it, and at the end, fold
	 *  back all the carry bits from the top 16 bits into the lower
	 *  16 bits.
	 */
	const unsigned short *w = addr;
	int nleft = len;
	int sum   = csum;
	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}
	/* mop up an odd byte, if necessary */
	if (nleft == 1)
		sum += ODDBYTE(*(unsigned char *)w); /* le16toh() may be unavailable on old systems */
	/* add back carry outs from top 16 bits to low 16 bits */
	sum  = (sum >> 16) + (sum & USHRT_MAX);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	unsigned short answer = ~sum;		/* truncate to 16 bits */
	return answer;
}

void print4_ip_options(const struct ping_rts *rts, const unsigned char *cp, int hlen) {
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
			printf(_("\n%cSRR: "), (*cp == IPOPT_SSRR) ? 'S' : 'L');
			int j = *++cp;
			cp++;
			if (j > IPOPT_MINOFF) {
				for (;;) {
					uint32_t address;
					memcpy(&address, cp, 4);
					cp += 4;
					if (address == 0)
						printf("\t0.0.0.0");
					else {
						struct sockaddr_in sin = {
							.sin_family = AF_INET,
							.sin_addr = {
								address
							}
						};
						printf("\t%s", SPRINT_RES_ADDR(rts, &sin, sizeof(sin)));
					}
					j -= 4;
					putchar('\n');
					if (j <= IPOPT_MINOFF)
						break;
				}
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
				printf(_("\t(same route)"));
				break;
			}
			old_rrlen = i;
			memcpy(old_rr, (char *)cp, i);
			printf(_("\nRR: "));
			cp++;
			for (;;) {
				uint32_t address;
				memcpy(&address, cp, 4);
				cp += 4;
				if (address == 0)
					printf("\t0.0.0.0");
				else {
					struct sockaddr_in sin = {
						.sin_family = AF_INET,
						.sin_addr = {
							address
						}
					};
					printf("\t%s", SPRINT_RES_ADDR(rts, &sin, sizeof(sin)));
				}
				i -= 4;
				putchar('\n');
				if (i <= 0)
					break;
			}
		}
			break;
		case IPOPT_TS: {
			int stdtime = 0, nonstdtime = 0;
			uint8_t flags;
			int j = *++cp;		/* get length */
			int i = *++cp;		/* and pointer */
			if (i > j)
				i = j;
			i -= 5;
			if (i <= 0)
				break;
			flags = *++cp;
			printf(_("\nTS: "));
			cp++;
			for (;;) {
				long l;

				if ((flags & 0xF) != IPOPT_TS_TSONLY) {
					uint32_t address;
					memcpy(&address, cp, 4);
					cp += 4;
					if (address == 0)
						printf("\t0.0.0.0");
					else {
						struct sockaddr_in sin = {
							.sin_family = AF_INET,
							.sin_addr = {
								address
							}
						};
						printf("\t%s", SPRINT_RES_ADDR(rts, &sin, sizeof(sin)));
					}
					i -= 4;
					if (i <= 0)
						break;
				}
				l = *cp++;
				l = (l << 8) + *cp++;
				l = (l << 8) + *cp++;
				l = (l << 8) + *cp++;

				if (l & 0x80000000) {
					if (nonstdtime == 0)
						printf(_("\t%ld absolute not-standard"), l & 0x7fffffff);
					else
						printf(_("\t%ld not-standard"), (l & 0x7fffffff) - nonstdtime);
					nonstdtime = l & 0x7fffffff;
				} else {
					if (stdtime == 0)
						printf(_("\t%ld absolute"), l);
					else
						printf("\t%ld", l - stdtime);
					stdtime = l;
				}
				i -= 4;
				putchar('\n');
				if (i <= 0)
					break;
			}
			if (flags >> 4)
				printf(_("Unrecorded hops: %d\n"), flags >> 4);
			break;
		}
		default:
			printf(_("\nunknown option %x"), *cp);
			break;
		}
		totlen -= olen;
		optptr += olen;
	}
}


/* Print an IP header with options */
static void print4_iph(const struct ping_rts *rts, const struct iphdr *ip) {
	printf(_("Vr HL TOS  Len   ID Flg  off TTL Pro  cks      Src      Dst Data\n"));
	printf(_(" %1x  %1x  %02x %04x %04x"),
	       ip->version, ip->ihl, ip->tos, ip->tot_len, ip->id);
	printf(_("   %1x %04x"), ((ip->frag_off) & 0xe000) >> 13,
	       (ip->frag_off) & 0x1fff);
	printf(_("  %02x  %02x %04x"), ip->ttl, ip->protocol, ip->check);
	printf(" %s ", inet_ntoa(*(struct in_addr *)&ip->saddr));
	printf(" %s ", inet_ntoa(*(struct in_addr *)&ip->daddr));
	printf("\n");
	int hlen = ip->ihl << 2;
	const unsigned char *cp = (unsigned char *)ip + 20;	/* point to options */
	print4_ip_options(rts, cp, hlen);
}


/* Print a descriptive string about an ICMP header */
void print4_icmph(const struct ping_rts *rts, uint8_t type, uint8_t code,
	uint32_t info, const struct icmphdr *icp)
{
	switch (type) {
	case ICMP_ECHOREPLY:
		printf(_("Echo Reply\n"));
		/* XXX ID + Seq + Data */
		break;
	case ICMP_DEST_UNREACH:
		switch (code) {
		case ICMP_NET_UNREACH:
			printf(_("Destination Net Unreachable\n"));
			break;
		case ICMP_HOST_UNREACH:
			printf(_("Destination Host Unreachable\n"));
			break;
		case ICMP_PROT_UNREACH:
			printf(_("Destination Protocol Unreachable\n"));
			break;
		case ICMP_PORT_UNREACH:
			printf(_("Destination Port Unreachable\n"));
			break;
		case ICMP_FRAG_NEEDED:
			printf(_("Frag needed and DF set (mtu = %u)\n"), info);
			break;
		case ICMP_SR_FAILED:
			printf(_("Source Route Failed\n"));
			break;
		case ICMP_NET_UNKNOWN:
			printf(_("Destination Net Unknown\n"));
			break;
		case ICMP_HOST_UNKNOWN:
			printf(_("Destination Host Unknown\n"));
			break;
		case ICMP_HOST_ISOLATED:
			printf(_("Source Host Isolated\n"));
			break;
		case ICMP_NET_ANO:
			printf(_("Destination Net Prohibited\n"));
			break;
		case ICMP_HOST_ANO:
			printf(_("Destination Host Prohibited\n"));
			break;
		case ICMP_NET_UNR_TOS:
			printf(_("Destination Net Unreachable for Type of Service\n"));
			break;
		case ICMP_HOST_UNR_TOS:
			printf(_("Destination Host Unreachable for Type of Service\n"));
			break;
		case ICMP_PKT_FILTERED:
			printf(_("Packet filtered\n"));
			break;
		case ICMP_PREC_VIOLATION:
			printf(_("Precedence Violation\n"));
			break;
		case ICMP_PREC_CUTOFF:
			printf(_("Precedence Cutoff\n"));
			break;
		default:
			printf(_("Dest Unreachable, Bad Code: %d\n"), code);
			break;
		}
		if (icp && rts->opt.verbose)
			print4_iph(rts, (struct iphdr *)(icp + 1));
		break;
	case ICMP_SOURCE_QUENCH:
		printf(_("Source Quench\n"));
		if (icp && rts->opt.verbose)
			print4_iph(rts, (struct iphdr *)(icp + 1));
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
			.sin_addr   = { .s_addr = icp ? icp->un.gateway : htonl(info) },
		  };
		  printf(_("(New nexthop: %s)\n"), SPRINT_RES_ADDR(rts, &sin, sizeof(sin)));
		}
		if (icp && rts->opt.verbose)
			print4_iph(rts, (struct iphdr *)(icp + 1));
		break;
	case ICMP_ECHO:
		printf(_("Echo Request\n"));
		/* XXX ID + Seq + Data */
		break;
	case ICMP_TIME_EXCEEDED:
		switch(code) {
		case ICMP_EXC_TTL:
			printf(_("Time to live exceeded\n"));
			break;
		case ICMP_EXC_FRAGTIME:
			printf(_("Frag reassembly time exceeded\n"));
			break;
		default:
			printf(_("Time exceeded, Bad Code: %d\n"), code);
			break;
		}
		if (icp && rts->opt.verbose)
			print4_iph(rts, (struct iphdr *)(icp + 1));
		break;
	case ICMP_PARAMETERPROB:
		printf(_("Parameter problem: pointer = %u\n"),
			icp ? (ntohl(icp->un.gateway) >> 24) : info);
		if (icp && rts->opt.verbose)
			print4_iph(rts, (struct iphdr *)(icp + 1));
		break;
	case ICMP_TIMESTAMP:
		printf(_("Timestamp\n"));
		/* XXX ID + Seq + 3 timestamps */
		break;
	case ICMP_TIMESTAMPREPLY:
		printf(_("Timestamp Reply\n"));
		/* XXX ID + Seq + 3 timestamps */
		break;
	case ICMP_INFO_REQUEST:
		printf(_("Information Request\n"));
		/* XXX ID + Seq */
		break;
	case ICMP_INFO_REPLY:
		printf(_("Information Reply\n"));
		/* XXX ID + Seq */
		break;
#ifdef ICMP_MASKREQ
	case ICMP_MASKREQ:
		printf(_("Address Mask Request\n"));
		break;
#endif
#ifdef ICMP_MASKREPLY
	case ICMP_MASKREPLY:
		printf(_("Address Mask Reply\n"));
		break;
#endif
	default:
		printf(_("Bad ICMP type: %d\n"), type);
	}
}

void print4_echo_reply(const uint8_t *hdr, size_t len) {
	if (len >= sizeof(struct icmphdr))
		printf(_(" icmp_seq=%u"),
			ntohs(((const struct icmphdr *)hdr)->un.echo.sequence));
}

