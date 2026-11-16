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

#include <stdio.h>
#include <arpa/inet.h>

#include "aux4.h"
#include "opt4.h"
#include "common.h"
#include "po.h"

#if BYTE_ORDER == LITTLE_ENDIAN
#define ODDBYTE(v)	(v)
#elif BYTE_ORDER == BIG_ENDIAN
#define ODDBYTE(v)	((uint16_t)(v) << 8)
#else
#define ODDBYTE(v)	htons((uint16_t)(v) << 8)
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


/* Print an IP header with options */
void print_ip4hdr(const struct iphdr *ip, bool resolve, bool flood) {
	printf("Vr HL TOS  Len   ID Flg  off TTL Pro  cks      Src      Dst Data\n");
	printf(" %1x  %1x  %02x %04x %04x", ip->version, ip->ihl, ip->tos, ip->tot_len, ip->id);
	printf("   %1x %04x", (ip->frag_off & 0xe000) >> 13, ip->frag_off & 0x1fff);
	printf("  %02x  %02x %04x", ip->ttl, ip->protocol, ip->check);
	printf(" %s ", inet_ntoa(*(struct in_addr *)&ip->saddr));
	printf(" %s ", inet_ntoa(*(struct in_addr *)&ip->daddr));
	putchar('\n');
	int olen = (ssize_t)(ip->ihl * 4) - sizeof(struct iphdr);
	if (olen > 0)
		print4_ip_opts((uint8_t *)ip + sizeof(struct iphdr), olen, resolve, flood);
}


// Print a descriptive string about an ICMP header
bool print_icmp4msg(uint8_t type, uint8_t code, uint32_t info, uint32_t gateway,
	bool resolve, uint8_t color)
{
	bool print_ip_hdr_too = false;
	if (color)
		printf(ESC_STRING "%um", color);
	switch (type) {
	case ICMP_ECHOREPLY:
		fputs(_ECHO_REPLY, stdout);
		/* XXX ID + Seq + Data */
		break;
	case ICMP_DEST_UNREACH:
		printf("%s: ", _UNREACH_DEST);
		switch (code) { // TODO: map[code]=mesg
		case ICMP_NET_UNREACH:
			fputs(_UNREACH_NET, stdout);
			break;
		case ICMP_HOST_UNREACH:
			fputs(_UNREACH_ADDR, stdout);
			break;
		case ICMP_PROT_UNREACH:
			fputs(_UNREACH_PROTO, stdout);
			break;
		case ICMP_PORT_UNREACH:
			fputs(_UNREACH_PORT, stdout);
			break;
		case ICMP_FRAG_NEEDED:
			printf("%s (mtu = %u)", _NEED_FRAG, info);
			break;
		case ICMP_SR_FAILED:
			fputs(_SRC_ROUTE_FAIL, stdout);
			break;
		case ICMP_NET_UNKNOWN:
			fputs(_UNKN_NET, stdout);
			break;
		case ICMP_HOST_UNKNOWN:
			fputs(_UNKN_HOST, stdout);
			break;
		case ICMP_HOST_ISOLATED:
			fputs(_SRC_HOST_ISOL, stdout);
			break;
		case ICMP_NET_ANO:
			fputs(_PROH_NET, stdout);
			break;
		case ICMP_HOST_ANO:
			fputs(_PROH_HOST, stdout);
			break;
		case ICMP_NET_UNR_TOS:
			fputs(_UNREACH_TOS_NET, stdout);
			break;
		case ICMP_HOST_UNR_TOS:
			fputs(_UNREACH_TOS_HOST, stdout);
			break;
		case ICMP_PKT_FILTERED:
			fputs(_PKT_FILTERED, stdout);
			break;
		case ICMP_PREC_VIOLATION:
			fputs(_PREC_VIOLATED, stdout);
			break;
		case ICMP_PREC_CUTOFF:
			fputs(_PREC_CUTOFF, stdout);
			break;
		default:
			printf("%s %u", _UNKN_CODE, code);
			break;
		}
		print_ip_hdr_too = true;
		break;
	case ICMP_SOURCE_QUENCH:
		fputs(_SRC_QUENCH, stdout);
		print_ip_hdr_too = true;
		break;
	case ICMP_REDIRECT:
		printf("%s: ", _REDIRECT);
		switch (code) {
		case ICMP_REDIR_NET:
			fputs(_NET, stdout);
			break;
		case ICMP_REDIR_HOST:
			fputs(_HOST_H, stdout);
			break;
		case ICMP_REDIR_NETTOS:
			fputs(_TOS_NET, stdout);
			break;
		case ICMP_REDIR_HOSTTOS:
			fputs(_TOS_HOST, stdout);
			break;
		default:
			printf("%s %u", _UNKN_CODE, code);
			break;
		}
		{ struct sockaddr_in sin = {
			.sin_family = AF_INET,
			.sin_addr.s_addr = gateway ? gateway : info,
		  };
		  printf(", %s %s", _NEW_NEXTHOP, sprint_addr(&sin, sizeof(sin), resolve));
		}
		print_ip_hdr_too = true;
		break;
	case ICMP_ECHO:
		fputs(_ECHO_REQUEST, stdout);
		/* XXX ID + Seq + Data */
		break;
	case ICMP_TIME_EXCEEDED:
		printf("%s: ", _TIME_EXCEED);
		switch(code) {
		case ICMP_EXC_TTL:
			fputs(_TTL_U, stdout);
			break;
		case ICMP_EXC_FRAGTIME:
			fputs(_DEFRAG_FAIL, stdout);
			break;
		default:
			printf("%s %u", _UNKN_CODE, code);
			break;
		}
		print_ip_hdr_too = true;
		break;
	case ICMP_PARAMETERPROB:
		printf("%s: %u", _PARAM_PROBLEM, gateway ? (gateway >> 24) : info);
		print_ip_hdr_too = true;
		break;
	case ICMP_TIMESTAMP:
		fputs(_TIMESTAMP, stdout);
		/* XXX ID + Seq + 3 timestamps */
		break;
	case ICMP_TIMESTAMPREPLY:
		fputs(_TS_REPLY, stdout);
		/* XXX ID + Seq + 3 timestamps */
		break;
	case ICMP_INFO_REQUEST:
		fputs(_INFO_QUERY, stdout);
		/* XXX ID + Seq */
		break;
	case ICMP_INFO_REPLY:
		fputs(_INFO_REPLY, stdout);
		/* XXX ID + Seq */
		break;
#if defined(ICMP_MASKREQ) || defined(ICMP_ADDRESS)
#ifdef ICMP_MASKREQ
	case ICMP_MASKREQ:
#else
	case ICMP_ADDRESS:
#endif
		fputs(_ADDRMASK_QUERY, stdout);
		break;
#endif
#if defined(ICMP_MASKREPLY) || defined(ICMP_ADDRESSREPLY)
#ifdef ICMP_MASKREPLY
	case ICMP_MASKREPLY:
#else
	case ICMP_ADDRESSREPLY:
#endif
		fputs(_ADDRMASK_REPLY, stdout);
		break;
#endif
	default:
		printf("%s: %d", _UNKN_ICMP_TYPE, type);
	}
	if (color)
		fputs(ESC_STRING "0m", stdout);
	return print_ip_hdr_too;
	// note: no \n, no stdout flush
}

