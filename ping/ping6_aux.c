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
// ping6.c auxiliary functions

#include "iputils_common.h"
#include "iputils_ni.h"
#include "common.h"
#include "ping6_aux.h"
#include "node_info.h"

#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/icmp6.h>
#include <resolv.h>
#include <net/if.h>

/* RFC 4443 addition not yet available in libc headers */
#ifndef ICMP6_DST_UNREACH_POLICYFAIL
#define ICMP6_DST_UNREACH_POLICYFAIL 5
#endif

/* RFC 4443 addition not yet available in libc headers */
#ifndef ICMP6_DST_UNREACH_REJECTROUTE
#define ICMP6_DST_UNREACH_REJECTROUTE 6
#endif

unsigned int if_name2index(const char *ifname) {
	unsigned int i = if_nametoindex(ifname);
	if (!i)
		error(2, 0, _("unknown iface: %s"), ifname);
	return i;
}

int build_niquery(struct ping_rts *rts, uint8_t *_nih,
		unsigned packet_size __attribute__((__unused__)))
{
	struct ni_hdr *nih = (struct ni_hdr *)_nih;
	nih->ni_cksum = 0;
	nih->ni_type  = IPUTILS_NI_ICMP6_QUERY;
	rts->datalen = 0;
	niquery_fill_nonce(&rts->ni, rts->ntransmitted + 1, nih->ni_nonce);
	nih->ni_code  = rts->ni.subject_type;
	nih->ni_qtype = htons(rts->ni.query);
	nih->ni_flags = rts->ni.flag;
	memcpy(nih + 1, rts->ni.subject, rts->ni.subject_len);
	return (sizeof(*nih) + rts->ni.subject_len);
}

/*
 * 	Compose and transmit an ICMP ECHO REQUEST packet.  The IP packet
 * will be added on by the kernel.  The ID field is our UNIX process ID,
 * and the sequence number is an ascending integer.  The first several bytes
 * of the data portion are used to hold a UNIX "timeval" struct in VAX
 * byte-order, to compute the round-trip time.
 */
int build_echo(struct ping_rts *rts, uint8_t *_icmph,
		unsigned packet_size __attribute__((__unused__)))
{
	struct icmp6_hdr *icmph;
	icmph = (struct icmp6_hdr *)_icmph;
	icmph->icmp6_type  = ICMP6_ECHO_REQUEST;
	icmph->icmp6_code  = 0;
	icmph->icmp6_cksum = 0;
	icmph->icmp6_seq   = htons(rts->ntransmitted + 1);
	icmph->icmp6_id    = rts->ident;
	if (rts->timing)
		gettimeofday((struct timeval *)&_icmph[8], NULL);
	return (rts->datalen + 8);	/* skips ICMP portion */
}

int print6_icmp(uint8_t type, uint8_t code, uint32_t info) {
	switch (type) {
	case ICMP6_DST_UNREACH:
		printf(_("Destination unreachable: "));
		switch (code) {
		case ICMP6_DST_UNREACH_NOROUTE:
			printf(_("No route"));
			break;
		case ICMP6_DST_UNREACH_ADMIN:
			printf(_("Administratively prohibited"));
			break;
		case ICMP6_DST_UNREACH_BEYONDSCOPE:
			printf(_("Beyond scope of source address"));
			break;
		case ICMP6_DST_UNREACH_ADDR:
			printf(_("Address unreachable"));
			break;
		case ICMP6_DST_UNREACH_NOPORT:
			printf(_("Port unreachable"));
			break;
		case ICMP6_DST_UNREACH_POLICYFAIL:
			printf(_("Source address failed ingress/egress policy"));
			break;
		case ICMP6_DST_UNREACH_REJECTROUTE:
			printf(_("Reject route to destination"));
			break;
		default:
			printf(_("Unknown code %d"), code);
			break;
		}
		break;
	case ICMP6_PACKET_TOO_BIG:
		printf(_("Packet too big: mtu=%u"), info);
		if (code)
			printf(_(", code=%d"), code);
		break;
	case ICMP6_TIME_EXCEEDED:
		printf(_("Time exceeded: "));
		if (code == ICMP6_TIME_EXCEED_TRANSIT)
			printf(_("Hop limit"));
		else if (code == ICMP6_TIME_EXCEED_REASSEMBLY)
			printf(_("Defragmentation failure"));
		else
			printf(_("code %d"), code);
		break;
	case ICMP6_PARAM_PROB:
		printf(_("Parameter problem: "));
		if (code == ICMP6_PARAMPROB_HEADER)
			printf(_("Wrong header field "));
		else if (code == ICMP6_PARAMPROB_NEXTHEADER)
			printf(_("Unknown header "));
		else if (code == ICMP6_PARAMPROB_OPTION)
			printf(_("Unknown option "));
		else
			printf(_("code %d "), code);
		printf(_("at %u"), info);
		break;
	case ICMP6_ECHO_REQUEST:
		printf(_("Echo request"));
		break;
	case ICMP6_ECHO_REPLY:
		printf(_("Echo reply"));
		break;
	case MLD_LISTENER_QUERY:
		printf(_("MLD Query"));
		break;
	case MLD_LISTENER_REPORT:
		printf(_("MLD Report"));
		break;
	case MLD_LISTENER_REDUCTION:
		printf(_("MLD Reduction"));
		break;
	default:
		printf(_("unknown icmp type: %u"), type);
	}
	return 0;
}

void print6_echo_reply(const uint8_t *hdr, size_t len) {
	if (len >= sizeof(struct icmp6_hdr))
		printf(_(" icmp_seq=%u"),
			ntohs(((struct icmp6_hdr *)hdr)->icmp6_seq));
}

static void putchar_safe(char c) {
	if (isprint(c))
		putchar(c);
	else
		printf("\\%03o", c);
}


static void pr_niquery_reply_name(const struct ni_hdr *hdr, size_t len) {
	const uint8_t *h = (uint8_t *)(hdr + 1);
	const uint8_t *p = h + 4;
	const uint8_t *end = (uint8_t *)hdr + len;
	int continued = 0;
	char buf[1024];
	int ret;

	size_t shift = sizeof(struct ni_hdr) + 4;
	if (len < shift) {
		printf(_(" parse error (too short)"));
		return;
	}
	len -= shift;
	while (p < end) {
		int fqdn = 1;
		memset(buf, 0xff, sizeof(buf));
		if (continued)
			putchar(',');

		ret = dn_expand(h, end, p, buf, sizeof(buf));
		if (ret < 0) {
			printf(_(" parse error (truncated)"));
			break;
		}
		if (p + ret < end && *(p + ret) == '\0')
			fqdn = 0;
		putchar(' ');

		for (size_t i = 0; i < strlen(buf); i++)
			putchar_safe(buf[i]);
		if (fqdn)
			putchar('.');

		p += ret + !fqdn;
		continued = 1;
	}
}


static void pr_niquery_reply_addr(const struct ni_hdr *nih, size_t len) {
	int af, truncated;
	size_t addrlen;
	switch (ntohs(nih->ni_qtype)) {
	case IPUTILS_NI_QTYPE_IPV4ADDR:
		af = AF_INET;
		addrlen = sizeof(struct in_addr);
		truncated = nih->ni_flags & IPUTILS_NI_IPV6_FLAG_TRUNCATE;
		break;
	case IPUTILS_NI_QTYPE_IPV6ADDR:
		af = AF_INET6;
		addrlen = sizeof(struct in6_addr);
		truncated = nih->ni_flags & IPUTILS_NI_IPV4_FLAG_TRUNCATE;
		break;
	default:
		/* should not happen */
		af = addrlen = truncated = 0;
	}

	size_t afaddr_len = sizeof(uint32_t) + addrlen;
	if (len < afaddr_len) {
		printf(_(" parse error (too short)"));
		return;
	}

	char buf[1024];
	int comma = 0;
	const uint8_t *p = (uint8_t *)(nih + 1);
	const uint8_t *end = (uint8_t *)nih + len;
	while (p < end) {
		if ((p + afaddr_len) > end) {
			printf(_(" parse error (truncated)"));
			break;
		}
		if (comma)
			putchar(',');
		if (!inet_ntop(af, p + sizeof(uint32_t), buf, sizeof(buf)))
			printf(_(" unexpected error in inet_ntop(%s)"),
			       strerror(errno));
		else
			printf(" %s", buf);
		p += afaddr_len;
		if (!comma)
			comma = 1;
	}
	if (truncated)
		printf(_(" (truncated)"));
}

void print6_ni_reply(const uint8_t *hdr, size_t len) {
	const struct ni_hdr *nih = (struct ni_hdr *)hdr;
	switch (nih->ni_code) {
	case IPUTILS_NI_ICMP6_SUCCESS:
		switch (ntohs(nih->ni_qtype)) {
		case IPUTILS_NI_QTYPE_DNSNAME:
			pr_niquery_reply_name(nih, len);
			break;
		case IPUTILS_NI_QTYPE_IPV4ADDR:
		case IPUTILS_NI_QTYPE_IPV6ADDR:
			pr_niquery_reply_addr(nih, len);
			break;
		default:
			printf(_(" unknown qtype(0x%02x)"), ntohs(nih->ni_qtype));
		}
		break;
	case IPUTILS_NI_ICMP6_REFUSED:
		printf(_(" refused"));
		break;
	case IPUTILS_NI_ICMP6_UNKNOWN:
		printf(_(" unknown"));
		break;
	default:
		printf(_(" unknown code(%02x)"), ntohs(nih->ni_code));
	}
	printf(_("; seq=%u;"), ntohsp((uint16_t *)nih->ni_nonce));
}

