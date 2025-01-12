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

#include <stdio.h>
#ifdef ENABLE_RFC4620
#include <ctype.h>
#include <errno.h>
#endif
#include <arpa/inet.h>
#include <netinet/icmp6.h>
#include <resolv.h>

#include "iputils_common.h"
#include "common.h"
#include "ping6_aux.h"
#ifdef ENABLE_RFC4620
#include "node_info.h"
#include "ni_defs.h"
#endif

/* RFC 4443 addition not yet available in libc headers */
#ifndef ICMP6_DST_UNREACH_POLICYFAIL
#define ICMP6_DST_UNREACH_POLICYFAIL 5
#endif

/* RFC 4443 addition not yet available in libc headers */
#ifndef ICMP6_DST_UNREACH_REJECTROUTE
#define ICMP6_DST_UNREACH_REJECTROUTE 6
#endif

/*
 * 	Compose and transmit an ICMP ECHO REQUEST packet.  The IP packet
 * will be added on by the kernel.  The ID field is our UNIX process ID,
 * and the sequence number is an ascending integer.  The first several bytes
 * of the data portion are used to hold a UNIX "timeval" struct in VAX
 * byte-order, to compute the round-trip time.
 */
ssize_t build_echo_hdr(const state_t *rts, uint8_t *hdr) {
	struct icmp6_hdr *icmp = (struct icmp6_hdr *)hdr;
	icmp->icmp6_type  = ICMP6_ECHO_REQUEST;
	icmp->icmp6_code  = 0;
	icmp->icmp6_cksum = 0;
	icmp->icmp6_seq   = htons(rts->ntransmitted + 1);
	icmp->icmp6_id    = rts->ident16;
	if (rts->timing)
		gettimeofday((struct timeval *)(icmp + 1), NULL);
	// note: timestamp is accounted in data area
	return sizeof(struct icmp6_hdr);
}

void print6_icmp(uint8_t type, uint8_t code, uint32_t info) {
	switch (type) {
	case ICMP6_DST_UNREACH:
		printf("%s: ", _("Destination unreachable"));
		switch (code) {
		case ICMP6_DST_UNREACH_NOROUTE:
			fputs(_("No route"), stdout);
			break;
		case ICMP6_DST_UNREACH_ADMIN:
			fputs(_("Administratively prohibited"), stdout);
			break;
		case ICMP6_DST_UNREACH_BEYONDSCOPE:
			fputs(_("Beyond scope of source address"), stdout);
			break;
		case ICMP6_DST_UNREACH_ADDR:
			fputs(_("Address unreachable"), stdout);
			break;
		case ICMP6_DST_UNREACH_NOPORT:
			fputs(_("Port unreachable"), stdout);
			break;
		case ICMP6_DST_UNREACH_POLICYFAIL:
			fputs(_("Source address failed ingress/egress policy"), stdout);
			break;
		case ICMP6_DST_UNREACH_REJECTROUTE:
			fputs(_("Reject route to destination"), stdout);
			break;
		default:
			printf("%s %d", _("unknown code"), code);
			break;
		}
		break;
	case ICMP6_PACKET_TOO_BIG:
		printf("%s: mtu=%u", _("Packet too big"), info);
		if (code)
			printf(", %s=%u", _("code"), code);
		break;
	case ICMP6_TIME_EXCEEDED:
		printf("%s: ", _("Time exceeded"));
		switch (code) {
		case ICMP6_TIME_EXCEED_TRANSIT:
			fputs(_("Hop limit"), stdout);
			break;
		case ICMP6_TIME_EXCEED_REASSEMBLY:
			fputs(_("Defragmentation failure"), stdout);
			break;
		default:
			printf("%s=%u", _("code"), code);
			break;
		}
		break;
	case ICMP6_PARAM_PROB:
		printf("%s: ", _("Parameter problem"));
		switch (code) {
		case ICMP6_PARAMPROB_HEADER:
			fputs(_("Wrong header field"), stdout);
			break;
		case ICMP6_PARAMPROB_NEXTHEADER:
			fputs(_("Unknown header"), stdout);
			break;
		case ICMP6_PARAMPROB_OPTION:
			fputs(_("Unknown option"), stdout);
			break;
		default:
			printf("%s=%u", _("code"), code);
			break;
		}
		printf("%s=%u", _("info"), info);
		break;
	case ICMP6_ECHO_REQUEST:
		fputs(_("Echo request"), stdout);
		break;
	case ICMP6_ECHO_REPLY:
		fputs(_("Echo reply"), stdout);
		break;
	case MLD_LISTENER_QUERY:
		fputs(_("MLD Query"), stdout);
		break;
	case MLD_LISTENER_REPORT:
		fputs(_("MLD Report"), stdout);
		break;
	case MLD_LISTENER_REDUCTION:
		fputs(_("MLD Reduction"), stdout);
		break;
	default:
		printf("%s: %u", _("Unknown icmp type"), type);
	}
	// note: no \n, no stdout flush
}

#ifdef ENABLE_RFC4620
ssize_t build_ni_hdr(struct ping_ni *ni, long ntransmitted, uint8_t *hdr) {
	struct ni_hdr *nih = (struct ni_hdr *)hdr;
	nih->ni_cksum = 0;
	nih->ni_type  = IPUTILS_NI_ICMP6_QUERY;
	niquery_fill_nonce(ni, ntransmitted + 1, nih->ni_nonce);
	nih->ni_code  = ni->subject_type;
	nih->ni_qtype = htons(ni->query);
	nih->ni_flags = ni->flag;
	memcpy(nih + 1, ni->subject, ni->subject_len);
	return (sizeof(*nih) + ni->subject_len);
}

static inline void putchar_safe(char c) {
	isprint(c) ? putchar(c) : printf("\\%03o", c);
}

static void print_ni_name(const struct ni_hdr *hdr, size_t len) {
	if (len < (sizeof(struct ni_hdr) + 4)) {
		printf("%s (%s)", _("parse error"), _("too short"));
		return;
	}
	//
	const uint8_t *h = (const uint8_t *)(hdr + 1);
	const uint8_t *p = h + 4;
	const uint8_t *end = (const uint8_t *)hdr + len;
	bool continued = false;
	char buf[1024];
	while (p < end) {
		memset(buf, -1, sizeof(buf));
		if (continued)
			putchar(',');
		//
		int rc = dn_expand(h, end, p, buf, sizeof(buf));
		if (rc < 0) {
			printf("%s (%s)", _("parse error"), _("truncated"));
			break;
		}
		putchar(' ');
		for (size_t i = 0; i < strnlen(buf, sizeof(buf)); i++)
			putchar_safe(buf[i]);
		p += rc;
		if ((p < end) && !*p)
			putchar('.');
		else
			p++;
		//
		continued = true;
	}
}

static void print_ni_addr(const struct ni_hdr *nih, size_t len) {
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
	//
	size_t afaddr_len = sizeof(uint32_t) + addrlen;
	if (len < afaddr_len) {
		printf("%s (%s)", _("parse error"), _("too short"));
		return;
	}
	//
	char buf[1024];
	char comma = 0;
	const uint8_t *end = (const uint8_t *)nih + len;
	for (const uint8_t *p = (const uint8_t *)(nih + 1);
			p < end; p += afaddr_len)
	{
		if ((p + afaddr_len) > end) {
			printf("%s (%s)", _("parse error"), _("truncated"));
			break;
		}
		if (comma)
			putchar(comma);
		if (!inet_ntop(af, p + sizeof(uint32_t), buf, sizeof(buf)))
			printf("[%s (inet_ntop: %s)]", _("unexpected error"), strerror(errno));
		else {
			putchar(' ');
			fputs(buf, stdout);
		}
		if (!comma)
			comma = ',';
	}
	if (truncated)
		printf("(%s)", _("truncated"));
}

void print6_ni_reply(bool ip6, const uint8_t *hdr, size_t len) {
	if (!ip6)
		return;
	const struct ni_hdr *nih = (const struct ni_hdr *)hdr;
	switch (nih->ni_code) {
	case IPUTILS_NI_ICMP6_SUCCESS:
		switch (ntohs(nih->ni_qtype)) {
		case IPUTILS_NI_QTYPE_DNSNAME:
			print_ni_name(nih, len);
			break;
		case IPUTILS_NI_QTYPE_IPV4ADDR:
		case IPUTILS_NI_QTYPE_IPV6ADDR:
			print_ni_addr(nih, len);
			break;
		default:
			printf("%s (0x%02x)", _("unknown qtype"), ntohs(nih->ni_qtype));
		}
		break;
	case IPUTILS_NI_ICMP6_REFUSED:
		fputs(_("refused"), stdout);
		break;
	case IPUTILS_NI_ICMP6_UNKNOWN:
		fputs(_("unknown"), stdout);
		break;
	default:
		printf("%s (%02x)", _("unknown code"), ntohs(nih->ni_code));
	}
	printf("; %s=%u;", _("icmp_seq"), ntohs(*(uint16_t *)nih->ni_nonce));
}
#endif /* ENABLE_RFC4620 */

