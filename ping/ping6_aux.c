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
// ping6.c aux functions

#include "iputils_common.h"
#include "iputils_ni.h"
#include "node_info.h"
#include "ping6_aux.h"

#include <net/if.h>

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

