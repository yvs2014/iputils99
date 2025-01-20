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

// former part of common.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <math.h>
#include <sys/time.h>
#include <netinet/ip_icmp.h>
#include <locale.h>

#include "stats.h"
#include "iputils.h"

#define MAXWAIT_USEC (MAXWAIT * 1000000)

// "min/avg/max/mdev ms"
#define TIMING_MS   "%s = " MSFMT "/" MSFMT "/" MSFMT "/" TM_MS
// "ipg/ewma ms"
#define ADAPTIVE_MS "%s = " MSFMT "/" TM_MS

// Called once at resume
static inline void stat_hops(uint8_t min, uint8_t max) {
	if (min > max)
		return;
	int peer_maxttl = 		// Estimation:
		(max <=  64) ?  64 :	// - Linux like
		(max <= 128) ? 128 :	// - Windows like
		UINT8_MAX;		// - Cisco like
	int away = peer_maxttl - max;
	if (away) { // skip ttl=0(1)
		printf(", %s ", _("probably"));
		if (min == max)
			printf("%d %s", away, _n("hop away", "hops away", away));
		else
			printf("%d-%d %s", away, peer_maxttl - min, _("hops away"));
	}
}

static inline void stat_header(const state_t *rts) {
	printf("--- %s%s ---\n", rts->hostname, _(" ping statistics"));
	printf("%ld %s", rts->ntransmitted,
_n("packet transmitted", "packets transmitted", rts->ntransmitted));
	printf(", %ld %s",  rts->nreceived, _("received"));
	if (rts->nrepeats)
		printf(", +%ld %s", rts->nrepeats,  _("duplicates"));
	if (rts->nchecksum)
		printf(", +%ld %s", rts->nchecksum, _("corrupted"));
	if (rts->nerrors)
		printf(", +%ld %s", rts->nerrors,   _("errors"));
	if (rts->ntransmitted)
		printf(", %g%% %s", (rts->ntransmitted - rts->nreceived) * 100.
			/ rts->ntransmitted, _("lost"));
	if (!rts->opt.broadcast && (rts->min_away >= 0))
		stat_hops(rts->min_away, rts->max_away);
	putchar('\n');
}

static inline void stat_timing(const state_t *rts) {
	char comma = 0;
	if (rts->nreceived && rts->timing) {
		long total = rts->nreceived + rts->nrepeats;
		long tmavg = rts->tsum / total;
		long long tmvar = (rts->tsum < INT_MAX) ?
			/* This slightly clumsy computation order is important to avoid
			 * integer rounding errors for small ping times */
			(rts->tsum2 - ((rts->tsum * rts->tsum) / total)) / total :
			(rts->tsum2 / total) - tmavg * tmavg;
		printf(TIMING_MS, _("rtt min/avg/max/mdev"),
			rts->tmin / 1000., tmavg / 1000., rts->tmax / 1000.,
			sqrt((tmvar < 0) ? -tmvar : tmvar) / 1000.,
			_("ms"));
		comma = ',';
	}
	//
	if (rts->pipesize > 1) {
		if (comma)
			printf("%c ", comma);
		printf("%s %d", _("pipe"), rts->pipesize);
		comma = ',';
	}
	//
	if ((!rts->interval || rts->opt.flood || rts->opt.adaptive)
			&& rts->nreceived && (rts->ntransmitted > 1)) {
		if (comma)
			printf("%c ", comma);
		struct timespec tv = {0};
		timespecsub(&rts->cur_time, &rts->start_time, &tv);
		double ipg = (tv.tv_sec * 1000 + tv.tv_nsec / 1000000.)
			/ (rts->ntransmitted - 1);
		printf(ADAPTIVE_MS, _("ipg/ewma"), ipg, rts->rtt / 8000., _("ms"));
	}
	//
	putchar('\n');
}

bool resume(const state_t *rts) {
	putchar('\n');
	fflush(stdout);
	stat_header(rts);
	stat_timing(rts);
	return (!rts->nreceived || (rts->deadline && (rts->nreceived < rts->npackets)));
}

void print_status(const state_t *rts) {
	static bool in_print_status;
	if (in_print_status)
		return;
	in_print_status = true;
	int lost = rts->ntransmitted ?
		(100ll * (rts->ntransmitted - rts->nreceived)) / rts->ntransmitted
		: 0;
	// stderr due to signals
	fprintf(stderr, "%ld/%ld %s", rts->nreceived, rts->ntransmitted, _("packets"));
	fprintf(stderr, ", %d%% %s", lost, _("lost"));
	if (rts->nreceived && rts->timing) {
		long tavg = rts->tsum / (rts->nreceived + rts->nrepeats);
		fprintf(stderr, ", " TIMING_MS, _("min/avg/ewma/max"),
			rts->tmin / 1000., tavg / 1000.,
			rts->rtt / 8000., rts->tmax / 1000.,
			_("ms"));
	}
	putc('\n', stderr);
	in_print_status = false;
}

void print_timestamp(void) {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	printf("[%lu.%06lu] ",
	       (unsigned long)tv.tv_sec, (unsigned long)tv.tv_usec);
}

void headline(const state_t *rts, size_t nodatalen) {
	// called once at ping setup
	socklen_t len = rts->ip6 ?
		sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
	const char *target = sprint_addr(&rts->whereto, len, false);
	printf("%s %s (%s)", _("PING"), rts->hostname, target);
	if (rts->ip6 && rts->flowlabel)
		printf(", %s 0x%05x", _("flow"), ntohl(rts->flowlabel));
	if (rts->device || rts->opt.strictsource) {
		const char *from = sprint_addr(&rts->source, len, false);
		printf("%s %s %s:", _(" from"), from, rts->device ? rts->device : "");
	}
	printf(" %zu(%zu) %s\n",
		rts->datalen, rts->datalen + nodatalen, _("data bytes"));
}

static inline bool print_stats(const state_t *rts, const stat_aux_t *stat) {
	if (rts->opt.flood) {
		if (stat->ack) {
			if (write(STDOUT_FILENO, "\b \b", 3)) {};
		} else {
			if (write(STDOUT_FILENO, "\bC", 2)) {};
		}
		return true;
	}
	//
	PRINT_TIMESTAMP;
	printf("%zd %s%s %s: ",
		stat->rcvd, BYTES(stat->rcvd), _(" from"), stat->from);
	if (stat->print) /* seq */
		stat->print(rts->ip6, stat->icmp, stat->rcvd);
	else
		printf("%s=%u", _("icmp_seq"), stat->seq);
	if (rts->opt.verbose)
		printf(" %s=%u", _("ident"), ntohs(rts->ident16));
	if (stat->away >= 0)
		printf(" %s=%d", _("ttl"), stat->away);
	if (stat->rcvd < (sizeof(struct icmphdr) + rts->datalen)) {
		printf(" (%s)\n", _("truncated"));
		return true;
	}
	//
	if (rts->timing)
		printf(" %s=" TM_MS, _("time"), stat->triptime / 1000., _("ms"));
	char* exclame[3] = {
		(stat->dup && (!rts->multicast || rts->opt.verbose)) ? "DUP" : NULL,
		stat->ack  ? NULL : "BAD CHECKSUM",
		stat->okay ? NULL : "DIFFERENT ADDRESS",
	};
	for (int i = 0; i < 3; i++)
		if (exclame[i])
			printf(" (%s!)", exclame[i]);
	// received data test out
	const uint8_t *in  = stat->data + sizeof(struct timeval);
	const uint8_t *out = &rts->outpack[sizeof(struct icmphdr) + sizeof(struct timeval)];
	for (size_t i = sizeof(struct timeval); i < rts->datalen; i++, in++, out++) {
		if (*in == *out)
			continue;
		putchar('\n');
		printf("\n%s %zu (%s%02x, %s%02x) ",
			_("wrong byte #"), i,
			_("expected 0x"), *out,
			_("got 0x"),      *in);
		in = stat->data;
		for (i = sizeof(struct timeval); i < rts->datalen; i++, in++) {
			if ((i % 32) == sizeof(struct timeval))
				printf("\n#%zu\t", i);
			printf("%x ", *in);
		}
	}
	//
	return false;
}

static inline void calculator(state_t *rts, stat_aux_t *stat) {
	rts->nreceived++;
	if (stat->ack)
		acknowledge(rts, stat->seq);
	if (rts->timing &&
	(stat->rcvd >= (sizeof(struct icmphdr) + sizeof(struct timeval)))) {
		struct timeval peer;
		memcpy(&peer, stat->data, sizeof(peer));
		struct timeval tv;
		memcpy(&tv, stat->tv, sizeof(tv));
		do {
			timersub(&tv, &peer, &tv);
			stat->triptime = tv.tv_sec * 1000000 + tv.tv_usec;
			if (stat->triptime >= 0)
				break;
			warnx("%s: %s: %ldus", _WARN,
				_("Time of day goes back, taking countermeasures"),
				stat->triptime);
			if (rts->opt.latency) {
				stat->triptime = 0;
				break;
			}
			rts->opt.latency = true;
			gettimeofday(&tv, NULL);
		} while (true);
		if (stat->triptime > MAXWAIT_USEC)
			stat->triptime = MAXWAIT_USEC;
		if (stat->ack) {
			rts->tsum  += stat->triptime;
			rts->tsum2 += (double)stat->triptime * stat->triptime;
			if (stat->triptime < rts->tmin)
				rts->tmin = stat->triptime;
			if (stat->triptime > rts->tmax)
				rts->tmax = stat->triptime;
			if (!rts->rtt)
				rts->rtt  = stat->triptime * 8;
			else
				rts->rtt += stat->triptime - rts->rtt / 8;
			if (rts->opt.adaptive)
				rts->interval = get_interval(rts);
		}
	}

	if (!stat->ack) {
		++rts->nchecksum;
		--rts->nreceived;
	} else if (rcvd_test(stat->seq, rts->bitmap)) {
		++rts->nrepeats;
		--rts->nreceived;
		stat->dup = true;
	} else
		rcvd_set(stat->seq, rts->bitmap);
	rts->confirm = rts->confirm_flag;

	if (stat->away >= 0) { // keep minmax TTL distanses
		if (rts->min_away < 0)
			rts->min_away = rts->max_away = stat->away;
		else if (stat->away < rts->min_away)
			rts->min_away = stat->away;
		else if (stat->away > rts->max_away)
			rts->max_away = stat->away;
	}
}

bool statistics(state_t *rts, stat_aux_t *stat) {
// note: do not use here functions with static buffers like inet_ntoa() and/or sprint_addr() for ex.
	calculator(rts, stat);
	bool finished = rts->opt.quiet ? true : print_stats(rts, stat);
	if (finished)
		fflush(stdout);
	return finished;
}

