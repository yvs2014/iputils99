#ifndef PING_AUX_H
#define PING_AUX_H

#include <netdb.h>
#include <linux/errqueue.h>
#include <linux/filter.h>

#include "common.h"

unsigned parse_flow(const char *str);
unsigned char parse_tos(const char *str);
void setsock_bpf(const state_t *rts,
	const sock_t *sock, const struct sock_fprog *prog);
void mtudisc_n_bind(state_t *rts, const sock_t *sock);
void setsock_recverr(int fd, bool ip6);
void setsock_noloop(int fd, bool ip6);
void setsock_ttl(int fd, bool ip6, int ttl);
void pmtu_interval(state_t *rts);
void set_estimate_buf(state_t *rts, int fd,
	size_t iplen, size_t extra, size_t icmplen);
void print_addr_seq(const state_t *rts, uint16_t seq,
	const struct sock_extended_err *ee, socklen_t salen);
void print_local_ee(const state_t *rts, const struct sock_extended_err *ee);

#define RETURN_IF_TOO_SHORT(received, minimum) do {		\
	if ((received) < (minimum)) {				\
		if (rts->opt.verbose)				\
			warnx("%s: %zd %s (%s: %zd)",		\
_("Packet too short"), (size_t)(received), BYTES(received),	\
_("minimal"), (size_t)(minimum));				\
		return true;					\
	}							\
} while (0)

#endif
