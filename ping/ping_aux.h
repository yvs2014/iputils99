#ifndef PING_AUX_H
#define PING_AUX_H

#include <netdb.h>
#include <linux/errqueue.h>
#include <linux/filter.h>

#include "common.h"

void mtudisc_n_bind(int fd, uint16_t port, bool strictsource,
	struct sockaddr *src, int mtudisc, bool ip6); // NONNULL(5)
void pmtu_interval(state_t *rts);
void print_local_ee(const state_t *rts, const struct sock_extended_err *ee);
int get_errmsg(state_t *rts, const sock_t *sock, struct msghdr *msg);

#define RETURN_IF_TOO_SHORT(received, minimum) do {		\
	if ((received) < (minimum)) {				\
		if (rts->opt.verbose)				\
			warnx("%s: %zd %s (%s: %zd)",		\
_("Packet too short"), (size_t)(received), BYTES(received),	\
_("minimal"), (size_t)(minimum));				\
		return true;					\
	}							\
} while (0)

#define CMSG_INT(cmsg, to) do {                  \
  if ((cmsg)->cmsg_len >= CMSG_LEN(sizeof(int))) \
    memcpy((to), CMSG_DATA(cmsg), sizeof(int));  \
} while (0)

#define MTUDISC_N_BIND mtudisc_n_bind(sock->fd,                    \
  (rts->opt.ident && !sock->raw) ? rts->ident16 : 0,               \
  rts->opt.strictsource, SA(&rts->source), rts->mtudisc, rts->ip6) \

#endif
