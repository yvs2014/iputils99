// Iputils Project
//
// setsockopt() stuff: ping, clockdiff

#include <err.h>
#include <errno.h> // IWYU pragma: keep
#include <sys/socket.h>
#include <net/if.h>
#ifdef USE_ALTNAMES
#include <linux/if.h>
#define MAXDEVNAME ALTIFNAMSIZ
#else
#define MAXDEVNAME IF_NAMESIZE
#endif

#include "sock_pc.h"
#include "iputils.h"

int setsock_ipopt_ts(int fd, struct ip_timestamp *opt, uint8_t flg, uint8_t len) { // NONNULL(2)
	if (len % 4)
		errx(EINVAL, "%s", _("timestamp length is not a multiple of 4"));
	opt->ipt_code = IPOPT_TIMESTAMP,
	opt->ipt_len  = len;
	opt->ipt_ptr  = 5;
	opt->ipt_flg  = flg;
	return setsockopt(fd, IPPROTO_IP, IP_OPTIONS, opt, opt->ipt_len);
}

