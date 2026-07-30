#ifndef PING_SOCKOPT_SYS_BPF_H
#define PING_SOCKOPT_SYS_BPF_H

#include <stdint.h>
#include <stdbool.h>

#include <linux/libc-compat.h>
#include <linux/filter.h>

#define SOCK_BPF_INFO(verbose, version, fd, ident) do { \
	if (verbose)                                    \
		warnx("bpf%c socket=%d ident=0x%04x",   \
		      (version), (fd), (ident));        \
} while (0)

void setsock_bpf(int fd, struct sock_fprog prog);

#endif
