#ifndef PING_SOCKOPT_SYS_BPF_H
#define PING_SOCKOPT_SYS_BPF_H

#include <stdint.h>
#include <stdbool.h>

#include <linux/libc-compat.h>
#include <linux/filter.h>

void setsock_bpf(int fd, uint16_t len, struct sock_filter filter[len], // NONNULL(2)
	bool verbose, char version, uint16_t id);

#endif
