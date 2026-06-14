#ifndef SOCK_PA_H
#define SOCK_PA_H

#include "cc_attr.h"

int bindtodev(int fd, const char dev[]); // NONNULL(2)
NORETURN void err_nodev(const char dev[]); // NONNULL(1)
void setsock_binddev(int fd, const char dev[]); // NONNULL(2)
void setsock_dontroute(int fd);

#endif
