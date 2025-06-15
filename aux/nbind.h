#ifndef NBIND_H
#define NBIND_H

// set SO_BINDTODEVICE socket option
int bindtodev(int fd, const char *name);

#endif
