#ifndef CAPS_H
#define CAPS_H

#include <sys/capability.h>

void limit_cap(const cap_value_t *limit, int ncap);
void drop_priv(void);

void modify_cap(cap_value_t cap, cap_flag_value_t on);
#define CAP_ON(cap)  modify_cap(cap, CAP_SET)
#define CAP_OFF(cap) modify_cap(cap, CAP_CLEAR)

#define NET_RAW_ON   CAP_ON (CAP_NET_RAW)
#define NET_RAW_OFF  CAP_OFF(CAP_NET_RAW)
#define SYS_NICE_ON  CAP_ON (CAP_SYS_NICE)
#define SYS_NICE_OFF CAP_OFF(CAP_SYS_NICE)
// not used in code:
//#define NET_ADMIN_ON  CAP_ON (CAP_NET_ADMIN)
//#define NET_ADMIN_OFF CAP_OFF(CAP_NET_ADMIN)
//#define NET_BPF_ON    CAP_ON (CAP_BPF)
//#define NET_BPF_OFF   CAP_OFF(CAP_BPF)

#endif
