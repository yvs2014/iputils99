#ifndef PERM_H
#define PERM_H

#include <stdbool.h>

void keep_euid(void);
void drop_priv(void);

void modify_euid(bool on);
#define SUID_ON  modify_euid(true)
#define SUID_OFF modify_euid(false)

#define NET_RAW_ON   SUID_ON
#define NET_RAW_OFF  SUID_OFF
#define SYS_NICE_ON  SUID_ON
#define SYS_NICE_OFF SUID_OFF
// legacy:
//#define NET_ADMIN_ON  SUID_ON
//#define NET_ADMIN_OFF SUID_OFF

#endif
