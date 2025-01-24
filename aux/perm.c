
// Iputils Project
//
// Calling process UID related part

#include <unistd.h>
#include <err.h>
#include <errno.h>

#include "perm.h"

static uid_t proc_euid;

void keep_euid(void) {
	proc_euid = geteuid();
}

void drop_priv(void) {
	uid_t uid = getuid();
	if (setuid(uid) < 0)
		err(errno, "setuid(%d)", uid);
}

void modify_euid(bool on) {
	uid_t uid = on ? proc_euid : getuid();
	if (seteuid(uid) < 0)
		err(errno, "seteuid(%u)", uid);
}

