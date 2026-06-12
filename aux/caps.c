
// Iputils Project
//
// Linux capabilities related part

#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <sys/prctl.h>

#include "caps.h"

static inline void set_caps(const cap_value_t flag[]) { // NONNULL(1)
	// init
	cap_t curr = cap_get_proc();
	if (!curr)
		err(errno, "%s", "cap_get_proc()");
	cap_t caps = cap_init();
	if (!caps)
		err(errno, "%s", "cap_init()");
	// take only those that permitted
	for (; *flag >= 0; flag++) {
		cap_flag_value_t c = CAP_CLEAR;
		if (cap_get_flag(curr, *flag, CAP_PERMITTED, &c) < 0)
			err(errno, "cap_get_flag(%s, %d)", "PERMITTED", *flag);
		if (c != CAP_CLEAR) // add to permitted
			if (cap_set_flag(caps, CAP_PERMITTED, 1, flag, CAP_SET) < 0)
				err(errno, "cap_set_flag(%s, flag=%d, onoff=%d)", "PERMITTED", *flag, CAP_SET);
	}
	// set them and clear others
	if (cap_set_proc(caps) < 0)
		err(errno, "%s", "cap_set_proc()");
	// clean
	cap_free(caps);
	cap_free(curr);
}

static inline void keep_cap_state(void) {
	uid_t uid = getuid();
	if (prctl(PR_SET_KEEPCAPS, 1) < 0)
		err(errno, "prctl(%s, %s)", "CAPS", "set");
	if (setuid(uid) < 0)
		err(errno, "setuid(%d)", uid);
	if (prctl(PR_SET_KEEPCAPS, 0) < 0)
		err(errno, "prctl(%s, %s)", "CAPS", "clear");
	if (seteuid(uid))
		err(errno, "seteuid(%d)", uid);
}

void limit_caps(const cap_value_t flag[]) { // NONNULL(1)
	set_caps(flag);
	keep_cap_state();
}

void drop_priv(void) {
	cap_t caps = cap_init();
	if (!caps)
		err(errno, "%s", "cap_init()");
	if (cap_set_proc(caps) < 0)
		err(errno, "%s", "cap_set_proc()");
	cap_free(caps);
}

void modify_cap(cap_value_t cap, cap_flag_value_t on) {
	cap_t curr = cap_get_proc();
	if (curr) {
		cap_flag_value_t perm = CAP_CLEAR;
		if (cap_get_flag(curr, cap, CAP_PERMITTED, &perm) < 0)
			err(errno, "cap_get_flag(%s, %d)", "PERMITTED", cap);
		else if (perm != CAP_CLEAR) { // i.e. permitted to set/clear
			if (cap_set_flag(curr, CAP_EFFECTIVE, 1, &cap, on) < 0)
				err(errno, "cap_set_flag(flag=%d, onoff=%d)", cap, on);
			else if (cap_set_proc(curr) < 0)
				err(errno, "cap_set_proc(flag=%d, onoff=%d)", cap, on);
		}
		cap_free(curr);
	} else
		err(errno, "%s", "cap_get_proc()");
}

