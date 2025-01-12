#ifndef NODE_INFO_H
#define NODE_INFO_H

#include <stdint.h>
#include <netinet/icmp6.h>
#ifndef NI_NONCE_MEMORY
#include <sys/time.h>
#endif

#define NI_NONCE_SIZE	8

/* Node Information Query */
struct ping_ni {
	int query;
	int flag;
	void *subject;
	int subject_len;
	int subject_type;
	char *group;
#if NI_NONCE_MEMORY
	uint8_t *nonce_ptr;
#else
	struct {
		struct timeval tv;
		pid_t pid;
	} nonce_secret;
#endif
};

int niquery_is_enabled(struct ping_ni *ni);
void niquery_init_nonce(struct ping_ni *ni);
int niquery_option_handler(struct ping_ni *ni, const char *opt_arg);
int niquery_is_subject_valid(struct ping_ni *ni);
int niquery_check_nonce(struct ping_ni *ni, uint8_t *nonce);
void niquery_fill_nonce(struct ping_ni *ni, uint16_t seq, uint8_t *nonce);

struct ni_hdr {
	struct icmp6_hdr	ni_u;
	uint8_t			ni_nonce[NI_NONCE_SIZE];
};
#define ni_type		ni_u.icmp6_type
#define ni_code		ni_u.icmp6_code
#define ni_cksum	ni_u.icmp6_cksum
#define ni_qtype	ni_u.icmp6_data16[0]
#define ni_flags	ni_u.icmp6_data16[1]

#endif
