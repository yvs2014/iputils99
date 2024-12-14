#ifndef PING_COMMON_H
#define PING_COMMON_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdint.h>
#include <unistd.h>
#include <limits.h>
#include <netdb.h>
#include <setjmp.h>
#ifdef HAVE_LIBCAP
# include <sys/capability.h>
#endif

#include "node_info.h"

#ifndef SCOPE_DELIMITER
/* defined in netdb.h */
# define SCOPE_DELIMITER '%'
#endif

#define MAXWAIT			10	/* Max seconds to wait for response */
#define MIN_MCAST_INTERVAL_MS	1000	/* Minimal allowed interval for non-root for broadcast/multicast ping */

/*
 * MAX_DUP_CHK is the number of bits in received table
 * i.e. the maximum number of received sequence numbers we can keep track of
 */
#define	MAX_DUP_CHK	0x10000

#if defined(__WORDSIZE) && __WORDSIZE == 64
/* WORDSIZE defined via limits.h */
typedef uint64_t	bitmap_t;
# define BITMAP_SHIFT	6
#else
typedef uint32_t	bitmap_t;
# define BITMAP_SHIFT	5
#endif

#if ((MAX_DUP_CHK >> (BITMAP_SHIFT + 3)) << (BITMAP_SHIFT + 3)) != MAX_DUP_CHK
# error Please MAX_DUP_CHK and/or BITMAP_SHIFT
#endif

struct rcvd_table {
	bitmap_t bitmap[MAX_DUP_CHK / (sizeof(bitmap_t) * 8)];
};

typedef struct socket_st {
	int fd;
	int socktype;
} socket_st;

/* ping runtime state */
struct ping_rts {
	unsigned int mark;
	unsigned char *outpack;

	struct rcvd_table rcvd_tbl;

	size_t datalen;
	char *hostname;
	uid_t uid;
	uint16_t ident;			/* process id to identify our packets */

	int sndbuf;
	int ttl;

	long npackets;			/* max packets to transmit */
	long nreceived;			/* # of packets we got back */
	long nrepeats;			/* number of duplicates */
	long ntransmitted;		/* sequence # for outbound packets = #sent */
	long nchecksum;			/* replies with bad checksum */
	long nerrors;			/* icmp errors */
	int interval;			/* interval between packets (msec) */
	int preload;
	int deadline;			/* time to die */
	int lingertime;
	struct timespec start_time, cur_time;
	int confirm;
	int confirm_flag;
	char *device;
	int pmtudisc;

	/* timing */
	int timing;			/* flag to do timing */
	long tmin;			/* minimum round trip time */
	long tmax;			/* maximum round trip time */
	double tsum;			/* sum of all times, for doing average */
	double tsum2;
	int rtt;
	int rtt_addend;
	uint16_t acked;
	int pipesize;

	uint32_t tclass;
	uint32_t flowlabel;
	struct sockaddr_in6 source6;
	struct sockaddr_in6 whereto6;
	struct sockaddr_in6 firsthop6;
	int multicast;

	/* Used only in ping.c */
	int ts_type;
	int nroute;
	uint32_t route[10];
	struct sockaddr_in whereto;	/* who to ping */
	int optlen;
	int settos;			/* Set TOS, Precedence or other QOS options */
	int broadcast_pings;
	struct sockaddr_in source;

	/* Used only in common.c */
	int screen_width;
#ifdef HAVE_LIBCAP
	cap_value_t cap_raw;
	cap_value_t cap_admin;
#endif

	/* Used only in ping6_common.c */
	int subnet_router_anycast; /* Subnet-Router anycast (RFC 4291) */
	struct sockaddr_in6 firsthop;
	unsigned char cmsgbuf[4096];
	size_t cmsglen;
	struct ping_ni ni;

	/* boolean option bits */
	unsigned int
		opt_adaptive:1,
		opt_audible:1,
		opt_flood:1,
		opt_flood_poll:1,
		opt_flowinfo:1,
		opt_force_lookup:1,
		opt_interval:1,
		opt_latency:1,
		opt_mark:1,
		opt_noloop:1,
		opt_numeric:1,
		opt_outstanding:1,
		opt_pingfilled:1,
		opt_ptimeofday:1,
		opt_quiet:1,
		opt_rroute:1,
		opt_so_debug:1,
		opt_so_dontroute:1,
		opt_sourceroute:1,
		opt_strictsource:1,
		opt_timestamp:1,
		opt_ttl:1,
		opt_verbose:1,
		opt_connect_sk:1;
};

typedef struct ping_func_set_st {
	ssize_t (*send_probe)(struct ping_rts *rts, int sockfd,
		void *packet, unsigned packet_size);
	int (*receive_error)(struct ping_rts *rts, const socket_st *sock);
	int (*parse_reply)(struct ping_rts *rts, int socktype,
		struct msghdr *msg, size_t received, void *addr, const struct timeval *at);
	void (*install_filter)(uint16_t ident, int sockfd);
} ping_func_set_st;

void rcvd_clear(struct ping_rts *rts, uint16_t seq);
void acknowledge(struct ping_rts *rts, uint16_t seq);

uid_t limit_capabilities(const struct ping_rts *rts);
#ifdef HAVE_LIBCAP
# include <sys/capability.h>
int modify_capability(cap_value_t, cap_flag_value_t);
#define  ENABLE_CAPABILITY_RAW   modify_capability(CAP_NET_RAW,   CAP_SET)
#define DISABLE_CAPABILITY_RAW   modify_capability(CAP_NET_RAW,   CAP_CLEAR)
#define  ENABLE_CAPABILITY_ADMIN modify_capability(CAP_NET_ADMIN, CAP_SET)
#define DISABLE_CAPABILITY_ADMIN modify_capability(CAP_NET_ADMIN, CAP_CLEAR)
#else
int modify_capability(int);
#define  ENABLE_SUID modify_capability(1)
#define DISABLE_SUID modify_capability(0)
#define  ENABLE_CAPABILITY_RAW    ENABLE_SUID
#define DISABLE_CAPABILITY_RAW   DISABLE_SUID
#define  ENABLE_CAPABILITY_ADMIN  ENABLE_SUID
#define DISABLE_CAPABILITY_ADMIN DISABLE_SUID
#endif
void drop_capabilities(void);

const char *sprint_addr_common(const struct ping_rts *rts, const void *sa,
	socklen_t salen, int resolve_name);
#define SPRINT_RES_ADDR(rts, sastruct, salen) sprint_addr_common((rts), (sastruct), (salen), 1)
#define SPRINT_RAW_ADDR(rts, sastruct, salen) sprint_addr_common((rts), (sastruct), (salen), 0)

void print_timestamp(void);
#define PRINT_TIMESTAMP do { if (rts->opt_ptimeofday) print_timestamp(); } while(0)

#define IS_OURS(rts, socktype, test_id) (((socktype) == SOCK_DGRAM) || ((test_id) == (rts)->ident))

const char *str_interval(int interval);
void sock_setbufs(struct ping_rts *rts, int sockfd, int alloc);
void sock_setmark(struct ping_rts *rts, int sockfd);
void ping_setup(struct ping_rts *rts, const socket_st *sock);
int main_loop(struct ping_rts *rts, const ping_func_set_st *fset, const socket_st *sock,
	uint8_t *packet, int packlen);
int gather_stats(struct ping_rts *rts, const uint8_t *icmph, int icmplen, size_t received,
	uint16_t seq, int hops, int csfailed, const struct timeval *tv, const char *from,
	void (*print_reply)(const uint8_t *hdr, size_t len), int multicast, int wrong_source);
void fill_packet(int quiet, const char *patp, unsigned char *packet, size_t packet_size);

void usage(void);

#endif
