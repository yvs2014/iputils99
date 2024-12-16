#ifndef PING_COMMON_H
#define PING_COMMON_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdbool.h>
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
	bool raw;
} socket_st;

typedef struct ping_bool_opts {
	bool adaptive;
	bool audible;
	bool flood;
	bool flood_poll;
	bool flowinfo;
	bool force_lookup;
	bool interval;
	bool latency;
	bool mark;
	bool noloop;
	bool numeric;
	bool outstanding;
	bool pingfilled;
	bool ptimeofday;
	bool quiet;
	bool rroute;
	bool so_debug;
	bool so_dontroute;
	bool sourceroute;
	bool strictsource;
	bool timestamp;
	bool ttl;
	bool verbose;
	bool connect_sk;
	bool broadcast;
} ping_bool_opts;

/* ping runtime state */
struct ping_rts {
	size_t datalen;
	char *hostname;
	uid_t uid;
	uint16_t ident16;		/* id to identify our packets */
	int custom_ident;		/* -e option */
	bool ip6;			/* true for IPv6 pings */
	//
	struct rcvd_table rcvd_tbl;
	unsigned char *outpack;
	int sndbuf;
	//
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
	int ttl;
	unsigned mark;
	//
	// timing
	bool timing;			/* flag to do timing */
	long tmin;			/* minimum round trip time */
	long tmax;			/* maximum round trip time */
	double tsum;			/* sum of all times, for doing average */
	double tsum2;
	int rtt;
	int rtt_addend;
	uint16_t acked;
	int pipesize;
	//
	struct sockaddr_storage source;
	struct sockaddr_storage whereto;	/* who to ping */
	struct sockaddr_storage firsthop;
	uint32_t flowlabel;
	uint8_t qos;				/* TOS/TCLASS */
	uint8_t ipt_flg;			/* IP option: timestamp flags */
	bool multicast;
	//
	/* Used only in ping.c */
	int nroute;
	uint32_t route[10];
	int optlen;
	//
	/* Used only in common.c */
	int screen_width;
#ifdef HAVE_LIBCAP
	cap_value_t cap_raw;
	cap_value_t cap_admin;
#endif
	//
	/* Used only in ping6_common.c */
	int subnet_router_anycast; /* Subnet-Router anycast (RFC 4291) */
	unsigned char cmsgbuf[4096];
	size_t cmsglen;
	struct ping_ni ni;
	//
	// boolean options
	struct ping_bool_opts opt;
};

typedef struct ping_func_set_st {
	ssize_t (*send_probe)(struct ping_rts *rts, int sockfd,
		void *packet, unsigned packet_size);
	int (*receive_error)(struct ping_rts *rts, const socket_st *sock);
	int (*parse_reply)(struct ping_rts *rts, bool rawsock,
		struct msghdr *msg, size_t received, void *addr, const struct timeval *at);
	void (*install_filter)(uint16_t ident, int sockfd);
} ping_func_set_st;

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
#define PRINT_TIMESTAMP do { if (rts->opt.ptimeofday) print_timestamp(); } while(0)

#define IS_OURS(rts, rawsock, rcvd_id) (!(rawsock) || ((rcvd_id) == (rts)->ident16))

const char *str_interval(int interval);
void sock_setbufs(struct ping_rts *rts, int sockfd, int alloc);
void sock_setmark(struct ping_rts *rts, int sockfd);
void ping_setup(struct ping_rts *rts, const socket_st *sock);
int main_loop(struct ping_rts *rts, const ping_func_set_st *fset, const socket_st *sock,
	uint8_t *packet, int packlen);
int gather_stats(struct ping_rts *rts, const uint8_t *icmph, int icmplen, size_t received,
	uint16_t seq, int hops, int csfailed, const struct timeval *tv, const char *from,
	void (*print_reply)(bool ip6, const uint8_t *hdr, size_t len), bool multicast, bool wrong_source);
void fill_packet(int quiet, const char *patp, unsigned char *packet, size_t packet_size);

void usage(void);

#endif
