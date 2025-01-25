#ifndef PING_COMMON_H
#define PING_COMMON_H

#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <limits.h>
#include <netdb.h>
#include <time.h>
#include <sys/time.h>

#ifdef ENABLE_RFC4620
#include "node_info.h"
#endif

#ifndef SCOPE_DELIMITER
/* defined in netdb.h */
# define SCOPE_DELIMITER '%'
#endif

#define DEFIPPAYLOAD	64
#define MAXWAIT		10	/* Max seconds to wait for response */
#define MIN_MCAST_MS	1000	/* Min milliseconds to broadcast/multicast by non-root users */
#define MS2LEN(val)	(((val) % 10) ? 3 : ((val) % 100) ? 2 : 1)

/* Min reserve for outpack */
#define	PACKHDRLEN	(sizeof(struct icmphdr) + sizeof(struct timeval))

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

typedef struct ping_sock {
	int fd;
	bool raw;
} sock_t;

#define MAX_ROUTES	9
typedef struct route_data {
	unsigned n;
	uint32_t data[MAX_ROUTES + 1];
} route_t;

#define MAX_CMSG_SIZE	4096
typedef struct cmsg_data {
	size_t len;
	uint8_t data[MAX_CMSG_SIZE];
} cmsg_t;

typedef struct ping_bool_opts {
	bool adaptive;
	bool audible;
	bool flood;
	bool flood_poll;
	bool flowinfo;
	bool interval;
	bool latency;
	bool mark;
	bool noloop;
	bool outstanding;
	bool pingfilled;
	bool ptimeofday;
	bool resolve;
	bool quiet;
	bool rroute;
	bool so_debug;
	bool so_dontroute;
	bool sourceroute;
	bool strictsource;
	bool timestamp;
	bool verbose;
	bool connect_sk;
	bool broadcast;
} ping_bool_opts;

/* ping runtime state */
typedef struct ping_state {
	size_t datalen;
	char *hostname;
	uid_t uid;
	uint16_t ident16;		/* id to identify our packets */
	int custom_ident;		/* -e option */
	bool ip6;			/* true for IPv6 pings */
	//
	bitmap_t bitmap[MAX_DUP_CHK / (sizeof(bitmap_t) * 8)];
	unsigned char *outpack;
	int sndbuf;
	//
	long npackets;			/* max packets to transmit */
	long nreceived;			/* # of packets we got back */
	long nrepeats;			/* number of duplicates */
	long ntransmitted;		/* sequence # for outbound packets = #sent */
	long nchecksum;			/* replies with bad checksum */
	long nerrors;			/* icmp errors */
	unsigned unidentified;		/* counter of unidentified packets */
	int interval;			/* interval between packets (msec) */
	int preload;
	int deadline;			/* time to die */
	int lingertime;
	struct timespec start_time, cur_time;
	int confirm;
	int confirm_flag;
	const char *device;
	int pmtudisc;
	unsigned mark;
	// ttl related
	int ttl;
	int min_away;
	int max_away;
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
	uint8_t qos;				/* TOS/TCLASS */
	bool multicast;
	// ping4 only
	uint8_t ipt_flg;	/* ip option: timestamp flags */
	route_t *route;		/* allocated in ping4 */
	// ping6 only
	uint32_t flowlabel;
	bool subnet_router_anycast;
	cmsg_t *cmsg;		/* allocated in ping6 */
#ifdef ENABLE_RFC4620
	struct ping_ni *ni;	/* allocated with -N option */
#endif
	// termios.h: ws_col type
	unsigned short screen_width;
	// boolean options
	struct ping_bool_opts opt;
} state_t;

typedef struct fnset_t {
	void (*bpf_filter)(const state_t *rts, const sock_t *sock);
	ssize_t (*send_probe)(state_t *rts, int fd, uint8_t *packet);
	int (*receive_error)(state_t *rts, const sock_t *sock);
	bool (*parse_reply)(state_t *rts, bool rawsock, struct msghdr *msg,
		size_t received, void *addr, const struct timeval *at);
} fnset_t;

const char *sprint_addr(const void *sa, socklen_t salen, bool resolve);
void acknowledge(state_t *rts, uint16_t seq);

#define IS_OURS(rts, rawsock, rcvd_id) (!(rawsock) || ((rcvd_id) == (rts)->ident16))

void sock_setmark(state_t *rts, int fd);
void sock_settos(int fd, int qos, bool ip6);
int setup_n_loop(state_t *rts, size_t hlen, const sock_t *sock,
	 const fnset_t* fnset);
int get_interval(const state_t *rts);
void fill_payload(int quiet, const char *str, unsigned char *payload, size_t len);

bitmap_t rcvd_test (uint16_t seq, const bitmap_t *map);
void     rcvd_set  (uint16_t seq, bitmap_t *map);
void     rcvd_clear(uint16_t seq, bitmap_t *map);

// wrapper: __has_attribute
#ifndef __has_attribute
#define __has_attribute(attr) 0
#endif
// attribute: noreturn
#if __has_attribute(__noreturn__)
#define NORETURN __attribute__((__noreturn__))
#else
#define NORETURN
#endif

void usage(int rc) NORETURN;

#endif
