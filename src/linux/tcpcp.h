/*
 * linux/tcpcp.h - TCP connection passing, data structures and prototypes
 *
 * Written 2002 by Werner Almesberger
 */

#ifndef _LINUX_TCPCP_H
#define _LINUX_TCPCP_H

#ifdef __KERNEL__
#include <linux/config.h>
#include <linux/types.h>
#endif /* __KERNEL__ */


/*
 * The socket option numbers should be in linux/tcp.h, but tcp.h can't be
 * included by user space, so in order to avoid duplication, they go here.
 */

#define TCP_MAXICISIZE		13      /* Max. size of Internal Conn. Info */
#define TCP_ICI			14      /* Retrieve/set Internal Conn. Info */
#define TCP_CP_FN		15      /* Perform special tcpcp operation */


/* TCP_KICK sub-function codes */
#define TCPCP_ACTIVATE		0	/* Activate dormant connection */

/*
 * For simplicity, ICIs (Internal Connection Information) use a fixed-size
 * struct, which is followed by the variable-size send and receive buffers.
 *
 * All ICI elements are padded to a multiple of four bytes. Numbers are always
 * in network byte order.
 *
 * When extending the ICI, fields that can safely be ignored should be added in
 * new IEs, before the buffer list, and only the minor version number needs to
 * be incremented. If the content of existing IEs changes, or if new
 * information can't be simply ignored, the major version number must be
 * incremented.
 *
 * Should ICI use TLVs (Type-Length-Value), like netlink does ? Well, maybe.
 * TLVs are more flexible, but they have also a bit more implementation
 * overhead, and you can't just "print" them from a debugger. So for now,
 * plain structs are better for development.
 */

/*
 * ICIEs represent a more or less arbitrary division of ICI data. The idea
 * behind dividing this into separate elements is to allow for future
 * replacements of relatively small blocks, in case kernel data structures
 * change.
 */

/* ICI element: ICI version and flags */

struct tcpcp_icie_version {
	uint8_t major;		/* incompatible structure revision */
				/*  0: current version */
	uint8_t minor;		/* compatible structure extension */
				/*  0: current version */
	uint8_t ip_version;	/* IP version */
				/*   4: IPv4 */
	uint8_t __pad1;
	uint16_t flags;		/* see TCPCP_ICIF_*, below */
	uint16_t __pad2;
	uint16_t ici_hdr_size;	/* sizeof(struct tcpcp_ici) */
	uint16_t buf_hdr_size;	/* sizeof(struct tcpcp_icie_buf) */
};

enum {
	TCPCP_ICIF_USEPERF = 1,	/* use perf. data (tcpcp_set_cong) */
};


/* ICI element: globally unique TCP connection ID */

struct tcpcp_icie_id4 {
	uint32_t ip_src;	/* source IP address */
	uint32_t ip_dst;	/* destination IP address */
};

struct tcpcp_icie_id {
	union {
		struct tcpcp_icie_id4 v4; /* IPv4 */
	} ip;
	uint16_t tcp_sport;	/* TCP source port */
	uint16_t tcp_dport;	/* TCP destination port */
};


/* ICI element: fixed general data */

struct tcpcp_icie_fixgen {
	uint8_t tcp_flags;	/* TCP flags; from linux/tcp.h */
				/*  1: TCPI_OPT_TIMESTAMPS */
				/*  2: TCPI_OPT_SACK */
				/*  4: TCPI_OPT_WSCALE */
				/*  8: TCPI_OPT_ECN */
	uint8_t	snd_wscale;	/* send window scale (0 if unused) */
	uint8_t rcv_wscale;	/* receive window scale (0 if unused) */
	uint8_t __pad;
	uint16_t snd_mss;	/* MSS sent */
	uint16_t rcv_mss;	/* MSS received */
};


/* ICI element: variable general data */

struct tcpcp_icie_vargen {
 	uint8_t state;		/* connection state; from linux/tcp.h */
				/*  1: TCP_ESTABLISHED */
				/*  2: TCP_SYN_SENT */
				/*  3: TCP_SYN_RECV */
				/*  4: TCP_FIN_WAIT1 */
				/*  5: TCP_FIN_WAIT2 */
				/*  6: TCP_TIME_WAIT */
				/*  7: TCP_CLOSE */
				/*  8: TCP_CLOSE_WAIT */
				/*  9: TCP_LAST_ACK */
				/* 10: TCP_LISTEN */
				/* 11: TCP_CLOSING */
				/* Note: TCP_ICI may not ever use some of these
				   values. */
	uint8_t __pad1;
	uint8_t __pad2;
	uint8_t __pad3;
	uint32_t snd_nxt;	/* sequence number of next new byte to send */
	uint32_t rcv_nxt;	/* sequence number of next new byte expected to
				   receive */
	uint32_t snd_wnd;	/* window received from peer */
	uint32_t rcv_wnd;	/* window advertized to peer */
	uint32_t ts_recent;	/* cached timestamp from peer (0 if none) */
	uint32_t ts_gen;	/* current locally generated timestamp */
				/* (0 if not using timestamps) */
};


/* ICI element: congestion avoidance data */

struct tcpcp_icie_cong {
};


/* ICI element: connection statistics */

struct tcpcp_icie_stat {
	/* [0-3]: retransmits 
	/ * [4-7]: probes sent
	/ * [8-11]: backoff */
};


/* ICI element: send or receive buffer */

struct tcpcp_icie_buf {
	/*** These fields must be first and in this order ! ******************/
	uint8_t type;		/* buffer type (TCPCP_ICIE_BUF_*, see below) */
	uint8_t __pad;                                                     /**/
	uint16_t length;	/* segment data length                       */
	/*********************************************************************/
	uint32_t seq;		/* sequence number of first byte */
	uint8_t data[0];	/* data, padded to multiple of 4 bytes */
};

enum {
	TPCPC_ICIE_BUF_SND = 1,	/* send buffer (only TCP segment, no IP) */
	TPCPC_ICIE_BUF_OOO = 2,	/* out of order buffer (only TCP segment) */
};


/* Internal Connection Information (ICI) */

struct tcpcp_ici {
	uint32_t ici_length;	/* total length of ICI */
	struct tcpcp_icie_version v; /* ICI version and flags */
	struct tcpcp_icie_id id; /* globally unique TCP connection ID */
	struct tcpcp_icie_fixgen fixgen; /* fixed general data */
	struct tcpcp_icie_vargen vargen; /* variable general data */
	struct tcpcp_icie_cong cong; /* congestion avoidance data */
	struct tcpcp_icie_stat stat; /* connection statistics */
	/* ----- ADD NEW IEs HERE ----- */
	struct tcpcp_icie_buf buf[0];
};

/*
 * Buffers are in sequence, first all send, then all out-of-order buffers.
 * Buffers must not overlap, and may not contain any extraneous data (e.g.
 * ack'ed bytes, or such). snd_nxt does not have to be at a buffer boundary.
 */


#ifdef __KERNEL__

#if defined(CONFIG_TCPCP) || defined(CONFIG_TCPCP_MODULE)

#include <net/sock.h>

extern int sysctl_tcpcp_privileged;

extern int (*tcpcp_maxicisize_hook)(struct sock *sk,int *size);
extern int (*tcpcp_getici_hook)(struct sock *sk,struct tcpcp_ici *user_ici,
    int *user_size);
extern int (*tcpcp_setici_hook)(struct sock *sk,
    const struct tcpcp_ici *user_ici,int size);
extern int (*tcpcp_fn_hook)(struct sock *sk,int fn_code);

void tcpcp_lock_hooks(void);
void tcpcp_unlock_hooks(void);

int tcpcp_maxicisize(struct sock *sk,int *size);
int tcpcp_getici(struct sock *sk,struct tcpcp_ici *user_ici,int *user_size);
int tcpcp_setici(struct sock *sk,const struct tcpcp_ici *user_ici,int size);
int tcpcp_fn(struct sock *sk,int fn_code);

#else /* defined(CONFIG_TCPCP) || defined(CONFIG_TCPCP_MODULE) */

#define tcpcp_maxicisize(sk,val) (-ENOPROTOOPT)
#define tcpcp_getici(sk,val,size) (-ENOPROTOOPT)
#define tcpcp_setici(sk,val,size) (-ENOPROTOOPT)
#define tcpcp_fn(sk,fn_code) (-ENOPROTOOPT)

#endif /* !defined(CONFIG_TCPCP) && !defined(CONFIG_TCPCP_MODULE) */

#endif /* __KERNEL__ */

#endif /* _LINUX_TCPCP_H */
