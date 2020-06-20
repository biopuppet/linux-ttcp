/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the TTCP protocol.
 *
 * Version:	@(#)ttcp.h	1.0.2	04/28/93
 *
 * Author:	Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _LINUX_TTCP_H
#define _LINUX_TTCP_H

#include <linux/types.h>
#include <asm/byteorder.h>
#include <linux/socket.h>

struct ttcphdr {
	__be16	source;
	__be16	dest;
	__be32	seq;
	__be32	ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16	res1:4,
		doff:4,
		fin:1,
		syn:1,
		rst:1,
		psh:1,
		ack:1,
		urg:1,
		ece:1,
		cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16	doff:4,
		res1:4,
		cwr:1,
		ece:1,
		urg:1,
		ack:1,
		psh:1,
		rst:1,
		syn:1,
		fin:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif	
	__be16	window;
	__sum16	check;
	__be16	urg_ptr;
};

/*
 *	The union cast uses a gcc extension to avoid aliasing problems
 *  (union is compatible to any of its members)
 *  This means this part of the code is -fstrict-aliasing safe now.
 */
union ttcp_word_hdr { 
	struct ttcphdr hdr;
	__be32 		  words[5];
}; 

#define ttcp_flag_word(tp) ( ((union ttcp_word_hdr *)(tp))->words [3]) 

enum { 
	TTCP_FLAG_CWR = __cpu_to_be32(0x00800000),
	TTCP_FLAG_ECE = __cpu_to_be32(0x00400000),
	TTCP_FLAG_URG = __cpu_to_be32(0x00200000),
	TTCP_FLAG_ACK = __cpu_to_be32(0x00100000),
	TTCP_FLAG_PSH = __cpu_to_be32(0x00080000),
	TTCP_FLAG_RST = __cpu_to_be32(0x00040000),
	TTCP_FLAG_SYN = __cpu_to_be32(0x00020000),
	TTCP_FLAG_FIN = __cpu_to_be32(0x00010000),
	TTCP_RESERVED_BITS = __cpu_to_be32(0x0F000000),
	TTCP_DATA_OFFSET = __cpu_to_be32(0xF0000000)
}; 

/*
 * TTCP general constants
 */
#define TTCP_MSS_DEFAULT		 536U	/* IPv4 (RFC1122, RFC2581) */
#define TTCP_MSS_DESIRED		1220U	/* IPv6 (tunneled), EDNS0 (RFC3226) */

/* TTCP socket options */
#define TTCP_NODELAY		1	/* Turn off Nagle's algorithm. */
#define TTCP_MAXSEG		2	/* Limit MSS */
#define TTCP_CORK		3	/* Never send partially complete segments */
#define TTCP_KEEPIDLE		4	/* Start keeplives after this period */
#define TTCP_KEEPINTVL		5	/* Interval between keepalives */
#define TTCP_KEEPCNT		6	/* Number of keepalives before death */
#define TTCP_SYNCNT		7	/* Number of SYN retransmits */
#define TTCP_LINGER2		8	/* Life time of orphaned FIN-WAIT-2 state */
#define TTCP_DEFER_ACCEPT	9	/* Wake up listener only when data arrive */
#define TTCP_WINDOW_CLAMP	10	/* Bound advertised window */
#define TTCP_INFO		11	/* Information about this connection. */
#define TTCP_QUICKACK		12	/* Block/reenable quick acks */
#define TTCP_CONGESTION		13	/* Congestion control algorithm */
#define TTCP_MD5SIG		14	/* TTCP MD5 Signature (RFC2385) */
#define TTCP_COOKIE_TRANSACTIONS	15	/* TTCP Cookie Transactions */
#define TTCP_THIN_LINEAR_TIMEOUTS 16      /* Use linear timeouts for thin streams*/
#define TTCP_THIN_DUPACK         17      /* Fast retrans. after 1 dupack */
#define TTCP_USER_TIMEOUT	18	/* How long for loss retry before timeout */

/* for TTCP_INFO socket option */
#define TTCPI_OPT_TIMESTAMPS	1
#define TTCPI_OPT_SACK		2
#define TTCPI_OPT_WSCALE		4
#define TTCPI_OPT_ECN		8

enum ttcp_ca_state {
	TTCP_CA_Open = 0,
#define TTCPF_CA_Open	(1<<TTCP_CA_Open)
	TTCP_CA_Disorder = 1,
#define TTCPF_CA_Disorder (1<<TTCP_CA_Disorder)
	TTCP_CA_CWR = 2,
#define TTCPF_CA_CWR	(1<<TTCP_CA_CWR)
	TTCP_CA_Recovery = 3,
#define TTCPF_CA_Recovery (1<<TTCP_CA_Recovery)
	TTCP_CA_Loss = 4
#define TTCPF_CA_Loss	(1<<TTCP_CA_Loss)
};

struct ttcp_info {
	__u8	ttcpi_state;
	__u8	ttcpi_ca_state;
	__u8	ttcpi_retransmits;
	__u8	ttcpi_probes;
	__u8	ttcpi_backoff;
	__u8	ttcpi_options;
	__u8	ttcpi_snd_wscale : 4, ttcpi_rcv_wscale : 4;

	__u32	ttcpi_rto;
	__u32	ttcpi_ato;
	__u32	ttcpi_snd_mss;
	__u32	ttcpi_rcv_mss;

	__u32	ttcpi_unacked;
	__u32	ttcpi_sacked;
	__u32	ttcpi_lost;
	__u32	ttcpi_retrans;
	__u32	ttcpi_fackets;

	/* Times. */
	__u32	ttcpi_last_data_sent;
	__u32	ttcpi_last_ack_sent;     /* Not remembered, sorry. */
	__u32	ttcpi_last_data_recv;
	__u32	ttcpi_last_ack_recv;

	/* Metrics. */
	__u32	ttcpi_pmtu;
	__u32	ttcpi_rcv_ssthresh;
	__u32	ttcpi_rtt;
	__u32	ttcpi_rttvar;
	__u32	ttcpi_snd_ssthresh;
	__u32	ttcpi_snd_cwnd;
	__u32	ttcpi_advmss;
	__u32	ttcpi_reordering;

	__u32	ttcpi_rcv_rtt;
	__u32	ttcpi_rcv_space;

	__u32	ttcpi_total_retrans;
};

/* for TTCP_MD5SIG socket option */
#define TTCP_MD5SIG_MAXKEYLEN	80

struct ttcp_md5sig {
	struct __kernel_sockaddr_storage ttcpm_addr;	/* address associated */
	__u16	__ttcpm_pad1;				/* zero */
	__u16	ttcpm_keylen;				/* key length */
	__u32	__ttcpm_pad2;				/* zero */
	__u8	ttcpm_key[TTCP_MD5SIG_MAXKEYLEN];		/* key (binary) */
};

/* for TTCP_COOKIE_TRANSACTIONS (TTCPCT) socket option */
#define TTCP_COOKIE_MIN		 8		/*  64-bits */
#define TTCP_COOKIE_MAX		16		/* 128-bits */
#define TTCP_COOKIE_PAIR_SIZE	(2*TTCP_COOKIE_MAX)

/* Flags for both getsockopt and setsockopt */
#define TTCP_COOKIE_IN_ALWAYS	(1 << 0)	/* Discard SYN without cookie */
#define TTCP_COOKIE_OUT_NEVER	(1 << 1)	/* Prohibit outgoing cookies,
						 * supercedes everything. */

/* Flags for getsockopt */
#define TTCP_S_DATA_IN		(1 << 2)	/* Was data received? */
#define TTCP_S_DATA_OUT		(1 << 3)	/* Was data sent? */

/* TTCP_COOKIE_TRANSACTIONS data */
struct ttcp_cookie_transactions {
	__u16	ttcpct_flags;			/* see above */
	__u8	__ttcpct_pad1;			/* zero */
	__u8	ttcpct_cookie_desired;		/* bytes */
	__u16	ttcpct_s_data_desired;		/* bytes of variable data */
	__u16	ttcpct_used;			/* bytes in value */
	__u8	ttcpct_value[TTCP_MSS_DEFAULT];
};

#ifdef __KERNEL__

#include <linux/skbuff.h>
#include <linux/dmaengine.h>
#include <net/sock.h>
#include <net/inet_connection_sock.h>
#include <net/inet_timewait_sock.h>

static inline struct ttcphdr *ttcp_hdr(const struct sk_buff *skb)
{
	return (struct ttcphdr *)skb_transport_header(skb);
}

static inline unsigned int ttcp_hdrlen(const struct sk_buff *skb)
{
	return ttcp_hdr(skb)->doff * 4;
}

static inline unsigned int ttcp_optlen(const struct sk_buff *skb)
{
	return (ttcp_hdr(skb)->doff - 5) * 4;
}

/* This defines a selective acknowledgement block. */
struct ttcp_sack_block_wire {
	__be32	start_seq;
	__be32	end_seq;
};

struct ttcp_sack_block {
	u32	start_seq;
	u32	end_seq;
};

struct ttcp_options_received {
/*	PAWS/RTTM data	*/
	long	ts_recent_stamp;/* Time we stored ts_recent (for aging) */
	u32	ts_recent;	/* Time stamp to echo next		*/
	u32	rcv_tsval;	/* Time stamp value             	*/
	u32	rcv_tsecr;	/* Time stamp echo reply        	*/
	u16 	saw_tstamp : 1,	/* Saw TIMESTAMP on last packet		*/
		tstamp_ok : 1,	/* TIMESTAMP seen on SYN packet		*/
		dsack : 1,	/* D-SACK is scheduled			*/
		wscale_ok : 1,	/* Wscale seen on SYN packet		*/
		sack_ok : 4,	/* SACK seen on SYN packet		*/
		snd_wscale : 4,	/* Window scaling received from sender	*/
		rcv_wscale : 4;	/* Window scaling to send to receiver	*/
	u8	cookie_plus:6,	/* bytes in authenticator/cookie option	*/
		cookie_out_never:1,
		cookie_in_always:1;
	u8	num_sacks;	/* Number of SACK blocks		*/
	u16	user_mss;	/* mss requested by user in ioctl	*/
	u16	mss_clamp;	/* Maximal mss, negotiated at connection setup */
};

static inline void ttcp_clear_options(struct ttcp_options_received *rx_opt)
{
	rx_opt->tstamp_ok = rx_opt->sack_ok = 0;
	rx_opt->wscale_ok = rx_opt->snd_wscale = 0;
	rx_opt->cookie_plus = 0;
}

/* This is the max number of SACKS that we'll generate and process. It's safe
 * to increase this, although since:
 *   size = TTCPOLEN_SACK_BASE_ALIGNED (4) + n * TTCPOLEN_SACK_PERBLOCK (8)
 * only four options will fit in a standard TTCP header */
#define TTCP_NUM_SACKS 4

struct ttcp_cookie_values;
struct ttcp_request_sock_ops;

struct ttcp_request_sock {
	struct inet_request_sock 	req;
#ifdef CONFIG_TTCP_MD5SIG
	/* Only used by TTCP MD5 Signature so far. */
	const struct ttcp_request_sock_ops *af_specific;
#endif
	u32				rcv_isn;
	u32				snt_isn;
};

static inline struct ttcp_request_sock *ttcp_rsk(const struct request_sock *req)
{
	return (struct ttcp_request_sock *)req;
}

struct ttcp_sock {
	/* inet_connection_sock has to be the first member of ttcp_sock */
	struct inet_connection_sock	inet_conn;
	u16	ttcp_header_len;	/* Bytes of ttcp header to send		*/
	u16	xmit_size_goal_segs; /* Goal for segmenting output packets */

/*
 *	Header prediction flags
 *	0x5?10 << 16 + snd_wnd in net byte order
 */
	__be32	pred_flags;

/*
 *	RFC793 variables by their proper names. This means you can
 *	read the code and the spec side by side (and laugh ...)
 *	See RFC793 and RFC1122. The RFC writes these in capitals.
 */
 	u32	rcv_nxt;	/* What we want to receive next 	*/
	u32	copied_seq;	/* Head of yet unread data		*/
	u32	rcv_wup;	/* rcv_nxt on last window update sent	*/
 	u32	snd_nxt;	/* Next sequence we send		*/

 	u32	snd_una;	/* First byte we want an ack for	*/
 	u32	snd_sml;	/* Last byte of the most recently transmitted small packet */
	u32	rcv_tstamp;	/* timestamp of last received ACK (for keepalives) */
	u32	lsndtime;	/* timestamp of last sent data packet (for restart window) */

	/* Data for direct copy to user */
	struct {
		struct sk_buff_head	prequeue;
		struct task_struct	*task;
		struct iovec		*iov;
		int			memory;
		int			len;
#ifdef CONFIG_NET_DMA
		/* members for async copy */
		struct dma_chan		*dma_chan;
		int			wakeup;
		struct dma_pinned_list	*pinned_list;
		dma_cookie_t		dma_cookie;
#endif
	} ucopy;

	u32	snd_wl1;	/* Sequence for window update		*/
	u32	snd_wnd;	/* The window we expect to receive	*/
	u32	max_window;	/* Maximal window ever seen from peer	*/
	u32	mss_cache;	/* Cached effective mss, not including SACKS */

	u32	window_clamp;	/* Maximal window to advertise		*/
	u32	rcv_ssthresh;	/* Current window clamp			*/

	u32	frto_highmark;	/* snd_nxt when RTO occurred */
	u16	advmss;		/* Advertised MSS			*/
	u8	frto_counter;	/* Number of new acks after RTO */
	u8	nonagle     : 4,/* Disable Nagle algorithm?             */
		thin_lto    : 1,/* Use linear timeouts for thin streams */
		thin_dupack : 1,/* Fast retransmit on first dupack      */
		unused      : 2;

/* RTT measurement */
	u32	srtt;		/* smoothed round trip time << 3	*/
	u32	mdev;		/* medium deviation			*/
	u32	mdev_max;	/* maximal mdev for the last rtt period	*/
	u32	rttvar;		/* smoothed mdev_max			*/
	u32	rtt_seq;	/* sequence number to update rttvar	*/

	u32	packets_out;	/* Packets which are "in flight"	*/
	u32	retrans_out;	/* Retransmitted packets out		*/

	u16	urg_data;	/* Saved octet of OOB data and control flags */
	u8	ecn_flags;	/* ECN status bits.			*/
	u8	reordering;	/* Packet reordering metric.		*/
	u32	snd_up;		/* Urgent pointer		*/

	u8	keepalive_probes; /* num of allowed keep alive probes	*/
/*
 *      Options received (usually on last packet, some only on SYN packets).
 */
	struct ttcp_options_received rx_opt;

/*
 *	Slow start and congestion control (see also Nagle, and Karn & Partridge)
 */
 	u32	snd_ssthresh;	/* Slow start size threshold		*/
 	u32	snd_cwnd;	/* Sending congestion window		*/
	u32	snd_cwnd_cnt;	/* Linear increase counter		*/
	u32	snd_cwnd_clamp; /* Do not allow snd_cwnd to grow above this */
	u32	snd_cwnd_used;
	u32	snd_cwnd_stamp;

 	u32	rcv_wnd;	/* Current receiver window		*/
	u32	write_seq;	/* Tail(+1) of data held in ttcp send buffer */
	u32	pushed_seq;	/* Last pushed seq, required to talk to windows */
	u32	lost_out;	/* Lost packets			*/
	u32	sacked_out;	/* SACK'd packets			*/
	u32	fackets_out;	/* FACK'd packets			*/
	u32	tso_deferred;
	u32	bytes_acked;	/* Appropriate Byte Counting - RFC3465 */

	/* from STTCP, retrans queue hinting */
	struct sk_buff* lost_skb_hint;
	struct sk_buff *scoreboard_skb_hint;
	struct sk_buff *retransmit_skb_hint;

	struct sk_buff_head	out_of_order_queue; /* Out of order segments go here */

	/* SACKs data, these 2 need to be together (see ttcp_build_and_update_options) */
	struct ttcp_sack_block duplicate_sack[1]; /* D-SACK block */
	struct ttcp_sack_block selective_acks[4]; /* The SACKS themselves*/

	struct ttcp_sack_block recv_sack_cache[4];

	struct sk_buff *highest_sack;   /* highest skb with SACK received
					 * (validity guaranteed only if
					 * sacked_out > 0)
					 */

	int     lost_cnt_hint;
	u32     retransmit_high;	/* L-bits may be on up to this seqno */

	u32	lost_retrans_low;	/* Sent seq after any rxmit (lowest) */

	u32	prior_ssthresh; /* ssthresh saved at recovery start	*/
	u32	high_seq;	/* snd_nxt at onset of congestion	*/

	u32	retrans_stamp;	/* Timestamp of the last retransmit,
				 * also used in SYN-SENT to remember stamp of
				 * the first SYN. */
	u32	undo_marker;	/* tracking retrans started here. */
	int	undo_retrans;	/* number of undoable retransmissions. */
	u32	total_retrans;	/* Total retransmits for entire connection */

	u32	urg_seq;	/* Seq of received urgent pointer */
	unsigned int		keepalive_time;	  /* time before keep alive takes place */
	unsigned int		keepalive_intvl;  /* time interval between keep alive probes */

	int			linger2;

/* Receiver side RTT estimation */
	struct {
		u32	rtt;
		u32	seq;
		u32	time;
	} rcv_rtt_est;

/* Receiver queue space */
	struct {
		int	space;
		u32	seq;
		u32	time;
	} rcvq_space;

/* TTCP-specific MTU probe information. */
	struct {
		u32		  probe_seq_start;
		u32		  probe_seq_end;
	} mtu_probe;

#ifdef CONFIG_TTCP_MD5SIG
/* TTCP AF-Specific parts; only used by MD5 Signature support so far */
	const struct ttcp_sock_af_ops	*af_specific;

/* TTCP MD5 Signature Option information */
	struct ttcp_md5sig_info	*md5sig_info;
#endif

	/* When the cookie options are generated and exchanged, then this
	 * object holds a reference to them (cookie_values->kref).  Also
	 * contains related ttcp_cookie_transactions fields.
	 */
	struct ttcp_cookie_values  *cookie_values;
};

static inline struct ttcp_sock *ttcp_sk(const struct sock *sk)
{
	return (struct ttcp_sock *)sk;
}

struct ttcp_timewait_sock {
	struct inet_timewait_sock tw_sk;
	u32			  tw_rcv_nxt;
	u32			  tw_snd_nxt;
	u32			  tw_rcv_wnd;
	u32			  tw_ts_recent;
	long			  tw_ts_recent_stamp;
#ifdef CONFIG_TTCP_MD5SIG
	u16			  tw_md5_keylen;
	u8			  tw_md5_key[TTCP_MD5SIG_MAXKEYLEN];
#endif
	/* Few sockets in timewait have cookies; in that case, then this
	 * object holds a reference to them (tw_cookie_values->kref).
	 */
	struct ttcp_cookie_values  *tw_cookie_values;
};

static inline struct ttcp_timewait_sock *ttcp_twsk(const struct sock *sk)
{
	return (struct ttcp_timewait_sock *)sk;
}

#endif	/* __KERNEL__ */

#endif	/* _LINUX_TTTCP_H */
