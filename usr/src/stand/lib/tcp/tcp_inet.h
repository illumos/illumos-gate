/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1982, 1986 Regents of the University of California.
 * All rights reserved. The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#ifndef _TCP_INET_H
#define	_TCP_INET_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include "tcp_sack.h"

/* TCP states */
#define	TCPS_ALL_ACKED		-7	/* Internal state for retransmissions */
#define	TCPS_CLOSED		-6
#define	TCPS_IDLE		-5	/* idle (opened, but not bound) */
#define	TCPS_BOUND		-4	/* bound, ready to connect or accept */
#define	TCPS_LISTEN		-3	/* listening for connection */
#define	TCPS_SYN_SENT		-2	/* active, have sent syn */
#define	TCPS_SYN_RCVD		-1	/* have received syn (and sent ours) */
/* states < TCPS_ESTABLISHED are those where connections not established */
#define	TCPS_ESTABLISHED	0	/* established */
#define	TCPS_CLOSE_WAIT		1	/* rcvd fin, waiting for close */
/* states > TCPS_CLOSE_WAIT are those where user has closed */
#define	TCPS_FIN_WAIT_1		2	/* have closed and sent fin */
#define	TCPS_CLOSING		3	/* closed, xchd FIN, await FIN ACK */
#define	TCPS_LAST_ACK		4	/* had fin and close; await FIN ACK */
/* states > TCPS_CLOSE_WAIT && < TCPS_FIN_WAIT_2 await ACK of FIN */
#define	TCPS_FIN_WAIT_2		5	/* have closed, fin is acked */
#define	TCPS_TIME_WAIT		6	/* in 2*msl quiet wait after close */

/*
 * Internal flags used in conjunction with the packet header flags.
 * Used in tcp_rput_data to keep track of what needs to be done.
 */
#define	TH_LIMIT_XMIT		0x0400	/* Limited xmit is needed */
#define	TH_XMIT_NEEDED		0x0800	/* Window opened - send queued data */
#define	TH_REXMIT_NEEDED	0x1000	/* Time expired for unacked data */
#define	TH_ACK_NEEDED		0x2000	/* Send an ack now. */
#define	TH_NEED_SACK_REXMIT	0x4000	/* Use SACK info to retransmission */
#define	TH_TIMER_NEEDED 0x8000	/* Start the delayed ack/push bit timer */

/*
 * Special Magic number used by TCP to issue a callback to recvfrom() in the
 * form of a dummy inetgram.
 */
#define	TCP_CALLB_MAGIC_ID	0xFFFF

/*
 * TCP sequence numbers are 32 bit integers operated
 * on with modular arithmetic.  These macros can be
 * used to compare such integers.
 */
#define	SEQ_LT(a, b)	((int32_t)((a)-(b)) < 0)
#define	SEQ_LEQ(a, b)	((int32_t)((a)-(b)) <= 0)
#define	SEQ_GT(a, b)	((int32_t)((a)-(b)) > 0)
#define	SEQ_GEQ(a, b)	((int32_t)((a)-(b)) >= 0)

/* TCP Protocol header */
typedef	struct tcphdr_s {
	uint8_t		th_lport[2];	/* Source port */
	uint8_t		th_fport[2];	/* Destination port */
	uint8_t		th_seq[4];	/* Sequence number */
	uint8_t		th_ack[4];	/* Acknowledgement number */
	uint8_t		th_offset_and_rsrvd[1]; /* Offset to the packet data */
	uint8_t		th_flags[1];
	uint8_t		th_win[2];	/* Allocation number */
	uint8_t		th_sum[2];	/* TCP checksum */
	uint8_t		th_urp[2];	/* Urgent pointer */
} tcph_t;

#define	TCP_HDR_LENGTH(tcph) (((tcph)->th_offset_and_rsrvd[0] >>2) &(0xF << 2))
#define	TCP_MAX_COMBINED_HEADER_LENGTH	(60 + 60) /* Maxed out ip + tcp */
#define	TCP_MAX_IP_OPTIONS_LENGTH	(60 - IP_SIMPLE_HDR_LENGTH)
#define	TCP_MAX_HDR_LENGTH		60
#define	TCP_MAX_TCP_OPTIONS_LENGTH	(60 - sizeof (tcph_t))
#define	TCP_MIN_HEADER_LENGTH		20
#define	TCP_MAXWIN			65535
#define	TCP_PORT_LEN			sizeof (in_port_t)
#define	TCP_MAX_WINSHIFT		14
#define	TCP_MAX_LARGEWIN		(TCP_MAXWIN << TCP_MAX_WINSHIFT)

#define	TCPIP_HDR_LENGTH(mp, n)					\
	(n) = IPH_HDR_LENGTH((mp)->b_rptr),			\
	(n) += TCP_HDR_LENGTH((tcph_t *)&(mp)->b_rptr[(n)])

/* TCP Protocol header (used if the header is known to be 32-bit aligned) */
typedef	struct tcphdra_s {
	in_port_t	tha_lport;	/* Source port */
	in_port_t	tha_fport;	/* Destination port */
	uint32_t	tha_seq;	/* Sequence number */
	uint32_t	tha_ack;	/* Acknowledgement number */
	uint8_t tha_offset_and_reserved; /* Offset to the packet data */
	uint8_t		tha_flags;
	uint16_t	tha_win;	/* Allocation number */
	uint16_t	tha_sum;	/* TCP checksum */
	uint16_t	tha_urp;	/* Urgent pointer */
} tcpha_t;

typedef struct tcp_s {
	struct tcp_s *tcp_time_wait_next; /* Next TCP in TIME_WAIT list */
	struct tcp_s *tcp_time_wait_prev; /* Prev TCP in TIME_WAIT list */
	uint32_t tcp_max_swnd;		/* Maximum swnd we have seen */
	uint32_t tcp_suna;		/* Sender unacknowledged */
	uint32_t tcp_csuna;		/* Clear (no rexmits in window) suna */
	uint32_t tcp_snxt;		/* Senders next seq num */
	uint32_t tcp_swnd;		/* Senders window (relative to suna) */
	uint32_t tcp_mss;		/* Max segment size */
	uint32_t tcp_iss;		/* Initial send seq num */
	uint32_t tcp_rnxt;		/* Seq we expect to recv next */
	uint32_t tcp_rwnd;		/* Current receive window */
	uint32_t tcp_rwnd_max;		/* Max receive window */

	uint32_t tcp_irs;		/* Initial recv seq num */
	uint32_t tcp_fss;		/* Final/fin send seq num */

	uint32_t tcp_swl1;		/* These help us avoid using stale */
	uint32_t tcp_swl2;		/*  packets to update state */

	uint32_t tcp_cwnd;		/* Congestion window */
	int32_t tcp_cwnd_cnt;		/* cwnd cnt in congestion avoidance */
	uint32_t tcp_cwnd_ssthresh;	/* Congestion window */
	uint32_t tcp_cwnd_max;

	int32_t	tcp_snd_burst;		/* Send burst factor */

	int32_t	tcp_state;
	int32_t	tcp_rcv_ws;		/* My window scale power */
	int32_t	tcp_snd_ws;		/* Sender's window scale power */
	uint32_t tcp_ts_recent;	/* Timestamp of earliest unacked */
					/*  data segment */

	uint32_t	tcp_if_mtu;	/* Outgoing interface MTU. */

	uint32_t	tcp_rtt_sa;	/* Round trip smoothed average */
	uint32_t	tcp_rtt_sd;	/* Round trip smoothed deviation */
	uint32_t	tcp_rtt_update;		/* Round trip update(s) */
	uint32_t 	tcp_ms_we_have_waited;	/* Total retrans time */
	uint32_t	tcp_rto;	/* Round trip timeout */
	uint32_t	tcp_rto_timeout;	/* RTT timeout time */
	uint32_t	tcp_time_wait_expire;
				/* time in hz when t/w expires */
	uint32_t	tcp_last_rcv_lbolt;
				/* lbolt on last packet, used for PAWS */
	int	tcp_lingertime;		/* Close linger time (in seconds) */

	uint32_t	tcp_first_timer_threshold;  /* When to prod IP */
	uint32_t tcp_second_timer_threshold; /* When to give up completely */
	uint32_t tcp_first_ctimer_threshold; /* 1st threshold when connecting */
	uint32_t tcp_second_ctimer_threshold; /* 2nd ... while connecting */

	uint32_t tcp_rexmit_nxt;	/* Next rexmit seq num */
	uint32_t tcp_rexmit_max;	/* Max retran seq num */

	uint32_t tcp_naglim;		/* Tunable nagle limit */
	uint32_t	tcp_valid_bits;
#define	TCP_ISS_VALID	0x1	/* Is the tcp_iss seq num active? */
#define	TCP_FSS_VALID	0x2	/* Is the tcp_fss seq num active? */
#define	TCP_URG_VALID	0x4	/* Is the tcp_urg seq num active? */
#define	TCP_OFO_FIN_VALID 0x8	/* Has TCP received an out of order FIN? */

	int32_t	tcp_xmit_hiwater;	/* Send buffer high water mark. */
	int32_t	tcp_xmit_lowater;	/* Send buffer low water mark. */

	uchar_t	tcp_timer_backoff;	/* Backoff shift count. */
	uint32_t tcp_last_recv_time;	/* Last time we receive a segment. */

	/* Fields arranged in approximate access order along main paths */
	mblk_t	*tcp_xmit_head;		/* Head of rexmit list */
	mblk_t	*tcp_xmit_last;		/* last valid data seen by tcp_wput */
	uint32_t tcp_unsent;		/* # of bytes in hand that are unsent */
	mblk_t	*tcp_xmit_tail;		/* Last rexmit data sent */
	uint32_t tcp_xmit_tail_unsent;	/* # of unsent bytes in xmit_tail */
	mblk_t	*tcp_rcv_list;		/* Queued until push or exceed */
	mblk_t	*tcp_rcv_last_tail;	/* tcp_rcv_push_wait. */
	uint32_t tcp_rcv_cnt;		/* tcp_rcv_list is b_next chain. */

	uint32_t tcp_rack;		/* Seq # we have acked */
	uint32_t tcp_rack_cnt;		/* # of bytes we have deferred ack */

	mblk_t	*tcp_reass_head;	 /* Out of order reassembly list head */
	mblk_t	*tcp_reass_tail;	 /* Out of order reassembly list tail */

	tcp_sack_info_t	*tcp_sack_info;

#define	tcp_pipe	tcp_sack_info->tcp_pipe
#define	tcp_fack	tcp_sack_info->tcp_fack
#define	tcp_sack_snxt	tcp_sack_info->tcp_sack_snxt
#define	tcp_max_sack_blk	tcp_sack_info->tcp_max_sack_blk
#define	tcp_num_sack_blk	tcp_sack_info->tcp_num_sack_blk
#define	tcp_sack_list		tcp_sack_info->tcp_sack_list
#define	tcp_num_notsack_blk	tcp_sack_info->tcp_num_notsack_blk
#define	tcp_cnt_notsack_list	tcp_sack_info->tcp_cnt_notsack_list
#define	tcp_notsack_list		tcp_sack_info->tcp_notsack_list

	int tcp_conn_req_cnt_q0;	/* # of conn reqs in SYN_RCVD */
	int tcp_conn_req_cnt_q;	/* # of conn reqs in ESTABLISHED */
	int tcp_conn_req_max;	/* # of ESTABLISHED conn reqs allowed */

	int	tcp_iphc_len;		/* actual allocated buffer size */
	int32_t	tcp_hdr_len;		/* Byte len of combined TCP/IP hdr */
	struct ip	*tcp_ipha;	/* IPv4 header in the buffer */
	int	tcp_ip_hdr_len;		/* Byte len of our current IPvx hdr */
	tcph_t	*tcp_tcph;		/* tcp header within combined hdr */
	int32_t	tcp_tcp_hdr_len;	/* tcp header len within combined */

	uint16_t tcp_last_sent_len;	/* Record length for nagle */
	uint16_t tcp_dupack_cnt;	/* # of consequtive duplicate acks */

	/*
	 * Address family that app wishes returned addrsses to be in.
	 * Currently taken from address family used in T_BIND_REQ, but
	 * should really come from family used in original socket() call.
	 * Value can be AF_INET or AF_INET6.
	 */
	uint_t	tcp_family;

	uint32_t	tcp_ofo_fin_seq; /* Recv out of order FIN seq num */
	uint32_t	tcp_cwr_snd_max;

	uint32_t
		tcp_fin_acked : 1,	/* Has our FIN been acked? */
		tcp_fin_rcvd : 1,	/* Have we seen a FIN? */
		tcp_fin_sent : 1,	/* Have we sent our FIN yet? */
		tcp_useloopback : 1,	/* SO_USELOOPBACK "socket" option. */

		tcp_conn_def_q0: 1,	/* move from q0 to q deferred */
		tcp_zero_win_probe: 1,	/* Zero win probing is in progress */
		tcp_set_timer : 1,
		tcp_active_open: 1,	/* This is a active open */

		tcp_timer_running: 1,	/* Retransmission timer running */
		tcp_rexmit : 1,		/* TCP is retransmitting */
		tcp_snd_sack_ok : 1,	/* Can use SACK for this connection */
		tcp_ecn_ok : 1,		/* Can use ECN for this connection */

		tcp_ecn_echo_on : 1,	/* Need to do ECN echo */
		tcp_ecn_cwr_sent : 1,	/* ECN_CWR has been sent */
		tcp_cwr : 1,		/* Cwnd has reduced recently */
		tcp_snd_ts_ok  : 1,

		tcp_snd_ws_ok  : 1,
		tcp_linger : 1,
		tcp_dontdrop : 1,
		tcp_junk_fill_thru_bit_31 : 13;

	char	*tcp_iphc;		/* Buffer holding tcp/ip hdr template */

	in_addr_t	tcp_remote;	/* true remote address - needed for */
					/* source routing. */
	in_addr_t	tcp_bound_source;	/* IP address in bind_req */
	/*
	 * These fields contain the same information as tcp_tcph->th_*port.
	 * However, the lookup functions can not use the header fields
	 * since during IP option manipulation the tcp_tcph pointer
	 * changes.
	 */
	union {
		struct {
			in_port_t	tcpu_fport;	/* Remote port */
			in_port_t	tcpu_lport;	/* Local port */
		} tcpu_ports1;
		uint32_t		tcpu_ports2;	/* Rem port, */
							/* local port */
					/* Used for TCP_MATCH performance */
	} tcp_tcpu;
#define	tcp_fport	tcp_tcpu.tcpu_ports1.tcpu_fport
#define	tcp_lport	tcp_tcpu.tcpu_ports1.tcpu_lport
#define	tcp_ports	tcp_tcpu.tcpu_ports2
	/*
	 * IP format that packets transmitted from this struct should use.
	 * Value can be IPV4_VERSION or IPV6_VERSION.  Determines whether
	 * IP+TCP header template above stores an IPv4 or IPv6 header.
	 */
	ushort_t	tcp_ipversion;
	int		tcp_client_errno;
	struct tcp_s *tcp_eager_next_q; /* next eager in ESTABLISHED state */
	struct tcp_s *tcp_eager_last_q;	/* last eager in ESTABLISHED state */
	struct tcp_s *tcp_eager_next_q0; /* next eager in SYN_RCVD state */
	struct tcp_s *tcp_eager_prev_q0; /* prev eager in SYN_RCVD state */
	struct tcp_s *tcp_listener;	/* Our listener */
} tcp_t;

/* External TCP functions. */
extern void tcp_socket_init(struct inetboot_socket *);
extern int tcp_connect(int);
extern int tcp_listen(int, int);
extern int tcp_bind(int);
extern int tcp_send(int, tcp_t *, const void *, int);
extern int tcp_opt_set(tcp_t *, int, int, const void *, socklen_t);
extern int tcp_accept(int, struct sockaddr *, socklen_t *);
extern int tcp_shutdown(int);

/* Exported for recvfrom */
extern void tcp_rcv_drain_sock(int);

/* Exported for stand/lib/sock/sock_test.c */
extern void tcp_time_wait_report(void);

#ifdef	__cplusplus
}
#endif

#endif /* _TCP_INET_H */
