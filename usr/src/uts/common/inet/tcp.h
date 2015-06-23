/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 1991, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2011, Joyent, Inc. All rights reserved.
 * Copyright (c) 2011 Nexenta Systems, Inc. All rights reserved.
 * Copyright (c) 2014 by Delphix. All rights reserved.
 */
/* Copyright (c) 1990 Mentat Inc. */

#ifndef	_INET_TCP_H
#define	_INET_TCP_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/inttypes.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/socket_proto.h>
#include <sys/md5.h>
#include <inet/common.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/mi.h>
#include <inet/mib2.h>
#include <inet/tcp_stack.h>
#include <inet/tcp_sack.h>

/* TCP states */
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
 * Used in tcp_input_data to keep track of what needs to be done.
 */
#define	TH_LIMIT_XMIT		0x0400	/* Limited xmit is needed */
#define	TH_XMIT_NEEDED		0x0800	/* Window opened - send queued data */
#define	TH_REXMIT_NEEDED	0x1000	/* Time expired for unacked data */
#define	TH_ACK_NEEDED		0x2000	/* Send an ack now. */
#define	TH_NEED_SACK_REXMIT	0x4000	/* Use SACK info to retransmission */
#define	TH_ACK_TIMER_NEEDED	0x8000	/* Start the delayed ACK timer */
#define	TH_ORDREL_NEEDED	0x10000	/* Generate an ordrel indication */
#define	TH_MARKNEXT_NEEDED	0x20000	/* Data should have MSGMARKNEXT */
#define	TH_SEND_URP_MARK	0x40000	/* Send up tcp_urp_mark_mp */

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

#define	TCP_HDR_LENGTH(tcph) \
	((((tcph_t *)tcph)->th_offset_and_rsrvd[0] >>2) &(0xF << 2))
#define	TCP_MAX_COMBINED_HEADER_LENGTH	(60 + 60) /* Maxed out ip + tcp */
#define	TCP_MAX_IP_OPTIONS_LENGTH	(60 - IP_SIMPLE_HDR_LENGTH)
#define	TCP_MAX_HDR_LENGTH		60
#define	TCP_MAX_TCP_OPTIONS_LENGTH	(60 - sizeof (tcpha_t))
#define	TCP_MIN_HEADER_LENGTH		20
#define	TCP_MAXWIN			65535
#define	TCP_PORT_LEN			sizeof (in_port_t)
#define	TCP_MAX_WINSHIFT		14
#define	TCP_MAX_LARGEWIN		(TCP_MAXWIN << TCP_MAX_WINSHIFT)
#define	TCP_MAX_LSO_LENGTH	(IP_MAXPACKET - TCP_MAX_COMBINED_HEADER_LENGTH)

#define	TCPIP_HDR_LENGTH(mp, n)					\
	(n) = IPH_HDR_LENGTH((mp)->b_rptr),			\
	(n) += TCP_HDR_LENGTH((tcpha_t *)&(mp)->b_rptr[(n)])

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

struct conn_s;
struct tcp_listen_cnt_s;

/*
 * Control structure for each open TCP stream,
 * defined only within the kernel or for a kmem user.
 * NOTE: tcp_reinit_values MUST have a line for each field in this structure!
 */
#if (defined(_KERNEL) || defined(_KMEMUSER))

typedef struct tcp_s {
	struct tcp_s	*tcp_time_wait_next;
				/* Pointer to next T/W block */
	struct tcp_s	*tcp_time_wait_prev;
				/* Pointer to previous T/W next */
	int64_t		tcp_time_wait_expire;

	struct conn_s	*tcp_connp;	/* back pointer to conn_t */
	tcp_stack_t	*tcp_tcps;	/* back pointer to tcp_stack_t */

	int32_t	tcp_state;
	int32_t	tcp_rcv_ws;		/* My window scale power */
	int32_t	tcp_snd_ws;		/* Sender's window scale power */
	uint32_t tcp_ts_recent;		/* Timestamp of earliest unacked */
					/*  data segment */
	clock_t	tcp_rto;		/* Round trip timeout */
	int64_t	tcp_last_rcv_lbolt;
				/* lbolt on last packet, used for PAWS */
	uint32_t tcp_rto_initial;	/* Initial RTO */
	uint32_t tcp_rto_min;		/* Minimum RTO */
	uint32_t tcp_rto_max;		/* Maximum RTO */

	uint32_t tcp_snxt;		/* Senders next seq num */
	uint32_t tcp_swnd;		/* Senders window (relative to suna) */
	uint32_t tcp_mss;		/* Max segment size */
	uint32_t tcp_iss;		/* Initial send seq num */
	uint32_t tcp_rnxt;		/* Seq we expect to recv next */
	uint32_t tcp_rwnd;

	/* Fields arranged in approximate access order along main paths */
	mblk_t	*tcp_xmit_head;		/* Head of xmit/rexmit list */
	mblk_t	*tcp_xmit_last;		/* Last valid data seen by tcp_wput */
	mblk_t	*tcp_xmit_tail;		/* Last data sent */
	uint32_t tcp_unsent;		/* # of bytes in hand that are unsent */
	uint32_t tcp_xmit_tail_unsent;	/* # of unsent bytes in xmit_tail */

	uint32_t tcp_suna;		/* Sender unacknowledged */
	uint32_t tcp_rexmit_nxt;	/* Next rexmit seq num */
	uint32_t tcp_rexmit_max;	/* Max retran seq num */
	uint32_t tcp_cwnd;		/* Congestion window */
	int32_t tcp_cwnd_cnt;		/* cwnd cnt in congestion avoidance */

	uint32_t tcp_ibsegs;		/* Inbound segments on this stream */
	uint32_t tcp_obsegs;		/* Outbound segments on this stream */

	uint32_t tcp_naglim;		/* Tunable nagle limit */
	uint32_t	tcp_valid_bits;
#define	TCP_ISS_VALID	0x1	/* Is the tcp_iss seq num active? */
#define	TCP_FSS_VALID	0x2	/* Is the tcp_fss seq num active? */
#define	TCP_URG_VALID	0x4	/* Is the tcp_urg seq num active? */
#define	TCP_OFO_FIN_VALID 0x8	/* Has TCP received an out of order FIN? */



	timeout_id_t	tcp_timer_tid;	/* Control block for timer service */
	uchar_t	tcp_timer_backoff;	/* Backoff shift count. */
	int64_t tcp_last_recv_time;	/* Last time we receive a segment. */
	uint32_t tcp_init_cwnd;		/* Initial cwnd (start/restart) */

	/* Following manipulated by TCP under squeue protection */
	uint32_t
		tcp_urp_last_valid : 1,	/* Is tcp_urp_last valid? */
		tcp_hard_binding : 1,	/* TCP_DETACHED_NONEAGER */
		tcp_fin_acked : 1,	/* Has our FIN been acked? */
		tcp_fin_rcvd : 1,	/* Have we seen a FIN? */

		tcp_fin_sent : 1,	/* Have we sent our FIN yet? */
		tcp_ordrel_done : 1,	/* Have we sent the ord_rel upstream? */
		tcp_detached : 1,	/* If we're detached from a stream */
		tcp_zero_win_probe: 1,	/* Zero win probing is in progress */

		tcp_loopback: 1,	/* src and dst are the same machine */
		tcp_localnet: 1,	/* src and dst are on the same subnet */
		tcp_syn_defense: 1,	/* For defense against SYN attack */
#define	tcp_dontdrop	tcp_syn_defense
		tcp_set_timer : 1,

		tcp_active_open: 1,	/* This is a active open */
		tcp_rexmit : 1,		/* TCP is retransmitting */
		tcp_snd_sack_ok : 1,	/* Can use SACK for this connection */
		tcp_hwcksum : 1,	/* The NIC is capable of hwcksum */

		tcp_ip_forward_progress : 1,
		tcp_ecn_ok : 1,		/* Can use ECN for this connection */
		tcp_ecn_echo_on : 1,	/* Need to do ECN echo */
		tcp_ecn_cwr_sent : 1,	/* ECN_CWR has been sent */

		tcp_cwr : 1,		/* Cwnd has reduced recently */

		tcp_pad_to_bit31 : 11;

	/* Following manipulated by TCP under squeue protection */
	uint32_t
		tcp_snd_ts_ok  : 1,
		tcp_snd_ws_ok  : 1,
		tcp_reserved_port : 1,
		tcp_in_free_list : 1,

		tcp_snd_zcopy_on : 1,	/* xmit zero-copy enabled */
		tcp_snd_zcopy_aware : 1, /* client is zero-copy aware */
		tcp_xmit_zc_clean : 1,	/* the xmit list is free of zc-mblk */
		tcp_wait_for_eagers : 1, /* Wait for eagers to disappear */

		tcp_accept_error : 1,	/* Error during TLI accept */
		tcp_send_discon_ind : 1, /* TLI accept err, send discon ind */
		tcp_cork : 1,		/* tcp_cork option */
		tcp_tconnind_started : 1, /* conn_ind message is being sent */

		tcp_lso :1,		/* Lower layer is capable of LSO */
		tcp_is_wnd_shrnk : 1,	/* Window has shrunk */

		tcp_pad_to_bit_31 : 18;

	uint32_t	tcp_initial_pmtu; /* Initial outgoing Path MTU. */

	mblk_t	*tcp_reass_head;	/* Out of order reassembly list head */
	mblk_t	*tcp_reass_tail;	/* Out of order reassembly list tail */

	/* SACK related info */
	tcp_sack_info_t	tcp_sack_info;

#define	tcp_pipe		tcp_sack_info.tcp_pipe
#define	tcp_fack		tcp_sack_info.tcp_fack
#define	tcp_sack_snxt		tcp_sack_info.tcp_sack_snxt
#define	tcp_max_sack_blk	tcp_sack_info.tcp_max_sack_blk
#define	tcp_num_sack_blk	tcp_sack_info.tcp_num_sack_blk
#define	tcp_sack_list		tcp_sack_info.tcp_sack_list
#define	tcp_num_notsack_blk	tcp_sack_info.tcp_num_notsack_blk
#define	tcp_cnt_notsack_list	tcp_sack_info.tcp_cnt_notsack_list
#define	tcp_notsack_list	tcp_sack_info.tcp_notsack_list

	mblk_t	*tcp_rcv_list;		/* Queued until push, urgent data, */
	mblk_t	*tcp_rcv_last_head;	/* optdata, or the count exceeds */
	mblk_t	*tcp_rcv_last_tail;	/* tcp_rcv_push_wait. */
	uint32_t tcp_rcv_cnt;		/* tcp_rcv_list is b_next chain. */

	uint32_t tcp_cwnd_ssthresh;	/* Congestion window */
	uint32_t tcp_cwnd_max;
	uint32_t tcp_csuna;		/* Clear (no rexmits in window) suna */

	clock_t	tcp_rtt_sa;		/* Round trip smoothed average */
	clock_t	tcp_rtt_sd;		/* Round trip smoothed deviation */
	clock_t	tcp_rtt_update;		/* Round trip update(s) */
	clock_t tcp_ms_we_have_waited;	/* Total retrans time */

	uint32_t tcp_swl1;		/* These help us avoid using stale */
	uint32_t tcp_swl2;		/*  packets to update state */

	uint32_t tcp_rack;		/* Seq # we have acked */
	uint32_t tcp_rack_cnt;		/* # of segs we have deferred ack */
	uint32_t tcp_rack_cur_max;	/* # of segs we may defer ack for now */
	uint32_t tcp_rack_abs_max;	/* # of segs we may defer ack ever */
	timeout_id_t	tcp_ack_tid;	/* Delayed ACK timer ID */
	timeout_id_t	tcp_push_tid;	/* Push timer ID */

	uint32_t tcp_max_swnd;		/* Maximum swnd we have seen */

	struct tcp_s *tcp_listener;	/* Our listener */

	uint32_t tcp_irs;		/* Initial recv seq num */
	uint32_t tcp_fss;		/* Final/fin send seq num */
	uint32_t tcp_urg;		/* Urgent data seq num */

	clock_t	tcp_first_timer_threshold;  /* When to prod IP */
	clock_t	tcp_second_timer_threshold; /* When to give up completely */
	clock_t	tcp_first_ctimer_threshold; /* 1st threshold while connecting */
	clock_t tcp_second_ctimer_threshold; /* 2nd ... while connecting */

	uint32_t tcp_urp_last;		/* Last urp for which signal sent */
	mblk_t	*tcp_urp_mp;		/* T_EXDATA_IND for urgent byte */
	mblk_t	*tcp_urp_mark_mp;	/* zero-length marked/unmarked msg */

	int tcp_conn_req_cnt_q0;	/* # of conn reqs in SYN_RCVD */
	int tcp_conn_req_cnt_q;	/* # of conn reqs in ESTABLISHED */
	int tcp_conn_req_max;	/* # of ESTABLISHED conn reqs allowed */
	t_scalar_t tcp_conn_req_seqnum;	/* Incrementing pending conn req ID */
#define	tcp_ip_addr_cache	tcp_reass_tail
					/* Cache ip addresses that */
					/* complete the 3-way handshake */
	kmutex_t  tcp_eager_lock;
	struct tcp_s *tcp_eager_next_q; /* next eager in ESTABLISHED state */
	struct tcp_s *tcp_eager_last_q;	/* last eager in ESTABLISHED state */
	struct tcp_s *tcp_eager_next_q0; /* next eager in SYN_RCVD state */
	struct tcp_s *tcp_eager_prev_q0; /* prev eager in SYN_RCVD state */
					/* all eagers form a circular list */
	boolean_t tcp_conn_def_q0;	/* move from q0 to q deferred */

	union {
	    mblk_t *tcp_eager_conn_ind; /* T_CONN_IND waiting for 3rd ack. */
	    mblk_t *tcp_opts_conn_req; /* T_CONN_REQ w/ options processed */
	} tcp_conn;
	uint32_t tcp_syn_rcvd_timeout;	/* How many SYN_RCVD timeout in q0 */

	/*
	 * TCP Keepalive Timer members.
	 * All keepalive timer intervals are in milliseconds.
	 */
	int32_t	tcp_ka_last_intrvl;	/* Last probe interval */
	timeout_id_t tcp_ka_tid;	/* Keepalive timer ID */
	uint32_t tcp_ka_interval;	/* Keepalive interval */

	/*
	 * TCP connection is terminated if we don't hear back from the peer
	 * for tcp_ka_abort_thres milliseconds after the first keepalive probe.
	 * tcp_ka_rinterval is the interval in milliseconds between successive
	 * keepalive probes. tcp_ka_cnt is the number of keepalive probes to
	 * be sent before terminating the connection, if we don't hear back from
	 * peer.
	 * tcp_ka_abort_thres = tcp_ka_rinterval * tcp_ka_cnt
	 */
	uint32_t tcp_ka_rinterval;	/* keepalive retransmit interval */
	uint32_t tcp_ka_abort_thres;	/* Keepalive abort threshold */
	uint32_t tcp_ka_cnt;		/* count of keepalive probes */

	int32_t	tcp_client_errno;	/* How the client screwed up */

	/*
	 * The header template lives in conn_ht_iphc allocated by tcp_build_hdrs
	 * We maintain three pointers into conn_ht_iphc.
	 */
	ipha_t	*tcp_ipha;		/* IPv4 header in conn_ht_iphc */
	ip6_t	*tcp_ip6h;		/* IPv6 header in conn_ht_iphc */
	tcpha_t	*tcp_tcpha;		/* TCP header in conn_ht_iphc */

	uint16_t tcp_last_sent_len;	/* Record length for nagle */
	uint16_t tcp_last_recv_len;	/* Used by DTrace */
	uint16_t tcp_dupack_cnt;	/* # of consequtive duplicate acks */

	kmutex_t	*tcp_acceptor_lockp;	/* Ptr to tf_lock */

	mblk_t		*tcp_ordrel_mp;		/* T_ordrel_ind mblk */
	t_uscalar_t	tcp_acceptor_id;	/* ACCEPTOR_id */

	int		tcp_ipsec_overhead;

	uint_t		tcp_recvifindex; /* Last received IPV6_RCVPKTINFO */
	uint_t		tcp_recvhops;	/* Last received IPV6_RECVHOPLIMIT */
	uint_t		tcp_recvtclass;	/* Last received IPV6_RECVTCLASS */
	ip6_hbh_t	*tcp_hopopts;	/* Last received IPV6_RECVHOPOPTS */
	ip6_dest_t	*tcp_dstopts;	/* Last received IPV6_RECVDSTOPTS */
	ip6_dest_t	*tcp_rthdrdstopts; /* Last recv IPV6_RECVRTHDRDSTOPTS */
	ip6_rthdr_t	*tcp_rthdr;	/* Last received IPV6_RECVRTHDR */
	uint_t		tcp_hopoptslen;
	uint_t		tcp_dstoptslen;
	uint_t		tcp_rthdrdstoptslen;
	uint_t		tcp_rthdrlen;

	mblk_t		*tcp_timercache;

	kmutex_t	tcp_closelock;
	kcondvar_t	tcp_closecv;
	uint8_t		tcp_closed;
	uint8_t		tcp_closeflags;
	mblk_t		tcp_closemp;
	timeout_id_t	tcp_linger_tid;	/* Linger timer ID */

	struct tcp_s *tcp_acceptor_hash; /* Acceptor hash chain */
	struct tcp_s **tcp_ptpahn; /* Pointer to previous accept hash next. */
	struct tcp_s *tcp_bind_hash; /* Bind hash chain */
	struct tcp_s *tcp_bind_hash_port; /* tcp_t's bound to the same lport */
	struct tcp_s **tcp_ptpbhn;

	uint_t		tcp_maxpsz_multiplier;

	uint32_t	tcp_lso_max; /* maximum LSO payload */

	uint32_t	tcp_ofo_fin_seq; /* Recv out of order FIN seq num */
	uint32_t	tcp_cwr_snd_max;

	struct tcp_s *tcp_saved_listener;	/* saved value of listener */

	uint32_t	tcp_in_ack_unsent;	/* ACK for unsent data cnt. */

	/*
	 * All fusion-related fields are protected by squeue.
	 */
	struct tcp_s *tcp_loopback_peer;	/* peer tcp for loopback */
	mblk_t	*tcp_fused_sigurg_mp;		/* M_PCSIG mblk for SIGURG */

	uint32_t
		tcp_fused : 1,		/* loopback tcp in fusion mode */
		tcp_unfusable : 1,	/* fusion not allowed on endpoint */
		tcp_fused_sigurg : 1,	/* send SIGURG upon draining */

		tcp_fuse_to_bit_31 : 29;

	kmutex_t tcp_non_sq_lock;

	/*
	 * This variable is accessed without any lock protection
	 * and therefore must not be declared as a bit field along
	 * with the rest which require such condition.
	 */
	boolean_t	tcp_issocket;	/* this is a socket tcp */

	/* protected by the tcp_non_sq_lock lock */
	uint32_t	tcp_squeue_bytes;

	/*
	 * tcp_closemp_used is protected by listener's tcp_eager_lock
	 * when used for eagers. When used for a tcp in TIME_WAIT state
	 * or in tcp_close(), it is not protected by any lock as we
	 * do not expect any other thread to use it concurrently.
	 * We do allow re-use of tcp_closemp in tcp_time_wait_collector()
	 * and tcp_close() but not concurrently.
	 */
	boolean_t tcp_closemp_used;

	/*
	 * previous and next eagers in the list of droppable eagers. See
	 * the comments before MAKE_DROPPABLE(). These pointers are
	 * protected by listener's tcp_eager_lock.
	 */
	struct tcp_s	*tcp_eager_prev_drop_q0;
	struct tcp_s	*tcp_eager_next_drop_q0;

	/*
	 * Have we flow controlled xmitter?
	 * This variable can be modified outside the squeue and hence must
	 * not be declared as a bit field along with the rest that are
	 * modified only within the squeue.
	 * protected by the tcp_non_sq_lock lock.
	 */
	boolean_t	tcp_flow_stopped;

	/*
	 * Sender's next sequence number at the time the window was shrunk.
	 */
	uint32_t	tcp_snxt_shrunk;

	/*
	 * Socket generation number which is bumped when a connection attempt
	 * is initiated. Its main purpose is to ensure that the socket does not
	 * miss the asynchronous connected/disconnected notification.
	 */
	sock_connid_t	tcp_connid;

	/* mblk_t used to enter TCP's squeue from the service routine. */
	mblk_t		*tcp_rsrv_mp;
	/* Mutex for accessing tcp_rsrv_mp */
	kmutex_t	tcp_rsrv_mp_lock;

	/* For connection counting. */
	struct tcp_listen_cnt_s	*tcp_listen_cnt;

	/* Segment reassembly timer. */
	timeout_id_t		tcp_reass_tid;

	/* FIN-WAIT-2 flush timeout */
	uint32_t		tcp_fin_wait_2_flush_interval;

#ifdef DEBUG
	pc_t			tcmp_stk[15];
#endif
} tcp_t;

#ifdef DEBUG
#define	TCP_DEBUG_GETPCSTACK(buffer, depth)	((void) getpcstack(buffer, \
						    depth))
#else
#define	TCP_DEBUG_GETPCSTACK(buffer, depth)
#endif

extern void	tcp_conn_reclaim(void *);
extern void 	tcp_free(tcp_t *tcp);
extern void	tcp_ddi_g_init(void);
extern void	tcp_ddi_g_destroy(void);
extern void 	*tcp_get_conn(void *arg, tcp_stack_t *);
extern mblk_t	*tcp_snmp_get(queue_t *, mblk_t *, boolean_t);
extern int	tcp_snmp_set(queue_t *, int, int, uchar_t *, int len);

/* Pad for the tf_t structure to avoid false cache line sharing. */
#define	TF_CACHEL_PAD	64

/*
 * The TCP Fanout structure for bind and acceptor hashes.
 * The hash tables and their linkage (tcp_*_hash, tcp_ptp*hn) are
 * protected by the per-bucket tf_lock.  Each tcp_t
 * inserted in the list points back at this lock using tcp_*_lockp.
 *
 * The bind and acceptor hash queues are lists of tcp_t.
 */
/* listener hash and acceptor hash queue head */
typedef struct tf_s {
	tcp_t		*tf_tcp;
	kmutex_t	tf_lock;
	unsigned char	tf_pad[TF_CACHEL_PAD -
	    (sizeof (tcp_t *) + sizeof (kmutex_t))];
} tf_t;


/* Also used in ipclassifier.c */
extern struct kmem_cache  *tcp_sack_info_cache;

#endif	/* (defined(_KERNEL) || defined(_KMEMUSER)) */

/* Contract private interface between TCP and Clustering. */

#define	CL_TCPI_V1	1	/* cl_tcpi_version number */

typedef struct cl_tcp_info_s {
	ushort_t	cl_tcpi_version;	/* cl_tcp_info_t's version no */
	ushort_t	cl_tcpi_ipversion;	/* IP version */
	int32_t		cl_tcpi_state;		/* TCP state */
	in_port_t	cl_tcpi_lport;		/* Local port */
	in_port_t	cl_tcpi_fport;		/* Remote port */
	in6_addr_t	cl_tcpi_laddr_v6;	/* Local IP address */
	in6_addr_t	cl_tcpi_faddr_v6;	/* Remote IP address */
#ifdef _KERNEL
/* Note: V4_PART_OF_V6 is meant to be used only for _KERNEL defined stuff */
#define	cl_tcpi_laddr	V4_PART_OF_V6(cl_tcpi_laddr_v6)
#define	cl_tcpi_faddr	V4_PART_OF_V6(cl_tcpi_faddr_v6)

#endif	/* _KERNEL */
} cl_tcp_info_t;

/*
 * Hook functions to enable cluster networking
 * On non-clustered systems these vectors must always be NULL.
 */
extern void	(*cl_inet_listen)(netstackid_t, uint8_t, sa_family_t,
		    uint8_t *, in_port_t, void *);
extern void	(*cl_inet_unlisten)(netstackid_t, uint8_t, sa_family_t,
		    uint8_t *, in_port_t, void *);

/*
 * Contracted Consolidation Private ioctl for aborting TCP connections.
 * In order to keep the offsets and size of the structure the same between
 * a 32-bit application and a 64-bit amd64 kernel, we use a #pragma
 * pack(4).
 */
#define	TCP_IOC_ABORT_CONN	(('T' << 8) + 91)

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack(4)
#endif

typedef struct tcp_ioc_abort_conn_s {
	struct sockaddr_storage ac_local;	/* local addr and port */
	struct sockaddr_storage ac_remote;	/* remote addr and port */
	int32_t ac_start;			/* start state */
	int32_t ac_end;				/* end state  */
	int32_t ac_zoneid;			/* zoneid */
} tcp_ioc_abort_conn_t;

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack()
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_TCP_H */
