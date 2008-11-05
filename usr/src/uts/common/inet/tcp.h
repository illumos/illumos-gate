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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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
#include <sys/sodirect.h>
#include <sys/multidata.h>
#include <sys/md5.h>
#include <inet/common.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/mi.h>
#include <inet/mib2.h>
#include <inet/tcp_stack.h>
#include <inet/tcp_sack.h>
#include <inet/kssl/ksslapi.h>

/*
 * Private (and possibly temporary) ioctl used by configuration code
 * to lock in the "default" stream for detached closes.
 */
#define	TCP_IOC_DEFAULT_Q	(('T' << 8) + 51)

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
 * Used in tcp_rput_data to keep track of what needs to be done.
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
#define	TCP_MAX_LSO_LENGTH	(IP_MAXPACKET - TCP_MAX_COMBINED_HEADER_LENGTH)

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

struct conn_s;

/*
 * Control structure for each open TCP stream,
 * defined only within the kernel or for a kmem user.
 * NOTE: tcp_reinit_values MUST have a line for each field in this structure!
 */
#if (defined(_KERNEL) || defined(_KMEMUSER))

typedef struct tcp_s {
				/* Pointer to previous bind hash next. */
	struct tcp_s	*tcp_time_wait_next;
				/* Pointer to next T/W block */
	struct tcp_s	*tcp_time_wait_prev;
				/* Pointer to previous T/W next */
	clock_t		tcp_time_wait_expire;

	struct conn_s	*tcp_connp;
	tcp_stack_t	*tcp_tcps;	/* Shortcut via conn_netstack */

	int32_t	tcp_state;
	int32_t	tcp_rcv_ws;		/* My window scale power */
	int32_t	tcp_snd_ws;		/* Sender's window scale power */
	uint32_t tcp_ts_recent;		/* Timestamp of earliest unacked */
					/*  data segment */
	clock_t	tcp_rto;		/* Round trip timeout */
	clock_t	tcp_last_rcv_lbolt;
				/* lbolt on last packet, used for PAWS */

	uint32_t tcp_snxt;		/* Senders next seq num */
	uint32_t tcp_swnd;		/* Senders window (relative to suna) */
	uint32_t tcp_mss;		/* Max segment size */
	uint32_t tcp_iss;		/* Initial send seq num */
	uint32_t tcp_rnxt;		/* Seq we expect to recv next */
	uint32_t tcp_rwnd;

	queue_t	*tcp_rq;		/* Our upstream neighbor (client) */
	queue_t	*tcp_wq;		/* Our downstream neighbor */

	/* Fields arranged in approximate access order along main paths */
	mblk_t	*tcp_xmit_head;		/* Head of rexmit list */
	mblk_t	*tcp_xmit_last;		/* last valid data seen by tcp_wput */
	mblk_t	*tcp_xmit_tail;		/* Last rexmit data sent */
	uint32_t tcp_unsent;		/* # of bytes in hand that are unsent */
	uint32_t tcp_xmit_tail_unsent;	/* # of unsent bytes in xmit_tail */

	uint32_t tcp_suna;		/* Sender unacknowledged */
	uint32_t tcp_rexmit_nxt;	/* Next rexmit seq num */
	uint32_t tcp_rexmit_max;	/* Max retran seq num */
	int32_t	tcp_snd_burst;		/* Send burst factor */
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


	int32_t	tcp_xmit_hiwater;	/* Send buffer high water mark. */

	timeout_id_t	tcp_timer_tid;	/* Control block for timer service */
	uchar_t	tcp_timer_backoff;	/* Backoff shift count. */
	int64_t tcp_last_recv_time;	/* Last time we receive a segment. */
	uint32_t tcp_init_cwnd;		/* Initial cwnd (start/restart) */

	/*
	 * Following socket options are set by sockfs outside the squeue
	 * and we want to separate these bit fields from the other bit fields
	 * set by TCP to avoid grabbing locks. sockfs ensures that only one
	 * thread in sockfs can set a socket option at a time on a conn_t.
	 * However TCP may read these options concurrently. The linger option
	 * needs atomicity since tcp_lingertime also needs to be in sync.
	 * However TCP uses it only during close, and by then no socket option
	 * can come down. So we don't need any locks, instead just separating
	 * the sockfs settable bit fields from the other bit fields is
	 * sufficient.
	 */
	uint32_t
		tcp_debug : 1,		/* SO_DEBUG "socket" option. */
		tcp_dontroute : 1,	/* SO_DONTROUTE "socket" option. */
		tcp_broadcast : 1,	/* SO_BROADCAST "socket" option. */
		tcp_useloopback : 1,	/* SO_USELOOPBACK "socket" option. */

		tcp_oobinline : 1,	/* SO_OOBINLINE "socket" option. */
		tcp_dgram_errind : 1,	/* SO_DGRAM_ERRIND option */
		tcp_linger : 1,		/* SO_LINGER turned on */
		tcp_reuseaddr	: 1,	/* SO_REUSEADDR "socket" option. */

		tcp_junk_to_bit_31 : 24;

	/* Following manipulated by TCP under squeue protection */
	uint32_t
		tcp_urp_last_valid : 1,	/* Is tcp_urp_last valid? */
		tcp_hard_binding : 1,	/* If we've started a full bind */
		tcp_hard_bound : 1,	/* If we've done a full bind with IP */
		tcp_fin_acked : 1,	/* Has our FIN been acked? */

		tcp_fin_rcvd : 1,	/* Have we seen a FIN? */
		tcp_fin_sent : 1,	/* Have we sent our FIN yet? */
		tcp_ordrel_done : 1,	/* Have we sent the ord_rel upstream? */
		tcp_detached : 1,	/* If we're detached from a stream */

		tcp_bind_pending : 1,	/* Client is waiting for bind ack */
		tcp_unbind_pending : 1, /* Client sent T_UNBIND_REQ */
		tcp_ka_enabled: 1,	/* Connection KeepAlive Timer needed */
		tcp_zero_win_probe: 1,	/* Zero win probing is in progress */

		tcp_loopback: 1,	/* src and dst are the same machine */
		tcp_localnet: 1,	/* src and dst are on the same subnet */
		tcp_syn_defense: 1,	/* For defense against SYN attack */
#define	tcp_dontdrop	tcp_syn_defense
		tcp_set_timer : 1,

		tcp_active_open: 1,	/* This is a active open */
		tcp_rexmit : 1,		/* TCP is retransmitting */
		tcp_snd_sack_ok : 1,	/* Can use SACK for this connection */
		tcp_empty_flag : 1,	/* Empty flag for future use */

		tcp_recvdstaddr : 1,	/* return T_EXTCONN_IND with dst addr */
		tcp_hwcksum : 1,	/* The NIC is capable of hwcksum */
		tcp_ip_forward_progress : 1,
		tcp_anon_priv_bind : 1,

		tcp_ecn_ok : 1,		/* Can use ECN for this connection */
		tcp_ecn_echo_on : 1,	/* Need to do ECN echo */
		tcp_ecn_cwr_sent : 1,	/* ECN_CWR has been sent */
		tcp_cwr : 1,		/* Cwnd has reduced recently */

		tcp_pad_to_bit31 : 4;
	/* Following manipulated by TCP under squeue protection */
	uint32_t
		tcp_mdt : 1,		/* Lower layer is capable of MDT */
		tcp_snd_ts_ok  : 1,
		tcp_snd_ws_ok  : 1,
		tcp_exclbind	: 1,	/* ``exclusive'' binding */

		tcp_hdr_grown	: 1,
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
		tcp_pad_to_bit_31 : 17;

	uint32_t	tcp_if_mtu;	/* Outgoing interface MTU. */

	mblk_t	*tcp_reass_head;	/* Out of order reassembly list head */
	mblk_t	*tcp_reass_tail;	/* Out of order reassembly list tail */

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

	int32_t	tcp_xmit_lowater;	/* Send buffer low water mark. */

	uint32_t tcp_irs;		/* Initial recv seq num */
	uint32_t tcp_fss;		/* Final/fin send seq num */
	uint32_t tcp_urg;		/* Urgent data seq num */

	clock_t	tcp_first_timer_threshold;  /* When to prod IP */
	clock_t	tcp_second_timer_threshold; /* When to give up completely */
	clock_t	tcp_first_ctimer_threshold; /* 1st threshold while connecting */
	clock_t tcp_second_ctimer_threshold; /* 2nd ... while connecting */

	int	tcp_lingertime;		/* Close linger time (in seconds) */

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

	/* TCP Keepalive Timer members */
	int32_t	tcp_ka_last_intrvl;	/* Last probe interval */
	timeout_id_t tcp_ka_tid;	/* Keepalive timer ID */
	uint32_t tcp_ka_interval;	/* Keepalive interval */
	uint32_t tcp_ka_abort_thres;	/* Keepalive abort threshold */

	int32_t	tcp_client_errno;	/* How the client screwed up */

	char	*tcp_iphc;		/* Buffer holding tcp/ip hdr template */
	int	tcp_iphc_len;		/* actual allocated buffer size */
	int32_t	tcp_hdr_len;		/* Byte len of combined TCP/IP hdr */
	ipha_t	*tcp_ipha;		/* IPv4 header in the buffer */
	ip6_t	*tcp_ip6h;		/* IPv6 header in the buffer */
	int	tcp_ip_hdr_len;		/* Byte len of our current IPvx hdr */
	tcph_t	*tcp_tcph;		/* tcp header within combined hdr */
	int32_t	tcp_tcp_hdr_len;	/* tcp header len within combined */

	uint32_t tcp_sum;		/* checksum to compensate for source */
					/* routed packets. Host byte order */
	uint16_t tcp_last_sent_len;	/* Record length for nagle */
	uint16_t tcp_dupack_cnt;	/* # of consequtive duplicate acks */

	kmutex_t	*tcp_acceptor_lockp;	/* Ptr to tf_lock */

	mblk_t		*tcp_ordrel_mp;		/* T_ordrel_ind mblk */
	t_uscalar_t	tcp_acceptor_id;	/* ACCEPTOR_id */

	int		tcp_ipsec_overhead;
	/*
	 * Address family that app wishes returned addrsses to be in.
	 * Currently taken from address family used in T_BIND_REQ, but
	 * should really come from family used in original socket() call.
	 * Value can be AF_INET or AF_INET6.
	 */
	uint_t	tcp_family;
	/*
	 * used for a quick test to determine if any ancillary bits are
	 * set
	 */
	uint_t		tcp_ipv6_recvancillary;		/* Flags */
#define	TCP_IPV6_RECVPKTINFO	0x01	/* IPV6_RECVPKTINFO option  */
#define	TCP_IPV6_RECVHOPLIMIT	0x02	/* IPV6_RECVHOPLIMIT option */
#define	TCP_IPV6_RECVHOPOPTS	0x04	/* IPV6_RECVHOPOPTS option */
#define	TCP_IPV6_RECVDSTOPTS	0x08	/* IPV6_RECVDSTOPTS option */
#define	TCP_IPV6_RECVRTHDR	0x10	/* IPV6_RECVRTHDR option */
#define	TCP_IPV6_RECVRTDSTOPTS	0x20	/* IPV6_RECVRTHDRDSTOPTS option */
#define	TCP_IPV6_RECVTCLASS	0x40	/* IPV6_RECVTCLASS option */
#define	TCP_OLD_IPV6_RECVDSTOPTS 0x80	/* old IPV6_RECVDSTOPTS option */

	uint_t		tcp_recvifindex; /* Last received IPV6_RCVPKTINFO */
	uint_t		tcp_recvhops;	/* Last received IPV6_RECVHOPLIMIT */
	uint_t		tcp_recvtclass;	/* Last received IPV6_RECVTCLASS */
	ip6_hbh_t	*tcp_hopopts;	/* Last received IPV6_RECVHOPOPTS */
	ip6_dest_t	*tcp_dstopts;	/* Last received IPV6_RECVDSTOPTS */
	ip6_dest_t	*tcp_rtdstopts;	/* Last recvd IPV6_RECVRTHDRDSTOPTS */
	ip6_rthdr_t	*tcp_rthdr;	/* Last received IPV6_RECVRTHDR */
	uint_t		tcp_hopoptslen;
	uint_t		tcp_dstoptslen;
	uint_t		tcp_rtdstoptslen;
	uint_t		tcp_rthdrlen;

	mblk_t		*tcp_timercache;
	cred_t		*tcp_cred;	/* Credentials when this was opened */
	pid_t		tcp_cpid;	/* Process id when this was opened */
	uint64_t	tcp_open_time;	/* time when this was opened */


	union {
		struct {
			uchar_t	v4_ttl;
				/* Dup of tcp_ipha.iph_type_of_service */
			uchar_t	v4_tos; /* Dup of tcp_ipha.iph_ttl */
		} v4_hdr_info;
		struct {
			uint_t	v6_vcf;		/* Dup of tcp_ip6h.ip6h_vcf */
			uchar_t	v6_hops;	/* Dup of tcp_ip6h.ip6h_hops */
		} v6_hdr_info;
	} tcp_hdr_info;
#define	tcp_ttl	tcp_hdr_info.v4_hdr_info.v4_ttl
#define	tcp_tos	tcp_hdr_info.v4_hdr_info.v4_tos
#define	tcp_ip6_vcf	tcp_hdr_info.v6_hdr_info.v6_vcf
#define	tcp_ip6_hops	tcp_hdr_info.v6_hdr_info.v6_hops

	ushort_t	tcp_ipversion;
	uint_t		tcp_bound_if;	/* IPV6_BOUND_IF */

#define	tcp_lport	tcp_connp->conn_lport
#define	tcp_fport	tcp_connp->conn_fport
#define	tcp_ports	tcp_connp->conn_ports

#define	tcp_remote	tcp_connp->conn_rem
#define	tcp_ip_src	tcp_connp->conn_src

#define	tcp_remote_v6	tcp_connp->conn_remv6
#define	tcp_ip_src_v6	tcp_connp->conn_srcv6
#define	tcp_bound_source_v6	tcp_connp->conn_bound_source_v6
#define	tcp_bound_source	tcp_connp->conn_bound_source

	kmutex_t	tcp_closelock;
	kcondvar_t	tcp_closecv;
	uint8_t		tcp_closed;
	uint8_t		tcp_closeflags;
	uint8_t		tcp_cleandeathtag;
	mblk_t		tcp_closemp;
	timeout_id_t	tcp_linger_tid;	/* Linger timer ID */

	struct tcp_s *tcp_acceptor_hash; /* Acceptor hash chain */
	struct tcp_s **tcp_ptpahn; /* Pointer to previous accept hash next. */
	struct tcp_s *tcp_bind_hash; /* Bind hash chain */
	struct tcp_s **tcp_ptpbhn;

	boolean_t	tcp_ire_ill_check_done;
	uint_t		tcp_maxpsz;

	/*
	 * used for Multidata Transmit
	 */
	uint_t	tcp_mdt_hdr_head; /* leading header fragment extra space */
	uint_t	tcp_mdt_hdr_tail; /* trailing header fragment extra space */
	int	tcp_mdt_max_pld;  /* maximum payload buffers per Multidata */

	uint32_t	tcp_lso_max; /* maximum LSO payload */

	uint32_t	tcp_ofo_fin_seq; /* Recv out of order FIN seq num */
	uint32_t	tcp_cwr_snd_max;
	uint_t		tcp_drop_opt_ack_cnt; /* # tcp generated optmgmt */
	ip6_pkt_t	tcp_sticky_ipp;			/* Sticky options */
#define	tcp_ipp_fields	tcp_sticky_ipp.ipp_fields	/* valid fields */
#define	tcp_ipp_ifindex	tcp_sticky_ipp.ipp_ifindex	/* pktinfo ifindex */
#define	tcp_ipp_addr	tcp_sticky_ipp.ipp_addr	/* pktinfo src/dst addr */
#define	tcp_ipp_hoplimit	tcp_sticky_ipp.ipp_hoplimit
#define	tcp_ipp_hopoptslen	tcp_sticky_ipp.ipp_hopoptslen
#define	tcp_ipp_rtdstoptslen	tcp_sticky_ipp.ipp_rtdstoptslen
#define	tcp_ipp_rthdrlen	tcp_sticky_ipp.ipp_rthdrlen
#define	tcp_ipp_dstoptslen	tcp_sticky_ipp.ipp_dstoptslen
#define	tcp_ipp_hopopts		tcp_sticky_ipp.ipp_hopopts
#define	tcp_ipp_rtdstopts	tcp_sticky_ipp.ipp_rtdstopts
#define	tcp_ipp_rthdr		tcp_sticky_ipp.ipp_rthdr
#define	tcp_ipp_dstopts		tcp_sticky_ipp.ipp_dstopts
#define	tcp_ipp_nexthop		tcp_sticky_ipp.ipp_nexthop
#define	tcp_ipp_use_min_mtu	tcp_sticky_ipp.ipp_use_min_mtu
	struct tcp_s *tcp_saved_listener;	/* saved value of listener */

	uint32_t	tcp_in_ack_unsent;	/* ACK for unsent data cnt. */

	/*
	 * The following fusion-related fields are protected by squeue.
	 */
	struct tcp_s *tcp_loopback_peer;	/* peer tcp for loopback */
	mblk_t	*tcp_fused_sigurg_mp;		/* M_PCSIG mblk for SIGURG */
	size_t	tcp_fuse_rcv_hiwater;		/* fusion receive queue size */
	uint_t	tcp_fuse_rcv_unread_hiwater;	/* max # of outstanding pkts */
	/*
	 * The following fusion-related fields and bit fields are to be
	 * manipulated with squeue protection or with tcp_non_sq_lock held.
	 * tcp_non_sq_lock is used to protect fields that may be modified
	 * accessed outside the squeue.
	 */
	kmutex_t tcp_non_sq_lock;
	kcondvar_t tcp_fuse_plugcv;
	uint_t tcp_fuse_rcv_unread_cnt;	/* # of outstanding pkts */
	uint32_t
		tcp_fused : 1,		/* loopback tcp in fusion mode */
		tcp_unfusable : 1,	/* fusion not allowed on endpoint */
		tcp_fused_sigurg : 1,	/* send SIGURG upon draining */
		tcp_direct_sockfs : 1,	/* direct calls to sockfs */

		tcp_fuse_syncstr_stopped : 1, /* synchronous streams stopped */
		tcp_fuse_syncstr_plugged : 1, /* synchronous streams plugged */
		tcp_fuse_to_bit_31 : 26;

	/*
	 * This variable is accessed without any lock protection
	 * and therefore must not be declared as a bit field along
	 * with the rest which require such condition.
	 */
	boolean_t	tcp_issocket;	/* this is a socket tcp */

	/* protected by the tcp_non_sq_lock lock */
	uint32_t	tcp_squeue_bytes;
	/*
	 * Kernel SSL session information
	 */
	boolean_t		tcp_kssl_pending; /* waiting for 1st SSL rec. */
	boolean_t		tcp_kssl_inhandshake; /* during SSL handshake */
	kssl_ent_t		tcp_kssl_ent;	/* SSL table entry */
	kssl_ctx_t		tcp_kssl_ctx;	/* SSL session */
	uint_t	tcp_label_len;	/* length of cached label */

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
	 * tcp_sodirect is used by tcp on the receive side to push mblk_t(s)
	 * directly to sockfs. Also, to schedule asynchronous copyout directly
	 * to a pending user-land uio buffer.
	 */
	sodirect_t	*tcp_sodirect;

	/* mblk_t used to enter TCP's squeue from the service routine. */
	mblk_t		*tcp_rsrv_mp;
	/* Mutex for accessing tcp_rsrv_mp */
	kmutex_t	tcp_rsrv_mp_lock;

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

/*
 * Track a reference count on the tcps in order to know when
 * the tcps_g_q can be removed. As long as there is any
 * tcp_t, other that the tcps_g_q itself, in the tcp_stack_t we
 * need to keep tcps_g_q around so that a closing connection can
 * switch to using tcps_g_q as part of it closing.
 */
#define	TCPS_REFHOLD(tcps) {					\
	atomic_add_32(&(tcps)->tcps_refcnt, 1);			\
	ASSERT((tcps)->tcps_refcnt != 0);			\
	DTRACE_PROBE1(tcps__refhold, tcp_stack_t, tcps);	\
}

/*
 * Decrement the reference count on the tcp_stack_t.
 * In architectures e.g sun4u, where atomic_add_32_nv is just
 * a cas, we need to maintain the right memory barrier semantics
 * as that of mutex_exit i.e all the loads and stores should complete
 * before the cas is executed. membar_exit() does that here.
 */
#define	TCPS_REFRELE(tcps) {					\
	ASSERT((tcps)->tcps_refcnt != 0);			\
	membar_exit();						\
	DTRACE_PROBE1(tcps__refrele, tcp_stack_t, tcps);	\
	if (atomic_add_32_nv(&(tcps)->tcps_refcnt, -1) == 0 &&	\
	    (tcps)->tcps_g_q != NULL) {				\
		/* Only tcps_g_q left */			\
		tcp_g_q_inactive(tcps);				\
	}							\
}

extern void 	tcp_free(tcp_t *tcp);
extern void	tcp_ddi_g_init(void);
extern void	tcp_ddi_g_destroy(void);
extern void	tcp_g_q_inactive(tcp_stack_t *);
extern void	tcp_xmit_listeners_reset(mblk_t *mp, uint_t ip_hdr_len,
    zoneid_t zoneid, tcp_stack_t *, conn_t *connp);
extern void	tcp_conn_request(void *arg, mblk_t *mp, void *arg2);
extern void	tcp_conn_request_unbound(void *arg, mblk_t *mp, void *arg2);
extern void 	tcp_input(void *arg, mblk_t *mp, void *arg2);
extern void	tcp_rput_data(void *arg, mblk_t *mp, void *arg2);
extern void 	*tcp_get_conn(void *arg, tcp_stack_t *);
extern void	tcp_time_wait_collector(void *arg);
extern mblk_t	*tcp_snmp_get(queue_t *, mblk_t *);
extern int	tcp_snmp_set(queue_t *, int, int, uchar_t *, int len);
extern mblk_t	*tcp_xmit_mp(tcp_t *tcp, mblk_t *mp, int32_t max_to_send,
		    int32_t *offset, mblk_t **end_mp, uint32_t seq,
		    boolean_t sendall, uint32_t *seg_len, boolean_t rexmit);
/*
 * The TCP Fanout structure.
 * The hash tables and their linkage (tcp_*_hash_next, tcp_ptp*hn) are
 * protected by the per-bucket tf_lock. Each tcp_t
 * inserted in the list points back at this lock using tcp_*_lockp.
 *
 * The listener and acceptor hash queues are lists of tcp_t.
 */
/* listener hash and acceptor hash queue head */
typedef struct tf_s {
	tcp_t		*tf_tcp;
	kmutex_t	tf_lock;
} tf_t;
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

extern void	(*cl_inet_listen)(uint8_t, sa_family_t, uint8_t *, in_port_t);
extern void	(*cl_inet_unlisten)(uint8_t, sa_family_t, uint8_t *,
		    in_port_t);

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

#if (defined(_KERNEL) || defined(_KMEMUSER))
extern void tcp_rput_other(tcp_t *tcp, mblk_t *mp);
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_TCP_H */
