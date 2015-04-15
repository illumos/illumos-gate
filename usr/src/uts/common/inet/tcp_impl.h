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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2011, Joyent Inc. All rights reserved.
 * Copyright (c) 2013, OmniTI Computer Consulting, Inc. All rights reserved.
 * Copyright (c) 2013, 2014 by Delphix. All rights reserved.
 */

#ifndef	_INET_TCP_IMPL_H
#define	_INET_TCP_IMPL_H

/*
 * TCP implementation private declarations.  These interfaces are
 * used to build the IP module and are not meant to be accessed
 * by any modules except IP itself.  They are undocumented and are
 * subject to change without notice.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

#include <sys/cpuvar.h>
#include <sys/clock_impl.h>	/* For LBOLT_FASTPATH{,64} */
#include <inet/optcom.h>
#include <inet/tcp.h>
#include <inet/tunables.h>

#define	TCP_MOD_ID	5105

extern struct qinit	tcp_sock_winit;
extern struct qinit	tcp_winit;

extern sock_downcalls_t sock_tcp_downcalls;

/*
 * Note that by default, the _snd_lowat_fraction tunable controls the value of
 * the transmit low water mark.  TCP_XMIT_LOWATER (and thus the _xmit_lowat
 * property) is only used if the administrator has disabled _snd_lowat_fraction
 * by setting it to 0.
 */
#define	TCP_XMIT_LOWATER	4096
#define	TCP_XMIT_HIWATER	49152
#define	TCP_RECV_LOWATER	2048
#define	TCP_RECV_HIWATER	128000

/*
 * Bind hash list size and has function.  It has to be a power of 2 for
 * hashing.
 */
#define	TCP_BIND_FANOUT_SIZE	1024
#define	TCP_BIND_HASH(lport) (ntohs(lport) & (TCP_BIND_FANOUT_SIZE - 1))

/*
 * This implementation follows the 4.3BSD interpretation of the urgent
 * pointer and not RFC 1122. Switching to RFC 1122 behavior would cause
 * incompatible changes in protocols like telnet and rlogin.
 */
#define	TCP_OLD_URP_INTERPRETATION	1

/* TCP option length */
#define	TCPOPT_NOP_LEN		1
#define	TCPOPT_MAXSEG_LEN	4
#define	TCPOPT_WS_LEN		3
#define	TCPOPT_REAL_WS_LEN	(TCPOPT_WS_LEN+1)
#define	TCPOPT_TSTAMP_LEN	10
#define	TCPOPT_REAL_TS_LEN	(TCPOPT_TSTAMP_LEN+2)
#define	TCPOPT_SACK_OK_LEN	2
#define	TCPOPT_REAL_SACK_OK_LEN	(TCPOPT_SACK_OK_LEN+2)
#define	TCPOPT_REAL_SACK_LEN	4
#define	TCPOPT_MAX_SACK_LEN	36
#define	TCPOPT_HEADER_LEN	2

/* Round up the value to the nearest mss. */
#define	MSS_ROUNDUP(value, mss)		((((value) - 1) / (mss) + 1) * (mss))

/*
 * Was this tcp created via socket() interface?
 */
#define	TCP_IS_SOCKET(tcp)	((tcp)->tcp_issocket)

/*
 * Is this tcp not attached to any upper client?
 */
#define	TCP_IS_DETACHED(tcp)	((tcp)->tcp_detached)

/* TCP timers related data strucutres.  Refer to tcp_timers.c. */
typedef struct tcp_timer_s {
	conn_t	*connp;
	void 	(*tcpt_proc)(void *);
	callout_id_t   tcpt_tid;
} tcp_timer_t;

extern kmem_cache_t *tcp_timercache;

/*
 * Macro for starting various timers.  Retransmission timer has its own macro,
 * TCP_TIMER_RESTART().  tim is in millisec.
 */
#define	TCP_TIMER(tcp, f, tim)		\
	tcp_timeout(tcp->tcp_connp, f, tim)
#define	TCP_TIMER_CANCEL(tcp, id)	\
	tcp_timeout_cancel(tcp->tcp_connp, id)

/*
 * To restart the TCP retransmission timer.  intvl is in millisec.
 */
#define	TCP_TIMER_RESTART(tcp, intvl) {					\
	if ((tcp)->tcp_timer_tid != 0)					\
		(void) TCP_TIMER_CANCEL((tcp), (tcp)->tcp_timer_tid);	\
	(tcp)->tcp_timer_tid = TCP_TIMER((tcp), tcp_timer, (intvl));	\
}

/*
 * For scalability, we must not run a timer for every TCP connection
 * in TIME_WAIT state.  To see why, consider (for time wait interval of
 * 1 minutes):
 *	10,000 connections/sec * 60 seconds/time wait = 600,000 active conn's
 *
 * This list is ordered by time, so you need only delete from the head
 * until you get to entries which aren't old enough to delete yet.
 * The list consists of only the detached TIME_WAIT connections.
 *
 * When a tcp_t enters TIME_WAIT state, a timer is started (timeout is
 * tcps_time_wait_interval).  When the tcp_t is detached (upper layer closes
 * the end point), it is moved to the time wait list and another timer is
 * started (expiry time is set at tcp_time_wait_expire, which is
 * also calculated using tcps_time_wait_interval).  This means that the
 * TIME_WAIT state can be extended (up to doubled) if the tcp_t doesn't
 * become detached for a long time.
 *
 * The list manipulations (including tcp_time_wait_next/prev)
 * are protected by the tcp_time_wait_lock. The content of the
 * detached TIME_WAIT connections is protected by the normal perimeters.
 *
 * This list is per squeue and squeues are shared across the tcp_stack_t's.
 * Things on tcp_time_wait_head remain associated with the tcp_stack_t
 * and conn_netstack.
 * The tcp_t's that are added to tcp_free_list are disassociated and
 * have NULL tcp_tcps and conn_netstack pointers.
 */
typedef struct tcp_squeue_priv_s {
	kmutex_t	tcp_time_wait_lock;
	callout_id_t	tcp_time_wait_tid;
	tcp_t		*tcp_time_wait_head;
	tcp_t		*tcp_time_wait_tail;
	tcp_t		*tcp_free_list;
	uint_t		tcp_free_list_cnt;
#ifdef DEBUG
	/*
	 * For debugging purpose, true when tcp_time_wait_collector() is
	 * running.
	 */
	boolean_t	tcp_time_wait_running;
#endif
} tcp_squeue_priv_t;

/*
 * Parameters for TCP Initial Send Sequence number (ISS) generation.  When
 * tcp_strong_iss is set to 1, which is the default, the ISS is calculated
 * by adding three components: a time component which grows by 1 every 4096
 * nanoseconds (versus every 4 microseconds suggested by RFC 793, page 27);
 * a per-connection component which grows by 125000 for every new connection;
 * and an "extra" component that grows by a random amount centered
 * approximately on 64000.  This causes the ISS generator to cycle every
 * 4.89 hours if no TCP connections are made, and faster if connections are
 * made.
 *
 * When tcp_strong_iss is set to 0, ISS is calculated by adding two
 * components: a time component which grows by 250000 every second; and
 * a per-connection component which grows by 125000 for every new connections.
 *
 * A third method, when tcp_strong_iss is set to 2, for generating ISS is
 * prescribed by Steve Bellovin.  This involves adding time, the 125000 per
 * connection, and a one-way hash (MD5) of the connection ID <sport, dport,
 * src, dst>, a "truly" random (per RFC 1750) number, and a console-entered
 * password.
 */
#define	ISS_INCR	250000
#define	ISS_NSEC_SHT	12

/* Macros for timestamp comparisons */
#define	TSTMP_GEQ(a, b)	((int32_t)((a)-(b)) >= 0)
#define	TSTMP_LT(a, b)	((int32_t)((a)-(b)) < 0)

/*
 * Initialize cwnd according to RFC 3390.  def_max_init_cwnd is
 * either tcp_slow_start_initial or tcp_slow_start_after idle
 * depending on the caller.  If the upper layer has not used the
 * TCP_INIT_CWND option to change the initial cwnd, tcp_init_cwnd
 * should be 0 and we use the formula in RFC 3390 to set tcp_cwnd.
 * If the upper layer has changed set the tcp_init_cwnd, just use
 * it to calculate the tcp_cwnd.
 *
 * "An Argument for Increasing TCP's Initial Congestion Window"
 * ACM SIGCOMM Computer Communications Review, vol. 40 (2010), pp. 27-33
 *  -- Nandita Dukkipati, Tiziana Refice, Yuchung Cheng,
 *     Hsiao-keng Jerry Chu, Tom Herbert, Amit Agarwal,
 *     Arvind Jain, Natalia Sutin
 *
 *   "Based on the results from our experiments, we believe the
 *    initial congestion window should be at least ten segments
 *    and the same be investigated for standardization by the IETF."
 *
 * As such, the def_max_init_cwnd argument with which this macro is
 * invoked is either the tcps_slow_start_initial or
 * tcps_slow_start_after_idle which both default to 0 and will respect
 * RFC 3390 exactly.  If the tunables are explicitly set by the operator,
 * then the initial congestion window should be set as the operator
 * demands, within reason. We shall arbitrarily define reason as a
 * maximum of 16 (same as used by the TCP_INIT_CWND setsockopt).
 */

/* Maximum TCP initial cwin (start/restart). */
#define	TCP_MAX_INIT_CWND	16

#define	TCP_SET_INIT_CWND(tcp, mss, def_max_init_cwnd)			\
{									\
	if ((tcp)->tcp_init_cwnd == 0) {				\
		if (def_max_init_cwnd == 0) {				\
			(tcp)->tcp_cwnd = MIN(4 * (mss),		\
			    MAX(2 * (mss), 4380 / (mss) * (mss)));	\
		} else {						\
			(tcp)->tcp_cwnd = MIN(TCP_MAX_INIT_CWND * (mss),\
			    def_max_init_cwnd * (mss));			\
		}							\
	} else {							\
		(tcp)->tcp_cwnd = (tcp)->tcp_init_cwnd * (mss);		\
	}								\
	tcp->tcp_cwnd_cnt = 0;						\
}

/*
 * Set ECN capable transport (ECT) code point in IP header.
 *
 * Note that there are 2 ECT code points '01' and '10', which are called
 * ECT(1) and ECT(0) respectively.  Here we follow the original ECT code
 * point ECT(0) for TCP as described in RFC 2481.
 */
#define	TCP_SET_ECT(tcp, iph) \
	if ((tcp)->tcp_connp->conn_ipversion == IPV4_VERSION) { \
		/* We need to clear the code point first. */ \
		((ipha_t *)(iph))->ipha_type_of_service &= 0xFC; \
		((ipha_t *)(iph))->ipha_type_of_service |= IPH_ECN_ECT0; \
	} else { \
		((ip6_t *)(iph))->ip6_vcf &= htonl(0xFFCFFFFF); \
		((ip6_t *)(iph))->ip6_vcf |= htonl(IPH_ECN_ECT0 << 20); \
	}

/*
 * Set tcp_rto with boundary checking.
 */
#define	TCP_SET_RTO(tcp, rto) \
	if ((rto) < (tcp)->tcp_rto_min)			\
		(tcp)->tcp_rto = (tcp)->tcp_rto_min;	\
	else if ((rto) > (tcp)->tcp_rto_max)		\
		(tcp)->tcp_rto = (tcp)->tcp_rto_max;	\
	else						\
		(tcp)->tcp_rto = (rto);

/*
 * TCP options struct returned from tcp_parse_options.
 */
typedef struct tcp_opt_s {
	uint32_t	tcp_opt_mss;
	uint32_t	tcp_opt_wscale;
	uint32_t	tcp_opt_ts_val;
	uint32_t	tcp_opt_ts_ecr;
	tcp_t		*tcp;
} tcp_opt_t;

/*
 * Flags returned from tcp_parse_options.
 */
#define	TCP_OPT_MSS_PRESENT	1
#define	TCP_OPT_WSCALE_PRESENT	2
#define	TCP_OPT_TSTAMP_PRESENT	4
#define	TCP_OPT_SACK_OK_PRESENT	8
#define	TCP_OPT_SACK_PRESENT	16

/*
 * Write-side flow-control is implemented via the per instance STREAMS
 * write-side Q by explicitly setting QFULL to stop the flow of mblk_t(s)
 * and clearing QFULL and calling qbackenable() to restart the flow based
 * on the number of TCP unsent bytes (i.e. those not on the wire waiting
 * for a remote ACK).
 *
 * This is different than a standard STREAMS kmod which when using the
 * STREAMS Q the framework would automatictly flow-control based on the
 * defined hiwat/lowat values as mblk_t's are enqueued/dequeued.
 *
 * As of FireEngine TCP write-side flow-control needs to take into account
 * both the unsent tcp_xmit list bytes but also any squeue_t enqueued bytes
 * (i.e. from tcp_wput() -> tcp_output()).
 *
 * This is accomplished by adding a new tcp_t fields, tcp_squeue_bytes, to
 * count the number of bytes enqueued by tcp_wput() and the number of bytes
 * dequeued and processed by tcp_output().
 *
 * So, the total number of bytes unsent is (squeue_bytes + unsent) with all
 * flow-control uses of unsent replaced with the macro TCP_UNSENT_BYTES.
 */
extern void	tcp_clrqfull(tcp_t *);
extern void	tcp_setqfull(tcp_t *);

#define	TCP_UNSENT_BYTES(tcp) \
	((tcp)->tcp_squeue_bytes + (tcp)->tcp_unsent)

/*
 * Linked list struct to store listener connection limit configuration per
 * IP stack.  The list is stored at tcps_listener_conf in tcp_stack_t.
 *
 * tl_port: the listener port of this limit configuration
 * tl_ratio: the maximum amount of memory consumed by all concurrent TCP
 *           connections created by a listener does not exceed 1/tl_ratio
 *           of the total system memory.  Note that this is only an
 *           approximation.
 * tl_link: linked list struct
 */
typedef struct tcp_listener_s {
	in_port_t	tl_port;
	uint32_t	tl_ratio;
	list_node_t	tl_link;
} tcp_listener_t;

/*
 * If there is a limit set on the number of connections allowed per each
 * listener, the following struct is used to store that counter.  It keeps
 * the number of TCP connection created by a listener.  Note that this needs
 * to be separated from the listener since the listener can go away before
 * all the connections are gone.
 *
 * When the struct is allocated, tlc_cnt is set to 1.  When a new connection
 * is created by the listener, tlc_cnt is incremented by 1.  When a connection
 * created by the listener goes away, tlc_count is decremented by 1.  When the
 * listener itself goes away, tlc_cnt is decremented  by one.  The last
 * connection (or the listener) which decrements tlc_cnt to zero frees the
 * struct.
 *
 * tlc_max is the maximum number of concurrent TCP connections created from a
 * listner.  It is calculated when the tcp_listen_cnt_t is allocated.
 *
 * tlc_report_time stores the time when cmn_err() is called to report that the
 * max has been exceeeded.  Report is done at most once every
 * TCP_TLC_REPORT_INTERVAL mins for a listener.
 *
 * tlc_drop stores the number of connection attempt dropped because the
 * limit has reached.
 */
typedef struct tcp_listen_cnt_s {
	uint32_t	tlc_max;
	uint32_t	tlc_cnt;
	int64_t		tlc_report_time;
	uint32_t	tlc_drop;
} tcp_listen_cnt_t;

#define	TCP_TLC_REPORT_INTERVAL	(30 * MINUTES)

#define	TCP_DECR_LISTEN_CNT(tcp)					\
{									\
	ASSERT((tcp)->tcp_listen_cnt->tlc_cnt > 0);			\
	if (atomic_dec_32_nv(&(tcp)->tcp_listen_cnt->tlc_cnt) == 0) \
		kmem_free((tcp)->tcp_listen_cnt, sizeof (tcp_listen_cnt_t)); \
	(tcp)->tcp_listen_cnt = NULL;					\
}

/* Increment and decrement the number of connections in tcp_stack_t. */
#define	TCPS_CONN_INC(tcps)						\
	atomic_inc_64(							\
	    (uint64_t *)&(tcps)->tcps_sc[CPU->cpu_seqid]->tcp_sc_conn_cnt)

#define	TCPS_CONN_DEC(tcps)						\
	atomic_dec_64(							\
	    (uint64_t *)&(tcps)->tcps_sc[CPU->cpu_seqid]->tcp_sc_conn_cnt)

/*
 * When the system is under memory pressure, stack variable tcps_reclaim is
 * true, we shorten the connection timeout abort interval to tcp_early_abort
 * seconds.  Defined in tcp.c.
 */
extern uint32_t tcp_early_abort;

/*
 * To reach to an eager in Q0 which can be dropped due to an incoming
 * new SYN request when Q0 is full, a new doubly linked list is
 * introduced. This list allows to select an eager from Q0 in O(1) time.
 * This is needed to avoid spending too much time walking through the
 * long list of eagers in Q0 when tcp_drop_q0() is called. Each member of
 * this new list has to be a member of Q0.
 * This list is headed by listener's tcp_t. When the list is empty,
 * both the pointers - tcp_eager_next_drop_q0 and tcp_eager_prev_drop_q0,
 * of listener's tcp_t point to listener's tcp_t itself.
 *
 * Given an eager in Q0 and a listener, MAKE_DROPPABLE() puts the eager
 * in the list. MAKE_UNDROPPABLE() takes the eager out of the list.
 * These macros do not affect the eager's membership to Q0.
 */
#define	MAKE_DROPPABLE(listener, eager)					\
	if ((eager)->tcp_eager_next_drop_q0 == NULL) {			\
		(listener)->tcp_eager_next_drop_q0->tcp_eager_prev_drop_q0\
		    = (eager);						\
		(eager)->tcp_eager_prev_drop_q0 = (listener);		\
		(eager)->tcp_eager_next_drop_q0 =			\
		    (listener)->tcp_eager_next_drop_q0;			\
		(listener)->tcp_eager_next_drop_q0 = (eager);		\
	}

#define	MAKE_UNDROPPABLE(eager)						\
	if ((eager)->tcp_eager_next_drop_q0 != NULL) {			\
		(eager)->tcp_eager_next_drop_q0->tcp_eager_prev_drop_q0	\
		    = (eager)->tcp_eager_prev_drop_q0;			\
		(eager)->tcp_eager_prev_drop_q0->tcp_eager_next_drop_q0	\
		    = (eager)->tcp_eager_next_drop_q0;			\
		(eager)->tcp_eager_prev_drop_q0 = NULL;			\
		(eager)->tcp_eager_next_drop_q0 = NULL;			\
	}

/*
 * The format argument to pass to tcp_display().
 * DISP_PORT_ONLY means that the returned string has only port info.
 * DISP_ADDR_AND_PORT means that the returned string also contains the
 * remote and local IP address.
 */
#define	DISP_PORT_ONLY		1
#define	DISP_ADDR_AND_PORT	2

#define	IP_ADDR_CACHE_SIZE	2048
#define	IP_ADDR_CACHE_HASH(faddr)					\
	(ntohl(faddr) & (IP_ADDR_CACHE_SIZE -1))

/*
 * TCP reassembly macros.  We hide starting and ending sequence numbers in
 * b_next and b_prev of messages on the reassembly queue.  The messages are
 * chained using b_cont.  These macros are used in tcp_reass() so we don't
 * have to see the ugly casts and assignments.
 */
#define	TCP_REASS_SEQ(mp)		((uint32_t)(uintptr_t)((mp)->b_next))
#define	TCP_REASS_SET_SEQ(mp, u)	((mp)->b_next = \
					(mblk_t *)(uintptr_t)(u))
#define	TCP_REASS_END(mp)		((uint32_t)(uintptr_t)((mp)->b_prev))
#define	TCP_REASS_SET_END(mp, u)	((mp)->b_prev = \
					(mblk_t *)(uintptr_t)(u))

#define	tcps_time_wait_interval		tcps_propinfo_tbl[0].prop_cur_uval
#define	tcps_conn_req_max_q		tcps_propinfo_tbl[1].prop_cur_uval
#define	tcps_conn_req_max_q0		tcps_propinfo_tbl[2].prop_cur_uval
#define	tcps_conn_req_min		tcps_propinfo_tbl[3].prop_cur_uval
#define	tcps_conn_grace_period		tcps_propinfo_tbl[4].prop_cur_uval
#define	tcps_cwnd_max_			tcps_propinfo_tbl[5].prop_cur_uval
#define	tcps_dbg			tcps_propinfo_tbl[6].prop_cur_uval
#define	tcps_smallest_nonpriv_port	tcps_propinfo_tbl[7].prop_cur_uval
#define	tcps_ip_abort_cinterval		tcps_propinfo_tbl[8].prop_cur_uval
#define	tcps_ip_abort_linterval		tcps_propinfo_tbl[9].prop_cur_uval
#define	tcps_ip_abort_interval		tcps_propinfo_tbl[10].prop_cur_uval
#define	tcps_ip_notify_cinterval	tcps_propinfo_tbl[11].prop_cur_uval
#define	tcps_ip_notify_interval		tcps_propinfo_tbl[12].prop_cur_uval
#define	tcps_ipv4_ttl			tcps_propinfo_tbl[13].prop_cur_uval
#define	tcps_keepalive_interval_high	tcps_propinfo_tbl[14].prop_max_uval
#define	tcps_keepalive_interval		tcps_propinfo_tbl[14].prop_cur_uval
#define	tcps_keepalive_interval_low	tcps_propinfo_tbl[14].prop_min_uval
#define	tcps_maxpsz_multiplier		tcps_propinfo_tbl[15].prop_cur_uval
#define	tcps_mss_def_ipv4		tcps_propinfo_tbl[16].prop_cur_uval
#define	tcps_mss_max_ipv4		tcps_propinfo_tbl[17].prop_cur_uval
#define	tcps_mss_min			tcps_propinfo_tbl[18].prop_cur_uval
#define	tcps_naglim_def			tcps_propinfo_tbl[19].prop_cur_uval
#define	tcps_rexmit_interval_initial_high	\
					tcps_propinfo_tbl[20].prop_max_uval
#define	tcps_rexmit_interval_initial	tcps_propinfo_tbl[20].prop_cur_uval
#define	tcps_rexmit_interval_initial_low	\
					tcps_propinfo_tbl[20].prop_min_uval
#define	tcps_rexmit_interval_max_high	tcps_propinfo_tbl[21].prop_max_uval
#define	tcps_rexmit_interval_max	tcps_propinfo_tbl[21].prop_cur_uval
#define	tcps_rexmit_interval_max_low	tcps_propinfo_tbl[21].prop_min_uval
#define	tcps_rexmit_interval_min_high	tcps_propinfo_tbl[22].prop_max_uval
#define	tcps_rexmit_interval_min	tcps_propinfo_tbl[22].prop_cur_uval
#define	tcps_rexmit_interval_min_low	tcps_propinfo_tbl[22].prop_min_uval
#define	tcps_deferred_ack_interval	tcps_propinfo_tbl[23].prop_cur_uval
#define	tcps_snd_lowat_fraction		tcps_propinfo_tbl[24].prop_cur_uval
#define	tcps_dupack_fast_retransmit	tcps_propinfo_tbl[25].prop_cur_uval
#define	tcps_ignore_path_mtu		tcps_propinfo_tbl[26].prop_cur_bval
#define	tcps_smallest_anon_port		tcps_propinfo_tbl[27].prop_cur_uval
#define	tcps_largest_anon_port		tcps_propinfo_tbl[28].prop_cur_uval
#define	tcps_xmit_hiwat			tcps_propinfo_tbl[29].prop_cur_uval
#define	tcps_xmit_lowat			tcps_propinfo_tbl[30].prop_cur_uval
#define	tcps_recv_hiwat			tcps_propinfo_tbl[31].prop_cur_uval
#define	tcps_recv_hiwat_minmss		tcps_propinfo_tbl[32].prop_cur_uval
#define	tcps_fin_wait_2_flush_interval_high	\
					tcps_propinfo_tbl[33].prop_max_uval
#define	tcps_fin_wait_2_flush_interval	tcps_propinfo_tbl[33].prop_cur_uval
#define	tcps_fin_wait_2_flush_interval_low	\
					tcps_propinfo_tbl[33].prop_min_uval
#define	tcps_max_buf			tcps_propinfo_tbl[34].prop_cur_uval
#define	tcps_strong_iss			tcps_propinfo_tbl[35].prop_cur_uval
#define	tcps_rtt_updates		tcps_propinfo_tbl[36].prop_cur_uval
#define	tcps_wscale_always		tcps_propinfo_tbl[37].prop_cur_bval
#define	tcps_tstamp_always		tcps_propinfo_tbl[38].prop_cur_bval
#define	tcps_tstamp_if_wscale		tcps_propinfo_tbl[39].prop_cur_bval
#define	tcps_rexmit_interval_extra	tcps_propinfo_tbl[40].prop_cur_uval
#define	tcps_deferred_acks_max		tcps_propinfo_tbl[41].prop_cur_uval
#define	tcps_slow_start_after_idle	tcps_propinfo_tbl[42].prop_cur_uval
#define	tcps_slow_start_initial		tcps_propinfo_tbl[43].prop_cur_uval
#define	tcps_sack_permitted		tcps_propinfo_tbl[44].prop_cur_uval
#define	tcps_ipv6_hoplimit		tcps_propinfo_tbl[45].prop_cur_uval
#define	tcps_mss_def_ipv6		tcps_propinfo_tbl[46].prop_cur_uval
#define	tcps_mss_max_ipv6		tcps_propinfo_tbl[47].prop_cur_uval
#define	tcps_rev_src_routes		tcps_propinfo_tbl[48].prop_cur_bval
#define	tcps_local_dack_interval	tcps_propinfo_tbl[49].prop_cur_uval
#define	tcps_local_dacks_max		tcps_propinfo_tbl[50].prop_cur_uval
#define	tcps_ecn_permitted		tcps_propinfo_tbl[51].prop_cur_uval
#define	tcps_rst_sent_rate_enabled	tcps_propinfo_tbl[52].prop_cur_bval
#define	tcps_rst_sent_rate		tcps_propinfo_tbl[53].prop_cur_uval
#define	tcps_push_timer_interval	tcps_propinfo_tbl[54].prop_cur_uval
#define	tcps_use_smss_as_mss_opt	tcps_propinfo_tbl[55].prop_cur_bval
#define	tcps_keepalive_abort_interval_high \
					tcps_propinfo_tbl[56].prop_max_uval
#define	tcps_keepalive_abort_interval \
					tcps_propinfo_tbl[56].prop_cur_uval
#define	tcps_keepalive_abort_interval_low \
					tcps_propinfo_tbl[56].prop_min_uval
#define	tcps_wroff_xtra			tcps_propinfo_tbl[57].prop_cur_uval
#define	tcps_dev_flow_ctl		tcps_propinfo_tbl[58].prop_cur_bval
#define	tcps_reass_timeout		tcps_propinfo_tbl[59].prop_cur_uval
#define	tcps_iss_incr			tcps_propinfo_tbl[65].prop_cur_uval

extern struct qinit tcp_rinitv4, tcp_rinitv6;
extern boolean_t do_tcp_fusion;

/*
 * Object to represent database of options to search passed to
 * {sock,tpi}optcom_req() interface routine to take care of option
 * management and associated methods.
 */
extern optdb_obj_t	tcp_opt_obj;
extern uint_t		tcp_max_optsize;

extern int tcp_squeue_flag;

extern uint_t tcp_free_list_max_cnt;

/*
 * Functions in tcp.c.
 */
extern void	tcp_acceptor_hash_insert(t_uscalar_t, tcp_t *);
extern tcp_t	*tcp_acceptor_hash_lookup(t_uscalar_t, tcp_stack_t *);
extern void	tcp_acceptor_hash_remove(tcp_t *);
extern mblk_t	*tcp_ack_mp(tcp_t *);
extern int	tcp_build_hdrs(tcp_t *);
extern void	tcp_cleanup(tcp_t *);
extern int	tcp_clean_death(tcp_t *, int);
extern void	tcp_clean_death_wrapper(void *, mblk_t *, void *,
		    ip_recv_attr_t *);
extern void	tcp_close_common(conn_t *, int);
extern void	tcp_close_detached(tcp_t *);
extern void	tcp_close_mpp(mblk_t **);
extern void	tcp_closei_local(tcp_t *);
extern sock_lower_handle_t tcp_create(int, int, int, sock_downcalls_t **,
		    uint_t *, int *, int, cred_t *);
extern conn_t	*tcp_create_common(cred_t *, boolean_t, boolean_t, int *);
extern void	tcp_disconnect(tcp_t *, mblk_t *);
extern char	*tcp_display(tcp_t *, char *, char);
extern int	tcp_do_bind(conn_t *, struct sockaddr *, socklen_t, cred_t *,
		    boolean_t);
extern int	tcp_do_connect(conn_t *, const struct sockaddr *, socklen_t,
		    cred_t *, pid_t);
extern int	tcp_do_listen(conn_t *, struct sockaddr *, socklen_t, int,
		    cred_t *, boolean_t);
extern int	tcp_do_unbind(conn_t *);
extern boolean_t	tcp_eager_blowoff(tcp_t *, t_scalar_t);
extern void	tcp_eager_cleanup(tcp_t *, boolean_t);
extern void	tcp_eager_kill(void *, mblk_t *, void *, ip_recv_attr_t *);
extern void	tcp_eager_unlink(tcp_t *);
extern void	tcp_init_values(tcp_t *, tcp_t *);
extern void	tcp_ipsec_cleanup(tcp_t *);
extern int	tcp_maxpsz_set(tcp_t *, boolean_t);
extern void	tcp_mss_set(tcp_t *, uint32_t);
extern void	tcp_reinput(conn_t *, mblk_t *, ip_recv_attr_t *, ip_stack_t *);
extern void	tcp_rsrv(queue_t *);
extern uint_t	tcp_rwnd_reopen(tcp_t *);
extern int	tcp_rwnd_set(tcp_t *, uint32_t);
extern int	tcp_set_destination(tcp_t *);
extern void	tcp_set_ws_value(tcp_t *);
extern void	tcp_stop_lingering(tcp_t *);
extern void	tcp_update_pmtu(tcp_t *, boolean_t);
extern mblk_t	*tcp_zcopy_backoff(tcp_t *, mblk_t *, boolean_t);
extern boolean_t	tcp_zcopy_check(tcp_t *);
extern void	tcp_zcopy_notify(tcp_t *);
extern void	tcp_get_proto_props(tcp_t *, struct sock_proto_props *);

/*
 * Bind related functions in tcp_bind.c
 */
extern int	tcp_bind_check(conn_t *, struct sockaddr *, socklen_t,
		    cred_t *, boolean_t);
extern void	tcp_bind_hash_insert(tf_t *, tcp_t *, int);
extern void	tcp_bind_hash_remove(tcp_t *);
extern in_port_t	tcp_bindi(tcp_t *, in_port_t, const in6_addr_t *,
			    int, boolean_t, boolean_t, boolean_t);
extern in_port_t	tcp_update_next_port(in_port_t, const tcp_t *,
			    boolean_t);

/*
 * Fusion related functions in tcp_fusion.c.
 */
extern void	tcp_fuse(tcp_t *, uchar_t *, tcpha_t *);
extern void	tcp_unfuse(tcp_t *);
extern boolean_t tcp_fuse_output(tcp_t *, mblk_t *, uint32_t);
extern void	tcp_fuse_output_urg(tcp_t *, mblk_t *);
extern boolean_t tcp_fuse_rcv_drain(queue_t *, tcp_t *, mblk_t **);
extern size_t	tcp_fuse_set_rcv_hiwat(tcp_t *, size_t);
extern int	tcp_fuse_maxpsz(tcp_t *);
extern void	tcp_fuse_backenable(tcp_t *);
extern void	tcp_iss_key_init(uint8_t *, int, tcp_stack_t *);

/*
 * Output related functions in tcp_output.c.
 */
extern void	tcp_close_output(void *, mblk_t *, void *, ip_recv_attr_t *);
extern void	tcp_output(void *, mblk_t *, void *, ip_recv_attr_t *);
extern void	tcp_output_urgent(void *, mblk_t *, void *, ip_recv_attr_t *);
extern void	tcp_rexmit_after_error(tcp_t *);
extern void	tcp_sack_rexmit(tcp_t *, uint_t *);
extern void	tcp_send_data(tcp_t *, mblk_t *);
extern void	tcp_send_synack(void *, mblk_t *, void *, ip_recv_attr_t *);
extern void	tcp_shutdown_output(void *, mblk_t *, void *, ip_recv_attr_t *);
extern void	tcp_ss_rexmit(tcp_t *);
extern void	tcp_update_xmit_tail(tcp_t *, uint32_t);
extern void	tcp_wput(queue_t *, mblk_t *);
extern void	tcp_wput_data(tcp_t *, mblk_t *, boolean_t);
extern void	tcp_wput_sock(queue_t *, mblk_t *);
extern void	tcp_wput_fallback(queue_t *, mblk_t *);
extern void	tcp_xmit_ctl(char *, tcp_t *, uint32_t, uint32_t, int);
extern void	tcp_xmit_listeners_reset(mblk_t *, ip_recv_attr_t *,
		    ip_stack_t *i, conn_t *);
extern mblk_t	*tcp_xmit_mp(tcp_t *, mblk_t *, int32_t, int32_t *,
		    mblk_t **, uint32_t, boolean_t, uint32_t *, boolean_t);

/*
 * Input related functions in tcp_input.c.
 */
extern void	tcp_icmp_input(void *, mblk_t *, void *, ip_recv_attr_t *);
extern void	tcp_input_data(void *, mblk_t *, void *, ip_recv_attr_t *);
extern void	tcp_input_listener_unbound(void *, mblk_t *, void *,
		    ip_recv_attr_t *);
extern boolean_t	tcp_paws_check(tcp_t *, const tcp_opt_t *);
extern int	tcp_parse_options(tcpha_t *, tcp_opt_t *);
extern uint_t	tcp_rcv_drain(tcp_t *);
extern void	tcp_rcv_enqueue(tcp_t *, mblk_t *, uint_t, cred_t *);
extern boolean_t	tcp_verifyicmp(conn_t *, void *, icmph_t *, icmp6_t *,
			    ip_recv_attr_t *);

/*
 * Kernel socket related functions in tcp_socket.c.
 */
extern int	tcp_fallback(sock_lower_handle_t, queue_t *, boolean_t,
		    so_proto_quiesced_cb_t, sock_quiesce_arg_t *);
extern boolean_t tcp_newconn_notify(tcp_t *, ip_recv_attr_t *);

/*
 * Timer related functions in tcp_timers.c.
 */
extern void	tcp_ack_timer(void *);
extern void	tcp_close_linger_timeout(void *);
extern void	tcp_keepalive_timer(void *);
extern void	tcp_push_timer(void *);
extern void	tcp_reass_timer(void *);
extern mblk_t	*tcp_timermp_alloc(int);
extern void	tcp_timermp_free(tcp_t *);
extern timeout_id_t tcp_timeout(conn_t *, void (*)(void *), hrtime_t);
extern clock_t	tcp_timeout_cancel(conn_t *, timeout_id_t);
extern void	tcp_timer(void *arg);
extern void	tcp_timers_stop(tcp_t *);

/*
 * TCP TPI related functions in tcp_tpi.c.
 */
extern void	tcp_addr_req(tcp_t *, mblk_t *);
extern void	tcp_capability_req(tcp_t *, mblk_t *);
extern boolean_t	tcp_conn_con(tcp_t *, uchar_t *, mblk_t *,
			    mblk_t **, ip_recv_attr_t *);
extern void	tcp_err_ack(tcp_t *, mblk_t *, int, int);
extern void	tcp_err_ack_prim(tcp_t *, mblk_t *, int, int, int);
extern void	tcp_info_req(tcp_t *, mblk_t *);
extern void	tcp_send_conn_ind(void *, mblk_t *, void *);
extern void	tcp_send_pending(void *, mblk_t *, void *, ip_recv_attr_t *);
extern void	tcp_tpi_accept(queue_t *, mblk_t *);
extern void	tcp_tpi_bind(tcp_t *, mblk_t *);
extern int	tcp_tpi_close(queue_t *, int);
extern int	tcp_tpi_close_accept(queue_t *);
extern void	tcp_tpi_connect(tcp_t *, mblk_t *);
extern int	tcp_tpi_opt_get(queue_t *, t_scalar_t, t_scalar_t, uchar_t *);
extern int	tcp_tpi_opt_set(queue_t *, uint_t, int, int, uint_t, uchar_t *,
		    uint_t *, uchar_t *, void *, cred_t *);
extern void	tcp_tpi_unbind(tcp_t *, mblk_t *);
extern void	tcp_tli_accept(tcp_t *, mblk_t *);
extern void	tcp_use_pure_tpi(tcp_t *);
extern void	tcp_do_capability_ack(tcp_t *, struct T_capability_ack *,
		    t_uscalar_t);

/*
 * TCP option processing related functions in tcp_opt_data.c
 */
extern int	tcp_opt_get(conn_t *, int, int, uchar_t *);
extern int	tcp_opt_set(conn_t *, uint_t, int, int, uint_t, uchar_t *,
		    uint_t *, uchar_t *, void *, cred_t *);

/*
 * TCP time wait processing related functions in tcp_time_wait.c.
 */
extern void		tcp_time_wait_append(tcp_t *);
extern void		tcp_time_wait_collector(void *);
extern boolean_t	tcp_time_wait_remove(tcp_t *, tcp_squeue_priv_t *);
extern void		tcp_time_wait_processing(tcp_t *, mblk_t *, uint32_t,
			    uint32_t, int, tcpha_t *, ip_recv_attr_t *);

/*
 * Misc functions in tcp_misc.c.
 */
extern uint32_t	tcp_find_listener_conf(tcp_stack_t *, in_port_t);
extern void	tcp_ioctl_abort_conn(queue_t *, mblk_t *);
extern void	tcp_listener_conf_cleanup(tcp_stack_t *);
extern void	tcp_stack_cpu_add(tcp_stack_t *, processorid_t);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_TCP_IMPL_H */
