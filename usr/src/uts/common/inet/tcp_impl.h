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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_INET_TCP_IMPL_H
#define	_INET_TCP_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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

#include <inet/tcp.h>

#define	TCP_MOD_ID	5105

/*
 * Was this tcp created via socket() interface?
 */
#define	TCP_IS_SOCKET(tcp)	((tcp)->tcp_issocket)

/*
 * Is this tcp not attached to any upper client?
 */
#define	TCP_IS_DETACHED(tcp)	((tcp)->tcp_detached)

#define	TCP_TIMER(tcp, f, tim)		\
	tcp_timeout(tcp->tcp_connp, f, tim)
#define	TCP_TIMER_CANCEL(tcp, id)	\
	tcp_timeout_cancel(tcp->tcp_connp, id)

/*
 * To restart the TCP retransmission timer.
 */
#define	TCP_TIMER_RESTART(tcp, intvl) {					\
	if ((tcp)->tcp_timer_tid != 0)					\
		(void) TCP_TIMER_CANCEL((tcp), (tcp)->tcp_timer_tid);	\
	(tcp)->tcp_timer_tid = TCP_TIMER((tcp), tcp_timer,		\
	    MSEC_TO_TICK(intvl));					\
}

/*
 * This stops synchronous streams for a fused tcp endpoint
 * and prevents tcp_fuse_rrw() from pulling data from it.
 */
#define	TCP_FUSE_SYNCSTR_STOP(tcp) {				\
	if ((tcp)->tcp_direct_sockfs) {				\
		mutex_enter(&(tcp)->tcp_fuse_lock);		\
		(tcp)->tcp_fuse_syncstr_stopped = B_TRUE;	\
		mutex_exit(&(tcp)->tcp_fuse_lock);		\
	}							\
}

/*
 * This causes all calls to tcp_fuse_rrw() to block until
 * TCP_FUSE_SYNCSTR_UNPLUG_DRAIN() is called.
 */
#define	TCP_FUSE_SYNCSTR_PLUG_DRAIN(tcp) {			\
	if ((tcp)->tcp_direct_sockfs) {				\
		mutex_enter(&(tcp)->tcp_fuse_lock);		\
		ASSERT(!(tcp)->tcp_fuse_syncstr_plugged);	\
		(tcp)->tcp_fuse_syncstr_plugged = B_TRUE;	\
		mutex_exit(&(tcp)->tcp_fuse_lock);		\
	}							\
}

/*
 * This unplugs the draining of data through tcp_fuse_rrw(); see
 * the comments in tcp_fuse_rrw() for how we preserve ordering.
 */
#define	TCP_FUSE_SYNCSTR_UNPLUG_DRAIN(tcp) {			\
	if ((tcp)->tcp_direct_sockfs) {				\
		mutex_enter(&(tcp)->tcp_fuse_lock);		\
		(tcp)->tcp_fuse_syncstr_plugged = B_FALSE;	\
		(void) cv_broadcast(&(tcp)->tcp_fuse_plugcv);	\
		mutex_exit(&(tcp)->tcp_fuse_lock);		\
	}							\
}

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

/* Named Dispatch Parameter Management Structure */
typedef struct tcpparam_s {
	uint32_t	tcp_param_min;
	uint32_t	tcp_param_max;
	uint32_t	tcp_param_val;
	char		*tcp_param_name;
} tcpparam_t;

extern tcpparam_t tcp_param_arr[];

#define	tcp_time_wait_interval			tcp_param_arr[0].tcp_param_val
#define	tcp_conn_req_max_q			tcp_param_arr[1].tcp_param_val
#define	tcp_conn_req_max_q0			tcp_param_arr[2].tcp_param_val
#define	tcp_conn_req_min			tcp_param_arr[3].tcp_param_val
#define	tcp_conn_grace_period			tcp_param_arr[4].tcp_param_val
#define	tcp_cwnd_max_				tcp_param_arr[5].tcp_param_val
#define	tcp_dbg					tcp_param_arr[6].tcp_param_val
#define	tcp_smallest_nonpriv_port		tcp_param_arr[7].tcp_param_val
#define	tcp_ip_abort_cinterval			tcp_param_arr[8].tcp_param_val
#define	tcp_ip_abort_linterval			tcp_param_arr[9].tcp_param_val
#define	tcp_ip_abort_interval			tcp_param_arr[10].tcp_param_val
#define	tcp_ip_notify_cinterval			tcp_param_arr[11].tcp_param_val
#define	tcp_ip_notify_interval			tcp_param_arr[12].tcp_param_val
#define	tcp_ipv4_ttl				tcp_param_arr[13].tcp_param_val
#define	tcp_keepalive_interval_high		tcp_param_arr[14].tcp_param_max
#define	tcp_keepalive_interval			tcp_param_arr[14].tcp_param_val
#define	tcp_keepalive_interval_low		tcp_param_arr[14].tcp_param_min
#define	tcp_maxpsz_multiplier			tcp_param_arr[15].tcp_param_val
#define	tcp_mss_def_ipv4			tcp_param_arr[16].tcp_param_val
#define	tcp_mss_max_ipv4			tcp_param_arr[17].tcp_param_val
#define	tcp_mss_min				tcp_param_arr[18].tcp_param_val
#define	tcp_naglim_def				tcp_param_arr[19].tcp_param_val
#define	tcp_rexmit_interval_initial		tcp_param_arr[20].tcp_param_val
#define	tcp_rexmit_interval_max			tcp_param_arr[21].tcp_param_val
#define	tcp_rexmit_interval_min			tcp_param_arr[22].tcp_param_val
#define	tcp_deferred_ack_interval		tcp_param_arr[23].tcp_param_val
#define	tcp_snd_lowat_fraction			tcp_param_arr[24].tcp_param_val
#define	tcp_sth_rcv_hiwat			tcp_param_arr[25].tcp_param_val
#define	tcp_sth_rcv_lowat			tcp_param_arr[26].tcp_param_val
#define	tcp_dupack_fast_retransmit		tcp_param_arr[27].tcp_param_val
#define	tcp_ignore_path_mtu			tcp_param_arr[28].tcp_param_val
#define	tcp_smallest_anon_port			tcp_param_arr[29].tcp_param_val
#define	tcp_largest_anon_port			tcp_param_arr[30].tcp_param_val
#define	tcp_xmit_hiwat				tcp_param_arr[31].tcp_param_val
#define	tcp_xmit_lowat				tcp_param_arr[32].tcp_param_val
#define	tcp_recv_hiwat				tcp_param_arr[33].tcp_param_val
#define	tcp_recv_hiwat_minmss			tcp_param_arr[34].tcp_param_val
#define	tcp_fin_wait_2_flush_interval		tcp_param_arr[35].tcp_param_val
#define	tcp_co_min				tcp_param_arr[36].tcp_param_val
#define	tcp_max_buf				tcp_param_arr[37].tcp_param_val
#define	tcp_strong_iss				tcp_param_arr[38].tcp_param_val
#define	tcp_rtt_updates				tcp_param_arr[39].tcp_param_val
#define	tcp_wscale_always			tcp_param_arr[40].tcp_param_val
#define	tcp_tstamp_always			tcp_param_arr[41].tcp_param_val
#define	tcp_tstamp_if_wscale			tcp_param_arr[42].tcp_param_val
#define	tcp_rexmit_interval_extra		tcp_param_arr[43].tcp_param_val
#define	tcp_deferred_acks_max			tcp_param_arr[44].tcp_param_val
#define	tcp_slow_start_after_idle		tcp_param_arr[45].tcp_param_val
#define	tcp_slow_start_initial			tcp_param_arr[46].tcp_param_val
#define	tcp_co_timer_interval			tcp_param_arr[47].tcp_param_val
#define	tcp_sack_permitted			tcp_param_arr[48].tcp_param_val
#define	tcp_trace				tcp_param_arr[49].tcp_param_val
#define	tcp_compression_enabled			tcp_param_arr[50].tcp_param_val
#define	tcp_ipv6_hoplimit			tcp_param_arr[51].tcp_param_val
#define	tcp_mss_def_ipv6			tcp_param_arr[52].tcp_param_val
#define	tcp_mss_max_ipv6			tcp_param_arr[53].tcp_param_val
#define	tcp_rev_src_routes			tcp_param_arr[54].tcp_param_val
#define	tcp_local_dack_interval			tcp_param_arr[55].tcp_param_val
#define	tcp_ndd_get_info_interval		tcp_param_arr[56].tcp_param_val
#define	tcp_local_dacks_max			tcp_param_arr[57].tcp_param_val
#define	tcp_ecn_permitted			tcp_param_arr[58].tcp_param_val
#define	tcp_rst_sent_rate_enabled		tcp_param_arr[59].tcp_param_val
#define	tcp_rst_sent_rate			tcp_param_arr[60].tcp_param_val
#define	tcp_push_timer_interval			tcp_param_arr[61].tcp_param_val
#define	tcp_use_smss_as_mss_opt			tcp_param_arr[62].tcp_param_val
#define	tcp_keepalive_abort_interval_high	tcp_param_arr[63].tcp_param_max
#define	tcp_keepalive_abort_interval		tcp_param_arr[63].tcp_param_val
#define	tcp_keepalive_abort_interval_low	tcp_param_arr[63].tcp_param_min

/* Kstats */
typedef struct tcp_stat {
	kstat_named_t	tcp_time_wait;
	kstat_named_t	tcp_time_wait_syn;
	kstat_named_t	tcp_time_wait_syn_success;
	kstat_named_t	tcp_time_wait_syn_fail;
	kstat_named_t	tcp_reinput_syn;
	kstat_named_t	tcp_ip_output;
	kstat_named_t	tcp_detach_non_time_wait;
	kstat_named_t	tcp_detach_time_wait;
	kstat_named_t	tcp_time_wait_reap;
	kstat_named_t	tcp_clean_death_nondetached;
	kstat_named_t	tcp_reinit_calls;
	kstat_named_t	tcp_eager_err1;
	kstat_named_t	tcp_eager_err2;
	kstat_named_t	tcp_eager_blowoff_calls;
	kstat_named_t	tcp_eager_blowoff_q;
	kstat_named_t	tcp_eager_blowoff_q0;
	kstat_named_t	tcp_not_hard_bound;
	kstat_named_t	tcp_no_listener;
	kstat_named_t	tcp_found_eager;
	kstat_named_t	tcp_wrong_queue;
	kstat_named_t	tcp_found_eager_binding1;
	kstat_named_t	tcp_found_eager_bound1;
	kstat_named_t	tcp_eager_has_listener1;
	kstat_named_t	tcp_open_alloc;
	kstat_named_t	tcp_open_detached_alloc;
	kstat_named_t	tcp_rput_time_wait;
	kstat_named_t	tcp_listendrop;
	kstat_named_t	tcp_listendropq0;
	kstat_named_t	tcp_wrong_rq;
	kstat_named_t	tcp_rsrv_calls;
	kstat_named_t	tcp_eagerfree2;
	kstat_named_t	tcp_eagerfree3;
	kstat_named_t	tcp_eagerfree4;
	kstat_named_t	tcp_eagerfree5;
	kstat_named_t	tcp_timewait_syn_fail;
	kstat_named_t	tcp_listen_badflags;
	kstat_named_t	tcp_timeout_calls;
	kstat_named_t	tcp_timeout_cached_alloc;
	kstat_named_t	tcp_timeout_cancel_reqs;
	kstat_named_t	tcp_timeout_canceled;
	kstat_named_t	tcp_timermp_alloced;
	kstat_named_t	tcp_timermp_freed;
	kstat_named_t	tcp_timermp_allocfail;
	kstat_named_t	tcp_timermp_allocdblfail;
	kstat_named_t	tcp_push_timer_cnt;
	kstat_named_t	tcp_ack_timer_cnt;
	kstat_named_t	tcp_ire_null1;
	kstat_named_t	tcp_ire_null;
	kstat_named_t	tcp_ip_send;
	kstat_named_t	tcp_ip_ire_send;
	kstat_named_t   tcp_wsrv_called;
	kstat_named_t   tcp_flwctl_on;
	kstat_named_t	tcp_timer_fire_early;
	kstat_named_t	tcp_timer_fire_miss;
	kstat_named_t	tcp_freelist_cleanup;
	kstat_named_t	tcp_rput_v6_error;
	kstat_named_t	tcp_out_sw_cksum;
	kstat_named_t	tcp_out_sw_cksum_bytes;
	kstat_named_t	tcp_zcopy_on;
	kstat_named_t	tcp_zcopy_off;
	kstat_named_t	tcp_zcopy_backoff;
	kstat_named_t	tcp_zcopy_disable;
	kstat_named_t	tcp_mdt_pkt_out;
	kstat_named_t	tcp_mdt_pkt_out_v4;
	kstat_named_t	tcp_mdt_pkt_out_v6;
	kstat_named_t	tcp_mdt_discarded;
	kstat_named_t	tcp_mdt_conn_halted1;
	kstat_named_t	tcp_mdt_conn_halted2;
	kstat_named_t	tcp_mdt_conn_halted3;
	kstat_named_t	tcp_mdt_conn_resumed1;
	kstat_named_t	tcp_mdt_conn_resumed2;
	kstat_named_t	tcp_mdt_legacy_small;
	kstat_named_t	tcp_mdt_legacy_all;
	kstat_named_t	tcp_mdt_legacy_ret;
	kstat_named_t	tcp_mdt_allocfail;
	kstat_named_t	tcp_mdt_addpdescfail;
	kstat_named_t	tcp_mdt_allocd;
	kstat_named_t	tcp_mdt_linked;
	kstat_named_t	tcp_fusion_flowctl;
	kstat_named_t	tcp_fusion_backenabled;
	kstat_named_t	tcp_fusion_urg;
	kstat_named_t	tcp_fusion_putnext;
	kstat_named_t	tcp_fusion_unfusable;
	kstat_named_t	tcp_fusion_aborted;
	kstat_named_t	tcp_fusion_unqualified;
	kstat_named_t	tcp_fusion_rrw_busy;
	kstat_named_t	tcp_fusion_rrw_msgcnt;
	kstat_named_t	tcp_fusion_rrw_plugged;
	kstat_named_t	tcp_in_ack_unsent_drop;
	kstat_named_t	tcp_sock_fallback;
} tcp_stat_t;

extern tcp_stat_t tcp_statistics;

#define	TCP_STAT(x)		(tcp_statistics.x.value.ui64++)
#define	TCP_STAT_UPDATE(x, n)	(tcp_statistics.x.value.ui64 += (n))
#define	TCP_STAT_SET(x, n)	(tcp_statistics.x.value.ui64 = (n))

extern struct qinit tcp_loopback_rinit, tcp_rinit;
extern boolean_t do_tcp_fusion;

extern int	tcp_maxpsz_set(tcp_t *, boolean_t);
extern void	tcp_timers_stop(tcp_t *);
extern void	tcp_rcv_enqueue(tcp_t *, mblk_t *, uint_t);
extern void	tcp_push_timer(void *);
extern timeout_id_t tcp_timeout(conn_t *, void (*)(void *), clock_t);
extern clock_t	tcp_timeout_cancel(conn_t *, timeout_id_t);

extern void	tcp_fuse(tcp_t *, uchar_t *, tcph_t *);
extern void	tcp_unfuse(tcp_t *);
extern boolean_t tcp_fuse_output(tcp_t *, mblk_t *, uint32_t);
extern void	tcp_fuse_output_urg(tcp_t *, mblk_t *);
extern boolean_t tcp_fuse_rcv_drain(queue_t *, tcp_t *, mblk_t **);
extern void	tcp_fuse_syncstr_enable_pair(tcp_t *);
extern void	tcp_fuse_disable_pair(tcp_t *, boolean_t);
extern int	tcp_fuse_rrw(queue_t *, struiod_t *);
extern int	tcp_fuse_rinfop(queue_t *, infod_t *);
extern size_t	tcp_fuse_set_rcv_hiwat(tcp_t *, size_t);
extern int	tcp_fuse_maxpsz_set(tcp_t *);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_TCP_IMPL_H */
