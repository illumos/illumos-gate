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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
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
		mutex_enter(&(tcp)->tcp_non_sq_lock);		\
		(tcp)->tcp_fuse_syncstr_stopped = B_TRUE;	\
		mutex_exit(&(tcp)->tcp_non_sq_lock);		\
	}							\
}

/*
 * This causes all calls to tcp_fuse_rrw() to block until
 * TCP_FUSE_SYNCSTR_UNPLUG_DRAIN() is called.
 */
#define	TCP_FUSE_SYNCSTR_PLUG_DRAIN(tcp) {			\
	if ((tcp)->tcp_direct_sockfs) {				\
		mutex_enter(&(tcp)->tcp_non_sq_lock);		\
		ASSERT(!(tcp)->tcp_fuse_syncstr_plugged);	\
		(tcp)->tcp_fuse_syncstr_plugged = B_TRUE;	\
		mutex_exit(&(tcp)->tcp_non_sq_lock);		\
	}							\
}

/*
 * This unplugs the draining of data through tcp_fuse_rrw(); see
 * the comments in tcp_fuse_rrw() for how we preserve ordering.
 */
#define	TCP_FUSE_SYNCSTR_UNPLUG_DRAIN(tcp) {			\
	if ((tcp)->tcp_direct_sockfs) {				\
		mutex_enter(&(tcp)->tcp_non_sq_lock);		\
		(tcp)->tcp_fuse_syncstr_plugged = B_FALSE;	\
		(void) cv_broadcast(&(tcp)->tcp_fuse_plugcv);	\
		mutex_exit(&(tcp)->tcp_non_sq_lock);		\
	}							\
}

/*
 * Before caching the conn IRE, we need to make sure certain TCP
 * states are in sync with the ire. The mismatch could occur if the
 * TCP state has been set in tcp_adapt_ire() using a different IRE,
 * e.g if an address was not present during an initial connect(),
 * tcp_adapt_ire() will set the state using the interface route.
 * Subsequently, if the address is added to the local machine, the
 * retransmitted SYN will get the correct (loopback) IRE, but the TCP
 * state (tcp_loopback and tcp_localnet) will remain out of sync.
 * This is especially an issue with TCP fusion which relies on the
 * TCP state to be accurate.
 *
 * This check/change should be made only if the TCP is not yet in
 * the established state, else it would lead to inconsistencies.
 */
#define	TCP_CHECK_IREINFO(tcp, ire) {					\
	if ((tcp)->tcp_state < TCPS_ESTABLISHED) {			\
		if (((ire)->ire_type & (IRE_LOOPBACK | 			\
		    IRE_LOCAL)) && !(tcp)->tcp_loopback) {		\
			(tcp)->tcp_loopback = B_TRUE;			\
		} else if ((tcp)->tcp_loopback && 			\
		    !((ire)->ire_type & (IRE_LOOPBACK | IRE_LOCAL))) {	\
			(tcp)->tcp_loopback = B_FALSE;			\
		}							\
		if ((tcp)->tcp_ipversion == IPV4_VERSION) {		\
			(tcp)->tcp_localnet =				\
			    ((ire)->ire_gateway_addr == 0);		\
		} else {						\
			(tcp)->tcp_localnet =				\
			    IN6_IS_ADDR_UNSPECIFIED(			\
			    &(ire)->ire_gateway_addr_v6);		\
		}							\
	}								\
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


#define	tcps_time_wait_interval		tcps_params[0].tcp_param_val
#define	tcps_conn_req_max_q		tcps_params[1].tcp_param_val
#define	tcps_conn_req_max_q0		tcps_params[2].tcp_param_val
#define	tcps_conn_req_min		tcps_params[3].tcp_param_val
#define	tcps_conn_grace_period		tcps_params[4].tcp_param_val
#define	tcps_cwnd_max_			tcps_params[5].tcp_param_val
#define	tcps_dbg			tcps_params[6].tcp_param_val
#define	tcps_smallest_nonpriv_port	tcps_params[7].tcp_param_val
#define	tcps_ip_abort_cinterval		tcps_params[8].tcp_param_val
#define	tcps_ip_abort_linterval		tcps_params[9].tcp_param_val
#define	tcps_ip_abort_interval		tcps_params[10].tcp_param_val
#define	tcps_ip_notify_cinterval	tcps_params[11].tcp_param_val
#define	tcps_ip_notify_interval		tcps_params[12].tcp_param_val
#define	tcps_ipv4_ttl			tcps_params[13].tcp_param_val
#define	tcps_keepalive_interval_high	tcps_params[14].tcp_param_max
#define	tcps_keepalive_interval		tcps_params[14].tcp_param_val
#define	tcps_keepalive_interval_low	tcps_params[14].tcp_param_min
#define	tcps_maxpsz_multiplier		tcps_params[15].tcp_param_val
#define	tcps_mss_def_ipv4		tcps_params[16].tcp_param_val
#define	tcps_mss_max_ipv4		tcps_params[17].tcp_param_val
#define	tcps_mss_min			tcps_params[18].tcp_param_val
#define	tcps_naglim_def			tcps_params[19].tcp_param_val
#define	tcps_rexmit_interval_initial	tcps_params[20].tcp_param_val
#define	tcps_rexmit_interval_max	tcps_params[21].tcp_param_val
#define	tcps_rexmit_interval_min	tcps_params[22].tcp_param_val
#define	tcps_deferred_ack_interval	tcps_params[23].tcp_param_val
#define	tcps_snd_lowat_fraction		tcps_params[24].tcp_param_val
#define	tcps_sth_rcv_hiwat		tcps_params[25].tcp_param_val
#define	__tcps_not_used1		tcps_params[26].tcp_param_val
#define	tcps_dupack_fast_retransmit	tcps_params[27].tcp_param_val
#define	tcps_ignore_path_mtu		tcps_params[28].tcp_param_val
#define	tcps_smallest_anon_port		tcps_params[29].tcp_param_val
#define	tcps_largest_anon_port		tcps_params[30].tcp_param_val
#define	tcps_xmit_hiwat			tcps_params[31].tcp_param_val
#define	tcps_xmit_lowat			tcps_params[32].tcp_param_val
#define	tcps_recv_hiwat			tcps_params[33].tcp_param_val
#define	tcps_recv_hiwat_minmss		tcps_params[34].tcp_param_val
#define	tcps_fin_wait_2_flush_interval	tcps_params[35].tcp_param_val
#define	__tcps_not_used2		tcps_params[36].tcp_param_val
#define	tcps_max_buf			tcps_params[37].tcp_param_val
#define	tcps_strong_iss			tcps_params[38].tcp_param_val
#define	tcps_rtt_updates		tcps_params[39].tcp_param_val
#define	tcps_wscale_always		tcps_params[40].tcp_param_val
#define	tcps_tstamp_always		tcps_params[41].tcp_param_val
#define	tcps_tstamp_if_wscale		tcps_params[42].tcp_param_val
#define	tcps_rexmit_interval_extra	tcps_params[43].tcp_param_val
#define	tcps_deferred_acks_max		tcps_params[44].tcp_param_val
#define	tcps_slow_start_after_idle	tcps_params[45].tcp_param_val
#define	tcps_slow_start_initial		tcps_params[46].tcp_param_val
#define	tcps_co_timer_interval		tcps_params[47].tcp_param_val
#define	tcps_sack_permitted		tcps_params[48].tcp_param_val
#define	tcps_trace			tcps_params[49].tcp_param_val
#define	__tcps_not_used4		tcps_params[50].tcp_param_val
#define	tcps_ipv6_hoplimit		tcps_params[51].tcp_param_val
#define	tcps_mss_def_ipv6		tcps_params[52].tcp_param_val
#define	tcps_mss_max_ipv6		tcps_params[53].tcp_param_val
#define	tcps_rev_src_routes		tcps_params[54].tcp_param_val
#define	tcps_local_dack_interval	tcps_params[55].tcp_param_val
#define	tcps_ndd_get_info_interval	tcps_params[56].tcp_param_val
#define	tcps_local_dacks_max		tcps_params[57].tcp_param_val
#define	tcps_ecn_permitted		tcps_params[58].tcp_param_val
#define	tcps_rst_sent_rate_enabled	tcps_params[59].tcp_param_val
#define	tcps_rst_sent_rate		tcps_params[60].tcp_param_val
#define	tcps_push_timer_interval	tcps_params[61].tcp_param_val
#define	tcps_use_smss_as_mss_opt	tcps_params[62].tcp_param_val
#define	tcps_keepalive_abort_interval_high	tcps_params[63].tcp_param_max
#define	tcps_keepalive_abort_interval		tcps_params[63].tcp_param_val
#define	tcps_keepalive_abort_interval_low	tcps_params[63].tcp_param_min

extern struct qinit tcp_loopback_rinit, tcp_rinitv4, tcp_rinitv6;
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

/*
 * Object to represent database of options to search passed to
 * {sock,tpi}optcom_req() interface routine to take care of option
 * management and associated methods.
 */
extern optdb_obj_t	tcp_opt_obj;
extern uint_t		tcp_max_optsize;

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_TCP_IMPL_H */
