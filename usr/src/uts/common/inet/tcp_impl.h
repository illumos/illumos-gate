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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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

#include <inet/optcom.h>
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
#define	tcps_dupack_fast_retransmit	tcps_params[25].tcp_param_val
#define	tcps_ignore_path_mtu		tcps_params[26].tcp_param_val
#define	tcps_smallest_anon_port		tcps_params[27].tcp_param_val
#define	tcps_largest_anon_port		tcps_params[28].tcp_param_val
#define	tcps_xmit_hiwat			tcps_params[29].tcp_param_val
#define	tcps_xmit_lowat			tcps_params[30].tcp_param_val
#define	tcps_recv_hiwat			tcps_params[31].tcp_param_val
#define	tcps_recv_hiwat_minmss		tcps_params[32].tcp_param_val
#define	tcps_fin_wait_2_flush_interval	tcps_params[33].tcp_param_val
#define	tcps_max_buf			tcps_params[34].tcp_param_val
#define	tcps_strong_iss			tcps_params[35].tcp_param_val
#define	tcps_rtt_updates		tcps_params[36].tcp_param_val
#define	tcps_wscale_always		tcps_params[37].tcp_param_val
#define	tcps_tstamp_always		tcps_params[38].tcp_param_val
#define	tcps_tstamp_if_wscale		tcps_params[39].tcp_param_val
#define	tcps_rexmit_interval_extra	tcps_params[40].tcp_param_val
#define	tcps_deferred_acks_max		tcps_params[41].tcp_param_val
#define	tcps_slow_start_after_idle	tcps_params[42].tcp_param_val
#define	tcps_slow_start_initial		tcps_params[43].tcp_param_val
#define	tcps_sack_permitted		tcps_params[44].tcp_param_val
#define	tcps_ipv6_hoplimit		tcps_params[45].tcp_param_val
#define	tcps_mss_def_ipv6		tcps_params[46].tcp_param_val
#define	tcps_mss_max_ipv6		tcps_params[47].tcp_param_val
#define	tcps_rev_src_routes		tcps_params[48].tcp_param_val
#define	tcps_local_dack_interval	tcps_params[49].tcp_param_val
#define	tcps_local_dacks_max		tcps_params[50].tcp_param_val
#define	tcps_ecn_permitted		tcps_params[51].tcp_param_val
#define	tcps_rst_sent_rate_enabled	tcps_params[52].tcp_param_val
#define	tcps_rst_sent_rate		tcps_params[53].tcp_param_val
#define	tcps_push_timer_interval	tcps_params[54].tcp_param_val
#define	tcps_use_smss_as_mss_opt	tcps_params[55].tcp_param_val
#define	tcps_keepalive_abort_interval_high	tcps_params[56].tcp_param_max
#define	tcps_keepalive_abort_interval		tcps_params[56].tcp_param_val
#define	tcps_keepalive_abort_interval_low	tcps_params[56].tcp_param_min
#define	tcps_dev_flow_ctl		tcps_params[57].tcp_param_val
#define	tcps_reass_timeout		tcps_params[58].tcp_param_val

extern struct qinit tcp_rinitv4, tcp_rinitv6;
extern boolean_t do_tcp_fusion;

extern int	tcp_maxpsz_set(tcp_t *, boolean_t);
extern void	tcp_timers_stop(tcp_t *);
extern void	tcp_rcv_enqueue(tcp_t *, mblk_t *, uint_t, cred_t *);
extern void	tcp_push_timer(void *);
extern timeout_id_t tcp_timeout(conn_t *, void (*)(void *), clock_t);
extern clock_t	tcp_timeout_cancel(conn_t *, timeout_id_t);

extern void	tcp_fuse(tcp_t *, uchar_t *, tcpha_t *);
extern void	tcp_unfuse(tcp_t *);
extern boolean_t tcp_fuse_output(tcp_t *, mblk_t *, uint32_t);
extern void	tcp_fuse_output_urg(tcp_t *, mblk_t *);
extern boolean_t tcp_fuse_rcv_drain(queue_t *, tcp_t *, mblk_t **);
extern size_t	tcp_fuse_set_rcv_hiwat(tcp_t *, size_t);
extern int	tcp_fuse_maxpsz(tcp_t *);
extern void	tcp_fuse_backenable(tcp_t *);
extern int	tcp_rwnd_set(tcp_t *, uint32_t);

/*
 * Object to represent database of options to search passed to
 * {sock,tpi}optcom_req() interface routine to take care of option
 * management and associated methods.
 */
extern optdb_obj_t	tcp_opt_obj;
extern uint_t		tcp_max_optsize;

extern sock_lower_handle_t tcp_create(int, int, int, sock_downcalls_t **,
    uint_t *, int *, int, cred_t *);
extern int tcp_fallback(sock_lower_handle_t, queue_t *, boolean_t,
    so_proto_quiesced_cb_t);

extern sock_downcalls_t sock_tcp_downcalls;


extern int	tcp_opt_default(queue_t *, t_scalar_t, t_scalar_t, uchar_t *);
extern int	tcp_tpi_opt_get(queue_t *, t_scalar_t, t_scalar_t, uchar_t *);
extern int	tcp_tpi_opt_set(queue_t *, uint_t, int, int, uint_t, uchar_t *,
		    uint_t *, uchar_t *, void *, cred_t *);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_TCP_IMPL_H */
