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

#ifndef	_INET_TCP_STACK_H
#define	_INET_TCP_STACK_H

#include <sys/netstack.h>
#include <inet/ip.h>
#include <inet/ipdrop.h>

#ifdef	__cplusplus
extern "C" {
#endif

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
	kstat_named_t	tcp_timermp_freed;
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
	kstat_named_t	tcp_lso_enabled;
	kstat_named_t	tcp_lso_disabled;
	kstat_named_t	tcp_lso_times;
	kstat_named_t	tcp_lso_pkt_out;
} tcp_stat_t;

#define	TCP_STAT(tcps, x)	((tcps)->tcps_statistics.x.value.ui64++)
#define	TCP_STAT_UPDATE(tcps, x, n)	\
	((tcps)->tcps_statistics.x.value.ui64 += (n))
#define	TCP_STAT_SET(tcps, x, n)	\
	((tcps)->tcps_statistics.x.value.ui64 = (n))

typedef struct tcp_g_stat {
	kstat_named_t	tcp_timermp_alloced;
	kstat_named_t	tcp_timermp_allocfail;
	kstat_named_t	tcp_timermp_allocdblfail;
	kstat_named_t	tcp_freelist_cleanup;
} tcp_g_stat_t;

#ifdef _KERNEL

/*
 * TCP stack instances
 */
struct tcp_stack {
	netstack_t	*tcps_netstack;	/* Common netstack */

	mib2_tcp_t	tcps_mib;

	/* Protected by tcps_g_q_lock */
	queue_t		*tcps_g_q;	/* Default queue */
	uint_t		tcps_refcnt;	/* Total number of tcp_t's */
	kmutex_t	tcps_g_q_lock;
	kcondvar_t	tcps_g_q_cv;
	kthread_t	*tcps_g_q_creator;
	struct __ldi_handle *tcps_g_q_lh;
	cred_t		*tcps_g_q_cr;    /* For _inactive close call */

	/* Protected by tcp_hsp_lock */
	struct tcp_hsp	**tcps_hsp_hash;	/* Hash table for HSPs */
	krwlock_t	 tcps_hsp_lock;

	/*
	 * Extra privileged ports. In host byte order.
	 * Protected by tcp_epriv_port_lock.
	 */
#define	TCP_NUM_EPRIV_PORTS	64
	int		tcps_g_num_epriv_ports;
	uint16_t	tcps_g_epriv_ports[TCP_NUM_EPRIV_PORTS];
	kmutex_t	tcps_epriv_port_lock;

	/*
	 * The smallest anonymous port in the priviledged port range which TCP
	 * looks for free port.  Use in the option TCP_ANONPRIVBIND.
	 */
	in_port_t	tcps_min_anonpriv_port;

	/* Only modified during _init and _fini thus no locking is needed. */
	caddr_t		tcps_g_nd;
	struct tcpparam_s *tcps_params;	/* ndd parameters */
	struct tcpparam_s *tcps_wroff_xtra_param;
	struct tcpparam_s *tcps_mdt_head_param;
	struct tcpparam_s *tcps_mdt_tail_param;
	struct tcpparam_s *tcps_mdt_max_pbufs_param;

	/* Hint not protected by any lock */
	uint_t		tcps_next_port_to_try;

	/* TCP bind hash list - all tcp_t with state >= BOUND. */
	struct tf_s	*tcps_bind_fanout;

	/* TCP queue hash list - all tcp_t in case they will be an acceptor. */
	struct tf_s	*tcps_acceptor_fanout;

	/*
	 * MIB-2 stuff for SNMP
	 * Note: tcpInErrs {tcp 15} is accumulated in ip.c
	 */
	kstat_t		*tcps_mibkp;	/* kstat exporting tcp_mib data */
	kstat_t		*tcps_kstat;
	tcp_stat_t	tcps_statistics;

	uint32_t	tcps_iss_incr_extra;
				/* Incremented for each connection */
	kmutex_t	tcps_iss_key_lock;
	MD5_CTX		tcps_iss_key;

	/* Packet dropper for TCP IPsec policy drops. */
	ipdropper_t	tcps_dropper;

	/*
	 * This controls the rate some ndd info report functions can be used
	 * by non-priviledged users.  It stores the last time such info is
	 * requested.  When those report functions are called again, this
	 * is checked with the current time and compare with the ndd param
	 * tcp_ndd_get_info_interval.
	 */
	clock_t		tcps_last_ndd_get_info_time;

	/*
	 * These two variables control the rate for TCP to generate RSTs in
	 * response to segments not belonging to any connections.  We limit
	 * TCP to sent out tcp_rst_sent_rate (ndd param) number of RSTs in
	 * each 1 second interval.  This is to protect TCP against DoS attack.
	 */
	clock_t		tcps_last_rst_intrvl;
	uint32_t	tcps_rst_cnt;
	/* The number of RST not sent because of the rate limit. */
	uint32_t	tcps_rst_unsent;
};
typedef struct tcp_stack tcp_stack_t;

#endif /* _KERNEL */
#ifdef	__cplusplus
}
#endif

#endif	/* _INET_TCP_STACK_H */
