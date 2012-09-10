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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_INET_TCP_STATS_H
#define	_INET_TCP_STATS_H

/*
 * TCP private kernel statistics declarations.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

/*
 * TCP Statistics.
 *
 * How TCP statistics work.
 *
 * There are two types of statistics invoked by two macros.
 *
 * TCP_STAT(name) does non-atomic increment of a named stat counter. It is
 * supposed to be used in non MT-hot paths of the code.
 *
 * TCP_DBGSTAT(name) does atomic increment of a named stat counter. It is
 * supposed to be used for DEBUG purposes and may be used on a hot path.
 * These counters are only available in a debugged kernel.  They are grouped
 * under the TCP_DEBUG_COUNTER C pre-processor condition.
 *
 * Both TCP_STAT and TCP_DBGSTAT counters are available using kstat
 * (use "kstat tcp" to get them).
 *
 * How to add new counters.
 *
 * 1) Add a field in the tcp_stat structure describing your counter.
 * 2) Add a line in the template in tcp_kstat2_init() with the name
 *    of the counter.
 * 3) Update tcp_clr_stats() and tcp_cp_stats() with the new counters.
 *    IMPORTANT!! - make sure that all the above functions are in sync !!
 * 4) Use either TCP_STAT or TCP_DBGSTAT with the name.
 *
 * Please avoid using private counters which are not kstat-exported.
 *
 * Implementation note.
 *
 * Both the MIB2 and tcp_stat_t counters are kept per CPU in the array
 * tcps_sc in tcp_stack_t.  Each array element is a pointer to a
 * tcp_stats_cpu_t struct.  Once allocated, the tcp_stats_cpu_t struct is
 * not freed until the tcp_stack_t is going away.  So there is no need to
 * acquire a lock before accessing the stats counters.
 */

#ifndef TCP_DEBUG_COUNTER
#ifdef DEBUG
#define	TCP_DEBUG_COUNTER 1
#else
#define	TCP_DEBUG_COUNTER 0
#endif
#endif

/* Kstats */
typedef struct tcp_stat {
	kstat_named_t	tcp_time_wait_syn_success;
	kstat_named_t	tcp_clean_death_nondetached;
	kstat_named_t	tcp_eager_blowoff_q;
	kstat_named_t	tcp_eager_blowoff_q0;
	kstat_named_t	tcp_no_listener;
	kstat_named_t	tcp_listendrop;
	kstat_named_t	tcp_listendropq0;
	kstat_named_t	tcp_wsrv_called;
	kstat_named_t	tcp_flwctl_on;
	kstat_named_t	tcp_timer_fire_early;
	kstat_named_t	tcp_timer_fire_miss;
	kstat_named_t	tcp_zcopy_on;
	kstat_named_t	tcp_zcopy_off;
	kstat_named_t	tcp_zcopy_backoff;
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
	kstat_named_t	tcp_listen_cnt_drop;
	kstat_named_t	tcp_listen_mem_drop;
	kstat_named_t	tcp_zwin_mem_drop;
	kstat_named_t	tcp_zwin_ack_syn;
	kstat_named_t	tcp_rst_unsent;
	kstat_named_t	tcp_reclaim_cnt;
	kstat_named_t	tcp_reass_timeout;
#ifdef TCP_DEBUG_COUNTER
	kstat_named_t	tcp_time_wait;
	kstat_named_t	tcp_rput_time_wait;
	kstat_named_t	tcp_detach_time_wait;
	kstat_named_t	tcp_timeout_calls;
	kstat_named_t	tcp_timeout_cached_alloc;
	kstat_named_t	tcp_timeout_cancel_reqs;
	kstat_named_t	tcp_timeout_canceled;
	kstat_named_t	tcp_timermp_freed;
	kstat_named_t	tcp_push_timer_cnt;
	kstat_named_t	tcp_ack_timer_cnt;
#endif
} tcp_stat_t;

/*
 * This struct contains only the counter part of tcp_stat_t.  It is used
 * in tcp_stats_cpu_t instead of tcp_stat_t to save memory space.
 */
typedef struct tcp_stat_counter_s {
	uint64_t	tcp_time_wait_syn_success;
	uint64_t	tcp_clean_death_nondetached;
	uint64_t	tcp_eager_blowoff_q;
	uint64_t	tcp_eager_blowoff_q0;
	uint64_t	tcp_no_listener;
	uint64_t	tcp_listendrop;
	uint64_t	tcp_listendropq0;
	uint64_t	tcp_wsrv_called;
	uint64_t	tcp_flwctl_on;
	uint64_t	tcp_timer_fire_early;
	uint64_t	tcp_timer_fire_miss;
	uint64_t	tcp_zcopy_on;
	uint64_t	tcp_zcopy_off;
	uint64_t	tcp_zcopy_backoff;
	uint64_t	tcp_fusion_flowctl;
	uint64_t	tcp_fusion_backenabled;
	uint64_t	tcp_fusion_urg;
	uint64_t	tcp_fusion_putnext;
	uint64_t	tcp_fusion_unfusable;
	uint64_t	tcp_fusion_aborted;
	uint64_t	tcp_fusion_unqualified;
	uint64_t	tcp_fusion_rrw_busy;
	uint64_t	tcp_fusion_rrw_msgcnt;
	uint64_t	tcp_fusion_rrw_plugged;
	uint64_t	tcp_in_ack_unsent_drop;
	uint64_t	tcp_sock_fallback;
	uint64_t	tcp_lso_enabled;
	uint64_t	tcp_lso_disabled;
	uint64_t	tcp_lso_times;
	uint64_t	tcp_lso_pkt_out;
	uint64_t	tcp_listen_cnt_drop;
	uint64_t	tcp_listen_mem_drop;
	uint64_t	tcp_zwin_mem_drop;
	uint64_t	tcp_zwin_ack_syn;
	uint64_t	tcp_rst_unsent;
	uint64_t	tcp_reclaim_cnt;
	uint64_t	tcp_reass_timeout;
#ifdef TCP_DEBUG_COUNTER
	uint64_t	tcp_time_wait;
	uint64_t	tcp_rput_time_wait;
	uint64_t	tcp_detach_time_wait;
	uint64_t	tcp_timeout_calls;
	uint64_t	tcp_timeout_cached_alloc;
	uint64_t	tcp_timeout_cancel_reqs;
	uint64_t	tcp_timeout_canceled;
	uint64_t	tcp_timermp_freed;
	uint64_t	tcp_push_timer_cnt;
	uint64_t	tcp_ack_timer_cnt;
#endif
} tcp_stat_counter_t;

typedef struct tcp_g_stat {
	kstat_named_t	tcp_timermp_alloced;
	kstat_named_t	tcp_timermp_allocfail;
	kstat_named_t	tcp_timermp_allocdblfail;
	kstat_named_t	tcp_freelist_cleanup;
} tcp_g_stat_t;

/* Per CPU stats: TCP MIB2, TCP kstat and connection counter. */
typedef struct {
	int64_t			tcp_sc_conn_cnt;
	mib2_tcp_t		tcp_sc_mib;
	tcp_stat_counter_t	tcp_sc_stats;
} tcp_stats_cpu_t;

#define	TCPS_BUMP_MIB(tcps, x) \
	BUMP_MIB(&(tcps)->tcps_sc[CPU->cpu_seqid]->tcp_sc_mib, x)

#define	TCPS_UPDATE_MIB(tcps, x, y) \
	UPDATE_MIB(&(tcps)->tcps_sc[CPU->cpu_seqid]->tcp_sc_mib, x, y)

#if TCP_DEBUG_COUNTER
#define	TCP_DBGSTAT(tcps, x)	\
	atomic_inc_64(		\
	    &((tcps)->tcps_sc[CPU->cpu_seqid]->tcp_sc_stats.x))
#define	TCP_G_DBGSTAT(x)	\
	atomic_inc_64(&(tcp_g_statistics.x.value.ui64))
#else
#define	TCP_DBGSTAT(tcps, x)
#define	TCP_G_DBGSTAT(x)
#endif

#define	TCP_G_STAT(x)	(tcp_g_statistics.x.value.ui64++)

#define	TCP_STAT(tcps, x)		\
	((tcps)->tcps_sc[CPU->cpu_seqid]->tcp_sc_stats.x++)
#define	TCP_STAT_UPDATE(tcps, x, n)	\
	((tcps)->tcps_sc[CPU->cpu_seqid]->tcp_sc_stats.x += (n))
#define	TCP_STAT_SET(tcps, x, n)	\
	((tcps)->tcps_sc[CPU->cpu_seqid]->tcp_sc_stats.x = (n))

/* Global TCP stats for all IP stacks. */
extern tcp_g_stat_t	tcp_g_statistics;
extern kstat_t	*tcp_g_kstat;

extern void	*tcp_g_kstat_init(tcp_g_stat_t *);
extern void	tcp_g_kstat_fini(kstat_t *);
extern void	*tcp_kstat_init(netstackid_t);
extern void	tcp_kstat_fini(netstackid_t, kstat_t *);
extern void	*tcp_kstat2_init(netstackid_t);
extern void	tcp_kstat2_fini(netstackid_t, kstat_t *);

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_TCP_STATS_H */
