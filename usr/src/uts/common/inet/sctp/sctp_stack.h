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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_INET_SCTP_SCTP_STACK_H
#define	_INET_SCTP_SCTP_STACK_H

#include <sys/netstack.h>
#include <sys/taskq.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* SCTP kstat */
typedef struct sctp_kstat_s {
	kstat_named_t	sctp_add_faddr;
	kstat_named_t	sctp_add_timer;
	kstat_named_t	sctp_conn_create;
	kstat_named_t	sctp_find_next_tq;
	kstat_named_t	sctp_fr_add_hdr;
	kstat_named_t	sctp_fr_not_found;
	kstat_named_t	sctp_output_failed;
	kstat_named_t	sctp_rexmit_failed;
	kstat_named_t	sctp_send_init_failed;
	kstat_named_t	sctp_send_cookie_failed;
	kstat_named_t	sctp_send_cookie_ack_failed;
	kstat_named_t	sctp_send_err_failed;
	kstat_named_t	sctp_send_sack_failed;
	kstat_named_t	sctp_send_shutdown_failed;
	kstat_named_t	sctp_send_shutdown_ack_failed;
	kstat_named_t	sctp_send_shutdown_comp_failed;
	kstat_named_t	sctp_send_user_abort_failed;
	kstat_named_t	sctp_send_asconf_failed;
	kstat_named_t	sctp_send_asconf_ack_failed;
	kstat_named_t	sctp_send_ftsn_failed;
	kstat_named_t	sctp_send_hb_failed;
	kstat_named_t	sctp_return_hb_failed;
	kstat_named_t	sctp_ss_rexmit_failed;
	kstat_named_t	sctp_cl_connect;
	kstat_named_t	sctp_cl_assoc_change;
	kstat_named_t	sctp_cl_check_addrs;
	kstat_named_t	sctp_reclaim_cnt;
	kstat_named_t	sctp_listen_cnt_drop;
} sctp_kstat_t;

/*
 * This struct contains only the counter part of sctp_kstat_t.  It is used
 * in sctp_stats_cpu_t instead of sctp_kstat_t to save memory space.
 */
typedef struct sctp_kstat_counter_s {
	uint64_t	sctp_add_faddr;
	uint64_t	sctp_add_timer;
	uint64_t	sctp_conn_create;
	uint64_t	sctp_find_next_tq;
	uint64_t	sctp_fr_add_hdr;
	uint64_t	sctp_fr_not_found;
	uint64_t	sctp_output_failed;
	uint64_t	sctp_rexmit_failed;
	uint64_t	sctp_send_init_failed;
	uint64_t	sctp_send_cookie_failed;
	uint64_t	sctp_send_cookie_ack_failed;
	uint64_t	sctp_send_err_failed;
	uint64_t	sctp_send_sack_failed;
	uint64_t	sctp_send_shutdown_failed;
	uint64_t	sctp_send_shutdown_ack_failed;
	uint64_t	sctp_send_shutdown_comp_failed;
	uint64_t	sctp_send_user_abort_failed;
	uint64_t	sctp_send_asconf_failed;
	uint64_t	sctp_send_asconf_ack_failed;
	uint64_t	sctp_send_ftsn_failed;
	uint64_t	sctp_send_hb_failed;
	uint64_t	sctp_return_hb_failed;
	uint64_t	sctp_ss_rexmit_failed;
	uint64_t	sctp_cl_connect;
	uint64_t	sctp_cl_assoc_change;
	uint64_t	sctp_cl_check_addrs;
	uint64_t	sctp_reclaim_cnt;
	uint64_t	sctp_listen_cnt_drop;
} sctp_kstat_counter_t;

/* Per CPU SCTP statistics counters. */
typedef struct {
	int64_t			sctp_sc_assoc_cnt;
	mib2_sctp_t		sctp_sc_mib;
	sctp_kstat_counter_t	sctp_sc_stats;
} sctp_stats_cpu_t;

#define	SCTP_KSTAT(sctps, x)		\
	((sctps)->sctps_sc[CPU->cpu_seqid]->sctp_sc_stats.x++)

#define	SCTPS_BUMP_MIB(sctps, x)	\
	BUMP_MIB(&(sctps)->sctps_sc[CPU->cpu_seqid]->sctp_sc_mib, x)

#define	SCTPS_UPDATE_MIB(sctps, x, y)	\
	UPDATE_MIB(&(sctps)->sctps_sc[CPU->cpu_seqid]->sctp_sc_mib, x, y)

/*
 * SCTP stack instances
 */
struct sctp_stack {
	netstack_t	*sctps_netstack;	/* Common netstack */

	/* Protected by sctps_g_lock */
	struct list	sctps_g_list;	/* SCTP instance data chain */
	kmutex_t	sctps_g_lock;

#define	SCTP_NUM_EPRIV_PORTS	64
	int		sctps_g_num_epriv_ports;
	in_port_t	sctps_g_epriv_ports[SCTP_NUM_EPRIV_PORTS];
	kmutex_t	sctps_epriv_port_lock;
	uint_t		sctps_next_port_to_try;

	/* SCTP bind hash list - all sctp_t with state >= BOUND. */
	struct sctp_tf_s	*sctps_bind_fanout;
	/* SCTP listen hash list - all sctp_t with state == LISTEN. */
	struct sctp_tf_s	*sctps_listen_fanout;
	struct sctp_tf_s	*sctps_conn_fanout;
	uint_t			sctps_conn_hash_size;

	/* holds sctp tunables */
	struct mod_prop_info_s	*sctps_propinfo_tbl;

	/*
	 * This lock protects the SCTP recvq_tq_list array and
	 * recvq_tq_list_cur_sz.
	 */
	kmutex_t		sctps_rq_tq_lock;
	int			sctps_recvq_tq_list_max_sz;
	taskq_t			**sctps_recvq_tq_list;

	/* Current number of recvq taskq.  At least 1 for the default taskq. */
	uint32_t		sctps_recvq_tq_list_cur_sz;
	uint32_t		sctps_recvq_tq_list_cur;

	/* Global list of SCTP ILLs */
	struct sctp_ill_hash_s	*sctps_g_ills;
	uint32_t		sctps_ills_count;
	krwlock_t		sctps_g_ills_lock;

	/* Global list of SCTP IPIFs */
	struct sctp_ipif_hash_s	*sctps_g_ipifs;
	uint32_t		sctps_g_ipifs_count;
	krwlock_t		sctps_g_ipifs_lock;

	/* kstat exporting mib2_sctp_t and sctp_kstat_t data */
	kstat_t			*sctps_mibkp;
	kstat_t			*sctps_kstat;

	/* Variables for handling kmem reclaim call back. */
	kmutex_t	sctps_reclaim_lock;
	boolean_t	sctps_reclaim;
	timeout_id_t	sctps_reclaim_tid;
	uint32_t	sctps_reclaim_period;

	/* Listener association limit configuration. */
	kmutex_t	sctps_listener_conf_lock;
	list_t		sctps_listener_conf;

	/*
	 * Per CPU stats
	 *
	 * sctps_sc: array of pointer to per CPU stats.  The i-th element in
	 *   the array represents the stats of the CPU with cpu_seqid.
	 * sctps_sc_cnt: number of CPU stats in the sctps_sc array.
	 */
	sctp_stats_cpu_t	**sctps_sc;
	int			sctps_sc_cnt;
};

typedef struct sctp_stack sctp_stack_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_SCTP_SCTP_STACK_H */
