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

#ifndef	_INET_SCTP_SCTP_STACK_H
#define	_INET_SCTP_SCTP_STACK_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
} sctp_kstat_t;

#define	SCTP_KSTAT(sctps, x)	((sctps)->sctps_statistics.x.value.ui64++)

/*
 * SCTP stack instances
 */
struct sctp_stack {
	netstack_t	*sctps_netstack;	/* Common netstack */

	mib2_sctp_t		sctps_mib;

	/* Protected by sctps_g_q_lock */
	queue_t		*sctps_g_q;
	uint_t		sctps_g_q_ref; /* Number of sctp_t's that use it */
	kmutex_t	sctps_g_q_lock;
	kcondvar_t	sctps_g_q_cv;
	kthread_t	*sctps_g_q_creator;
	struct __ldi_handle *sctps_g_q_lh;
	cred_t		*sctps_g_q_cr;    /* For _inactive close call */
	/* The default sctp_t for responding out of the blue packets. */
	struct sctp_s	*sctps_gsctp;

	/* Protected by sctps_g_lock */
	struct list	sctps_g_list;	/* SCTP instance data chain */
	kmutex_t	sctps_g_lock;

#define	SCTP_NUM_EPRIV_PORTS	64
	int		sctps_g_num_epriv_ports;
	uint16_t	sctps_g_epriv_ports[SCTP_NUM_EPRIV_PORTS];
	kmutex_t	sctps_epriv_port_lock;
	uint_t		sctps_next_port_to_try;

	/* SCTP bind hash list - all sctp_t with state >= BOUND. */
	struct sctp_tf_s	*sctps_bind_fanout;
	/* SCTP listen hash list - all sctp_t with state == LISTEN. */
	struct sctp_tf_s	*sctps_listen_fanout;
	struct sctp_tf_s	*sctps_conn_fanout;
	uint_t			sctps_conn_hash_size;

	/* Only modified during _init and _fini thus no locking is needed. */
	caddr_t			sctps_g_nd;
	struct sctpparam_s	*sctps_params;
	struct sctpparam_s	*sctps_wroff_xtra_param;

/* This lock protects the SCTP recvq_tq_list array and recvq_tq_list_cur_sz. */
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

	/* kstat exporting sctp_mib data */
	kstat_t			*sctps_mibkp;
	kstat_t			*sctps_kstat;
	sctp_kstat_t		sctps_statistics;
};
typedef struct sctp_stack sctp_stack_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_SCTP_SCTP_STACK_H */
