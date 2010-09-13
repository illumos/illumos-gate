/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_IB_MGT_IBMF_IBMF_KSTAT_H
#define	_SYS_IB_MGT_IBMF_IBMF_KSTAT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains the IBMF kstat structures and defines.
 */

#ifdef __cplusplus
extern "C" {
#endif

/* Kstat structure definitions */
typedef struct ibmf_port_kstat_s {
	kstat_named_t	clients_registered; /* # clients registered on HCA */
	kstat_named_t	client_regs_failed; /* client registration failures */
	kstat_named_t	send_wqes_alloced; /* # currently allocated send WQEs */
	kstat_named_t	recv_wqes_alloced; /* # currently allocated recv WQEs */
	kstat_named_t	swqe_allocs_failed; /* send WQE allocations failed */
	kstat_named_t	rwqe_allocs_failed; /* recv WQE allocations failed */
} ibmf_port_kstat_t;

typedef struct ibmf_kstat_s {
	kstat_named_t	msgs_alloced;	  /* # currently allocated messages */
	kstat_named_t	msgs_active;	  /* # currently active messages */
	kstat_named_t	msgs_sent;	  /* # total msgs sent per port */
	kstat_named_t	msgs_received;	  /* # total msgs recv per port */
	kstat_named_t	sends_active;    /* # currently active send messages */
	kstat_named_t	recvs_active;    /* # currently active recv messages */
	kstat_named_t	ud_dests_alloced;  /* # currently allocated UD Dests */
	kstat_named_t	alt_qps_alloced;  /* # currently allocated alt. QPs */
	kstat_named_t	send_cb_active;	  /* # active send callbacks */
	kstat_named_t	recv_cb_active;	  /* # active send callbacks */
	kstat_named_t	recv_bufs_alloced; /* # receive buffers allocated */
	kstat_named_t	msg_allocs_failed; /* message allocations failed */
	kstat_named_t	uddest_allocs_failed; /* UD dest allocations failed */
	kstat_named_t	alt_qp_allocs_failed; /* alt. QP allocations failed */
	kstat_named_t	send_pkt_failed; /* send packet failures */
	kstat_named_t	rmpp_errors;	/* count of rmpp errors */
} ibmf_kstat_t;

#define	IBMF_ADD32_KSTATS(clientp, xx, val)				\
	if ((clientp != NULL) && (clientp->ic_kstatp != NULL)) {	\
		ibmf_kstat_t	*kp;					\
		kp = (ibmf_kstat_t *)clientp->ic_kstatp->ks_data;	\
		kp->xx.value.ui32 += val;				\
	}

#define	IBMF_SUB32_KSTATS(clientp, xx, val)				\
	if ((clientp != NULL) && (clientp->ic_kstatp != NULL)) {	\
		ibmf_kstat_t	*kp;					\
		kp = (ibmf_kstat_t *)clientp->ic_kstatp->ks_data;	\
		kp->xx.value.ui32 -= val;				\
	}

#define	IBMF_ADD32_PORT_KSTATS(cip, xx, val)				\
	if ((cip != NULL) && (cip->ci_port_kstatp != NULL)) {		\
		ibmf_port_kstat_t	*kp;				\
		kp = (ibmf_port_kstat_t *)cip->ci_port_kstatp->ks_data;	\
		kp->xx.value.ui32 += val;				\
	}

#define	IBMF_SUB32_PORT_KSTATS(cip, xx, val)				\
	if ((cip != NULL) && (cip->ci_port_kstatp != NULL)) {		\
		ibmf_port_kstat_t	*kp;				\
		kp = (ibmf_port_kstat_t *)cip->ci_port_kstatp->ks_data;	\
		kp->xx.value.ui32 -= val;				\
	}

#ifdef __cplusplus
}
#endif

#endif /* _SYS_IB_MGT_IBMF_IBMF_KSTAT_H */
