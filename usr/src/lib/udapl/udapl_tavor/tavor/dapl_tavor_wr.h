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

#ifndef	_DAPL_TAVOR_WR_H
#define	_DAPL_TAVOR_WR_H

/*
 * dapl_tavor_wr.h
 *	Contains the definition of all structures that are used for
 *	doing the work request handling.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include "dapl_osd.h"
#include "dapl_hash.h"
#include "dapl_tavor_ibtf.h"
#include "dapl_tavor_hw.h"

typedef struct dapls_tavor_workq_hdr_s		dapls_tavor_workq_hdr_t;
typedef struct dapls_tavor_wrid_list_hdr_s	dapls_tavor_wrid_list_hdr_t;
typedef struct dapls_tavor_wrid_entry_s		dapls_tavor_wrid_entry_t;
typedef struct dapls_tavor_wrid_lock_s		dapls_tavor_wrid_lock_t;

/*
 * Defines the lock that protects the wrid list.
 * For send queues and receive queues this is allocated with the workq header
 * structure. For SRQs it is allocated with the wrid_list_hdr and the receive
 * workq header points to it.
 */
struct dapls_tavor_wrid_lock_s {
	uint32_t	wrl_on_srq; /* lock resides in the srq wridlist */
	DAPL_OS_LOCK	wrl_lock;
};

/*
 * Defines the workq header for each queue in the QP. This points to the
 * dapls_tavor_wrid_list_hdr_t which has the work request id list.
 */
struct dapls_tavor_workq_hdr_s {
	uint32_t			wq_qpn;
	uint32_t			wq_send_or_recv;
	dapls_tavor_wrid_lock_t		*wq_wrid_lock;
	uint32_t			wq_size;
	uint32_t			wq_head;
	uint32_t			wq_tail;
	uint32_t			wq_full;
	dapls_tavor_wrid_list_hdr_t	*wq_wrid_poll;
	dapls_tavor_wrid_list_hdr_t	*wq_wrid_post;
};
/* Type of the work queue */
#define	TAVOR_WR_SEND			0x1
#define	TAVOR_WR_RECV			0x0


/*
 * Defines each work request id entry
 */
struct dapls_tavor_wrid_entry_s {
	uint64_t		wr_wrid;
	uint32_t		wr_wqeaddrsz;
	uint32_t		wr_signaled_dbd;
};
#define	TAVOR_WRID_ENTRY_SIGNALED	(1 << 0)
#define	TAVOR_WRID_ENTRY_DOORBELLED	(1 << 1)

/*
 * Defines each work request id list which has an array of wrid entries
 */
struct dapls_tavor_wrid_list_hdr_s {
	dapls_tavor_wrid_list_hdr_t	*wl_next;
	dapls_tavor_wrid_list_hdr_t	*wl_prev;
	dapls_tavor_wrid_list_hdr_t	*wl_reap_next;
	dapls_tavor_workq_hdr_t		*wl_wqhdr;
	dapls_tavor_wrid_entry_t	*wl_wre;
	dapls_tavor_wrid_entry_t	*wl_wre_old_tail;
	uint32_t			wl_size;
	uint32_t			wl_full;
	uint32_t			wl_head;
	uint32_t			wl_tail;
	dapls_tavor_wrid_lock_t		*wl_lock; /* valid only for SRQs */

	/* For SRQ */
	uint_t				wl_srq_en;
	uint32_t			*wl_free_list; /* free descrptr list */
	uint32_t			wl_freel_head;
	uint32_t			wl_freel_tail;
	uint32_t			wl_freel_entries; /* # free entries */
	uint32_t			wl_srq_wqesz;
	uint64_t			wl_srq_desc_addr;
};

extern dapls_tavor_wrid_entry_t *dapli_tavor_wrid_find_match_srq(
	dapls_tavor_wrid_list_hdr_t *, tavor_hw_cqe_t *);

#ifdef __cplusplus
}
#endif

#endif	/* _DAPL_TAVOR_WR_H */
