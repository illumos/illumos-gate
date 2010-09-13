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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_IB_ADAPTERS_TAVOR_WR_H
#define	_SYS_IB_ADAPTERS_TAVOR_WR_H

/*
 * tavor_wr.h
 *    Contains all of the prototypes, #defines, and structures necessary
 *    for the Tavor Work Request Processing Routines
 *    Specifically it contains #defines, macros, and prototypes for each of
 *    building each of the various types of WQE and for managing the WRID
 *    tracking mechanisms.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The following macro is used to convert WQE address and size into the
 * "wqeaddrsz" value needed in the tavor_wrid_entry_t (see below).
 */
#define	TAVOR_QP_WQEADDRSZ(addr, size)					\
	((((uintptr_t)(addr)) & ~TAVOR_WQE_NDS_MASK) |			\
	((size) & TAVOR_WQE_NDS_MASK))

/*
 * The following macros are used to calculate pointers to the Send or Receive
 * (or SRQ) WQEs on a given QP, respectively
 */
#define	TAVOR_QP_SQ_ENTRY(qp, tail)					\
	((uint64_t *)((uintptr_t)((qp)->qp_sq_buf) +			\
	((tail) << (qp)->qp_sq_log_wqesz)))
#define	TAVOR_QP_RQ_ENTRY(qp, tail)					\
	((uint64_t *)((uintptr_t)((qp)->qp_rq_buf) +			\
	((tail) << (qp)->qp_rq_log_wqesz)))
#define	TAVOR_SRQ_WQ_ENTRY(srq, tail)					\
	((uint64_t *)((uintptr_t)((srq)->srq_wq_buf) +			\
	((tail) << (srq)->srq_wq_log_wqesz)))

/*
 * The following macro is used to calculate the 'wqe_index' field during SRQ
 * operation.  This returns the index based on the WQE size, that can be used
 * to reference WQEs in an SRQ.
 */
#define	TAVOR_SRQ_WQE_INDEX(srq_base_addr, wqe_addr, log_wqesz)		\
	(((uint32_t)(uintptr_t)wqe_addr -				\
	(uint32_t)(uintptr_t)srq_base_addr) >> log_wqesz)

#define	TAVOR_SRQ_WQE_ADDR(srq, wqe_index)				\
	((uint64_t *)((uintptr_t)srq->srq_wq_buf +			\
	(wqe_index << srq->srq_wq_log_wqesz)))

/*
 * The following macros are used to access specific fields in Directed Route
 * MAD packets.  We can extract the MgmtClass, "hop pointer", and "hop count".
 * We can also update the "hop pointer" as appropriate.  Note:  Again, because
 * of the limited amount of direct handling the Tavor hardware does on special
 * QP request (specifically on Directed Route MADs), the driver needs to
 * update (as necessary) the "hop pointer" value depending on whether a MAD
 * is outbound or inbound (i.e. depending on the relationship between "hop
 * pointer" and "hop count" in the given MAD)
 */
#define	TAVOR_SPECIAL_QP_DRMAD_GET_MGMTCLASS(mgmtclass, offset, va, len) \
	if (((mgmtclass) == NULL) && ((offset) + (len) > 1)) {		 \
	    (mgmtclass) = &((uint8_t *)(uintptr_t)(va))[1 - (offset)];	 \
	}
#define	TAVOR_SPECIAL_QP_DRMAD_GET_HOPPOINTER(hp, offset, va, len)	\
	if (((hp) == NULL) &&					  	\
	    ((offset) + (len) > 6)) {					\
	    (hp) = &((uint8_t *)(uintptr_t)(va))[6 - (offset)];		\
	}
#define	TAVOR_SPECIAL_QP_DRMAD_GET_HOPCOUNT(hc, offset, va, len)	\
	if (((hc) == NULL) &&						\
	    ((offset) + (len) > 7)) {					\
	    (hc) = &((uint8_t *)(uintptr_t)(va))[7 - (offset)];		\
	}
#define	TAVOR_SPECIAL_QP_DRMAD_DO_HOPPOINTER_MODIFY(mgmtclass, hp, hc)	\
	if ((mgmtclass) == 0x81) {					\
		if ((hp) < (hc)) {					\
			(hp) = (hp) + 1;				\
		} else if ((hp) > (hc)) {				\
			(hp) = (hp) - 1;				\
		}							\
	}


/*
 * The tavor_wrid_entry_s structure is used internally by the Tavor
 * driver to contain all the information necessary for tracking WRIDs.
 * Specifically, this structure contains the 64-bit WRID, the 32-bit quantity
 * called "wr_wqeaddrsz" (which can also be found in every CQE), and the
 * "wr_signaled_dbd" information which indicates whether a given entry was
 * signaled or not and whether a doorbell was subsequently rung for this
 * particular work request.  Note: the latter piece of information is
 * particularly useful during completion processing on errored CQEs.
 */
struct tavor_wrid_entry_s {
	uint64_t		wr_wrid;
	uint32_t		wr_wqeaddrsz;
	uint32_t		wr_signaled_dbd;
};
#define	TAVOR_WRID_ENTRY_SIGNALED	(1 << 0)
#define	TAVOR_WRID_ENTRY_DOORBELLED	(1 << 1)

/*
 * The tavor_sw_wqe_dbinfo_t structure is used internally by the Tavor
 * driver to return information (from the tavor_wqe_mlx_build_nextctl() and
 * tavor_wqe_send_build_nextctl() routines) regarding the type of Tavor
 * doorbell necessary.
 */
typedef struct tavor_sw_wqe_dbinfo_s {
	uint_t	db_nopcode;
	uint_t	db_fence;
} tavor_sw_wqe_dbinfo_t;

/*
 * The Work Queue Lock (WQL) structure.  Each WQHDR (tavor_workq_hdr_t defined
 * below) must lock access to the wridlist during any wridlist manipulation.
 * Also, any Shared Receive Queue (SRQ) must also be able to lock the wridlist
 * since it maintains wridlist's differently than normal QPs.  This
 * 'tavor_wq_lock_t' structure is shared and accessible through the WQ or the
 * SRQ, and refcnt is maintained.  The last entity to decrement use of the
 * lock, also will free up the memory.
 */
struct tavor_wq_lock_s {
	kmutex_t	wql_lock;
	uint_t		wql_refcnt;
};

/*
 * The tavor_wrid_list_hdr_s structure is used internally by the Tavor driver
 * to track all the information necessary to manage a queue of WRID entries
 * (the tavor_wrid_entry_s struct above).
 * It contains some information regarding the status of a given WRID list
 * (e.g. head index, tail index, queue full condition, etc.).  Note:  Although
 * some of this information is also kept by the tavor_workq_hdr_s below, what
 * is kept here may, in fact, represent the state of an old WRID list.  It
 * could be different from what is kept in the tavor_workq_hdr_s because this
 * WRID list may no longer be the active WRID list.  If it is an active list,
 * however, then both sets of information should be up-to-date and consistent.
 * Several of these structures are chained together on each work queue header
 * to form a linked list (using the "wl_next" and "wl_prev").  These structs,
 * in turn, each have a pointer to a queue of WRID entries.  They also each
 * have a pointer to the next "reapable" entry ("wl_reap_next") which is only
 * used when a WRID list has been retired and is ready to be freed up.
 * Lastly, it has a backpointer to the work queue header to which the WRID
 * list belongs (this is for proper handling on removal).
 */
struct tavor_wrid_list_hdr_s {
	tavor_wrid_list_hdr_t	*wl_next;
	tavor_wrid_list_hdr_t	*wl_prev;
	tavor_wrid_list_hdr_t	*wl_reap_next;
	tavor_workq_hdr_t	*wl_wqhdr;

	tavor_wrid_entry_t	*wl_wre;
	tavor_wrid_entry_t	*wl_wre_old_tail;
	uint32_t		wl_size;
	uint32_t		wl_full;
	uint32_t		wl_head;
	uint32_t		wl_tail;

	/* For SRQ */
	uint_t			wl_srq_en;
	int			wl_free_list_indx;
	ddi_acc_handle_t	wl_acchdl;
	uint32_t		*wl_srq_wq_buf;
	uint32_t		wl_srq_wq_bufsz;
	uint64_t		wl_srq_desc_off;
	uint32_t		wl_srq_log_wqesz;
};
_NOTE(MUTEX_PROTECTS_DATA(tavor_sw_cq_s::cq_wrid_wqhdr_lock,
    tavor_wrid_list_hdr_s::wl_next
    tavor_wrid_list_hdr_s::wl_prev
    tavor_wrid_list_hdr_s::wl_wqhdr))
_NOTE(MUTEX_PROTECTS_DATA(tavor_wq_lock_s::wql_lock,
    tavor_wrid_list_hdr_s::wl_wre
    tavor_wrid_list_hdr_s::wl_wre_old_tail
    tavor_wrid_list_hdr_s::wl_size
    tavor_wrid_list_hdr_s::wl_full
    tavor_wrid_list_hdr_s::wl_head
    tavor_wrid_list_hdr_s::wl_tail
    tavor_wrid_list_hdr_s::wl_srq_en
    tavor_wrid_list_hdr_s::wl_free_list_indx
    tavor_wrid_list_hdr_s::wl_acchdl
    tavor_wrid_list_hdr_s::wl_srq_wq_buf
    tavor_wrid_list_hdr_s::wl_srq_desc_off
    tavor_wrid_list_hdr_s::wl_srq_log_wqesz))

/*
 * The tavor_workq_hdr_s structure is used internally by the Tavor driver to
 * track all the information necessary to manage the work queues associated
 * with a given completion queue.  It contains much of the information
 * regarding the status of a given work queue (e.g. head index, tail index,
 * queue full condition, etc.).  Note:  This information is kept here (i.e.
 * associated with a completion queue) rather than as part of the QP because
 * the queue pair may potentially be destroyed while outstanding CQEs still
 * remain on the CQ.
 * Several of these structures are chained together on each CQ to form a
 * linked list (using the "wq_next" and "wq_prev").  These headers, in turn,
 * link to the containers for the individual WRID entries (managed with the
 * tavor_wrid_list_hdr_s structs above).  Note: We keep a list of these
 * tavor_wrid_list_hdr_s because a given QP may be used, destroyed (or
 * transition to "Reset"), and then reused.  The list helps us track where
 * to put new WRID entries and where to pull old entries from.
 * The "wq_qpn" (QP number) and "wq_send_or_recv" (TAVOR_WR_SEND or
 * TAVOR_WR_RECV) are used to uniquely identify the given work queue.
 * Lookups into the work queue list (to find a given work queue) will use
 * these two fields as identifiers.
 */
struct tavor_workq_hdr_s {
	avl_node_t		wq_avl_link;
	uint32_t		wq_qpn;
	uint32_t		wq_type;

	tavor_wq_lock_t		*wq_wrid_wql;

	uint32_t		wq_size;
	uint32_t		wq_head;
	uint32_t		wq_tail;
	uint32_t		wq_full;
	tavor_wrid_list_hdr_t	*wq_wrid_poll;
	tavor_wrid_list_hdr_t	*wq_wrid_post;
};
_NOTE(MUTEX_PROTECTS_DATA(tavor_sw_cq_s::cq_wrid_wqhdr_lock,
    tavor_workq_hdr_s::wq_avl_link
    tavor_workq_hdr_s::wq_qpn
    tavor_workq_hdr_s::wq_type
    tavor_sw_cq_s::cq_wrid_reap_head
    tavor_sw_cq_s::cq_wrid_reap_tail))
_NOTE(MUTEX_PROTECTS_DATA(tavor_wq_lock_s::wql_lock,
    tavor_workq_hdr_s::wq_size
    tavor_workq_hdr_s::wq_head
    tavor_workq_hdr_s::wq_tail
    tavor_workq_hdr_s::wq_full
    tavor_workq_hdr_s::wq_wrid_poll
    tavor_workq_hdr_s::wq_wrid_post
    tavor_wrid_list_hdr_s::wl_wre
    tavor_wrid_list_hdr_s::wl_wre_old_tail
    tavor_wrid_list_hdr_s::wl_size
    tavor_wrid_list_hdr_s::wl_full
    tavor_wrid_list_hdr_s::wl_head
    tavor_wrid_list_hdr_s::wl_tail))
_NOTE(MUTEX_PROTECTS_DATA(tavor_sw_cq_s::cq_wrid_wqhdr_lock,
    tavor_wrid_list_hdr_s::wl_reap_next))
_NOTE(LOCK_ORDER(tavor_sw_cq_s::cq_lock
    tavor_sw_cq_s::cq_wrid_wqhdr_lock
    tavor_wq_lock_s::wql_lock))
#define	TAVOR_WR_RECV			0x0
#define	TAVOR_WR_SEND			0x1
#define	TAVOR_WR_SRQ			0x2

extern int tavor_wrid_wqhdr_compare(const void *p1, const void *p2);
typedef struct tavor_workq_compare_s {
	uint32_t cmp_type;
	uint32_t cmp_qpn;
} tavor_workq_compare_t;

/* For Work Request posting */
int tavor_post_send(tavor_state_t *state, tavor_qphdl_t qphdl,
    ibt_send_wr_t *wr_p, uint_t num_wr, uint_t *num_posted);
int tavor_post_recv(tavor_state_t *state, tavor_qphdl_t qphdl,
    ibt_recv_wr_t *wr_p, uint_t num_wr, uint_t *num_posted);
int tavor_post_srq(tavor_state_t *state, tavor_srqhdl_t srqhdl,
    ibt_recv_wr_t *wr_p, uint_t num_wr, uint_t *num_posted);

/* For WRID handling */
int tavor_wrid_from_reset_handling(tavor_state_t *state, tavor_qphdl_t qp);
void tavor_wrid_to_reset_handling(tavor_state_t *state, tavor_qphdl_t qp);
void tavor_wrid_add_entry(tavor_workq_hdr_t *wq, uint64_t wrid,
    uint32_t wqeaddr_sz, uint_t signaled_dbd);
void tavor_wrid_add_entry_srq(tavor_srqhdl_t srq, uint64_t wrid,
    uint_t signaled_dbd);
uint64_t tavor_wrid_get_entry(tavor_cqhdl_t cqhdl, tavor_hw_cqe_t *cqe,
    tavor_wrid_entry_t *wre);
tavor_wq_lock_t *tavor_wrid_wql_create(tavor_state_t *state);
tavor_wrid_list_hdr_t *tavor_wrid_get_list(uint32_t size);
void tavor_wrid_list_srq_init(tavor_wrid_list_hdr_t *r_wridlist,
    tavor_srqhdl_t srq, uint_t wq_start);
void tavor_wrid_cq_reap(tavor_cqhdl_t cq);
void tavor_wrid_cq_force_reap(tavor_cqhdl_t cq);
void tavor_wql_refcnt_dec(tavor_wq_lock_t *wq_lock);
void tavor_wql_refcnt_inc(tavor_wq_lock_t *wq_lock);
tavor_wrid_entry_t *tavor_wrid_find_match_srq(tavor_wrid_list_hdr_t *wq,
    tavor_cqhdl_t cq, tavor_hw_cqe_t *cqe);

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_IB_ADAPTERS_TAVOR_WR_H */
