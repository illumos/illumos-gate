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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * tavor_wr.c
 *    Tavor Work Request Processing Routines
 *
 *    Implements all the routines necessary to provide the PostSend(),
 *    PostRecv() and PostSRQ() verbs.  Also contains all the code
 *    necessary to implement the Tavor WRID tracking mechanism.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/avl.h>

#include <sys/ib/adapters/tavor/tavor.h>

static void tavor_qp_send_doorbell(tavor_state_t *state, uint32_t nda,
    uint32_t nds, uint32_t qpn, uint32_t fence, uint32_t nopcode);
static void tavor_qp_recv_doorbell(tavor_state_t *state, uint32_t nda,
    uint32_t nds, uint32_t qpn, uint32_t credits);
static uint32_t tavor_wr_get_immediate(ibt_send_wr_t *wr);
static int tavor_wr_bind_check(tavor_state_t *state, ibt_send_wr_t *wr);
static int tavor_wqe_send_build(tavor_state_t *state, tavor_qphdl_t qp,
    ibt_send_wr_t *wr, uint64_t *desc, uint_t *size);
static void tavor_wqe_send_linknext(ibt_send_wr_t *curr_wr,
    ibt_send_wr_t *prev_wr, uint64_t *curr_desc, uint_t curr_descsz,
    uint64_t *prev_desc, tavor_sw_wqe_dbinfo_t *dbinfo, tavor_qphdl_t qp);
static int tavor_wqe_mlx_build(tavor_state_t *state, tavor_qphdl_t qp,
    ibt_send_wr_t *wr, uint64_t *desc, uint_t *size);
static void tavor_wqe_mlx_linknext(ibt_send_wr_t *prev_wr, uint64_t *curr_desc,
    uint_t curr_descsz, uint64_t *prev_desc, tavor_sw_wqe_dbinfo_t *dbinfo,
    tavor_qphdl_t qp);
static int tavor_wqe_recv_build(tavor_state_t *state, tavor_qphdl_t qp,
    ibt_recv_wr_t *wr, uint64_t *desc, uint_t *size);
static void tavor_wqe_recv_linknext(uint64_t *desc, uint_t desc_sz,
    uint64_t *prev, tavor_qphdl_t qp);
static int tavor_wqe_srq_build(tavor_state_t *state, tavor_srqhdl_t srq,
    ibt_recv_wr_t *wr, uint64_t *desc);
static void tavor_wqe_srq_linknext(uint64_t *desc, uint64_t *prev,
    tavor_srqhdl_t srq);
static void tavor_wqe_sync(void *hdl, uint_t sync_from,
    uint_t sync_to, uint_t sync_type, uint_t flag);
static tavor_wrid_entry_t *tavor_wrid_find_match(tavor_workq_hdr_t *wq,
    tavor_cqhdl_t cq, tavor_hw_cqe_t *cqe);
static void tavor_wrid_reaplist_add(tavor_cqhdl_t cq, tavor_workq_hdr_t *wq);
static tavor_workq_hdr_t *tavor_wrid_wqhdr_find(tavor_cqhdl_t cq, uint_t qpn,
    uint_t send_or_recv);
static tavor_workq_hdr_t *tavor_wrid_wqhdr_create(tavor_state_t *state,
    tavor_cqhdl_t cq, uint_t qpn, uint_t wq_type, uint_t create_wql);
static uint32_t tavor_wrid_get_wqeaddrsz(tavor_workq_hdr_t *wq);
static void tavor_wrid_wqhdr_add(tavor_workq_hdr_t *wqhdr,
    tavor_wrid_list_hdr_t *wrid_list);
static void tavor_wrid_wqhdr_remove(tavor_workq_hdr_t *wqhdr,
    tavor_wrid_list_hdr_t *wrid_list);
static tavor_workq_hdr_t *tavor_wrid_list_reap(tavor_wrid_list_hdr_t *wq);
static void tavor_wrid_wqhdr_lock_both(tavor_qphdl_t qp);
static void tavor_wrid_wqhdr_unlock_both(tavor_qphdl_t qp);
static void tavor_cq_wqhdr_add(tavor_cqhdl_t cq, tavor_workq_hdr_t *wqhdr);
static void tavor_cq_wqhdr_remove(tavor_cqhdl_t cq, tavor_workq_hdr_t *wqhdr);

/*
 * tavor_post_send()
 *    Context: Can be called from interrupt or base context.
 */
int
tavor_post_send(tavor_state_t *state, tavor_qphdl_t qp,
    ibt_send_wr_t *wr, uint_t num_wr, uint_t *num_posted)
{
	tavor_sw_wqe_dbinfo_t		dbinfo;
	tavor_wrid_list_hdr_t		*wridlist;
	tavor_wrid_entry_t		*wre_last;
	uint64_t			*desc, *prev, *first;
	uint32_t			desc_sz, first_sz;
	uint32_t			wqeaddrsz, signaled_dbd;
	uint32_t			head, tail, next_tail, qsize_msk;
	uint32_t			sync_from, sync_to;
	uint_t				currindx, wrindx, numremain;
	uint_t				chainlen, chainbegin, posted_cnt;
	uint_t				maxdb = TAVOR_QP_MAXDESC_PER_DB;
	int				status;

	/*
	 * Check for user-mappable QP memory.  Note:  We do not allow kernel
	 * clients to post to QP memory that is accessible directly by the
	 * user.  If the QP memory is user accessible, then return an error.
	 */
	if (qp->qp_is_umap) {
		return (IBT_QP_HDL_INVALID);
	}

	/* Initialize posted_cnt */
	posted_cnt = 0;

	mutex_enter(&qp->qp_lock);

	/*
	 * Check QP state.  Can not post Send requests from the "Reset",
	 * "Init", or "RTR" states
	 */
	if ((qp->qp_state == TAVOR_QP_RESET) ||
	    (qp->qp_state == TAVOR_QP_INIT) ||
	    (qp->qp_state == TAVOR_QP_RTR)) {
		mutex_exit(&qp->qp_lock);
		return (IBT_QP_STATE_INVALID);
	}

	/* Grab the lock for the WRID list */
	mutex_enter(&qp->qp_sq_wqhdr->wq_wrid_wql->wql_lock);
	wridlist  = qp->qp_sq_wqhdr->wq_wrid_post;

	/* Save away some initial QP state */
	qsize_msk = qp->qp_sq_wqhdr->wq_size - 1;
	tail	  = qp->qp_sq_wqhdr->wq_tail;
	head	  = qp->qp_sq_wqhdr->wq_head;

	/*
	 * For each ibt_send_wr_t in the wr[] list passed in, parse the
	 * request and build a Send WQE.  Note:  Because we are potentially
	 * building a chain of WQEs, we want to link them all together.
	 * However, we do not want to link the first one to the previous
	 * WQE until the entire chain has been linked.  Then in the last
	 * step we ring the appropriate doorbell.  Note:  It is possible for
	 * more Work Requests to be posted than the HW will support at one
	 * shot.  If this happens, we need to be able to post and ring
	 * several chains here until the the entire request is complete.
	 */
	wrindx = 0;
	numremain = num_wr;
	status	  = DDI_SUCCESS;
	while ((wrindx < num_wr) && (status == DDI_SUCCESS)) {
		/*
		 * For the first WQE on a new chain we need "prev" to point
		 * to the current descriptor.  As we begin to process
		 * further, "prev" will be updated to point to the previous
		 * WQE on the current chain (see below).
		 */
		prev = TAVOR_QP_SQ_ENTRY(qp, tail);

		/*
		 * Before we begin, save the current "tail index" for later
		 * DMA sync
		 */
		sync_from = tail;

		/*
		 * Break the request up into chains that are less than or
		 * equal to the maximum number of WQEs that can be posted
		 * per doorbell ring
		 */
		chainlen   = (numremain > maxdb) ? maxdb : numremain;
		numremain -= chainlen;
		chainbegin = wrindx;
		for (currindx = 0; currindx < chainlen; currindx++, wrindx++) {
			/*
			 * Check for "queue full" condition.  If the queue
			 * is already full, then no more WQEs can be posted.
			 * So break out, ring a doorbell (if necessary) and
			 * return an error
			 */
			if (qp->qp_sq_wqhdr->wq_full != 0) {
				status = IBT_QP_FULL;
				break;
			}

			/*
			 * Increment the "tail index" and check for "queue
			 * full" condition.  If we detect that the current
			 * work request is going to fill the work queue, then
			 * we mark this condition and continue.
			 */
			next_tail = (tail + 1) & qsize_msk;
			if (next_tail == head) {
				qp->qp_sq_wqhdr->wq_full = 1;
			}

			/*
			 * Get the address of the location where the next
			 * Send WQE should be built
			 */
			desc = TAVOR_QP_SQ_ENTRY(qp, tail);

			/*
			 * Call tavor_wqe_send_build() to build the WQE
			 * at the given address.  This routine uses the
			 * information in the ibt_send_wr_t list (wr[]) and
			 * returns the size of the WQE when it returns.
			 */
			status = tavor_wqe_send_build(state, qp,
			    &wr[wrindx], desc, &desc_sz);
			if (status != DDI_SUCCESS) {
				break;
			}

			/*
			 * Add a WRID entry to the WRID list.  Need to
			 * calculate the "wqeaddrsz" and "signaled_dbd"
			 * values to pass to tavor_wrid_add_entry()
			 */
			wqeaddrsz = TAVOR_QP_WQEADDRSZ((uint64_t *)(uintptr_t)
			    ((uint64_t)(uintptr_t)desc - qp->qp_desc_off),
			    desc_sz);
			if ((qp->qp_sq_sigtype == TAVOR_QP_SQ_ALL_SIGNALED) ||
			    (wr[wrindx].wr_flags & IBT_WR_SEND_SIGNAL)) {
				signaled_dbd = TAVOR_WRID_ENTRY_SIGNALED;
			} else {
				signaled_dbd = 0;
			}
			tavor_wrid_add_entry(qp->qp_sq_wqhdr,
			    wr[wrindx].wr_id, wqeaddrsz, signaled_dbd);

			/*
			 * If this is not the first descriptor on the current
			 * chain, then link it to the previous WQE.  Otherwise,
			 * save the address and size of this descriptor (in
			 * "first" and "first_sz" respectively) and continue.
			 * Note: Linking a WQE to the the previous one will
			 * depend on whether the two WQEs are from "special
			 * QPs" (i.e. MLX transport WQEs) or whether they are
			 * normal Send WQEs.
			 */
			if (currindx != 0) {
				if (qp->qp_is_special) {
					tavor_wqe_mlx_linknext(&wr[wrindx - 1],
					    desc, desc_sz, prev, NULL, qp);
				} else {
					tavor_wqe_send_linknext(&wr[wrindx],
					    &wr[wrindx - 1], desc, desc_sz,
					    prev, NULL, qp);
				}
				prev = desc;
			} else {
				first	 = desc;
				first_sz = desc_sz;
			}

			/*
			 * Update the current "tail index" and increment
			 * "posted_cnt"
			 */
			tail = next_tail;
			posted_cnt++;
		}

		/*
		 * If we reach here and there are one or more WQEs which have
		 * been successfully chained together, then we need to link
		 * the current chain to the previously executing chain of
		 * descriptor (if there is one) and ring the doorbell for the
		 * send work queue.
		 */
		if (currindx != 0) {
			/*
			 * Before we link the chain, we need to ensure that the
			 * "next" field on the last WQE is set to NULL (to
			 * indicate the end of the chain).  Note: Just as it
			 * did above, the format for the "next" fields in a
			 * given WQE depend on whether the WQE is MLX
			 * transport or not.
			 */
			if (qp->qp_is_special) {
				tavor_wqe_mlx_linknext(&wr[chainbegin +
				    currindx - 1], NULL, 0, prev, NULL, qp);
			} else {
				tavor_wqe_send_linknext(NULL,
				    &wr[chainbegin + currindx - 1], NULL, 0,
				    prev, NULL, qp);
			}

			/* Save away updated "tail index" for the DMA sync */
			sync_to = tail;

			/* Do a DMA sync for current send WQE(s) */
			tavor_wqe_sync(qp, sync_from, sync_to, TAVOR_WR_SEND,
			    DDI_DMA_SYNC_FORDEV);

			/*
			 * Now link the chain to the old chain (if there was
			 * one.  Note: still need to pay attention to whether
			 * the QP used MLX transport WQEs or not.
			 */
			if (qp->qp_is_special) {
				tavor_wqe_mlx_linknext(NULL, first, first_sz,
				    qp->qp_sq_lastwqeaddr, &dbinfo, qp);
			} else {
				tavor_wqe_send_linknext(&wr[chainbegin], NULL,
				    first, first_sz, qp->qp_sq_lastwqeaddr,
				    &dbinfo, qp);
			}

			/*
			 * If there was a valid previous WQE (i.e. non-NULL),
			 * then sync it too.  This is because we have updated
			 * its "next" fields and we want to ensure that the
			 * hardware can see the changes.
			 */
			if (qp->qp_sq_lastwqeaddr != NULL) {
				sync_to   = sync_from;
				sync_from = (sync_from - 1) & qsize_msk;
				tavor_wqe_sync(qp, sync_from, sync_to,
				    TAVOR_WR_SEND, DDI_DMA_SYNC_FORDEV);
			}

			/*
			 * Now if the WRID tail entry is non-NULL, then this
			 * represents the entry to which we are chaining the
			 * new entries.  Since we are going to ring the
			 * doorbell for this WQE, we want set its "dbd" bit.
			 *
			 * On the other hand, if the tail is NULL, even though
			 * we will have rung the doorbell for the previous WQE
			 * (for the hardware's sake) it is irrelevant to our
			 * purposes (for tracking WRIDs) because we know the
			 * request must have already completed.
			 */
			wre_last = wridlist->wl_wre_old_tail;
			if (wre_last != NULL) {
				wre_last->wr_signaled_dbd |=
				    TAVOR_WRID_ENTRY_DOORBELLED;
			}

			/* Update some of the state in the QP */
			qp->qp_sq_lastwqeaddr	 = desc;
			qp->qp_sq_wqhdr->wq_tail = tail;

			/* Ring the doorbell */
			tavor_qp_send_doorbell(state,
			    (uint32_t)((uintptr_t)first - qp->qp_desc_off),
			    first_sz, qp->qp_qpnum, dbinfo.db_fence,
			    dbinfo.db_nopcode);
		}
	}

	/*
	 * Update the "num_posted" return value (if necessary).  Then drop
	 * the locks and return success.
	 */
	if (num_posted != NULL) {
		*num_posted = posted_cnt;
	}

	mutex_exit(&qp->qp_sq_wqhdr->wq_wrid_wql->wql_lock);
	mutex_exit(&qp->qp_lock);

	return (status);
}


/*
 * tavor_post_recv()
 *    Context: Can be called from interrupt or base context.
 */
int
tavor_post_recv(tavor_state_t *state, tavor_qphdl_t qp,
    ibt_recv_wr_t *wr, uint_t num_wr, uint_t *num_posted)
{
	uint64_t			*desc, *prev, *first;
	uint32_t			desc_sz, first_sz;
	uint32_t			wqeaddrsz, signaled_dbd;
	uint32_t			head, tail, next_tail, qsize_msk;
	uint32_t			sync_from, sync_to;
	uint_t				currindx, wrindx, numremain;
	uint_t				chainlen, posted_cnt;
	uint_t				maxdb = TAVOR_QP_MAXDESC_PER_DB;
	int				status;

	/*
	 * Check for user-mappable QP memory.  Note:  We do not allow kernel
	 * clients to post to QP memory that is accessible directly by the
	 * user.  If the QP memory is user accessible, then return an error.
	 */
	if (qp->qp_is_umap) {
		return (IBT_QP_HDL_INVALID);
	}

	/* Initialize posted_cnt */
	posted_cnt = 0;

	mutex_enter(&qp->qp_lock);

	/*
	 * Check if QP is associated with an SRQ
	 */
	if (qp->qp_srq_en == TAVOR_QP_SRQ_ENABLED) {
		mutex_exit(&qp->qp_lock);
		return (IBT_SRQ_IN_USE);
	}

	/*
	 * Check QP state.  Can not post Recv requests from the "Reset" state
	 */
	if (qp->qp_state == TAVOR_QP_RESET) {
		mutex_exit(&qp->qp_lock);
		return (IBT_QP_STATE_INVALID);
	}

	/* Grab the lock for the WRID list */
	mutex_enter(&qp->qp_rq_wqhdr->wq_wrid_wql->wql_lock);

	/* Save away some initial QP state */
	qsize_msk = qp->qp_rq_wqhdr->wq_size - 1;
	tail	  = qp->qp_rq_wqhdr->wq_tail;
	head	  = qp->qp_rq_wqhdr->wq_head;

	/*
	 * For each ibt_recv_wr_t in the wr[] list passed in, parse the
	 * request and build a Recv WQE.  Note:  Because we are potentially
	 * building a chain of WQEs, we want to link them all together.
	 * However, we do not want to link the first one to the previous
	 * WQE until the entire chain has been linked.  Then in the last
	 * step we ring the appropriate doorbell.  Note:  It is possible for
	 * more Work Requests to be posted than the HW will support at one
	 * shot.  If this happens, we need to be able to post and ring
	 * several chains here until the the entire request is complete.
	 */
	wrindx = 0;
	numremain = num_wr;
	status	  = DDI_SUCCESS;
	while ((wrindx < num_wr) && (status == DDI_SUCCESS)) {
		/*
		 * For the first WQE on a new chain we need "prev" to point
		 * to the current descriptor.  As we begin to process
		 * further, "prev" will be updated to point to the previous
		 * WQE on the current chain (see below).
		 */
		prev = TAVOR_QP_RQ_ENTRY(qp, tail);

		/*
		 * Before we begin, save the current "tail index" for later
		 * DMA sync
		 */
		sync_from = tail;

		/*
		 * Break the request up into chains that are less than or
		 * equal to the maximum number of WQEs that can be posted
		 * per doorbell ring
		 */
		chainlen = (numremain > maxdb) ? maxdb : numremain;
		numremain -= chainlen;
		for (currindx = 0; currindx < chainlen; currindx++, wrindx++) {
			/*
			 * Check for "queue full" condition.  If the queue
			 * is already full, then no more WQEs can be posted.
			 * So break out, ring a doorbell (if necessary) and
			 * return an error
			 */
			if (qp->qp_rq_wqhdr->wq_full != 0) {
				status = IBT_QP_FULL;
				break;
			}

			/*
			 * Increment the "tail index" and check for "queue
			 * full" condition.  If we detect that the current
			 * work request is going to fill the work queue, then
			 * we mark this condition and continue.
			 */
			next_tail = (tail + 1) & qsize_msk;
			if (next_tail == head) {
				qp->qp_rq_wqhdr->wq_full = 1;
			}

			/*
			 * Get the address of the location where the next
			 * Recv WQE should be built
			 */
			desc = TAVOR_QP_RQ_ENTRY(qp, tail);

			/*
			 * Call tavor_wqe_recv_build() to build the WQE
			 * at the given address.  This routine uses the
			 * information in the ibt_recv_wr_t list (wr[]) and
			 * returns the size of the WQE when it returns.
			 */
			status = tavor_wqe_recv_build(state, qp, &wr[wrindx],
			    desc, &desc_sz);
			if (status != DDI_SUCCESS) {
				break;
			}

			/*
			 * Add a WRID entry to the WRID list.  Need to
			 * calculate the "wqeaddrsz" and "signaled_dbd"
			 * values to pass to tavor_wrid_add_entry().  Note:
			 * all Recv WQEs are essentially "signaled" and
			 * "doorbelled" (since Tavor HW requires all
			 * RecvWQE's to have their "DBD" bits set).
			 */
			wqeaddrsz = TAVOR_QP_WQEADDRSZ((uint64_t *)(uintptr_t)
			    ((uint64_t)(uintptr_t)desc - qp->qp_desc_off),
			    desc_sz);
			signaled_dbd = TAVOR_WRID_ENTRY_SIGNALED |
			    TAVOR_WRID_ENTRY_DOORBELLED;
			tavor_wrid_add_entry(qp->qp_rq_wqhdr,
			    wr[wrindx].wr_id, wqeaddrsz, signaled_dbd);

			/*
			 * If this is not the first descriptor on the current
			 * chain, then link it to the previous WQE.  Otherwise,
			 * save the address and size of this descriptor (in
			 * "first" and "first_sz" respectively) and continue.
			 */
			if (currindx != 0) {
				tavor_wqe_recv_linknext(desc, desc_sz, prev,
				    qp);
				prev = desc;
			} else {
				first	 = desc;
				first_sz = desc_sz;
			}

			/*
			 * Update the current "tail index" and increment
			 * "posted_cnt"
			 */
			tail = next_tail;
			posted_cnt++;
		}

		/*
		 * If we reach here and there are one or more WQEs which have
		 * been successfully chained together, then we need to link
		 * the current chain to the previously executing chain of
		 * descriptor (if there is one) and ring the doorbell for the
		 * recv work queue.
		 */
		if (currindx != 0) {
			/*
			 * Before we link the chain, we need to ensure that the
			 * "next" field on the last WQE is set to NULL (to
			 * indicate the end of the chain).
			 */
			tavor_wqe_recv_linknext(NULL, 0, prev, qp);

			/* Save away updated "tail index" for the DMA sync */
			sync_to = tail;

			/* Do a DMA sync for current recv WQE(s) */
			tavor_wqe_sync(qp, sync_from, sync_to, TAVOR_WR_RECV,
			    DDI_DMA_SYNC_FORDEV);

			/*
			 * Now link the chain to the old chain (if there was
			 * one.
			 */
			tavor_wqe_recv_linknext(first, first_sz,
			    qp->qp_rq_lastwqeaddr, qp);

			/*
			 * If there was a valid previous WQE (i.e. non-NULL),
			 * then sync it too.  This is because we have updated
			 * its "next" fields and we want to ensure that the
			 * hardware can see the changes.
			 */
			if (qp->qp_rq_lastwqeaddr != NULL) {
				sync_to	  = sync_from;
				sync_from = (sync_from - 1) & qsize_msk;
				tavor_wqe_sync(qp, sync_from, sync_to,
				    TAVOR_WR_RECV, DDI_DMA_SYNC_FORDEV);
			}

			/* Update some of the state in the QP */
			qp->qp_rq_lastwqeaddr	 = desc;
			qp->qp_rq_wqhdr->wq_tail = tail;

			/* Ring the doorbell */
			tavor_qp_recv_doorbell(state,
			    (uint32_t)((uintptr_t)first - qp->qp_desc_off),
			    first_sz, qp->qp_qpnum, (chainlen % maxdb));
		}
	}

	/*
	 * Update the "num_posted" return value (if necessary).  Then drop
	 * the locks and return success.
	 */
	if (num_posted != NULL) {
		*num_posted = posted_cnt;
	}

	mutex_exit(&qp->qp_rq_wqhdr->wq_wrid_wql->wql_lock);
	mutex_exit(&qp->qp_lock);

	return (status);
}

/*
 * tavor_post_srq()
 *    Context: Can be called from interrupt or base context.
 */
int
tavor_post_srq(tavor_state_t *state, tavor_srqhdl_t srq,
    ibt_recv_wr_t *wr, uint_t num_wr, uint_t *num_posted)
{
	uint64_t			*desc, *prev, *first, *last_wqe_addr;
	uint32_t			signaled_dbd;
	uint32_t			sync_indx;
	uint_t				currindx, wrindx, numremain;
	uint_t				chainlen, posted_cnt;
	uint_t				maxdb = TAVOR_QP_MAXDESC_PER_DB;
	int				status;

	/*
	 * Check for user-mappable QP memory.  Note:  We do not allow kernel
	 * clients to post to QP memory that is accessible directly by the
	 * user.  If the QP memory is user accessible, then return an error.
	 */
	if (srq->srq_is_umap) {
		return (IBT_SRQ_HDL_INVALID);
	}

	/* Initialize posted_cnt */
	posted_cnt = 0;

	mutex_enter(&srq->srq_lock);

	/*
	 * Check SRQ state.  Can not post Recv requests when SRQ is in error
	 */
	if (srq->srq_state == TAVOR_SRQ_STATE_ERROR) {
		mutex_exit(&srq->srq_lock);
		return (IBT_QP_STATE_INVALID);
	}

	/* Grab the lock for the WRID list */
	mutex_enter(&srq->srq_wrid_wql->wql_lock);

	/*
	 * For each ibt_recv_wr_t in the wr[] list passed in, parse the
	 * request and build a Recv WQE.  Note:  Because we are potentially
	 * building a chain of WQEs, we want to link them all together.
	 * However, we do not want to link the first one to the previous
	 * WQE until the entire chain has been linked.  Then in the last
	 * step we ring the appropriate doorbell.  Note:  It is possible for
	 * more Work Requests to be posted than the HW will support at one
	 * shot.  If this happens, we need to be able to post and ring
	 * several chains here until the the entire request is complete.
	 */
	wrindx = 0;
	numremain = num_wr;
	status	  = DDI_SUCCESS;
	while ((wrindx < num_wr) && (status == DDI_SUCCESS)) {
		/*
		 * For the first WQE on a new chain we need "prev" to point
		 * to the current descriptor.  As we begin to process
		 * further, "prev" will be updated to point to the previous
		 * WQE on the current chain (see below).
		 */
		if (srq->srq_wq_lastwqeindx == -1) {
			prev = NULL;
		} else {
			prev = TAVOR_SRQ_WQE_ADDR(srq, srq->srq_wq_lastwqeindx);
		}

		/*
		 * Break the request up into chains that are less than or
		 * equal to the maximum number of WQEs that can be posted
		 * per doorbell ring
		 */
		chainlen = (numremain > maxdb) ? maxdb : numremain;
		numremain -= chainlen;
		for (currindx = 0; currindx < chainlen; currindx++, wrindx++) {

			/*
			 * Check for "queue full" condition.  If the queue
			 * is already full, then no more WQEs can be posted.
			 * So break out, ring a doorbell (if necessary) and
			 * return an error
			 */
			if (srq->srq_wridlist->wl_free_list_indx == -1) {
				status = IBT_QP_FULL;
				break;
			}

			/*
			 * Get the address of the location where the next
			 * Recv WQE should be built
			 */
			desc = TAVOR_SRQ_WQE_ADDR(srq,
			    srq->srq_wridlist->wl_free_list_indx);

			/*
			 * Add a WRID entry to the WRID list.  Need to
			 * set the "signaled_dbd" values to pass to
			 * tavor_wrid_add_entry().  Note: all Recv WQEs are
			 * essentially "signaled"
			 *
			 * The 'size' is stored at srq_alloc time, in the
			 * srq_wq_stride.  This is a constant value required
			 * for SRQ.
			 */
			signaled_dbd = TAVOR_WRID_ENTRY_SIGNALED;
			tavor_wrid_add_entry_srq(srq, wr[wrindx].wr_id,
			    signaled_dbd);

			/*
			 * Call tavor_wqe_srq_build() to build the WQE
			 * at the given address.  This routine uses the
			 * information in the ibt_recv_wr_t list (wr[]) and
			 * returns the size of the WQE when it returns.
			 */
			status = tavor_wqe_srq_build(state, srq, &wr[wrindx],
			    desc);
			if (status != DDI_SUCCESS) {
				break;
			}

			/*
			 * If this is not the first descriptor on the current
			 * chain, then link it to the previous WQE.  Otherwise,
			 * save the address of this descriptor (in "first") and
			 * continue.
			 */
			if (currindx != 0) {
				tavor_wqe_srq_linknext(desc, prev, srq);
				sync_indx = TAVOR_SRQ_WQE_INDEX(
				    srq->srq_wq_buf, prev,
				    srq->srq_wq_log_wqesz);

				/* Do a DMA sync for previous recv WQE */
				tavor_wqe_sync(srq, sync_indx, sync_indx+1,
				    TAVOR_WR_SRQ, DDI_DMA_SYNC_FORDEV);

				prev = desc;
			} else {

				/*
				 * In this case, the last WQE on the chain is
				 * also considered 'first'.  So set prev to
				 * first, here.
				 */
				first = prev = desc;
			}

			/*
			 * Increment "posted_cnt"
			 */
			posted_cnt++;
		}

		/*
		 * If we reach here and there are one or more WQEs which have
		 * been successfully chained together, then we need to link
		 * the current chain to the previously executing chain of
		 * descriptor (if there is one) and ring the doorbell for the
		 * recv work queue.
		 */
		if (currindx != 0) {
			/*
			 * Before we link the chain, we need to ensure that the
			 * "next" field on the last WQE is set to NULL (to
			 * indicate the end of the chain).
			 */
			tavor_wqe_srq_linknext(NULL, prev, srq);

			sync_indx = TAVOR_SRQ_WQE_INDEX(srq->srq_wq_buf, prev,
			    srq->srq_wq_log_wqesz);

			/* Do a DMA sync for current recv WQE */
			tavor_wqe_sync(srq, sync_indx, sync_indx+1,
			    TAVOR_WR_SRQ, DDI_DMA_SYNC_FORDEV);

			/*
			 * Now link the chain to the old chain (if there was
			 * one).
			 */
			if (srq->srq_wq_lastwqeindx == -1) {
				last_wqe_addr = NULL;
			} else {
				last_wqe_addr = TAVOR_SRQ_WQE_ADDR(srq,
				    srq->srq_wq_lastwqeindx);
			}
			tavor_wqe_srq_linknext(first, last_wqe_addr, srq);

			/*
			 * If there was a valid previous WQE (i.e. valid index),
			 * then sync it too.  This is because we have updated
			 * its "next" fields and we want to ensure that the
			 * hardware can see the changes.
			 */
			if (srq->srq_wq_lastwqeindx != -1) {
				sync_indx = srq->srq_wq_lastwqeindx;
				tavor_wqe_sync(srq, sync_indx, sync_indx+1,
				    TAVOR_WR_SRQ, DDI_DMA_SYNC_FORDEV);
			}

			/* Update some of the state in the QP */
			srq->srq_wq_lastwqeindx = TAVOR_SRQ_WQE_INDEX(
			    srq->srq_wq_buf, desc,
			    srq->srq_wq_log_wqesz);

			/* Ring the doorbell */
			/* SRQ needs NDS of 0 */
			tavor_qp_recv_doorbell(state,
			    (uint32_t)((uintptr_t)first - srq->srq_desc_off),
			    0, srq->srq_srqnum, (chainlen % maxdb));
		}
	}

	/*
	 * Update the "num_posted" return value (if necessary).  Then drop
	 * the locks and return success.
	 */
	if (num_posted != NULL) {
		*num_posted = posted_cnt;
	}

	mutex_exit(&srq->srq_wrid_wql->wql_lock);
	mutex_exit(&srq->srq_lock);

	return (status);
}


/*
 * tavor_qp_send_doorbell()
 *    Context: Can be called from interrupt or base context.
 */
static void
tavor_qp_send_doorbell(tavor_state_t *state, uint32_t nda, uint32_t nds,
    uint32_t qpn, uint32_t fence, uint32_t nopcode)
{
	uint64_t	doorbell = 0;

	/* Build the doorbell from the parameters */
	doorbell = (((uint64_t)nda & TAVOR_QPSNDDB_NDA_MASK) <<
	    TAVOR_QPSNDDB_NDA_SHIFT) |
	    ((uint64_t)fence << TAVOR_QPSNDDB_F_SHIFT) |
	    ((uint64_t)nopcode << TAVOR_QPSNDDB_NOPCODE_SHIFT) |
	    ((uint64_t)qpn << TAVOR_QPSNDDB_QPN_SHIFT) | nds;

	/* Write the doorbell to UAR */
	TAVOR_UAR_DOORBELL(state, (uint64_t *)&state->ts_uar->send,
	    doorbell);
}


/*
 * tavor_qp_recv_doorbell()
 *    Context: Can be called from interrupt or base context.
 */
static void
tavor_qp_recv_doorbell(tavor_state_t *state, uint32_t nda, uint32_t nds,
    uint32_t qpn, uint32_t credits)
{
	uint64_t	doorbell = 0;

	/* Build the doorbell from the parameters */
	doorbell = (((uint64_t)nda & TAVOR_QPRCVDB_NDA_MASK) <<
	    TAVOR_QPRCVDB_NDA_SHIFT) |
	    ((uint64_t)nds << TAVOR_QPRCVDB_NDS_SHIFT) |
	    ((uint64_t)qpn << TAVOR_QPRCVDB_QPN_SHIFT) | credits;

	/* Write the doorbell to UAR */
	TAVOR_UAR_DOORBELL(state, (uint64_t *)&state->ts_uar->recv,
	    doorbell);
}


/*
 * tavor_wqe_send_build()
 *    Context: Can be called from interrupt or base context.
 */
static int
tavor_wqe_send_build(tavor_state_t *state, tavor_qphdl_t qp,
    ibt_send_wr_t *wr, uint64_t *desc, uint_t *size)
{
	tavor_hw_snd_wqe_ud_t		*ud;
	tavor_hw_snd_wqe_remaddr_t	*rc;
	tavor_hw_snd_wqe_atomic_t	*at;
	tavor_hw_snd_wqe_remaddr_t	*uc;
	tavor_hw_snd_wqe_bind_t		*bn;
	tavor_hw_wqe_sgl_t		*ds;
	ibt_wr_ds_t			*sgl;
	tavor_ahhdl_t			ah;
	uint32_t			nds;
	int				i, num_ds, status;

	ASSERT(MUTEX_HELD(&qp->qp_lock));

	/* Initialize the information for the Data Segments */
	ds = (tavor_hw_wqe_sgl_t *)((uintptr_t)desc +
	    sizeof (tavor_hw_snd_wqe_nextctrl_t));
	nds = wr->wr_nds;
	sgl = wr->wr_sgl;
	num_ds = 0;

	/*
	 * Build a Send WQE depends first and foremost on the transport
	 * type of Work Request (i.e. UD, RC, or UC)
	 */
	switch (wr->wr_trans) {
	case IBT_UD_SRV:
		/* Ensure that work request transport type matches QP type */
		if (qp->qp_serv_type != TAVOR_QP_UD) {
			return (IBT_QP_SRV_TYPE_INVALID);
		}

		/*
		 * Validate the operation type.  For UD requests, only the
		 * "Send" operation is valid
		 */
		if (wr->wr_opcode != IBT_WRC_SEND) {
			return (IBT_QP_OP_TYPE_INVALID);
		}

		/*
		 * If this is a Special QP (QP0 or QP1), then we need to
		 * build MLX WQEs instead.  So jump to tavor_wqe_mlx_build()
		 * and return whatever status it returns
		 */
		if (qp->qp_is_special) {
			status = tavor_wqe_mlx_build(state, qp, wr, desc, size);
			return (status);
		}

		/*
		 * Otherwise, if this is a normal UD Send request, then fill
		 * all the fields in the Tavor UD header for the WQE.  Note:
		 * to do this we'll need to extract some information from the
		 * Address Handle passed with the work request.
		 */
		ud = (tavor_hw_snd_wqe_ud_t *)((uintptr_t)desc +
		    sizeof (tavor_hw_snd_wqe_nextctrl_t));
		ah = (tavor_ahhdl_t)wr->wr.ud.udwr_dest->ud_ah;
		if (ah == NULL) {
			return (IBT_AH_HDL_INVALID);
		}

		/*
		 * Build the Unreliable Datagram Segment for the WQE, using
		 * the information from the address handle and the work
		 * request.
		 */
		mutex_enter(&ah->ah_lock);
		TAVOR_WQE_BUILD_UD(qp, ud, ah, wr);
		mutex_exit(&ah->ah_lock);

		/* Update "ds" for filling in Data Segments (below) */
		ds = (tavor_hw_wqe_sgl_t *)((uintptr_t)ud +
		    sizeof (tavor_hw_snd_wqe_ud_t));
		break;

	case IBT_RC_SRV:
		/* Ensure that work request transport type matches QP type */
		if (qp->qp_serv_type != TAVOR_QP_RC) {
			return (IBT_QP_SRV_TYPE_INVALID);
		}

		/*
		 * Validate the operation type.  For RC requests, we allow
		 * "Send", "RDMA Read", "RDMA Write", various "Atomic"
		 * operations, and memory window "Bind"
		 */
		if ((wr->wr_opcode != IBT_WRC_SEND) &&
		    (wr->wr_opcode != IBT_WRC_RDMAR) &&
		    (wr->wr_opcode != IBT_WRC_RDMAW) &&
		    (wr->wr_opcode != IBT_WRC_CSWAP) &&
		    (wr->wr_opcode != IBT_WRC_FADD) &&
		    (wr->wr_opcode != IBT_WRC_BIND)) {
			return (IBT_QP_OP_TYPE_INVALID);
		}

		/*
		 * If this is a Send request, then all we need to do is break
		 * out and here and begin the Data Segment processing below
		 */
		if (wr->wr_opcode == IBT_WRC_SEND) {
			break;
		}

		/*
		 * If this is an RDMA Read or RDMA Write request, then fill
		 * in the "Remote Address" header fields.
		 */
		if ((wr->wr_opcode == IBT_WRC_RDMAR) ||
		    (wr->wr_opcode == IBT_WRC_RDMAW)) {
			rc = (tavor_hw_snd_wqe_remaddr_t *)((uintptr_t)desc +
			    sizeof (tavor_hw_snd_wqe_nextctrl_t));

			/*
			 * Build the Remote Address Segment for the WQE, using
			 * the information from the RC work request.
			 */
			TAVOR_WQE_BUILD_REMADDR(qp, rc, &wr->wr.rc.rcwr.rdma);

			/* Update "ds" for filling in Data Segments (below) */
			ds = (tavor_hw_wqe_sgl_t *)((uintptr_t)rc +
			    sizeof (tavor_hw_snd_wqe_remaddr_t));
			break;
		}

		/*
		 * If this is one of the Atomic type operations (i.e
		 * Compare-Swap or Fetch-Add), then fill in both the "Remote
		 * Address" header fields and the "Atomic" header fields.
		 */
		if ((wr->wr_opcode == IBT_WRC_CSWAP) ||
		    (wr->wr_opcode == IBT_WRC_FADD)) {
			rc = (tavor_hw_snd_wqe_remaddr_t *)((uintptr_t)desc +
			    sizeof (tavor_hw_snd_wqe_nextctrl_t));
			at = (tavor_hw_snd_wqe_atomic_t *)((uintptr_t)rc +
			    sizeof (tavor_hw_snd_wqe_remaddr_t));

			/*
			 * Build the Remote Address and Atomic Segments for
			 * the WQE, using the information from the RC Atomic
			 * work request.
			 */
			TAVOR_WQE_BUILD_RC_ATOMIC_REMADDR(qp, rc, wr);
			TAVOR_WQE_BUILD_ATOMIC(qp, at, wr->wr.rc.rcwr.atomic);

			/* Update "ds" for filling in Data Segments (below) */
			ds = (tavor_hw_wqe_sgl_t *)((uintptr_t)at +
			    sizeof (tavor_hw_snd_wqe_atomic_t));

			/*
			 * Update "nds" and "sgl" because Atomic requests have
			 * only a single Data Segment (and they are encoded
			 * somewhat differently in the work request.
			 */
			nds = 1;
			sgl = wr->wr_sgl;
			break;
		}

		/*
		 * If this is memory window Bind operation, then we call the
		 * tavor_wr_bind_check() routine to validate the request and
		 * to generate the updated RKey.  If this is successful, then
		 * we fill in the WQE's "Bind" header fields.
		 */
		if (wr->wr_opcode == IBT_WRC_BIND) {
			status = tavor_wr_bind_check(state, wr);
			if (status != DDI_SUCCESS) {
				return (status);
			}

			bn = (tavor_hw_snd_wqe_bind_t *)((uintptr_t)desc +
			    sizeof (tavor_hw_snd_wqe_nextctrl_t));

			/*
			 * Build the Bind Memory Window Segments for the WQE,
			 * using the information from the RC Bind memory
			 * window work request.
			 */
			TAVOR_WQE_BUILD_BIND(qp, bn, wr->wr.rc.rcwr.bind);

			/*
			 * Update the "ds" pointer.  Even though the "bind"
			 * operation requires no SGLs, this is necessary to
			 * facilitate the correct descriptor size calculations
			 * (below).
			 */
			ds = (tavor_hw_wqe_sgl_t *)((uintptr_t)bn +
			    sizeof (tavor_hw_snd_wqe_bind_t));
			nds = 0;
		}
		break;

	case IBT_UC_SRV:
		/* Ensure that work request transport type matches QP type */
		if (qp->qp_serv_type != TAVOR_QP_UC) {
			return (IBT_QP_SRV_TYPE_INVALID);
		}

		/*
		 * Validate the operation type.  For UC requests, we only
		 * allow "Send", "RDMA Write", and memory window "Bind".
		 * Note: Unlike RC, UC does not allow "RDMA Read" or "Atomic"
		 * operations
		 */
		if ((wr->wr_opcode != IBT_WRC_SEND) &&
		    (wr->wr_opcode != IBT_WRC_RDMAW) &&
		    (wr->wr_opcode != IBT_WRC_BIND)) {
			return (IBT_QP_OP_TYPE_INVALID);
		}

		/*
		 * If this is a Send request, then all we need to do is break
		 * out and here and begin the Data Segment processing below
		 */
		if (wr->wr_opcode == IBT_WRC_SEND) {
			break;
		}

		/*
		 * If this is an RDMA Write request, then fill in the "Remote
		 * Address" header fields.
		 */
		if (wr->wr_opcode == IBT_WRC_RDMAW) {
			uc = (tavor_hw_snd_wqe_remaddr_t *)((uintptr_t)desc +
			    sizeof (tavor_hw_snd_wqe_nextctrl_t));

			/*
			 * Build the Remote Address Segment for the WQE, using
			 * the information from the UC work request.
			 */
			TAVOR_WQE_BUILD_REMADDR(qp, uc, &wr->wr.uc.ucwr.rdma);

			/* Update "ds" for filling in Data Segments (below) */
			ds = (tavor_hw_wqe_sgl_t *)((uintptr_t)uc +
			    sizeof (tavor_hw_snd_wqe_remaddr_t));
			break;
		}

		/*
		 * If this is memory window Bind operation, then we call the
		 * tavor_wr_bind_check() routine to validate the request and
		 * to generate the updated RKey.  If this is successful, then
		 * we fill in the WQE's "Bind" header fields.
		 */
		if (wr->wr_opcode == IBT_WRC_BIND) {
			status = tavor_wr_bind_check(state, wr);
			if (status != DDI_SUCCESS) {
				return (status);
			}

			bn = (tavor_hw_snd_wqe_bind_t *)((uintptr_t)desc +
			    sizeof (tavor_hw_snd_wqe_nextctrl_t));

			/*
			 * Build the Bind Memory Window Segments for the WQE,
			 * using the information from the UC Bind memory
			 * window work request.
			 */
			TAVOR_WQE_BUILD_BIND(qp, bn, wr->wr.uc.ucwr.bind);

			/*
			 * Update the "ds" pointer.  Even though the "bind"
			 * operation requires no SGLs, this is necessary to
			 * facilitate the correct descriptor size calculations
			 * (below).
			 */
			ds = (tavor_hw_wqe_sgl_t *)((uintptr_t)bn +
			    sizeof (tavor_hw_snd_wqe_bind_t));
			nds = 0;
		}
		break;

	default:
		return (IBT_QP_SRV_TYPE_INVALID);
	}

	/*
	 * Now fill in the Data Segments (SGL) for the Send WQE based on
	 * the values setup above (i.e. "sgl", "nds", and the "ds" pointer
	 * Start by checking for a valid number of SGL entries
	 */
	if (nds > qp->qp_sq_sgl) {
		return (IBT_QP_SGL_LEN_INVALID);
	}

	/*
	 * For each SGL in the Send Work Request, fill in the Send WQE's data
	 * segments.  Note: We skip any SGL with zero size because Tavor
	 * hardware cannot handle a zero for "byte_cnt" in the WQE.  Actually
	 * the encoding for zero means a 2GB transfer.  Because of this special
	 * encoding in the hardware, we mask the requested length with
	 * TAVOR_WQE_SGL_BYTE_CNT_MASK (so that 2GB will end up encoded as
	 * zero.)
	 */
	for (i = 0; i < nds; i++) {
		if (sgl[i].ds_len == 0) {
			continue;
		}

		/*
		 * Fill in the Data Segment(s) for the current WQE, using the
		 * information contained in the scatter-gather list of the
		 * work request.
		 */
		TAVOR_WQE_BUILD_DATA_SEG(qp, &ds[num_ds], &sgl[i]);
		num_ds++;
	}

	/* Return the size of descriptor (in 16-byte chunks) */
	*size = ((uintptr_t)&ds[num_ds] - (uintptr_t)desc) >> 4;

	return (DDI_SUCCESS);
}


/*
 * tavor_wqe_send_linknext()
 *    Context: Can be called from interrupt or base context.
 */
static void
tavor_wqe_send_linknext(ibt_send_wr_t *curr_wr, ibt_send_wr_t *prev_wr,
    uint64_t *curr_desc, uint_t curr_descsz, uint64_t *prev_desc,
    tavor_sw_wqe_dbinfo_t *dbinfo, tavor_qphdl_t qp)
{
	uint64_t	next, ctrl;
	uint32_t	nopcode, fence;

	/*
	 * Calculate the "next" field of the descriptor.  This amounts to
	 * setting up the "next_wqe_addr", "nopcode", "fence", and "nds"
	 * fields (see tavor_hw.h for more).  Note:  If there is no next
	 * descriptor (i.e. if the current descriptor is the last WQE on
	 * the chain), then set "next" to zero.
	 */
	if (curr_desc != NULL) {
		/*
		 * Determine the value for the Tavor WQE "nopcode" field
		 * by using the IBTF opcode from the work request
		 */
		switch (curr_wr->wr_opcode) {
		case IBT_WRC_RDMAW:
			if (curr_wr->wr_flags & IBT_WR_SEND_IMMED) {
				nopcode = TAVOR_WQE_SEND_NOPCODE_RDMAWI;
			} else {
				nopcode = TAVOR_WQE_SEND_NOPCODE_RDMAW;
			}
			break;

		case IBT_WRC_SEND:
			if (curr_wr->wr_flags & IBT_WR_SEND_IMMED) {
				nopcode = TAVOR_WQE_SEND_NOPCODE_SENDI;
			} else {
				nopcode = TAVOR_WQE_SEND_NOPCODE_SEND;
			}
			break;

		case IBT_WRC_RDMAR:
			nopcode = TAVOR_WQE_SEND_NOPCODE_RDMAR;
			break;

		case IBT_WRC_CSWAP:
			nopcode = TAVOR_WQE_SEND_NOPCODE_ATMCS;
			break;

		case IBT_WRC_FADD:
			nopcode = TAVOR_WQE_SEND_NOPCODE_ATMFA;
			break;

		case IBT_WRC_BIND:
			nopcode = TAVOR_WQE_SEND_NOPCODE_BIND;
			break;
		}

		curr_desc = (uint64_t *)(uintptr_t)((uintptr_t)curr_desc
		    - qp->qp_desc_off);
		next  = ((uint64_t)(uintptr_t)curr_desc &
		    TAVOR_WQE_NDA_MASK) << 32;
		next  = next | ((uint64_t)nopcode << 32);
		fence = (curr_wr->wr_flags & IBT_WR_SEND_FENCE) ? 1 : 0;
		if (fence) {
			next = next | TAVOR_WQE_SEND_FENCE_MASK;
		}
		next = next | (curr_descsz & TAVOR_WQE_NDS_MASK);

		/*
		 * If a send queue doorbell will be rung for the next
		 * WQE on the chain, then set the current WQE's "dbd" bit.
		 * Note: We also update the "dbinfo" structure here to pass
		 * back information about what should (later) be included
		 * in the send queue doorbell.
		 */
		if (dbinfo) {
			next = next | TAVOR_WQE_DBD_MASK;
			dbinfo->db_nopcode = nopcode;
			dbinfo->db_fence   = fence;
		}
	} else {
		next = 0;
	}

	/*
	 * If this WQE is supposed to be linked to the previous descriptor,
	 * then we need to update not only the previous WQE's "next" fields
	 * but we must also update this WQE's "ctrl" fields (i.e. the "c", "e",
	 * "s", "i" and "immediate" fields - see tavor_hw.h for more).  Note:
	 * the "e" bit is always hardcoded to zero.
	 */
	if (prev_desc != NULL) {
		/*
		 * If a send queue doorbell will be rung for the next WQE on
		 * the chain, then update the current WQE's "next" field and
		 * return.
		 * Note: We don't want to modify the "ctrl" field here because
		 * that portion of the previous WQE has already been set
		 * correctly at some previous point in time.
		 */
		if (dbinfo) {
			TAVOR_WQE_LINKFIRST(qp, prev_desc, next);
			return;
		}

		ctrl = 0;

		/* Set the "c" (i.e. "signaled") bit appropriately */
		if (prev_wr->wr_flags & IBT_WR_SEND_SIGNAL) {
			ctrl = ctrl | TAVOR_WQE_SEND_SIGNALED_MASK;
		}

		/* Set the "s" (i.e. "solicited") bit appropriately */
		if (prev_wr->wr_flags & IBT_WR_SEND_SOLICIT) {
			ctrl = ctrl | TAVOR_WQE_SEND_SOLICIT_MASK;
		}

		/* Set the "i" bit and the immediate data appropriately */
		if (prev_wr->wr_flags & IBT_WR_SEND_IMMED) {
			ctrl = ctrl | TAVOR_WQE_SEND_IMMEDIATE_MASK;
			ctrl = ctrl | tavor_wr_get_immediate(prev_wr);
		}

		TAVOR_WQE_LINKNEXT(qp, prev_desc, ctrl, next);
	}
}


/*
 * tavor_wqe_mlx_build()
 *    Context: Can be called from interrupt or base context.
 */
static int
tavor_wqe_mlx_build(tavor_state_t *state, tavor_qphdl_t qp,
    ibt_send_wr_t *wr, uint64_t *desc, uint_t *size)
{
	tavor_hw_udav_t		udav;
	tavor_ahhdl_t		ah;
	ib_lrh_hdr_t		*lrh;
	ib_grh_t		*grh;
	ib_bth_hdr_t		*bth;
	ib_deth_hdr_t		*deth;
	tavor_hw_wqe_sgl_t	*ds;
	ibt_wr_ds_t		*sgl;
	uint8_t			*mgmtclass, *hpoint, *hcount;
	uint64_t		data;
	uint32_t		nds, offset, pktlen;
	uint32_t		desc_sz, udav_sz;
	int			i, num_ds;

	ASSERT(MUTEX_HELD(&qp->qp_lock));

	/* Initialize the information for the Data Segments */
	ds = (tavor_hw_wqe_sgl_t *)((uintptr_t)desc +
	    sizeof (tavor_hw_mlx_wqe_nextctrl_t));

	/*
	 * Pull the address handle from the work request and read in
	 * the contents of the UDAV.  This will be used to answer some
	 * questions about the request.
	 */
	ah = (tavor_ahhdl_t)wr->wr.ud.udwr_dest->ud_ah;
	if (ah == NULL) {
		return (IBT_AH_HDL_INVALID);
	}
	mutex_enter(&ah->ah_lock);
	udav_sz = sizeof (tavor_hw_udav_t) >> 3;
	for (i = 0; i < udav_sz; i++) {
		data = ddi_get64(ah->ah_udavrsrcp->tr_acchdl,
		    ((uint64_t *)ah->ah_udavrsrcp->tr_addr + i));
		((uint64_t *)&udav)[i] = data;
	}
	mutex_exit(&ah->ah_lock);

	/*
	 * If the request is for QP1 and the destination LID is equal to
	 * the Permissive LID, then return an error.  This combination is
	 * not allowed
	 */
	if ((udav.rlid == IB_LID_PERMISSIVE) &&
	    (qp->qp_is_special == TAVOR_QP_GSI)) {
		return (IBT_AH_HDL_INVALID);
	}

	/*
	 * Calculate the size of the packet headers, including the GRH
	 * (if necessary)
	 */
	desc_sz = sizeof (ib_lrh_hdr_t) + sizeof (ib_bth_hdr_t) +
	    sizeof (ib_deth_hdr_t);
	if (udav.grh) {
		desc_sz += sizeof (ib_grh_t);
	}

	/*
	 * Begin to build the first "inline" data segment for the packet
	 * headers.  Note:  By specifying "inline" we can build the contents
	 * of the MAD packet headers directly into the work queue (as part
	 * descriptor).  This has the advantage of both speeding things up
	 * and of not requiring the driver to allocate/register any additional
	 * memory for the packet headers.
	 */
	TAVOR_WQE_BUILD_INLINE(qp, &ds[0], desc_sz);
	desc_sz += 4;

	/*
	 * Build Local Route Header (LRH)
	 *    We start here by building the LRH into a temporary location.
	 *    When we have finished we copy the LRH data into the descriptor.
	 *
	 *    Notice that the VL values are hardcoded.  This is not a problem
	 *    because VL15 is decided later based on the value in the MLX
	 *    transport "next/ctrl" header (see the "vl15" bit below), and it
	 *    is otherwise (meaning for QP1) chosen from the SL-to-VL table
	 *    values.  This rule does not hold for loopback packets however
	 *    (all of which bypass the SL-to-VL tables) and it is the reason
	 *    that non-QP0 MADs are setup with VL hardcoded to zero below.
	 *
	 *    Notice also that Source LID is hardcoded to the Permissive LID
	 *    (0xFFFF).  This is also not a problem because if the Destination
	 *    LID is not the Permissive LID, then the "slr" value in the MLX
	 *    transport "next/ctrl" header will be set to zero and the hardware
	 *    will pull the LID from value in the port.
	 */
	lrh = (ib_lrh_hdr_t *)((uintptr_t)&ds[0] + 4);
	pktlen = (desc_sz + 0x100) >> 2;
	TAVOR_WQE_BUILD_MLX_LRH(lrh, qp, udav, pktlen);

	/*
	 * Build Global Route Header (GRH)
	 *    This is only built if necessary as defined by the "grh" bit in
	 *    the address vector.  Note:  We also calculate the offset to the
	 *    next header (BTH) based on whether or not the "grh" bit is set.
	 */
	if (udav.grh) {
		/*
		 * If the request is for QP0, then return an error.  The
		 * combination of global routine (GRH) and QP0 is not allowed.
		 */
		if (qp->qp_is_special == TAVOR_QP_SMI) {
			return (IBT_AH_HDL_INVALID);
		}
		grh = (ib_grh_t *)((uintptr_t)lrh + sizeof (ib_lrh_hdr_t));
		TAVOR_WQE_BUILD_MLX_GRH(state, grh, qp, udav, pktlen);

		bth = (ib_bth_hdr_t *)((uintptr_t)grh + sizeof (ib_grh_t));
	} else {
		bth = (ib_bth_hdr_t *)((uintptr_t)lrh + sizeof (ib_lrh_hdr_t));
	}


	/*
	 * Build Base Transport Header (BTH)
	 *    Notice that the M, PadCnt, and TVer fields are all set
	 *    to zero implicitly.  This is true for all Management Datagrams
	 *    MADs whether GSI are SMI.
	 */
	TAVOR_WQE_BUILD_MLX_BTH(state, bth, qp, wr);

	/*
	 * Build Datagram Extended Transport Header (DETH)
	 */
	deth = (ib_deth_hdr_t *)((uintptr_t)bth + sizeof (ib_bth_hdr_t));
	TAVOR_WQE_BUILD_MLX_DETH(deth, qp);

	/* Ensure that the Data Segment is aligned on a 16-byte boundary */
	ds = (tavor_hw_wqe_sgl_t *)((uintptr_t)deth + sizeof (ib_deth_hdr_t));
	ds = (tavor_hw_wqe_sgl_t *)(((uintptr_t)ds + 0xF) & ~0xF);
	nds = wr->wr_nds;
	sgl = wr->wr_sgl;
	num_ds = 0;

	/*
	 * Now fill in the Data Segments (SGL) for the MLX WQE based on the
	 * values set up above (i.e. "sgl", "nds", and the "ds" pointer
	 * Start by checking for a valid number of SGL entries
	 */
	if (nds > qp->qp_sq_sgl) {
		return (IBT_QP_SGL_LEN_INVALID);
	}

	/*
	 * For each SGL in the Send Work Request, fill in the MLX WQE's data
	 * segments.  Note: We skip any SGL with zero size because Tavor
	 * hardware cannot handle a zero for "byte_cnt" in the WQE.  Actually
	 * the encoding for zero means a 2GB transfer.  Because of this special
	 * encoding in the hardware, we mask the requested length with
	 * TAVOR_WQE_SGL_BYTE_CNT_MASK (so that 2GB will end up encoded as
	 * zero.)
	 */
	mgmtclass = hpoint = hcount = NULL;
	offset = 0;
	for (i = 0; i < nds; i++) {
		if (sgl[i].ds_len == 0) {
			continue;
		}

		/*
		 * Fill in the Data Segment(s) for the MLX send WQE, using
		 * the information contained in the scatter-gather list of
		 * the work request.
		 */
		TAVOR_WQE_BUILD_DATA_SEG(qp, &ds[num_ds], &sgl[i]);

		/*
		 * Search through the contents of all MADs posted to QP0 to
		 * initialize pointers to the places where Directed Route "hop
		 * pointer", "hop count", and "mgmtclass" would be.  Tavor
		 * needs these updated (i.e. incremented or decremented, as
		 * necessary) by software.
		 */
		if (qp->qp_is_special == TAVOR_QP_SMI) {

			TAVOR_SPECIAL_QP_DRMAD_GET_MGMTCLASS(mgmtclass,
			    offset, sgl[i].ds_va, sgl[i].ds_len);

			TAVOR_SPECIAL_QP_DRMAD_GET_HOPPOINTER(hpoint,
			    offset, sgl[i].ds_va, sgl[i].ds_len);

			TAVOR_SPECIAL_QP_DRMAD_GET_HOPCOUNT(hcount,
			    offset, sgl[i].ds_va, sgl[i].ds_len);

			offset += sgl[i].ds_len;
		}
		num_ds++;
	}

	/*
	 * Tavor's Directed Route MADs need to have the "hop pointer"
	 * incremented/decremented (as necessary) depending on whether it is
	 * currently less than or greater than the "hop count" (i.e. whether
	 * the MAD is a request or a response.)
	 */
	if (qp->qp_is_special == TAVOR_QP_SMI) {
		TAVOR_SPECIAL_QP_DRMAD_DO_HOPPOINTER_MODIFY(*mgmtclass,
		    *hpoint, *hcount);
	}

	/*
	 * Now fill in the ICRC Data Segment.  This data segment is inlined
	 * just like the packets headers above, but it is only four bytes and
	 * set to zero (to indicate that we wish the hardware to generate ICRC.
	 */
	TAVOR_WQE_BUILD_INLINE_ICRC(qp, &ds[num_ds], 4, 0);
	num_ds++;

	/* Return the size of descriptor (in 16-byte chunks) */
	*size = ((uintptr_t)&ds[num_ds] - (uintptr_t)desc) >> 0x4;

	return (DDI_SUCCESS);
}


/*
 * tavor_wqe_mlx_linknext()
 *    Context: Can be called from interrupt or base context.
 */
static void
tavor_wqe_mlx_linknext(ibt_send_wr_t *prev_wr, uint64_t *curr_desc,
    uint_t curr_descsz, uint64_t *prev_desc, tavor_sw_wqe_dbinfo_t *dbinfo,
    tavor_qphdl_t qp)
{
	tavor_hw_udav_t		udav;
	tavor_ahhdl_t		ah;
	uint64_t		next, ctrl, data;
	uint_t			nopcode;
	uint_t			udav_sz;
	int			i;

	/*
	 * Calculate the "next" field of the descriptor.  This amounts to
	 * setting up the "next_wqe_addr", "nopcode", and "nds" fields (see
	 * tavor_hw.h for more).  Note:  If there is no next descriptor (i.e.
	 * if the current descriptor is the last WQE on the chain), then set
	 * "next" to zero.
	 */
	if (curr_desc != NULL) {
		/*
		 * The only valid Tavor WQE "nopcode" for MLX transport
		 * requests is the "Send" code.
		 */
		nopcode = TAVOR_WQE_SEND_NOPCODE_SEND;
		curr_desc = (uint64_t *)(uintptr_t)((uint64_t)
		    (uintptr_t)curr_desc - qp->qp_desc_off);
		next = (uint64_t)((uintptr_t)curr_desc &
		    TAVOR_WQE_NDA_MASK) << 32;
		next = next | ((uint64_t)nopcode << 32);
		next = next | (curr_descsz & TAVOR_WQE_NDS_MASK);

		/*
		 * If a send queue doorbell will be rung for the next
		 * WQE on the chain, then set the current WQE's "dbd" bit.
		 * Note: We also update the "dbinfo" structure here to pass
		 * back information about what should (later) be included
		 * in the send queue doorbell.
		 */
		if (dbinfo) {
			next = next | TAVOR_WQE_DBD_MASK;
			dbinfo->db_nopcode = nopcode;
			dbinfo->db_fence   = 0;
		}
	} else {
		next = 0;
	}

	/*
	 * If this WQE is supposed to be linked to the previous descriptor,
	 * then we need to update not only the previous WQE's "next" fields
	 * but we must also update this WQE's "ctrl" fields (i.e. the "vl15",
	 * "slr", "max_srate", "sl", "c", "e", "rlid", and "vcrc" fields -
	 * see tavor_hw.h for more) Note: the "e" bit and "vcrc" fields are
	 * always hardcoded to zero.
	 */
	if (prev_desc != NULL) {
		/*
		 * If a send queue doorbell will be rung for the next WQE on
		 * the chain, then update the current WQE's "next" field and
		 * return.
		 * Note: We don't want to modify the "ctrl" field here because
		 * that portion of the previous WQE has already been set
		 * correctly at some previous point in time.
		 */
		if (dbinfo) {
			TAVOR_WQE_LINKFIRST(qp, prev_desc, next);
			return;
		}

		/*
		 * Pull the address handle from the work request and read in
		 * the contents of the UDAV.  This will be used to answer some
		 * questions about the request.
		 */
		ah = (tavor_ahhdl_t)prev_wr->wr.ud.udwr_dest->ud_ah;
		mutex_enter(&ah->ah_lock);
		udav_sz = sizeof (tavor_hw_udav_t) >> 3;
		for (i = 0; i < udav_sz; i++) {
			data = ddi_get64(ah->ah_udavrsrcp->tr_acchdl,
			    ((uint64_t *)ah->ah_udavrsrcp->tr_addr + i));
			((uint64_t *)&udav)[i] = data;
		}
		mutex_exit(&ah->ah_lock);

		ctrl = 0;

		/* Only QP0 uses VL15, otherwise use VL in the packet */
		if (qp->qp_is_special == TAVOR_QP_SMI) {
			ctrl = ctrl | TAVOR_WQE_MLXHDR_VL15_MASK;
		}

		/*
		 * The SLR (Source LID Replace) bit determines whether the
		 * source LID for an outgoing MLX packet should come from the
		 * PortInfo (SLR = 0) or should be left as it is in the
		 * descriptor (SLR = 1).  The latter is necessary for packets
		 * to be sent with the Permissive LID.
		 */
		if (udav.rlid == IB_LID_PERMISSIVE) {
			ctrl = ctrl | TAVOR_WQE_MLXHDR_SLR_MASK;
		}

		/* Fill in the max static rate from the address handle */
		ctrl = ctrl | ((uint64_t)udav.max_stat_rate <<
		    TAVOR_WQE_MLXHDR_SRATE_SHIFT);

		/* All VL15 (i.e. SMI) traffic is required to use SL 0 */
		if (qp->qp_is_special != TAVOR_QP_SMI) {
			ctrl = ctrl | ((uint64_t)udav.sl <<
			    TAVOR_WQE_MLXHDR_SL_SHIFT);
		}

		/* Set the "c" (i.e. "signaled") bit appropriately */
		if (prev_wr->wr_flags & IBT_WR_SEND_SIGNAL) {
			ctrl = ctrl | TAVOR_WQE_MLXHDR_SIGNALED_MASK;
		}

		/* Fill in the destination LID from the address handle */
		ctrl = ctrl | ((uint64_t)udav.rlid <<
		    TAVOR_WQE_MLXHDR_RLID_SHIFT);

		TAVOR_WQE_LINKNEXT(qp, prev_desc, ctrl, next);
	}
}


/*
 * tavor_wqe_recv_build()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static int
tavor_wqe_recv_build(tavor_state_t *state, tavor_qphdl_t qp,
    ibt_recv_wr_t *wr, uint64_t *desc, uint_t *size)
{
	tavor_hw_wqe_sgl_t	*ds;
	int			i, num_ds;

	ASSERT(MUTEX_HELD(&qp->qp_lock));

	/* Check that work request transport type is valid */
	if ((qp->qp_serv_type != TAVOR_QP_UD) &&
	    (qp->qp_serv_type != TAVOR_QP_RC) &&
	    (qp->qp_serv_type != TAVOR_QP_UC)) {
		return (IBT_QP_SRV_TYPE_INVALID);
	}

	/* Fill in the Data Segments (SGL) for the Recv WQE */
	ds = (tavor_hw_wqe_sgl_t *)((uintptr_t)desc +
	    sizeof (tavor_hw_rcv_wqe_nextctrl_t));
	num_ds = 0;

	/* Check for valid number of SGL entries */
	if (wr->wr_nds > qp->qp_rq_sgl) {
		return (IBT_QP_SGL_LEN_INVALID);
	}

	/*
	 * For each SGL in the Recv Work Request, fill in the Recv WQE's data
	 * segments.  Note: We skip any SGL with zero size because Tavor
	 * hardware cannot handle a zero for "byte_cnt" in the WQE.  Actually
	 * the encoding for zero means a 2GB transfer.  Because of this special
	 * encoding in the hardware, we mask the requested length with
	 * TAVOR_WQE_SGL_BYTE_CNT_MASK (so that 2GB will end up encoded as
	 * zero.)
	 */
	for (i = 0; i < wr->wr_nds; i++) {
		if (wr->wr_sgl[i].ds_len == 0) {
			continue;
		}

		/*
		 * Fill in the Data Segment(s) for the receive WQE, using the
		 * information contained in the scatter-gather list of the
		 * work request.
		 */
		TAVOR_WQE_BUILD_DATA_SEG(qp, &ds[num_ds], &wr->wr_sgl[i]);
		num_ds++;
	}

	/* Return the size of descriptor (in 16-byte chunks) */
	*size = ((uintptr_t)&ds[num_ds] - (uintptr_t)desc) >> 0x4;

	return (DDI_SUCCESS);
}


/*
 * tavor_wqe_recv_linknext()
 *    Context: Can be called from interrupt or base context.
 */
static void
tavor_wqe_recv_linknext(uint64_t *curr_desc, uint_t curr_descsz,
    uint64_t *prev_desc, tavor_qphdl_t qp)
{
	uint64_t	next;

	/*
	 * Calculate the "next" field of the descriptor.  This amounts to
	 * setting up the "next_wqe_addr", "dbd", and "nds" fields (see
	 * tavor_hw.h for more).  Note:  If there is no next descriptor (i.e.
	 * if the current descriptor is the last WQE on the chain), then set
	 * "next" field to TAVOR_WQE_DBD_MASK.  This is because the Tavor
	 * hardware requires the "dbd" bit to be set to one for all Recv WQEs.
	 * In either case, we must add a single bit in the "reserved" field
	 * (TAVOR_RCV_WQE_NDA0_WA_MASK) following the NDA.  This is the
	 * workaround for a known Tavor errata that can cause Recv WQEs with
	 * zero in the NDA field to behave improperly.
	 */
	if (curr_desc != NULL) {
		curr_desc = (uint64_t *)(uintptr_t)((uintptr_t)curr_desc -
		    qp->qp_desc_off);
		next = (uint64_t)((uintptr_t)curr_desc &
		    TAVOR_WQE_NDA_MASK) << 32;
		next = next | (curr_descsz & TAVOR_WQE_NDS_MASK) |
		    TAVOR_WQE_DBD_MASK | TAVOR_RCV_WQE_NDA0_WA_MASK;
	} else {
		next = TAVOR_WQE_DBD_MASK | TAVOR_RCV_WQE_NDA0_WA_MASK;
	}

	/*
	 * If this WQE is supposed to be linked to the previous descriptor,
	 * then we need to update not only the previous WQE's "next" fields
	 * but we must also update this WQE's "ctrl" fields (i.e. the "c" and
	 * "e" bits - see tavor_hw.h for more).  Note: both the "c" and "e"
	 * bits are always hardcoded to zero.
	 */
	if (prev_desc != NULL) {
		TAVOR_WQE_LINKNEXT(qp, prev_desc, 0, next);
	}
}


/*
 * tavor_wqe_srq_build()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static int
tavor_wqe_srq_build(tavor_state_t *state, tavor_srqhdl_t srq,
    ibt_recv_wr_t *wr, uint64_t *desc)
{
	tavor_hw_wqe_sgl_t	*ds;
	ibt_wr_ds_t		end_sgl;
	int			i, num_ds;

	ASSERT(MUTEX_HELD(&srq->srq_lock));

	/* Fill in the Data Segments (SGL) for the Recv WQE */
	ds = (tavor_hw_wqe_sgl_t *)((uintptr_t)desc +
	    sizeof (tavor_hw_rcv_wqe_nextctrl_t));
	num_ds = 0;

	/* Check for valid number of SGL entries */
	if (wr->wr_nds > srq->srq_wq_sgl) {
		return (IBT_QP_SGL_LEN_INVALID);
	}

	/*
	 * For each SGL in the Recv Work Request, fill in the Recv WQE's data
	 * segments.  Note: We skip any SGL with zero size because Tavor
	 * hardware cannot handle a zero for "byte_cnt" in the WQE.  Actually
	 * the encoding for zero means a 2GB transfer.  Because of this special
	 * encoding in the hardware, we mask the requested length with
	 * TAVOR_WQE_SGL_BYTE_CNT_MASK (so that 2GB will end up encoded as
	 * zero.)
	 */
	for (i = 0; i < wr->wr_nds; i++) {
		if (wr->wr_sgl[i].ds_len == 0) {
			continue;
		}

		/*
		 * Fill in the Data Segment(s) for the receive WQE, using the
		 * information contained in the scatter-gather list of the
		 * work request.
		 */
		TAVOR_WQE_BUILD_DATA_SEG_SRQ(srq, &ds[num_ds], &wr->wr_sgl[i]);
		num_ds++;
	}

	/*
	 * For SRQ, if the number of data segments is less than the maximum
	 * specified at alloc, then we have to fill in a special "key" entry in
	 * the sgl entry after the last valid one in this post request.  We do
	 * that here.
	 */
	if (num_ds < srq->srq_wq_sgl) {
		end_sgl.ds_va  = 0;
		end_sgl.ds_len = 0;
		end_sgl.ds_key = 0x1;
		TAVOR_WQE_BUILD_DATA_SEG_SRQ(srq, &ds[num_ds], &end_sgl);
	}

	return (DDI_SUCCESS);
}


/*
 * tavor_wqe_srq_linknext()
 *    Context: Can be called from interrupt or base context.
 */
static void
tavor_wqe_srq_linknext(uint64_t *curr_desc, uint64_t *prev_desc,
    tavor_srqhdl_t srq)
{
	uint64_t	next;

	/*
	 * Calculate the "next" field of the descriptor.  This amounts to
	 * setting up the "next_wqe_addr", "dbd", and "nds" fields (see
	 * tavor_hw.h for more).  Note:  If there is no next descriptor (i.e.
	 * if the current descriptor is the last WQE on the chain), then set
	 * "next" field to TAVOR_WQE_DBD_MASK.  This is because the Tavor
	 * hardware requires the "dbd" bit to be set to one for all Recv WQEs.
	 * In either case, we must add a single bit in the "reserved" field
	 * (TAVOR_RCV_WQE_NDA0_WA_MASK) following the NDA.  This is the
	 * workaround for a known Tavor errata that can cause Recv WQEs with
	 * zero in the NDA field to behave improperly.
	 */
	if (curr_desc != NULL) {
		curr_desc = (uint64_t *)(uintptr_t)((uintptr_t)curr_desc -
		    srq->srq_desc_off);
		next = (uint64_t)((uintptr_t)curr_desc &
		    TAVOR_WQE_NDA_MASK) << 32;
		next = next | TAVOR_WQE_DBD_MASK | TAVOR_RCV_WQE_NDA0_WA_MASK;
	} else {
		next = TAVOR_RCV_WQE_NDA0_WA_MASK;
	}

	/*
	 * If this WQE is supposed to be linked to the previous descriptor,
	 * then we need to update not only the previous WQE's "next" fields
	 * but we must also update this WQE's "ctrl" fields (i.e. the "c" and
	 * "e" bits - see tavor_hw.h for more).  Note: both the "c" and "e"
	 * bits are always hardcoded to zero.
	 */
	if (prev_desc != NULL) {
		TAVOR_WQE_LINKNEXT_SRQ(srq, prev_desc, 0, next);
	}
}


/*
 * tavor_wr_get_immediate()
 *    Context: Can be called from interrupt or base context.
 */
static uint32_t
tavor_wr_get_immediate(ibt_send_wr_t *wr)
{
	/*
	 * This routine extracts the "immediate data" from the appropriate
	 * location in the IBTF work request.  Because of the way the
	 * work request structure is defined, the location for this data
	 * depends on the actual work request operation type.
	 */

	/* For RDMA Write, test if RC or UC */
	if (wr->wr_opcode == IBT_WRC_RDMAW) {
		if (wr->wr_trans == IBT_RC_SRV) {
			return (wr->wr.rc.rcwr.rdma.rdma_immed);
		} else {  /* IBT_UC_SRV */
			return (wr->wr.uc.ucwr.rdma.rdma_immed);
		}
	}

	/* For Send, test if RC, UD, or UC */
	if (wr->wr_opcode == IBT_WRC_SEND) {
		if (wr->wr_trans == IBT_RC_SRV) {
			return (wr->wr.rc.rcwr.send_immed);
		} else if (wr->wr_trans == IBT_UD_SRV) {
			return (wr->wr.ud.udwr_immed);
		} else {  /* IBT_UC_SRV */
			return (wr->wr.uc.ucwr.send_immed);
		}
	}

	/*
	 * If any other type of request, then immediate is undefined
	 */
	return (0);
}


/*
 * tavor_wqe_sync()
 *    Context: Can be called from interrupt or base context.
 */
static void
tavor_wqe_sync(void *hdl, uint_t sync_from, uint_t sync_to,
    uint_t sync_type, uint_t flag)
{
	tavor_qphdl_t		qp;
	tavor_srqhdl_t		srq;
	uint_t			is_sync_req;
	uint64_t		*wqe_from, *wqe_to, *wqe_base, *wqe_top;
	ddi_dma_handle_t	dmahdl;
	off_t			offset;
	size_t			length;
	uint32_t		qsize;
	int			status;

	if (sync_type == TAVOR_WR_SRQ) {
		srq = (tavor_srqhdl_t)hdl;
		is_sync_req = srq->srq_sync;
		/* Get the DMA handle from SRQ context */
		dmahdl = srq->srq_mrhdl->mr_bindinfo.bi_dmahdl;
	} else {
		qp = (tavor_qphdl_t)hdl;
		is_sync_req = qp->qp_sync;
		/* Get the DMA handle from QP context */
		dmahdl = qp->qp_mrhdl->mr_bindinfo.bi_dmahdl;
	}

	/* Determine if the work queues need to be synced or not */
	if (is_sync_req == 0) {
		return;
	}

	/*
	 * Depending on the type of the work queue, we grab information
	 * about the address ranges we need to DMA sync.
	 */
	if (sync_type == TAVOR_WR_SEND) {
		wqe_from = TAVOR_QP_SQ_ENTRY(qp, sync_from);
		wqe_to   = TAVOR_QP_SQ_ENTRY(qp, sync_to);
		qsize	 = qp->qp_sq_bufsz;

		wqe_base = TAVOR_QP_SQ_ENTRY(qp, 0);
		wqe_top	 = TAVOR_QP_SQ_ENTRY(qp, qsize);
	} else if (sync_type == TAVOR_WR_RECV) {
		wqe_from = TAVOR_QP_RQ_ENTRY(qp, sync_from);
		wqe_to   = TAVOR_QP_RQ_ENTRY(qp, sync_to);
		qsize	 = qp->qp_rq_bufsz;

		wqe_base = TAVOR_QP_RQ_ENTRY(qp, 0);
		wqe_top	 = TAVOR_QP_RQ_ENTRY(qp, qsize);
	} else {
		wqe_from = TAVOR_SRQ_WQ_ENTRY(srq, sync_from);
		wqe_to   = TAVOR_SRQ_WQ_ENTRY(srq, sync_to);
		qsize	 = srq->srq_wq_bufsz;

		wqe_base = TAVOR_SRQ_WQ_ENTRY(srq, 0);
		wqe_top	 = TAVOR_SRQ_WQ_ENTRY(srq, qsize);
	}

	/*
	 * There are two possible cases for the beginning and end of the WQE
	 * chain we are trying to sync.  Either this is the simple case, where
	 * the end of the chain is below the beginning of the chain, or it is
	 * the "wrap-around" case, where the end of the chain has wrapped over
	 * the end of the queue.  In the former case, we simply need to
	 * calculate the span from beginning to end and sync it.  In the latter
	 * case, however, we need to calculate the span from the top of the
	 * work queue to the end of the chain and sync that, and then we need
	 * to find the other portion (from beginning of chain to end of queue)
	 * and sync that as well.  Note: if the "top to end" span is actually
	 * zero length, then we don't do a DMA sync because a zero length DMA
	 * sync unnecessarily syncs the entire work queue.
	 */
	if (wqe_to > wqe_from) {
		/* "From Beginning to End" */
		offset = (off_t)((uintptr_t)wqe_from - (uintptr_t)wqe_base);
		length = (size_t)((uintptr_t)wqe_to - (uintptr_t)wqe_from);

		status = ddi_dma_sync(dmahdl, offset, length, flag);
		if (status != DDI_SUCCESS) {
			return;
		}
	} else {
		/* "From Top to End" */
		offset = (off_t)0;
		length = (size_t)((uintptr_t)wqe_to - (uintptr_t)wqe_base);
		if (length) {
			status = ddi_dma_sync(dmahdl, offset, length, flag);
			if (status != DDI_SUCCESS) {
				return;
			}
		}

		/* "From Beginning to Bottom" */
		offset = (off_t)((uintptr_t)wqe_from - (uintptr_t)wqe_base);
		length = (size_t)((uintptr_t)wqe_top - (uintptr_t)wqe_from);
		status = ddi_dma_sync(dmahdl, offset, length, flag);
		if (status != DDI_SUCCESS) {
			return;
		}
	}
}


/*
 * tavor_wr_bind_check()
 *    Context: Can be called from interrupt or base context.
 */
static int
tavor_wr_bind_check(tavor_state_t *state, ibt_send_wr_t *wr)
{
	ibt_bind_flags_t	bind_flags;
	uint64_t		vaddr, len;
	uint64_t		reg_start_addr, reg_end_addr;
	tavor_mwhdl_t		mw;
	tavor_mrhdl_t		mr;
	tavor_rsrc_t		*mpt;
	uint32_t		new_rkey;

	/* Check for a valid Memory Window handle in the WR */
	mw = (tavor_mwhdl_t)wr->wr.rc.rcwr.bind->bind_ibt_mw_hdl;
	if (mw == NULL) {
		return (IBT_MW_HDL_INVALID);
	}

	/* Check for a valid Memory Region handle in the WR */
	mr = (tavor_mrhdl_t)wr->wr.rc.rcwr.bind->bind_ibt_mr_hdl;
	if (mr == NULL) {
		return (IBT_MR_HDL_INVALID);
	}

	mutex_enter(&mr->mr_lock);
	mutex_enter(&mw->mr_lock);

	/*
	 * Check here to see if the memory region has already been partially
	 * deregistered as a result of a tavor_umap_umemlock_cb() callback.
	 * If so, this is an error, return failure.
	 */
	if ((mr->mr_is_umem) && (mr->mr_umemcookie == NULL)) {
		mutex_exit(&mr->mr_lock);
		mutex_exit(&mw->mr_lock);
		return (IBT_MR_HDL_INVALID);
	}

	/* Check for a valid Memory Window RKey (i.e. a matching RKey) */
	if (mw->mr_rkey != wr->wr.rc.rcwr.bind->bind_rkey) {
		mutex_exit(&mr->mr_lock);
		mutex_exit(&mw->mr_lock);
		return (IBT_MR_RKEY_INVALID);
	}

	/* Check for a valid Memory Region LKey (i.e. a matching LKey) */
	if (mr->mr_lkey != wr->wr.rc.rcwr.bind->bind_lkey) {
		mutex_exit(&mr->mr_lock);
		mutex_exit(&mw->mr_lock);
		return (IBT_MR_LKEY_INVALID);
	}

	/*
	 * Now check for valid "vaddr" and "len".  Note:  We don't check the
	 * "vaddr" range when "len == 0" (i.e. on unbind operations)
	 */
	len = wr->wr.rc.rcwr.bind->bind_len;
	if (len != 0) {
		vaddr = wr->wr.rc.rcwr.bind->bind_va;
		reg_start_addr = mr->mr_bindinfo.bi_addr;
		reg_end_addr   = mr->mr_bindinfo.bi_addr +
		    (mr->mr_bindinfo.bi_len - 1);
		if ((vaddr < reg_start_addr) || (vaddr > reg_end_addr)) {
			mutex_exit(&mr->mr_lock);
			mutex_exit(&mw->mr_lock);
			return (IBT_MR_VA_INVALID);
		}
		vaddr = (vaddr + len) - 1;
		if (vaddr > reg_end_addr) {
			mutex_exit(&mr->mr_lock);
			mutex_exit(&mw->mr_lock);
			return (IBT_MR_LEN_INVALID);
		}
	}

	/*
	 * Validate the bind access flags.  Remote Write and Atomic access for
	 * the Memory Window require that Local Write access be set in the
	 * corresponding Memory Region.
	 */
	bind_flags = wr->wr.rc.rcwr.bind->bind_flags;
	if (((bind_flags & IBT_WR_BIND_WRITE) ||
	    (bind_flags & IBT_WR_BIND_ATOMIC)) &&
	    !(mr->mr_accflag & IBT_MR_LOCAL_WRITE)) {
		mutex_exit(&mr->mr_lock);
		mutex_exit(&mw->mr_lock);
		return (IBT_MR_ACCESS_REQ_INVALID);
	}

	/* Calculate the new RKey for the Memory Window */
	mpt = mw->mr_mptrsrcp;
	tavor_mr_keycalc(state, mpt->tr_indx, &new_rkey);

	wr->wr.rc.rcwr.bind->bind_rkey_out = new_rkey;
	mw->mr_rkey = new_rkey;

	mutex_exit(&mr->mr_lock);
	mutex_exit(&mw->mr_lock);
	return (DDI_SUCCESS);
}


/*
 * tavor_wrid_from_reset_handling()
 *    Context: Can be called from interrupt or base context.
 */
int
tavor_wrid_from_reset_handling(tavor_state_t *state, tavor_qphdl_t qp)
{
	tavor_workq_hdr_t	*swq, *rwq;
	tavor_wrid_list_hdr_t	*s_wridlist, *r_wridlist;
	uint_t			create_new_swq = 0, create_new_rwq = 0;
	uint_t			create_wql = 0;
	uint_t			qp_srq_en;

	/*
	 * For each of this QP's Work Queues, make sure we have a (properly
	 * initialized) Work Request ID list attached to the relevant
	 * completion queue.  Grab the CQ lock(s) before manipulating the
	 * lists.
	 */
	tavor_wrid_wqhdr_lock_both(qp);
	swq = tavor_wrid_wqhdr_find(qp->qp_sq_cqhdl, qp->qp_qpnum,
	    TAVOR_WR_SEND);
	if (swq == NULL) {
		/* Couldn't find matching work queue header, create it */
		create_new_swq = create_wql = 1;
		swq = tavor_wrid_wqhdr_create(state, qp->qp_sq_cqhdl,
		    qp->qp_qpnum, TAVOR_WR_SEND, create_wql);
		if (swq == NULL) {
			/*
			 * If we couldn't find/allocate space for the workq
			 * header, then drop the lock(s) and return failure.
			 */
			tavor_wrid_wqhdr_unlock_both(qp);
			return (ibc_get_ci_failure(0));
		}
	}
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*swq))
	qp->qp_sq_wqhdr = swq;
	swq->wq_size = qp->qp_sq_bufsz;
	swq->wq_head = 0;
	swq->wq_tail = 0;
	swq->wq_full = 0;

	/*
	 * Allocate space for the tavor_wrid_entry_t container
	 */
	s_wridlist = tavor_wrid_get_list(swq->wq_size);
	if (s_wridlist == NULL) {
		/*
		 * If we couldn't allocate space for tracking the WRID
		 * entries, then cleanup the workq header from above (if
		 * necessary, i.e. if we created the workq header).  Then
		 * drop the lock(s) and return failure.
		 */
		if (create_new_swq) {
			tavor_cq_wqhdr_remove(qp->qp_sq_cqhdl, swq);
		}

		tavor_wrid_wqhdr_unlock_both(qp);
		return (ibc_get_ci_failure(0));
	}
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*s_wridlist))
	s_wridlist->wl_wqhdr = swq;

	/* Chain the new WRID list container to the workq hdr list */
	mutex_enter(&swq->wq_wrid_wql->wql_lock);
	tavor_wrid_wqhdr_add(swq, s_wridlist);
	mutex_exit(&swq->wq_wrid_wql->wql_lock);

	qp_srq_en = qp->qp_srq_en;

#ifdef __lock_lint
	mutex_enter(&qp->qp_srqhdl->srq_lock);
#else
	if (qp_srq_en == TAVOR_QP_SRQ_ENABLED) {
		mutex_enter(&qp->qp_srqhdl->srq_lock);
	}
#endif
	/*
	 * Now we repeat all the above operations for the receive work queue,
	 * or shared receive work queue.
	 *
	 * Note: We still use the 'qp_rq_cqhdl' even in the SRQ case.
	 */
	rwq = tavor_wrid_wqhdr_find(qp->qp_rq_cqhdl, qp->qp_qpnum,
	    TAVOR_WR_RECV);
	if (rwq == NULL) {
		create_new_rwq = create_wql = 1;

		/*
		 * If this QP is associated with an SRQ, and this isn't the
		 * first QP on the SRQ, then the 'srq_wrid_wql' will already be
		 * created.  Since the WQL is created at 'wqhdr_create' time we
		 * pass in the flag 'create_wql' here to be 0 if we have
		 * already created it.  And later on below we then next setup
		 * the WQL and rwq information based off the existing SRQ info.
		 */
		if (qp_srq_en == TAVOR_QP_SRQ_ENABLED &&
		    qp->qp_srqhdl->srq_wrid_wql != NULL) {
			create_wql = 0;
		}

		rwq = tavor_wrid_wqhdr_create(state, qp->qp_rq_cqhdl,
		    qp->qp_qpnum, TAVOR_WR_RECV, create_wql);
		if (rwq == NULL) {
			/*
			 * If we couldn't find/allocate space for the workq
			 * header, then free all the send queue resources we
			 * just allocated and setup (above), drop the lock(s)
			 * and return failure.
			 */
			mutex_enter(&swq->wq_wrid_wql->wql_lock);
			tavor_wrid_wqhdr_remove(swq, s_wridlist);
			mutex_exit(&swq->wq_wrid_wql->wql_lock);
			if (create_new_swq) {
				tavor_cq_wqhdr_remove(qp->qp_sq_cqhdl,
				    swq);
			}

#ifdef __lock_lint
			mutex_exit(&qp->qp_srqhdl->srq_lock);
#else
			if (qp_srq_en == TAVOR_QP_SRQ_ENABLED) {
				mutex_exit(&qp->qp_srqhdl->srq_lock);
			}
#endif

			tavor_wrid_wqhdr_unlock_both(qp);
			return (ibc_get_ci_failure(0));
		}
	}
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*rwq))

	/*
	 * Setup receive workq hdr
	 *
	 * If the QP is on an SRQ, we setup the SRQ specific fields, setting
	 * keeping a copy of the rwq pointer, setting the rwq bufsize
	 * appropriately, and initializing our part of the WQLock.
	 *
	 * In the normal QP case, the QP recv queue bufsize is used.
	 */
	if (qp_srq_en == TAVOR_QP_SRQ_ENABLED) {
		rwq->wq_size = qp->qp_srqhdl->srq_wq_bufsz;
		if (qp->qp_srqhdl->srq_wrid_wql == NULL) {
			qp->qp_srqhdl->srq_wrid_wql = rwq->wq_wrid_wql;
		} else {
			rwq->wq_wrid_wql = qp->qp_srqhdl->srq_wrid_wql;
		}
		tavor_wql_refcnt_inc(qp->qp_srqhdl->srq_wrid_wql);

	} else {
		rwq->wq_size = qp->qp_rq_bufsz;
	}

	qp->qp_rq_wqhdr = rwq;
	rwq->wq_head = 0;
	rwq->wq_tail = 0;
	rwq->wq_full = 0;

	/*
	 * Allocate space for the tavor_wrid_entry_t container.
	 *
	 * If QP is on an SRQ, and the wrq_wridlist is NULL then we must
	 * allocate the wridlist normally.  However, if the srq_wridlist is !=
	 * NULL, then we know this SRQ has already been initialized, thus the
	 * wridlist has already been initialized.  So we re-use the
	 * srq_wridlist as the r_wridlist for this QP in this case.
	 */
	if (qp_srq_en == TAVOR_QP_SRQ_ENABLED &&
	    qp->qp_srqhdl->srq_wridlist != NULL) {
		/* Use existing srq_wridlist pointer */
		r_wridlist = qp->qp_srqhdl->srq_wridlist;
		ASSERT(r_wridlist != NULL);
	} else {
		/* Allocate memory for the r_wridlist */
		r_wridlist = tavor_wrid_get_list(rwq->wq_size);
	}

	/*
	 * If the memory allocation failed for r_wridlist (or the SRQ pointer
	 * is mistakenly NULL), we cleanup our previous swq allocation from
	 * above
	 */
	if (r_wridlist == NULL) {
		/*
		 * If we couldn't allocate space for tracking the WRID
		 * entries, then cleanup all the stuff from above.  Then
		 * drop the lock(s) and return failure.
		 */
		mutex_enter(&swq->wq_wrid_wql->wql_lock);
		tavor_wrid_wqhdr_remove(swq, s_wridlist);
		mutex_exit(&swq->wq_wrid_wql->wql_lock);
		if (create_new_swq) {
			tavor_cq_wqhdr_remove(qp->qp_sq_cqhdl, swq);
		}
		if (create_new_rwq) {
			tavor_cq_wqhdr_remove(qp->qp_rq_cqhdl, rwq);
		}

#ifdef __lock_lint
		mutex_exit(&qp->qp_srqhdl->srq_lock);
#else
		if (qp_srq_en == TAVOR_QP_SRQ_ENABLED) {
			mutex_exit(&qp->qp_srqhdl->srq_lock);
		}
#endif

		tavor_wrid_wqhdr_unlock_both(qp);
		return (ibc_get_ci_failure(0));
	}
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*r_wridlist))

	/*
	 * Initialize the wridlist
	 *
	 * In the normal QP case, there is no special initialization needed.
	 * We simply setup the wridlist backpointer to be the receive wqhdr
	 * (rwq).
	 *
	 * But in the SRQ case, there is no backpointer to the wqhdr possible.
	 * Instead we set 'wl_srq_en', specifying this wridlist is on an SRQ
	 * and thus potentially shared across multiple QPs with the SRQ.  We
	 * also setup the srq_wridlist pointer to be the r_wridlist, and
	 * intialize the freelist to an invalid index.  This srq_wridlist
	 * pointer is used above on future moves from_reset to let us know that
	 * the srq_wridlist has been initialized already.
	 *
	 * And finally, if we are in a non-UMAP case, we setup the srq wrid
	 * free list.
	 */
	if (qp_srq_en == TAVOR_QP_SRQ_ENABLED &&
	    qp->qp_srqhdl->srq_wridlist == NULL) {
		r_wridlist->wl_srq_en = 1;
		r_wridlist->wl_free_list_indx = -1;
		qp->qp_srqhdl->srq_wridlist = r_wridlist;

		/* Initialize srq wrid free list */
		if (qp->qp_srqhdl->srq_is_umap == 0) {
			mutex_enter(&rwq->wq_wrid_wql->wql_lock);
			tavor_wrid_list_srq_init(r_wridlist, qp->qp_srqhdl, 0);
			mutex_exit(&rwq->wq_wrid_wql->wql_lock);
		}
	} else {
		r_wridlist->wl_wqhdr = rwq;
	}

	/* Chain the WRID list "container" to the workq hdr list */
	mutex_enter(&rwq->wq_wrid_wql->wql_lock);
	tavor_wrid_wqhdr_add(rwq, r_wridlist);
	mutex_exit(&rwq->wq_wrid_wql->wql_lock);

#ifdef __lock_lint
	mutex_exit(&qp->qp_srqhdl->srq_lock);
#else
	if (qp_srq_en == TAVOR_QP_SRQ_ENABLED) {
		mutex_exit(&qp->qp_srqhdl->srq_lock);
	}
#endif

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*r_wridlist))
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*rwq))
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*s_wridlist))
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*swq))

	tavor_wrid_wqhdr_unlock_both(qp);
	return (DDI_SUCCESS);
}


/*
 * tavor_wrid_to_reset_handling()
 *    Context: Can be called from interrupt or base context.
 */
void
tavor_wrid_to_reset_handling(tavor_state_t *state, tavor_qphdl_t qp)
{
	uint_t		free_wqhdr = 0;

	/*
	 * For each of this QP's Work Queues, move the WRID "container" to
	 * the "reapable" list.  Although there may still be unpolled
	 * entries in these containers, it is not a big deal.  We will not
	 * reap the list until either the Poll CQ command detects an empty
	 * condition or the CQ itself is freed.  Grab the CQ lock(s) before
	 * manipulating the lists.
	 */
	mutex_enter(&qp->qp_rq_cqhdl->cq_lock);
	tavor_wrid_wqhdr_lock_both(qp);
	tavor_wrid_reaplist_add(qp->qp_sq_cqhdl, qp->qp_sq_wqhdr);

	/*
	 * Add the receive work queue header on to the reaplist.  But if we are
	 * on SRQ, then don't add anything to the reaplist.  Instead we flush
	 * the SRQ entries on the CQ, remove wridlist from WQHDR, and free the
	 * WQHDR (if needed).  We must hold the WQL for these operations, yet
	 * the call to tavor_cq_wqhdr_remove grabs the WQL internally.  So we
	 * drop WQL before that call.  Then release the CQ WQHDR locks and the
	 * CQ lock and return.
	 */
	if (qp->qp_srq_en == TAVOR_QP_SRQ_ENABLED) {

		/*
		 * Pull off all (if any) entries for this QP from CQ.  This
		 * only includes entries that have not yet been polled
		 */
		mutex_enter(&qp->qp_rq_wqhdr->wq_wrid_wql->wql_lock);
		tavor_cq_srq_entries_flush(state, qp);

		/* Remove wridlist from WQHDR */
		tavor_wrid_wqhdr_remove(qp->qp_rq_wqhdr,
		    qp->qp_rq_wqhdr->wq_wrid_post);

		/* If wridlist chain is now empty, remove the wqhdr as well */
		if (qp->qp_rq_wqhdr->wq_wrid_post == NULL) {
			free_wqhdr = 1;
		} else {
			free_wqhdr = 0;
		}

		mutex_exit(&qp->qp_rq_wqhdr->wq_wrid_wql->wql_lock);

		/* Free the WQHDR */
		if (free_wqhdr) {
			tavor_cq_wqhdr_remove(qp->qp_rq_cqhdl, qp->qp_rq_wqhdr);
		}
	} else {
		tavor_wrid_reaplist_add(qp->qp_rq_cqhdl, qp->qp_rq_wqhdr);
	}
	tavor_wrid_wqhdr_unlock_both(qp);
	mutex_exit(&qp->qp_rq_cqhdl->cq_lock);
}


/*
 * tavor_wrid_add_entry()
 *    Context: Can be called from interrupt or base context.
 */
void
tavor_wrid_add_entry(tavor_workq_hdr_t *wq, uint64_t wrid, uint32_t wqeaddrsz,
    uint_t signaled_dbd)
{
	tavor_wrid_entry_t	*wre_tmp;
	uint32_t		head, tail, size;

	ASSERT(MUTEX_HELD(&wq->wq_wrid_wql->wql_lock));

	/*
	 * Find the entry in the container pointed to by the "tail" index.
	 * Add all of the relevant information to that entry, including WRID,
	 * "wqeaddrsz" parameter, and whether it was signaled/unsignaled
	 * and/or doorbelled.
	 */
	head = wq->wq_wrid_post->wl_head;
	tail = wq->wq_wrid_post->wl_tail;
	size = wq->wq_wrid_post->wl_size;
	wre_tmp = &wq->wq_wrid_post->wl_wre[tail];
	wre_tmp->wr_wrid	  = wrid;
	wre_tmp->wr_wqeaddrsz	  = wqeaddrsz;
	wre_tmp->wr_signaled_dbd  = signaled_dbd;

	/*
	 * Update the "wrid_old_tail" pointer to point to the entry we just
	 * inserted into the queue.  By tracking this pointer (the pointer to
	 * the most recently inserted entry) it will possible later in the
	 * PostSend() and PostRecv() code paths to find the entry that needs
	 * its "doorbelled" flag set (see comment in tavor_post_recv() and/or
	 * tavor_post_send()).
	 */
	wq->wq_wrid_post->wl_wre_old_tail = wre_tmp;

	/* Update the tail index */
	tail = ((tail + 1) & (size - 1));
	wq->wq_wrid_post->wl_tail = tail;

	/*
	 * If the "tail" index has just wrapped over into the "head" index,
	 * then we have filled the container.  We use the "full" flag to
	 * indicate this condition and to distinguish it from the "empty"
	 * condition (where head and tail are also equal).
	 */
	if (head == tail) {
		wq->wq_wrid_post->wl_full = 1;
	}
}

/*
 * tavor_wrid_add_entry_srq()
 * Context: Can be called from interrupt or base context
 */
void
tavor_wrid_add_entry_srq(tavor_srqhdl_t srq, uint64_t wrid, uint_t signaled_dbd)
{
	tavor_wrid_entry_t	*wre;
	uint64_t		*wl_wqe;
	uint32_t		wqe_index;

	/*
	 * Find the next available WQE from the SRQ free_list.  Then update the
	 * free_list to point to the next entry
	 */
	wl_wqe = TAVOR_SRQ_WQE_ADDR(srq, srq->srq_wridlist->wl_free_list_indx);

	wqe_index = srq->srq_wridlist->wl_free_list_indx;

	/* ASSERT on impossible wqe_index values */
	ASSERT(wqe_index < srq->srq_wq_bufsz);

	/*
	 * Setup the WRE.
	 *
	 * Given the 'wqe_index' value, we store the WRID at this WRE offset.
	 * And we set the WRE to be signaled_dbd so that on poll CQ we can find
	 * this information and associate the WRID to the WQE found on the CQE.
	 */
	wre = &srq->srq_wridlist->wl_wre[wqe_index];
	wre->wr_wrid = wrid;
	wre->wr_signaled_dbd  = signaled_dbd;

	/* Update the free list index */
	srq->srq_wridlist->wl_free_list_indx = ddi_get32(
	    srq->srq_wridlist->wl_acchdl, (uint32_t *)wl_wqe);
}


/*
 * tavor_wrid_get_entry()
 *    Context: Can be called from interrupt or base context.
 */
uint64_t
tavor_wrid_get_entry(tavor_cqhdl_t cq, tavor_hw_cqe_t *cqe,
    tavor_wrid_entry_t *wre)
{
	tavor_workq_hdr_t	*wq;
	tavor_wrid_entry_t	*wre_tmp;
	uint64_t		wrid;
	uint_t			send_or_recv, qpnum, error, opcode;

	/* Lock the list of work queues associated with this CQ */
	mutex_enter(&cq->cq_wrid_wqhdr_lock);

	/*
	 * Determine whether this CQE is a send or receive completion (and
	 * whether it was a "successful" completion or not)
	 */
	opcode = TAVOR_CQE_OPCODE_GET(cq, cqe);
	if ((opcode == TAVOR_CQE_SEND_ERR_OPCODE) ||
	    (opcode == TAVOR_CQE_RECV_ERR_OPCODE)) {
		error = 1;
		send_or_recv = (opcode == TAVOR_CQE_SEND_ERR_OPCODE) ?
		    TAVOR_COMPLETION_SEND : TAVOR_COMPLETION_RECV;
	} else {
		error = 0;
		send_or_recv = TAVOR_CQE_SENDRECV_GET(cq, cqe);
	}

	/* Find the work queue for this QP number (send or receive side) */
	qpnum = TAVOR_CQE_QPNUM_GET(cq, cqe);
	wq = tavor_wrid_wqhdr_find(cq, qpnum, send_or_recv);
	ASSERT(wq != NULL);

	/*
	 * Regardless of whether the completion is the result of a "success"
	 * or a "failure", we lock the list of "containers" and attempt to
	 * search for the the first matching completion (i.e. the first WR
	 * with a matching WQE addr and size).  Once we find it, we pull out
	 * the "wrid" field and return it (see below).  Note: One possible
	 * future enhancement would be to enable this routine to skip over
	 * any "unsignaled" completions to go directly to the next "signaled"
	 * entry on success. XXX
	 */
	mutex_enter(&wq->wq_wrid_wql->wql_lock);
	wre_tmp = tavor_wrid_find_match(wq, cq, cqe);

	/*
	 * If this is a "successful" completion, then we assert that this
	 * completion must be a "signaled" completion.
	 */
	ASSERT(error || (wre_tmp->wr_signaled_dbd & TAVOR_WRID_ENTRY_SIGNALED));

	/*
	 * If the completion is a "failed" completion, then we save away the
	 * contents of the entry (into the "wre" field passed in) for use
	 * in later CQE processing. Note: We use the tavor_wrid_get_wqeaddrsz()
	 * function to grab "wqeaddrsz" from the next entry in the container.
	 * This is required for error processing (where updating these fields
	 * properly is necessary to correct handling of the "error" CQE)
	 */
	if (error && (wre != NULL)) {
		*wre = *wre_tmp;
		wre->wr_wqeaddrsz = tavor_wrid_get_wqeaddrsz(wq);
	}

	/* Pull out the WRID and return it */
	wrid = wre_tmp->wr_wrid;

	mutex_exit(&wq->wq_wrid_wql->wql_lock);
	mutex_exit(&cq->cq_wrid_wqhdr_lock);

	return (wrid);
}


/*
 * tavor_wrid_find_match()
 *    Context: Can be called from interrupt or base context.
 */
static tavor_wrid_entry_t *
tavor_wrid_find_match(tavor_workq_hdr_t *wq, tavor_cqhdl_t cq,
    tavor_hw_cqe_t *cqe)
{
	tavor_wrid_entry_t	*curr = NULL;
	tavor_wrid_list_hdr_t	*container;
	uint32_t		wqeaddr_size;
	uint32_t		head, tail, size;
	int			found = 0, last_container;

	ASSERT(MUTEX_HELD(&wq->wq_wrid_wql->wql_lock));

	/* Pull the "wqeaddrsz" information from the CQE */
	wqeaddr_size = TAVOR_CQE_WQEADDRSZ_GET(cq, cqe);

	/*
	 * Walk the "containers" list(s), find first WR with a matching WQE
	 * addr.  If the current "container" is not the last one on the list,
	 * i.e. not the current one to which we are posting new WRID entries,
	 * then we do not attempt to update the "q_head", "q_tail", and
	 * "q_full" indicators on the main work queue header.  We do, however,
	 * update the "head" and "full" indicators on the individual containers
	 * as we go.  This is imperative because we need to be able to
	 * determine when the current container has been emptied (so that we
	 * can move on to the next container).
	 */
	container = wq->wq_wrid_poll;
	while (container != NULL) {
		/* Is this the last/only "container" on the list */
		last_container = (container != wq->wq_wrid_post) ? 0 : 1;

		/*
		 * First check if we are on an SRQ.  If so, we grab the entry
		 * and break out.  Since SRQ wridlist's are never added to
		 * reaplist, they can only be the last container.
		 */
		if (container->wl_srq_en) {
			ASSERT(last_container == 1);
			curr = tavor_wrid_find_match_srq(container, cq, cqe);
			break;
		}

		/*
		 * Grab the current "head", "tail" and "size" fields before
		 * walking the list in the current container. Note: the "size"
		 * field here must always be a power-of-2.  The "full"
		 * parameter is checked (and updated) here to distinguish the
		 * "queue full" condition from "queue empty".
		 */
		head = container->wl_head;
		tail = container->wl_tail;
		size = container->wl_size;
		while ((head != tail) || (container->wl_full)) {
			container->wl_full = 0;
			curr = &container->wl_wre[head];
			head = ((head + 1) & (size - 1));

			/*
			 * If the current entry's "wqeaddrsz" matches the one
			 * we're searching for, then this must correspond to
			 * the work request that caused the completion.  Set
			 * the "found" flag and bail out.
			 */
			if (curr->wr_wqeaddrsz == wqeaddr_size) {
				found = 1;
				break;
			}
		}

		/*
		 * If the current container is empty (having reached here the
		 * "head == tail" condition can only mean that the container
		 * is empty), then NULL out the "wrid_old_tail" field (see
		 * tavor_post_send() and tavor_post_recv() for more details)
		 * and (potentially) remove the current container from future
		 * searches.
		 */
		if (head == tail) {

			container->wl_wre_old_tail = NULL;
			/*
			 * If this wasn't the last "container" on the chain,
			 * i.e. the one to which new WRID entries will be
			 * added, then remove it from the list.
			 * Note: we don't "lose" the memory pointed to by this
			 * because we should have already put this container
			 * on the "reapable" list (from where it will later be
			 * pulled).
			 */
			if (!last_container) {
				wq->wq_wrid_poll = container->wl_next;
			}
		}

		/* Update the head index for the container */
		container->wl_head = head;

		/*
		 * If the entry was found in this container, then continue to
		 * bail out.  Else reset the "curr" pointer and move on to the
		 * next container (if there is one).  Note: the only real
		 * reason for setting "curr = NULL" here is so that the ASSERT
		 * below can catch the case where no matching entry was found
		 * on any of the lists.
		 */
		if (found) {
			break;
		} else {
			curr = NULL;
			container = container->wl_next;
		}
	}

	/*
	 * Update work queue header's "head" and "full" conditions to match
	 * the last entry on the container list.  (Note: Only if we're pulling
	 * entries from the last work queue portion of the list, i.e. not from
	 * the previous portions that may be the "reapable" list.)
	 */
	if (last_container) {
		wq->wq_head = wq->wq_wrid_post->wl_head;
		wq->wq_full = wq->wq_wrid_post->wl_full;
	}

	/* Ensure that we've actually found what we were searching for */
	ASSERT(curr != NULL);

	return (curr);
}


/*
 * tavor_wrid_find_match_srq()
 *    Context: Can be called from interrupt or base context.
 */
tavor_wrid_entry_t *
tavor_wrid_find_match_srq(tavor_wrid_list_hdr_t *wl, tavor_cqhdl_t cq,
    tavor_hw_cqe_t *cqe)
{
	tavor_wrid_entry_t	*wre;
	uint64_t		*wl_wqe;
	uint32_t		wqe_index;
	uint64_t		wqe_addr;
	uint32_t		cqe_wqe_addr;

	/* Grab the WQE addr out of the CQE */
	cqe_wqe_addr = TAVOR_CQE_WQEADDRSZ_GET(cq, cqe) & 0xFFFFFFC0;

	/*
	 * Use the WQE addr as the lower 32-bit, we add back on the
	 * 'wl_srq_desc_off' because we have a zero-based queue.  Then the
	 * upper 32-bit of the 'wl_srq_wq_buf' OR'd on gives us the WQE addr in
	 * the SRQ Work Queue itself.  We use this address as the index to find
	 * out which Work Queue Entry this CQE corresponds with.
	 *
	 * We also use this address below to add the WQE back on to the free
	 * list.
	 */
	wqe_addr = ((uintptr_t)wl->wl_srq_wq_buf & 0xFFFFFFFF00000000ull) |
	    (cqe_wqe_addr + wl->wl_srq_desc_off);

	/*
	 * Given the 'wqe_addr' just calculated and the srq buf address, we
	 * find the 'wqe_index'.  The 'wre' returned below contains the WRID
	 * that we are looking for.  This indexes into the wre_list for this
	 * specific WQE.
	 */
	wqe_index = TAVOR_SRQ_WQE_INDEX(wl->wl_srq_wq_buf, wqe_addr,
	    wl->wl_srq_log_wqesz);

	/* ASSERT on impossible wqe_index values */
	ASSERT(wqe_index < wl->wl_srq_wq_bufsz);

	/* Get the pointer to this WQE */
	wl_wqe = (uint64_t *)(uintptr_t)wqe_addr;

	/* Put this WQE index back on the free list */
	ddi_put32(wl->wl_acchdl, (uint32_t *)wl_wqe, wl->wl_free_list_indx);
	wl->wl_free_list_indx = wqe_index;

	/* Using the index, return the Work Request ID Entry (wre) */
	wre = &wl->wl_wre[wqe_index];

	return (wre);
}


/*
 * tavor_wrid_cq_reap()
 *    Context: Can be called from interrupt or base context.
 */
void
tavor_wrid_cq_reap(tavor_cqhdl_t cq)
{
	tavor_workq_hdr_t	*consume_wqhdr;
	tavor_wrid_list_hdr_t	*container, *to_free;

	ASSERT(MUTEX_HELD(&cq->cq_lock));

	/* Lock the list of work queues associated with this CQ */
	mutex_enter(&cq->cq_wrid_wqhdr_lock);

	/* Walk the "reapable" list and free up containers */
	container = cq->cq_wrid_reap_head;
	while (container != NULL) {
		to_free	  = container;
		container = container->wl_reap_next;
		/*
		 * If reaping the WRID list containers pulls the last
		 * container from the given work queue header, then we free
		 * the work queue header as well.
		 */
		consume_wqhdr = tavor_wrid_list_reap(to_free);
		if (consume_wqhdr != NULL) {
			tavor_cq_wqhdr_remove(cq, consume_wqhdr);
		}
	}

	/* Once finished reaping, we reset the CQ's reap list */
	cq->cq_wrid_reap_head = cq->cq_wrid_reap_tail = NULL;

	mutex_exit(&cq->cq_wrid_wqhdr_lock);
}


/*
 * tavor_wrid_cq_force_reap()
 *    Context: Can be called from interrupt or base context.
 */
void
tavor_wrid_cq_force_reap(tavor_cqhdl_t cq)
{
	tavor_workq_hdr_t	*curr;
	tavor_wrid_list_hdr_t	*container, *to_free;
	avl_tree_t		*treep;
	void			*cookie = NULL;

	ASSERT(MUTEX_HELD(&cq->cq_lock));

	/*
	 * The first step is to walk the "reapable" list and free up those
	 * containers.  This is necessary because the containers on the
	 * reapable list are not otherwise connected to the work queue headers
	 * anymore.
	 */
	tavor_wrid_cq_reap(cq);

	/* Now lock the list of work queues associated with this CQ */
	mutex_enter(&cq->cq_wrid_wqhdr_lock);

	/*
	 * Walk the list of work queue headers and free up all the WRID list
	 * containers chained to it.  Note: We don't need to grab the locks
	 * for each of the individual WRID lists here because the only way
	 * things can be added or removed from the list at this point would be
	 * through post a work request to a QP.  But if we've come this far,
	 * then we can be assured that there are no longer any QP associated
	 * with the CQ that we are trying to free.
	 */
#ifdef __lock_lint
	tavor_wrid_wqhdr_compare(NULL, NULL);
#endif
	treep = &cq->cq_wrid_wqhdr_avl_tree;
	while ((curr = avl_destroy_nodes(treep, &cookie)) != NULL) {
		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*curr))
		container = curr->wq_wrid_poll;
		while (container != NULL) {
			to_free	  = container;
			container = container->wl_next;
			/*
			 * If reaping the WRID list containers pulls the last
			 * container from the given work queue header, then
			 * we free the work queue header as well.  Note: we
			 * ignore the return value because we know that the
			 * work queue header should always be freed once the
			 * list of containers has come to an end.
			 */
			(void) tavor_wrid_list_reap(to_free);
			if (container == NULL) {
				tavor_cq_wqhdr_remove(cq, curr);
			}
		}
	}
	avl_destroy(treep);

	mutex_exit(&cq->cq_wrid_wqhdr_lock);
}


/*
 * tavor_wrid_get_list()
 *    Context: Can be called from interrupt or base context.
 */
tavor_wrid_list_hdr_t *
tavor_wrid_get_list(uint32_t qsize)
{
	tavor_wrid_list_hdr_t	*wridlist;
	uint32_t		size;

	/*
	 * The WRID list "container" consists of the tavor_wrid_list_hdr_t,
	 * which holds the pointers necessary for maintaining the "reapable"
	 * list, chaining together multiple "containers" old and new, and
	 * tracking the head, tail, size, etc. for each container.
	 *
	 * The "container" also holds all the tavor_wrid_entry_t's, which is
	 * allocated separately, one for each entry on the corresponding work
	 * queue.
	 */
	size = sizeof (tavor_wrid_list_hdr_t);

	/*
	 * Note that this allocation has to be a NOSLEEP operation here
	 * because we are holding the "wqhdr_list_lock" and, therefore,
	 * could get raised to the interrupt level.
	 */
	wridlist = (tavor_wrid_list_hdr_t *)kmem_zalloc(size, KM_NOSLEEP);
	if (wridlist == NULL) {
		return (NULL);
	}
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*wridlist))

	/* Complete the "container" initialization */
	wridlist->wl_size = qsize;
	wridlist->wl_full = 0;
	wridlist->wl_head = 0;
	wridlist->wl_tail = 0;
	wridlist->wl_wre = (tavor_wrid_entry_t *)kmem_zalloc(qsize *
	    sizeof (tavor_wrid_entry_t), KM_NOSLEEP);
	if (wridlist->wl_wre == NULL) {
		kmem_free(wridlist, size);
		return (NULL);
	}
	wridlist->wl_wre_old_tail  = NULL;
	wridlist->wl_reap_next = NULL;
	wridlist->wl_next  = NULL;
	wridlist->wl_prev  = NULL;
	wridlist->wl_srq_en = 0;

	return (wridlist);
}

/*
 * tavor_wrid_list_srq_init()
 * Context: Can be called from interrupt or base context
 */
void
tavor_wrid_list_srq_init(tavor_wrid_list_hdr_t *wridlist, tavor_srqhdl_t srq,
    uint_t wq_start)
{
	uint64_t *wl_wqe;
	int wqe_index;

	ASSERT(MUTEX_HELD(&srq->srq_wrid_wql->wql_lock));

	/* Setup pointers for use later when we are polling the CQ */
	wridlist->wl_srq_wq_buf = srq->srq_wq_buf;
	wridlist->wl_srq_wq_bufsz = srq->srq_wq_bufsz;
	wridlist->wl_srq_log_wqesz = srq->srq_wq_log_wqesz;
	wridlist->wl_srq_desc_off = srq->srq_desc_off;
	wridlist->wl_acchdl = srq->srq_wqinfo.qa_acchdl;

	/* Given wq_start to start initializing buf at, verify sanity */
	ASSERT(wq_start >= 0 && wq_start < srq->srq_wq_bufsz);

	/*
	 * Initialize wridlist free list
	 *
	 * For each WQ up to the size of our queue, we store an index in the WQ
	 * memory itself, representing the next available free entry.  The
	 * 'wl_free_list_indx' always holds the index of the next available
	 * free entry in the WQ.  If 'wl_free_list_indx' is -1, then we are
	 * completely full.  This gives us the advantage of being able to have
	 * entries complete or be polled off the WQ out-of-order.
	 *
	 * For now, we write the free_list entries inside the WQ itself.  It
	 * may be useful in the future to store this information in a separate
	 * structure for debugging purposes.
	 */
	for (wqe_index = wq_start; wqe_index < srq->srq_wq_bufsz; wqe_index++) {
		wl_wqe = TAVOR_SRQ_WQE_ADDR(srq, wqe_index);
		ddi_put32(wridlist->wl_acchdl, (uint32_t *)wl_wqe,
		    wridlist->wl_free_list_indx);
		wridlist->wl_free_list_indx = wqe_index;
	}
}


/*
 * tavor_wrid_reaplist_add()
 *    Context: Can be called from interrupt or base context.
 */
static void
tavor_wrid_reaplist_add(tavor_cqhdl_t cq, tavor_workq_hdr_t *wq)
{
	ASSERT(MUTEX_HELD(&cq->cq_wrid_wqhdr_lock));

	mutex_enter(&wq->wq_wrid_wql->wql_lock);

	/*
	 * Add the "post" container (the last one on the current chain) to
	 * the CQ's "reapable" list
	 */
	if ((cq->cq_wrid_reap_head == NULL) &&
	    (cq->cq_wrid_reap_tail == NULL)) {
		cq->cq_wrid_reap_head = wq->wq_wrid_post;
		cq->cq_wrid_reap_tail = wq->wq_wrid_post;
	} else {
		cq->cq_wrid_reap_tail->wl_reap_next = wq->wq_wrid_post;
		cq->cq_wrid_reap_tail = wq->wq_wrid_post;
	}

	mutex_exit(&wq->wq_wrid_wql->wql_lock);
}


int
tavor_wrid_wqhdr_compare(const void *p1, const void *p2)
{
	tavor_workq_compare_t	*cmpp;
	tavor_workq_hdr_t	*curr;

	cmpp = (tavor_workq_compare_t *)p1;
	curr = (tavor_workq_hdr_t *)p2;

	if (cmpp->cmp_qpn < curr->wq_qpn)
		return (-1);
	else if (cmpp->cmp_qpn > curr->wq_qpn)
		return (+1);
	else if (cmpp->cmp_type < curr->wq_type)
		return (-1);
	else if (cmpp->cmp_type > curr->wq_type)
		return (+1);
	else
		return (0);
}


/*
 * tavor_wrid_wqhdr_find()
 *    Context: Can be called from interrupt or base context.
 */
static tavor_workq_hdr_t *
tavor_wrid_wqhdr_find(tavor_cqhdl_t cq, uint_t qpn, uint_t wq_type)
{
	tavor_workq_hdr_t	*curr;
	tavor_workq_compare_t	cmp;

	ASSERT(MUTEX_HELD(&cq->cq_wrid_wqhdr_lock));

	/*
	 * Walk the CQ's work queue list, trying to find a send or recv queue
	 * with the same QP number.  We do this even if we are going to later
	 * create a new entry because it helps us easily find the end of the
	 * list.
	 */
	cmp.cmp_qpn = qpn;
	cmp.cmp_type = wq_type;
#ifdef __lock_lint
	tavor_wrid_wqhdr_compare(NULL, NULL);
#endif
	curr = avl_find(&cq->cq_wrid_wqhdr_avl_tree, &cmp, NULL);

	return (curr);
}


/*
 * tavor_wrid_wqhdr_create()
 *    Context: Can be called from interrupt or base context.
 */
static tavor_workq_hdr_t *
tavor_wrid_wqhdr_create(tavor_state_t *state, tavor_cqhdl_t cq, uint_t qpn,
    uint_t wq_type, uint_t create_wql)
{
	tavor_workq_hdr_t	*wqhdr_tmp;

	ASSERT(MUTEX_HELD(&cq->cq_wrid_wqhdr_lock));

	/*
	 * Allocate space a work queue header structure and initialize it.
	 * Each work queue header structure includes a "wq_wrid_wql"
	 * which needs to be initialized.  Note that this allocation has to be
	 * a NOSLEEP operation because we are holding the "cq_wrid_wqhdr_lock"
	 * and, therefore, could get raised to the interrupt level.
	 */
	wqhdr_tmp = (tavor_workq_hdr_t *)kmem_zalloc(
	    sizeof (tavor_workq_hdr_t), KM_NOSLEEP);
	if (wqhdr_tmp == NULL) {
		return (NULL);
	}
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*wqhdr_tmp))
	wqhdr_tmp->wq_qpn	= qpn;
	wqhdr_tmp->wq_type	= wq_type;

	if (create_wql) {
		wqhdr_tmp->wq_wrid_wql = tavor_wrid_wql_create(state);
		if (wqhdr_tmp->wq_wrid_wql == NULL) {
			kmem_free(wqhdr_tmp, sizeof (tavor_workq_hdr_t));
			return (NULL);
		}
	}

	wqhdr_tmp->wq_wrid_poll = NULL;
	wqhdr_tmp->wq_wrid_post = NULL;

	/* Chain the newly allocated work queue header to the CQ's list */
	tavor_cq_wqhdr_add(cq, wqhdr_tmp);

	return (wqhdr_tmp);
}


/*
 * tavor_wrid_wql_create()
 *    Context: Can be called from interrupt or base context.
 */
tavor_wq_lock_t *
tavor_wrid_wql_create(tavor_state_t *state)
{
	tavor_wq_lock_t *wql;

	/*
	 * Allocate the WQL and initialize it.
	 */
	wql = kmem_zalloc(sizeof (tavor_wq_lock_t), KM_NOSLEEP);
	if (wql == NULL) {
		return (NULL);
	}

	mutex_init(&wql->wql_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(state->ts_intrmsi_pri));

	/* Add refcount to WQL */
	tavor_wql_refcnt_inc(wql);

	return (wql);
}


/*
 * tavor_wrid_get_wqeaddrsz()
 *    Context: Can be called from interrupt or base context.
 */
static uint32_t
tavor_wrid_get_wqeaddrsz(tavor_workq_hdr_t *wq)
{
	tavor_wrid_entry_t	*wre;
	uint32_t		wqeaddrsz;
	uint32_t		head;

	/*
	 * If the container is empty, then there is no next entry. So just
	 * return zero.  Note: the "head == tail" condition here can only
	 * mean that the container is empty because we have previously pulled
	 * something from the container.
	 *
	 * If the container is not empty, then find the next entry and return
	 * the contents of its "wqeaddrsz" field.
	 */
	if (wq->wq_wrid_poll->wl_head == wq->wq_wrid_poll->wl_tail) {
		wqeaddrsz = 0;
	} else {
		/*
		 * We don't need to calculate the "next" head pointer here
		 * because "head" should already point to the next entry on
		 * the list (since we just pulled something off - in
		 * tavor_wrid_find_match() - and moved the head index forward.)
		 */
		head = wq->wq_wrid_poll->wl_head;
		wre = &wq->wq_wrid_poll->wl_wre[head];
		wqeaddrsz = wre->wr_wqeaddrsz;
	}
	return (wqeaddrsz);
}


/*
 * tavor_wrid_wqhdr_add()
 *    Context: Can be called from interrupt or base context.
 */
static void
tavor_wrid_wqhdr_add(tavor_workq_hdr_t *wqhdr,
    tavor_wrid_list_hdr_t *wridlist)
{
	ASSERT(MUTEX_HELD(&wqhdr->wq_wrid_wql->wql_lock));

	/* Chain the new WRID list "container" to the work queue list */
	if ((wqhdr->wq_wrid_post == NULL) &&
	    (wqhdr->wq_wrid_poll == NULL)) {
		wqhdr->wq_wrid_poll = wridlist;
		wqhdr->wq_wrid_post = wridlist;
	} else {
		wqhdr->wq_wrid_post->wl_next = wridlist;
		wridlist->wl_prev = wqhdr->wq_wrid_post;
		wqhdr->wq_wrid_post = wridlist;
	}
}


/*
 * tavor_wrid_wqhdr_remove()
 *    Context: Can be called from interrupt or base context.
 *
 *    Note: this is only called to remove the most recently added WRID list
 *    container (i.e. in tavor_from_reset() above)
 */
static void
tavor_wrid_wqhdr_remove(tavor_workq_hdr_t *wqhdr,
    tavor_wrid_list_hdr_t *wridlist)
{
	tavor_wrid_list_hdr_t	*prev, *next;

	ASSERT(MUTEX_HELD(&wqhdr->wq_wrid_wql->wql_lock));

	/* Unlink the WRID list "container" from the work queue list */
	prev = wridlist->wl_prev;
	next = wridlist->wl_next;
	if (prev != NULL) {
		prev->wl_next = next;
	}
	if (next != NULL) {
		next->wl_prev = prev;
	}

	/*
	 * Update any pointers in the work queue hdr that may point to this
	 * WRID list container
	 */
	if (wqhdr->wq_wrid_post == wridlist) {
		wqhdr->wq_wrid_post = prev;
	}
	if (wqhdr->wq_wrid_poll == wridlist) {
		wqhdr->wq_wrid_poll = NULL;
	}
}


/*
 * tavor_wrid_list_reap()
 *    Context: Can be called from interrupt or base context.
 *    Note: The "wqhdr_list_lock" must be held.
 */
static tavor_workq_hdr_t *
tavor_wrid_list_reap(tavor_wrid_list_hdr_t *wridlist)
{
	tavor_workq_hdr_t	*wqhdr, *consume_wqhdr = NULL;
	tavor_wrid_list_hdr_t	*prev, *next;
	uint32_t		size;

	/* Get the back pointer to the work queue header (see below) */
	wqhdr = wridlist->wl_wqhdr;
	mutex_enter(&wqhdr->wq_wrid_wql->wql_lock);

	/* Unlink the WRID list "container" from the work queue list */
	prev = wridlist->wl_prev;
	next = wridlist->wl_next;
	if (prev != NULL) {
		prev->wl_next = next;
	}
	if (next != NULL) {
		next->wl_prev = prev;
	}

	/*
	 * If the back pointer to the work queue header shows that it
	 * was pointing to the entry we are about to remove, then the work
	 * queue header is reapable as well.
	 */
	if ((wqhdr->wq_wrid_poll == wridlist) &&
	    (wqhdr->wq_wrid_post == wridlist)) {
		consume_wqhdr = wqhdr;
	}

	/* Be sure to update the "poll" and "post" container pointers */
	if (wqhdr->wq_wrid_poll == wridlist) {
		wqhdr->wq_wrid_poll = next;
	}
	if (wqhdr->wq_wrid_post == wridlist) {
		wqhdr->wq_wrid_post = NULL;
	}

	/* Calculate the size and free the container */
	size = (wridlist->wl_size * sizeof (tavor_wrid_entry_t));
	kmem_free(wridlist->wl_wre, size);
	kmem_free(wridlist, sizeof (tavor_wrid_list_hdr_t));

	mutex_exit(&wqhdr->wq_wrid_wql->wql_lock);

	return (consume_wqhdr);
}


/*
 * tavor_wrid_wqhdr_lock_both()
 *    Context: Can be called from interrupt or base context.
 */
static void
tavor_wrid_wqhdr_lock_both(tavor_qphdl_t qp)
{
	tavor_cqhdl_t	sq_cq, rq_cq;

	sq_cq = qp->qp_sq_cqhdl;
	rq_cq = qp->qp_rq_cqhdl;

_NOTE(MUTEX_ACQUIRED_AS_SIDE_EFFECT(&sq_cq->cq_wrid_wqhdr_lock))
_NOTE(MUTEX_ACQUIRED_AS_SIDE_EFFECT(&rq_cq->cq_wrid_wqhdr_lock))

	/*
	 * If both work queues (send and recv) share a completion queue, then
	 * grab the common lock.  If they use different CQs (hence different
	 * "cq_wrid_wqhdr_list" locks), then grab the send one first, then the
	 * receive.  We do this consistently and correctly in
	 * tavor_wrid_wqhdr_unlock_both() below to avoid introducing any kind
	 * of dead lock condition.  Note:  We add the "__lock_lint" code here
	 * to fake out warlock into thinking we've grabbed both locks (when,
	 * in fact, we only needed the one).
	 */
	if (sq_cq == rq_cq) {
		mutex_enter(&sq_cq->cq_wrid_wqhdr_lock);
#ifdef	__lock_lint
		mutex_enter(&rq_cq->cq_wrid_wqhdr_lock);
#endif
	} else {
		mutex_enter(&sq_cq->cq_wrid_wqhdr_lock);
		mutex_enter(&rq_cq->cq_wrid_wqhdr_lock);
	}
}

/*
 * tavor_wrid_wqhdr_unlock_both()
 *    Context: Can be called from interrupt or base context.
 */
static void
tavor_wrid_wqhdr_unlock_both(tavor_qphdl_t qp)
{
	tavor_cqhdl_t	sq_cq, rq_cq;

	sq_cq = qp->qp_sq_cqhdl;
	rq_cq = qp->qp_rq_cqhdl;

_NOTE(LOCK_RELEASED_AS_SIDE_EFFECT(&rq_cq->cq_wrid_wqhdr_lock))
_NOTE(LOCK_RELEASED_AS_SIDE_EFFECT(&sq_cq->cq_wrid_wqhdr_lock))

	/*
	 * See tavor_wrid_wqhdr_lock_both() above for more detail
	 */
	if (sq_cq == rq_cq) {
#ifdef	__lock_lint
		mutex_exit(&rq_cq->cq_wrid_wqhdr_lock);
#endif
		mutex_exit(&sq_cq->cq_wrid_wqhdr_lock);
	} else {
		mutex_exit(&rq_cq->cq_wrid_wqhdr_lock);
		mutex_exit(&sq_cq->cq_wrid_wqhdr_lock);
	}
}


/*
 * tavor_cq_wqhdr_add()
 *    Context: Can be called from interrupt or base context.
 */
static void
tavor_cq_wqhdr_add(tavor_cqhdl_t cq, tavor_workq_hdr_t *wqhdr)
{
	tavor_workq_compare_t	cmp;
	avl_index_t		where;

	ASSERT(MUTEX_HELD(&cq->cq_wrid_wqhdr_lock));

	cmp.cmp_qpn = wqhdr->wq_qpn;
	cmp.cmp_type = wqhdr->wq_type;
#ifdef __lock_lint
	tavor_wrid_wqhdr_compare(NULL, NULL);
#endif
	(void) avl_find(&cq->cq_wrid_wqhdr_avl_tree, &cmp, &where);
	/*
	 * If the CQ's work queue list is empty, then just add it.
	 * Otherwise, chain it to the beginning of the list.
	 */
	avl_insert(&cq->cq_wrid_wqhdr_avl_tree, wqhdr, where);
}


/*
 * tavor_cq_wqhdr_remove()
 *    Context: Can be called from interrupt or base context.
 */
static void
tavor_cq_wqhdr_remove(tavor_cqhdl_t cq, tavor_workq_hdr_t *wqhdr)
{
	ASSERT(MUTEX_HELD(&cq->cq_wrid_wqhdr_lock));

#ifdef __lock_lint
	tavor_wrid_wqhdr_compare(NULL, NULL);
#endif
	/* Remove "wqhdr" from the work queue header list on "cq" */
	avl_remove(&cq->cq_wrid_wqhdr_avl_tree, wqhdr);

	/*
	 * Release reference to WQL; If this is the last reference, this call
	 * also has the side effect of freeing up the 'wq_wrid_wql' memory.
	 */
	tavor_wql_refcnt_dec(wqhdr->wq_wrid_wql);

	/* Free the memory associated with "wqhdr" */
	kmem_free(wqhdr, sizeof (tavor_workq_hdr_t));
}


/*
 * tavor_wql_refcnt_inc()
 * Context: Can be called from interrupt or base context
 */
void
tavor_wql_refcnt_inc(tavor_wq_lock_t *wql)
{
	ASSERT(wql != NULL);

	mutex_enter(&wql->wql_lock);
	wql->wql_refcnt++;
	mutex_exit(&wql->wql_lock);
}

/*
 * tavor_wql_refcnt_dec()
 * Context: Can be called from interrupt or base context
 */
void
tavor_wql_refcnt_dec(tavor_wq_lock_t *wql)
{
	int	refcnt;

	ASSERT(wql != NULL);

	mutex_enter(&wql->wql_lock);
	wql->wql_refcnt--;
	refcnt = wql->wql_refcnt;
	mutex_exit(&wql->wql_lock);

	/*
	 *
	 * Free up WQL memory if we're the last one associated with this
	 * structure.
	 */
	if (refcnt == 0) {
		mutex_destroy(&wql->wql_lock);
		kmem_free(wql, sizeof (tavor_wq_lock_t));
	}
}
