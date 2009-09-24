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

/*
 * hermon_wr.c
 *    Hermon Work Request Processing Routines
 *
 *    Implements all the routines necessary to provide the PostSend(),
 *    PostRecv() and PostSRQ() verbs.  Also contains all the code
 *    necessary to implement the Hermon WRID tracking mechanism.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/avl.h>

#include <sys/ib/adapters/hermon/hermon.h>

static uint32_t hermon_wr_get_immediate(ibt_send_wr_t *wr);
static int hermon_wr_bind_check(hermon_state_t *state, ibt_send_wr_t *wr);
static int hermon_wqe_send_build(hermon_state_t *state, hermon_qphdl_t qp,
    ibt_send_wr_t *wr, uint64_t *desc, uint_t *size);
static int hermon_wqe_mlx_build(hermon_state_t *state, hermon_qphdl_t qp,
    ibt_send_wr_t *wr, uint64_t *desc, uint_t *size);
static void hermon_wqe_headroom(uint_t from, hermon_qphdl_t qp);
static int hermon_wqe_recv_build(hermon_state_t *state, hermon_qphdl_t qp,
    ibt_recv_wr_t *wr, uint64_t *desc);
static int hermon_wqe_srq_build(hermon_state_t *state, hermon_srqhdl_t srq,
    ibt_recv_wr_t *wr, uint64_t *desc);
static void hermon_wqe_sync(void *hdl, uint_t sync_from,
    uint_t sync_to, uint_t sync_type, uint_t flag);
static hermon_workq_avl_t *hermon_wrid_wqavl_find(hermon_cqhdl_t cq, uint_t qpn,
    uint_t send_or_recv);
static void hermon_cq_workq_add(hermon_cqhdl_t cq, hermon_workq_avl_t *wqavl);
static void hermon_cq_workq_remove(hermon_cqhdl_t cq,
    hermon_workq_avl_t *wqavl);

static	ibt_wr_ds_t	null_sgl = { 0, 0x00000100, 0 };

static int
hermon_post_send_ud(hermon_state_t *state, hermon_qphdl_t qp,
    ibt_send_wr_t *wr, uint_t num_wr, uint_t *num_posted)
{
	hermon_hw_snd_wqe_ud_t		*ud;
	hermon_workq_hdr_t		*wq;
	hermon_ahhdl_t			ah;
	ibt_ud_dest_t			*dest;
	uint64_t			*desc;
	uint32_t			desc_sz;
	uint32_t			signaled_dbd, solicited;
	uint32_t			head, tail, next_tail, qsize_msk;
	uint32_t			hdrmwqes;
	uint32_t			nopcode, fence, immed_data = 0;
	hermon_hw_wqe_sgl_t		*ds, *old_ds;
	ibt_wr_ds_t			*sgl;
	uint32_t			nds, dnds;
	int				i, j, last_ds, num_ds, status;
	uint32_t			*wqe_start;
	int				sectperwqe;
	uint_t				posted_cnt = 0;

	/* initialize the FMA retry loop */
	hermon_pio_init(fm_loop_cnt, fm_status, fm_test_num);

	ASSERT(MUTEX_HELD(&qp->qp_sq_lock));
	_NOTE(LOCK_RELEASED_AS_SIDE_EFFECT(&qp->qp_sq_lock))

	/* Grab the lock for the WRID list */
	membar_consumer();

	/* Save away some initial QP state */
	wq = qp->qp_sq_wqhdr;
	qsize_msk = wq->wq_mask;
	hdrmwqes  = qp->qp_sq_hdrmwqes;		/* in WQEs  */
	sectperwqe = 1 << (qp->qp_sq_log_wqesz - 2);

	tail	  = wq->wq_tail;
	head	  = wq->wq_head;
	status	  = DDI_SUCCESS;

post_next:
	/*
	 * Check for "queue full" condition.  If the queue
	 * is already full, then no more WQEs can be posted.
	 * So break out, ring a doorbell (if necessary) and
	 * return an error
	 */
	if (wq->wq_full != 0) {
		status = IBT_QP_FULL;
		goto done;
	}

	next_tail = (tail + 1) & qsize_msk;
	if (((tail + hdrmwqes) & qsize_msk) == head) {
		wq->wq_full = 1;
	}

	desc = HERMON_QP_SQ_ENTRY(qp, tail);

	ud = (hermon_hw_snd_wqe_ud_t *)((uintptr_t)desc +
	    sizeof (hermon_hw_snd_wqe_ctrl_t));
	ds = (hermon_hw_wqe_sgl_t *)((uintptr_t)ud +
	    sizeof (hermon_hw_snd_wqe_ud_t));
	nds = wr->wr_nds;
	sgl = wr->wr_sgl;
	num_ds = 0;

	/* need to know the count of destination nds for backward loop */
	for (dnds = 0, i = 0; i < nds; i++) {
		if (sgl[i].ds_len != 0)
			dnds++;
	}

	/*
	 * Build a Send or Send_LSO WQE
	 */
	if (wr->wr_opcode == IBT_WRC_SEND_LSO) {
		int total_len;

		nopcode = HERMON_WQE_SEND_NOPCODE_LSO;
		if (wr->wr.ud_lso.lso_hdr_sz > 60) {
			nopcode |= (1 << 6);	/* ReRead bit must be set */
		}
		dest = wr->wr.ud_lso.lso_ud_dest;
		ah = (hermon_ahhdl_t)dest->ud_ah;
		if (ah == NULL) {
			status = IBT_AH_HDL_INVALID;
			goto done;
		}
		HERMON_WQE_BUILD_UD(qp, ud, ah, dest);

		total_len = (4 + 0xf + wr->wr.ud_lso.lso_hdr_sz) & ~0xf;
		if ((uintptr_t)ds + total_len + (nds * 16) >
		    (uintptr_t)desc + (1 << qp->qp_sq_log_wqesz)) {
			status = IBT_QP_SGL_LEN_INVALID;
			goto done;
		}
		old_ds = ds;
		bcopy(wr->wr.ud_lso.lso_hdr, (uint32_t *)old_ds + 1,
		    wr->wr.ud_lso.lso_hdr_sz);
		ds = (hermon_hw_wqe_sgl_t *)((uintptr_t)ds + total_len);
		i = 0;
	} else if (wr->wr_opcode == IBT_WRC_SEND) {
		if (wr->wr_flags & IBT_WR_SEND_IMMED) {
			nopcode = HERMON_WQE_SEND_NOPCODE_SENDI;
			immed_data = wr->wr.ud.udwr_immed;
		} else {
			nopcode = HERMON_WQE_SEND_NOPCODE_SEND;
		}
		dest = wr->wr.ud.udwr_dest;
		ah = (hermon_ahhdl_t)dest->ud_ah;
		if (ah == NULL) {
			status = IBT_AH_HDL_INVALID;
			goto done;
		}
		HERMON_WQE_BUILD_UD(qp, ud, ah, dest);
		i = 0;
	} else {
		status = IBT_QP_OP_TYPE_INVALID;
		goto done;
	}

	if (nds > qp->qp_sq_sgl) {
		status = IBT_QP_SGL_LEN_INVALID;
		goto done;
	}
	for (last_ds = num_ds, j = i; j < nds; j++) {
		if (sgl[j].ds_len != 0)
			last_ds++;	/* real last ds of wqe to fill */
	}
	desc_sz = ((uintptr_t)&ds[last_ds] - (uintptr_t)desc) >> 0x4;
	for (j = nds; --j >= i; ) {
		if (sgl[j].ds_len == 0) {
			continue;
		}

		/*
		 * Fill in the Data Segment(s) for the current WQE, using the
		 * information contained in the scatter-gather list of the
		 * work request.
		 */
		last_ds--;
		HERMON_WQE_BUILD_DATA_SEG_SEND(&ds[last_ds], &sgl[j]);
	}

	membar_producer();

	if (wr->wr_opcode == IBT_WRC_SEND_LSO) {
		HERMON_WQE_BUILD_LSO(qp, old_ds, wr->wr.ud_lso.lso_mss,
		    wr->wr.ud_lso.lso_hdr_sz);
	}

	fence = (wr->wr_flags & IBT_WR_SEND_FENCE) ? 1 : 0;

	signaled_dbd = ((qp->qp_sq_sigtype == HERMON_QP_SQ_ALL_SIGNALED) ||
	    (wr->wr_flags & IBT_WR_SEND_SIGNAL)) ? 1 : 0;

	solicited = (wr->wr_flags & IBT_WR_SEND_SOLICIT) ? 1 : 0;

	HERMON_WQE_SET_CTRL_SEGMENT(desc, desc_sz, fence, immed_data,
	    solicited, signaled_dbd, wr->wr_flags & IBT_WR_SEND_CKSUM, qp);

	wq->wq_wrid[tail] = wr->wr_id;

	tail = next_tail;

	/* Update some of the state in the QP */
	wq->wq_tail = tail;

	membar_producer();

	/* Now set the ownership bit and opcode (first dword). */
	HERMON_SET_SEND_WQE_OWNER(qp, (uint32_t *)desc, nopcode);

	posted_cnt++;
	if (--num_wr > 0) {
		/* do the invalidate of the headroom */
		wqe_start = (uint32_t *)HERMON_QP_SQ_ENTRY(qp,
		    (tail + hdrmwqes) & qsize_msk);
		for (i = 16; i < sectperwqe; i += 16) {
			wqe_start[i] = 0xFFFFFFFF;
		}

		wr++;
		goto post_next;
	}
done:
	if (posted_cnt != 0) {
		ddi_acc_handle_t uarhdl = hermon_get_uarhdl(state);

		membar_producer();

		/* the FMA retry loop starts for Hermon doorbell register. */
		hermon_pio_start(state, uarhdl, pio_error, fm_loop_cnt,
		    fm_status, fm_test_num);

		HERMON_UAR_DOORBELL(state, uarhdl,
		    (uint64_t *)(void *)&state->hs_uar->send,
		    (uint64_t)qp->qp_ring);

		/* the FMA retry loop ends. */
		hermon_pio_end(state, uarhdl, pio_error, fm_loop_cnt,
		    fm_status, fm_test_num);

		/* do the invalidate of the headroom */
		wqe_start = (uint32_t *)HERMON_QP_SQ_ENTRY(qp,
		    (tail + hdrmwqes) & qsize_msk);
		for (i = 16; i < sectperwqe; i += 16) {
			wqe_start[i] = 0xFFFFFFFF;
		}
	}
	if (num_posted != NULL)
		*num_posted = posted_cnt;

	mutex_exit(&qp->qp_sq_lock);

	return (status);

pio_error:
	mutex_exit(&qp->qp_sq_lock);
	hermon_fm_ereport(state, HCA_SYS_ERR, HCA_ERR_SRV_LOST);
	return (ibc_get_ci_failure(0));
}

static int
hermon_post_send_rc(hermon_state_t *state, hermon_qphdl_t qp,
    ibt_send_wr_t *wr, uint_t num_wr, uint_t *num_posted)
{
	uint64_t			*desc;
	hermon_workq_hdr_t		*wq;
	uint32_t			desc_sz;
	uint32_t			signaled_dbd, solicited;
	uint32_t			head, tail, next_tail, qsize_msk;
	uint32_t			hdrmwqes;
	int				status;
	uint32_t			nopcode, fence, immed_data = 0;
	hermon_hw_snd_wqe_remaddr_t	*rc;
	hermon_hw_snd_wqe_atomic_t	*at;
	hermon_hw_snd_wqe_bind_t	*bn;
	hermon_hw_wqe_sgl_t		*ds;
	ibt_wr_ds_t			*sgl;
	uint32_t			nds;
	int				i, last_ds, num_ds;
	uint32_t			*wqe_start;
	int				sectperwqe;
	uint_t				posted_cnt = 0;

	/* initialize the FMA retry loop */
	hermon_pio_init(fm_loop_cnt, fm_status, fm_test_num);

	ASSERT(MUTEX_HELD(&qp->qp_sq_lock));
	_NOTE(LOCK_RELEASED_AS_SIDE_EFFECT(&qp->qp_sq_lock))

	/* make sure we see any update of wq_head */
	membar_consumer();

	/* Save away some initial QP state */
	wq = qp->qp_sq_wqhdr;
	qsize_msk = wq->wq_mask;
	hdrmwqes  = qp->qp_sq_hdrmwqes;		/* in WQEs  */
	sectperwqe = 1 << (qp->qp_sq_log_wqesz - 2);

	tail	  = wq->wq_tail;
	head	  = wq->wq_head;
	status	  = DDI_SUCCESS;

post_next:
	/*
	 * Check for "queue full" condition.  If the queue
	 * is already full, then no more WQEs can be posted.
	 * So break out, ring a doorbell (if necessary) and
	 * return an error
	 */
	if (wq->wq_full != 0) {
		status = IBT_QP_FULL;
		goto done;
	}
	next_tail = (tail + 1) & qsize_msk;
	if (((tail + hdrmwqes) & qsize_msk) == head) {
		wq->wq_full = 1;
	}

	desc = HERMON_QP_SQ_ENTRY(qp, tail);

	ds = (hermon_hw_wqe_sgl_t *)((uintptr_t)desc +
	    sizeof (hermon_hw_snd_wqe_ctrl_t));
	nds = wr->wr_nds;
	sgl = wr->wr_sgl;
	num_ds = 0;

	/*
	 * Validate the operation type.  For RC requests, we allow
	 * "Send", "RDMA Read", "RDMA Write", various "Atomic"
	 * operations, and memory window "Bind"
	 */
	switch (wr->wr_opcode) {
	default:
		status = IBT_QP_OP_TYPE_INVALID;
		goto done;

	case IBT_WRC_SEND:
		if (wr->wr_flags & IBT_WR_SEND_IMMED) {
			nopcode = HERMON_WQE_SEND_NOPCODE_SENDI;
			immed_data = wr->wr.rc.rcwr.send_immed;
		} else {
			nopcode = HERMON_WQE_SEND_NOPCODE_SEND;
		}
		break;

	/*
	 * If this is an RDMA Read or RDMA Write request, then fill
	 * in the "Remote Address" header fields.
	 */
	case IBT_WRC_RDMAW:
		if (wr->wr_flags & IBT_WR_SEND_IMMED) {
			nopcode = HERMON_WQE_SEND_NOPCODE_RDMAWI;
			immed_data = wr->wr.rc.rcwr.rdma.rdma_immed;
		} else {
			nopcode = HERMON_WQE_SEND_NOPCODE_RDMAW;
		}
		/* FALLTHROUGH */
	case IBT_WRC_RDMAR:
		if (wr->wr_opcode == IBT_WRC_RDMAR)
			nopcode = HERMON_WQE_SEND_NOPCODE_RDMAR;
		rc = (hermon_hw_snd_wqe_remaddr_t *)((uintptr_t)desc +
		    sizeof (hermon_hw_snd_wqe_ctrl_t));

		/*
		 * Build the Remote Address Segment for the WQE, using
		 * the information from the RC work request.
		 */
		HERMON_WQE_BUILD_REMADDR(qp, rc, &wr->wr.rc.rcwr.rdma);

		/* Update "ds" for filling in Data Segments (below) */
		ds = (hermon_hw_wqe_sgl_t *)((uintptr_t)rc +
		    sizeof (hermon_hw_snd_wqe_remaddr_t));
		break;

	/*
	 * If this is one of the Atomic type operations (i.e
	 * Compare-Swap or Fetch-Add), then fill in both the "Remote
	 * Address" header fields and the "Atomic" header fields.
	 */
	case IBT_WRC_CSWAP:
		nopcode = HERMON_WQE_SEND_NOPCODE_ATMCS;
		/* FALLTHROUGH */
	case IBT_WRC_FADD:
		if (wr->wr_opcode == IBT_WRC_FADD)
			nopcode = HERMON_WQE_SEND_NOPCODE_ATMFA;
		rc = (hermon_hw_snd_wqe_remaddr_t *)((uintptr_t)desc +
		    sizeof (hermon_hw_snd_wqe_ctrl_t));
		at = (hermon_hw_snd_wqe_atomic_t *)((uintptr_t)rc +
		    sizeof (hermon_hw_snd_wqe_remaddr_t));

		/*
		 * Build the Remote Address and Atomic Segments for
		 * the WQE, using the information from the RC Atomic
		 * work request.
		 */
		HERMON_WQE_BUILD_RC_ATOMIC_REMADDR(qp, rc, wr);
		HERMON_WQE_BUILD_ATOMIC(qp, at, wr->wr.rc.rcwr.atomic);

		/* Update "ds" for filling in Data Segments (below) */
		ds = (hermon_hw_wqe_sgl_t *)((uintptr_t)at +
		    sizeof (hermon_hw_snd_wqe_atomic_t));

		/*
		 * Update "nds" and "sgl" because Atomic requests have
		 * only a single Data Segment.
		 */
		nds = 1;
		sgl = wr->wr_sgl;
		break;

	/*
	 * If this is memory window Bind operation, then we call the
	 * hermon_wr_bind_check() routine to validate the request and
	 * to generate the updated RKey.  If this is successful, then
	 * we fill in the WQE's "Bind" header fields.
	 */
	case IBT_WRC_BIND:
		nopcode = HERMON_WQE_SEND_NOPCODE_BIND;
		status = hermon_wr_bind_check(state, wr);
		if (status != DDI_SUCCESS)
			goto done;

		bn = (hermon_hw_snd_wqe_bind_t *)((uintptr_t)desc +
		    sizeof (hermon_hw_snd_wqe_ctrl_t));

		/*
		 * Build the Bind Memory Window Segments for the WQE,
		 * using the information from the RC Bind memory
		 * window work request.
		 */
		HERMON_WQE_BUILD_BIND(qp, bn, wr->wr.rc.rcwr.bind);

		/*
		 * Update the "ds" pointer.  Even though the "bind"
		 * operation requires no SGLs, this is necessary to
		 * facilitate the correct descriptor size calculations
		 * (below).
		 */
		ds = (hermon_hw_wqe_sgl_t *)((uintptr_t)bn +
		    sizeof (hermon_hw_snd_wqe_bind_t));
		nds = 0;
	}

	/*
	 * Now fill in the Data Segments (SGL) for the Send WQE based
	 * on the values setup above (i.e. "sgl", "nds", and the "ds"
	 * pointer. Start by checking for a valid number of SGL entries
	 */
	if (nds > qp->qp_sq_sgl) {
		status = IBT_QP_SGL_LEN_INVALID;
		goto done;
	}

	for (last_ds = num_ds, i = 0; i < nds; i++) {
		if (sgl[i].ds_len != 0)
			last_ds++;	/* real last ds of wqe to fill */
	}
	desc_sz = ((uintptr_t)&ds[last_ds] - (uintptr_t)desc) >> 0x4;
	for (i = nds; --i >= 0; ) {
		if (sgl[i].ds_len == 0) {
			continue;
		}

		/*
		 * Fill in the Data Segment(s) for the current WQE, using the
		 * information contained in the scatter-gather list of the
		 * work request.
		 */
		last_ds--;
		HERMON_WQE_BUILD_DATA_SEG_SEND(&ds[last_ds], &sgl[i]);
	}

	fence = (wr->wr_flags & IBT_WR_SEND_FENCE) ? 1 : 0;

	signaled_dbd = ((qp->qp_sq_sigtype == HERMON_QP_SQ_ALL_SIGNALED) ||
	    (wr->wr_flags & IBT_WR_SEND_SIGNAL)) ? 1 : 0;

	solicited = (wr->wr_flags & IBT_WR_SEND_SOLICIT) ? 1 : 0;

	HERMON_WQE_SET_CTRL_SEGMENT(desc, desc_sz, fence, immed_data, solicited,
	    signaled_dbd, wr->wr_flags & IBT_WR_SEND_CKSUM, qp);

	wq->wq_wrid[tail] = wr->wr_id;

	tail = next_tail;

	/* Update some of the state in the QP */
	wq->wq_tail = tail;

	membar_producer();

	/* Now set the ownership bit of the first one in the chain. */
	HERMON_SET_SEND_WQE_OWNER(qp, (uint32_t *)desc, nopcode);

	posted_cnt++;
	if (--num_wr > 0) {
		/* do the invalidate of the headroom */
		wqe_start = (uint32_t *)HERMON_QP_SQ_ENTRY(qp,
		    (tail + hdrmwqes) & qsize_msk);
		for (i = 16; i < sectperwqe; i += 16) {
			wqe_start[i] = 0xFFFFFFFF;
		}

		wr++;
		goto post_next;
	}
done:

	if (posted_cnt != 0) {
		ddi_acc_handle_t uarhdl = hermon_get_uarhdl(state);

		membar_producer();

		/* the FMA retry loop starts for Hermon doorbell register. */
		hermon_pio_start(state, uarhdl, pio_error, fm_loop_cnt,
		    fm_status, fm_test_num);

		/* Ring the doorbell */
		HERMON_UAR_DOORBELL(state, uarhdl,
		    (uint64_t *)(void *)&state->hs_uar->send,
		    (uint64_t)qp->qp_ring);

		/* the FMA retry loop ends. */
		hermon_pio_end(state, uarhdl, pio_error, fm_loop_cnt,
		    fm_status, fm_test_num);

		/* do the invalidate of the headroom */
		wqe_start = (uint32_t *)HERMON_QP_SQ_ENTRY(qp,
		    (tail + hdrmwqes) & qsize_msk);
		for (i = 16; i < sectperwqe; i += 16) {
			wqe_start[i] = 0xFFFFFFFF;
		}
	}
	/*
	 * Update the "num_posted" return value (if necessary).
	 * Then drop the locks and return success.
	 */
	if (num_posted != NULL) {
		*num_posted = posted_cnt;
	}

	mutex_exit(&qp->qp_sq_lock);
	return (status);

pio_error:
	mutex_exit(&qp->qp_sq_lock);
	hermon_fm_ereport(state, HCA_SYS_ERR, HCA_ERR_SRV_LOST);
	return (ibc_get_ci_failure(0));
}

/*
 * hermon_post_send()
 *    Context: Can be called from interrupt or base context.
 */
int
hermon_post_send(hermon_state_t *state, hermon_qphdl_t qp,
    ibt_send_wr_t *wr, uint_t num_wr, uint_t *num_posted)
{
	ibt_send_wr_t 			*curr_wr;
	hermon_workq_hdr_t		*wq;
	hermon_ahhdl_t			ah;
	uint64_t			*desc, *prev;
	uint32_t			desc_sz;
	uint32_t			signaled_dbd, solicited;
	uint32_t			head, tail, next_tail, qsize_msk;
	uint32_t			sync_from, sync_to;
	uint32_t			hdrmwqes;
	uint_t				currindx, wrindx, numremain;
	uint_t				chainlen;
	uint_t				posted_cnt, maxstat;
	uint_t				total_posted;
	int				status;
	uint32_t			nopcode, fence, immed_data = 0;
	uint32_t			prev_nopcode;

	/* initialize the FMA retry loop */
	hermon_pio_init(fm_loop_cnt, fm_status, fm_test);

	/*
	 * Check for user-mappable QP memory.  Note:  We do not allow kernel
	 * clients to post to QP memory that is accessible directly by the
	 * user.  If the QP memory is user accessible, then return an error.
	 */
	if (qp->qp_is_umap) {
		return (IBT_QP_HDL_INVALID);
	}

	mutex_enter(&qp->qp_lock);

	/*
	 * Check QP state.  Can not post Send requests from the "Reset",
	 * "Init", or "RTR" states
	 */
	if ((qp->qp_state == HERMON_QP_RESET) ||
	    (qp->qp_state == HERMON_QP_INIT) ||
	    (qp->qp_state == HERMON_QP_RTR)) {
		mutex_exit(&qp->qp_lock);
		return (IBT_QP_STATE_INVALID);
	}
	mutex_exit(&qp->qp_lock);
	mutex_enter(&qp->qp_sq_lock);

	if (qp->qp_is_special)
		goto post_many;

	/* Use these optimized functions most of the time */
	if (qp->qp_serv_type == HERMON_QP_UD)
		return (hermon_post_send_ud(state, qp, wr, num_wr, num_posted));

	if (qp->qp_serv_type == HERMON_QP_RC)
		return (hermon_post_send_rc(state, qp, wr, num_wr, num_posted));

	if (qp->qp_serv_type == HERMON_QP_UC)
		goto post_many;

	mutex_exit(&qp->qp_sq_lock);
	return (IBT_QP_SRV_TYPE_INVALID);

post_many:
	/* general loop for non-optimized posting */

	/* Grab the lock for the WRID list */
	membar_consumer();

	/* Save away some initial QP state */
	wq = qp->qp_sq_wqhdr;
	qsize_msk = wq->wq_mask;
	tail	  = wq->wq_tail;
	head	  = wq->wq_head;
	hdrmwqes  = qp->qp_sq_hdrmwqes;		/* in WQEs  */

	/* Initialize posted_cnt */
	posted_cnt = 0;
	total_posted = 0;

	/*
	 * For each ibt_send_wr_t in the wr[] list passed in, parse the
	 * request and build a Send WQE.  NOTE:  Because we are potentially
	 * building a chain of WQEs to post, we want to build them all first,
	 * and set the valid (HW Ownership) bit on all but the first.
	 * However, we do not want to validate the first one until the
	 * entire chain of WQEs has been built.  Then in the final
	 * we set the valid bit in the first, flush if needed, and as a last
	 * step ring the appropriate doorbell.  NOTE: the doorbell ring may
	 * NOT be needed if the HCA is already processing, but the doorbell
	 * ring will be done regardless. NOTE ALSO:  It is possible for
	 * more Work Requests to be posted than the HW will support at one
	 * shot.  If this happens, we need to be able to post and ring
	 * several chains here until the the entire request is complete.
	 * NOTE ALSO:  the term "chain" is used to differentiate it from
	 * Work Request List passed in; and because that's the terminology
	 * from the previous generations of HCA - but the WQEs are not, in fact
	 * chained together for Hermon
	 */

	wrindx = 0;
	numremain = num_wr;
	status	  = DDI_SUCCESS;
	while ((wrindx < num_wr) && (status == DDI_SUCCESS)) {
		/*
		 * For the first WQE on a new chain we need "prev" to point
		 * to the current descriptor.
		 */
		prev = HERMON_QP_SQ_ENTRY(qp, tail);

	/*
	 * unlike Tavor & Arbel, tail will maintain the number of the
	 * next (this) WQE to be posted.  Since there is no backward linking
	 * in Hermon, we can always just look ahead
	 */
		/*
		 * Before we begin, save the current "tail index" for later
		 * DMA sync
		 */
		/* NOTE: don't need to go back one like arbel/tavor */
		sync_from = tail;

		/*
		 * Break the request up into lists that are less than or
		 * equal to the maximum number of WQEs that can be posted
		 * per doorbell ring - 256 currently
		 */
		chainlen = (numremain > HERMON_QP_MAXDESC_PER_DB) ?
		    HERMON_QP_MAXDESC_PER_DB : numremain;
		numremain -= chainlen;

		for (currindx = 0; currindx < chainlen; currindx++, wrindx++) {
			/*
			 * Check for "queue full" condition.  If the queue
			 * is already full, then no more WQEs can be posted.
			 * So break out, ring a doorbell (if necessary) and
			 * return an error
			 */
			if (wq->wq_full != 0) {
				status = IBT_QP_FULL;
				break;
			}

			/*
			 * Increment the "tail index". Check for "queue
			 * full" condition incl. headroom.  If we detect that
			 * the current work request is going to fill the work
			 * queue, then we mark this condition and continue.
			 * Don't need >=, because going one-by-one we have to
			 * hit it exactly sooner or later
			 */

			next_tail = (tail + 1) & qsize_msk;
			if (((tail + hdrmwqes) & qsize_msk) == head) {
				wq->wq_full = 1;
			}

			/*
			 * Get the address of the location where the next
			 * Send WQE should be built
			 */
			desc = HERMON_QP_SQ_ENTRY(qp, tail);
			/*
			 * Call hermon_wqe_send_build() to build the WQE
			 * at the given address.  This routine uses the
			 * information in the ibt_send_wr_t list (wr[]) and
			 * returns the size of the WQE when it returns.
			 */
			status = hermon_wqe_send_build(state, qp,
			    &wr[wrindx], desc, &desc_sz);
			if (status != DDI_SUCCESS) {
				break;
			}

			/*
			 * Now, build the Ctrl Segment based on
			 * what was just done
			 */
			curr_wr = &wr[wrindx];

			switch (curr_wr->wr_opcode) {
			case IBT_WRC_RDMAW:
				if (curr_wr->wr_flags & IBT_WR_SEND_IMMED) {
					nopcode =
					    HERMON_WQE_SEND_NOPCODE_RDMAWI;
					immed_data =
					    hermon_wr_get_immediate(curr_wr);
				} else {
					nopcode = HERMON_WQE_SEND_NOPCODE_RDMAW;
				}
				break;

			case IBT_WRC_SEND:
				if (curr_wr->wr_flags & IBT_WR_SEND_IMMED) {
					nopcode = HERMON_WQE_SEND_NOPCODE_SENDI;
					immed_data =
					    hermon_wr_get_immediate(curr_wr);
				} else {
					nopcode = HERMON_WQE_SEND_NOPCODE_SEND;
				}
				break;

			case IBT_WRC_SEND_LSO:
				nopcode = HERMON_WQE_SEND_NOPCODE_LSO;
				break;

			case IBT_WRC_RDMAR:
				nopcode = HERMON_WQE_SEND_NOPCODE_RDMAR;
				break;

			case IBT_WRC_CSWAP:
				nopcode = HERMON_WQE_SEND_NOPCODE_ATMCS;
				break;

			case IBT_WRC_FADD:
				nopcode = HERMON_WQE_SEND_NOPCODE_ATMFA;
				break;

			case IBT_WRC_BIND:
				nopcode = HERMON_WQE_SEND_NOPCODE_BIND;
				break;
			}

			fence = (curr_wr->wr_flags & IBT_WR_SEND_FENCE) ? 1 : 0;

			/*
			 * now, build up the control segment, leaving the
			 * owner bit as it is
			 */

			if ((qp->qp_sq_sigtype == HERMON_QP_SQ_ALL_SIGNALED) ||
			    (curr_wr->wr_flags & IBT_WR_SEND_SIGNAL)) {
				signaled_dbd = 1;
			} else {
				signaled_dbd = 0;
			}
			if (curr_wr->wr_flags & IBT_WR_SEND_SOLICIT)
				solicited = 1;
			else
				solicited = 0;

			if (qp->qp_is_special) {
				ah = (hermon_ahhdl_t)
				    curr_wr->wr.ud.udwr_dest->ud_ah;
				mutex_enter(&ah->ah_lock);
				maxstat = ah->ah_udav->max_stat_rate;
				HERMON_WQE_SET_MLX_CTRL_SEGMENT(desc, desc_sz,
				    signaled_dbd, maxstat, ah->ah_udav->rlid,
				    qp, ah->ah_udav->sl);
				mutex_exit(&ah->ah_lock);
			} else {
				HERMON_WQE_SET_CTRL_SEGMENT(desc, desc_sz,
				    fence, immed_data, solicited,
				    signaled_dbd, curr_wr->wr_flags &
				    IBT_WR_SEND_CKSUM, qp);
			}
			wq->wq_wrid[tail] = curr_wr->wr_id;

			/*
			 * If this is not the first descriptor on the current
			 * chain, then set the ownership bit.
			 */
			if (currindx != 0) {		/* not the first */
				membar_producer();
				HERMON_SET_SEND_WQE_OWNER(qp,
				    (uint32_t *)desc, nopcode);
			} else
				prev_nopcode = nopcode;

			/*
			 * Update the current "tail index" and increment
			 * "posted_cnt"
			 */
			tail = next_tail;
			posted_cnt++;
		}

		/*
		 * If we reach here and there are one or more WQEs which have
		 * been successfully built as a chain, we have to finish up
		 * and prepare them for writing to the HW
		 * The steps are:
		 * 	1. do the headroom fixup
		 *	2. add in the size of the headroom for the sync
		 *	3. write the owner bit for the first WQE
		 *	4. sync them
		 *	5. fix up the structures
		 *	6. hit the doorbell in UAR
		 */
		if (posted_cnt != 0) {
			ddi_acc_handle_t uarhdl = hermon_get_uarhdl(state);

			/*
			 * Save away updated "tail index" for the DMA sync
			 * including the headroom that will be needed
			 */
			sync_to = (tail + hdrmwqes) & qsize_msk;

			/* do the invalidate of the headroom */

			hermon_wqe_headroom(tail, qp);

			/* Do a DMA sync for current send WQE(s) */
			hermon_wqe_sync(qp, sync_from, sync_to, HERMON_WR_SEND,
			    DDI_DMA_SYNC_FORDEV);

			/* Update some of the state in the QP */
			wq->wq_tail = tail;
			total_posted += posted_cnt;
			posted_cnt = 0;

			membar_producer();

			/*
			 * Now set the ownership bit of the first
			 * one in the chain
			 */
			HERMON_SET_SEND_WQE_OWNER(qp, (uint32_t *)prev,
			    prev_nopcode);

			/* the FMA retry loop starts for Hermon doorbell. */
			hermon_pio_start(state, uarhdl, pio_error, fm_loop_cnt,
			    fm_status, fm_test);

			HERMON_UAR_DOORBELL(state, uarhdl,
			    (uint64_t *)(void *)&state->hs_uar->send,
			    (uint64_t)qp->qp_ring);

			/* the FMA retry loop ends. */
			hermon_pio_end(state, uarhdl, pio_error, fm_loop_cnt,
			    fm_status, fm_test);
		}
	}

	/*
	 * Update the "num_posted" return value (if necessary).
	 * Then drop the locks and return success.
	 */
	if (num_posted != NULL) {
		*num_posted = total_posted;
	}
	mutex_exit(&qp->qp_sq_lock);
	return (status);

pio_error:
	mutex_exit(&qp->qp_sq_lock);
	hermon_fm_ereport(state, HCA_SYS_ERR, HCA_ERR_SRV_LOST);
	return (ibc_get_ci_failure(0));
}


/*
 * hermon_post_recv()
 *    Context: Can be called from interrupt or base context.
 */
int
hermon_post_recv(hermon_state_t *state, hermon_qphdl_t qp,
    ibt_recv_wr_t *wr, uint_t num_wr, uint_t *num_posted)
{
	uint64_t			*desc;
	hermon_workq_hdr_t		*wq;
	uint32_t			head, tail, next_tail, qsize_msk;
	uint32_t			sync_from, sync_to;
	uint_t				wrindx;
	uint_t				posted_cnt;
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
	if (qp->qp_srq_en == HERMON_QP_SRQ_ENABLED) {
		mutex_exit(&qp->qp_lock);
		return (IBT_SRQ_IN_USE);
	}

	/*
	 * Check QP state.  Can not post Recv requests from the "Reset" state
	 */
	if (qp->qp_state == HERMON_QP_RESET) {
		mutex_exit(&qp->qp_lock);
		return (IBT_QP_STATE_INVALID);
	}

	/* Check that work request transport type is valid */
	if ((qp->qp_serv_type != HERMON_QP_UD) &&
	    (qp->qp_serv_type != HERMON_QP_RC) &&
	    (qp->qp_serv_type != HERMON_QP_UC)) {
		mutex_exit(&qp->qp_lock);
		return (IBT_QP_SRV_TYPE_INVALID);
	}

	mutex_exit(&qp->qp_lock);
	mutex_enter(&qp->qp_rq_lock);

	/*
	 * Grab the lock for the WRID list, i.e., membar_consumer().
	 * This is not needed because the mutex_enter() above has
	 * the same effect.
	 */

	/* Save away some initial QP state */
	wq = qp->qp_rq_wqhdr;
	qsize_msk = wq->wq_mask;
	tail	  = wq->wq_tail;
	head	  = wq->wq_head;

	wrindx = 0;
	status	  = DDI_SUCCESS;
	/*
	 * Before we begin, save the current "tail index" for later
	 * DMA sync
	 */
	sync_from = tail;

	for (wrindx = 0; wrindx < num_wr; wrindx++) {
		if (wq->wq_full != 0) {
			status = IBT_QP_FULL;
			break;
		}
		next_tail = (tail + 1) & qsize_msk;
		if (next_tail == head) {
			wq->wq_full = 1;
		}
		desc = HERMON_QP_RQ_ENTRY(qp, tail);
		status = hermon_wqe_recv_build(state, qp, &wr[wrindx], desc);
		if (status != DDI_SUCCESS) {
			break;
		}

		wq->wq_wrid[tail] = wr[wrindx].wr_id;
		qp->qp_rq_wqecntr++;

		tail = next_tail;
		posted_cnt++;
	}

	if (posted_cnt != 0) {
		/* Save away updated "tail index" for the DMA sync */
		sync_to = tail;

		hermon_wqe_sync(qp, sync_from, sync_to, HERMON_WR_RECV,
		    DDI_DMA_SYNC_FORDEV);

		wq->wq_tail = tail;

		membar_producer();	/* ensure wrids are visible */

		/* Update the doorbell record w/ wqecntr */
		HERMON_UAR_DB_RECORD_WRITE(qp->qp_rq_vdbr,
		    qp->qp_rq_wqecntr & 0xFFFF);
	}

	if (num_posted != NULL) {
		*num_posted = posted_cnt;
	}


	mutex_exit(&qp->qp_rq_lock);
	return (status);
}

/*
 * hermon_post_srq()
 *    Context: Can be called from interrupt or base context.
 */
int
hermon_post_srq(hermon_state_t *state, hermon_srqhdl_t srq,
    ibt_recv_wr_t *wr, uint_t num_wr, uint_t *num_posted)
{
	uint64_t			*desc;
	hermon_workq_hdr_t		*wq;
	uint_t				indx, wrindx;
	uint_t				posted_cnt;
	int				status;

	mutex_enter(&srq->srq_lock);

	/*
	 * Check for user-mappable QP memory.  Note:  We do not allow kernel
	 * clients to post to QP memory that is accessible directly by the
	 * user.  If the QP memory is user accessible, then return an error.
	 */
	if (srq->srq_is_umap) {
		mutex_exit(&srq->srq_lock);
		return (IBT_SRQ_HDL_INVALID);
	}

	/*
	 * Check SRQ state.  Can not post Recv requests when SRQ is in error
	 */
	if (srq->srq_state == HERMON_SRQ_STATE_ERROR) {
		mutex_exit(&srq->srq_lock);
		return (IBT_QP_STATE_INVALID);
	}

	status = DDI_SUCCESS;
	posted_cnt = 0;
	wq = srq->srq_wq_wqhdr;
	indx = wq->wq_head;

	for (wrindx = 0; wrindx < num_wr; wrindx++) {

		if (indx == wq->wq_tail) {
			status = IBT_QP_FULL;
			break;
		}
		desc = HERMON_SRQ_WQE_ADDR(srq, indx);

		wq->wq_wrid[indx] = wr[wrindx].wr_id;

		status = hermon_wqe_srq_build(state, srq, &wr[wrindx], desc);
		if (status != DDI_SUCCESS) {
			break;
		}

		hermon_wqe_sync(srq, indx, indx + 1,
		    HERMON_WR_SRQ, DDI_DMA_SYNC_FORDEV);
		posted_cnt++;
		indx = htons(((uint16_t *)desc)[1]);
		wq->wq_head = indx;
	}

	if (posted_cnt != 0) {

		srq->srq_wq_wqecntr += posted_cnt;

		membar_producer();	/* ensure wrids are visible */

		/* Ring the doorbell w/ wqecntr */
		HERMON_UAR_DB_RECORD_WRITE(srq->srq_wq_vdbr,
		    srq->srq_wq_wqecntr & 0xFFFF);
	}

	if (num_posted != NULL) {
		*num_posted = posted_cnt;
	}

	mutex_exit(&srq->srq_lock);
	return (status);
}


/*
 * hermon_wqe_send_build()
 *    Context: Can be called from interrupt or base context.
 */
static int
hermon_wqe_send_build(hermon_state_t *state, hermon_qphdl_t qp,
    ibt_send_wr_t *wr, uint64_t *desc, uint_t *size)
{
	hermon_hw_snd_wqe_ud_t		*ud;
	hermon_hw_snd_wqe_remaddr_t	*rc;
	hermon_hw_snd_wqe_atomic_t	*at;
	hermon_hw_snd_wqe_remaddr_t	*uc;
	hermon_hw_snd_wqe_bind_t	*bn;
	hermon_hw_wqe_sgl_t		*ds, *old_ds;
	ibt_ud_dest_t			*dest;
	ibt_wr_ds_t			*sgl;
	hermon_ahhdl_t			ah;
	uint32_t			nds;
	int				i, j, last_ds, num_ds, status;
	int				tmpsize;

	ASSERT(MUTEX_HELD(&qp->qp_sq_lock));

	/* Initialize the information for the Data Segments */
	ds = (hermon_hw_wqe_sgl_t *)((uintptr_t)desc +
	    sizeof (hermon_hw_snd_wqe_ctrl_t));
	nds = wr->wr_nds;
	sgl = wr->wr_sgl;
	num_ds = 0;
	i = 0;

	/*
	 * Build a Send WQE depends first and foremost on the transport
	 * type of Work Request (i.e. UD, RC, or UC)
	 */
	switch (wr->wr_trans) {
	case IBT_UD_SRV:
		/* Ensure that work request transport type matches QP type */
		if (qp->qp_serv_type != HERMON_QP_UD) {
			return (IBT_QP_SRV_TYPE_INVALID);
		}

		/*
		 * Validate the operation type.  For UD requests, only the
		 * "Send" and "Send LSO" operations are valid.
		 */
		if (wr->wr_opcode != IBT_WRC_SEND &&
		    wr->wr_opcode != IBT_WRC_SEND_LSO) {
			return (IBT_QP_OP_TYPE_INVALID);
		}

		/*
		 * If this is a Special QP (QP0 or QP1), then we need to
		 * build MLX WQEs instead.  So jump to hermon_wqe_mlx_build()
		 * and return whatever status it returns
		 */
		if (qp->qp_is_special) {
			if (wr->wr_opcode == IBT_WRC_SEND_LSO) {
				return (IBT_QP_OP_TYPE_INVALID);
			}
			status = hermon_wqe_mlx_build(state, qp,
			    wr, desc, size);
			return (status);
		}

		/*
		 * Otherwise, if this is a normal UD Send request, then fill
		 * all the fields in the Hermon UD header for the WQE.  Note:
		 * to do this we'll need to extract some information from the
		 * Address Handle passed with the work request.
		 */
		ud = (hermon_hw_snd_wqe_ud_t *)((uintptr_t)desc +
		    sizeof (hermon_hw_snd_wqe_ctrl_t));
		if (wr->wr_opcode == IBT_WRC_SEND) {
			dest = wr->wr.ud.udwr_dest;
		} else {
			dest = wr->wr.ud_lso.lso_ud_dest;
		}
		ah = (hermon_ahhdl_t)dest->ud_ah;
		if (ah == NULL) {
			return (IBT_AH_HDL_INVALID);
		}

		/*
		 * Build the Unreliable Datagram Segment for the WQE, using
		 * the information from the address handle and the work
		 * request.
		 */
		/* mutex_enter(&ah->ah_lock); */
		if (wr->wr_opcode == IBT_WRC_SEND) {
			HERMON_WQE_BUILD_UD(qp, ud, ah, wr->wr.ud.udwr_dest);
		} else {	/* IBT_WRC_SEND_LSO */
			HERMON_WQE_BUILD_UD(qp, ud, ah,
			    wr->wr.ud_lso.lso_ud_dest);
		}
		/* mutex_exit(&ah->ah_lock); */

		/* Update "ds" for filling in Data Segments (below) */
		ds = (hermon_hw_wqe_sgl_t *)((uintptr_t)ud +
		    sizeof (hermon_hw_snd_wqe_ud_t));

		if (wr->wr_opcode == IBT_WRC_SEND_LSO) {
			int total_len;

			total_len = (4 + 0xf + wr->wr.ud_lso.lso_hdr_sz) & ~0xf;
			if ((uintptr_t)ds + total_len + (nds * 16) >
			    (uintptr_t)desc + (1 << qp->qp_sq_log_wqesz))
				return (IBT_QP_SGL_LEN_INVALID);

			bcopy(wr->wr.ud_lso.lso_hdr, (uint32_t *)ds + 1,
			    wr->wr.ud_lso.lso_hdr_sz);
			old_ds = ds;
			ds = (hermon_hw_wqe_sgl_t *)((uintptr_t)ds + total_len);
			for (; i < nds; i++) {
				if (sgl[i].ds_len == 0)
					continue;
				HERMON_WQE_BUILD_DATA_SEG_SEND(&ds[num_ds],
				    &sgl[i]);
				num_ds++;
				i++;
				break;
			}
			membar_producer();
			HERMON_WQE_BUILD_LSO(qp, old_ds, wr->wr.ud_lso.lso_mss,
			    wr->wr.ud_lso.lso_hdr_sz);
		}

		break;

	case IBT_RC_SRV:
		/* Ensure that work request transport type matches QP type */
		if (qp->qp_serv_type != HERMON_QP_RC) {
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
			rc = (hermon_hw_snd_wqe_remaddr_t *)((uintptr_t)desc +
			    sizeof (hermon_hw_snd_wqe_ctrl_t));

			/*
			 * Build the Remote Address Segment for the WQE, using
			 * the information from the RC work request.
			 */
			HERMON_WQE_BUILD_REMADDR(qp, rc, &wr->wr.rc.rcwr.rdma);

			/* Update "ds" for filling in Data Segments (below) */
			ds = (hermon_hw_wqe_sgl_t *)((uintptr_t)rc +
			    sizeof (hermon_hw_snd_wqe_remaddr_t));
			break;
		}

		/*
		 * If this is one of the Atomic type operations (i.e
		 * Compare-Swap or Fetch-Add), then fill in both the "Remote
		 * Address" header fields and the "Atomic" header fields.
		 */
		if ((wr->wr_opcode == IBT_WRC_CSWAP) ||
		    (wr->wr_opcode == IBT_WRC_FADD)) {
			rc = (hermon_hw_snd_wqe_remaddr_t *)((uintptr_t)desc +
			    sizeof (hermon_hw_snd_wqe_ctrl_t));
			at = (hermon_hw_snd_wqe_atomic_t *)((uintptr_t)rc +
			    sizeof (hermon_hw_snd_wqe_remaddr_t));

			/*
			 * Build the Remote Address and Atomic Segments for
			 * the WQE, using the information from the RC Atomic
			 * work request.
			 */
			HERMON_WQE_BUILD_RC_ATOMIC_REMADDR(qp, rc, wr);
			HERMON_WQE_BUILD_ATOMIC(qp, at, wr->wr.rc.rcwr.atomic);

			/* Update "ds" for filling in Data Segments (below) */
			ds = (hermon_hw_wqe_sgl_t *)((uintptr_t)at +
			    sizeof (hermon_hw_snd_wqe_atomic_t));

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
		 * hermon_wr_bind_check() routine to validate the request and
		 * to generate the updated RKey.  If this is successful, then
		 * we fill in the WQE's "Bind" header fields.
		 */
		if (wr->wr_opcode == IBT_WRC_BIND) {
			status = hermon_wr_bind_check(state, wr);
			if (status != DDI_SUCCESS) {
				return (status);
			}

			bn = (hermon_hw_snd_wqe_bind_t *)((uintptr_t)desc +
			    sizeof (hermon_hw_snd_wqe_ctrl_t));

			/*
			 * Build the Bind Memory Window Segments for the WQE,
			 * using the information from the RC Bind memory
			 * window work request.
			 */
			HERMON_WQE_BUILD_BIND(qp, bn, wr->wr.rc.rcwr.bind);

			/*
			 * Update the "ds" pointer.  Even though the "bind"
			 * operation requires no SGLs, this is necessary to
			 * facilitate the correct descriptor size calculations
			 * (below).
			 */
			ds = (hermon_hw_wqe_sgl_t *)((uintptr_t)bn +
			    sizeof (hermon_hw_snd_wqe_bind_t));
			nds = 0;
		}
		break;

	case IBT_UC_SRV:
		/* Ensure that work request transport type matches QP type */
		if (qp->qp_serv_type != HERMON_QP_UC) {
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
			uc = (hermon_hw_snd_wqe_remaddr_t *)((uintptr_t)desc +
			    sizeof (hermon_hw_snd_wqe_ctrl_t));

			/*
			 * Build the Remote Address Segment for the WQE, using
			 * the information from the UC work request.
			 */
			HERMON_WQE_BUILD_REMADDR(qp, uc, &wr->wr.uc.ucwr.rdma);

			/* Update "ds" for filling in Data Segments (below) */
			ds = (hermon_hw_wqe_sgl_t *)((uintptr_t)uc +
			    sizeof (hermon_hw_snd_wqe_remaddr_t));
			break;
		}

		/*
		 * If this is memory window Bind operation, then we call the
		 * hermon_wr_bind_check() routine to validate the request and
		 * to generate the updated RKey.  If this is successful, then
		 * we fill in the WQE's "Bind" header fields.
		 */
		if (wr->wr_opcode == IBT_WRC_BIND) {
			status = hermon_wr_bind_check(state, wr);
			if (status != DDI_SUCCESS) {
				return (status);
			}

			bn = (hermon_hw_snd_wqe_bind_t *)((uintptr_t)desc +
			    sizeof (hermon_hw_snd_wqe_ctrl_t));

			/*
			 * Build the Bind Memory Window Segments for the WQE,
			 * using the information from the UC Bind memory
			 * window work request.
			 */
			HERMON_WQE_BUILD_BIND(qp, bn, wr->wr.uc.ucwr.bind);

			/*
			 * Update the "ds" pointer.  Even though the "bind"
			 * operation requires no SGLs, this is necessary to
			 * facilitate the correct descriptor size calculations
			 * (below).
			 */
			ds = (hermon_hw_wqe_sgl_t *)((uintptr_t)bn +
			    sizeof (hermon_hw_snd_wqe_bind_t));
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
	 * segments.  Note: We skip any SGL with zero size because Hermon
	 * hardware cannot handle a zero for "byte_cnt" in the WQE.  Actually
	 * the encoding for zero means a 2GB transfer.
	 */
	for (last_ds = num_ds, j = i; j < nds; j++) {
		if (sgl[j].ds_len != 0)
			last_ds++;	/* real last ds of wqe to fill */
	}

	/*
	 * Return the size of descriptor (in 16-byte chunks)
	 * For Hermon, we want them (for now) to be on stride size
	 * boundaries, which was implicit in Tavor/Arbel
	 *
	 */
	tmpsize = ((uintptr_t)&ds[last_ds] - (uintptr_t)desc);

	*size = tmpsize >> 0x4;

	for (j = nds; --j >= i; ) {
		if (sgl[j].ds_len == 0) {
			continue;
		}

		/*
		 * Fill in the Data Segment(s) for the current WQE, using the
		 * information contained in the scatter-gather list of the
		 * work request.
		 */
		last_ds--;
		HERMON_WQE_BUILD_DATA_SEG_SEND(&ds[last_ds], &sgl[j]);
	}

	return (DDI_SUCCESS);
}



/*
 * hermon_wqe_mlx_build()
 *    Context: Can be called from interrupt or base context.
 */
static int
hermon_wqe_mlx_build(hermon_state_t *state, hermon_qphdl_t qp,
    ibt_send_wr_t *wr, uint64_t *desc, uint_t *size)
{
	hermon_ahhdl_t		ah;
	hermon_hw_udav_t	*udav;
	ib_lrh_hdr_t		*lrh;
	ib_grh_t		*grh;
	ib_bth_hdr_t		*bth;
	ib_deth_hdr_t		*deth;
	hermon_hw_wqe_sgl_t	*ds;
	ibt_wr_ds_t		*sgl;
	uint8_t			*mgmtclass, *hpoint, *hcount;
	uint32_t		nds, offset, pktlen;
	uint32_t		desc_sz;
	int			i, num_ds;
	int			tmpsize;

	ASSERT(MUTEX_HELD(&qp->qp_sq_lock));

	/* Initialize the information for the Data Segments */
	ds = (hermon_hw_wqe_sgl_t *)((uintptr_t)desc +
	    sizeof (hermon_hw_mlx_wqe_nextctrl_t));

	/*
	 * Pull the address handle from the work request. The UDAV will
	 * be used to answer some questions about the request.
	 */
	ah = (hermon_ahhdl_t)wr->wr.ud.udwr_dest->ud_ah;
	if (ah == NULL) {
		return (IBT_AH_HDL_INVALID);
	}
	mutex_enter(&ah->ah_lock);
	udav = ah->ah_udav;

	/*
	 * If the request is for QP1 and the destination LID is equal to
	 * the Permissive LID, then return an error.  This combination is
	 * not allowed
	 */
	if ((udav->rlid == IB_LID_PERMISSIVE) &&
	    (qp->qp_is_special == HERMON_QP_GSI)) {
		mutex_exit(&ah->ah_lock);
		return (IBT_AH_HDL_INVALID);
	}

	/*
	 * Calculate the size of the packet headers, including the GRH
	 * (if necessary)
	 */
	desc_sz = sizeof (ib_lrh_hdr_t) + sizeof (ib_bth_hdr_t) +
	    sizeof (ib_deth_hdr_t);
	if (udav->grh) {
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
	HERMON_WQE_BUILD_INLINE(qp, &ds[0], desc_sz);
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
	HERMON_WQE_BUILD_MLX_LRH(lrh, qp, udav, pktlen);

	/*
	 * Build Global Route Header (GRH)
	 *    This is only built if necessary as defined by the "grh" bit in
	 *    the address vector.  Note:  We also calculate the offset to the
	 *    next header (BTH) based on whether or not the "grh" bit is set.
	 */
	if (udav->grh) {
		/*
		 * If the request is for QP0, then return an error.  The
		 * combination of global routine (GRH) and QP0 is not allowed.
		 */
		if (qp->qp_is_special == HERMON_QP_SMI) {
			mutex_exit(&ah->ah_lock);
			return (IBT_AH_HDL_INVALID);
		}
		grh = (ib_grh_t *)((uintptr_t)lrh + sizeof (ib_lrh_hdr_t));
		HERMON_WQE_BUILD_MLX_GRH(state, grh, qp, udav, pktlen);

		bth = (ib_bth_hdr_t *)((uintptr_t)grh + sizeof (ib_grh_t));
	} else {
		bth = (ib_bth_hdr_t *)((uintptr_t)lrh + sizeof (ib_lrh_hdr_t));
	}
	mutex_exit(&ah->ah_lock);


	/*
	 * Build Base Transport Header (BTH)
	 *    Notice that the M, PadCnt, and TVer fields are all set
	 *    to zero implicitly.  This is true for all Management Datagrams
	 *    MADs whether GSI are SMI.
	 */
	HERMON_WQE_BUILD_MLX_BTH(state, bth, qp, wr);

	/*
	 * Build Datagram Extended Transport Header (DETH)
	 */
	deth = (ib_deth_hdr_t *)((uintptr_t)bth + sizeof (ib_bth_hdr_t));
	HERMON_WQE_BUILD_MLX_DETH(deth, qp);

	/* Ensure that the Data Segment is aligned on a 16-byte boundary */
	ds = (hermon_hw_wqe_sgl_t *)((uintptr_t)deth + sizeof (ib_deth_hdr_t));
	ds = (hermon_hw_wqe_sgl_t *)(((uintptr_t)ds + 0xF) & ~0xF);
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
	 * segments.  Note: We skip any SGL with zero size because Hermon
	 * hardware cannot handle a zero for "byte_cnt" in the WQE.  Actually
	 * the encoding for zero means a 2GB transfer.  Because of this special
	 * encoding in the hardware, we mask the requested length with
	 * HERMON_WQE_SGL_BYTE_CNT_MASK (so that 2GB will end up encoded as
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
		HERMON_WQE_BUILD_DATA_SEG_SEND(&ds[num_ds], &sgl[i]);

		/*
		 * Search through the contents of all MADs posted to QP0 to
		 * initialize pointers to the places where Directed Route "hop
		 * pointer", "hop count", and "mgmtclass" would be.  Hermon
		 * needs these updated (i.e. incremented or decremented, as
		 * necessary) by software.
		 */
		if (qp->qp_is_special == HERMON_QP_SMI) {

			HERMON_SPECIAL_QP_DRMAD_GET_MGMTCLASS(mgmtclass,
			    offset, sgl[i].ds_va, sgl[i].ds_len);

			HERMON_SPECIAL_QP_DRMAD_GET_HOPPOINTER(hpoint,
			    offset, sgl[i].ds_va, sgl[i].ds_len);

			HERMON_SPECIAL_QP_DRMAD_GET_HOPCOUNT(hcount,
			    offset, sgl[i].ds_va, sgl[i].ds_len);

			offset += sgl[i].ds_len;
		}
		num_ds++;
	}

	/*
	 * Hermon's Directed Route MADs need to have the "hop pointer"
	 * incremented/decremented (as necessary) depending on whether it is
	 * currently less than or greater than the "hop count" (i.e. whether
	 * the MAD is a request or a response.)
	 */
	if (qp->qp_is_special == HERMON_QP_SMI) {
		HERMON_SPECIAL_QP_DRMAD_DO_HOPPOINTER_MODIFY(*mgmtclass,
		    *hpoint, *hcount);
	}

	/*
	 * Now fill in the ICRC Data Segment.  This data segment is inlined
	 * just like the packets headers above, but it is only four bytes and
	 * set to zero (to indicate that we wish the hardware to generate ICRC.
	 */
	HERMON_WQE_BUILD_INLINE_ICRC(qp, &ds[num_ds], 4, 0);
	num_ds++;

	/*
	 * Return the size of descriptor (in 16-byte chunks)
	 * For Hermon, we want them (for now) to be on stride size
	 * boundaries, which was implicit in Tavor/Arbel
	 */
	tmpsize = ((uintptr_t)&ds[num_ds] - (uintptr_t)desc);

	*size = tmpsize >> 0x04;

	return (DDI_SUCCESS);
}



/*
 * hermon_wqe_recv_build()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static int
hermon_wqe_recv_build(hermon_state_t *state, hermon_qphdl_t qp,
    ibt_recv_wr_t *wr, uint64_t *desc)
{
	hermon_hw_wqe_sgl_t	*ds;
	int			i, num_ds;

	ASSERT(MUTEX_HELD(&qp->qp_rq_lock));

	/*
	 * Fill in the Data Segments (SGL) for the Recv WQE  - don't
	 * need to have a reserved for the ctrl, there is none on the
	 * recv queue for hermon, but will need to put an invalid
	 * (null) scatter pointer per PRM
	 */
	ds = (hermon_hw_wqe_sgl_t *)(uintptr_t)desc;
	num_ds = 0;

	/* Check for valid number of SGL entries */
	if (wr->wr_nds > qp->qp_rq_sgl) {
		return (IBT_QP_SGL_LEN_INVALID);
	}

	/*
	 * For each SGL in the Recv Work Request, fill in the Recv WQE's data
	 * segments.  Note: We skip any SGL with zero size because Hermon
	 * hardware cannot handle a zero for "byte_cnt" in the WQE.  Actually
	 * the encoding for zero means a 2GB transfer.  Because of this special
	 * encoding in the hardware, we mask the requested length with
	 * HERMON_WQE_SGL_BYTE_CNT_MASK (so that 2GB will end up encoded as
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
		HERMON_WQE_BUILD_DATA_SEG_RECV(&ds[num_ds], &wr->wr_sgl[i]);
		num_ds++;
	}

	/* put the null sgl pointer as well if needed */
	if (num_ds < qp->qp_rq_sgl) {
		HERMON_WQE_BUILD_DATA_SEG_RECV(&ds[num_ds], &null_sgl);
	}

	return (DDI_SUCCESS);
}



/*
 * hermon_wqe_srq_build()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static int
hermon_wqe_srq_build(hermon_state_t *state, hermon_srqhdl_t srq,
    ibt_recv_wr_t *wr, uint64_t *desc)
{
	hermon_hw_wqe_sgl_t	*ds;
	int			i, num_ds;

	ASSERT(MUTEX_HELD(&srq->srq_lock));

	/* Fill in the Data Segments (SGL) for the Recv WQE */
	ds = (hermon_hw_wqe_sgl_t *)((uintptr_t)desc +
	    sizeof (hermon_hw_srq_wqe_next_t));
	num_ds = 0;

	/* Check for valid number of SGL entries */
	if (wr->wr_nds > srq->srq_wq_sgl) {
		return (IBT_QP_SGL_LEN_INVALID);
	}

	/*
	 * For each SGL in the Recv Work Request, fill in the Recv WQE's data
	 * segments.  Note: We skip any SGL with zero size because Hermon
	 * hardware cannot handle a zero for "byte_cnt" in the WQE.  Actually
	 * the encoding for zero means a 2GB transfer.  Because of this special
	 * encoding in the hardware, we mask the requested length with
	 * HERMON_WQE_SGL_BYTE_CNT_MASK (so that 2GB will end up encoded as
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
		HERMON_WQE_BUILD_DATA_SEG_RECV(&ds[num_ds], &wr->wr_sgl[i]);
		num_ds++;
	}

	/*
	 * put in the null sgl pointer as well, if needed
	 */
	if (num_ds < srq->srq_wq_sgl) {
		HERMON_WQE_BUILD_DATA_SEG_RECV(&ds[num_ds], &null_sgl);
	}

	return (DDI_SUCCESS);
}


/*
 * hermon_wr_get_immediate()
 *    Context: Can be called from interrupt or base context.
 */
static uint32_t
hermon_wr_get_immediate(ibt_send_wr_t *wr)
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
 * hermon_wqe_headroom()
 *	Context: can be called from interrupt or base, currently only from
 *	base context.
 * Routine that fills in the headroom for the Send Queue
 */

static void
hermon_wqe_headroom(uint_t from, hermon_qphdl_t qp)
{
	uint32_t	*wqe_start, *wqe_top, *wqe_base, qsize;
	int		hdrmwqes, wqesizebytes, sectperwqe;
	uint32_t	invalue;
	int		i, j;

	qsize	 = qp->qp_sq_bufsz;
	wqesizebytes = 1 << qp->qp_sq_log_wqesz;
	sectperwqe = wqesizebytes >> 6; 	/* 64 bytes/section */
	hdrmwqes = qp->qp_sq_hdrmwqes;
	wqe_base  = (uint32_t *)HERMON_QP_SQ_ENTRY(qp, 0);
	wqe_top	  = (uint32_t *)HERMON_QP_SQ_ENTRY(qp, qsize);
	wqe_start = (uint32_t *)HERMON_QP_SQ_ENTRY(qp, from);

	for (i = 0; i < hdrmwqes; i++)	{
		for (j = 0; j < sectperwqe; j++) {
			if (j == 0) {		/* 1st section of wqe */
				/* perserve ownership bit */
				invalue = ddi_get32(qp->qp_wqinfo.qa_acchdl,
				    wqe_start) | 0x7FFFFFFF;
			} else {
				/* or just invalidate it */
				invalue = 0xFFFFFFFF;
			}
			ddi_put32(qp->qp_wqinfo.qa_acchdl, wqe_start, invalue);
			wqe_start += 16;	/* move 64 bytes */
		}
		if (wqe_start == wqe_top)	/* hit the end of the queue */
			wqe_start = wqe_base;	/* wrap to start */
	}
}

/*
 * hermon_wqe_sync()
 *    Context: Can be called from interrupt or base context.
 */
static void
hermon_wqe_sync(void *hdl, uint_t sync_from, uint_t sync_to,
    uint_t sync_type, uint_t flag)
{
	hermon_qphdl_t		qp;
	hermon_srqhdl_t		srq;
	uint64_t		*wqe_from, *wqe_to;
	uint64_t		*wq_base, *wq_top, *qp_base;
	ddi_dma_handle_t	dmahdl;
	off_t			offset;
	size_t			length;
	uint32_t		qsize;
	int			status;

	if (sync_type == HERMON_WR_SRQ) {
		srq = (hermon_srqhdl_t)hdl;
		/* Get the DMA handle from SRQ context */
		dmahdl = srq->srq_mrhdl->mr_bindinfo.bi_dmahdl;
		/* get base addr of the buffer */
		qp_base = (uint64_t *)(void *)srq->srq_wq_buf;
	} else {
		qp = (hermon_qphdl_t)hdl;
		/* Get the DMA handle from QP context */
		dmahdl = qp->qp_mrhdl->mr_bindinfo.bi_dmahdl;
		/* Determine the base address of the QP buffer */
		if (qp->qp_sq_baseaddr == 0) {
			qp_base = (uint64_t *)(void *)(qp->qp_sq_buf);
		} else {
			qp_base = (uint64_t *)(void *)(qp->qp_rq_buf);
		}
	}

	/*
	 * Depending on the type of the work queue, we grab information
	 * about the address ranges we need to DMA sync.
	 */

	if (sync_type == HERMON_WR_SEND) {
		wqe_from = HERMON_QP_SQ_ENTRY(qp, sync_from);
		wqe_to   = HERMON_QP_SQ_ENTRY(qp, sync_to);
		qsize	 = qp->qp_sq_bufsz;

		wq_base = HERMON_QP_SQ_ENTRY(qp, 0);
		wq_top	 = HERMON_QP_SQ_ENTRY(qp, qsize);
	} else if (sync_type == HERMON_WR_RECV) {
		wqe_from = HERMON_QP_RQ_ENTRY(qp, sync_from);
		wqe_to   = HERMON_QP_RQ_ENTRY(qp, sync_to);
		qsize	 = qp->qp_rq_bufsz;

		wq_base = HERMON_QP_RQ_ENTRY(qp, 0);
		wq_top	 = HERMON_QP_RQ_ENTRY(qp, qsize);
	} else {
		wqe_from = HERMON_SRQ_WQ_ENTRY(srq, sync_from);
		wqe_to   = HERMON_SRQ_WQ_ENTRY(srq, sync_to);
		qsize	 = srq->srq_wq_bufsz;

		wq_base = HERMON_SRQ_WQ_ENTRY(srq, 0);
		wq_top	 = HERMON_SRQ_WQ_ENTRY(srq, qsize);
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

		offset = (off_t)((uintptr_t)wqe_from - (uintptr_t)qp_base);
		length = (size_t)((uintptr_t)wqe_to - (uintptr_t)wqe_from);

		status = ddi_dma_sync(dmahdl, offset, length, flag);
		if (status != DDI_SUCCESS) {
			return;
		}
	} else {
		/* "From Top to End" */

		offset = (off_t)((uintptr_t)wq_base - (uintptr_t)qp_base);
		length = (size_t)((uintptr_t)wqe_to - (uintptr_t)wq_base);
		if (length) {
			status = ddi_dma_sync(dmahdl, offset, length, flag);
			if (status != DDI_SUCCESS) {
				return;
			}
		}

		/* "From Beginning to Bottom" */

		offset = (off_t)((uintptr_t)wqe_from - (uintptr_t)qp_base);
		length = (size_t)((uintptr_t)wq_top - (uintptr_t)wqe_from);
		status = ddi_dma_sync(dmahdl, offset, length, flag);
		if (status != DDI_SUCCESS) {
			return;
		}
	}
}


/*
 * hermon_wr_bind_check()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static int
hermon_wr_bind_check(hermon_state_t *state, ibt_send_wr_t *wr)
{
	ibt_bind_flags_t	bind_flags;
	uint64_t		vaddr, len;
	uint64_t		reg_start_addr, reg_end_addr;
	hermon_mwhdl_t		mw;
	hermon_mrhdl_t		mr;
	hermon_rsrc_t		*mpt;
	uint32_t		new_rkey;

	/* Check for a valid Memory Window handle in the WR */
	mw = (hermon_mwhdl_t)wr->wr.rc.rcwr.bind->bind_ibt_mw_hdl;
	if (mw == NULL) {
		return (IBT_MW_HDL_INVALID);
	}

	/* Check for a valid Memory Region handle in the WR */
	mr = (hermon_mrhdl_t)wr->wr.rc.rcwr.bind->bind_ibt_mr_hdl;
	if (mr == NULL) {
		return (IBT_MR_HDL_INVALID);
	}

	mutex_enter(&mr->mr_lock);
	mutex_enter(&mw->mr_lock);

	/*
	 * Check here to see if the memory region has already been partially
	 * deregistered as a result of a hermon_umap_umemlock_cb() callback.
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
	new_rkey = hermon_mr_keycalc(mpt->hr_indx);
	new_rkey = hermon_mr_key_swap(new_rkey);

	wr->wr.rc.rcwr.bind->bind_rkey_out = new_rkey;
	mw->mr_rkey = new_rkey;

	mutex_exit(&mr->mr_lock);
	mutex_exit(&mw->mr_lock);
	return (DDI_SUCCESS);
}


/*
 * hermon_wrid_from_reset_handling()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
int
hermon_wrid_from_reset_handling(hermon_state_t *state, hermon_qphdl_t qp)
{
	hermon_workq_hdr_t	*swq, *rwq;
	uint_t			qp_srq_en;

	if (qp->qp_is_umap)
		return (DDI_SUCCESS);

	/* grab the cq lock(s) to modify the wqavl tree */
	mutex_enter(&qp->qp_rq_cqhdl->cq_lock);
#ifdef __lock_lint
	mutex_enter(&qp->qp_sq_cqhdl->cq_lock);
#else
	if (qp->qp_rq_cqhdl != qp->qp_sq_cqhdl)
		mutex_enter(&qp->qp_sq_cqhdl->cq_lock);
#endif

	/* Chain the newly allocated work queue header to the CQ's list */
	hermon_cq_workq_add(qp->qp_sq_cqhdl, &qp->qp_sq_wqavl);

	swq = qp->qp_sq_wqhdr;
	swq->wq_head = 0;
	swq->wq_tail = 0;
	swq->wq_full = 0;

	/*
	 * Now we repeat all the above operations for the receive work queue,
	 * or shared receive work queue.
	 *
	 * Note: We still use the 'qp_rq_cqhdl' even in the SRQ case.
	 */
	qp_srq_en = qp->qp_srq_en;

#ifdef __lock_lint
	mutex_enter(&qp->qp_srqhdl->srq_lock);
#else
	if (qp_srq_en == HERMON_QP_SRQ_ENABLED) {
		mutex_enter(&qp->qp_srqhdl->srq_lock);
	} else {
		rwq = qp->qp_rq_wqhdr;
		rwq->wq_head = 0;
		rwq->wq_tail = 0;
		rwq->wq_full = 0;
		qp->qp_rq_wqecntr = 0;
	}
#endif
	hermon_cq_workq_add(qp->qp_rq_cqhdl, &qp->qp_rq_wqavl);

#ifdef __lock_lint
	mutex_exit(&qp->qp_srqhdl->srq_lock);
#else
	if (qp_srq_en == HERMON_QP_SRQ_ENABLED) {
		mutex_exit(&qp->qp_srqhdl->srq_lock);
	}
#endif

#ifdef __lock_lint
	mutex_exit(&qp->qp_sq_cqhdl->cq_lock);
#else
	if (qp->qp_rq_cqhdl != qp->qp_sq_cqhdl)
		mutex_exit(&qp->qp_sq_cqhdl->cq_lock);
#endif
	mutex_exit(&qp->qp_rq_cqhdl->cq_lock);
	return (DDI_SUCCESS);
}


/*
 * hermon_wrid_to_reset_handling()
 *    Context: Can be called from interrupt or base context.
 */
int
hermon_wrid_to_reset_handling(hermon_state_t *state, hermon_qphdl_t qp)
{
	uint_t			qp_srq_en;

	if (qp->qp_is_umap)
		return (DDI_SUCCESS);

	/*
	 * If there are unpolled entries in these CQs, they are
	 * polled/flushed.
	 * Grab the CQ lock(s) before manipulating the lists.
	 */
	mutex_enter(&qp->qp_rq_cqhdl->cq_lock);
#ifdef __lock_lint
	mutex_enter(&qp->qp_sq_cqhdl->cq_lock);
#else
	if (qp->qp_rq_cqhdl != qp->qp_sq_cqhdl)
		mutex_enter(&qp->qp_sq_cqhdl->cq_lock);
#endif

	qp_srq_en = qp->qp_srq_en;
#ifdef __lock_lint
	mutex_enter(&qp->qp_srqhdl->srq_lock);
#else
	if (qp_srq_en == HERMON_QP_SRQ_ENABLED) {
		mutex_enter(&qp->qp_srqhdl->srq_lock);
	}
#endif
	/*
	 * Flush the entries on the CQ for this QP's QPN.
	 */
	hermon_cq_entries_flush(state, qp);

#ifdef __lock_lint
	mutex_exit(&qp->qp_srqhdl->srq_lock);
#else
	if (qp_srq_en == HERMON_QP_SRQ_ENABLED) {
		mutex_exit(&qp->qp_srqhdl->srq_lock);
	}
#endif

	hermon_cq_workq_remove(qp->qp_rq_cqhdl, &qp->qp_rq_wqavl);
	hermon_cq_workq_remove(qp->qp_sq_cqhdl, &qp->qp_sq_wqavl);

#ifdef __lock_lint
	mutex_exit(&qp->qp_sq_cqhdl->cq_lock);
#else
	if (qp->qp_rq_cqhdl != qp->qp_sq_cqhdl)
		mutex_exit(&qp->qp_sq_cqhdl->cq_lock);
#endif
	mutex_exit(&qp->qp_rq_cqhdl->cq_lock);

	return (IBT_SUCCESS);
}


/*
 * hermon_wrid_get_entry()
 *    Context: Can be called from interrupt or base context.
 */
uint64_t
hermon_wrid_get_entry(hermon_cqhdl_t cq, hermon_hw_cqe_t *cqe)
{
	hermon_workq_avl_t	*wqa;
	hermon_workq_hdr_t	*wq;
	uint64_t		wrid;
	uint_t			send_or_recv, qpnum;
	uint32_t		indx;

	/*
	 * Determine whether this CQE is a send or receive completion.
	 */
	send_or_recv = HERMON_CQE_SENDRECV_GET(cq, cqe);

	/* Find the work queue for this QP number (send or receive side) */
	qpnum = HERMON_CQE_QPNUM_GET(cq, cqe);
	wqa = hermon_wrid_wqavl_find(cq, qpnum, send_or_recv);
	wq = wqa->wqa_wq;

	/*
	 * Regardless of whether the completion is the result of a "success"
	 * or a "failure", we lock the list of "containers" and attempt to
	 * search for the the first matching completion (i.e. the first WR
	 * with a matching WQE addr and size).  Once we find it, we pull out
	 * the "wrid" field and return it (see below).  XXX Note: One possible
	 * future enhancement would be to enable this routine to skip over
	 * any "unsignaled" completions to go directly to the next "signaled"
	 * entry on success.
	 */
	indx = HERMON_CQE_WQEADDRSZ_GET(cq, cqe) & wq->wq_mask;
	wrid = wq->wq_wrid[indx];
	if (wqa->wqa_srq_en) {
		struct hermon_sw_srq_s	*srq;
		uint64_t		*desc;

		/* put wqe back on the srq free list */
		srq = wqa->wqa_srq;
		mutex_enter(&srq->srq_lock);
		desc = HERMON_SRQ_WQE_ADDR(srq, wq->wq_tail);
		((uint16_t *)desc)[1] = htons(indx);
		wq->wq_tail = indx;
		mutex_exit(&srq->srq_lock);
	} else {
		wq->wq_head = (indx + 1) & wq->wq_mask;
		wq->wq_full = 0;
	}

	return (wrid);
}


int
hermon_wrid_workq_compare(const void *p1, const void *p2)
{
	hermon_workq_compare_t	*cmpp;
	hermon_workq_avl_t	*curr;

	cmpp = (hermon_workq_compare_t *)p1;
	curr = (hermon_workq_avl_t *)p2;

	if (cmpp->cmp_qpn < curr->wqa_qpn)
		return (-1);
	else if (cmpp->cmp_qpn > curr->wqa_qpn)
		return (+1);
	else if (cmpp->cmp_type < curr->wqa_type)
		return (-1);
	else if (cmpp->cmp_type > curr->wqa_type)
		return (+1);
	else
		return (0);
}


/*
 * hermon_wrid_workq_find()
 *    Context: Can be called from interrupt or base context.
 */
static hermon_workq_avl_t *
hermon_wrid_wqavl_find(hermon_cqhdl_t cq, uint_t qpn, uint_t wq_type)
{
	hermon_workq_avl_t	*curr;
	hermon_workq_compare_t	cmp;

	/*
	 * Walk the CQ's work queue list, trying to find a send or recv queue
	 * with the same QP number.  We do this even if we are going to later
	 * create a new entry because it helps us easily find the end of the
	 * list.
	 */
	cmp.cmp_qpn = qpn;
	cmp.cmp_type = wq_type;
#ifdef __lock_lint
	hermon_wrid_workq_compare(NULL, NULL);
#endif
	curr = avl_find(&cq->cq_wrid_wqhdr_avl_tree, &cmp, NULL);

	return (curr);
}


/*
 * hermon_wrid_wqhdr_create()
 *    Context: Can be called from base context.
 */
/* ARGSUSED */
hermon_workq_hdr_t *
hermon_wrid_wqhdr_create(int bufsz)
{
	hermon_workq_hdr_t	*wqhdr;

	/*
	 * Allocate space for the wqhdr, and an array to record all the wrids.
	 */
	wqhdr = (hermon_workq_hdr_t *)kmem_zalloc(sizeof (*wqhdr), KM_NOSLEEP);
	if (wqhdr == NULL) {
		return (NULL);
	}
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*wqhdr))
	wqhdr->wq_wrid = kmem_zalloc(bufsz * sizeof (uint64_t), KM_NOSLEEP);
	if (wqhdr->wq_wrid == NULL) {
		kmem_free(wqhdr, sizeof (*wqhdr));
		return (NULL);
	}
	wqhdr->wq_size = bufsz;
	wqhdr->wq_mask = bufsz - 1;

	return (wqhdr);
}

void
hermon_wrid_wqhdr_destroy(hermon_workq_hdr_t *wqhdr)
{
	kmem_free(wqhdr->wq_wrid, wqhdr->wq_size * sizeof (uint64_t));
	kmem_free(wqhdr, sizeof (*wqhdr));
}


/*
 * hermon_cq_workq_add()
 *    Context: Can be called from interrupt or base context.
 */
static void
hermon_cq_workq_add(hermon_cqhdl_t cq, hermon_workq_avl_t *wqavl)
{
	hermon_workq_compare_t	cmp;
	avl_index_t		where;

	cmp.cmp_qpn = wqavl->wqa_qpn;
	cmp.cmp_type = wqavl->wqa_type;
#ifdef __lock_lint
	hermon_wrid_workq_compare(NULL, NULL);
#endif
	(void) avl_find(&cq->cq_wrid_wqhdr_avl_tree, &cmp, &where);
	avl_insert(&cq->cq_wrid_wqhdr_avl_tree, wqavl, where);
}


/*
 * hermon_cq_workq_remove()
 *    Context: Can be called from interrupt or base context.
 */
static void
hermon_cq_workq_remove(hermon_cqhdl_t cq, hermon_workq_avl_t *wqavl)
{
#ifdef __lock_lint
	hermon_wrid_workq_compare(NULL, NULL);
#endif
	avl_remove(&cq->cq_wrid_wqhdr_avl_tree, wqavl);
}
