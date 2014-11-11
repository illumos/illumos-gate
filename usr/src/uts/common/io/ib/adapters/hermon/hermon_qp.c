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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * hermon_qp.c
 *    Hermon Queue Pair Processing Routines
 *
 *    Implements all the routines necessary for allocating, freeing, and
 *    querying the Hermon queue pairs.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/bitmap.h>
#include <sys/sysmacros.h>

#include <sys/ib/adapters/hermon/hermon.h>
#include <sys/ib/ib_pkt_hdrs.h>

static int hermon_qp_create_qpn(hermon_state_t *state, hermon_qphdl_t qp,
    hermon_rsrc_t *qpc);
static int hermon_qpn_avl_compare(const void *q, const void *e);
static int hermon_special_qp_rsrc_alloc(hermon_state_t *state,
    ibt_sqp_type_t type, uint_t port, hermon_rsrc_t **qp_rsrc);
static int hermon_special_qp_rsrc_free(hermon_state_t *state,
    ibt_sqp_type_t type, uint_t port);
static void hermon_qp_sgl_to_logwqesz(hermon_state_t *state, uint_t num_sgl,
    uint_t real_max_sgl, hermon_qp_wq_type_t wq_type,
    uint_t *logwqesz, uint_t *max_sgl);

/*
 * hermon_qp_alloc()
 *    Context: Can be called only from user or kernel context.
 */
int
hermon_qp_alloc(hermon_state_t *state, hermon_qp_info_t *qpinfo,
    uint_t sleepflag)
{
	hermon_rsrc_t			*qpc, *rsrc;
	hermon_rsrc_type_t		rsrc_type;
	hermon_umap_db_entry_t		*umapdb;
	hermon_qphdl_t			qp;
	ibt_qp_alloc_attr_t		*attr_p;
	ibt_qp_alloc_flags_t		alloc_flags;
	ibt_qp_type_t			type;
	hermon_qp_wq_type_t		swq_type;
	ibtl_qp_hdl_t			ibt_qphdl;
	ibt_chan_sizes_t		*queuesz_p;
	ib_qpn_t			*qpn;
	hermon_qphdl_t			*qphdl;
	ibt_mr_attr_t			mr_attr;
	hermon_mr_options_t		mr_op;
	hermon_srqhdl_t			srq;
	hermon_pdhdl_t			pd;
	hermon_cqhdl_t			sq_cq, rq_cq;
	hermon_mrhdl_t			mr;
	uint64_t			value, qp_desc_off;
	uint64_t			*thewqe, thewqesz;
	uint32_t			*sq_buf, *rq_buf;
	uint32_t			log_qp_sq_size, log_qp_rq_size;
	uint32_t			sq_size, rq_size;
	uint32_t			sq_depth, rq_depth;
	uint32_t			sq_wqe_size, rq_wqe_size, wqesz_shift;
	uint32_t			max_sgl, max_recv_sgl, uarpg;
	uint_t				qp_is_umap;
	uint_t				qp_srq_en, i, j;
	int				status, flag;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*attr_p, *queuesz_p))

	/*
	 * Extract the necessary info from the hermon_qp_info_t structure
	 */
	attr_p	  = qpinfo->qpi_attrp;
	type	  = qpinfo->qpi_type;
	ibt_qphdl = qpinfo->qpi_ibt_qphdl;
	queuesz_p = qpinfo->qpi_queueszp;
	qpn	  = qpinfo->qpi_qpn;
	qphdl	  = &qpinfo->qpi_qphdl;
	alloc_flags = attr_p->qp_alloc_flags;

	/*
	 * Verify correctness of alloc_flags.
	 *
	 * 1. FEXCH and RSS are only allocated via qp_range.
	 */
	if (alloc_flags & (IBT_QP_USES_FEXCH | IBT_QP_USES_RSS)) {
		return (IBT_INVALID_PARAM);
	}
	rsrc_type = HERMON_QPC;
	qp_is_umap = 0;

	/* 2. Make sure only one of these flags is set. */
	switch (alloc_flags &
	    (IBT_QP_USER_MAP | IBT_QP_USES_RFCI | IBT_QP_USES_FCMD)) {
	case IBT_QP_USER_MAP:
		qp_is_umap = 1;
		break;
	case IBT_QP_USES_RFCI:
		if (type != IBT_UD_RQP)
			return (IBT_INVALID_PARAM);

		switch (attr_p->qp_fc.fc_hca_port) {
		case 1:
			rsrc_type = HERMON_QPC_RFCI_PORT1;
			break;
		case 2:
			rsrc_type = HERMON_QPC_RFCI_PORT2;
			break;
		default:
			return (IBT_INVALID_PARAM);
		}
		break;
	case IBT_QP_USES_FCMD:
		if (type != IBT_UD_RQP)
			return (IBT_INVALID_PARAM);
		break;
	case 0:
		break;
	default:
		return (IBT_INVALID_PARAM);	/* conflicting flags set */
	}

	/*
	 * Determine whether QP is being allocated for userland access or
	 * whether it is being allocated for kernel access.  If the QP is
	 * being allocated for userland access, then lookup the UAR
	 * page number for the current process.  Note:  If this is not found
	 * (e.g. if the process has not previously open()'d the Hermon driver),
	 * then an error is returned.
	 */
	if (qp_is_umap) {
		status = hermon_umap_db_find(state->hs_instance, ddi_get_pid(),
		    MLNX_UMAP_UARPG_RSRC, &value, 0, NULL);
		if (status != DDI_SUCCESS) {
			return (IBT_INVALID_PARAM);
		}
		uarpg = ((hermon_rsrc_t *)(uintptr_t)value)->hr_indx;
	} else {
		uarpg = state->hs_kernel_uar_index;
	}

	/*
	 * Determine whether QP is being associated with an SRQ
	 */
	qp_srq_en = (alloc_flags & IBT_QP_USES_SRQ) ? 1 : 0;
	if (qp_srq_en) {
		/*
		 * Check for valid SRQ handle pointers
		 */
		if (attr_p->qp_ibc_srq_hdl == NULL) {
			status = IBT_SRQ_HDL_INVALID;
			goto qpalloc_fail;
		}
		srq = (hermon_srqhdl_t)attr_p->qp_ibc_srq_hdl;
	}

	/*
	 * Check for valid QP service type (only UD/RC/UC supported)
	 */
	if (((type != IBT_UD_RQP) && (type != IBT_RC_RQP) &&
	    (type != IBT_UC_RQP))) {
		status = IBT_QP_SRV_TYPE_INVALID;
		goto qpalloc_fail;
	}


	/*
	 * Check for valid PD handle pointer
	 */
	if (attr_p->qp_pd_hdl == NULL) {
		status = IBT_PD_HDL_INVALID;
		goto qpalloc_fail;
	}
	pd = (hermon_pdhdl_t)attr_p->qp_pd_hdl;

	/*
	 * If on an SRQ, check to make sure the PD is the same
	 */
	if (qp_srq_en && (pd->pd_pdnum != srq->srq_pdhdl->pd_pdnum)) {
		status = IBT_PD_HDL_INVALID;
		goto qpalloc_fail;
	}

	/* Increment the reference count on the protection domain (PD) */
	hermon_pd_refcnt_inc(pd);

	/*
	 * Check for valid CQ handle pointers
	 *
	 * FCMD QPs do not require a receive cq handle.
	 */
	if (attr_p->qp_ibc_scq_hdl == NULL) {
		status = IBT_CQ_HDL_INVALID;
		goto qpalloc_fail1;
	}
	sq_cq = (hermon_cqhdl_t)attr_p->qp_ibc_scq_hdl;
	if ((attr_p->qp_ibc_rcq_hdl == NULL)) {
		if ((alloc_flags & IBT_QP_USES_FCMD) == 0) {
			status = IBT_CQ_HDL_INVALID;
			goto qpalloc_fail1;
		}
		rq_cq = sq_cq;	/* just use the send cq */
	} else
		rq_cq = (hermon_cqhdl_t)attr_p->qp_ibc_rcq_hdl;

	/*
	 * Increment the reference count on the CQs.  One or both of these
	 * could return error if we determine that the given CQ is already
	 * being used with a special (SMI/GSI) QP.
	 */
	status = hermon_cq_refcnt_inc(sq_cq, HERMON_CQ_IS_NORMAL);
	if (status != DDI_SUCCESS) {
		status = IBT_CQ_HDL_INVALID;
		goto qpalloc_fail1;
	}
	status = hermon_cq_refcnt_inc(rq_cq, HERMON_CQ_IS_NORMAL);
	if (status != DDI_SUCCESS) {
		status = IBT_CQ_HDL_INVALID;
		goto qpalloc_fail2;
	}

	/*
	 * Allocate an QP context entry.  This will be filled in with all
	 * the necessary parameters to define the Queue Pair.  Unlike
	 * other Hermon hardware resources, ownership is not immediately
	 * given to hardware in the final step here.  Instead, we must
	 * wait until the QP is later transitioned to the "Init" state before
	 * passing the QP to hardware.  If we fail here, we must undo all
	 * the reference count (CQ and PD).
	 */
	status = hermon_rsrc_alloc(state, rsrc_type, 1, sleepflag, &qpc);
	if (status != DDI_SUCCESS) {
		status = IBT_INSUFF_RESOURCE;
		goto qpalloc_fail3;
	}

	/*
	 * Allocate the software structure for tracking the queue pair
	 * (i.e. the Hermon Queue Pair handle).  If we fail here, we must
	 * undo the reference counts and the previous resource allocation.
	 */
	status = hermon_rsrc_alloc(state, HERMON_QPHDL, 1, sleepflag, &rsrc);
	if (status != DDI_SUCCESS) {
		status = IBT_INSUFF_RESOURCE;
		goto qpalloc_fail4;
	}
	qp = (hermon_qphdl_t)rsrc->hr_addr;
	bzero(qp, sizeof (struct hermon_sw_qp_s));
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*qp))

	qp->qp_alloc_flags = alloc_flags;

	/*
	 * Calculate the QP number from QPC index.  This routine handles
	 * all of the operations necessary to keep track of used, unused,
	 * and released QP numbers.
	 */
	if (type == IBT_UD_RQP) {
		qp->qp_qpnum = qpc->hr_indx;
		qp->qp_ring = qp->qp_qpnum << 8;
		qp->qp_qpn_hdl = NULL;
	} else {
		status = hermon_qp_create_qpn(state, qp, qpc);
		if (status != DDI_SUCCESS) {
			status = IBT_INSUFF_RESOURCE;
			goto qpalloc_fail5;
		}
	}

	/*
	 * If this will be a user-mappable QP, then allocate an entry for
	 * the "userland resources database".  This will later be added to
	 * the database (after all further QP operations are successful).
	 * If we fail here, we must undo the reference counts and the
	 * previous resource allocation.
	 */
	if (qp_is_umap) {
		umapdb = hermon_umap_db_alloc(state->hs_instance, qp->qp_qpnum,
		    MLNX_UMAP_QPMEM_RSRC, (uint64_t)(uintptr_t)rsrc);
		if (umapdb == NULL) {
			status = IBT_INSUFF_RESOURCE;
			goto qpalloc_fail6;
		}
	}

	/*
	 * Allocate the doorbell record.  Hermon just needs one for the RQ,
	 * if the QP is not associated with an SRQ, and use uarpg (above) as
	 * the uar index
	 */

	if (!qp_srq_en) {
		status = hermon_dbr_alloc(state, uarpg, &qp->qp_rq_dbr_acchdl,
		    &qp->qp_rq_vdbr, &qp->qp_rq_pdbr, &qp->qp_rdbr_mapoffset);
		if (status != DDI_SUCCESS) {
			status = IBT_INSUFF_RESOURCE;
			goto qpalloc_fail6;
		}
	}

	qp->qp_uses_lso = (attr_p->qp_flags & IBT_USES_LSO);

	/*
	 * We verify that the requested number of SGL is valid (i.e.
	 * consistent with the device limits and/or software-configured
	 * limits).  If not, then obviously the same cleanup needs to be done.
	 */
	if (type == IBT_UD_RQP) {
		max_sgl = state->hs_ibtfinfo.hca_attr->hca_ud_send_sgl_sz;
		swq_type = HERMON_QP_WQ_TYPE_SENDQ_UD;
	} else {
		max_sgl = state->hs_ibtfinfo.hca_attr->hca_conn_send_sgl_sz;
		swq_type = HERMON_QP_WQ_TYPE_SENDQ_CONN;
	}
	max_recv_sgl = state->hs_ibtfinfo.hca_attr->hca_recv_sgl_sz;
	if ((attr_p->qp_sizes.cs_sq_sgl > max_sgl) ||
	    (!qp_srq_en && (attr_p->qp_sizes.cs_rq_sgl > max_recv_sgl))) {
		status = IBT_HCA_SGL_EXCEEDED;
		goto qpalloc_fail7;
	}

	/*
	 * Determine this QP's WQE stride (for both the Send and Recv WQEs).
	 * This will depend on the requested number of SGLs.  Note: this
	 * has the side-effect of also calculating the real number of SGLs
	 * (for the calculated WQE size).
	 *
	 * For QP's on an SRQ, we set these to 0.
	 */
	if (qp_srq_en) {
		qp->qp_rq_log_wqesz = 0;
		qp->qp_rq_sgl = 0;
	} else {
		hermon_qp_sgl_to_logwqesz(state, attr_p->qp_sizes.cs_rq_sgl,
		    max_recv_sgl, HERMON_QP_WQ_TYPE_RECVQ,
		    &qp->qp_rq_log_wqesz, &qp->qp_rq_sgl);
	}
	hermon_qp_sgl_to_logwqesz(state, attr_p->qp_sizes.cs_sq_sgl,
	    max_sgl, swq_type, &qp->qp_sq_log_wqesz, &qp->qp_sq_sgl);

	sq_wqe_size = 1 << qp->qp_sq_log_wqesz;

	/* NOTE: currently policy in driver, later maybe IBTF interface */
	qp->qp_no_prefetch = 0;

	/*
	 * for prefetching, we need to add the number of wqes in
	 * the 2k area plus one to the number requested, but
	 * ONLY for send queue.  If no_prefetch == 1 (prefetch off)
	 * it's exactly TWO wqes for the headroom
	 */
	if (qp->qp_no_prefetch)
		qp->qp_sq_headroom = 2 * sq_wqe_size;
	else
		qp->qp_sq_headroom = sq_wqe_size + HERMON_QP_OH_SIZE;
	/*
	 * hdrm wqes must be integral since both sq_wqe_size &
	 * HERMON_QP_OH_SIZE are power of 2
	 */
	qp->qp_sq_hdrmwqes = (qp->qp_sq_headroom / sq_wqe_size);


	/*
	 * Calculate the appropriate size for the work queues.
	 * For send queue, add in the headroom wqes to the calculation.
	 * Note:  All Hermon QP work queues must be a power-of-2 in size.  Also
	 * they may not be any smaller than HERMON_QP_MIN_SIZE.  This step is
	 * to round the requested size up to the next highest power-of-2
	 */
	/* first, adjust to a minimum and tell the caller the change */
	attr_p->qp_sizes.cs_sq = max(attr_p->qp_sizes.cs_sq,
	    HERMON_QP_MIN_SIZE);
	attr_p->qp_sizes.cs_rq = max(attr_p->qp_sizes.cs_rq,
	    HERMON_QP_MIN_SIZE);
	/*
	 * now, calculate the alloc size, taking into account
	 * the headroom for the sq
	 */
	log_qp_sq_size = highbit(attr_p->qp_sizes.cs_sq + qp->qp_sq_hdrmwqes);
	/* if the total is a power of two, reduce it */
	if (ISP2(attr_p->qp_sizes.cs_sq + qp->qp_sq_hdrmwqes))	{
		log_qp_sq_size = log_qp_sq_size - 1;
	}

	log_qp_rq_size = highbit(attr_p->qp_sizes.cs_rq);
	if (ISP2(attr_p->qp_sizes.cs_rq)) {
		log_qp_rq_size = log_qp_rq_size - 1;
	}

	/*
	 * Next we verify that the rounded-up size is valid (i.e. consistent
	 * with the device limits and/or software-configured limits).  If not,
	 * then obviously we have a lot of cleanup to do before returning.
	 *
	 * NOTE: the first condition deals with the (test) case of cs_sq
	 * being just less than 2^32.  In this case, the headroom addition
	 * to the requested cs_sq will pass the test when it should not.
	 * This test no longer lets that case slip through the check.
	 */
	if ((attr_p->qp_sizes.cs_sq >
	    (1 << state->hs_cfg_profile->cp_log_max_qp_sz)) ||
	    (log_qp_sq_size > state->hs_cfg_profile->cp_log_max_qp_sz) ||
	    (!qp_srq_en && (log_qp_rq_size >
	    state->hs_cfg_profile->cp_log_max_qp_sz))) {
		status = IBT_HCA_WR_EXCEEDED;
		goto qpalloc_fail7;
	}

	/*
	 * Allocate the memory for QP work queues. Since Hermon work queues
	 * are not allowed to cross a 32-bit (4GB) boundary, the alignment of
	 * the work queue memory is very important.  We used to allocate
	 * work queues (the combined receive and send queues) so that they
	 * would be aligned on their combined size.  That alignment guaranteed
	 * that they would never cross the 4GB boundary (Hermon work queues
	 * are on the order of MBs at maximum).  Now we are able to relax
	 * this alignment constraint by ensuring that the IB address assigned
	 * to the queue memory (as a result of the hermon_mr_register() call)
	 * is offset from zero.
	 * Previously, we had wanted to use the ddi_dma_mem_alloc() routine to
	 * guarantee the alignment, but when attempting to use IOMMU bypass
	 * mode we found that we were not allowed to specify any alignment
	 * that was more restrictive than the system page size.
	 * So we avoided this constraint by passing two alignment values,
	 * one for the memory allocation itself and the other for the DMA
	 * handle (for later bind).  This used to cause more memory than
	 * necessary to be allocated (in order to guarantee the more
	 * restrictive alignment contraint).  But by guaranteeing the
	 * zero-based IB virtual address for the queue, we are able to
	 * conserve this memory.
	 */
	sq_wqe_size = 1 << qp->qp_sq_log_wqesz;
	sq_depth    = 1 << log_qp_sq_size;
	sq_size	    = sq_depth * sq_wqe_size;

	/* QP on SRQ sets these to 0 */
	if (qp_srq_en) {
		rq_wqe_size = 0;
		rq_size	    = 0;
	} else {
		rq_wqe_size = 1 << qp->qp_rq_log_wqesz;
		rq_depth    = 1 << log_qp_rq_size;
		rq_size	    = rq_depth * rq_wqe_size;
	}

	qp->qp_wqinfo.qa_size = sq_size + rq_size;

	qp->qp_wqinfo.qa_alloc_align = PAGESIZE;
	qp->qp_wqinfo.qa_bind_align  = PAGESIZE;

	if (qp_is_umap) {
		qp->qp_wqinfo.qa_location = HERMON_QUEUE_LOCATION_USERLAND;
	} else {
		qp->qp_wqinfo.qa_location = HERMON_QUEUE_LOCATION_NORMAL;
	}
	status = hermon_queue_alloc(state, &qp->qp_wqinfo, sleepflag);
	if (status != DDI_SUCCESS) {
		status = IBT_INSUFF_RESOURCE;
		goto qpalloc_fail7;
	}

	/*
	 * Sort WQs in memory according to stride (*q_wqe_size), largest first
	 * If they are equal, still put the SQ first
	 */
	qp->qp_sq_baseaddr = 0;
	qp->qp_rq_baseaddr = 0;
	if ((sq_wqe_size > rq_wqe_size) || (sq_wqe_size == rq_wqe_size)) {
		sq_buf = qp->qp_wqinfo.qa_buf_aligned;

		/* if this QP is on an SRQ, set the rq_buf to NULL */
		if (qp_srq_en) {
			rq_buf = NULL;
		} else {
			rq_buf = (uint32_t *)((uintptr_t)sq_buf + sq_size);
			qp->qp_rq_baseaddr = sq_size;
		}
	} else {
		rq_buf = qp->qp_wqinfo.qa_buf_aligned;
		sq_buf = (uint32_t *)((uintptr_t)rq_buf + rq_size);
		qp->qp_sq_baseaddr = rq_size;
	}

	if (qp_is_umap == 0) {
		qp->qp_sq_wqhdr = hermon_wrid_wqhdr_create(sq_depth);
		if (qp->qp_sq_wqhdr == NULL) {
			status = IBT_INSUFF_RESOURCE;
			goto qpalloc_fail8;
		}
		if (qp_srq_en) {
			qp->qp_rq_wqavl.wqa_wq = srq->srq_wq_wqhdr;
			qp->qp_rq_wqavl.wqa_srq_en = 1;
			qp->qp_rq_wqavl.wqa_srq = srq;
		} else {
			qp->qp_rq_wqhdr = hermon_wrid_wqhdr_create(rq_depth);
			if (qp->qp_rq_wqhdr == NULL) {
				status = IBT_INSUFF_RESOURCE;
				goto qpalloc_fail8;
			}
			qp->qp_rq_wqavl.wqa_wq = qp->qp_rq_wqhdr;
		}
		qp->qp_sq_wqavl.wqa_qpn = qp->qp_qpnum;
		qp->qp_sq_wqavl.wqa_type = HERMON_WR_SEND;
		qp->qp_sq_wqavl.wqa_wq = qp->qp_sq_wqhdr;
		qp->qp_rq_wqavl.wqa_qpn = qp->qp_qpnum;
		qp->qp_rq_wqavl.wqa_type = HERMON_WR_RECV;
	}

	/*
	 * Register the memory for the QP work queues.  The memory for the
	 * QP must be registered in the Hermon cMPT tables.  This gives us the
	 * LKey to specify in the QP context later.  Note: The memory for
	 * Hermon work queues (both Send and Recv) must be contiguous and
	 * registered as a single memory region.  Note: If the QP memory is
	 * user-mappable, force DDI_DMA_CONSISTENT mapping. Also, in order to
	 * meet the alignment restriction, we pass the "mro_bind_override_addr"
	 * flag in the call to hermon_mr_register(). This guarantees that the
	 * resulting IB vaddr will be zero-based (modulo the offset into the
	 * first page). If we fail here, we still have the bunch of resource
	 * and reference count cleanup to do.
	 */
	flag = (sleepflag == HERMON_SLEEP) ? IBT_MR_SLEEP :
	    IBT_MR_NOSLEEP;
	mr_attr.mr_vaddr    = (uint64_t)(uintptr_t)qp->qp_wqinfo.qa_buf_aligned;
	mr_attr.mr_len	    = qp->qp_wqinfo.qa_size;
	mr_attr.mr_as	    = NULL;
	mr_attr.mr_flags    = flag;
	if (qp_is_umap) {
		mr_op.mro_bind_type = state->hs_cfg_profile->cp_iommu_bypass;
	} else {
		/* HERMON_QUEUE_LOCATION_NORMAL */
		mr_op.mro_bind_type =
		    state->hs_cfg_profile->cp_iommu_bypass;
	}
	mr_op.mro_bind_dmahdl = qp->qp_wqinfo.qa_dmahdl;
	mr_op.mro_bind_override_addr = 1;
	status = hermon_mr_register(state, pd, &mr_attr, &mr,
	    &mr_op, HERMON_QP_CMPT);
	if (status != DDI_SUCCESS) {
		status = IBT_INSUFF_RESOURCE;
		goto qpalloc_fail9;
	}

	/*
	 * Calculate the offset between the kernel virtual address space
	 * and the IB virtual address space.  This will be used when
	 * posting work requests to properly initialize each WQE.
	 */
	qp_desc_off = (uint64_t)(uintptr_t)qp->qp_wqinfo.qa_buf_aligned -
	    (uint64_t)mr->mr_bindinfo.bi_addr;

	/*
	 * Fill in all the return arguments (if necessary).  This includes
	 * real work queue sizes (in wqes), real SGLs, and QP number
	 */
	if (queuesz_p != NULL) {
		queuesz_p->cs_sq 	=
		    (1 << log_qp_sq_size) - qp->qp_sq_hdrmwqes;
		queuesz_p->cs_sq_sgl	= qp->qp_sq_sgl;

		/* if this QP is on an SRQ, set these to 0 */
		if (qp_srq_en) {
			queuesz_p->cs_rq	= 0;
			queuesz_p->cs_rq_sgl	= 0;
		} else {
			queuesz_p->cs_rq	= (1 << log_qp_rq_size);
			queuesz_p->cs_rq_sgl	= qp->qp_rq_sgl;
		}
	}
	if (qpn != NULL) {
		*qpn = (ib_qpn_t)qp->qp_qpnum;
	}

	/*
	 * Fill in the rest of the Hermon Queue Pair handle.
	 */
	qp->qp_qpcrsrcp		= qpc;
	qp->qp_rsrcp		= rsrc;
	qp->qp_state		= HERMON_QP_RESET;
	HERMON_SET_QP_POST_SEND_STATE(qp, HERMON_QP_RESET);
	qp->qp_pdhdl		= pd;
	qp->qp_mrhdl		= mr;
	qp->qp_sq_sigtype	= (attr_p->qp_flags & IBT_WR_SIGNALED) ?
	    HERMON_QP_SQ_WR_SIGNALED : HERMON_QP_SQ_ALL_SIGNALED;
	qp->qp_is_special	= 0;
	qp->qp_uarpg		= uarpg;
	qp->qp_umap_dhp		= (devmap_cookie_t)NULL;
	qp->qp_sq_cqhdl		= sq_cq;
	qp->qp_sq_bufsz		= (1 << log_qp_sq_size);
	qp->qp_sq_logqsz	= log_qp_sq_size;
	qp->qp_sq_buf		= sq_buf;
	qp->qp_desc_off		= qp_desc_off;
	qp->qp_rq_cqhdl		= rq_cq;
	qp->qp_rq_buf		= rq_buf;
	qp->qp_rlky		= (attr_p->qp_flags & IBT_FAST_REG_RES_LKEY) !=
	    0;

	/* if this QP is on an SRQ, set rq_bufsz to 0 */
	if (qp_srq_en) {
		qp->qp_rq_bufsz		= 0;
		qp->qp_rq_logqsz	= 0;
	} else {
		qp->qp_rq_bufsz		= (1 << log_qp_rq_size);
		qp->qp_rq_logqsz	= log_qp_rq_size;
	}

	qp->qp_forward_sqd_event  = 0;
	qp->qp_sqd_still_draining = 0;
	qp->qp_hdlrarg		= (void *)ibt_qphdl;
	qp->qp_mcg_refcnt	= 0;

	/*
	 * If this QP is to be associated with an SRQ, set the SRQ handle
	 */
	if (qp_srq_en) {
		qp->qp_srqhdl = srq;
		hermon_srq_refcnt_inc(qp->qp_srqhdl);
	} else {
		qp->qp_srqhdl = NULL;
	}

	/* Determine the QP service type */
	qp->qp_type = type;
	if (type == IBT_RC_RQP) {
		qp->qp_serv_type = HERMON_QP_RC;
	} else if (type == IBT_UD_RQP) {
		if (alloc_flags & IBT_QP_USES_RFCI)
			qp->qp_serv_type = HERMON_QP_RFCI;
		else if (alloc_flags & IBT_QP_USES_FCMD)
			qp->qp_serv_type = HERMON_QP_FCMND;
		else
			qp->qp_serv_type = HERMON_QP_UD;
	} else {
		qp->qp_serv_type = HERMON_QP_UC;
	}

	/*
	 * Initialize the RQ WQEs - unlike Arbel, no Rcv init is needed
	 */

	/*
	 * Initialize the SQ WQEs - all that needs to be done is every 64 bytes
	 * set the quadword to all F's - high-order bit is owner (init to one)
	 * and the rest for the headroom definition of prefetching
	 *
	 */
	wqesz_shift = qp->qp_sq_log_wqesz;
	thewqesz    = 1 << wqesz_shift;
	thewqe = (uint64_t *)(void *)(qp->qp_sq_buf);
	if (qp_is_umap == 0) {
		for (i = 0; i < sq_depth; i++) {
			/*
			 * for each stride, go through and every 64 bytes
			 * write the init value - having set the address
			 * once, just keep incrementing it
			 */
			for (j = 0; j < thewqesz; j += 64, thewqe += 8) {
				*(uint32_t *)thewqe = 0xFFFFFFFF;
			}
		}
	}

	/* Zero out the QP context */
	bzero(&qp->qpc, sizeof (hermon_hw_qpc_t));

	/*
	 * Put QP handle in Hermon QPNum-to-QPHdl list.  Then fill in the
	 * "qphdl" and return success
	 */
	hermon_icm_set_num_to_hdl(state, HERMON_QPC, qpc->hr_indx, qp);

	/*
	 * If this is a user-mappable QP, then we need to insert the previously
	 * allocated entry into the "userland resources database".  This will
	 * allow for later lookup during devmap() (i.e. mmap()) calls.
	 */
	if (qp_is_umap) {
		hermon_umap_db_add(umapdb);
	}
	mutex_init(&qp->qp_sq_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(state->hs_intrmsi_pri));

	*qphdl = qp;

	return (DDI_SUCCESS);

/*
 * The following is cleanup for all possible failure cases in this routine
 */
qpalloc_fail9:
	hermon_queue_free(&qp->qp_wqinfo);
qpalloc_fail8:
	if (qp->qp_sq_wqhdr)
		hermon_wrid_wqhdr_destroy(qp->qp_sq_wqhdr);
	if (qp->qp_rq_wqhdr)
		hermon_wrid_wqhdr_destroy(qp->qp_rq_wqhdr);
qpalloc_fail7:
	if (qp_is_umap) {
		hermon_umap_db_free(umapdb);
	}
	if (!qp_srq_en) {
		hermon_dbr_free(state, uarpg, qp->qp_rq_vdbr);
	}

qpalloc_fail6:
	/*
	 * Releasing the QPN will also free up the QPC context.  Update
	 * the QPC context pointer to indicate this.
	 */
	if (qp->qp_qpn_hdl) {
		hermon_qp_release_qpn(state, qp->qp_qpn_hdl,
		    HERMON_QPN_RELEASE);
	} else {
		hermon_rsrc_free(state, &qpc);
	}
	qpc = NULL;
qpalloc_fail5:
	hermon_rsrc_free(state, &rsrc);
qpalloc_fail4:
	if (qpc) {
		hermon_rsrc_free(state, &qpc);
	}
qpalloc_fail3:
	hermon_cq_refcnt_dec(rq_cq);
qpalloc_fail2:
	hermon_cq_refcnt_dec(sq_cq);
qpalloc_fail1:
	hermon_pd_refcnt_dec(pd);
qpalloc_fail:
	return (status);
}



/*
 * hermon_special_qp_alloc()
 *    Context: Can be called only from user or kernel context.
 */
int
hermon_special_qp_alloc(hermon_state_t *state, hermon_qp_info_t *qpinfo,
    uint_t sleepflag)
{
	hermon_rsrc_t		*qpc, *rsrc;
	hermon_qphdl_t		qp;
	ibt_qp_alloc_attr_t	*attr_p;
	ibt_sqp_type_t		type;
	uint8_t			port;
	ibtl_qp_hdl_t		ibt_qphdl;
	ibt_chan_sizes_t	*queuesz_p;
	hermon_qphdl_t		*qphdl;
	ibt_mr_attr_t		mr_attr;
	hermon_mr_options_t	mr_op;
	hermon_pdhdl_t		pd;
	hermon_cqhdl_t		sq_cq, rq_cq;
	hermon_mrhdl_t		mr;
	uint64_t		qp_desc_off;
	uint64_t		*thewqe, thewqesz;
	uint32_t		*sq_buf, *rq_buf;
	uint32_t		log_qp_sq_size, log_qp_rq_size;
	uint32_t		sq_size, rq_size, max_sgl;
	uint32_t		uarpg;
	uint32_t		sq_depth;
	uint32_t		sq_wqe_size, rq_wqe_size, wqesz_shift;
	int			status, flag, i, j;

	/*
	 * Extract the necessary info from the hermon_qp_info_t structure
	 */
	attr_p	  = qpinfo->qpi_attrp;
	type	  = qpinfo->qpi_type;
	port	  = qpinfo->qpi_port;
	ibt_qphdl = qpinfo->qpi_ibt_qphdl;
	queuesz_p = qpinfo->qpi_queueszp;
	qphdl	  = &qpinfo->qpi_qphdl;

	/*
	 * Check for valid special QP type (only SMI & GSI supported)
	 */
	if ((type != IBT_SMI_SQP) && (type != IBT_GSI_SQP)) {
		status = IBT_QP_SPECIAL_TYPE_INVALID;
		goto spec_qpalloc_fail;
	}

	/*
	 * Check for valid port number
	 */
	if (!hermon_portnum_is_valid(state, port)) {
		status = IBT_HCA_PORT_INVALID;
		goto spec_qpalloc_fail;
	}
	port = port - 1;

	/*
	 * Check for valid PD handle pointer
	 */
	if (attr_p->qp_pd_hdl == NULL) {
		status = IBT_PD_HDL_INVALID;
		goto spec_qpalloc_fail;
	}
	pd = (hermon_pdhdl_t)attr_p->qp_pd_hdl;

	/* Increment the reference count on the PD */
	hermon_pd_refcnt_inc(pd);

	/*
	 * Check for valid CQ handle pointers
	 */
	if ((attr_p->qp_ibc_scq_hdl == NULL) ||
	    (attr_p->qp_ibc_rcq_hdl == NULL)) {
		status = IBT_CQ_HDL_INVALID;
		goto spec_qpalloc_fail1;
	}
	sq_cq = (hermon_cqhdl_t)attr_p->qp_ibc_scq_hdl;
	rq_cq = (hermon_cqhdl_t)attr_p->qp_ibc_rcq_hdl;

	/*
	 * Increment the reference count on the CQs.  One or both of these
	 * could return error if we determine that the given CQ is already
	 * being used with a non-special QP (i.e. a normal QP).
	 */
	status = hermon_cq_refcnt_inc(sq_cq, HERMON_CQ_IS_SPECIAL);
	if (status != DDI_SUCCESS) {
		status = IBT_CQ_HDL_INVALID;
		goto spec_qpalloc_fail1;
	}
	status = hermon_cq_refcnt_inc(rq_cq, HERMON_CQ_IS_SPECIAL);
	if (status != DDI_SUCCESS) {
		status = IBT_CQ_HDL_INVALID;
		goto spec_qpalloc_fail2;
	}

	/*
	 * Allocate the special QP resources.  Essentially, this allocation
	 * amounts to checking if the request special QP has already been
	 * allocated.  If successful, the QP context return is an actual
	 * QP context that has been "aliased" to act as a special QP of the
	 * appropriate type (and for the appropriate port).  Just as in
	 * hermon_qp_alloc() above, ownership for this QP context is not
	 * immediately given to hardware in the final step here.  Instead, we
	 * wait until the QP is later transitioned to the "Init" state before
	 * passing the QP to hardware.  If we fail here, we must undo all
	 * the reference count (CQ and PD).
	 */
	status = hermon_special_qp_rsrc_alloc(state, type, port, &qpc);
	if (status != DDI_SUCCESS) {
		goto spec_qpalloc_fail3;
	}

	/*
	 * Allocate the software structure for tracking the special queue
	 * pair (i.e. the Hermon Queue Pair handle).  If we fail here, we
	 * must undo the reference counts and the previous resource allocation.
	 */
	status = hermon_rsrc_alloc(state, HERMON_QPHDL, 1, sleepflag, &rsrc);
	if (status != DDI_SUCCESS) {
		status = IBT_INSUFF_RESOURCE;
		goto spec_qpalloc_fail4;
	}
	qp = (hermon_qphdl_t)rsrc->hr_addr;

	bzero(qp, sizeof (struct hermon_sw_qp_s));

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*qp))
	qp->qp_alloc_flags = attr_p->qp_alloc_flags;

	/*
	 * Actual QP number is a combination of the index of the QPC and
	 * the port number.  This is because the special QP contexts must
	 * be allocated two-at-a-time.
	 */
	qp->qp_qpnum = qpc->hr_indx + port;
	qp->qp_ring = qp->qp_qpnum << 8;

	uarpg = state->hs_kernel_uar_index; /* must be for spec qp */
	/*
	 * Allocate the doorbell record.  Hermon uses only one for the RQ so
	 * alloc a qp doorbell, using uarpg (above) as the uar index
	 */

	status = hermon_dbr_alloc(state, uarpg, &qp->qp_rq_dbr_acchdl,
	    &qp->qp_rq_vdbr, &qp->qp_rq_pdbr, &qp->qp_rdbr_mapoffset);
	if (status != DDI_SUCCESS) {
		status = IBT_INSUFF_RESOURCE;
		goto spec_qpalloc_fail5;
	}
	/*
	 * Calculate the appropriate size for the work queues.
	 * Note:  All Hermon QP work queues must be a power-of-2 in size.  Also
	 * they may not be any smaller than HERMON_QP_MIN_SIZE.  This step is
	 * to round the requested size up to the next highest power-of-2
	 */
	attr_p->qp_sizes.cs_sq =
	    max(attr_p->qp_sizes.cs_sq, HERMON_QP_MIN_SIZE);
	attr_p->qp_sizes.cs_rq =
	    max(attr_p->qp_sizes.cs_rq, HERMON_QP_MIN_SIZE);
	log_qp_sq_size = highbit(attr_p->qp_sizes.cs_sq);
	if (ISP2(attr_p->qp_sizes.cs_sq)) {
		log_qp_sq_size = log_qp_sq_size - 1;
	}
	log_qp_rq_size = highbit(attr_p->qp_sizes.cs_rq);
	if (ISP2(attr_p->qp_sizes.cs_rq)) {
		log_qp_rq_size = log_qp_rq_size - 1;
	}

	/*
	 * Next we verify that the rounded-up size is valid (i.e. consistent
	 * with the device limits and/or software-configured limits).  If not,
	 * then obviously we have a bit of cleanup to do before returning.
	 */
	if ((log_qp_sq_size > state->hs_cfg_profile->cp_log_max_qp_sz) ||
	    (log_qp_rq_size > state->hs_cfg_profile->cp_log_max_qp_sz)) {
		status = IBT_HCA_WR_EXCEEDED;
		goto spec_qpalloc_fail5a;
	}

	/*
	 * Next we verify that the requested number of SGL is valid (i.e.
	 * consistent with the device limits and/or software-configured
	 * limits).  If not, then obviously the same cleanup needs to be done.
	 */
	max_sgl = state->hs_cfg_profile->cp_wqe_real_max_sgl;
	if ((attr_p->qp_sizes.cs_sq_sgl > max_sgl) ||
	    (attr_p->qp_sizes.cs_rq_sgl > max_sgl)) {
		status = IBT_HCA_SGL_EXCEEDED;
		goto spec_qpalloc_fail5a;
	}

	/*
	 * Determine this QP's WQE stride (for both the Send and Recv WQEs).
	 * This will depend on the requested number of SGLs.  Note: this
	 * has the side-effect of also calculating the real number of SGLs
	 * (for the calculated WQE size).
	 */
	hermon_qp_sgl_to_logwqesz(state, attr_p->qp_sizes.cs_rq_sgl,
	    max_sgl, HERMON_QP_WQ_TYPE_RECVQ,
	    &qp->qp_rq_log_wqesz, &qp->qp_rq_sgl);
	if (type == IBT_SMI_SQP) {
		hermon_qp_sgl_to_logwqesz(state, attr_p->qp_sizes.cs_sq_sgl,
		    max_sgl, HERMON_QP_WQ_TYPE_SENDMLX_QP0,
		    &qp->qp_sq_log_wqesz, &qp->qp_sq_sgl);
	} else {
		hermon_qp_sgl_to_logwqesz(state, attr_p->qp_sizes.cs_sq_sgl,
		    max_sgl, HERMON_QP_WQ_TYPE_SENDMLX_QP1,
		    &qp->qp_sq_log_wqesz, &qp->qp_sq_sgl);
	}

	/*
	 * Allocate the memory for QP work queues. Since Hermon work queues
	 * are not allowed to cross a 32-bit (4GB) boundary, the alignment of
	 * the work queue memory is very important.  We used to allocate
	 * work queues (the combined receive and send queues) so that they
	 * would be aligned on their combined size.  That alignment guaranteed
	 * that they would never cross the 4GB boundary (Hermon work queues
	 * are on the order of MBs at maximum).  Now we are able to relax
	 * this alignment constraint by ensuring that the IB address assigned
	 * to the queue memory (as a result of the hermon_mr_register() call)
	 * is offset from zero.
	 * Previously, we had wanted to use the ddi_dma_mem_alloc() routine to
	 * guarantee the alignment, but when attempting to use IOMMU bypass
	 * mode we found that we were not allowed to specify any alignment
	 * that was more restrictive than the system page size.
	 * So we avoided this constraint by passing two alignment values,
	 * one for the memory allocation itself and the other for the DMA
	 * handle (for later bind).  This used to cause more memory than
	 * necessary to be allocated (in order to guarantee the more
	 * restrictive alignment contraint).  But by guaranteeing the
	 * zero-based IB virtual address for the queue, we are able to
	 * conserve this memory.
	 */
	sq_wqe_size = 1 << qp->qp_sq_log_wqesz;
	sq_depth    = 1 << log_qp_sq_size;
	sq_size	    = (1 << log_qp_sq_size) * sq_wqe_size;

	rq_wqe_size = 1 << qp->qp_rq_log_wqesz;
	rq_size	    = (1 << log_qp_rq_size) * rq_wqe_size;

	qp->qp_wqinfo.qa_size	  = sq_size + rq_size;

	qp->qp_wqinfo.qa_alloc_align = PAGESIZE;
	qp->qp_wqinfo.qa_bind_align  = PAGESIZE;
	qp->qp_wqinfo.qa_location = HERMON_QUEUE_LOCATION_NORMAL;

	status = hermon_queue_alloc(state, &qp->qp_wqinfo, sleepflag);
	if (status != NULL) {
		status = IBT_INSUFF_RESOURCE;
		goto spec_qpalloc_fail5a;
	}

	/*
	 * Sort WQs in memory according to depth, stride (*q_wqe_size),
	 * biggest first. If equal, the Send Queue still goes first
	 */
	qp->qp_sq_baseaddr = 0;
	qp->qp_rq_baseaddr = 0;
	if ((sq_wqe_size > rq_wqe_size) || (sq_wqe_size == rq_wqe_size)) {
		sq_buf = qp->qp_wqinfo.qa_buf_aligned;
		rq_buf = (uint32_t *)((uintptr_t)sq_buf + sq_size);
		qp->qp_rq_baseaddr = sq_size;
	} else {
		rq_buf = qp->qp_wqinfo.qa_buf_aligned;
		sq_buf = (uint32_t *)((uintptr_t)rq_buf + rq_size);
		qp->qp_sq_baseaddr = rq_size;
	}

	qp->qp_sq_wqhdr = hermon_wrid_wqhdr_create(sq_depth);
	if (qp->qp_sq_wqhdr == NULL) {
		status = IBT_INSUFF_RESOURCE;
		goto spec_qpalloc_fail6;
	}
	qp->qp_rq_wqhdr = hermon_wrid_wqhdr_create(1 << log_qp_rq_size);
	if (qp->qp_rq_wqhdr == NULL) {
		status = IBT_INSUFF_RESOURCE;
		goto spec_qpalloc_fail6;
	}
	qp->qp_sq_wqavl.wqa_qpn = qp->qp_qpnum;
	qp->qp_sq_wqavl.wqa_type = HERMON_WR_SEND;
	qp->qp_sq_wqavl.wqa_wq = qp->qp_sq_wqhdr;
	qp->qp_rq_wqavl.wqa_qpn = qp->qp_qpnum;
	qp->qp_rq_wqavl.wqa_type = HERMON_WR_RECV;
	qp->qp_rq_wqavl.wqa_wq = qp->qp_rq_wqhdr;

	/*
	 * Register the memory for the special QP work queues.  The memory for
	 * the special QP must be registered in the Hermon cMPT tables.  This
	 * gives us the LKey to specify in the QP context later.  Note: The
	 * memory for Hermon work queues (both Send and Recv) must be contiguous
	 * and registered as a single memory region. Also, in order to meet the
	 * alignment restriction, we pass the "mro_bind_override_addr" flag in
	 * the call to hermon_mr_register(). This guarantees that the resulting
	 * IB vaddr will be zero-based (modulo the offset into the first page).
	 * If we fail here, we have a bunch of resource and reference count
	 * cleanup to do.
	 */
	flag = (sleepflag == HERMON_SLEEP) ? IBT_MR_SLEEP :
	    IBT_MR_NOSLEEP;
	mr_attr.mr_vaddr    = (uint64_t)(uintptr_t)qp->qp_wqinfo.qa_buf_aligned;
	mr_attr.mr_len	    = qp->qp_wqinfo.qa_size;
	mr_attr.mr_as	    = NULL;
	mr_attr.mr_flags    = flag;

	mr_op.mro_bind_type = state->hs_cfg_profile->cp_iommu_bypass;
	mr_op.mro_bind_dmahdl = qp->qp_wqinfo.qa_dmahdl;
	mr_op.mro_bind_override_addr = 1;

	status = hermon_mr_register(state, pd, &mr_attr, &mr, &mr_op,
	    HERMON_QP_CMPT);
	if (status != DDI_SUCCESS) {
		status = IBT_INSUFF_RESOURCE;
		goto spec_qpalloc_fail6;
	}

	/*
	 * Calculate the offset between the kernel virtual address space
	 * and the IB virtual address space.  This will be used when
	 * posting work requests to properly initialize each WQE.
	 */
	qp_desc_off = (uint64_t)(uintptr_t)qp->qp_wqinfo.qa_buf_aligned -
	    (uint64_t)mr->mr_bindinfo.bi_addr;

	/* set the prefetch - initially, not prefetching */
	qp->qp_no_prefetch = 1;

	if (qp->qp_no_prefetch)
		qp->qp_sq_headroom = 2 * sq_wqe_size;
	else
		qp->qp_sq_headroom = sq_wqe_size + HERMON_QP_OH_SIZE;
	/*
	 * hdrm wqes must be integral since both sq_wqe_size &
	 * HERMON_QP_OH_SIZE are power of 2
	 */
	qp->qp_sq_hdrmwqes = (qp->qp_sq_headroom / sq_wqe_size);
	/*
	 * Fill in all the return arguments (if necessary).  This includes
	 * real work queue sizes, real SGLs, and QP number (which will be
	 * either zero or one, depending on the special QP type)
	 */
	if (queuesz_p != NULL) {
		queuesz_p->cs_sq	=
		    (1 << log_qp_sq_size) - qp->qp_sq_hdrmwqes;
		queuesz_p->cs_sq_sgl	= qp->qp_sq_sgl;
		queuesz_p->cs_rq	= (1 << log_qp_rq_size);
		queuesz_p->cs_rq_sgl	= qp->qp_rq_sgl;
	}

	/*
	 * Fill in the rest of the Hermon Queue Pair handle.  We can update
	 * the following fields for use in further operations on the QP.
	 */
	qp->qp_qpcrsrcp		= qpc;
	qp->qp_rsrcp		= rsrc;
	qp->qp_state		= HERMON_QP_RESET;
	HERMON_SET_QP_POST_SEND_STATE(qp, HERMON_QP_RESET);
	qp->qp_pdhdl		= pd;
	qp->qp_mrhdl		= mr;
	qp->qp_sq_sigtype	= (attr_p->qp_flags & IBT_WR_SIGNALED) ?
	    HERMON_QP_SQ_WR_SIGNALED : HERMON_QP_SQ_ALL_SIGNALED;
	qp->qp_is_special	= (type == IBT_SMI_SQP) ?
	    HERMON_QP_SMI : HERMON_QP_GSI;
	qp->qp_uarpg		= uarpg;
	qp->qp_umap_dhp		= (devmap_cookie_t)NULL;
	qp->qp_sq_cqhdl		= sq_cq;
	qp->qp_sq_bufsz		= (1 << log_qp_sq_size);
	qp->qp_sq_buf		= sq_buf;
	qp->qp_sq_logqsz	= log_qp_sq_size;
	qp->qp_desc_off		= qp_desc_off;
	qp->qp_rq_cqhdl		= rq_cq;
	qp->qp_rq_bufsz		= (1 << log_qp_rq_size);
	qp->qp_rq_buf		= rq_buf;
	qp->qp_rq_logqsz	= log_qp_rq_size;
	qp->qp_portnum		= port;
	qp->qp_pkeyindx		= 0;
	qp->qp_forward_sqd_event  = 0;
	qp->qp_sqd_still_draining = 0;
	qp->qp_hdlrarg		= (void *)ibt_qphdl;
	qp->qp_mcg_refcnt	= 0;
	qp->qp_srqhdl		= NULL;

	/* All special QPs are UD QP service type */
	qp->qp_type = IBT_UD_RQP;
	qp->qp_serv_type = HERMON_QP_UD;

	/*
	 * Initialize the RQ WQEs - unlike Arbel, no Rcv init is needed
	 */

	/*
	 * Initialize the SQ WQEs - all that needs to be done is every 64 bytes
	 * set the quadword to all F's - high-order bit is owner (init to one)
	 * and the rest for the headroom definition of prefetching
	 *
	 */

	wqesz_shift = qp->qp_sq_log_wqesz;
	thewqesz    = 1 << wqesz_shift;
	thewqe = (uint64_t *)(void *)(qp->qp_sq_buf);
	for (i = 0; i < sq_depth; i++) {
		/*
		 * for each stride, go through and every 64 bytes write the
		 * init value - having set the address once, just keep
		 * incrementing it
		 */
		for (j = 0; j < thewqesz; j += 64, thewqe += 8) {
			*(uint32_t *)thewqe = 0xFFFFFFFF;
		}
	}


	/* Zero out the QP context */
	bzero(&qp->qpc, sizeof (hermon_hw_qpc_t));

	/*
	 * Put QP handle in Hermon QPNum-to-QPHdl list.  Then fill in the
	 * "qphdl" and return success
	 */
	hermon_icm_set_num_to_hdl(state, HERMON_QPC, qpc->hr_indx + port, qp);

	mutex_init(&qp->qp_sq_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(state->hs_intrmsi_pri));

	*qphdl = qp;

	return (DDI_SUCCESS);

/*
 * The following is cleanup for all possible failure cases in this routine
 */
spec_qpalloc_fail6:
	hermon_queue_free(&qp->qp_wqinfo);
	if (qp->qp_sq_wqhdr)
		hermon_wrid_wqhdr_destroy(qp->qp_sq_wqhdr);
	if (qp->qp_rq_wqhdr)
		hermon_wrid_wqhdr_destroy(qp->qp_rq_wqhdr);
spec_qpalloc_fail5a:
	hermon_dbr_free(state, uarpg, qp->qp_rq_vdbr);
spec_qpalloc_fail5:
	hermon_rsrc_free(state, &rsrc);
spec_qpalloc_fail4:
	if (hermon_special_qp_rsrc_free(state, type, port) != DDI_SUCCESS) {
		HERMON_WARNING(state, "failed to free special QP rsrc");
	}
spec_qpalloc_fail3:
	hermon_cq_refcnt_dec(rq_cq);
spec_qpalloc_fail2:
	hermon_cq_refcnt_dec(sq_cq);
spec_qpalloc_fail1:
	hermon_pd_refcnt_dec(pd);
spec_qpalloc_fail:
	return (status);
}


/*
 * hermon_qp_alloc_range()
 *    Context: Can be called only from user or kernel context.
 */
int
hermon_qp_alloc_range(hermon_state_t *state, uint_t log2,
    hermon_qp_info_t *qpinfo, ibtl_qp_hdl_t *ibt_qphdl,
    ibc_cq_hdl_t *send_cq, ibc_cq_hdl_t *recv_cq,
    hermon_qphdl_t *qphdl, uint_t sleepflag)
{
	hermon_rsrc_t			*qpc, *rsrc;
	hermon_rsrc_type_t		rsrc_type;
	hermon_qphdl_t			qp;
	hermon_qp_range_t		*qp_range_p;
	ibt_qp_alloc_attr_t		*attr_p;
	ibt_qp_type_t			type;
	hermon_qp_wq_type_t		swq_type;
	ibt_chan_sizes_t		*queuesz_p;
	ibt_mr_attr_t			mr_attr;
	hermon_mr_options_t		mr_op;
	hermon_srqhdl_t			srq;
	hermon_pdhdl_t			pd;
	hermon_cqhdl_t			sq_cq, rq_cq;
	hermon_mrhdl_t			mr;
	uint64_t			qp_desc_off;
	uint64_t			*thewqe, thewqesz;
	uint32_t			*sq_buf, *rq_buf;
	uint32_t			log_qp_sq_size, log_qp_rq_size;
	uint32_t			sq_size, rq_size;
	uint32_t			sq_depth, rq_depth;
	uint32_t			sq_wqe_size, rq_wqe_size, wqesz_shift;
	uint32_t			max_sgl, max_recv_sgl, uarpg;
	uint_t				qp_srq_en, i, j;
	int				ii;	/* loop counter for range */
	int				status, flag;
	uint_t				serv_type;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*attr_p, *queuesz_p))

	/*
	 * Extract the necessary info from the hermon_qp_info_t structure
	 */
	attr_p	  = qpinfo->qpi_attrp;
	type	  = qpinfo->qpi_type;
	queuesz_p = qpinfo->qpi_queueszp;

	if (attr_p->qp_alloc_flags & IBT_QP_USES_RSS) {
		if (log2 > state->hs_ibtfinfo.hca_attr->hca_rss_max_log2_table)
			return (IBT_INSUFF_RESOURCE);
		rsrc_type = HERMON_QPC;
		serv_type = HERMON_QP_UD;
	} else if (attr_p->qp_alloc_flags & IBT_QP_USES_FEXCH) {
		if (log2 > state->hs_ibtfinfo.hca_attr->hca_fexch_max_log2_qp)
			return (IBT_INSUFF_RESOURCE);
		switch (attr_p->qp_fc.fc_hca_port) {
		case 1:
			rsrc_type = HERMON_QPC_FEXCH_PORT1;
			break;
		case 2:
			rsrc_type = HERMON_QPC_FEXCH_PORT2;
			break;
		default:
			return (IBT_INVALID_PARAM);
		}
		serv_type = HERMON_QP_FEXCH;
	} else
		return (IBT_INVALID_PARAM);

	/*
	 * Determine whether QP is being allocated for userland access or
	 * whether it is being allocated for kernel access.  If the QP is
	 * being allocated for userland access, fail (too complex for now).
	 */
	if (attr_p->qp_alloc_flags & IBT_QP_USER_MAP) {
		return (IBT_NOT_SUPPORTED);
	} else {
		uarpg = state->hs_kernel_uar_index;
	}

	/*
	 * Determine whether QP is being associated with an SRQ
	 */
	qp_srq_en = (attr_p->qp_alloc_flags & IBT_QP_USES_SRQ) ? 1 : 0;
	if (qp_srq_en) {
		/*
		 * Check for valid SRQ handle pointers
		 */
		if (attr_p->qp_ibc_srq_hdl == NULL) {
			return (IBT_SRQ_HDL_INVALID);
		}
		srq = (hermon_srqhdl_t)attr_p->qp_ibc_srq_hdl;
	}

	/*
	 * Check for valid QP service type (only UD supported)
	 */
	if (type != IBT_UD_RQP) {
		return (IBT_QP_SRV_TYPE_INVALID);
	}

	/*
	 * Check for valid PD handle pointer
	 */
	if (attr_p->qp_pd_hdl == NULL) {
		return (IBT_PD_HDL_INVALID);
	}
	pd = (hermon_pdhdl_t)attr_p->qp_pd_hdl;

	/*
	 * If on an SRQ, check to make sure the PD is the same
	 */
	if (qp_srq_en && (pd->pd_pdnum != srq->srq_pdhdl->pd_pdnum)) {
		return (IBT_PD_HDL_INVALID);
	}

	/* set loop variable here, for freeing resources on error */
	ii = 0;

	/*
	 * Allocate 2^log2 contiguous/aligned QP context entries.  This will
	 * be filled in with all the necessary parameters to define the
	 * Queue Pairs.  Unlike other Hermon hardware resources, ownership
	 * is not immediately given to hardware in the final step here.
	 * Instead, we must wait until the QP is later transitioned to the
	 * "Init" state before passing the QP to hardware.  If we fail here,
	 * we must undo all the reference count (CQ and PD).
	 */
	status = hermon_rsrc_alloc(state, rsrc_type, 1 << log2, sleepflag,
	    &qpc);
	if (status != DDI_SUCCESS) {
		return (IBT_INSUFF_RESOURCE);
	}

	if (attr_p->qp_alloc_flags & IBT_QP_USES_FEXCH)
		/*
		 * Need to init the MKEYs for the FEXCH QPs.
		 *
		 * For FEXCH QP subranges, we return the QPN base as
		 * "relative" to the full FEXCH QP range for the port.
		 */
		*(qpinfo->qpi_qpn) = hermon_fcoib_fexch_relative_qpn(state,
		    attr_p->qp_fc.fc_hca_port, qpc->hr_indx);
	else
		*(qpinfo->qpi_qpn) = (ib_qpn_t)qpc->hr_indx;

	qp_range_p = kmem_alloc(sizeof (*qp_range_p),
	    (sleepflag == HERMON_SLEEP) ? KM_SLEEP : KM_NOSLEEP);
	if (qp_range_p == NULL) {
		status = IBT_INSUFF_RESOURCE;
		goto qpalloc_fail0;
	}
	mutex_init(&qp_range_p->hqpr_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(state->hs_intrmsi_pri));
	mutex_enter(&qp_range_p->hqpr_lock);
	qp_range_p->hqpr_refcnt = 1 << log2;
	qp_range_p->hqpr_qpcrsrc = qpc;
	mutex_exit(&qp_range_p->hqpr_lock);

for_each_qp:

	/* Increment the reference count on the protection domain (PD) */
	hermon_pd_refcnt_inc(pd);

	rq_cq = (hermon_cqhdl_t)recv_cq[ii];
	sq_cq = (hermon_cqhdl_t)send_cq[ii];
	if (sq_cq == NULL) {
		if (attr_p->qp_alloc_flags & IBT_QP_USES_FEXCH) {
			/* if no send completions, just use rq_cq */
			sq_cq = rq_cq;
		} else {
			status = IBT_CQ_HDL_INVALID;
			goto qpalloc_fail1;
		}
	}

	/*
	 * Increment the reference count on the CQs.  One or both of these
	 * could return error if we determine that the given CQ is already
	 * being used with a special (SMI/GSI) QP.
	 */
	status = hermon_cq_refcnt_inc(sq_cq, HERMON_CQ_IS_NORMAL);
	if (status != DDI_SUCCESS) {
		status = IBT_CQ_HDL_INVALID;
		goto qpalloc_fail1;
	}
	status = hermon_cq_refcnt_inc(rq_cq, HERMON_CQ_IS_NORMAL);
	if (status != DDI_SUCCESS) {
		status = IBT_CQ_HDL_INVALID;
		goto qpalloc_fail2;
	}

	/*
	 * Allocate the software structure for tracking the queue pair
	 * (i.e. the Hermon Queue Pair handle).  If we fail here, we must
	 * undo the reference counts and the previous resource allocation.
	 */
	status = hermon_rsrc_alloc(state, HERMON_QPHDL, 1, sleepflag, &rsrc);
	if (status != DDI_SUCCESS) {
		status = IBT_INSUFF_RESOURCE;
		goto qpalloc_fail4;
	}
	qp = (hermon_qphdl_t)rsrc->hr_addr;
	bzero(qp, sizeof (struct hermon_sw_qp_s));
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*qp))
	qp->qp_alloc_flags = attr_p->qp_alloc_flags;

	/*
	 * Calculate the QP number from QPC index.  This routine handles
	 * all of the operations necessary to keep track of used, unused,
	 * and released QP numbers.
	 */
	qp->qp_qpnum = qpc->hr_indx + ii;
	qp->qp_ring = qp->qp_qpnum << 8;
	qp->qp_qpn_hdl = NULL;

	/*
	 * Allocate the doorbell record.  Hermon just needs one for the RQ,
	 * if the QP is not associated with an SRQ, and use uarpg (above) as
	 * the uar index
	 */

	if (!qp_srq_en) {
		status = hermon_dbr_alloc(state, uarpg, &qp->qp_rq_dbr_acchdl,
		    &qp->qp_rq_vdbr, &qp->qp_rq_pdbr, &qp->qp_rdbr_mapoffset);
		if (status != DDI_SUCCESS) {
			status = IBT_INSUFF_RESOURCE;
			goto qpalloc_fail6;
		}
	}

	qp->qp_uses_lso = (attr_p->qp_flags & IBT_USES_LSO);

	/*
	 * We verify that the requested number of SGL is valid (i.e.
	 * consistent with the device limits and/or software-configured
	 * limits).  If not, then obviously the same cleanup needs to be done.
	 */
	max_sgl = state->hs_ibtfinfo.hca_attr->hca_ud_send_sgl_sz;
	swq_type = HERMON_QP_WQ_TYPE_SENDQ_UD;
	max_recv_sgl = state->hs_ibtfinfo.hca_attr->hca_recv_sgl_sz;
	if ((attr_p->qp_sizes.cs_sq_sgl > max_sgl) ||
	    (!qp_srq_en && (attr_p->qp_sizes.cs_rq_sgl > max_recv_sgl))) {
		status = IBT_HCA_SGL_EXCEEDED;
		goto qpalloc_fail7;
	}

	/*
	 * Determine this QP's WQE stride (for both the Send and Recv WQEs).
	 * This will depend on the requested number of SGLs.  Note: this
	 * has the side-effect of also calculating the real number of SGLs
	 * (for the calculated WQE size).
	 *
	 * For QP's on an SRQ, we set these to 0.
	 */
	if (qp_srq_en) {
		qp->qp_rq_log_wqesz = 0;
		qp->qp_rq_sgl = 0;
	} else {
		hermon_qp_sgl_to_logwqesz(state, attr_p->qp_sizes.cs_rq_sgl,
		    max_recv_sgl, HERMON_QP_WQ_TYPE_RECVQ,
		    &qp->qp_rq_log_wqesz, &qp->qp_rq_sgl);
	}
	hermon_qp_sgl_to_logwqesz(state, attr_p->qp_sizes.cs_sq_sgl,
	    max_sgl, swq_type, &qp->qp_sq_log_wqesz, &qp->qp_sq_sgl);

	sq_wqe_size = 1 << qp->qp_sq_log_wqesz;

	/* NOTE: currently policy in driver, later maybe IBTF interface */
	qp->qp_no_prefetch = 0;

	/*
	 * for prefetching, we need to add the number of wqes in
	 * the 2k area plus one to the number requested, but
	 * ONLY for send queue.  If no_prefetch == 1 (prefetch off)
	 * it's exactly TWO wqes for the headroom
	 */
	if (qp->qp_no_prefetch)
		qp->qp_sq_headroom = 2 * sq_wqe_size;
	else
		qp->qp_sq_headroom = sq_wqe_size + HERMON_QP_OH_SIZE;
	/*
	 * hdrm wqes must be integral since both sq_wqe_size &
	 * HERMON_QP_OH_SIZE are power of 2
	 */
	qp->qp_sq_hdrmwqes = (qp->qp_sq_headroom / sq_wqe_size);


	/*
	 * Calculate the appropriate size for the work queues.
	 * For send queue, add in the headroom wqes to the calculation.
	 * Note:  All Hermon QP work queues must be a power-of-2 in size.  Also
	 * they may not be any smaller than HERMON_QP_MIN_SIZE.  This step is
	 * to round the requested size up to the next highest power-of-2
	 */
	/* first, adjust to a minimum and tell the caller the change */
	attr_p->qp_sizes.cs_sq = max(attr_p->qp_sizes.cs_sq,
	    HERMON_QP_MIN_SIZE);
	attr_p->qp_sizes.cs_rq = max(attr_p->qp_sizes.cs_rq,
	    HERMON_QP_MIN_SIZE);
	/*
	 * now, calculate the alloc size, taking into account
	 * the headroom for the sq
	 */
	log_qp_sq_size = highbit(attr_p->qp_sizes.cs_sq + qp->qp_sq_hdrmwqes);
	/* if the total is a power of two, reduce it */
	if (ISP2(attr_p->qp_sizes.cs_sq + qp->qp_sq_hdrmwqes))	{
		log_qp_sq_size = log_qp_sq_size - 1;
	}

	log_qp_rq_size = highbit(attr_p->qp_sizes.cs_rq);
	if (ISP2(attr_p->qp_sizes.cs_rq)) {
		log_qp_rq_size = log_qp_rq_size - 1;
	}

	/*
	 * Next we verify that the rounded-up size is valid (i.e. consistent
	 * with the device limits and/or software-configured limits).  If not,
	 * then obviously we have a lot of cleanup to do before returning.
	 *
	 * NOTE: the first condition deals with the (test) case of cs_sq
	 * being just less than 2^32.  In this case, the headroom addition
	 * to the requested cs_sq will pass the test when it should not.
	 * This test no longer lets that case slip through the check.
	 */
	if ((attr_p->qp_sizes.cs_sq >
	    (1 << state->hs_cfg_profile->cp_log_max_qp_sz)) ||
	    (log_qp_sq_size > state->hs_cfg_profile->cp_log_max_qp_sz) ||
	    (!qp_srq_en && (log_qp_rq_size >
	    state->hs_cfg_profile->cp_log_max_qp_sz))) {
		status = IBT_HCA_WR_EXCEEDED;
		goto qpalloc_fail7;
	}

	/*
	 * Allocate the memory for QP work queues. Since Hermon work queues
	 * are not allowed to cross a 32-bit (4GB) boundary, the alignment of
	 * the work queue memory is very important.  We used to allocate
	 * work queues (the combined receive and send queues) so that they
	 * would be aligned on their combined size.  That alignment guaranteed
	 * that they would never cross the 4GB boundary (Hermon work queues
	 * are on the order of MBs at maximum).  Now we are able to relax
	 * this alignment constraint by ensuring that the IB address assigned
	 * to the queue memory (as a result of the hermon_mr_register() call)
	 * is offset from zero.
	 * Previously, we had wanted to use the ddi_dma_mem_alloc() routine to
	 * guarantee the alignment, but when attempting to use IOMMU bypass
	 * mode we found that we were not allowed to specify any alignment
	 * that was more restrictive than the system page size.
	 * So we avoided this constraint by passing two alignment values,
	 * one for the memory allocation itself and the other for the DMA
	 * handle (for later bind).  This used to cause more memory than
	 * necessary to be allocated (in order to guarantee the more
	 * restrictive alignment contraint).  But by guaranteeing the
	 * zero-based IB virtual address for the queue, we are able to
	 * conserve this memory.
	 */
	sq_wqe_size = 1 << qp->qp_sq_log_wqesz;
	sq_depth    = 1 << log_qp_sq_size;
	sq_size	    = sq_depth * sq_wqe_size;

	/* QP on SRQ sets these to 0 */
	if (qp_srq_en) {
		rq_wqe_size = 0;
		rq_size	    = 0;
	} else {
		rq_wqe_size = 1 << qp->qp_rq_log_wqesz;
		rq_depth    = 1 << log_qp_rq_size;
		rq_size	    = rq_depth * rq_wqe_size;
	}

	qp->qp_wqinfo.qa_size = sq_size + rq_size;
	qp->qp_wqinfo.qa_alloc_align = PAGESIZE;
	qp->qp_wqinfo.qa_bind_align  = PAGESIZE;
	qp->qp_wqinfo.qa_location = HERMON_QUEUE_LOCATION_NORMAL;
	status = hermon_queue_alloc(state, &qp->qp_wqinfo, sleepflag);
	if (status != DDI_SUCCESS) {
		status = IBT_INSUFF_RESOURCE;
		goto qpalloc_fail7;
	}

	/*
	 * Sort WQs in memory according to stride (*q_wqe_size), largest first
	 * If they are equal, still put the SQ first
	 */
	qp->qp_sq_baseaddr = 0;
	qp->qp_rq_baseaddr = 0;
	if ((sq_wqe_size > rq_wqe_size) || (sq_wqe_size == rq_wqe_size)) {
		sq_buf = qp->qp_wqinfo.qa_buf_aligned;

		/* if this QP is on an SRQ, set the rq_buf to NULL */
		if (qp_srq_en) {
			rq_buf = NULL;
		} else {
			rq_buf = (uint32_t *)((uintptr_t)sq_buf + sq_size);
			qp->qp_rq_baseaddr = sq_size;
		}
	} else {
		rq_buf = qp->qp_wqinfo.qa_buf_aligned;
		sq_buf = (uint32_t *)((uintptr_t)rq_buf + rq_size);
		qp->qp_sq_baseaddr = rq_size;
	}

	qp->qp_sq_wqhdr = hermon_wrid_wqhdr_create(sq_depth);
	if (qp->qp_sq_wqhdr == NULL) {
		status = IBT_INSUFF_RESOURCE;
		goto qpalloc_fail8;
	}
	if (qp_srq_en) {
		qp->qp_rq_wqavl.wqa_wq = srq->srq_wq_wqhdr;
		qp->qp_rq_wqavl.wqa_srq_en = 1;
		qp->qp_rq_wqavl.wqa_srq = srq;
	} else {
		qp->qp_rq_wqhdr = hermon_wrid_wqhdr_create(rq_depth);
		if (qp->qp_rq_wqhdr == NULL) {
			status = IBT_INSUFF_RESOURCE;
			goto qpalloc_fail8;
		}
		qp->qp_rq_wqavl.wqa_wq = qp->qp_rq_wqhdr;
	}
	qp->qp_sq_wqavl.wqa_qpn = qp->qp_qpnum;
	qp->qp_sq_wqavl.wqa_type = HERMON_WR_SEND;
	qp->qp_sq_wqavl.wqa_wq = qp->qp_sq_wqhdr;
	qp->qp_rq_wqavl.wqa_qpn = qp->qp_qpnum;
	qp->qp_rq_wqavl.wqa_type = HERMON_WR_RECV;

	/*
	 * Register the memory for the QP work queues.  The memory for the
	 * QP must be registered in the Hermon cMPT tables.  This gives us the
	 * LKey to specify in the QP context later.  Note: The memory for
	 * Hermon work queues (both Send and Recv) must be contiguous and
	 * registered as a single memory region.  Note: If the QP memory is
	 * user-mappable, force DDI_DMA_CONSISTENT mapping. Also, in order to
	 * meet the alignment restriction, we pass the "mro_bind_override_addr"
	 * flag in the call to hermon_mr_register(). This guarantees that the
	 * resulting IB vaddr will be zero-based (modulo the offset into the
	 * first page). If we fail here, we still have the bunch of resource
	 * and reference count cleanup to do.
	 */
	flag = (sleepflag == HERMON_SLEEP) ? IBT_MR_SLEEP :
	    IBT_MR_NOSLEEP;
	mr_attr.mr_vaddr    = (uint64_t)(uintptr_t)qp->qp_wqinfo.qa_buf_aligned;
	mr_attr.mr_len	    = qp->qp_wqinfo.qa_size;
	mr_attr.mr_as	    = NULL;
	mr_attr.mr_flags    = flag;
	/* HERMON_QUEUE_LOCATION_NORMAL */
	mr_op.mro_bind_type =
	    state->hs_cfg_profile->cp_iommu_bypass;
	mr_op.mro_bind_dmahdl = qp->qp_wqinfo.qa_dmahdl;
	mr_op.mro_bind_override_addr = 1;
	status = hermon_mr_register(state, pd, &mr_attr, &mr,
	    &mr_op, HERMON_QP_CMPT);
	if (status != DDI_SUCCESS) {
		status = IBT_INSUFF_RESOURCE;
		goto qpalloc_fail9;
	}

	/*
	 * Calculate the offset between the kernel virtual address space
	 * and the IB virtual address space.  This will be used when
	 * posting work requests to properly initialize each WQE.
	 */
	qp_desc_off = (uint64_t)(uintptr_t)qp->qp_wqinfo.qa_buf_aligned -
	    (uint64_t)mr->mr_bindinfo.bi_addr;

	/*
	 * Fill in all the return arguments (if necessary).  This includes
	 * real work queue sizes (in wqes), real SGLs, and QP number
	 */
	if (queuesz_p != NULL) {
		queuesz_p->cs_sq 	=
		    (1 << log_qp_sq_size) - qp->qp_sq_hdrmwqes;
		queuesz_p->cs_sq_sgl	= qp->qp_sq_sgl;

		/* if this QP is on an SRQ, set these to 0 */
		if (qp_srq_en) {
			queuesz_p->cs_rq	= 0;
			queuesz_p->cs_rq_sgl	= 0;
		} else {
			queuesz_p->cs_rq	= (1 << log_qp_rq_size);
			queuesz_p->cs_rq_sgl	= qp->qp_rq_sgl;
		}
	}

	/*
	 * Fill in the rest of the Hermon Queue Pair handle.
	 */
	qp->qp_qpcrsrcp		= NULL;
	qp->qp_rsrcp		= rsrc;
	qp->qp_state		= HERMON_QP_RESET;
	HERMON_SET_QP_POST_SEND_STATE(qp, HERMON_QP_RESET);
	qp->qp_pdhdl		= pd;
	qp->qp_mrhdl		= mr;
	qp->qp_sq_sigtype	= (attr_p->qp_flags & IBT_WR_SIGNALED) ?
	    HERMON_QP_SQ_WR_SIGNALED : HERMON_QP_SQ_ALL_SIGNALED;
	qp->qp_is_special	= 0;
	qp->qp_uarpg		= uarpg;
	qp->qp_umap_dhp		= (devmap_cookie_t)NULL;
	qp->qp_sq_cqhdl		= sq_cq;
	qp->qp_sq_bufsz		= (1 << log_qp_sq_size);
	qp->qp_sq_logqsz	= log_qp_sq_size;
	qp->qp_sq_buf		= sq_buf;
	qp->qp_desc_off		= qp_desc_off;
	qp->qp_rq_cqhdl		= rq_cq;
	qp->qp_rq_buf		= rq_buf;
	qp->qp_rlky		= (attr_p->qp_flags & IBT_FAST_REG_RES_LKEY) !=
	    0;

	/* if this QP is on an SRQ, set rq_bufsz to 0 */
	if (qp_srq_en) {
		qp->qp_rq_bufsz		= 0;
		qp->qp_rq_logqsz	= 0;
	} else {
		qp->qp_rq_bufsz		= (1 << log_qp_rq_size);
		qp->qp_rq_logqsz	= log_qp_rq_size;
	}

	qp->qp_forward_sqd_event  = 0;
	qp->qp_sqd_still_draining = 0;
	qp->qp_hdlrarg		= (void *)ibt_qphdl[ii];
	qp->qp_mcg_refcnt	= 0;

	/*
	 * If this QP is to be associated with an SRQ, set the SRQ handle
	 */
	if (qp_srq_en) {
		qp->qp_srqhdl = srq;
		hermon_srq_refcnt_inc(qp->qp_srqhdl);
	} else {
		qp->qp_srqhdl = NULL;
	}

	qp->qp_type = IBT_UD_RQP;
	qp->qp_serv_type = serv_type;

	/*
	 * Initialize the RQ WQEs - unlike Arbel, no Rcv init is needed
	 */

	/*
	 * Initialize the SQ WQEs - all that needs to be done is every 64 bytes
	 * set the quadword to all F's - high-order bit is owner (init to one)
	 * and the rest for the headroom definition of prefetching.
	 */
	if ((attr_p->qp_alloc_flags & IBT_QP_USES_FEXCH) == 0) {
		wqesz_shift = qp->qp_sq_log_wqesz;
		thewqesz    = 1 << wqesz_shift;
		thewqe = (uint64_t *)(void *)(qp->qp_sq_buf);
		for (i = 0; i < sq_depth; i++) {
			/*
			 * for each stride, go through and every 64 bytes
			 * write the init value - having set the address
			 * once, just keep incrementing it
			 */
			for (j = 0; j < thewqesz; j += 64, thewqe += 8) {
				*(uint32_t *)thewqe = 0xFFFFFFFF;
			}
		}
	}

	/* Zero out the QP context */
	bzero(&qp->qpc, sizeof (hermon_hw_qpc_t));

	/*
	 * Put QP handle in Hermon QPNum-to-QPHdl list.  Then fill in the
	 * "qphdl" and return success
	 */
	hermon_icm_set_num_to_hdl(state, HERMON_QPC, qpc->hr_indx + ii, qp);

	mutex_init(&qp->qp_sq_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(state->hs_intrmsi_pri));

	qp->qp_rangep = qp_range_p;

	qphdl[ii] = qp;

	if (++ii < (1 << log2))
		goto for_each_qp;

	return (DDI_SUCCESS);

/*
 * The following is cleanup for all possible failure cases in this routine
 */
qpalloc_fail9:
	hermon_queue_free(&qp->qp_wqinfo);
qpalloc_fail8:
	if (qp->qp_sq_wqhdr)
		hermon_wrid_wqhdr_destroy(qp->qp_sq_wqhdr);
	if (qp->qp_rq_wqhdr)
		hermon_wrid_wqhdr_destroy(qp->qp_rq_wqhdr);
qpalloc_fail7:
	if (!qp_srq_en) {
		hermon_dbr_free(state, uarpg, qp->qp_rq_vdbr);
	}

qpalloc_fail6:
	hermon_rsrc_free(state, &rsrc);
qpalloc_fail4:
	hermon_cq_refcnt_dec(rq_cq);
qpalloc_fail2:
	hermon_cq_refcnt_dec(sq_cq);
qpalloc_fail1:
	hermon_pd_refcnt_dec(pd);
qpalloc_fail0:
	if (ii == 0) {
		if (qp_range_p)
			kmem_free(qp_range_p, sizeof (*qp_range_p));
		hermon_rsrc_free(state, &qpc);
	} else {
		/* qp_range_p and qpc rsrc will be freed in hermon_qp_free */

		mutex_enter(&qp->qp_rangep->hqpr_lock);
		qp_range_p->hqpr_refcnt = ii;
		mutex_exit(&qp->qp_rangep->hqpr_lock);
		while (--ii >= 0) {
			ibc_qpn_hdl_t qpn_hdl;
			int free_status;

			free_status = hermon_qp_free(state, &qphdl[ii],
			    IBC_FREE_QP_AND_QPN, &qpn_hdl, sleepflag);
			if (free_status != DDI_SUCCESS)
				cmn_err(CE_CONT, "!qp_range: status 0x%x: "
				    "error status %x during free",
				    status, free_status);
		}
	}

	return (status);
}


/*
 * hermon_qp_free()
 *    This function frees up the QP resources.  Depending on the value
 *    of the "free_qp_flags", the QP number may not be released until
 *    a subsequent call to hermon_qp_release_qpn().
 *
 *    Context: Can be called only from user or kernel context.
 */
/* ARGSUSED */
int
hermon_qp_free(hermon_state_t *state, hermon_qphdl_t *qphdl,
    ibc_free_qp_flags_t free_qp_flags, ibc_qpn_hdl_t *qpnh,
    uint_t sleepflag)
{
	hermon_rsrc_t		*qpc, *rsrc;
	hermon_umap_db_entry_t	*umapdb;
	hermon_qpn_entry_t	*entry;
	hermon_pdhdl_t		pd;
	hermon_mrhdl_t		mr;
	hermon_cqhdl_t		sq_cq, rq_cq;
	hermon_srqhdl_t		srq;
	hermon_qphdl_t		qp;
	uint64_t		value;
	uint_t			type, port;
	uint_t			maxprot;
	uint_t			qp_srq_en;
	int			status;

	/*
	 * Pull all the necessary information from the Hermon Queue Pair
	 * handle.  This is necessary here because the resource for the
	 * QP handle is going to be freed up as part of this operation.
	 */
	qp	= *qphdl;
	mutex_enter(&qp->qp_lock);
	qpc	= qp->qp_qpcrsrcp;	/* NULL if part of a "range" */
	rsrc	= qp->qp_rsrcp;
	pd	= qp->qp_pdhdl;
	srq	= qp->qp_srqhdl;
	mr	= qp->qp_mrhdl;
	rq_cq	= qp->qp_rq_cqhdl;
	sq_cq	= qp->qp_sq_cqhdl;
	port	= qp->qp_portnum;
	qp_srq_en = qp->qp_alloc_flags & IBT_QP_USES_SRQ;

	/*
	 * If the QP is part of an MCG, then we fail the qp_free
	 */
	if (qp->qp_mcg_refcnt != 0) {
		mutex_exit(&qp->qp_lock);
		status = ibc_get_ci_failure(0);
		goto qpfree_fail;
	}

	/*
	 * If the QP is not already in "Reset" state, then transition to
	 * "Reset".  This is necessary because software does not reclaim
	 * ownership of the QP context until the QP is in the "Reset" state.
	 * If the ownership transfer fails for any reason, then it is an
	 * indication that something (either in HW or SW) has gone seriously
	 * wrong.  So we print a warning message and return.
	 */
	if (qp->qp_state != HERMON_QP_RESET) {
		if (hermon_qp_to_reset(state, qp) != DDI_SUCCESS) {
			mutex_exit(&qp->qp_lock);
			HERMON_WARNING(state, "failed to reset QP context");
			status = ibc_get_ci_failure(0);
			goto qpfree_fail;
		}
		qp->qp_state = HERMON_QP_RESET;
		HERMON_SET_QP_POST_SEND_STATE(qp, HERMON_QP_RESET);

		/*
		 * Do any additional handling necessary for the transition
		 * to the "Reset" state (e.g. update the WRID lists)
		 */
		if (hermon_wrid_to_reset_handling(state, qp) != DDI_SUCCESS) {
			mutex_exit(&qp->qp_lock);
			HERMON_WARNING(state, "failed to reset QP WRID list");
			status = ibc_get_ci_failure(0);
			goto qpfree_fail;
		}
	}

	/*
	 * If this was a user-mappable QP, then we need to remove its entry
	 * from the "userland resources database".  If it is also currently
	 * mmap()'d out to a user process, then we need to call
	 * devmap_devmem_remap() to remap the QP memory to an invalid mapping.
	 * We also need to invalidate the QP tracking information for the
	 * user mapping.
	 */
	if (qp->qp_alloc_flags & IBT_QP_USER_MAP) {
		status = hermon_umap_db_find(state->hs_instance, qp->qp_qpnum,
		    MLNX_UMAP_QPMEM_RSRC, &value, HERMON_UMAP_DB_REMOVE,
		    &umapdb);
		if (status != DDI_SUCCESS) {
			mutex_exit(&qp->qp_lock);
			HERMON_WARNING(state, "failed to find in database");
			return (ibc_get_ci_failure(0));
		}
		hermon_umap_db_free(umapdb);
		if (qp->qp_umap_dhp != NULL) {
			maxprot = (PROT_READ | PROT_WRITE | PROT_USER);
			status = devmap_devmem_remap(qp->qp_umap_dhp,
			    state->hs_dip, 0, 0, qp->qp_wqinfo.qa_size,
			    maxprot, DEVMAP_MAPPING_INVALID, NULL);
			if (status != DDI_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				HERMON_WARNING(state, "failed in QP memory "
				    "devmap_devmem_remap()");
				return (ibc_get_ci_failure(0));
			}
			qp->qp_umap_dhp = (devmap_cookie_t)NULL;
		}
	}


	/*
	 * Put NULL into the Hermon QPNum-to-QPHdl list.  This will allow any
	 * in-progress events to detect that the QP corresponding to this
	 * number has been freed.  Note: it does depend in whether we are
	 * freeing a special QP or not.
	 */
	if (qpc == NULL) {
		hermon_icm_set_num_to_hdl(state, HERMON_QPC,
		    qp->qp_qpnum, NULL);
	} else if (qp->qp_is_special) {
		hermon_icm_set_num_to_hdl(state, HERMON_QPC,
		    qpc->hr_indx + port, NULL);
	} else {
		hermon_icm_set_num_to_hdl(state, HERMON_QPC,
		    qpc->hr_indx, NULL);
	}

	/*
	 * Drop the QP lock
	 *    At this point the lock is no longer necessary.  We cannot
	 *    protect from multiple simultaneous calls to free the same QP.
	 *    In addition, since the QP lock is contained in the QP "software
	 *    handle" resource, which we will free (see below), it is
	 *    important that we have no further references to that memory.
	 */
	mutex_exit(&qp->qp_lock);
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*qp))

	/*
	 * Free the QP resources
	 *    Start by deregistering and freeing the memory for work queues.
	 *    Next free any previously allocated context information
	 *    (depending on QP type)
	 *    Finally, decrement the necessary reference counts.
	 * If this fails for any reason, then it is an indication that
	 * something (either in HW or SW) has gone seriously wrong.  So we
	 * print a warning message and return.
	 */
	status = hermon_mr_deregister(state, &mr, HERMON_MR_DEREG_ALL,
	    sleepflag);
	if (status != DDI_SUCCESS) {
		HERMON_WARNING(state, "failed to deregister QP memory");
		status = ibc_get_ci_failure(0);
		goto qpfree_fail;
	}

	/* Free the memory for the QP */
	hermon_queue_free(&qp->qp_wqinfo);

	if (qp->qp_sq_wqhdr)
		hermon_wrid_wqhdr_destroy(qp->qp_sq_wqhdr);
	if (qp->qp_rq_wqhdr)
		hermon_wrid_wqhdr_destroy(qp->qp_rq_wqhdr);

	/* Free the dbr */
	if (!qp_srq_en) {
		hermon_dbr_free(state, qp->qp_uarpg, qp->qp_rq_vdbr);
	}

	/*
	 * Free up the remainder of the QP resources.  Note: we have a few
	 * different resources to free up depending on whether the QP is a
	 * special QP or not.  As described above, if any of these fail for
	 * any reason it is an indication that something (either in HW or SW)
	 * has gone seriously wrong.  So we print a warning message and
	 * return.
	 */
	if (qp->qp_is_special) {
		type = (qp->qp_is_special == HERMON_QP_SMI) ?
		    IBT_SMI_SQP : IBT_GSI_SQP;

		/* Free up resources for the special QP */
		status = hermon_special_qp_rsrc_free(state, type, port);
		if (status != DDI_SUCCESS) {
			HERMON_WARNING(state, "failed to free special QP rsrc");
			status = ibc_get_ci_failure(0);
			goto qpfree_fail;
		}

	} else if (qp->qp_rangep) {
		int refcnt;
		mutex_enter(&qp->qp_rangep->hqpr_lock);
		refcnt = --qp->qp_rangep->hqpr_refcnt;
		mutex_exit(&qp->qp_rangep->hqpr_lock);
		if (refcnt == 0) {
			mutex_destroy(&qp->qp_rangep->hqpr_lock);
			hermon_rsrc_free(state, &qp->qp_rangep->hqpr_qpcrsrc);
			kmem_free(qp->qp_rangep, sizeof (*qp->qp_rangep));
		}
		qp->qp_rangep = NULL;
	} else if (qp->qp_qpn_hdl == NULL) {
		hermon_rsrc_free(state, &qpc);
	} else {
		/*
		 * Check the flags and determine whether to release the
		 * QPN or not, based on their value.
		 */
		if (free_qp_flags == IBC_FREE_QP_ONLY) {
			entry = qp->qp_qpn_hdl;
			hermon_qp_release_qpn(state, qp->qp_qpn_hdl,
			    HERMON_QPN_FREE_ONLY);
			*qpnh = (ibc_qpn_hdl_t)entry;
		} else {
			hermon_qp_release_qpn(state, qp->qp_qpn_hdl,
			    HERMON_QPN_RELEASE);
		}
	}

	mutex_destroy(&qp->qp_sq_lock);

	/* Free the Hermon Queue Pair handle */
	hermon_rsrc_free(state, &rsrc);

	/* Decrement the reference counts on CQs, PD and SRQ (if needed) */
	hermon_cq_refcnt_dec(rq_cq);
	hermon_cq_refcnt_dec(sq_cq);
	hermon_pd_refcnt_dec(pd);
	if (qp_srq_en == HERMON_QP_SRQ_ENABLED) {
		hermon_srq_refcnt_dec(srq);
	}

	/* Set the qphdl pointer to NULL and return success */
	*qphdl = NULL;

	return (DDI_SUCCESS);

qpfree_fail:
	return (status);
}


/*
 * hermon_qp_query()
 *    Context: Can be called from interrupt or base context.
 */
int
hermon_qp_query(hermon_state_t *state, hermon_qphdl_t qp,
    ibt_qp_query_attr_t *attr_p)
{
	ibt_cep_state_t		qp_state;
	ibt_qp_ud_attr_t	*ud;
	ibt_qp_rc_attr_t	*rc;
	ibt_qp_uc_attr_t	*uc;
	ibt_cep_flags_t		enable_flags;
	hermon_hw_addr_path_t	*qpc_path, *qpc_alt_path;
	ibt_cep_path_t		*path_ptr, *alt_path_ptr;
	hermon_hw_qpc_t		*qpc;
	int			status;
	uint_t			tmp_sched_q, tmp_alt_sched_q;

	mutex_enter(&qp->qp_lock);

	/*
	 * Grab the temporary QPC entry from QP software state
	 */
	qpc = &qp->qpc;

	/* Convert the current Hermon QP state to IBTF QP state */
	switch (qp->qp_state) {
	case HERMON_QP_RESET:
		qp_state = IBT_STATE_RESET;		/* "Reset" */
		break;
	case HERMON_QP_INIT:
		qp_state = IBT_STATE_INIT;		/* Initialized */
		break;
	case HERMON_QP_RTR:
		qp_state = IBT_STATE_RTR;		/* Ready to Receive */
		break;
	case HERMON_QP_RTS:
		qp_state = IBT_STATE_RTS;		/* Ready to Send */
		break;
	case HERMON_QP_SQERR:
		qp_state = IBT_STATE_SQE;		/* Send Queue Error */
		break;
	case HERMON_QP_SQD:
		if (qp->qp_sqd_still_draining) {
			qp_state = IBT_STATE_SQDRAIN;	/* SQ Draining */
		} else {
			qp_state = IBT_STATE_SQD;	/* SQ Drained */
		}
		break;
	case HERMON_QP_ERR:
		qp_state = IBT_STATE_ERROR;		/* Error */
		break;
	default:
		mutex_exit(&qp->qp_lock);
		return (ibc_get_ci_failure(0));
	}
	attr_p->qp_info.qp_state = qp_state;

	/* SRQ Hook. */
	attr_p->qp_srq = NULL;

	/*
	 * The following QP information is always returned, regardless of
	 * the current QP state.  Note: Some special handling is necessary
	 * for calculating the QP number on special QP (QP0 and QP1).
	 */
	attr_p->qp_sq_cq    =
	    (qp->qp_sq_cqhdl == NULL) ? NULL : qp->qp_sq_cqhdl->cq_hdlrarg;
	attr_p->qp_rq_cq    =
	    (qp->qp_rq_cqhdl == NULL) ? NULL : qp->qp_rq_cqhdl->cq_hdlrarg;
	if (qp->qp_is_special) {
		attr_p->qp_qpn = (qp->qp_is_special == HERMON_QP_SMI) ? 0 : 1;
	} else {
		attr_p->qp_qpn = (ib_qpn_t)qp->qp_qpnum;
	}
	attr_p->qp_sq_sgl   = qp->qp_sq_sgl;
	attr_p->qp_rq_sgl   = qp->qp_rq_sgl;
	attr_p->qp_info.qp_sq_sz = qp->qp_sq_bufsz - qp->qp_sq_hdrmwqes;
	attr_p->qp_info.qp_rq_sz = qp->qp_rq_bufsz;

	/*
	 * If QP is currently in the "Reset" state, then only the above are
	 * returned
	 */
	if (qp_state == IBT_STATE_RESET) {
		mutex_exit(&qp->qp_lock);
		return (DDI_SUCCESS);
	}

	/*
	 * Post QUERY_QP command to firmware
	 *
	 * We do a HERMON_NOSLEEP here because we are holding the "qp_lock".
	 * Since we may be in the interrupt context (or subsequently raised
	 * to interrupt level by priority inversion), we do not want to block
	 * in this routine waiting for success.
	 */
	tmp_sched_q = qpc->pri_addr_path.sched_q;
	tmp_alt_sched_q = qpc->alt_addr_path.sched_q;
	status = hermon_cmn_query_cmd_post(state, QUERY_QP, 0, qp->qp_qpnum,
	    qpc, sizeof (hermon_hw_qpc_t), HERMON_CMD_NOSLEEP_SPIN);
	if (status != HERMON_CMD_SUCCESS) {
		mutex_exit(&qp->qp_lock);
		cmn_err(CE_WARN, "hermon%d: hermon_qp_query: QUERY_QP "
		    "command failed: %08x\n", state->hs_instance, status);
		if (status == HERMON_CMD_INVALID_STATUS) {
			hermon_fm_ereport(state, HCA_SYS_ERR, HCA_ERR_SRV_LOST);
		}
		return (ibc_get_ci_failure(0));
	}
	qpc->pri_addr_path.sched_q = tmp_sched_q;
	qpc->alt_addr_path.sched_q = tmp_alt_sched_q;

	/*
	 * Fill in the additional QP info based on the QP's transport type.
	 */
	if (qp->qp_type == IBT_UD_RQP) {

		/* Fill in the UD-specific info */
		ud = &attr_p->qp_info.qp_transport.ud;
		ud->ud_qkey	= (ib_qkey_t)qpc->qkey;
		ud->ud_sq_psn	= qpc->next_snd_psn;
		ud->ud_pkey_ix	= qpc->pri_addr_path.pkey_indx;
		/* port+1 for port 1/2 */
		ud->ud_port	=
		    (uint8_t)(((qpc->pri_addr_path.sched_q >> 6) & 0x01) + 1);

		attr_p->qp_info.qp_trans = IBT_UD_SRV;

		if (qp->qp_serv_type == HERMON_QP_FEXCH) {
			ibt_pmr_desc_t *pmr;
			uint64_t heart_beat;

			_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*pmr))
			pmr = &attr_p->qp_query_fexch.fq_uni_mem_desc;
			pmr->pmd_iova = 0;
			pmr->pmd_lkey = pmr->pmd_rkey =
			    hermon_fcoib_qpn_to_mkey(state, qp->qp_qpnum);
			pmr->pmd_phys_buf_list_sz =
			    state->hs_fcoib.hfc_mtts_per_mpt;
			pmr->pmd_sync_required = 0;

			pmr = &attr_p->qp_query_fexch.fq_bi_mem_desc;
			pmr->pmd_iova = 0;
			pmr->pmd_lkey = 0;
			pmr->pmd_rkey = 0;
			pmr->pmd_phys_buf_list_sz = 0;
			pmr->pmd_sync_required = 0;

			attr_p->qp_query_fexch.fq_flags =
			    ((hermon_get_heart_beat_rq_cmd_post(state,
			    qp->qp_qpnum, &heart_beat) == HERMON_CMD_SUCCESS) &&
			    (heart_beat == 0)) ? IBT_FEXCH_HEART_BEAT_OK :
			    IBT_FEXCH_NO_FLAGS;

			ud->ud_fc = qp->qp_fc_attr;
		} else if (qp->qp_serv_type == HERMON_QP_FCMND ||
		    qp->qp_serv_type == HERMON_QP_RFCI) {
			ud->ud_fc = qp->qp_fc_attr;
		}

	} else if (qp->qp_serv_type == HERMON_QP_RC) {

		/* Fill in the RC-specific info */
		rc = &attr_p->qp_info.qp_transport.rc;
		rc->rc_sq_psn	= qpc->next_snd_psn;
		rc->rc_rq_psn	= qpc->next_rcv_psn;
		rc->rc_dst_qpn	= qpc->rem_qpn;

		/* Grab the path migration state information */
		if (qpc->pm_state == HERMON_QP_PMSTATE_MIGRATED) {
			rc->rc_mig_state = IBT_STATE_MIGRATED;
		} else if (qpc->pm_state == HERMON_QP_PMSTATE_REARM) {
			rc->rc_mig_state = IBT_STATE_REARMED;
		} else {
			rc->rc_mig_state = IBT_STATE_ARMED;
		}
		rc->rc_rdma_ra_out = (1 << qpc->sra_max);
		rc->rc_rdma_ra_in  = (1 << qpc->rra_max);
		rc->rc_min_rnr_nak = qpc->min_rnr_nak;
		rc->rc_path_mtu	   = qpc->mtu;
		rc->rc_retry_cnt   = qpc->retry_cnt;

		/* Get the common primary address path fields */
		qpc_path = &qpc->pri_addr_path;
		path_ptr = &rc->rc_path;
		hermon_get_addr_path(state, qpc_path, &path_ptr->cep_adds_vect,
		    HERMON_ADDRPATH_QP);

		/* Fill in the additional primary address path fields */
		path_ptr->cep_pkey_ix	   = qpc_path->pkey_indx;
		path_ptr->cep_hca_port_num =
		    path_ptr->cep_adds_vect.av_port_num =
		    (uint8_t)(((qpc_path->sched_q >> 6) & 0x01) + 1);
		path_ptr->cep_timeout	   = qpc_path->ack_timeout;

		/* Get the common alternate address path fields */
		qpc_alt_path = &qpc->alt_addr_path;
		alt_path_ptr = &rc->rc_alt_path;
		hermon_get_addr_path(state, qpc_alt_path,
		    &alt_path_ptr->cep_adds_vect, HERMON_ADDRPATH_QP);

		/* Fill in the additional alternate address path fields */
		alt_path_ptr->cep_pkey_ix	= qpc_alt_path->pkey_indx;
		alt_path_ptr->cep_hca_port_num	=
		    alt_path_ptr->cep_adds_vect.av_port_num =
		    (uint8_t)(((qpc_alt_path->sched_q >> 6) & 0x01) + 1);
		alt_path_ptr->cep_timeout	= qpc_alt_path->ack_timeout;

		/* Get the RNR retry time from primary path */
		rc->rc_rnr_retry_cnt = qpc->rnr_retry;

		/* Set the enable flags based on RDMA/Atomic enable bits */
		enable_flags = IBT_CEP_NO_FLAGS;
		enable_flags |= ((qpc->rre == 0) ? 0 : IBT_CEP_RDMA_RD);
		enable_flags |= ((qpc->rwe == 0) ? 0 : IBT_CEP_RDMA_WR);
		enable_flags |= ((qpc->rae == 0) ? 0 : IBT_CEP_ATOMIC);
		attr_p->qp_info.qp_flags = enable_flags;

		attr_p->qp_info.qp_trans = IBT_RC_SRV;

	} else if (qp->qp_serv_type == HERMON_QP_UC) {

		/* Fill in the UC-specific info */
		uc = &attr_p->qp_info.qp_transport.uc;
		uc->uc_sq_psn	= qpc->next_snd_psn;
		uc->uc_rq_psn	= qpc->next_rcv_psn;
		uc->uc_dst_qpn	= qpc->rem_qpn;

		/* Grab the path migration state information */
		if (qpc->pm_state == HERMON_QP_PMSTATE_MIGRATED) {
			uc->uc_mig_state = IBT_STATE_MIGRATED;
		} else if (qpc->pm_state == HERMON_QP_PMSTATE_REARM) {
			uc->uc_mig_state = IBT_STATE_REARMED;
		} else {
			uc->uc_mig_state = IBT_STATE_ARMED;
		}
		uc->uc_path_mtu = qpc->mtu;

		/* Get the common primary address path fields */
		qpc_path = &qpc->pri_addr_path;
		path_ptr = &uc->uc_path;
		hermon_get_addr_path(state, qpc_path, &path_ptr->cep_adds_vect,
		    HERMON_ADDRPATH_QP);

		/* Fill in the additional primary address path fields */
		path_ptr->cep_pkey_ix	   = qpc_path->pkey_indx;
		path_ptr->cep_hca_port_num =
		    path_ptr->cep_adds_vect.av_port_num =
		    (uint8_t)(((qpc_path->sched_q >> 6) & 0x01) + 1);

		/* Get the common alternate address path fields */
		qpc_alt_path = &qpc->alt_addr_path;
		alt_path_ptr = &uc->uc_alt_path;
		hermon_get_addr_path(state, qpc_alt_path,
		    &alt_path_ptr->cep_adds_vect, HERMON_ADDRPATH_QP);

		/* Fill in the additional alternate address path fields */
		alt_path_ptr->cep_pkey_ix	= qpc_alt_path->pkey_indx;
		alt_path_ptr->cep_hca_port_num	=
		    alt_path_ptr->cep_adds_vect.av_port_num =
		    (uint8_t)(((qpc_alt_path->sched_q >> 6) & 0x01) + 1);

		/*
		 * Set the enable flags based on RDMA enable bits (by
		 * definition UC doesn't support Atomic or RDMA Read)
		 */
		enable_flags = ((qpc->rwe == 0) ? 0 : IBT_CEP_RDMA_WR);
		attr_p->qp_info.qp_flags = enable_flags;

		attr_p->qp_info.qp_trans = IBT_UC_SRV;

	} else {
		HERMON_WARNING(state, "unexpected QP transport type");
		mutex_exit(&qp->qp_lock);
		return (ibc_get_ci_failure(0));
	}

	/*
	 * Under certain circumstances it is possible for the Hermon hardware
	 * to transition to one of the error states without software directly
	 * knowing about it.  The QueryQP() call is the one place where we
	 * have an opportunity to sample and update our view of the QP state.
	 */
	if (qpc->state == HERMON_QP_SQERR) {
		attr_p->qp_info.qp_state = IBT_STATE_SQE;
		qp->qp_state = HERMON_QP_SQERR;
		HERMON_SET_QP_POST_SEND_STATE(qp, HERMON_QP_SQERR);
	}
	if (qpc->state == HERMON_QP_ERR) {
		attr_p->qp_info.qp_state = IBT_STATE_ERROR;
		qp->qp_state = HERMON_QP_ERR;
		HERMON_SET_QP_POST_SEND_STATE(qp, HERMON_QP_ERR);
	}
	mutex_exit(&qp->qp_lock);

	return (DDI_SUCCESS);
}


/*
 * hermon_qp_create_qpn()
 *    Context: Can be called from interrupt or base context.
 */
static int
hermon_qp_create_qpn(hermon_state_t *state, hermon_qphdl_t qp,
    hermon_rsrc_t *qpc)
{
	hermon_qpn_entry_t	query;
	hermon_qpn_entry_t	*entry;
	avl_index_t		where;

	/*
	 * Build a query (for the AVL tree lookup) and attempt to find
	 * a previously added entry that has a matching QPC index.  If
	 * no matching entry is found, then allocate, initialize, and
	 * add an entry to the AVL tree.
	 * If a matching entry is found, then increment its QPN counter
	 * and reference counter.
	 */
	query.qpn_indx = qpc->hr_indx;
	mutex_enter(&state->hs_qpn_avl_lock);
	entry = (hermon_qpn_entry_t *)avl_find(&state->hs_qpn_avl,
	    &query, &where);
	if (entry == NULL) {
		/*
		 * Allocate and initialize a QPN entry, then insert
		 * it into the AVL tree.
		 */
		entry = (hermon_qpn_entry_t *)kmem_zalloc(
		    sizeof (hermon_qpn_entry_t), KM_NOSLEEP);
		if (entry == NULL) {
			mutex_exit(&state->hs_qpn_avl_lock);
			return (DDI_FAILURE);
		}
		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*entry))

		entry->qpn_indx	   = qpc->hr_indx;
		entry->qpn_refcnt  = 0;
		entry->qpn_counter = 0;

		avl_insert(&state->hs_qpn_avl, entry, where);
	}

	/*
	 * Make the AVL tree entry point to the QP context resource that
	 * it will be responsible for tracking
	 */
	entry->qpn_qpc = qpc;

	/*
	 * Setup the QP handle to point to the AVL tree entry.  Then
	 * generate the new QP number from the entry's QPN counter value
	 * and the hardware's QP context table index.
	 */
	qp->qp_qpn_hdl	= entry;
	qp->qp_qpnum	= ((entry->qpn_counter <<
	    state->hs_cfg_profile->cp_log_num_qp) | qpc->hr_indx) &
	    HERMON_QP_MAXNUMBER_MSK;
	qp->qp_ring = qp->qp_qpnum << 8;

	/*
	 * Increment the reference counter and QPN counter.  The QPN
	 * counter always indicates the next available number for use.
	 */
	entry->qpn_counter++;
	entry->qpn_refcnt++;

	mutex_exit(&state->hs_qpn_avl_lock);

	return (DDI_SUCCESS);
}


/*
 * hermon_qp_release_qpn()
 *    Context: Can be called only from user or kernel context.
 */
void
hermon_qp_release_qpn(hermon_state_t *state, hermon_qpn_entry_t *entry,
    int flags)
{
	ASSERT(entry != NULL);

	mutex_enter(&state->hs_qpn_avl_lock);

	/*
	 * If we are releasing the QP number here, then we decrement the
	 * reference count and check for zero references.  If there are
	 * zero references, then we free the QPC context (if it hadn't
	 * already been freed during a HERMON_QPN_FREE_ONLY free, i.e. for
	 * reuse with another similar QP number) and remove the tracking
	 * structure from the QP number AVL tree and free the structure.
	 * If we are not releasing the QP number here, then, as long as we
	 * have not exhausted the usefulness of the QPC context (that is,
	 * re-used it too many times without the reference count having
	 * gone to zero), we free up the QPC context for use by another
	 * thread (which will use it to construct a different QP number
	 * from the same QPC table index).
	 */
	if (flags == HERMON_QPN_RELEASE) {
		entry->qpn_refcnt--;

		/*
		 * If the reference count is zero, then we free the QPC
		 * context (if it hadn't already been freed in an early
		 * step, e.g. HERMON_QPN_FREE_ONLY) and remove/free the
		 * tracking structure from the QP number AVL tree.
		 */
		if (entry->qpn_refcnt == 0) {
			if (entry->qpn_qpc != NULL) {
				hermon_rsrc_free(state, &entry->qpn_qpc);
			}

			/*
			 * If the current entry has served it's useful
			 * purpose (i.e. been reused the maximum allowable
			 * number of times), then remove it from QP number
			 * AVL tree and free it up.
			 */
			if (entry->qpn_counter >= (1 <<
			    (24 - state->hs_cfg_profile->cp_log_num_qp))) {
				avl_remove(&state->hs_qpn_avl, entry);
				kmem_free(entry, sizeof (hermon_qpn_entry_t));
			}
		}

	} else if (flags == HERMON_QPN_FREE_ONLY) {
		/*
		 * Even if we are not freeing the QP number, that will not
		 * always prevent us from releasing the QPC context.  In fact,
		 * since the QPC context only forms part of the whole QPN,
		 * we want to free it up for use by other consumers.  But
		 * if the reference count is non-zero (which it will always
		 * be when we are doing HERMON_QPN_FREE_ONLY) and the counter
		 * has reached its maximum value, then we cannot reuse the
		 * QPC context until the reference count eventually reaches
		 * zero (in HERMON_QPN_RELEASE, above).
		 */
		if (entry->qpn_counter < (1 <<
		    (24 - state->hs_cfg_profile->cp_log_num_qp))) {
			hermon_rsrc_free(state, &entry->qpn_qpc);
		}
	}
	mutex_exit(&state->hs_qpn_avl_lock);
}


/*
 * hermon_qpn_avl_compare()
 *    Context: Can be called from user or kernel context.
 */
static int
hermon_qpn_avl_compare(const void *q, const void *e)
{
	hermon_qpn_entry_t	*entry, *query;

	entry = (hermon_qpn_entry_t *)e;
	query = (hermon_qpn_entry_t *)q;

	if (query->qpn_indx < entry->qpn_indx) {
		return (-1);
	} else if (query->qpn_indx > entry->qpn_indx) {
		return (+1);
	} else {
		return (0);
	}
}


/*
 * hermon_qpn_avl_init()
 *    Context: Only called from attach() path context
 */
void
hermon_qpn_avl_init(hermon_state_t *state)
{
	/* Initialize the lock used for QP number (QPN) AVL tree access */
	mutex_init(&state->hs_qpn_avl_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(state->hs_intrmsi_pri));

	/* Initialize the AVL tree for the QP number (QPN) storage */
	avl_create(&state->hs_qpn_avl, hermon_qpn_avl_compare,
	    sizeof (hermon_qpn_entry_t),
	    offsetof(hermon_qpn_entry_t, qpn_avlnode));
}


/*
 * hermon_qpn_avl_fini()
 *    Context: Only called from attach() and/or detach() path contexts
 */
void
hermon_qpn_avl_fini(hermon_state_t *state)
{
	hermon_qpn_entry_t	*entry;
	void			*cookie;

	/*
	 * Empty all entries (if necessary) and destroy the AVL tree
	 * that was used for QP number (QPN) tracking.
	 */
	cookie = NULL;
	while ((entry = (hermon_qpn_entry_t *)avl_destroy_nodes(
	    &state->hs_qpn_avl, &cookie)) != NULL) {
		kmem_free(entry, sizeof (hermon_qpn_entry_t));
	}
	avl_destroy(&state->hs_qpn_avl);

	/* Destroy the lock used for QP number (QPN) AVL tree access */
	mutex_destroy(&state->hs_qpn_avl_lock);
}


/*
 * hermon_qphdl_from_qpnum()
 *    Context: Can be called from interrupt or base context.
 *
 *    This routine is important because changing the unconstrained
 *    portion of the QP number is critical to the detection of a
 *    potential race condition in the QP event handler code (i.e. the case
 *    where a QP is freed and alloc'd again before an event for the
 *    "old" QP can be handled).
 *
 *    While this is not a perfect solution (not sure that one exists)
 *    it does help to mitigate the chance that this race condition will
 *    cause us to deliver a "stale" event to the new QP owner.  Note:
 *    this solution does not scale well because the number of constrained
 *    bits increases (and, hence, the number of unconstrained bits
 *    decreases) as the number of supported QPs grows.  For small and
 *    intermediate values, it should hopefully provide sufficient
 *    protection.
 */
hermon_qphdl_t
hermon_qphdl_from_qpnum(hermon_state_t *state, uint_t qpnum)
{
	uint_t	qpindx, qpmask;

	/* Calculate the QP table index from the qpnum */
	qpmask = (1 << state->hs_cfg_profile->cp_log_num_qp) - 1;
	qpindx = qpnum & qpmask;
	return (hermon_icm_num_to_hdl(state, HERMON_QPC, qpindx));
}


/*
 * hermon_special_qp_rsrc_alloc
 *    Context: Can be called from interrupt or base context.
 */
static int
hermon_special_qp_rsrc_alloc(hermon_state_t *state, ibt_sqp_type_t type,
    uint_t port, hermon_rsrc_t **qp_rsrc)
{
	uint_t		mask, flags;
	int		status;

	mutex_enter(&state->hs_spec_qplock);
	flags = state->hs_spec_qpflags;
	if (type == IBT_SMI_SQP) {
		/*
		 * Check here to see if the driver has been configured
		 * to instruct the Hermon firmware to handle all incoming
		 * SMP messages (i.e. messages sent to SMA).  If so,
		 * then we will treat QP0 as if it has already been
		 * allocated (for internal use).  Otherwise, if we allow
		 * the allocation to happen, it will cause unexpected
		 * behaviors (e.g. Hermon SMA becomes unresponsive).
		 */
		if (state->hs_cfg_profile->cp_qp0_agents_in_fw != 0) {
			mutex_exit(&state->hs_spec_qplock);
			return (IBT_QP_IN_USE);
		}

		/*
		 * If this is the first QP0 allocation, then post
		 * a CONF_SPECIAL_QP firmware command
		 */
		if ((flags & HERMON_SPECIAL_QP0_RSRC_MASK) == 0) {
			status = hermon_conf_special_qp_cmd_post(state,
			    state->hs_spec_qp0->hr_indx, HERMON_CMD_QP_SMI,
			    HERMON_CMD_NOSLEEP_SPIN,
			    HERMON_CMD_SPEC_QP_OPMOD(
			    state->hs_cfg_profile->cp_qp0_agents_in_fw,
			    state->hs_cfg_profile->cp_qp1_agents_in_fw));
			if (status != HERMON_CMD_SUCCESS) {
				mutex_exit(&state->hs_spec_qplock);
				cmn_err(CE_NOTE, "hermon%d: CONF_SPECIAL_QP "
				    "command failed: %08x\n",
				    state->hs_instance, status);
				return (IBT_INSUFF_RESOURCE);
			}
		}

		/*
		 * Now check (and, if necessary, modify) the flags to indicate
		 * whether the allocation was successful
		 */
		mask = (1 << (HERMON_SPECIAL_QP0_RSRC + port));
		if (flags & mask) {
			mutex_exit(&state->hs_spec_qplock);
			return (IBT_QP_IN_USE);
		}
		state->hs_spec_qpflags |= mask;
		*qp_rsrc = state->hs_spec_qp0;

	} else {
		/*
		 * If this is the first QP1 allocation, then post
		 * a CONF_SPECIAL_QP firmware command
		 */
		if ((flags & HERMON_SPECIAL_QP1_RSRC_MASK) == 0) {
			status = hermon_conf_special_qp_cmd_post(state,
			    state->hs_spec_qp1->hr_indx, HERMON_CMD_QP_GSI,
			    HERMON_CMD_NOSLEEP_SPIN,
			    HERMON_CMD_SPEC_QP_OPMOD(
			    state->hs_cfg_profile->cp_qp0_agents_in_fw,
			    state->hs_cfg_profile->cp_qp1_agents_in_fw));
			if (status != HERMON_CMD_SUCCESS) {
				mutex_exit(&state->hs_spec_qplock);
				cmn_err(CE_NOTE, "hermon%d: CONF_SPECIAL_QP "
				    "command failed: %08x\n",
				    state->hs_instance, status);
				return (IBT_INSUFF_RESOURCE);
			}
		}

		/*
		 * Now check (and, if necessary, modify) the flags to indicate
		 * whether the allocation was successful
		 */
		mask = (1 << (HERMON_SPECIAL_QP1_RSRC + port));
		if (flags & mask) {
			mutex_exit(&state->hs_spec_qplock);
			return (IBT_QP_IN_USE);
		}
		state->hs_spec_qpflags |= mask;
		*qp_rsrc = state->hs_spec_qp1;
	}

	mutex_exit(&state->hs_spec_qplock);
	return (DDI_SUCCESS);
}


/*
 * hermon_special_qp_rsrc_free
 *    Context: Can be called from interrupt or base context.
 */
static int
hermon_special_qp_rsrc_free(hermon_state_t *state, ibt_sqp_type_t type,
    uint_t port)
{
	uint_t		mask, flags;
	int		status;

	mutex_enter(&state->hs_spec_qplock);
	if (type == IBT_SMI_SQP) {
		mask = (1 << (HERMON_SPECIAL_QP0_RSRC + port));
		state->hs_spec_qpflags &= ~mask;
		flags = state->hs_spec_qpflags;

		/*
		 * If this is the last QP0 free, then post a CONF_SPECIAL_QP
		 * NOW, If this is the last Special QP free, then post a
		 * CONF_SPECIAL_QP firmware command - it'll stop them all
		 */
		if (flags) {
			status = hermon_conf_special_qp_cmd_post(state, 0,
			    HERMON_CMD_QP_SMI, HERMON_CMD_NOSLEEP_SPIN, 0);
			if (status != HERMON_CMD_SUCCESS) {
				mutex_exit(&state->hs_spec_qplock);
				cmn_err(CE_NOTE, "hermon%d: CONF_SPECIAL_QP "
				    "command failed: %08x\n",
				    state->hs_instance, status);
				if (status == HERMON_CMD_INVALID_STATUS) {
					hermon_fm_ereport(state, HCA_SYS_ERR,
					    HCA_ERR_SRV_LOST);
				}
				return (ibc_get_ci_failure(0));
			}
		}
	} else {
		mask = (1 << (HERMON_SPECIAL_QP1_RSRC + port));
		state->hs_spec_qpflags &= ~mask;
		flags = state->hs_spec_qpflags;

		/*
		 * If this is the last QP1 free, then post a CONF_SPECIAL_QP
		 * NOW, if this is the last special QP free, then post a
		 * CONF_SPECIAL_QP firmware command - it'll stop them all
		 */
		if (flags) {
			status = hermon_conf_special_qp_cmd_post(state, 0,
			    HERMON_CMD_QP_GSI, HERMON_CMD_NOSLEEP_SPIN, 0);
			if (status != HERMON_CMD_SUCCESS) {
				mutex_exit(&state->hs_spec_qplock);
				cmn_err(CE_NOTE, "hermon%d: CONF_SPECIAL_QP "
				    "command failed: %08x\n",
				    state->hs_instance, status);
				if (status == HERMON_CMD_INVALID_STATUS) {
					hermon_fm_ereport(state, HCA_SYS_ERR,
					    HCA_ERR_SRV_LOST);
				}
				return (ibc_get_ci_failure(0));
			}
		}
	}

	mutex_exit(&state->hs_spec_qplock);
	return (DDI_SUCCESS);
}


/*
 * hermon_qp_sgl_to_logwqesz()
 *    Context: Can be called from interrupt or base context.
 */
static void
hermon_qp_sgl_to_logwqesz(hermon_state_t *state, uint_t num_sgl,
    uint_t real_max_sgl, hermon_qp_wq_type_t wq_type,
    uint_t *logwqesz, uint_t *max_sgl)
{
	uint_t	max_size, log2, actual_sgl;

	switch (wq_type) {
	case HERMON_QP_WQ_TYPE_SENDQ_UD:
		/*
		 * Use requested maximum SGL to calculate max descriptor size
		 * (while guaranteeing that the descriptor size is a
		 * power-of-2 cachelines).
		 */
		max_size = (HERMON_QP_WQE_MLX_SND_HDRS + (num_sgl << 4));
		log2 = highbit(max_size);
		if (ISP2(max_size)) {
			log2 = log2 - 1;
		}

		/* Make sure descriptor is at least the minimum size */
		log2 = max(log2, HERMON_QP_WQE_LOG_MINIMUM);

		/* Calculate actual number of SGL (given WQE size) */
		actual_sgl = ((1 << log2) -
		    sizeof (hermon_hw_snd_wqe_ctrl_t)) >> 4;
		break;

	case HERMON_QP_WQ_TYPE_SENDQ_CONN:
		/*
		 * Use requested maximum SGL to calculate max descriptor size
		 * (while guaranteeing that the descriptor size is a
		 * power-of-2 cachelines).
		 */
		max_size = (HERMON_QP_WQE_MLX_SND_HDRS + (num_sgl << 4));
		log2 = highbit(max_size);
		if (ISP2(max_size)) {
			log2 = log2 - 1;
		}

		/* Make sure descriptor is at least the minimum size */
		log2 = max(log2, HERMON_QP_WQE_LOG_MINIMUM);

		/* Calculate actual number of SGL (given WQE size) */
		actual_sgl = ((1 << log2) - HERMON_QP_WQE_MLX_SND_HDRS) >> 4;
		break;

	case HERMON_QP_WQ_TYPE_RECVQ:
		/*
		 * Same as above (except for Recv WQEs)
		 */
		max_size = (HERMON_QP_WQE_MLX_RCV_HDRS + (num_sgl << 4));
		log2 = highbit(max_size);
		if (ISP2(max_size)) {
			log2 = log2 - 1;
		}

		/* Make sure descriptor is at least the minimum size */
		log2 = max(log2, HERMON_QP_WQE_LOG_MINIMUM);

		/* Calculate actual number of SGL (given WQE size) */
		actual_sgl = ((1 << log2) - HERMON_QP_WQE_MLX_RCV_HDRS) >> 4;
		break;

	case HERMON_QP_WQ_TYPE_SENDMLX_QP0:
		/*
		 * Same as above (except for MLX transport WQEs).  For these
		 * WQEs we have to account for the space consumed by the
		 * "inline" packet headers.  (This is smaller than for QP1
		 * below because QP0 is not allowed to send packets with a GRH.
		 */
		max_size = (HERMON_QP_WQE_MLX_QP0_HDRS + (num_sgl << 4));
		log2 = highbit(max_size);
		if (ISP2(max_size)) {
			log2 = log2 - 1;
		}

		/* Make sure descriptor is at least the minimum size */
		log2 = max(log2, HERMON_QP_WQE_LOG_MINIMUM);

		/* Calculate actual number of SGL (given WQE size) */
		actual_sgl = ((1 << log2) - HERMON_QP_WQE_MLX_QP0_HDRS) >> 4;
		break;

	case HERMON_QP_WQ_TYPE_SENDMLX_QP1:
		/*
		 * Same as above.  For these WQEs we again have to account for
		 * the space consumed by the "inline" packet headers.  (This
		 * is larger than for QP0 above because we have to account for
		 * the possibility of a GRH in each packet - and this
		 * introduces an alignment issue that causes us to consume
		 * an additional 8 bytes).
		 */
		max_size = (HERMON_QP_WQE_MLX_QP1_HDRS + (num_sgl << 4));
		log2 = highbit(max_size);
		if (ISP2(max_size)) {
			log2 = log2 - 1;
		}

		/* Make sure descriptor is at least the minimum size */
		log2 = max(log2, HERMON_QP_WQE_LOG_MINIMUM);

		/* Calculate actual number of SGL (given WQE size) */
		actual_sgl = ((1 << log2) - HERMON_QP_WQE_MLX_QP1_HDRS) >> 4;
		break;

	default:
		HERMON_WARNING(state, "unexpected work queue type");
		break;
	}

	/* Fill in the return values */
	*logwqesz = log2;
	*max_sgl  = min(real_max_sgl, actual_sgl);
}
