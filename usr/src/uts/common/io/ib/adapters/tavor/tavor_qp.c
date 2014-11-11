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
 * tavor_qp.c
 *    Tavor Queue Pair Processing Routines
 *
 *    Implements all the routines necessary for allocating, freeing, and
 *    querying the Tavor queue pairs.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/bitmap.h>
#include <sys/sysmacros.h>

#include <sys/ib/adapters/tavor/tavor.h>
#include <sys/ib/ib_pkt_hdrs.h>

static int tavor_qp_create_qpn(tavor_state_t *state, tavor_qphdl_t qp,
    tavor_rsrc_t *qpc);
static int tavor_qpn_avl_compare(const void *q, const void *e);
static int tavor_special_qp_rsrc_alloc(tavor_state_t *state,
    ibt_sqp_type_t type, uint_t port, tavor_rsrc_t **qp_rsrc);
static int tavor_special_qp_rsrc_free(tavor_state_t *state, ibt_sqp_type_t type,
    uint_t port);
static void tavor_qp_sgl_to_logwqesz(tavor_state_t *state, uint_t num_sgl,
    tavor_qp_wq_type_t wq_type, uint_t *logwqesz, uint_t *max_sgl);

/*
 * tavor_qp_alloc()
 *    Context: Can be called only from user or kernel context.
 */
int
tavor_qp_alloc(tavor_state_t *state, tavor_qp_info_t *qpinfo,
    uint_t sleepflag, tavor_qp_options_t *op)
{
	tavor_rsrc_pool_info_t	*rsrc_pool;
	tavor_rsrc_t		*qpc, *rsrc, *rdb;
	tavor_umap_db_entry_t	*umapdb;
	tavor_qphdl_t		qp;
	ibt_qp_alloc_attr_t	*attr_p;
	ibt_qp_type_t		type;
	ibtl_qp_hdl_t		ibt_qphdl;
	ibt_chan_sizes_t	*queuesz_p;
	ib_qpn_t		*qpn;
	tavor_qphdl_t		*qphdl;
	ibt_mr_attr_t		mr_attr;
	tavor_mr_options_t	mr_op;
	tavor_srqhdl_t		srq;
	tavor_pdhdl_t		pd;
	tavor_cqhdl_t		sq_cq, rq_cq;
	tavor_mrhdl_t		mr;
	uint64_t		value, qp_desc_off;
	uint32_t		*sq_buf, *rq_buf;
	uint32_t		log_qp_sq_size, log_qp_rq_size;
	uint32_t		sq_size, rq_size;
	uint32_t		sq_wqe_size, rq_wqe_size;
	uint32_t		max_rdb, max_sgl, uarpg;
	uint_t			wq_location, dma_xfer_mode, qp_is_umap;
	uint_t			qp_srq_en;
	int			status, flag;
	char			*errormsg;

	TAVOR_TNF_ENTER(tavor_qp_alloc);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*attr_p, *queuesz_p))

	/*
	 * Check the "options" flag.  Currently this flag tells the driver
	 * whether or not the QP's work queues should be come from normal
	 * system memory or whether they should be allocated from DDR memory.
	 */
	if (op == NULL) {
		wq_location = TAVOR_QUEUE_LOCATION_NORMAL;
	} else {
		wq_location = op->qpo_wq_loc;
	}

	/*
	 * Extract the necessary info from the tavor_qp_info_t structure
	 */
	attr_p	  = qpinfo->qpi_attrp;
	type	  = qpinfo->qpi_type;
	ibt_qphdl = qpinfo->qpi_ibt_qphdl;
	queuesz_p = qpinfo->qpi_queueszp;
	qpn	  = qpinfo->qpi_qpn;
	qphdl	  = &qpinfo->qpi_qphdl;

	/*
	 * Determine whether QP is being allocated for userland access or
	 * whether it is being allocated for kernel access.  If the QP is
	 * being allocated for userland access, then lookup the UAR doorbell
	 * page number for the current process.  Note:  If this is not found
	 * (e.g. if the process has not previously open()'d the Tavor driver),
	 * then an error is returned.
	 */
	qp_is_umap = (attr_p->qp_alloc_flags & IBT_QP_USER_MAP) ? 1 : 0;
	if (qp_is_umap) {
		status = tavor_umap_db_find(state->ts_instance, ddi_get_pid(),
		    MLNX_UMAP_UARPG_RSRC, &value, 0, NULL);
		if (status != DDI_SUCCESS) {
			/* Set "status" and "errormsg" and goto failure */
			TAVOR_TNF_FAIL(IBT_INVALID_PARAM, "failed UAR page");
			goto qpalloc_fail;
		}
		uarpg = ((tavor_rsrc_t *)(uintptr_t)value)->tr_indx;
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
			/* Set "status" and "errormsg" and goto failure */
			TAVOR_TNF_FAIL(IBT_SRQ_HDL_INVALID,
			    "invalid SRQ handle");
			goto qpalloc_fail;
		}
		srq = (tavor_srqhdl_t)attr_p->qp_ibc_srq_hdl;
	}

	/*
	 * Check for valid QP service type (only UD/RC/UC supported)
	 */
	if (((type != IBT_UD_RQP) && (type != IBT_RC_RQP) &&
	    (type != IBT_UC_RQP))) {
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(IBT_QP_SRV_TYPE_INVALID, "invalid serv type");
		goto qpalloc_fail;
	}

	/*
	 * Only RC is supported on an SRQ -- This is a Tavor hardware
	 * limitation.  Arbel native mode will not have this shortcoming.
	 */
	if (qp_srq_en && type != IBT_RC_RQP) {
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(IBT_INVALID_PARAM, "invalid serv type with SRQ");
		goto qpalloc_fail;
	}

	/*
	 * Check for valid PD handle pointer
	 */
	if (attr_p->qp_pd_hdl == NULL) {
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(IBT_PD_HDL_INVALID, "invalid PD handle");
		goto qpalloc_fail;
	}
	pd = (tavor_pdhdl_t)attr_p->qp_pd_hdl;

	/*
	 * If on an SRQ, check to make sure the PD is the same
	 */
	if (qp_srq_en && (pd->pd_pdnum != srq->srq_pdhdl->pd_pdnum)) {
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(IBT_PD_HDL_INVALID, "invalid PD handle");
		goto qpalloc_fail;
	}

	/* Increment the reference count on the protection domain (PD) */
	tavor_pd_refcnt_inc(pd);

	/*
	 * Check for valid CQ handle pointers
	 */
	if ((attr_p->qp_ibc_scq_hdl == NULL) ||
	    (attr_p->qp_ibc_rcq_hdl == NULL)) {
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(IBT_CQ_HDL_INVALID, "invalid CQ handle");
		goto qpalloc_fail1;
	}
	sq_cq = (tavor_cqhdl_t)attr_p->qp_ibc_scq_hdl;
	rq_cq = (tavor_cqhdl_t)attr_p->qp_ibc_rcq_hdl;

	/*
	 * Increment the reference count on the CQs.  One or both of these
	 * could return error if we determine that the given CQ is already
	 * being used with a special (SMI/GSI) QP.
	 */
	status = tavor_cq_refcnt_inc(sq_cq, TAVOR_CQ_IS_NORMAL);
	if (status != DDI_SUCCESS) {
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(IBT_CQ_HDL_INVALID, "invalid CQ handle");
		goto qpalloc_fail1;
	}
	status = tavor_cq_refcnt_inc(rq_cq, TAVOR_CQ_IS_NORMAL);
	if (status != DDI_SUCCESS) {
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(IBT_CQ_HDL_INVALID, "invalid CQ handle");
		goto qpalloc_fail2;
	}

	/*
	 * Allocate an QP context entry.  This will be filled in with all
	 * the necessary parameters to define the Queue Pair.  Unlike
	 * other Tavor hardware resources, ownership is not immediately
	 * given to hardware in the final step here.  Instead, we must
	 * wait until the QP is later transitioned to the "Init" state before
	 * passing the QP to hardware.  If we fail here, we must undo all
	 * the reference count (CQ and PD).
	 */
	status = tavor_rsrc_alloc(state, TAVOR_QPC, 1, sleepflag, &qpc);
	if (status != DDI_SUCCESS) {
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(IBT_INSUFF_RESOURCE, "failed QP context");
		goto qpalloc_fail3;
	}

	/*
	 * Allocate the software structure for tracking the queue pair
	 * (i.e. the Tavor Queue Pair handle).  If we fail here, we must
	 * undo the reference counts and the previous resource allocation.
	 */
	status = tavor_rsrc_alloc(state, TAVOR_QPHDL, 1, sleepflag, &rsrc);
	if (status != DDI_SUCCESS) {
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(IBT_INSUFF_RESOURCE, "failed QP handle");
		goto qpalloc_fail4;
	}
	qp = (tavor_qphdl_t)rsrc->tr_addr;
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*qp))

	/*
	 * Calculate the QP number from QPC index.  This routine handles
	 * all of the operations necessary to keep track of used, unused,
	 * and released QP numbers.
	 */
	status = tavor_qp_create_qpn(state, qp, qpc);
	if (status != DDI_SUCCESS) {
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(IBT_INSUFF_RESOURCE, "failed QPN create");
		goto qpalloc_fail5;
	}

	/*
	 * If this will be a user-mappable QP, then allocate an entry for
	 * the "userland resources database".  This will later be added to
	 * the database (after all further QP operations are successful).
	 * If we fail here, we must undo the reference counts and the
	 * previous resource allocation.
	 */
	if (qp_is_umap) {
		umapdb = tavor_umap_db_alloc(state->ts_instance, qp->qp_qpnum,
		    MLNX_UMAP_QPMEM_RSRC, (uint64_t)(uintptr_t)rsrc);
		if (umapdb == NULL) {
			/* Set "status" and "errormsg" and goto failure */
			TAVOR_TNF_FAIL(IBT_INSUFF_RESOURCE, "failed umap add");
			goto qpalloc_fail6;
		}
	}

	/*
	 * If this is an RC QP, then pre-allocate the maximum number of RDB
	 * entries.  This allows us to ensure that we can later cover all
	 * the resources needed by hardware for handling multiple incoming
	 * RDMA Reads.  Note: These resources are obviously not always
	 * necessary.  They are allocated here anyway.  Someday maybe this
	 * can be modified to allocate these on-the-fly (i.e. only if RDMA
	 * Read or Atomic operations are enabled) XXX
	 * If we fail here, we have a bunch of resource and reference count
	 * cleanup to do.
	 */
	if (type == IBT_RC_RQP) {
		max_rdb = state->ts_cfg_profile->cp_hca_max_rdma_in_qp;
		status = tavor_rsrc_alloc(state, TAVOR_RDB, max_rdb,
		    sleepflag, &rdb);
		if (status != DDI_SUCCESS) {
			/* Set "status" and "errormsg" and goto failure */
			TAVOR_TNF_FAIL(IBT_INSUFF_RESOURCE, "failed RDB");
			goto qpalloc_fail7;
		}
		qp->qp_rdbrsrcp = rdb;
		/* Calculate offset (into DDR memory) of RDB entries */
		rsrc_pool = &state->ts_rsrc_hdl[TAVOR_RDB];
		qp->qp_rdb_ddraddr = (uintptr_t)rsrc_pool->rsrc_ddr_offset +
		    (rdb->tr_indx << TAVOR_RDB_SIZE_SHIFT);
	}

	/*
	 * Calculate the appropriate size for the work queues.
	 * Note:  All Tavor QP work queues must be a power-of-2 in size.  Also
	 * they may not be any smaller than TAVOR_QP_MIN_SIZE.  This step is
	 * to round the requested size up to the next highest power-of-2
	 */
	attr_p->qp_sizes.cs_sq = max(attr_p->qp_sizes.cs_sq, TAVOR_QP_MIN_SIZE);
	attr_p->qp_sizes.cs_rq = max(attr_p->qp_sizes.cs_rq, TAVOR_QP_MIN_SIZE);
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
	 * then obviously we have a lot of cleanup to do before returning.
	 */
	if ((log_qp_sq_size > state->ts_cfg_profile->cp_log_max_qp_sz) ||
	    (!qp_srq_en && (log_qp_rq_size >
	    state->ts_cfg_profile->cp_log_max_qp_sz))) {
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(IBT_HCA_WR_EXCEEDED, "max QP size");
		goto qpalloc_fail8;
	}

	/*
	 * Next we verify that the requested number of SGL is valid (i.e.
	 * consistent with the device limits and/or software-configured
	 * limits).  If not, then obviously the same cleanup needs to be done.
	 */
	max_sgl = state->ts_cfg_profile->cp_wqe_real_max_sgl;
	if ((attr_p->qp_sizes.cs_sq_sgl > max_sgl) ||
	    (!qp_srq_en && (attr_p->qp_sizes.cs_rq_sgl > max_sgl))) {
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(IBT_HCA_SGL_EXCEEDED, "max QP SGL");
		goto qpalloc_fail8;
	}

	/*
	 * Determine this QP's WQE sizes (for both the Send and Recv WQEs).
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
		tavor_qp_sgl_to_logwqesz(state, attr_p->qp_sizes.cs_rq_sgl,
		    TAVOR_QP_WQ_TYPE_RECVQ, &qp->qp_rq_log_wqesz,
		    &qp->qp_rq_sgl);
	}
	tavor_qp_sgl_to_logwqesz(state, attr_p->qp_sizes.cs_sq_sgl,
	    TAVOR_QP_WQ_TYPE_SENDQ, &qp->qp_sq_log_wqesz, &qp->qp_sq_sgl);

	/*
	 * Allocate the memory for QP work queues.  Note:  The location from
	 * which we will allocate these work queues has been passed in
	 * through the tavor_qp_options_t structure.  Since Tavor work queues
	 * are not allowed to cross a 32-bit (4GB) boundary, the alignment of
	 * the work queue memory is very important.  We used to allocate
	 * work queues (the combined receive and send queues) so that they
	 * would be aligned on their combined size.  That alignment guaranteed
	 * that they would never cross the 4GB boundary (Tavor work queues
	 * are on the order of MBs at maximum).  Now we are able to relax
	 * this alignment constraint by ensuring that the IB address assigned
	 * to the queue memory (as a result of the tavor_mr_register() call)
	 * is offset from zero.
	 * Previously, we had wanted to use the ddi_dma_mem_alloc() routine to
	 * guarantee the alignment, but when attempting to use IOMMU bypass
	 * mode we found that we were not allowed to specify any alignment
	 * that was more restrictive than the system page size.
	 * So we avoided this constraint by passing two alignment values,
	 * one for the memory allocation itself and the other for the DMA
	 * handle (for later bind).  This used to cause more memory than
	 * necessary to be allocated (in order to guarantee the more
	 * restrictive alignment contraint).  But be guaranteeing the
	 * zero-based IB virtual address for the queue, we are able to
	 * conserve this memory.
	 * Note: If QP is not user-mappable, then it may come from either
	 * kernel system memory or from HCA-attached local DDR memory.
	 */
	sq_wqe_size = 1 << qp->qp_sq_log_wqesz;
	sq_size	    = (1 << log_qp_sq_size) * sq_wqe_size;

	/* QP on SRQ sets these to 0 */
	if (qp_srq_en) {
		rq_wqe_size = 0;
		rq_size	    = 0;
	} else {
		rq_wqe_size = 1 << qp->qp_rq_log_wqesz;
		rq_size	    = (1 << log_qp_rq_size) * rq_wqe_size;
	}

	qp->qp_wqinfo.qa_size = sq_size + rq_size;
	qp->qp_wqinfo.qa_alloc_align = max(sq_wqe_size, rq_wqe_size);
	qp->qp_wqinfo.qa_bind_align  = max(sq_wqe_size, rq_wqe_size);
	if (qp_is_umap) {
		qp->qp_wqinfo.qa_location = TAVOR_QUEUE_LOCATION_USERLAND;
	} else {
		qp->qp_wqinfo.qa_location = wq_location;
	}
	status = tavor_queue_alloc(state, &qp->qp_wqinfo, sleepflag);
	if (status != DDI_SUCCESS) {
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(IBT_INSUFF_RESOURCE, "failed work queue");
		goto qpalloc_fail8;
	}
	if (sq_wqe_size > rq_wqe_size) {
		sq_buf = qp->qp_wqinfo.qa_buf_aligned;

		/*
		 * If QP's on an SRQ, we set the rq_buf to NULL
		 */
		if (qp_srq_en)
			rq_buf = NULL;
		else
			rq_buf = (uint32_t *)((uintptr_t)sq_buf + sq_size);
	} else {
		rq_buf = qp->qp_wqinfo.qa_buf_aligned;
		sq_buf = (uint32_t *)((uintptr_t)rq_buf + rq_size);
	}

	/*
	 * Register the memory for the QP work queues.  The memory for the
	 * QP must be registered in the Tavor TPT tables.  This gives us the
	 * LKey to specify in the QP context later.  Note: The memory for
	 * Tavor work queues (both Send and Recv) must be contiguous and
	 * registered as a single memory region.  Note also: If the work
	 * queue is to be allocated from DDR memory, then only a "bypass"
	 * mapping is appropriate.  And if the QP memory is user-mappable,
	 * then we force DDI_DMA_CONSISTENT mapping.
	 * Also, in order to meet the alignment restriction, we pass the
	 * "mro_bind_override_addr" flag in the call to tavor_mr_register().
	 * This guarantees that the resulting IB vaddr will be zero-based
	 * (modulo the offset into the first page).
	 * If we fail here, we still have the bunch of resource and reference
	 * count cleanup to do.
	 */
	flag = (sleepflag == TAVOR_SLEEP) ? IBT_MR_SLEEP :
	    IBT_MR_NOSLEEP;
	mr_attr.mr_vaddr    = (uint64_t)(uintptr_t)qp->qp_wqinfo.qa_buf_aligned;
	mr_attr.mr_len	    = qp->qp_wqinfo.qa_size;
	mr_attr.mr_as	    = NULL;
	mr_attr.mr_flags    = flag;
	if (qp_is_umap) {
		mr_op.mro_bind_type = state->ts_cfg_profile->cp_iommu_bypass;
	} else {
		if (wq_location == TAVOR_QUEUE_LOCATION_NORMAL) {
			mr_op.mro_bind_type =
			    state->ts_cfg_profile->cp_iommu_bypass;
			dma_xfer_mode =
			    state->ts_cfg_profile->cp_streaming_consistent;
			if (dma_xfer_mode == DDI_DMA_STREAMING) {
				mr_attr.mr_flags |= IBT_MR_NONCOHERENT;
			}
		} else {
			mr_op.mro_bind_type = TAVOR_BINDMEM_BYPASS;
		}
	}
	mr_op.mro_bind_dmahdl = qp->qp_wqinfo.qa_dmahdl;
	mr_op.mro_bind_override_addr = 1;
	status = tavor_mr_register(state, pd, &mr_attr, &mr, &mr_op);
	if (status != DDI_SUCCESS) {
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(IBT_INSUFF_RESOURCE, "failed register mr");
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
	 * real work queue sizes, real SGLs, and QP number
	 */
	if (queuesz_p != NULL) {
		queuesz_p->cs_sq	= (1 << log_qp_sq_size);
		queuesz_p->cs_sq_sgl	= qp->qp_sq_sgl;

		/* QP on an SRQ set these to 0 */
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
	 * Fill in the rest of the Tavor Queue Pair handle.  We can update
	 * the following fields for use in further operations on the QP.
	 */
	qp->qp_qpcrsrcp		= qpc;
	qp->qp_rsrcp		= rsrc;
	qp->qp_state		= TAVOR_QP_RESET;
	qp->qp_pdhdl		= pd;
	qp->qp_mrhdl		= mr;
	qp->qp_sq_sigtype	= (attr_p->qp_flags & IBT_WR_SIGNALED) ?
	    TAVOR_QP_SQ_WR_SIGNALED : TAVOR_QP_SQ_ALL_SIGNALED;
	qp->qp_is_special	= 0;
	qp->qp_is_umap		= qp_is_umap;
	qp->qp_uarpg		= (qp->qp_is_umap) ? uarpg : 0;
	qp->qp_umap_dhp		= (devmap_cookie_t)NULL;
	qp->qp_sq_cqhdl		= sq_cq;
	qp->qp_sq_lastwqeaddr	= NULL;
	qp->qp_sq_bufsz		= (1 << log_qp_sq_size);
	qp->qp_sq_buf		= sq_buf;
	qp->qp_desc_off		= qp_desc_off;
	qp->qp_rq_cqhdl		= rq_cq;
	qp->qp_rq_lastwqeaddr	= NULL;
	qp->qp_rq_buf		= rq_buf;

	/* QP on an SRQ sets this to 0 */
	if (qp_srq_en) {
		qp->qp_rq_bufsz		= 0;
	} else {
		qp->qp_rq_bufsz		= (1 << log_qp_rq_size);
	}

	qp->qp_forward_sqd_event  = 0;
	qp->qp_sqd_still_draining = 0;
	qp->qp_hdlrarg		= (void *)ibt_qphdl;
	qp->qp_mcg_refcnt	= 0;

	/*
	 * If this QP is to be associated with an SRQ, then set the SRQ handle
	 * appropriately.
	 */
	if (qp_srq_en) {
		qp->qp_srqhdl = srq;
		qp->qp_srq_en = TAVOR_QP_SRQ_ENABLED;
		tavor_srq_refcnt_inc(qp->qp_srqhdl);
	} else {
		qp->qp_srqhdl = NULL;
		qp->qp_srq_en = TAVOR_QP_SRQ_DISABLED;
	}

	/* Determine if later ddi_dma_sync will be necessary */
	qp->qp_sync = TAVOR_QP_IS_SYNC_REQ(state, qp->qp_wqinfo);

	/* Determine the QP service type */
	if (type == IBT_RC_RQP) {
		qp->qp_serv_type = TAVOR_QP_RC;
	} else if (type == IBT_UD_RQP) {
		qp->qp_serv_type = TAVOR_QP_UD;
	} else {
		qp->qp_serv_type = TAVOR_QP_UC;
	}

	/* Zero out the QP context */
	bzero(&qp->qpc, sizeof (tavor_hw_qpc_t));

	/*
	 * Put QP handle in Tavor QPNum-to-QPHdl list.  Then fill in the
	 * "qphdl" and return success
	 */
	ASSERT(state->ts_qphdl[qpc->tr_indx] == NULL);
	state->ts_qphdl[qpc->tr_indx] = qp;

	/*
	 * If this is a user-mappable QP, then we need to insert the previously
	 * allocated entry into the "userland resources database".  This will
	 * allow for later lookup during devmap() (i.e. mmap()) calls.
	 */
	if (qp_is_umap) {
		tavor_umap_db_add(umapdb);
	}

	*qphdl = qp;

	TAVOR_TNF_EXIT(tavor_qp_alloc);
	return (DDI_SUCCESS);

/*
 * The following is cleanup for all possible failure cases in this routine
 */
qpalloc_fail9:
	tavor_queue_free(state, &qp->qp_wqinfo);
qpalloc_fail8:
	if (type == IBT_RC_RQP) {
		tavor_rsrc_free(state, &rdb);
	}
qpalloc_fail7:
	if (qp_is_umap) {
		tavor_umap_db_free(umapdb);
	}
qpalloc_fail6:
	/*
	 * Releasing the QPN will also free up the QPC context.  Update
	 * the QPC context pointer to indicate this.
	 */
	tavor_qp_release_qpn(state, qp->qp_qpn_hdl, TAVOR_QPN_RELEASE);
	qpc = NULL;
qpalloc_fail5:
	tavor_rsrc_free(state, &rsrc);
qpalloc_fail4:
	if (qpc) {
		tavor_rsrc_free(state, &qpc);
	}
qpalloc_fail3:
	tavor_cq_refcnt_dec(rq_cq);
qpalloc_fail2:
	tavor_cq_refcnt_dec(sq_cq);
qpalloc_fail1:
	tavor_pd_refcnt_dec(pd);
qpalloc_fail:
	TNF_PROBE_1(tavor_qp_alloc_fail, TAVOR_TNF_ERROR, "",
	    tnf_string, msg, errormsg);
	TAVOR_TNF_EXIT(tavor_qp_alloc);
	return (status);
}



/*
 * tavor_special_qp_alloc()
 *    Context: Can be called only from user or kernel context.
 */
int
tavor_special_qp_alloc(tavor_state_t *state, tavor_qp_info_t *qpinfo,
    uint_t sleepflag, tavor_qp_options_t *op)
{
	tavor_rsrc_t		*qpc, *rsrc;
	tavor_qphdl_t		qp;
	ibt_qp_alloc_attr_t	*attr_p;
	ibt_sqp_type_t		type;
	uint8_t			port;
	ibtl_qp_hdl_t		ibt_qphdl;
	ibt_chan_sizes_t	*queuesz_p;
	tavor_qphdl_t		*qphdl;
	ibt_mr_attr_t		mr_attr;
	tavor_mr_options_t	mr_op;
	tavor_pdhdl_t		pd;
	tavor_cqhdl_t		sq_cq, rq_cq;
	tavor_mrhdl_t		mr;
	uint64_t		qp_desc_off;
	uint32_t		*sq_buf, *rq_buf;
	uint32_t		log_qp_sq_size, log_qp_rq_size;
	uint32_t		sq_size, rq_size, max_sgl;
	uint32_t		sq_wqe_size, rq_wqe_size;
	uint_t			wq_location, dma_xfer_mode;
	int			status, flag;
	char			*errormsg;

	TAVOR_TNF_ENTER(tavor_special_qp_alloc);

	/*
	 * Check the "options" flag.  Currently this flag tells the driver
	 * whether or not the QP's work queues should be come from normal
	 * system memory or whether they should be allocated from DDR memory.
	 */
	if (op == NULL) {
		wq_location = TAVOR_QUEUE_LOCATION_NORMAL;
	} else {
		wq_location = op->qpo_wq_loc;
	}

	/*
	 * Extract the necessary info from the tavor_qp_info_t structure
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
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(IBT_QP_SPECIAL_TYPE_INVALID, "invalid QP type");
		goto spec_qpalloc_fail;
	}

	/*
	 * Check for valid port number
	 */
	if (!tavor_portnum_is_valid(state, port)) {
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(IBT_HCA_PORT_INVALID, "invalid port num");
		goto spec_qpalloc_fail;
	}
	port = port - 1;

	/*
	 * Check for valid PD handle pointer
	 */
	if (attr_p->qp_pd_hdl == NULL) {
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(IBT_PD_HDL_INVALID, "invalid PD handle");
		goto spec_qpalloc_fail;
	}
	pd = (tavor_pdhdl_t)attr_p->qp_pd_hdl;

	/* Increment the reference count on the PD */
	tavor_pd_refcnt_inc(pd);

	/*
	 * Check for valid CQ handle pointers
	 */
	if ((attr_p->qp_ibc_scq_hdl == NULL) ||
	    (attr_p->qp_ibc_rcq_hdl == NULL)) {
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(IBT_CQ_HDL_INVALID, "invalid CQ handle");
		goto spec_qpalloc_fail1;
	}
	sq_cq = (tavor_cqhdl_t)attr_p->qp_ibc_scq_hdl;
	rq_cq = (tavor_cqhdl_t)attr_p->qp_ibc_rcq_hdl;

	/*
	 * Increment the reference count on the CQs.  One or both of these
	 * could return error if we determine that the given CQ is already
	 * being used with a non-special QP (i.e. a normal QP).
	 */
	status = tavor_cq_refcnt_inc(sq_cq, TAVOR_CQ_IS_SPECIAL);
	if (status != DDI_SUCCESS) {
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(IBT_CQ_HDL_INVALID, "invalid CQ handle");
		goto spec_qpalloc_fail1;
	}
	status = tavor_cq_refcnt_inc(rq_cq, TAVOR_CQ_IS_SPECIAL);
	if (status != DDI_SUCCESS) {
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(IBT_CQ_HDL_INVALID, "invalid CQ handle");
		goto spec_qpalloc_fail2;
	}

	/*
	 * Allocate the special QP resources.  Essentially, this allocation
	 * amounts to checking if the request special QP has already been
	 * allocated.  If successful, the QP context return is an actual
	 * QP context that has been "aliased" to act as a special QP of the
	 * appropriate type (and for the appropriate port).  Just as in
	 * tavor_qp_alloc() above, ownership for this QP context is not
	 * immediately given to hardware in the final step here.  Instead, we
	 * wait until the QP is later transitioned to the "Init" state before
	 * passing the QP to hardware.  If we fail here, we must undo all
	 * the reference count (CQ and PD).
	 */
	status = tavor_special_qp_rsrc_alloc(state, type, port, &qpc);
	if (status != DDI_SUCCESS) {
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(status, "failed special QP rsrc");
		goto spec_qpalloc_fail3;
	}

	/*
	 * Allocate the software structure for tracking the special queue
	 * pair (i.e. the Tavor Queue Pair handle).  If we fail here, we
	 * must undo the reference counts and the previous resource allocation.
	 */
	status = tavor_rsrc_alloc(state, TAVOR_QPHDL, 1, sleepflag, &rsrc);
	if (status != DDI_SUCCESS) {
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(IBT_INSUFF_RESOURCE, "failed QP handle");
		goto spec_qpalloc_fail4;
	}
	qp = (tavor_qphdl_t)rsrc->tr_addr;
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*qp))

	/*
	 * Actual QP number is a combination of the index of the QPC and
	 * the port number.  This is because the special QP contexts must
	 * be allocated two-at-a-time.
	 */
	qp->qp_qpnum = qpc->tr_indx + port;

	/*
	 * Calculate the appropriate size for the work queues.
	 * Note:  All Tavor QP work queues must be a power-of-2 in size.  Also
	 * they may not be any smaller than TAVOR_QP_MIN_SIZE.  This step is
	 * to round the requested size up to the next highest power-of-2
	 */
	attr_p->qp_sizes.cs_sq = max(attr_p->qp_sizes.cs_sq, TAVOR_QP_MIN_SIZE);
	attr_p->qp_sizes.cs_rq = max(attr_p->qp_sizes.cs_rq, TAVOR_QP_MIN_SIZE);
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
	if ((log_qp_sq_size > state->ts_cfg_profile->cp_log_max_qp_sz) ||
	    (log_qp_rq_size > state->ts_cfg_profile->cp_log_max_qp_sz)) {
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(IBT_HCA_WR_EXCEEDED, "max QP size");
		goto spec_qpalloc_fail5;
	}

	/*
	 * Next we verify that the requested number of SGL is valid (i.e.
	 * consistent with the device limits and/or software-configured
	 * limits).  If not, then obviously the same cleanup needs to be done.
	 */
	max_sgl = state->ts_cfg_profile->cp_wqe_real_max_sgl;
	if ((attr_p->qp_sizes.cs_sq_sgl > max_sgl) ||
	    (attr_p->qp_sizes.cs_rq_sgl > max_sgl)) {
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(IBT_HCA_SGL_EXCEEDED, "max QP SGL");
		goto spec_qpalloc_fail5;
	}

	/*
	 * Determine this QP's WQE sizes (for both the Send and Recv WQEs).
	 * This will depend on the requested number of SGLs.  Note: this
	 * has the side-effect of also calculating the real number of SGLs
	 * (for the calculated WQE size).
	 */
	tavor_qp_sgl_to_logwqesz(state, attr_p->qp_sizes.cs_rq_sgl,
	    TAVOR_QP_WQ_TYPE_RECVQ, &qp->qp_rq_log_wqesz, &qp->qp_rq_sgl);
	if (type == IBT_SMI_SQP) {
		tavor_qp_sgl_to_logwqesz(state, attr_p->qp_sizes.cs_sq_sgl,
		    TAVOR_QP_WQ_TYPE_SENDMLX_QP0, &qp->qp_sq_log_wqesz,
		    &qp->qp_sq_sgl);
	} else {
		tavor_qp_sgl_to_logwqesz(state, attr_p->qp_sizes.cs_sq_sgl,
		    TAVOR_QP_WQ_TYPE_SENDMLX_QP1, &qp->qp_sq_log_wqesz,
		    &qp->qp_sq_sgl);
	}

	/*
	 * Allocate the memory for QP work queues.  Note:  The location from
	 * which we will allocate these work queues has been passed in
	 * through the tavor_qp_options_t structure.  Since Tavor work queues
	 * are not allowed to cross a 32-bit (4GB) boundary, the alignment of
	 * the work queue memory is very important.  We used to allocate
	 * work queues (the combined receive and send queues) so that they
	 * would be aligned on their combined size.  That alignment guaranteed
	 * that they would never cross the 4GB boundary (Tavor work queues
	 * are on the order of MBs at maximum).  Now we are able to relax
	 * this alignment constraint by ensuring that the IB address assigned
	 * to the queue memory (as a result of the tavor_mr_register() call)
	 * is offset from zero.
	 * Previously, we had wanted to use the ddi_dma_mem_alloc() routine to
	 * guarantee the alignment, but when attempting to use IOMMU bypass
	 * mode we found that we were not allowed to specify any alignment
	 * that was more restrictive than the system page size.
	 * So we avoided this constraint by passing two alignment values,
	 * one for the memory allocation itself and the other for the DMA
	 * handle (for later bind).  This used to cause more memory than
	 * necessary to be allocated (in order to guarantee the more
	 * restrictive alignment contraint).  But be guaranteeing the
	 * zero-based IB virtual address for the queue, we are able to
	 * conserve this memory.
	 */
	sq_wqe_size = 1 << qp->qp_sq_log_wqesz;
	rq_wqe_size = 1 << qp->qp_rq_log_wqesz;
	sq_size	    = (1 << log_qp_sq_size) * sq_wqe_size;
	rq_size	    = (1 << log_qp_rq_size) * rq_wqe_size;
	qp->qp_wqinfo.qa_size	  = sq_size + rq_size;
	qp->qp_wqinfo.qa_alloc_align = max(sq_wqe_size, rq_wqe_size);
	qp->qp_wqinfo.qa_bind_align  = max(sq_wqe_size, rq_wqe_size);
	qp->qp_wqinfo.qa_location = wq_location;
	status = tavor_queue_alloc(state, &qp->qp_wqinfo, sleepflag);
	if (status != NULL) {
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(IBT_INSUFF_RESOURCE, "failed work queue");
		goto spec_qpalloc_fail5;
	}
	if (sq_wqe_size > rq_wqe_size) {
		sq_buf = qp->qp_wqinfo.qa_buf_aligned;
		rq_buf = (uint32_t *)((uintptr_t)sq_buf + sq_size);
	} else {
		rq_buf = qp->qp_wqinfo.qa_buf_aligned;
		sq_buf = (uint32_t *)((uintptr_t)rq_buf + rq_size);
	}

	/*
	 * Register the memory for the special QP work queues.  The memory for
	 * the special QP must be registered in the Tavor TPT tables.  This
	 * gives us the LKey to specify in the QP context later.  Note: The
	 * memory for Tavor work queues (both Send and Recv) must be contiguous
	 * and registered as a single memory region.  Note also: If the work
	 * queue is to be allocated from DDR memory, then only a "bypass"
	 * mapping is appropriate.
	 * Also, in order to meet the alignment restriction, we pass the
	 * "mro_bind_override_addr" flag in the call to tavor_mr_register().
	 * This guarantees that the resulting IB vaddr will be zero-based
	 * (modulo the offset into the first page).
	 * If we fail here, we have a bunch of resource and reference count
	 * cleanup to do.
	 */
	flag = (sleepflag == TAVOR_SLEEP) ? IBT_MR_SLEEP :
	    IBT_MR_NOSLEEP;
	mr_attr.mr_vaddr    = (uint64_t)(uintptr_t)qp->qp_wqinfo.qa_buf_aligned;
	mr_attr.mr_len	    = qp->qp_wqinfo.qa_size;
	mr_attr.mr_as	    = NULL;
	mr_attr.mr_flags    = flag;
	if (wq_location == TAVOR_QUEUE_LOCATION_NORMAL) {
		mr_op.mro_bind_type = state->ts_cfg_profile->cp_iommu_bypass;

		dma_xfer_mode = state->ts_cfg_profile->cp_streaming_consistent;
		if (dma_xfer_mode == DDI_DMA_STREAMING) {
			mr_attr.mr_flags |= IBT_MR_NONCOHERENT;
		}
	} else {
		mr_op.mro_bind_type = TAVOR_BINDMEM_BYPASS;
	}
	mr_op.mro_bind_dmahdl = qp->qp_wqinfo.qa_dmahdl;
	mr_op.mro_bind_override_addr = 1;
	status = tavor_mr_register(state, pd, &mr_attr, &mr, &mr_op);
	if (status != DDI_SUCCESS) {
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(IBT_INSUFF_RESOURCE, "failed register mr");
		goto spec_qpalloc_fail6;
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
	 * real work queue sizes, real SGLs, and QP number (which will be
	 * either zero or one, depending on the special QP type)
	 */
	if (queuesz_p != NULL) {
		queuesz_p->cs_sq	= (1 << log_qp_sq_size);
		queuesz_p->cs_sq_sgl	= qp->qp_sq_sgl;
		queuesz_p->cs_rq	= (1 << log_qp_rq_size);
		queuesz_p->cs_rq_sgl	= qp->qp_rq_sgl;
	}

	/*
	 * Fill in the rest of the Tavor Queue Pair handle.  We can update
	 * the following fields for use in further operations on the QP.
	 */
	qp->qp_qpcrsrcp		= qpc;
	qp->qp_rsrcp		= rsrc;
	qp->qp_state		= TAVOR_QP_RESET;
	qp->qp_pdhdl		= pd;
	qp->qp_mrhdl		= mr;
	qp->qp_sq_sigtype	= (attr_p->qp_flags & IBT_WR_SIGNALED) ?
	    TAVOR_QP_SQ_WR_SIGNALED : TAVOR_QP_SQ_ALL_SIGNALED;
	qp->qp_is_special	= (type == IBT_SMI_SQP) ?
	    TAVOR_QP_SMI : TAVOR_QP_GSI;
	qp->qp_is_umap		= 0;
	qp->qp_uarpg		= 0;
	qp->qp_sq_cqhdl		= sq_cq;
	qp->qp_sq_lastwqeaddr	= NULL;
	qp->qp_sq_bufsz		= (1 << log_qp_sq_size);
	qp->qp_sq_buf		= sq_buf;
	qp->qp_desc_off		= qp_desc_off;
	qp->qp_rq_cqhdl		= rq_cq;
	qp->qp_rq_lastwqeaddr	= NULL;
	qp->qp_rq_bufsz		= (1 << log_qp_rq_size);
	qp->qp_rq_buf		= rq_buf;
	qp->qp_portnum		= port;
	qp->qp_pkeyindx		= 0;
	qp->qp_hdlrarg		= (void *)ibt_qphdl;
	qp->qp_mcg_refcnt	= 0;
	qp->qp_srq_en		= 0;
	qp->qp_srqhdl		= NULL;

	/* Determine if later ddi_dma_sync will be necessary */
	qp->qp_sync = TAVOR_QP_IS_SYNC_REQ(state, qp->qp_wqinfo);

	/* All special QPs are UD QP service type */
	qp->qp_serv_type = TAVOR_QP_UD;

	/* Zero out the QP context */
	bzero(&qp->qpc, sizeof (tavor_hw_qpc_t));

	/*
	 * Put QP handle in Tavor QPNum-to-QPHdl list.  Then fill in the
	 * "qphdl" and return success
	 */
	ASSERT(state->ts_qphdl[qpc->tr_indx + port] == NULL);
	state->ts_qphdl[qpc->tr_indx + port] = qp;

	*qphdl = qp;

	TAVOR_TNF_EXIT(tavor_special_qp_alloc);
	return (DDI_SUCCESS);

/*
 * The following is cleanup for all possible failure cases in this routine
 */
spec_qpalloc_fail6:
	tavor_queue_free(state, &qp->qp_wqinfo);
spec_qpalloc_fail5:
	tavor_rsrc_free(state, &rsrc);
spec_qpalloc_fail4:
	if (tavor_special_qp_rsrc_free(state, type, port) != DDI_SUCCESS) {
		TAVOR_WARNING(state, "failed to free special QP rsrc");
	}
spec_qpalloc_fail3:
	tavor_cq_refcnt_dec(rq_cq);
spec_qpalloc_fail2:
	tavor_cq_refcnt_dec(sq_cq);
spec_qpalloc_fail1:
	tavor_pd_refcnt_dec(pd);
spec_qpalloc_fail:
	TNF_PROBE_1(tavor_special_qp_alloc_fail, TAVOR_TNF_ERROR, "",
	    tnf_string, msg, errormsg);
	TAVOR_TNF_EXIT(tavor_special_qp_alloc);
	return (status);
}


/*
 * tavor_qp_free()
 *    This function frees up the QP resources.  Depending on the value
 *    of the "free_qp_flags", the QP number may not be released until
 *    a subsequent call to tavor_qp_release_qpn().
 *
 *    Context: Can be called only from user or kernel context.
 */
/* ARGSUSED */
int
tavor_qp_free(tavor_state_t *state, tavor_qphdl_t *qphdl,
    ibc_free_qp_flags_t free_qp_flags, ibc_qpn_hdl_t *qpnh,
    uint_t sleepflag)
{
	tavor_rsrc_t		*qpc, *rdb, *rsrc;
	tavor_umap_db_entry_t	*umapdb;
	tavor_qpn_entry_t	*entry;
	tavor_pdhdl_t		pd;
	tavor_mrhdl_t		mr;
	tavor_cqhdl_t		sq_cq, rq_cq;
	tavor_srqhdl_t		srq;
	tavor_qphdl_t		qp;
	uint64_t		value;
	uint_t			type, port;
	uint_t			maxprot;
	uint_t			qp_srq_en;
	int			status;
	char			*errormsg;

	TAVOR_TNF_ENTER(tavor_qp_free);

	/*
	 * Pull all the necessary information from the Tavor Queue Pair
	 * handle.  This is necessary here because the resource for the
	 * QP handle is going to be freed up as part of this operation.
	 */
	qp	= *qphdl;
	mutex_enter(&qp->qp_lock);
	qpc	= qp->qp_qpcrsrcp;
	rsrc	= qp->qp_rsrcp;
	pd	= qp->qp_pdhdl;
	srq	= qp->qp_srqhdl;
	mr	= qp->qp_mrhdl;
	rq_cq	= qp->qp_rq_cqhdl;
	sq_cq	= qp->qp_sq_cqhdl;
	rdb	= qp->qp_rdbrsrcp;
	port	= qp->qp_portnum;
	qp_srq_en = qp->qp_srq_en;

	/*
	 * If the QP is part of an MCG, then we fail the qp_free
	 */
	if (qp->qp_mcg_refcnt != 0) {
		mutex_exit(&qp->qp_lock);
		TAVOR_TNF_FAIL(ibc_get_ci_failure(0), "QP part of MCG on free");
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
	if (qp->qp_state != TAVOR_QP_RESET) {
		if (tavor_qp_to_reset(state, qp) != DDI_SUCCESS) {
			mutex_exit(&qp->qp_lock);
			TAVOR_WARNING(state, "failed to reset QP context");
			/* Set "status" and "errormsg" and goto failure */
			TAVOR_TNF_FAIL(ibc_get_ci_failure(0),
			    "reset QP context");
			goto qpfree_fail;
		}
		qp->qp_state = TAVOR_QP_RESET;

		/*
		 * Do any additional handling necessary for the transition
		 * to the "Reset" state (e.g. update the WRID lists)
		 */
		tavor_wrid_to_reset_handling(state, qp);
	}

	/*
	 * If this was a user-mappable QP, then we need to remove its entry
	 * from the "userland resources database".  If it is also currently
	 * mmap()'d out to a user process, then we need to call
	 * devmap_devmem_remap() to remap the QP memory to an invalid mapping.
	 * We also need to invalidate the QP tracking information for the
	 * user mapping.
	 */
	if (qp->qp_is_umap) {
		status = tavor_umap_db_find(state->ts_instance, qp->qp_qpnum,
		    MLNX_UMAP_QPMEM_RSRC, &value, TAVOR_UMAP_DB_REMOVE,
		    &umapdb);
		if (status != DDI_SUCCESS) {
			mutex_exit(&qp->qp_lock);
			TAVOR_WARNING(state, "failed to find in database");
			TAVOR_TNF_EXIT(tavor_qp_free);
			return (ibc_get_ci_failure(0));
		}
		tavor_umap_db_free(umapdb);
		if (qp->qp_umap_dhp != NULL) {
			maxprot = (PROT_READ | PROT_WRITE | PROT_USER);
			status = devmap_devmem_remap(qp->qp_umap_dhp,
			    state->ts_dip, 0, 0, qp->qp_wqinfo.qa_size,
			    maxprot, DEVMAP_MAPPING_INVALID, NULL);
			if (status != DDI_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				TAVOR_WARNING(state, "failed in QP memory "
				    "devmap_devmem_remap()");
				TAVOR_TNF_EXIT(tavor_qp_free);
				return (ibc_get_ci_failure(0));
			}
			qp->qp_umap_dhp = (devmap_cookie_t)NULL;
		}
	}

	/*
	 * Put NULL into the Tavor QPNum-to-QPHdl list.  This will allow any
	 * in-progress events to detect that the QP corresponding to this
	 * number has been freed.  Note: it does depend in whether we are
	 * freeing a special QP or not.
	 */
	if (qp->qp_is_special) {
		state->ts_qphdl[qpc->tr_indx + port] = NULL;
	} else {
		state->ts_qphdl[qpc->tr_indx] = NULL;
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
	status = tavor_mr_deregister(state, &mr, TAVOR_MR_DEREG_ALL,
	    sleepflag);
	if (status != DDI_SUCCESS) {
		TAVOR_WARNING(state, "failed to deregister QP memory");
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(ibc_get_ci_failure(0), "failed deregister mr");
		goto qpfree_fail;
	}

	/* Free the memory for the QP */
	tavor_queue_free(state, &qp->qp_wqinfo);

	/*
	 * Free up the remainder of the QP resources.  Note: we have a few
	 * different resources to free up depending on whether the QP is a
	 * special QP or not.  As described above, if any of these fail for
	 * any reason it is an indication that something (either in HW or SW)
	 * has gone seriously wrong.  So we print a warning message and
	 * return.
	 */
	if (qp->qp_is_special) {
		type = (qp->qp_is_special == TAVOR_QP_SMI) ?
		    IBT_SMI_SQP : IBT_GSI_SQP;

		/* Free up resources for the special QP */
		status = tavor_special_qp_rsrc_free(state, type, port);
		if (status != DDI_SUCCESS) {
			TAVOR_WARNING(state, "failed to free special QP rsrc");
			/* Set "status" and "errormsg" and goto failure */
			TAVOR_TNF_FAIL(ibc_get_ci_failure(0),
			    "failed special QP rsrc");
			goto qpfree_fail;
		}

	} else {
		type = qp->qp_serv_type;

		/* Free up the RDB entries resource */
		if (type == TAVOR_QP_RC) {
			tavor_rsrc_free(state, &rdb);
		}

		/*
		 * Check the flags and determine whether to release the
		 * QPN or not, based on their value.
		 */
		if (free_qp_flags == IBC_FREE_QP_ONLY) {
			entry = qp->qp_qpn_hdl;
			tavor_qp_release_qpn(state, qp->qp_qpn_hdl,
			    TAVOR_QPN_FREE_ONLY);
			*qpnh = (ibc_qpn_hdl_t)entry;
		} else {
			tavor_qp_release_qpn(state, qp->qp_qpn_hdl,
			    TAVOR_QPN_RELEASE);
		}
	}

	/* Free the Tavor Queue Pair handle */
	tavor_rsrc_free(state, &rsrc);

	/* Decrement the reference counts on CQs, PD and SRQ (if needed) */
	tavor_cq_refcnt_dec(rq_cq);
	tavor_cq_refcnt_dec(sq_cq);
	tavor_pd_refcnt_dec(pd);
	if (qp_srq_en == TAVOR_QP_SRQ_ENABLED) {
		tavor_srq_refcnt_dec(srq);
	}

	/* Set the qphdl pointer to NULL and return success */
	*qphdl = NULL;

	TAVOR_TNF_EXIT(tavor_qp_free);
	return (DDI_SUCCESS);

qpfree_fail:
	TNF_PROBE_1(tavor_qp_free_fail, TAVOR_TNF_ERROR, "",
	    tnf_string, msg, errormsg);
	TAVOR_TNF_EXIT(tavor_qp_free);
	return (status);
}


/*
 * tavor_qp_query()
 *    Context: Can be called from interrupt or base context.
 */
int
tavor_qp_query(tavor_state_t *state, tavor_qphdl_t qp,
    ibt_qp_query_attr_t *attr_p)
{
	ibt_cep_state_t		qp_state;
	ibt_qp_ud_attr_t	*ud;
	ibt_qp_rc_attr_t	*rc;
	ibt_qp_uc_attr_t	*uc;
	ibt_cep_flags_t		enable_flags;
	tavor_hw_addr_path_t	*qpc_path, *qpc_alt_path;
	ibt_cep_path_t		*path_ptr, *alt_path_ptr;
	tavor_hw_qpc_t		*qpc;
	int			status;

	TAVOR_TNF_ENTER(tavor_qp_query);

	mutex_enter(&qp->qp_lock);

	/*
	 * Grab the temporary QPC entry from QP software state
	 */
	qpc = &qp->qpc;

	/* Convert the current Tavor QP state to IBTF QP state */
	switch (qp->qp_state) {
	case TAVOR_QP_RESET:
		qp_state = IBT_STATE_RESET;		/* "Reset" */
		break;
	case TAVOR_QP_INIT:
		qp_state = IBT_STATE_INIT;		/* Initialized */
		break;
	case TAVOR_QP_RTR:
		qp_state = IBT_STATE_RTR;		/* Ready to Receive */
		break;
	case TAVOR_QP_RTS:
		qp_state = IBT_STATE_RTS;		/* Ready to Send */
		break;
	case TAVOR_QP_SQERR:
		qp_state = IBT_STATE_SQE;		/* Send Queue Error */
		break;
	case TAVOR_QP_SQD:
		if (qp->qp_sqd_still_draining) {
			qp_state = IBT_STATE_SQDRAIN;	/* SQ Draining */
		} else {
			qp_state = IBT_STATE_SQD;	/* SQ Drained */
		}
		break;
	case TAVOR_QP_ERR:
		qp_state = IBT_STATE_ERROR;		/* Error */
		break;
	default:
		mutex_exit(&qp->qp_lock);
		TNF_PROBE_1(tavor_qp_query_inv_qpstate_fail,
		    TAVOR_TNF_ERROR, "", tnf_uint, qpstate, qp->qp_state);
		TAVOR_TNF_EXIT(tavor_qp_query);
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
	attr_p->qp_sq_cq    = qp->qp_sq_cqhdl->cq_hdlrarg;
	attr_p->qp_rq_cq    = qp->qp_rq_cqhdl->cq_hdlrarg;
	if (qp->qp_is_special) {
		attr_p->qp_qpn = (qp->qp_is_special == TAVOR_QP_SMI) ? 0 : 1;
	} else {
		attr_p->qp_qpn = (ib_qpn_t)qp->qp_qpnum;
	}
	attr_p->qp_sq_sgl   = qp->qp_sq_sgl;
	attr_p->qp_rq_sgl   = qp->qp_rq_sgl;
	attr_p->qp_info.qp_sq_sz = qp->qp_sq_bufsz;
	attr_p->qp_info.qp_rq_sz = qp->qp_rq_bufsz;

	/*
	 * If QP is currently in the "Reset" state, then only the above are
	 * returned
	 */
	if (qp_state == IBT_STATE_RESET) {
		mutex_exit(&qp->qp_lock);
		TAVOR_TNF_EXIT(tavor_qp_query);
		return (DDI_SUCCESS);
	}

	/*
	 * Post QUERY_QP command to firmware
	 *
	 * We do a TAVOR_NOSLEEP here because we are holding the "qp_lock".
	 * Since we may be in the interrupt context (or subsequently raised
	 * to interrupt level by priority inversion), we do not want to block
	 * in this routine waiting for success.
	 */
	status = tavor_cmn_query_cmd_post(state, QUERY_QP, qp->qp_qpnum,
	    qpc, sizeof (tavor_hw_qpc_t), TAVOR_CMD_NOSLEEP_SPIN);
	if (status != TAVOR_CMD_SUCCESS) {
		mutex_exit(&qp->qp_lock);
		cmn_err(CE_CONT, "Tavor: QUERY_QP command failed: %08x\n",
		    status);
		TNF_PROBE_1(tavor_qp_query_cmd_fail, TAVOR_TNF_ERROR, "",
		    tnf_uint, status, status);
		TAVOR_TNF_EXIT(tavor_qp_query);
		return (ibc_get_ci_failure(0));
	}

	/*
	 * Fill in the additional QP info based on the QP's transport type.
	 */
	if (qp->qp_serv_type == TAVOR_QP_UD) {

		/* Fill in the UD-specific info */
		ud = &attr_p->qp_info.qp_transport.ud;
		ud->ud_qkey	= (ib_qkey_t)qpc->qkey;
		ud->ud_sq_psn	= qpc->next_snd_psn;
		ud->ud_pkey_ix	= qpc->pri_addr_path.pkey_indx;
		ud->ud_port	= qpc->pri_addr_path.portnum;

		attr_p->qp_info.qp_trans = IBT_UD_SRV;

	} else if (qp->qp_serv_type == TAVOR_QP_RC) {

		/* Fill in the RC-specific info */
		rc = &attr_p->qp_info.qp_transport.rc;
		rc->rc_sq_psn	= qpc->next_snd_psn;
		rc->rc_rq_psn	= qpc->next_rcv_psn;
		rc->rc_dst_qpn	= qpc->rem_qpn;

		/* Grab the path migration state information */
		if (qpc->pm_state == TAVOR_QP_PMSTATE_MIGRATED) {
			rc->rc_mig_state = IBT_STATE_MIGRATED;
		} else if (qpc->pm_state == TAVOR_QP_PMSTATE_REARM) {
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
		tavor_get_addr_path(state, qpc_path, &path_ptr->cep_adds_vect,
		    TAVOR_ADDRPATH_QP, qp);

		/* Fill in the additional primary address path fields */
		path_ptr->cep_pkey_ix	   = qpc_path->pkey_indx;
		path_ptr->cep_hca_port_num = qpc_path->portnum;
		path_ptr->cep_timeout	   = qpc_path->ack_timeout;

		/* Get the common alternate address path fields */
		qpc_alt_path = &qpc->alt_addr_path;
		alt_path_ptr = &rc->rc_alt_path;
		tavor_get_addr_path(state, qpc_alt_path,
		    &alt_path_ptr->cep_adds_vect, TAVOR_ADDRPATH_QP, qp);

		/* Fill in the additional alternate address path fields */
		alt_path_ptr->cep_pkey_ix	= qpc_alt_path->pkey_indx;
		alt_path_ptr->cep_hca_port_num	= qpc_alt_path->portnum;
		alt_path_ptr->cep_timeout	= qpc_alt_path->ack_timeout;

		/* Get the RNR retry time from primary path */
		rc->rc_rnr_retry_cnt = qpc_path->rnr_retry;

		/* Set the enable flags based on RDMA/Atomic enable bits */
		enable_flags = IBT_CEP_NO_FLAGS;
		enable_flags |= ((qpc->rre == 0) ? 0 : IBT_CEP_RDMA_RD);
		enable_flags |= ((qpc->rwe == 0) ? 0 : IBT_CEP_RDMA_WR);
		enable_flags |= ((qpc->rae == 0) ? 0 : IBT_CEP_ATOMIC);
		attr_p->qp_info.qp_flags = enable_flags;

		attr_p->qp_info.qp_trans = IBT_RC_SRV;

	} else if (qp->qp_serv_type == TAVOR_QP_UC) {

		/* Fill in the UC-specific info */
		uc = &attr_p->qp_info.qp_transport.uc;
		uc->uc_sq_psn	= qpc->next_snd_psn;
		uc->uc_rq_psn	= qpc->next_rcv_psn;
		uc->uc_dst_qpn	= qpc->rem_qpn;

		/* Grab the path migration state information */
		if (qpc->pm_state == TAVOR_QP_PMSTATE_MIGRATED) {
			uc->uc_mig_state = IBT_STATE_MIGRATED;
		} else if (qpc->pm_state == TAVOR_QP_PMSTATE_REARM) {
			uc->uc_mig_state = IBT_STATE_REARMED;
		} else {
			uc->uc_mig_state = IBT_STATE_ARMED;
		}
		uc->uc_path_mtu = qpc->mtu;

		/* Get the common primary address path fields */
		qpc_path = &qpc->pri_addr_path;
		path_ptr = &uc->uc_path;
		tavor_get_addr_path(state, qpc_path, &path_ptr->cep_adds_vect,
		    TAVOR_ADDRPATH_QP, qp);

		/* Fill in the additional primary address path fields */
		path_ptr->cep_pkey_ix	   = qpc_path->pkey_indx;
		path_ptr->cep_hca_port_num = qpc_path->portnum;

		/* Get the common alternate address path fields */
		qpc_alt_path = &qpc->alt_addr_path;
		alt_path_ptr = &uc->uc_alt_path;
		tavor_get_addr_path(state, qpc_alt_path,
		    &alt_path_ptr->cep_adds_vect, TAVOR_ADDRPATH_QP, qp);

		/* Fill in the additional alternate address path fields */
		alt_path_ptr->cep_pkey_ix	= qpc_alt_path->pkey_indx;
		alt_path_ptr->cep_hca_port_num	= qpc_alt_path->portnum;

		/*
		 * Set the enable flags based on RDMA enable bits (by
		 * definition UC doesn't support Atomic or RDMA Read)
		 */
		enable_flags = ((qpc->rwe == 0) ? 0 : IBT_CEP_RDMA_WR);
		attr_p->qp_info.qp_flags = enable_flags;

		attr_p->qp_info.qp_trans = IBT_UC_SRV;

	} else {
		TAVOR_WARNING(state, "unexpected QP transport type");
		mutex_exit(&qp->qp_lock);
		return (ibc_get_ci_failure(0));
	}

	/*
	 * Under certain circumstances it is possible for the Tavor hardware
	 * to transition to one of the error states without software directly
	 * knowing about it.  The QueryQP() call is the one place where we
	 * have an opportunity to sample and update our view of the QP state.
	 */
	if (qpc->state == TAVOR_QP_SQERR) {
		attr_p->qp_info.qp_state = IBT_STATE_SQE;
		qp->qp_state = TAVOR_QP_SQERR;
	}
	if (qpc->state == TAVOR_QP_ERR) {
		attr_p->qp_info.qp_state = IBT_STATE_ERROR;
		qp->qp_state = TAVOR_QP_ERR;
	}
	mutex_exit(&qp->qp_lock);

	TAVOR_TNF_EXIT(tavor_qp_query);
	return (DDI_SUCCESS);
}


/*
 * tavor_qp_create_qpn()
 *    Context: Can be called from interrupt or base context.
 */
static int
tavor_qp_create_qpn(tavor_state_t *state, tavor_qphdl_t qp, tavor_rsrc_t *qpc)
{
	tavor_qpn_entry_t	query;
	tavor_qpn_entry_t	*entry;
	avl_index_t		where;

	TAVOR_TNF_ENTER(tavor_qp_create_qpn);

	/*
	 * Build a query (for the AVL tree lookup) and attempt to find
	 * a previously added entry that has a matching QPC index.  If
	 * no matching entry is found, then allocate, initialize, and
	 * add an entry to the AVL tree.
	 * If a matching entry is found, then increment its QPN counter
	 * and reference counter.
	 */
	query.qpn_indx = qpc->tr_indx;
	mutex_enter(&state->ts_qpn_avl_lock);
	entry = (tavor_qpn_entry_t *)avl_find(&state->ts_qpn_avl,
	    &query, &where);
	if (entry == NULL) {
		/*
		 * Allocate and initialize a QPN entry, then insert
		 * it into the AVL tree.
		 */
		entry = (tavor_qpn_entry_t *)kmem_zalloc(
		    sizeof (tavor_qpn_entry_t), KM_NOSLEEP);
		if (entry == NULL) {
			mutex_exit(&state->ts_qpn_avl_lock);
			TAVOR_TNF_EXIT(tavor_qp_create_qpn);
			return (DDI_FAILURE);
		}
		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*entry))

		entry->qpn_indx	   = qpc->tr_indx;
		entry->qpn_refcnt  = 0;
		entry->qpn_counter = 0;

		avl_insert(&state->ts_qpn_avl, entry, where);
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
	    state->ts_cfg_profile->cp_log_num_qp) | qpc->tr_indx) &
	    TAVOR_QP_MAXNUMBER_MSK;

	/*
	 * Increment the reference counter and QPN counter.  The QPN
	 * counter always indicates the next available number for use.
	 */
	entry->qpn_counter++;
	entry->qpn_refcnt++;

	mutex_exit(&state->ts_qpn_avl_lock);
	TAVOR_TNF_EXIT(tavor_qp_create_qpn);
	return (DDI_SUCCESS);
}


/*
 * tavor_qp_release_qpn()
 *    Context: Can be called only from user or kernel context.
 */
void
tavor_qp_release_qpn(tavor_state_t *state, tavor_qpn_entry_t *entry, int flags)
{
	TAVOR_TNF_ENTER(tavor_qp_release_qpn);

	ASSERT(entry != NULL);

	mutex_enter(&state->ts_qpn_avl_lock);

	/*
	 * If we are releasing the QP number here, then we decrement the
	 * reference count and check for zero references.  If there are
	 * zero references, then we free the QPC context (if it hadn't
	 * already been freed during a TAVOR_QPN_FREE_ONLY free, i.e. for
	 * reuse with another similar QP number) and remove the tracking
	 * structure from the QP number AVL tree and free the structure.
	 * If we are not releasing the QP number here, then, as long as we
	 * have not exhausted the usefulness of the QPC context (that is,
	 * re-used it too many times without the reference count having
	 * gone to zero), we free up the QPC context for use by another
	 * thread (which will use it to construct a different QP number
	 * from the same QPC table index).
	 */
	if (flags == TAVOR_QPN_RELEASE) {
		entry->qpn_refcnt--;

		/*
		 * If the reference count is zero, then we free the QPC
		 * context (if it hadn't already been freed in an early
		 * step, e.g. TAVOR_QPN_FREE_ONLY) and remove/free the
		 * tracking structure from the QP number AVL tree.
		 */
		if (entry->qpn_refcnt == 0) {
			if (entry->qpn_qpc != NULL) {
				tavor_rsrc_free(state, &entry->qpn_qpc);
			}

			/*
			 * If the current entry has served it's useful
			 * purpose (i.e. been reused the maximum allowable
			 * number of times), then remove it from QP number
			 * AVL tree and free it up.
			 */
			if (entry->qpn_counter >= (1 <<
			    (24 - state->ts_cfg_profile->cp_log_num_qp))) {
				avl_remove(&state->ts_qpn_avl, entry);
				kmem_free(entry, sizeof (tavor_qpn_entry_t));
			}
		}

	} else if (flags == TAVOR_QPN_FREE_ONLY) {
		/*
		 * Even if we are not freeing the QP number, that will not
		 * always prevent us from releasing the QPC context.  In fact,
		 * since the QPC context only forms part of the whole QPN,
		 * we want to free it up for use by other consumers.  But
		 * if the reference count is non-zero (which it will always
		 * be when we are doing TAVOR_QPN_FREE_ONLY) and the counter
		 * has reached its maximum value, then we cannot reuse the
		 * QPC context until the reference count eventually reaches
		 * zero (in TAVOR_QPN_RELEASE, above).
		 */
		if (entry->qpn_counter < (1 <<
		    (24 - state->ts_cfg_profile->cp_log_num_qp))) {
			tavor_rsrc_free(state, &entry->qpn_qpc);
		}
	}
	mutex_exit(&state->ts_qpn_avl_lock);

	TAVOR_TNF_EXIT(tavor_qp_release_qpn);
}


/*
 * tavor_qpn_db_compare()
 *    Context: Can be called from user or kernel context.
 */
static int
tavor_qpn_avl_compare(const void *q, const void *e)
{
	tavor_qpn_entry_t	*entry, *query;

	TAVOR_TNF_ENTER(tavor_qpn_avl_compare);

	entry = (tavor_qpn_entry_t *)e;
	query = (tavor_qpn_entry_t *)q;

	if (query->qpn_indx < entry->qpn_indx) {
		TAVOR_TNF_EXIT(tavor_qpn_avl_compare);
		return (-1);
	} else if (query->qpn_indx > entry->qpn_indx) {
		TAVOR_TNF_EXIT(tavor_qpn_avl_compare);
		return (+1);
	} else {
		TAVOR_TNF_EXIT(tavor_qpn_avl_compare);
		return (0);
	}
}


/*
 * tavor_qpn_avl_init()
 *    Context: Only called from attach() path context
 */
void
tavor_qpn_avl_init(tavor_state_t *state)
{
	TAVOR_TNF_ENTER(tavor_qpn_avl_init);

	/* Initialize the lock used for QP number (QPN) AVL tree access */
	mutex_init(&state->ts_qpn_avl_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(state->ts_intrmsi_pri));

	/* Initialize the AVL tree for the QP number (QPN) storage */
	avl_create(&state->ts_qpn_avl, tavor_qpn_avl_compare,
	    sizeof (tavor_qpn_entry_t),
	    offsetof(tavor_qpn_entry_t, qpn_avlnode));

	TAVOR_TNF_EXIT(tavor_qpn_avl_init);
}


/*
 * tavor_qpn_avl_fini()
 *    Context: Only called from attach() and/or detach() path contexts
 */
void
tavor_qpn_avl_fini(tavor_state_t *state)
{
	tavor_qpn_entry_t	*entry;
	void			*cookie;

	TAVOR_TNF_ENTER(tavor_qpn_avl_fini);

	/*
	 * Empty all entries (if necessary) and destroy the AVL tree
	 * that was used for QP number (QPN) tracking.
	 */
	cookie = NULL;
	while ((entry = (tavor_qpn_entry_t *)avl_destroy_nodes(
	    &state->ts_qpn_avl, &cookie)) != NULL) {
		kmem_free(entry, sizeof (tavor_qpn_entry_t));
	}
	avl_destroy(&state->ts_qpn_avl);

	/* Destroy the lock used for QP number (QPN) AVL tree access */
	mutex_destroy(&state->ts_qpn_avl_lock);

	TAVOR_TNF_EXIT(tavor_qpn_avl_fini);
}


/*
 * tavor_qphdl_from_qpnum()
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
tavor_qphdl_t
tavor_qphdl_from_qpnum(tavor_state_t *state, uint_t qpnum)
{
	uint_t	qpindx, qpmask;

	/* Calculate the QP table index from the qpnum */
	qpmask = (1 << state->ts_cfg_profile->cp_log_num_qp) - 1;
	qpindx = qpnum & qpmask;
	return (state->ts_qphdl[qpindx]);
}


/*
 * tavor_special_qp_rsrc_alloc
 *    Context: Can be called from interrupt or base context.
 */
static int
tavor_special_qp_rsrc_alloc(tavor_state_t *state, ibt_sqp_type_t type,
    uint_t port, tavor_rsrc_t **qp_rsrc)
{
	uint_t		mask, flags;
	int		status;

	TAVOR_TNF_ENTER(tavor_special_qp_rsrc_alloc);

	mutex_enter(&state->ts_spec_qplock);
	flags = state->ts_spec_qpflags;
	if (type == IBT_SMI_SQP) {
		/*
		 * Check here to see if the driver has been configured
		 * to instruct the Tavor firmware to handle all incoming
		 * SMP messages (i.e. messages sent to SMA).  If so,
		 * then we will treat QP0 as if it has already been
		 * allocated (for internal use).  Otherwise, if we allow
		 * the allocation to happen, it will cause unexpected
		 * behaviors (e.g. Tavor SMA becomes unresponsive).
		 */
		if (state->ts_cfg_profile->cp_qp0_agents_in_fw != 0) {
			mutex_exit(&state->ts_spec_qplock);
			TNF_PROBE_0(tavor_special_qp0_alloc_already_in_fw,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_special_qp_rsrc_alloc);
			return (IBT_QP_IN_USE);
		}

		/*
		 * If this is the first QP0 allocation, then post
		 * a CONF_SPECIAL_QP firmware command
		 */
		if ((flags & TAVOR_SPECIAL_QP0_RSRC_MASK) == 0) {
			status = tavor_conf_special_qp_cmd_post(state,
			    state->ts_spec_qp0->tr_indx, TAVOR_CMD_QP_SMI,
			    TAVOR_CMD_NOSLEEP_SPIN);
			if (status != TAVOR_CMD_SUCCESS) {
				mutex_exit(&state->ts_spec_qplock);
				cmn_err(CE_CONT, "Tavor: CONF_SPECIAL_QP "
				    "command failed: %08x\n", status);
				TNF_PROBE_1(tavor_conf_special_qp_cmd_fail,
				    TAVOR_TNF_ERROR, "", tnf_uint, status,
				    status);
				TAVOR_TNF_EXIT(tavor_special_qp_rsrc_alloc);
				return (IBT_INSUFF_RESOURCE);
			}
		}

		/*
		 * Now check (and, if necessary, modify) the flags to indicate
		 * whether the allocation was successful
		 */
		mask = (1 << (TAVOR_SPECIAL_QP0_RSRC + port));
		if (flags & mask) {
			mutex_exit(&state->ts_spec_qplock);
			TNF_PROBE_1(tavor_ts_spec_qp0_alloc_already,
			    TAVOR_TNF_ERROR, "", tnf_uint, port, port);
			TAVOR_TNF_EXIT(tavor_special_qp_rsrc_alloc);
			return (IBT_QP_IN_USE);
		}
		state->ts_spec_qpflags |= mask;
		*qp_rsrc = state->ts_spec_qp0;

	} else {
		/*
		 * If this is the first QP1 allocation, then post
		 * a CONF_SPECIAL_QP firmware command
		 */
		if ((flags & TAVOR_SPECIAL_QP1_RSRC_MASK) == 0) {
			status = tavor_conf_special_qp_cmd_post(state,
			    state->ts_spec_qp1->tr_indx, TAVOR_CMD_QP_GSI,
			    TAVOR_CMD_NOSLEEP_SPIN);
			if (status != TAVOR_CMD_SUCCESS) {
				mutex_exit(&state->ts_spec_qplock);
				cmn_err(CE_CONT, "Tavor: CONF_SPECIAL_QP "
				    "command failed: %08x\n", status);
				TNF_PROBE_1(tavor_conf_special_qp_cmd_fail,
				    TAVOR_TNF_ERROR, "", tnf_uint, status,
				    status);
				TAVOR_TNF_EXIT(tavor_special_qp_rsrc_alloc);
				return (IBT_INSUFF_RESOURCE);
			}
		}

		/*
		 * Now check (and, if necessary, modify) the flags to indicate
		 * whether the allocation was successful
		 */
		mask = (1 << (TAVOR_SPECIAL_QP1_RSRC + port));
		if (flags & mask) {
			mutex_exit(&state->ts_spec_qplock);
			TNF_PROBE_0(tavor_ts_spec_qp1_alloc_already,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_special_qp_rsrc_alloc);
			return (IBT_QP_IN_USE);
		}
		state->ts_spec_qpflags |= mask;
		*qp_rsrc = state->ts_spec_qp1;
	}

	mutex_exit(&state->ts_spec_qplock);
	TAVOR_TNF_EXIT(tavor_special_qp_rsrc_alloc);
	return (DDI_SUCCESS);
}


/*
 * tavor_special_qp_rsrc_free
 *    Context: Can be called from interrupt or base context.
 */
static int
tavor_special_qp_rsrc_free(tavor_state_t *state, ibt_sqp_type_t type,
    uint_t port)
{
	uint_t		mask, flags;
	int		status;

	TAVOR_TNF_ENTER(tavor_special_qp_rsrc_free);

	mutex_enter(&state->ts_spec_qplock);
	if (type == IBT_SMI_SQP) {
		mask = (1 << (TAVOR_SPECIAL_QP0_RSRC + port));
		state->ts_spec_qpflags &= ~mask;
		flags = state->ts_spec_qpflags;

		/*
		 * If this is the last QP0 free, then post a CONF_SPECIAL_QP
		 * firmware command
		 */
		if ((flags & TAVOR_SPECIAL_QP0_RSRC_MASK) == 0) {
			status = tavor_conf_special_qp_cmd_post(state, 0,
			    TAVOR_CMD_QP_SMI, TAVOR_CMD_NOSLEEP_SPIN);
			if (status != TAVOR_CMD_SUCCESS) {
				mutex_exit(&state->ts_spec_qplock);
				cmn_err(CE_CONT, "Tavor: CONF_SPECIAL_QP "
				    "command failed: %08x\n", status);
				TNF_PROBE_1(tavor_conf_special_qp_cmd_fail,
				    TAVOR_TNF_ERROR, "", tnf_uint, status,
				    status);
				TAVOR_TNF_EXIT(tavor_special_qp_rsrc_free);
				return (ibc_get_ci_failure(0));
			}
		}
	} else {
		mask = (1 << (TAVOR_SPECIAL_QP1_RSRC + port));
		state->ts_spec_qpflags &= ~mask;
		flags = state->ts_spec_qpflags;

		/*
		 * If this is the last QP1 free, then post a CONF_SPECIAL_QP
		 * firmware command
		 */
		if ((flags & TAVOR_SPECIAL_QP1_RSRC_MASK) == 0) {
			status = tavor_conf_special_qp_cmd_post(state, 0,
			    TAVOR_CMD_QP_GSI, TAVOR_CMD_NOSLEEP_SPIN);
			if (status != TAVOR_CMD_SUCCESS) {
				mutex_exit(&state->ts_spec_qplock);
				cmn_err(CE_CONT, "Tavor: CONF_SPECIAL_QP "
				    "command failed: %08x\n", status);
				TNF_PROBE_1(tavor_conf_special_qp_cmd_fail,
				    TAVOR_TNF_ERROR, "", tnf_uint, status,
				    status);
				TAVOR_TNF_EXIT(tavor_special_qp_rsrc_free);
				return (ibc_get_ci_failure(0));
			}
		}
	}

	mutex_exit(&state->ts_spec_qplock);
	TAVOR_TNF_EXIT(tavor_special_qp_rsrc_free);
	return (DDI_SUCCESS);
}


/*
 * tavor_qp_sgl_to_logwqesz()
 *    Context: Can be called from interrupt or base context.
 */
static void
tavor_qp_sgl_to_logwqesz(tavor_state_t *state, uint_t num_sgl,
    tavor_qp_wq_type_t wq_type, uint_t *logwqesz, uint_t *max_sgl)
{
	uint_t	max_size, log2, actual_sgl;

	TAVOR_TNF_ENTER(tavor_qp_sgl_to_logwqesz);

	switch (wq_type) {
	case TAVOR_QP_WQ_TYPE_SENDQ:
		/*
		 * Use requested maximum SGL to calculate max descriptor size
		 * (while guaranteeing that the descriptor size is a
		 * power-of-2 cachelines).
		 */
		max_size = (TAVOR_QP_WQE_MLX_SND_HDRS + (num_sgl << 4));
		log2 = highbit(max_size);
		if (ISP2(max_size)) {
			log2 = log2 - 1;
		}

		/* Make sure descriptor is at least the minimum size */
		log2 = max(log2, TAVOR_QP_WQE_LOG_MINIMUM);

		/* Calculate actual number of SGL (given WQE size) */
		actual_sgl = ((1 << log2) - TAVOR_QP_WQE_MLX_SND_HDRS) >> 4;
		break;

	case TAVOR_QP_WQ_TYPE_RECVQ:
		/*
		 * Same as above (except for Recv WQEs)
		 */
		max_size = (TAVOR_QP_WQE_MLX_RCV_HDRS + (num_sgl << 4));
		log2 = highbit(max_size);
		if (ISP2(max_size)) {
			log2 = log2 - 1;
		}

		/* Make sure descriptor is at least the minimum size */
		log2 = max(log2, TAVOR_QP_WQE_LOG_MINIMUM);

		/* Calculate actual number of SGL (given WQE size) */
		actual_sgl = ((1 << log2) - TAVOR_QP_WQE_MLX_RCV_HDRS) >> 4;
		break;

	case TAVOR_QP_WQ_TYPE_SENDMLX_QP0:
		/*
		 * Same as above (except for MLX transport WQEs).  For these
		 * WQEs we have to account for the space consumed by the
		 * "inline" packet headers.  (This is smaller than for QP1
		 * below because QP0 is not allowed to send packets with a GRH.
		 */
		max_size = (TAVOR_QP_WQE_MLX_QP0_HDRS + (num_sgl << 4));
		log2 = highbit(max_size);
		if (ISP2(max_size)) {
			log2 = log2 - 1;
		}

		/* Make sure descriptor is at least the minimum size */
		log2 = max(log2, TAVOR_QP_WQE_LOG_MINIMUM);

		/* Calculate actual number of SGL (given WQE size) */
		actual_sgl = ((1 << log2) - TAVOR_QP_WQE_MLX_QP0_HDRS) >> 4;
		break;

	case TAVOR_QP_WQ_TYPE_SENDMLX_QP1:
		/*
		 * Same as above.  For these WQEs we again have to account for
		 * the space consumed by the "inline" packet headers.  (This
		 * is larger than for QP0 above because we have to account for
		 * the possibility of a GRH in each packet - and this
		 * introduces an alignment issue that causes us to consume
		 * an additional 8 bytes).
		 */
		max_size = (TAVOR_QP_WQE_MLX_QP1_HDRS + (num_sgl << 4));
		log2 = highbit(max_size);
		if (ISP2(max_size)) {
			log2 = log2 - 1;
		}

		/* Make sure descriptor is at least the minimum size */
		log2 = max(log2, TAVOR_QP_WQE_LOG_MINIMUM);

		/* Calculate actual number of SGL (given WQE size) */
		actual_sgl = ((1 << log2) - TAVOR_QP_WQE_MLX_QP1_HDRS) >> 4;
		break;

	default:
		TAVOR_WARNING(state, "unexpected work queue type");
		TNF_PROBE_0(tavor_qp_sgl_to_logwqesz_inv_wqtype_fail,
		    TAVOR_TNF_ERROR, "");
		break;
	}

	/* Fill in the return values */
	*logwqesz = log2;
	*max_sgl  = min(state->ts_cfg_profile->cp_wqe_real_max_sgl, actual_sgl);

	TAVOR_TNF_EXIT(tavor_qp_sgl_to_logwqesz);
}
