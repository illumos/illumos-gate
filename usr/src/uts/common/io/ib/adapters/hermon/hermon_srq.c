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
 * hermon_srq.c
 *    Hermon Shared Receive Queue Processing Routines
 *
 *    Implements all the routines necessary for allocating, freeing, querying,
 *    modifying and posting shared receive queues.
 */

#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/bitmap.h>

#include <sys/ib/adapters/hermon/hermon.h>

static void hermon_srq_sgl_to_logwqesz(hermon_state_t *state, uint_t num_sgl,
    hermon_qp_wq_type_t wq_type, uint_t *logwqesz, uint_t *max_sgl);

/*
 * hermon_srq_alloc()
 *    Context: Can be called only from user or kernel context.
 */
int
hermon_srq_alloc(hermon_state_t *state, hermon_srq_info_t *srqinfo,
    uint_t sleepflag)
{
	ibt_srq_hdl_t		ibt_srqhdl;
	hermon_pdhdl_t		pd;
	ibt_srq_sizes_t		*sizes;
	ibt_srq_sizes_t		*real_sizes;
	hermon_srqhdl_t		*srqhdl;
	ibt_srq_flags_t		flags;
	hermon_rsrc_t		*srqc, *rsrc;
	hermon_hw_srqc_t	srqc_entry;
	uint32_t		*buf;
	hermon_srqhdl_t		srq;
	hermon_umap_db_entry_t	*umapdb;
	ibt_mr_attr_t		mr_attr;
	hermon_mr_options_t	mr_op;
	hermon_mrhdl_t		mr;
	uint64_t		value, srq_desc_off;
	uint32_t		log_srq_size;
	uint32_t		uarpg;
	uint_t			srq_is_umap;
	int			flag, status;
	uint_t			max_sgl;
	uint_t			wqesz;
	uint_t			srq_wr_sz;
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*sizes))

	/*
	 * options-->wq_location used to be for location, now explicitly
	 * LOCATION_NORMAL
	 */

	/*
	 * Extract the necessary info from the hermon_srq_info_t structure
	 */
	real_sizes = srqinfo->srqi_real_sizes;
	sizes	   = srqinfo->srqi_sizes;
	pd	   = srqinfo->srqi_pd;
	ibt_srqhdl = srqinfo->srqi_ibt_srqhdl;
	flags	   = srqinfo->srqi_flags;
	srqhdl	   = srqinfo->srqi_srqhdl;

	/*
	 * Determine whether SRQ is being allocated for userland access or
	 * whether it is being allocated for kernel access.  If the SRQ is
	 * being allocated for userland access, then lookup the UAR doorbell
	 * page number for the current process.  Note:  If this is not found
	 * (e.g. if the process has not previously open()'d the Hermon driver),
	 * then an error is returned.
	 */
	srq_is_umap = (flags & IBT_SRQ_USER_MAP) ? 1 : 0;
	if (srq_is_umap) {
		status = hermon_umap_db_find(state->hs_instance, ddi_get_pid(),
		    MLNX_UMAP_UARPG_RSRC, &value, 0, NULL);
		if (status != DDI_SUCCESS) {
			status = IBT_INVALID_PARAM;
			goto srqalloc_fail3;
		}
		uarpg = ((hermon_rsrc_t *)(uintptr_t)value)->hr_indx;
	} else {
		uarpg = state->hs_kernel_uar_index;
	}

	/* Increase PD refcnt */
	hermon_pd_refcnt_inc(pd);

	/* Allocate an SRQ context entry */
	status = hermon_rsrc_alloc(state, HERMON_SRQC, 1, sleepflag, &srqc);
	if (status != DDI_SUCCESS) {
		status = IBT_INSUFF_RESOURCE;
		goto srqalloc_fail1;
	}

	/* Allocate the SRQ Handle entry */
	status = hermon_rsrc_alloc(state, HERMON_SRQHDL, 1, sleepflag, &rsrc);
	if (status != DDI_SUCCESS) {
		status = IBT_INSUFF_RESOURCE;
		goto srqalloc_fail2;
	}

	srq = (hermon_srqhdl_t)rsrc->hr_addr;
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*srq))

	bzero(srq, sizeof (struct hermon_sw_srq_s));
	/* Calculate the SRQ number */

	/* just use the index, implicit in Hermon */
	srq->srq_srqnum = srqc->hr_indx;

	/*
	 * If this will be a user-mappable SRQ, then allocate an entry for
	 * the "userland resources database".  This will later be added to
	 * the database (after all further SRQ operations are successful).
	 * If we fail here, we must undo the reference counts and the
	 * previous resource allocation.
	 */
	if (srq_is_umap) {
		umapdb = hermon_umap_db_alloc(state->hs_instance,
		    srq->srq_srqnum, MLNX_UMAP_SRQMEM_RSRC,
		    (uint64_t)(uintptr_t)rsrc);
		if (umapdb == NULL) {
			status = IBT_INSUFF_RESOURCE;
			goto srqalloc_fail3;
		}
	}

	/*
	 * Allocate the doorbell record.  Hermon just needs one for the
	 * SRQ, and use uarpg (above) as the uar index
	 */

	status = hermon_dbr_alloc(state, uarpg, &srq->srq_wq_dbr_acchdl,
	    &srq->srq_wq_vdbr, &srq->srq_wq_pdbr, &srq->srq_rdbr_mapoffset);
	if (status != DDI_SUCCESS) {
		status = IBT_INSUFF_RESOURCE;
		goto srqalloc_fail4;
	}

	/*
	 * Calculate the appropriate size for the SRQ.
	 * Note:  All Hermon SRQs must be a power-of-2 in size.  Also
	 * they may not be any smaller than HERMON_SRQ_MIN_SIZE.  This step
	 * is to round the requested size up to the next highest power-of-2
	 */
	srq_wr_sz = max(sizes->srq_wr_sz + 1, HERMON_SRQ_MIN_SIZE);
	log_srq_size = highbit(srq_wr_sz);
	if (ISP2(srq_wr_sz)) {
		log_srq_size = log_srq_size - 1;
	}

	/*
	 * Next we verify that the rounded-up size is valid (i.e. consistent
	 * with the device limits and/or software-configured limits).  If not,
	 * then obviously we have a lot of cleanup to do before returning.
	 */
	if (log_srq_size > state->hs_cfg_profile->cp_log_max_srq_sz) {
		status = IBT_HCA_WR_EXCEEDED;
		goto srqalloc_fail4a;
	}

	/*
	 * Next we verify that the requested number of SGL is valid (i.e.
	 * consistent with the device limits and/or software-configured
	 * limits).  If not, then obviously the same cleanup needs to be done.
	 */
	max_sgl = state->hs_ibtfinfo.hca_attr->hca_max_srq_sgl;
	if (sizes->srq_sgl_sz > max_sgl) {
		status = IBT_HCA_SGL_EXCEEDED;
		goto srqalloc_fail4a;
	}

	/*
	 * Determine the SRQ's WQE sizes.  This depends on the requested
	 * number of SGLs.  Note: This also has the side-effect of
	 * calculating the real number of SGLs (for the calculated WQE size)
	 */
	hermon_srq_sgl_to_logwqesz(state, sizes->srq_sgl_sz,
	    HERMON_QP_WQ_TYPE_RECVQ, &srq->srq_wq_log_wqesz,
	    &srq->srq_wq_sgl);

	/*
	 * Allocate the memory for SRQ work queues.  Note:  The location from
	 * which we will allocate these work queues is always
	 * QUEUE_LOCATION_NORMAL.  Since Hermon work queues are not
	 * allowed to cross a 32-bit (4GB) boundary, the alignment of the work
	 * queue memory is very important.  We used to allocate work queues
	 * (the combined receive and send queues) so that they would be aligned
	 * on their combined size.  That alignment guaranteed that they would
	 * never cross the 4GB boundary (Hermon work queues are on the order of
	 * MBs at maximum).  Now we are able to relax this alignment constraint
	 * by ensuring that the IB address assigned to the queue memory (as a
	 * result of the hermon_mr_register() call) is offset from zero.
	 * Previously, we had wanted to use the ddi_dma_mem_alloc() routine to
	 * guarantee the alignment, but when attempting to use IOMMU bypass
	 * mode we found that we were not allowed to specify any alignment that
	 * was more restrictive than the system page size.  So we avoided this
	 * constraint by passing two alignment values, one for the memory
	 * allocation itself and the other for the DMA handle (for later bind).
	 * This used to cause more memory than necessary to be allocated (in
	 * order to guarantee the more restrictive alignment contraint).  But
	 * be guaranteeing the zero-based IB virtual address for the queue, we
	 * are able to conserve this memory.
	 *
	 * Note: If SRQ is not user-mappable, then it may come from either
	 * kernel system memory or from HCA-attached local DDR memory.
	 *
	 * Note2: We align this queue on a pagesize boundary.  This is required
	 * to make sure that all the resulting IB addresses will start at 0, for
	 * a zero-based queue.  By making sure we are aligned on at least a
	 * page, any offset we use into our queue will be the same as when we
	 * perform hermon_srq_modify() operations later.
	 */
	wqesz = (1 << srq->srq_wq_log_wqesz);
	srq->srq_wqinfo.qa_size = (1 << log_srq_size) * wqesz;
	srq->srq_wqinfo.qa_alloc_align = PAGESIZE;
	srq->srq_wqinfo.qa_bind_align = PAGESIZE;
	if (srq_is_umap) {
		srq->srq_wqinfo.qa_location = HERMON_QUEUE_LOCATION_USERLAND;
	} else {
		srq->srq_wqinfo.qa_location = HERMON_QUEUE_LOCATION_NORMAL;
	}
	status = hermon_queue_alloc(state, &srq->srq_wqinfo, sleepflag);
	if (status != DDI_SUCCESS) {
		status = IBT_INSUFF_RESOURCE;
		goto srqalloc_fail4a;
	}
	buf = (uint32_t *)srq->srq_wqinfo.qa_buf_aligned;
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*buf))

	/*
	 * Register the memory for the SRQ work queues.  The memory for the SRQ
	 * must be registered in the Hermon cMPT tables.  This gives us the LKey
	 * to specify in the SRQ context later.  Note: If the work queue is to
	 * be allocated from DDR memory, then only a "bypass" mapping is
	 * appropriate.  And if the SRQ memory is user-mappable, then we force
	 * DDI_DMA_CONSISTENT mapping.  Also, in order to meet the alignment
	 * restriction, we pass the "mro_bind_override_addr" flag in the call
	 * to hermon_mr_register().  This guarantees that the resulting IB vaddr
	 * will be zero-based (modulo the offset into the first page).  If we
	 * fail here, we still have the bunch of resource and reference count
	 * cleanup to do.
	 */
	flag = (sleepflag == HERMON_SLEEP) ? IBT_MR_SLEEP :
	    IBT_MR_NOSLEEP;
	mr_attr.mr_vaddr = (uint64_t)(uintptr_t)buf;
	mr_attr.mr_len   = srq->srq_wqinfo.qa_size;
	mr_attr.mr_as    = NULL;
	mr_attr.mr_flags = flag | IBT_MR_ENABLE_LOCAL_WRITE;
	mr_op.mro_bind_type   = state->hs_cfg_profile->cp_iommu_bypass;
	mr_op.mro_bind_dmahdl = srq->srq_wqinfo.qa_dmahdl;
	mr_op.mro_bind_override_addr = 1;
	status = hermon_mr_register(state, pd, &mr_attr, &mr,
	    &mr_op, HERMON_SRQ_CMPT);
	if (status != DDI_SUCCESS) {
		status = IBT_INSUFF_RESOURCE;
		goto srqalloc_fail5;
	}
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*mr))

	/*
	 * Calculate the offset between the kernel virtual address space
	 * and the IB virtual address space.  This will be used when
	 * posting work requests to properly initialize each WQE.
	 */
	srq_desc_off = (uint64_t)(uintptr_t)srq->srq_wqinfo.qa_buf_aligned -
	    (uint64_t)mr->mr_bindinfo.bi_addr;

	srq->srq_wq_wqhdr = hermon_wrid_wqhdr_create(1 << log_srq_size);

	/*
	 * Fill in all the return arguments (if necessary).  This includes
	 * real queue size and real SGLs.
	 */
	if (real_sizes != NULL) {
		real_sizes->srq_wr_sz = (1 << log_srq_size) - 1;
		real_sizes->srq_sgl_sz = srq->srq_wq_sgl;
	}

	/*
	 * Fill in the SRQC entry.  This is the final step before passing
	 * ownership of the SRQC entry to the Hermon hardware.  We use all of
	 * the information collected/calculated above to fill in the
	 * requisite portions of the SRQC.  Note: If this SRQ is going to be
	 * used for userland access, then we need to set the UAR page number
	 * appropriately (otherwise it's a "don't care")
	 */
	bzero(&srqc_entry, sizeof (hermon_hw_srqc_t));
	srqc_entry.state	   = HERMON_SRQ_STATE_HW_OWNER;
	srqc_entry.log_srq_size	   = log_srq_size;
	srqc_entry.srqn		   = srq->srq_srqnum;
	srqc_entry.log_rq_stride   = srq->srq_wq_log_wqesz - 4;
					/* 16-byte chunks */

	srqc_entry.page_offs	   = srq->srq_wqinfo.qa_pgoffs >> 6;
	srqc_entry.log2_pgsz	   = mr->mr_log2_pgsz;
	srqc_entry.mtt_base_addrh  = (uint32_t)((mr->mr_mttaddr >> 32) & 0xFF);
	srqc_entry.mtt_base_addrl  = mr->mr_mttaddr >> 3;
	srqc_entry.pd		   = pd->pd_pdnum;
	srqc_entry.dbr_addrh = (uint32_t)((uint64_t)srq->srq_wq_pdbr >> 32);
	srqc_entry.dbr_addrl = (uint32_t)((uint64_t)srq->srq_wq_pdbr >> 2);

	/*
	 * all others - specifically, xrcd, cqn_xrc, lwm, wqe_cnt, and wqe_cntr
	 * are zero thanks to the bzero of the structure
	 */

	/*
	 * Write the SRQC entry to hardware.  Lastly, we pass ownership of
	 * the entry to the hardware (using the Hermon SW2HW_SRQ firmware
	 * command).  Note: In general, this operation shouldn't fail.  But
	 * if it does, we have to undo everything we've done above before
	 * returning error.
	 */
	status = hermon_cmn_ownership_cmd_post(state, SW2HW_SRQ, &srqc_entry,
	    sizeof (hermon_hw_srqc_t), srq->srq_srqnum,
	    sleepflag);
	if (status != HERMON_CMD_SUCCESS) {
		cmn_err(CE_CONT, "Hermon: SW2HW_SRQ command failed: %08x\n",
		    status);
		if (status == HERMON_CMD_INVALID_STATUS) {
			hermon_fm_ereport(state, HCA_SYS_ERR, HCA_ERR_SRV_LOST);
		}
		status = ibc_get_ci_failure(0);
		goto srqalloc_fail8;
	}

	/*
	 * Fill in the rest of the Hermon SRQ handle.  We can update
	 * the following fields for use in further operations on the SRQ.
	 */
	srq->srq_srqcrsrcp = srqc;
	srq->srq_rsrcp	   = rsrc;
	srq->srq_mrhdl	   = mr;
	srq->srq_refcnt	   = 0;
	srq->srq_is_umap   = srq_is_umap;
	srq->srq_uarpg	   = uarpg;
	srq->srq_umap_dhp  = (devmap_cookie_t)NULL;
	srq->srq_pdhdl	   = pd;
	srq->srq_wq_bufsz  = (1 << log_srq_size);
	srq->srq_wq_buf	   = buf;
	srq->srq_desc_off  = srq_desc_off;
	srq->srq_hdlrarg   = (void *)ibt_srqhdl;
	srq->srq_state	   = 0;
	srq->srq_real_sizes.srq_wr_sz = (1 << log_srq_size);
	srq->srq_real_sizes.srq_sgl_sz = srq->srq_wq_sgl;

	/*
	 * Put SRQ handle in Hermon SRQNum-to-SRQhdl list.  Then fill in the
	 * "srqhdl" and return success
	 */
	hermon_icm_set_num_to_hdl(state, HERMON_SRQC, srqc->hr_indx, srq);

	/*
	 * If this is a user-mappable SRQ, then we need to insert the
	 * previously allocated entry into the "userland resources database".
	 * This will allow for later lookup during devmap() (i.e. mmap())
	 * calls.
	 */
	if (srq->srq_is_umap) {
		hermon_umap_db_add(umapdb);
	} else {	/* initialize work queue for kernel SRQs */
		int i, len, last;
		uint16_t *desc;

		desc = (uint16_t *)buf;
		len = wqesz / sizeof (*desc);
		last = srq->srq_wq_bufsz - 1;
		for (i = 0; i < last; i++) {
			desc[1] = htons(i + 1);
			desc += len;
		}
		srq->srq_wq_wqhdr->wq_tail = last;
		srq->srq_wq_wqhdr->wq_head = 0;
	}

	*srqhdl = srq;

	return (status);

/*
 * The following is cleanup for all possible failure cases in this routine
 */
srqalloc_fail8:
	hermon_wrid_wqhdr_destroy(srq->srq_wq_wqhdr);
srqalloc_fail7:
	if (hermon_mr_deregister(state, &mr, HERMON_MR_DEREG_ALL,
	    HERMON_SLEEPFLAG_FOR_CONTEXT()) != DDI_SUCCESS) {
		HERMON_WARNING(state, "failed to deregister SRQ memory");
	}
srqalloc_fail5:
	hermon_queue_free(&srq->srq_wqinfo);
srqalloc_fail4a:
	hermon_dbr_free(state, uarpg, srq->srq_wq_vdbr);
srqalloc_fail4:
	if (srq_is_umap) {
		hermon_umap_db_free(umapdb);
	}
srqalloc_fail3:
	hermon_rsrc_free(state, &rsrc);
srqalloc_fail2:
	hermon_rsrc_free(state, &srqc);
srqalloc_fail1:
	hermon_pd_refcnt_dec(pd);
srqalloc_fail:
	return (status);
}


/*
 * hermon_srq_free()
 *    Context: Can be called only from user or kernel context.
 */
/* ARGSUSED */
int
hermon_srq_free(hermon_state_t *state, hermon_srqhdl_t *srqhdl,
    uint_t sleepflag)
{
	hermon_rsrc_t		*srqc, *rsrc;
	hermon_umap_db_entry_t	*umapdb;
	uint64_t		value;
	hermon_srqhdl_t		srq;
	hermon_mrhdl_t		mr;
	hermon_pdhdl_t		pd;
	hermon_hw_srqc_t	srqc_entry;
	uint32_t		srqnum;
	uint_t			maxprot;
	int			status;

	/*
	 * Pull all the necessary information from the Hermon Shared Receive
	 * Queue handle.  This is necessary here because the resource for the
	 * SRQ handle is going to be freed up as part of this operation.
	 */
	srq	= *srqhdl;
	mutex_enter(&srq->srq_lock);
	srqc	= srq->srq_srqcrsrcp;
	rsrc	= srq->srq_rsrcp;
	pd	= srq->srq_pdhdl;
	mr	= srq->srq_mrhdl;
	srqnum	= srq->srq_srqnum;

	/*
	 * If there are work queues still associated with the SRQ, then return
	 * an error.  Otherwise, we will be holding the SRQ lock.
	 */
	if (srq->srq_refcnt != 0) {
		mutex_exit(&srq->srq_lock);
		return (IBT_SRQ_IN_USE);
	}

	/*
	 * If this was a user-mappable SRQ, then we need to remove its entry
	 * from the "userland resources database".  If it is also currently
	 * mmap()'d out to a user process, then we need to call
	 * devmap_devmem_remap() to remap the SRQ memory to an invalid mapping.
	 * We also need to invalidate the SRQ tracking information for the
	 * user mapping.
	 */
	if (srq->srq_is_umap) {
		status = hermon_umap_db_find(state->hs_instance,
		    srq->srq_srqnum, MLNX_UMAP_SRQMEM_RSRC, &value,
		    HERMON_UMAP_DB_REMOVE, &umapdb);
		if (status != DDI_SUCCESS) {
			mutex_exit(&srq->srq_lock);
			HERMON_WARNING(state, "failed to find in database");
			return (ibc_get_ci_failure(0));
		}
		hermon_umap_db_free(umapdb);
		if (srq->srq_umap_dhp != NULL) {
			maxprot = (PROT_READ | PROT_WRITE | PROT_USER);
			status = devmap_devmem_remap(srq->srq_umap_dhp,
			    state->hs_dip, 0, 0, srq->srq_wqinfo.qa_size,
			    maxprot, DEVMAP_MAPPING_INVALID, NULL);
			if (status != DDI_SUCCESS) {
				mutex_exit(&srq->srq_lock);
				HERMON_WARNING(state, "failed in SRQ memory "
				    "devmap_devmem_remap()");
				return (ibc_get_ci_failure(0));
			}
			srq->srq_umap_dhp = (devmap_cookie_t)NULL;
		}
	}

	/*
	 * Put NULL into the Hermon SRQNum-to-SRQHdl list.  This will allow any
	 * in-progress events to detect that the SRQ corresponding to this
	 * number has been freed.
	 */
	hermon_icm_set_num_to_hdl(state, HERMON_SRQC, srqc->hr_indx, NULL);

	mutex_exit(&srq->srq_lock);
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*srq));

	/*
	 * Reclaim SRQC entry from hardware (using the Hermon HW2SW_SRQ
	 * firmware command).  If the ownership transfer fails for any reason,
	 * then it is an indication that something (either in HW or SW) has
	 * gone seriously wrong.
	 */
	status = hermon_cmn_ownership_cmd_post(state, HW2SW_SRQ, &srqc_entry,
	    sizeof (hermon_hw_srqc_t), srqnum, sleepflag);
	if (status != HERMON_CMD_SUCCESS) {
		HERMON_WARNING(state, "failed to reclaim SRQC ownership");
		cmn_err(CE_CONT, "Hermon: HW2SW_SRQ command failed: %08x\n",
		    status);
		if (status == HERMON_CMD_INVALID_STATUS) {
			hermon_fm_ereport(state, HCA_SYS_ERR, HCA_ERR_SRV_LOST);
		}
		return (ibc_get_ci_failure(0));
	}

	/*
	 * Deregister the memory for the Shared Receive Queue.  If this fails
	 * for any reason, then it is an indication that something (either
	 * in HW or SW) has gone seriously wrong.  So we print a warning
	 * message and return.
	 */
	status = hermon_mr_deregister(state, &mr, HERMON_MR_DEREG_ALL,
	    sleepflag);
	if (status != DDI_SUCCESS) {
		HERMON_WARNING(state, "failed to deregister SRQ memory");
		return (IBT_FAILURE);
	}

	hermon_wrid_wqhdr_destroy(srq->srq_wq_wqhdr);

	/* Free the memory for the SRQ */
	hermon_queue_free(&srq->srq_wqinfo);

	/* Free the dbr */
	hermon_dbr_free(state, srq->srq_uarpg, srq->srq_wq_vdbr);

	/* Free the Hermon SRQ Handle */
	hermon_rsrc_free(state, &rsrc);

	/* Free the SRQC entry resource */
	hermon_rsrc_free(state, &srqc);

	/* Decrement the reference count on the protection domain (PD) */
	hermon_pd_refcnt_dec(pd);

	/* Set the srqhdl pointer to NULL and return success */
	*srqhdl = NULL;

	return (DDI_SUCCESS);
}


/*
 * hermon_srq_modify()
 *    Context: Can be called only from user or kernel context.
 */
int
hermon_srq_modify(hermon_state_t *state, hermon_srqhdl_t srq, uint_t size,
    uint_t *real_size, uint_t sleepflag)
{
	hermon_qalloc_info_t	new_srqinfo, old_srqinfo;
	hermon_rsrc_t		*mtt, *old_mtt;
	hermon_bind_info_t	bind;
	hermon_bind_info_t	old_bind;
	hermon_mrhdl_t		mr;
	hermon_hw_srqc_t	srqc_entry;
	hermon_hw_dmpt_t	mpt_entry;
	uint64_t		*wre_new, *wre_old;
	uint64_t		mtt_addr;
	uint64_t		srq_pgoffs;
	uint64_t		srq_desc_off;
	uint32_t		*buf, srq_old_bufsz;
	uint32_t		wqesz;
	uint_t			max_srq_size;
	uint_t			mtt_pgsize_bits;
	uint_t			log_srq_size, maxprot;
	int			status;

	if ((state->hs_devlim.mod_wr_srq == 0) ||
	    (state->hs_cfg_profile->cp_srq_resize_enabled == 0))
		return (IBT_NOT_SUPPORTED);

	/*
	 * If size requested is larger than device capability, return
	 * Insufficient Resources
	 */
	max_srq_size = (1 << state->hs_cfg_profile->cp_log_max_srq_sz);
	if (size > max_srq_size) {
		return (IBT_HCA_WR_EXCEEDED);
	}

	/*
	 * Calculate the appropriate size for the SRQ.
	 * Note:  All Hermon SRQs must be a power-of-2 in size.  Also
	 * they may not be any smaller than HERMON_SRQ_MIN_SIZE.  This step
	 * is to round the requested size up to the next highest power-of-2
	 */
	size = max(size, HERMON_SRQ_MIN_SIZE);
	log_srq_size = highbit(size);
	if (ISP2(size)) {
		log_srq_size = log_srq_size - 1;
	}

	/*
	 * Next we verify that the rounded-up size is valid (i.e. consistent
	 * with the device limits and/or software-configured limits).
	 */
	if (log_srq_size > state->hs_cfg_profile->cp_log_max_srq_sz) {
		status = IBT_HCA_WR_EXCEEDED;
		goto srqmodify_fail;
	}

	/*
	 * Allocate the memory for newly resized Shared Receive Queue.
	 *
	 * Note: If SRQ is not user-mappable, then it may come from either
	 * kernel system memory or from HCA-attached local DDR memory.
	 *
	 * Note2: We align this queue on a pagesize boundary.  This is required
	 * to make sure that all the resulting IB addresses will start at 0,
	 * for a zero-based queue.  By making sure we are aligned on at least a
	 * page, any offset we use into our queue will be the same as it was
	 * when we allocated it at hermon_srq_alloc() time.
	 */
	wqesz = (1 << srq->srq_wq_log_wqesz);
	new_srqinfo.qa_size = (1 << log_srq_size) * wqesz;
	new_srqinfo.qa_alloc_align = PAGESIZE;
	new_srqinfo.qa_bind_align  = PAGESIZE;
	if (srq->srq_is_umap) {
		new_srqinfo.qa_location = HERMON_QUEUE_LOCATION_USERLAND;
	} else {
		new_srqinfo.qa_location = HERMON_QUEUE_LOCATION_NORMAL;
	}
	status = hermon_queue_alloc(state, &new_srqinfo, sleepflag);
	if (status != DDI_SUCCESS) {
		status = IBT_INSUFF_RESOURCE;
		goto srqmodify_fail;
	}
	buf = (uint32_t *)new_srqinfo.qa_buf_aligned;
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*buf))

	/*
	 * Allocate the memory for the new WRE list.  This will be used later
	 * when we resize the wridlist based on the new SRQ size.
	 */
	wre_new = kmem_zalloc((1 << log_srq_size) * sizeof (uint64_t),
	    sleepflag);
	if (wre_new == NULL) {
		status = IBT_INSUFF_RESOURCE;
		goto srqmodify_fail;
	}

	/*
	 * Fill in the "bind" struct.  This struct provides the majority
	 * of the information that will be used to distinguish between an
	 * "addr" binding (as is the case here) and a "buf" binding (see
	 * below).  The "bind" struct is later passed to hermon_mr_mem_bind()
	 * which does most of the "heavy lifting" for the Hermon memory
	 * registration routines.
	 */
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(bind))
	bzero(&bind, sizeof (hermon_bind_info_t));
	bind.bi_type  = HERMON_BINDHDL_VADDR;
	bind.bi_addr  = (uint64_t)(uintptr_t)buf;
	bind.bi_len   = new_srqinfo.qa_size;
	bind.bi_as    = NULL;
	bind.bi_flags = sleepflag == HERMON_SLEEP ? IBT_MR_SLEEP :
	    IBT_MR_NOSLEEP | IBT_MR_ENABLE_LOCAL_WRITE;
	bind.bi_bypass = state->hs_cfg_profile->cp_iommu_bypass;

	status = hermon_mr_mtt_bind(state, &bind, new_srqinfo.qa_dmahdl, &mtt,
	    &mtt_pgsize_bits, 0); /* no relaxed ordering */
	if (status != DDI_SUCCESS) {
		status = status;
		kmem_free(wre_new, (1 << log_srq_size) *
		    sizeof (uint64_t));
		hermon_queue_free(&new_srqinfo);
		goto srqmodify_fail;
	}

	/*
	 * Calculate the offset between the kernel virtual address space
	 * and the IB virtual address space.  This will be used when
	 * posting work requests to properly initialize each WQE.
	 *
	 * Note: bind addr is zero-based (from alloc) so we calculate the
	 * correct new offset here.
	 */
	bind.bi_addr = bind.bi_addr & ((1 << mtt_pgsize_bits) - 1);
	srq_desc_off = (uint64_t)(uintptr_t)new_srqinfo.qa_buf_aligned -
	    (uint64_t)bind.bi_addr;
	srq_pgoffs   = (uint_t)
	    ((uintptr_t)new_srqinfo.qa_buf_aligned & HERMON_PAGEOFFSET);

	/*
	 * Fill in the MPT entry.  This is the final step before passing
	 * ownership of the MPT entry to the Hermon hardware.  We use all of
	 * the information collected/calculated above to fill in the
	 * requisite portions of the MPT.
	 */
	bzero(&mpt_entry, sizeof (hermon_hw_dmpt_t));
	mpt_entry.reg_win_len	= bind.bi_len;
	mtt_addr = (mtt->hr_indx << HERMON_MTT_SIZE_SHIFT);
	mpt_entry.mtt_addr_h = mtt_addr >> 32;
	mpt_entry.mtt_addr_l = mtt_addr >> 3;

	/*
	 * for hermon we build up a new srqc and pass that (partially filled
	 * to resize SRQ instead of modifying the (d)mpt directly
	 */



	/*
	 * Now we grab the SRQ lock.  Since we will be updating the actual
	 * SRQ location and the producer/consumer indexes, we should hold
	 * the lock.
	 *
	 * We do a HERMON_NOSLEEP here (and below), though, because we are
	 * holding the "srq_lock" and if we got raised to interrupt level
	 * by priority inversion, we would not want to block in this routine
	 * waiting for success.
	 */
	mutex_enter(&srq->srq_lock);

	/*
	 * Copy old entries to new buffer
	 */
	srq_old_bufsz = srq->srq_wq_bufsz;
	bcopy(srq->srq_wq_buf, buf, srq_old_bufsz * wqesz);

	/*
	 * Setup MPT information for use in the MODIFY_MPT command
	 */
	mr = srq->srq_mrhdl;
	mutex_enter(&mr->mr_lock);

	/*
	 * now, setup the srqc information needed for resize - limit the
	 * values, but use the same structure as the srqc
	 */

	srqc_entry.log_srq_size	  = log_srq_size;
	srqc_entry.page_offs	  = srq_pgoffs >> 6;
	srqc_entry.log2_pgsz	  = mr->mr_log2_pgsz;
	srqc_entry.mtt_base_addrl = (uint64_t)mtt_addr >> 32;
	srqc_entry.mtt_base_addrh = mtt_addr >> 3;

	/*
	 * RESIZE_SRQ
	 *
	 * If this fails for any reason, then it is an indication that
	 * something (either in HW or SW) has gone seriously wrong.  So we
	 * print a warning message and return.
	 */
	status = hermon_resize_srq_cmd_post(state, &srqc_entry,
	    srq->srq_srqnum, sleepflag);
	if (status != HERMON_CMD_SUCCESS) {
		cmn_err(CE_CONT, "Hermon: RESIZE_SRQ command failed: %08x\n",
		    status);
		if (status == HERMON_CMD_INVALID_STATUS) {
			hermon_fm_ereport(state, HCA_SYS_ERR, HCA_ERR_SRV_LOST);
		}
		(void) hermon_mr_mtt_unbind(state, &bind, mtt);
		kmem_free(wre_new, (1 << log_srq_size) *
		    sizeof (uint64_t));
		hermon_queue_free(&new_srqinfo);
		mutex_exit(&mr->mr_lock);
		mutex_exit(&srq->srq_lock);
		return (ibc_get_ci_failure(0));
	}
	/*
	 * Update the Hermon Shared Receive Queue handle with all the new
	 * information.  At the same time, save away all the necessary
	 * information for freeing up the old resources
	 */
	old_srqinfo	   = srq->srq_wqinfo;
	old_mtt		   = srq->srq_mrhdl->mr_mttrsrcp;
	bcopy(&srq->srq_mrhdl->mr_bindinfo, &old_bind,
	    sizeof (hermon_bind_info_t));

	/* Now set the new info */
	srq->srq_wqinfo	   = new_srqinfo;
	srq->srq_wq_buf	   = buf;
	srq->srq_wq_bufsz  = (1 << log_srq_size);
	bcopy(&bind, &srq->srq_mrhdl->mr_bindinfo, sizeof (hermon_bind_info_t));
	srq->srq_mrhdl->mr_mttrsrcp = mtt;
	srq->srq_desc_off  = srq_desc_off;
	srq->srq_real_sizes.srq_wr_sz = (1 << log_srq_size);

	/* Update MR mtt pagesize */
	mr->mr_logmttpgsz = mtt_pgsize_bits;
	mutex_exit(&mr->mr_lock);

	/*
	 * Initialize new wridlist, if needed.
	 *
	 * If a wridlist already is setup on an SRQ (the QP associated with an
	 * SRQ has moved "from_reset") then we must update this wridlist based
	 * on the new SRQ size.  We allocate the new size of Work Request ID
	 * Entries, copy over the old entries to the new list, and
	 * re-initialize the srq wridlist in non-umap case
	 */
	wre_old = srq->srq_wq_wqhdr->wq_wrid;

	bcopy(wre_old, wre_new, srq_old_bufsz * sizeof (uint64_t));

	/* Setup new sizes in wre */
	srq->srq_wq_wqhdr->wq_wrid = wre_new;

	/*
	 * If "old" SRQ was a user-mappable SRQ that is currently mmap()'d out
	 * to a user process, then we need to call devmap_devmem_remap() to
	 * invalidate the mapping to the SRQ memory.  We also need to
	 * invalidate the SRQ tracking information for the user mapping.
	 *
	 * Note: On failure, the remap really shouldn't ever happen.  So, if it
	 * does, it is an indication that something has gone seriously wrong.
	 * So we print a warning message and return error (knowing, of course,
	 * that the "old" SRQ memory will be leaked)
	 */
	if ((srq->srq_is_umap) && (srq->srq_umap_dhp != NULL)) {
		maxprot = (PROT_READ | PROT_WRITE | PROT_USER);
		status = devmap_devmem_remap(srq->srq_umap_dhp,
		    state->hs_dip, 0, 0, srq->srq_wqinfo.qa_size, maxprot,
		    DEVMAP_MAPPING_INVALID, NULL);
		if (status != DDI_SUCCESS) {
			mutex_exit(&srq->srq_lock);
			HERMON_WARNING(state, "failed in SRQ memory "
			    "devmap_devmem_remap()");
			/* We can, however, free the memory for old wre */
			kmem_free(wre_old, srq_old_bufsz * sizeof (uint64_t));
			return (ibc_get_ci_failure(0));
		}
		srq->srq_umap_dhp = (devmap_cookie_t)NULL;
	}

	/*
	 * Drop the SRQ lock now.  The only thing left to do is to free up
	 * the old resources.
	 */
	mutex_exit(&srq->srq_lock);

	/*
	 * Unbind the MTT entries.
	 */
	status = hermon_mr_mtt_unbind(state, &old_bind, old_mtt);
	if (status != DDI_SUCCESS) {
		HERMON_WARNING(state, "failed to unbind old SRQ memory");
		status = ibc_get_ci_failure(0);
		goto srqmodify_fail;
	}

	/* Free the memory for old wre */
	kmem_free(wre_old, srq_old_bufsz * sizeof (uint64_t));

	/* Free the memory for the old SRQ */
	hermon_queue_free(&old_srqinfo);

	/*
	 * Fill in the return arguments (if necessary).  This includes the
	 * real new completion queue size.
	 */
	if (real_size != NULL) {
		*real_size = (1 << log_srq_size);
	}

	return (DDI_SUCCESS);

srqmodify_fail:
	return (status);
}


/*
 * hermon_srq_refcnt_inc()
 *    Context: Can be called from interrupt or base context.
 */
void
hermon_srq_refcnt_inc(hermon_srqhdl_t srq)
{
	mutex_enter(&srq->srq_lock);
	srq->srq_refcnt++;
	mutex_exit(&srq->srq_lock);
}


/*
 * hermon_srq_refcnt_dec()
 *    Context: Can be called from interrupt or base context.
 */
void
hermon_srq_refcnt_dec(hermon_srqhdl_t srq)
{
	mutex_enter(&srq->srq_lock);
	srq->srq_refcnt--;
	mutex_exit(&srq->srq_lock);
}


/*
 * hermon_srqhdl_from_srqnum()
 *    Context: Can be called from interrupt or base context.
 *
 *    This routine is important because changing the unconstrained
 *    portion of the SRQ number is critical to the detection of a
 *    potential race condition in the SRQ handler code (i.e. the case
 *    where a SRQ is freed and alloc'd again before an event for the
 *    "old" SRQ can be handled).
 *
 *    While this is not a perfect solution (not sure that one exists)
 *    it does help to mitigate the chance that this race condition will
 *    cause us to deliver a "stale" event to the new SRQ owner.  Note:
 *    this solution does not scale well because the number of constrained
 *    bits increases (and, hence, the number of unconstrained bits
 *    decreases) as the number of supported SRQ grows.  For small and
 *    intermediate values, it should hopefully provide sufficient
 *    protection.
 */
hermon_srqhdl_t
hermon_srqhdl_from_srqnum(hermon_state_t *state, uint_t srqnum)
{
	uint_t	srqindx, srqmask;

	/* Calculate the SRQ table index from the srqnum */
	srqmask = (1 << state->hs_cfg_profile->cp_log_num_srq) - 1;
	srqindx = srqnum & srqmask;
	return (hermon_icm_num_to_hdl(state, HERMON_SRQC, srqindx));
}


/*
 * hermon_srq_sgl_to_logwqesz()
 *    Context: Can be called from interrupt or base context.
 */
static void
hermon_srq_sgl_to_logwqesz(hermon_state_t *state, uint_t num_sgl,
    hermon_qp_wq_type_t wq_type, uint_t *logwqesz, uint_t *max_sgl)
{
	uint_t	max_size, log2, actual_sgl;

	switch (wq_type) {
	case HERMON_QP_WQ_TYPE_RECVQ:
		/*
		 * Use requested maximum SGL to calculate max descriptor size
		 * (while guaranteeing that the descriptor size is a
		 * power-of-2 cachelines).
		 */
		max_size = (HERMON_QP_WQE_MLX_SRQ_HDRS + (num_sgl << 4));
		log2 = highbit(max_size);
		if (ISP2(max_size)) {
			log2 = log2 - 1;
		}

		/* Make sure descriptor is at least the minimum size */
		log2 = max(log2, HERMON_QP_WQE_LOG_MINIMUM);

		/* Calculate actual number of SGL (given WQE size) */
		actual_sgl = ((1 << log2) - HERMON_QP_WQE_MLX_SRQ_HDRS) >> 4;
		break;

	default:
		HERMON_WARNING(state, "unexpected work queue type");
		break;
	}

	/* Fill in the return values */
	*logwqesz = log2;
	*max_sgl  = min(state->hs_cfg_profile->cp_srq_max_sgl, actual_sgl);
}
