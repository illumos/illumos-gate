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
 * tavor_srq.c
 *    Tavor Shared Receive Queue Processing Routines
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

#include <sys/ib/adapters/tavor/tavor.h>

static void tavor_srq_sgl_to_logwqesz(tavor_state_t *state, uint_t num_sgl,
    tavor_qp_wq_type_t wq_type, uint_t *logwqesz, uint_t *max_sgl);

/*
 * tavor_srq_alloc()
 *    Context: Can be called only from user or kernel context.
 */
int
tavor_srq_alloc(tavor_state_t *state, tavor_srq_info_t *srqinfo,
    uint_t sleepflag, tavor_srq_options_t *op)
{
	ibt_srq_hdl_t		ibt_srqhdl;
	tavor_pdhdl_t		pd;
	ibt_srq_sizes_t		*sizes;
	ibt_srq_sizes_t		*real_sizes;
	tavor_srqhdl_t		*srqhdl;
	ibt_srq_flags_t		flags;
	tavor_rsrc_t		*srqc, *rsrc;
	tavor_hw_srqc_t		srqc_entry;
	uint32_t		*buf;
	tavor_srqhdl_t		srq;
	tavor_umap_db_entry_t	*umapdb;
	ibt_mr_attr_t		mr_attr;
	tavor_mr_options_t	mr_op;
	tavor_mrhdl_t		mr;
	uint64_t		addr;
	uint64_t		value, srq_desc_off;
	uint32_t		lkey;
	uint32_t		log_srq_size;
	uint32_t		uarpg;
	uint_t			wq_location, dma_xfer_mode, srq_is_umap;
	int			flag, status;
	uint_t			max_sgl;
	uint_t			wqesz;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*sizes))

	/*
	 * Check the "options" flag.  Currently this flag tells the driver
	 * whether or not the SRQ's work queues should be come from normal
	 * system memory or whether they should be allocated from DDR memory.
	 */
	if (op == NULL) {
		wq_location = TAVOR_QUEUE_LOCATION_NORMAL;
	} else {
		wq_location = op->srqo_wq_loc;
	}

	/*
	 * Extract the necessary info from the tavor_srq_info_t structure
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
	 * (e.g. if the process has not previously open()'d the Tavor driver),
	 * then an error is returned.
	 */
	srq_is_umap = (flags & IBT_SRQ_USER_MAP) ? 1 : 0;
	if (srq_is_umap) {
		status = tavor_umap_db_find(state->ts_instance, ddi_get_pid(),
		    MLNX_UMAP_UARPG_RSRC, &value, 0, NULL);
		if (status != DDI_SUCCESS) {
			goto srqalloc_fail3;
		}
		uarpg = ((tavor_rsrc_t *)(uintptr_t)value)->tr_indx;
	}

	/* Increase PD refcnt */
	tavor_pd_refcnt_inc(pd);

	/* Allocate an SRQ context entry */
	status = tavor_rsrc_alloc(state, TAVOR_SRQC, 1, sleepflag, &srqc);
	if (status != DDI_SUCCESS) {
		goto srqalloc_fail1;
	}

	/* Allocate the SRQ Handle entry */
	status = tavor_rsrc_alloc(state, TAVOR_SRQHDL, 1, sleepflag, &rsrc);
	if (status != DDI_SUCCESS) {
		goto srqalloc_fail2;
	}

	srq = (tavor_srqhdl_t)rsrc->tr_addr;
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*srq))

	srq->srq_srqnum = srqc->tr_indx;	/* just use index */

	/*
	 * If this will be a user-mappable SRQ, then allocate an entry for
	 * the "userland resources database".  This will later be added to
	 * the database (after all further SRQ operations are successful).
	 * If we fail here, we must undo the reference counts and the
	 * previous resource allocation.
	 */
	if (srq_is_umap) {
		umapdb = tavor_umap_db_alloc(state->ts_instance,
		    srq->srq_srqnum, MLNX_UMAP_SRQMEM_RSRC,
		    (uint64_t)(uintptr_t)rsrc);
		if (umapdb == NULL) {
			goto srqalloc_fail3;
		}
	}

	/*
	 * Calculate the appropriate size for the SRQ.
	 * Note:  All Tavor SRQs must be a power-of-2 in size.  Also
	 * they may not be any smaller than TAVOR_SRQ_MIN_SIZE.  This step
	 * is to round the requested size up to the next highest power-of-2
	 */
	sizes->srq_wr_sz = max(sizes->srq_wr_sz, TAVOR_SRQ_MIN_SIZE);
	log_srq_size = highbit(sizes->srq_wr_sz);
	if (ISP2(sizes->srq_wr_sz)) {
		log_srq_size = log_srq_size - 1;
	}

	/*
	 * Next we verify that the rounded-up size is valid (i.e. consistent
	 * with the device limits and/or software-configured limits).  If not,
	 * then obviously we have a lot of cleanup to do before returning.
	 */
	if (log_srq_size > state->ts_cfg_profile->cp_log_max_srq_sz) {
		goto srqalloc_fail4;
	}

	/*
	 * Next we verify that the requested number of SGL is valid (i.e.
	 * consistent with the device limits and/or software-configured
	 * limits).  If not, then obviously the same cleanup needs to be done.
	 */
	max_sgl = state->ts_cfg_profile->cp_srq_max_sgl;
	if (sizes->srq_sgl_sz > max_sgl) {
		goto srqalloc_fail4;
	}

	/*
	 * Determine the SRQ's WQE sizes.  This depends on the requested
	 * number of SGLs.  Note: This also has the side-effect of
	 * calculating the real number of SGLs (for the calculated WQE size)
	 */
	tavor_srq_sgl_to_logwqesz(state, sizes->srq_sgl_sz,
	    TAVOR_QP_WQ_TYPE_RECVQ, &srq->srq_wq_log_wqesz,
	    &srq->srq_wq_sgl);

	/*
	 * Allocate the memory for SRQ work queues.  Note:  The location from
	 * which we will allocate these work queues has been passed in through
	 * the tavor_qp_options_t structure.  Since Tavor work queues are not
	 * allowed to cross a 32-bit (4GB) boundary, the alignment of the work
	 * queue memory is very important.  We used to allocate work queues
	 * (the combined receive and send queues) so that they would be aligned
	 * on their combined size.  That alignment guaranteed that they would
	 * never cross the 4GB boundary (Tavor work queues are on the order of
	 * MBs at maximum).  Now we are able to relax this alignment constraint
	 * by ensuring that the IB address assigned to the queue memory (as a
	 * result of the tavor_mr_register() call) is offset from zero.
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
	 * perform tavor_srq_modify() operations later.
	 */
	wqesz = (1 << srq->srq_wq_log_wqesz);
	srq->srq_wqinfo.qa_size = (1 << log_srq_size) * wqesz;
	srq->srq_wqinfo.qa_alloc_align = PAGESIZE;
	srq->srq_wqinfo.qa_bind_align = PAGESIZE;
	if (srq_is_umap) {
		srq->srq_wqinfo.qa_location = TAVOR_QUEUE_LOCATION_USERLAND;
	} else {
		srq->srq_wqinfo.qa_location = wq_location;
	}
	status = tavor_queue_alloc(state, &srq->srq_wqinfo, sleepflag);
	if (status != DDI_SUCCESS) {
		goto srqalloc_fail4;
	}
	buf = (uint32_t *)srq->srq_wqinfo.qa_buf_aligned;
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*buf))

	/*
	 * Register the memory for the SRQ work queues.  The memory for the SRQ
	 * must be registered in the Tavor TPT tables.  This gives us the LKey
	 * to specify in the SRQ context later.  Note: If the work queue is to
	 * be allocated from DDR memory, then only a "bypass" mapping is
	 * appropriate.  And if the SRQ memory is user-mappable, then we force
	 * DDI_DMA_CONSISTENT mapping.  Also, in order to meet the alignment
	 * restriction, we pass the "mro_bind_override_addr" flag in the call
	 * to tavor_mr_register().  This guarantees that the resulting IB vaddr
	 * will be zero-based (modulo the offset into the first page).  If we
	 * fail here, we still have the bunch of resource and reference count
	 * cleanup to do.
	 */
	flag = (sleepflag == TAVOR_SLEEP) ? IBT_MR_SLEEP :
	    IBT_MR_NOSLEEP;
	mr_attr.mr_vaddr = (uint64_t)(uintptr_t)buf;
	mr_attr.mr_len   = srq->srq_wqinfo.qa_size;
	mr_attr.mr_as    = NULL;
	mr_attr.mr_flags = flag | IBT_MR_ENABLE_LOCAL_WRITE;
	if (srq_is_umap) {
		mr_op.mro_bind_type   = state->ts_cfg_profile->cp_iommu_bypass;
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
	mr_op.mro_bind_dmahdl = srq->srq_wqinfo.qa_dmahdl;
	mr_op.mro_bind_override_addr = 1;
	status = tavor_mr_register(state, pd, &mr_attr, &mr, &mr_op);
	if (status != DDI_SUCCESS) {
		goto srqalloc_fail5;
	}
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*mr))
	addr = mr->mr_bindinfo.bi_addr;
	lkey = mr->mr_lkey;

	/*
	 * Calculate the offset between the kernel virtual address space
	 * and the IB virtual address space.  This will be used when
	 * posting work requests to properly initialize each WQE.
	 */
	srq_desc_off = (uint64_t)(uintptr_t)srq->srq_wqinfo.qa_buf_aligned -
	    (uint64_t)mr->mr_bindinfo.bi_addr;

	/*
	 * Create WQL and Wridlist for use by this SRQ
	 */
	srq->srq_wrid_wql = tavor_wrid_wql_create(state);
	if (srq->srq_wrid_wql == NULL) {
		goto srqalloc_fail6;
	}
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*(srq->srq_wrid_wql)))

	srq->srq_wridlist = tavor_wrid_get_list(1 << log_srq_size);
	if (srq->srq_wridlist == NULL) {
		goto srqalloc_fail7;
	}
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*(srq->srq_wridlist)))

	srq->srq_wridlist->wl_srq_en = 1;
	srq->srq_wridlist->wl_free_list_indx = -1;

	/*
	 * Fill in all the return arguments (if necessary).  This includes
	 * real queue size and real SGLs.
	 */
	if (real_sizes != NULL) {
		real_sizes->srq_wr_sz = (1 << log_srq_size);
		real_sizes->srq_sgl_sz = srq->srq_wq_sgl;
	}

	/*
	 * Fill in the SRQC entry.  This is the final step before passing
	 * ownership of the SRQC entry to the Tavor hardware.  We use all of
	 * the information collected/calculated above to fill in the
	 * requisite portions of the SRQC.  Note: If this SRQ is going to be
	 * used for userland access, then we need to set the UAR page number
	 * appropriately (otherwise it's a "don't care")
	 */
	bzero(&srqc_entry, sizeof (tavor_hw_srqc_t));
	srqc_entry.wqe_addr_h	   = (addr >> 32);
	srqc_entry.next_wqe_addr_l = 0;
	srqc_entry.ds		   = (wqesz >> 4);
	srqc_entry.state	   = TAVOR_SRQ_STATE_HW_OWNER;
	srqc_entry.pd		   = pd->pd_pdnum;
	srqc_entry.lkey		   = lkey;
	srqc_entry.wqe_cnt	   = 0;
	if (srq_is_umap) {
		srqc_entry.uar	   = uarpg;
	} else {
		srqc_entry.uar	   = 0;
	}

	/*
	 * Write the SRQC entry to hardware.  Lastly, we pass ownership of
	 * the entry to the hardware (using the Tavor SW2HW_SRQ firmware
	 * command).  Note: In general, this operation shouldn't fail.  But
	 * if it does, we have to undo everything we've done above before
	 * returning error.
	 */
	status = tavor_cmn_ownership_cmd_post(state, SW2HW_SRQ, &srqc_entry,
	    sizeof (tavor_hw_srqc_t), srq->srq_srqnum,
	    sleepflag);
	if (status != TAVOR_CMD_SUCCESS) {
		cmn_err(CE_CONT, "Tavor: SW2HW_SRQ command failed: %08x\n",
		    status);
		goto srqalloc_fail8;
	}

	/*
	 * Fill in the rest of the Tavor SRQ handle.  We can update
	 * the following fields for use in further operations on the SRQ.
	 */
	srq->srq_srqcrsrcp = srqc;
	srq->srq_rsrcp	   = rsrc;
	srq->srq_mrhdl	   = mr;
	srq->srq_refcnt	   = 0;
	srq->srq_is_umap   = srq_is_umap;
	srq->srq_uarpg	   = (srq->srq_is_umap) ? uarpg : 0;
	srq->srq_umap_dhp  = (devmap_cookie_t)NULL;
	srq->srq_pdhdl	   = pd;
	srq->srq_wq_lastwqeindx = -1;
	srq->srq_wq_bufsz  = (1 << log_srq_size);
	srq->srq_wq_buf	   = buf;
	srq->srq_desc_off  = srq_desc_off;
	srq->srq_hdlrarg   = (void *)ibt_srqhdl;
	srq->srq_state	   = 0;
	srq->srq_real_sizes.srq_wr_sz = (1 << log_srq_size);
	srq->srq_real_sizes.srq_sgl_sz = srq->srq_wq_sgl;

	/* Determine if later ddi_dma_sync will be necessary */
	srq->srq_sync = TAVOR_SRQ_IS_SYNC_REQ(state, srq->srq_wqinfo);

	/*
	 * Put SRQ handle in Tavor SRQNum-to-SRQhdl list.  Then fill in the
	 * "srqhdl" and return success
	 */
	ASSERT(state->ts_srqhdl[srqc->tr_indx] == NULL);
	state->ts_srqhdl[srqc->tr_indx] = srq;

	/*
	 * If this is a user-mappable SRQ, then we need to insert the
	 * previously allocated entry into the "userland resources database".
	 * This will allow for later lookup during devmap() (i.e. mmap())
	 * calls.
	 */
	if (srq->srq_is_umap) {
		tavor_umap_db_add(umapdb);
	} else {
		mutex_enter(&srq->srq_wrid_wql->wql_lock);
		tavor_wrid_list_srq_init(srq->srq_wridlist, srq, 0);
		mutex_exit(&srq->srq_wrid_wql->wql_lock);
	}

	*srqhdl = srq;

	return (status);

/*
 * The following is cleanup for all possible failure cases in this routine
 */
srqalloc_fail8:
	kmem_free(srq->srq_wridlist->wl_wre, srq->srq_wridlist->wl_size *
	    sizeof (tavor_wrid_entry_t));
	kmem_free(srq->srq_wridlist, sizeof (tavor_wrid_list_hdr_t));
srqalloc_fail7:
	tavor_wql_refcnt_dec(srq->srq_wrid_wql);
srqalloc_fail6:
	if (tavor_mr_deregister(state, &mr, TAVOR_MR_DEREG_ALL,
	    TAVOR_SLEEPFLAG_FOR_CONTEXT()) != DDI_SUCCESS) {
		TAVOR_WARNING(state, "failed to deregister SRQ memory");
	}
srqalloc_fail5:
	tavor_queue_free(state, &srq->srq_wqinfo);
srqalloc_fail4:
	if (srq_is_umap) {
		tavor_umap_db_free(umapdb);
	}
srqalloc_fail3:
	tavor_rsrc_free(state, &rsrc);
srqalloc_fail2:
	tavor_rsrc_free(state, &srqc);
srqalloc_fail1:
	tavor_pd_refcnt_dec(pd);
srqalloc_fail:
	return (status);
}


/*
 * tavor_srq_free()
 *    Context: Can be called only from user or kernel context.
 */
/* ARGSUSED */
int
tavor_srq_free(tavor_state_t *state, tavor_srqhdl_t *srqhdl, uint_t sleepflag)
{
	tavor_rsrc_t		*srqc, *rsrc;
	tavor_umap_db_entry_t	*umapdb;
	uint64_t		value;
	tavor_srqhdl_t		srq;
	tavor_mrhdl_t		mr;
	tavor_pdhdl_t		pd;
	tavor_hw_srqc_t		srqc_entry;
	uint32_t		srqnum;
	uint32_t		size;
	uint_t			maxprot;
	int			status;

	/*
	 * Pull all the necessary information from the Tavor Shared Receive
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
		status = tavor_umap_db_find(state->ts_instance, srq->srq_srqnum,
		    MLNX_UMAP_SRQMEM_RSRC, &value, TAVOR_UMAP_DB_REMOVE,
		    &umapdb);
		if (status != DDI_SUCCESS) {
			mutex_exit(&srq->srq_lock);
			TAVOR_WARNING(state, "failed to find in database");
			return (ibc_get_ci_failure(0));
		}
		tavor_umap_db_free(umapdb);
		if (srq->srq_umap_dhp != NULL) {
			maxprot = (PROT_READ | PROT_WRITE | PROT_USER);
			status = devmap_devmem_remap(srq->srq_umap_dhp,
			    state->ts_dip, 0, 0, srq->srq_wqinfo.qa_size,
			    maxprot, DEVMAP_MAPPING_INVALID, NULL);
			if (status != DDI_SUCCESS) {
				mutex_exit(&srq->srq_lock);
				TAVOR_WARNING(state, "failed in SRQ memory "
				    "devmap_devmem_remap()");
				return (ibc_get_ci_failure(0));
			}
			srq->srq_umap_dhp = (devmap_cookie_t)NULL;
		}
	}

	/*
	 * Put NULL into the Tavor SRQNum-to-SRQHdl list.  This will allow any
	 * in-progress events to detect that the SRQ corresponding to this
	 * number has been freed.
	 */
	state->ts_srqhdl[srqc->tr_indx] = NULL;

	mutex_exit(&srq->srq_lock);
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*srq));
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*srq->srq_wridlist));

	/*
	 * Reclaim SRQC entry from hardware (using the Tavor HW2SW_SRQ
	 * firmware command).  If the ownership transfer fails for any reason,
	 * then it is an indication that something (either in HW or SW) has
	 * gone seriously wrong.
	 */
	status = tavor_cmn_ownership_cmd_post(state, HW2SW_SRQ, &srqc_entry,
	    sizeof (tavor_hw_srqc_t), srqnum, sleepflag);
	if (status != TAVOR_CMD_SUCCESS) {
		TAVOR_WARNING(state, "failed to reclaim SRQC ownership");
		cmn_err(CE_CONT, "Tavor: HW2SW_SRQ command failed: %08x\n",
		    status);
		return (IBT_FAILURE);
	}

	/*
	 * Deregister the memory for the Shared Receive Queue.  If this fails
	 * for any reason, then it is an indication that something (either
	 * in HW or SW) has gone seriously wrong.  So we print a warning
	 * message and return.
	 */
	status = tavor_mr_deregister(state, &mr, TAVOR_MR_DEREG_ALL,
	    sleepflag);
	if (status != DDI_SUCCESS) {
		TAVOR_WARNING(state, "failed to deregister SRQ memory");
		return (IBT_FAILURE);
	}

	/* Calculate the size and free the wridlist container */
	if (srq->srq_wridlist != NULL) {
		size = (srq->srq_wridlist->wl_size *
		    sizeof (tavor_wrid_entry_t));
		kmem_free(srq->srq_wridlist->wl_wre, size);
		kmem_free(srq->srq_wridlist, sizeof (tavor_wrid_list_hdr_t));

		/*
		 * Release reference to WQL; If this is the last reference,
		 * this call also has the side effect of freeing up the
		 * 'srq_wrid_wql' memory.
		 */
		tavor_wql_refcnt_dec(srq->srq_wrid_wql);
	}

	/* Free the memory for the SRQ */
	tavor_queue_free(state, &srq->srq_wqinfo);

	/* Free the Tavor SRQ Handle */
	tavor_rsrc_free(state, &rsrc);

	/* Free the SRQC entry resource */
	tavor_rsrc_free(state, &srqc);

	/* Decrement the reference count on the protection domain (PD) */
	tavor_pd_refcnt_dec(pd);

	/* Set the srqhdl pointer to NULL and return success */
	*srqhdl = NULL;

	return (DDI_SUCCESS);
}


/*
 * tavor_srq_modify()
 *    Context: Can be called only from user or kernel context.
 */
int
tavor_srq_modify(tavor_state_t *state, tavor_srqhdl_t srq, uint_t size,
    uint_t *real_size, uint_t sleepflag)
{
	tavor_qalloc_info_t	new_srqinfo, old_srqinfo;
	tavor_rsrc_t		*mtt, *mpt, *old_mtt;
	tavor_bind_info_t	bind;
	tavor_bind_info_t	old_bind;
	tavor_rsrc_pool_info_t	*rsrc_pool;
	tavor_mrhdl_t		mr;
	tavor_hw_mpt_t		mpt_entry;
	tavor_wrid_entry_t	*wre_new, *wre_old;
	uint64_t		mtt_ddrbaseaddr, mtt_addr;
	uint64_t		srq_desc_off;
	uint32_t		*buf, srq_old_bufsz;
	uint32_t		wqesz;
	uint_t			max_srq_size;
	uint_t			dma_xfer_mode, mtt_pgsize_bits;
	uint_t			srq_sync, log_srq_size, maxprot;
	uint_t			wq_location;
	int			status;

	/*
	 * Check the "inddr" flag.  This flag tells the driver whether or not
	 * the SRQ's work queues should be come from normal system memory or
	 * whether they should be allocated from DDR memory.
	 */
	wq_location = state->ts_cfg_profile->cp_srq_wq_inddr;

	/*
	 * If size requested is larger than device capability, return
	 * Insufficient Resources
	 */
	max_srq_size = (1 << state->ts_cfg_profile->cp_log_max_srq_sz);
	if (size > max_srq_size) {
		return (IBT_HCA_WR_EXCEEDED);
	}

	/*
	 * Calculate the appropriate size for the SRQ.
	 * Note:  All Tavor SRQs must be a power-of-2 in size.  Also
	 * they may not be any smaller than TAVOR_SRQ_MIN_SIZE.  This step
	 * is to round the requested size up to the next highest power-of-2
	 */
	size = max(size, TAVOR_SRQ_MIN_SIZE);
	log_srq_size = highbit(size);
	if (ISP2(size)) {
		log_srq_size = log_srq_size - 1;
	}

	/*
	 * Next we verify that the rounded-up size is valid (i.e. consistent
	 * with the device limits and/or software-configured limits).
	 */
	if (log_srq_size > state->ts_cfg_profile->cp_log_max_srq_sz) {
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
	 * when we allocated it at tavor_srq_alloc() time.
	 */
	wqesz = (1 << srq->srq_wq_log_wqesz);
	new_srqinfo.qa_size = (1 << log_srq_size) * wqesz;
	new_srqinfo.qa_alloc_align = PAGESIZE;
	new_srqinfo.qa_bind_align  = PAGESIZE;
	if (srq->srq_is_umap) {
		new_srqinfo.qa_location = TAVOR_QUEUE_LOCATION_USERLAND;
	} else {
		new_srqinfo.qa_location = wq_location;
	}
	status = tavor_queue_alloc(state, &new_srqinfo, sleepflag);
	if (status != DDI_SUCCESS) {
		goto srqmodify_fail;
	}
	buf = (uint32_t *)new_srqinfo.qa_buf_aligned;
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*buf))

	/*
	 * Allocate the memory for the new WRE list.  This will be used later
	 * when we resize the wridlist based on the new SRQ size.
	 */
	wre_new = (tavor_wrid_entry_t *)kmem_zalloc((1 << log_srq_size) *
	    sizeof (tavor_wrid_entry_t), sleepflag);
	if (wre_new == NULL) {
		goto srqmodify_fail;
	}

	/*
	 * Fill in the "bind" struct.  This struct provides the majority
	 * of the information that will be used to distinguish between an
	 * "addr" binding (as is the case here) and a "buf" binding (see
	 * below).  The "bind" struct is later passed to tavor_mr_mem_bind()
	 * which does most of the "heavy lifting" for the Tavor memory
	 * registration routines.
	 */
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(bind))
	bzero(&bind, sizeof (tavor_bind_info_t));
	bind.bi_type  = TAVOR_BINDHDL_VADDR;
	bind.bi_addr  = (uint64_t)(uintptr_t)buf;
	bind.bi_len   = new_srqinfo.qa_size;
	bind.bi_as    = NULL;
	bind.bi_flags = sleepflag == TAVOR_SLEEP ? IBT_MR_SLEEP :
	    IBT_MR_NOSLEEP | IBT_MR_ENABLE_LOCAL_WRITE;
	if (srq->srq_is_umap) {
		bind.bi_bypass = state->ts_cfg_profile->cp_iommu_bypass;
	} else {
		if (wq_location == TAVOR_QUEUE_LOCATION_NORMAL) {
			bind.bi_bypass =
			    state->ts_cfg_profile->cp_iommu_bypass;
			dma_xfer_mode =
			    state->ts_cfg_profile->cp_streaming_consistent;
			if (dma_xfer_mode == DDI_DMA_STREAMING) {
				bind.bi_flags |= IBT_MR_NONCOHERENT;
			}
		} else {
			bind.bi_bypass = TAVOR_BINDMEM_BYPASS;
		}
	}
	status = tavor_mr_mtt_bind(state, &bind, new_srqinfo.qa_dmahdl, &mtt,
	    &mtt_pgsize_bits);
	if (status != DDI_SUCCESS) {
		kmem_free(wre_new, srq->srq_wq_bufsz *
		    sizeof (tavor_wrid_entry_t));
		tavor_queue_free(state, &new_srqinfo);
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

	/*
	 * Get the base address for the MTT table.  This will be necessary
	 * below when we are modifying the MPT entry.
	 */
	rsrc_pool = &state->ts_rsrc_hdl[TAVOR_MTT];
	mtt_ddrbaseaddr = (uint64_t)(uintptr_t)rsrc_pool->rsrc_ddr_offset;

	/*
	 * Fill in the MPT entry.  This is the final step before passing
	 * ownership of the MPT entry to the Tavor hardware.  We use all of
	 * the information collected/calculated above to fill in the
	 * requisite portions of the MPT.
	 */
	bzero(&mpt_entry, sizeof (tavor_hw_mpt_t));
	mpt_entry.reg_win_len	= bind.bi_len;
	mtt_addr = mtt_ddrbaseaddr + (mtt->tr_indx << TAVOR_MTT_SIZE_SHIFT);
	mpt_entry.mttseg_addr_h = mtt_addr >> 32;
	mpt_entry.mttseg_addr_l = mtt_addr >> 6;

	/*
	 * Now we grab the SRQ lock.  Since we will be updating the actual
	 * SRQ location and the producer/consumer indexes, we should hold
	 * the lock.
	 *
	 * We do a TAVOR_NOSLEEP here (and below), though, because we are
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

	/* Determine if later ddi_dma_sync will be necessary */
	srq_sync = TAVOR_SRQ_IS_SYNC_REQ(state, srq->srq_wqinfo);

	/* Sync entire "new" SRQ for use by hardware (if necessary) */
	if (srq_sync) {
		(void) ddi_dma_sync(bind.bi_dmahdl, 0,
		    new_srqinfo.qa_size, DDI_DMA_SYNC_FORDEV);
	}

	/*
	 * Setup MPT information for use in the MODIFY_MPT command
	 */
	mr = srq->srq_mrhdl;
	mutex_enter(&mr->mr_lock);
	mpt = srq->srq_mrhdl->mr_mptrsrcp;

	/*
	 * MODIFY_MPT
	 *
	 * If this fails for any reason, then it is an indication that
	 * something (either in HW or SW) has gone seriously wrong.  So we
	 * print a warning message and return.
	 */
	status = tavor_modify_mpt_cmd_post(state, &mpt_entry, mpt->tr_indx,
	    TAVOR_CMD_MODIFY_MPT_RESIZESRQ, sleepflag);
	if (status != TAVOR_CMD_SUCCESS) {
		cmn_err(CE_CONT, "Tavor: MODIFY_MPT command failed: %08x\n",
		    status);
		(void) tavor_mr_mtt_unbind(state, &srq->srq_mrhdl->mr_bindinfo,
		    srq->srq_mrhdl->mr_mttrsrcp);
		kmem_free(wre_new, srq->srq_wq_bufsz *
		    sizeof (tavor_wrid_entry_t));
		tavor_queue_free(state, &new_srqinfo);
		mutex_exit(&mr->mr_lock);
		mutex_exit(&srq->srq_lock);
		return (ibc_get_ci_failure(0));
	}

	/*
	 * Update the Tavor Shared Receive Queue handle with all the new
	 * information.  At the same time, save away all the necessary
	 * information for freeing up the old resources
	 */
	old_srqinfo	   = srq->srq_wqinfo;
	old_mtt		   = srq->srq_mrhdl->mr_mttrsrcp;
	bcopy(&srq->srq_mrhdl->mr_bindinfo, &old_bind,
	    sizeof (tavor_bind_info_t));

	/* Now set the new info */
	srq->srq_wqinfo	   = new_srqinfo;
	srq->srq_wq_buf	   = buf;
	srq->srq_wq_bufsz  = (1 << log_srq_size);
	bcopy(&bind, &srq->srq_mrhdl->mr_bindinfo, sizeof (tavor_bind_info_t));
	srq->srq_mrhdl->mr_mttrsrcp = mtt;
	srq->srq_desc_off  = srq_desc_off;
	srq->srq_real_sizes.srq_wr_sz = (1 << log_srq_size);

	/* Update MR mtt pagesize */
	mr->mr_logmttpgsz = mtt_pgsize_bits;
	mutex_exit(&mr->mr_lock);

#ifdef __lock_lint
	mutex_enter(&srq->srq_wrid_wql->wql_lock);
#else
	if (srq->srq_wrid_wql != NULL) {
		mutex_enter(&srq->srq_wrid_wql->wql_lock);
	}
#endif

	/*
	 * Initialize new wridlist, if needed.
	 *
	 * If a wridlist already is setup on an SRQ (the QP associated with an
	 * SRQ has moved "from_reset") then we must update this wridlist based
	 * on the new SRQ size.  We allocate the new size of Work Request ID
	 * Entries, copy over the old entries to the new list, and
	 * re-initialize the srq wridlist in non-umap case
	 */
	wre_old = NULL;
	if (srq->srq_wridlist != NULL) {
		wre_old = srq->srq_wridlist->wl_wre;

		bcopy(wre_old, wre_new, srq_old_bufsz *
		    sizeof (tavor_wrid_entry_t));

		/* Setup new sizes in wre */
		srq->srq_wridlist->wl_wre = wre_new;
		srq->srq_wridlist->wl_size = srq->srq_wq_bufsz;

		if (!srq->srq_is_umap) {
			tavor_wrid_list_srq_init(srq->srq_wridlist, srq,
			    srq_old_bufsz);
		}
	}

#ifdef __lock_lint
	mutex_exit(&srq->srq_wrid_wql->wql_lock);
#else
	if (srq->srq_wrid_wql != NULL) {
		mutex_exit(&srq->srq_wrid_wql->wql_lock);
	}
#endif

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
		    state->ts_dip, 0, 0, srq->srq_wqinfo.qa_size, maxprot,
		    DEVMAP_MAPPING_INVALID, NULL);
		if (status != DDI_SUCCESS) {
			mutex_exit(&srq->srq_lock);
			TAVOR_WARNING(state, "failed in SRQ memory "
			    "devmap_devmem_remap()");
			/* We can, however, free the memory for old wre */
			if (wre_old != NULL) {
				kmem_free(wre_old, srq_old_bufsz *
				    sizeof (tavor_wrid_entry_t));
			}
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
	status = tavor_mr_mtt_unbind(state, &old_bind, old_mtt);
	if (status != DDI_SUCCESS) {
		TAVOR_WARNING(state, "failed to unbind old SRQ memory");
		goto srqmodify_fail;
	}

	/* Free the memory for old wre */
	if (wre_old != NULL) {
		kmem_free(wre_old, srq_old_bufsz *
		    sizeof (tavor_wrid_entry_t));
	}

	/* Free the memory for the old SRQ */
	tavor_queue_free(state, &old_srqinfo);

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
 * tavor_srq_refcnt_inc()
 *    Context: Can be called from interrupt or base context.
 */
void
tavor_srq_refcnt_inc(tavor_srqhdl_t srq)
{
	mutex_enter(&srq->srq_lock);
	srq->srq_refcnt++;
	mutex_exit(&srq->srq_lock);
}


/*
 * tavor_srq_refcnt_dec()
 *    Context: Can be called from interrupt or base context.
 */
void
tavor_srq_refcnt_dec(tavor_srqhdl_t srq)
{
	mutex_enter(&srq->srq_lock);
	srq->srq_refcnt--;
	mutex_exit(&srq->srq_lock);
}


/*
 * tavor_srqhdl_from_srqnum()
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
tavor_srqhdl_t
tavor_srqhdl_from_srqnum(tavor_state_t *state, uint_t srqnum)
{
	uint_t	srqindx, srqmask;

	/* Calculate the SRQ table index from the srqnum */
	srqmask = (1 << state->ts_cfg_profile->cp_log_num_srq) - 1;
	srqindx = srqnum & srqmask;
	return (state->ts_srqhdl[srqindx]);
}


/*
 * tavor_srq_sgl_to_logwqesz()
 *    Context: Can be called from interrupt or base context.
 */
static void
tavor_srq_sgl_to_logwqesz(tavor_state_t *state, uint_t num_sgl,
    tavor_qp_wq_type_t wq_type, uint_t *logwqesz, uint_t *max_sgl)
{
	uint_t	max_size, log2, actual_sgl;

	switch (wq_type) {
	case TAVOR_QP_WQ_TYPE_RECVQ:
		/*
		 * Use requested maximum SGL to calculate max descriptor size
		 * (while guaranteeing that the descriptor size is a
		 * power-of-2 cachelines).
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

	default:
		TAVOR_WARNING(state, "unexpected work queue type");
		break;
	}

	/* Fill in the return values */
	*logwqesz = log2;
	*max_sgl  = min(state->ts_cfg_profile->cp_srq_max_sgl, actual_sgl);
}
