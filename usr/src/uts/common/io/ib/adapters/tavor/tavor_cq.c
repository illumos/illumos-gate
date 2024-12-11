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
 * tavor_cq.c
 *    Tavor Completion Queue Processing Routines
 *
 *    Implements all the routines necessary for allocating, freeing, resizing,
 *    and handling the completion type events that the Tavor hardware can
 *    generate.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/bitmap.h>
#include <sys/sysmacros.h>

#include <sys/ib/adapters/tavor/tavor.h>

static void tavor_cq_doorbell(tavor_state_t *state, uint32_t cq_cmd,
    uint32_t cqn, uint32_t cq_param);
static int tavor_cq_cqe_consume(tavor_state_t *state, tavor_cqhdl_t cq,
    tavor_hw_cqe_t *cqe, ibt_wc_t *wc);
static int tavor_cq_errcqe_consume(tavor_state_t *state, tavor_cqhdl_t cq,
    tavor_hw_cqe_t *cqe, ibt_wc_t *wc);
static void tavor_cqe_sync(tavor_cqhdl_t cq, tavor_hw_cqe_t *cqe,
    uint_t flag);
static void tavor_cq_resize_helper(tavor_cqhdl_t cq, tavor_hw_cqe_t *new_cqbuf,
    uint32_t old_cons_indx, uint32_t num_newcqe);

/*
 * tavor_cq_alloc()
 *    Context: Can be called only from user or kernel context.
 */
int
tavor_cq_alloc(tavor_state_t *state, ibt_cq_hdl_t ibt_cqhdl,
    ibt_cq_attr_t *cq_attr, uint_t *actual_size, tavor_cqhdl_t *cqhdl,
    uint_t sleepflag)
{
	tavor_rsrc_t		*cqc, *rsrc;
	tavor_umap_db_entry_t	*umapdb;
	tavor_hw_cqc_t		cqc_entry;
	tavor_cqhdl_t		cq;
	ibt_mr_attr_t		mr_attr;
	tavor_mr_options_t	op;
	tavor_pdhdl_t		pd;
	tavor_mrhdl_t		mr;
	tavor_hw_cqe_t		*buf;
	uint64_t		addr, value;
	uint32_t		log_cq_size, lkey, uarpg;
	uint_t			dma_xfer_mode, cq_sync, cq_is_umap;
	int			status, i, flag;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*cq_attr))

	/*
	 * Determine whether CQ is being allocated for userland access or
	 * whether it is being allocated for kernel access.  If the CQ is
	 * being allocated for userland access, then lookup the UAR doorbell
	 * page number for the current process.  Note:  If this is not found
	 * (e.g. if the process has not previously open()'d the Tavor driver),
	 * then an error is returned.
	 */
	cq_is_umap = (cq_attr->cq_flags & IBT_CQ_USER_MAP) ? 1 : 0;
	if (cq_is_umap) {
		status = tavor_umap_db_find(state->ts_instance, ddi_get_pid(),
		    MLNX_UMAP_UARPG_RSRC, &value, 0, NULL);
		if (status != DDI_SUCCESS) {
			goto cqalloc_fail;
		}
		uarpg = ((tavor_rsrc_t *)(uintptr_t)value)->tr_indx;
	}

	/* Use the internal protection domain (PD) for setting up CQs */
	pd = state->ts_pdhdl_internal;

	/* Increment the reference count on the protection domain (PD) */
	tavor_pd_refcnt_inc(pd);

	/*
	 * Allocate an CQ context entry.  This will be filled in with all
	 * the necessary parameters to define the Completion Queue.  And then
	 * ownership will be passed to the hardware in the final step
	 * below.  If we fail here, we must undo the protection domain
	 * reference count.
	 */
	status = tavor_rsrc_alloc(state, TAVOR_CQC, 1, sleepflag, &cqc);
	if (status != DDI_SUCCESS) {
		goto cqalloc_fail1;
	}

	/*
	 * Allocate the software structure for tracking the completion queue
	 * (i.e. the Tavor Completion Queue handle).  If we fail here, we must
	 * undo the protection domain reference count and the previous
	 * resource allocation.
	 */
	status = tavor_rsrc_alloc(state, TAVOR_CQHDL, 1, sleepflag, &rsrc);
	if (status != DDI_SUCCESS) {
		goto cqalloc_fail2;
	}
	cq = (tavor_cqhdl_t)rsrc->tr_addr;
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*cq))
	cq->cq_is_umap = cq_is_umap;

	/* Use the index as CQ number */
	cq->cq_cqnum = cqc->tr_indx;

	/*
	 * If this will be a user-mappable CQ, then allocate an entry for
	 * the "userland resources database".  This will later be added to
	 * the database (after all further CQ operations are successful).
	 * If we fail here, we must undo the reference counts and the
	 * previous resource allocation.
	 */
	if (cq->cq_is_umap) {
		umapdb = tavor_umap_db_alloc(state->ts_instance, cq->cq_cqnum,
		    MLNX_UMAP_CQMEM_RSRC, (uint64_t)(uintptr_t)rsrc);
		if (umapdb == NULL) {
			goto cqalloc_fail3;
		}
	}

	/*
	 * Calculate the appropriate size for the completion queue.
	 * Note:  All Tavor CQs must be a power-of-2 minus 1 in size.  Also
	 * they may not be any smaller than TAVOR_CQ_MIN_SIZE.  This step is
	 * to round the requested size up to the next highest power-of-2
	 */
	cq_attr->cq_size = max(cq_attr->cq_size, TAVOR_CQ_MIN_SIZE);
	log_cq_size = highbit(cq_attr->cq_size);

	/*
	 * Next we verify that the rounded-up size is valid (i.e. consistent
	 * with the device limits and/or software-configured limits)
	 */
	if (log_cq_size > state->ts_cfg_profile->cp_log_max_cq_sz) {
		goto cqalloc_fail4;
	}

	/*
	 * Allocate the memory for Completion Queue.
	 *
	 * Note: Although we use the common queue allocation routine, we
	 * always specify TAVOR_QUEUE_LOCATION_NORMAL (i.e. CQ located in
	 * kernel system memory) for kernel CQs because it would be
	 * inefficient to have CQs located in DDR memory.  This is primarily
	 * because CQs are read from (by software) more than they are written
	 * to. (We always specify TAVOR_QUEUE_LOCATION_USERLAND for all
	 * user-mappable CQs for a similar reason.)
	 * It is also worth noting that, unlike Tavor QP work queues,
	 * completion queues do not have the same strict alignment
	 * requirements.  It is sufficient for the CQ memory to be both
	 * aligned to and bound to addresses which are a multiple of CQE size.
	 */
	cq->cq_cqinfo.qa_size = (1 << log_cq_size) * sizeof (tavor_hw_cqe_t);
	cq->cq_cqinfo.qa_alloc_align = sizeof (tavor_hw_cqe_t);
	cq->cq_cqinfo.qa_bind_align  = sizeof (tavor_hw_cqe_t);
	if (cq->cq_is_umap) {
		cq->cq_cqinfo.qa_location = TAVOR_QUEUE_LOCATION_USERLAND;
	} else {
		cq->cq_cqinfo.qa_location = TAVOR_QUEUE_LOCATION_NORMAL;
	}
	status = tavor_queue_alloc(state, &cq->cq_cqinfo, sleepflag);
	if (status != DDI_SUCCESS) {
		goto cqalloc_fail4;
	}
	buf = (tavor_hw_cqe_t *)cq->cq_cqinfo.qa_buf_aligned;
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*buf))

	/*
	 * Initialize each of the Completion Queue Entries (CQE) by setting
	 * their ownership to hardware ("owner" bit set to HW).  This is in
	 * preparation for the final transfer of ownership (below) of the
	 * CQ context itself.
	 */
	for (i = 0; i < (1 << log_cq_size); i++) {
		TAVOR_CQE_OWNER_SET_HW(cq, &buf[i]);
	}

	/*
	 * Register the memory for the CQ.  The memory for the CQ must
	 * be registered in the Tavor TPT tables.  This gives us the LKey
	 * to specify in the CQ context below.  Note: If this is a user-
	 * mappable CQ, then we will force DDI_DMA_CONSISTENT mapping.
	 */
	flag = (sleepflag == TAVOR_SLEEP) ?  IBT_MR_SLEEP : IBT_MR_NOSLEEP;
	mr_attr.mr_vaddr = (uint64_t)(uintptr_t)buf;
	mr_attr.mr_len	 = cq->cq_cqinfo.qa_size;
	mr_attr.mr_as	 = NULL;
	mr_attr.mr_flags = flag | IBT_MR_ENABLE_LOCAL_WRITE;
	if (cq->cq_is_umap) {
		dma_xfer_mode = DDI_DMA_CONSISTENT;
	} else {
		dma_xfer_mode = state->ts_cfg_profile->cp_streaming_consistent;
	}
	if (dma_xfer_mode == DDI_DMA_STREAMING) {
		mr_attr.mr_flags |= IBT_MR_NONCOHERENT;
	}
	op.mro_bind_type   = state->ts_cfg_profile->cp_iommu_bypass;
	op.mro_bind_dmahdl = cq->cq_cqinfo.qa_dmahdl;
	op.mro_bind_override_addr = 0;
	status = tavor_mr_register(state, pd, &mr_attr, &mr, &op);
	if (status != DDI_SUCCESS) {
		goto cqalloc_fail5;
	}
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*mr))
	addr = mr->mr_bindinfo.bi_addr;
	lkey = mr->mr_lkey;

	/* Determine if later ddi_dma_sync will be necessary */
	cq_sync = TAVOR_CQ_IS_SYNC_REQ(state, cq->cq_cqinfo);

	/* Sync entire CQ for use by the hardware (if necessary). */
	if (cq_sync) {
		(void) ddi_dma_sync(mr->mr_bindinfo.bi_dmahdl, 0,
		    cq->cq_cqinfo.qa_size, DDI_DMA_SYNC_FORDEV);
	}

	/*
	 * Fill in the CQC entry.  This is the final step before passing
	 * ownership of the CQC entry to the Tavor hardware.  We use all of
	 * the information collected/calculated above to fill in the
	 * requisite portions of the CQC.  Note: If this CQ is going to be
	 * used for userland access, then we need to set the UAR page number
	 * appropriately (otherwise it's a "don't care")
	 */
	bzero(&cqc_entry, sizeof (tavor_hw_cqc_t));
	cq->cq_eqnum		= TAVOR_CQ_EQNUM_GET(cq->cq_cqnum);
	cq->cq_erreqnum		= TAVOR_CQ_ERREQNUM_GET(cq->cq_cqnum);
	cqc_entry.xlat		= TAVOR_VA2PA_XLAT_ENABLED;
	cqc_entry.state		= TAVOR_CQ_DISARMED;
	cqc_entry.start_addr_h	= (addr >> 32);
	cqc_entry.start_addr_l	= (addr & 0xFFFFFFFF);
	cqc_entry.log_cq_sz	= log_cq_size;
	if (cq->cq_is_umap) {
		cqc_entry.usr_page = uarpg;
	} else {
		cqc_entry.usr_page = 0;
	}
	cqc_entry.pd		= pd->pd_pdnum;
	cqc_entry.lkey		= lkey;
	cqc_entry.e_eqn		= cq->cq_erreqnum;
	cqc_entry.c_eqn		= cq->cq_eqnum;
	cqc_entry.cqn		= cq->cq_cqnum;

	/*
	 * Write the CQC entry to hardware.  Lastly, we pass ownership of
	 * the entry to the hardware (using the Tavor SW2HW_CQ firmware
	 * command).  Note: In general, this operation shouldn't fail.  But
	 * if it does, we have to undo everything we've done above before
	 * returning error.
	 */
	status = tavor_cmn_ownership_cmd_post(state, SW2HW_CQ, &cqc_entry,
	    sizeof (tavor_hw_cqc_t), cq->cq_cqnum, sleepflag);
	if (status != TAVOR_CMD_SUCCESS) {
		cmn_err(CE_CONT, "Tavor: SW2HW_CQ command failed: %08x\n",
		    status);
		goto cqalloc_fail6;
	}

	/*
	 * Fill in the rest of the Tavor Completion Queue handle.  Having
	 * successfully transferred ownership of the CQC, we can update the
	 * following fields for use in further operations on the CQ.
	 */
	cq->cq_cqcrsrcp	  = cqc;
	cq->cq_rsrcp	  = rsrc;
	cq->cq_consindx	  = 0;
	cq->cq_buf	  = buf;
	cq->cq_bufsz	  = (1 << log_cq_size);
	cq->cq_mrhdl	  = mr;
	cq->cq_sync	  = cq_sync;
	cq->cq_refcnt	  = 0;
	cq->cq_is_special = 0;
	cq->cq_uarpg	  = uarpg;
	cq->cq_umap_dhp	  = (devmap_cookie_t)NULL;
	avl_create(&cq->cq_wrid_wqhdr_avl_tree, tavor_wrid_wqhdr_compare,
	    sizeof (struct tavor_workq_hdr_s),
	    offsetof(struct tavor_workq_hdr_s, wq_avl_link));

	cq->cq_wrid_reap_head  = NULL;
	cq->cq_wrid_reap_tail  = NULL;
	cq->cq_hdlrarg	  = (void *)ibt_cqhdl;

	/*
	 * Put CQ handle in Tavor CQNum-to-CQHdl list.  Then fill in the
	 * "actual_size" and "cqhdl" and return success
	 */
	ASSERT(state->ts_cqhdl[cqc->tr_indx] == NULL);
	state->ts_cqhdl[cqc->tr_indx] = cq;

	/*
	 * If this is a user-mappable CQ, then we need to insert the previously
	 * allocated entry into the "userland resources database".  This will
	 * allow for later lookup during devmap() (i.e. mmap()) calls.
	 */
	if (cq->cq_is_umap) {
		tavor_umap_db_add(umapdb);
	}

	/*
	 * Fill in the return arguments (if necessary).  This includes the
	 * real completion queue size.
	 */
	if (actual_size != NULL) {
		*actual_size = (1 << log_cq_size) - 1;
	}
	*cqhdl = cq;

	return (DDI_SUCCESS);

/*
 * The following is cleanup for all possible failure cases in this routine
 */
cqalloc_fail6:
	if (tavor_mr_deregister(state, &mr, TAVOR_MR_DEREG_ALL,
	    sleepflag) != DDI_SUCCESS) {
		TAVOR_WARNING(state, "failed to deregister CQ memory");
	}
cqalloc_fail5:
	tavor_queue_free(state, &cq->cq_cqinfo);
cqalloc_fail4:
	if (cq_is_umap) {
		tavor_umap_db_free(umapdb);
	}
cqalloc_fail3:
	tavor_rsrc_free(state, &rsrc);
cqalloc_fail2:
	tavor_rsrc_free(state, &cqc);
cqalloc_fail1:
	tavor_pd_refcnt_dec(pd);
cqalloc_fail:
	return (status);
}


/*
 * tavor_cq_free()
 *    Context: Can be called only from user or kernel context.
 */
/* ARGSUSED */
int
tavor_cq_free(tavor_state_t *state, tavor_cqhdl_t *cqhdl, uint_t sleepflag)
{
	tavor_rsrc_t		*cqc, *rsrc;
	tavor_umap_db_entry_t	*umapdb;
	tavor_hw_cqc_t		cqc_entry;
	tavor_pdhdl_t		pd;
	tavor_mrhdl_t		mr;
	tavor_cqhdl_t		cq;
	uint32_t		cqnum;
	uint64_t		value;
	uint_t			maxprot;
	int			status;

	/*
	 * Pull all the necessary information from the Tavor Completion Queue
	 * handle.  This is necessary here because the resource for the
	 * CQ handle is going to be freed up as part of this operation.
	 */
	cq	= *cqhdl;
	mutex_enter(&cq->cq_lock);
	cqc	= cq->cq_cqcrsrcp;
	rsrc	= cq->cq_rsrcp;
	pd	= state->ts_pdhdl_internal;
	mr	= cq->cq_mrhdl;
	cqnum	= cq->cq_cqnum;

	/*
	 * If there are work queues still associated with the CQ, then return
	 * an error.  Otherwise, we will be holding the CQ lock.
	 */
	if (cq->cq_refcnt != 0) {
		mutex_exit(&cq->cq_lock);
		return (IBT_CQ_BUSY);
	}

	/*
	 * If this was a user-mappable CQ, then we need to remove its entry
	 * from the "userland resources database".  If it is also currently
	 * mmap()'d out to a user process, then we need to call
	 * devmap_devmem_remap() to remap the CQ memory to an invalid mapping.
	 * We also need to invalidate the CQ tracking information for the
	 * user mapping.
	 */
	if (cq->cq_is_umap) {
		status = tavor_umap_db_find(state->ts_instance, cqnum,
		    MLNX_UMAP_CQMEM_RSRC, &value, TAVOR_UMAP_DB_REMOVE,
		    &umapdb);
		if (status != DDI_SUCCESS) {
			mutex_exit(&cq->cq_lock);
			TAVOR_WARNING(state, "failed to find in database");
			return (ibc_get_ci_failure(0));
		}
		tavor_umap_db_free(umapdb);
		if (cq->cq_umap_dhp != NULL) {
			maxprot = (PROT_READ | PROT_WRITE | PROT_USER);
			status = devmap_devmem_remap(cq->cq_umap_dhp,
			    state->ts_dip, 0, 0, cq->cq_cqinfo.qa_size,
			    maxprot, DEVMAP_MAPPING_INVALID, NULL);
			if (status != DDI_SUCCESS) {
				mutex_exit(&cq->cq_lock);
				TAVOR_WARNING(state, "failed in CQ memory "
				    "devmap_devmem_remap()");
				return (ibc_get_ci_failure(0));
			}
			cq->cq_umap_dhp = (devmap_cookie_t)NULL;
		}
	}

	/*
	 * Put NULL into the Tavor CQNum-to-CQHdl list.  This will allow any
	 * in-progress events to detect that the CQ corresponding to this
	 * number has been freed.
	 */
	state->ts_cqhdl[cqc->tr_indx] = NULL;

	/*
	 * While we hold the CQ lock, do a "forced reap" of the workQ WRID
	 * list.  This cleans up all the structures associated with the WRID
	 * processing for this CQ.  Once we complete, drop the lock and finish
	 * the deallocation of the CQ.
	 */
	tavor_wrid_cq_force_reap(cq);

	mutex_exit(&cq->cq_lock);
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*cq))

	/*
	 * Reclaim CQC entry from hardware (using the Tavor HW2SW_CQ
	 * firmware command).  If the ownership transfer fails for any reason,
	 * then it is an indication that something (either in HW or SW) has
	 * gone seriously wrong.
	 */
	status = tavor_cmn_ownership_cmd_post(state, HW2SW_CQ, &cqc_entry,
	    sizeof (tavor_hw_cqc_t), cqnum, sleepflag);
	if (status != TAVOR_CMD_SUCCESS) {
		TAVOR_WARNING(state, "failed to reclaim CQC ownership");
		cmn_err(CE_CONT, "Tavor: HW2SW_CQ command failed: %08x\n",
		    status);
		return (ibc_get_ci_failure(0));
	}

	/*
	 * Deregister the memory for the Completion Queue.  If this fails
	 * for any reason, then it is an indication that something (either
	 * in HW or SW) has gone seriously wrong.  So we print a warning
	 * message and return.
	 */
	status = tavor_mr_deregister(state, &mr, TAVOR_MR_DEREG_ALL,
	    sleepflag);
	if (status != DDI_SUCCESS) {
		TAVOR_WARNING(state, "failed to deregister CQ memory");
		return (ibc_get_ci_failure(0));
	}

	/* Free the memory for the CQ */
	tavor_queue_free(state, &cq->cq_cqinfo);

	/* Free the Tavor Completion Queue handle */
	tavor_rsrc_free(state, &rsrc);

	/* Free up the CQC entry resource */
	tavor_rsrc_free(state, &cqc);

	/* Decrement the reference count on the protection domain (PD) */
	tavor_pd_refcnt_dec(pd);

	/* Set the cqhdl pointer to NULL and return success */
	*cqhdl = NULL;

	return (DDI_SUCCESS);
}


/*
 * tavor_cq_resize()
 *    Context: Can be called only from user or kernel context.
 */
int
tavor_cq_resize(tavor_state_t *state, tavor_cqhdl_t cq, uint_t req_size,
    uint_t *actual_size, uint_t sleepflag)
{
	tavor_hw_cqc_t		cqc_entry;
	tavor_qalloc_info_t	new_cqinfo, old_cqinfo;
	ibt_mr_attr_t		mr_attr;
	tavor_mr_options_t	op;
	tavor_pdhdl_t		pd;
	tavor_mrhdl_t		mr, mr_old;
	tavor_hw_cqe_t		*buf;
	uint32_t		new_prod_indx, old_cons_indx;
	uint_t			dma_xfer_mode, cq_sync, log_cq_size, maxprot;
	int			status, i, flag;

	/* Use the internal protection domain (PD) for CQs */
	pd = state->ts_pdhdl_internal;

	/*
	 * Calculate the appropriate size for the new resized completion queue.
	 * Note:  All Tavor CQs must be a power-of-2 minus 1 in size.  Also
	 * they may not be any smaller than TAVOR_CQ_MIN_SIZE.  This step is
	 * to round the requested size up to the next highest power-of-2
	 */
	req_size = max(req_size, TAVOR_CQ_MIN_SIZE);
	log_cq_size = highbit(req_size);

	/*
	 * Next we verify that the rounded-up size is valid (i.e. consistent
	 * with the device limits and/or software-configured limits)
	 */
	if (log_cq_size > state->ts_cfg_profile->cp_log_max_cq_sz) {
		goto cqresize_fail;
	}

	/*
	 * Allocate the memory for newly resized Completion Queue.
	 *
	 * Note: Although we use the common queue allocation routine, we
	 * always specify TAVOR_QUEUE_LOCATION_NORMAL (i.e. CQ located in
	 * kernel system memory) for kernel CQs because it would be
	 * inefficient to have CQs located in DDR memory.  This is the same
	 * as we do when we first allocate completion queues primarily
	 * because CQs are read from (by software) more than they are written
	 * to. (We always specify TAVOR_QUEUE_LOCATION_USERLAND for all
	 * user-mappable CQs for a similar reason.)
	 * It is also worth noting that, unlike Tavor QP work queues,
	 * completion queues do not have the same strict alignment
	 * requirements.  It is sufficient for the CQ memory to be both
	 * aligned to and bound to addresses which are a multiple of CQE size.
	 */
	new_cqinfo.qa_size = (1 << log_cq_size) * sizeof (tavor_hw_cqe_t);
	new_cqinfo.qa_alloc_align = sizeof (tavor_hw_cqe_t);
	new_cqinfo.qa_bind_align  = sizeof (tavor_hw_cqe_t);
	if (cq->cq_is_umap) {
		new_cqinfo.qa_location = TAVOR_QUEUE_LOCATION_USERLAND;
	} else {
		new_cqinfo.qa_location = TAVOR_QUEUE_LOCATION_NORMAL;
	}
	status = tavor_queue_alloc(state, &new_cqinfo, sleepflag);
	if (status != DDI_SUCCESS) {
		goto cqresize_fail;
	}
	buf = (tavor_hw_cqe_t *)new_cqinfo.qa_buf_aligned;
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*buf))

	/*
	 * Initialize each of the Completion Queue Entries (CQE) by setting
	 * their ownership to hardware ("owner" bit set to HW).  This is in
	 * preparation for the final resize operation (below).
	 */
	for (i = 0; i < (1 << log_cq_size); i++) {
		TAVOR_CQE_OWNER_SET_HW(cq, &buf[i]);
	}

	/*
	 * Register the memory for the CQ.  The memory for the CQ must
	 * be registered in the Tavor TPT tables.  This gives us the LKey
	 * to specify in the CQ context below.
	 */
	flag = (sleepflag == TAVOR_SLEEP) ? IBT_MR_SLEEP : IBT_MR_NOSLEEP;
	mr_attr.mr_vaddr = (uint64_t)(uintptr_t)buf;
	mr_attr.mr_len	 = new_cqinfo.qa_size;
	mr_attr.mr_as	 = NULL;
	mr_attr.mr_flags = flag | IBT_MR_ENABLE_LOCAL_WRITE;
	if (cq->cq_is_umap) {
		dma_xfer_mode = DDI_DMA_CONSISTENT;
	} else {
		dma_xfer_mode = state->ts_cfg_profile->cp_streaming_consistent;
	}
	if (dma_xfer_mode == DDI_DMA_STREAMING) {
		mr_attr.mr_flags |= IBT_MR_NONCOHERENT;
	}
	op.mro_bind_type = state->ts_cfg_profile->cp_iommu_bypass;
	op.mro_bind_dmahdl = new_cqinfo.qa_dmahdl;
	op.mro_bind_override_addr = 0;
	status = tavor_mr_register(state, pd, &mr_attr, &mr, &op);
	if (status != DDI_SUCCESS) {
		tavor_queue_free(state, &new_cqinfo);
		goto cqresize_fail;
	}
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*mr))

	/* Determine if later ddi_dma_sync will be necessary */
	cq_sync = TAVOR_CQ_IS_SYNC_REQ(state, new_cqinfo);

	/* Sync entire "new" CQ for use by hardware (if necessary) */
	if (cq_sync) {
		(void) ddi_dma_sync(mr->mr_bindinfo.bi_dmahdl, 0,
		    new_cqinfo.qa_size, DDI_DMA_SYNC_FORDEV);
	}

	/*
	 * Now we grab the CQ lock.  Since we will be updating the actual
	 * CQ location and the producer/consumer indexes, we should hold
	 * the lock.
	 *
	 * We do a TAVOR_NOSLEEP here (and below), though, because we are
	 * holding the "cq_lock" and if we got raised to interrupt level
	 * by priority inversion, we would not want to block in this routine
	 * waiting for success.
	 */
	mutex_enter(&cq->cq_lock);

	/*
	 * Determine the current CQ "consumer index".
	 *
	 * Note:  This will depend on whether the CQ had previously been
	 * mapped for user access or whether it is a kernel CQ.  If this
	 * is a kernel CQ, then all PollCQ() operations have come through
	 * the IBTF and, hence, the driver's CQ state structure will
	 * contain the current consumer index.  If, however, the user has
	 * accessed this CQ by bypassing the driver (OS-bypass), then we
	 * need to query the firmware to determine the current CQ consumer
	 * index.  This also assumes that the user process will not continue
	 * to consume entries while at the same time doing the ResizeCQ()
	 * operation.  If the user process does not guarantee this, then it
	 * may see duplicate or missed completions.  But under no
	 * circumstances should this panic the system.
	 */
	if (cq->cq_is_umap) {
		status = tavor_cmn_query_cmd_post(state, QUERY_CQ,
		    cq->cq_cqnum, &cqc_entry, sizeof (tavor_hw_cqc_t),
		    TAVOR_NOSLEEP);
		if (status != TAVOR_CMD_SUCCESS) {
			/* Query CQ has failed, drop CQ lock and cleanup */
			mutex_exit(&cq->cq_lock);
			if (tavor_mr_deregister(state, &mr, TAVOR_MR_DEREG_ALL,
			    sleepflag) != DDI_SUCCESS) {
				TAVOR_WARNING(state, "failed to deregister "
				    "CQ memory");
			}
			tavor_queue_free(state, &new_cqinfo);
			TAVOR_WARNING(state, "failed to find in database");

			goto cqresize_fail;
		}
		old_cons_indx = cqc_entry.cons_indx;
	} else {
		old_cons_indx = cq->cq_consindx;
	}

	/*
	 * Fill in the CQC entry.  For the resize operation this is the
	 * final step before attempting the resize operation on the CQC entry.
	 * We use all of the information collected/calculated above to fill
	 * in the requisite portions of the CQC.
	 */
	bzero(&cqc_entry, sizeof (tavor_hw_cqc_t));
	cqc_entry.start_addr_h	= (mr->mr_bindinfo.bi_addr >> 32);
	cqc_entry.start_addr_l	= (mr->mr_bindinfo.bi_addr & 0xFFFFFFFF);
	cqc_entry.log_cq_sz	= log_cq_size;
	cqc_entry.lkey		= mr->mr_lkey;

	/*
	 * Write the CQC entry to hardware.  Lastly, we pass ownership of
	 * the entry to the hardware (using the Tavor RESIZE_CQ firmware
	 * command).  Note: In general, this operation shouldn't fail.  But
	 * if it does, we have to undo everything we've done above before
	 * returning error.  Also note that the status returned may indicate
	 * the code to return to the IBTF.
	 */
	status = tavor_resize_cq_cmd_post(state, &cqc_entry, cq->cq_cqnum,
	    &new_prod_indx, TAVOR_CMD_NOSLEEP_SPIN);
	if (status != TAVOR_CMD_SUCCESS) {
		/* Resize attempt has failed, drop CQ lock and cleanup */
		mutex_exit(&cq->cq_lock);
		if (tavor_mr_deregister(state, &mr, TAVOR_MR_DEREG_ALL,
		    sleepflag) != DDI_SUCCESS) {
			TAVOR_WARNING(state, "failed to deregister CQ memory");
		}
		tavor_queue_free(state, &new_cqinfo);
		if (status == TAVOR_CMD_BAD_SIZE) {
			return (IBT_CQ_SZ_INSUFFICIENT);
		} else {
			cmn_err(CE_CONT, "Tavor: RESIZE_CQ command failed: "
			    "%08x\n", status);
			return (ibc_get_ci_failure(0));
		}
	}

	/*
	 * The CQ resize attempt was successful.  Before dropping the CQ lock,
	 * copy all of the CQEs from the "old" CQ into the "new" CQ.  Note:
	 * the Tavor firmware guarantees us that sufficient space is set aside
	 * in the "new" CQ to handle any un-polled CQEs from the "old" CQ.
	 * The two parameters to this helper function ("old_cons_indx" and
	 * "new_prod_indx") essentially indicate the starting index and number
	 * of any CQEs that might remain in the "old" CQ memory.
	 */
	tavor_cq_resize_helper(cq, buf, old_cons_indx, new_prod_indx);

	/* Sync entire "new" CQ for use by hardware (if necessary) */
	if (cq_sync) {
		(void) ddi_dma_sync(mr->mr_bindinfo.bi_dmahdl, 0,
		    new_cqinfo.qa_size, DDI_DMA_SYNC_FORDEV);
	}

	/*
	 * Update the Tavor Completion Queue handle with all the new
	 * information.  At the same time, save away all the necessary
	 * information for freeing up the old resources
	 */
	mr_old		 = cq->cq_mrhdl;
	old_cqinfo	 = cq->cq_cqinfo;
	cq->cq_cqinfo	 = new_cqinfo;
	cq->cq_consindx	 = 0;
	cq->cq_buf	 = buf;
	cq->cq_bufsz	 = (1 << log_cq_size);
	cq->cq_mrhdl	 = mr;
	cq->cq_sync	 = cq_sync;

	/*
	 * If "old" CQ was a user-mappable CQ that is currently mmap()'d out
	 * to a user process, then we need to call devmap_devmem_remap() to
	 * invalidate the mapping to the CQ memory.  We also need to
	 * invalidate the CQ tracking information for the user mapping.
	 */
	if ((cq->cq_is_umap) && (cq->cq_umap_dhp != NULL)) {
		maxprot = (PROT_READ | PROT_WRITE | PROT_USER);
		status = devmap_devmem_remap(cq->cq_umap_dhp,
		    state->ts_dip, 0, 0, cq->cq_cqinfo.qa_size, maxprot,
		    DEVMAP_MAPPING_INVALID, NULL);
		if (status != DDI_SUCCESS) {
			mutex_exit(&cq->cq_lock);
			TAVOR_WARNING(state, "failed in CQ memory "
			    "devmap_devmem_remap()");
			return (ibc_get_ci_failure(0));
		}
		cq->cq_umap_dhp = (devmap_cookie_t)NULL;
	}

	/*
	 * Drop the CQ lock now.  The only thing left to do is to free up
	 * the old resources.
	 */
	mutex_exit(&cq->cq_lock);

	/*
	 * Deregister the memory for the old Completion Queue.  Note: We
	 * really can't return error here because we have no good way to
	 * cleanup.  Plus, the deregistration really shouldn't ever happen.
	 * So, if it does, it is an indication that something has gone
	 * seriously wrong.  So we print a warning message and return error
	 * (knowing, of course, that the "old" CQ memory will be leaked)
	 */
	status = tavor_mr_deregister(state, &mr_old, TAVOR_MR_DEREG_ALL,
	    sleepflag);
	if (status != DDI_SUCCESS) {
		TAVOR_WARNING(state, "failed to deregister old CQ memory");
		goto cqresize_fail;
	}

	/* Free the memory for the old CQ */
	tavor_queue_free(state, &old_cqinfo);

	/*
	 * Fill in the return arguments (if necessary).  This includes the
	 * real new completion queue size.
	 */
	if (actual_size != NULL) {
		*actual_size = (1 << log_cq_size) - 1;
	}

	return (DDI_SUCCESS);

cqresize_fail:
	return (status);
}


/*
 * tavor_cq_notify()
 *    Context: Can be called from interrupt or base context.
 */
int
tavor_cq_notify(tavor_state_t *state, tavor_cqhdl_t cq,
    ibt_cq_notify_flags_t flags)
{
	uint_t		cqnum;

	/*
	 * Determine if we are trying to get the next completion or the next
	 * "solicited" completion.  Then hit the appropriate doorbell.
	 *
	 * NOTE: Please see the comment in tavor_event.c:tavor_eq_poll
	 * regarding why we do not have to do an extra PIO read here, and we
	 * will not lose an event after writing this doorbell.
	 */
	cqnum = cq->cq_cqnum;
	if (flags == IBT_NEXT_COMPLETION) {
		tavor_cq_doorbell(state, TAVOR_CQDB_NOTIFY_CQ, cqnum,
		    TAVOR_CQDB_DEFAULT_PARAM);

	} else if (flags == IBT_NEXT_SOLICITED) {
		tavor_cq_doorbell(state, TAVOR_CQDB_NOTIFY_CQ_SOLICIT,
		    cqnum, TAVOR_CQDB_DEFAULT_PARAM);

	} else {
		return (IBT_CQ_NOTIFY_TYPE_INVALID);
	}

	return (DDI_SUCCESS);
}


/*
 * tavor_cq_poll()
 *    Context: Can be called from interrupt or base context.
 */
int
tavor_cq_poll(tavor_state_t *state, tavor_cqhdl_t cq, ibt_wc_t *wc_p,
    uint_t num_wc, uint_t *num_polled)
{
	tavor_hw_cqe_t	*cqe;
	uint32_t	cons_indx, wrap_around_mask;
	uint32_t	polled_cnt, num_to_increment;
	int		status;

	/*
	 * Check for user-mappable CQ memory.  Note:  We do not allow kernel
	 * clients to poll CQ memory that is accessible directly by the user.
	 * If the CQ memory is user accessible, then return an error.
	 */
	if (cq->cq_is_umap) {
		return (IBT_CQ_HDL_INVALID);
	}

	mutex_enter(&cq->cq_lock);

	/* Get the consumer index */
	cons_indx = cq->cq_consindx;

	/*
	 * Calculate the wrap around mask.  Note: This operation only works
	 * because all Tavor completion queues have power-of-2 sizes
	 */
	wrap_around_mask = (cq->cq_bufsz - 1);

	/* Calculate the pointer to the first CQ entry */
	cqe = &cq->cq_buf[cons_indx];

	/* Sync the current CQE to read */
	tavor_cqe_sync(cq, cqe, DDI_DMA_SYNC_FORCPU);

	/*
	 * Keep pulling entries from the CQ until we find an entry owned by
	 * the hardware.  As long as there the CQE's owned by SW, process
	 * each entry by calling tavor_cq_cqe_consume() and updating the CQ
	 * consumer index.  Note:  We only update the consumer index if
	 * tavor_cq_cqe_consume() returns TAVOR_CQ_SYNC_AND_DB.  Otherwise,
	 * it indicates that we are going to "recycle" the CQE (probably
	 * because it is a error CQE and corresponds to more than one
	 * completion).
	 */
	polled_cnt = 0;
	while (TAVOR_CQE_OWNER_IS_SW(cq, cqe)) {
		status = tavor_cq_cqe_consume(state, cq, cqe,
		    &wc_p[polled_cnt++]);
		if (status == TAVOR_CQ_SYNC_AND_DB) {
			/* Reset entry to hardware ownership */
			TAVOR_CQE_OWNER_SET_HW(cq, cqe);

			/* Sync the current CQE for device */
			tavor_cqe_sync(cq, cqe, DDI_DMA_SYNC_FORDEV);

			/* Increment the consumer index */
			cons_indx = (cons_indx + 1) & wrap_around_mask;

			/* Update the pointer to the next CQ entry */
			cqe = &cq->cq_buf[cons_indx];

			/* Sync the next CQE to read */
			tavor_cqe_sync(cq, cqe, DDI_DMA_SYNC_FORCPU);
		}

		/*
		 * If we have run out of space to store work completions,
		 * then stop and return the ones we have pulled of the CQ.
		 */
		if (polled_cnt >= num_wc) {
			break;
		}
	}

	/*
	 * Now we only ring the doorbell (to update the consumer index) if
	 * we've actually consumed a CQ entry.  If we have, for example,
	 * pulled from a CQE that we are still in the process of "recycling"
	 * for error purposes, then we would not update the consumer index.
	 */
	if ((polled_cnt != 0) && (cq->cq_consindx != cons_indx)) {
		/*
		 * Post doorbell to update the consumer index.  Doorbell
		 * value indicates number of entries consumed (minus 1)
		 */
		if (cons_indx > cq->cq_consindx) {
			num_to_increment = (cons_indx - cq->cq_consindx) - 1;
		} else {
			num_to_increment = ((cons_indx + cq->cq_bufsz) -
			    cq->cq_consindx) - 1;
		}
		cq->cq_consindx = cons_indx;
		tavor_cq_doorbell(state, TAVOR_CQDB_INCR_CONSINDX,
		    cq->cq_cqnum, num_to_increment);

	} else if (polled_cnt == 0) {
		/*
		 * If the CQ is empty, we can try to free up some of the WRID
		 * list containers.  See tavor_wr.c for more details on this
		 * operation.
		 */
		tavor_wrid_cq_reap(cq);
	}

	mutex_exit(&cq->cq_lock);

	/* Set "num_polled" (if necessary) */
	if (num_polled != NULL) {
		*num_polled = polled_cnt;
	}

	/* Set CQ_EMPTY condition if needed, otherwise return success */
	if (polled_cnt == 0) {
		status = IBT_CQ_EMPTY;
	} else {
		status = DDI_SUCCESS;
	}

	/*
	 * Check if the system is currently panicking.  If it is, then call
	 * the Tavor interrupt service routine.  This step is necessary here
	 * because we might be in a polled I/O mode and without the call to
	 * tavor_isr() - and its subsequent calls to poll and rearm each
	 * event queue - we might overflow our EQs and render the system
	 * unable to sync/dump.
	 */
	if (ddi_in_panic() != 0) {
		(void) tavor_isr((caddr_t)state, (caddr_t)NULL);
	}

	return (status);
}


/*
 * tavor_cq_handler()
 *    Context: Only called from interrupt context
 */
int
tavor_cq_handler(tavor_state_t *state, tavor_eqhdl_t eq,
    tavor_hw_eqe_t *eqe)
{
	tavor_cqhdl_t		cq;
	uint_t			cqnum;
	uint_t			eqe_evttype;

	eqe_evttype = TAVOR_EQE_EVTTYPE_GET(eq, eqe);

	ASSERT(eqe_evttype == TAVOR_EVT_COMPLETION ||
	    eqe_evttype == TAVOR_EVT_EQ_OVERFLOW);

	if (eqe_evttype == TAVOR_EVT_EQ_OVERFLOW) {
		tavor_eq_overflow_handler(state, eq, eqe);

		return (DDI_FAILURE);
	}


	/* Get the CQ handle from CQ number in event descriptor */
	cqnum = TAVOR_EQE_CQNUM_GET(eq, eqe);
	cq = tavor_cqhdl_from_cqnum(state, cqnum);

	/*
	 * Post the EQ doorbell to move the CQ to the "disarmed" state.
	 * This operation is to enable subsequent CQ doorbells (e.g. those
	 * that can be rung by tavor_cq_notify() above) to rearm the CQ.
	 */
	tavor_eq_doorbell(state, TAVOR_EQDB_DISARM_CQ, eq->eq_eqnum, cqnum);

	/*
	 * If the CQ handle is NULL, this is probably an indication
	 * that the CQ has been freed already.  In which case, we
	 * should not deliver this event.
	 *
	 * We also check that the CQ number in the handle is the
	 * same as the CQ number in the event queue entry.  This
	 * extra check allows us to handle the case where a CQ was
	 * freed and then allocated again in the time it took to
	 * handle the event queue processing.  By constantly incrementing
	 * the non-constrained portion of the CQ number every time
	 * a new CQ is allocated, we mitigate (somewhat) the chance
	 * that a stale event could be passed to the client's CQ
	 * handler.
	 *
	 * Lastly, we check if "ts_ibtfpriv" is NULL.  If it is then it
	 * means that we've have either received this event before we
	 * finished attaching to the IBTF or we've received it while we
	 * are in the process of detaching.
	 */
	if ((cq != NULL) && (cq->cq_cqnum == cqnum) &&
	    (state->ts_ibtfpriv != NULL)) {
		TAVOR_DO_IBTF_CQ_CALLB(state, cq);
	}

	return (DDI_SUCCESS);
}


/*
 * tavor_cq_err_handler()
 *    Context: Only called from interrupt context
 */
int
tavor_cq_err_handler(tavor_state_t *state, tavor_eqhdl_t eq,
    tavor_hw_eqe_t *eqe)
{
	tavor_cqhdl_t		cq;
	uint_t			cqnum;
	ibc_async_event_t	event;
	ibt_async_code_t	type;
	uint_t			eqe_evttype;

	eqe_evttype = TAVOR_EQE_EVTTYPE_GET(eq, eqe);

	ASSERT(eqe_evttype == TAVOR_EVT_CQ_ERRORS ||
	    eqe_evttype == TAVOR_EVT_EQ_OVERFLOW);

	if (eqe_evttype == TAVOR_EVT_EQ_OVERFLOW) {
		tavor_eq_overflow_handler(state, eq, eqe);

		return (DDI_FAILURE);
	}

	/* cmn_err(CE_CONT, "CQ Error handler\n"); */

	/* Get the CQ handle from CQ number in event descriptor */
	cqnum = TAVOR_EQE_CQNUM_GET(eq, eqe);
	cq = tavor_cqhdl_from_cqnum(state, cqnum);

	/*
	 * If the CQ handle is NULL, this is probably an indication
	 * that the CQ has been freed already.  In which case, we
	 * should not deliver this event.
	 *
	 * We also check that the CQ number in the handle is the
	 * same as the CQ number in the event queue entry.  This
	 * extra check allows us to handle the case where a CQ was
	 * freed and then allocated again in the time it took to
	 * handle the event queue processing.  By constantly incrementing
	 * the non-constrained portion of the CQ number every time
	 * a new CQ is allocated, we mitigate (somewhat) the chance
	 * that a stale event could be passed to the client's CQ
	 * handler.
	 *
	 * And then we check if "ts_ibtfpriv" is NULL.  If it is then it
	 * means that we've have either received this event before we
	 * finished attaching to the IBTF or we've received it while we
	 * are in the process of detaching.
	 */
	if ((cq != NULL) && (cq->cq_cqnum == cqnum) &&
	    (state->ts_ibtfpriv != NULL)) {
		event.ev_cq_hdl = (ibt_cq_hdl_t)cq->cq_hdlrarg;
		type		= IBT_ERROR_CQ;

		TAVOR_DO_IBTF_ASYNC_CALLB(state, type, &event);
	}

	return (DDI_SUCCESS);
}


/*
 * tavor_cq_refcnt_inc()
 *    Context: Can be called from interrupt or base context.
 */
int
tavor_cq_refcnt_inc(tavor_cqhdl_t cq, uint_t is_special)
{
	/*
	 * Increment the completion queue's reference count.  Note: In order
	 * to ensure compliance with IBA C11-15, we must ensure that a given
	 * CQ is not used for both special (SMI/GSI) QP and non-special QP.
	 * This is accomplished here by keeping track of how the referenced
	 * CQ is being used.
	 */
	mutex_enter(&cq->cq_lock);
	if (cq->cq_refcnt == 0) {
		cq->cq_is_special = is_special;
	} else {
		if (cq->cq_is_special != is_special) {
			mutex_exit(&cq->cq_lock);
			return (DDI_FAILURE);
		}
	}
	cq->cq_refcnt++;
	mutex_exit(&cq->cq_lock);
	return (DDI_SUCCESS);
}


/*
 * tavor_cq_refcnt_dec()
 *    Context: Can be called from interrupt or base context.
 */
void
tavor_cq_refcnt_dec(tavor_cqhdl_t cq)
{
	/* Decrement the completion queue's reference count */
	mutex_enter(&cq->cq_lock);
	cq->cq_refcnt--;
	mutex_exit(&cq->cq_lock);
}


/*
 * tavor_cq_doorbell()
 *    Context: Can be called from interrupt or base context.
 */
static void
tavor_cq_doorbell(tavor_state_t *state, uint32_t cq_cmd, uint32_t cqn,
    uint32_t cq_param)
{
	uint64_t	doorbell = 0;

	/* Build the doorbell from the parameters */
	doorbell = ((uint64_t)cq_cmd << TAVOR_CQDB_CMD_SHIFT) |
	    ((uint64_t)cqn << TAVOR_CQDB_CQN_SHIFT) | cq_param;

	/* Write the doorbell to UAR */
	TAVOR_UAR_DOORBELL(state, (uint64_t *)&state->ts_uar->cq,
	    doorbell);
}


/*
 * tavor_cqhdl_from_cqnum()
 *    Context: Can be called from interrupt or base context.
 *
 *    This routine is important because changing the unconstrained
 *    portion of the CQ number is critical to the detection of a
 *    potential race condition in the CQ handler code (i.e. the case
 *    where a CQ is freed and alloc'd again before an event for the
 *    "old" CQ can be handled).
 *
 *    While this is not a perfect solution (not sure that one exists)
 *    it does help to mitigate the chance that this race condition will
 *    cause us to deliver a "stale" event to the new CQ owner.  Note:
 *    this solution does not scale well because the number of constrained
 *    bits increases (and, hence, the number of unconstrained bits
 *    decreases) as the number of supported CQs grows.  For small and
 *    intermediate values, it should hopefully provide sufficient
 *    protection.
 */
tavor_cqhdl_t
tavor_cqhdl_from_cqnum(tavor_state_t *state, uint_t cqnum)
{
	uint_t	cqindx, cqmask;

	/* Calculate the CQ table index from the cqnum */
	cqmask = (1 << state->ts_cfg_profile->cp_log_num_cq) - 1;
	cqindx = cqnum & cqmask;
	return (state->ts_cqhdl[cqindx]);
}


/*
 * tavor_cq_cqe_consume()
 *    Context: Can be called from interrupt or base context.
 */
static int
tavor_cq_cqe_consume(tavor_state_t *state, tavor_cqhdl_t cq,
    tavor_hw_cqe_t *cqe, ibt_wc_t *wc)
{
	uint_t		flags, type, opcode, qpnum, qp1_indx;
	int		status;

	/*
	 * Determine if this is an "error" CQE by examining "opcode".  If it
	 * is an error CQE, then call tavor_cq_errcqe_consume() and return
	 * whatever status it returns.  Otherwise, this is a successful
	 * completion.
	 */
	opcode = TAVOR_CQE_OPCODE_GET(cq, cqe);
	if ((opcode == TAVOR_CQE_SEND_ERR_OPCODE) ||
	    (opcode == TAVOR_CQE_RECV_ERR_OPCODE)) {
		status = tavor_cq_errcqe_consume(state, cq, cqe, wc);
		return (status);
	}

	/*
	 * Fetch the Work Request ID using the information in the CQE.
	 * See tavor_wr.c for more details.
	 */
	wc->wc_id = tavor_wrid_get_entry(cq, cqe, NULL);

	/*
	 * Parse the CQE opcode to determine completion type.  This will set
	 * not only the type of the completion, but also any flags that might
	 * be associated with it (e.g. whether immediate data is present).
	 */
	flags = IBT_WC_NO_FLAGS;
	if (TAVOR_CQE_SENDRECV_GET(cq, cqe) != TAVOR_COMPLETION_RECV) {

		/* Send CQE */
		switch (opcode) {
		case TAVOR_CQE_SND_RDMAWR_IMM:
			flags |= IBT_WC_IMMED_DATA_PRESENT;
			/* FALLTHROUGH */
		case TAVOR_CQE_SND_RDMAWR:
			type = IBT_WRC_RDMAW;
			break;

		case TAVOR_CQE_SND_SEND_IMM:
			flags |= IBT_WC_IMMED_DATA_PRESENT;
			/* FALLTHROUGH */
		case TAVOR_CQE_SND_SEND:
			type = IBT_WRC_SEND;
			break;

		case TAVOR_CQE_SND_RDMARD:
			type = IBT_WRC_RDMAR;
			break;

		case TAVOR_CQE_SND_ATOMIC_CS:
			type = IBT_WRC_CSWAP;
			break;

		case TAVOR_CQE_SND_ATOMIC_FA:
			type = IBT_WRC_FADD;
			break;

		case TAVOR_CQE_SND_BIND_MW:
			type = IBT_WRC_BIND;
			break;

		default:
			TAVOR_WARNING(state, "unknown send CQE type");
			wc->wc_status = IBT_WC_LOCAL_QP_OP_ERR;
			return (TAVOR_CQ_SYNC_AND_DB);
		}
	} else {

		/* Receive CQE */
		switch (opcode & 0x1F) {
		case TAVOR_CQE_RCV_RECV_IMM:
			/* FALLTHROUGH */
		case TAVOR_CQE_RCV_RECV_IMM2:
			/*
			 * Note:  According to the Tavor PRM, all QP1 recv
			 * completions look like the result of a Send with
			 * Immediate.  They are not, however, (MADs are Send
			 * Only) so we need to check the QP number and set
			 * the flag only if it is non-QP1.
			 */
			qpnum	 = TAVOR_CQE_QPNUM_GET(cq, cqe);
			qp1_indx = state->ts_spec_qp1->tr_indx;
			if ((qpnum < qp1_indx) || (qpnum > qp1_indx + 1)) {
				flags |= IBT_WC_IMMED_DATA_PRESENT;
			}
			/* FALLTHROUGH */
		case TAVOR_CQE_RCV_RECV:
			/* FALLTHROUGH */
		case TAVOR_CQE_RCV_RECV2:
			type = IBT_WRC_RECV;
			break;

		case TAVOR_CQE_RCV_RDMAWR_IMM:
			/* FALLTHROUGH */
		case TAVOR_CQE_RCV_RDMAWR_IMM2:
			flags |= IBT_WC_IMMED_DATA_PRESENT;
			type = IBT_WRC_RECV_RDMAWI;
			break;

		default:
			TAVOR_WARNING(state, "unknown recv CQE type");
			wc->wc_status = IBT_WC_LOCAL_QP_OP_ERR;
			return (TAVOR_CQ_SYNC_AND_DB);
		}
	}
	wc->wc_type = type;

	/*
	 * Check for GRH, update the flags, then fill in "wc_flags" field
	 * in the work completion
	 */
	if (TAVOR_CQE_GRH_GET(cq, cqe) != 0) {
		flags |= IBT_WC_GRH_PRESENT;
	}
	wc->wc_flags = flags;

	/* If we got here, completion status must be success */
	wc->wc_status = IBT_WC_SUCCESS;

	/*
	 * Parse the remaining contents of the CQE into the work completion.
	 * This means filling in SL, QP number, SLID, immediate data, etc.
	 * Note:  Not all of these fields are valid in a given completion.
	 * Many of them depend on the actual type of completion.  So we fill
	 * in all of the fields and leave it up to the IBTF and consumer to
	 * sort out which are valid based on their context.
	 */
	wc->wc_sl	  = TAVOR_CQE_SL_GET(cq, cqe);
	wc->wc_immed_data = TAVOR_CQE_IMM_ETH_PKEY_CRED_GET(cq, cqe);
	wc->wc_qpn	  = TAVOR_CQE_DQPN_GET(cq, cqe);
	wc->wc_res_hash	  = 0;
	wc->wc_slid	  = TAVOR_CQE_DLID_GET(cq, cqe);
	wc->wc_ethertype  = (wc->wc_immed_data & 0xFFFF);
	wc->wc_pkey_ix	  = (wc->wc_immed_data >> 16);

	/*
	 * Depending on whether the completion was a receive or a send
	 * completion, fill in "bytes transferred" as appropriate.  Also,
	 * if necessary, fill in the "path bits" field.
	 */
	if (TAVOR_CQE_SENDRECV_GET(cq, cqe) == TAVOR_COMPLETION_RECV) {
		wc->wc_path_bits = TAVOR_CQE_PATHBITS_GET(cq, cqe);
		wc->wc_bytes_xfer = TAVOR_CQE_BYTECNT_GET(cq, cqe);

	} else if ((wc->wc_type == IBT_WRC_RDMAR) ||
	    (wc->wc_type == IBT_WRC_CSWAP) || (wc->wc_type == IBT_WRC_FADD)) {
		wc->wc_bytes_xfer = TAVOR_CQE_BYTECNT_GET(cq, cqe);
	}

	return (TAVOR_CQ_SYNC_AND_DB);
}


/*
 * tavor_cq_errcqe_consume()
 *    Context: Can be called from interrupt or base context.
 */
static int
tavor_cq_errcqe_consume(tavor_state_t *state, tavor_cqhdl_t cq,
    tavor_hw_cqe_t *cqe, ibt_wc_t *wc)
{
	uint64_t		next_wqeaddr;
	uint32_t		imm_eth_pkey_cred;
	uint_t			nextwqesize, dbd;
	uint_t			doorbell_cnt, status;
	tavor_wrid_entry_t	wre;

	/*
	 * Fetch the Work Request ID using the information in the CQE.
	 * See tavor_wr.c for more details.
	 */
	wc->wc_id = tavor_wrid_get_entry(cq, cqe, &wre);

	/*
	 * Parse the CQE opcode to determine completion type.  We know that
	 * the CQE is an error completion, so we extract only the completion
	 * status here.
	 */
	imm_eth_pkey_cred = TAVOR_CQE_IMM_ETH_PKEY_CRED_GET(cq, cqe);
	status = imm_eth_pkey_cred >> TAVOR_CQE_ERR_STATUS_SHIFT;
	switch (status) {
	case TAVOR_CQE_LOC_LEN_ERR:
		status = IBT_WC_LOCAL_LEN_ERR;
		break;

	case TAVOR_CQE_LOC_OP_ERR:
		status = IBT_WC_LOCAL_QP_OP_ERR;
		break;

	case TAVOR_CQE_LOC_PROT_ERR:
		status = IBT_WC_LOCAL_PROTECT_ERR;
		break;

	case TAVOR_CQE_WR_FLUSHED_ERR:
		status = IBT_WC_WR_FLUSHED_ERR;
		break;

	case TAVOR_CQE_MW_BIND_ERR:
		status = IBT_WC_MEM_WIN_BIND_ERR;
		break;

	case TAVOR_CQE_BAD_RESPONSE_ERR:
		status = IBT_WC_BAD_RESPONSE_ERR;
		break;

	case TAVOR_CQE_LOCAL_ACCESS_ERR:
		status = IBT_WC_LOCAL_ACCESS_ERR;
		break;

	case TAVOR_CQE_REM_INV_REQ_ERR:
		status = IBT_WC_REMOTE_INVALID_REQ_ERR;
		break;

	case TAVOR_CQE_REM_ACC_ERR:
		status = IBT_WC_REMOTE_ACCESS_ERR;
		break;

	case TAVOR_CQE_REM_OP_ERR:
		status = IBT_WC_REMOTE_OP_ERR;
		break;

	case TAVOR_CQE_TRANS_TO_ERR:
		status = IBT_WC_TRANS_TIMEOUT_ERR;
		break;

	case TAVOR_CQE_RNRNAK_TO_ERR:
		status = IBT_WC_RNR_NAK_TIMEOUT_ERR;
		break;

	/*
	 * The following error codes are not supported in the Tavor driver
	 * as they relate only to Reliable Datagram completion statuses:
	 *    case TAVOR_CQE_LOCAL_RDD_VIO_ERR:
	 *    case TAVOR_CQE_REM_INV_RD_REQ_ERR:
	 *    case TAVOR_CQE_EEC_REM_ABORTED_ERR:
	 *    case TAVOR_CQE_INV_EEC_NUM_ERR:
	 *    case TAVOR_CQE_INV_EEC_STATE_ERR:
	 *    case TAVOR_CQE_LOC_EEC_ERR:
	 */

	default:
		TAVOR_WARNING(state, "unknown error CQE status");
		status = IBT_WC_LOCAL_QP_OP_ERR;
		break;
	}
	wc->wc_status = status;

	/*
	 * Now we do all the checking that's necessary to handle completion
	 * queue entry "recycling"
	 *
	 * It is not necessary here to try to sync the WQE as we are only
	 * attempting to read from the Work Queue (and hardware does not
	 * write to it).
	 */

	/*
	 * We can get doorbell info, WQE address, size for the next WQE
	 * from the "wre" (which was filled in above in the call to the
	 * tavor_wrid_get_entry() routine)
	 */
	dbd = (wre.wr_signaled_dbd & TAVOR_WRID_ENTRY_DOORBELLED) ? 1 : 0;
	next_wqeaddr = wre.wr_wqeaddrsz;
	nextwqesize  = wre.wr_wqeaddrsz & TAVOR_WQE_NDS_MASK;

	/*
	 * Get the doorbell count from the CQE.  This indicates how many
	 * completions this one CQE represents.
	 */
	doorbell_cnt = imm_eth_pkey_cred & TAVOR_CQE_ERR_DBDCNT_MASK;

	/*
	 * Determine if we're ready to consume this CQE yet or not.  If the
	 * next WQE has size zero (i.e. no next WQE) or if the doorbell count
	 * is down to zero, then this is the last/only completion represented
	 * by the current CQE (return TAVOR_CQ_SYNC_AND_DB).  Otherwise, the
	 * current CQE needs to be recycled (see below).
	 */
	if ((nextwqesize == 0) || ((doorbell_cnt == 0) && (dbd == 1))) {
		/*
		 * Consume the CQE
		 *    Return status to indicate that doorbell and sync may be
		 *    necessary.
		 */
		return (TAVOR_CQ_SYNC_AND_DB);

	} else {
		/*
		 * Recycle the CQE for use in the next PollCQ() call
		 *    Decrement the doorbell count, modify the error status,
		 *    and update the WQE address and size (to point to the
		 *    next WQE on the chain.  Put these update entries back
		 *    into the CQE.
		 *    Despite the fact that we have updated the CQE, it is not
		 *    necessary for us to attempt to sync this entry just yet
		 *    as we have not changed the "hardware's view" of the
		 *    entry (i.e. we have not modified the "owner" bit - which
		 *    is all that the Tavor hardware really cares about.
		 */
		doorbell_cnt = doorbell_cnt - dbd;
		TAVOR_CQE_IMM_ETH_PKEY_CRED_SET(cq, cqe,
		    ((TAVOR_CQE_WR_FLUSHED_ERR << TAVOR_CQE_ERR_STATUS_SHIFT) |
		    (doorbell_cnt & TAVOR_CQE_ERR_DBDCNT_MASK)));
		TAVOR_CQE_WQEADDRSZ_SET(cq, cqe,
		    TAVOR_QP_WQEADDRSZ(next_wqeaddr, nextwqesize));

		return (TAVOR_CQ_RECYCLE_ENTRY);
	}
}


/*
 * tavor_cqe_sync()
 *    Context: Can be called from interrupt or base context.
 */
static void
tavor_cqe_sync(tavor_cqhdl_t cq, tavor_hw_cqe_t *cqe, uint_t flag)
{
	ddi_dma_handle_t	dmahdl;
	off_t			offset;

	/* Determine if CQ needs to be synced or not */
	if (cq->cq_sync == 0)
		return;

	/* Get the DMA handle from CQ context */
	dmahdl = cq->cq_mrhdl->mr_bindinfo.bi_dmahdl;

	/* Calculate offset of next CQE */
	offset = (off_t)((uintptr_t)cqe - (uintptr_t)&cq->cq_buf[0]);
	(void) ddi_dma_sync(dmahdl, offset, sizeof (tavor_hw_cqe_t), flag);
}


/*
 * tavor_cq_resize_helper()
 *    Context: Can be called only from user or kernel context.
 */
static void
tavor_cq_resize_helper(tavor_cqhdl_t cq, tavor_hw_cqe_t *new_cqbuf,
    uint32_t old_cons_indx, uint32_t num_newcqe)
{
	tavor_hw_cqe_t	*old_cqe, *new_cqe;
	uint32_t	new_cons_indx, wrap_around_mask;
	int		i;

	ASSERT(MUTEX_HELD(&cq->cq_lock));

	/* Get the consumer index */
	new_cons_indx = 0;

	/*
	 * Calculate the wrap around mask.  Note: This operation only works
	 * because all Tavor completion queues have power-of-2 sizes
	 */
	wrap_around_mask = (cq->cq_bufsz - 1);

	/*
	 * Calculate the pointers to the first CQ entry (in the "old" CQ)
	 * and the first CQ entry in the "new" CQ
	 */
	old_cqe = &cq->cq_buf[old_cons_indx];
	new_cqe = &new_cqbuf[new_cons_indx];

	/* Sync entire "old" CQ for use by software (if necessary). */
	if (cq->cq_sync) {
		(void) ddi_dma_sync(cq->cq_mrhdl->mr_bindinfo.bi_dmahdl,
		    0, cq->cq_cqinfo.qa_size, DDI_DMA_SYNC_FORCPU);
	}

	/*
	 * Keep pulling entries from the "old" CQ until we find an entry owned
	 * by the hardware.  Process each entry by copying it into the "new"
	 * CQ and updating respective indices and pointers in the "old" CQ.
	 */
	for (i = 0; i < num_newcqe; i++) {

		/* Copy this old CQE into the "new_cqe" pointer */
		bcopy(old_cqe, new_cqe, sizeof (tavor_hw_cqe_t));

		/* Increment the consumer index (for both CQs) */
		old_cons_indx = (old_cons_indx + 1) & wrap_around_mask;
		new_cons_indx = (new_cons_indx + 1);

		/* Update the pointer to the next CQ entry */
		old_cqe = &cq->cq_buf[old_cons_indx];
		new_cqe = &new_cqbuf[new_cons_indx];
	}
}

/*
 * tavor_cq_srq_entries_flush()
 * Context: Can be called from interrupt or base context.
 */
void
tavor_cq_srq_entries_flush(tavor_state_t *state, tavor_qphdl_t qp)
{
	tavor_cqhdl_t		cq;
	tavor_workq_hdr_t	*wqhdr;
	tavor_hw_cqe_t		*cqe;
	tavor_hw_cqe_t		*next_cqe;
	uint32_t		cons_indx, tail_cons_indx, wrap_around_mask;
	uint32_t		new_indx, check_indx, indx;
	uint32_t		num_to_increment;
	int			cqe_qpnum, cqe_type;
	int			outstanding_cqes, removed_cqes;
	int			i;

	ASSERT(MUTEX_HELD(&qp->qp_rq_cqhdl->cq_lock));

	cq = qp->qp_rq_cqhdl;
	wqhdr = qp->qp_rq_wqhdr;

	ASSERT(wqhdr->wq_wrid_post != NULL);
	ASSERT(wqhdr->wq_wrid_post->wl_srq_en != 0);

	/*
	 * Check for user-mapped CQ memory.  Note:  We do not allow kernel
	 * clients to modify any userland mapping CQ.  If the CQ is
	 * user-mapped, then we simply return here, and this "flush" function
	 * becomes a NO-OP in this case.
	 */
	if (cq->cq_is_umap) {
		return;
	}

	/* Get the consumer index */
	cons_indx = cq->cq_consindx;

	/*
	 * Calculate the wrap around mask.  Note: This operation only works
	 * because all Tavor completion queues have power-of-2 sizes
	 */
	wrap_around_mask = (cq->cq_bufsz - 1);

	/* Calculate the pointer to the first CQ entry */
	cqe = &cq->cq_buf[cons_indx];

	/* Sync the current CQE to read */
	tavor_cqe_sync(cq, cqe, DDI_DMA_SYNC_FORCPU);

	/*
	 * Loop through the CQ looking for entries owned by software.  If an
	 * entry is owned by software then we increment an 'outstanding_cqes'
	 * count to know how many entries total we have on our CQ.  We use this
	 * value further down to know how many entries to loop through looking
	 * for our same QP number.
	 */
	outstanding_cqes = 0;
	tail_cons_indx = cons_indx;
	while (TAVOR_CQE_OWNER_IS_SW(cq, cqe)) {
		/* increment total cqes count */
		outstanding_cqes++;

		/* increment the consumer index */
		tail_cons_indx = (tail_cons_indx + 1) & wrap_around_mask;

		/* update the pointer to the next cq entry */
		cqe = &cq->cq_buf[tail_cons_indx];

		/* sync the next cqe to read */
		tavor_cqe_sync(cq, cqe, DDI_DMA_SYNC_FORCPU);
	}

	/*
	 * Using the 'tail_cons_indx' that was just set, we now know how many
	 * total CQEs possible there are.  Set the 'check_indx' and the
	 * 'new_indx' to the last entry identified by 'tail_cons_indx'
	 */
	check_indx = new_indx = (tail_cons_indx - 1) & wrap_around_mask;

	for (i = 0; i < outstanding_cqes; i++) {
		cqe = &cq->cq_buf[check_indx];

		/* Grab QP number from CQE */
		cqe_qpnum = TAVOR_CQE_QPNUM_GET(cq, cqe);
		cqe_type = TAVOR_CQE_SENDRECV_GET(cq, cqe);

		/*
		 * If the QP number is the same in the CQE as the QP that we
		 * have on this SRQ, then we must free up the entry off the
		 * SRQ.  We also make sure that the completion type is of the
		 * 'TAVOR_COMPLETION_RECV' type.  So any send completions on
		 * this CQ will be left as-is.  The handling of returning
		 * entries back to HW ownership happens further down.
		 */
		if (cqe_qpnum == qp->qp_qpnum &&
		    cqe_type == TAVOR_COMPLETION_RECV) {

			/* Add back to SRQ free list */
			(void) tavor_wrid_find_match_srq(wqhdr->wq_wrid_post,
			    cq, cqe);
		} else {
			/* Do Copy */
			if (check_indx != new_indx) {
				next_cqe = &cq->cq_buf[new_indx];

				/*
				 * Copy the CQE into the "next_cqe"
				 * pointer.
				 */
				bcopy(cqe, next_cqe, sizeof (tavor_hw_cqe_t));
			}
			new_indx = (new_indx - 1) & wrap_around_mask;
		}
		/* Move index to next CQE to check */
		check_indx = (check_indx - 1) & wrap_around_mask;
	}

	/* Initialize removed cqes count */
	removed_cqes = 0;

	/* If an entry was removed */
	if (check_indx != new_indx) {

		/*
		 * Set current pointer back to the beginning consumer index.
		 * At this point, all unclaimed entries have been copied to the
		 * index specified by 'new_indx'.  This 'new_indx' will be used
		 * as the new consumer index after we mark all freed entries as
		 * having HW ownership.  We do that here.
		 */

		/* Loop through all entries until we reach our new pointer */
		for (indx = cons_indx; indx <= new_indx;
		    indx = (indx + 1) & wrap_around_mask) {
			removed_cqes++;
			cqe = &cq->cq_buf[indx];

			/* Reset entry to hardware ownership */
			TAVOR_CQE_OWNER_SET_HW(cq, cqe);
		}
	}

	/*
	 * Update consumer index to be the 'new_indx'.  This moves it past all
	 * removed entries.  Because 'new_indx' is pointing to the last
	 * previously valid SW owned entry, we add 1 to point the cons_indx to
	 * the first HW owned entry.
	 */
	cons_indx = (new_indx + 1) & wrap_around_mask;

	/*
	 * Now we only ring the doorbell (to update the consumer index) if
	 * we've actually consumed a CQ entry.  If we found no QP number
	 * matches above, then we would not have removed anything.  So only if
	 * something was removed do we ring the doorbell.
	 */
	if ((removed_cqes != 0) && (cq->cq_consindx != cons_indx)) {
		/*
		 * Post doorbell to update the consumer index.  Doorbell
		 * value indicates number of entries consumed (minus 1)
		 */
		if (cons_indx > cq->cq_consindx) {
			num_to_increment = (cons_indx - cq->cq_consindx) - 1;
		} else {
			num_to_increment = ((cons_indx + cq->cq_bufsz) -
			    cq->cq_consindx) - 1;
		}
		cq->cq_consindx = cons_indx;

		tavor_cq_doorbell(state, TAVOR_CQDB_INCR_CONSINDX,
		    cq->cq_cqnum, num_to_increment);
	}
}
