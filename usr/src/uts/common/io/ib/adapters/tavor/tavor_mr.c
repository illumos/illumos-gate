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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * tavor_mr.c
 *    Tavor Memory Region/Window Routines
 *
 *    Implements all the routines necessary to provide the requisite memory
 *    registration verbs.  These include operations like RegisterMemRegion(),
 *    DeregisterMemRegion(), ReregisterMemRegion, RegisterSharedMemRegion,
 *    etc., that affect Memory Regions.  It also includes the verbs that
 *    affect Memory Windows, including AllocMemWindow(), FreeMemWindow(),
 *    and QueryMemWindow().
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/esunddi.h>

#include <sys/ib/adapters/tavor/tavor.h>


/*
 * Used by tavor_mr_keycalc() below to fill in the "unconstrained" portion
 * of Tavor memory keys (LKeys and RKeys)
 */
static uint_t tavor_debug_memkey_cnt = 0x00000000;

static int tavor_mr_common_reg(tavor_state_t *state, tavor_pdhdl_t pd,
    tavor_bind_info_t *bind, tavor_mrhdl_t *mrhdl, tavor_mr_options_t *op);
static int tavor_mr_common_rereg(tavor_state_t *state, tavor_mrhdl_t mr,
    tavor_pdhdl_t pd, tavor_bind_info_t *bind, tavor_mrhdl_t *mrhdl_new,
    tavor_mr_options_t *op);
static int tavor_mr_rereg_xlat_helper(tavor_state_t *state, tavor_mrhdl_t mr,
    tavor_bind_info_t *bind, tavor_mr_options_t *op, uint64_t *mtt_addr,
    uint_t sleep, uint_t *dereg_level);
static uint64_t tavor_mr_nummtt_needed(tavor_state_t *state,
    tavor_bind_info_t *bind, uint_t *mtt_pgsize);
static int tavor_mr_mem_bind(tavor_state_t *state, tavor_bind_info_t *bind,
    ddi_dma_handle_t dmahdl, uint_t sleep);
static void tavor_mr_mem_unbind(tavor_state_t *state,
    tavor_bind_info_t *bind);
static int tavor_mr_fast_mtt_write(tavor_rsrc_t *mtt, tavor_bind_info_t *bind,
    uint32_t mtt_pgsize_bits);
static int tavor_mtt_refcnt_inc(tavor_rsrc_t *rsrc);
static int tavor_mtt_refcnt_dec(tavor_rsrc_t *rsrc);

/*
 * The Tavor umem_lockmemory() callback ops.  When userland memory is
 * registered, these callback ops are specified.  The tavor_umap_umemlock_cb()
 * callback will be called whenever the memory for the corresponding
 * ddi_umem_cookie_t is being freed.
 */
static struct umem_callback_ops tavor_umem_cbops = {
	UMEM_CALLBACK_VERSION,
	tavor_umap_umemlock_cb,
};


/*
 * tavor_mr_register()
 *    Context: Can be called from interrupt or base context.
 */
int
tavor_mr_register(tavor_state_t *state, tavor_pdhdl_t pd,
    ibt_mr_attr_t *mr_attr, tavor_mrhdl_t *mrhdl, tavor_mr_options_t *op)
{
	tavor_bind_info_t	bind;
	int			status;

	/*
	 * Fill in the "bind" struct.  This struct provides the majority
	 * of the information that will be used to distinguish between an
	 * "addr" binding (as is the case here) and a "buf" binding (see
	 * below).  The "bind" struct is later passed to tavor_mr_mem_bind()
	 * which does most of the "heavy lifting" for the Tavor memory
	 * registration routines.
	 */
	bind.bi_type  = TAVOR_BINDHDL_VADDR;
	bind.bi_addr  = mr_attr->mr_vaddr;
	bind.bi_len   = mr_attr->mr_len;
	bind.bi_as    = mr_attr->mr_as;
	bind.bi_flags = mr_attr->mr_flags;
	status = tavor_mr_common_reg(state, pd, &bind, mrhdl, op);

	return (status);
}


/*
 * tavor_mr_register_buf()
 *    Context: Can be called from interrupt or base context.
 */
int
tavor_mr_register_buf(tavor_state_t *state, tavor_pdhdl_t pd,
    ibt_smr_attr_t *mr_attr, struct buf *buf, tavor_mrhdl_t *mrhdl,
    tavor_mr_options_t *op)
{
	tavor_bind_info_t	bind;
	int			status;

	/*
	 * Fill in the "bind" struct.  This struct provides the majority
	 * of the information that will be used to distinguish between an
	 * "addr" binding (see above) and a "buf" binding (as is the case
	 * here).  The "bind" struct is later passed to tavor_mr_mem_bind()
	 * which does most of the "heavy lifting" for the Tavor memory
	 * registration routines.  Note: We have chosen to provide
	 * "b_un.b_addr" as the IB address (when the IBT_MR_PHYS_IOVA flag is
	 * not set).  It is not critical what value we choose here as it need
	 * only be unique for the given RKey (which will happen by default),
	 * so the choice here is somewhat arbitrary.
	 */
	bind.bi_type  = TAVOR_BINDHDL_BUF;
	bind.bi_buf   = buf;
	if (mr_attr->mr_flags & IBT_MR_PHYS_IOVA) {
		bind.bi_addr  = mr_attr->mr_vaddr;
	} else {
		bind.bi_addr  = (uint64_t)(uintptr_t)buf->b_un.b_addr;
	}
	bind.bi_as    = NULL;
	bind.bi_len   = (uint64_t)buf->b_bcount;
	bind.bi_flags = mr_attr->mr_flags;
	status = tavor_mr_common_reg(state, pd, &bind, mrhdl, op);

	return (status);
}


/*
 * tavor_mr_register_shared()
 *    Context: Can be called from interrupt or base context.
 */
int
tavor_mr_register_shared(tavor_state_t *state, tavor_mrhdl_t mrhdl,
    tavor_pdhdl_t pd, ibt_smr_attr_t *mr_attr, tavor_mrhdl_t *mrhdl_new)
{
	tavor_rsrc_pool_info_t	*rsrc_pool;
	tavor_rsrc_t		*mpt, *mtt, *rsrc;
	tavor_umap_db_entry_t	*umapdb;
	tavor_hw_mpt_t		mpt_entry;
	tavor_mrhdl_t		mr;
	tavor_bind_info_t	*bind;
	ddi_umem_cookie_t	umem_cookie;
	size_t			umem_len;
	caddr_t			umem_addr;
	uint64_t		mtt_addr, mtt_ddrbaseaddr, pgsize_msk;
	uint_t			sleep, mr_is_umem;
	int			status, umem_flags;

	/*
	 * Check the sleep flag.  Ensure that it is consistent with the
	 * current thread context (i.e. if we are currently in the interrupt
	 * context, then we shouldn't be attempting to sleep).
	 */
	sleep = (mr_attr->mr_flags & IBT_MR_NOSLEEP) ? TAVOR_NOSLEEP :
	    TAVOR_SLEEP;
	if ((sleep == TAVOR_SLEEP) &&
	    (sleep != TAVOR_SLEEPFLAG_FOR_CONTEXT())) {
		goto mrshared_fail;
	}

	/* Increment the reference count on the protection domain (PD) */
	tavor_pd_refcnt_inc(pd);

	/*
	 * Allocate an MPT entry.  This will be filled in with all the
	 * necessary parameters to define the shared memory region.
	 * Specifically, it will be made to reference the currently existing
	 * MTT entries and ownership of the MPT will be passed to the hardware
	 * in the last step below.  If we fail here, we must undo the
	 * protection domain reference count.
	 */
	status = tavor_rsrc_alloc(state, TAVOR_MPT, 1, sleep, &mpt);
	if (status != DDI_SUCCESS) {
		goto mrshared_fail1;
	}

	/*
	 * Allocate the software structure for tracking the shared memory
	 * region (i.e. the Tavor Memory Region handle).  If we fail here, we
	 * must undo the protection domain reference count and the previous
	 * resource allocation.
	 */
	status = tavor_rsrc_alloc(state, TAVOR_MRHDL, 1, sleep, &rsrc);
	if (status != DDI_SUCCESS) {
		goto mrshared_fail2;
	}
	mr = (tavor_mrhdl_t)rsrc->tr_addr;
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*mr))

	/*
	 * Setup and validate the memory region access flags.  This means
	 * translating the IBTF's enable flags into the access flags that
	 * will be used in later operations.
	 */
	mr->mr_accflag = 0;
	if (mr_attr->mr_flags & IBT_MR_ENABLE_WINDOW_BIND)
		mr->mr_accflag |= IBT_MR_WINDOW_BIND;
	if (mr_attr->mr_flags & IBT_MR_ENABLE_LOCAL_WRITE)
		mr->mr_accflag |= IBT_MR_LOCAL_WRITE;
	if (mr_attr->mr_flags & IBT_MR_ENABLE_REMOTE_READ)
		mr->mr_accflag |= IBT_MR_REMOTE_READ;
	if (mr_attr->mr_flags & IBT_MR_ENABLE_REMOTE_WRITE)
		mr->mr_accflag |= IBT_MR_REMOTE_WRITE;
	if (mr_attr->mr_flags & IBT_MR_ENABLE_REMOTE_ATOMIC)
		mr->mr_accflag |= IBT_MR_REMOTE_ATOMIC;

	/*
	 * Calculate keys (Lkey, Rkey) from MPT index.  Each key is formed
	 * from a certain number of "constrained" bits (the least significant
	 * bits) and some number of "unconstrained" bits.  The constrained
	 * bits must be set to the index of the entry in the MPT table, but
	 * the unconstrained bits can be set to any value we wish.  Note:
	 * if no remote access is required, then the RKey value is not filled
	 * in.  Otherwise both Rkey and LKey are given the same value.
	 */
	tavor_mr_keycalc(state, mpt->tr_indx, &mr->mr_lkey);
	if ((mr->mr_accflag & IBT_MR_REMOTE_READ) ||
	    (mr->mr_accflag & IBT_MR_REMOTE_WRITE) ||
	    (mr->mr_accflag & IBT_MR_REMOTE_ATOMIC)) {
		mr->mr_rkey = mr->mr_lkey;
	}

	/* Grab the MR lock for the current memory region */
	mutex_enter(&mrhdl->mr_lock);

	/*
	 * Check here to see if the memory region has already been partially
	 * deregistered as a result of a tavor_umap_umemlock_cb() callback.
	 * If so, this is an error, return failure.
	 */
	if ((mrhdl->mr_is_umem) && (mrhdl->mr_umemcookie == NULL)) {
		mutex_exit(&mrhdl->mr_lock);
		goto mrshared_fail3;
	}

	/*
	 * Determine if the original memory was from userland and, if so, pin
	 * the pages (again) with umem_lockmemory().  This will guarantee a
	 * separate callback for each of this shared region's MR handles.
	 * If this is userland memory, then allocate an entry in the
	 * "userland resources database".  This will later be added to
	 * the database (after all further memory registration operations are
	 * successful).  If we fail here, we must undo all the above setup.
	 */
	mr_is_umem = mrhdl->mr_is_umem;
	if (mr_is_umem) {
		umem_len   = ptob(btopr(mrhdl->mr_bindinfo.bi_len +
		    ((uintptr_t)mrhdl->mr_bindinfo.bi_addr & PAGEOFFSET)));
		umem_addr  = (caddr_t)((uintptr_t)mrhdl->mr_bindinfo.bi_addr &
		    ~PAGEOFFSET);
		umem_flags = (DDI_UMEMLOCK_WRITE | DDI_UMEMLOCK_READ |
		    DDI_UMEMLOCK_LONGTERM);
		status = umem_lockmemory(umem_addr, umem_len, umem_flags,
		    &umem_cookie, &tavor_umem_cbops, NULL);
		if (status != 0) {
			mutex_exit(&mrhdl->mr_lock);
			goto mrshared_fail3;
		}

		umapdb = tavor_umap_db_alloc(state->ts_instance,
		    (uint64_t)(uintptr_t)umem_cookie, MLNX_UMAP_MRMEM_RSRC,
		    (uint64_t)(uintptr_t)rsrc);
		if (umapdb == NULL) {
			mutex_exit(&mrhdl->mr_lock);
			goto mrshared_fail4;
		}
	}

	/*
	 * Copy the MTT resource pointer (and additional parameters) from
	 * the original Tavor Memory Region handle.  Note: this is normally
	 * where the tavor_mr_mem_bind() routine would be called, but because
	 * we already have bound and filled-in MTT entries it is simply a
	 * matter here of managing the MTT reference count and grabbing the
	 * address of the MTT table entries (for filling in the shared region's
	 * MPT entry).
	 */
	mr->mr_mttrsrcp	  = mrhdl->mr_mttrsrcp;
	mr->mr_logmttpgsz = mrhdl->mr_logmttpgsz;
	mr->mr_bindinfo	  = mrhdl->mr_bindinfo;
	mr->mr_mttrefcntp = mrhdl->mr_mttrefcntp;
	mutex_exit(&mrhdl->mr_lock);
	bind = &mr->mr_bindinfo;
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*bind))
	mtt = mr->mr_mttrsrcp;

	/*
	 * Increment the MTT reference count (to reflect the fact that
	 * the MTT is now shared)
	 */
	(void) tavor_mtt_refcnt_inc(mr->mr_mttrefcntp);

	/*
	 * Update the new "bind" virtual address.  Do some extra work here
	 * to ensure proper alignment.  That is, make sure that the page
	 * offset for the beginning of the old range is the same as the
	 * offset for this new mapping
	 */
	pgsize_msk = (((uint64_t)1 << mr->mr_logmttpgsz) - 1);
	bind->bi_addr = ((mr_attr->mr_vaddr & ~pgsize_msk) |
	    (mr->mr_bindinfo.bi_addr & pgsize_msk));

	/*
	 * Get the base address for the MTT table.  This will be necessary
	 * in the next step when we are setting up the MPT entry.
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
	mpt_entry.m_io	  = TAVOR_MEM_CYCLE_GENERATE;
	mpt_entry.en_bind = (mr->mr_accflag & IBT_MR_WINDOW_BIND)   ? 1 : 0;
	mpt_entry.atomic  = (mr->mr_accflag & IBT_MR_REMOTE_ATOMIC) ? 1 : 0;
	mpt_entry.rw	  = (mr->mr_accflag & IBT_MR_REMOTE_WRITE)  ? 1 : 0;
	mpt_entry.rr	  = (mr->mr_accflag & IBT_MR_REMOTE_READ)   ? 1 : 0;
	mpt_entry.lw	  = (mr->mr_accflag & IBT_MR_LOCAL_WRITE)   ? 1 : 0;
	mpt_entry.lr	  = 1;
	mpt_entry.reg_win = TAVOR_MPT_IS_REGION;
	mpt_entry.page_sz	= mr->mr_logmttpgsz - 0xC;
	mpt_entry.mem_key	= mr->mr_lkey;
	mpt_entry.pd		= pd->pd_pdnum;
	mpt_entry.start_addr	= bind->bi_addr;
	mpt_entry.reg_win_len	= bind->bi_len;
	mpt_entry.win_cnt_limit	= TAVOR_UNLIMITED_WIN_BIND;
	mtt_addr = mtt_ddrbaseaddr + (mtt->tr_indx << TAVOR_MTT_SIZE_SHIFT);
	mpt_entry.mttseg_addr_h = mtt_addr >> 32;
	mpt_entry.mttseg_addr_l = mtt_addr >> 6;

	/*
	 * Write the MPT entry to hardware.  Lastly, we pass ownership of
	 * the entry to the hardware.  Note: in general, this operation
	 * shouldn't fail.  But if it does, we have to undo everything we've
	 * done above before returning error.
	 */
	status = tavor_cmn_ownership_cmd_post(state, SW2HW_MPT, &mpt_entry,
	    sizeof (tavor_hw_mpt_t), mpt->tr_indx, sleep);
	if (status != TAVOR_CMD_SUCCESS) {
		cmn_err(CE_CONT, "Tavor: SW2HW_MPT command failed: %08x\n",
		    status);
		goto mrshared_fail5;
	}

	/*
	 * Fill in the rest of the Tavor Memory Region handle.  Having
	 * successfully transferred ownership of the MPT, we can update the
	 * following fields for use in further operations on the MR.
	 */
	mr->mr_mptrsrcp	  = mpt;
	mr->mr_mttrsrcp	  = mtt;
	mr->mr_pdhdl	  = pd;
	mr->mr_rsrcp	  = rsrc;
	mr->mr_is_umem	  = mr_is_umem;
	mr->mr_umemcookie = (mr_is_umem != 0) ? umem_cookie : NULL;
	mr->mr_umem_cbfunc = NULL;
	mr->mr_umem_cbarg1 = NULL;
	mr->mr_umem_cbarg2 = NULL;

	/*
	 * If this is userland memory, then we need to insert the previously
	 * allocated entry into the "userland resources database".  This will
	 * allow for later coordination between the tavor_umap_umemlock_cb()
	 * callback and tavor_mr_deregister().
	 */
	if (mr_is_umem) {
		tavor_umap_db_add(umapdb);
	}

	*mrhdl_new = mr;

	return (DDI_SUCCESS);

/*
 * The following is cleanup for all possible failure cases in this routine
 */
mrshared_fail5:
	(void) tavor_mtt_refcnt_dec(mr->mr_mttrefcntp);
	if (mr_is_umem) {
		tavor_umap_db_free(umapdb);
	}
mrshared_fail4:
	if (mr_is_umem) {
		ddi_umem_unlock(umem_cookie);
	}
mrshared_fail3:
	tavor_rsrc_free(state, &rsrc);
mrshared_fail2:
	tavor_rsrc_free(state, &mpt);
mrshared_fail1:
	tavor_pd_refcnt_dec(pd);
mrshared_fail:
	return (status);
}


/*
 * tavor_mr_deregister()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
int
tavor_mr_deregister(tavor_state_t *state, tavor_mrhdl_t *mrhdl, uint_t level,
    uint_t sleep)
{
	tavor_rsrc_t		*mpt, *mtt, *rsrc, *mtt_refcnt;
	tavor_umap_db_entry_t	*umapdb;
	tavor_pdhdl_t		pd;
	tavor_mrhdl_t		mr;
	tavor_bind_info_t	*bind;
	uint64_t		value;
	int			status, shared_mtt;

	/*
	 * Check the sleep flag.  Ensure that it is consistent with the
	 * current thread context (i.e. if we are currently in the interrupt
	 * context, then we shouldn't be attempting to sleep).
	 */
	if ((sleep == TAVOR_SLEEP) &&
	    (sleep != TAVOR_SLEEPFLAG_FOR_CONTEXT())) {
		return (status);
	}

	/*
	 * Pull all the necessary information from the Tavor Memory Region
	 * handle.  This is necessary here because the resource for the
	 * MR handle is going to be freed up as part of the this
	 * deregistration
	 */
	mr	= *mrhdl;
	mutex_enter(&mr->mr_lock);
	mpt	= mr->mr_mptrsrcp;
	mtt	= mr->mr_mttrsrcp;
	mtt_refcnt = mr->mr_mttrefcntp;
	rsrc	= mr->mr_rsrcp;
	pd	= mr->mr_pdhdl;
	bind	= &mr->mr_bindinfo;

	/*
	 * Check here to see if the memory region has already been partially
	 * deregistered as a result of the tavor_umap_umemlock_cb() callback.
	 * If so, then jump to the end and free the remaining resources.
	 */
	if ((mr->mr_is_umem) && (mr->mr_umemcookie == NULL)) {
		goto mrdereg_finish_cleanup;
	}

	/*
	 * We must drop the "mr_lock" here to ensure that both SLEEP and
	 * NOSLEEP calls into the firmware work as expected.  Also, if two
	 * threads are attemping to access this MR (via de-register,
	 * re-register, or otherwise), then we allow the firmware to enforce
	 * the checking, that only one deregister is valid.
	 */
	mutex_exit(&mr->mr_lock);

	/*
	 * Reclaim MPT entry from hardware (if necessary).  Since the
	 * tavor_mr_deregister() routine is used in the memory region
	 * reregistration process as well, it is possible that we will
	 * not always wish to reclaim ownership of the MPT.  Check the
	 * "level" arg and, if necessary, attempt to reclaim it.  If
	 * the ownership transfer fails for any reason, we check to see
	 * what command status was returned from the hardware.  The only
	 * "expected" error status is the one that indicates an attempt to
	 * deregister a memory region that has memory windows bound to it
	 */
	if (level >= TAVOR_MR_DEREG_ALL) {
		status = tavor_cmn_ownership_cmd_post(state, HW2SW_MPT,
		    NULL, 0, mpt->tr_indx, sleep);
		if (status != TAVOR_CMD_SUCCESS) {
			if (status == TAVOR_CMD_REG_BOUND) {
				return (IBT_MR_IN_USE);
			} else {
				cmn_err(CE_CONT, "Tavor: HW2SW_MPT command "
				    "failed: %08x\n", status);
				return (IBT_INVALID_PARAM);
			}
		}
	}

	/*
	 * Re-grab the mr_lock here.  Since further access to the protected
	 * 'mr' structure is needed, and we would have returned previously for
	 * the multiple deregistration case, we can safely grab the lock here.
	 */
	mutex_enter(&mr->mr_lock);

	/*
	 * If the memory had come from userland, then we do a lookup in the
	 * "userland resources database".  On success, we free the entry, call
	 * ddi_umem_unlock(), and continue the cleanup.  On failure (which is
	 * an indication that the umem_lockmemory() callback has called
	 * tavor_mr_deregister()), we call ddi_umem_unlock() and invalidate
	 * the "mr_umemcookie" field in the MR handle (this will be used
	 * later to detect that only partial cleaup still remains to be done
	 * on the MR handle).
	 */
	if (mr->mr_is_umem) {
		status = tavor_umap_db_find(state->ts_instance,
		    (uint64_t)(uintptr_t)mr->mr_umemcookie,
		    MLNX_UMAP_MRMEM_RSRC, &value, TAVOR_UMAP_DB_REMOVE,
		    &umapdb);
		if (status == DDI_SUCCESS) {
			tavor_umap_db_free(umapdb);
			ddi_umem_unlock(mr->mr_umemcookie);
		} else {
			ddi_umem_unlock(mr->mr_umemcookie);
			mr->mr_umemcookie = NULL;
		}
	}

	/* mtt_refcnt is NULL in the case of tavor_dma_mr_register() */
	if (mtt_refcnt != NULL) {
		/*
		 * Decrement the MTT reference count.  Since the MTT resource
		 * may be shared between multiple memory regions (as a result
		 * of a "RegisterSharedMR" verb) it is important that we not
		 * free up or unbind resources prematurely.  If it's not shared
		 * (as indicated by the return status), then free the resource.
		 */
		shared_mtt = tavor_mtt_refcnt_dec(mtt_refcnt);
		if (!shared_mtt) {
			tavor_rsrc_free(state, &mtt_refcnt);
		}

		/*
		 * Free up the MTT entries and unbind the memory.  Here,
		 * as above, we attempt to free these resources only if
		 * it is appropriate to do so.
		 */
		if (!shared_mtt) {
			if (level >= TAVOR_MR_DEREG_NO_HW2SW_MPT) {
				tavor_mr_mem_unbind(state, bind);
			}
			tavor_rsrc_free(state, &mtt);
		}
	}

	/*
	 * If the MR handle has been invalidated, then drop the
	 * lock and return success.  Note: This only happens because
	 * the umem_lockmemory() callback has been triggered.  The
	 * cleanup here is partial, and further cleanup (in a
	 * subsequent tavor_mr_deregister() call) will be necessary.
	 */
	if ((mr->mr_is_umem) && (mr->mr_umemcookie == NULL)) {
		mutex_exit(&mr->mr_lock);
		return (DDI_SUCCESS);
	}

mrdereg_finish_cleanup:
	mutex_exit(&mr->mr_lock);

	/* Free the Tavor Memory Region handle */
	tavor_rsrc_free(state, &rsrc);

	/* Free up the MPT entry resource */
	tavor_rsrc_free(state, &mpt);

	/* Decrement the reference count on the protection domain (PD) */
	tavor_pd_refcnt_dec(pd);

	/* Set the mrhdl pointer to NULL and return success */
	*mrhdl = NULL;

	return (DDI_SUCCESS);
}


/*
 * tavor_mr_query()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
int
tavor_mr_query(tavor_state_t *state, tavor_mrhdl_t mr,
    ibt_mr_query_attr_t *attr)
{
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*attr))

	mutex_enter(&mr->mr_lock);

	/*
	 * Check here to see if the memory region has already been partially
	 * deregistered as a result of a tavor_umap_umemlock_cb() callback.
	 * If so, this is an error, return failure.
	 */
	if ((mr->mr_is_umem) && (mr->mr_umemcookie == NULL)) {
		mutex_exit(&mr->mr_lock);
		return (IBT_MR_HDL_INVALID);
	}

	/* Fill in the queried attributes */
	attr->mr_attr_flags = mr->mr_accflag;
	attr->mr_pd	= (ibt_pd_hdl_t)mr->mr_pdhdl;

	/* Fill in the "local" attributes */
	attr->mr_lkey = (ibt_lkey_t)mr->mr_lkey;
	attr->mr_lbounds.pb_addr = (ib_vaddr_t)mr->mr_bindinfo.bi_addr;
	attr->mr_lbounds.pb_len  = (size_t)mr->mr_bindinfo.bi_len;

	/*
	 * Fill in the "remote" attributes (if necessary).  Note: the
	 * remote attributes are only valid if the memory region has one
	 * or more of the remote access flags set.
	 */
	if ((mr->mr_accflag & IBT_MR_REMOTE_READ) ||
	    (mr->mr_accflag & IBT_MR_REMOTE_WRITE) ||
	    (mr->mr_accflag & IBT_MR_REMOTE_ATOMIC)) {
		attr->mr_rkey = (ibt_rkey_t)mr->mr_rkey;
		attr->mr_rbounds.pb_addr = (ib_vaddr_t)mr->mr_bindinfo.bi_addr;
		attr->mr_rbounds.pb_len  = (size_t)mr->mr_bindinfo.bi_len;
	}

	/*
	 * If region is mapped for streaming (i.e. noncoherent), then set sync
	 * is required
	 */
	attr->mr_sync_required = (mr->mr_bindinfo.bi_flags &
	    IBT_MR_NONCOHERENT) ? B_TRUE : B_FALSE;

	mutex_exit(&mr->mr_lock);
	return (DDI_SUCCESS);
}


/*
 * tavor_mr_reregister()
 *    Context: Can be called from interrupt or base context.
 */
int
tavor_mr_reregister(tavor_state_t *state, tavor_mrhdl_t mr,
    tavor_pdhdl_t pd, ibt_mr_attr_t *mr_attr, tavor_mrhdl_t *mrhdl_new,
    tavor_mr_options_t *op)
{
	tavor_bind_info_t	bind;
	int			status;

	/*
	 * Fill in the "bind" struct.  This struct provides the majority
	 * of the information that will be used to distinguish between an
	 * "addr" binding (as is the case here) and a "buf" binding (see
	 * below).  The "bind" struct is later passed to tavor_mr_mem_bind()
	 * which does most of the "heavy lifting" for the Tavor memory
	 * registration (and reregistration) routines.
	 */
	bind.bi_type  = TAVOR_BINDHDL_VADDR;
	bind.bi_addr  = mr_attr->mr_vaddr;
	bind.bi_len   = mr_attr->mr_len;
	bind.bi_as    = mr_attr->mr_as;
	bind.bi_flags = mr_attr->mr_flags;
	status = tavor_mr_common_rereg(state, mr, pd, &bind, mrhdl_new, op);

	return (status);
}


/*
 * tavor_mr_reregister_buf()
 *    Context: Can be called from interrupt or base context.
 */
int
tavor_mr_reregister_buf(tavor_state_t *state, tavor_mrhdl_t mr,
    tavor_pdhdl_t pd, ibt_smr_attr_t *mr_attr, struct buf *buf,
    tavor_mrhdl_t *mrhdl_new, tavor_mr_options_t *op)
{
	tavor_bind_info_t	bind;
	int			status;

	/*
	 * Fill in the "bind" struct.  This struct provides the majority
	 * of the information that will be used to distinguish between an
	 * "addr" binding (see above) and a "buf" binding (as is the case
	 * here).  The "bind" struct is later passed to tavor_mr_mem_bind()
	 * which does most of the "heavy lifting" for the Tavor memory
	 * registration routines.  Note: We have chosen to provide
	 * "b_un.b_addr" as the IB address (when the IBT_MR_PHYS_IOVA flag is
	 * not set).  It is not critical what value we choose here as it need
	 * only be unique for the given RKey (which will happen by default),
	 * so the choice here is somewhat arbitrary.
	 */
	bind.bi_type  = TAVOR_BINDHDL_BUF;
	bind.bi_buf   = buf;
	if (mr_attr->mr_flags & IBT_MR_PHYS_IOVA) {
		bind.bi_addr  = mr_attr->mr_vaddr;
	} else {
		bind.bi_addr  = (uint64_t)(uintptr_t)buf->b_un.b_addr;
	}
	bind.bi_len   = (uint64_t)buf->b_bcount;
	bind.bi_flags = mr_attr->mr_flags;
	bind.bi_as = NULL;
	status = tavor_mr_common_rereg(state, mr, pd, &bind, mrhdl_new, op);

	return (status);
}


/*
 * tavor_mr_sync()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
int
tavor_mr_sync(tavor_state_t *state, ibt_mr_sync_t *mr_segs, size_t num_segs)
{
	tavor_mrhdl_t		mrhdl;
	uint64_t		seg_vaddr, seg_len, seg_end;
	uint64_t		mr_start, mr_end;
	uint_t			type;
	int			status, i;

	/* Process each of the ibt_mr_sync_t's */
	for (i = 0; i < num_segs; i++) {
		mrhdl = (tavor_mrhdl_t)mr_segs[i].ms_handle;

		/* Check for valid memory region handle */
		if (mrhdl == NULL) {
			goto mrsync_fail;
		}

		mutex_enter(&mrhdl->mr_lock);

		/*
		 * Check here to see if the memory region has already been
		 * partially deregistered as a result of a
		 * tavor_umap_umemlock_cb() callback.  If so, this is an
		 * error, return failure.
		 */
		if ((mrhdl->mr_is_umem) && (mrhdl->mr_umemcookie == NULL)) {
			mutex_exit(&mrhdl->mr_lock);
			goto mrsync_fail;
		}

		/* Check for valid bounds on sync request */
		seg_vaddr = mr_segs[i].ms_vaddr;
		seg_len	  = mr_segs[i].ms_len;
		seg_end	  = seg_vaddr + seg_len - 1;
		mr_start  = mrhdl->mr_bindinfo.bi_addr;
		mr_end	  = mr_start + mrhdl->mr_bindinfo.bi_len - 1;
		if ((seg_vaddr < mr_start) || (seg_vaddr > mr_end)) {
			mutex_exit(&mrhdl->mr_lock);
			goto mrsync_fail;
		}
		if ((seg_end < mr_start) || (seg_end > mr_end)) {
			mutex_exit(&mrhdl->mr_lock);
			goto mrsync_fail;
		}

		/* Determine what type (i.e. direction) for sync */
		if (mr_segs[i].ms_flags & IBT_SYNC_READ) {
			type = DDI_DMA_SYNC_FORDEV;
		} else if (mr_segs[i].ms_flags & IBT_SYNC_WRITE) {
			type = DDI_DMA_SYNC_FORCPU;
		} else {
			mutex_exit(&mrhdl->mr_lock);
			goto mrsync_fail;
		}

		(void) ddi_dma_sync(mrhdl->mr_bindinfo.bi_dmahdl,
		    (off_t)(seg_vaddr - mr_start), (size_t)seg_len, type);
		mutex_exit(&mrhdl->mr_lock);
	}

	return (DDI_SUCCESS);

mrsync_fail:
	return (status);
}


/*
 * tavor_mw_alloc()
 *    Context: Can be called from interrupt or base context.
 */
int
tavor_mw_alloc(tavor_state_t *state, tavor_pdhdl_t pd, ibt_mw_flags_t flags,
    tavor_mwhdl_t *mwhdl)
{
	tavor_rsrc_t		*mpt, *rsrc;
	tavor_hw_mpt_t		mpt_entry;
	tavor_mwhdl_t		mw;
	uint_t			sleep;
	int			status;

	/*
	 * Check the sleep flag.  Ensure that it is consistent with the
	 * current thread context (i.e. if we are currently in the interrupt
	 * context, then we shouldn't be attempting to sleep).
	 */
	sleep = (flags & IBT_MW_NOSLEEP) ? TAVOR_NOSLEEP : TAVOR_SLEEP;
	if ((sleep == TAVOR_SLEEP) &&
	    (sleep != TAVOR_SLEEPFLAG_FOR_CONTEXT())) {
		goto mwalloc_fail;
	}

	/* Increment the reference count on the protection domain (PD) */
	tavor_pd_refcnt_inc(pd);

	/*
	 * Allocate an MPT entry (for use as a memory window).  Since the
	 * Tavor hardware uses the MPT entry for memory regions and for
	 * memory windows, we will fill in this MPT with all the necessary
	 * parameters for the memory window.  And then (just as we do for
	 * memory regions) ownership will be passed to the hardware in the
	 * final step below.  If we fail here, we must undo the protection
	 * domain reference count.
	 */
	status = tavor_rsrc_alloc(state, TAVOR_MPT, 1, sleep, &mpt);
	if (status != DDI_SUCCESS) {
		goto mwalloc_fail1;
	}

	/*
	 * Allocate the software structure for tracking the memory window (i.e.
	 * the Tavor Memory Window handle).  Note: This is actually the same
	 * software structure used for tracking memory regions, but since many
	 * of the same properties are needed, only a single structure is
	 * necessary.  If we fail here, we must undo the protection domain
	 * reference count and the previous resource allocation.
	 */
	status = tavor_rsrc_alloc(state, TAVOR_MRHDL, 1, sleep, &rsrc);
	if (status != DDI_SUCCESS) {
		goto mwalloc_fail2;
	}
	mw = (tavor_mwhdl_t)rsrc->tr_addr;
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*mw))

	/*
	 * Calculate an "unbound" RKey from MPT index.  In much the same way
	 * as we do for memory regions (above), this key is constructed from
	 * a "constrained" (which depends on the MPT index) and an
	 * "unconstrained" portion (which may be arbitrarily chosen).
	 */
	tavor_mr_keycalc(state, mpt->tr_indx, &mw->mr_rkey);

	/*
	 * Fill in the MPT entry.  This is the final step before passing
	 * ownership of the MPT entry to the Tavor hardware.  We use all of
	 * the information collected/calculated above to fill in the
	 * requisite portions of the MPT.  Note: fewer entries in the MPT
	 * entry are necessary to allocate a memory window.
	 */
	bzero(&mpt_entry, sizeof (tavor_hw_mpt_t));
	mpt_entry.reg_win	= TAVOR_MPT_IS_WINDOW;
	mpt_entry.mem_key	= mw->mr_rkey;
	mpt_entry.pd		= pd->pd_pdnum;

	/*
	 * Write the MPT entry to hardware.  Lastly, we pass ownership of
	 * the entry to the hardware.  Note: in general, this operation
	 * shouldn't fail.  But if it does, we have to undo everything we've
	 * done above before returning error.
	 */
	status = tavor_cmn_ownership_cmd_post(state, SW2HW_MPT, &mpt_entry,
	    sizeof (tavor_hw_mpt_t), mpt->tr_indx, sleep);
	if (status != TAVOR_CMD_SUCCESS) {
		cmn_err(CE_CONT, "Tavor: SW2HW_MPT command failed: %08x\n",
		    status);
		goto mwalloc_fail3;
	}

	/*
	 * Fill in the rest of the Tavor Memory Window handle.  Having
	 * successfully transferred ownership of the MPT, we can update the
	 * following fields for use in further operations on the MW.
	 */
	mw->mr_mptrsrcp	= mpt;
	mw->mr_pdhdl	= pd;
	mw->mr_rsrcp	= rsrc;
	*mwhdl = mw;

	return (DDI_SUCCESS);

mwalloc_fail3:
	tavor_rsrc_free(state, &rsrc);
mwalloc_fail2:
	tavor_rsrc_free(state, &mpt);
mwalloc_fail1:
	tavor_pd_refcnt_dec(pd);
mwalloc_fail:
	return (status);
}


/*
 * tavor_mw_free()
 *    Context: Can be called from interrupt or base context.
 */
int
tavor_mw_free(tavor_state_t *state, tavor_mwhdl_t *mwhdl, uint_t sleep)
{
	tavor_rsrc_t		*mpt, *rsrc;
	tavor_mwhdl_t		mw;
	int			status;
	tavor_pdhdl_t		pd;

	/*
	 * Check the sleep flag.  Ensure that it is consistent with the
	 * current thread context (i.e. if we are currently in the interrupt
	 * context, then we shouldn't be attempting to sleep).
	 */
	if ((sleep == TAVOR_SLEEP) &&
	    (sleep != TAVOR_SLEEPFLAG_FOR_CONTEXT())) {
		return (status);
	}

	/*
	 * Pull all the necessary information from the Tavor Memory Window
	 * handle.  This is necessary here because the resource for the
	 * MW handle is going to be freed up as part of the this operation.
	 */
	mw	= *mwhdl;
	mutex_enter(&mw->mr_lock);
	mpt	= mw->mr_mptrsrcp;
	rsrc	= mw->mr_rsrcp;
	pd	= mw->mr_pdhdl;
	mutex_exit(&mw->mr_lock);
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*mw))

	/*
	 * Reclaim the MPT entry from hardware.  Note: in general, it is
	 * unexpected for this operation to return an error.
	 */
	status = tavor_cmn_ownership_cmd_post(state, HW2SW_MPT, NULL,
	    0, mpt->tr_indx, sleep);
	if (status != TAVOR_CMD_SUCCESS) {
		cmn_err(CE_CONT, "Tavor: HW2SW_MPT command failed: %08x\n",
		    status);
		return (IBT_INVALID_PARAM);
	}

	/* Free the Tavor Memory Window handle */
	tavor_rsrc_free(state, &rsrc);

	/* Free up the MPT entry resource */
	tavor_rsrc_free(state, &mpt);

	/* Decrement the reference count on the protection domain (PD) */
	tavor_pd_refcnt_dec(pd);

	/* Set the mwhdl pointer to NULL and return success */
	*mwhdl = NULL;

	return (DDI_SUCCESS);
}


/*
 * tavor_mr_keycalc()
 *    Context: Can be called from interrupt or base context.
 */
void
tavor_mr_keycalc(tavor_state_t *state, uint32_t indx, uint32_t *key)
{
	uint32_t	tmp, log_num_mpt;

	/*
	 * Generate a simple key from counter.  Note:  We increment this
	 * static variable _intentionally_ without any kind of mutex around
	 * it.  First, single-threading all operations through a single lock
	 * would be a bad idea (from a performance point-of-view).  Second,
	 * the upper "unconstrained" bits don't really have to be unique
	 * because the lower bits are guaranteed to be (although we do make a
	 * best effort to ensure that they are).  Third, the window for the
	 * race (where both threads read and update the counter at the same
	 * time) is incredibly small.
	 * And, lastly, we'd like to make this into a "random" key XXX
	 */
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(tavor_debug_memkey_cnt))
	log_num_mpt = state->ts_cfg_profile->cp_log_num_mpt;
	tmp = (tavor_debug_memkey_cnt++) << log_num_mpt;
	*key = tmp | indx;
}


/*
 * tavor_mr_common_reg()
 *    Context: Can be called from interrupt or base context.
 */
static int
tavor_mr_common_reg(tavor_state_t *state, tavor_pdhdl_t pd,
    tavor_bind_info_t *bind, tavor_mrhdl_t *mrhdl, tavor_mr_options_t *op)
{
	tavor_rsrc_pool_info_t	*rsrc_pool;
	tavor_rsrc_t		*mpt, *mtt, *rsrc, *mtt_refcnt;
	tavor_umap_db_entry_t	*umapdb;
	tavor_sw_refcnt_t	*swrc_tmp;
	tavor_hw_mpt_t		mpt_entry;
	tavor_mrhdl_t		mr;
	ibt_mr_flags_t		flags;
	tavor_bind_info_t	*bh;
	ddi_dma_handle_t	bind_dmahdl;
	ddi_umem_cookie_t	umem_cookie;
	size_t			umem_len;
	caddr_t			umem_addr;
	uint64_t		mtt_addr, mtt_ddrbaseaddr, max_sz;
	uint_t			sleep, mtt_pgsize_bits, bind_type, mr_is_umem;
	int			status, umem_flags, bind_override_addr;

	/*
	 * Check the "options" flag.  Currently this flag tells the driver
	 * whether or not the region should be bound normally (i.e. with
	 * entries written into the PCI IOMMU), whether it should be
	 * registered to bypass the IOMMU, and whether or not the resulting
	 * address should be "zero-based" (to aid the alignment restrictions
	 * for QPs).
	 */
	if (op == NULL) {
		bind_type   = TAVOR_BINDMEM_NORMAL;
		bind_dmahdl = NULL;
		bind_override_addr = 0;
	} else {
		bind_type	   = op->mro_bind_type;
		bind_dmahdl	   = op->mro_bind_dmahdl;
		bind_override_addr = op->mro_bind_override_addr;
	}

	/* Extract the flags field from the tavor_bind_info_t */
	flags = bind->bi_flags;

	/*
	 * Check for invalid length.  Check is the length is zero or if the
	 * length is larger than the maximum configured value.  Return error
	 * if it is.
	 */
	max_sz = ((uint64_t)1 << state->ts_cfg_profile->cp_log_max_mrw_sz);
	if ((bind->bi_len == 0) || (bind->bi_len > max_sz)) {
		goto mrcommon_fail;
	}

	/*
	 * Check the sleep flag.  Ensure that it is consistent with the
	 * current thread context (i.e. if we are currently in the interrupt
	 * context, then we shouldn't be attempting to sleep).
	 */
	sleep = (flags & IBT_MR_NOSLEEP) ? TAVOR_NOSLEEP: TAVOR_SLEEP;
	if ((sleep == TAVOR_SLEEP) &&
	    (sleep != TAVOR_SLEEPFLAG_FOR_CONTEXT())) {
		goto mrcommon_fail;
	}

	/*
	 * Get the base address for the MTT table.  This will be necessary
	 * below when we are setting up the MPT entry.
	 */
	rsrc_pool = &state->ts_rsrc_hdl[TAVOR_MTT];
	mtt_ddrbaseaddr = (uint64_t)(uintptr_t)rsrc_pool->rsrc_ddr_offset;

	/* Increment the reference count on the protection domain (PD) */
	tavor_pd_refcnt_inc(pd);

	/*
	 * Allocate an MPT entry.  This will be filled in with all the
	 * necessary parameters to define the memory region.  And then
	 * ownership will be passed to the hardware in the final step
	 * below.  If we fail here, we must undo the protection domain
	 * reference count.
	 */
	status = tavor_rsrc_alloc(state, TAVOR_MPT, 1, sleep, &mpt);
	if (status != DDI_SUCCESS) {
		goto mrcommon_fail1;
	}

	/*
	 * Allocate the software structure for tracking the memory region (i.e.
	 * the Tavor Memory Region handle).  If we fail here, we must undo
	 * the protection domain reference count and the previous resource
	 * allocation.
	 */
	status = tavor_rsrc_alloc(state, TAVOR_MRHDL, 1, sleep, &rsrc);
	if (status != DDI_SUCCESS) {
		goto mrcommon_fail2;
	}
	mr = (tavor_mrhdl_t)rsrc->tr_addr;
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*mr))

	/*
	 * Setup and validate the memory region access flags.  This means
	 * translating the IBTF's enable flags into the access flags that
	 * will be used in later operations.
	 */
	mr->mr_accflag = 0;
	if (flags & IBT_MR_ENABLE_WINDOW_BIND)
		mr->mr_accflag |= IBT_MR_WINDOW_BIND;
	if (flags & IBT_MR_ENABLE_LOCAL_WRITE)
		mr->mr_accflag |= IBT_MR_LOCAL_WRITE;
	if (flags & IBT_MR_ENABLE_REMOTE_READ)
		mr->mr_accflag |= IBT_MR_REMOTE_READ;
	if (flags & IBT_MR_ENABLE_REMOTE_WRITE)
		mr->mr_accflag |= IBT_MR_REMOTE_WRITE;
	if (flags & IBT_MR_ENABLE_REMOTE_ATOMIC)
		mr->mr_accflag |= IBT_MR_REMOTE_ATOMIC;

	/*
	 * Calculate keys (Lkey, Rkey) from MPT index.  Each key is formed
	 * from a certain number of "constrained" bits (the least significant
	 * bits) and some number of "unconstrained" bits.  The constrained
	 * bits must be set to the index of the entry in the MPT table, but
	 * the unconstrained bits can be set to any value we wish.  Note:
	 * if no remote access is required, then the RKey value is not filled
	 * in.  Otherwise both Rkey and LKey are given the same value.
	 */
	tavor_mr_keycalc(state, mpt->tr_indx, &mr->mr_lkey);
	if ((mr->mr_accflag & IBT_MR_REMOTE_READ) ||
	    (mr->mr_accflag & IBT_MR_REMOTE_WRITE) ||
	    (mr->mr_accflag & IBT_MR_REMOTE_ATOMIC)) {
		mr->mr_rkey = mr->mr_lkey;
	}

	/*
	 * Determine if the memory is from userland and pin the pages
	 * with umem_lockmemory() if necessary.
	 * Then, if this is userland memory, allocate an entry in the
	 * "userland resources database".  This will later be added to
	 * the database (after all further memory registration operations are
	 * successful).  If we fail here, we must undo the reference counts
	 * and the previous resource allocations.
	 */
	mr_is_umem = (((bind->bi_as != NULL) && (bind->bi_as != &kas)) ? 1 : 0);
	if (mr_is_umem) {
		umem_len   = ptob(btopr(bind->bi_len +
		    ((uintptr_t)bind->bi_addr & PAGEOFFSET)));
		umem_addr  = (caddr_t)((uintptr_t)bind->bi_addr & ~PAGEOFFSET);
		umem_flags = (DDI_UMEMLOCK_WRITE | DDI_UMEMLOCK_READ |
		    DDI_UMEMLOCK_LONGTERM);
		status = umem_lockmemory(umem_addr, umem_len, umem_flags,
		    &umem_cookie, &tavor_umem_cbops, NULL);
		if (status != 0) {
			goto mrcommon_fail3;
		}

		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*bind))
		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*bind->bi_buf))

		bind->bi_buf = ddi_umem_iosetup(umem_cookie, 0, umem_len,
		    B_WRITE, 0, 0, NULL, DDI_UMEM_SLEEP);
		if (bind->bi_buf == NULL) {
			goto mrcommon_fail3;
		}
		bind->bi_type = TAVOR_BINDHDL_UBUF;
		bind->bi_buf->b_flags |= B_READ;

		_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*bind->bi_buf))
		_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*bind))

		umapdb = tavor_umap_db_alloc(state->ts_instance,
		    (uint64_t)(uintptr_t)umem_cookie, MLNX_UMAP_MRMEM_RSRC,
		    (uint64_t)(uintptr_t)rsrc);
		if (umapdb == NULL) {
			goto mrcommon_fail4;
		}
	}

	/*
	 * Setup the bindinfo for the mtt bind call
	 */
	bh = &mr->mr_bindinfo;
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*bh))
	bcopy(bind, bh, sizeof (tavor_bind_info_t));
	bh->bi_bypass = bind_type;
	status = tavor_mr_mtt_bind(state, bh, bind_dmahdl, &mtt,
	    &mtt_pgsize_bits);
	if (status != DDI_SUCCESS) {
		/*
		 * When mtt_bind fails, freerbuf has already been done,
		 * so make sure not to call it again.
		 */
		bind->bi_type = bh->bi_type;
		goto mrcommon_fail5;
	}
	mr->mr_logmttpgsz = mtt_pgsize_bits;

	/*
	 * Allocate MTT reference count (to track shared memory regions).
	 * This reference count resource may never be used on the given
	 * memory region, but if it is ever later registered as "shared"
	 * memory region then this resource will be necessary.  If we fail
	 * here, we do pretty much the same as above to clean up.
	 */
	status = tavor_rsrc_alloc(state, TAVOR_REFCNT, 1, sleep,
	    &mtt_refcnt);
	if (status != DDI_SUCCESS) {
		goto mrcommon_fail6;
	}
	mr->mr_mttrefcntp = mtt_refcnt;
	swrc_tmp = (tavor_sw_refcnt_t *)mtt_refcnt->tr_addr;
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*swrc_tmp))
	TAVOR_MTT_REFCNT_INIT(swrc_tmp);

	/*
	 * Fill in the MPT entry.  This is the final step before passing
	 * ownership of the MPT entry to the Tavor hardware.  We use all of
	 * the information collected/calculated above to fill in the
	 * requisite portions of the MPT.
	 */
	bzero(&mpt_entry, sizeof (tavor_hw_mpt_t));
	mpt_entry.m_io	  = TAVOR_MEM_CYCLE_GENERATE;
	mpt_entry.en_bind = (mr->mr_accflag & IBT_MR_WINDOW_BIND)   ? 1 : 0;
	mpt_entry.atomic  = (mr->mr_accflag & IBT_MR_REMOTE_ATOMIC) ? 1 : 0;
	mpt_entry.rw	  = (mr->mr_accflag & IBT_MR_REMOTE_WRITE)  ? 1 : 0;
	mpt_entry.rr	  = (mr->mr_accflag & IBT_MR_REMOTE_READ)   ? 1 : 0;
	mpt_entry.lw	  = (mr->mr_accflag & IBT_MR_LOCAL_WRITE)   ? 1 : 0;
	mpt_entry.lr	  = 1;
	mpt_entry.reg_win = TAVOR_MPT_IS_REGION;
	mpt_entry.page_sz	= mr->mr_logmttpgsz - 0xC;
	mpt_entry.mem_key	= mr->mr_lkey;
	mpt_entry.pd		= pd->pd_pdnum;
	if (bind_override_addr == 0) {
		mpt_entry.start_addr = bh->bi_addr;
	} else {
		bh->bi_addr = bh->bi_addr & ((1 << mr->mr_logmttpgsz) - 1);
		mpt_entry.start_addr = bh->bi_addr;
	}
	mpt_entry.reg_win_len	= bh->bi_len;
	mpt_entry.win_cnt_limit	= TAVOR_UNLIMITED_WIN_BIND;
	mtt_addr = mtt_ddrbaseaddr + (mtt->tr_indx << TAVOR_MTT_SIZE_SHIFT);
	mpt_entry.mttseg_addr_h = mtt_addr >> 32;
	mpt_entry.mttseg_addr_l = mtt_addr >> 6;

	/*
	 * Write the MPT entry to hardware.  Lastly, we pass ownership of
	 * the entry to the hardware.  Note: in general, this operation
	 * shouldn't fail.  But if it does, we have to undo everything we've
	 * done above before returning error.
	 */
	status = tavor_cmn_ownership_cmd_post(state, SW2HW_MPT, &mpt_entry,
	    sizeof (tavor_hw_mpt_t), mpt->tr_indx, sleep);
	if (status != TAVOR_CMD_SUCCESS) {
		cmn_err(CE_CONT, "Tavor: SW2HW_MPT command failed: %08x\n",
		    status);
		goto mrcommon_fail7;
	}

	/*
	 * Fill in the rest of the Tavor Memory Region handle.  Having
	 * successfully transferred ownership of the MPT, we can update the
	 * following fields for use in further operations on the MR.
	 */
	mr->mr_mptrsrcp	  = mpt;
	mr->mr_mttrsrcp	  = mtt;
	mr->mr_pdhdl	  = pd;
	mr->mr_rsrcp	  = rsrc;
	mr->mr_is_umem	  = mr_is_umem;
	mr->mr_umemcookie = (mr_is_umem != 0) ? umem_cookie : NULL;
	mr->mr_umem_cbfunc = NULL;
	mr->mr_umem_cbarg1 = NULL;
	mr->mr_umem_cbarg2 = NULL;

	/*
	 * If this is userland memory, then we need to insert the previously
	 * allocated entry into the "userland resources database".  This will
	 * allow for later coordination between the tavor_umap_umemlock_cb()
	 * callback and tavor_mr_deregister().
	 */
	if (mr_is_umem) {
		tavor_umap_db_add(umapdb);
	}

	*mrhdl = mr;

	return (DDI_SUCCESS);

/*
 * The following is cleanup for all possible failure cases in this routine
 */
mrcommon_fail7:
	tavor_rsrc_free(state, &mtt_refcnt);
mrcommon_fail6:
	tavor_rsrc_free(state, &mtt);
	tavor_mr_mem_unbind(state, bh);
	bind->bi_type = bh->bi_type;
mrcommon_fail5:
	if (mr_is_umem) {
		tavor_umap_db_free(umapdb);
	}
mrcommon_fail4:
	if (mr_is_umem) {
		/*
		 * Free up the memory ddi_umem_iosetup() allocates
		 * internally.
		 */
		if (bind->bi_type == TAVOR_BINDHDL_UBUF) {
			freerbuf(bind->bi_buf);
			_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*bind))
			bind->bi_type = TAVOR_BINDHDL_NONE;
			_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*bind))
		}
		ddi_umem_unlock(umem_cookie);
	}
mrcommon_fail3:
	tavor_rsrc_free(state, &rsrc);
mrcommon_fail2:
	tavor_rsrc_free(state, &mpt);
mrcommon_fail1:
	tavor_pd_refcnt_dec(pd);
mrcommon_fail:
	return (status);
}

int
tavor_dma_mr_register(tavor_state_t *state, tavor_pdhdl_t pd,
    ibt_dmr_attr_t *mr_attr, tavor_mrhdl_t *mrhdl)
{
	tavor_rsrc_t		*mpt, *rsrc;
	tavor_hw_mpt_t		mpt_entry;
	tavor_mrhdl_t		mr;
	ibt_mr_flags_t		flags;
	uint_t			sleep;
	int			status;

	/* Extract the flags field */
	flags = mr_attr->dmr_flags;

	/*
	 * Check the sleep flag.  Ensure that it is consistent with the
	 * current thread context (i.e. if we are currently in the interrupt
	 * context, then we shouldn't be attempting to sleep).
	 */
	sleep = (flags & IBT_MR_NOSLEEP) ? TAVOR_NOSLEEP: TAVOR_SLEEP;
	if ((sleep == TAVOR_SLEEP) &&
	    (sleep != TAVOR_SLEEPFLAG_FOR_CONTEXT())) {
		status = IBT_INVALID_PARAM;
		goto mrcommon_fail;
	}

	/* Increment the reference count on the protection domain (PD) */
	tavor_pd_refcnt_inc(pd);

	/*
	 * Allocate an MPT entry.  This will be filled in with all the
	 * necessary parameters to define the memory region.  And then
	 * ownership will be passed to the hardware in the final step
	 * below.  If we fail here, we must undo the protection domain
	 * reference count.
	 */
	status = tavor_rsrc_alloc(state, TAVOR_MPT, 1, sleep, &mpt);
	if (status != DDI_SUCCESS) {
		status = IBT_INSUFF_RESOURCE;
		goto mrcommon_fail1;
	}

	/*
	 * Allocate the software structure for tracking the memory region (i.e.
	 * the Tavor Memory Region handle).  If we fail here, we must undo
	 * the protection domain reference count and the previous resource
	 * allocation.
	 */
	status = tavor_rsrc_alloc(state, TAVOR_MRHDL, 1, sleep, &rsrc);
	if (status != DDI_SUCCESS) {
		status = IBT_INSUFF_RESOURCE;
		goto mrcommon_fail2;
	}
	mr = (tavor_mrhdl_t)rsrc->tr_addr;
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*mr))
	bzero(mr, sizeof (*mr));

	/*
	 * Setup and validate the memory region access flags.  This means
	 * translating the IBTF's enable flags into the access flags that
	 * will be used in later operations.
	 */
	mr->mr_accflag = 0;
	if (flags & IBT_MR_ENABLE_WINDOW_BIND)
		mr->mr_accflag |= IBT_MR_WINDOW_BIND;
	if (flags & IBT_MR_ENABLE_LOCAL_WRITE)
		mr->mr_accflag |= IBT_MR_LOCAL_WRITE;
	if (flags & IBT_MR_ENABLE_REMOTE_READ)
		mr->mr_accflag |= IBT_MR_REMOTE_READ;
	if (flags & IBT_MR_ENABLE_REMOTE_WRITE)
		mr->mr_accflag |= IBT_MR_REMOTE_WRITE;
	if (flags & IBT_MR_ENABLE_REMOTE_ATOMIC)
		mr->mr_accflag |= IBT_MR_REMOTE_ATOMIC;

	/*
	 * Calculate keys (Lkey, Rkey) from MPT index.  Each key is formed
	 * from a certain number of "constrained" bits (the least significant
	 * bits) and some number of "unconstrained" bits.  The constrained
	 * bits must be set to the index of the entry in the MPT table, but
	 * the unconstrained bits can be set to any value we wish.  Note:
	 * if no remote access is required, then the RKey value is not filled
	 * in.  Otherwise both Rkey and LKey are given the same value.
	 */
	tavor_mr_keycalc(state, mpt->tr_indx, &mr->mr_lkey);
	if ((mr->mr_accflag & IBT_MR_REMOTE_READ) ||
	    (mr->mr_accflag & IBT_MR_REMOTE_WRITE) ||
	    (mr->mr_accflag & IBT_MR_REMOTE_ATOMIC)) {
		mr->mr_rkey = mr->mr_lkey;
	}

	/*
	 * Fill in the MPT entry.  This is the final step before passing
	 * ownership of the MPT entry to the Tavor hardware.  We use all of
	 * the information collected/calculated above to fill in the
	 * requisite portions of the MPT.
	 */
	bzero(&mpt_entry, sizeof (tavor_hw_mpt_t));

	mpt_entry.m_io	  = TAVOR_MEM_CYCLE_GENERATE;
	mpt_entry.en_bind = (mr->mr_accflag & IBT_MR_WINDOW_BIND)   ? 1 : 0;
	mpt_entry.atomic  = (mr->mr_accflag & IBT_MR_REMOTE_ATOMIC) ? 1 : 0;
	mpt_entry.rw	  = (mr->mr_accflag & IBT_MR_REMOTE_WRITE)  ? 1 : 0;
	mpt_entry.rr	  = (mr->mr_accflag & IBT_MR_REMOTE_READ)   ? 1 : 0;
	mpt_entry.lw	  = (mr->mr_accflag & IBT_MR_LOCAL_WRITE)   ? 1 : 0;
	mpt_entry.lr	  = 1;
	mpt_entry.phys_addr = 1;	/* critical bit for this */
	mpt_entry.reg_win = TAVOR_MPT_IS_REGION;

	mpt_entry.page_sz	= mr->mr_logmttpgsz - 0xC;
	mpt_entry.mem_key	= mr->mr_lkey;
	mpt_entry.pd		= pd->pd_pdnum;
	mpt_entry.win_cnt_limit = TAVOR_UNLIMITED_WIN_BIND;

	mpt_entry.start_addr = mr_attr->dmr_paddr;
	mpt_entry.reg_win_len = mr_attr->dmr_len;

	mpt_entry.mttseg_addr_h = 0;
	mpt_entry.mttseg_addr_l = 0;

	/*
	 * Write the MPT entry to hardware.  Lastly, we pass ownership of
	 * the entry to the hardware if needed.  Note: in general, this
	 * operation shouldn't fail.  But if it does, we have to undo
	 * everything we've done above before returning error.
	 *
	 * For Tavor, this routine (which is common to the contexts) will only
	 * set the ownership if needed - the process of passing the context
	 * itself to HW will take care of setting up the MPT (based on type
	 * and index).
	 */

	status = tavor_cmn_ownership_cmd_post(state, SW2HW_MPT, &mpt_entry,
	    sizeof (tavor_hw_mpt_t), mpt->tr_indx, sleep);
	if (status != TAVOR_CMD_SUCCESS) {
		cmn_err(CE_CONT, "Tavor: SW2HW_MPT command failed: %08x\n",
		    status);
		status = ibc_get_ci_failure(0);
		goto mrcommon_fail7;
	}

	/*
	 * Fill in the rest of the Tavor Memory Region handle.  Having
	 * successfully transferred ownership of the MPT, we can update the
	 * following fields for use in further operations on the MR.
	 */
	mr->mr_mptrsrcp	   = mpt;
	mr->mr_mttrsrcp	   = NULL;
	mr->mr_pdhdl	   = pd;
	mr->mr_rsrcp	   = rsrc;
	mr->mr_is_umem	   = 0;
	mr->mr_umemcookie  = NULL;
	mr->mr_umem_cbfunc = NULL;
	mr->mr_umem_cbarg1 = NULL;
	mr->mr_umem_cbarg2 = NULL;

	*mrhdl = mr;

	return (DDI_SUCCESS);

/*
 * The following is cleanup for all possible failure cases in this routine
 */
mrcommon_fail7:
	tavor_rsrc_free(state, &rsrc);
mrcommon_fail2:
	tavor_rsrc_free(state, &mpt);
mrcommon_fail1:
	tavor_pd_refcnt_dec(pd);
mrcommon_fail:
	return (status);
}

/*
 * tavor_mr_mtt_bind()
 *    Context: Can be called from interrupt or base context.
 */
int
tavor_mr_mtt_bind(tavor_state_t *state, tavor_bind_info_t *bind,
    ddi_dma_handle_t bind_dmahdl, tavor_rsrc_t **mtt, uint_t *mtt_pgsize_bits)
{
	uint64_t		nummtt;
	uint_t			sleep;
	int			status;

	/*
	 * Check the sleep flag.  Ensure that it is consistent with the
	 * current thread context (i.e. if we are currently in the interrupt
	 * context, then we shouldn't be attempting to sleep).
	 */
	sleep = (bind->bi_flags & IBT_MR_NOSLEEP) ? TAVOR_NOSLEEP: TAVOR_SLEEP;
	if ((sleep == TAVOR_SLEEP) &&
	    (sleep != TAVOR_SLEEPFLAG_FOR_CONTEXT())) {
		goto mrmttbind_fail;
	}

	/*
	 * Bind the memory and determine the mapped addresses.  This is
	 * the first of two routines that do all the "heavy lifting" for
	 * the Tavor memory registration routines.  The tavor_mr_mem_bind()
	 * routine takes the "bind" struct with all its fields filled
	 * in and returns a list of DMA cookies (for the PCI mapped addresses
	 * corresponding to the specified address region) which are used by
	 * the tavor_mr_fast_mtt_write() routine below.  If we fail here, we
	 * must undo all the previous resource allocation (and PD reference
	 * count).
	 */
	status = tavor_mr_mem_bind(state, bind, bind_dmahdl, sleep);
	if (status != DDI_SUCCESS) {
		goto mrmttbind_fail;
	}

	/*
	 * Determine number of pages spanned.  This routine uses the
	 * information in the "bind" struct to determine the required
	 * number of MTT entries needed (and returns the suggested page size -
	 * as a "power-of-2" - for each MTT entry).
	 */
	nummtt = tavor_mr_nummtt_needed(state, bind, mtt_pgsize_bits);

	/*
	 * Allocate the MTT entries.  Use the calculations performed above to
	 * allocate the required number of MTT entries.  Note: MTT entries are
	 * allocated in "MTT segments" which consist of complete cachelines
	 * (i.e. 8 entries, 16 entries, etc.)  So the TAVOR_NUMMTT_TO_MTTSEG()
	 * macro is used to do the proper conversion.  If we fail here, we
	 * must not only undo all the previous resource allocation (and PD
	 * reference count), but we must also unbind the memory.
	 */
	status = tavor_rsrc_alloc(state, TAVOR_MTT,
	    TAVOR_NUMMTT_TO_MTTSEG(nummtt), sleep, mtt);
	if (status != DDI_SUCCESS) {
		goto mrmttbind_fail2;
	}

	/*
	 * Write the mapped addresses into the MTT entries.  This is part two
	 * of the "heavy lifting" routines that we talked about above.  Note:
	 * we pass the suggested page size from the earlier operation here.
	 * And if we fail here, we again do pretty much the same huge clean up.
	 */
	status = tavor_mr_fast_mtt_write(*mtt, bind, *mtt_pgsize_bits);
	if (status != DDI_SUCCESS) {
		goto mrmttbind_fail3;
	}
	return (DDI_SUCCESS);

/*
 * The following is cleanup for all possible failure cases in this routine
 */
mrmttbind_fail3:
	tavor_rsrc_free(state, mtt);
mrmttbind_fail2:
	tavor_mr_mem_unbind(state, bind);
mrmttbind_fail:
	return (status);
}


/*
 * tavor_mr_mtt_unbind()
 *    Context: Can be called from interrupt or base context.
 */
int
tavor_mr_mtt_unbind(tavor_state_t *state, tavor_bind_info_t *bind,
    tavor_rsrc_t *mtt)
{
	/*
	 * Free up the MTT entries and unbind the memory.  Here, as above, we
	 * attempt to free these resources only if it is appropriate to do so.
	 */
	tavor_mr_mem_unbind(state, bind);
	tavor_rsrc_free(state, &mtt);

	return (DDI_SUCCESS);
}


/*
 * tavor_mr_common_rereg()
 *    Context: Can be called from interrupt or base context.
 */
static int
tavor_mr_common_rereg(tavor_state_t *state, tavor_mrhdl_t mr,
    tavor_pdhdl_t pd, tavor_bind_info_t *bind, tavor_mrhdl_t *mrhdl_new,
    tavor_mr_options_t *op)
{
	tavor_rsrc_t		*mpt;
	ibt_mr_attr_flags_t	acc_flags_to_use;
	ibt_mr_flags_t		flags;
	tavor_pdhdl_t		pd_to_use;
	tavor_hw_mpt_t		mpt_entry;
	uint64_t		mtt_addr_to_use, vaddr_to_use, len_to_use;
	uint_t			sleep, dereg_level;
	int			status;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*bind))

	/*
	 * Check here to see if the memory region corresponds to a userland
	 * mapping.  Reregistration of userland memory regions is not
	 * currently supported.  Return failure. XXX
	 */
	if (mr->mr_is_umem) {
		goto mrrereg_fail;
	}

	mutex_enter(&mr->mr_lock);

	/* Pull MPT resource pointer from the Tavor Memory Region handle */
	mpt = mr->mr_mptrsrcp;

	/* Extract the flags field from the tavor_bind_info_t */
	flags = bind->bi_flags;

	/*
	 * Check the sleep flag.  Ensure that it is consistent with the
	 * current thread context (i.e. if we are currently in the interrupt
	 * context, then we shouldn't be attempting to sleep).
	 */
	sleep = (flags & IBT_MR_NOSLEEP) ? TAVOR_NOSLEEP: TAVOR_SLEEP;
	if ((sleep == TAVOR_SLEEP) &&
	    (sleep != TAVOR_SLEEPFLAG_FOR_CONTEXT())) {
		mutex_exit(&mr->mr_lock);
		goto mrrereg_fail;
	}

	/*
	 * First step is to temporarily invalidate the MPT entry.  This
	 * regains ownership from the hardware, and gives us the opportunity
	 * to modify the entry.  Note: The HW2SW_MPT command returns the
	 * current MPT entry contents.  These are saved away here because
	 * they will be reused in a later step below.  If the region has
	 * bound memory windows that we fail returning an "in use" error code.
	 * Otherwise, this is an unexpected error and we deregister the
	 * memory region and return error.
	 *
	 * We use TAVOR_CMD_NOSLEEP_SPIN here always because we must protect
	 * against holding the lock around this rereg call in all contexts.
	 */
	status = tavor_cmn_ownership_cmd_post(state, HW2SW_MPT, &mpt_entry,
	    sizeof (tavor_hw_mpt_t), mpt->tr_indx, TAVOR_CMD_NOSLEEP_SPIN);
	if (status != TAVOR_CMD_SUCCESS) {
		mutex_exit(&mr->mr_lock);
		if (status == TAVOR_CMD_REG_BOUND) {
			return (IBT_MR_IN_USE);
		} else {
			cmn_err(CE_CONT, "Tavor: HW2SW_MPT command failed: "
			    "%08x\n", status);

			/*
			 * Call deregister and ensure that all current
			 * resources get freed up
			 */
			if (tavor_mr_deregister(state, &mr,
			    TAVOR_MR_DEREG_ALL, sleep) != DDI_SUCCESS) {
				TAVOR_WARNING(state, "failed to deregister "
				    "memory region");
			}
			return (ibc_get_ci_failure(0));
		}
	}

	/*
	 * If we're changing the protection domain, then validate the new one
	 */
	if (flags & IBT_MR_CHANGE_PD) {

		/* Check for valid PD handle pointer */
		if (pd == NULL) {
			mutex_exit(&mr->mr_lock);
			/*
			 * Call deregister and ensure that all current
			 * resources get properly freed up. Unnecessary
			 * here to attempt to regain software ownership
			 * of the MPT entry as that has already been
			 * done above.
			 */
			if (tavor_mr_deregister(state, &mr,
			    TAVOR_MR_DEREG_NO_HW2SW_MPT, sleep) !=
			    DDI_SUCCESS) {
				TAVOR_WARNING(state, "failed to deregister "
				    "memory region");
			}
			goto mrrereg_fail;
		}

		/* Use the new PD handle in all operations below */
		pd_to_use = pd;

	} else {
		/* Use the current PD handle in all operations below */
		pd_to_use = mr->mr_pdhdl;
	}

	/*
	 * If we're changing access permissions, then validate the new ones
	 */
	if (flags & IBT_MR_CHANGE_ACCESS) {
		/*
		 * Validate the access flags.  Both remote write and remote
		 * atomic require the local write flag to be set
		 */
		if (((flags & IBT_MR_ENABLE_REMOTE_WRITE) ||
		    (flags & IBT_MR_ENABLE_REMOTE_ATOMIC)) &&
		    !(flags & IBT_MR_ENABLE_LOCAL_WRITE)) {
			mutex_exit(&mr->mr_lock);
			/*
			 * Call deregister and ensure that all current
			 * resources get properly freed up. Unnecessary
			 * here to attempt to regain software ownership
			 * of the MPT entry as that has already been
			 * done above.
			 */
			if (tavor_mr_deregister(state, &mr,
			    TAVOR_MR_DEREG_NO_HW2SW_MPT, sleep) !=
			    DDI_SUCCESS) {
				TAVOR_WARNING(state, "failed to deregister "
				    "memory region");
			}
			goto mrrereg_fail;
		}

		/*
		 * Setup and validate the memory region access flags.  This
		 * means translating the IBTF's enable flags into the access
		 * flags that will be used in later operations.
		 */
		acc_flags_to_use = 0;
		if (flags & IBT_MR_ENABLE_WINDOW_BIND)
			acc_flags_to_use |= IBT_MR_WINDOW_BIND;
		if (flags & IBT_MR_ENABLE_LOCAL_WRITE)
			acc_flags_to_use |= IBT_MR_LOCAL_WRITE;
		if (flags & IBT_MR_ENABLE_REMOTE_READ)
			acc_flags_to_use |= IBT_MR_REMOTE_READ;
		if (flags & IBT_MR_ENABLE_REMOTE_WRITE)
			acc_flags_to_use |= IBT_MR_REMOTE_WRITE;
		if (flags & IBT_MR_ENABLE_REMOTE_ATOMIC)
			acc_flags_to_use |= IBT_MR_REMOTE_ATOMIC;

	} else {
		acc_flags_to_use = mr->mr_accflag;
	}

	/*
	 * If we're modifying the translation, then figure out whether
	 * we can reuse the current MTT resources.  This means calling
	 * tavor_mr_rereg_xlat_helper() which does most of the heavy lifting
	 * for the reregistration.  If the current memory region contains
	 * sufficient MTT entries for the new regions, then it will be
	 * reused and filled in.  Otherwise, new entries will be allocated,
	 * the old ones will be freed, and the new entries will be filled
	 * in.  Note:  If we're not modifying the translation, then we
	 * should already have all the information we need to update the MPT.
	 * Also note: If tavor_mr_rereg_xlat_helper() fails, it will return
	 * a "dereg_level" which is the level of cleanup that needs to be
	 * passed to tavor_mr_deregister() to finish the cleanup.
	 */
	if (flags & IBT_MR_CHANGE_TRANSLATION) {
		status = tavor_mr_rereg_xlat_helper(state, mr, bind, op,
		    &mtt_addr_to_use, sleep, &dereg_level);
		if (status != DDI_SUCCESS) {
			mutex_exit(&mr->mr_lock);
			/*
			 * Call deregister and ensure that all resources get
			 * properly freed up.
			 */
			if (tavor_mr_deregister(state, &mr, dereg_level,
			    sleep) != DDI_SUCCESS) {
				TAVOR_WARNING(state, "failed to deregister "
				    "memory region");
			}

			goto mrrereg_fail;
		}
		vaddr_to_use = mr->mr_bindinfo.bi_addr;
		len_to_use   = mr->mr_bindinfo.bi_len;
	} else {
		mtt_addr_to_use = (((uint64_t)mpt_entry.mttseg_addr_h << 32) |
		    ((uint64_t)mpt_entry.mttseg_addr_l << 6));
		vaddr_to_use = mr->mr_bindinfo.bi_addr;
		len_to_use   = mr->mr_bindinfo.bi_len;
	}

	/*
	 * Calculate new keys (Lkey, Rkey) from MPT index.  Just like they were
	 * when the region was first registered, each key is formed from
	 * "constrained" bits and "unconstrained" bits.  Note:  If no remote
	 * access is required, then the RKey value is not filled in.  Otherwise
	 * both Rkey and LKey are given the same value.
	 */
	tavor_mr_keycalc(state, mpt->tr_indx, &mr->mr_lkey);
	if ((acc_flags_to_use & IBT_MR_REMOTE_READ) ||
	    (acc_flags_to_use & IBT_MR_REMOTE_WRITE) ||
	    (acc_flags_to_use & IBT_MR_REMOTE_ATOMIC)) {
		mr->mr_rkey = mr->mr_lkey;
	}

	/*
	 * Update the MPT entry with the new information.  Some of this
	 * information is retained from the previous operation, some of
	 * it is new based on request.
	 */
	mpt_entry.en_bind = (acc_flags_to_use & IBT_MR_WINDOW_BIND)   ? 1 : 0;
	mpt_entry.atomic  = (acc_flags_to_use & IBT_MR_REMOTE_ATOMIC) ? 1 : 0;
	mpt_entry.rw	  = (acc_flags_to_use & IBT_MR_REMOTE_WRITE)  ? 1 : 0;
	mpt_entry.rr	  = (acc_flags_to_use & IBT_MR_REMOTE_READ)   ? 1 : 0;
	mpt_entry.lw	  = (acc_flags_to_use & IBT_MR_LOCAL_WRITE)   ? 1 : 0;
	mpt_entry.page_sz	= mr->mr_logmttpgsz - 0xC;
	mpt_entry.mem_key	= mr->mr_lkey;
	mpt_entry.pd		= pd_to_use->pd_pdnum;
	mpt_entry.start_addr	= vaddr_to_use;
	mpt_entry.reg_win_len	= len_to_use;
	mpt_entry.mttseg_addr_h = mtt_addr_to_use >> 32;
	mpt_entry.mttseg_addr_l = mtt_addr_to_use >> 6;

	/*
	 * Write the updated MPT entry to hardware
	 *
	 * We use TAVOR_CMD_NOSLEEP_SPIN here always because we must protect
	 * against holding the lock around this rereg call in all contexts.
	 */
	status = tavor_cmn_ownership_cmd_post(state, SW2HW_MPT, &mpt_entry,
	    sizeof (tavor_hw_mpt_t), mpt->tr_indx, TAVOR_CMD_NOSLEEP_SPIN);
	if (status != TAVOR_CMD_SUCCESS) {
		mutex_exit(&mr->mr_lock);
		cmn_err(CE_CONT, "Tavor: SW2HW_MPT command failed: %08x\n",
		    status);
		/*
		 * Call deregister and ensure that all current resources get
		 * properly freed up. Unnecessary here to attempt to regain
		 * software ownership of the MPT entry as that has already
		 * been done above.
		 */
		if (tavor_mr_deregister(state, &mr,
		    TAVOR_MR_DEREG_NO_HW2SW_MPT, sleep) != DDI_SUCCESS) {
			TAVOR_WARNING(state, "failed to deregister memory "
			    "region");
		}
		return (ibc_get_ci_failure(0));
	}

	/*
	 * If we're changing PD, then update their reference counts now.
	 * This means decrementing the reference count on the old PD and
	 * incrementing the reference count on the new PD.
	 */
	if (flags & IBT_MR_CHANGE_PD) {
		tavor_pd_refcnt_dec(mr->mr_pdhdl);
		tavor_pd_refcnt_inc(pd);
	}

	/*
	 * Update the contents of the Tavor Memory Region handle to reflect
	 * what has been changed.
	 */
	mr->mr_pdhdl	  = pd_to_use;
	mr->mr_accflag	  = acc_flags_to_use;
	mr->mr_is_umem	  = 0;
	mr->mr_umemcookie = NULL;

	/* New MR handle is same as the old */
	*mrhdl_new = mr;
	mutex_exit(&mr->mr_lock);

	return (DDI_SUCCESS);

mrrereg_fail:
	return (status);
}


/*
 * tavor_mr_rereg_xlat_helper
 *    Context: Can be called from interrupt or base context.
 *    Note: This routine expects the "mr_lock" to be held when it
 *    is called.  Upon returning failure, this routine passes information
 *    about what "dereg_level" should be passed to tavor_mr_deregister().
 */
static int
tavor_mr_rereg_xlat_helper(tavor_state_t *state, tavor_mrhdl_t mr,
    tavor_bind_info_t *bind, tavor_mr_options_t *op, uint64_t *mtt_addr,
    uint_t sleep, uint_t *dereg_level)
{
	tavor_rsrc_pool_info_t	*rsrc_pool;
	tavor_rsrc_t		*mtt, *mtt_refcnt;
	tavor_sw_refcnt_t	*swrc_old, *swrc_new;
	ddi_dma_handle_t	dmahdl;
	uint64_t		nummtt_needed, nummtt_in_currrsrc, max_sz;
	uint64_t		mtt_ddrbaseaddr;
	uint_t			mtt_pgsize_bits, bind_type, reuse_dmahdl;
	int			status;

	ASSERT(MUTEX_HELD(&mr->mr_lock));

	/*
	 * Check the "options" flag.  Currently this flag tells the driver
	 * whether or not the region should be bound normally (i.e. with
	 * entries written into the PCI IOMMU) or whether it should be
	 * registered to bypass the IOMMU.
	 */
	if (op == NULL) {
		bind_type = TAVOR_BINDMEM_NORMAL;
	} else {
		bind_type = op->mro_bind_type;
	}

	/*
	 * Check for invalid length.  Check is the length is zero or if the
	 * length is larger than the maximum configured value.  Return error
	 * if it is.
	 */
	max_sz = ((uint64_t)1 << state->ts_cfg_profile->cp_log_max_mrw_sz);
	if ((bind->bi_len == 0) || (bind->bi_len > max_sz)) {
		/*
		 * Deregister will be called upon returning failure from this
		 * routine. This will ensure that all current resources get
		 * properly freed up. Unnecessary to attempt to regain
		 * software ownership of the MPT entry as that has already
		 * been done above (in tavor_mr_reregister())
		 */
		*dereg_level = TAVOR_MR_DEREG_NO_HW2SW_MPT;

		goto mrrereghelp_fail;
	}

	/*
	 * Determine the number of pages necessary for new region and the
	 * number of pages supported by the current MTT resources
	 */
	nummtt_needed = tavor_mr_nummtt_needed(state, bind, &mtt_pgsize_bits);
	nummtt_in_currrsrc = mr->mr_mttrsrcp->tr_len >> TAVOR_MTT_SIZE_SHIFT;

	/*
	 * Depending on whether we have enough pages or not, the next step is
	 * to fill in a set of MTT entries that reflect the new mapping.  In
	 * the first case below, we already have enough entries.  This means
	 * we need to unbind the memory from the previous mapping, bind the
	 * memory for the new mapping, write the new MTT entries, and update
	 * the mr to reflect the changes.
	 * In the second case below, we do not have enough entries in the
	 * current mapping.  So, in this case, we need not only to unbind the
	 * current mapping, but we need to free up the MTT resources associated
	 * with that mapping.  After we've successfully done that, we continue
	 * by binding the new memory, allocating new MTT entries, writing the
	 * new MTT entries, and updating the mr to reflect the changes.
	 */

	/*
	 * If this region is being shared (i.e. MTT refcount != 1), then we
	 * can't reuse the current MTT resources regardless of their size.
	 * Instead we'll need to alloc new ones (below) just as if there
	 * hadn't been enough room in the current entries.
	 */
	swrc_old = (tavor_sw_refcnt_t *)mr->mr_mttrefcntp->tr_addr;
	if (TAVOR_MTT_IS_NOT_SHARED(swrc_old) &&
	    (nummtt_needed <= nummtt_in_currrsrc)) {

		/*
		 * Unbind the old mapping for this memory region, but retain
		 * the ddi_dma_handle_t (if possible) for reuse in the bind
		 * operation below.  Note:  If original memory region was
		 * bound for IOMMU bypass and the new region can not use
		 * bypass, then a new DMA handle will be necessary.
		 */
		if (TAVOR_MR_REUSE_DMAHDL(mr, bind->bi_flags)) {
			mr->mr_bindinfo.bi_free_dmahdl = 0;
			tavor_mr_mem_unbind(state, &mr->mr_bindinfo);
			dmahdl = mr->mr_bindinfo.bi_dmahdl;
			reuse_dmahdl = 1;
		} else {
			tavor_mr_mem_unbind(state, &mr->mr_bindinfo);
			dmahdl = NULL;
			reuse_dmahdl = 0;
		}

		/*
		 * Bind the new memory and determine the mapped addresses.
		 * As described, this routine and tavor_mr_fast_mtt_write()
		 * do the majority of the work for the memory registration
		 * operations.  Note:  When we successfully finish the binding,
		 * we will set the "bi_free_dmahdl" flag to indicate that
		 * even though we may have reused the ddi_dma_handle_t we do
		 * wish it to be freed up at some later time.  Note also that
		 * if we fail, we may need to cleanup the ddi_dma_handle_t.
		 */
		bind->bi_bypass	= bind_type;
		status = tavor_mr_mem_bind(state, bind, dmahdl, sleep);
		if (status != DDI_SUCCESS) {
			if (reuse_dmahdl) {
				ddi_dma_free_handle(&dmahdl);
			}

			/*
			 * Deregister will be called upon returning failure
			 * from this routine. This will ensure that all
			 * current resources get properly freed up.
			 * Unnecessary to attempt to regain software ownership
			 * of the MPT entry as that has already been done
			 * above (in tavor_mr_reregister()).  Also unnecessary
			 * to attempt to unbind the memory.
			 */
			*dereg_level = TAVOR_MR_DEREG_NO_HW2SW_MPT_OR_UNBIND;

			goto mrrereghelp_fail;
		}
		if (reuse_dmahdl) {
			bind->bi_free_dmahdl = 1;
		}

		/*
		 * Using the new mapping, but reusing the current MTT
		 * resources, write the updated entries to MTT
		 */
		mtt    = mr->mr_mttrsrcp;
		status = tavor_mr_fast_mtt_write(mtt, bind, mtt_pgsize_bits);
		if (status != DDI_SUCCESS) {
			/*
			 * Deregister will be called upon returning failure
			 * from this routine. This will ensure that all
			 * current resources get properly freed up.
			 * Unnecessary to attempt to regain software ownership
			 * of the MPT entry as that has already been done
			 * above (in tavor_mr_reregister()).  Also unnecessary
			 * to attempt to unbind the memory.
			 *
			 * But we do need to unbind the newly bound memory
			 * before returning.
			 */
			tavor_mr_mem_unbind(state, bind);
			*dereg_level = TAVOR_MR_DEREG_NO_HW2SW_MPT_OR_UNBIND;

			goto mrrereghelp_fail;
		}

		/* Put the updated information into the Mem Region handle */
		mr->mr_bindinfo	  = *bind;
		mr->mr_logmttpgsz = mtt_pgsize_bits;

	} else {
		/*
		 * Check if the memory region MTT is shared by any other MRs.
		 * Since the resource may be shared between multiple memory
		 * regions (as a result of a "RegisterSharedMR()" verb) it is
		 * important that we not unbind any resources prematurely.
		 */
		if (!TAVOR_MTT_IS_SHARED(swrc_old)) {
			/*
			 * Unbind the old mapping for this memory region, but
			 * retain the ddi_dma_handle_t for reuse in the bind
			 * operation below. Note: This can only be done here
			 * because the region being reregistered is not
			 * currently shared.  Also if original memory region
			 * was bound for IOMMU bypass and the new region can
			 * not use bypass, then a new DMA handle will be
			 * necessary.
			 */
			if (TAVOR_MR_REUSE_DMAHDL(mr, bind->bi_flags)) {
				mr->mr_bindinfo.bi_free_dmahdl = 0;
				tavor_mr_mem_unbind(state, &mr->mr_bindinfo);
				dmahdl = mr->mr_bindinfo.bi_dmahdl;
				reuse_dmahdl = 1;
			} else {
				tavor_mr_mem_unbind(state, &mr->mr_bindinfo);
				dmahdl = NULL;
				reuse_dmahdl = 0;
			}
		} else {
			dmahdl = NULL;
			reuse_dmahdl = 0;
		}

		/*
		 * Bind the new memory and determine the mapped addresses.
		 * As described, this routine and tavor_mr_fast_mtt_write()
		 * do the majority of the work for the memory registration
		 * operations.  Note:  When we successfully finish the binding,
		 * we will set the "bi_free_dmahdl" flag to indicate that
		 * even though we may have reused the ddi_dma_handle_t we do
		 * wish it to be freed up at some later time.  Note also that
		 * if we fail, we may need to cleanup the ddi_dma_handle_t.
		 */
		bind->bi_bypass	= bind_type;
		status = tavor_mr_mem_bind(state, bind, dmahdl, sleep);
		if (status != DDI_SUCCESS) {
			if (reuse_dmahdl) {
				ddi_dma_free_handle(&dmahdl);
			}

			/*
			 * Deregister will be called upon returning failure
			 * from this routine. This will ensure that all
			 * current resources get properly freed up.
			 * Unnecessary to attempt to regain software ownership
			 * of the MPT entry as that has already been done
			 * above (in tavor_mr_reregister()).  Also unnecessary
			 * to attempt to unbind the memory.
			 */
			*dereg_level = TAVOR_MR_DEREG_NO_HW2SW_MPT_OR_UNBIND;

			goto mrrereghelp_fail;
		}
		if (reuse_dmahdl) {
			bind->bi_free_dmahdl = 1;
		}

		/*
		 * Allocate the new MTT entries resource
		 */
		status = tavor_rsrc_alloc(state, TAVOR_MTT,
		    TAVOR_NUMMTT_TO_MTTSEG(nummtt_needed), sleep, &mtt);
		if (status != DDI_SUCCESS) {
			/*
			 * Deregister will be called upon returning failure
			 * from this routine. This will ensure that all
			 * current resources get properly freed up.
			 * Unnecessary to attempt to regain software ownership
			 * of the MPT entry as that has already been done
			 * above (in tavor_mr_reregister()).  Also unnecessary
			 * to attempt to unbind the memory.
			 *
			 * But we do need to unbind the newly bound memory
			 * before returning.
			 */
			tavor_mr_mem_unbind(state, bind);
			*dereg_level = TAVOR_MR_DEREG_NO_HW2SW_MPT_OR_UNBIND;

			goto mrrereghelp_fail;
		}

		/*
		 * Allocate MTT reference count (to track shared memory
		 * regions).  As mentioned elsewhere above, this reference
		 * count resource may never be used on the given memory region,
		 * but if it is ever later registered as a "shared" memory
		 * region then this resource will be necessary.  Note:  This
		 * is only necessary here if the existing memory region is
		 * already being shared (because otherwise we already have
		 * a useable reference count resource).
		 */
		if (TAVOR_MTT_IS_SHARED(swrc_old)) {
			status = tavor_rsrc_alloc(state, TAVOR_REFCNT, 1,
			    sleep, &mtt_refcnt);
			if (status != DDI_SUCCESS) {
				/*
				 * Deregister will be called upon returning
				 * failure from this routine. This will ensure
				 * that all current resources get properly
				 * freed up.  Unnecessary to attempt to regain
				 * software ownership of the MPT entry as that
				 * has already been done above (in
				 * tavor_mr_reregister()).  Also unnecessary
				 * to attempt to unbind the memory.
				 *
				 * But we need to unbind the newly bound
				 * memory and free up the newly allocated MTT
				 * entries before returning.
				 */
				tavor_mr_mem_unbind(state, bind);
				tavor_rsrc_free(state, &mtt);
				*dereg_level =
				    TAVOR_MR_DEREG_NO_HW2SW_MPT_OR_UNBIND;

				goto mrrereghelp_fail;
			}
			swrc_new = (tavor_sw_refcnt_t *)mtt_refcnt->tr_addr;
			_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*swrc_new))
			TAVOR_MTT_REFCNT_INIT(swrc_new);
		} else {
			mtt_refcnt = mr->mr_mttrefcntp;
		}

		/*
		 * Using the new mapping and the new MTT resources, write the
		 * updated entries to MTT
		 */
		status = tavor_mr_fast_mtt_write(mtt, bind, mtt_pgsize_bits);
		if (status != DDI_SUCCESS) {
			/*
			 * Deregister will be called upon returning failure
			 * from this routine. This will ensure that all
			 * current resources get properly freed up.
			 * Unnecessary to attempt to regain software ownership
			 * of the MPT entry as that has already been done
			 * above (in tavor_mr_reregister()).  Also unnecessary
			 * to attempt to unbind the memory.
			 *
			 * But we need to unbind the newly bound memory,
			 * free up the newly allocated MTT entries, and
			 * (possibly) free the new MTT reference count
			 * resource before returning.
			 */
			if (TAVOR_MTT_IS_SHARED(swrc_old)) {
				tavor_rsrc_free(state, &mtt_refcnt);
			}
			tavor_mr_mem_unbind(state, bind);
			tavor_rsrc_free(state, &mtt);
			*dereg_level = TAVOR_MR_DEREG_NO_HW2SW_MPT_OR_UNBIND;

			goto mrrereghelp_fail;
		}

		/*
		 * Check if the memory region MTT is shared by any other MRs.
		 * Since the resource may be shared between multiple memory
		 * regions (as a result of a "RegisterSharedMR()" verb) it is
		 * important that we not free up any resources prematurely.
		 */
		if (TAVOR_MTT_IS_SHARED(swrc_old)) {
			/* Decrement MTT reference count for "old" region */
			(void) tavor_mtt_refcnt_dec(mr->mr_mttrefcntp);
		} else {
			/* Free up the old MTT entries resource */
			tavor_rsrc_free(state, &mr->mr_mttrsrcp);
		}

		/* Put the updated information into the mrhdl */
		mr->mr_bindinfo	  = *bind;
		mr->mr_logmttpgsz = mtt_pgsize_bits;
		mr->mr_mttrsrcp   = mtt;
		mr->mr_mttrefcntp = mtt_refcnt;
	}

	/*
	 * Calculate and return the updated MTT address (in the DDR address
	 * space).  This will be used by the caller (tavor_mr_reregister) in
	 * the updated MPT entry
	 */
	rsrc_pool	= &state->ts_rsrc_hdl[TAVOR_MTT];
	mtt_ddrbaseaddr = (uint64_t)(uintptr_t)rsrc_pool->rsrc_ddr_offset;
	*mtt_addr	= mtt_ddrbaseaddr + (mtt->tr_indx <<
	    TAVOR_MTT_SIZE_SHIFT);

	return (DDI_SUCCESS);

mrrereghelp_fail:
	return (status);
}


/*
 * tavor_mr_nummtt_needed()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static uint64_t
tavor_mr_nummtt_needed(tavor_state_t *state, tavor_bind_info_t *bind,
    uint_t *mtt_pgsize_bits)
{
	uint64_t	pg_offset_mask;
	uint64_t	pg_offset, tmp_length;

	/*
	 * For now we specify the page size as 8Kb (the default page size for
	 * the sun4u architecture), or 4Kb for x86.  Figure out optimal page
	 * size by examining the dmacookies XXX
	 */
	*mtt_pgsize_bits = PAGESHIFT;

	pg_offset_mask = ((uint64_t)1 << *mtt_pgsize_bits) - 1;
	pg_offset = bind->bi_addr & pg_offset_mask;
	tmp_length = pg_offset + (bind->bi_len - 1);
	return ((tmp_length >> *mtt_pgsize_bits) + 1);
}


/*
 * tavor_mr_mem_bind()
 *    Context: Can be called from interrupt or base context.
 */
static int
tavor_mr_mem_bind(tavor_state_t *state, tavor_bind_info_t *bind,
    ddi_dma_handle_t dmahdl, uint_t sleep)
{
	ddi_dma_attr_t	dma_attr;
	int		(*callback)(caddr_t);
	uint_t		dma_xfer_mode;
	int		status;

	/* bi_type must be set to a meaningful value to get a bind handle */
	ASSERT(bind->bi_type == TAVOR_BINDHDL_VADDR ||
	    bind->bi_type == TAVOR_BINDHDL_BUF ||
	    bind->bi_type == TAVOR_BINDHDL_UBUF);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*bind))

	/* Set the callback flag appropriately */
	callback = (sleep == TAVOR_SLEEP) ? DDI_DMA_SLEEP : DDI_DMA_DONTWAIT;

	/* Determine whether to map STREAMING or CONSISTENT */
	dma_xfer_mode = (bind->bi_flags & IBT_MR_NONCOHERENT) ?
	    DDI_DMA_STREAMING : DDI_DMA_CONSISTENT;

	/*
	 * Initialize many of the default DMA attributes.  Then, if we're
	 * bypassing the IOMMU, set the DDI_DMA_FORCE_PHYSICAL flag.
	 */
	if (dmahdl == NULL) {
		tavor_dma_attr_init(&dma_attr);
#ifdef	__sparc
		/*
		 * First, disable streaming and switch to consistent if
		 * configured to do so and IOMMU BYPASS is enabled.
		 */
		if (state->ts_cfg_profile->cp_disable_streaming_on_bypass &&
		    dma_xfer_mode == DDI_DMA_STREAMING &&
		    bind->bi_bypass == TAVOR_BINDMEM_BYPASS) {
			dma_xfer_mode = DDI_DMA_CONSISTENT;
		}

		/*
		 * Then, if streaming is still specified, then "bypass" is not
		 * allowed.
		 */
		if ((dma_xfer_mode == DDI_DMA_CONSISTENT) &&
		    (bind->bi_bypass == TAVOR_BINDMEM_BYPASS)) {
			dma_attr.dma_attr_flags = DDI_DMA_FORCE_PHYSICAL;
		}
#endif
		/* Allocate a DMA handle for the binding */
		status = ddi_dma_alloc_handle(state->ts_dip, &dma_attr,
		    callback, NULL, &bind->bi_dmahdl);
		if (status != DDI_SUCCESS) {
			return (status);
		}
		bind->bi_free_dmahdl = 1;

	} else  {
		bind->bi_dmahdl = dmahdl;
		bind->bi_free_dmahdl = 0;
	}

	/*
	 * Bind the memory to get the PCI mapped addresses.  The decision
	 * to call ddi_dma_addr_bind_handle() or ddi_dma_buf_bind_handle()
	 * is determined by the "bi_type" flag.  Note: if the bind operation
	 * fails then we have to free up the DMA handle and return error.
	 */
	if (bind->bi_type == TAVOR_BINDHDL_VADDR) {
		status = ddi_dma_addr_bind_handle(bind->bi_dmahdl, NULL,
		    (caddr_t)(uintptr_t)bind->bi_addr, bind->bi_len,
		    (DDI_DMA_RDWR | dma_xfer_mode), callback, NULL,
		    &bind->bi_dmacookie, &bind->bi_cookiecnt);
	} else { /* TAVOR_BINDHDL_BUF || TAVOR_BINDHDL_UBUF */
		status = ddi_dma_buf_bind_handle(bind->bi_dmahdl,
		    bind->bi_buf, (DDI_DMA_RDWR | dma_xfer_mode), callback,
		    NULL, &bind->bi_dmacookie, &bind->bi_cookiecnt);
	}

	if (status != DDI_DMA_MAPPED) {
		if (bind->bi_free_dmahdl != 0) {
			ddi_dma_free_handle(&bind->bi_dmahdl);
		}
		return (status);
	}

	return (DDI_SUCCESS);
}


/*
 * tavor_mr_mem_unbind()
 *    Context: Can be called from interrupt or base context.
 */
static void
tavor_mr_mem_unbind(tavor_state_t *state, tavor_bind_info_t *bind)
{
	int	status;

	/*
	 * In case of TAVOR_BINDHDL_UBUF, the memory bi_buf points to
	 * is actually allocated by ddi_umem_iosetup() internally, then
	 * it's required to free it here. Reset bi_type to TAVOR_BINDHDL_NONE
	 * not to free it again later.
	 */
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*bind))
	if (bind->bi_type == TAVOR_BINDHDL_UBUF) {
		freerbuf(bind->bi_buf);
		bind->bi_type = TAVOR_BINDHDL_NONE;
	}
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*bind))

	/*
	 * Unbind the DMA memory for the region
	 *
	 * Note: The only way ddi_dma_unbind_handle() currently
	 * can return an error is if the handle passed in is invalid.
	 * Since this should never happen, we choose to return void
	 * from this function!  If this does return an error, however,
	 * then we print a warning message to the console.
	 */
	status = ddi_dma_unbind_handle(bind->bi_dmahdl);
	if (status != DDI_SUCCESS) {
		TAVOR_WARNING(state, "failed to unbind DMA mapping");
		return;
	}

	/* Free up the DMA handle */
	if (bind->bi_free_dmahdl != 0) {
		ddi_dma_free_handle(&bind->bi_dmahdl);
	}
}


/*
 * tavor_mr_fast_mtt_write()
 *    Context: Can be called from interrupt or base context.
 */
static int
tavor_mr_fast_mtt_write(tavor_rsrc_t *mtt, tavor_bind_info_t *bind,
    uint32_t mtt_pgsize_bits)
{
	ddi_dma_cookie_t	dmacookie;
	uint_t			cookie_cnt;
	uint64_t		*mtt_table;
	uint64_t		mtt_entry;
	uint64_t		addr, endaddr;
	uint64_t		pagesize;
	int			i;

	/* Calculate page size from the suggested value passed in */
	pagesize = ((uint64_t)1 << mtt_pgsize_bits);

	/*
	 * Walk the "cookie list" and fill in the MTT table entries
	 */
	i = 0;
	mtt_table  = (uint64_t *)mtt->tr_addr;
	dmacookie  = bind->bi_dmacookie;
	cookie_cnt = bind->bi_cookiecnt;
	while (cookie_cnt-- > 0) {
		addr	= dmacookie.dmac_laddress;
		endaddr = addr + (dmacookie.dmac_size - 1);
		addr	= addr & ~((uint64_t)pagesize - 1);
		while (addr <= endaddr) {
			/*
			 * Fill in the mapped addresses (calculated above) and
			 * set TAVOR_MTT_ENTRY_PRESET flag for each MTT entry.
			 */
			mtt_entry = addr | TAVOR_MTT_ENTRY_PRESET;
			ddi_put64(mtt->tr_acchdl, &mtt_table[i], mtt_entry);
			addr += pagesize;
			i++;

			if (addr == 0) {
				static int do_once = 1;
				_NOTE(SCHEME_PROTECTS_DATA("safe sharing",
				    do_once))
				if (do_once) {
					do_once = 0;
					cmn_err(CE_NOTE, "probable error in "
					    "dma_cookie address from caller\n");
				}
				break;
			}
		}

		/*
		 * When we've reached the end of the current DMA cookie,
		 * jump to the next cookie (if there are more)
		 */
		if (cookie_cnt != 0) {
			ddi_dma_nextcookie(bind->bi_dmahdl, &dmacookie);
		}
	}

	return (DDI_SUCCESS);
}

/*
 * tavor_mtt_refcnt_inc()
 *    Context: Can be called from interrupt or base context.
 */
static int
tavor_mtt_refcnt_inc(tavor_rsrc_t *rsrc)
{
	tavor_sw_refcnt_t *rc;
	uint32_t	  cnt;

	rc = (tavor_sw_refcnt_t *)rsrc->tr_addr;

	/* Increment the MTT's reference count */
	mutex_enter(&rc->swrc_lock);
	cnt = rc->swrc_refcnt++;
	mutex_exit(&rc->swrc_lock);

	return (cnt);
}


/*
 * tavor_mtt_refcnt_dec()
 *    Context: Can be called from interrupt or base context.
 */
static int
tavor_mtt_refcnt_dec(tavor_rsrc_t *rsrc)
{
	tavor_sw_refcnt_t *rc;
	uint32_t	  cnt;

	rc = (tavor_sw_refcnt_t *)rsrc->tr_addr;

	/* Decrement the MTT's reference count */
	mutex_enter(&rc->swrc_lock);
	cnt = --rc->swrc_refcnt;
	mutex_exit(&rc->swrc_lock);

	return (cnt);
}
