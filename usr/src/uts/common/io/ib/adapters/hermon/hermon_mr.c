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
 * hermon_mr.c
 *    Hermon Memory Region/Window Routines
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

#include <sys/ib/adapters/hermon/hermon.h>

extern uint32_t hermon_kernel_data_ro;
extern uint32_t hermon_user_data_ro;
extern int hermon_rdma_debug;

/*
 * Used by hermon_mr_keycalc() below to fill in the "unconstrained" portion
 * of Hermon memory keys (LKeys and RKeys)
 */
static	uint_t hermon_memkey_cnt = 0x00;
#define	HERMON_MEMKEY_SHIFT	24

/* initial state of an MPT */
#define	HERMON_MPT_SW_OWNERSHIP	0xF	/* memory regions */
#define	HERMON_MPT_FREE		0x3	/* allocate lkey */

static int hermon_mr_common_reg(hermon_state_t *state, hermon_pdhdl_t pd,
    hermon_bind_info_t *bind, hermon_mrhdl_t *mrhdl, hermon_mr_options_t *op,
    hermon_mpt_rsrc_type_t mpt_type);
static int hermon_mr_common_rereg(hermon_state_t *state, hermon_mrhdl_t mr,
    hermon_pdhdl_t pd, hermon_bind_info_t *bind, hermon_mrhdl_t *mrhdl_new,
    hermon_mr_options_t *op);
static int hermon_mr_rereg_xlat_helper(hermon_state_t *state, hermon_mrhdl_t mr,
    hermon_bind_info_t *bind, hermon_mr_options_t *op, uint64_t *mtt_addr,
    uint_t sleep, uint_t *dereg_level);
static uint64_t hermon_mr_nummtt_needed(hermon_state_t *state,
    hermon_bind_info_t *bind, uint_t *mtt_pgsize);
static int hermon_mr_mem_bind(hermon_state_t *state, hermon_bind_info_t *bind,
    ddi_dma_handle_t dmahdl, uint_t sleep, uint_t is_buffer);
static void hermon_mr_mem_unbind(hermon_state_t *state,
    hermon_bind_info_t *bind);
static int hermon_mr_fast_mtt_write(hermon_state_t *state, hermon_rsrc_t *mtt,
    hermon_bind_info_t *bind, uint32_t mtt_pgsize_bits);
static int hermon_mr_fast_mtt_write_fmr(hermon_state_t *state,
    hermon_rsrc_t *mtt, ibt_pmr_attr_t *mem_pattr, uint32_t mtt_pgsize_bits);
static uint_t hermon_mtt_refcnt_inc(hermon_rsrc_t *rsrc);
static uint_t hermon_mtt_refcnt_dec(hermon_rsrc_t *rsrc);


/*
 * The Hermon umem_lockmemory() callback ops.  When userland memory is
 * registered, these callback ops are specified.  The hermon_umap_umemlock_cb()
 * callback will be called whenever the memory for the corresponding
 * ddi_umem_cookie_t is being freed.
 */
static struct umem_callback_ops hermon_umem_cbops = {
	UMEM_CALLBACK_VERSION,
	hermon_umap_umemlock_cb,
};



/*
 * hermon_mr_register()
 *    Context: Can be called from interrupt or base context.
 */
int
hermon_mr_register(hermon_state_t *state, hermon_pdhdl_t pd,
    ibt_mr_attr_t *mr_attr, hermon_mrhdl_t *mrhdl, hermon_mr_options_t *op,
    hermon_mpt_rsrc_type_t mpt_type)
{
	hermon_bind_info_t	bind;
	int			status;

	/*
	 * Fill in the "bind" struct.  This struct provides the majority
	 * of the information that will be used to distinguish between an
	 * "addr" binding (as is the case here) and a "buf" binding (see
	 * below).  The "bind" struct is later passed to hermon_mr_mem_bind()
	 * which does most of the "heavy lifting" for the Hermon memory
	 * registration routines.
	 */
	bind.bi_type  = HERMON_BINDHDL_VADDR;
	bind.bi_addr  = mr_attr->mr_vaddr;
	bind.bi_len   = mr_attr->mr_len;
	bind.bi_as    = mr_attr->mr_as;
	bind.bi_flags = mr_attr->mr_flags;
	status = hermon_mr_common_reg(state, pd, &bind, mrhdl, op,
	    mpt_type);
	return (status);
}


/*
 * hermon_mr_register_buf()
 *    Context: Can be called from interrupt or base context.
 */
int
hermon_mr_register_buf(hermon_state_t *state, hermon_pdhdl_t pd,
    ibt_smr_attr_t *mr_attr, struct buf *buf, hermon_mrhdl_t *mrhdl,
    hermon_mr_options_t *op, hermon_mpt_rsrc_type_t mpt_type)
{
	hermon_bind_info_t	bind;
	int			status;

	/*
	 * Fill in the "bind" struct.  This struct provides the majority
	 * of the information that will be used to distinguish between an
	 * "addr" binding (see above) and a "buf" binding (as is the case
	 * here).  The "bind" struct is later passed to hermon_mr_mem_bind()
	 * which does most of the "heavy lifting" for the Hermon memory
	 * registration routines.  Note: We have chosen to provide
	 * "b_un.b_addr" as the IB address (when the IBT_MR_PHYS_IOVA flag is
	 * not set).  It is not critical what value we choose here as it need
	 * only be unique for the given RKey (which will happen by default),
	 * so the choice here is somewhat arbitrary.
	 */
	bind.bi_type  = HERMON_BINDHDL_BUF;
	bind.bi_buf   = buf;
	if (mr_attr->mr_flags & IBT_MR_PHYS_IOVA) {
		bind.bi_addr  = mr_attr->mr_vaddr;
	} else {
		bind.bi_addr  = (uint64_t)(uintptr_t)buf->b_un.b_addr;
	}
	bind.bi_as    = NULL;
	bind.bi_len   = (uint64_t)buf->b_bcount;
	bind.bi_flags = mr_attr->mr_flags;
	status = hermon_mr_common_reg(state, pd, &bind, mrhdl, op, mpt_type);
	return (status);
}


/*
 * hermon_mr_register_shared()
 *    Context: Can be called from interrupt or base context.
 */
int
hermon_mr_register_shared(hermon_state_t *state, hermon_mrhdl_t mrhdl,
    hermon_pdhdl_t pd, ibt_smr_attr_t *mr_attr, hermon_mrhdl_t *mrhdl_new)
{
	hermon_rsrc_t		*mpt, *mtt, *rsrc;
	hermon_umap_db_entry_t	*umapdb;
	hermon_hw_dmpt_t	mpt_entry;
	hermon_mrhdl_t		mr;
	hermon_bind_info_t	*bind;
	ddi_umem_cookie_t	umem_cookie;
	size_t			umem_len;
	caddr_t			umem_addr;
	uint64_t		mtt_addr, pgsize_msk;
	uint_t			sleep, mr_is_umem;
	int			status, umem_flags;

	/*
	 * Check the sleep flag.  Ensure that it is consistent with the
	 * current thread context (i.e. if we are currently in the interrupt
	 * context, then we shouldn't be attempting to sleep).
	 */
	sleep = (mr_attr->mr_flags & IBT_MR_NOSLEEP) ? HERMON_NOSLEEP :
	    HERMON_SLEEP;
	if ((sleep == HERMON_SLEEP) &&
	    (sleep != HERMON_SLEEPFLAG_FOR_CONTEXT())) {
		status = IBT_INVALID_PARAM;
		goto mrshared_fail;
	}

	/* Increment the reference count on the protection domain (PD) */
	hermon_pd_refcnt_inc(pd);

	/*
	 * Allocate an MPT entry.  This will be filled in with all the
	 * necessary parameters to define the shared memory region.
	 * Specifically, it will be made to reference the currently existing
	 * MTT entries and ownership of the MPT will be passed to the hardware
	 * in the last step below.  If we fail here, we must undo the
	 * protection domain reference count.
	 */
	status = hermon_rsrc_alloc(state, HERMON_DMPT, 1, sleep, &mpt);
	if (status != DDI_SUCCESS) {
		status = IBT_INSUFF_RESOURCE;
		goto mrshared_fail1;
	}

	/*
	 * Allocate the software structure for tracking the shared memory
	 * region (i.e. the Hermon Memory Region handle).  If we fail here, we
	 * must undo the protection domain reference count and the previous
	 * resource allocation.
	 */
	status = hermon_rsrc_alloc(state, HERMON_MRHDL, 1, sleep, &rsrc);
	if (status != DDI_SUCCESS) {
		status = IBT_INSUFF_RESOURCE;
		goto mrshared_fail2;
	}
	mr = (hermon_mrhdl_t)rsrc->hr_addr;
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
	mr->mr_rkey = mr->mr_lkey = hermon_mr_keycalc(mpt->hr_indx);

	/* Grab the MR lock for the current memory region */
	mutex_enter(&mrhdl->mr_lock);

	/*
	 * Check here to see if the memory region has already been partially
	 * deregistered as a result of a hermon_umap_umemlock_cb() callback.
	 * If so, this is an error, return failure.
	 */
	if ((mrhdl->mr_is_umem) && (mrhdl->mr_umemcookie == NULL)) {
		mutex_exit(&mrhdl->mr_lock);
		status = IBT_MR_HDL_INVALID;
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
		umem_len   = ptob(btopr(mrhdl->mr_bindinfo.bi_len));
		umem_addr  = (caddr_t)((uintptr_t)mrhdl->mr_bindinfo.bi_addr &
		    ~PAGEOFFSET);
		umem_flags = (DDI_UMEMLOCK_WRITE | DDI_UMEMLOCK_READ |
		    DDI_UMEMLOCK_LONGTERM);
		status = umem_lockmemory(umem_addr, umem_len, umem_flags,
		    &umem_cookie, &hermon_umem_cbops, NULL);
		if (status != 0) {
			mutex_exit(&mrhdl->mr_lock);
			status = IBT_INSUFF_RESOURCE;
			goto mrshared_fail3;
		}

		umapdb = hermon_umap_db_alloc(state->hs_instance,
		    (uint64_t)(uintptr_t)umem_cookie, MLNX_UMAP_MRMEM_RSRC,
		    (uint64_t)(uintptr_t)rsrc);
		if (umapdb == NULL) {
			mutex_exit(&mrhdl->mr_lock);
			status = IBT_INSUFF_RESOURCE;
			goto mrshared_fail4;
		}
	}

	/*
	 * Copy the MTT resource pointer (and additional parameters) from
	 * the original Hermon Memory Region handle.  Note: this is normally
	 * where the hermon_mr_mem_bind() routine would be called, but because
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
	(void) hermon_mtt_refcnt_inc(mr->mr_mttrefcntp);

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
	 * Fill in the MPT entry.  This is the final step before passing
	 * ownership of the MPT entry to the Hermon hardware.  We use all of
	 * the information collected/calculated above to fill in the
	 * requisite portions of the MPT.
	 */
	bzero(&mpt_entry, sizeof (hermon_hw_dmpt_t));
	mpt_entry.en_bind = (mr->mr_accflag & IBT_MR_WINDOW_BIND)   ? 1 : 0;
	mpt_entry.atomic  = (mr->mr_accflag & IBT_MR_REMOTE_ATOMIC) ? 1 : 0;
	mpt_entry.rw	  = (mr->mr_accflag & IBT_MR_REMOTE_WRITE)  ? 1 : 0;
	mpt_entry.rr	  = (mr->mr_accflag & IBT_MR_REMOTE_READ)   ? 1 : 0;
	mpt_entry.lw	  = (mr->mr_accflag & IBT_MR_LOCAL_WRITE)   ? 1 : 0;
	mpt_entry.lr	  = 1;
	mpt_entry.reg_win = HERMON_MPT_IS_REGION;
	mpt_entry.entity_sz	= mr->mr_logmttpgsz;
	mpt_entry.mem_key	= mr->mr_lkey;
	mpt_entry.pd		= pd->pd_pdnum;
	mpt_entry.start_addr	= bind->bi_addr;
	mpt_entry.reg_win_len	= bind->bi_len;
	mtt_addr = (mtt->hr_indx << HERMON_MTT_SIZE_SHIFT);
	mpt_entry.mtt_addr_h = mtt_addr >> 32;
	mpt_entry.mtt_addr_l = mtt_addr >> 3;

	/*
	 * Write the MPT entry to hardware.  Lastly, we pass ownership of
	 * the entry to the hardware.  Note: in general, this operation
	 * shouldn't fail.  But if it does, we have to undo everything we've
	 * done above before returning error.
	 */
	status = hermon_cmn_ownership_cmd_post(state, SW2HW_MPT, &mpt_entry,
	    sizeof (hermon_hw_dmpt_t), mpt->hr_indx, sleep);
	if (status != HERMON_CMD_SUCCESS) {
		cmn_err(CE_CONT, "Hermon: SW2HW_MPT command failed: %08x\n",
		    status);
		if (status == HERMON_CMD_INVALID_STATUS) {
			hermon_fm_ereport(state, HCA_SYS_ERR, HCA_ERR_SRV_LOST);
		}
		status = ibc_get_ci_failure(0);
		goto mrshared_fail5;
	}

	/*
	 * Fill in the rest of the Hermon Memory Region handle.  Having
	 * successfully transferred ownership of the MPT, we can update the
	 * following fields for use in further operations on the MR.
	 */
	mr->mr_mptrsrcp	  = mpt;
	mr->mr_mttrsrcp	  = mtt;
	mr->mr_mpt_type	  = HERMON_MPT_DMPT;
	mr->mr_pdhdl	  = pd;
	mr->mr_rsrcp	  = rsrc;
	mr->mr_is_umem	  = mr_is_umem;
	mr->mr_is_fmr	  = 0;
	mr->mr_umemcookie = (mr_is_umem != 0) ? umem_cookie : NULL;
	mr->mr_umem_cbfunc = NULL;
	mr->mr_umem_cbarg1 = NULL;
	mr->mr_umem_cbarg2 = NULL;
	mr->mr_lkey	   = hermon_mr_key_swap(mr->mr_lkey);
	mr->mr_rkey	   = hermon_mr_key_swap(mr->mr_rkey);

	/*
	 * If this is userland memory, then we need to insert the previously
	 * allocated entry into the "userland resources database".  This will
	 * allow for later coordination between the hermon_umap_umemlock_cb()
	 * callback and hermon_mr_deregister().
	 */
	if (mr_is_umem) {
		hermon_umap_db_add(umapdb);
	}

	*mrhdl_new = mr;

	return (DDI_SUCCESS);

/*
 * The following is cleanup for all possible failure cases in this routine
 */
mrshared_fail5:
	(void) hermon_mtt_refcnt_dec(mr->mr_mttrefcntp);
	if (mr_is_umem) {
		hermon_umap_db_free(umapdb);
	}
mrshared_fail4:
	if (mr_is_umem) {
		ddi_umem_unlock(umem_cookie);
	}
mrshared_fail3:
	hermon_rsrc_free(state, &rsrc);
mrshared_fail2:
	hermon_rsrc_free(state, &mpt);
mrshared_fail1:
	hermon_pd_refcnt_dec(pd);
mrshared_fail:
	return (status);
}

/*
 * hermon_mr_alloc_fmr()
 *    Context: Can be called from interrupt or base context.
 */
int
hermon_mr_alloc_fmr(hermon_state_t *state, hermon_pdhdl_t pd,
    hermon_fmrhdl_t fmr_pool, hermon_mrhdl_t *mrhdl)
{
	hermon_rsrc_t		*mpt, *mtt, *rsrc;
	hermon_hw_dmpt_t	mpt_entry;
	hermon_mrhdl_t		mr;
	hermon_bind_info_t	bind;
	uint64_t		mtt_addr;
	uint64_t		nummtt;
	uint_t			sleep, mtt_pgsize_bits;
	int			status;
	offset_t		i;
	hermon_icm_table_t	*icm_table;
	hermon_dma_info_t	*dma_info;
	uint32_t		index1, index2, rindx;

	/*
	 * Check the sleep flag.  Ensure that it is consistent with the
	 * current thread context (i.e. if we are currently in the interrupt
	 * context, then we shouldn't be attempting to sleep).
	 */
	sleep = (fmr_pool->fmr_flags & IBT_MR_SLEEP) ? HERMON_SLEEP :
	    HERMON_NOSLEEP;
	if ((sleep == HERMON_SLEEP) &&
	    (sleep != HERMON_SLEEPFLAG_FOR_CONTEXT())) {
		return (IBT_INVALID_PARAM);
	}

	/* Increment the reference count on the protection domain (PD) */
	hermon_pd_refcnt_inc(pd);

	/*
	 * Allocate an MPT entry.  This will be filled in with all the
	 * necessary parameters to define the FMR.  Specifically, it will be
	 * made to reference the currently existing MTT entries and ownership
	 * of the MPT will be passed to the hardware in the last step below.
	 * If we fail here, we must undo the protection domain reference count.
	 */

	status = hermon_rsrc_alloc(state, HERMON_DMPT, 1, sleep, &mpt);
	if (status != DDI_SUCCESS) {
		status = IBT_INSUFF_RESOURCE;
		goto fmralloc_fail1;
	}

	/*
	 * Allocate the software structure for tracking the fmr memory
	 * region (i.e. the Hermon Memory Region handle).  If we fail here, we
	 * must undo the protection domain reference count and the previous
	 * resource allocation.
	 */
	status = hermon_rsrc_alloc(state, HERMON_MRHDL, 1, sleep, &rsrc);
	if (status != DDI_SUCCESS) {
		status = IBT_INSUFF_RESOURCE;
		goto fmralloc_fail2;
	}
	mr = (hermon_mrhdl_t)rsrc->hr_addr;
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*mr))

	/*
	 * Setup and validate the memory region access flags.  This means
	 * translating the IBTF's enable flags into the access flags that
	 * will be used in later operations.
	 */
	mr->mr_accflag = 0;
	if (fmr_pool->fmr_flags & IBT_MR_ENABLE_LOCAL_WRITE)
		mr->mr_accflag |= IBT_MR_LOCAL_WRITE;
	if (fmr_pool->fmr_flags & IBT_MR_ENABLE_REMOTE_READ)
		mr->mr_accflag |= IBT_MR_REMOTE_READ;
	if (fmr_pool->fmr_flags & IBT_MR_ENABLE_REMOTE_WRITE)
		mr->mr_accflag |= IBT_MR_REMOTE_WRITE;
	if (fmr_pool->fmr_flags & IBT_MR_ENABLE_REMOTE_ATOMIC)
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
	mr->mr_fmr_key = 1;	/* ready for the next reload */
	mr->mr_rkey = mr->mr_lkey = mpt->hr_indx;

	/*
	 * Determine number of pages spanned.  This routine uses the
	 * information in the "bind" struct to determine the required
	 * number of MTT entries needed (and returns the suggested page size -
	 * as a "power-of-2" - for each MTT entry).
	 */
	/* Assume address will be page aligned later */
	bind.bi_addr = 0;
	/* Calculate size based on given max pages */
	bind.bi_len = fmr_pool->fmr_max_pages << PAGESHIFT;
	nummtt = hermon_mr_nummtt_needed(state, &bind, &mtt_pgsize_bits);

	/*
	 * Allocate the MTT entries.  Use the calculations performed above to
	 * allocate the required number of MTT entries.  If we fail here, we
	 * must not only undo all the previous resource allocation (and PD
	 * reference count), but we must also unbind the memory.
	 */
	status = hermon_rsrc_alloc(state, HERMON_MTT, nummtt, sleep, &mtt);
	if (status != DDI_SUCCESS) {
		IBTF_DPRINTF_L2("FMR", "FATAL: too few MTTs");
		status = IBT_INSUFF_RESOURCE;
		goto fmralloc_fail3;
	}
	mr->mr_logmttpgsz = mtt_pgsize_bits;

	/*
	 * Fill in the MPT entry.  This is the final step before passing
	 * ownership of the MPT entry to the Hermon hardware.  We use all of
	 * the information collected/calculated above to fill in the
	 * requisite portions of the MPT.
	 */
	bzero(&mpt_entry, sizeof (hermon_hw_dmpt_t));
	mpt_entry.en_bind = 0;
	mpt_entry.atomic  = (mr->mr_accflag & IBT_MR_REMOTE_ATOMIC) ? 1 : 0;
	mpt_entry.rw	  = (mr->mr_accflag & IBT_MR_REMOTE_WRITE)  ? 1 : 0;
	mpt_entry.rr	  = (mr->mr_accflag & IBT_MR_REMOTE_READ)   ? 1 : 0;
	mpt_entry.lw	  = (mr->mr_accflag & IBT_MR_LOCAL_WRITE)   ? 1 : 0;
	mpt_entry.lr	  = 1;
	mpt_entry.reg_win = HERMON_MPT_IS_REGION;
	mpt_entry.pd		= pd->pd_pdnum;

	mpt_entry.entity_sz	= mr->mr_logmttpgsz;
	mtt_addr = (mtt->hr_indx << HERMON_MTT_SIZE_SHIFT);
	mpt_entry.fast_reg_en = 1;
	mpt_entry.mtt_size = (uint_t)nummtt;
	mpt_entry.mtt_addr_h = mtt_addr >> 32;
	mpt_entry.mtt_addr_l = mtt_addr >> 3;
	mpt_entry.mem_key = mr->mr_lkey;

	/*
	 * FMR sets these to 0 for now.  Later during actual fmr registration
	 * these values are filled in.
	 */
	mpt_entry.start_addr	= 0;
	mpt_entry.reg_win_len	= 0;

	/*
	 * Write the MPT entry to hardware.  Lastly, we pass ownership of
	 * the entry to the hardware.  Note: in general, this operation
	 * shouldn't fail.  But if it does, we have to undo everything we've
	 * done above before returning error.
	 */
	status = hermon_cmn_ownership_cmd_post(state, SW2HW_MPT, &mpt_entry,
	    sizeof (hermon_hw_dmpt_t), mpt->hr_indx, sleep);
	if (status != HERMON_CMD_SUCCESS) {
		cmn_err(CE_CONT, "Hermon: SW2HW_MPT command failed: %08x\n",
		    status);
		if (status == HERMON_CMD_INVALID_STATUS) {
			hermon_fm_ereport(state, HCA_SYS_ERR, HCA_ERR_SRV_LOST);
		}
		status = ibc_get_ci_failure(0);
		goto fmralloc_fail4;
	}

	/*
	 * Fill in the rest of the Hermon Memory Region handle.  Having
	 * successfully transferred ownership of the MPT, we can update the
	 * following fields for use in further operations on the MR.  Also, set
	 * that this is an FMR region.
	 */
	mr->mr_mptrsrcp	  = mpt;
	mr->mr_mttrsrcp	  = mtt;

	mr->mr_mpt_type   = HERMON_MPT_DMPT;
	mr->mr_pdhdl	  = pd;
	mr->mr_rsrcp	  = rsrc;
	mr->mr_is_fmr	  = 1;
	mr->mr_lkey	   = hermon_mr_key_swap(mr->mr_lkey);
	mr->mr_rkey	   = hermon_mr_key_swap(mr->mr_rkey);
	mr->mr_mttaddr	   = mtt_addr;
	(void) memcpy(&mr->mr_bindinfo, &bind, sizeof (hermon_bind_info_t));

	/* initialize hr_addr for use during register/deregister/invalidate */
	icm_table = &state->hs_icm[HERMON_DMPT];
	rindx = mpt->hr_indx;
	hermon_index(index1, index2, rindx, icm_table, i);
	dma_info = icm_table->icm_dma[index1] + index2;
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*mpt))
	mpt->hr_addr = (void *)((uintptr_t)(dma_info->vaddr + i * mpt->hr_len));

	*mrhdl = mr;

	return (DDI_SUCCESS);

/*
 * The following is cleanup for all possible failure cases in this routine
 */
fmralloc_fail4:
	kmem_free(mtt, sizeof (hermon_rsrc_t) * nummtt);
fmralloc_fail3:
	hermon_rsrc_free(state, &rsrc);
fmralloc_fail2:
	hermon_rsrc_free(state, &mpt);
fmralloc_fail1:
	hermon_pd_refcnt_dec(pd);
	return (status);
}


/*
 * hermon_mr_register_physical_fmr()
 *    Context: Can be called from interrupt or base context.
 */
/*ARGSUSED*/
int
hermon_mr_register_physical_fmr(hermon_state_t *state,
    ibt_pmr_attr_t *mem_pattr_p, hermon_mrhdl_t mr, ibt_pmr_desc_t *mem_desc_p)
{
	hermon_rsrc_t		*mpt;
	uint64_t		*mpt_table;
	int			status;
	uint32_t		key;

	mutex_enter(&mr->mr_lock);
	mpt = mr->mr_mptrsrcp;
	mpt_table = (uint64_t *)mpt->hr_addr;

	/* Write MPT status to SW bit */
	*(uint8_t *)mpt_table = 0xF0;

	membar_producer();

	/*
	 * Write the mapped addresses into the MTT entries.  FMR needs to do
	 * this a little differently, so we call the fmr specific fast mtt
	 * write here.
	 */
	status = hermon_mr_fast_mtt_write_fmr(state, mr->mr_mttrsrcp,
	    mem_pattr_p, mr->mr_logmttpgsz);
	if (status != DDI_SUCCESS) {
		mutex_exit(&mr->mr_lock);
		status = ibc_get_ci_failure(0);
		goto fmr_reg_fail1;
	}

	/*
	 * Calculate keys (Lkey, Rkey) from MPT index.  Each key is formed
	 * from a certain number of "constrained" bits (the least significant
	 * bits) and some number of "unconstrained" bits.  The constrained
	 * bits must be set to the index of the entry in the MPT table, but
	 * the unconstrained bits can be set to any value we wish.  Note:
	 * if no remote access is required, then the RKey value is not filled
	 * in.  Otherwise both Rkey and LKey are given the same value.
	 */
	key = mpt->hr_indx | (mr->mr_fmr_key++ << HERMON_MEMKEY_SHIFT);
	mr->mr_lkey = mr->mr_rkey = hermon_mr_key_swap(key);

	/* write mem key value */
	*(uint32_t *)&mpt_table[1] = htonl(key);

	/* write length value */
	mpt_table[3] = htonll(mem_pattr_p->pmr_len);

	/* write start addr value */
	mpt_table[2] = htonll(mem_pattr_p->pmr_iova);

	/* write lkey value */
	*(uint32_t *)&mpt_table[4] = htonl(key);

	membar_producer();

	/* Write MPT status to HW bit */
	*(uint8_t *)mpt_table = 0x00;

	/* Fill in return parameters */
	mem_desc_p->pmd_lkey = mr->mr_lkey;
	mem_desc_p->pmd_rkey = mr->mr_rkey;
	mem_desc_p->pmd_iova = mem_pattr_p->pmr_iova;
	mem_desc_p->pmd_phys_buf_list_sz = mem_pattr_p->pmr_len;

	/* Fill in MR bindinfo struct for later sync or query operations */
	mr->mr_bindinfo.bi_addr = mem_pattr_p->pmr_iova;
	mr->mr_bindinfo.bi_flags = mem_pattr_p->pmr_flags & IBT_MR_NONCOHERENT;

	mutex_exit(&mr->mr_lock);

	return (DDI_SUCCESS);

fmr_reg_fail1:
	/*
	 * Note, we fail here, and purposely leave the memory ownership in
	 * software.  The memory tables may be corrupt, so we leave the region
	 * unregistered.
	 */
	return (status);
}


/*
 * hermon_mr_deregister()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
int
hermon_mr_deregister(hermon_state_t *state, hermon_mrhdl_t *mrhdl, uint_t level,
    uint_t sleep)
{
	hermon_rsrc_t		*mpt, *mtt, *rsrc, *mtt_refcnt;
	hermon_umap_db_entry_t	*umapdb;
	hermon_pdhdl_t		pd;
	hermon_mrhdl_t		mr;
	hermon_bind_info_t	*bind;
	uint64_t		value;
	int			status;
	uint_t			shared_mtt;

	/*
	 * Check the sleep flag.  Ensure that it is consistent with the
	 * current thread context (i.e. if we are currently in the interrupt
	 * context, then we shouldn't be attempting to sleep).
	 */
	if ((sleep == HERMON_SLEEP) &&
	    (sleep != HERMON_SLEEPFLAG_FOR_CONTEXT())) {
		status = IBT_INVALID_PARAM;
		return (status);
	}

	/*
	 * Pull all the necessary information from the Hermon Memory Region
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
	 * Check here if the memory region is really an FMR.  If so, this is a
	 * bad thing and we shouldn't be here.  Return failure.
	 */
	if (mr->mr_is_fmr) {
		mutex_exit(&mr->mr_lock);
		return (IBT_INVALID_PARAM);
	}

	/*
	 * Check here to see if the memory region has already been partially
	 * deregistered as a result of the hermon_umap_umemlock_cb() callback.
	 * If so, then jump to the end and free the remaining resources.
	 */
	if ((mr->mr_is_umem) && (mr->mr_umemcookie == NULL)) {
		goto mrdereg_finish_cleanup;
	}
	if (hermon_rdma_debug & 0x4)
		IBTF_DPRINTF_L2("mr", "dereg: mr %p  key %x",
		    mr, mr->mr_rkey);

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
	 * hermon_mr_deregister() routine is used in the memory region
	 * reregistration process as well, it is possible that we will
	 * not always wish to reclaim ownership of the MPT.  Check the
	 * "level" arg and, if necessary, attempt to reclaim it.  If
	 * the ownership transfer fails for any reason, we check to see
	 * what command status was returned from the hardware.  The only
	 * "expected" error status is the one that indicates an attempt to
	 * deregister a memory region that has memory windows bound to it
	 */
	if (level >= HERMON_MR_DEREG_ALL) {
		if (mr->mr_mpt_type >= HERMON_MPT_DMPT) {
			status = hermon_cmn_ownership_cmd_post(state, HW2SW_MPT,
			    NULL, 0, mpt->hr_indx, sleep);
			if (status != HERMON_CMD_SUCCESS) {
				if (status == HERMON_CMD_REG_BOUND) {
					return (IBT_MR_IN_USE);
				} else {
					cmn_err(CE_CONT, "Hermon: HW2SW_MPT "
					    "command failed: %08x\n", status);
					if (status ==
					    HERMON_CMD_INVALID_STATUS) {
						hermon_fm_ereport(state,
						    HCA_SYS_ERR,
						    DDI_SERVICE_LOST);
					}
					return (IBT_INVALID_PARAM);
				}
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
	 * hermon_mr_deregister()), we call ddi_umem_unlock() and invalidate
	 * the "mr_umemcookie" field in the MR handle (this will be used
	 * later to detect that only partial cleaup still remains to be done
	 * on the MR handle).
	 */
	if (mr->mr_is_umem) {
		status = hermon_umap_db_find(state->hs_instance,
		    (uint64_t)(uintptr_t)mr->mr_umemcookie,
		    MLNX_UMAP_MRMEM_RSRC, &value, HERMON_UMAP_DB_REMOVE,
		    &umapdb);
		if (status == DDI_SUCCESS) {
			hermon_umap_db_free(umapdb);
			ddi_umem_unlock(mr->mr_umemcookie);
		} else {
			ddi_umem_unlock(mr->mr_umemcookie);
			mr->mr_umemcookie = NULL;
		}
	}

	/* mtt_refcnt is NULL in the case of hermon_dma_mr_register() */
	if (mtt_refcnt != NULL) {
		/*
		 * Decrement the MTT reference count.  Since the MTT resource
		 * may be shared between multiple memory regions (as a result
		 * of a "RegisterSharedMR" verb) it is important that we not
		 * free up or unbind resources prematurely.  If it's not shared
		 * (as indicated by the return status), then free the resource.
		 */
		shared_mtt = hermon_mtt_refcnt_dec(mtt_refcnt);
		if (!shared_mtt) {
			hermon_rsrc_free(state, &mtt_refcnt);
		}

		/*
		 * Free up the MTT entries and unbind the memory.  Here,
		 * as above, we attempt to free these resources only if
		 * it is appropriate to do so.
		 * Note, 'bind' is NULL in the alloc_lkey case.
		 */
		if (!shared_mtt) {
			if (level >= HERMON_MR_DEREG_NO_HW2SW_MPT) {
				hermon_mr_mem_unbind(state, bind);
			}
			hermon_rsrc_free(state, &mtt);
		}
	}

	/*
	 * If the MR handle has been invalidated, then drop the
	 * lock and return success.  Note: This only happens because
	 * the umem_lockmemory() callback has been triggered.  The
	 * cleanup here is partial, and further cleanup (in a
	 * subsequent hermon_mr_deregister() call) will be necessary.
	 */
	if ((mr->mr_is_umem) && (mr->mr_umemcookie == NULL)) {
		mutex_exit(&mr->mr_lock);
		return (DDI_SUCCESS);
	}

mrdereg_finish_cleanup:
	mutex_exit(&mr->mr_lock);

	/* Free the Hermon Memory Region handle */
	hermon_rsrc_free(state, &rsrc);

	/* Free up the MPT entry resource */
	if (mpt != NULL)
		hermon_rsrc_free(state, &mpt);

	/* Decrement the reference count on the protection domain (PD) */
	hermon_pd_refcnt_dec(pd);

	/* Set the mrhdl pointer to NULL and return success */
	*mrhdl = NULL;

	return (DDI_SUCCESS);
}

/*
 * hermon_mr_dealloc_fmr()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
int
hermon_mr_dealloc_fmr(hermon_state_t *state, hermon_mrhdl_t *mrhdl)
{
	hermon_rsrc_t		*mpt, *mtt, *rsrc;
	hermon_pdhdl_t		pd;
	hermon_mrhdl_t		mr;

	/*
	 * Pull all the necessary information from the Hermon Memory Region
	 * handle.  This is necessary here because the resource for the
	 * MR handle is going to be freed up as part of the this
	 * deregistration
	 */
	mr	= *mrhdl;
	mutex_enter(&mr->mr_lock);
	mpt	= mr->mr_mptrsrcp;
	mtt	= mr->mr_mttrsrcp;
	rsrc	= mr->mr_rsrcp;
	pd	= mr->mr_pdhdl;
	mutex_exit(&mr->mr_lock);

	/* Free the MTT entries */
	hermon_rsrc_free(state, &mtt);

	/* Free the Hermon Memory Region handle */
	hermon_rsrc_free(state, &rsrc);

	/* Free up the MPT entry resource */
	hermon_rsrc_free(state, &mpt);

	/* Decrement the reference count on the protection domain (PD) */
	hermon_pd_refcnt_dec(pd);

	/* Set the mrhdl pointer to NULL and return success */
	*mrhdl = NULL;

	return (DDI_SUCCESS);
}


/*
 * hermon_mr_query()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
int
hermon_mr_query(hermon_state_t *state, hermon_mrhdl_t mr,
    ibt_mr_query_attr_t *attr)
{
	int			status;
	hermon_hw_dmpt_t	mpt_entry;
	uint32_t		lkey;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*attr))

	mutex_enter(&mr->mr_lock);

	/*
	 * Check here to see if the memory region has already been partially
	 * deregistered as a result of a hermon_umap_umemlock_cb() callback.
	 * If so, this is an error, return failure.
	 */
	if ((mr->mr_is_umem) && (mr->mr_umemcookie == NULL)) {
		mutex_exit(&mr->mr_lock);
		return (IBT_MR_HDL_INVALID);
	}

	status = hermon_cmn_query_cmd_post(state, QUERY_MPT, 0,
	    mr->mr_lkey >> 8, &mpt_entry, sizeof (hermon_hw_dmpt_t),
	    HERMON_NOSLEEP);
	if (status != HERMON_CMD_SUCCESS) {
		cmn_err(CE_CONT, "Hermon: QUERY_MPT failed: status %x", status);
		mutex_exit(&mr->mr_lock);
		return (ibc_get_ci_failure(0));
	}

	/* Update the mr sw struct from the hw struct. */
	lkey = mpt_entry.mem_key;
	mr->mr_lkey = mr->mr_rkey = (lkey >> 8) | (lkey << 24);
	mr->mr_bindinfo.bi_addr = mpt_entry.start_addr;
	mr->mr_bindinfo.bi_len = mpt_entry.reg_win_len;
	mr->mr_accflag = (mr->mr_accflag & IBT_MR_RO_DISABLED) |
	    (mpt_entry.lw ? IBT_MR_LOCAL_WRITE : 0) |
	    (mpt_entry.rr ? IBT_MR_REMOTE_READ : 0) |
	    (mpt_entry.rw ? IBT_MR_REMOTE_WRITE : 0) |
	    (mpt_entry.atomic ? IBT_MR_REMOTE_ATOMIC : 0) |
	    (mpt_entry.en_bind ? IBT_MR_WINDOW_BIND : 0);
	mr->mr_mttaddr = ((uint64_t)mpt_entry.mtt_addr_h << 32) |
	    (mpt_entry.mtt_addr_l << 3);
	mr->mr_logmttpgsz = mpt_entry.entity_sz;

	/* Fill in the queried attributes */
	attr->mr_lkey_state =
	    (mpt_entry.status == HERMON_MPT_FREE) ? IBT_KEY_FREE :
	    (mpt_entry.status == HERMON_MPT_SW_OWNERSHIP) ? IBT_KEY_INVALID :
	    IBT_KEY_VALID;
	attr->mr_phys_buf_list_sz = mpt_entry.mtt_size;
	attr->mr_attr_flags = mr->mr_accflag;
	attr->mr_pd = (ibt_pd_hdl_t)mr->mr_pdhdl;

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
 * hermon_mr_reregister()
 *    Context: Can be called from interrupt or base context.
 */
int
hermon_mr_reregister(hermon_state_t *state, hermon_mrhdl_t mr,
    hermon_pdhdl_t pd, ibt_mr_attr_t *mr_attr, hermon_mrhdl_t *mrhdl_new,
    hermon_mr_options_t *op)
{
	hermon_bind_info_t	bind;
	int			status;

	/*
	 * Fill in the "bind" struct.  This struct provides the majority
	 * of the information that will be used to distinguish between an
	 * "addr" binding (as is the case here) and a "buf" binding (see
	 * below).  The "bind" struct is later passed to hermon_mr_mem_bind()
	 * which does most of the "heavy lifting" for the Hermon memory
	 * registration (and reregistration) routines.
	 */
	bind.bi_type  = HERMON_BINDHDL_VADDR;
	bind.bi_addr  = mr_attr->mr_vaddr;
	bind.bi_len   = mr_attr->mr_len;
	bind.bi_as    = mr_attr->mr_as;
	bind.bi_flags = mr_attr->mr_flags;
	status = hermon_mr_common_rereg(state, mr, pd, &bind, mrhdl_new, op);
	return (status);
}


/*
 * hermon_mr_reregister_buf()
 *    Context: Can be called from interrupt or base context.
 */
int
hermon_mr_reregister_buf(hermon_state_t *state, hermon_mrhdl_t mr,
    hermon_pdhdl_t pd, ibt_smr_attr_t *mr_attr, struct buf *buf,
    hermon_mrhdl_t *mrhdl_new, hermon_mr_options_t *op)
{
	hermon_bind_info_t	bind;
	int			status;

	/*
	 * Fill in the "bind" struct.  This struct provides the majority
	 * of the information that will be used to distinguish between an
	 * "addr" binding (see above) and a "buf" binding (as is the case
	 * here).  The "bind" struct is later passed to hermon_mr_mem_bind()
	 * which does most of the "heavy lifting" for the Hermon memory
	 * registration routines.  Note: We have chosen to provide
	 * "b_un.b_addr" as the IB address (when the IBT_MR_PHYS_IOVA flag is
	 * not set).  It is not critical what value we choose here as it need
	 * only be unique for the given RKey (which will happen by default),
	 * so the choice here is somewhat arbitrary.
	 */
	bind.bi_type  = HERMON_BINDHDL_BUF;
	bind.bi_buf   = buf;
	if (mr_attr->mr_flags & IBT_MR_PHYS_IOVA) {
		bind.bi_addr  = mr_attr->mr_vaddr;
	} else {
		bind.bi_addr  = (uint64_t)(uintptr_t)buf->b_un.b_addr;
	}
	bind.bi_len   = (uint64_t)buf->b_bcount;
	bind.bi_flags = mr_attr->mr_flags;
	bind.bi_as    = NULL;
	status = hermon_mr_common_rereg(state, mr, pd, &bind, mrhdl_new, op);
	return (status);
}


/*
 * hermon_mr_sync()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
int
hermon_mr_sync(hermon_state_t *state, ibt_mr_sync_t *mr_segs, size_t num_segs)
{
	hermon_mrhdl_t		mrhdl;
	uint64_t		seg_vaddr, seg_len, seg_end;
	uint64_t		mr_start, mr_end;
	uint_t			type;
	int			status, i;

	/* Process each of the ibt_mr_sync_t's */
	for (i = 0; i < num_segs; i++) {
		mrhdl = (hermon_mrhdl_t)mr_segs[i].ms_handle;

		/* Check for valid memory region handle */
		if (mrhdl == NULL) {
			status = IBT_MR_HDL_INVALID;
			goto mrsync_fail;
		}

		mutex_enter(&mrhdl->mr_lock);

		/*
		 * Check here to see if the memory region has already been
		 * partially deregistered as a result of a
		 * hermon_umap_umemlock_cb() callback.  If so, this is an
		 * error, return failure.
		 */
		if ((mrhdl->mr_is_umem) && (mrhdl->mr_umemcookie == NULL)) {
			mutex_exit(&mrhdl->mr_lock);
			status = IBT_MR_HDL_INVALID;
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
			status = IBT_MR_VA_INVALID;
			goto mrsync_fail;
		}
		if ((seg_end < mr_start) || (seg_end > mr_end)) {
			mutex_exit(&mrhdl->mr_lock);
			status = IBT_MR_LEN_INVALID;
			goto mrsync_fail;
		}

		/* Determine what type (i.e. direction) for sync */
		if (mr_segs[i].ms_flags & IBT_SYNC_READ) {
			type = DDI_DMA_SYNC_FORDEV;
		} else if (mr_segs[i].ms_flags & IBT_SYNC_WRITE) {
			type = DDI_DMA_SYNC_FORCPU;
		} else {
			mutex_exit(&mrhdl->mr_lock);
			status = IBT_INVALID_PARAM;
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
 * hermon_mw_alloc()
 *    Context: Can be called from interrupt or base context.
 */
int
hermon_mw_alloc(hermon_state_t *state, hermon_pdhdl_t pd, ibt_mw_flags_t flags,
    hermon_mwhdl_t *mwhdl)
{
	hermon_rsrc_t		*mpt, *rsrc;
	hermon_hw_dmpt_t		mpt_entry;
	hermon_mwhdl_t		mw;
	uint_t			sleep;
	int			status;

	if (state != NULL)	/* XXX - bogus test that is always TRUE */
		return (IBT_INSUFF_RESOURCE);

	/*
	 * Check the sleep flag.  Ensure that it is consistent with the
	 * current thread context (i.e. if we are currently in the interrupt
	 * context, then we shouldn't be attempting to sleep).
	 */
	sleep = (flags & IBT_MW_NOSLEEP) ? HERMON_NOSLEEP : HERMON_SLEEP;
	if ((sleep == HERMON_SLEEP) &&
	    (sleep != HERMON_SLEEPFLAG_FOR_CONTEXT())) {
		status = IBT_INVALID_PARAM;
		goto mwalloc_fail;
	}

	/* Increment the reference count on the protection domain (PD) */
	hermon_pd_refcnt_inc(pd);

	/*
	 * Allocate an MPT entry (for use as a memory window).  Since the
	 * Hermon hardware uses the MPT entry for memory regions and for
	 * memory windows, we will fill in this MPT with all the necessary
	 * parameters for the memory window.  And then (just as we do for
	 * memory regions) ownership will be passed to the hardware in the
	 * final step below.  If we fail here, we must undo the protection
	 * domain reference count.
	 */
	status = hermon_rsrc_alloc(state, HERMON_DMPT, 1, sleep, &mpt);
	if (status != DDI_SUCCESS) {
		status = IBT_INSUFF_RESOURCE;
		goto mwalloc_fail1;
	}

	/*
	 * Allocate the software structure for tracking the memory window (i.e.
	 * the Hermon Memory Window handle).  Note: This is actually the same
	 * software structure used for tracking memory regions, but since many
	 * of the same properties are needed, only a single structure is
	 * necessary.  If we fail here, we must undo the protection domain
	 * reference count and the previous resource allocation.
	 */
	status = hermon_rsrc_alloc(state, HERMON_MRHDL, 1, sleep, &rsrc);
	if (status != DDI_SUCCESS) {
		status = IBT_INSUFF_RESOURCE;
		goto mwalloc_fail2;
	}
	mw = (hermon_mwhdl_t)rsrc->hr_addr;
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*mw))

	/*
	 * Calculate an "unbound" RKey from MPT index.  In much the same way
	 * as we do for memory regions (above), this key is constructed from
	 * a "constrained" (which depends on the MPT index) and an
	 * "unconstrained" portion (which may be arbitrarily chosen).
	 */
	mw->mr_rkey = hermon_mr_keycalc(mpt->hr_indx);

	/*
	 * Fill in the MPT entry.  This is the final step before passing
	 * ownership of the MPT entry to the Hermon hardware.  We use all of
	 * the information collected/calculated above to fill in the
	 * requisite portions of the MPT.  Note: fewer entries in the MPT
	 * entry are necessary to allocate a memory window.
	 */
	bzero(&mpt_entry, sizeof (hermon_hw_dmpt_t));
	mpt_entry.reg_win	= HERMON_MPT_IS_WINDOW;
	mpt_entry.mem_key	= mw->mr_rkey;
	mpt_entry.pd		= pd->pd_pdnum;
	mpt_entry.lr		= 1;

	/*
	 * Write the MPT entry to hardware.  Lastly, we pass ownership of
	 * the entry to the hardware.  Note: in general, this operation
	 * shouldn't fail.  But if it does, we have to undo everything we've
	 * done above before returning error.
	 */
	status = hermon_cmn_ownership_cmd_post(state, SW2HW_MPT, &mpt_entry,
	    sizeof (hermon_hw_dmpt_t), mpt->hr_indx, sleep);
	if (status != HERMON_CMD_SUCCESS) {
		cmn_err(CE_CONT, "Hermon: SW2HW_MPT command failed: %08x\n",
		    status);
		if (status == HERMON_CMD_INVALID_STATUS) {
			hermon_fm_ereport(state, HCA_SYS_ERR, HCA_ERR_SRV_LOST);
		}
		status = ibc_get_ci_failure(0);
		goto mwalloc_fail3;
	}

	/*
	 * Fill in the rest of the Hermon Memory Window handle.  Having
	 * successfully transferred ownership of the MPT, we can update the
	 * following fields for use in further operations on the MW.
	 */
	mw->mr_mptrsrcp	= mpt;
	mw->mr_pdhdl	= pd;
	mw->mr_rsrcp	= rsrc;
	mw->mr_rkey	= hermon_mr_key_swap(mw->mr_rkey);
	*mwhdl = mw;

	return (DDI_SUCCESS);

mwalloc_fail3:
	hermon_rsrc_free(state, &rsrc);
mwalloc_fail2:
	hermon_rsrc_free(state, &mpt);
mwalloc_fail1:
	hermon_pd_refcnt_dec(pd);
mwalloc_fail:
	return (status);
}


/*
 * hermon_mw_free()
 *    Context: Can be called from interrupt or base context.
 */
int
hermon_mw_free(hermon_state_t *state, hermon_mwhdl_t *mwhdl, uint_t sleep)
{
	hermon_rsrc_t		*mpt, *rsrc;
	hermon_mwhdl_t		mw;
	int			status;
	hermon_pdhdl_t		pd;

	/*
	 * Check the sleep flag.  Ensure that it is consistent with the
	 * current thread context (i.e. if we are currently in the interrupt
	 * context, then we shouldn't be attempting to sleep).
	 */
	if ((sleep == HERMON_SLEEP) &&
	    (sleep != HERMON_SLEEPFLAG_FOR_CONTEXT())) {
		status = IBT_INVALID_PARAM;
		return (status);
	}

	/*
	 * Pull all the necessary information from the Hermon Memory Window
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
	status = hermon_cmn_ownership_cmd_post(state, HW2SW_MPT, NULL,
	    0, mpt->hr_indx, sleep);
	if (status != HERMON_CMD_SUCCESS) {
		cmn_err(CE_CONT, "Hermon: HW2SW_MPT command failed: %08x\n",
		    status);
		if (status == HERMON_CMD_INVALID_STATUS) {
			hermon_fm_ereport(state, HCA_SYS_ERR, HCA_ERR_SRV_LOST);
		}
		return (ibc_get_ci_failure(0));
	}

	/* Free the Hermon Memory Window handle */
	hermon_rsrc_free(state, &rsrc);

	/* Free up the MPT entry resource */
	hermon_rsrc_free(state, &mpt);

	/* Decrement the reference count on the protection domain (PD) */
	hermon_pd_refcnt_dec(pd);

	/* Set the mwhdl pointer to NULL and return success */
	*mwhdl = NULL;

	return (DDI_SUCCESS);
}


/*
 * hermon_mr_keycalc()
 *    Context: Can be called from interrupt or base context.
 *    NOTE:  Produces a key in the form of
 *		KKKKKKKK IIIIIIII IIIIIIII IIIIIIIII
 *    where K == the arbitrary bits and I == the index
 */
uint32_t
hermon_mr_keycalc(uint32_t indx)
{
	uint32_t tmp_key, tmp_indx;

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
	 * And, lastly, we'd like to make this into a "random" key
	 */
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(hermon_memkey_cnt))
	tmp_key = (hermon_memkey_cnt++) << HERMON_MEMKEY_SHIFT;
	tmp_indx = indx & 0xffffff;
	return (tmp_key | tmp_indx);
}


/*
 * hermon_mr_key_swap()
 *    Context: Can be called from interrupt or base context.
 *    NOTE:  Produces a key in the form of
 *		IIIIIIII IIIIIIII IIIIIIIII KKKKKKKK
 *    where K == the arbitrary bits and I == the index
 */
uint32_t
hermon_mr_key_swap(uint32_t indx)
{
	/*
	 * The memory key format to pass down to the hardware is
	 * (key[7:0],index[23:0]), which defines the index to the
	 * hardware resource. When the driver passes this as a memory
	 * key, (i.e. to retrieve a resource) the format is
	 * (index[23:0],key[7:0]).
	 */
	return (((indx >> 24) & 0x000000ff) | ((indx << 8) & 0xffffff00));
}

/*
 * hermon_mr_common_reg()
 *    Context: Can be called from interrupt or base context.
 */
static int
hermon_mr_common_reg(hermon_state_t *state, hermon_pdhdl_t pd,
    hermon_bind_info_t *bind, hermon_mrhdl_t *mrhdl, hermon_mr_options_t *op,
    hermon_mpt_rsrc_type_t mpt_type)
{
	hermon_rsrc_t		*mpt, *mtt, *rsrc, *mtt_refcnt;
	hermon_umap_db_entry_t	*umapdb;
	hermon_sw_refcnt_t	*swrc_tmp;
	hermon_hw_dmpt_t	mpt_entry;
	hermon_mrhdl_t		mr;
	ibt_mr_flags_t		flags;
	hermon_bind_info_t	*bh;
	ddi_dma_handle_t	bind_dmahdl;
	ddi_umem_cookie_t	umem_cookie;
	size_t			umem_len;
	caddr_t			umem_addr;
	uint64_t		mtt_addr, max_sz;
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
		bind_type   = HERMON_BINDMEM_NORMAL;
		bind_dmahdl = NULL;
		bind_override_addr = 0;
	} else {
		bind_type	   = op->mro_bind_type;
		bind_dmahdl	   = op->mro_bind_dmahdl;
		bind_override_addr = op->mro_bind_override_addr;
	}

	/* check what kind of mpt to use */

	/* Extract the flags field from the hermon_bind_info_t */
	flags = bind->bi_flags;

	/*
	 * Check for invalid length.  Check is the length is zero or if the
	 * length is larger than the maximum configured value.  Return error
	 * if it is.
	 */
	max_sz = ((uint64_t)1 << state->hs_cfg_profile->cp_log_max_mrw_sz);
	if ((bind->bi_len == 0) || (bind->bi_len > max_sz)) {
		status = IBT_MR_LEN_INVALID;
		goto mrcommon_fail;
	}

	/*
	 * Check the sleep flag.  Ensure that it is consistent with the
	 * current thread context (i.e. if we are currently in the interrupt
	 * context, then we shouldn't be attempting to sleep).
	 */
	sleep = (flags & IBT_MR_NOSLEEP) ? HERMON_NOSLEEP: HERMON_SLEEP;
	if ((sleep == HERMON_SLEEP) &&
	    (sleep != HERMON_SLEEPFLAG_FOR_CONTEXT())) {
		status = IBT_INVALID_PARAM;
		goto mrcommon_fail;
	}

	/* Increment the reference count on the protection domain (PD) */
	hermon_pd_refcnt_inc(pd);

	/*
	 * Allocate an MPT entry.  This will be filled in with all the
	 * necessary parameters to define the memory region.  And then
	 * ownership will be passed to the hardware in the final step
	 * below.  If we fail here, we must undo the protection domain
	 * reference count.
	 */
	if (mpt_type == HERMON_MPT_DMPT) {
		status = hermon_rsrc_alloc(state, HERMON_DMPT, 1, sleep, &mpt);
		if (status != DDI_SUCCESS) {
			status = IBT_INSUFF_RESOURCE;
			goto mrcommon_fail1;
		}
	} else {
		mpt = NULL;
	}

	/*
	 * Allocate the software structure for tracking the memory region (i.e.
	 * the Hermon Memory Region handle).  If we fail here, we must undo
	 * the protection domain reference count and the previous resource
	 * allocation.
	 */
	status = hermon_rsrc_alloc(state, HERMON_MRHDL, 1, sleep, &rsrc);
	if (status != DDI_SUCCESS) {
		status = IBT_INSUFF_RESOURCE;
		goto mrcommon_fail2;
	}
	mr = (hermon_mrhdl_t)rsrc->hr_addr;
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
	if (mpt)
		mr->mr_rkey = mr->mr_lkey = hermon_mr_keycalc(mpt->hr_indx);

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
		    &umem_cookie, &hermon_umem_cbops, NULL);
		if (status != 0) {
			status = IBT_INSUFF_RESOURCE;
			goto mrcommon_fail3;
		}

		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*bind))
		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*bind->bi_buf))

		bind->bi_buf = ddi_umem_iosetup(umem_cookie, 0, umem_len,
		    B_WRITE, 0, 0, NULL, DDI_UMEM_SLEEP);
		if (bind->bi_buf == NULL) {
			status = IBT_INSUFF_RESOURCE;
			goto mrcommon_fail3;
		}
		bind->bi_type = HERMON_BINDHDL_UBUF;
		bind->bi_buf->b_flags |= B_READ;

		_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*bind->bi_buf))
		_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*bind))

		umapdb = hermon_umap_db_alloc(state->hs_instance,
		    (uint64_t)(uintptr_t)umem_cookie, MLNX_UMAP_MRMEM_RSRC,
		    (uint64_t)(uintptr_t)rsrc);
		if (umapdb == NULL) {
			status = IBT_INSUFF_RESOURCE;
			goto mrcommon_fail4;
		}
	}

	/*
	 * Setup the bindinfo for the mtt bind call
	 */
	bh = &mr->mr_bindinfo;
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*bh))
	bcopy(bind, bh, sizeof (hermon_bind_info_t));
	bh->bi_bypass = bind_type;
	status = hermon_mr_mtt_bind(state, bh, bind_dmahdl, &mtt,
	    &mtt_pgsize_bits, mpt != NULL);
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
	status = hermon_rsrc_alloc(state, HERMON_REFCNT, 1, sleep,
	    &mtt_refcnt);
	if (status != DDI_SUCCESS) {
		status = IBT_INSUFF_RESOURCE;
		goto mrcommon_fail6;
	}
	mr->mr_mttrefcntp = mtt_refcnt;
	swrc_tmp = (hermon_sw_refcnt_t *)mtt_refcnt->hr_addr;
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*swrc_tmp))
	HERMON_MTT_REFCNT_INIT(swrc_tmp);

	mtt_addr = (mtt->hr_indx << HERMON_MTT_SIZE_SHIFT);

	/*
	 * Fill in the MPT entry.  This is the final step before passing
	 * ownership of the MPT entry to the Hermon hardware.  We use all of
	 * the information collected/calculated above to fill in the
	 * requisite portions of the MPT.  Do this ONLY for DMPTs.
	 */
	if (mpt == NULL)
		goto no_passown;

	bzero(&mpt_entry, sizeof (hermon_hw_dmpt_t));

	mpt_entry.status  = HERMON_MPT_SW_OWNERSHIP;
	mpt_entry.en_bind = (mr->mr_accflag & IBT_MR_WINDOW_BIND)   ? 1 : 0;
	mpt_entry.atomic  = (mr->mr_accflag & IBT_MR_REMOTE_ATOMIC) ? 1 : 0;
	mpt_entry.rw	  = (mr->mr_accflag & IBT_MR_REMOTE_WRITE)  ? 1 : 0;
	mpt_entry.rr	  = (mr->mr_accflag & IBT_MR_REMOTE_READ)   ? 1 : 0;
	mpt_entry.lw	  = (mr->mr_accflag & IBT_MR_LOCAL_WRITE)   ? 1 : 0;
	mpt_entry.lr	  = 1;
	mpt_entry.phys_addr = 0;
	mpt_entry.reg_win = HERMON_MPT_IS_REGION;

	mpt_entry.entity_sz	= mr->mr_logmttpgsz;
	mpt_entry.mem_key	= mr->mr_lkey;
	mpt_entry.pd		= pd->pd_pdnum;
	mpt_entry.rem_acc_en = 0;
	mpt_entry.fast_reg_en = 0;
	mpt_entry.en_inval = 0;
	mpt_entry.lkey = 0;
	mpt_entry.win_cnt = 0;

	if (bind_override_addr == 0) {
		mpt_entry.start_addr = bh->bi_addr;
	} else {
		bh->bi_addr = bh->bi_addr & ((1 << mr->mr_logmttpgsz) - 1);
		mpt_entry.start_addr = bh->bi_addr;
	}
	mpt_entry.reg_win_len	= bh->bi_len;

	mpt_entry.mtt_addr_h = mtt_addr >> 32;  /* only 8 more bits */
	mpt_entry.mtt_addr_l = mtt_addr >> 3;	/* only 29 bits */

	/*
	 * Write the MPT entry to hardware.  Lastly, we pass ownership of
	 * the entry to the hardware if needed.  Note: in general, this
	 * operation shouldn't fail.  But if it does, we have to undo
	 * everything we've done above before returning error.
	 *
	 * For Hermon, this routine (which is common to the contexts) will only
	 * set the ownership if needed - the process of passing the context
	 * itself to HW will take care of setting up the MPT (based on type
	 * and index).
	 */

	mpt_entry.bnd_qp = 0;	/* dMPT for a qp, check for window */
	status = hermon_cmn_ownership_cmd_post(state, SW2HW_MPT, &mpt_entry,
	    sizeof (hermon_hw_dmpt_t), mpt->hr_indx, sleep);
	if (status != HERMON_CMD_SUCCESS) {
		cmn_err(CE_CONT, "Hermon: SW2HW_MPT command failed: %08x\n",
		    status);
		if (status == HERMON_CMD_INVALID_STATUS) {
			hermon_fm_ereport(state, HCA_SYS_ERR, HCA_ERR_SRV_LOST);
		}
		status = ibc_get_ci_failure(0);
		goto mrcommon_fail7;
	}
	if (hermon_rdma_debug & 0x4)
		IBTF_DPRINTF_L2("mr", "  reg: mr %p  key %x",
		    mr, hermon_mr_key_swap(mr->mr_rkey));
no_passown:

	/*
	 * Fill in the rest of the Hermon Memory Region handle.  Having
	 * successfully transferred ownership of the MPT, we can update the
	 * following fields for use in further operations on the MR.
	 */
	mr->mr_mttaddr	   = mtt_addr;

	mr->mr_log2_pgsz   = (mr->mr_logmttpgsz - HERMON_PAGESHIFT);
	mr->mr_mptrsrcp	   = mpt;
	mr->mr_mttrsrcp	   = mtt;
	mr->mr_pdhdl	   = pd;
	mr->mr_rsrcp	   = rsrc;
	mr->mr_is_umem	   = mr_is_umem;
	mr->mr_is_fmr	   = 0;
	mr->mr_umemcookie  = (mr_is_umem != 0) ? umem_cookie : NULL;
	mr->mr_umem_cbfunc = NULL;
	mr->mr_umem_cbarg1 = NULL;
	mr->mr_umem_cbarg2 = NULL;
	mr->mr_lkey	   = hermon_mr_key_swap(mr->mr_lkey);
	mr->mr_rkey	   = hermon_mr_key_swap(mr->mr_rkey);
	mr->mr_mpt_type	   = mpt_type;

	/*
	 * If this is userland memory, then we need to insert the previously
	 * allocated entry into the "userland resources database".  This will
	 * allow for later coordination between the hermon_umap_umemlock_cb()
	 * callback and hermon_mr_deregister().
	 */
	if (mr_is_umem) {
		hermon_umap_db_add(umapdb);
	}

	*mrhdl = mr;

	return (DDI_SUCCESS);

/*
 * The following is cleanup for all possible failure cases in this routine
 */
mrcommon_fail7:
	hermon_rsrc_free(state, &mtt_refcnt);
mrcommon_fail6:
	hermon_mr_mem_unbind(state, bh);
	bind->bi_type = bh->bi_type;
mrcommon_fail5:
	if (mr_is_umem) {
		hermon_umap_db_free(umapdb);
	}
mrcommon_fail4:
	if (mr_is_umem) {
		/*
		 * Free up the memory ddi_umem_iosetup() allocates
		 * internally.
		 */
		if (bind->bi_type == HERMON_BINDHDL_UBUF) {
			freerbuf(bind->bi_buf);
			_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*bind))
			bind->bi_type = HERMON_BINDHDL_NONE;
			_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*bind))
		}
		ddi_umem_unlock(umem_cookie);
	}
mrcommon_fail3:
	hermon_rsrc_free(state, &rsrc);
mrcommon_fail2:
	if (mpt != NULL)
		hermon_rsrc_free(state, &mpt);
mrcommon_fail1:
	hermon_pd_refcnt_dec(pd);
mrcommon_fail:
	return (status);
}

/*
 * hermon_dma_mr_register()
 *    Context: Can be called from base context.
 */
int
hermon_dma_mr_register(hermon_state_t *state, hermon_pdhdl_t pd,
    ibt_dmr_attr_t *mr_attr, hermon_mrhdl_t *mrhdl)
{
	hermon_rsrc_t		*mpt, *rsrc;
	hermon_hw_dmpt_t	mpt_entry;
	hermon_mrhdl_t		mr;
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
	sleep = (flags & IBT_MR_NOSLEEP) ? HERMON_NOSLEEP: HERMON_SLEEP;
	if ((sleep == HERMON_SLEEP) &&
	    (sleep != HERMON_SLEEPFLAG_FOR_CONTEXT())) {
		status = IBT_INVALID_PARAM;
		goto mrcommon_fail;
	}

	/* Increment the reference count on the protection domain (PD) */
	hermon_pd_refcnt_inc(pd);

	/*
	 * Allocate an MPT entry.  This will be filled in with all the
	 * necessary parameters to define the memory region.  And then
	 * ownership will be passed to the hardware in the final step
	 * below.  If we fail here, we must undo the protection domain
	 * reference count.
	 */
	status = hermon_rsrc_alloc(state, HERMON_DMPT, 1, sleep, &mpt);
	if (status != DDI_SUCCESS) {
		status = IBT_INSUFF_RESOURCE;
		goto mrcommon_fail1;
	}

	/*
	 * Allocate the software structure for tracking the memory region (i.e.
	 * the Hermon Memory Region handle).  If we fail here, we must undo
	 * the protection domain reference count and the previous resource
	 * allocation.
	 */
	status = hermon_rsrc_alloc(state, HERMON_MRHDL, 1, sleep, &rsrc);
	if (status != DDI_SUCCESS) {
		status = IBT_INSUFF_RESOURCE;
		goto mrcommon_fail2;
	}
	mr = (hermon_mrhdl_t)rsrc->hr_addr;
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
	if (mpt)
		mr->mr_rkey = mr->mr_lkey = hermon_mr_keycalc(mpt->hr_indx);

	/*
	 * Fill in the MPT entry.  This is the final step before passing
	 * ownership of the MPT entry to the Hermon hardware.  We use all of
	 * the information collected/calculated above to fill in the
	 * requisite portions of the MPT.  Do this ONLY for DMPTs.
	 */
	bzero(&mpt_entry, sizeof (hermon_hw_dmpt_t));

	mpt_entry.status  = HERMON_MPT_SW_OWNERSHIP;
	mpt_entry.en_bind = (mr->mr_accflag & IBT_MR_WINDOW_BIND)   ? 1 : 0;
	mpt_entry.atomic  = (mr->mr_accflag & IBT_MR_REMOTE_ATOMIC) ? 1 : 0;
	mpt_entry.rw	  = (mr->mr_accflag & IBT_MR_REMOTE_WRITE)  ? 1 : 0;
	mpt_entry.rr	  = (mr->mr_accflag & IBT_MR_REMOTE_READ)   ? 1 : 0;
	mpt_entry.lw	  = (mr->mr_accflag & IBT_MR_LOCAL_WRITE)   ? 1 : 0;
	mpt_entry.lr	  = 1;
	mpt_entry.phys_addr = 1;	/* critical bit for this */
	mpt_entry.reg_win = HERMON_MPT_IS_REGION;

	mpt_entry.entity_sz	= mr->mr_logmttpgsz;
	mpt_entry.mem_key	= mr->mr_lkey;
	mpt_entry.pd		= pd->pd_pdnum;
	mpt_entry.rem_acc_en = 0;
	mpt_entry.fast_reg_en = 0;
	mpt_entry.en_inval = 0;
	mpt_entry.lkey = 0;
	mpt_entry.win_cnt = 0;

	mpt_entry.start_addr = mr_attr->dmr_paddr;
	mpt_entry.reg_win_len = mr_attr->dmr_len;
	if (mr_attr->dmr_len == 0)
		mpt_entry.len_b64 = 1;	/* needed for 2^^64 length */

	mpt_entry.mtt_addr_h = 0;
	mpt_entry.mtt_addr_l = 0;

	/*
	 * Write the MPT entry to hardware.  Lastly, we pass ownership of
	 * the entry to the hardware if needed.  Note: in general, this
	 * operation shouldn't fail.  But if it does, we have to undo
	 * everything we've done above before returning error.
	 *
	 * For Hermon, this routine (which is common to the contexts) will only
	 * set the ownership if needed - the process of passing the context
	 * itself to HW will take care of setting up the MPT (based on type
	 * and index).
	 */

	mpt_entry.bnd_qp = 0;	/* dMPT for a qp, check for window */
	status = hermon_cmn_ownership_cmd_post(state, SW2HW_MPT, &mpt_entry,
	    sizeof (hermon_hw_dmpt_t), mpt->hr_indx, sleep);
	if (status != HERMON_CMD_SUCCESS) {
		cmn_err(CE_CONT, "Hermon: SW2HW_MPT command failed: %08x\n",
		    status);
		if (status == HERMON_CMD_INVALID_STATUS) {
			hermon_fm_ereport(state, HCA_SYS_ERR, HCA_ERR_SRV_LOST);
		}
		status = ibc_get_ci_failure(0);
		goto mrcommon_fail7;
	}

	/*
	 * Fill in the rest of the Hermon Memory Region handle.  Having
	 * successfully transferred ownership of the MPT, we can update the
	 * following fields for use in further operations on the MR.
	 */
	mr->mr_mttaddr	   = 0;

	mr->mr_log2_pgsz   = 0;
	mr->mr_mptrsrcp	   = mpt;
	mr->mr_mttrsrcp	   = NULL;
	mr->mr_pdhdl	   = pd;
	mr->mr_rsrcp	   = rsrc;
	mr->mr_is_umem	   = 0;
	mr->mr_is_fmr	   = 0;
	mr->mr_umemcookie  = NULL;
	mr->mr_umem_cbfunc = NULL;
	mr->mr_umem_cbarg1 = NULL;
	mr->mr_umem_cbarg2 = NULL;
	mr->mr_lkey	   = hermon_mr_key_swap(mr->mr_lkey);
	mr->mr_rkey	   = hermon_mr_key_swap(mr->mr_rkey);
	mr->mr_mpt_type	   = HERMON_MPT_DMPT;

	*mrhdl = mr;

	return (DDI_SUCCESS);

/*
 * The following is cleanup for all possible failure cases in this routine
 */
mrcommon_fail7:
	hermon_rsrc_free(state, &rsrc);
mrcommon_fail2:
	hermon_rsrc_free(state, &mpt);
mrcommon_fail1:
	hermon_pd_refcnt_dec(pd);
mrcommon_fail:
	return (status);
}

/*
 * hermon_mr_alloc_lkey()
 *    Context: Can be called from base context.
 */
int
hermon_mr_alloc_lkey(hermon_state_t *state, hermon_pdhdl_t pd,
    ibt_lkey_flags_t flags, uint_t nummtt, hermon_mrhdl_t *mrhdl)
{
	hermon_rsrc_t		*mpt, *mtt, *rsrc, *mtt_refcnt;
	hermon_sw_refcnt_t	*swrc_tmp;
	hermon_hw_dmpt_t	mpt_entry;
	hermon_mrhdl_t		mr;
	uint64_t		mtt_addr;
	uint_t			sleep;
	int			status;

	/* Increment the reference count on the protection domain (PD) */
	hermon_pd_refcnt_inc(pd);

	sleep = (flags & IBT_KEY_NOSLEEP) ? HERMON_NOSLEEP: HERMON_SLEEP;

	/*
	 * Allocate an MPT entry.  This will be filled in with "some" of the
	 * necessary parameters to define the memory region.  And then
	 * ownership will be passed to the hardware in the final step
	 * below.  If we fail here, we must undo the protection domain
	 * reference count.
	 *
	 * The MTTs will get filled in when the FRWR is processed.
	 */
	status = hermon_rsrc_alloc(state, HERMON_DMPT, 1, sleep, &mpt);
	if (status != DDI_SUCCESS) {
		status = IBT_INSUFF_RESOURCE;
		goto alloclkey_fail1;
	}

	/*
	 * Allocate the software structure for tracking the memory region (i.e.
	 * the Hermon Memory Region handle).  If we fail here, we must undo
	 * the protection domain reference count and the previous resource
	 * allocation.
	 */
	status = hermon_rsrc_alloc(state, HERMON_MRHDL, 1, sleep, &rsrc);
	if (status != DDI_SUCCESS) {
		status = IBT_INSUFF_RESOURCE;
		goto alloclkey_fail2;
	}
	mr = (hermon_mrhdl_t)rsrc->hr_addr;
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*mr))
	bzero(mr, sizeof (*mr));
	mr->mr_bindinfo.bi_type = HERMON_BINDHDL_LKEY;

	mr->mr_lkey = hermon_mr_keycalc(mpt->hr_indx);

	status = hermon_rsrc_alloc(state, HERMON_MTT, nummtt, sleep, &mtt);
	if (status != DDI_SUCCESS) {
		status = IBT_INSUFF_RESOURCE;
		goto alloclkey_fail3;
	}
	mr->mr_logmttpgsz = PAGESHIFT;

	/*
	 * Allocate MTT reference count (to track shared memory regions).
	 * This reference count resource may never be used on the given
	 * memory region, but if it is ever later registered as "shared"
	 * memory region then this resource will be necessary.  If we fail
	 * here, we do pretty much the same as above to clean up.
	 */
	status = hermon_rsrc_alloc(state, HERMON_REFCNT, 1, sleep,
	    &mtt_refcnt);
	if (status != DDI_SUCCESS) {
		status = IBT_INSUFF_RESOURCE;
		goto alloclkey_fail4;
	}
	mr->mr_mttrefcntp = mtt_refcnt;
	swrc_tmp = (hermon_sw_refcnt_t *)mtt_refcnt->hr_addr;
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*swrc_tmp))
	HERMON_MTT_REFCNT_INIT(swrc_tmp);

	mtt_addr = (mtt->hr_indx << HERMON_MTT_SIZE_SHIFT);

	bzero(&mpt_entry, sizeof (hermon_hw_dmpt_t));
	mpt_entry.status = HERMON_MPT_FREE;
	mpt_entry.lw = 1;
	mpt_entry.lr = 1;
	mpt_entry.reg_win = HERMON_MPT_IS_REGION;
	mpt_entry.entity_sz = mr->mr_logmttpgsz;
	mpt_entry.mem_key = mr->mr_lkey;
	mpt_entry.pd = pd->pd_pdnum;
	mpt_entry.fast_reg_en = 1;
	mpt_entry.rem_acc_en = 1;
	mpt_entry.en_inval = 1;
	if (flags & IBT_KEY_REMOTE) {
		mpt_entry.ren_inval = 1;
	}
	mpt_entry.mtt_size = nummtt;
	mpt_entry.mtt_addr_h = mtt_addr >> 32;	/* only 8 more bits */
	mpt_entry.mtt_addr_l = mtt_addr >> 3;	/* only 29 bits */

	/*
	 * Write the MPT entry to hardware.  Lastly, we pass ownership of
	 * the entry to the hardware if needed.  Note: in general, this
	 * operation shouldn't fail.  But if it does, we have to undo
	 * everything we've done above before returning error.
	 *
	 * For Hermon, this routine (which is common to the contexts) will only
	 * set the ownership if needed - the process of passing the context
	 * itself to HW will take care of setting up the MPT (based on type
	 * and index).
	 */
	status = hermon_cmn_ownership_cmd_post(state, SW2HW_MPT, &mpt_entry,
	    sizeof (hermon_hw_dmpt_t), mpt->hr_indx, sleep);
	if (status != HERMON_CMD_SUCCESS) {
		cmn_err(CE_CONT, "Hermon: alloc_lkey: SW2HW_MPT command "
		    "failed: %08x\n", status);
		if (status == HERMON_CMD_INVALID_STATUS) {
			hermon_fm_ereport(state, HCA_SYS_ERR, HCA_ERR_SRV_LOST);
		}
		status = ibc_get_ci_failure(0);
		goto alloclkey_fail5;
	}

	/*
	 * Fill in the rest of the Hermon Memory Region handle.  Having
	 * successfully transferred ownership of the MPT, we can update the
	 * following fields for use in further operations on the MR.
	 */
	mr->mr_accflag = IBT_MR_LOCAL_WRITE;
	mr->mr_mttaddr = mtt_addr;
	mr->mr_log2_pgsz = (mr->mr_logmttpgsz - HERMON_PAGESHIFT);
	mr->mr_mptrsrcp = mpt;
	mr->mr_mttrsrcp = mtt;
	mr->mr_pdhdl = pd;
	mr->mr_rsrcp = rsrc;
	mr->mr_lkey = hermon_mr_key_swap(mr->mr_lkey);
	mr->mr_rkey = mr->mr_lkey;
	mr->mr_mpt_type = HERMON_MPT_DMPT;

	*mrhdl = mr;
	return (DDI_SUCCESS);

alloclkey_fail5:
	hermon_rsrc_free(state, &mtt_refcnt);
alloclkey_fail4:
	hermon_rsrc_free(state, &mtt);
alloclkey_fail3:
	hermon_rsrc_free(state, &rsrc);
alloclkey_fail2:
	hermon_rsrc_free(state, &mpt);
alloclkey_fail1:
	hermon_pd_refcnt_dec(pd);
	return (status);
}

/*
 * hermon_mr_fexch_mpt_init()
 *    Context: Can be called from base context.
 *
 * This is the same as alloc_lkey, but not returning an mrhdl.
 */
int
hermon_mr_fexch_mpt_init(hermon_state_t *state, hermon_pdhdl_t pd,
    uint32_t mpt_indx, uint_t nummtt, uint64_t mtt_addr, uint_t sleep)
{
	hermon_hw_dmpt_t	mpt_entry;
	int			status;

	/*
	 * The MTTs will get filled in when the FRWR is processed.
	 */

	bzero(&mpt_entry, sizeof (hermon_hw_dmpt_t));
	mpt_entry.status = HERMON_MPT_FREE;
	mpt_entry.lw = 1;
	mpt_entry.lr = 1;
	mpt_entry.rw = 1;
	mpt_entry.rr = 1;
	mpt_entry.reg_win = HERMON_MPT_IS_REGION;
	mpt_entry.entity_sz = PAGESHIFT;
	mpt_entry.mem_key = mpt_indx;
	mpt_entry.pd = pd->pd_pdnum;
	mpt_entry.fast_reg_en = 1;
	mpt_entry.rem_acc_en = 1;
	mpt_entry.en_inval = 1;
	mpt_entry.ren_inval = 1;
	mpt_entry.mtt_size = nummtt;
	mpt_entry.mtt_addr_h = mtt_addr >> 32;	/* only 8 more bits */
	mpt_entry.mtt_addr_l = mtt_addr >> 3;	/* only 29 bits */

	/*
	 * Write the MPT entry to hardware.  Lastly, we pass ownership of
	 * the entry to the hardware if needed.  Note: in general, this
	 * operation shouldn't fail.  But if it does, we have to undo
	 * everything we've done above before returning error.
	 *
	 * For Hermon, this routine (which is common to the contexts) will only
	 * set the ownership if needed - the process of passing the context
	 * itself to HW will take care of setting up the MPT (based on type
	 * and index).
	 */
	status = hermon_cmn_ownership_cmd_post(state, SW2HW_MPT, &mpt_entry,
	    sizeof (hermon_hw_dmpt_t), mpt_indx, sleep);
	if (status != HERMON_CMD_SUCCESS) {
		cmn_err(CE_CONT, "Hermon: fexch_mpt_init: SW2HW_MPT command "
		    "failed: %08x\n", status);
		if (status == HERMON_CMD_INVALID_STATUS) {
			hermon_fm_ereport(state, HCA_SYS_ERR, HCA_ERR_SRV_LOST);
		}
		status = ibc_get_ci_failure(0);
		return (status);
	}
	/* Increment the reference count on the protection domain (PD) */
	hermon_pd_refcnt_inc(pd);

	return (DDI_SUCCESS);
}

/*
 * hermon_mr_fexch_mpt_fini()
 *    Context: Can be called from base context.
 *
 * This is the same as deregister_mr, without an mrhdl.
 */
int
hermon_mr_fexch_mpt_fini(hermon_state_t *state, hermon_pdhdl_t pd,
    uint32_t mpt_indx, uint_t sleep)
{
	int			status;

	status = hermon_cmn_ownership_cmd_post(state, HW2SW_MPT,
	    NULL, 0, mpt_indx, sleep);
	if (status != DDI_SUCCESS) {
		cmn_err(CE_CONT, "Hermon: fexch_mpt_fini: HW2SW_MPT command "
		    "failed: %08x\n", status);
		if (status == HERMON_CMD_INVALID_STATUS) {
			hermon_fm_ereport(state, HCA_SYS_ERR, HCA_ERR_SRV_LOST);
		}
		status = ibc_get_ci_failure(0);
		return (status);
	}

	/* Decrement the reference count on the protection domain (PD) */
	hermon_pd_refcnt_dec(pd);

	return (DDI_SUCCESS);
}

/*
 * hermon_mr_mtt_bind()
 *    Context: Can be called from interrupt or base context.
 */
int
hermon_mr_mtt_bind(hermon_state_t *state, hermon_bind_info_t *bind,
    ddi_dma_handle_t bind_dmahdl, hermon_rsrc_t **mtt, uint_t *mtt_pgsize_bits,
    uint_t is_buffer)
{
	uint64_t		nummtt;
	uint_t			sleep;
	int			status;

	/*
	 * Check the sleep flag.  Ensure that it is consistent with the
	 * current thread context (i.e. if we are currently in the interrupt
	 * context, then we shouldn't be attempting to sleep).
	 */
	sleep = (bind->bi_flags & IBT_MR_NOSLEEP) ?
	    HERMON_NOSLEEP : HERMON_SLEEP;
	if ((sleep == HERMON_SLEEP) &&
	    (sleep != HERMON_SLEEPFLAG_FOR_CONTEXT())) {
		status = IBT_INVALID_PARAM;
		goto mrmttbind_fail;
	}

	/*
	 * Bind the memory and determine the mapped addresses.  This is
	 * the first of two routines that do all the "heavy lifting" for
	 * the Hermon memory registration routines.  The hermon_mr_mem_bind()
	 * routine takes the "bind" struct with all its fields filled
	 * in and returns a list of DMA cookies (for the PCI mapped addresses
	 * corresponding to the specified address region) which are used by
	 * the hermon_mr_fast_mtt_write() routine below.  If we fail here, we
	 * must undo all the previous resource allocation (and PD reference
	 * count).
	 */
	status = hermon_mr_mem_bind(state, bind, bind_dmahdl, sleep, is_buffer);
	if (status != DDI_SUCCESS) {
		status = IBT_INSUFF_RESOURCE;
		goto mrmttbind_fail;
	}

	/*
	 * Determine number of pages spanned.  This routine uses the
	 * information in the "bind" struct to determine the required
	 * number of MTT entries needed (and returns the suggested page size -
	 * as a "power-of-2" - for each MTT entry).
	 */
	nummtt = hermon_mr_nummtt_needed(state, bind, mtt_pgsize_bits);

	/*
	 * Allocate the MTT entries.  Use the calculations performed above to
	 * allocate the required number of MTT entries. If we fail here, we
	 * must not only undo all the previous resource allocation (and PD
	 * reference count), but we must also unbind the memory.
	 */
	status = hermon_rsrc_alloc(state, HERMON_MTT, nummtt, sleep, mtt);
	if (status != DDI_SUCCESS) {
		status = IBT_INSUFF_RESOURCE;
		goto mrmttbind_fail2;
	}

	/*
	 * Write the mapped addresses into the MTT entries.  This is part two
	 * of the "heavy lifting" routines that we talked about above.  Note:
	 * we pass the suggested page size from the earlier operation here.
	 * And if we fail here, we again do pretty much the same huge clean up.
	 */
	status = hermon_mr_fast_mtt_write(state, *mtt, bind, *mtt_pgsize_bits);
	if (status != DDI_SUCCESS) {
		/*
		 * hermon_mr_fast_mtt_write() returns DDI_FAILURE
		 * only if it detects a HW error during DMA.
		 */
		hermon_fm_ereport(state, HCA_SYS_ERR, HCA_ERR_SRV_LOST);
		status = ibc_get_ci_failure(0);
		goto mrmttbind_fail3;
	}
	return (DDI_SUCCESS);

/*
 * The following is cleanup for all possible failure cases in this routine
 */
mrmttbind_fail3:
	hermon_rsrc_free(state, mtt);
mrmttbind_fail2:
	hermon_mr_mem_unbind(state, bind);
mrmttbind_fail:
	return (status);
}


/*
 * hermon_mr_mtt_unbind()
 *    Context: Can be called from interrupt or base context.
 */
int
hermon_mr_mtt_unbind(hermon_state_t *state, hermon_bind_info_t *bind,
    hermon_rsrc_t *mtt)
{
	/*
	 * Free up the MTT entries and unbind the memory.  Here, as above, we
	 * attempt to free these resources only if it is appropriate to do so.
	 */
	hermon_mr_mem_unbind(state, bind);
	hermon_rsrc_free(state, &mtt);

	return (DDI_SUCCESS);
}


/*
 * hermon_mr_common_rereg()
 *    Context: Can be called from interrupt or base context.
 */
static int
hermon_mr_common_rereg(hermon_state_t *state, hermon_mrhdl_t mr,
    hermon_pdhdl_t pd, hermon_bind_info_t *bind, hermon_mrhdl_t *mrhdl_new,
    hermon_mr_options_t *op)
{
	hermon_rsrc_t		*mpt;
	ibt_mr_attr_flags_t	acc_flags_to_use;
	ibt_mr_flags_t		flags;
	hermon_pdhdl_t		pd_to_use;
	hermon_hw_dmpt_t	mpt_entry;
	uint64_t		mtt_addr_to_use, vaddr_to_use, len_to_use;
	uint_t			sleep, dereg_level;
	int			status;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*bind))

	/*
	 * Check here to see if the memory region corresponds to a userland
	 * mapping.  Reregistration of userland memory regions is not
	 * currently supported.  Return failure.
	 */
	if (mr->mr_is_umem) {
		status = IBT_MR_HDL_INVALID;
		goto mrrereg_fail;
	}

	mutex_enter(&mr->mr_lock);

	/* Pull MPT resource pointer from the Hermon Memory Region handle */
	mpt = mr->mr_mptrsrcp;

	/* Extract the flags field from the hermon_bind_info_t */
	flags = bind->bi_flags;

	/*
	 * Check the sleep flag.  Ensure that it is consistent with the
	 * current thread context (i.e. if we are currently in the interrupt
	 * context, then we shouldn't be attempting to sleep).
	 */
	sleep = (flags & IBT_MR_NOSLEEP) ? HERMON_NOSLEEP: HERMON_SLEEP;
	if ((sleep == HERMON_SLEEP) &&
	    (sleep != HERMON_SLEEPFLAG_FOR_CONTEXT())) {
		mutex_exit(&mr->mr_lock);
		status = IBT_INVALID_PARAM;
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
	 * We use HERMON_CMD_NOSLEEP_SPIN here always because we must protect
	 * against holding the lock around this rereg call in all contexts.
	 */
	status = hermon_cmn_ownership_cmd_post(state, HW2SW_MPT, &mpt_entry,
	    sizeof (hermon_hw_dmpt_t), mpt->hr_indx, HERMON_CMD_NOSLEEP_SPIN);
	if (status != HERMON_CMD_SUCCESS) {
		mutex_exit(&mr->mr_lock);
		if (status == HERMON_CMD_REG_BOUND) {
			return (IBT_MR_IN_USE);
		} else {
			cmn_err(CE_CONT, "Hermon: HW2SW_MPT command failed: "
			    "%08x\n", status);
			if (status == HERMON_CMD_INVALID_STATUS) {
				hermon_fm_ereport(state, HCA_SYS_ERR,
				    HCA_ERR_SRV_LOST);
			}
			/*
			 * Call deregister and ensure that all current
			 * resources get freed up
			 */
			if (hermon_mr_deregister(state, &mr,
			    HERMON_MR_DEREG_ALL, sleep) != DDI_SUCCESS) {
				HERMON_WARNING(state, "failed to deregister "
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
			if (hermon_mr_deregister(state, &mr,
			    HERMON_MR_DEREG_NO_HW2SW_MPT, sleep) !=
			    DDI_SUCCESS) {
				HERMON_WARNING(state, "failed to deregister "
				    "memory region");
			}
			status = IBT_PD_HDL_INVALID;
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
			if (hermon_mr_deregister(state, &mr,
			    HERMON_MR_DEREG_NO_HW2SW_MPT, sleep) !=
			    DDI_SUCCESS) {
				HERMON_WARNING(state, "failed to deregister "
				    "memory region");
			}
			status = IBT_MR_ACCESS_REQ_INVALID;
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
	 * hermon_mr_rereg_xlat_helper() which does most of the heavy lifting
	 * for the reregistration.  If the current memory region contains
	 * sufficient MTT entries for the new regions, then it will be
	 * reused and filled in.  Otherwise, new entries will be allocated,
	 * the old ones will be freed, and the new entries will be filled
	 * in.  Note:  If we're not modifying the translation, then we
	 * should already have all the information we need to update the MPT.
	 * Also note: If hermon_mr_rereg_xlat_helper() fails, it will return
	 * a "dereg_level" which is the level of cleanup that needs to be
	 * passed to hermon_mr_deregister() to finish the cleanup.
	 */
	if (flags & IBT_MR_CHANGE_TRANSLATION) {
		status = hermon_mr_rereg_xlat_helper(state, mr, bind, op,
		    &mtt_addr_to_use, sleep, &dereg_level);
		if (status != DDI_SUCCESS) {
			mutex_exit(&mr->mr_lock);
			/*
			 * Call deregister and ensure that all resources get
			 * properly freed up.
			 */
			if (hermon_mr_deregister(state, &mr, dereg_level,
			    sleep) != DDI_SUCCESS) {
				HERMON_WARNING(state, "failed to deregister "
				    "memory region");
			}
			goto mrrereg_fail;
		}
		vaddr_to_use = mr->mr_bindinfo.bi_addr;
		len_to_use   = mr->mr_bindinfo.bi_len;
	} else {
		mtt_addr_to_use = mr->mr_mttaddr;
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
	mr->mr_lkey = hermon_mr_keycalc(mpt->hr_indx);
	if ((acc_flags_to_use & IBT_MR_REMOTE_READ) ||
	    (acc_flags_to_use & IBT_MR_REMOTE_WRITE) ||
	    (acc_flags_to_use & IBT_MR_REMOTE_ATOMIC)) {
		mr->mr_rkey = mr->mr_lkey;
	} else
		mr->mr_rkey = 0;

	/*
	 * Fill in the MPT entry.  This is the final step before passing
	 * ownership of the MPT entry to the Hermon hardware.  We use all of
	 * the information collected/calculated above to fill in the
	 * requisite portions of the MPT.
	 */
	bzero(&mpt_entry, sizeof (hermon_hw_dmpt_t));

	mpt_entry.status  = HERMON_MPT_SW_OWNERSHIP;
	mpt_entry.en_bind = (acc_flags_to_use & IBT_MR_WINDOW_BIND)   ? 1 : 0;
	mpt_entry.atomic  = (acc_flags_to_use & IBT_MR_REMOTE_ATOMIC) ? 1 : 0;
	mpt_entry.rw	  = (acc_flags_to_use & IBT_MR_REMOTE_WRITE)  ? 1 : 0;
	mpt_entry.rr	  = (acc_flags_to_use & IBT_MR_REMOTE_READ)   ? 1 : 0;
	mpt_entry.lw	  = (acc_flags_to_use & IBT_MR_LOCAL_WRITE)   ? 1 : 0;
	mpt_entry.lr	  = 1;
	mpt_entry.phys_addr = 0;
	mpt_entry.reg_win = HERMON_MPT_IS_REGION;

	mpt_entry.entity_sz	= mr->mr_logmttpgsz;
	mpt_entry.mem_key	= mr->mr_lkey;
	mpt_entry.pd		= pd_to_use->pd_pdnum;

	mpt_entry.start_addr	= vaddr_to_use;
	mpt_entry.reg_win_len	= len_to_use;
	mpt_entry.mtt_addr_h = mtt_addr_to_use >> 32;
	mpt_entry.mtt_addr_l = mtt_addr_to_use >> 3;

	/*
	 * Write the updated MPT entry to hardware
	 *
	 * We use HERMON_CMD_NOSLEEP_SPIN here always because we must protect
	 * against holding the lock around this rereg call in all contexts.
	 */
	status = hermon_cmn_ownership_cmd_post(state, SW2HW_MPT, &mpt_entry,
	    sizeof (hermon_hw_dmpt_t), mpt->hr_indx, HERMON_CMD_NOSLEEP_SPIN);
	if (status != HERMON_CMD_SUCCESS) {
		mutex_exit(&mr->mr_lock);
		cmn_err(CE_CONT, "Hermon: SW2HW_MPT command failed: %08x\n",
		    status);
		if (status == HERMON_CMD_INVALID_STATUS) {
			hermon_fm_ereport(state, HCA_SYS_ERR, HCA_ERR_SRV_LOST);
		}
		/*
		 * Call deregister and ensure that all current resources get
		 * properly freed up. Unnecessary here to attempt to regain
		 * software ownership of the MPT entry as that has already
		 * been done above.
		 */
		if (hermon_mr_deregister(state, &mr,
		    HERMON_MR_DEREG_NO_HW2SW_MPT, sleep) != DDI_SUCCESS) {
			HERMON_WARNING(state, "failed to deregister memory "
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
		hermon_pd_refcnt_dec(mr->mr_pdhdl);
		hermon_pd_refcnt_inc(pd);
	}

	/*
	 * Update the contents of the Hermon Memory Region handle to reflect
	 * what has been changed.
	 */
	mr->mr_pdhdl	  = pd_to_use;
	mr->mr_accflag	  = acc_flags_to_use;
	mr->mr_is_umem	  = 0;
	mr->mr_is_fmr	  = 0;
	mr->mr_umemcookie = NULL;
	mr->mr_lkey	  = hermon_mr_key_swap(mr->mr_lkey);
	mr->mr_rkey	  = hermon_mr_key_swap(mr->mr_rkey);

	/* New MR handle is same as the old */
	*mrhdl_new = mr;
	mutex_exit(&mr->mr_lock);

	return (DDI_SUCCESS);

mrrereg_fail:
	return (status);
}


/*
 * hermon_mr_rereg_xlat_helper
 *    Context: Can be called from interrupt or base context.
 *    Note: This routine expects the "mr_lock" to be held when it
 *    is called.  Upon returning failure, this routine passes information
 *    about what "dereg_level" should be passed to hermon_mr_deregister().
 */
static int
hermon_mr_rereg_xlat_helper(hermon_state_t *state, hermon_mrhdl_t mr,
    hermon_bind_info_t *bind, hermon_mr_options_t *op, uint64_t *mtt_addr,
    uint_t sleep, uint_t *dereg_level)
{
	hermon_rsrc_t		*mtt, *mtt_refcnt;
	hermon_sw_refcnt_t	*swrc_old, *swrc_new;
	ddi_dma_handle_t	dmahdl;
	uint64_t		nummtt_needed, nummtt_in_currrsrc, max_sz;
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
		bind_type = HERMON_BINDMEM_NORMAL;
	} else {
		bind_type = op->mro_bind_type;
	}

	/*
	 * Check for invalid length.  Check is the length is zero or if the
	 * length is larger than the maximum configured value.  Return error
	 * if it is.
	 */
	max_sz = ((uint64_t)1 << state->hs_cfg_profile->cp_log_max_mrw_sz);
	if ((bind->bi_len == 0) || (bind->bi_len > max_sz)) {
		/*
		 * Deregister will be called upon returning failure from this
		 * routine. This will ensure that all current resources get
		 * properly freed up. Unnecessary to attempt to regain
		 * software ownership of the MPT entry as that has already
		 * been done above (in hermon_mr_reregister())
		 */
		*dereg_level = HERMON_MR_DEREG_NO_HW2SW_MPT;

		status = IBT_MR_LEN_INVALID;
		goto mrrereghelp_fail;
	}

	/*
	 * Determine the number of pages necessary for new region and the
	 * number of pages supported by the current MTT resources
	 */
	nummtt_needed = hermon_mr_nummtt_needed(state, bind, &mtt_pgsize_bits);
	nummtt_in_currrsrc = mr->mr_mttrsrcp->hr_len >> HERMON_MTT_SIZE_SHIFT;

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
	swrc_old = (hermon_sw_refcnt_t *)mr->mr_mttrefcntp->hr_addr;
	if (HERMON_MTT_IS_NOT_SHARED(swrc_old) &&
	    (nummtt_needed <= nummtt_in_currrsrc)) {

		/*
		 * Unbind the old mapping for this memory region, but retain
		 * the ddi_dma_handle_t (if possible) for reuse in the bind
		 * operation below.  Note:  If original memory region was
		 * bound for IOMMU bypass and the new region can not use
		 * bypass, then a new DMA handle will be necessary.
		 */
		if (HERMON_MR_REUSE_DMAHDL(mr, bind->bi_flags)) {
			mr->mr_bindinfo.bi_free_dmahdl = 0;
			hermon_mr_mem_unbind(state, &mr->mr_bindinfo);
			dmahdl = mr->mr_bindinfo.bi_dmahdl;
			reuse_dmahdl = 1;
		} else {
			hermon_mr_mem_unbind(state, &mr->mr_bindinfo);
			dmahdl = NULL;
			reuse_dmahdl = 0;
		}

		/*
		 * Bind the new memory and determine the mapped addresses.
		 * As described, this routine and hermon_mr_fast_mtt_write()
		 * do the majority of the work for the memory registration
		 * operations.  Note:  When we successfully finish the binding,
		 * we will set the "bi_free_dmahdl" flag to indicate that
		 * even though we may have reused the ddi_dma_handle_t we do
		 * wish it to be freed up at some later time.  Note also that
		 * if we fail, we may need to cleanup the ddi_dma_handle_t.
		 */
		bind->bi_bypass	= bind_type;
		status = hermon_mr_mem_bind(state, bind, dmahdl, sleep, 1);
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
			 * above (in hermon_mr_reregister()).  Also unnecessary
			 * to attempt to unbind the memory.
			 */
			*dereg_level = HERMON_MR_DEREG_NO_HW2SW_MPT_OR_UNBIND;

			status = IBT_INSUFF_RESOURCE;
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
		status = hermon_mr_fast_mtt_write(state, mtt, bind,
		    mtt_pgsize_bits);
		if (status != DDI_SUCCESS) {
			/*
			 * Deregister will be called upon returning failure
			 * from this routine. This will ensure that all
			 * current resources get properly freed up.
			 * Unnecessary to attempt to regain software ownership
			 * of the MPT entry as that has already been done
			 * above (in hermon_mr_reregister()).  Also unnecessary
			 * to attempt to unbind the memory.
			 *
			 * But we do need to unbind the newly bound memory
			 * before returning.
			 */
			hermon_mr_mem_unbind(state, bind);
			*dereg_level = HERMON_MR_DEREG_NO_HW2SW_MPT_OR_UNBIND;

			/*
			 * hermon_mr_fast_mtt_write() returns DDI_FAILURE
			 * only if it detects a HW error during DMA.
			 */
			hermon_fm_ereport(state, HCA_SYS_ERR, HCA_ERR_SRV_LOST);
			status = ibc_get_ci_failure(0);
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
		if (!HERMON_MTT_IS_SHARED(swrc_old)) {
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
			if (HERMON_MR_REUSE_DMAHDL(mr, bind->bi_flags)) {
				mr->mr_bindinfo.bi_free_dmahdl = 0;
				hermon_mr_mem_unbind(state, &mr->mr_bindinfo);
				dmahdl = mr->mr_bindinfo.bi_dmahdl;
				reuse_dmahdl = 1;
			} else {
				hermon_mr_mem_unbind(state, &mr->mr_bindinfo);
				dmahdl = NULL;
				reuse_dmahdl = 0;
			}
		} else {
			dmahdl = NULL;
			reuse_dmahdl = 0;
		}

		/*
		 * Bind the new memory and determine the mapped addresses.
		 * As described, this routine and hermon_mr_fast_mtt_write()
		 * do the majority of the work for the memory registration
		 * operations.  Note:  When we successfully finish the binding,
		 * we will set the "bi_free_dmahdl" flag to indicate that
		 * even though we may have reused the ddi_dma_handle_t we do
		 * wish it to be freed up at some later time.  Note also that
		 * if we fail, we may need to cleanup the ddi_dma_handle_t.
		 */
		bind->bi_bypass	= bind_type;
		status = hermon_mr_mem_bind(state, bind, dmahdl, sleep, 1);
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
			 * above (in hermon_mr_reregister()).  Also unnecessary
			 * to attempt to unbind the memory.
			 */
			*dereg_level = HERMON_MR_DEREG_NO_HW2SW_MPT_OR_UNBIND;

			status = IBT_INSUFF_RESOURCE;
			goto mrrereghelp_fail;
		}
		if (reuse_dmahdl) {
			bind->bi_free_dmahdl = 1;
		}

		/*
		 * Allocate the new MTT entries resource
		 */
		status = hermon_rsrc_alloc(state, HERMON_MTT, nummtt_needed,
		    sleep, &mtt);
		if (status != DDI_SUCCESS) {
			/*
			 * Deregister will be called upon returning failure
			 * from this routine. This will ensure that all
			 * current resources get properly freed up.
			 * Unnecessary to attempt to regain software ownership
			 * of the MPT entry as that has already been done
			 * above (in hermon_mr_reregister()).  Also unnecessary
			 * to attempt to unbind the memory.
			 *
			 * But we do need to unbind the newly bound memory
			 * before returning.
			 */
			hermon_mr_mem_unbind(state, bind);
			*dereg_level = HERMON_MR_DEREG_NO_HW2SW_MPT_OR_UNBIND;

			status = IBT_INSUFF_RESOURCE;
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
		if (HERMON_MTT_IS_SHARED(swrc_old)) {
			status = hermon_rsrc_alloc(state, HERMON_REFCNT, 1,
			    sleep, &mtt_refcnt);
			if (status != DDI_SUCCESS) {
				/*
				 * Deregister will be called upon returning
				 * failure from this routine. This will ensure
				 * that all current resources get properly
				 * freed up.  Unnecessary to attempt to regain
				 * software ownership of the MPT entry as that
				 * has already been done above (in
				 * hermon_mr_reregister()).  Also unnecessary
				 * to attempt to unbind the memory.
				 *
				 * But we need to unbind the newly bound
				 * memory and free up the newly allocated MTT
				 * entries before returning.
				 */
				hermon_mr_mem_unbind(state, bind);
				hermon_rsrc_free(state, &mtt);
				*dereg_level =
				    HERMON_MR_DEREG_NO_HW2SW_MPT_OR_UNBIND;

				status = IBT_INSUFF_RESOURCE;
				goto mrrereghelp_fail;
			}
			swrc_new = (hermon_sw_refcnt_t *)mtt_refcnt->hr_addr;
			_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*swrc_new))
			HERMON_MTT_REFCNT_INIT(swrc_new);
		} else {
			mtt_refcnt = mr->mr_mttrefcntp;
		}

		/*
		 * Using the new mapping and the new MTT resources, write the
		 * updated entries to MTT
		 */
		status = hermon_mr_fast_mtt_write(state, mtt, bind,
		    mtt_pgsize_bits);
		if (status != DDI_SUCCESS) {
			/*
			 * Deregister will be called upon returning failure
			 * from this routine. This will ensure that all
			 * current resources get properly freed up.
			 * Unnecessary to attempt to regain software ownership
			 * of the MPT entry as that has already been done
			 * above (in hermon_mr_reregister()).  Also unnecessary
			 * to attempt to unbind the memory.
			 *
			 * But we need to unbind the newly bound memory,
			 * free up the newly allocated MTT entries, and
			 * (possibly) free the new MTT reference count
			 * resource before returning.
			 */
			if (HERMON_MTT_IS_SHARED(swrc_old)) {
				hermon_rsrc_free(state, &mtt_refcnt);
			}
			hermon_mr_mem_unbind(state, bind);
			hermon_rsrc_free(state, &mtt);
			*dereg_level = HERMON_MR_DEREG_NO_HW2SW_MPT_OR_UNBIND;

			status = IBT_INSUFF_RESOURCE;
			goto mrrereghelp_fail;
		}

		/*
		 * Check if the memory region MTT is shared by any other MRs.
		 * Since the resource may be shared between multiple memory
		 * regions (as a result of a "RegisterSharedMR()" verb) it is
		 * important that we not free up any resources prematurely.
		 */
		if (HERMON_MTT_IS_SHARED(swrc_old)) {
			/* Decrement MTT reference count for "old" region */
			(void) hermon_mtt_refcnt_dec(mr->mr_mttrefcntp);
		} else {
			/* Free up the old MTT entries resource */
			hermon_rsrc_free(state, &mr->mr_mttrsrcp);
		}

		/* Put the updated information into the mrhdl */
		mr->mr_bindinfo	  = *bind;
		mr->mr_logmttpgsz = mtt_pgsize_bits;
		mr->mr_mttrsrcp   = mtt;
		mr->mr_mttrefcntp = mtt_refcnt;
	}

	/*
	 * Calculate and return the updated MTT address (in the DDR address
	 * space).  This will be used by the caller (hermon_mr_reregister) in
	 * the updated MPT entry
	 */
	*mtt_addr = mtt->hr_indx << HERMON_MTT_SIZE_SHIFT;

	return (DDI_SUCCESS);

mrrereghelp_fail:
	return (status);
}


/*
 * hermon_mr_nummtt_needed()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static uint64_t
hermon_mr_nummtt_needed(hermon_state_t *state, hermon_bind_info_t *bind,
    uint_t *mtt_pgsize_bits)
{
	uint64_t	pg_offset_mask;
	uint64_t	pg_offset, tmp_length;

	/*
	 * For now we specify the page size as 8Kb (the default page size for
	 * the sun4u architecture), or 4Kb for x86.  Figure out optimal page
	 * size by examining the dmacookies
	 */
	*mtt_pgsize_bits = PAGESHIFT;

	pg_offset_mask = ((uint64_t)1 << *mtt_pgsize_bits) - 1;
	pg_offset = bind->bi_addr & pg_offset_mask;
	tmp_length = pg_offset + (bind->bi_len - 1);
	return ((tmp_length >> *mtt_pgsize_bits) + 1);
}


/*
 * hermon_mr_mem_bind()
 *    Context: Can be called from interrupt or base context.
 */
static int
hermon_mr_mem_bind(hermon_state_t *state, hermon_bind_info_t *bind,
    ddi_dma_handle_t dmahdl, uint_t sleep, uint_t is_buffer)
{
	ddi_dma_attr_t	dma_attr;
	int		(*callback)(caddr_t);
	int		status;

	/* bi_type must be set to a meaningful value to get a bind handle */
	ASSERT(bind->bi_type == HERMON_BINDHDL_VADDR ||
	    bind->bi_type == HERMON_BINDHDL_BUF ||
	    bind->bi_type == HERMON_BINDHDL_UBUF);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*bind))

	/* Set the callback flag appropriately */
	callback = (sleep == HERMON_SLEEP) ? DDI_DMA_SLEEP : DDI_DMA_DONTWAIT;

	/*
	 * Initialize many of the default DMA attributes.  Then, if we're
	 * bypassing the IOMMU, set the DDI_DMA_FORCE_PHYSICAL flag.
	 */
	if (dmahdl == NULL) {
		hermon_dma_attr_init(state, &dma_attr);
#ifdef	__sparc
		if (bind->bi_bypass == HERMON_BINDMEM_BYPASS) {
			dma_attr.dma_attr_flags = DDI_DMA_FORCE_PHYSICAL;
		}
#endif

		/* set RO if needed - tunable set and 'is_buffer' is non-0 */
		if (is_buffer) {
			if (! (bind->bi_flags & IBT_MR_DISABLE_RO)) {
				if ((bind->bi_type != HERMON_BINDHDL_UBUF) &&
				    (hermon_kernel_data_ro ==
				    HERMON_RO_ENABLED)) {
					dma_attr.dma_attr_flags |=
					    DDI_DMA_RELAXED_ORDERING;
				}
				if (((bind->bi_type == HERMON_BINDHDL_UBUF) &&
				    (hermon_user_data_ro ==
				    HERMON_RO_ENABLED))) {
					dma_attr.dma_attr_flags |=
					    DDI_DMA_RELAXED_ORDERING;
				}
			}
		}

		/* Allocate a DMA handle for the binding */
		status = ddi_dma_alloc_handle(state->hs_dip, &dma_attr,
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
	if (bind->bi_type == HERMON_BINDHDL_VADDR) {
		status = ddi_dma_addr_bind_handle(bind->bi_dmahdl, NULL,
		    (caddr_t)(uintptr_t)bind->bi_addr, bind->bi_len,
		    (DDI_DMA_RDWR | DDI_DMA_CONSISTENT), callback, NULL,
		    &bind->bi_dmacookie, &bind->bi_cookiecnt);

	} else {  /* HERMON_BINDHDL_BUF or HERMON_BINDHDL_UBUF */

		status = ddi_dma_buf_bind_handle(bind->bi_dmahdl,
		    bind->bi_buf, (DDI_DMA_RDWR | DDI_DMA_CONSISTENT), callback,
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
 * hermon_mr_mem_unbind()
 *    Context: Can be called from interrupt or base context.
 */
static void
hermon_mr_mem_unbind(hermon_state_t *state, hermon_bind_info_t *bind)
{
	int	status;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*bind))
	/* there is nothing to unbind for alloc_lkey */
	if (bind->bi_type == HERMON_BINDHDL_LKEY)
		return;

	/*
	 * In case of HERMON_BINDHDL_UBUF, the memory bi_buf points to
	 * is actually allocated by ddi_umem_iosetup() internally, then
	 * it's required to free it here. Reset bi_type to HERMON_BINDHDL_NONE
	 * not to free it again later.
	 */
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*bind))
	if (bind->bi_type == HERMON_BINDHDL_UBUF) {
		freerbuf(bind->bi_buf);
		bind->bi_type = HERMON_BINDHDL_NONE;
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
		HERMON_WARNING(state, "failed to unbind DMA mapping");
		return;
	}

	/* Free up the DMA handle */
	if (bind->bi_free_dmahdl != 0) {
		ddi_dma_free_handle(&bind->bi_dmahdl);
	}
}


/*
 * hermon_mr_fast_mtt_write()
 *    Context: Can be called from interrupt or base context.
 */
static int
hermon_mr_fast_mtt_write(hermon_state_t *state, hermon_rsrc_t *mtt,
    hermon_bind_info_t *bind, uint32_t mtt_pgsize_bits)
{
	hermon_icm_table_t	*icm_table;
	hermon_dma_info_t	*dma_info;
	uint32_t		index1, index2, rindx;
	ddi_dma_cookie_t	dmacookie;
	uint_t			cookie_cnt;
	uint64_t		*mtt_table;
	uint64_t		mtt_entry;
	uint64_t		addr, endaddr;
	uint64_t		pagesize;
	offset_t		i, start;
	uint_t			per_span;
	int			sync_needed;

	/*
	 * XXX According to the PRM, we are to use the WRITE_MTT
	 * command to write out MTTs. Tavor does not do this,
	 * instead taking advantage of direct access to the MTTs,
	 * and knowledge that Mellanox FMR relies on our ability
	 * to write directly to the MTTs without any further
	 * notification to the firmware. Likewise, we will choose
	 * to not use the WRITE_MTT command, but to simply write
	 * out the MTTs.
	 */

	/* Calculate page size from the suggested value passed in */
	pagesize = ((uint64_t)1 << mtt_pgsize_bits);

	/* Walk the "cookie list" and fill in the MTT table entries */
	dmacookie  = bind->bi_dmacookie;
	cookie_cnt = bind->bi_cookiecnt;

	icm_table = &state->hs_icm[HERMON_MTT];
	rindx = mtt->hr_indx;
	hermon_index(index1, index2, rindx, icm_table, i);
	start = i;

	per_span   = icm_table->span;
	dma_info   = icm_table->icm_dma[index1] + index2;
	mtt_table  = (uint64_t *)(uintptr_t)dma_info->vaddr;

	sync_needed = 0;
	while (cookie_cnt-- > 0) {
		addr    = dmacookie.dmac_laddress;
		endaddr = addr + (dmacookie.dmac_size - 1);
		addr    = addr & ~((uint64_t)pagesize - 1);

		while (addr <= endaddr) {

			/*
			 * Fill in the mapped addresses (calculated above) and
			 * set HERMON_MTT_ENTRY_PRESENT flag for each MTT entry.
			 */
			mtt_entry = addr | HERMON_MTT_ENTRY_PRESENT;
			mtt_table[i] = htonll(mtt_entry);
			i++;
			rindx++;

			if (i == per_span) {

				(void) ddi_dma_sync(dma_info->dma_hdl,
				    start * sizeof (hermon_hw_mtt_t),
				    (i - start) * sizeof (hermon_hw_mtt_t),
				    DDI_DMA_SYNC_FORDEV);

				if ((addr + pagesize > endaddr) &&
				    (cookie_cnt == 0))
					return (DDI_SUCCESS);

				hermon_index(index1, index2, rindx, icm_table,
				    i);
				start = i * sizeof (hermon_hw_mtt_t);
				dma_info = icm_table->icm_dma[index1] + index2;
				mtt_table =
				    (uint64_t *)(uintptr_t)dma_info->vaddr;

				sync_needed = 0;
			} else {
				sync_needed = 1;
			}

			addr += pagesize;
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

	/* done all the cookies, now sync the memory for the device */
	if (sync_needed)
		(void) ddi_dma_sync(dma_info->dma_hdl,
		    start * sizeof (hermon_hw_mtt_t),
		    (i - start) * sizeof (hermon_hw_mtt_t),
		    DDI_DMA_SYNC_FORDEV);

	return (DDI_SUCCESS);
}

/*
 * hermon_mr_fast_mtt_write_fmr()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static int
hermon_mr_fast_mtt_write_fmr(hermon_state_t *state, hermon_rsrc_t *mtt,
    ibt_pmr_attr_t *mem_pattr, uint32_t mtt_pgsize_bits)
{
	hermon_icm_table_t	*icm_table;
	hermon_dma_info_t	*dma_info;
	uint32_t		index1, index2, rindx;
	uint64_t		*mtt_table;
	offset_t		i, j;
	uint_t			per_span;

	icm_table = &state->hs_icm[HERMON_MTT];
	rindx = mtt->hr_indx;
	hermon_index(index1, index2, rindx, icm_table, i);
	per_span   = icm_table->span;
	dma_info   = icm_table->icm_dma[index1] + index2;
	mtt_table  = (uint64_t *)(uintptr_t)dma_info->vaddr;

	/*
	 * Fill in the MTT table entries
	 */
	for (j = 0; j < mem_pattr->pmr_num_buf; j++) {
		mtt_table[i] = mem_pattr->pmr_addr_list[j].p_laddr;
		i++;
		rindx++;
		if (i == per_span) {
			hermon_index(index1, index2, rindx, icm_table, i);
			dma_info = icm_table->icm_dma[index1] + index2;
			mtt_table = (uint64_t *)(uintptr_t)dma_info->vaddr;
		}
	}

	return (DDI_SUCCESS);
}


/*
 * hermon_mtt_refcnt_inc()
 *    Context: Can be called from interrupt or base context.
 */
static uint_t
hermon_mtt_refcnt_inc(hermon_rsrc_t *rsrc)
{
	hermon_sw_refcnt_t *rc;

	rc = (hermon_sw_refcnt_t *)rsrc->hr_addr;
	return (atomic_inc_uint_nv(&rc->swrc_refcnt));
}


/*
 * hermon_mtt_refcnt_dec()
 *    Context: Can be called from interrupt or base context.
 */
static uint_t
hermon_mtt_refcnt_dec(hermon_rsrc_t *rsrc)
{
	hermon_sw_refcnt_t *rc;

	rc = (hermon_sw_refcnt_t *)rsrc->hr_addr;
	return (atomic_dec_uint_nv(&rc->swrc_refcnt));
}
