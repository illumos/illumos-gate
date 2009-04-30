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
 * tavor_misc.c
 *    Tavor Miscellaneous routines - Address Handle, Multicast, Protection
 *    Domain, and port-related operations
 *
 *    Implements all the routines necessary for allocating, freeing, querying
 *    and modifying Address Handles and Protection Domains.  Also implements
 *    all the routines necessary for adding and removing Queue Pairs to/from
 *    Multicast Groups.  Lastly, it implements the routines necessary for
 *    port-related query and modify operations.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/bitmap.h>
#include <sys/sysmacros.h>

#include <sys/ib/adapters/tavor/tavor.h>

/* used for helping uniquify fmr pool taskq name */
static uint_t tavor_debug_fmrpool_cnt = 0x00000000;

static void tavor_udav_sync(tavor_ahhdl_t ah, tavor_hw_udav_t *udav,
    uint_t flag);
static int tavor_mcg_qplist_add(tavor_state_t *state, tavor_mcghdl_t mcg,
    tavor_hw_mcg_qp_list_t *mcg_qplist, tavor_qphdl_t qp, uint_t *qp_found);
static int tavor_mcg_qplist_remove(tavor_mcghdl_t mcg,
    tavor_hw_mcg_qp_list_t *mcg_qplist, tavor_qphdl_t qp);
static void tavor_qp_mcg_refcnt_inc(tavor_qphdl_t qp);
static void tavor_qp_mcg_refcnt_dec(tavor_qphdl_t qp);
static uint_t tavor_mcg_walk_mgid_hash(tavor_state_t *state,
    uint64_t start_indx, ib_gid_t mgid, uint_t *prev_indx);
static void tavor_mcg_setup_new_hdr(tavor_mcghdl_t mcg,
    tavor_hw_mcg_t *mcg_hdr, ib_gid_t mgid, tavor_rsrc_t *mcg_rsrc);
static int tavor_mcg_hash_list_remove(tavor_state_t *state, uint_t curr_indx,
    uint_t prev_indx, tavor_hw_mcg_t *mcg_entry);
static int tavor_mcg_entry_invalidate(tavor_state_t *state,
    tavor_hw_mcg_t *mcg_entry, uint_t indx);
static int tavor_mgid_is_valid(ib_gid_t gid);
static int tavor_mlid_is_valid(ib_lid_t lid);
static void tavor_fmr_processing(void *fmr_args);
static int tavor_fmr_cleanup(tavor_state_t *state, tavor_fmrhdl_t pool);
static void tavor_fmr_cache_init(tavor_fmrhdl_t fmr);
static void tavor_fmr_cache_fini(tavor_fmrhdl_t fmr);
static int tavor_fmr_avl_compare(const void *q, const void *e);


/*
 * tavor_ah_alloc()
 *    Context: Can be called only from user or kernel context.
 */
int
tavor_ah_alloc(tavor_state_t *state, tavor_pdhdl_t pd,
    ibt_adds_vect_t *attr_p, tavor_ahhdl_t *ahhdl, uint_t sleepflag)
{
	tavor_rsrc_t		*udav, *rsrc;
	tavor_hw_udav_t		udav_entry;
	tavor_ahhdl_t		ah;
	ibt_mr_attr_t		mr_attr;
	tavor_mr_options_t	op;
	tavor_mrhdl_t		mr;
	uint64_t		data;
	uint32_t		size;
	int			status, i, flag;
	char			*errormsg;

	TAVOR_TNF_ENTER(tavor_ah_alloc);

	/*
	 * Someday maybe the "ibt_adds_vect_t *attr_p" will be NULL to
	 * indicate that we wish to allocate an "invalid" (i.e. empty)
	 * address handle XXX
	 */

	/* Validate that specified port number is legal */
	if (!tavor_portnum_is_valid(state, attr_p->av_port_num)) {
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(IBT_HCA_PORT_INVALID, "invalid port num");
		goto ahalloc_fail;
	}

	/*
	 * Allocate a UDAV entry.  This will be filled in with all the
	 * necessary parameters to define the Address Handle.  Unlike the
	 * other hardware resources no ownership transfer takes place as
	 * these UDAV entries are always owned by hardware.
	 */
	status = tavor_rsrc_alloc(state, TAVOR_UDAV, 1, sleepflag, &udav);
	if (status != DDI_SUCCESS) {
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(IBT_INSUFF_RESOURCE, "failed UDAV");
		goto ahalloc_fail;
	}

	/*
	 * Allocate the software structure for tracking the address handle
	 * (i.e. the Tavor Address Handle struct).  If we fail here, we must
	 * undo the previous resource allocation.
	 */
	status = tavor_rsrc_alloc(state, TAVOR_AHHDL, 1, sleepflag, &rsrc);
	if (status != DDI_SUCCESS) {
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(IBT_INSUFF_RESOURCE, "failed AH handler");
		goto ahalloc_fail1;
	}
	ah = (tavor_ahhdl_t)rsrc->tr_addr;
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*ah))

	/* Increment the reference count on the protection domain (PD) */
	tavor_pd_refcnt_inc(pd);

	/*
	 * Fill in the UDAV entry.  Note: We are only filling in a temporary
	 * copy here, which we will later copy into the actual entry in
	 * Tavor DDR memory.  This starts be zeroing out the temporary copy
	 * and then calling tavor_set_addr_path() to fill in the common
	 * portions that can be pulled from the "ibt_adds_vect_t" passed in
	 */
	bzero(&udav_entry, sizeof (tavor_hw_udav_t));
	status = tavor_set_addr_path(state, attr_p,
	    (tavor_hw_addr_path_t *)&udav_entry, TAVOR_ADDRPATH_UDAV, NULL);
	if (status != DDI_SUCCESS) {
		tavor_pd_refcnt_dec(pd);
		tavor_rsrc_free(state, &rsrc);
		tavor_rsrc_free(state, &udav);
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(status, "failed in tavor_set_addr_path");
		goto ahalloc_fail;
	}
	udav_entry.pd	  = pd->pd_pdnum;
	udav_entry.msg_sz = state->ts_cfg_profile->cp_max_mtu - 1;

	/*
	 * Register the memory for the UDAV.  The memory for the UDAV must
	 * be registered in the Tavor TPT tables.  This gives us the LKey
	 * that we will need when we later post a UD work request that
	 * uses this address handle.
	 * We might be able to pre-register all the memory for the UDAV XXX
	 */
	flag = (sleepflag == TAVOR_SLEEP) ? IBT_MR_SLEEP : IBT_MR_NOSLEEP;
	mr_attr.mr_vaddr = (uint64_t)(uintptr_t)udav->tr_addr;
	mr_attr.mr_len	 = udav->tr_len;
	mr_attr.mr_as	 = NULL;
	mr_attr.mr_flags = flag;
	op.mro_bind_type = state->ts_cfg_profile->cp_iommu_bypass;
	op.mro_bind_dmahdl = NULL;
	op.mro_bind_override_addr = 0;
	status = tavor_mr_register(state, pd, &mr_attr, &mr, &op);
	if (status != DDI_SUCCESS) {
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(IBT_INSUFF_RESOURCE, "failed register mr");
		goto ahalloc_fail2;
	}

	/*
	 * Fill in the UDAV entry.  Here we copy all the information from
	 * the temporary UDAV into the DDR memory for the real UDAV entry.
	 * Note that we copy everything but the first 64-bit word.  This
	 * is where the PD number for the address handle resides.
	 * By filling everything except the PD and then writing the PD in
	 * a separate step below, we can ensure that the UDAV is not
	 * accessed while there are partially written values in it (something
	 * which really should not happen anyway).  This is guaranteed
	 * because we take measures to ensure that the PD number is zero for
	 * all unused UDAV (and because PD#0 is reserved for Tavor).
	 */
	size = sizeof (tavor_hw_udav_t) >> 3;
	for (i = 1; i < size; i++) {
		data = ((uint64_t *)&udav_entry)[i];
		ddi_put64(udav->tr_acchdl, ((uint64_t *)udav->tr_addr + i),
		    data);
	}
	data = ((uint64_t *)&udav_entry)[0];
	ddi_put64(udav->tr_acchdl, (uint64_t *)udav->tr_addr, data);

	/*
	 * Fill in the rest of the Tavor Address Handle struct.  Having
	 * successfully copied the UDAV into the hardware, we update the
	 * following fields for use in further operations on the AH.
	 *
	 * NOTE: We are saving away a copy of the "av_dgid.gid_guid" field
	 * here because we may need to return it later to the IBTF (as a
	 * result of a subsequent query operation).  Unlike the other UDAV
	 * parameters, the value of "av_dgid.gid_guid" is not always preserved
	 * by being written to hardware.  The reason for this is described in
	 * tavor_set_addr_path().
	 */
	ah->ah_udavrsrcp = udav;
	ah->ah_rsrcp	 = rsrc;
	ah->ah_pdhdl	 = pd;
	ah->ah_mrhdl	 = mr;
	ah->ah_save_guid = attr_p->av_dgid.gid_guid;
	ah->ah_save_srate = attr_p->av_srate;
	*ahhdl = ah;

	/* Determine if later ddi_dma_sync will be necessary */
	ah->ah_sync = TAVOR_UDAV_IS_SYNC_REQ(state);

	/* Sync the UDAV for use by the hardware */
	tavor_udav_sync(ah, udav->tr_addr, DDI_DMA_SYNC_FORDEV);

	TAVOR_TNF_EXIT(tavor_ah_alloc);
	return (DDI_SUCCESS);

ahalloc_fail2:
	tavor_pd_refcnt_dec(pd);
	tavor_rsrc_free(state, &rsrc);
ahalloc_fail1:
	tavor_rsrc_free(state, &udav);
ahalloc_fail:
	TNF_PROBE_1(tavor_ah_alloc_fail, TAVOR_TNF_ERROR, "",
	    tnf_string, msg, errormsg);
	TAVOR_TNF_EXIT(tavor_ah_alloc);
	return (status);
}


/*
 * tavor_ah_free()
 *    Context: Can be called only from user or kernel context.
 */
/* ARGSUSED */
int
tavor_ah_free(tavor_state_t *state, tavor_ahhdl_t *ahhdl, uint_t sleepflag)
{
	tavor_rsrc_t		*udav, *rsrc;
	tavor_pdhdl_t		pd;
	tavor_mrhdl_t		mr;
	tavor_ahhdl_t		ah;
	int			status;

	TAVOR_TNF_ENTER(tavor_ah_free);

	/*
	 * Pull all the necessary information from the Tavor Address Handle
	 * struct.  This is necessary here because the resource for the
	 * AH is going to be freed up as part of this operation.
	 */
	ah    = *ahhdl;
	mutex_enter(&ah->ah_lock);
	udav  = ah->ah_udavrsrcp;
	rsrc  = ah->ah_rsrcp;
	pd    = ah->ah_pdhdl;
	mr    = ah->ah_mrhdl;
	mutex_exit(&ah->ah_lock);
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*ah))

	/*
	 * Deregister the memory for the UDAV.  If this fails for any reason,
	 * then it is an indication that something (either in HW or SW) has
	 * gone seriously wrong.  So we print a warning message and return
	 * failure.
	 */
	status = tavor_mr_deregister(state, &mr, TAVOR_MR_DEREG_ALL,
	    sleepflag);
	if (status != DDI_SUCCESS) {
		TNF_PROBE_0(tavor_ah_free_dereg_mr_fail, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ah_free);
		return (ibc_get_ci_failure(0));
	}

	/*
	 * Write zero to the first 64-bit word in the UDAV entry.  As
	 * described above (in tavor_ah_alloc), the PD number is stored in
	 * the first 64-bits of each UDAV and setting this to zero is
	 * guaranteed to invalidate the entry.
	 */
	ddi_put64(udav->tr_acchdl, (uint64_t *)udav->tr_addr, 0);

	/* Sync the UDAV for use by the hardware */
	tavor_udav_sync(ah, udav->tr_addr, DDI_DMA_SYNC_FORDEV);

	/* Decrement the reference count on the protection domain (PD) */
	tavor_pd_refcnt_dec(pd);

	/* Free the Tavor Address Handle structure */
	tavor_rsrc_free(state, &rsrc);

	/* Free up the UDAV entry resource */
	tavor_rsrc_free(state, &udav);

	/* Set the ahhdl pointer to NULL and return success */
	*ahhdl = NULL;

	TAVOR_TNF_EXIT(tavor_ah_free);
	return (DDI_SUCCESS);
}


/*
 * tavor_ah_query()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
int
tavor_ah_query(tavor_state_t *state, tavor_ahhdl_t ah, tavor_pdhdl_t *pd,
    ibt_adds_vect_t *attr_p)
{
	tavor_hw_udav_t		udav_entry;
	tavor_rsrc_t		*udav;
	uint64_t		data;
	uint32_t		size;
	int			i;

	TAVOR_TNF_ENTER(tavor_ah_query);

	mutex_enter(&ah->ah_lock);
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*attr_p))

	/*
	 * Pull all the necessary information from the Tavor Address Handle
	 * structure
	 */
	udav	= ah->ah_udavrsrcp;
	*pd	= ah->ah_pdhdl;

	/*
	 * Copy the UDAV entry into the temporary copy.  Here we copy all
	 * the information from the UDAV entry in DDR memory into the
	 * temporary UDAV.  Note:  We don't need to sync the UDAV for
	 * reading by software because Tavor HW never modifies the entry.
	 */
	size = sizeof (tavor_hw_udav_t) >> 3;
	for (i = 0; i < size; i++) {
		data = ddi_get64(udav->tr_acchdl,
		    ((uint64_t *)udav->tr_addr + i));
		((uint64_t *)&udav_entry)[i] = data;
	}

	/*
	 * Fill in "ibt_adds_vect_t".  We call tavor_get_addr_path() to fill
	 * the common portions that can be pulled from the UDAV we pass in.
	 *
	 * NOTE: We will also fill the "av_dgid.gid_guid" field from the
	 * "ah_save_guid" field we have previously saved away.  The reason
	 * for this is described in tavor_ah_alloc() and tavor_ah_modify().
	 */
	tavor_get_addr_path(state, (tavor_hw_addr_path_t *)&udav_entry,
	    attr_p, TAVOR_ADDRPATH_UDAV, NULL);

	attr_p->av_dgid.gid_guid = ah->ah_save_guid;
	attr_p->av_srate = ah->ah_save_srate;

	mutex_exit(&ah->ah_lock);
	TAVOR_TNF_EXIT(tavor_ah_query);
	return (DDI_SUCCESS);
}


/*
 * tavor_ah_modify()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
int
tavor_ah_modify(tavor_state_t *state, tavor_ahhdl_t ah,
    ibt_adds_vect_t *attr_p)
{
	tavor_hw_udav_t		udav_entry;
	tavor_rsrc_t		*udav;
	uint64_t		data_new, data_old;
	uint32_t		udav_pd, size, portnum_new;
	int			i, status;

	TAVOR_TNF_ENTER(tavor_ah_modify);

	/* Validate that specified port number is legal */
	if (!tavor_portnum_is_valid(state, attr_p->av_port_num)) {
		TNF_PROBE_1(tavor_ah_modify_inv_portnum,
		    TAVOR_TNF_ERROR, "", tnf_uint, port, attr_p->av_port_num);
		TAVOR_TNF_EXIT(tavor_ah_modify);
		return (IBT_HCA_PORT_INVALID);
	}

	mutex_enter(&ah->ah_lock);

	/*
	 * Pull all the necessary information from the Tavor Address Handle
	 * structure
	 */
	udav = ah->ah_udavrsrcp;

	/*
	 * Fill in the UDAV entry.  Note: we are only filling in a temporary
	 * copy here, which we will later copy into the actual entry in
	 * Tavor DDR memory.  This starts be zeroing out the temporary copy
	 * and then calling tavor_set_addr_path() to fill in the common
	 * portions that can be pulled from the "ibt_adds_vect_t" passed in
	 *
	 * NOTE: We also need to save away a copy of the "av_dgid.gid_guid"
	 * field here (just as we did during tavor_ah_alloc()) because we
	 * may need to return it later to the IBTF (as a result of a
	 * subsequent query operation).  As explained in tavor_ah_alloc(),
	 * unlike the other UDAV parameters, the value of "av_dgid.gid_guid"
	 * is not always preserved by being written to hardware.  The reason
	 * for this is described in tavor_set_addr_path().
	 */
	bzero(&udav_entry, sizeof (tavor_hw_udav_t));
	status = tavor_set_addr_path(state, attr_p,
	    (tavor_hw_addr_path_t *)&udav_entry, TAVOR_ADDRPATH_UDAV, NULL);
	if (status != DDI_SUCCESS) {
		mutex_exit(&ah->ah_lock);
		TNF_PROBE_0(tavor_ah_modify_setaddrpath_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ah_modify);
		return (status);
	}
	ah->ah_save_guid = attr_p->av_dgid.gid_guid;
	ah->ah_save_srate = attr_p->av_srate;

	/*
	 * Save away the current PD number for this UDAV.  Then temporarily
	 * invalidate the entry (by setting the PD to zero).  Note:  Since
	 * the first 32 bits of the UDAV actually contain the current port
	 * number _and_ current PD number, we need to mask off some bits.
	 */
	udav_pd = ddi_get32(udav->tr_acchdl, (uint32_t *)udav->tr_addr);
	udav_pd = udav_pd & 0xFFFFFF;
	ddi_put32(udav->tr_acchdl, (uint32_t *)udav->tr_addr, 0);

	/* Sync the UDAV for use by the hardware */
	tavor_udav_sync(ah, udav->tr_addr, DDI_DMA_SYNC_FORDEV);

	/*
	 * Copy UDAV structure to the entry
	 *    Note:  We copy in 64-bit chunks.  For the first two of these
	 *    chunks it is necessary to read the current contents of the
	 *    UDAV, mask off the modifiable portions (maintaining any
	 *    of the "reserved" portions), and then mask on the new data.
	 */
	size = sizeof (tavor_hw_udav_t) >> 3;
	for (i = 0; i < size; i++) {
		data_new = ((uint64_t *)&udav_entry)[i];
		data_old = ddi_get64(udav->tr_acchdl,
		    ((uint64_t *)udav->tr_addr + i));

		/*
		 * Apply mask to change only the relevant values.  Note: We
		 * extract the new portnum from the address handle here
		 * because the "PD" and "portnum" fields are in the same
		 * 32-bit word in the UDAV.  We will use the (new) port
		 * number extracted here when we write the valid PD number
		 * in the last step below.
		 */
		if (i == 0) {
			data_old = data_old & TAVOR_UDAV_MODIFY_MASK0;
			portnum_new = data_new >> 56;
		} else if (i == 1) {
			data_old = data_old & TAVOR_UDAV_MODIFY_MASK1;
		} else {
			data_old = 0;
		}

		/* Write the updated values to the UDAV (in DDR) */
		data_new = data_old | data_new;
		ddi_put64(udav->tr_acchdl, ((uint64_t *)udav->tr_addr + i),
		    data_new);
	}

	/*
	 * Sync the body of the UDAV for use by the hardware.  After we
	 * have updated the PD number (to make the UDAV valid), we sync
	 * again to push the entire entry out for hardware access.
	 */
	tavor_udav_sync(ah, udav->tr_addr, DDI_DMA_SYNC_FORDEV);

	/*
	 * Put the valid PD number back into UDAV entry.  Note: Because port
	 * number and PD number are in the same word, we must mask the
	 * new port number with the old PD number before writing it back
	 * to the UDAV entry
	 */
	udav_pd = ((portnum_new << 24) | udav_pd);
	ddi_put32(udav->tr_acchdl, (uint32_t *)udav->tr_addr, udav_pd);

	/* Sync the rest of the UDAV for use by the hardware */
	tavor_udav_sync(ah, udav->tr_addr, DDI_DMA_SYNC_FORDEV);

	mutex_exit(&ah->ah_lock);
	TAVOR_TNF_EXIT(tavor_ah_modify);
	return (DDI_SUCCESS);
}


/*
 * tavor_udav_sync()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static void
tavor_udav_sync(tavor_ahhdl_t ah, tavor_hw_udav_t *udav, uint_t flag)
{
	ddi_dma_handle_t	dmahdl;
	off_t			offset;
	int			status;

	TAVOR_TNF_ENTER(tavor_udav_sync);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*ah))

	/* Determine if AH needs to be synced or not */
	if (ah->ah_sync == 0) {
		TAVOR_TNF_EXIT(tavor_udav_sync);
		return;
	}

	/* Get the DMA handle from AH handle */
	dmahdl = ah->ah_mrhdl->mr_bindinfo.bi_dmahdl;

	/* Calculate offset into address handle */
	offset = (off_t)0;
	status = ddi_dma_sync(dmahdl, offset, sizeof (tavor_hw_udav_t), flag);
	if (status != DDI_SUCCESS) {
		TNF_PROBE_0(tavor_udav_sync_getnextentry_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_udav_sync);
		return;
	}

	TAVOR_TNF_EXIT(tavor_udav_sync);
}


/*
 * tavor_mcg_attach()
 *    Context: Can be called only from user or kernel context.
 */
int
tavor_mcg_attach(tavor_state_t *state, tavor_qphdl_t qp, ib_gid_t gid,
    ib_lid_t lid)
{
	tavor_rsrc_t		*rsrc;
	tavor_hw_mcg_t		*mcg_entry;
	tavor_hw_mcg_qp_list_t	*mcg_entry_qplist;
	tavor_mcghdl_t		mcg, newmcg;
	uint64_t		mgid_hash;
	uint32_t		end_indx;
	int			status;
	uint_t			qp_found;
	char			*errormsg;

	TAVOR_TNF_ENTER(tavor_mcg_attach);

	/*
	 * It is only allowed to attach MCG to UD queue pairs.  Verify
	 * that the intended QP is of the appropriate transport type
	 */
	if (qp->qp_serv_type != TAVOR_QP_UD) {
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(IBT_QP_SRV_TYPE_INVALID, "invalid service type");
		goto mcgattach_fail;
	}

	/*
	 * Check for invalid Multicast DLID.  Specifically, all Multicast
	 * LIDs should be within a well defined range.  If the specified LID
	 * is outside of that range, then return an error.
	 */
	if (tavor_mlid_is_valid(lid) == 0) {
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(IBT_MC_MLID_INVALID, "invalid MLID");
		goto mcgattach_fail;
	}
	/*
	 * Check for invalid Multicast GID.  All Multicast GIDs should have
	 * a well-defined pattern of bits and flags that are allowable.  If
	 * the specified GID does not meet the criteria, then return an error.
	 */
	if (tavor_mgid_is_valid(gid) == 0) {
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(IBT_MC_MGID_INVALID, "invalid MGID");
		goto mcgattach_fail;
	}

	/*
	 * Compute the MGID hash value.  Since the MCG table is arranged as
	 * a number of separate hash chains, this operation converts the
	 * specified MGID into the starting index of an entry in the hash
	 * table (i.e. the index for the start of the appropriate hash chain).
	 * Subsequent operations below will walk the chain searching for the
	 * right place to add this new QP.
	 */
	status = tavor_mgid_hash_cmd_post(state, gid.gid_prefix, gid.gid_guid,
	    &mgid_hash, TAVOR_SLEEPFLAG_FOR_CONTEXT());
	if (status != TAVOR_CMD_SUCCESS) {
		cmn_err(CE_CONT, "Tavor: MGID_HASH command failed: %08x\n",
		    status);
		TNF_PROBE_1(tavor_mcg_attach_mgid_hash_cmd_fail,
		    TAVOR_TNF_ERROR, "", tnf_uint, cmd_status, status);
		TAVOR_TNF_EXIT(tavor_mcg_attach);
		return (ibc_get_ci_failure(0));
	}

	/*
	 * Grab the multicast group mutex.  Then grab the pre-allocated
	 * temporary buffer used for holding and/or modifying MCG entries.
	 * Zero out the temporary MCG entry before we begin.
	 */
	mutex_enter(&state->ts_mcglock);
	mcg_entry = state->ts_mcgtmp;
	mcg_entry_qplist = TAVOR_MCG_GET_QPLIST_PTR(mcg_entry);
	bzero(mcg_entry, TAVOR_MCGMEM_SZ(state));

	/*
	 * Walk through the array of MCG entries starting at "mgid_hash".
	 * Try to find the appropriate place for this new QP to be added.
	 * This could happen when the first entry of the chain has MGID == 0
	 * (which means that the hash chain is empty), or because we find
	 * an entry with the same MGID (in which case we'll add the QP to
	 * that MCG), or because we come to the end of the chain (in which
	 * case this is the first QP being added to the multicast group that
	 * corresponds to the MGID.  The tavor_mcg_walk_mgid_hash() routine
	 * walks the list and returns an index into the MCG table.  The entry
	 * at this index is then checked to determine which case we have
	 * fallen into (see below).  Note:  We are using the "shadow" MCG
	 * list (of tavor_mcg_t structs) for this lookup because the real
	 * MCG entries are in hardware (and the lookup process would be much
	 * more time consuming).
	 */
	end_indx = tavor_mcg_walk_mgid_hash(state, mgid_hash, gid, NULL);
	mcg	 = &state->ts_mcghdl[end_indx];

	/*
	 * If MGID == 0, then the hash chain is empty.  Just fill in the
	 * current entry.  Note:  No need to allocate an MCG table entry
	 * as all the hash chain "heads" are already preallocated.
	 */
	if ((mcg->mcg_mgid_h == 0) && (mcg->mcg_mgid_l == 0)) {

		/* Fill in the current entry in the "shadow" MCG list */
		tavor_mcg_setup_new_hdr(mcg, mcg_entry, gid, NULL);

		/*
		 * Try to add the new QP number to the list.  This (and the
		 * above) routine fills in a temporary MCG.  The "mcg_entry"
		 * and "mcg_entry_qplist" pointers simply point to different
		 * offsets within the same temporary copy of the MCG (for
		 * convenience).  Note:  If this fails, we need to invalidate
		 * the entries we've already put into the "shadow" list entry
		 * above.
		 */
		status = tavor_mcg_qplist_add(state, mcg, mcg_entry_qplist, qp,
		    &qp_found);
		if (status != DDI_SUCCESS) {
			bzero(mcg, sizeof (struct tavor_sw_mcg_list_s));
			mutex_exit(&state->ts_mcglock);
			/* Set "status" and "errormsg" and goto failure */
			TAVOR_TNF_FAIL(status, "failed qplist add");
			goto mcgattach_fail;
		}

		/*
		 * Once the temporary MCG has been filled in, write the entry
		 * into the appropriate location in the Tavor MCG entry table.
		 * If it's successful, then drop the lock and return success.
		 * Note: In general, this operation shouldn't fail.  If it
		 * does, then it is an indication that something (probably in
		 * HW, but maybe in SW) has gone seriously wrong.  We still
		 * want to zero out the entries that we've filled in above
		 * (in the tavor_mcg_setup_new_hdr() routine).
		 */
		status = tavor_write_mgm_cmd_post(state, mcg_entry, end_indx,
		    TAVOR_CMD_NOSLEEP_SPIN);
		if (status != TAVOR_CMD_SUCCESS) {
			bzero(mcg, sizeof (struct tavor_sw_mcg_list_s));
			mutex_exit(&state->ts_mcglock);
			TAVOR_WARNING(state, "failed to write MCG entry");
			cmn_err(CE_CONT, "Tavor: WRITE_MGM command failed: "
			    "%08x\n", status);
			TNF_PROBE_2(tavor_mcg_attach_write_mgm_cmd_fail,
			    TAVOR_TNF_ERROR, "", tnf_uint, cmd_status, status,
			    tnf_uint, indx, end_indx);
			TAVOR_TNF_EXIT(tavor_mcg_attach);
			return (ibc_get_ci_failure(0));
		}

		/*
		 * Now that we know all the Tavor firmware accesses have been
		 * successful, we update the "shadow" MCG entry by incrementing
		 * the "number of attached QPs" count.
		 *
		 * We increment only if the QP is not already part of the
		 * MCG by checking the 'qp_found' flag returned from the
		 * qplist_add above.
		 */
		if (!qp_found) {
			mcg->mcg_num_qps++;

			/*
			 * Increment the refcnt for this QP.  Because the QP
			 * was added to this MCG, the refcnt must be
			 * incremented.
			 */
			tavor_qp_mcg_refcnt_inc(qp);
		}

		/*
		 * We drop the lock and return success.
		 */
		mutex_exit(&state->ts_mcglock);
		TAVOR_TNF_EXIT(tavor_mcg_attach);
		return (DDI_SUCCESS);
	}

	/*
	 * If the specified MGID matches the MGID in the current entry, then
	 * we need to try to add the QP to the current MCG entry.  In this
	 * case, it means that we need to read the existing MCG entry (into
	 * the temporary MCG), add the new QP number to the temporary entry
	 * (using the same method we used above), and write the entry back
	 * to the hardware (same as above).
	 */
	if ((mcg->mcg_mgid_h == gid.gid_prefix) &&
	    (mcg->mcg_mgid_l == gid.gid_guid)) {

		/*
		 * Read the current MCG entry into the temporary MCG.  Note:
		 * In general, this operation shouldn't fail.  If it does,
		 * then it is an indication that something (probably in HW,
		 * but maybe in SW) has gone seriously wrong.
		 */
		status = tavor_read_mgm_cmd_post(state, mcg_entry, end_indx,
		    TAVOR_CMD_NOSLEEP_SPIN);
		if (status != TAVOR_CMD_SUCCESS) {
			mutex_exit(&state->ts_mcglock);
			TAVOR_WARNING(state, "failed to read MCG entry");
			cmn_err(CE_CONT, "Tavor: READ_MGM command failed: "
			    "%08x\n", status);
			TNF_PROBE_2(tavor_mcg_attach_read_mgm_cmd_fail,
			    TAVOR_TNF_ERROR, "", tnf_uint, cmd_status, status,
			    tnf_uint, indx, end_indx);
			TAVOR_TNF_EXIT(tavor_mcg_attach);
			return (ibc_get_ci_failure(0));
		}

		/*
		 * Try to add the new QP number to the list.  This routine
		 * fills in the necessary pieces of the temporary MCG.  The
		 * "mcg_entry_qplist" pointer is used to point to the portion
		 * of the temporary MCG that holds the QP numbers.
		 *
		 * Note: tavor_mcg_qplist_add() returns SUCCESS if it
		 * already found the QP in the list.  In this case, the QP is
		 * not added on to the list again.  Check the flag 'qp_found'
		 * if this value is needed to be known.
		 *
		 */
		status = tavor_mcg_qplist_add(state, mcg, mcg_entry_qplist, qp,
		    &qp_found);
		if (status != DDI_SUCCESS) {
			mutex_exit(&state->ts_mcglock);
			/* Set "status" and "errormsg" and goto failure */
			TAVOR_TNF_FAIL(status, "failed qplist add");
			goto mcgattach_fail;
		}

		/*
		 * Once the temporary MCG has been updated, write the entry
		 * into the appropriate location in the Tavor MCG entry table.
		 * If it's successful, then drop the lock and return success.
		 * Note: In general, this operation shouldn't fail.  If it
		 * does, then it is an indication that something (probably in
		 * HW, but maybe in SW) has gone seriously wrong.
		 */
		status = tavor_write_mgm_cmd_post(state, mcg_entry, end_indx,
		    TAVOR_CMD_NOSLEEP_SPIN);
		if (status != TAVOR_CMD_SUCCESS) {
			mutex_exit(&state->ts_mcglock);
			TAVOR_WARNING(state, "failed to write MCG entry");
			cmn_err(CE_CONT, "Tavor: WRITE_MGM command failed: "
			    "%08x\n", status);
			TNF_PROBE_2(tavor_mcg_attach_write_mgm_cmd_fail,
			    TAVOR_TNF_ERROR, "", tnf_uint, cmd_status, status,
			    tnf_uint, indx, end_indx);
			TAVOR_TNF_EXIT(tavor_mcg_attach);
			return (ibc_get_ci_failure(0));
		}

		/*
		 * Now that we know all the Tavor firmware accesses have been
		 * successful, we update the current "shadow" MCG entry by
		 * incrementing the "number of attached QPs" count.
		 *
		 * We increment only if the QP is not already part of the
		 * MCG by checking the 'qp_found' flag returned from the
		 * qplist_add above.
		 */
		if (!qp_found) {
			mcg->mcg_num_qps++;

			/*
			 * Increment the refcnt for this QP.  Because the QP
			 * was added to this MCG, the refcnt must be
			 * incremented.
			 */
			tavor_qp_mcg_refcnt_inc(qp);
		}

		/*
		 * We drop the lock and return success.
		 */
		mutex_exit(&state->ts_mcglock);
		TAVOR_TNF_EXIT(tavor_mcg_attach);
		return (DDI_SUCCESS);
	}

	/*
	 * If we've reached here, then we're at the end of the hash chain.
	 * We need to allocate a new MCG entry, fill it in, write it to Tavor,
	 * and update the previous entry to link the new one to the end of the
	 * chain.
	 */

	/*
	 * Allocate an MCG table entry.  This will be filled in with all
	 * the necessary parameters to define the multicast group.  Then it
	 * will be written to the hardware in the next-to-last step below.
	 */
	status = tavor_rsrc_alloc(state, TAVOR_MCG, 1, TAVOR_NOSLEEP, &rsrc);
	if (status != DDI_SUCCESS) {
		mutex_exit(&state->ts_mcglock);
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(IBT_INSUFF_RESOURCE, "failed MCG");
		goto mcgattach_fail;
	}

	/*
	 * Fill in the new entry in the "shadow" MCG list.  Note:  Just as
	 * it does above, tavor_mcg_setup_new_hdr() also fills in a portion
	 * of the temporary MCG entry (the rest of which will be filled in by
	 * tavor_mcg_qplist_add() below)
	 */
	newmcg = &state->ts_mcghdl[rsrc->tr_indx];
	tavor_mcg_setup_new_hdr(newmcg, mcg_entry, gid, rsrc);

	/*
	 * Try to add the new QP number to the list.  This routine fills in
	 * the final necessary pieces of the temporary MCG.  The
	 * "mcg_entry_qplist" pointer is used to point to the portion of the
	 * temporary MCG that holds the QP numbers.  If we fail here, we
	 * must undo the previous resource allocation.
	 *
	 * Note: tavor_mcg_qplist_add() can we return SUCCESS if it already
	 * found the QP in the list.  In this case, the QP is not added on to
	 * the list again.  Check the flag 'qp_found' if this value is needed
	 * to be known.
	 */
	status = tavor_mcg_qplist_add(state, newmcg, mcg_entry_qplist, qp,
	    &qp_found);
	if (status != DDI_SUCCESS) {
		bzero(newmcg, sizeof (struct tavor_sw_mcg_list_s));
		tavor_rsrc_free(state, &rsrc);
		mutex_exit(&state->ts_mcglock);
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(status, "failed qplist add");
		goto mcgattach_fail;
	}

	/*
	 * Once the temporary MCG has been updated, write the entry into the
	 * appropriate location in the Tavor MCG entry table.  If this is
	 * successful, then we need to chain the previous entry to this one.
	 * Note: In general, this operation shouldn't fail.  If it does, then
	 * it is an indication that something (probably in HW, but maybe in
	 * SW) has gone seriously wrong.
	 */
	status = tavor_write_mgm_cmd_post(state, mcg_entry, rsrc->tr_indx,
	    TAVOR_CMD_NOSLEEP_SPIN);
	if (status != TAVOR_CMD_SUCCESS) {
		bzero(newmcg, sizeof (struct tavor_sw_mcg_list_s));
		tavor_rsrc_free(state, &rsrc);
		mutex_exit(&state->ts_mcglock);
		TAVOR_WARNING(state, "failed to write MCG entry");
		cmn_err(CE_CONT, "Tavor: WRITE_MGM command failed: %08x\n",
		    status);
		TNF_PROBE_2(tavor_mcg_attach_write_mgm_cmd_fail,
		    TAVOR_TNF_ERROR, "", tnf_uint, cmd_status, status,
		    tnf_uint, indx, rsrc->tr_indx);
		TAVOR_TNF_EXIT(tavor_mcg_attach);
		return (ibc_get_ci_failure(0));
	}

	/*
	 * Now read the current MCG entry (the one previously at the end of
	 * hash chain) into the temporary MCG.  We are going to update its
	 * "next_gid_indx" now and write the entry back to the MCG table.
	 * Note:  In general, this operation shouldn't fail.  If it does, then
	 * it is an indication that something (probably in HW, but maybe in SW)
	 * has gone seriously wrong.  We will free up the MCG entry resource,
	 * but we will not undo the previously written MCG entry in the HW.
	 * This is OK, though, because the MCG entry is not currently attached
	 * to any hash chain.
	 */
	status = tavor_read_mgm_cmd_post(state, mcg_entry, end_indx,
	    TAVOR_CMD_NOSLEEP_SPIN);
	if (status != TAVOR_CMD_SUCCESS) {
		bzero(newmcg, sizeof (struct tavor_sw_mcg_list_s));
		tavor_rsrc_free(state, &rsrc);
		mutex_exit(&state->ts_mcglock);
		TAVOR_WARNING(state, "failed to read MCG entry");
		cmn_err(CE_CONT, "Tavor: READ_MGM command failed: %08x\n",
		    status);
		TNF_PROBE_2(tavor_mcg_attach_read_mgm_cmd_fail,
		    TAVOR_TNF_ERROR, "", tnf_uint, cmd_status, status,
		    tnf_uint, indx, end_indx);
		TAVOR_TNF_EXIT(tavor_mcg_attach);
		return (ibc_get_ci_failure(0));
	}

	/*
	 * Finally, we update the "next_gid_indx" field in the temporary MCG
	 * and attempt to write the entry back into the Tavor MCG table.  If
	 * this succeeds, then we update the "shadow" list to reflect the
	 * change, drop the lock, and return success.  Note:  In general, this
	 * operation shouldn't fail.  If it does, then it is an indication
	 * that something (probably in HW, but maybe in SW) has gone seriously
	 * wrong.  Just as we do above, we will free up the MCG entry resource,
	 * but we will not try to undo the previously written MCG entry.  This
	 * is OK, though, because (since we failed here to update the end of
	 * the chain) that other entry is not currently attached to any chain.
	 */
	mcg_entry->next_gid_indx = rsrc->tr_indx;
	status = tavor_write_mgm_cmd_post(state, mcg_entry, end_indx,
	    TAVOR_CMD_NOSLEEP_SPIN);
	if (status != TAVOR_CMD_SUCCESS) {
		bzero(newmcg, sizeof (struct tavor_sw_mcg_list_s));
		tavor_rsrc_free(state, &rsrc);
		mutex_exit(&state->ts_mcglock);
		TAVOR_WARNING(state, "failed to write MCG entry");
		cmn_err(CE_CONT, "Tavor: WRITE_MGM command failed: %08x\n",
		    status);
		TNF_PROBE_2(tavor_mcg_attach_write_mgm_cmd_fail,
		    TAVOR_TNF_ERROR, "", tnf_uint, cmd_status, status,
		    tnf_uint, indx, end_indx);
		TAVOR_TNF_EXIT(tavor_mcg_attach);
		return (ibc_get_ci_failure(0));
	}
	mcg = &state->ts_mcghdl[end_indx];
	mcg->mcg_next_indx = rsrc->tr_indx;

	/*
	 * Now that we know all the Tavor firmware accesses have been
	 * successful, we update the new "shadow" MCG entry by incrementing
	 * the "number of attached QPs" count.  Then we drop the lock and
	 * return success.
	 */
	newmcg->mcg_num_qps++;

	/*
	 * Increment the refcnt for this QP.  Because the QP
	 * was added to this MCG, the refcnt must be
	 * incremented.
	 */
	tavor_qp_mcg_refcnt_inc(qp);

	mutex_exit(&state->ts_mcglock);
	TAVOR_TNF_EXIT(tavor_mcg_attach);
	return (DDI_SUCCESS);

mcgattach_fail:
	TNF_PROBE_1(tavor_mcg_attach_fail, TAVOR_TNF_ERROR, "", tnf_string,
	    msg, errormsg);
	TAVOR_TNF_EXIT(tavor_mcg_attach);
	return (status);
}


/*
 * tavor_mcg_detach()
 *    Context: Can be called only from user or kernel context.
 */
int
tavor_mcg_detach(tavor_state_t *state, tavor_qphdl_t qp, ib_gid_t gid,
    ib_lid_t lid)
{
	tavor_hw_mcg_t		*mcg_entry;
	tavor_hw_mcg_qp_list_t	*mcg_entry_qplist;
	tavor_mcghdl_t		mcg;
	uint64_t		mgid_hash;
	uint32_t		end_indx, prev_indx;
	int			status;

	TAVOR_TNF_ENTER(tavor_mcg_detach);

	/*
	 * Check for invalid Multicast DLID.  Specifically, all Multicast
	 * LIDs should be within a well defined range.  If the specified LID
	 * is outside of that range, then return an error.
	 */
	if (tavor_mlid_is_valid(lid) == 0) {
		TNF_PROBE_0(tavor_mcg_detach_invmlid_fail, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_mcg_detach);
		return (IBT_MC_MLID_INVALID);
	}

	/*
	 * Compute the MGID hash value.  As described above, the MCG table is
	 * arranged as a number of separate hash chains.  This operation
	 * converts the specified MGID into the starting index of an entry in
	 * the hash table (i.e. the index for the start of the appropriate
	 * hash chain).  Subsequent operations below will walk the chain
	 * searching for a matching entry from which to attempt to remove
	 * the specified QP.
	 */
	status = tavor_mgid_hash_cmd_post(state, gid.gid_prefix, gid.gid_guid,
	    &mgid_hash, TAVOR_SLEEPFLAG_FOR_CONTEXT());
	if (status != TAVOR_CMD_SUCCESS) {
		cmn_err(CE_CONT, "Tavor: MGID_HASH command failed: %08x\n",
		    status);
		TNF_PROBE_1(tavor_mcg_detach_mgid_hash_cmd_fail,
		    TAVOR_TNF_ERROR, "", tnf_uint, cmd_status, status);
		TAVOR_TNF_EXIT(tavor_mcg_attach);
		return (ibc_get_ci_failure(0));
	}

	/*
	 * Grab the multicast group mutex.  Then grab the pre-allocated
	 * temporary buffer used for holding and/or modifying MCG entries.
	 */
	mutex_enter(&state->ts_mcglock);
	mcg_entry = state->ts_mcgtmp;
	mcg_entry_qplist = TAVOR_MCG_GET_QPLIST_PTR(mcg_entry);

	/*
	 * Walk through the array of MCG entries starting at "mgid_hash".
	 * Try to find an MCG entry with a matching MGID.  The
	 * tavor_mcg_walk_mgid_hash() routine walks the list and returns an
	 * index into the MCG table.  The entry at this index is checked to
	 * determine whether it is a match or not.  If it is a match, then
	 * we continue on to attempt to remove the QP from the MCG.  If it
	 * is not a match (or not a valid MCG entry), then we return an error.
	 */
	end_indx = tavor_mcg_walk_mgid_hash(state, mgid_hash, gid, &prev_indx);
	mcg	 = &state->ts_mcghdl[end_indx];

	/*
	 * If MGID == 0 (the hash chain is empty) or if the specified MGID
	 * does not match the MGID in the current entry, then return
	 * IBT_MC_MGID_INVALID (to indicate that the specified MGID is not
	 * valid).
	 */
	if (((mcg->mcg_mgid_h == 0) && (mcg->mcg_mgid_l == 0)) ||
	    ((mcg->mcg_mgid_h != gid.gid_prefix) ||
	    (mcg->mcg_mgid_l != gid.gid_guid))) {
		mutex_exit(&state->ts_mcglock);
		TNF_PROBE_0(tavor_mcg_detach_invmgid_fail, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_mcg_detach);
		return (IBT_MC_MGID_INVALID);
	}

	/*
	 * Read the current MCG entry into the temporary MCG.  Note: In
	 * general, this operation shouldn't fail.  If it does, then it is
	 * an indication that something (probably in HW, but maybe in SW)
	 * has gone seriously wrong.
	 */
	status = tavor_read_mgm_cmd_post(state, mcg_entry, end_indx,
	    TAVOR_CMD_NOSLEEP_SPIN);
	if (status != TAVOR_CMD_SUCCESS) {
		mutex_exit(&state->ts_mcglock);
		TAVOR_WARNING(state, "failed to read MCG entry");
		cmn_err(CE_CONT, "Tavor: READ_MGM command failed: %08x\n",
		    status);
		TNF_PROBE_2(tavor_mcg_detach_read_mgm_cmd_fail,
		    TAVOR_TNF_ERROR, "", tnf_uint, cmd_status, status,
		    tnf_uint, indx, end_indx);
		TAVOR_TNF_EXIT(tavor_mcg_attach);
		return (ibc_get_ci_failure(0));
	}

	/*
	 * Search the QP number list for a match.  If a match is found, then
	 * remove the entry from the QP list.  Otherwise, if no match is found,
	 * return an error.
	 */
	status = tavor_mcg_qplist_remove(mcg, mcg_entry_qplist, qp);
	if (status != DDI_SUCCESS) {
		mutex_exit(&state->ts_mcglock);
		TAVOR_TNF_EXIT(tavor_mcg_detach);
		return (status);
	}

	/*
	 * Decrement the MCG count for this QP.  When the 'qp_mcg'
	 * field becomes 0, then this QP is no longer a member of any
	 * MCG.
	 */
	tavor_qp_mcg_refcnt_dec(qp);

	/*
	 * If the current MCG's QP number list is about to be made empty
	 * ("mcg_num_qps" == 1), then remove the entry itself from the hash
	 * chain.  Otherwise, just write the updated MCG entry back to the
	 * hardware.  In either case, once we successfully update the hardware
	 * chain, then we decrement the "shadow" list entry's "mcg_num_qps"
	 * count (or zero out the entire "shadow" list entry) before returning
	 * success.  Note:  Zeroing out the "shadow" list entry is done
	 * inside of tavor_mcg_hash_list_remove().
	 */
	if (mcg->mcg_num_qps == 1) {

		/* Remove an MCG entry from the hash chain */
		status = tavor_mcg_hash_list_remove(state, end_indx, prev_indx,
		    mcg_entry);
		if (status != DDI_SUCCESS) {
			mutex_exit(&state->ts_mcglock);
			TAVOR_TNF_EXIT(tavor_mcg_detach);
			return (status);
		}

	} else {
		/*
		 * Write the updated MCG entry back to the Tavor MCG table.
		 * If this succeeds, then we update the "shadow" list to
		 * reflect the change (i.e. decrement the "mcg_num_qps"),
		 * drop the lock, and return success.  Note:  In general,
		 * this operation shouldn't fail.  If it does, then it is an
		 * indication that something (probably in HW, but maybe in SW)
		 * has gone seriously wrong.
		 */
		status = tavor_write_mgm_cmd_post(state, mcg_entry, end_indx,
		    TAVOR_CMD_NOSLEEP_SPIN);
		if (status != TAVOR_CMD_SUCCESS) {
			mutex_exit(&state->ts_mcglock);
			TAVOR_WARNING(state, "failed to write MCG entry");
			cmn_err(CE_CONT, "Tavor: WRITE_MGM command failed: "
			    "%08x\n", status);
			TNF_PROBE_2(tavor_mcg_detach_write_mgm_cmd_fail,
			    TAVOR_TNF_ERROR, "", tnf_uint, cmd_status, status,
			    tnf_uint, indx, end_indx);
			TAVOR_TNF_EXIT(tavor_mcg_detach);
			return (ibc_get_ci_failure(0));
		}
		mcg->mcg_num_qps--;
	}

	mutex_exit(&state->ts_mcglock);
	TAVOR_TNF_EXIT(tavor_mcg_detach);
	return (DDI_SUCCESS);
}

/*
 * tavor_qp_mcg_refcnt_inc()
 *    Context: Can be called from interrupt or base context.
 */
static void
tavor_qp_mcg_refcnt_inc(tavor_qphdl_t qp)
{
	/* Increment the QP's MCG reference count */
	mutex_enter(&qp->qp_lock);
	qp->qp_mcg_refcnt++;
	TNF_PROBE_1_DEBUG(tavor_qp_mcg_refcnt_inc, TAVOR_TNF_TRACE, "",
	    tnf_uint, refcnt, qp->qp_mcg_refcnt);
	mutex_exit(&qp->qp_lock);
}


/*
 * tavor_qp_mcg_refcnt_dec()
 *    Context: Can be called from interrupt or base context.
 */
static void
tavor_qp_mcg_refcnt_dec(tavor_qphdl_t qp)
{
	/* Decrement the QP's MCG reference count */
	mutex_enter(&qp->qp_lock);
	qp->qp_mcg_refcnt--;
	TNF_PROBE_1_DEBUG(tavor_qp_mcg_refcnt_dec, TAVOR_TNF_TRACE, "",
	    tnf_uint, refcnt, qp->qp_mcg_refcnt);
	mutex_exit(&qp->qp_lock);
}


/*
 * tavor_mcg_qplist_add()
 *    Context: Can be called from interrupt or base context.
 */
static int
tavor_mcg_qplist_add(tavor_state_t *state, tavor_mcghdl_t mcg,
    tavor_hw_mcg_qp_list_t *mcg_qplist, tavor_qphdl_t qp,
    uint_t *qp_found)
{
	uint_t		qplist_indx;

	TAVOR_TNF_ENTER(tavor_mcg_qplist_add);

	ASSERT(MUTEX_HELD(&state->ts_mcglock));

	qplist_indx = mcg->mcg_num_qps;

	/*
	 * Determine if we have exceeded the maximum number of QP per
	 * multicast group.  If we have, then return an error
	 */
	if (qplist_indx >= state->ts_cfg_profile->cp_num_qp_per_mcg) {
		TNF_PROBE_0(tavor_mcg_qplist_add_too_many_qps,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_mcg_qplist_add);
		return (IBT_HCA_MCG_QP_EXCEEDED);
	}

	/*
	 * Determine if the QP is already attached to this MCG table.  If it
	 * is, then we break out and treat this operation as a NO-OP
	 */
	for (qplist_indx = 0; qplist_indx < mcg->mcg_num_qps;
	    qplist_indx++) {
		if (mcg_qplist[qplist_indx].qpn == qp->qp_qpnum) {
			break;
		}
	}

	/*
	 * If the QP was already on the list, set 'qp_found' to TRUE.  We still
	 * return SUCCESS in this case, but the qplist will not have been
	 * updated because the QP was already on the list.
	 */
	if (qplist_indx < mcg->mcg_num_qps) {
		*qp_found = 1;
	} else {
		/*
		 * Otherwise, append the new QP number to the end of the
		 * current QP list.  Note: We will increment the "mcg_num_qps"
		 * field on the "shadow" MCG list entry later (after we know
		 * that all necessary Tavor firmware accesses have been
		 * successful).
		 *
		 * Set 'qp_found' to 0 so we know the QP was added on to the
		 * list for sure.
		 */
		mcg_qplist[qplist_indx].q   = TAVOR_MCG_QPN_VALID;
		mcg_qplist[qplist_indx].qpn = qp->qp_qpnum;
		*qp_found = 0;
	}

	TAVOR_TNF_EXIT(tavor_mcg_qplist_add);
	return (DDI_SUCCESS);
}



/*
 * tavor_mcg_qplist_remove()
 *    Context: Can be called from interrupt or base context.
 */
static int
tavor_mcg_qplist_remove(tavor_mcghdl_t mcg, tavor_hw_mcg_qp_list_t *mcg_qplist,
    tavor_qphdl_t qp)
{
	uint_t		i, qplist_indx;

	TAVOR_TNF_ENTER(tavor_mcg_qplist_remove);

	/*
	 * Search the MCG QP list for a matching QPN.  When
	 * it's found, we swap the last entry with the current
	 * one, set the last entry to zero, decrement the last
	 * entry, and return.  If it's not found, then it's
	 * and error.
	 */
	qplist_indx = mcg->mcg_num_qps;
	for (i = 0; i < qplist_indx; i++) {
		if (mcg_qplist[i].qpn == qp->qp_qpnum) {
			mcg_qplist[i] = mcg_qplist[qplist_indx - 1];
			mcg_qplist[qplist_indx - 1].q = TAVOR_MCG_QPN_INVALID;
			mcg_qplist[qplist_indx - 1].qpn = 0;

			TAVOR_TNF_EXIT(tavor_mcg_qplist_remove);
			return (DDI_SUCCESS);
		}
	}

	TNF_PROBE_0(tavor_mcg_qplist_remove_invqphdl_fail, TAVOR_TNF_ERROR, "");
	TAVOR_TNF_EXIT(tavor_mcg_qplist_remove);
	return (IBT_QP_HDL_INVALID);
}


/*
 * tavor_mcg_walk_mgid_hash()
 *    Context: Can be called from interrupt or base context.
 */
static uint_t
tavor_mcg_walk_mgid_hash(tavor_state_t *state, uint64_t start_indx,
    ib_gid_t mgid, uint_t *p_indx)
{
	tavor_mcghdl_t	curr_mcghdl;
	uint_t		curr_indx, prev_indx;

	TAVOR_TNF_ENTER(tavor_mcg_walk_mgid_hash);

	ASSERT(MUTEX_HELD(&state->ts_mcglock));

	/* Start at the head of the hash chain */
	curr_indx   = start_indx;
	prev_indx   = curr_indx;
	curr_mcghdl = &state->ts_mcghdl[curr_indx];

	/* If the first entry in the chain has MGID == 0, then stop */
	if ((curr_mcghdl->mcg_mgid_h == 0) &&
	    (curr_mcghdl->mcg_mgid_l == 0)) {
		goto end_mgid_hash_walk;
	}

	/* If the first entry in the chain matches the MGID, then stop */
	if ((curr_mcghdl->mcg_mgid_h == mgid.gid_prefix) &&
	    (curr_mcghdl->mcg_mgid_l == mgid.gid_guid)) {
		goto end_mgid_hash_walk;
	}

	/* Otherwise, walk the hash chain looking for a match */
	while (curr_mcghdl->mcg_next_indx != 0) {
		prev_indx = curr_indx;
		curr_indx = curr_mcghdl->mcg_next_indx;
		curr_mcghdl = &state->ts_mcghdl[curr_indx];

		if ((curr_mcghdl->mcg_mgid_h == mgid.gid_prefix) &&
		    (curr_mcghdl->mcg_mgid_l == mgid.gid_guid)) {
			break;
		}
	}

end_mgid_hash_walk:
	/*
	 * If necessary, return the index of the previous entry too.  This
	 * is primarily used for detaching a QP from a multicast group.  It
	 * may be necessary, in that case, to delete an MCG entry from the
	 * hash chain and having the index of the previous entry is helpful.
	 */
	if (p_indx != NULL) {
		*p_indx = prev_indx;
	}
	TAVOR_TNF_EXIT(tavor_mcg_walk_mgid_hash);
	return (curr_indx);
}


/*
 * tavor_mcg_setup_new_hdr()
 *    Context: Can be called from interrupt or base context.
 */
static void
tavor_mcg_setup_new_hdr(tavor_mcghdl_t mcg, tavor_hw_mcg_t *mcg_hdr,
    ib_gid_t mgid, tavor_rsrc_t *mcg_rsrc)
{
	TAVOR_TNF_ENTER(tavor_mcg_setup_new_hdr);

	/*
	 * Fill in the fields of the "shadow" entry used by software
	 * to track MCG hardware entry
	 */
	mcg->mcg_mgid_h	   = mgid.gid_prefix;
	mcg->mcg_mgid_l	   = mgid.gid_guid;
	mcg->mcg_rsrcp	   = mcg_rsrc;
	mcg->mcg_next_indx = 0;
	mcg->mcg_num_qps   = 0;

	/*
	 * Fill the header fields of the MCG entry (in the temporary copy)
	 */
	mcg_hdr->mgid_h		= mgid.gid_prefix;
	mcg_hdr->mgid_l		= mgid.gid_guid;
	mcg_hdr->next_gid_indx	= 0;

	TAVOR_TNF_EXIT(tavor_mcg_setup_new_hdr);
}


/*
 * tavor_mcg_hash_list_remove()
 *    Context: Can be called only from user or kernel context.
 */
static int
tavor_mcg_hash_list_remove(tavor_state_t *state, uint_t curr_indx,
    uint_t prev_indx, tavor_hw_mcg_t *mcg_entry)
{
	tavor_mcghdl_t		curr_mcg, prev_mcg, next_mcg;
	uint_t			next_indx;
	int			status;

	/* Get the pointer to "shadow" list for current entry */
	curr_mcg = &state->ts_mcghdl[curr_indx];

	/*
	 * If this is the first entry on a hash chain, then attempt to replace
	 * the entry with the next entry on the chain.  If there are no
	 * subsequent entries on the chain, then this is the only entry and
	 * should be invalidated.
	 */
	if (curr_indx == prev_indx) {

		/*
		 * If this is the only entry on the chain, then invalidate it.
		 * Note:  Invalidating an MCG entry means writing all zeros
		 * to the entry.  This is only necessary for those MCG
		 * entries that are the "head" entries of the individual hash
		 * chains.  Regardless of whether this operation returns
		 * success or failure, return that result to the caller.
		 */
		next_indx = curr_mcg->mcg_next_indx;
		if (next_indx == 0) {
			status = tavor_mcg_entry_invalidate(state, mcg_entry,
			    curr_indx);
			bzero(curr_mcg, sizeof (struct tavor_sw_mcg_list_s));
			TAVOR_TNF_EXIT(tavor_mcg_hash_list_remove);
			return (status);
		}

		/*
		 * Otherwise, this is just the first entry on the chain, so
		 * grab the next one
		 */
		next_mcg = &state->ts_mcghdl[next_indx];

		/*
		 * Read the next MCG entry into the temporary MCG.  Note:
		 * In general, this operation shouldn't fail.  If it does,
		 * then it is an indication that something (probably in HW,
		 * but maybe in SW) has gone seriously wrong.
		 */
		status = tavor_read_mgm_cmd_post(state, mcg_entry, next_indx,
		    TAVOR_CMD_NOSLEEP_SPIN);
		if (status != TAVOR_CMD_SUCCESS) {
			TAVOR_WARNING(state, "failed to read MCG entry");
			cmn_err(CE_CONT, "Tavor: READ_MGM command failed: "
			    "%08x\n", status);
			TNF_PROBE_2(tavor_mcg_hash_list_rem_read_mgm_cmd_fail,
			    TAVOR_TNF_ERROR, "", tnf_uint, cmd_status, status,
			    tnf_uint, indx, next_indx);
			TAVOR_TNF_EXIT(tavor_mcg_hash_list_remove);
			return (ibc_get_ci_failure(0));
		}

		/*
		 * Copy/Write the temporary MCG back to the hardware MCG list
		 * using the current index.  This essentially removes the
		 * current MCG entry from the list by writing over it with
		 * the next one.  If this is successful, then we can do the
		 * same operation for the "shadow" list.  And we can also
		 * free up the Tavor MCG entry resource that was associated
		 * with the (old) next entry.  Note:  In general, this
		 * operation shouldn't fail.  If it does, then it is an
		 * indication that something (probably in HW, but maybe in SW)
		 * has gone seriously wrong.
		 */
		status = tavor_write_mgm_cmd_post(state, mcg_entry, curr_indx,
		    TAVOR_CMD_NOSLEEP_SPIN);
		if (status != TAVOR_CMD_SUCCESS) {
			TAVOR_WARNING(state, "failed to write MCG entry");
			cmn_err(CE_CONT, "Tavor: WRITE_MGM command failed: "
			    "%08x\n", status);
			TNF_PROBE_2(tavor_mcg_hash_list_rem_write_mgm_cmd_fail,
			    TAVOR_TNF_ERROR, "", tnf_uint, cmd_status, status,
			    tnf_uint, indx, curr_indx);
			TAVOR_TNF_EXIT(tavor_mcg_hash_list_remove);
			return (ibc_get_ci_failure(0));
		}

		/*
		 * Copy all the software tracking information from the next
		 * entry on the "shadow" MCG list into the current entry on
		 * the list.  Then invalidate (zero out) the other "shadow"
		 * list entry.
		 */
		bcopy(next_mcg, curr_mcg, sizeof (struct tavor_sw_mcg_list_s));
		bzero(next_mcg, sizeof (struct tavor_sw_mcg_list_s));

		/*
		 * Free up the Tavor MCG entry resource used by the "next"
		 * MCG entry.  That resource is no longer needed by any
		 * MCG entry which is first on a hash chain (like the "next"
		 * entry has just become).
		 */
		tavor_rsrc_free(state, &curr_mcg->mcg_rsrcp);

		TAVOR_TNF_EXIT(tavor_mcg_hash_list_remove);
		return (DDI_SUCCESS);
	}

	/*
	 * Else if this is the last entry on the hash chain (or a middle
	 * entry, then we update the previous entry's "next_gid_index" field
	 * to make it point instead to the next entry on the chain.  By
	 * skipping over the removed entry in this way, we can then free up
	 * any resources associated with the current entry.  Note:  We don't
	 * need to invalidate the "skipped over" hardware entry because it
	 * will no be longer connected to any hash chains, and if/when it is
	 * finally re-used, it will be written with entirely new values.
	 */

	/*
	 * Read the next MCG entry into the temporary MCG.  Note:  In general,
	 * this operation shouldn't fail.  If it does, then it is an
	 * indication that something (probably in HW, but maybe in SW) has
	 * gone seriously wrong.
	 */
	status = tavor_read_mgm_cmd_post(state, mcg_entry, prev_indx,
	    TAVOR_CMD_NOSLEEP_SPIN);
	if (status != TAVOR_CMD_SUCCESS) {
		TAVOR_WARNING(state, "failed to read MCG entry");
		cmn_err(CE_CONT, "Tavor: READ_MGM command failed: %08x\n",
		    status);
		TNF_PROBE_2(tavor_mcg_hash_list_rem_read_mgm_cmd_fail,
		    TAVOR_TNF_ERROR, "", tnf_uint, cmd_status, status,
		    tnf_uint, indx, prev_indx);
		TAVOR_TNF_EXIT(tavor_mcg_hash_list_remove);
		return (ibc_get_ci_failure(0));
	}

	/*
	 * Finally, we update the "next_gid_indx" field in the temporary MCG
	 * and attempt to write the entry back into the Tavor MCG table.  If
	 * this succeeds, then we update the "shadow" list to reflect the
	 * change, free up the Tavor MCG entry resource that was associated
	 * with the current entry, and return success.  Note:  In general,
	 * this operation shouldn't fail.  If it does, then it is an indication
	 * that something (probably in HW, but maybe in SW) has gone seriously
	 * wrong.
	 */
	mcg_entry->next_gid_indx = curr_mcg->mcg_next_indx;
	status = tavor_write_mgm_cmd_post(state, mcg_entry, prev_indx,
	    TAVOR_CMD_NOSLEEP_SPIN);
	if (status != TAVOR_CMD_SUCCESS) {
		TAVOR_WARNING(state, "failed to write MCG entry");
		cmn_err(CE_CONT, "Tavor: WRITE_MGM command failed: %08x\n",
		    status);
		TNF_PROBE_2(tavor_mcg_hash_list_rem_write_mgm_cmd_fail,
		    TAVOR_TNF_ERROR, "", tnf_uint, cmd_status, status,
		    tnf_uint, indx, prev_indx);
		TAVOR_TNF_EXIT(tavor_mcg_hash_list_remove);
		return (ibc_get_ci_failure(0));
	}

	/*
	 * Get the pointer to the "shadow" MCG list entry for the previous
	 * MCG.  Update its "mcg_next_indx" to point to the next entry
	 * the one after the current entry. Note:  This next index may be
	 * zero, indicating the end of the list.
	 */
	prev_mcg = &state->ts_mcghdl[prev_indx];
	prev_mcg->mcg_next_indx = curr_mcg->mcg_next_indx;

	/*
	 * Free up the Tavor MCG entry resource used by the current entry.
	 * This resource is no longer needed because the chain now skips over
	 * the current entry.  Then invalidate (zero out) the current "shadow"
	 * list entry.
	 */
	tavor_rsrc_free(state, &curr_mcg->mcg_rsrcp);
	bzero(curr_mcg, sizeof (struct tavor_sw_mcg_list_s));

	TAVOR_TNF_EXIT(tavor_mcg_hash_list_remove);
	return (DDI_SUCCESS);
}


/*
 * tavor_mcg_entry_invalidate()
 *    Context: Can be called only from user or kernel context.
 */
static int
tavor_mcg_entry_invalidate(tavor_state_t *state, tavor_hw_mcg_t *mcg_entry,
    uint_t indx)
{
	int		status;

	TAVOR_TNF_ENTER(tavor_mcg_entry_invalidate);

	/*
	 * Invalidate the hardware MCG entry by zeroing out this temporary
	 * MCG and writing it the the hardware.  Note: In general, this
	 * operation shouldn't fail.  If it does, then it is an indication
	 * that something (probably in HW, but maybe in SW) has gone seriously
	 * wrong.
	 */
	bzero(mcg_entry, TAVOR_MCGMEM_SZ(state));
	status = tavor_write_mgm_cmd_post(state, mcg_entry, indx,
	    TAVOR_CMD_NOSLEEP_SPIN);
	if (status != TAVOR_CMD_SUCCESS) {
		TAVOR_WARNING(state, "failed to write MCG entry");
		cmn_err(CE_CONT, "Tavor: WRITE_MGM command failed: %08x\n",
		    status);
		TNF_PROBE_2(tavor_mcg_entry_invalidate_write_mgm_cmd_fail,
		    TAVOR_TNF_ERROR, "", tnf_uint, cmd_status, status,
		    tnf_uint, indx, indx);
		TAVOR_TNF_EXIT(tavor_mcg_entry_invalidate);
		return (ibc_get_ci_failure(0));
	}

	TAVOR_TNF_EXIT(tavor_mcg_entry_invalidate);
	return (DDI_SUCCESS);
}


/*
 * tavor_mgid_is_valid()
 *    Context: Can be called from interrupt or base context.
 */
static int
tavor_mgid_is_valid(ib_gid_t gid)
{
	uint_t		topbits, flags, scope;

	TAVOR_TNF_ENTER(tavor_mgid_is_valid);

	/*
	 * According to IBA 1.1 specification (section 4.1.1) a valid
	 * "multicast GID" must have its top eight bits set to all ones
	 */
	topbits = (gid.gid_prefix >> TAVOR_MCG_TOPBITS_SHIFT) &
	    TAVOR_MCG_TOPBITS_MASK;
	if (topbits != TAVOR_MCG_TOPBITS) {
		TNF_PROBE_0(tavor_mgid_is_valid_invbits_fail, TAVOR_TNF_ERROR,
		    "");
		TAVOR_TNF_EXIT(tavor_mgid_is_valid);
		return (0);
	}

	/*
	 * The next 4 bits are the "flag" bits.  These are valid only
	 * if they are "0" (which correspond to permanently assigned/
	 * "well-known" multicast GIDs) or "1" (for so-called "transient"
	 * multicast GIDs).  All other values are reserved.
	 */
	flags = (gid.gid_prefix >> TAVOR_MCG_FLAGS_SHIFT) &
	    TAVOR_MCG_FLAGS_MASK;
	if (!((flags == TAVOR_MCG_FLAGS_PERM) ||
	    (flags == TAVOR_MCG_FLAGS_NONPERM))) {
		TNF_PROBE_1(tavor_mgid_is_valid_invflags_fail, TAVOR_TNF_ERROR,
		    "", tnf_uint, flags, flags);
		TAVOR_TNF_EXIT(tavor_mgid_is_valid);
		return (0);
	}

	/*
	 * The next 4 bits are the "scope" bits.  These are valid only
	 * if they are "2" (Link-local), "5" (Site-local), "8"
	 * (Organization-local) or "E" (Global).  All other values
	 * are reserved (or currently unassigned).
	 */
	scope = (gid.gid_prefix >> TAVOR_MCG_SCOPE_SHIFT) &
	    TAVOR_MCG_SCOPE_MASK;
	if (!((scope == TAVOR_MCG_SCOPE_LINKLOC) ||
	    (scope == TAVOR_MCG_SCOPE_SITELOC)	 ||
	    (scope == TAVOR_MCG_SCOPE_ORGLOC)	 ||
	    (scope == TAVOR_MCG_SCOPE_GLOBAL))) {
		TNF_PROBE_1(tavor_mgid_is_valid_invscope_fail, TAVOR_TNF_ERROR,
		    "", tnf_uint, scope, scope);
		TAVOR_TNF_EXIT(tavor_mgid_is_valid);
		return (0);
	}

	/*
	 * If it passes all of the above checks, then we will consider it
	 * a valid multicast GID.
	 */
	TAVOR_TNF_EXIT(tavor_mgid_is_valid);
	return (1);
}


/*
 * tavor_mlid_is_valid()
 *    Context: Can be called from interrupt or base context.
 */
static int
tavor_mlid_is_valid(ib_lid_t lid)
{
	TAVOR_TNF_ENTER(tavor_mlid_is_valid);

	/*
	 * According to IBA 1.1 specification (section 4.1.1) a valid
	 * "multicast DLID" must be between 0xC000 and 0xFFFE.
	 */
	if ((lid < IB_LID_MC_FIRST) || (lid > IB_LID_MC_LAST)) {
		TNF_PROBE_1(tavor_mlid_is_valid_invdlid_fail, TAVOR_TNF_ERROR,
		    "", tnf_uint, mlid, lid);
		TAVOR_TNF_EXIT(tavor_mlid_is_valid);
		return (0);
	}

	TAVOR_TNF_EXIT(tavor_mlid_is_valid);
	return (1);
}


/*
 * tavor_pd_alloc()
 *    Context: Can be called only from user or kernel context.
 */
int
tavor_pd_alloc(tavor_state_t *state, tavor_pdhdl_t *pdhdl, uint_t sleepflag)
{
	tavor_rsrc_t	*rsrc;
	tavor_pdhdl_t	pd;
	int		status;

	TAVOR_TNF_ENTER(tavor_pd_alloc);

	/*
	 * Allocate the software structure for tracking the protection domain
	 * (i.e. the Tavor Protection Domain handle).  By default each PD
	 * structure will have a unique PD number assigned to it.  All that
	 * is necessary is for software to initialize the PD reference count
	 * (to zero) and return success.
	 */
	status = tavor_rsrc_alloc(state, TAVOR_PDHDL, 1, sleepflag, &rsrc);
	if (status != DDI_SUCCESS) {
		TNF_PROBE_0(tavor_pd_alloc_rsrcalloc_fail, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_pd_alloc);
		return (IBT_INSUFF_RESOURCE);
	}
	pd = (tavor_pdhdl_t)rsrc->tr_addr;
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*pd))

	pd->pd_refcnt = 0;
	*pdhdl = pd;

	TAVOR_TNF_EXIT(tavor_pd_alloc);
	return (DDI_SUCCESS);
}


/*
 * tavor_pd_free()
 *    Context: Can be called only from user or kernel context.
 */
int
tavor_pd_free(tavor_state_t *state, tavor_pdhdl_t *pdhdl)
{
	tavor_rsrc_t	*rsrc;
	tavor_pdhdl_t	pd;

	TAVOR_TNF_ENTER(tavor_pd_free);

	/*
	 * Pull all the necessary information from the Tavor Protection Domain
	 * handle.  This is necessary here because the resource for the
	 * PD is going to be freed up as part of this operation.
	 */
	pd   = *pdhdl;
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*pd))
	rsrc = pd->pd_rsrcp;

	/*
	 * Check the PD reference count.  If the reference count is non-zero,
	 * then it means that this protection domain is still referenced by
	 * some memory region, queue pair, address handle, or other IB object
	 * If it is non-zero, then return an error.  Otherwise, free the
	 * Tavor resource and return success.
	 */
	if (pd->pd_refcnt != 0) {
		TNF_PROBE_1(tavor_pd_free_refcnt_fail, TAVOR_TNF_ERROR, "",
		    tnf_int, refcnt, pd->pd_refcnt);
		TAVOR_TNF_EXIT(tavor_pd_free);
		return (IBT_PD_IN_USE);
	}

	/* Free the Tavor Protection Domain handle */
	tavor_rsrc_free(state, &rsrc);

	/* Set the pdhdl pointer to NULL and return success */
	*pdhdl = (tavor_pdhdl_t)NULL;

	TAVOR_TNF_EXIT(tavor_pd_free);
	return (DDI_SUCCESS);
}


/*
 * tavor_pd_refcnt_inc()
 *    Context: Can be called from interrupt or base context.
 */
void
tavor_pd_refcnt_inc(tavor_pdhdl_t pd)
{
	/* Increment the protection domain's reference count */
	mutex_enter(&pd->pd_lock);
	TNF_PROBE_1_DEBUG(tavor_pd_refcnt_inc, TAVOR_TNF_TRACE, "",
	    tnf_uint, refcnt, pd->pd_refcnt);
	pd->pd_refcnt++;
	mutex_exit(&pd->pd_lock);

}


/*
 * tavor_pd_refcnt_dec()
 *    Context: Can be called from interrupt or base context.
 */
void
tavor_pd_refcnt_dec(tavor_pdhdl_t pd)
{
	/* Decrement the protection domain's reference count */
	mutex_enter(&pd->pd_lock);
	pd->pd_refcnt--;
	TNF_PROBE_1_DEBUG(tavor_pd_refcnt_dec, TAVOR_TNF_TRACE, "",
	    tnf_uint, refcnt, pd->pd_refcnt);
	mutex_exit(&pd->pd_lock);

}


/*
 * tavor_port_query()
 *    Context: Can be called only from user or kernel context.
 */
int
tavor_port_query(tavor_state_t *state, uint_t port, ibt_hca_portinfo_t *pi)
{
	sm_portinfo_t		portinfo;
	sm_guidinfo_t		guidinfo;
	sm_pkey_table_t		pkeytable;
	ib_gid_t		*sgid;
	uint_t			sgid_max, pkey_max, tbl_size;
	int			i, j, indx, status;

	TAVOR_TNF_ENTER(tavor_port_query);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*pi))

	/* Validate that specified port number is legal */
	if (!tavor_portnum_is_valid(state, port)) {
		TNF_PROBE_1(tavor_port_query_inv_portnum_fail,
		    TAVOR_TNF_ERROR, "", tnf_uint, port, port);
		TAVOR_TNF_EXIT(tavor_port_query);
		return (IBT_HCA_PORT_INVALID);
	}

	/*
	 * We use the Tavor MAD_IFC command to post a GetPortInfo MAD
	 * to the firmware (for the specified port number).  This returns
	 * a full PortInfo MAD (in "portinfo") which we subsequently
	 * parse to fill in the "ibt_hca_portinfo_t" structure returned
	 * to the IBTF.
	 */
	status = tavor_getportinfo_cmd_post(state, port,
	    TAVOR_SLEEPFLAG_FOR_CONTEXT(), &portinfo);
	if (status != TAVOR_CMD_SUCCESS) {
		cmn_err(CE_CONT, "Tavor: GetPortInfo (port %02d) command "
		    "failed: %08x\n", port, status);
		TNF_PROBE_1(tavor_port_query_getportinfo_cmd_fail,
		    TAVOR_TNF_ERROR, "", tnf_uint, cmd_status, status);
		TAVOR_TNF_EXIT(tavor_port_query);
		return (ibc_get_ci_failure(0));
	}

	/*
	 * Parse the PortInfo MAD and fill in the IBTF structure
	 */
	pi->p_base_lid		= portinfo.LID;
	pi->p_qkey_violations	= portinfo.Q_KeyViolations;
	pi->p_pkey_violations	= portinfo.P_KeyViolations;
	pi->p_sm_sl		= portinfo.MasterSMSL;
	pi->p_sm_lid		= portinfo.MasterSMLID;
	pi->p_linkstate		= portinfo.PortState;
	pi->p_port_num		= portinfo.LocalPortNum;
	pi->p_mtu		= portinfo.MTUCap;
	pi->p_lmc		= portinfo.LMC;
	pi->p_max_vl		= portinfo.VLCap;
	pi->p_subnet_timeout	= portinfo.SubnetTimeOut;
	pi->p_msg_sz		= ((uint32_t)1 << TAVOR_QP_LOG_MAX_MSGSZ);
	tbl_size = state->ts_cfg_profile->cp_log_max_gidtbl;
	pi->p_sgid_tbl_sz	= (1 << tbl_size);
	tbl_size = state->ts_cfg_profile->cp_log_max_pkeytbl;
	pi->p_pkey_tbl_sz	= (1 << tbl_size);

	/*
	 * Convert InfiniBand-defined port capability flags to the format
	 * specified by the IBTF
	 */
	if (portinfo.CapabilityMask & SM_CAP_MASK_IS_SM)
		pi->p_capabilities |= IBT_PORT_CAP_SM;
	if (portinfo.CapabilityMask & SM_CAP_MASK_IS_SM_DISABLED)
		pi->p_capabilities |= IBT_PORT_CAP_SM_DISABLED;
	if (portinfo.CapabilityMask & SM_CAP_MASK_IS_SNMP_SUPPD)
		pi->p_capabilities |= IBT_PORT_CAP_SNMP_TUNNEL;
	if (portinfo.CapabilityMask & SM_CAP_MASK_IS_DM_SUPPD)
		pi->p_capabilities |= IBT_PORT_CAP_DM;
	if (portinfo.CapabilityMask & SM_CAP_MASK_IS_VM_SUPPD)
		pi->p_capabilities |= IBT_PORT_CAP_VENDOR;

	/*
	 * Fill in the SGID table.  Since the only access to the Tavor
	 * GID tables is through the firmware's MAD_IFC interface, we
	 * post as many GetGUIDInfo MADs as necessary to read in the entire
	 * contents of the SGID table (for the specified port).  Note:  The
	 * GetGUIDInfo command only gets eight GUIDs per operation.  These
	 * GUIDs are then appended to the GID prefix for the port (from the
	 * GetPortInfo above) to form the entire SGID table.
	 */
	for (i = 0; i < pi->p_sgid_tbl_sz; i += 8) {
		status = tavor_getguidinfo_cmd_post(state, port, i >> 3,
		    TAVOR_SLEEPFLAG_FOR_CONTEXT(), &guidinfo);
		if (status != TAVOR_CMD_SUCCESS) {
			cmn_err(CE_CONT, "Tavor: GetGUIDInfo (port %02d) "
			    "command failed: %08x\n", port, status);
			TNF_PROBE_1(tavor_port_query_getguidinfo_cmd_fail,
			    TAVOR_TNF_ERROR, "", tnf_uint, cmd_status, status);
			TAVOR_TNF_EXIT(tavor_port_query);
			return (ibc_get_ci_failure(0));
		}

		/* Figure out how many of the entries are valid */
		sgid_max = min((pi->p_sgid_tbl_sz - i), 8);
		for (j = 0; j < sgid_max; j++) {
			indx = (i + j);
			sgid = &pi->p_sgid_tbl[indx];
			_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*sgid))
			sgid->gid_prefix = portinfo.GidPrefix;
			sgid->gid_guid	 = guidinfo.GUIDBlocks[j];
		}
	}

	/*
	 * Fill in the PKey table.  Just as for the GID tables above, the
	 * only access to the Tavor PKey tables is through the firmware's
	 * MAD_IFC interface.  We post as many GetPKeyTable MADs as necessary
	 * to read in the entire contents of the PKey table (for the specified
	 * port).  Note:  The GetPKeyTable command only gets 32 PKeys per
	 * operation.
	 */
	for (i = 0; i < pi->p_pkey_tbl_sz; i += 32) {
		status = tavor_getpkeytable_cmd_post(state, port, i,
		    TAVOR_SLEEPFLAG_FOR_CONTEXT(), &pkeytable);
		if (status != TAVOR_CMD_SUCCESS) {
			cmn_err(CE_CONT, "Tavor: GetPKeyTable (port %02d) "
			    "command failed: %08x\n", port, status);
			TNF_PROBE_1(tavor_port_query_getpkeytable_cmd_fail,
			    TAVOR_TNF_ERROR, "", tnf_uint, cmd_status, status);
			TAVOR_TNF_EXIT(tavor_port_query);
			return (ibc_get_ci_failure(0));
		}

		/* Figure out how many of the entries are valid */
		pkey_max = min((pi->p_pkey_tbl_sz - i), 32);
		for (j = 0; j < pkey_max; j++) {
			indx = (i + j);
			pi->p_pkey_tbl[indx] = pkeytable.P_KeyTableBlocks[j];
		}
	}

	TAVOR_TNF_EXIT(tavor_port_query);
	return (DDI_SUCCESS);
}


/*
 * tavor_port_modify()
 *    Context: Can be called only from user or kernel context.
 */
/* ARGSUSED */
int
tavor_port_modify(tavor_state_t *state, uint8_t port,
    ibt_port_modify_flags_t flags, uint8_t init_type)
{
	sm_portinfo_t	portinfo;
	uint32_t	capmask, reset_qkey;
	int		status;

	TAVOR_TNF_ENTER(tavor_port_modify);

	/*
	 * Return an error if either of the unsupported flags are set
	 */
	if ((flags & IBT_PORT_SHUTDOWN) ||
	    (flags & IBT_PORT_SET_INIT_TYPE)) {
		TNF_PROBE_1(tavor_port_modify_inv_flags_fail,
		    TAVOR_TNF_ERROR, "", tnf_uint, flags, flags);
		TAVOR_TNF_EXIT(tavor_port_modify);
		return (IBT_NOT_SUPPORTED);
	}

	/*
	 * Determine whether we are trying to reset the QKey counter
	 */
	reset_qkey = (flags & IBT_PORT_RESET_QKEY) ? 1 : 0;

	/* Validate that specified port number is legal */
	if (!tavor_portnum_is_valid(state, port)) {
		TNF_PROBE_1(tavor_port_modify_inv_portnum_fail,
		    TAVOR_TNF_ERROR, "", tnf_uint, port, port);
		TAVOR_TNF_EXIT(tavor_port_modify);
		return (IBT_HCA_PORT_INVALID);
	}

	/*
	 * Use the Tavor MAD_IFC command to post a GetPortInfo MAD to the
	 * firmware (for the specified port number).  This returns a full
	 * PortInfo MAD (in "portinfo") from which we pull the current
	 * capability mask.  We then modify the capability mask as directed
	 * by the "pmod_flags" field, and write the updated capability mask
	 * using the Tavor SET_IB command (below).
	 */
	status = tavor_getportinfo_cmd_post(state, port,
	    TAVOR_SLEEPFLAG_FOR_CONTEXT(), &portinfo);
	if (status != TAVOR_CMD_SUCCESS) {
		TNF_PROBE_1(tavor_port_modify_getportinfo_cmd_fail,
		    TAVOR_TNF_ERROR, "", tnf_uint, cmd_status, status);
		TAVOR_TNF_EXIT(tavor_port_modify);
		return (ibc_get_ci_failure(0));
	}

	/*
	 * Convert InfiniBand-defined port capability flags to the format
	 * specified by the IBTF.  Specifically, we modify the capability
	 * mask based on the specified values.
	 */
	capmask = portinfo.CapabilityMask;

	if (flags & IBT_PORT_RESET_SM)
		capmask &= ~SM_CAP_MASK_IS_SM;
	else if (flags & IBT_PORT_SET_SM)
		capmask |= SM_CAP_MASK_IS_SM;

	if (flags & IBT_PORT_RESET_SNMP)
		capmask &= ~SM_CAP_MASK_IS_SNMP_SUPPD;
	else if (flags & IBT_PORT_SET_SNMP)
		capmask |= SM_CAP_MASK_IS_SNMP_SUPPD;

	if (flags & IBT_PORT_RESET_DEVMGT)
		capmask &= ~SM_CAP_MASK_IS_DM_SUPPD;
	else if (flags & IBT_PORT_SET_DEVMGT)
		capmask |= SM_CAP_MASK_IS_DM_SUPPD;

	if (flags & IBT_PORT_RESET_VENDOR)
		capmask &= ~SM_CAP_MASK_IS_VM_SUPPD;
	else if (flags & IBT_PORT_SET_VENDOR)
		capmask |= SM_CAP_MASK_IS_VM_SUPPD;

	/*
	 * Use the Tavor SET_IB command to update the capability mask and
	 * (possibly) reset the QKey violation counter for the specified port.
	 * Note: In general, this operation shouldn't fail.  If it does, then
	 * it is an indication that something (probably in HW, but maybe in
	 * SW) has gone seriously wrong.
	 */
	status = tavor_set_ib_cmd_post(state, capmask, port, reset_qkey,
	    TAVOR_SLEEPFLAG_FOR_CONTEXT());
	if (status != TAVOR_CMD_SUCCESS) {
		TAVOR_WARNING(state, "failed to modify port capabilities");
		cmn_err(CE_CONT, "Tavor: SET_IB (port %02d) command failed: "
		    "%08x\n", port, status);
		TNF_PROBE_1(tavor_port_modify_set_ib_cmd_fail,
		    TAVOR_TNF_ERROR, "", tnf_uint, cmd_status, status);
		TAVOR_TNF_EXIT(tavor_port_modify);
		return (ibc_get_ci_failure(0));
	}

	TAVOR_TNF_EXIT(tavor_port_modify);
	return (DDI_SUCCESS);
}


/*
 * tavor_set_addr_path()
 *    Context: Can be called from interrupt or base context.
 *
 * Note: This routine is used for two purposes.  It is used to fill in the
 * Tavor UDAV fields, and it is used to fill in the address path information
 * for QPs.  Because the two Tavor structures are similar, common fields can
 * be filled in here.  Because they are slightly different, however, we pass
 * an additional flag to indicate which type is being filled.
 */
int
tavor_set_addr_path(tavor_state_t *state, ibt_adds_vect_t *av,
    tavor_hw_addr_path_t *path, uint_t type, tavor_qphdl_t qp)
{
	uint_t		gidtbl_sz;

	TAVOR_TNF_ENTER(tavor_set_addr_path);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*av))
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*path))

	path->ml_path	= av->av_src_path;
	path->rlid	= av->av_dlid;
	path->sl	= av->av_srvl;

	/* Port number only valid (in "av_port_num") if this is a UDAV */
	if (type == TAVOR_ADDRPATH_UDAV) {
		path->portnum = av->av_port_num;
	}

	/*
	 * Validate (and fill in) static rate.
	 *
	 * The stat_rate_sup is used to decide how to set the rate and
	 * if it is zero, the driver uses the old interface.
	 */
	if (state->ts_devlim.stat_rate_sup) {
		if (av->av_srate == IBT_SRATE_20) {
			path->max_stat_rate = 0; /* 4x@DDR injection rate */
		} else if (av->av_srate == IBT_SRATE_5) {
			path->max_stat_rate = 3; /* 1x@DDR injection rate */
		} else if (av->av_srate == IBT_SRATE_10) {
			path->max_stat_rate = 2; /* 4x@SDR injection rate */
		} else if (av->av_srate == IBT_SRATE_2) {
			path->max_stat_rate = 1; /* 1x@SDR injection rate */
		} else if (av->av_srate == IBT_SRATE_NOT_SPECIFIED) {
			path->max_stat_rate = 0; /* Max */
		} else {
			TNF_PROBE_1(tavor_set_addr_path_inv_srate_fail,
			    TAVOR_TNF_ERROR, "", tnf_uint, srate, av->av_srate);
			TAVOR_TNF_EXIT(tavor_set_addr_path);
			return (IBT_STATIC_RATE_INVALID);
		}
	} else {
		if (av->av_srate == IBT_SRATE_10) {
			path->max_stat_rate = 0; /* 4x@SDR injection rate */
		} else if (av->av_srate == IBT_SRATE_2) {
			path->max_stat_rate = 1; /* 1x@SDR injection rate */
		} else if (av->av_srate == IBT_SRATE_NOT_SPECIFIED) {
			path->max_stat_rate = 0; /* Max */
		} else {
			TNF_PROBE_1(tavor_set_addr_path_inv_srate_fail,
			    TAVOR_TNF_ERROR, "", tnf_uint, srate, av->av_srate);
			TAVOR_TNF_EXIT(tavor_set_addr_path);
			return (IBT_STATIC_RATE_INVALID);
		}
	}

	/*
	 * If this is a QP operation save asoft copy.
	 */
	if (qp) {
		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(qp->qp_save_srate))
		qp->qp_save_srate = av->av_srate;
	}

	/* If "grh" flag is set, then check for valid SGID index too */
	gidtbl_sz = (1 << state->ts_devlim.log_max_gid);
	if ((av->av_send_grh) && (av->av_sgid_ix > gidtbl_sz)) {
		TNF_PROBE_1(tavor_set_addr_path_inv_sgid_ix_fail,
		    TAVOR_TNF_ERROR, "", tnf_uint, sgid_ix, av->av_sgid_ix);
		TAVOR_TNF_EXIT(tavor_set_addr_path);
		return (IBT_SGID_INVALID);
	}

	/*
	 * Fill in all "global" values regardless of the value in the GRH
	 * flag.  Because "grh" is not set unless "av_send_grh" is set, the
	 * hardware will ignore the other "global" values as necessary.  Note:
	 * SW does this here to enable later query operations to return
	 * exactly the same params that were passed when the addr path was
	 * last written.
	 */
	path->grh = av->av_send_grh;
	if (type == TAVOR_ADDRPATH_QP) {
		path->mgid_index = av->av_sgid_ix;
	} else {
		/*
		 * For Tavor UDAV, the "mgid_index" field is the index into
		 * a combined table (not a per-port table). So some extra
		 * calculations are necessary.
		 */
		path->mgid_index = ((av->av_port_num - 1) * gidtbl_sz) +
		    av->av_sgid_ix;
	}
	path->flow_label = av->av_flow;
	path->tclass	 = av->av_tclass;
	path->hop_limit	 = av->av_hop;
	path->rgid_h	 = av->av_dgid.gid_prefix;

	/*
	 * According to Tavor PRM, the (31:0) part of rgid_l must be set to
	 * "0x2" if the 'grh' or 'g' bit is cleared.  It also says that we
	 * only need to do it for UDAV's.  So we enforce that here.
	 *
	 * NOTE: The entire 64 bits worth of GUID info is actually being
	 * preserved (for UDAVs) by the callers of this function
	 * (tavor_ah_alloc() and tavor_ah_modify()) and as long as the
	 * 'grh' bit is not set, the upper 32 bits (63:32) of rgid_l are
	 * "don't care".
	 */
	if ((path->grh) || (type == TAVOR_ADDRPATH_QP)) {
		path->rgid_l = av->av_dgid.gid_guid;
	} else {
		path->rgid_l = 0x2;
	}

	TAVOR_TNF_EXIT(tavor_set_addr_path);
	return (DDI_SUCCESS);
}


/*
 * tavor_get_addr_path()
 *    Context: Can be called from interrupt or base context.
 *
 * Note: Just like tavor_set_addr_path() above, this routine is used for two
 * purposes.  It is used to read in the Tavor UDAV fields, and it is used to
 * read in the address path information for QPs.  Because the two Tavor
 * structures are similar, common fields can be read in here.  But because
 * they are slightly different, we pass an additional flag to indicate which
 * type is being read.
 */
void
tavor_get_addr_path(tavor_state_t *state, tavor_hw_addr_path_t *path,
    ibt_adds_vect_t *av, uint_t type, tavor_qphdl_t qp)
{
	uint_t		gidtbl_sz;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*path))
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*av))

	av->av_src_path	= path->ml_path;
	av->av_port_num	= path->portnum;
	av->av_dlid	= path->rlid;
	av->av_srvl	= path->sl;

	/*
	 * Set "av_ipd" value from max_stat_rate.
	 */
	if (qp) {
		/*
		 * If a QP operation use the soft copy
		 */
		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(qp->qp_save_srate))
		av->av_srate = qp->qp_save_srate;
	} else {
		/*
		 * The stat_rate_sup is used to decide how the srate value is
		 * set and
		 * if it is zero, the driver uses the old interface.
		 */
		if (state->ts_devlim.stat_rate_sup) {
			if (path->max_stat_rate	== 0) {
				av->av_srate = IBT_SRATE_20; /* 4x@DDR rate */
			} else if (path->max_stat_rate	== 1) {
				av->av_srate = IBT_SRATE_2;  /* 1x@SDR rate */
			} else if (path->max_stat_rate	== 2) {
				av->av_srate = IBT_SRATE_10; /* 4x@SDR rate */
			} else if (path->max_stat_rate	== 3) {
				av->av_srate = IBT_SRATE_5;  /* 1xDDR rate */
			}
		} else {
			if (path->max_stat_rate	== 0) {
				av->av_srate = IBT_SRATE_10; /* 4x@SDR rate */
			} else if (path->max_stat_rate	== 1) {
				av->av_srate = IBT_SRATE_2;  /* 1x@SDR rate */
			}
		}
	}

	/*
	 * Extract all "global" values regardless of the value in the GRH
	 * flag.  Because "av_send_grh" is set only if "grh" is set, software
	 * knows to ignore the other "global" values as necessary.  Note: SW
	 * does it this way to enable these query operations to return exactly
	 * the same params that were passed when the addr path was last written.
	 */
	av->av_send_grh		= path->grh;
	if (type == TAVOR_ADDRPATH_QP) {
		av->av_sgid_ix  = path->mgid_index;
	} else {
		/*
		 * For Tavor UDAV, the "mgid_index" field is the index into
		 * a combined table (not a per-port table). So some extra
		 * calculations are necessary.
		 */
		gidtbl_sz = (1 << state->ts_devlim.log_max_gid);
		av->av_sgid_ix = path->mgid_index - ((av->av_port_num - 1) *
		    gidtbl_sz);
	}
	av->av_flow		= path->flow_label;
	av->av_tclass		= path->tclass;
	av->av_hop		= path->hop_limit;
	av->av_dgid.gid_prefix	= path->rgid_h;
	av->av_dgid.gid_guid	= path->rgid_l;
}


/*
 * tavor_portnum_is_valid()
 *    Context: Can be called from interrupt or base context.
 */
int
tavor_portnum_is_valid(tavor_state_t *state, uint_t portnum)
{
	uint_t	max_port;

	max_port = state->ts_cfg_profile->cp_num_ports;
	if ((portnum <= max_port) && (portnum != 0)) {
		return (1);
	} else {
		return (0);
	}
}


/*
 * tavor_pkeyindex_is_valid()
 *    Context: Can be called from interrupt or base context.
 */
int
tavor_pkeyindex_is_valid(tavor_state_t *state, uint_t pkeyindx)
{
	uint_t	max_pkeyindx;

	max_pkeyindx = 1 << state->ts_cfg_profile->cp_log_max_pkeytbl;
	if (pkeyindx < max_pkeyindx) {
		return (1);
	} else {
		return (0);
	}
}


/*
 * tavor_queue_alloc()
 *    Context: Can be called from interrupt or base context.
 */
int
tavor_queue_alloc(tavor_state_t *state, tavor_qalloc_info_t *qa_info,
    uint_t sleepflag)
{
	ddi_dma_attr_t		dma_attr;
	int			(*callback)(caddr_t);
	uint64_t		realsize, alloc_mask;
	uint_t			dma_xfer_mode, type;
	int			flag, status;

	TAVOR_TNF_ENTER(tavor_queue_alloc);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*qa_info))

	/* Set the callback flag appropriately */
	callback = (sleepflag == TAVOR_SLEEP) ? DDI_DMA_SLEEP :
	    DDI_DMA_DONTWAIT;

	/*
	 * Initialize many of the default DMA attributes.  Then set additional
	 * alignment restrictions as necessary for the queue memory.  Also
	 * respect the configured value for IOMMU bypass
	 */
	tavor_dma_attr_init(&dma_attr);
	dma_attr.dma_attr_align = qa_info->qa_bind_align;
	type = state->ts_cfg_profile->cp_iommu_bypass;
	if (type == TAVOR_BINDMEM_BYPASS) {
		dma_attr.dma_attr_flags = DDI_DMA_FORCE_PHYSICAL;
	}

	/* Allocate a DMA handle */
	status = ddi_dma_alloc_handle(state->ts_dip, &dma_attr, callback, NULL,
	    &qa_info->qa_dmahdl);
	if (status != DDI_SUCCESS) {
		TNF_PROBE_0(tavor_queue_alloc_dmahdl_fail, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_queue_alloc);
		return (DDI_FAILURE);
	}

	/*
	 * Determine the amount of memory to allocate, depending on the values
	 * in "qa_bind_align" and "qa_alloc_align".  The problem we are trying
	 * to solve here is that allocating a DMA handle with IOMMU bypass
	 * (DDI_DMA_FORCE_PHYSICAL) constrains us to only requesting alignments
	 * that are less than the page size.  Since we may need stricter
	 * alignments on the memory allocated by ddi_dma_mem_alloc() (e.g. in
	 * Tavor QP work queue memory allocation), we use the following method
	 * to calculate how much additional memory to request, and we enforce
	 * our own alignment on the allocated result.
	 */
	alloc_mask = qa_info->qa_alloc_align - 1;
	if (qa_info->qa_bind_align == qa_info->qa_alloc_align) {
		realsize = qa_info->qa_size;
	} else {
		realsize = qa_info->qa_size + alloc_mask;
	}

	/*
	 * If we are to allocate the queue from system memory, then use
	 * ddi_dma_mem_alloc() to find the space.  Otherwise, if we are to
	 * allocate the queue from locally-attached DDR memory, then use the
	 * vmem allocator to find the space.  In either case, return a pointer
	 * to the memory range allocated (including any necessary alignment
	 * adjustments), the "real" memory pointer, the "real" size, and a
	 * ddi_acc_handle_t to use when reading from/writing to the memory.
	 */
	if (qa_info->qa_location == TAVOR_QUEUE_LOCATION_NORMAL) {

		/*
		 * Determine whether to map STREAMING or CONSISTENT.  This is
		 * based on the value set in the configuration profile at
		 * attach time.
		 */
		dma_xfer_mode = state->ts_cfg_profile->cp_streaming_consistent;

		/* Allocate system memory for the queue */
		status = ddi_dma_mem_alloc(qa_info->qa_dmahdl, realsize,
		    &state->ts_reg_accattr, dma_xfer_mode, callback, NULL,
		    (caddr_t *)&qa_info->qa_buf_real,
		    (size_t *)&qa_info->qa_buf_realsz, &qa_info->qa_acchdl);
		if (status != DDI_SUCCESS) {
			ddi_dma_free_handle(&qa_info->qa_dmahdl);
			TNF_PROBE_0(tavor_queue_alloc_dma_memalloc_fail,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_queue_alloc);
			return (DDI_FAILURE);
		}

		/*
		 * Save temporary copy of the real pointer.  (This may be
		 * modified in the last step below).
		 */
		qa_info->qa_buf_aligned = qa_info->qa_buf_real;

	} else if (qa_info->qa_location == TAVOR_QUEUE_LOCATION_USERLAND) {

		/* Allocate userland mappable memory for the queue */
		flag = (sleepflag == TAVOR_SLEEP) ? DDI_UMEM_SLEEP :
		    DDI_UMEM_NOSLEEP;
		qa_info->qa_buf_real = ddi_umem_alloc(realsize, flag,
		    &qa_info->qa_umemcookie);
		if (qa_info->qa_buf_real == NULL) {
			ddi_dma_free_handle(&qa_info->qa_dmahdl);
			TNF_PROBE_0(tavor_queue_alloc_umem_fail,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_queue_alloc);
			return (DDI_FAILURE);
		}

		/*
		 * Save temporary copy of the real pointer.  (This may be
		 * modified in the last step below).
		 */
		qa_info->qa_buf_aligned = qa_info->qa_buf_real;

	} else {  /* TAVOR_QUEUE_LOCATION_INDDR */

		/* Allocate DDR memory for the queue */
		flag = (sleepflag == TAVOR_SLEEP) ? VM_SLEEP : VM_NOSLEEP;
		qa_info->qa_buf_real = (uint32_t *)vmem_xalloc(
		    state->ts_ddrvmem, realsize, qa_info->qa_bind_align, 0, 0,
		    NULL, NULL, flag);
		if (qa_info->qa_buf_real == NULL) {
			ddi_dma_free_handle(&qa_info->qa_dmahdl);
			TNF_PROBE_0(tavor_queue_alloc_vmxa_fail,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_queue_alloc);
			return (DDI_FAILURE);
		}

		/*
		 * Since "qa_buf_real" will be a PCI address (the offset into
		 * the DDR memory), we first need to do some calculations to
		 * convert it to its kernel mapped address.  (Note: This may
		 * be modified again below, when any additional "alloc"
		 * alignment constraint is applied).
		 */
		qa_info->qa_buf_aligned = (uint32_t *)(uintptr_t)(((uintptr_t)
		    state->ts_reg_ddr_baseaddr) + ((uintptr_t)
		    qa_info->qa_buf_real - state->ts_ddr.ddr_baseaddr));
		qa_info->qa_buf_realsz	= realsize;
		qa_info->qa_acchdl	= state->ts_reg_ddrhdl;
	}

	/*
	 * The last step is to ensure that the final address ("qa_buf_aligned")
	 * has the appropriate "alloc" alignment restriction applied to it
	 * (if necessary).
	 */
	if (qa_info->qa_bind_align != qa_info->qa_alloc_align) {
		qa_info->qa_buf_aligned = (uint32_t *)(uintptr_t)(((uintptr_t)
		    qa_info->qa_buf_aligned + alloc_mask) & ~alloc_mask);
	}

	TAVOR_TNF_EXIT(tavor_queue_alloc);
	return (DDI_SUCCESS);
}


/*
 * tavor_queue_free()
 *    Context: Can be called from interrupt or base context.
 */
void
tavor_queue_free(tavor_state_t *state, tavor_qalloc_info_t *qa_info)
{
	TAVOR_TNF_ENTER(tavor_queue_free);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*qa_info))

	/*
	 * Depending on how (i.e. from where) we allocated the memory for
	 * this queue, we choose the appropriate method for releasing the
	 * resources.
	 */
	if (qa_info->qa_location == TAVOR_QUEUE_LOCATION_NORMAL) {

		ddi_dma_mem_free(&qa_info->qa_acchdl);

	} else if (qa_info->qa_location == TAVOR_QUEUE_LOCATION_USERLAND) {

		ddi_umem_free(qa_info->qa_umemcookie);

	} else {  /* TAVOR_QUEUE_LOCATION_INDDR */

		vmem_xfree(state->ts_ddrvmem, qa_info->qa_buf_real,
		    qa_info->qa_buf_realsz);
	}

	/* Always free the dma handle */
	ddi_dma_free_handle(&qa_info->qa_dmahdl);

	TAVOR_TNF_EXIT(tavor_queue_free);
}


/*
 * tavor_dmaattr_get()
 *    Context: Can be called from interrupt or base context.
 */
void
tavor_dma_attr_init(ddi_dma_attr_t *dma_attr)
{
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*dma_attr))

	dma_attr->dma_attr_version	= DMA_ATTR_V0;
	dma_attr->dma_attr_addr_lo	= 0;
	dma_attr->dma_attr_addr_hi	= 0xFFFFFFFFFFFFFFFFull;
	dma_attr->dma_attr_count_max	= 0xFFFFFFFFFFFFFFFFull;
	dma_attr->dma_attr_align	= 1;
	dma_attr->dma_attr_burstsizes	= 0x3FF;
	dma_attr->dma_attr_minxfer	= 1;
	dma_attr->dma_attr_maxxfer	= 0xFFFFFFFFFFFFFFFFull;
	dma_attr->dma_attr_seg		= 0xFFFFFFFFFFFFFFFFull;
	dma_attr->dma_attr_sgllen	= 0x7FFFFFFF;
	dma_attr->dma_attr_granular	= 1;
	dma_attr->dma_attr_flags	= 0;
}

/*
 * tavor_destroy_fmr_pool()
 * Create a pool of FMRs.
 *     Context: Can be called from kernel context only.
 */
int
tavor_create_fmr_pool(tavor_state_t *state, tavor_pdhdl_t pd,
    ibt_fmr_pool_attr_t *fmr_attr, tavor_fmrhdl_t *fmrpoolp)
{
	tavor_fmrhdl_t	fmrpool;
	tavor_fmr_list_t *fmr, *fmr_next;
	tavor_mrhdl_t   mr;
	char		taskqname[48];
	char		*errormsg;
	int		status;
	int		sleep;
	int		i;

	TAVOR_TNF_ENTER(tavor_create_fmr_pool);

	sleep = (fmr_attr->fmr_flags & IBT_MR_SLEEP) ? TAVOR_SLEEP :
	    TAVOR_NOSLEEP;
	if ((sleep == TAVOR_SLEEP) &&
	    (sleep != TAVOR_SLEEPFLAG_FOR_CONTEXT())) {
		TNF_PROBE_0(tavor_create_fmr_pool_invalid_flags,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_create_fmr_pool);
		return (IBT_INVALID_PARAM);
	}

	fmrpool = (tavor_fmrhdl_t)kmem_zalloc(sizeof (*fmrpool), sleep);
	if (fmrpool == NULL) {
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(IBT_INSUFF_RESOURCE, "failed FMR Pool handle");
		goto fail;
	}
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*fmrpool))

	mutex_init(&fmrpool->fmr_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(state->ts_intrmsi_pri));

	fmrpool->fmr_state	    = state;
	fmrpool->fmr_flush_function = fmr_attr->fmr_func_hdlr;
	fmrpool->fmr_flush_arg	    = fmr_attr->fmr_func_arg;
	fmrpool->fmr_pool_size	    = 0;
	fmrpool->fmr_cache	    = 0;
	fmrpool->fmr_max_pages	    = fmr_attr->fmr_max_pages_per_fmr;
	fmrpool->fmr_page_sz	    = fmr_attr->fmr_page_sz;
	fmrpool->fmr_dirty_watermark = fmr_attr->fmr_dirty_watermark;
	fmrpool->fmr_dirty_len	    = 0;
	fmrpool->fmr_flags	    = fmr_attr->fmr_flags;

	/* Create taskq to handle cleanup and flush processing */
	(void) snprintf(taskqname, 50, "fmrpool/%d/%d @ 0x%" PRIx64,
	    fmr_attr->fmr_pool_size, tavor_debug_fmrpool_cnt,
	    (uint64_t)(uintptr_t)fmrpool);
	fmrpool->fmr_taskq = ddi_taskq_create(state->ts_dip, taskqname,
	    TAVOR_TASKQ_NTHREADS, TASKQ_DEFAULTPRI, 0);
	if (fmrpool->fmr_taskq == NULL) {
		TAVOR_TNF_FAIL(IBT_INSUFF_RESOURCE, "failed task queue");
		goto fail1;
	}

	fmrpool->fmr_free_list = NULL;
	fmrpool->fmr_dirty_list = NULL;

	if (fmr_attr->fmr_cache) {
		tavor_fmr_cache_init(fmrpool);
	}

	for (i = 0; i < fmr_attr->fmr_pool_size; i++) {
		status = tavor_mr_alloc_fmr(state, pd, fmrpool, &mr);
		if (status != DDI_SUCCESS) {
			TAVOR_TNF_FAIL(status, "failed fmr alloc");
			goto fail2;
		}

		fmr = (tavor_fmr_list_t *)kmem_zalloc(
		    sizeof (tavor_fmr_list_t), sleep);
		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*fmr))

		fmr->fmr = mr;
		fmr->fmr_refcnt = 0;
		fmr->fmr_remaps = 0;
		fmr->fmr_pool = fmrpool;
		fmr->fmr_in_cache = 0;
		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*mr))
		mr->mr_fmr = fmr;

		fmr->fmr_next = fmrpool->fmr_free_list;
		fmrpool->fmr_free_list = fmr;
		fmrpool->fmr_pool_size++;
	}

	/* Set to return pool */
	*fmrpoolp = fmrpool;

	TAVOR_TNF_EXIT(tavor_create_fmr_pool);
	return (IBT_SUCCESS);
fail2:
	tavor_fmr_cache_fini(fmrpool);
	for (fmr = fmrpool->fmr_free_list; fmr != NULL; fmr = fmr_next) {
		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*fmr))
		fmr_next = fmr->fmr_next;
		(void) tavor_mr_dealloc_fmr(state, &fmr->fmr);
		kmem_free(fmr, sizeof (tavor_fmr_list_t));
	}
	ddi_taskq_destroy(fmrpool->fmr_taskq);
fail1:
	kmem_free(fmrpool, sizeof (*fmrpool));
fail:
	TNF_PROBE_1(tavor_create_fmr_pool_fail, TAVOR_TNF_ERROR, "",
	    tnf_string, msg, errormsg);
	TAVOR_TNF_EXIT(tavor_create_fmr_pool);
	if (status == DDI_FAILURE) {
		return (ibc_get_ci_failure(0));
	} else {
		return (status);
	}
}

/*
 * tavor_destroy_fmr_pool()
 * Destroy an FMR pool and free all associated resources.
 *     Context: Can be called from kernel context only.
 */
int
tavor_destroy_fmr_pool(tavor_state_t *state, tavor_fmrhdl_t fmrpool)
{
	tavor_fmr_list_t	*fmr, *fmr_next;
	char			*errormsg;
	int			status;

	TAVOR_TNF_ENTER(tavor_destroy_fmr_pool);

	mutex_enter(&fmrpool->fmr_lock);
	status = tavor_fmr_cleanup(state, fmrpool);
	if (status != DDI_SUCCESS) {
		mutex_exit(&fmrpool->fmr_lock);
		TAVOR_TNF_FAIL(ibc_get_ci_failure(0), "failed fmr cleanup");
		goto fail;
	}

	if (fmrpool->fmr_cache) {
		tavor_fmr_cache_fini(fmrpool);
	}

	for (fmr = fmrpool->fmr_free_list; fmr != NULL; fmr = fmr_next) {
		fmr_next = fmr->fmr_next;

		(void) tavor_mr_dealloc_fmr(state, &fmr->fmr);
		kmem_free(fmr, sizeof (tavor_fmr_list_t));
	}
	mutex_exit(&fmrpool->fmr_lock);

	ddi_taskq_destroy(fmrpool->fmr_taskq);
	mutex_destroy(&fmrpool->fmr_lock);

	kmem_free(fmrpool, sizeof (*fmrpool));

	TAVOR_TNF_EXIT(tavor_destroy_fmr_pool);
	return (DDI_SUCCESS);
fail:
	TNF_PROBE_1(tavor_destroy_fmr_pool_fail, TAVOR_TNF_ERROR, "",
	    tnf_string, msg, errormsg);
	TAVOR_TNF_EXIT(tavor_destroy_fmr_pool);
	return (status);
}

/*
 * tavor_flush_fmr_pool()
 * Ensure that all unmapped FMRs are fully invalidated.
 *     Context: Can be called from kernel context only.
 */
int
tavor_flush_fmr_pool(tavor_state_t *state, tavor_fmrhdl_t fmrpool)
{
	char		*errormsg;
	int		status;

	TAVOR_TNF_ENTER(tavor_flush_fmr_pool);

	/*
	 * Force the unmapping of all entries on the dirty list, regardless of
	 * whether the watermark has been hit yet.
	 */
	/* grab the pool lock */
	mutex_enter(&fmrpool->fmr_lock);
	status = tavor_fmr_cleanup(state, fmrpool);
	if (status != DDI_SUCCESS) {
		mutex_exit(&fmrpool->fmr_lock);
		TAVOR_TNF_FAIL(ibc_get_ci_failure(0), "failed fmr cleanup");
		goto fail;
	}
	/* release the pool lock */
	mutex_exit(&fmrpool->fmr_lock);

	TAVOR_TNF_EXIT(tavor_flush_fmr_pool);
	return (DDI_SUCCESS);
fail:
	TNF_PROBE_1(tavor_flush_fmr_pool_fail, TAVOR_TNF_ERROR, "",
	    tnf_string, msg, errormsg);
	TAVOR_TNF_EXIT(tavor_flush_fmr_pool);
	return (status);
}

/*
 * tavor_deregister_fmr()
 * Map memory into FMR
 *    Context: Can be called from interrupt or base context.
 */
int
tavor_register_physical_fmr(tavor_state_t *state, tavor_fmrhdl_t fmrpool,
    ibt_pmr_attr_t *mem_pattr, tavor_mrhdl_t *mr,
    ibt_pmr_desc_t *mem_desc_p)
{
	tavor_fmr_list_t	*fmr;
	tavor_fmr_list_t	query;
	avl_index_t		where;
	int			status;

	TAVOR_TNF_ENTER(tavor_register_physical_fmr);

	/* Check length */
	mutex_enter(&fmrpool->fmr_lock);
	if (mem_pattr->pmr_len < 1 || (mem_pattr->pmr_num_buf >
	    fmrpool->fmr_max_pages)) {
		mutex_exit(&fmrpool->fmr_lock);
		TNF_PROBE_0(tavor_register_physical_fmr_length_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_register_physical_fmr);
		return (IBT_MR_LEN_INVALID);
	}

	mutex_enter(&fmrpool->fmr_cachelock);
	/* lookup in fmr cache */
	/* if exists, grab it, and return it */
	if (fmrpool->fmr_cache) {
		query.fmr_desc.pmd_iova = mem_pattr->pmr_iova;
		query.fmr_desc.pmd_phys_buf_list_sz = mem_pattr->pmr_len;
		fmr = (tavor_fmr_list_t *)avl_find(&fmrpool->fmr_cache_avl,
		    &query, &where);

		/*
		 * If valid FMR was found in cache, return that fmr info
		 */
		if (fmr != NULL) {
			fmr->fmr_refcnt++;
			/* Store pmr desc for use in cache */
			(void) memcpy(mem_desc_p, &fmr->fmr_desc,
			    sizeof (ibt_pmr_desc_t));
			*mr = (tavor_mrhdl_t)fmr->fmr;
			mutex_exit(&fmrpool->fmr_cachelock);
			mutex_exit(&fmrpool->fmr_lock);
			TAVOR_TNF_EXIT(tavor_register_physical_fmr);
			return (DDI_SUCCESS);
		}
	}

	/* FMR does not exist in cache, proceed with registration */

	/* grab next free entry */
	fmr = fmrpool->fmr_free_list;
	if (fmr == NULL) {
		mutex_exit(&fmrpool->fmr_cachelock);
		mutex_exit(&fmrpool->fmr_lock);
		TNF_PROBE_0(tavor_register_physical_fmr_none_free,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_register_physical_fmr);
		return (IBT_INSUFF_RESOURCE);
	}

	fmrpool->fmr_free_list = fmrpool->fmr_free_list->fmr_next;
	fmr->fmr_next = NULL;

	status = tavor_mr_register_physical_fmr(state, mem_pattr, fmr->fmr,
	    mem_desc_p);
	if (status != DDI_SUCCESS) {
		mutex_exit(&fmrpool->fmr_cachelock);
		mutex_exit(&fmrpool->fmr_lock);
		TNF_PROBE_0(tavor_register_physical_fmr_reg_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_register_physical_fmr);
		return (status);
	}

	fmr->fmr_refcnt = 1;
	fmr->fmr_remaps++;

	/* Store pmr desc for use in cache */
	(void) memcpy(&fmr->fmr_desc, mem_desc_p, sizeof (ibt_pmr_desc_t));
	*mr = (tavor_mrhdl_t)fmr->fmr;

	/* Store in cache */
	if (fmrpool->fmr_cache) {
		if (!fmr->fmr_in_cache) {
			avl_insert(&fmrpool->fmr_cache_avl, fmr, where);
			fmr->fmr_in_cache = 1;
		}
	}

	mutex_exit(&fmrpool->fmr_cachelock);
	mutex_exit(&fmrpool->fmr_lock);
	TAVOR_TNF_EXIT(tavor_register_physical_fmr);
	return (DDI_SUCCESS);
}

/*
 * tavor_deregister_fmr()
 * Unmap FMR
 *    Context: Can be called from kernel context only.
 */
int
tavor_deregister_fmr(tavor_state_t *state, tavor_mrhdl_t mr)
{
	tavor_fmr_list_t	*fmr;
	tavor_fmrhdl_t		fmrpool;
	int			status;

	fmr = mr->mr_fmr;
	fmrpool = fmr->fmr_pool;

	/* Grab pool lock */
	mutex_enter(&fmrpool->fmr_lock);
	fmr->fmr_refcnt--;

	if (fmr->fmr_refcnt == 0) {
		/*
		 * First, do some bit of invalidation, reducing our exposure to
		 * having this region still registered in hardware.
		 */
		(void) tavor_mr_invalidate_fmr(state, mr);

		/*
		 * If we've exhausted our remaps then add the FMR to the dirty
		 * list, not allowing it to be re-used until we have done a
		 * flush.  Otherwise, simply add it back to the free list for
		 * re-mapping.
		 */
		if (fmr->fmr_remaps <
		    state->ts_cfg_profile->cp_fmr_max_remaps) {
			/* add to free list */
			fmr->fmr_next = fmrpool->fmr_free_list;
			fmrpool->fmr_free_list = fmr;
		} else {
			/* add to dirty list */
			fmr->fmr_next = fmrpool->fmr_dirty_list;
			fmrpool->fmr_dirty_list = fmr;
			fmrpool->fmr_dirty_len++;

			status = ddi_taskq_dispatch(fmrpool->fmr_taskq,
			    tavor_fmr_processing, fmrpool, DDI_NOSLEEP);
			if (status == DDI_FAILURE) {
				mutex_exit(&fmrpool->fmr_lock);
				TNF_PROBE_0(tavor_agent_request_cb_taskq_fail,
				    TAVOR_TNF_ERROR, "");
				return (IBT_INSUFF_RESOURCE);
			}
		}
	}
	/* Release pool lock */
	mutex_exit(&fmrpool->fmr_lock);

	return (DDI_SUCCESS);
}


/*
 * tavor_fmr_processing()
 * If required, perform cleanup.
 *     Context: Called from taskq context only.
 */
static void
tavor_fmr_processing(void *fmr_args)
{
	tavor_fmrhdl_t		fmrpool;
	char			*errormsg;
	int			status;

	TAVOR_TNF_ENTER(tavor_fmr_processing);

	ASSERT(fmr_args != NULL);

	fmrpool = (tavor_fmrhdl_t)fmr_args;

	/* grab pool lock */
	mutex_enter(&fmrpool->fmr_lock);
	if (fmrpool->fmr_dirty_len >= fmrpool->fmr_dirty_watermark) {
		status = tavor_fmr_cleanup(fmrpool->fmr_state, fmrpool);
		if (status != DDI_SUCCESS) {
			mutex_exit(&fmrpool->fmr_lock);
			TAVOR_TNF_FAIL(ibc_get_ci_failure(0),
			    "failed fmr cleanup");
			goto fail;
		}

		if (fmrpool->fmr_flush_function != NULL) {
			(void) fmrpool->fmr_flush_function(
			    (ibc_fmr_pool_hdl_t)fmrpool,
			    fmrpool->fmr_flush_arg);
		}
	}

	/* let pool lock go */
	mutex_exit(&fmrpool->fmr_lock);

	TAVOR_TNF_EXIT(tavor_fmr_processing);
	return;
fail:
	TNF_PROBE_1(tavor_fmr_processing, TAVOR_TNF_ERROR, "",
	    tnf_string, msg, errormsg);
	TAVOR_TNF_EXIT(tavor_fmr_processing);
}

/*
 * tavor_fmr_cleanup()
 * Perform cleaning processing, walking the list and performing the MTT sync
 * operation if required.
 *    Context: can be called from taskq or base context.
 */
static int
tavor_fmr_cleanup(tavor_state_t *state, tavor_fmrhdl_t fmrpool)
{
	tavor_fmr_list_t	*fmr;
	tavor_fmr_list_t	*fmr_next;
	int			sync_needed;
	int			status;

	TAVOR_TNF_ENTER(tavor_fmr_cleanup);

	ASSERT(MUTEX_HELD(&fmrpool->fmr_lock));

	sync_needed = 0;
	for (fmr = fmrpool->fmr_dirty_list; fmr; fmr = fmr_next) {
		fmr_next = fmr->fmr_next;
		fmr->fmr_remaps = 0;

		(void) tavor_mr_deregister_fmr(state, fmr->fmr);

		/*
		 * Update lists.
		 * - add fmr back to free list
		 * - remove fmr from dirty list
		 */
		fmr->fmr_next = fmrpool->fmr_free_list;
		fmrpool->fmr_free_list = fmr;


		/*
		 * Because we have updated the dirty list, and deregistered the
		 * FMR entry, we do need to sync the TPT, so we set the
		 * 'sync_needed' flag here so we sync once we finish dirty_list
		 * processing.
		 */
		sync_needed = 1;
	}

	fmrpool->fmr_dirty_list = NULL;
	fmrpool->fmr_dirty_len = 0;

	if (sync_needed) {
		status = tavor_sync_tpt_cmd_post(state, TAVOR_CMD_NOSLEEP_SPIN);
		if (status != TAVOR_CMD_SUCCESS) {
			TNF_PROBE_0(tavor_fmr_cleanup, TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_fmr_cleanup);
			return (status);
		}
	}

	TAVOR_TNF_EXIT(tavor_fmr_cleanup);
	return (DDI_SUCCESS);
}

/*
 * tavor_fmr_avl_compare()
 *    Context: Can be called from user or kernel context.
 */
static int
tavor_fmr_avl_compare(const void *q, const void *e)
{
	tavor_fmr_list_t *entry, *query;

	TAVOR_TNF_ENTER(tavor_qpn_avl_compare);

	entry = (tavor_fmr_list_t *)e;
	query = (tavor_fmr_list_t *)q;

	if (query->fmr_desc.pmd_iova < entry->fmr_desc.pmd_iova) {
		TAVOR_TNF_EXIT(tavor_qpn_avl_compare);
		return (-1);
	} else if (query->fmr_desc.pmd_iova > entry->fmr_desc.pmd_iova) {
		TAVOR_TNF_EXIT(tavor_qpn_avl_compare);
		return (+1);
	} else {
		TAVOR_TNF_EXIT(tavor_qpn_avl_compare);
		return (0);
	}
}


/*
 * tavor_fmr_cache_init()
 *    Context: Can be called from user or kernel context.
 */
static void
tavor_fmr_cache_init(tavor_fmrhdl_t fmr)
{
	TAVOR_TNF_ENTER(tavor_fmr_cache_init);

	/* Initialize the lock used for FMR cache AVL tree access */
	mutex_init(&fmr->fmr_cachelock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(fmr->fmr_state->ts_intrmsi_pri));

	/* Initialize the AVL tree for the FMR cache */
	avl_create(&fmr->fmr_cache_avl, tavor_fmr_avl_compare,
	    sizeof (tavor_fmr_list_t),
	    offsetof(tavor_fmr_list_t, fmr_avlnode));

	fmr->fmr_cache = 1;

	TAVOR_TNF_EXIT(tavor_fmr_cache_init);
}


/*
 * tavor_fmr_cache_fini()
 *    Context: Can be called from user or kernel context.
 */
static void
tavor_fmr_cache_fini(tavor_fmrhdl_t fmr)
{
	void			*cookie;

	TAVOR_TNF_ENTER(tavor_fmr_cache_fini);

	/*
	 * Empty all entries (if necessary) and destroy the AVL tree.
	 * The FMRs themselves are freed as part of destroy_pool()
	 */
	cookie = NULL;
	while (((void *)(tavor_fmr_list_t *)avl_destroy_nodes(
	    &fmr->fmr_cache_avl, &cookie)) != NULL) {
		/* loop through */
	}
	avl_destroy(&fmr->fmr_cache_avl);

	/* Destroy the lock used for FMR cache */
	mutex_destroy(&fmr->fmr_cachelock);

	TAVOR_TNF_EXIT(tavor_fmr_cache_fini);
}

/*
 * tavor_get_dma_cookies()
 * Return DMA cookies in the pre-allocated paddr_list_p based on the length
 * needed.
 *    Context: Can be called from interrupt or base context.
 */
int
tavor_get_dma_cookies(tavor_state_t *state, ibt_phys_buf_t *paddr_list_p,
    ibt_va_attr_t *va_attrs, uint_t list_len, uint_t *cookiecnt,
    ibc_ma_hdl_t *ibc_ma_hdl_p)
{
	ddi_dma_handle_t	dma_hdl;
	ddi_dma_attr_t		dma_attr;
	ddi_dma_cookie_t	dmacookie;
	uint_t			dma_xfer_mode;
	int			(*callback)(caddr_t);
	int			status;
	int			i;

	TAVOR_TNF_ENTER(tavor_get_dma_cookies);

	/* Set the callback flag appropriately */
	callback = (va_attrs->va_flags & IBT_VA_NOSLEEP) ? DDI_DMA_DONTWAIT :
	    DDI_DMA_SLEEP;
	if ((callback == DDI_DMA_SLEEP) &&
	    (TAVOR_SLEEP != TAVOR_SLEEPFLAG_FOR_CONTEXT())) {
		TNF_PROBE_0(tavor_ci_map_mem_area_invalid_flags,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ci_map_mem_area);
		return (IBT_INVALID_PARAM);
	}

	/*
	 * Initialize many of the default DMA attributes and allocate the DMA
	 * handle.  Then, if we're bypassing the IOMMU, set the
	 * DDI_DMA_FORCE_PHYSICAL flag.
	 */
	tavor_dma_attr_init(&dma_attr);

#ifdef __x86
	/*
	 * On x86 we can specify a maximum segment length for our returned
	 * cookies.
	 */
	if (va_attrs->va_flags & IBT_VA_FMR) {
		dma_attr.dma_attr_seg = PAGESIZE - 1;
	}
#endif

	/* Determine whether to map STREAMING or CONSISTENT */
	dma_xfer_mode = (va_attrs->va_flags & IBT_VA_NONCOHERENT) ?
	    DDI_DMA_STREAMING : DDI_DMA_CONSISTENT;

#ifdef	__sparc
	/*
	 * First, disable streaming and switch to consistent if
	 * configured to do so and IOMMU BYPASS is enabled.
	 */
	if (state->ts_cfg_profile->cp_disable_streaming_on_bypass &&
	    dma_xfer_mode == DDI_DMA_STREAMING &&
	    state->ts_cfg_profile->cp_iommu_bypass == TAVOR_BINDMEM_BYPASS) {
		dma_xfer_mode = DDI_DMA_CONSISTENT;
	}

	/*
	 * Then, if streaming is still specified, then "bypass" is not
	 * allowed.
	 */
	if ((dma_xfer_mode == DDI_DMA_CONSISTENT) &&
	    (state->ts_cfg_profile->cp_iommu_bypass == TAVOR_BINDMEM_BYPASS)) {
		dma_attr.dma_attr_flags = DDI_DMA_FORCE_PHYSICAL;
	}
#endif

	status = ddi_dma_alloc_handle(state->ts_dip, &dma_attr,
	    callback, NULL, &dma_hdl);
	if (status != DDI_SUCCESS) {
		TNF_PROBE_1(tavor_ci_map_mem_area_alloc_handle_fail,
		    TAVOR_TNF_ERROR, "", tnf_uint, status, status);
		TAVOR_TNF_EXIT(tavor_ci_map_mem_area);

		switch (status) {
		case DDI_DMA_NORESOURCES:
			return (IBT_INSUFF_RESOURCE);
		case DDI_DMA_BADATTR:
		default:
			return (ibc_get_ci_failure(0));
		}
	}

	/*
	 * Now bind the handle with the correct DMA attributes.
	 */
	if (va_attrs->va_flags & IBT_VA_BUF) {
		status = ddi_dma_buf_bind_handle(dma_hdl, va_attrs->va_buf,
		    DDI_DMA_RDWR | dma_xfer_mode, DDI_DMA_DONTWAIT,
		    NULL, &dmacookie, cookiecnt);
	} else {
		status = ddi_dma_addr_bind_handle(dma_hdl, NULL,
		    (caddr_t)(uintptr_t)va_attrs->va_vaddr, va_attrs->va_len,
		    DDI_DMA_RDWR | dma_xfer_mode, DDI_DMA_DONTWAIT,
		    NULL, &dmacookie, cookiecnt);
	}
	if (status != DDI_SUCCESS) {
		ddi_dma_free_handle(&dma_hdl);
		TNF_PROBE_0(tavor_ci_map_mem_area_bind_handle_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ci_map_mem_area);

		switch (status) {
		case DDI_DMA_NORESOURCES:
			return (IBT_INSUFF_RESOURCE);
		case DDI_DMA_TOOBIG:
			return (IBT_INVALID_PARAM);
		case DDI_DMA_PARTIAL_MAP:
		case DDI_DMA_INUSE:
		case DDI_DMA_NOMAPPING:
		default:
			return (ibc_get_ci_failure(0));
		}
	}

	/*
	 * Verify our physical buffer list (PBL) is large enough to handle the
	 * number of cookies that were returned.
	 */
	if (*cookiecnt > list_len) {
		(void) ddi_dma_unbind_handle(dma_hdl);
		ddi_dma_free_handle(&dma_hdl);
		TNF_PROBE_0(tavor_ci_map_mem_area_toomany_cookie_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ci_map_mem_area);
		return (IBT_PBL_TOO_SMALL);
	}

	/*
	 * We store the cookies returned by the DDI into our own PBL.  This
	 * sets the cookies up for later processing (for example, if we want to
	 * split up the cookies into smaller chunks).  We use the laddr and
	 * size fields in each cookie to create each individual entry (PBE).
	 */

	/*
	 * Store first cookie info first
	 */
	paddr_list_p[0].p_laddr = dmacookie.dmac_laddress;
	paddr_list_p[0].p_size = dmacookie.dmac_size;

	/*
	 * Loop through each cookie, storing each cookie into our physical
	 * buffer list.
	 */
	for (i = 1; i < *cookiecnt; i++) {
		ddi_dma_nextcookie(dma_hdl, &dmacookie);

		paddr_list_p[i].p_laddr = dmacookie.dmac_laddress;
		paddr_list_p[i].p_size  = dmacookie.dmac_size;
	}

	/* return handle */
	*ibc_ma_hdl_p = (ibc_ma_hdl_t)dma_hdl;
	TAVOR_TNF_EXIT(tavor_get_dma_cookies);
	return (DDI_SUCCESS);
}

/*
 * tavor_split_dma_cookies()
 * Split up cookies passed in from paddr_list_p, returning the new list in the
 * same buffers, based on the pagesize to split the cookies into.
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
int
tavor_split_dma_cookies(tavor_state_t *state, ibt_phys_buf_t *paddr_list,
    ib_memlen_t *paddr_offset, uint_t list_len, uint_t *cookiecnt,
    uint_t pagesize)
{
	uint64_t	pageoffset;
	uint64_t	pagemask;
	uint_t		pageshift;
	uint_t		current_cookiecnt;
	uint_t		cookies_needed;
	uint64_t	last_size, extra_cookie;
	int		i_increment;
	int		i, k;
	int		status;

	TAVOR_TNF_ENTER(tavor_split_dma_cookies);

	/* Setup pagesize calculations */
	pageoffset = pagesize - 1;
	pagemask = (~pageoffset);
	pageshift = highbit(pagesize) - 1;

	/*
	 * Setup first cookie offset based on pagesize requested.
	 */
	*paddr_offset = paddr_list[0].p_laddr & pageoffset;
	paddr_list[0].p_laddr &= pagemask;

	/* Save away the current number of cookies that are passed in */
	current_cookiecnt = *cookiecnt;

	/* Perform splitting up of current cookies into pagesize blocks */
	for (i = 0; i < current_cookiecnt; i += i_increment) {
		/*
		 * If the cookie is smaller than pagesize, or already is
		 * pagesize, then we are already within our limits, so we skip
		 * it.
		 */
		if (paddr_list[i].p_size <= pagesize) {
			i_increment = 1;
			continue;
		}

		/*
		 * If this is our first cookie, then we have to deal with the
		 * offset that may be present in the first address.  So add
		 * that to our size, to calculate potential change to the last
		 * cookie's size.
		 *
		 * Also, calculate the number of cookies that we'll need to
		 * split up this block into.
		 */
		if (i == 0) {
			last_size = (paddr_list[i].p_size + *paddr_offset) &
			    pageoffset;
			cookies_needed = (paddr_list[i].p_size +
			    *paddr_offset) >> pageshift;
		} else {
			last_size = 0;
			cookies_needed = paddr_list[i].p_size >> pageshift;
		}

		/*
		 * If our size is not a multiple of pagesize, we need one more
		 * cookie.
		 */
		if (last_size) {
			extra_cookie = 1;
		} else {
			extra_cookie = 0;
		}

		/*
		 * Split cookie into pagesize chunks, shifting list of cookies
		 * down, using more cookie slots in the PBL if necessary.
		 */
		status = tavor_dma_cookie_shift(paddr_list, i, list_len,
		    current_cookiecnt - i, cookies_needed + extra_cookie);
		if (status != 0) {
			TNF_PROBE_0(tavor_split_cookies_toomany_fail,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_dma_split_cookies);
			return (status);
		}

		/*
		 * If the very first cookie, we must take possible offset into
		 * account.
		 */
		if (i == 0) {
			paddr_list[i].p_size = pagesize - *paddr_offset;
		} else {
			paddr_list[i].p_size = pagesize;
		}

		/*
		 * We have shifted the existing cookies down the PBL, now fill
		 * in the blank entries by splitting up our current block.
		 */
		for (k = 1; k < cookies_needed; k++) {
			paddr_list[i + k].p_laddr =
			    paddr_list[i + k - 1].p_laddr + pagesize;
			paddr_list[i + k].p_size = pagesize;
		}

		/* If we have one extra cookie (of less than pagesize...) */
		if (extra_cookie) {
			paddr_list[i + k].p_laddr =
			    paddr_list[i + k - 1].p_laddr + pagesize;
			paddr_list[i + k].p_size = last_size;
		}

		/* Increment cookiecnt appropriately based on cookies used */
		i_increment = cookies_needed + extra_cookie;
		current_cookiecnt += i_increment - 1;
	}

	/* Update to new cookie count */
	*cookiecnt = current_cookiecnt;
	TAVOR_TNF_EXIT(tavor_dma_split_cookies);
	return (DDI_SUCCESS);
}

/*
 * tavor_dma_cookie_shift()
 *    Context: Can be called from interrupt or base context.
 */
int
tavor_dma_cookie_shift(ibt_phys_buf_t *paddr_list, int start, int end,
    int cookiecnt, int num_shift)
{
	int shift_start;
	int i;

	TAVOR_TNF_ENTER(tavor_dma_cookie_shift);

	/* Calculating starting point in the PBL list */
	shift_start = start + cookiecnt - 1;

	/* Check if we're at the end of our PBL list */
	if ((shift_start + num_shift - 1) >= end) {
		TNF_PROBE_0(tavor_dma_cookie_shift_toomany_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_dma_cookie_shift);
		return (IBT_PBL_TOO_SMALL);
	}

	for (i = shift_start; i > start; i--) {
		paddr_list[i + num_shift - 1] = paddr_list[i];
	}

	TAVOR_TNF_EXIT(tavor_dma_cookie_shift);
	return (DDI_SUCCESS);
}


/*
 * tavor_free_dma_cookies()
 *    Context: Can be called from interrupt or base context.
 */
int
tavor_free_dma_cookies(ibc_ma_hdl_t ma_hdl)
{
	ddi_dma_handle_t	dma_hdl;
	int			status;

	dma_hdl = (ddi_dma_handle_t)ma_hdl;

	status = ddi_dma_unbind_handle(dma_hdl);
	if (status != DDI_SUCCESS) {
		TNF_PROBE_0(tavor_ci_free_dma_unbind_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_ci_unmap_mem_area);
		return (ibc_get_ci_failure(0));
	}

	ddi_dma_free_handle(&dma_hdl);

	return (DDI_SUCCESS);
}
