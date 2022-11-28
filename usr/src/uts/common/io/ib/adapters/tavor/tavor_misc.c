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

	/*
	 * Someday maybe the "ibt_adds_vect_t *attr_p" will be NULL to
	 * indicate that we wish to allocate an "invalid" (i.e. empty)
	 * address handle XXX
	 */

	/* Validate that specified port number is legal */
	if (!tavor_portnum_is_valid(state, attr_p->av_port_num)) {
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
		goto ahalloc_fail;
	}

	/*
	 * Allocate the software structure for tracking the address handle
	 * (i.e. the Tavor Address Handle struct).  If we fail here, we must
	 * undo the previous resource allocation.
	 */
	status = tavor_rsrc_alloc(state, TAVOR_AHHDL, 1, sleepflag, &rsrc);
	if (status != DDI_SUCCESS) {
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

	return (DDI_SUCCESS);

ahalloc_fail2:
	tavor_pd_refcnt_dec(pd);
	tavor_rsrc_free(state, &rsrc);
ahalloc_fail1:
	tavor_rsrc_free(state, &udav);
ahalloc_fail:
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

	/* Validate that specified port number is legal */
	if (!tavor_portnum_is_valid(state, attr_p->av_port_num)) {
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

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*ah))

	/* Determine if AH needs to be synced or not */
	if (ah->ah_sync == 0) {
		return;
	}

	/* Get the DMA handle from AH handle */
	dmahdl = ah->ah_mrhdl->mr_bindinfo.bi_dmahdl;

	/* Calculate offset into address handle */
	offset = (off_t)0;
	status = ddi_dma_sync(dmahdl, offset, sizeof (tavor_hw_udav_t), flag);
	if (status != DDI_SUCCESS) {
		return;
	}
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

	/*
	 * It is only allowed to attach MCG to UD queue pairs.  Verify
	 * that the intended QP is of the appropriate transport type
	 */
	if (qp->qp_serv_type != TAVOR_QP_UD) {
		goto mcgattach_fail;
	}

	/*
	 * Check for invalid Multicast DLID.  Specifically, all Multicast
	 * LIDs should be within a well defined range.  If the specified LID
	 * is outside of that range, then return an error.
	 */
	if (tavor_mlid_is_valid(lid) == 0) {
		goto mcgattach_fail;
	}
	/*
	 * Check for invalid Multicast GID.  All Multicast GIDs should have
	 * a well-defined pattern of bits and flags that are allowable.  If
	 * the specified GID does not meet the criteria, then return an error.
	 */
	if (tavor_mgid_is_valid(gid) == 0) {
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
	return (DDI_SUCCESS);

mcgattach_fail:
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

	/*
	 * Check for invalid Multicast DLID.  Specifically, all Multicast
	 * LIDs should be within a well defined range.  If the specified LID
	 * is outside of that range, then return an error.
	 */
	if (tavor_mlid_is_valid(lid) == 0) {
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
			return (ibc_get_ci_failure(0));
		}
		mcg->mcg_num_qps--;
	}

	mutex_exit(&state->ts_mcglock);
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

	ASSERT(MUTEX_HELD(&state->ts_mcglock));

	qplist_indx = mcg->mcg_num_qps;

	/*
	 * Determine if we have exceeded the maximum number of QP per
	 * multicast group.  If we have, then return an error
	 */
	if (qplist_indx >= state->ts_cfg_profile->cp_num_qp_per_mcg) {
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

			return (DDI_SUCCESS);
		}
	}

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
		return (ibc_get_ci_failure(0));
	}

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

	/*
	 * According to IBA 1.1 specification (section 4.1.1) a valid
	 * "multicast GID" must have its top eight bits set to all ones
	 */
	topbits = (gid.gid_prefix >> TAVOR_MCG_TOPBITS_SHIFT) &
	    TAVOR_MCG_TOPBITS_MASK;
	if (topbits != TAVOR_MCG_TOPBITS) {
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
		return (0);
	}

	/*
	 * If it passes all of the above checks, then we will consider it
	 * a valid multicast GID.
	 */
	return (1);
}


/*
 * tavor_mlid_is_valid()
 *    Context: Can be called from interrupt or base context.
 */
static int
tavor_mlid_is_valid(ib_lid_t lid)
{
	/*
	 * According to IBA 1.1 specification (section 4.1.1) a valid
	 * "multicast DLID" must be between 0xC000 and 0xFFFE.
	 */
	if ((lid < IB_LID_MC_FIRST) || (lid > IB_LID_MC_LAST)) {
		return (0);
	}

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

	/*
	 * Allocate the software structure for tracking the protection domain
	 * (i.e. the Tavor Protection Domain handle).  By default each PD
	 * structure will have a unique PD number assigned to it.  All that
	 * is necessary is for software to initialize the PD reference count
	 * (to zero) and return success.
	 */
	status = tavor_rsrc_alloc(state, TAVOR_PDHDL, 1, sleepflag, &rsrc);
	if (status != DDI_SUCCESS) {
		return (IBT_INSUFF_RESOURCE);
	}
	pd = (tavor_pdhdl_t)rsrc->tr_addr;
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*pd))

	pd->pd_refcnt = 0;
	*pdhdl = pd;

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
		return (IBT_PD_IN_USE);
	}

	/* Free the Tavor Protection Domain handle */
	tavor_rsrc_free(state, &rsrc);

	/* Set the pdhdl pointer to NULL and return success */
	*pdhdl = (tavor_pdhdl_t)NULL;

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

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*pi))

	/* Validate that specified port number is legal */
	if (!tavor_portnum_is_valid(state, port)) {
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
	pi->p_phys_state	= portinfo.PortPhysicalState;
	pi->p_width_supported	= portinfo.LinkWidthSupported;
	pi->p_width_enabled	= portinfo.LinkWidthEnabled;
	pi->p_width_active	= portinfo.LinkWidthActive;
	pi->p_speed_supported	= portinfo.LinkSpeedSupported;
	pi->p_speed_enabled	= portinfo.LinkSpeedEnabled;
	pi->p_speed_active	= portinfo.LinkSpeedActive;
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
			return (ibc_get_ci_failure(0));
		}

		/* Figure out how many of the entries are valid */
		pkey_max = min((pi->p_pkey_tbl_sz - i), 32);
		for (j = 0; j < pkey_max; j++) {
			indx = (i + j);
			pi->p_pkey_tbl[indx] = pkeytable.P_KeyTableBlocks[j];
		}
	}

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

	/*
	 * Return an error if either of the unsupported flags are set
	 */
	if ((flags & IBT_PORT_SHUTDOWN) ||
	    (flags & IBT_PORT_SET_INIT_TYPE)) {
		return (IBT_NOT_SUPPORTED);
	}

	/*
	 * Determine whether we are trying to reset the QKey counter
	 */
	reset_qkey = (flags & IBT_PORT_RESET_QKEY) ? 1 : 0;

	/* Validate that specified port number is legal */
	if (!tavor_portnum_is_valid(state, port)) {
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
		return (ibc_get_ci_failure(0));
	}

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

	return (DDI_SUCCESS);
}


/*
 * tavor_queue_free()
 *    Context: Can be called from interrupt or base context.
 */
void
tavor_queue_free(tavor_state_t *state, tavor_qalloc_info_t *qa_info)
{
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
