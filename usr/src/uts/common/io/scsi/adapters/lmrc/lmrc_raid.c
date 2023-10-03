/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2023 Racktop Systems, Inc.
 */

/*
 * This file implements the RAID iport and tgtmap of lmrc.
 *
 * When the RAID iport is attached, a FULLSET tgtmap is created for RAID
 * devices (LDs). This does not only include RAID volumes, as one would expect,
 * but also physical disk on some controllers in JBOD mode.
 *
 * During attach or as a result of an async event received from the hardware,
 * we'll get the LD list from the HBA and populate the tgtmap with what we have
 * found. For each LD we'll try to get the SAS WWN by sending an INQUIRY for
 * VPD 0x83, setting up a temporary struct scsi_device to be able to use the
 * normal SCSI I/O code path despite the device not being known to the system
 * at this point.
 *
 * If the device has a SAS WWN, this will be used as device address. Otherwise
 * we'll use the internal target ID the HBA uses.
 *
 * The target activate and deactivate callbacks for RAID devices are kept really
 * simple, just calling the common lmrc_tgt init/clear functions.
 */

#include <sys/ddi.h>
#include <sys/sunddi.h>

#include "lmrc.h"
#include "lmrc_reg.h"
#include "lmrc_raid.h"

static int lmrc_get_raidmap(lmrc_t *, lmrc_fw_raid_map_t **);
static int lmrc_sync_raidmap(lmrc_t *);
static void lmrc_sync_raidmap_again(lmrc_t *, lmrc_mfi_cmd_t *);
static void lmrc_complete_sync_raidmap(lmrc_t *, lmrc_mfi_cmd_t *);
static int lmrc_validate_raidmap(lmrc_t *, lmrc_fw_raid_map_t *);

static void lmrc_raid_tgt_activate_cb(void *, char *, scsi_tgtmap_tgt_type_t,
    void **);
static boolean_t lmrc_raid_tgt_deactivate_cb(void *, char *,
    scsi_tgtmap_tgt_type_t, void *, scsi_tgtmap_deact_rsn_t);
static struct buf *lmrc_raid_send_inquiry(lmrc_t *, lmrc_tgt_t *, uint8_t,
    uint8_t);
static uint64_t lmrc_raid_get_wwn(lmrc_t *, uint8_t);
static int lmrc_raid_update_tgtmap(lmrc_t *, lmrc_ld_tgtid_list_t *);


/*
 * lmrc_get_raidmap
 *
 * Get the RAID map from firmware. Return a minimally sized copy.
 */
static int
lmrc_get_raidmap(lmrc_t *lmrc, lmrc_fw_raid_map_t **raidmap)
{
	lmrc_mfi_cmd_t *mfi;
	lmrc_fw_raid_map_t *rm;
	int ret;

	mfi = lmrc_get_dcmd(lmrc, MFI_FRAME_DIR_READ, LMRC_DCMD_LD_MAP_GET_INFO,
	    lmrc->l_max_map_sz, 4);

	if (mfi == NULL)
		return (DDI_FAILURE);

	ret = lmrc_issue_blocked_mfi(lmrc, mfi);

	if (ret != DDI_SUCCESS)
		goto out;

	(void) ddi_dma_sync(mfi->mfi_data_dma.ld_hdl, 0,
	    mfi->mfi_data_dma.ld_len, DDI_DMA_SYNC_FORKERNEL);

	rm = mfi->mfi_data_dma.ld_buf;
	if (rm->rm_raidmap_sz > lmrc->l_max_map_sz) {
		dev_err(lmrc->l_dip, CE_WARN,
		    "!FW reports a too large RAID map size: %d",
		    rm->rm_raidmap_sz);
		ret = DDI_FAILURE;
		goto out;
	}

	*raidmap = kmem_zalloc(rm->rm_raidmap_sz, KM_SLEEP);
	bcopy(rm, *raidmap, rm->rm_raidmap_sz);

out:
	lmrc_put_dcmd(lmrc, mfi);

	return (ret);
}

/*
 * lmrc_sync_raidmap
 *
 * Generate a LD target map from the RAID map and send that to the firmware.
 * The command will complete when firmware detects a change, returning a new
 * RAID map in the DMA memory. The size of the RAID map isn't expected to
 * change, so thats what's used as size for the DMA memory.
 *
 * mbox byte values:
 * [0]:		number of LDs
 * [1]:		PEND_FLAG, delay completion until a config change pending
 */
static int
lmrc_sync_raidmap(lmrc_t *lmrc)
{
	lmrc_fw_raid_map_t *rm;
	lmrc_mfi_cmd_t *mfi;
	lmrc_mfi_dcmd_payload_t *dcmd;

	rw_enter(&lmrc->l_raidmap_lock, RW_READER);
	rm = lmrc->l_raidmap;
	mfi = lmrc_get_dcmd(lmrc, MFI_FRAME_DIR_WRITE,
	    LMRC_DCMD_LD_MAP_GET_INFO, rm->rm_raidmap_sz, 4);

	if (mfi == NULL) {
		rw_exit(&lmrc->l_raidmap_lock);
		return (DDI_FAILURE);
	}

	dcmd = &mfi->mfi_frame->mf_dcmd;
	dcmd->md_mbox_8[0] = rm->rm_ld_count;
	dcmd->md_mbox_8[1] = LMRC_DCMD_MBOX_PEND_FLAG;
	rw_exit(&lmrc->l_raidmap_lock);

	mutex_enter(&mfi->mfi_lock);
	lmrc_sync_raidmap_again(lmrc, mfi);
	mutex_exit(&mfi->mfi_lock);

	return (DDI_SUCCESS);
}

/*
 * lmrc_sync_raidmap_again
 *
 * Called by lmrc_sync_raidmap() and lmrc_complete_sync_raidmap() to avoid
 * deallocating and reallocating DMA memory and MFI command in the latter,
 * while executing in interrupt context.
 *
 * This is doing the actual work of building the LD target map for FW and
 * issuing the command, but it does no sleeping allocations and it cannot fail.
 */
static void
lmrc_sync_raidmap_again(lmrc_t *lmrc, lmrc_mfi_cmd_t *mfi)
{
	lmrc_fw_raid_map_t *rm;
	lmrc_dma_t *dma = &mfi->mfi_data_dma;
	lmrc_ld_tgt_t *ld_sync = dma->ld_buf;
	lmrc_mfi_dcmd_payload_t *dcmd = &mfi->mfi_frame->mf_dcmd;
	uint32_t ld;

	bzero(dma->ld_buf, dma->ld_len);

	rw_enter(&lmrc->l_raidmap_lock, RW_READER);
	rm = lmrc->l_raidmap;
	for (ld = 0; ld < rm->rm_ld_count; ld++) {
		lmrc_ld_raid_t *lr = lmrc_ld_raid_get(ld, rm);

		ASSERT(lr != NULL);

		ld_sync[ld].lt_tgtid = lr->lr_target_id;
		ld_sync[ld].lt_seqnum = lr->lr_seq_num;
	}
	dcmd->md_mbox_8[0] = rm->rm_ld_count;
	rw_exit(&lmrc->l_raidmap_lock);

	ASSERT(mutex_owned(&mfi->mfi_lock));
	lmrc_issue_mfi(lmrc, mfi, lmrc_complete_sync_raidmap);
}

/*
 * lmrc_complete_sync_raidmap
 *
 * The firmware completed our request to sync the LD target map, indicating
 * that the configuration has changed. There's a new RAID map in the DMA memory.
 */
static void
lmrc_complete_sync_raidmap(lmrc_t *lmrc, lmrc_mfi_cmd_t *mfi)
{
	lmrc_mfi_header_t *hdr = &mfi->mfi_frame->mf_hdr;
	lmrc_dma_t *dma = &mfi->mfi_data_dma;
	lmrc_fw_raid_map_t *rm = dma->ld_buf;

	ASSERT(mutex_owned(&mfi->mfi_lock));

	if (hdr->mh_cmd_status != MFI_STAT_OK) {
		/* Was the command aborted? */
		if (hdr->mh_cmd_status == MFI_STAT_NOT_FOUND)
			return;

		dev_err(lmrc->l_dip, CE_WARN,
		    "!LD target map sync failed, status = %d",
		    hdr->mh_cmd_status);
		taskq_dispatch_ent(lmrc->l_taskq, (task_func_t *)lmrc_put_mfi,
		    mfi, TQ_NOSLEEP, &mfi->mfi_tqent);
		return;
	}

	if (lmrc_validate_raidmap(lmrc, rm) != DDI_SUCCESS)
		return;

	rw_enter(&lmrc->l_raidmap_lock, RW_WRITER);
	VERIFY3U(lmrc->l_raidmap->rm_raidmap_sz, ==, dma->ld_len);
	bcopy(rm, lmrc->l_raidmap, lmrc->l_raidmap->rm_raidmap_sz);
	rw_exit(&lmrc->l_raidmap_lock);
	lmrc_sync_raidmap_again(lmrc, mfi);
}

/*
 * lmrc_validata_raidmap
 *
 * Basic sanity checks of a RAID map as returned by the firmware.
 */
static int
lmrc_validate_raidmap(lmrc_t *lmrc, lmrc_fw_raid_map_t *raidmap)
{
	lmrc_raid_map_desc_t *desc;
	int i;

	/* Do a basic sanity check of the descriptor table offset and sizes. */
	if (raidmap->rm_desc_table_off > raidmap->rm_raidmap_sz)
		return (DDI_FAILURE);
	if (raidmap->rm_desc_table_off + raidmap->rm_desc_table_sz >
	    raidmap->rm_raidmap_sz)
		return (DDI_FAILURE);
	if (raidmap->rm_desc_table_nelem != LMRC_RAID_MAP_DESC_TYPES_COUNT)
		return (DDI_FAILURE);
	if (raidmap->rm_desc_table_sz !=
	    raidmap->rm_desc_table_nelem * sizeof (lmrc_raid_map_desc_t))
		return (DDI_FAILURE);

	desc = (lmrc_raid_map_desc_t *)
	    ((uint8_t *)raidmap + raidmap->rm_desc_table_off);

	/* Fill in descriptor pointers */
	for (i = 0; i < raidmap->rm_desc_table_nelem; i++) {
		/* Do a basic sanity check of the descriptor itself. */
		if (desc[i].rmd_type >= LMRC_RAID_MAP_DESC_TYPES_COUNT)
			return (DDI_FAILURE);
		if (desc[i].rmd_off + raidmap->rm_desc_table_off +
		    raidmap->rm_desc_table_sz >
		    raidmap->rm_raidmap_sz)
			return (DDI_FAILURE);
		if (desc[i].rmd_off + desc[i].rmd_bufsz +
		    raidmap->rm_desc_table_off + raidmap->rm_desc_table_sz >
		    raidmap->rm_raidmap_sz)
			return (DDI_FAILURE);

		raidmap->rm_desc_ptrs[desc[i].rmd_type] = (void *)
		    ((uint8_t *)desc + raidmap->rm_desc_table_sz +
		    desc[i].rmd_off);
	}

	return (DDI_SUCCESS);
}

/*
 * lmrc_setup_raidmap
 *
 * Get the crrent RAID map from the firmware. If it validates, replace the
 * copy in the soft state and send a LD target map to the firmware.
 */
int
lmrc_setup_raidmap(lmrc_t *lmrc)
{
	lmrc_fw_raid_map_t *raidmap;
	int ret;

	ret = lmrc_get_raidmap(lmrc, &raidmap);
	if (ret != DDI_SUCCESS)
		return (ret);

	ret = lmrc_validate_raidmap(lmrc, raidmap);
	if (ret != DDI_SUCCESS) {
		kmem_free(raidmap, raidmap->rm_raidmap_sz);
		return (ret);
	}

	rw_enter(&lmrc->l_raidmap_lock, RW_WRITER);
	lmrc_free_raidmap(lmrc);
	lmrc->l_raidmap = raidmap;
	rw_exit(&lmrc->l_raidmap_lock);

	ret = lmrc_sync_raidmap(lmrc);

	return (ret);
}

/*
 * lmrc_free_raidmap
 *
 * Free the buffer used to hold the RAID map.
 */
void
lmrc_free_raidmap(lmrc_t *lmrc)
{
	if (lmrc->l_raidmap != NULL) {
		kmem_free(lmrc->l_raidmap, lmrc->l_raidmap->rm_raidmap_sz);
		lmrc->l_raidmap = NULL;
	}
}

/*
 * lmrc_ld_tm_capable
 */
boolean_t
lmrc_ld_tm_capable(lmrc_t *lmrc, uint16_t tgtid)
{
	boolean_t tm_capable = B_FALSE;

	rw_enter(&lmrc->l_raidmap_lock, RW_READER);
	if (lmrc->l_raidmap != NULL) {
		uint16_t ld_id = lmrc_ld_id_get(tgtid, lmrc->l_raidmap);
		lmrc_ld_raid_t *lr = lmrc_ld_raid_get(ld_id, lmrc->l_raidmap);

		if (lr->lr_cap.lc_tm_cap != 0)
			tm_capable = B_TRUE;
	}
	rw_exit(&lmrc->l_raidmap_lock);

	return (tm_capable);
}



/*
 * lmrc_raid_tgt_activate_cb
 *
 * Set up a tgt structure for a newly discovered LD.
 */
static void
lmrc_raid_tgt_activate_cb(void *tgtmap_priv, char *tgt_addr,
    scsi_tgtmap_tgt_type_t type, void **tgt_privp)
{
	lmrc_t *lmrc = tgtmap_priv;
	lmrc_tgt_t *tgt = *tgt_privp;
	uint16_t tgtid = tgt - lmrc->l_targets;

	VERIFY(lmrc == tgt->tgt_lmrc);

	VERIFY3U(tgtid, <, LMRC_MAX_LD);

	lmrc_tgt_init(tgt, tgtid, tgt_addr, NULL);
}

/*
 * lmrc_raid_tgt_deactivate_cb
 *
 * Tear down the tgt structure of a LD that is no longer present.
 */
static boolean_t
lmrc_raid_tgt_deactivate_cb(void *tgtmap_priv, char *tgtaddr,
    scsi_tgtmap_tgt_type_t type, void *tgt_priv, scsi_tgtmap_deact_rsn_t deact)
{
	lmrc_t *lmrc = tgtmap_priv;
	lmrc_tgt_t *tgt = tgt_priv;

	VERIFY(lmrc == tgt->tgt_lmrc);

	lmrc_tgt_clear(tgt);

	return (B_FALSE);
}

/*
 * lmrc_raid_send_inquiry
 *
 * Fake a scsi_device and scsi_address, use the SCSA functions to allocate
 * a buf and a scsi_pkt, and issue a INQUIRY command to the target. Return
 * the buf on success, NULL otherwise.
 */
static struct buf *
lmrc_raid_send_inquiry(lmrc_t *lmrc, lmrc_tgt_t *tgt, uint8_t evpd,
    uint8_t page_code)
{
	struct buf *inq_bp = NULL;
	struct scsi_pkt *inq_pkt = NULL;
	const size_t len = 0xf0; /* max INQUIRY length */
	struct scsi_device sd;
	int ret;

	/*
	 * Fake a scsi_device and scsi_address so we can use the scsi functions,
	 * which in turn call our tran_setup_pkt and tran_start functions.
	 */
	bzero(&sd, sizeof (sd));
	sd.sd_address.a_hba_tran = ddi_get_driver_private(lmrc->l_raid_dip);
	sd.sd_address.a.a_sd = &sd;
	scsi_device_hba_private_set(&sd, tgt);

	/*
	 * Get a buffer for INQUIRY.
	 */
	inq_bp = scsi_alloc_consistent_buf(&sd.sd_address, NULL,
	    len, B_READ, SLEEP_FUNC, NULL);

	if (inq_bp == NULL)
		goto out;

	inq_pkt = scsi_init_pkt(&sd.sd_address, NULL, inq_bp, CDB_GROUP0,
	    sizeof (struct scsi_arq_status), 0, PKT_CONSISTENT, SLEEP_FUNC,
	    NULL);

	if (inq_pkt == NULL)
		goto fail;

	(void) scsi_setup_cdb((union scsi_cdb *)inq_pkt->pkt_cdbp,
	    SCMD_INQUIRY, 0, len, 0);
	inq_pkt->pkt_cdbp[1] = evpd;
	inq_pkt->pkt_cdbp[2] = page_code;

	ret = scsi_poll(inq_pkt);

	scsi_destroy_pkt(inq_pkt);

	if (ret != 0) {
fail:
		scsi_free_consistent_buf(inq_bp);
		inq_bp = NULL;
	}

out:
	return (inq_bp);
}

/*
 * lmrc_raid_get_wwn
 *
 * LDs may have a WWN, but the hardware doesn't just tell us about it.
 * Send an INQUIRY to the target and get VPD page 0x83. If the target
 * does have a WWN, return it.
 */
static uint64_t
lmrc_raid_get_wwn(lmrc_t *lmrc, uint8_t tgtid)
{
	lmrc_tgt_t *tgt = &lmrc->l_targets[tgtid];
	char *guid = NULL;
	struct buf *inq_bp = NULL, *inq83_bp = NULL;
	uint64_t wwn = 0;
	ddi_devid_t devid;
	int ret;

	/*
	 * Make sure we have the target ID set in the target structure.
	 */
	rw_enter(&tgt->tgt_lock, RW_WRITER);
	VERIFY3U(tgt->tgt_lmrc, ==, lmrc);
	if (tgt->tgt_dev_id == LMRC_DEVHDL_INVALID)
		tgt->tgt_dev_id = tgtid;
	else
		VERIFY3U(tgt->tgt_dev_id, ==, tgtid);
	rw_exit(&tgt->tgt_lock);

	/* Get basic INQUIRY data from device. */
	inq_bp = lmrc_raid_send_inquiry(lmrc, tgt, 0, 0);
	if (inq_bp == NULL)
		goto fail;

	/* Get VPD 83 from INQUIRY. */
	inq83_bp = lmrc_raid_send_inquiry(lmrc, tgt, 1, 0x83);
	if (inq83_bp == NULL)
		goto fail;

	/* Try to turn the VPD83 data into a devid. */
	ret = ddi_devid_scsi_encode(DEVID_SCSI_ENCODE_VERSION1,
	    NULL, (uchar_t *)inq_bp->b_un.b_addr, sizeof (struct scsi_inquiry),
	    NULL, 0, (uchar_t *)inq83_bp->b_un.b_addr, inq83_bp->b_bcount,
	    &devid);
	if (ret != DDI_SUCCESS)
		goto fail;

	/* Extract the GUID from the devid. */
	guid = ddi_devid_to_guid(devid);
	if (guid == NULL)
		goto fail;

	/* Convert the GUID to a WWN. */
	(void) scsi_wwnstr_to_wwn(guid, &wwn);

	ddi_devid_free_guid(guid);

fail:
	if (inq_bp != NULL)
		scsi_free_consistent_buf(inq_bp);
	if (inq83_bp != NULL)
		scsi_free_consistent_buf(inq83_bp);

	return (wwn);
}

/*
 * lmrc_raid_update_tgtmap
 *
 * Feed the LD target ID list into the target map. Try to get a WWN for each LD.
 */
static int
lmrc_raid_update_tgtmap(lmrc_t *lmrc, lmrc_ld_tgtid_list_t *ld_list)
{
	int ret;
	int i;

	if (ld_list->ltl_count > lmrc->l_fw_supported_vd_count)
		return (DDI_FAILURE);

	ret = scsi_hba_tgtmap_set_begin(lmrc->l_raid_tgtmap);
	if (ret != DDI_SUCCESS)
		return (ret);

	for (i = 0; i < ld_list->ltl_count; i++) {
		uint8_t tgtid = ld_list->ltl_tgtid[i];
		char name[SCSI_WWN_BUFLEN];
		uint64_t wwn;

		if (tgtid > lmrc->l_fw_supported_vd_count) {
			dev_err(lmrc->l_dip, CE_WARN,
			    "!%s: invalid LD tgt id %d", __func__, tgtid);
			goto fail;
		}

		wwn = lmrc_raid_get_wwn(lmrc, tgtid);
		if (wwn != 0)
			(void) scsi_wwn_to_wwnstr(wwn, 0, name);
		else
			(void) snprintf(name, sizeof (name), "%d", tgtid);

		ret = scsi_hba_tgtmap_set_add(lmrc->l_raid_tgtmap,
		    SCSI_TGT_SCSI_DEVICE, name, &lmrc->l_targets[tgtid]);

		if (ret != DDI_SUCCESS)
			goto fail;
	}

	return (scsi_hba_tgtmap_set_end(lmrc->l_raid_tgtmap, 0));

fail:
	(void) scsi_hba_tgtmap_set_flush(lmrc->l_raid_tgtmap);
	return (DDI_FAILURE);
}

/*
 * lmrc_get_ld_list
 *
 * Query the controller for a list of currently known LDs. Use the information
 * to update the target map.
 */
int
lmrc_get_ld_list(lmrc_t *lmrc)
{
	lmrc_mfi_dcmd_payload_t *dcmd;
	lmrc_mfi_cmd_t *mfi;
	int ret;

	mfi = lmrc_get_dcmd(lmrc, MFI_FRAME_DIR_READ, LMRC_DCMD_LD_LIST_QUERY,
	    sizeof (lmrc_ld_tgtid_list_t) + lmrc->l_fw_supported_vd_count, 1);

	if (mfi == NULL)
		return (DDI_FAILURE);

	dcmd = &mfi->mfi_frame->mf_dcmd;
	dcmd->md_mbox_8[0] = LMRC_LD_QUERY_TYPE_EXPOSED_TO_HOST;

	if (lmrc->l_max_256_vd_support)
		dcmd->md_mbox_8[2] = 1;

	ret = lmrc_issue_blocked_mfi(lmrc, mfi);

	if (ret != DDI_SUCCESS)
		goto out;

	ret = lmrc_raid_update_tgtmap(lmrc, mfi->mfi_data_dma.ld_buf);

out:
	lmrc_put_dcmd(lmrc, mfi);
	return (ret);
}

/*
 * lmrc_raid_aen_handler
 *
 * Handle AENs with locale code LMRC_EVT_LOCALE_LD. If the LD configuration
 * changed, update the LD list and target map.
 */
int
lmrc_raid_aen_handler(lmrc_t *lmrc, lmrc_evt_t *evt)
{
	int ret = DDI_SUCCESS;

	switch (evt->evt_code) {
	case LMRC_EVT_LD_CC_STARTED:
	case LMRC_EVT_LD_CC_PROGRESS:
	case LMRC_EVT_LD_CC_COMPLETE:
		/*
		 * Consistency Check. I/O is possible during consistency check,
		 * so there's no need to do anything.
		 */
		break;

	case LMRC_EVT_LD_FAST_INIT_STARTED:
	case LMRC_EVT_LD_FULL_INIT_STARTED:
		/*
		 * A LD initialization process has been started.
		 */
		ret = lmrc_get_ld_list(lmrc);
		break;

	case LMRC_EVT_LD_BG_INIT_PROGRESS:
	case LMRC_EVT_LD_INIT_PROGRESS:
		/*
		 * FULL INIT reports these for every percent of completion.
		 * Ignore.
		 */
		break;

	case LMRC_EVT_LD_INIT_ABORTED:
	case LMRC_EVT_LD_INIT_COMPLETE:
		/*
		 * The LD initialization has ended, one way or another.
		 */
		ret = lmrc_get_ld_list(lmrc);
		break;

	case LMRC_EVT_LD_BBT_CLEARED:
		/*
		 * The Bad Block Table for the LD has been cleared. This usually
		 * follows a INIT_COMPLETE, but may occur in other situations.
		 * Ignore.
		 */
		break;

	case LMRC_EVT_LD_PROP_CHANGED:
		/*
		 * Happens when LD props are changed, such as setting the
		 * "hidden" property. There's little we can do here as we
		 * don't which property changed which way. In any case,
		 * this is usually followed by a HOST BUS SCAN REQD which
		 * will handle any changes.
		 */
		break;

	case LMRC_EVT_LD_OFFLINE:
		/*
		 * Not sure when this happens, but since the LD is offline we
		 * should just remove it from the target map.
		 */
		ret = lmrc_get_ld_list(lmrc);
		break;

	case LMRC_EVT_LD_DELETED:
		/*
		 * A LD was deleted, remove it from target map.
		 */
		ret = lmrc_get_ld_list(lmrc);
		break;

	case LMRC_EVT_LD_OPTIMAL:
		/*
		 * There might be several cases when this event occurs,
		 * in particular when a LD is created. In that case it's the
		 * first of several events, so we can ignore it.
		 */
		break;

	case LMRC_EVT_LD_CREATED:
		/*
		 * This is the 2nd event generated when a LD is created, and
		 * it's the one FreeBSD and Linux act on. Add the LD to the
		 * target map.
		 */
		ret = lmrc_get_ld_list(lmrc);
		break;

	case LMRC_EVT_LD_AVAILABLE:
		/*
		 * This event happens last when a LD is created, but there may
		 * be other scenarios where this occurs. Ignore it for now.
		 */
		break;

	case LMRC_EVT_LD_STATE_CHANGE:
		/*
		 * Not sure when this happens, but updating the LD list is
		 * probably a good idea.
		 */
		ret = lmrc_get_ld_list(lmrc);
		break;

	default:
		ret = DDI_FAILURE;
	}

	return (ret);
}

int
lmrc_raid_attach(dev_info_t *dip)
{
	scsi_hba_tran_t *tran = ddi_get_driver_private(dip);
	dev_info_t *pdip = ddi_get_parent(dip);
	lmrc_t *lmrc = ddi_get_soft_state(lmrc_state, ddi_get_instance(pdip));
	int ret;

	VERIFY(tran != NULL);
	VERIFY(lmrc != NULL);

	if (lmrc->l_fw_fault)
		return (DDI_FAILURE);

	tran->tran_hba_private = lmrc;
	lmrc->l_raid_dip = dip;

	ret = scsi_hba_tgtmap_create(dip, SCSI_TM_FULLSET, MICROSEC,
	    2 * MICROSEC, lmrc, lmrc_raid_tgt_activate_cb,
	    lmrc_raid_tgt_deactivate_cb, &lmrc->l_raid_tgtmap);
	if (ret != DDI_SUCCESS)
		return (ret);

	ret = lmrc_setup_raidmap(lmrc);
	if (ret != DDI_SUCCESS) {
		dev_err(lmrc->l_dip, CE_WARN, "!RAID map setup failed.");
		return (DDI_FAILURE);
	}

	ret = lmrc_get_ld_list(lmrc);
	if (ret != DDI_SUCCESS) {
		dev_err(lmrc->l_dip, CE_WARN, "!Failed to get LD list.");
		return (ret);
	}

	return (DDI_SUCCESS);
}

int
lmrc_raid_detach(dev_info_t *dip)
{
	dev_info_t *pdip = ddi_get_parent(dip);
	lmrc_t *lmrc = ddi_get_soft_state(lmrc_state, ddi_get_instance(pdip));

	VERIFY(lmrc != NULL);

	if (lmrc->l_raid_tgtmap != NULL) {
		scsi_hba_tgtmap_destroy(lmrc->l_raid_tgtmap);
		lmrc->l_raid_tgtmap = NULL;
	}

	lmrc->l_raid_dip = NULL;

	return (DDI_SUCCESS);
}
