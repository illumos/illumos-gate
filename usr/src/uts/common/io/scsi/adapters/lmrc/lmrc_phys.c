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
 * Copyright 2024 Racktop Systems, Inc.
 */

/*
 * This file implementes the iport and tgtmap for physical devices on lmrc.
 *
 * When the phys iport is attached, a FULLSET tgtmap is created for physical
 * devices (PDs).
 *
 * During attach or as a result of an async event received from the hardware,
 * we'll get the PD list from the HBA and populate the tgtmap with what we have
 * found. The PD list includes the SAS WWN of each device found, which we will
 * use for the unit address.
 *
 * In the target activation callback, we'll retrieve the PD info from the HBA
 * and pass it to lmrc_tgt_init(). This contains additional information such as
 * the device and interconnect types.
 */

#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/scsi/adapters/mfi/mfi.h>
#include <sys/scsi/adapters/mfi/mfi_evt.h>
#include <sys/scsi/adapters/mfi/mfi_pd.h>

#include "lmrc.h"
#include "lmrc_reg.h"
#include "lmrc_raid.h"
#include "lmrc_phys.h"

static int lmrc_get_pdmap(lmrc_t *, mfi_pd_map_t **);
static int lmrc_sync_pdmap(lmrc_t *, size_t);
static void lmrc_complete_sync_pdmap(lmrc_t *, lmrc_mfi_cmd_t *);

static mfi_pd_info_t *lmrc_get_pd_info(lmrc_t *, uint16_t);
static void lmrc_phys_tgt_activate_cb(void *, char *, scsi_tgtmap_tgt_type_t,
    void **);
static boolean_t lmrc_phys_tgt_deactivate_cb(void *, char *,
    scsi_tgtmap_tgt_type_t, void *, scsi_tgtmap_deact_rsn_t);
static int lmrc_phys_update_tgtmap(lmrc_t *, mfi_pd_list_t *);

/*
 * lmrc_get_pdmap
 *
 * Get the physical device map from the firmware. Return a minimally sized copy.
 */
static int
lmrc_get_pdmap(lmrc_t *lmrc, mfi_pd_map_t **pdmap)
{
	uint32_t pdmap_sz = sizeof (mfi_pd_map_t) +
	    sizeof (mfi_pd_cfg_t) * MFI_MAX_PHYSICAL_DRIVES;
	lmrc_mfi_cmd_t *mfi;
	mfi_pd_map_t *pm;
	int ret;

	mfi = lmrc_get_dcmd(lmrc, MFI_FRAME_DIR_READ,
	    MFI_DCMD_SYSTEM_PD_MAP_GET_INFO, pdmap_sz, 4);

	if (mfi == NULL)
		return (DDI_FAILURE);

	ret = lmrc_issue_blocked_mfi(lmrc, mfi);

	if (ret != DDI_SUCCESS)
		goto out;

	pm = mfi->mfi_data_dma.ld_buf;

	if (pm->pm_count > MFI_MAX_PHYSICAL_DRIVES) {
		dev_err(lmrc->l_dip, CE_WARN,
		    "!FW reports too many PDs: %d", pm->pm_count);
		ret = DDI_FAILURE;
		goto out;
	}

	pdmap_sz = sizeof (mfi_pd_map_t) + pm->pm_count * sizeof (mfi_pd_cfg_t);
	*pdmap = kmem_zalloc(pdmap_sz, KM_SLEEP);
	bcopy(pm, *pdmap, pdmap_sz);

out:
	lmrc_put_dcmd(lmrc, mfi);
	return (ret);
}

/*
 * lmrc_sync_pdmap
 *
 * Get the physical device map to the firmware. The command will complete
 * when the firmware detects a change.
 *
 * mbox byte values:
 * [0]:		PEND_FLAG, delay completion until a config change pending
 */
static int
lmrc_sync_pdmap(lmrc_t *lmrc, size_t pd_count)
{
	uint32_t pdmap_sz = sizeof (mfi_pd_map_t) +
	    pd_count * sizeof (mfi_pd_cfg_t);
	mfi_dcmd_payload_t *dcmd;
	lmrc_mfi_cmd_t *mfi;

	mfi = lmrc_get_dcmd(lmrc, MFI_FRAME_DIR_WRITE,
	    MFI_DCMD_SYSTEM_PD_MAP_GET_INFO, pdmap_sz, 4);

	if (mfi == NULL)
		return (DDI_FAILURE);

	dcmd = &mfi->mfi_frame->mf_dcmd;
	dcmd->md_mbox_8[0] = MFI_DCMD_MBOX_PEND_FLAG;

	mutex_enter(&mfi->mfi_lock);
	lmrc_issue_mfi(lmrc, mfi, lmrc_complete_sync_pdmap);
	mutex_exit(&mfi->mfi_lock);

	return (DDI_SUCCESS);
}

/*
 * lmrc_complete_sync_pdmap
 *
 * The PDMAP GET INFO command completed, most likely due to the hardware
 * detecting a change and informing us.
 */
static void
lmrc_complete_sync_pdmap(lmrc_t *lmrc, lmrc_mfi_cmd_t *mfi)
{
	mfi_header_t *hdr = &mfi->mfi_frame->mf_hdr;
	lmrc_dma_t *dma = &mfi->mfi_data_dma;
	mfi_pd_map_t *pm = dma->ld_buf;
	uint32_t pdmap_sz = sizeof (mfi_pd_map_t) +
	    lmrc->l_pdmap->pm_count * sizeof (mfi_pd_cfg_t);

	ASSERT(mutex_owned(&mfi->mfi_lock));

	if (hdr->mh_cmd_status != MFI_STAT_OK) {
		/* Was the command aborted? */
		if (hdr->mh_cmd_status == MFI_STAT_NOT_FOUND)
			return;

		/*
		 * In the case of any other error, log the error and schedule
		 * a taskq to clean up the command.
		 */
		dev_err(lmrc->l_dip, CE_WARN,
		    "!PD map sync failed, status = %d",
		    hdr->mh_cmd_status);
		lmrc->l_use_seqnum_jbod_fp = B_FALSE;
		taskq_dispatch_ent(lmrc->l_taskq, (task_func_t *)lmrc_put_mfi,
		    mfi, TQ_NOSLEEP, &mfi->mfi_tqent);
		return;
	}

	VERIFY3U(pdmap_sz, ==, dma->ld_len);

	/* Update our copy of the pdmap and restart the command. */
	rw_enter(&lmrc->l_pdmap_lock, RW_WRITER);
	bcopy(pm, lmrc->l_pdmap, pdmap_sz);
	rw_exit(&lmrc->l_pdmap_lock);
	bzero(pm, pdmap_sz);
	lmrc_issue_mfi(lmrc, mfi, lmrc_complete_sync_pdmap);
}

/*
 * lmrc_setup_pdmap
 *
 * Get the physical device map from the firmware, and sync it back.
 * Replace the copy in the soft state if successful.
 */
int
lmrc_setup_pdmap(lmrc_t *lmrc)
{
	mfi_pd_map_t *pdmap = NULL;
	int ret;

	ret = lmrc_get_pdmap(lmrc, &pdmap);
	if (ret != DDI_SUCCESS)
		return (ret);

	rw_enter(&lmrc->l_pdmap_lock, RW_WRITER);
	ASSERT(lmrc->l_pdmap == NULL);
	lmrc->l_pdmap = pdmap;
	rw_exit(&lmrc->l_pdmap_lock);

	ret = lmrc_sync_pdmap(lmrc, pdmap->pm_count);
	return (ret);
}

/*
 * lmrc_free_pdmap
 *
 * Free the buffer used to hold the physical device map.
 */
void
lmrc_free_pdmap(lmrc_t *lmrc)
{
	if (lmrc->l_pdmap != NULL) {
		uint32_t pdmap_sz = sizeof (mfi_pd_map_t) +
		    lmrc->l_pdmap->pm_count * sizeof (mfi_pd_cfg_t);
		kmem_free(lmrc->l_pdmap, pdmap_sz);
		lmrc->l_pdmap = NULL;
	}
}

/*
 * lmrc_pd_tm_capable
 *
 * Determine whether a PD can be sent TASK MGMT requests. By default we assume
 * it can't, unless the the PD map indicates otherwise.
 */
boolean_t
lmrc_pd_tm_capable(lmrc_t *lmrc, uint16_t tgtid)
{
	boolean_t tm_capable = B_FALSE;

	rw_enter(&lmrc->l_pdmap_lock, RW_READER);
	if (lmrc->l_pdmap != NULL &&
	    lmrc->l_pdmap->pm_pdcfg[tgtid].pd_tgtid != LMRC_DEVHDL_INVALID &&
	    lmrc->l_pdmap->pm_pdcfg[tgtid].pd_tm_capable != 0)
		tm_capable = B_TRUE;
	rw_exit(&lmrc->l_pdmap_lock);

	return (tm_capable);
}

/*
 * lmrc_get_pd_info
 *
 * Get physical drive info from FW.
 */
static mfi_pd_info_t *
lmrc_get_pd_info(lmrc_t *lmrc, uint16_t dev_id)
{
	mfi_pd_info_t *pdinfo = NULL;
	lmrc_mfi_cmd_t *mfi;
	mfi_dcmd_payload_t *dcmd;
	int ret;

	mfi = lmrc_get_dcmd(lmrc, MFI_FRAME_DIR_READ, MFI_DCMD_PD_GET_INFO,
	    sizeof (mfi_pd_info_t), 1);

	if (mfi == NULL)
		return (NULL);

	dcmd = &mfi->mfi_frame->mf_dcmd;
	dcmd->md_mbox_16[0] = dev_id;

	ret = lmrc_issue_blocked_mfi(lmrc, mfi);

	if (ret != DDI_SUCCESS)
		goto out;

	pdinfo = kmem_zalloc(sizeof (mfi_pd_info_t), KM_SLEEP);
	bcopy(mfi->mfi_data_dma.ld_buf, pdinfo, sizeof (mfi_pd_info_t));

out:
	lmrc_put_dcmd(lmrc, mfi);
	return (pdinfo);
}

/*
 * lmrc_phys_tgt_activate_cb
 *
 * Set up a tgt structure for a newly discovered PD.
 */
static void
lmrc_phys_tgt_activate_cb(void *tgtmap_priv, char *tgt_addr,
    scsi_tgtmap_tgt_type_t type, void **tgt_privp)
{
	lmrc_t *lmrc = tgtmap_priv;
	lmrc_tgt_t *tgt = *tgt_privp;
	uint16_t dev_id = tgt - lmrc->l_targets;
	mfi_pd_info_t *pd_info;

	VERIFY(lmrc == tgt->tgt_lmrc);

	dev_id -= LMRC_MAX_LD;

	VERIFY3U(dev_id, <, LMRC_MAX_PD);

	pd_info = lmrc_get_pd_info(lmrc, dev_id);
	if (pd_info == NULL)
		return;

	lmrc_tgt_init(tgt, dev_id, tgt_addr, pd_info);
}

/*
 * lmrc_phys_tgt_deactivate_cb
 *
 * Tear down the tgt structure of a PD that is no longer present.
 */
static boolean_t
lmrc_phys_tgt_deactivate_cb(void *tgtmap_priv, char *tgt_addr,
    scsi_tgtmap_tgt_type_t type, void *tgt_priv, scsi_tgtmap_deact_rsn_t deact)
{
	lmrc_t *lmrc = tgtmap_priv;
	lmrc_tgt_t *tgt = tgt_priv;

	VERIFY(lmrc == tgt->tgt_lmrc);

	lmrc_tgt_clear(tgt);

	return (B_FALSE);
}

/*
 * lmrc_phys_update_tgtmap
 *
 * Feed the PD list into the target map.
 */
static int
lmrc_phys_update_tgtmap(lmrc_t *lmrc, mfi_pd_list_t *pd_list)
{
	int ret;
	int i;

	if (pd_list->pl_count > LMRC_MAX_PD)
		return (DDI_FAILURE);

	ret = scsi_hba_tgtmap_set_begin(lmrc->l_phys_tgtmap);
	if (ret != DDI_SUCCESS)
		return (ret);

	for (i = 0; i < pd_list->pl_count; i++) {
		mfi_pd_addr_t *pa = &pd_list->pl_addr[i];
		char name[SCSI_WWN_BUFLEN];

		if (pa->pa_dev_id > MFI_MAX_PHYSICAL_DRIVES) {
			dev_err(lmrc->l_dip, CE_WARN,
			    "!%s: invalid PD dev id %d", __func__,
			    pa->pa_dev_id);
			goto fail;
		}

		if (scsi_wwn_to_wwnstr(pa->pa_sas_addr[0], 1, name) == NULL)
			goto fail;

		ret = scsi_hba_tgtmap_set_add(lmrc->l_phys_tgtmap,
		    SCSI_TGT_SCSI_DEVICE, name,
		    &lmrc->l_targets[pa->pa_dev_id + LMRC_MAX_LD]);

		if (ret != DDI_SUCCESS)
			goto fail;
	}

	return (scsi_hba_tgtmap_set_end(lmrc->l_phys_tgtmap, 0));

fail:
	(void) scsi_hba_tgtmap_set_flush(lmrc->l_raid_tgtmap);
	return (DDI_FAILURE);
}

/*
 * lmrc_get_pd_list
 *
 * Get the list of physical devices from the firmware and update the target map.
 */
int
lmrc_get_pd_list(lmrc_t *lmrc)
{
	lmrc_mfi_cmd_t *mfi;
	mfi_dcmd_payload_t *dcmd;
	int ret;

	/* If the phys iport isn't attached yet, just return success. */
	if (!INITLEVEL_ACTIVE(lmrc, LMRC_INITLEVEL_PHYS))
		return (DDI_SUCCESS);

	mfi = lmrc_get_dcmd(lmrc, MFI_FRAME_DIR_READ, MFI_DCMD_PD_LIST_QUERY,
	    sizeof (mfi_pd_list_t) + sizeof (mfi_pd_addr_t) * LMRC_MAX_PD, 1);

	if (mfi == NULL)
		return (DDI_FAILURE);

	dcmd = &mfi->mfi_frame->mf_dcmd;
	dcmd->md_mbox_8[0] = MFI_PD_QUERY_TYPE_EXPOSED_TO_HOST;

	ret = lmrc_issue_blocked_mfi(lmrc, mfi);

	if (ret != DDI_SUCCESS)
		goto out;

	ret = lmrc_phys_update_tgtmap(lmrc, mfi->mfi_data_dma.ld_buf);

out:
	lmrc_put_dcmd(lmrc, mfi);
	return (ret);
}

/*
 * lmrc_phys_aen_handler
 *
 * Handle AENs with locale code MFI_EVT_LOCALE_PD. If the PD configuration
 * changed, update the PD list and target map.
 */

int
lmrc_phys_aen_handler(lmrc_t *lmrc, mfi_evt_detail_t *evt)
{
	int ret = DDI_SUCCESS;

	switch (evt->evt_code) {
	case MFI_EVT_PD_INSERTED:
	case MFI_EVT_PD_REMOVED:
	case MFI_EVT_PD_CHANGED:
		/*
		 * For any change w.r.t. the PDs, refresh the PD list.
		 */
		ret = lmrc_get_pd_list(lmrc);
		break;

	case MFI_EVT_PD_PATROL_READ_PROGRESS:
	case MFI_EVT_PD_RESET:
		break;

	default:
		ret = DDI_FAILURE;
	}

	return (ret);
}

int
lmrc_phys_attach(dev_info_t *dip)
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
	lmrc->l_phys_dip = dip;

	ret = scsi_hba_tgtmap_create(dip, SCSI_TM_FULLSET, MICROSEC,
	    2 * MICROSEC, lmrc, lmrc_phys_tgt_activate_cb,
	    lmrc_phys_tgt_deactivate_cb, &lmrc->l_phys_tgtmap);
	if (ret != DDI_SUCCESS)
		return (DDI_FAILURE);

	if (lmrc->l_use_seqnum_jbod_fp)
		if (lmrc_setup_pdmap(lmrc) != DDI_SUCCESS)
			lmrc->l_use_seqnum_jbod_fp = B_FALSE;

	INITLEVEL_SET(lmrc, LMRC_INITLEVEL_PHYS);

	ret = lmrc_get_pd_list(lmrc);
	if (ret != DDI_SUCCESS) {
		dev_err(lmrc->l_dip, CE_WARN, "!Failed to get PD list.");
		return (ret);
	}

	return (DDI_SUCCESS);
}

int
lmrc_phys_detach(dev_info_t *dip)
{
	dev_info_t *pdip = ddi_get_parent(dip);
	lmrc_t *lmrc = ddi_get_soft_state(lmrc_state, ddi_get_instance(pdip));

	VERIFY(lmrc != NULL);
	INITLEVEL_CLEAR(lmrc, LMRC_INITLEVEL_PHYS);

	if (lmrc->l_phys_tgtmap != NULL) {
		scsi_hba_tgtmap_destroy(lmrc->l_phys_tgtmap);
		lmrc->l_phys_tgtmap = NULL;
	}

	lmrc->l_phys_dip = NULL;

	return (DDI_SUCCESS);
}
