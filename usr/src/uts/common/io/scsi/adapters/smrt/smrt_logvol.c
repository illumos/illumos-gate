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
 * Copyright (c) 2017, Joyent, Inc.
 */

#include <sys/scsi/adapters/smrt/smrt.h>

static void
smrt_logvol_free(smrt_volume_t *smlv)
{
	/*
	 * By this stage of teardown, all of the SCSI target drivers
	 * must have been detached from this logical volume.
	 */
	VERIFY(list_is_empty(&smlv->smlv_targets));
	list_destroy(&smlv->smlv_targets);

	kmem_free(smlv, sizeof (*smlv));
}

smrt_volume_t *
smrt_logvol_lookup_by_id(smrt_t *smrt, unsigned long id)
{
	VERIFY(MUTEX_HELD(&smrt->smrt_mutex));

	for (smrt_volume_t *smlv = list_head(&smrt->smrt_volumes);
	    smlv != NULL; smlv = list_next(&smrt->smrt_volumes, smlv)) {
		if (smlv->smlv_addr.LogDev.VolId == id) {
			return (smlv);
		}
	}

	return (NULL);
}

static int
smrt_read_logvols(smrt_t *smrt, smrt_report_logical_lun_t *smrll, uint64_t gen)
{
	smrt_report_logical_lun_ent_t *ents = smrll->smrll_data.ents;
	uint32_t count = BE_32(smrll->smrll_datasize) /
	    sizeof (smrt_report_logical_lun_ent_t);

	VERIFY(MUTEX_HELD(&smrt->smrt_mutex));

	if (count > SMRT_MAX_LOGDRV) {
		count = SMRT_MAX_LOGDRV;
	}

	for (unsigned i = 0; i < count; i++) {
		smrt_volume_t *smlv;
		char id[SCSI_MAXNAMELEN];

		DTRACE_PROBE2(read_logvol, unsigned, i,
		    smrt_report_logical_lun_ent_t *, &ents[i]);

		if ((smlv = smrt_logvol_lookup_by_id(smrt,
		    ents[i].smrle_addr.VolId)) == NULL) {

			/*
			 * This is a new Logical Volume, so add it the the list.
			 */
			if ((smlv = kmem_zalloc(sizeof (*smlv), KM_NOSLEEP)) ==
			    NULL) {
				return (ENOMEM);
			}

			list_create(&smlv->smlv_targets,
			    sizeof (smrt_target_t),
			    offsetof(smrt_target_t, smtg_link_lun));

			smlv->smlv_ctlr = smrt;
			list_insert_tail(&smrt->smrt_volumes, smlv);
		}

		/*
		 * Always make sure that the address and the generation are up
		 * to date, regardless of where this came from.
		 */
		smlv->smlv_addr.LogDev = ents[i].smrle_addr;
		smlv->smlv_gen = gen;
		(void) snprintf(id, sizeof (id), "%x",
		    smlv->smlv_addr.LogDev.VolId);
		if (!ddi_in_panic() &&
		    scsi_hba_tgtmap_set_add(smrt->smrt_virt_tgtmap,
		    SCSI_TGT_SCSI_DEVICE, id, NULL) != DDI_SUCCESS) {
			return (EIO);
		}
	}

	return (0);
}

static int
smrt_read_logvols_ext(smrt_t *smrt, smrt_report_logical_lun_t *smrll,
    uint64_t gen)
{
	smrt_report_logical_lun_extent_t *extents =
	    smrll->smrll_data.extents;
	uint32_t count = BE_32(smrll->smrll_datasize) /
	    sizeof (smrt_report_logical_lun_extent_t);

	VERIFY(MUTEX_HELD(&smrt->smrt_mutex));

	if (count > SMRT_MAX_LOGDRV) {
		count = SMRT_MAX_LOGDRV;
	}

	for (unsigned i = 0; i < count; i++) {
		smrt_volume_t *smlv;
		char id[SCSI_MAXNAMELEN];

		DTRACE_PROBE2(read_logvol_ext, unsigned, i,
		    smrt_report_logical_lun_extent_t *, &extents[i]);

		if ((smlv = smrt_logvol_lookup_by_id(smrt,
		    extents[i].smrle_addr.VolId)) != NULL) {
			if ((smlv->smlv_flags & SMRT_VOL_FLAG_WWN) &&
			    bcmp(extents[i].smrle_wwn, smlv->smlv_wwn,
			    16) != 0) {
				dev_err(smrt->smrt_dip, CE_PANIC, "logical "
				    "volume %u WWN changed unexpectedly", i);
			}
		} else {
			/*
			 * This is a new Logical Volume, so add it the the list.
			 */
			if ((smlv = kmem_zalloc(sizeof (*smlv), KM_NOSLEEP)) ==
			    NULL) {
				return (ENOMEM);
			}

			bcopy(extents[i].smrle_wwn, smlv->smlv_wwn, 16);
			smlv->smlv_flags |= SMRT_VOL_FLAG_WWN;

			list_create(&smlv->smlv_targets,
			    sizeof (smrt_target_t),
			    offsetof(smrt_target_t, smtg_link_lun));

			smlv->smlv_ctlr = smrt;
			list_insert_tail(&smrt->smrt_volumes, smlv);
		}

		/*
		 * Always make sure that the address and the generation are up
		 * to date.  The address may have changed on a reset.
		 */
		smlv->smlv_addr.LogDev = extents[i].smrle_addr;
		smlv->smlv_gen = gen;
		(void) snprintf(id, sizeof (id), "%x",
		    smlv->smlv_addr.LogDev.VolId);
		if (!ddi_in_panic() &&
		    scsi_hba_tgtmap_set_add(smrt->smrt_virt_tgtmap,
		    SCSI_TGT_SCSI_DEVICE, id, NULL) != DDI_SUCCESS) {
			return (EIO);
		}
	}

	return (0);
}

/*
 * Discover the currently visible set of Logical Volumes exposed by the
 * controller.
 */
int
smrt_logvol_discover(smrt_t *smrt, uint16_t timeout, uint64_t gen)
{
	smrt_command_t *smcm;
	smrt_report_logical_lun_t *smrll;
	smrt_report_logical_lun_req_t smrllr = { 0 };
	int r;

	/*
	 * Allocate the command to send to the device, including buffer space
	 * for the returned list of Logical Volumes.
	 */
	if ((smcm = smrt_command_alloc(smrt, SMRT_CMDTYPE_INTERNAL,
	    KM_NOSLEEP)) == NULL || smrt_command_attach_internal(smrt, smcm,
	    sizeof (smrt_report_logical_lun_t), KM_NOSLEEP) != 0) {
		r = ENOMEM;
		mutex_enter(&smrt->smrt_mutex);
		goto out;
	}

	smrll = smcm->smcm_internal->smcmi_va;

	smrt_write_controller_lun_addr(&smcm->smcm_va_cmd->Header.LUN);

	smcm->smcm_va_cmd->Request.CDBLen = sizeof (smrllr);
	smcm->smcm_va_cmd->Request.Timeout = LE_16(timeout);
	smcm->smcm_va_cmd->Request.Type.Type = CISS_TYPE_CMD;
	smcm->smcm_va_cmd->Request.Type.Attribute = CISS_ATTR_SIMPLE;
	smcm->smcm_va_cmd->Request.Type.Direction = CISS_XFER_READ;

	/*
	 * The Report Logical LUNs command is essentially a vendor-specific
	 * SCSI command, which we assemble into the CDB region of the command
	 * block.
	 */
	bzero(&smrllr, sizeof (smrllr));
	smrllr.smrllr_opcode = CISS_SCMD_REPORT_LOGICAL_LUNS;
	smrllr.smrllr_extflag = 1;
	smrllr.smrllr_datasize = htonl(sizeof (smrt_report_logical_lun_t));
	bcopy(&smrllr, &smcm->smcm_va_cmd->Request.CDB[0],
	    MIN(CISS_CDBLEN, sizeof (smrllr)));

	mutex_enter(&smrt->smrt_mutex);

	/*
	 * Send the command to the device.
	 */
	smcm->smcm_status |= SMRT_CMD_STATUS_POLLED;
	if ((r = smrt_submit(smrt, smcm)) != 0) {
		goto out;
	}

	/*
	 * Poll for completion.
	 */
	smcm->smcm_expiry = gethrtime() + timeout * NANOSEC;
	if ((r = smrt_poll_for(smrt, smcm)) != 0) {
		VERIFY3S(r, ==, ETIMEDOUT);
		VERIFY0(smcm->smcm_status & SMRT_CMD_STATUS_POLL_COMPLETE);

		/*
		 * The command timed out; abandon it now.  Remove the POLLED
		 * flag so that the periodic routine will send an abort to
		 * clean it up next time around.
		 */
		smcm->smcm_status |= SMRT_CMD_STATUS_ABANDONED;
		smcm->smcm_status &= ~SMRT_CMD_STATUS_POLLED;
		smcm = NULL;
		goto out;
	}

	if (smcm->smcm_status & SMRT_CMD_STATUS_RESET_SENT) {
		/*
		 * The controller was reset while we were trying to discover
		 * logical volumes.  Report failure.
		 */
		r = EIO;
		goto out;
	}

	if (smcm->smcm_status & SMRT_CMD_STATUS_ERROR) {
		ErrorInfo_t *ei = smcm->smcm_va_err;

		if (ei->CommandStatus != CISS_CMD_DATA_UNDERRUN) {
			dev_err(smrt->smrt_dip, CE_WARN, "logical volume "
			    "discovery error: status 0x%x", ei->CommandStatus);
			r = EIO;
			goto out;
		}
	}

	if (!ddi_in_panic() &&
	    scsi_hba_tgtmap_set_begin(smrt->smrt_virt_tgtmap) != DDI_SUCCESS) {
		dev_err(smrt->smrt_dip, CE_WARN, "failed to begin target map "
		    "observation on %s", SMRT_IPORT_VIRT);
		r = EIO;
		goto out;
	}

	if ((smrll->smrll_extflag & 0x1) != 0) {
		r = smrt_read_logvols_ext(smrt, smrll, gen);
	} else {
		r = smrt_read_logvols(smrt, smrll, gen);
	}

	if (r == 0 && !ddi_in_panic()) {
		if (scsi_hba_tgtmap_set_end(smrt->smrt_virt_tgtmap, 0) !=
		    DDI_SUCCESS) {
			dev_err(smrt->smrt_dip, CE_WARN, "failed to end target "
			    "map observation on %s", SMRT_IPORT_VIRT);
			r = EIO;
		}
	} else if (r != 0 && !ddi_in_panic()) {
		if (scsi_hba_tgtmap_set_flush(smrt->smrt_virt_tgtmap) !=
		    DDI_SUCCESS) {
			dev_err(smrt->smrt_dip, CE_WARN, "failed to end target "
			    "map observation on %s", SMRT_IPORT_VIRT);
			r = EIO;
		}
	}

	if (r == 0) {
		/*
		 * Update the time of the last successful Logical Volume
		 * discovery:
		 */
		smrt->smrt_last_log_discovery = gethrtime();
	}

out:
	mutex_exit(&smrt->smrt_mutex);

	if (smcm != NULL) {
		smrt_command_free(smcm);
	}
	return (r);
}

void
smrt_logvol_tgtmap_activate(void *arg, char *addr, scsi_tgtmap_tgt_type_t type,
    void **privpp)
{
	smrt_t *smrt = arg;
	unsigned long volume;
	char *eptr;

	VERIFY(type == SCSI_TGT_SCSI_DEVICE);
	VERIFY0(ddi_strtoul(addr, &eptr, 16, &volume));
	VERIFY3S(*eptr, ==, '\0');
	VERIFY3S(volume, >=, 0);
	VERIFY3S(volume, <, SMRT_MAX_LOGDRV);
	mutex_enter(&smrt->smrt_mutex);
	VERIFY(smrt_logvol_lookup_by_id(smrt, volume) != NULL);
	mutex_exit(&smrt->smrt_mutex);
	*privpp = NULL;
}

boolean_t
smrt_logvol_tgtmap_deactivate(void *arg, char *addr,
    scsi_tgtmap_tgt_type_t type, void *priv, scsi_tgtmap_deact_rsn_t reason)
{
	smrt_t *smrt = arg;
	smrt_volume_t *smlv;
	unsigned long volume;
	char *eptr;

	VERIFY(type == SCSI_TGT_SCSI_DEVICE);
	VERIFY(priv == NULL);
	VERIFY0(ddi_strtoul(addr, &eptr, 16, &volume));
	VERIFY3S(*eptr, ==, '\0');
	VERIFY3S(volume, >=, 0);
	VERIFY3S(volume, <, SMRT_MAX_LOGDRV);

	mutex_enter(&smrt->smrt_mutex);
	smlv = smrt_logvol_lookup_by_id(smrt, volume);
	VERIFY(smlv != NULL);

	list_remove(&smrt->smrt_volumes, smlv);
	smrt_logvol_free(smlv);
	mutex_exit(&smrt->smrt_mutex);

	return (B_FALSE);
}

void
smrt_logvol_teardown(smrt_t *smrt)
{
	smrt_volume_t *smlv;

	while ((smlv = list_remove_head(&smrt->smrt_volumes)) != NULL) {
		smrt_logvol_free(smlv);
	}
}
