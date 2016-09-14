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
 * Copyright 2016 Joyent, Inc.
 */

#include <sys/scsi/adapters/smrt/smrt.h>

smrt_volume_t *
smrt_logvol_lookup_by_id(smrt_t *smrt, unsigned id)
{
	VERIFY(MUTEX_HELD(&smrt->smrt_mutex));

	for (smrt_volume_t *smlv = list_head(&smrt->smrt_volumes);
	    smlv != NULL; smlv = list_next(&smrt->smrt_volumes, smlv)) {
		if (smlv->smlv_addr.VolId == id) {
			return (smlv);
		}
	}

	return (NULL);
}

smrt_volume_t *
smrt_logvol_lookup_by_addr(smrt_t *smrt, struct scsi_address *sa)
{
	VERIFY(MUTEX_HELD(&smrt->smrt_mutex));

	/*
	 * As outlined in scsi_address(9S), a SCSI target device is described
	 * by an address in two parts: the target ID, and a logical unit
	 * number.  Logical volumes are essentially a simple, single-unit SCSI
	 * "device", which for our purposes is only available on logical unit
	 * number 0.
	 */
	if (sa->a_lun != 0) {
		return (NULL);
	}

	return (smrt_logvol_lookup_by_id(smrt, sa->a_target));
}

static int
smrt_read_logvols(smrt_t *smrt, smrt_report_logical_lun_t *smrll)
{
	smrt_report_logical_lun_ent_t *ents = smrll->smrll_data.ents;
	uint32_t count = BE_32(smrll->smrll_datasize) /
	    sizeof (smrt_report_logical_lun_ent_t);

	if (count > SMRT_MAX_LOGDRV) {
		count = SMRT_MAX_LOGDRV;
	}

	for (unsigned i = 0; i < count; i++) {
		smrt_volume_t *smlv;

		DTRACE_PROBE2(read_logvol, unsigned, i,
		    smrt_report_logical_lun_ent_t *, &ents[i]);

		if ((smlv = smrt_logvol_lookup_by_id(smrt,
		    ents[i].smrle_addr.VolId)) != NULL) {
			continue;
		}

		/*
		 * This is a new Logical Volume, so add it the the list.
		 */
		if ((smlv = kmem_zalloc(sizeof (*smlv), KM_NOSLEEP)) ==
		    NULL) {
			return (ENOMEM);
		}

		smlv->smlv_addr = ents[i].smrle_addr;

		list_create(&smlv->smlv_targets,
		    sizeof (smrt_target_t),
		    offsetof(smrt_target_t, smtg_link_volume));

		smlv->smlv_ctlr = smrt;
		list_insert_tail(&smrt->smrt_volumes, smlv);
	}

	return (0);
}

static int
smrt_read_logvols_ext(smrt_t *smrt, smrt_report_logical_lun_t *smrll)
{
	smrt_report_logical_lun_extent_t *extents =
	    smrll->smrll_data.extents;
	uint32_t count = BE_32(smrll->smrll_datasize) /
	    sizeof (smrt_report_logical_lun_extent_t);

	if (count > SMRT_MAX_LOGDRV) {
		count = SMRT_MAX_LOGDRV;
	}

	for (unsigned i = 0; i < count; i++) {
		smrt_volume_t *smlv;

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
			continue;
		}

		/*
		 * This is a new Logical Volume, so add it the the list.
		 */
		if ((smlv = kmem_zalloc(sizeof (*smlv), KM_NOSLEEP)) ==
		    NULL) {
			return (ENOMEM);
		}

		smlv->smlv_addr = extents[i].smrle_addr;

		bcopy(extents[i].smrle_wwn, smlv->smlv_wwn, 16);
		smlv->smlv_flags |= SMRT_VOL_FLAG_WWN;

		list_create(&smlv->smlv_targets,
		    sizeof (smrt_target_t),
		    offsetof(smrt_target_t, smtg_link_volume));

		smlv->smlv_ctlr = smrt;
		list_insert_tail(&smrt->smrt_volumes, smlv);
	}

	return (0);
}

/*
 * Discover the currently visible set of Logical Volumes exposed by the
 * controller.
 */
int
smrt_logvol_discover(smrt_t *smrt, uint16_t timeout)
{
	smrt_command_t *smcm;
	smrt_report_logical_lun_t *smrll;
	smrt_report_logical_lun_req_t smrllr = { 0 };
	int r;

	if (!ddi_in_panic()) {
		mutex_enter(&smrt->smrt_mutex);
		while (smrt->smrt_status & SMRT_CTLR_STATUS_DISCOVERY) {
			/*
			 * A discovery is already occuring.  Wait for
			 * completion.
			 */
			cv_wait(&smrt->smrt_cv_finishq, &smrt->smrt_mutex);
		}

		if (gethrtime() < smrt->smrt_last_discovery + 5 * NANOSEC) {
			/*
			 * A discovery completed successfully within the
			 * last five seconds.  Just use the existing data.
			 */
			mutex_exit(&smrt->smrt_mutex);
			return (0);
		}

		smrt->smrt_status |= SMRT_CTLR_STATUS_DISCOVERY;
		mutex_exit(&smrt->smrt_mutex);
	}

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

	/*
	 * According to the CISS Specification, the Report Logical LUNs
	 * command is sent to the controller itself.  The Masked Peripheral
	 * Device addressing mode is used, with LUN of 0.
	 */
	smrt_write_lun_addr_phys(&smcm->smcm_va_cmd->Header.LUN, B_TRUE,
	    0, 0);

	smcm->smcm_va_cmd->Request.CDBLen = 12;
	smcm->smcm_va_cmd->Request.Timeout = timeout;
	smcm->smcm_va_cmd->Request.Type.Type = CISS_TYPE_CMD;
	smcm->smcm_va_cmd->Request.Type.Attribute = CISS_ATTR_ORDERED;
	smcm->smcm_va_cmd->Request.Type.Direction = CISS_XFER_READ;

	/*
	 * The Report Logical LUNs command is essentially a vendor-specific
	 * SCSI command, which we assemble into the CDB region of the command
	 * block.
	 */
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
	if (smrt_submit(smrt, smcm) != 0) {
		r = EIO;
		goto out;
	}

	/*
	 * Poll for completion.
	 */
	smcm->smcm_expiry = gethrtime() + timeout * NANOSEC;
	if ((r = smrt_poll_for(smrt, smcm)) != 0) {
		VERIFY(r == ETIMEDOUT);
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

	if ((smrll->smrll_extflag & 0x1) != 0) {
		r = smrt_read_logvols_ext(smrt, smrll);
	} else {
		r = smrt_read_logvols(smrt, smrll);
	}

	if (r == 0) {
		/*
		 * Update the time of the last successful Logical Volume
		 * discovery:
		 */
		smrt->smrt_last_discovery = gethrtime();
	}

out:
	smrt->smrt_status &= ~SMRT_CTLR_STATUS_DISCOVERY;
	cv_broadcast(&smrt->smrt_cv_finishq);
	mutex_exit(&smrt->smrt_mutex);

	if (smcm != NULL) {
		smrt_command_free(smcm);
	}
	return (r);
}

void
smrt_logvol_teardown(smrt_t *smrt)
{
	smrt_volume_t *smlv;

	while ((smlv = list_remove_head(&smrt->smrt_volumes)) != NULL) {
		/*
		 * By this stage of teardown, all of the SCSI target drivers
		 * must have been detached from this logical volume.
		 */
		VERIFY(list_is_empty(&smlv->smlv_targets));
		list_destroy(&smlv->smlv_targets);

		kmem_free(smlv, sizeof (*smlv));
	}
}
