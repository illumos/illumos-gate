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
 * Copyright (c) 2017 Joyent, Inc.
 */

#include <sys/scsi/adapters/smrt/smrt.h>

static void
smrt_physical_free(smrt_physical_t *smpt)
{
	VERIFY(list_is_empty(&smpt->smpt_targets));
	VERIFY(smpt->smpt_info != NULL);

	kmem_free(smpt->smpt_info, sizeof (*smpt->smpt_info));
	list_destroy(&smpt->smpt_targets);
	kmem_free(smpt, sizeof (*smpt));
}

/*
 * Determine if a physical device enumerated should be shown to the world. There
 * are three conditions to satisfy for this to be true.
 *
 * 1. The device (SAS, SATA, SES, etc.) must not have a masked CISS address.  A
 * masked CISS address indicates a device that we should not be performing I/O
 * to.
 * 2. The drive (SAS or SATA device) must not be marked as a member of a logical
 * volume.
 * 3. The drive (SAS or SATA device) must not be marked as a spare.
 */
static boolean_t
smrt_physical_visible(PhysDevAddr_t *addr, smrt_identify_physical_drive_t *info)
{
	if (addr->Mode == SMRT_CISS_MODE_MASKED) {
		return (B_FALSE);
	}

	if ((info->sipd_more_flags & (SMRT_MORE_FLAGS_LOGVOL |
	    SMRT_MORE_FLAGS_SPARE)) != 0) {
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Note, the caller is responsible for making sure that the unit-address form of
 * the WWN is pased in.  Any additional information to target a specific LUN
 * will be ignored.
 */
smrt_physical_t *
smrt_phys_lookup_by_ua(smrt_t *smrt, const char *ua)
{
	VERIFY(MUTEX_HELD(&smrt->smrt_mutex));

	/*
	 * Sanity check that the caller has provided us enough bytes for a
	 * properly formed unit-address form of a WWN.
	 */
	if (strlen(ua) < SCSI_WWN_UA_STRLEN)
		return (NULL);

	for (smrt_physical_t *smpt = list_head(&smrt->smrt_physicals);
	    smpt != NULL; smpt = list_next(&smrt->smrt_physicals, smpt)) {
		char wwnstr[SCSI_WWN_BUFLEN];

		(void) scsi_wwn_to_wwnstr(smpt->smpt_wwn, 1, wwnstr);
		if (strncmp(wwnstr, ua, SCSI_WWN_UA_STRLEN) != 0)
			continue;

		/*
		 * Verify that the UA string is either a comma or null there.
		 * We accept the comma in case it's being used as part of a
		 * normal UA with a LUN.
		 */
		if (ua[SCSI_WWN_UA_STRLEN] != '\0' &&
		    ua[SCSI_WWN_UA_STRLEN] != ',') {
			continue;
		}

		return (smpt);
	}

	return (NULL);
}

static smrt_physical_t *
smrt_phys_lookup_by_wwn(smrt_t *smrt, uint64_t wwn)
{
	VERIFY(MUTEX_HELD(&smrt->smrt_mutex));

	for (smrt_physical_t *smpt = list_head(&smrt->smrt_physicals);
	    smpt != NULL; smpt = list_next(&smrt->smrt_physicals, smpt)) {
		if (wwn == smpt->smpt_wwn)
			return (smpt);
	}

	return (NULL);
}

static int
smrt_phys_identify(smrt_t *smrt, smrt_identify_physical_drive_t *info,
    uint16_t bmic, uint16_t timeout)
{
	smrt_command_t *smcm = NULL;
	smrt_identify_physical_drive_t *sipd;
	smrt_identify_physical_drive_req_t sipdr;
	int ret;
	size_t sz, copysz;

	sz = sizeof (smrt_identify_physical_drive_t);
	sz = P2ROUNDUP_TYPED(sz, 512, size_t);
	if ((smcm = smrt_command_alloc(smrt, SMRT_CMDTYPE_INTERNAL,
	    KM_NOSLEEP)) == NULL || smrt_command_attach_internal(smrt, smcm,
	    sizeof (*sipd), KM_NOSLEEP) != 0) {
		ret = ENOMEM;
		goto out;
	}

	sipd = smcm->smcm_internal->smcmi_va;

	smrt_write_controller_lun_addr(&smcm->smcm_va_cmd->Header.LUN);

	smcm->smcm_va_cmd->Request.CDBLen = sizeof (sipdr);
	smcm->smcm_va_cmd->Request.Timeout = LE_16(timeout);
	smcm->smcm_va_cmd->Request.Type.Type = CISS_TYPE_CMD;
	smcm->smcm_va_cmd->Request.Type.Attribute = CISS_ATTR_SIMPLE;
	smcm->smcm_va_cmd->Request.Type.Direction = CISS_XFER_READ;

	/*
	 * Construct the IDENTIFY PHYSICAL DEVICE request CDB.  Note that any
	 * reserved fields in the request must be filled with zeroes.
	 */
	bzero(&sipdr, sizeof (sipdr));
	sipdr.sipdr_opcode = CISS_SCMD_BMIC_READ;
	sipdr.sipdr_lun = 0;
	sipdr.sipdr_bmic_index1 = bmic & 0x00ff;
	sipdr.sipdr_command = CISS_BMIC_IDENTIFY_PHYSICAL_DEVICE;
	sipdr.sipdr_bmic_index2 = (bmic & 0xff00) >> 8;
	bcopy(&sipdr, &smcm->smcm_va_cmd->Request.CDB[0],
	    MIN(CISS_CDBLEN, sizeof (sipdr)));

	mutex_enter(&smrt->smrt_mutex);

	/*
	 * Send the command to the device.
	 */
	smcm->smcm_status |= SMRT_CMD_STATUS_POLLED;
	if ((ret = smrt_submit(smrt, smcm)) != 0) {
		mutex_exit(&smrt->smrt_mutex);
		goto out;
	}

	/*
	 * Poll for completion.
	 */
	smcm->smcm_expiry = gethrtime() + timeout * NANOSEC;
	if ((ret = smrt_poll_for(smrt, smcm)) != 0) {
		VERIFY3S(ret, ==, ETIMEDOUT);
		VERIFY0(smcm->smcm_status & SMRT_CMD_STATUS_POLL_COMPLETE);

		/*
		 * The command timed out; abandon it now.  Remove the POLLED
		 * flag so that the periodic routine will send an abort to
		 * clean it up next time around.
		 */
		smcm->smcm_status |= SMRT_CMD_STATUS_ABANDONED;
		smcm->smcm_status &= ~SMRT_CMD_STATUS_POLLED;
		smcm = NULL;
		mutex_exit(&smrt->smrt_mutex);
		goto out;
	}
	mutex_exit(&smrt->smrt_mutex);

	if (smcm->smcm_status & SMRT_CMD_STATUS_RESET_SENT) {
		/*
		 * The controller was reset while we were trying to discover
		 * physical volumes.  Report failure.
		 */
		ret = EIO;
		goto out;
	}

	if (smcm->smcm_status & SMRT_CMD_STATUS_ERROR) {
		ErrorInfo_t *ei = smcm->smcm_va_err;

		if (ei->CommandStatus != CISS_CMD_DATA_UNDERRUN) {
			dev_err(smrt->smrt_dip, CE_WARN, "identify physical "
			    "device error: status 0x%x", ei->CommandStatus);
			ret = EIO;
			goto out;
		}

		copysz = MIN(sizeof (*sipd), sz - ei->ResidualCnt);
	} else {
		copysz = sizeof (*sipd);
	}


	sz = MIN(sizeof (*sipd), copysz);
	bcopy(sipd, info, sizeof (*sipd));

	ret = 0;
out:
	if (smcm != NULL) {
		smrt_command_free(smcm);
	}

	return (ret);
}

static int
smrt_read_phys_ext(smrt_t *smrt, smrt_report_physical_lun_t *smrpl,
    uint16_t timeout, uint64_t gen)
{
	smrt_report_physical_lun_extent_t *extents = smrpl->smrpl_data.extents;
	uint32_t count = BE_32(smrpl->smrpl_datasize) /
	    sizeof (smrt_report_physical_lun_extent_t);
	uint32_t i;

	VERIFY(MUTEX_HELD(&smrt->smrt_mutex));

	if (count > SMRT_MAX_PHYSDEV) {
		count = SMRT_MAX_PHYSDEV;
	}

	for (i = 0; i < count; i++) {
		int ret;
		smrt_physical_t *smpt;
		smrt_identify_physical_drive_t *info;
		smrt_report_physical_opdi_t *opdi;
		uint16_t bmic;
		uint64_t wwn, satawwn;
		char name[SCSI_MAXNAMELEN];

		opdi = &extents[i].srple_extdata.srple_opdi;

		mutex_exit(&smrt->smrt_mutex);

		/*
		 * Get the extended information about this device.
		 */
		info = kmem_zalloc(sizeof (*info), KM_NOSLEEP);
		if (info == NULL) {
			mutex_enter(&smrt->smrt_mutex);
			return (ENOMEM);
		}

		bmic = smrt_lun_addr_to_bmic(&extents[i].srple_addr);
		ret = smrt_phys_identify(smrt, info, bmic, timeout);
		if (ret != 0) {
			mutex_enter(&smrt->smrt_mutex);
			kmem_free(info, sizeof (*info));
			return (ret);
		}

		wwn = *(uint64_t *)opdi->srpo_wwid;
		wwn = BE_64(wwn);

		/*
		 * SATA devices may not have a proper WWN returned from firmware
		 * based on the SATL specification.  Try to fetch the proper id
		 * for SATA devices, if the drive has one.  If the drive doesn't
		 * have one or the SATL refuses to give us one, we use whatever
		 * the controller told us.
		 */
		if (opdi->srpo_dtype == SMRT_DTYPE_SATA &&
		    smrt_sata_determine_wwn(smrt, &extents[i].srple_addr,
		    &satawwn, timeout) == 0) {
			wwn = satawwn;
		}

		mutex_enter(&smrt->smrt_mutex);
		smpt = smrt_phys_lookup_by_wwn(smrt, wwn);
		if (smpt != NULL) {
			/*
			 * Sanity check that the model and serial number of this
			 * device is the same for this WWN.  If it's not, the
			 * controller is probably lying about something.
			 */
			if (bcmp(smpt->smpt_info->sipd_model, info->sipd_model,
			    sizeof (info->sipd_model)) != 0 ||
			    bcmp(smpt->smpt_info->sipd_serial,
			    info->sipd_serial, sizeof (info->sipd_serial)) !=
			    0 || smpt->smpt_dtype != opdi->srpo_dtype) {
				dev_err(smrt->smrt_dip, CE_PANIC, "physical "
				    "target with wwn 0x%" PRIx64 " changed "
				    "model, serial, or type unexpectedly: "
				    "smrt_physical_t %p, phys info: %p", wwn,
				    smpt, info);
			}

			/*
			 * When panicking, we don't allow a device's visibility
			 * to change to being invisible and be able to actually
			 * panic.  We only worry about devices which are used
			 * for I/O.  We purposefully ignore SES devices.
			 */
			if (ddi_in_panic() &&
			    (opdi->srpo_dtype == SMRT_DTYPE_SATA ||
			    opdi->srpo_dtype == SMRT_DTYPE_SAS)) {
				boolean_t visible;

				visible = smrt_physical_visible(
				    &smpt->smpt_addr.PhysDev, smpt->smpt_info);

				if (visible != smpt->smpt_visible) {
					dev_err(smrt->smrt_dip, CE_PANIC,
					    "physical target with wwn 0x%"
					    PRIx64 " changed visibility status "
					    "unexpectedly", wwn);
				}
			}

			kmem_free(smpt->smpt_info, sizeof (*smpt->smpt_info));
			smpt->smpt_info = NULL;
		} else {
			smpt = kmem_zalloc(sizeof (smrt_physical_t),
			    KM_NOSLEEP);
			if (smpt == NULL) {
				kmem_free(info, sizeof (*info));
				return (ENOMEM);
			}

			smpt->smpt_wwn = wwn;
			smpt->smpt_dtype = opdi->srpo_dtype;
			list_create(&smpt->smpt_targets, sizeof (smrt_target_t),
			    offsetof(smrt_target_t, smtg_link_lun));
			smpt->smpt_ctlr = smrt;
			list_insert_tail(&smrt->smrt_physicals, smpt);
		}

		VERIFY3P(smpt->smpt_info, ==, NULL);

		/*
		 * Determine if this device is supported and if it's visible to
		 * the system.  Some devices may not be visible to the system
		 * because they're used in logical volumes or spares.
		 * Unsupported devices are also not visible.
		 */
		switch (smpt->smpt_dtype) {
		case SMRT_DTYPE_SATA:
		case SMRT_DTYPE_SAS:
			smpt->smpt_supported = B_TRUE;
			smpt->smpt_visible =
			    smrt_physical_visible(&extents[i].srple_addr, info);
			break;
		case SMRT_DTYPE_SES:
			smpt->smpt_supported = B_TRUE;
			smpt->smpt_visible =
			    smrt_physical_visible(&extents[i].srple_addr, info);
			break;
		default:
			smpt->smpt_visible = B_FALSE;
			smpt->smpt_supported = B_FALSE;
		}

		smpt->smpt_info = info;
		smpt->smpt_addr.PhysDev = extents[i].srple_addr;
		smpt->smpt_bmic = bmic;
		smpt->smpt_gen = gen;
		(void) scsi_wwn_to_wwnstr(smpt->smpt_wwn, 1, name);
		if (!ddi_in_panic() && smpt->smpt_visible &&
		    scsi_hba_tgtmap_set_add(smrt->smrt_phys_tgtmap,
		    SCSI_TGT_SCSI_DEVICE, name, NULL) != DDI_SUCCESS) {
			return (EIO);
		}
	}

	return (0);
}

int
smrt_phys_discover(smrt_t *smrt, uint16_t timeout, uint64_t gen)
{
	smrt_command_t *smcm;
	smrt_report_physical_lun_t *smrpl;
	smrt_report_physical_lun_req_t smrplr;
	int r;

	/*
	 * Allocate the command to send to the device, including buffer space
	 * for the returned list of Physical Volumes.
	 */
	if ((smcm = smrt_command_alloc(smrt, SMRT_CMDTYPE_INTERNAL,
	    KM_NOSLEEP)) == NULL || smrt_command_attach_internal(smrt, smcm,
	    sizeof (*smrpl), KM_NOSLEEP) != 0) {
		r = ENOMEM;
		mutex_enter(&smrt->smrt_mutex);
		goto out;
	}

	smrpl = smcm->smcm_internal->smcmi_va;

	smrt_write_controller_lun_addr(&smcm->smcm_va_cmd->Header.LUN);

	smcm->smcm_va_cmd->Request.CDBLen = sizeof (smrplr);
	smcm->smcm_va_cmd->Request.Timeout = LE_16(timeout);
	smcm->smcm_va_cmd->Request.Type.Type = CISS_TYPE_CMD;
	smcm->smcm_va_cmd->Request.Type.Attribute = CISS_ATTR_SIMPLE;
	smcm->smcm_va_cmd->Request.Type.Direction = CISS_XFER_READ;

	/*
	 * The Report Physical LUNs command is essentially a vendor-specific
	 * SCSI command, which we assemble into the CDB region of the command
	 * block.
	 */
	bzero(&smrplr, sizeof (smrplr));
	smrplr.smrplr_opcode = CISS_SCMD_REPORT_PHYSICAL_LUNS;
	smrplr.smrplr_extflag = SMRT_REPORT_PHYSICAL_LUN_EXT_OPDI;
	smrplr.smrplr_datasize = BE_32(sizeof (smrt_report_physical_lun_t));
	bcopy(&smrplr, &smcm->smcm_va_cmd->Request.CDB[0],
	    MIN(CISS_CDBLEN, sizeof (smrplr)));

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
		 *
		 * The controller was reset while we were trying to discover
		 * logical volumes.  Report failure.
		 */
		r = EIO;
		goto out;
	}

	if (smcm->smcm_status & SMRT_CMD_STATUS_ERROR) {
		ErrorInfo_t *ei = smcm->smcm_va_err;

		if (ei->CommandStatus != CISS_CMD_DATA_UNDERRUN) {
			dev_err(smrt->smrt_dip, CE_WARN, "physical target "
			    "discovery error: status 0x%x", ei->CommandStatus);
			r = EIO;
			goto out;
		}
	}

	/*
	 * If the controller doesn't support extended physical reporting, it
	 * likely doesn't even support physical devices that we'd care about
	 * exposing.  As such, we treat this as an OK case.
	 */
	if ((smrpl->smrpl_extflag & SMRT_REPORT_PHYSICAL_LUN_EXT_MASK) !=
	    SMRT_REPORT_PHYSICAL_LUN_EXT_OPDI) {
		r = 0;
		goto out;
	}

	if (!ddi_in_panic() &&
	    scsi_hba_tgtmap_set_begin(smrt->smrt_phys_tgtmap) != DDI_SUCCESS) {
		dev_err(smrt->smrt_dip, CE_WARN, "failed to begin target map "
		    "observation on %s", SMRT_IPORT_PHYS);
		r = EIO;
		goto out;
	}

	r = smrt_read_phys_ext(smrt, smrpl, timeout, gen);

	if (r == 0 && !ddi_in_panic()) {
		if (scsi_hba_tgtmap_set_end(smrt->smrt_phys_tgtmap, 0) !=
		    DDI_SUCCESS) {
			dev_err(smrt->smrt_dip, CE_WARN, "failed to end target "
			    "map observation on %s", SMRT_IPORT_PHYS);
			r = EIO;
		}
	} else if (r != 0 && !ddi_in_panic()) {
		if (scsi_hba_tgtmap_set_flush(smrt->smrt_phys_tgtmap) !=
		    DDI_SUCCESS) {
			dev_err(smrt->smrt_dip, CE_WARN, "failed to end target "
			    "map observation on %s", SMRT_IPORT_PHYS);
			r = EIO;
		}
	}

	if (r == 0) {
		smrt_physical_t *smpt, *next;

		/*
		 * Prune physical devices that do not match the current
		 * generation and are not marked as visible devices.  Visible
		 * devices will be dealt with as part of the target map work.
		 */
		for (smpt = list_head(&smrt->smrt_physicals), next = NULL;
		    smpt != NULL; smpt = next) {
			next = list_next(&smrt->smrt_physicals, smpt);
			if (smpt->smpt_visible || smpt->smpt_gen == gen)
				continue;
			list_remove(&smrt->smrt_physicals, smpt);
			smrt_physical_free(smpt);
		}

		/*
		 * Update the time of the last successful Physical Volume
		 * discovery:
		 */
		smrt->smrt_last_phys_discovery = gethrtime();

		/*
		 * Now, for each unsupported device that we haven't warned about
		 * encountering, try and give the administrator some hope of
		 * knowing about this.
		 */
		for (smpt = list_head(&smrt->smrt_physicals), next = NULL;
		    smpt != NULL; smpt = next) {
			if (smpt->smpt_supported || smpt->smpt_unsup_warn)
				continue;
			smpt->smpt_unsup_warn = B_TRUE;
			dev_err(smrt->smrt_dip, CE_WARN, "encountered "
			    "unsupported device with device type %d",
			    smpt->smpt_dtype);
		}
	}

out:
	mutex_exit(&smrt->smrt_mutex);

	if (smcm != NULL) {
		smrt_command_free(smcm);
	}
	return (r);
}

void
smrt_phys_tgtmap_activate(void *arg, char *addr, scsi_tgtmap_tgt_type_t type,
    void **privpp)
{
	smrt_t *smrt = arg;
	smrt_physical_t *smpt;

	VERIFY3S(type, ==, SCSI_TGT_SCSI_DEVICE);
	mutex_enter(&smrt->smrt_mutex);
	smpt = smrt_phys_lookup_by_ua(smrt, addr);
	VERIFY(smpt != NULL);
	VERIFY(smpt->smpt_supported);
	VERIFY(smpt->smpt_visible);
	*privpp = NULL;
	mutex_exit(&smrt->smrt_mutex);
}

boolean_t
smrt_phys_tgtmap_deactivate(void *arg, char *addr, scsi_tgtmap_tgt_type_t type,
    void *priv, scsi_tgtmap_deact_rsn_t reason)
{
	smrt_t *smrt = arg;
	smrt_physical_t *smpt;

	VERIFY3S(type, ==, SCSI_TGT_SCSI_DEVICE);
	VERIFY3P(priv, ==, NULL);

	mutex_enter(&smrt->smrt_mutex);
	smpt = smrt_phys_lookup_by_ua(smrt, addr);

	/*
	 * If the device disappeared or became invisible, then it may have
	 * already been removed.
	 */
	if (smpt == NULL || !smpt->smpt_visible) {
		mutex_exit(&smrt->smrt_mutex);
		return (B_FALSE);
	}

	list_remove(&smrt->smrt_physicals, smpt);
	smrt_physical_free(smpt);
	mutex_exit(&smrt->smrt_mutex);
	return (B_FALSE);
}

void
smrt_phys_teardown(smrt_t *smrt)
{
	smrt_physical_t *smpt;

	VERIFY(MUTEX_HELD(&smrt->smrt_mutex));
	while ((smpt = list_remove_head(&smrt->smrt_physicals)) != NULL) {
		smrt_physical_free(smpt);
	}
}
