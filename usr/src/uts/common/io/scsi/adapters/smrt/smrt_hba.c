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

/*
 * The controller is not allowed to attach.
 */
static int
smrt_ctrl_tran_tgt_init(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd)
{
	return (DDI_FAILURE);
}

/*
 * The controller is not allowed to send packets.
 */
static int
smrt_ctrl_tran_start(struct scsi_address *sa, struct scsi_pkt *pkt)
{
	return (TRAN_BADPKT);
}

static boolean_t
smrt_logvol_parse(const char *ua, uint_t *targp)
{
	long targ, lun;
	const char *comma;
	char *eptr;

	comma = strchr(ua, ',');
	if (comma == NULL) {
		return (B_FALSE);
	}

	/*
	 * We expect the target number for a logical unit number to be zero for
	 * a logical volume.
	 */
	if (ddi_strtol(comma + 1, &eptr, 16, &lun) != 0 || *eptr != '\0' ||
	    lun != 0) {
		return (B_FALSE);
	}

	if (ddi_strtol(ua, &eptr, 16, &targ) != 0 || eptr != comma ||
	    targ < 0 || targ >= SMRT_MAX_LOGDRV) {
		return (B_FALSE);
	}

	*targp = (uint_t)targ;

	return (B_TRUE);
}

static int
smrt_logvol_tran_tgt_init(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd)
{
	_NOTE(ARGUNUSED(hba_dip))

	smrt_volume_t *smlv;
	smrt_target_t *smtg;
	const char *ua;
	uint_t targ;

	smrt_t *smrt = (smrt_t *)hba_tran->tran_hba_private;
	dev_info_t *dip = smrt->smrt_dip;

	/*
	 * The unit address comes in the form of 'target,lun'.  We expect the
	 * lun to be zero.  The target is what we set when we added it to the
	 * target map earlier.
	 */
	ua = scsi_device_unit_address(sd);
	if (ua == NULL) {
		return (DDI_FAILURE);
	}

	if (!smrt_logvol_parse(ua, &targ)) {
		return (DDI_FAILURE);
	}

	if ((smtg = kmem_zalloc(sizeof (*smtg), KM_NOSLEEP)) == NULL) {
		dev_err(dip, CE_WARN, "could not allocate target object "
		    "due to memory exhaustion");
		return (DDI_FAILURE);
	}

	mutex_enter(&smrt->smrt_mutex);

	if (smrt->smrt_status & SMRT_CTLR_STATUS_DETACHING) {
		/*
		 * We are detaching.  Do not accept any more requests to
		 * attach targets from the framework.
		 */
		mutex_exit(&smrt->smrt_mutex);
		kmem_free(smtg, sizeof (*smtg));
		return (DDI_FAILURE);
	}

	/*
	 * Look for a logical volume for the SCSI unit address of this target.
	 */
	if ((smlv = smrt_logvol_lookup_by_id(smrt, targ)) == NULL) {
		mutex_exit(&smrt->smrt_mutex);
		kmem_free(smtg, sizeof (*smtg));
		return (DDI_FAILURE);
	}

	smtg->smtg_lun.smtg_vol = smlv;
	smtg->smtg_addr = &smlv->smlv_addr;
	smtg->smtg_physical = B_FALSE;
	list_insert_tail(&smlv->smlv_targets, smtg);

	/*
	 * Link this target object to the controller:
	 */
	smtg->smtg_ctlr = smrt;
	list_insert_tail(&smrt->smrt_targets, smtg);

	smtg->smtg_scsi_dev = sd;
	VERIFY(sd->sd_dev == tgt_dip);

	scsi_device_hba_private_set(sd, smtg);

	mutex_exit(&smrt->smrt_mutex);
	return (DDI_SUCCESS);
}

static void
smrt_logvol_tran_tgt_free(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd)
{
	_NOTE(ARGUNUSED(hba_dip, tgt_dip))

	smrt_t *smrt = (smrt_t *)hba_tran->tran_hba_private;
	smrt_target_t *smtg = scsi_device_hba_private_get(sd);
	smrt_volume_t *smlv = smtg->smtg_lun.smtg_vol;

	VERIFY(smtg->smtg_scsi_dev == sd);
	VERIFY(smtg->smtg_physical == B_FALSE);

	mutex_enter(&smrt->smrt_mutex);
	list_remove(&smlv->smlv_targets, smtg);
	list_remove(&smrt->smrt_targets, smtg);

	scsi_device_hba_private_set(sd, NULL);

	mutex_exit(&smrt->smrt_mutex);

	kmem_free(smtg, sizeof (*smtg));
}

static int
smrt_phys_tran_tgt_init(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd)
{
	_NOTE(ARGUNUSED(hba_dip))

	smrt_target_t *smtg;
	smrt_physical_t *smpt;
	const char *ua, *comma;
	char *eptr;
	long lun;

	smrt_t *smrt = (smrt_t *)hba_tran->tran_hba_private;
	dev_info_t *dip = smrt->smrt_dip;

	/*
	 * The unit address comes in the form of 'target,lun'.  We expect the
	 * lun to be zero.  The target is what we set when we added it to the
	 * target map earlier.
	 */
	ua = scsi_device_unit_address(sd);
	if (ua == NULL)
		return (DDI_FAILURE);

	comma = strchr(ua, ',');
	if (comma == NULL) {
		return (DDI_FAILURE);
	}

	/*
	 * Confirm the LUN is zero.  We may want to instead check the scsi
	 * 'lun'/'lun64' property or do so in addition to this logic.
	 */
	if (ddi_strtol(comma + 1, &eptr, 16, &lun) != 0 || *eptr != '\0' ||
	    lun != 0) {
		return (DDI_FAILURE);
	}

	if ((smtg = kmem_zalloc(sizeof (*smtg), KM_NOSLEEP)) == NULL) {
		dev_err(dip, CE_WARN, "could not allocate target object "
		    "due to memory exhaustion");
		return (DDI_FAILURE);
	}

	mutex_enter(&smrt->smrt_mutex);

	if (smrt->smrt_status & SMRT_CTLR_STATUS_DETACHING) {
		/*
		 * We are detaching.  Do not accept any more requests to
		 * attach targets from the framework.
		 */
		mutex_exit(&smrt->smrt_mutex);
		kmem_free(smtg, sizeof (*smtg));
		return (DDI_FAILURE);
	}


	/*
	 * Look for a physical target based on the unit address of the target
	 * (which will encode its WWN and LUN).
	 */
	smpt = smrt_phys_lookup_by_ua(smrt, ua);
	if (smpt == NULL) {
		mutex_exit(&smrt->smrt_mutex);
		kmem_free(smtg, sizeof (*smtg));
		return (DDI_FAILURE);
	}

	smtg->smtg_scsi_dev = sd;
	smtg->smtg_physical = B_TRUE;
	smtg->smtg_lun.smtg_phys = smpt;
	list_insert_tail(&smpt->smpt_targets, smtg);
	smtg->smtg_addr = &smpt->smpt_addr;

	/*
	 * Link this target object to the controller:
	 */
	smtg->smtg_ctlr = smrt;
	list_insert_tail(&smrt->smrt_targets, smtg);

	VERIFY(sd->sd_dev == tgt_dip);
	smtg->smtg_scsi_dev = sd;

	scsi_device_hba_private_set(sd, smtg);
	mutex_exit(&smrt->smrt_mutex);

	return (DDI_SUCCESS);
}

static void
smrt_phys_tran_tgt_free(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd)
{
	_NOTE(ARGUNUSED(hba_dip, tgt_dip))

	smrt_t *smrt = (smrt_t *)hba_tran->tran_hba_private;
	smrt_target_t *smtg = scsi_device_hba_private_get(sd);
	smrt_physical_t *smpt = smtg->smtg_lun.smtg_phys;

	VERIFY(smtg->smtg_scsi_dev == sd);
	VERIFY(smtg->smtg_physical == B_TRUE);

	mutex_enter(&smrt->smrt_mutex);
	list_remove(&smpt->smpt_targets, smtg);
	list_remove(&smrt->smrt_targets, smtg);

	scsi_device_hba_private_set(sd, NULL);
	mutex_exit(&smrt->smrt_mutex);
	kmem_free(smtg, sizeof (*smtg));
}

/*
 * This function is called when the SCSI framework has allocated a packet and
 * our private per-packet object.
 *
 * We choose not to have the framework pre-allocate memory for the CDB.
 * Instead, we will make available the CDB area in the controller command block
 * itself.
 *
 * Status block memory is allocated by the framework because we passed
 * SCSI_HBA_TRAN_SCB to scsi_hba_attach_setup(9F).
 */
static int
smrt_tran_setup_pkt(struct scsi_pkt *pkt, int (*callback)(caddr_t),
    caddr_t arg)
{
	_NOTE(ARGUNUSED(arg))

	struct scsi_device *sd;
	smrt_target_t *smtg;
	smrt_t *smrt;
	smrt_command_t *smcm;
	smrt_command_scsa_t *smcms;
	int kmflags = callback == SLEEP_FUNC ? KM_SLEEP : KM_NOSLEEP;

	sd = scsi_address_device(&pkt->pkt_address);
	VERIFY(sd != NULL);
	smtg = scsi_device_hba_private_get(sd);
	VERIFY(smtg != NULL);
	smrt = smtg->smtg_ctlr;
	VERIFY(smrt != NULL);
	smcms = (smrt_command_scsa_t *)pkt->pkt_ha_private;

	/*
	 * Check that we have enough space in the command object for the
	 * request from the target driver:
	 */
	if (pkt->pkt_cdblen > CISS_CDBLEN) {
		/*
		 * The CDB member of the Request Block of a controller
		 * command is fixed at 16 bytes.
		 */
		dev_err(smrt->smrt_dip, CE_WARN, "oversize CDB: had %u, "
		    "needed %u", CISS_CDBLEN, pkt->pkt_cdblen);
		return (-1);
	}

	/*
	 * Allocate our command block:
	 */
	if ((smcm = smrt_command_alloc(smrt, SMRT_CMDTYPE_SCSA,
	    kmflags)) == NULL) {
		return (-1);
	}
	smcm->smcm_scsa = smcms;
	smcms->smcms_command = smcm;
	smcms->smcms_pkt = pkt;

	pkt->pkt_cdbp = &smcm->smcm_va_cmd->Request.CDB[0];
	smcm->smcm_va_cmd->Request.CDBLen = pkt->pkt_cdblen;

	smcm->smcm_target = smtg;

	return (0);
}

static void
smrt_tran_teardown_pkt(struct scsi_pkt *pkt)
{
	smrt_command_scsa_t *smcms = (smrt_command_scsa_t *)
	    pkt->pkt_ha_private;
	smrt_command_t *smcm = smcms->smcms_command;

	smrt_command_free(smcm);

	pkt->pkt_cdbp = NULL;
}

static void
smrt_set_arq_data(struct scsi_pkt *pkt, uchar_t key)
{
	struct scsi_arq_status *sts;

	VERIFY3U(pkt->pkt_scblen, >=, sizeof (struct scsi_arq_status));

	/* LINTED: E_BAD_PTR_CAST_ALIGN */
	sts = (struct scsi_arq_status *)(pkt->pkt_scbp);
	bzero(sts, sizeof (*sts));

	/*
	 * Mock up a CHECK CONDITION SCSI status for the original command:
	 */
	sts->sts_status.sts_chk = 1;

	/*
	 * Pretend that we successfully performed REQUEST SENSE:
	 */
	sts->sts_rqpkt_reason = CMD_CMPLT;
	sts->sts_rqpkt_resid = 0;
	sts->sts_rqpkt_state = STATE_GOT_BUS | STATE_GOT_TARGET |
	    STATE_SENT_CMD | STATE_XFERRED_DATA;
	sts->sts_rqpkt_statistics = 0;

	/*
	 * Return the key value we were provided in the fake sense data:
	 */
	sts->sts_sensedata.es_valid = 1;
	sts->sts_sensedata.es_class = CLASS_EXTENDED_SENSE;
	sts->sts_sensedata.es_key = key;

	pkt->pkt_state |= STATE_ARQ_DONE;
}

/*
 * When faking up a REPORT LUNS data structure, we simply report one LUN, LUN 0.
 * We need 16 bytes for this, 4 for the size, 4 reserved bytes, and the 8 for
 * the actual LUN.
 */
static void
smrt_fake_report_lun(smrt_command_t *smcm, struct scsi_pkt *pkt)
{
	size_t sz;
	char resp[16];
	struct buf *bp;

	pkt->pkt_reason = CMD_CMPLT;
	pkt->pkt_state |= STATE_GOT_BUS | STATE_GOT_TARGET | STATE_SENT_CMD |
	    STATE_GOT_STATUS;

	/*
	 * Check to make sure this is valid.  If reserved bits are set or if the
	 * mode is one other than 0x00, 0x01, 0x02, then it's an illegal
	 * request.
	 */
	if (pkt->pkt_cdbp[1] != 0 || pkt->pkt_cdbp[3] != 0 ||
	    pkt->pkt_cdbp[4] != 0 || pkt->pkt_cdbp[5] != 0 ||
	    pkt->pkt_cdbp[10] != 0 || pkt->pkt_cdbp[11] != 0 ||
	    pkt->pkt_cdbp[2] > 0x2) {
		smrt_set_arq_data(pkt, KEY_ILLEGAL_REQUEST);
		return;
	}

	/*
	 * Construct the actual REPORT LUNS reply.  We need to indicate a single
	 * LUN of all zeros.  This means that the length needs to be 8 bytes,
	 * the size of the lun.  Otherwise, the rest of this structure can be
	 * zeros.
	 */
	bzero(resp, sizeof (resp));
	resp[3] = sizeof (scsi_lun_t);

	bp = scsi_pkt2bp(pkt);
	sz = MIN(sizeof (resp), bp->b_bcount);

	bp_mapin(bp);
	bcopy(resp, bp->b_un.b_addr, sz);
	bp_mapout(bp);
	pkt->pkt_state |= STATE_XFERRED_DATA;
	pkt->pkt_resid = bp->b_bcount - sz;
	if (pkt->pkt_scblen >= 1) {
		pkt->pkt_scbp[0] = STATUS_GOOD;
	}
}

static int
smrt_tran_start(struct scsi_address *sa, struct scsi_pkt *pkt)
{
	_NOTE(ARGUNUSED(sa))

	struct scsi_device *sd;
	smrt_target_t *smtg;
	smrt_t *smrt;
	smrt_command_scsa_t *smcms;
	smrt_command_t *smcm;
	int r;

	sd = scsi_address_device(&pkt->pkt_address);
	VERIFY(sd != NULL);
	smtg = scsi_device_hba_private_get(sd);
	VERIFY(smtg != NULL);
	smrt = smtg->smtg_ctlr;
	VERIFY(smrt != NULL);
	smcms = (smrt_command_scsa_t *)pkt->pkt_ha_private;
	VERIFY(smcms != NULL);
	smcm = smcms->smcms_command;
	VERIFY(smcm != NULL);

	if (smcm->smcm_status & SMRT_CMD_STATUS_TRAN_START) {
		/*
		 * This is a retry of a command that has already been
		 * used once.  Assign it a new tag number.
		 */
		smrt_command_reuse(smcm);
	}
	smcm->smcm_status |= SMRT_CMD_STATUS_TRAN_START;

	/*
	 * The sophisticated firmware in this controller cannot possibly bear
	 * the following SCSI commands.  It appears to return a response with
	 * the status STATUS_ACA_ACTIVE (0x30), which is not something we
	 * expect.  Instead, fake up a failure response.
	 */
	switch (pkt->pkt_cdbp[0]) {
	case SCMD_FORMAT:
	case SCMD_LOG_SENSE_G1:
	case SCMD_MODE_SELECT:
	case SCMD_PERSISTENT_RESERVE_IN:
		if (smtg->smtg_physical) {
			break;
		}

		smrt->smrt_stats.smrts_ignored_scsi_cmds++;
		smcm->smcm_status |= SMRT_CMD_STATUS_TRAN_IGNORED;

		/*
		 * Mark the command as completed to the point where we
		 * received a SCSI status code:
		 */
		pkt->pkt_reason = CMD_CMPLT;
		pkt->pkt_state |= STATE_GOT_BUS | STATE_GOT_TARGET |
		    STATE_SENT_CMD | STATE_GOT_STATUS;

		/*
		 * Mock up sense data for an illegal request:
		 */
		smrt_set_arq_data(pkt, KEY_ILLEGAL_REQUEST);

		scsi_hba_pkt_comp(pkt);
		return (TRAN_ACCEPT);
	case SCMD_REPORT_LUNS:
		/*
		 * The SMRT controller does not accept a REPORT LUNS command for
		 * logical volumes.  As such, we need to fake up a REPORT LUNS
		 * response that has a single LUN, LUN 0.
		 */
		if (smtg->smtg_physical) {
			break;
		}

		smrt_fake_report_lun(smcm, pkt);

		scsi_hba_pkt_comp(pkt);
		return (TRAN_ACCEPT);
	default:
		break;
	}

	if (pkt->pkt_flags & FLAG_NOINTR) {
		/*
		 * We must sleep and wait for the completion of this command.
		 */
		smcm->smcm_status |= SMRT_CMD_STATUS_POLLED;
	}

	/*
	 * Because we provide a tran_setup_pkt(9E) entrypoint, we must now
	 * set up the Scatter/Gather List in the Command to reflect any
	 * DMA resources passed to us by the framework.
	 */
	if (pkt->pkt_numcookies > smrt->smrt_sg_cnt) {
		/*
		 * More DMA cookies than we are prepared to handle.
		 */
		dev_err(smrt->smrt_dip, CE_WARN, "too many DMA cookies (got %u;"
		    " expected %u)", pkt->pkt_numcookies, smrt->smrt_sg_cnt);
		return (TRAN_BADPKT);
	}
	smcm->smcm_va_cmd->Header.SGList = pkt->pkt_numcookies;
	smcm->smcm_va_cmd->Header.SGTotal = pkt->pkt_numcookies;
	for (unsigned i = 0; i < pkt->pkt_numcookies; i++) {
		smcm->smcm_va_cmd->SG[i].Addr =
		    LE_64(pkt->pkt_cookies[i].dmac_laddress);
		smcm->smcm_va_cmd->SG[i].Len =
		    LE_32(pkt->pkt_cookies[i].dmac_size);
	}

	/*
	 * Copy logical volume address from the target object:
	 */
	smcm->smcm_va_cmd->Header.LUN = *smcm->smcm_target->smtg_addr;

	/*
	 * Initialise the command block.
	 */
	smcm->smcm_va_cmd->Request.CDBLen = pkt->pkt_cdblen;
	smcm->smcm_va_cmd->Request.Type.Type = CISS_TYPE_CMD;
	smcm->smcm_va_cmd->Request.Type.Attribute = CISS_ATTR_SIMPLE;
	smcm->smcm_va_cmd->Request.Timeout = LE_16(pkt->pkt_time);
	if (pkt->pkt_numcookies > 0) {
		/*
		 * There are DMA resources; set the transfer direction
		 * appropriately:
		 */
		if (pkt->pkt_dma_flags & DDI_DMA_READ) {
			smcm->smcm_va_cmd->Request.Type.Direction =
			    CISS_XFER_READ;
		} else if (pkt->pkt_dma_flags & DDI_DMA_WRITE) {
			smcm->smcm_va_cmd->Request.Type.Direction =
			    CISS_XFER_WRITE;
		} else {
			smcm->smcm_va_cmd->Request.Type.Direction =
			    CISS_XFER_NONE;
		}
	} else {
		/*
		 * No DMA resources means no transfer.
		 */
		smcm->smcm_va_cmd->Request.Type.Direction = CISS_XFER_NONE;
	}

	/*
	 * Initialise the SCSI packet as described in tran_start(9E).  We will
	 * progressively update these fields as the command moves through the
	 * submission and completion states.
	 */
	pkt->pkt_resid = 0;
	pkt->pkt_reason = CMD_CMPLT;
	pkt->pkt_statistics = 0;
	pkt->pkt_state = 0;

	/*
	 * If this SCSI packet has a timeout, configure an appropriate
	 * expiry time:
	 */
	if (pkt->pkt_time != 0) {
		smcm->smcm_expiry = gethrtime() + pkt->pkt_time * NANOSEC;
	}

	/*
	 * Submit the command to the controller.
	 */
	mutex_enter(&smrt->smrt_mutex);

	/*
	 * If we're dumping, there's a chance that the target we're talking to
	 * could have ended up disappearing during the process of discovery.  If
	 * this target is part of the dump device, we check here and return that
	 * we hit a fatal error.
	 */
	if (ddi_in_panic() && smtg->smtg_gone) {
		mutex_exit(&smrt->smrt_mutex);

		dev_err(smrt->smrt_dip, CE_WARN, "smrt_submit failed: target "
		    "%s is gone, it did not come back after post-panic reset "
		    "device discovery", scsi_device_unit_address(sd));

		return (TRAN_FATAL_ERROR);
	}

	smrt->smrt_stats.smrts_tran_starts++;
	if ((r = smrt_submit(smrt, smcm)) != 0) {
		mutex_exit(&smrt->smrt_mutex);

		dev_err(smrt->smrt_dip, CE_WARN, "smrt_submit failed %d", r);

		/*
		 * Inform the SCSI framework that we could not submit
		 * the command.
		 */
		return (r == EAGAIN ? TRAN_BUSY : TRAN_FATAL_ERROR);
	}

	/*
	 * Update the SCSI packet to reflect submission of the command.
	 */
	pkt->pkt_state |= STATE_GOT_BUS | STATE_GOT_TARGET | STATE_SENT_CMD;

	if (pkt->pkt_flags & FLAG_NOINTR) {
		/*
		 * Poll the controller for completion of the command we
		 * submitted.  Once this routine has returned, the completion
		 * callback will have been fired with either an active response
		 * (success or error) or a timeout.  The command is freed by
		 * the completion callback, so it may not be referenced again
		 * after this call returns.
		 */
		smrt_poll_for(smrt, smcm);
	}

	mutex_exit(&smrt->smrt_mutex);
	return (TRAN_ACCEPT);
}

static int
smrt_tran_reset(struct scsi_address *sa, int level)
{
	_NOTE(ARGUNUSED(level))

	struct scsi_device *sd;
	smrt_target_t *smtg;
	smrt_t *smrt;
	smrt_command_t *smcm;
	int r;

	sd = scsi_address_device(sa);
	VERIFY(sd != NULL);
	smtg = scsi_device_hba_private_get(sd);
	VERIFY(smtg != NULL);
	smrt = smtg->smtg_ctlr;

	/*
	 * The framework has requested some kind of SCSI reset.  A
	 * controller-level soft reset can take a very long time -- often on
	 * the order of 30-60 seconds -- but might well be our only option if
	 * the controller is non-responsive.
	 *
	 * First, check if the controller is responding to pings.
	 */
again:
	if ((smcm = smrt_command_alloc(smrt, SMRT_CMDTYPE_INTERNAL,
	    KM_NOSLEEP)) == NULL) {
		return (0);
	}

	smrt_write_message_nop(smcm, SMRT_PING_CHECK_TIMEOUT);

	mutex_enter(&smrt->smrt_mutex);
	smrt->smrt_stats.smrts_tran_resets++;
	if (ddi_in_panic()) {
		goto skip_check;
	}

	if (smrt->smrt_status & SMRT_CTLR_STATUS_RESETTING) {
		/*
		 * The controller is already resetting.  Wait for that
		 * to finish.
		 */
		while (smrt->smrt_status & SMRT_CTLR_STATUS_RESETTING) {
			cv_wait(&smrt->smrt_cv_finishq, &smrt->smrt_mutex);
		}
	}

skip_check:
	/*
	 * Submit our ping to the controller.
	 */
	smcm->smcm_status |= SMRT_CMD_STATUS_POLLED;
	smcm->smcm_expiry = gethrtime() + SMRT_PING_CHECK_TIMEOUT * NANOSEC;
	if (smrt_submit(smrt, smcm) != 0) {
		mutex_exit(&smrt->smrt_mutex);
		smrt_command_free(smcm);
		return (0);
	}

	if ((r = smrt_poll_for(smrt, smcm)) != 0) {
		VERIFY3S(r, ==, ETIMEDOUT);
		VERIFY0(smcm->smcm_status & SMRT_CMD_STATUS_POLL_COMPLETE);

		/*
		 * The ping command timed out.  Abandon it now.
		 */
		dev_err(smrt->smrt_dip, CE_WARN, "controller ping timed out");
		smcm->smcm_status |= SMRT_CMD_STATUS_ABANDONED;
		smcm->smcm_status &= ~SMRT_CMD_STATUS_POLLED;

	} else if ((smcm->smcm_status & SMRT_CMD_STATUS_RESET_SENT) ||
	    (smcm->smcm_status & SMRT_CMD_STATUS_ERROR)) {
		/*
		 * The command completed in error, or a controller reset
		 * was sent while we were trying to ping.
		 */
		dev_err(smrt->smrt_dip, CE_WARN, "controller ping error");
		mutex_exit(&smrt->smrt_mutex);
		smrt_command_free(smcm);
		mutex_enter(&smrt->smrt_mutex);

	} else {
		VERIFY(smcm->smcm_status & SMRT_CMD_STATUS_COMPLETE);

		/*
		 * The controller is responsive, and a full soft reset would be
		 * extremely disruptive to the system.  Given our spotty
		 * support for some SCSI commands (which can upset the target
		 * drivers) and the historically lax behaviour of the "smrt"
		 * driver, we grit our teeth and pretend we were able to
		 * perform a reset.
		 */
		mutex_exit(&smrt->smrt_mutex);
		smrt_command_free(smcm);
		return (1);
	}

	/*
	 * If a reset has been initiated in the last 90 seconds, try
	 * another ping.
	 */
	if (gethrtime() < smrt->smrt_last_reset_start + 90 * NANOSEC) {
		dev_err(smrt->smrt_dip, CE_WARN, "controller ping failed, but "
		    "was recently reset; retrying ping");
		mutex_exit(&smrt->smrt_mutex);

		/*
		 * Sleep for a second first.
		 */
		if (ddi_in_panic()) {
			drv_usecwait(1 * MICROSEC);
		} else {
			delay(drv_usectohz(1 * MICROSEC));
		}
		goto again;
	}

	dev_err(smrt->smrt_dip, CE_WARN, "controller ping failed; resetting "
	    "controller");
	if (smrt_ctlr_reset(smrt) != 0) {
		dev_err(smrt->smrt_dip, CE_WARN, "controller reset failure");
		mutex_exit(&smrt->smrt_mutex);
		return (0);
	}

	mutex_exit(&smrt->smrt_mutex);
	return (1);
}

static int
smrt_tran_abort(struct scsi_address *sa, struct scsi_pkt *pkt)
{
	struct scsi_device *sd;
	smrt_target_t *smtg;
	smrt_t *smrt;
	smrt_command_t *smcm = NULL;
	smrt_command_t *abort_smcm;

	sd = scsi_address_device(sa);
	VERIFY(sd != NULL);
	smtg = scsi_device_hba_private_get(sd);
	VERIFY(smtg != NULL);
	smrt = smtg->smtg_ctlr;
	VERIFY(smrt != NULL);


	if ((abort_smcm = smrt_command_alloc(smrt, SMRT_CMDTYPE_INTERNAL,
	    KM_NOSLEEP)) == NULL) {
		/*
		 * No resources available to send an abort message.
		 */
		return (0);
	}

	mutex_enter(&smrt->smrt_mutex);
	smrt->smrt_stats.smrts_tran_aborts++;
	if (pkt != NULL) {
		/*
		 * The framework wants us to abort a specific SCSI packet.
		 */
		smrt_command_scsa_t *smcms = (smrt_command_scsa_t *)
		    pkt->pkt_ha_private;
		smcm = smcms->smcms_command;

		if (!(smcm->smcm_status & SMRT_CMD_STATUS_INFLIGHT)) {
			/*
			 * This message is not currently in flight, so we
			 * cannot abort it.
			 */
			goto fail;
		}

		if (smcm->smcm_status & SMRT_CMD_STATUS_ABORT_SENT) {
			/*
			 * An abort message for this command has already been
			 * sent to the controller.  Return failure.
			 */
			goto fail;
		}

		smrt_write_message_abort_one(abort_smcm, smcm->smcm_tag);
	} else {
		/*
		 * The framework wants us to abort every in flight command
		 * for the target with this address.
		 */
		smrt_write_message_abort_all(abort_smcm, smtg->smtg_addr);
	}

	/*
	 * Submit the abort message to the controller.
	 */
	abort_smcm->smcm_status |= SMRT_CMD_STATUS_POLLED;
	if (smrt_submit(smrt, abort_smcm) != 0) {
		goto fail;
	}

	if (pkt != NULL) {
		/*
		 * Record some debugging information about the abort we
		 * sent:
		 */
		smcm->smcm_abort_time = gethrtime();
		smcm->smcm_abort_tag = abort_smcm->smcm_tag;

		/*
		 * Mark the command as aborted so that we do not send
		 * a second abort message:
		 */
		smcm->smcm_status |= SMRT_CMD_STATUS_ABORT_SENT;
	}

	/*
	 * Poll for completion of the abort message.  Note that this function
	 * only fails if we set a timeout on the command, which we have not
	 * done.
	 */
	VERIFY0(smrt_poll_for(smrt, abort_smcm));

	if ((abort_smcm->smcm_status & SMRT_CMD_STATUS_RESET_SENT) ||
	    (abort_smcm->smcm_status & SMRT_CMD_STATUS_ERROR)) {
		/*
		 * Either the controller was reset or the abort command
		 * failed.
		 */
		goto fail;
	}

	/*
	 * The command was successfully aborted.
	 */
	mutex_exit(&smrt->smrt_mutex);
	smrt_command_free(abort_smcm);
	return (1);

fail:
	mutex_exit(&smrt->smrt_mutex);
	smrt_command_free(abort_smcm);
	return (0);
}

static void
smrt_hba_complete_status(smrt_command_t *smcm)
{
	ErrorInfo_t *ei = smcm->smcm_va_err;
	struct scsi_pkt *pkt = smcm->smcm_scsa->smcms_pkt;

	bzero(pkt->pkt_scbp, pkt->pkt_scblen);

	if (ei->ScsiStatus != STATUS_CHECK) {
		/*
		 * If the SCSI status is not CHECK CONDITION, we don't want
		 * to try and read the sense data buffer.
		 */
		goto simple_status;
	}

	if (pkt->pkt_scblen < sizeof (struct scsi_arq_status)) {
		/*
		 * There is not enough room for a request sense structure.
		 * Fall back to reporting just the SCSI status code.
		 */
		goto simple_status;
	}

	/* LINTED: E_BAD_PTR_CAST_ALIGN */
	struct scsi_arq_status *sts = (struct scsi_arq_status *)pkt->pkt_scbp;

	/*
	 * Copy in the SCSI status from the original command.
	 */
	bcopy(&ei->ScsiStatus, &sts->sts_status, sizeof (sts->sts_status));

	/*
	 * Mock up a successful REQUEST SENSE:
	 */
	sts->sts_rqpkt_reason = CMD_CMPLT;
	sts->sts_rqpkt_resid = 0;
	sts->sts_rqpkt_state = STATE_GOT_BUS | STATE_GOT_TARGET |
	    STATE_SENT_CMD | STATE_XFERRED_DATA | STATE_GOT_STATUS;
	sts->sts_rqpkt_statistics = 0;

	/*
	 * The sense data from the controller should be copied into place
	 * starting at the "sts_sensedata" member of the auto request
	 * sense object.
	 */
	size_t sense_len = pkt->pkt_scblen - offsetof(struct scsi_arq_status,
	    sts_sensedata);
	if (ei->SenseLen < sense_len) {
		/*
		 * Only copy sense data bytes that are within the region
		 * the controller marked as valid.
		 */
		sense_len = ei->SenseLen;
	}
	bcopy(ei->SenseInfo, &sts->sts_sensedata, sense_len);

	pkt->pkt_state |= STATE_ARQ_DONE;
	return;

simple_status:
	if (pkt->pkt_scblen < sizeof (struct scsi_status)) {
		/*
		 * There is not even enough room for the SCSI status byte.
		 */
		return;
	}

	bcopy(&ei->ScsiStatus, pkt->pkt_scbp, sizeof (struct scsi_status));
}

static void
smrt_hba_complete_log_error(smrt_command_t *smcm, const char *name)
{
	smrt_t *smrt = smcm->smcm_ctlr;
	ErrorInfo_t *ei = smcm->smcm_va_err;

	dev_err(smrt->smrt_dip, CE_WARN, "!SCSI command failed: %s: "
	    "SCSI op %x, CISS status %x, SCSI status %x", name,
	    (unsigned)smcm->smcm_va_cmd->Request.CDB[0],
	    (unsigned)ei->CommandStatus, (unsigned)ei->ScsiStatus);
}

/*
 * Completion routine for commands submitted to the controller via the SCSI
 * framework.
 */
void
smrt_hba_complete(smrt_command_t *smcm)
{
	smrt_t *smrt = smcm->smcm_ctlr;
	ErrorInfo_t *ei = smcm->smcm_va_err;
	struct scsi_pkt *pkt = smcm->smcm_scsa->smcms_pkt;

	VERIFY(MUTEX_HELD(&smrt->smrt_mutex));

	pkt->pkt_resid = ei->ResidualCnt;

	/*
	 * Check if the controller was reset while this packet was in flight.
	 */
	if (smcm->smcm_status & SMRT_CMD_STATUS_RESET_SENT) {
		if (pkt->pkt_reason != CMD_CMPLT) {
			/*
			 * If another error status has already been written,
			 * do not overwrite it.
			 */
			pkt->pkt_reason = CMD_RESET;
		}
		pkt->pkt_statistics |= STAT_BUS_RESET | STAT_DEV_RESET;
		goto finish;
	}

	if (!(smcm->smcm_status & SMRT_CMD_STATUS_ERROR)) {
		/*
		 * The command was completed without error by the controller.
		 *
		 * As per the specification, if an error was not signalled
		 * by the controller through the CISS transport method,
		 * the error information (including CommandStatus) has not
		 * been written and should not be checked.
		 */
		pkt->pkt_state |= STATE_XFERRED_DATA | STATE_GOT_STATUS;
		goto finish;
	}

	/*
	 * Check the completion status to determine what befell this request.
	 */
	switch (ei->CommandStatus) {
	case CISS_CMD_SUCCESS:
		/*
		 * In a certain sense, the specification contradicts itself.
		 * On the one hand, it suggests that a successful command
		 * will not result in a controller write to the error
		 * information block; on the other hand, it makes room
		 * for a status code (0) which denotes a successful
		 * execution.
		 *
		 * To be on the safe side, we check for that condition here.
		 */
		pkt->pkt_state |= STATE_XFERRED_DATA | STATE_GOT_STATUS;
		break;

	case CISS_CMD_DATA_UNDERRUN:
		/*
		 * A data underrun occurred.  Ideally this will result in
		 * an appropriate SCSI status and sense data.
		 */
		pkt->pkt_state |= STATE_XFERRED_DATA | STATE_GOT_STATUS;
		break;

	case CISS_CMD_TARGET_STATUS:
		/*
		 * The command completed, but an error occurred.  We need
		 * to provide the sense data to the SCSI framework.
		 */
		pkt->pkt_state |= STATE_XFERRED_DATA | STATE_GOT_STATUS;
		break;

	case CISS_CMD_DATA_OVERRUN:
		/*
		 * Data overrun has occurred.
		 */
		smrt_hba_complete_log_error(smcm, "data overrun");
		pkt->pkt_reason = CMD_DATA_OVR;
		pkt->pkt_state |= STATE_XFERRED_DATA | STATE_GOT_STATUS;
		break;

	case CISS_CMD_INVALID:
		/*
		 * One or more fields in the command has invalid data.
		 */
		smrt_hba_complete_log_error(smcm, "invalid command");
		pkt->pkt_reason = CMD_BADMSG;
		pkt->pkt_state |= STATE_GOT_STATUS;
		break;

	case CISS_CMD_PROTOCOL_ERR:
		/*
		 * An error occurred in communication with the end device.
		 */
		smrt_hba_complete_log_error(smcm, "protocol error");
		pkt->pkt_reason = CMD_BADMSG;
		pkt->pkt_state |= STATE_GOT_STATUS;
		break;

	case CISS_CMD_HARDWARE_ERR:
		/*
		 * A hardware error occurred.
		 */
		smrt_hba_complete_log_error(smcm, "hardware error");
		pkt->pkt_reason = CMD_INCOMPLETE;
		break;

	case CISS_CMD_CONNECTION_LOST:
		/*
		 * The connection with the end device cannot be
		 * re-established.
		 */
		smrt_hba_complete_log_error(smcm, "connection lost");
		pkt->pkt_reason = CMD_INCOMPLETE;
		break;

	case CISS_CMD_ABORTED:
	case CISS_CMD_UNSOLICITED_ABORT:
		if (smcm->smcm_status & SMRT_CMD_STATUS_TIMEOUT) {
			/*
			 * This abort was arranged by the periodic routine
			 * in response to an elapsed timeout.
			 */
			pkt->pkt_reason = CMD_TIMEOUT;
			pkt->pkt_statistics |= STAT_TIMEOUT;
		} else {
			pkt->pkt_reason = CMD_ABORTED;
		}
		pkt->pkt_state |= STATE_XFERRED_DATA | STATE_GOT_STATUS;
		pkt->pkt_statistics |= STAT_ABORTED;
		break;

	case CISS_CMD_TIMEOUT:
		smrt_hba_complete_log_error(smcm, "timeout");
		pkt->pkt_reason = CMD_TIMEOUT;
		pkt->pkt_statistics |= STAT_TIMEOUT;
		break;

	default:
		/*
		 * This is an error that we were not prepared to handle.
		 * Signal a generic transport-level error to the framework.
		 */
		smrt_hba_complete_log_error(smcm, "unexpected error");
		pkt->pkt_reason = CMD_TRAN_ERR;
	}

	/*
	 * Attempt to read a SCSI status code and any automatic
	 * request sense data that may exist:
	 */
	smrt_hba_complete_status(smcm);

finish:
	mutex_exit(&smrt->smrt_mutex);
	scsi_hba_pkt_comp(pkt);
	mutex_enter(&smrt->smrt_mutex);
}

static int
smrt_getcap(struct scsi_address *sa, char *cap, int whom)
{
	_NOTE(ARGUNUSED(whom))

	struct scsi_device *sd;
	smrt_target_t *smtg;
	smrt_t *smrt;
	int index;

	sd = scsi_address_device(sa);
	VERIFY(sd != NULL);
	smtg = scsi_device_hba_private_get(sd);
	VERIFY(smtg != NULL);
	smrt = smtg->smtg_ctlr;
	VERIFY(smrt != NULL);

	if ((index = scsi_hba_lookup_capstr(cap)) == DDI_FAILURE) {
		/*
		 * This capability string could not be translated to an
		 * ID number, so it must not exist.
		 */
		return (-1);
	}

	switch (index) {
	case SCSI_CAP_CDB_LEN:
		/*
		 * The CDB field in the CISS request block is fixed at 16
		 * bytes.
		 */
		return (CISS_CDBLEN);

	case SCSI_CAP_DMA_MAX:
		if (smrt->smrt_dma_attr.dma_attr_maxxfer > INT_MAX) {
			return (INT_MAX);
		}
		return ((int)smrt->smrt_dma_attr.dma_attr_maxxfer);

	case SCSI_CAP_SECTOR_SIZE:
		if (smrt->smrt_dma_attr.dma_attr_granular > INT_MAX) {
			return (-1);
		}
		return ((int)smrt->smrt_dma_attr.dma_attr_granular);

	/*
	 * If this target corresponds to a physical device, then we always
	 * indicate that we're on a SAS interconnect.  Otherwise, we default to
	 * saying that we're on a parallel bus.  We can't use SAS for
	 * everything, unfortunately.  When you declare yourself to be a SAS
	 * interconnect, it's expected that you have a full 16-byte WWN as the
	 * target.  If not, devfsadm will not be able to enumerate the device
	 * and create /dev/[r]dsk entries.
	 */
	case SCSI_CAP_INTERCONNECT_TYPE:
		if (smtg->smtg_physical) {
			return (INTERCONNECT_SAS);
		} else {
			return (INTERCONNECT_PARALLEL);
		}

	case SCSI_CAP_DISCONNECT:
	case SCSI_CAP_SYNCHRONOUS:
	case SCSI_CAP_WIDE_XFER:
	case SCSI_CAP_ARQ:
	case SCSI_CAP_UNTAGGED_QING:
	case SCSI_CAP_TAGGED_QING:
		/*
		 * These capabilities are supported by the driver and the
		 * controller.  See scsi_ifgetcap(9F) for more information.
		 */
		return (1);

	case SCSI_CAP_INITIATOR_ID:
	case SCSI_CAP_RESET_NOTIFICATION:
		/*
		 * These capabilities are not supported.
		 */
		return (0);

	default:
		/*
		 * The property in question is not known to this driver.
		 */
		return (-1);
	}
}

/* ARGSUSED */
static int
smrt_setcap(struct scsi_address *sa, char *cap, int value, int whom)
{
	int index;

	if ((index = scsi_hba_lookup_capstr(cap)) == DDI_FAILURE) {
		/*
		 * This capability string could not be translated to an
		 * ID number, so it must not exist.
		 */
		return (-1);
	}

	if (whom == 0) {
		/*
		 * When whom is 0, this is a request to set a capability for
		 * all targets.  As per the recommendation in tran_setcap(9E),
		 * we do not support this mode of operation.
		 */
		return (-1);
	}

	switch (index) {
	case SCSI_CAP_CDB_LEN:
	case SCSI_CAP_DMA_MAX:
	case SCSI_CAP_SECTOR_SIZE:
	case SCSI_CAP_INITIATOR_ID:
	case SCSI_CAP_DISCONNECT:
	case SCSI_CAP_SYNCHRONOUS:
	case SCSI_CAP_WIDE_XFER:
	case SCSI_CAP_ARQ:
	case SCSI_CAP_UNTAGGED_QING:
	case SCSI_CAP_TAGGED_QING:
	case SCSI_CAP_RESET_NOTIFICATION:
	case SCSI_CAP_INTERCONNECT_TYPE:
		/*
		 * We do not support changing any capabilities at this time.
		 */
		return (0);

	default:
		/*
		 * The capability in question is not known to this driver.
		 */
		return (-1);
	}
}

int
smrt_ctrl_hba_setup(smrt_t *smrt)
{
	int flags;
	dev_info_t *dip = smrt->smrt_dip;
	scsi_hba_tran_t *tran;

	if ((tran = scsi_hba_tran_alloc(dip, SCSI_HBA_CANSLEEP)) == NULL) {
		dev_err(dip, CE_WARN, "could not allocate SCSA resources");
		return (DDI_FAILURE);
	}

	smrt->smrt_hba_tran = tran;
	tran->tran_hba_private = smrt;

	tran->tran_tgt_init = smrt_ctrl_tran_tgt_init;
	tran->tran_tgt_probe = scsi_hba_probe;

	tran->tran_start = smrt_ctrl_tran_start;

	tran->tran_getcap = smrt_getcap;
	tran->tran_setcap = smrt_setcap;

	tran->tran_setup_pkt = smrt_tran_setup_pkt;
	tran->tran_teardown_pkt = smrt_tran_teardown_pkt;
	tran->tran_hba_len = sizeof (smrt_command_scsa_t);
	tran->tran_interconnect_type = INTERCONNECT_SAS;

	flags = SCSI_HBA_HBA | SCSI_HBA_TRAN_SCB | SCSI_HBA_ADDR_COMPLEX;
	if (scsi_hba_attach_setup(dip, &smrt->smrt_dma_attr, tran, flags) !=
	    DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "could not attach to SCSA framework");
		scsi_hba_tran_free(tran);
		return (DDI_FAILURE);
	}

	smrt->smrt_init_level |= SMRT_INITLEVEL_SCSA;
	return (DDI_SUCCESS);
}

void
smrt_ctrl_hba_teardown(smrt_t *smrt)
{
	if (smrt->smrt_init_level & SMRT_INITLEVEL_SCSA) {
		VERIFY(scsi_hba_detach(smrt->smrt_dip) != DDI_FAILURE);
		scsi_hba_tran_free(smrt->smrt_hba_tran);
		smrt->smrt_init_level &= ~SMRT_INITLEVEL_SCSA;
	}
}

int
smrt_logvol_hba_setup(smrt_t *smrt, dev_info_t *iport)
{
	scsi_hba_tran_t *tran;

	tran = ddi_get_driver_private(iport);
	if (tran == NULL)
		return (DDI_FAILURE);

	tran->tran_tgt_init = smrt_logvol_tran_tgt_init;
	tran->tran_tgt_free = smrt_logvol_tran_tgt_free;

	tran->tran_start = smrt_tran_start;
	tran->tran_reset = smrt_tran_reset;
	tran->tran_abort = smrt_tran_abort;

	tran->tran_hba_private = smrt;

	mutex_enter(&smrt->smrt_mutex);
	if (scsi_hba_tgtmap_create(iport, SCSI_TM_FULLSET, MICROSEC,
	    2 * MICROSEC, smrt, smrt_logvol_tgtmap_activate,
	    smrt_logvol_tgtmap_deactivate, &smrt->smrt_virt_tgtmap) !=
	    DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	smrt_discover_request(smrt);
	mutex_exit(&smrt->smrt_mutex);

	return (DDI_SUCCESS);
}

void
smrt_logvol_hba_teardown(smrt_t *smrt, dev_info_t *iport)
{
	ASSERT(smrt->smrt_virt_iport == iport);

	mutex_enter(&smrt->smrt_mutex);

	if (smrt->smrt_virt_tgtmap != NULL) {
		scsi_hba_tgtmap_t *t;

		/*
		 * Ensure that we can't be racing with discovery.
		 */
		while (smrt->smrt_status & SMRT_CTLR_DISCOVERY_RUNNING) {
			mutex_exit(&smrt->smrt_mutex);
			ddi_taskq_wait(smrt->smrt_discover_taskq);
			mutex_enter(&smrt->smrt_mutex);
		}

		t = smrt->smrt_virt_tgtmap;
		smrt->smrt_virt_tgtmap = NULL;
		mutex_exit(&smrt->smrt_mutex);
		scsi_hba_tgtmap_destroy(t);
		mutex_enter(&smrt->smrt_mutex);
	}

	mutex_exit(&smrt->smrt_mutex);
}

int
smrt_phys_hba_setup(smrt_t *smrt, dev_info_t *iport)
{
	scsi_hba_tran_t *tran;

	tran = ddi_get_driver_private(iport);
	if (tran == NULL)
		return (DDI_FAILURE);

	tran->tran_tgt_init = smrt_phys_tran_tgt_init;
	tran->tran_tgt_free = smrt_phys_tran_tgt_free;

	tran->tran_start = smrt_tran_start;
	tran->tran_reset = smrt_tran_reset;
	tran->tran_abort = smrt_tran_abort;

	tran->tran_hba_private = smrt;

	mutex_enter(&smrt->smrt_mutex);
	if (scsi_hba_tgtmap_create(iport, SCSI_TM_FULLSET, MICROSEC,
	    2 * MICROSEC, smrt, smrt_phys_tgtmap_activate,
	    smrt_phys_tgtmap_deactivate, &smrt->smrt_phys_tgtmap) !=
	    DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	smrt_discover_request(smrt);
	mutex_exit(&smrt->smrt_mutex);

	return (DDI_SUCCESS);
}

void
smrt_phys_hba_teardown(smrt_t *smrt, dev_info_t *iport)
{
	ASSERT(smrt->smrt_phys_iport == iport);

	mutex_enter(&smrt->smrt_mutex);

	if (smrt->smrt_phys_tgtmap != NULL) {
		scsi_hba_tgtmap_t *t;

		/*
		 * Ensure that we can't be racing with discovery.
		 */
		while (smrt->smrt_status & SMRT_CTLR_DISCOVERY_RUNNING) {
			mutex_exit(&smrt->smrt_mutex);
			ddi_taskq_wait(smrt->smrt_discover_taskq);
			mutex_enter(&smrt->smrt_mutex);
		}

		t = smrt->smrt_phys_tgtmap;
		smrt->smrt_phys_tgtmap = NULL;
		mutex_exit(&smrt->smrt_mutex);
		scsi_hba_tgtmap_destroy(t);
		mutex_enter(&smrt->smrt_mutex);
	}

	mutex_exit(&smrt->smrt_mutex);
}
