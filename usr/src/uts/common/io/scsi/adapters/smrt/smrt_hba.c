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

static boolean_t
smrt_device_is_controller(struct scsi_device *sd)
{
	return (sd->sd_address.a_target == SMRT_CONTROLLER_TARGET &&
	    sd->sd_address.a_lun == 0);
}

static int
smrt_tran_tgt_init(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd)
{
	_NOTE(ARGUNUSED(hba_dip))

	smrt_t *smrt = (smrt_t *)hba_tran->tran_hba_private;
	smrt_volume_t *smlv;
	smrt_target_t *smtg;
	dev_info_t *dip = smrt->smrt_dip;

	/*
	 * Check to see if new logical volumes are available.
	 */
	if (smrt_logvol_discover(smrt, SMRT_LOGVOL_DISCOVER_TIMEOUT) != 0) {
		dev_err(dip, CE_WARN, "discover logical volumes failure");
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
	 * Check to see if this is the SCSI address of the pseudo target
	 * representing the Smart Array controller itself.
	 */
	if (smrt_device_is_controller(sd)) {
		smtg->smtg_controller_target = B_TRUE;
		goto skip_logvol;
	}

	/*
	 * Look for a logical volume for the SCSI address of this target.
	 */
	if ((smlv = smrt_logvol_lookup_by_addr(smrt, &sd->sd_address)) ==
	    NULL) {
		mutex_exit(&smrt->smrt_mutex);
		kmem_free(smtg, sizeof (*smtg));
		return (DDI_FAILURE);
	}

	smtg->smtg_volume = smlv;
	list_insert_tail(&smlv->smlv_targets, smtg);

skip_logvol:
	/*
	 * Link this target object to the controller:
	 */
	smtg->smtg_ctlr = smrt;
	list_insert_tail(&smrt->smrt_targets, smtg);

	smtg->smtg_scsi_dev = sd;
	VERIFY(sd->sd_dev == tgt_dip);

	/*
	 * We passed SCSI_HBA_TRAN_CLONE to scsi_hba_attach(9F), so we
	 * can stash our target-specific data structure on the (cloned)
	 * "hba_tran" without affecting the private data pointers of the
	 * HBA or of other targets.
	 */
	hba_tran->tran_tgt_private = smtg;

	mutex_exit(&smrt->smrt_mutex);
	return (DDI_SUCCESS);
}

static void
smrt_tran_tgt_free(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd)
{
	_NOTE(ARGUNUSED(hba_dip, tgt_dip))

	smrt_t *smrt = (smrt_t *)hba_tran->tran_hba_private;
	smrt_target_t *smtg = (smrt_target_t *)hba_tran->tran_tgt_private;
	smrt_volume_t *smlv = smtg->smtg_volume;

	VERIFY(smtg->smtg_scsi_dev == sd);

	mutex_enter(&smrt->smrt_mutex);

	/*
	 * Remove this target from the tracking lists:
	 */
	if (!smtg->smtg_controller_target) {
		list_remove(&smlv->smlv_targets, smtg);
	}
	list_remove(&smrt->smrt_targets, smtg);

	/*
	 * Clear the target-specific private data pointer; see comments
	 * in smrt_tran_tgt_init() above.
	 */
	hba_tran->tran_tgt_private = NULL;

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

	scsi_hba_tran_t *tran = pkt->pkt_address.a_hba_tran;
	smrt_t *smrt = (smrt_t *)tran->tran_hba_private;
	smrt_target_t *smtg = (smrt_target_t *)tran->tran_tgt_private;
	smrt_command_scsa_t *smcms = (smrt_command_scsa_t *)
	    pkt->pkt_ha_private;
	smrt_command_t *smcm;
	int kmflags = callback == SLEEP_FUNC ? KM_SLEEP : KM_NOSLEEP;

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

static int
smrt_tran_start(struct scsi_address *sa, struct scsi_pkt *pkt)
{
	_NOTE(ARGUNUSED(sa))

	scsi_hba_tran_t *tran = pkt->pkt_address.a_hba_tran;
	smrt_t *smrt = (smrt_t *)tran->tran_hba_private;
	smrt_command_scsa_t *smcms = (smrt_command_scsa_t *)
	    pkt->pkt_ha_private;
	smrt_command_t *smcm = smcms->smcms_command;
	int r;

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

	if (smcm->smcm_target->smtg_controller_target) {
		/*
		 * The controller is, according to the CISS Specification,
		 * always LUN 0 in the peripheral device addressing mode.
		 */
		smrt_write_lun_addr_phys(&smcm->smcm_va_cmd->Header.LUN,
		    B_TRUE, 0, 0);
	} else {
		/*
		 * Copy logical volume address from the target object:
		 */
		smcm->smcm_va_cmd->Header.LUN.LogDev = smcm->smcm_target->
		    smtg_volume->smlv_addr;
	}

	/*
	 * Initialise the command block.
	 */
	smcm->smcm_va_cmd->Request.CDBLen = pkt->pkt_cdblen;
	smcm->smcm_va_cmd->Request.Type.Type = CISS_TYPE_CMD;
	smcm->smcm_va_cmd->Request.Type.Attribute = CISS_ATTR_ORDERED;
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

	scsi_hba_tran_t *tran = sa->a_hba_tran;
	smrt_t *smrt = (smrt_t *)tran->tran_hba_private;
	int r;
	smrt_command_t *smcm;

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
	scsi_hba_tran_t *tran = sa->a_hba_tran;
	smrt_t *smrt = (smrt_t *)tran->tran_hba_private;
	smrt_command_t *smcm = NULL;
	smrt_command_t *abort_smcm;

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
		smrt_target_t *smtg = (smrt_target_t *)tran->
		    tran_tgt_private;

		if (smtg->smtg_volume == NULL) {
			/*
			 * We currently do not support sending an abort
			 * to anything but a Logical Volume.
			 */
			goto fail;
		}

		smrt_write_message_abort_all(abort_smcm,
		    &smtg->smtg_volume->smlv_addr);
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

	scsi_hba_tran_t *tran = sa->a_hba_tran;
	smrt_t *smrt = (smrt_t *)tran->tran_hba_private;
	int index;

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

	case SCSI_CAP_INITIATOR_ID:
		return (SMRT_CONTROLLER_TARGET);

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

	case SCSI_CAP_RESET_NOTIFICATION:
		/*
		 * This capability is not supported.
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
smrt_hba_setup(smrt_t *smrt)
{
	dev_info_t *dip = smrt->smrt_dip;
	scsi_hba_tran_t *tran;

	if ((tran = scsi_hba_tran_alloc(dip, SCSI_HBA_CANSLEEP)) == NULL) {
		dev_err(dip, CE_WARN, "could not allocate SCSA resources");
		return (DDI_FAILURE);
	}

	smrt->smrt_hba_tran = tran;
	tran->tran_hba_private = smrt;

	tran->tran_tgt_init = smrt_tran_tgt_init;
	tran->tran_tgt_probe = scsi_hba_probe;
	tran->tran_tgt_free = smrt_tran_tgt_free;

	tran->tran_start = smrt_tran_start;
	tran->tran_reset = smrt_tran_reset;
	tran->tran_abort = smrt_tran_abort;

	tran->tran_getcap = smrt_getcap;
	tran->tran_setcap = smrt_setcap;

	tran->tran_setup_pkt = smrt_tran_setup_pkt;
	tran->tran_teardown_pkt = smrt_tran_teardown_pkt;
	tran->tran_hba_len = sizeof (smrt_command_scsa_t);

	if (scsi_hba_attach_setup(dip, &smrt->smrt_dma_attr, tran,
	    SCSI_HBA_TRAN_CLONE | SCSI_HBA_TRAN_SCB) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "could not attach to SCSA framework");
		scsi_hba_tran_free(tran);
		return (DDI_FAILURE);
	}

	smrt->smrt_init_level |= SMRT_INITLEVEL_SCSA;
	return (DDI_SUCCESS);
}

void
smrt_hba_teardown(smrt_t *smrt)
{
	if (smrt->smrt_init_level & SMRT_INITLEVEL_SCSA) {
		VERIFY(scsi_hba_detach(smrt->smrt_dip) != DDI_FAILURE);
		scsi_hba_tran_free(smrt->smrt_hba_tran);
		smrt->smrt_init_level &= ~SMRT_INITLEVEL_SCSA;
	}
}
