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

static int smrt_ctlr_versions(smrt_t *, uint16_t, smrt_versions_t *);

/*
 * The maximum number of seconds to wait for the controller to come online.
 */
unsigned smrt_ciss_init_time = 90;


void
smrt_write_lun_addr_phys(LUNAddr_t *lun, boolean_t masked, unsigned bus,
    unsigned target)
{
	lun->PhysDev.Mode = masked ? MASK_PERIPHERIAL_DEV_ADDR :
	    PERIPHERIAL_DEV_ADDR;

	lun->PhysDev.TargetId = target;
	lun->PhysDev.Bus = bus;

	bzero(&lun->PhysDev.Target, sizeof (lun->PhysDev.Target));
}

void
smrt_write_message_common(smrt_command_t *smcm, uint8_t type, int timeout_secs)
{
	switch (type) {
	case CISS_MSG_ABORT:
	case CISS_MSG_RESET:
	case CISS_MSG_NOP:
		break;

	default:
		panic("unknown message type");
	}

	smcm->smcm_va_cmd->Request.Type.Type = CISS_TYPE_MSG;
	smcm->smcm_va_cmd->Request.Type.Attribute = CISS_ATTR_HEADOFQUEUE;
	smcm->smcm_va_cmd->Request.Type.Direction = CISS_XFER_NONE;
	smcm->smcm_va_cmd->Request.Timeout = LE_16(timeout_secs);
	smcm->smcm_va_cmd->Request.CDBLen = CISS_CDBLEN;
	smcm->smcm_va_cmd->Request.CDB[0] = type;
}

void
smrt_write_message_abort_one(smrt_command_t *smcm, uint32_t tag)
{
	smrt_tag_t cisstag;

	/*
	 * When aborting a particular command, the request is addressed
	 * to the controller.
	 */
	smrt_write_lun_addr_phys(&smcm->smcm_va_cmd->Header.LUN,
	    B_TRUE, 0, 0);

	smrt_write_message_common(smcm, CISS_MSG_ABORT, 0);

	/*
	 * Abort a single command.
	 */
	smcm->smcm_va_cmd->Request.CDB[1] = CISS_ABORT_TASK;

	/*
	 * The CISS Specification says that the tag value for a task-level
	 * abort should be in the CDB in bytes 4-11.
	 */
	bzero(&cisstag, sizeof (cisstag));
	cisstag.tag_value = tag;
	bcopy(&cisstag, &smcm->smcm_va_cmd->Request.CDB[4],
	    sizeof (cisstag));
}

void
smrt_write_message_abort_all(smrt_command_t *smcm, LogDevAddr_t *addr)
{
	/*
	 * When aborting all tasks for a particular Logical Volume,
	 * the command is addressed not to the controller but to
	 * the Volume itself.
	 */
	smcm->smcm_va_cmd->Header.LUN.LogDev = *addr;

	smrt_write_message_common(smcm, CISS_MSG_ABORT, 0);

	/*
	 * Abort all commands for a particular Logical Volume.
	 */
	smcm->smcm_va_cmd->Request.CDB[1] = CISS_ABORT_TASKSET;
}

void
smrt_write_message_reset_ctlr(smrt_command_t *smcm)
{
	smrt_write_lun_addr_phys(&smcm->smcm_va_cmd->Header.LUN,
	    B_TRUE, 0, 0);

	smrt_write_message_common(smcm, CISS_MSG_RESET, 0);

	smcm->smcm_va_cmd->Request.CDB[1] = CISS_RESET_CTLR;
}

void
smrt_write_message_nop(smrt_command_t *smcm, int timeout_secs)
{
	/*
	 * No-op messages are always sent to the controller.
	 */
	smrt_write_lun_addr_phys(&smcm->smcm_va_cmd->Header.LUN,
	    B_TRUE, 0, 0);

	smrt_write_message_common(smcm, CISS_MSG_NOP, timeout_secs);
}

/*
 * This routine is executed regularly by ddi_periodic_add(9F).  It checks the
 * health of the controller and looks for submitted commands that have timed
 * out.
 */
void
smrt_periodic(void *arg)
{
	smrt_t *smrt = arg;

	mutex_enter(&smrt->smrt_mutex);
	if (!(smrt->smrt_status & SMRT_CTLR_STATUS_RUNNING)) {
		/*
		 * The device is currently not active, e.g. due to an
		 * in-progress controller reset.
		 */
		mutex_exit(&smrt->smrt_mutex);
		return;
	}

	/*
	 * Check on the health of the controller firmware.  Note that if the
	 * controller has locked up, this routine will panic the system.
	 */
	smrt_lockup_check(smrt);

	/*
	 * Check inflight commands to see if they have timed out.
	 */
	for (smrt_command_t *smcm = avl_first(&smrt->smrt_inflight);
	    smcm != NULL; smcm = AVL_NEXT(&smrt->smrt_inflight, smcm)) {
		if (smcm->smcm_status & SMRT_CMD_STATUS_POLLED) {
			/*
			 * Polled commands are timed out by the polling
			 * routine.
			 */
			continue;
		}

		if (smcm->smcm_status & SMRT_CMD_STATUS_ABORT_SENT) {
			/*
			 * This command has been aborted; either it will
			 * complete or the controller will be reset.
			 */
			continue;
		}

		if (list_link_active(&smcm->smcm_link_abort)) {
			/*
			 * Already on the abort queue.
			 */
			continue;
		}

		if (smcm->smcm_expiry == 0) {
			/*
			 * This command has no expiry time.
			 */
			continue;
		}

		if (gethrtime() > smcm->smcm_expiry) {
			list_insert_tail(&smrt->smrt_abortq, smcm);
			smcm->smcm_status |= SMRT_CMD_STATUS_TIMEOUT;
		}
	}

	/*
	 * Process the abort queue.
	 */
	(void) smrt_process_abortq(smrt);

	mutex_exit(&smrt->smrt_mutex);
}

int
smrt_retrieve(smrt_t *smrt)
{
	VERIFY(MUTEX_HELD(&smrt->smrt_mutex));

	switch (smrt->smrt_ctlr_mode) {
	case SMRT_CTLR_MODE_SIMPLE:
		smrt_retrieve_simple(smrt);
		return (DDI_SUCCESS);

	case SMRT_CTLR_MODE_UNKNOWN:
		break;
	}

	panic("unknown controller mode");
	/* LINTED: E_FUNC_NO_RET_VAL */
}

/*
 * Grab a new tag number for this command.  We aim to avoid reusing tag numbers
 * as much as possible, so as to avoid spurious double completion from the
 * controller.
 */
static void
smrt_set_new_tag(smrt_t *smrt, smrt_command_t *smcm)
{
	VERIFY(MUTEX_HELD(&smrt->smrt_mutex));

	/*
	 * Loop until we find a tag that is not in use.  The tag space is
	 * very large (~30 bits) and the maximum number of inflight commands
	 * is comparatively small (~1024 in current controllers).
	 */
	for (;;) {
		uint32_t new_tag = smrt->smrt_next_tag;

		if (++smrt->smrt_next_tag > SMRT_MAX_TAG_NUMBER) {
			smrt->smrt_next_tag = SMRT_MIN_TAG_NUMBER;
		}

		if (smrt_lookup_inflight(smrt, new_tag) != NULL) {
			/*
			 * This tag is already used on an inflight command.
			 * Choose another.
			 */
			continue;
		}

		/*
		 * Set the tag for the command and also write it into the
		 * appropriate part of the request block.
		 */
		smcm->smcm_tag = new_tag;
		smcm->smcm_va_cmd->Header.Tag.tag_value = new_tag;
		return;
	}
}

/*
 * Submit a command to the controller.
 */
int
smrt_submit(smrt_t *smrt, smrt_command_t *smcm)
{
	VERIFY(MUTEX_HELD(&smrt->smrt_mutex));
	VERIFY(smcm->smcm_type != SMRT_CMDTYPE_PREINIT);

	/*
	 * If the controller is currently being reset, do not allow command
	 * submission.
	 */
	if (!(smrt->smrt_status & SMRT_CTLR_STATUS_RUNNING)) {
		return (EIO);
	}

	/*
	 * Do not allow submission of more concurrent commands than the
	 * controller supports.
	 */
	if (avl_numnodes(&smrt->smrt_inflight) >= smrt->smrt_maxcmds) {
		return (EAGAIN);
	}

	/*
	 * Synchronise the Command Block DMA resources to ensure that the
	 * device has a consistent view before we pass it the command.
	 */
	if (ddi_dma_sync(smcm->smcm_contig.smdma_dma_handle, 0, 0,
	    DDI_DMA_SYNC_FORDEV) != DDI_SUCCESS) {
		dev_err(smrt->smrt_dip, CE_PANIC, "DMA sync failure");
		return (EIO);
	}

	/*
	 * Ensure that this command is not re-used without issuing a new
	 * tag number and performing any appropriate cleanup.
	 */
	VERIFY(!(smcm->smcm_status & SMRT_CMD_STATUS_USED));
	smcm->smcm_status |= SMRT_CMD_STATUS_USED;

	/*
	 * Assign a tag that is not currently in use
	 */
	smrt_set_new_tag(smrt, smcm);

	/*
	 * Insert this command into the inflight AVL.
	 */
	avl_index_t where;
	if (avl_find(&smrt->smrt_inflight, smcm, &where) != NULL) {
		dev_err(smrt->smrt_dip, CE_PANIC, "duplicate submit tag %x",
		    smcm->smcm_tag);
	}
	avl_insert(&smrt->smrt_inflight, smcm, where);
	if (smrt->smrt_stats.smrts_max_inflight <
	    avl_numnodes(&smrt->smrt_inflight)) {
		smrt->smrt_stats.smrts_max_inflight =
		    avl_numnodes(&smrt->smrt_inflight);
	}

	VERIFY(!(smcm->smcm_status & SMRT_CMD_STATUS_INFLIGHT));
	smcm->smcm_status |= SMRT_CMD_STATUS_INFLIGHT;

	smcm->smcm_time_submit = gethrtime();

	switch (smrt->smrt_ctlr_mode) {
	case SMRT_CTLR_MODE_SIMPLE:
		smrt_submit_simple(smrt, smcm);
		return (0);

	case SMRT_CTLR_MODE_UNKNOWN:
		break;
	}
	panic("unknown controller mode");
	/* LINTED: E_FUNC_NO_RET_VAL */
}

static void
smrt_process_finishq_sync(smrt_command_t *smcm)
{
	smrt_t *smrt = smcm->smcm_ctlr;

	if (ddi_dma_sync(smcm->smcm_contig.smdma_dma_handle, 0, 0,
	    DDI_DMA_SYNC_FORCPU) != DDI_SUCCESS) {
		dev_err(smrt->smrt_dip, CE_PANIC, "finishq DMA sync failure");
	}
}

static void
smrt_process_finishq_one(smrt_command_t *smcm)
{
	smrt_t *smrt = smcm->smcm_ctlr;

	VERIFY(!(smcm->smcm_status & SMRT_CMD_STATUS_COMPLETE));
	smcm->smcm_status |= SMRT_CMD_STATUS_COMPLETE;

	switch (smcm->smcm_type) {
	case SMRT_CMDTYPE_INTERNAL:
		cv_broadcast(&smcm->smcm_ctlr->smrt_cv_finishq);
		return;

	case SMRT_CMDTYPE_SCSA:
		smrt_hba_complete(smcm);
		return;

	case SMRT_CMDTYPE_ABORTQ:
		/*
		 * Abort messages sent as part of abort queue processing
		 * do not require any completion activity.
		 */
		mutex_exit(&smrt->smrt_mutex);
		smrt_command_free(smcm);
		mutex_enter(&smrt->smrt_mutex);
		return;

	case SMRT_CMDTYPE_PREINIT:
		dev_err(smrt->smrt_dip, CE_PANIC, "preinit command "
		    "completed after initialisation");
		return;
	}

	panic("unknown command type");
}

/*
 * Process commands in the completion queue.
 */
void
smrt_process_finishq(smrt_t *smrt)
{
	smrt_command_t *smcm;

	VERIFY(MUTEX_HELD(&smrt->smrt_mutex));

	while ((smcm = list_remove_head(&smrt->smrt_finishq)) != NULL) {
		/*
		 * Synchronise the Command Block before we read from it or
		 * free it, to ensure that any writes from the controller are
		 * visible.
		 */
		smrt_process_finishq_sync(smcm);

		/*
		 * Check if this command was in line to be aborted.
		 */
		if (list_link_active(&smcm->smcm_link_abort)) {
			/*
			 * This command was in line, but the controller
			 * subsequently completed the command before we
			 * were able to do so.
			 */
			list_remove(&smrt->smrt_abortq, smcm);
			smcm->smcm_status &= ~SMRT_CMD_STATUS_TIMEOUT;
		}

		/*
		 * Check if this command has been abandoned by the original
		 * submitter.  If it has, free it now to avoid a leak.
		 */
		if (smcm->smcm_status & SMRT_CMD_STATUS_ABANDONED) {
			mutex_exit(&smrt->smrt_mutex);
			smrt_command_free(smcm);
			mutex_enter(&smrt->smrt_mutex);
			continue;
		}

		if (smcm->smcm_status & SMRT_CMD_STATUS_POLLED) {
			/*
			 * This command will be picked up and processed
			 * by "smrt_poll_for()" once the CV is triggered
			 * at the end of processing.
			 */
			smcm->smcm_status |= SMRT_CMD_STATUS_POLL_COMPLETE;
			continue;
		}

		smrt_process_finishq_one(smcm);
	}

	cv_broadcast(&smrt->smrt_cv_finishq);
}

/*
 * Process commands in the abort queue.
 */
void
smrt_process_abortq(smrt_t *smrt)
{
	smrt_command_t *smcm;
	smrt_command_t *abort_smcm = NULL;

	VERIFY(MUTEX_HELD(&smrt->smrt_mutex));

	if (list_is_empty(&smrt->smrt_abortq)) {
		goto out;
	}

another:
	mutex_exit(&smrt->smrt_mutex);
	if ((abort_smcm = smrt_command_alloc(smrt, SMRT_CMDTYPE_ABORTQ,
	    KM_NOSLEEP)) == NULL) {
		/*
		 * No resources available to send abort messages.  We will
		 * try again the next time around.
		 */
		mutex_enter(&smrt->smrt_mutex);
		goto out;
	}
	mutex_enter(&smrt->smrt_mutex);

	while ((smcm = list_remove_head(&smrt->smrt_abortq)) != NULL) {
		if (!(smcm->smcm_status & SMRT_CMD_STATUS_INFLIGHT)) {
			/*
			 * This message is not currently inflight, so
			 * no abort is needed.
			 */
			continue;
		}

		if (smcm->smcm_status & SMRT_CMD_STATUS_ABORT_SENT) {
			/*
			 * An abort message has already been sent for
			 * this command.
			 */
			continue;
		}

		/*
		 * Send an abort message for the command.
		 */
		smrt_write_message_abort_one(abort_smcm, smcm->smcm_tag);
		if (smrt_submit(smrt, abort_smcm) != 0) {
			/*
			 * The command could not be submitted to the
			 * controller.  Put it back in the abort queue
			 * and give up for now.
			 */
			list_insert_head(&smrt->smrt_abortq, smcm);
			goto out;
		}
		smcm->smcm_status |= SMRT_CMD_STATUS_ABORT_SENT;

		/*
		 * Record some debugging information about the abort we
		 * sent:
		 */
		smcm->smcm_abort_time = gethrtime();
		smcm->smcm_abort_tag = abort_smcm->smcm_tag;

		/*
		 * The abort message was sent.  Release it and
		 * allocate another command.
		 */
		abort_smcm = NULL;
		goto another;
	}

out:
	cv_broadcast(&smrt->smrt_cv_finishq);
	if (abort_smcm != NULL) {
		mutex_exit(&smrt->smrt_mutex);
		smrt_command_free(abort_smcm);
		mutex_enter(&smrt->smrt_mutex);
	}
}

int
smrt_poll_for(smrt_t *smrt, smrt_command_t *smcm)
{
	VERIFY(MUTEX_HELD(&smrt->smrt_mutex));
	VERIFY(smcm->smcm_status & SMRT_CMD_STATUS_POLLED);

	while (!(smcm->smcm_status & SMRT_CMD_STATUS_POLL_COMPLETE)) {
		if (smcm->smcm_expiry != 0) {
			/*
			 * This command has an expiry time.  Check to see
			 * if it has already passed:
			 */
			if (smcm->smcm_expiry < gethrtime()) {
				return (ETIMEDOUT);
			}
		}

		if (ddi_in_panic()) {
			/*
			 * When the system is panicking, there are no
			 * interrupts or other threads.  Drive the polling loop
			 * on our own, but with a small delay to avoid
			 * aggrevating the controller while we're trying to
			 * dump.
			 */
			(void) smrt_retrieve(smrt);
			smrt_process_finishq(smrt);
			drv_usecwait(100);
			continue;
		}

		/*
		 * Wait for command completion to return through the regular
		 * interrupt handling path.
		 */
		if (smcm->smcm_expiry == 0) {
			cv_wait(&smrt->smrt_cv_finishq, &smrt->smrt_mutex);
		} else {
			/*
			 * Wait only until the expiry time for this command.
			 */
			(void) cv_timedwait_sig_hrtime(&smrt->smrt_cv_finishq,
			    &smrt->smrt_mutex, smcm->smcm_expiry);
		}
	}

	/*
	 * Fire the completion callback for this command.  The callback
	 * is responsible for freeing the command, so it may not be
	 * referenced again once this call returns.
	 */
	smrt_process_finishq_one(smcm);

	return (0);
}

void
smrt_intr_set(smrt_t *smrt, boolean_t enabled)
{
	/*
	 * Read the Interrupt Mask Register.
	 */
	uint32_t imr = smrt_get32(smrt, CISS_I2O_INTERRUPT_MASK);

	switch (smrt->smrt_ctlr_mode) {
	case SMRT_CTLR_MODE_SIMPLE:
		if (enabled) {
			imr &= ~CISS_IMR_BIT_SIMPLE_INTR_DISABLE;
		} else {
			imr |= CISS_IMR_BIT_SIMPLE_INTR_DISABLE;
		}
		smrt_put32(smrt, CISS_I2O_INTERRUPT_MASK, imr);
		return;

	case SMRT_CTLR_MODE_UNKNOWN:
		break;
	}
	panic("unknown controller mode");
}

/*
 * Signal to the controller that we have updated the Configuration Table by
 * writing to the Inbound Doorbell Register.  The controller will, after some
 * number of seconds, acknowledge this by clearing the bit.
 *
 * If successful, return DDI_SUCCESS.  If the controller takes too long to
 * acknowledge, return DDI_FAILURE.
 */
int
smrt_cfgtbl_flush(smrt_t *smrt)
{
	/*
	 * Read the current value of the Inbound Doorbell Register.
	 */
	uint32_t idr = smrt_get32(smrt, CISS_I2O_INBOUND_DOORBELL);

	/*
	 * Signal the Configuration Table change to the controller.
	 */
	idr |= CISS_IDR_BIT_CFGTBL_CHANGE;
	smrt_put32(smrt, CISS_I2O_INBOUND_DOORBELL, idr);

	/*
	 * Wait for the controller to acknowledge the change.
	 */
	for (unsigned i = 0; i < smrt_ciss_init_time; i++) {
		idr = smrt_get32(smrt, CISS_I2O_INBOUND_DOORBELL);

		if ((idr & CISS_IDR_BIT_CFGTBL_CHANGE) == 0) {
			return (DDI_SUCCESS);
		}

		/*
		 * Wait for one second before trying again.
		 */
		delay(drv_usectohz(1000000));
	}

	dev_err(smrt->smrt_dip, CE_WARN, "time out expired before controller "
	    "configuration completed");
	return (DDI_FAILURE);
}

int
smrt_cfgtbl_transport_has_support(smrt_t *smrt, int xport)
{
	VERIFY(xport == CISS_CFGTBL_XPORT_SIMPLE);

	/*
	 * Read the current value of the "Supported Transport Methods" field in
	 * the Configuration Table.
	 */
	uint32_t xport_active = ddi_get32(smrt->smrt_ct_handle,
	    &smrt->smrt_ct->TransportSupport);

	/*
	 * Check that the desired transport method is supported by the
	 * controller:
	 */
	if ((xport_active & xport) == 0) {
		dev_err(smrt->smrt_dip, CE_WARN, "controller does not support "
		    "method \"%s\"", xport == CISS_CFGTBL_XPORT_SIMPLE ?
		    "simple" : "performant");
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

void
smrt_cfgtbl_transport_set(smrt_t *smrt, int xport)
{
	VERIFY(xport == CISS_CFGTBL_XPORT_SIMPLE);

	ddi_put32(smrt->smrt_ct_handle, &smrt->smrt_ct->TransportRequest,
	    xport);
}

int
smrt_cfgtbl_transport_confirm(smrt_t *smrt, int xport)
{
	VERIFY(xport == CISS_CFGTBL_XPORT_SIMPLE);

	/*
	 * Read the current value of the TransportActive field in the
	 * Configuration Table.
	 */
	uint32_t xport_active = ddi_get32(smrt->smrt_ct_handle,
	    &smrt->smrt_ct->TransportActive);

	/*
	 * Check that the desired transport method is now active:
	 */
	if ((xport_active & xport) == 0) {
		dev_err(smrt->smrt_dip, CE_WARN, "failed to enable transport "
		    "method \"%s\"", xport == CISS_CFGTBL_XPORT_SIMPLE ?
		    "simple" : "performant");
		return (DDI_FAILURE);
	}

	/*
	 * Ensure that the controller is now ready to accept commands.
	 */
	if ((xport_active & CISS_CFGTBL_READY_FOR_COMMANDS) == 0) {
		dev_err(smrt->smrt_dip, CE_WARN, "controller not ready to "
		    "accept commands");
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

uint32_t
smrt_ctlr_get_maxsgelements(smrt_t *smrt)
{
	return (ddi_get32(smrt->smrt_ct_handle, &smrt->smrt_ct->MaxSGElements));
}

uint32_t
smrt_ctlr_get_cmdsoutmax(smrt_t *smrt)
{
	return (ddi_get32(smrt->smrt_ct_handle, &smrt->smrt_ct->CmdsOutMax));
}

static uint32_t
smrt_ctlr_get_hostdrvsup(smrt_t *smrt)
{
	return (ddi_get32(smrt->smrt_ct_handle,
	    &smrt->smrt_ct->HostDrvrSupport));
}

int
smrt_ctlr_init(smrt_t *smrt)
{
	uint8_t signature[4] = { 'C', 'I', 'S', 'S' };
	int e;

	if ((e = smrt_ctlr_wait_for_state(smrt,
	    SMRT_WAIT_STATE_READY)) != DDI_SUCCESS) {
		return (e);
	}

	/*
	 * The configuration table contains an ASCII signature ("CISS") which
	 * should be checked as we initialise the controller.
	 * See: "9.1 Configuration Table" in CISS Specification.
	 */
	for (unsigned i = 0; i < 4; i++) {
		if (ddi_get8(smrt->smrt_ct_handle,
		    &smrt->smrt_ct->Signature[i]) != signature[i]) {
			dev_err(smrt->smrt_dip, CE_WARN, "invalid signature "
			    "detected");
			return (DDI_FAILURE);
		}
	}

	/*
	 * Initialise an appropriate Transport Method.  For now, this driver
	 * only supports the "Simple" method.
	 */
	if ((e = smrt_ctlr_init_simple(smrt)) != DDI_SUCCESS) {
		return (e);
	}

	/*
	 * Save some common feature support bitfields.
	 */
	smrt->smrt_host_support = smrt_ctlr_get_hostdrvsup(smrt);
	smrt->smrt_bus_support = ddi_get32(smrt->smrt_ct_handle,
	    &smrt->smrt_ct->BusTypes);

	/*
	 * Read initial controller heartbeat value and mark the current
	 * reading time.
	 */
	smrt->smrt_last_heartbeat = ddi_get32(smrt->smrt_ct_handle,
	    &smrt->smrt_ct->HeartBeat);
	smrt->smrt_last_heartbeat_time = gethrtime();

	/*
	 * Determine the firmware version of the controller so that we can
	 * select which type of interrupts to use.
	 */
	if ((e = smrt_ctlr_versions(smrt, SMRT_LOGVOL_DISCOVER_TIMEOUT,
	    &smrt->smrt_versions)) != 0) {
		dev_err(smrt->smrt_dip, CE_WARN, "could not identify "
		    "controller (%d)", e);
		return (DDI_FAILURE);
	}

	dev_err(smrt->smrt_dip, CE_NOTE, "!firmware rev %s",
	    smrt->smrt_versions.smrtv_firmware_rev);

	return (DDI_SUCCESS);
}

void
smrt_ctlr_teardown(smrt_t *smrt)
{
	smrt->smrt_status &= ~SMRT_CTLR_STATUS_RUNNING;

	switch (smrt->smrt_ctlr_mode) {
	case SMRT_CTLR_MODE_SIMPLE:
		smrt_ctlr_teardown_simple(smrt);
		return;

	case SMRT_CTLR_MODE_UNKNOWN:
		return;
	}

	panic("unknown controller mode");
}

int
smrt_ctlr_wait_for_state(smrt_t *smrt, smrt_wait_state_t state)
{
	unsigned wait_usec = 100 * 1000;
	unsigned wait_count = SMRT_WAIT_DELAY_SECONDS * 1000000 / wait_usec;

	VERIFY(state == SMRT_WAIT_STATE_READY ||
	    state == SMRT_WAIT_STATE_UNREADY);

	/*
	 * Read from the Scratchpad Register until the expected ready signature
	 * is detected.  This behaviour is not described in the CISS
	 * specification.
	 *
	 * If the device is not in the desired state immediately, sleep for a
	 * second and try again.  If the device has not become ready in 300
	 * seconds, give up.
	 */
	for (unsigned i = 0; i < wait_count; i++) {
		uint32_t spr = smrt_get32(smrt, CISS_I2O_SCRATCHPAD);

		switch (state) {
		case SMRT_WAIT_STATE_READY:
			if (spr == CISS_SCRATCHPAD_INITIALISED) {
				return (DDI_SUCCESS);
			}
			break;

		case SMRT_WAIT_STATE_UNREADY:
			if (spr != CISS_SCRATCHPAD_INITIALISED) {
				return (DDI_SUCCESS);
			}
			break;
		}

		if (ddi_in_panic()) {
			/*
			 * There is no sleep for the panicking, so we
			 * must spin wait:
			 */
			drv_usecwait(wait_usec);
		} else {
			/*
			 * Wait for a quarter second and try again.
			 */
			delay(drv_usectohz(wait_usec));
		}
	}

	dev_err(smrt->smrt_dip, CE_WARN, "time out waiting for controller "
	    "to enter state \"%s\"", state == SMRT_WAIT_STATE_READY ?
	    "ready": "unready");
	return (DDI_FAILURE);
}

void
smrt_lockup_check(smrt_t *smrt)
{
	/*
	 * Read the current controller heartbeat value.
	 */
	uint32_t heartbeat = ddi_get32(smrt->smrt_ct_handle,
	    &smrt->smrt_ct->HeartBeat);

	VERIFY(MUTEX_HELD(&smrt->smrt_mutex));

	/*
	 * Check to see if the value is the same as last time we looked:
	 */
	if (heartbeat != smrt->smrt_last_heartbeat) {
		/*
		 * The heartbeat value has changed, which suggests that the
		 * firmware in the controller has not yet come to a complete
		 * stop.  Record the new value, as well as the current time.
		 */
		smrt->smrt_last_heartbeat = heartbeat;
		smrt->smrt_last_heartbeat_time = gethrtime();
		return;
	}

	/*
	 * The controller _might_ have been able to signal to us that is
	 * has locked up.  This is a truly unfathomable state of affairs:
	 * If the firmware can tell it has flown off the rails, why not
	 * simply reset the controller?
	 */
	uint32_t odr = smrt_get32(smrt, CISS_I2O_OUTBOUND_DOORBELL_STATUS);
	uint32_t spr = smrt_get32(smrt, CISS_I2O_SCRATCHPAD);
	if ((odr & CISS_ODR_BIT_LOCKUP) != 0) {
		dev_err(smrt->smrt_dip, CE_PANIC, "HP SmartArray firmware has "
		    "reported a critical fault (odr %08x spr %08x)",
		    odr, spr);
	}

	if (gethrtime() > smrt->smrt_last_heartbeat_time + 60 * NANOSEC) {
		dev_err(smrt->smrt_dip, CE_PANIC, "HP SmartArray firmware has "
		    "stopped responding (odr %08x spr %08x)",
		    odr, spr);
	}
}

/*
 * Probe the controller with the IDENTIFY CONTROLLER request.  This is a BMIC
 * command, so it must be submitted to the controller and we must poll for its
 * completion.  This functionality is only presently used during controller
 * initialisation, so it uses the special pre-initialisation path for command
 * allocation and submission.
 */
static int
smrt_ctlr_identify(smrt_t *smrt, uint16_t timeout,
    smrt_identify_controller_t *resp)
{
	smrt_command_t *smcm;
	smrt_identify_controller_req_t smicr;
	int r;
	size_t sz;

	/*
	 * Allocate a command with a data buffer; the controller will fill it
	 * with identification information.  There is some suggestion in the
	 * firmware-level specification that the buffer length should be a
	 * multiple of 512 bytes for some controllers, so we round up.
	 */
	sz = P2ROUNDUP_TYPED(sizeof (*resp), 512, size_t);
	if ((smcm = smrt_command_alloc_preinit(smrt, sz, KM_SLEEP)) == NULL) {
		return (ENOMEM);
	}

	/*
	 * This BMIC command is addressed to the controller itself.  The
	 * Masked Peripheral Device addressing mode is used, with a LUN of 0.
	 */
	smrt_write_lun_addr_phys(&smcm->smcm_va_cmd->Header.LUN, B_TRUE,
	    0, 0);

	smcm->smcm_va_cmd->Request.CDBLen = sizeof (smicr);
	smcm->smcm_va_cmd->Request.Timeout = timeout;
	smcm->smcm_va_cmd->Request.Type.Type = CISS_TYPE_CMD;
	smcm->smcm_va_cmd->Request.Type.Attribute = CISS_ATTR_ORDERED;
	smcm->smcm_va_cmd->Request.Type.Direction = CISS_XFER_READ;

	/*
	 * Construct the IDENTIFY CONTROLLER request CDB.  Note that any
	 * reserved fields in the request must be filled with zeroes.
	 */
	bzero(&smicr, sizeof (smicr));
	smicr.smicr_opcode = CISS_SCMD_BMIC_READ;
	smicr.smicr_lun = 0;
	smicr.smicr_command = CISS_BMIC_IDENTIFY_CONTROLLER;
	bcopy(&smicr, &smcm->smcm_va_cmd->Request.CDB[0],
	    MIN(CISS_CDBLEN, sizeof (smicr)));

	/*
	 * Send the command to the device and poll for its completion.
	 */
	smcm->smcm_status |= SMRT_CMD_STATUS_POLLED;
	smcm->smcm_expiry = gethrtime() + timeout * NANOSEC;
	if ((r = smrt_preinit_command_simple(smrt, smcm)) != 0) {
		VERIFY3S(r, ==, ETIMEDOUT);
		VERIFY0(smcm->smcm_status & SMRT_CMD_STATUS_POLL_COMPLETE);

		/*
		 * This command timed out, but the driver is not presently
		 * initialised to the point where we can try to abort it.
		 * The command was created with the PREINIT type, so it
		 * does not appear in the global command tracking list.
		 * In order to avoid problems with DMA from the controller,
		 * we have to leak the command allocation.
		 */
		smcm = NULL;
		goto out;
	}

	if (smcm->smcm_status & SMRT_CMD_STATUS_RESET_SENT) {
		/*
		 * The controller was reset while we were trying to identify
		 * it.  Report failure.
		 */
		r = EIO;
		goto out;
	}

	if (smcm->smcm_status & SMRT_CMD_STATUS_ERROR) {
		ErrorInfo_t *ei = smcm->smcm_va_err;

		if (ei->CommandStatus != CISS_CMD_DATA_UNDERRUN) {
			dev_err(smrt->smrt_dip, CE_WARN, "identify "
			    "controller error: status 0x%x",
			    ei->CommandStatus);
			r = EIO;
			goto out;
		}
	}

	if (resp != NULL) {
		/*
		 * Copy the identify response out for the caller.
		 */
		bcopy(smcm->smcm_internal->smcmi_va, resp, sizeof (*resp));
	}

	r = 0;

out:
	if (smcm != NULL) {
		smrt_command_free(smcm);
	}
	return (r);
}

/*
 * The firmware versions in an IDENTIFY CONTROLLER response generally take
 * the form of a four byte ASCII string containing a dotted decimal version
 * number; e.g., "8.00".
 *
 * This function sanitises the firmware version, replacing unexpected
 * values with a question mark.
 */
static void
smrt_copy_firmware_version(uint8_t *src, char *dst)
{
	for (unsigned i = 0; i < 4; i++) {
		/*
		 * Make sure that this is a 7-bit clean ASCII value.
		 */
		char c = src[i] <= 0x7f ? (char)(src[i] & 0x7f) : '?';

		if (isalnum(c) || c == '.' || c == ' ') {
			dst[i] = c;
		} else {
			dst[i] = '?';
		}
	}
	dst[4] = '\0';
}

/*
 * Using an IDENTIFY CONTROLLER request, determine firmware and controller
 * version details.  See the comments for "smrt_ctlr_identify()" for more
 * details about calling context.
 */
static int
smrt_ctlr_versions(smrt_t *smrt, uint16_t timeout, smrt_versions_t *smrtv)
{
	smrt_identify_controller_t smic;
	int r;

	if ((r = smrt_ctlr_identify(smrt, timeout, &smic)) != 0) {
		return (r);
	}

	smrtv->smrtv_hardware_version = smic.smic_hardware_version;
	smrt_copy_firmware_version(smic.smic_firmware_rev,
	    smrtv->smrtv_firmware_rev);
	smrt_copy_firmware_version(smic.smic_recovery_rev,
	    smrtv->smrtv_recovery_rev);
	smrt_copy_firmware_version(smic.smic_bootblock_rev,
	    smrtv->smrtv_bootblock_rev);

	return (0);
}

int
smrt_ctlr_reset(smrt_t *smrt)
{
	smrt_command_t *smcm, *smcm_nop;
	int r;

	VERIFY(MUTEX_HELD(&smrt->smrt_mutex));

	if (ddi_in_panic()) {
		goto skip_check;
	}

	if (smrt->smrt_status & SMRT_CTLR_STATUS_RESETTING) {
		/*
		 * Don't pile on.  One reset is enough.  Wait until
		 * it's complete, and then return success.
		 */
		while (smrt->smrt_status & SMRT_CTLR_STATUS_RESETTING) {
			cv_wait(&smrt->smrt_cv_finishq, &smrt->smrt_mutex);
		}
		return (0);
	}
	smrt->smrt_status |= SMRT_CTLR_STATUS_RESETTING;
	smrt->smrt_last_reset_start = gethrtime();
	smrt->smrt_stats.smrts_ctlr_resets++;

skip_check:
	/*
	 * Allocate two commands: one for the soft reset message, which we
	 * cannot free until the controller has reset; and one for the ping we
	 * will use to determine when it is once again functional.
	 */
	mutex_exit(&smrt->smrt_mutex);
	if ((smcm = smrt_command_alloc(smrt, SMRT_CMDTYPE_INTERNAL,
	    KM_NOSLEEP)) == NULL) {
		mutex_enter(&smrt->smrt_mutex);
		return (ENOMEM);
	}
	if ((smcm_nop = smrt_command_alloc(smrt, SMRT_CMDTYPE_INTERNAL,
	    KM_NOSLEEP)) == NULL) {
		smrt_command_free(smcm);
		mutex_enter(&smrt->smrt_mutex);
		return (ENOMEM);
	}
	mutex_enter(&smrt->smrt_mutex);

	/*
	 * Send a soft reset command to the controller.  If this command
	 * succeeds, there will likely be no completion notification.  Instead,
	 * the device should become unavailable for some period of time and
	 * then become available again.  Once available again, we know the soft
	 * reset has completed and should abort all in-flight commands.
	 */
	smrt_write_message_reset_ctlr(smcm);

	/*
	 * Disable interrupts now.
	 */
	smrt_intr_set(smrt, B_FALSE);

	dev_err(smrt->smrt_dip, CE_WARN, "attempting controller soft reset");
	smcm->smcm_status |= SMRT_CMD_STATUS_POLLED;
	if ((r = smrt_submit(smrt, smcm)) != 0) {
		dev_err(smrt->smrt_dip, CE_PANIC, "soft reset failed: "
		    "submit failed (%d)", r);
	}

	/*
	 * Mark every currently inflight command as being reset, including the
	 * soft reset command we just sent.  Once we confirm the reset works,
	 * we can safely report that these commands have failed.
	 */
	for (smrt_command_t *t = avl_first(&smrt->smrt_inflight);
	    t != NULL; t = AVL_NEXT(&smrt->smrt_inflight, t)) {
		t->smcm_status |= SMRT_CMD_STATUS_RESET_SENT;
	}

	/*
	 * Now that we have submitted our soft reset command, prevent
	 * the rest of the driver from interacting with the controller.
	 */
	smrt->smrt_status &= ~SMRT_CTLR_STATUS_RUNNING;

	/*
	 * We do not expect a completion from the controller for our soft
	 * reset command, but we also cannot remove it from the inflight
	 * list until we know the controller has actually reset.  To do
	 * otherwise would potentially allow the controller to scribble
	 * on the memory we were using.
	 */
	smcm->smcm_status |= SMRT_CMD_STATUS_ABANDONED;

	if (smrt_ctlr_wait_for_state(smrt, SMRT_WAIT_STATE_UNREADY) !=
	    DDI_SUCCESS) {
		dev_err(smrt->smrt_dip, CE_PANIC, "soft reset failed: "
		    "controller did not become unready");
	}
	dev_err(smrt->smrt_dip, CE_NOTE, "soft reset: controller unready");

	if (smrt_ctlr_wait_for_state(smrt, SMRT_WAIT_STATE_READY) !=
	    DDI_SUCCESS) {
		dev_err(smrt->smrt_dip, CE_PANIC, "soft reset failed: "
		    "controller did not come become ready");
	}
	dev_err(smrt->smrt_dip, CE_NOTE, "soft reset: controller ready");

	/*
	 * In at least the Smart Array P420i, the controller can take 30-45
	 * seconds after the scratchpad register shows it as being available
	 * before it is ready to receive commands.  In order to avoid hitting
	 * it too early with our post-reset ping, we will sleep for 10 seconds
	 * here.
	 */
	if (ddi_in_panic()) {
		drv_usecwait(10 * MICROSEC);
	} else {
		delay(drv_usectohz(10 * MICROSEC));
	}

	smrt_ctlr_teardown(smrt);
	if (smrt_ctlr_init(smrt) != DDI_SUCCESS) {
		dev_err(smrt->smrt_dip, CE_PANIC, "soft reset failed: "
		    "controller transport could not be configured");
	}
	dev_err(smrt->smrt_dip, CE_NOTE, "soft reset: controller configured");

	smrt_write_message_nop(smcm_nop, 0);
	smcm_nop->smcm_status |= SMRT_CMD_STATUS_POLLED;
	smrt->smrt_status |= SMRT_CTLR_STATUS_RUNNING;
	if ((r = smrt_submit(smrt, smcm_nop)) != 0) {
		dev_err(smrt->smrt_dip, CE_PANIC, "soft reset failed: "
		    "ping could not be submitted (%d)", r);
	}
	smrt->smrt_status &= ~SMRT_CTLR_STATUS_RUNNING;

	/*
	 * Interrupts are still masked at this stage.  Poll manually in
	 * a way that will not trigger regular finish queue processing:
	 */
	VERIFY(smcm_nop->smcm_status & SMRT_CMD_STATUS_INFLIGHT);
	for (unsigned i = 0; i < 600; i++) {
		smrt_retrieve_simple(smrt);

		if (!(smcm_nop->smcm_status & SMRT_CMD_STATUS_INFLIGHT)) {
			/*
			 * Remove the ping command from the finish queue and
			 * process it manually.  This processing must mirror
			 * what would have been done in smrt_process_finishq().
			 */
			VERIFY(list_link_active(&smcm_nop->smcm_link_finish));
			list_remove(&smrt->smrt_finishq, smcm_nop);
			smrt_process_finishq_sync(smcm_nop);
			smcm_nop->smcm_status |= SMRT_CMD_STATUS_POLL_COMPLETE;
			smrt_process_finishq_one(smcm_nop);
			break;
		}

		if (ddi_in_panic()) {
			drv_usecwait(100 * 1000);
		} else {
			delay(drv_usectohz(100 * 1000));
		}
	}

	if (!(smcm_nop->smcm_status & SMRT_CMD_STATUS_COMPLETE)) {
		dev_err(smrt->smrt_dip, CE_PANIC, "soft reset failed: "
		    "ping did not complete");
	} else if (smcm_nop->smcm_status & SMRT_CMD_STATUS_ERROR) {
		dev_err(smrt->smrt_dip, CE_WARN, "soft reset: ping completed "
		    "in error (status %u)",
		    (unsigned)smcm_nop->smcm_va_err->CommandStatus);
	} else {
		dev_err(smrt->smrt_dip, CE_NOTE, "soft reset: ping completed");
	}

	/*
	 * Now that the controller is working again, we can abort any
	 * commands that were inflight during the reset.
	 */
	smrt_command_t *nt;
	for (smrt_command_t *t = avl_first(&smrt->smrt_inflight);
	    t != NULL; t = nt) {
		nt = AVL_NEXT(&smrt->smrt_inflight, t);

		if (t->smcm_status & SMRT_CMD_STATUS_RESET_SENT) {
			avl_remove(&smrt->smrt_inflight, t);
			t->smcm_status &= ~SMRT_CMD_STATUS_INFLIGHT;

			list_insert_tail(&smrt->smrt_finishq, t);
		}
	}

	/*
	 * Re-enable interrupts, mark the controller running and
	 * the reset as complete....
	 */
	smrt_intr_set(smrt, B_TRUE);
	smrt->smrt_status |= SMRT_CTLR_STATUS_RUNNING;
	smrt->smrt_status &= ~SMRT_CTLR_STATUS_RESETTING;
	smrt->smrt_last_reset_finish = gethrtime();

	/*
	 * Wake anybody that was waiting for the reset to complete.
	 */
	cv_broadcast(&smrt->smrt_cv_finishq);

	/*
	 * Process the completion queue one last time before we let go
	 * of the mutex.
	 */
	smrt_process_finishq(smrt);

	mutex_exit(&smrt->smrt_mutex);
	smrt_command_free(smcm_nop);
	mutex_enter(&smrt->smrt_mutex);
	return (0);
}
