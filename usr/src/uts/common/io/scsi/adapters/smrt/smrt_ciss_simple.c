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

uint_t
smrt_isr_hw_simple(caddr_t arg1, caddr_t arg2)
{
	_NOTE(ARGUNUSED(arg2))

	/* LINTED: E_BAD_PTR_CAST_ALIGN */
	smrt_t *smrt = (smrt_t *)arg1;
	uint32_t isr = smrt_get32(smrt, CISS_I2O_INTERRUPT_STATUS);
	hrtime_t now = gethrtime();

	mutex_enter(&smrt->smrt_mutex);
	if (!(smrt->smrt_status & SMRT_CTLR_STATUS_RUNNING)) {
		smrt->smrt_stats.smrts_unclaimed_interrupts++;
		smrt->smrt_last_interrupt_unclaimed = now;

		/*
		 * We should not be receiving interrupts from the controller
		 * while the driver is not running.
		 */
		mutex_exit(&smrt->smrt_mutex);
		return (DDI_INTR_UNCLAIMED);
	}

	/*
	 * Check to see if this interrupt came from the device:
	 */
	if ((isr & CISS_ISR_BIT_SIMPLE_INTR) == 0) {
		smrt->smrt_stats.smrts_unclaimed_interrupts++;
		smrt->smrt_last_interrupt_unclaimed = now;

		/*
		 * Check to see if the firmware has come to rest.  If it has,
		 * this routine will panic the system.
		 */
		smrt_lockup_check(smrt);

		mutex_exit(&smrt->smrt_mutex);
		return (DDI_INTR_UNCLAIMED);
	}

	smrt->smrt_stats.smrts_claimed_interrupts++;
	smrt->smrt_last_interrupt_claimed = now;

	/*
	 * The interrupt was from our controller, so collect any pending
	 * command completions.
	 */
	smrt_retrieve_simple(smrt);

	/*
	 * Process any commands in the completion queue.
	 */
	smrt_process_finishq(smrt);

	mutex_exit(&smrt->smrt_mutex);
	return (DDI_INTR_CLAIMED);
}

/*
 * Read tags and process completion of the associated command until the supply
 * of tags is exhausted.
 */
void
smrt_retrieve_simple(smrt_t *smrt)
{
	uint32_t opq;
	uint32_t none = 0xffffffff;

	VERIFY(MUTEX_HELD(&smrt->smrt_mutex));

	while ((opq = smrt_get32(smrt, CISS_I2O_OUTBOUND_POST_Q)) != none) {
		uint32_t tag = CISS_OPQ_READ_TAG(opq);
		smrt_command_t *smcm;

		if ((smcm = smrt_lookup_inflight(smrt, tag)) == NULL) {
			dev_err(smrt->smrt_dip, CE_WARN, "spurious tag %x",
			    tag);
			continue;
		}

		avl_remove(&smrt->smrt_inflight, smcm);
		smcm->smcm_status &= ~SMRT_CMD_STATUS_INFLIGHT;
		if (CISS_OPQ_READ_ERROR(opq) != 0) {
			smcm->smcm_status |= SMRT_CMD_STATUS_ERROR;
		}
		smcm->smcm_time_complete = gethrtime();

		/*
		 * Push this command onto the completion queue.
		 */
		list_insert_tail(&smrt->smrt_finishq, smcm);
	}
}

/*
 * Submit a command to the controller by posting it to the Inbound Post Queue
 * Register.
 */
void
smrt_submit_simple(smrt_t *smrt, smrt_command_t *smcm)
{
	smrt_put32(smrt, CISS_I2O_INBOUND_POST_Q, smcm->smcm_pa_cmd);
}

/*
 * Submit a command to the controller by posting it to the Inbound Post Queue
 * Register.  Immediately begin polling on the completion of that command.
 *
 * NOTE: This function is for controller initialisation only.  It discards
 * completions of commands other than the expected command as spurious, and
 * will not interact correctly with the rest of the driver once it is running.
 */
int
smrt_preinit_command_simple(smrt_t *smrt, smrt_command_t *smcm)
{
	/*
	 * The controller must be initialised to use the Simple Transport
	 * Method, but not be marked RUNNING.  The command to process must be a
	 * PREINIT command with the expected tag number, marked for polling.
	 */
	VERIFY(smrt->smrt_ctlr_mode == SMRT_CTLR_MODE_SIMPLE);
	VERIFY(!(smrt->smrt_status & SMRT_CTLR_STATUS_RUNNING));
	VERIFY(smcm->smcm_type == SMRT_CMDTYPE_PREINIT);
	VERIFY(smcm->smcm_status & SMRT_CMD_STATUS_POLLED);
	VERIFY3U(smcm->smcm_tag, ==, SMRT_PRE_TAG_NUMBER);

	/*
	 * Submit this command to the controller.
	 */
	smcm->smcm_status |= SMRT_CMD_STATUS_INFLIGHT;
	smrt_put32(smrt, CISS_I2O_INBOUND_POST_Q, smcm->smcm_pa_cmd);

	/*
	 * Poll the controller for completions until we see the command we just
	 * sent, or the timeout expires.
	 */
	for (;;) {
		uint32_t none = 0xffffffff;
		uint32_t opq = smrt_get32(smrt, CISS_I2O_OUTBOUND_POST_Q);
		uint32_t tag;

		if (smcm->smcm_expiry != 0) {
			/*
			 * This command has an expiry time.  Check to see
			 * if it has already passed:
			 */
			if (smcm->smcm_expiry < gethrtime()) {
				return (ETIMEDOUT);
			}
		}

		if (opq == none) {
			delay(drv_usectohz(10 * 1000));
			continue;
		}

		if ((tag = CISS_OPQ_READ_TAG(opq)) != SMRT_PRE_TAG_NUMBER) {
			dev_err(smrt->smrt_dip, CE_WARN, "unexpected tag 0x%x"
			    " completed during driver init", tag);
			delay(drv_usectohz(10 * 1000));
			continue;
		}

		smcm->smcm_status &= ~SMRT_CMD_STATUS_INFLIGHT;
		if (CISS_OPQ_READ_ERROR(opq) != 0) {
			smcm->smcm_status |= SMRT_CMD_STATUS_ERROR;
		}
		smcm->smcm_time_complete = gethrtime();
		smcm->smcm_status |= SMRT_CMD_STATUS_POLL_COMPLETE;

		return (0);
	}
}

int
smrt_ctlr_init_simple(smrt_t *smrt)
{
	VERIFY(smrt->smrt_ctlr_mode == SMRT_CTLR_MODE_UNKNOWN);

	if (smrt_cfgtbl_transport_has_support(smrt,
	    CISS_CFGTBL_XPORT_SIMPLE) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}
	smrt->smrt_ctlr_mode = SMRT_CTLR_MODE_SIMPLE;

	/*
	 * Disable device interrupts while we are setting up.
	 */
	smrt_intr_set(smrt, B_FALSE);

	if ((smrt->smrt_maxcmds = smrt_ctlr_get_cmdsoutmax(smrt)) == 0) {
		dev_err(smrt->smrt_dip, CE_WARN, "maximum outstanding "
		    "commands set to zero");
		return (DDI_FAILURE);
	}

	/*
	 * Determine the number of Scatter/Gather List entries this controller
	 * supports.  The maximum number we allow is CISS_MAXSGENTRIES: the
	 * number of elements in the static struct we use for command
	 * submission.
	 */
	if ((smrt->smrt_sg_cnt = smrt_ctlr_get_maxsgelements(smrt)) == 0) {
		/*
		 * The CISS specification states that if this value is
		 * zero, we should assume a value of 31 for compatibility
		 * with older firmware.
		 */
		smrt->smrt_sg_cnt = CISS_SGCNT_FALLBACK;

	} else if (smrt->smrt_sg_cnt > CISS_MAXSGENTRIES) {
		/*
		 * If the controller supports more than we have allocated,
		 * just cap the count at the allocation size.
		 */
		smrt->smrt_sg_cnt = CISS_MAXSGENTRIES;
	}

	/*
	 * Zero the upper 32 bits of the address in the Controller.
	 */
	ddi_put32(smrt->smrt_ct_handle, &smrt->smrt_ct->Upper32Addr, 0);

	/*
	 * Set the Transport Method and flush the changes to the
	 * Configuration Table.
	 */
	smrt_cfgtbl_transport_set(smrt, CISS_CFGTBL_XPORT_SIMPLE);
	if (smrt_cfgtbl_flush(smrt) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	if (smrt_cfgtbl_transport_confirm(smrt,
	    CISS_CFGTBL_XPORT_SIMPLE) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/*
	 * Check the outstanding command cap a second time now that we have
	 * flushed out the new Transport Method.  This is entirely defensive;
	 * we do not expect this value to change.
	 */
	uint32_t check_again = smrt_ctlr_get_cmdsoutmax(smrt);
	if (check_again != smrt->smrt_maxcmds) {
		dev_err(smrt->smrt_dip, CE_WARN, "maximum outstanding commands "
		    "changed during initialisation (was %u, now %u)",
		    smrt->smrt_maxcmds, check_again);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

void
smrt_ctlr_teardown_simple(smrt_t *smrt)
{
	VERIFY(smrt->smrt_ctlr_mode == SMRT_CTLR_MODE_SIMPLE);

	/*
	 * Due to the nominal simplicity of the simple mode, we have no
	 * particular teardown to perform as we do not allocate anything
	 * on the way up.
	 */
	smrt->smrt_ctlr_mode = SMRT_CTLR_MODE_UNKNOWN;
}
