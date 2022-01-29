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
 * Copyright 2017 Joyent, Inc.
 */

/*
 * Collection of routines specific to SATA devices and attempting to make them
 * work.
 */

#include <sys/scsi/adapters/smrt/smrt.h>

/*
 * This is a buffer size that should easily cover all of the data that we need
 * to properly determine the buffer allocation.
 */
#define	SMRT_SATA_INQ83_LEN	256

/*
 * We need to try and determine if a SATA WWN exists on the device.  SAT-2
 * defines that the response to the inquiry page 0x83.
 */
int
smrt_sata_determine_wwn(smrt_t *smrt, PhysDevAddr_t *addr, uint64_t *wwnp,
    uint16_t timeout)
{
	smrt_command_t *smcm;
	int r;
	uint8_t *inq;
	uint64_t wwn;
	size_t resid;

	VERIFY3P(wwnp, !=, NULL);

	if ((smcm = smrt_command_alloc(smrt, SMRT_CMDTYPE_INTERNAL,
	    KM_NOSLEEP)) == NULL || smrt_command_attach_internal(smrt, smcm,
	    SMRT_SATA_INQ83_LEN, KM_NOSLEEP) != 0) {
		if (smcm != NULL) {
			smrt_command_free(smcm);
		}
		return (ENOMEM);
	}

	smcm->smcm_va_cmd->Header.LUN.PhysDev = *addr;
	smcm->smcm_va_cmd->Request.CDBLen = CDB_GROUP0;
	smcm->smcm_va_cmd->Request.Type.Type = CISS_TYPE_CMD;
	smcm->smcm_va_cmd->Request.Type.Attribute = CISS_ATTR_SIMPLE;
	smcm->smcm_va_cmd->Request.Type.Direction = CISS_XFER_READ;
	smcm->smcm_va_cmd->Request.Timeout = LE_16(timeout);

	smcm->smcm_va_cmd->Request.CDB[0] = SCMD_INQUIRY;
	smcm->smcm_va_cmd->Request.CDB[1] = 1;
	smcm->smcm_va_cmd->Request.CDB[2] = 0x83;
	smcm->smcm_va_cmd->Request.CDB[3] = (SMRT_SATA_INQ83_LEN & 0xff00) >> 8;
	smcm->smcm_va_cmd->Request.CDB[4] = SMRT_SATA_INQ83_LEN & 0x00ff;
	smcm->smcm_va_cmd->Request.CDB[5] = 0;

	mutex_enter(&smrt->smrt_mutex);

	/*
	 * Send the command to the device.
	 */
	smcm->smcm_status |= SMRT_CMD_STATUS_POLLED;
	if ((r = smrt_submit(smrt, smcm)) != 0) {
		mutex_exit(&smrt->smrt_mutex);
		smrt_command_free(smcm);
		return (r);
	}

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
		mutex_exit(&smrt->smrt_mutex);
		return (r);
	}

	if (smcm->smcm_status & SMRT_CMD_STATUS_RESET_SENT) {
		/*
		 * The controller was reset while we were trying to discover
		 * logical volumes.  Report failure.
		 */
		mutex_exit(&smrt->smrt_mutex);
		smrt_command_free(smcm);
		return (EIO);
	}

	if (smcm->smcm_status & SMRT_CMD_STATUS_ERROR) {
		ErrorInfo_t *ei = smcm->smcm_va_err;

		if (ei->CommandStatus != CISS_CMD_DATA_UNDERRUN) {
			dev_err(smrt->smrt_dip, CE_WARN, "physical target "
			    "SATA WWN error: status 0x%x", ei->CommandStatus);
			mutex_exit(&smrt->smrt_mutex);
			smrt_command_free(smcm);
			return (EIO);
		}
		resid = ei->ResidualCnt;
	} else {
		resid = 0;
	}

	mutex_exit(&smrt->smrt_mutex);

	/*
	 * We must have at least 12 bytes.  The first four bytes are the header,
	 * the next four are for the LUN header, and the last 8 are for the
	 * actual WWN, which according to SAT-2 will always be first.
	 */
	if (SMRT_SATA_INQ83_LEN - resid < 16) {
		smrt_command_free(smcm);
		return (EINVAL);
	}
	inq = smcm->smcm_internal->smcmi_va;

	/*
	 * Sanity check we have the right page.
	 */
	if (inq[1] != 0x83) {
		smrt_command_free(smcm);
		return (EINVAL);
	}

	/*
	 * Check to see if we have a proper Network Address Authority (NAA)
	 * based world wide number for this LUN.  It is possible that firmware
	 * interposes on this and constructs a fake world wide number (WWN).  If
	 * this is the case, we don't want to actually use it.  We need to
	 * verify that the WWN declares the correct naming authority and is of
	 * the proper length.
	 */
	if ((inq[5] & 0x30) != 0 || (inq[5] & 0x0f) != 3 || inq[7] != 8) {
		smrt_command_free(smcm);
		return (ENOTSUP);
	}

	bcopy(&inq[8], &wwn, sizeof (uint64_t));
	*wwnp = BE_64(wwn);

	smrt_command_free(smcm);

	return (0);
}
