/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * scsa2usb_ms_bulkonly.c:
 *
 * This file implements USB Mass Storage Class
 * Bulk Only (BO) transport v1.0
 * http://www.usb.org/developers/data/devclass/usbmassbulk_10.pdf
 */
#include <sys/usb/usba/usbai_version.h>
#include <sys/scsi/scsi.h>
#include <sys/callb.h>		/* needed by scsa2usb.h */
#include <sys/strsubr.h>
#include <sys/strsun.h>

#include <sys/usb/usba.h>
#include <sys/usb/usba/usba_private.h>
#include <sys/usb/usba/usba_ugen.h>

#include <sys/usb/clients/mass_storage/usb_bulkonly.h>
#include <sys/usb/scsa2usb/scsa2usb.h>

/*
 * Function Prototypes
 */
int		scsa2usb_bulk_only_transport(scsa2usb_state_t *,
		    scsa2usb_cmd_t *);
static void	scsa2usb_fill_in_cbw(scsa2usb_state_t *, scsa2usb_cmd_t *,
		    mblk_t *);
static void	scsa2usb_bulk_only_reset_recovery(scsa2usb_state_t *);
static void	scsa2usb_bulk_only_handle_error(scsa2usb_state_t *,
		    usb_bulk_req_t *);
int		scsa2usb_bulk_only_get_max_lun(scsa2usb_state_t *);
static int	scsa2usb_handle_status_start(scsa2usb_state_t *,
		    usb_bulk_req_t *);
static int	scsa2usb_handle_csw_result(scsa2usb_state_t *, mblk_t *);


/* extern functions */
extern void	scsa2usb_setup_next_xfer(scsa2usb_state_t *, scsa2usb_cmd_t *);
extern int	scsa2usb_handle_data_start(scsa2usb_state_t *,
		    scsa2usb_cmd_t *, usb_bulk_req_t *);
extern void	scsa2usb_handle_data_done(scsa2usb_state_t *, scsa2usb_cmd_t *,
		    usb_bulk_req_t *);
extern usb_bulk_req_t *scsa2usb_init_bulk_req(scsa2usb_state_t *,
			    size_t, uint_t, usb_req_attrs_t, usb_flags_t);
extern int	scsa2usb_bulk_timeout(int);
extern int	scsa2usb_clear_ept_stall(scsa2usb_state_t *, uint_t,
		    usb_pipe_handle_t, char *);
extern void	scsa2usb_close_usb_pipes(scsa2usb_state_t *);

#ifdef DEBUG	/* debugging information */
extern void	scsa2usb_print_cdb(scsa2usb_state_t *, scsa2usb_cmd_t *);
#endif	/* DEBUG */


#ifdef	SCSA2USB_BULK_ONLY_TEST
/*
 * Test 13 cases. (See USB Mass Storage Class - Bulk Only Transport).
 * We are not covering test cases 1, 6, and 12 as these are the "good"
 * test cases and are tested as part of the normal drive access operations.
 *
 * NOTE: This is for testing only. It will be replaced by a uscsi test.
 */
int scsa2usb_test_case_2 = 0;
int scsa2usb_test_case_3 = 0;
int scsa2usb_test_case_4 = 0;
int scsa2usb_test_case_7 = 0;
extern int scsa2usb_test_case_8;
int scsa2usb_test_case_9 = 0;
extern int scsa2usb_test_case_10;
int scsa2usb_test_case_13 = 0;
#endif	/* SCSA2USB_BULK_ONLY_TEST */


/*
 * scsa2usb_bulk_only_transport:
 *	Implements the BO state machine by these steps:
 *	a) Issues CBW to a Bulk Only device.
 *	b) Start Data Phase if applicable
 *	c) Start Status Phase
 *
 *	returns TRAN_* values
 *
 * scsa2usb_bulk_only_state_machine:
 *
 * scsa2usb_bulk_only_transport() handles the normal transitions or
 * continuation after clearing stalls or error recovery.
 *
 * Command Phase:
 *	prepare a valid CBW and transport it on bulk-out pipe
 *	if error on bulkout:
 *		set pkt_reason to CMD_TRAN_ERR
 *		new pkt state is SCSA2USB_PKT_DO_COMP
 *		reset recovery synchronously
 *	else
 *		proceed to data phase
 *
 * Data Phase:
 *	if data in:
 *		setup data in on bulkin
 *	else if data out:
 *		setup data out on bulkout
 *
 *	data: (in)
 *		copy data transferred so far, no more data to transfer
 *
 *		if stall on bulkin pipe
 *			terminate data transfers, set cmd_done
 *			clear stall on bulkin syncrhonously
 *		else if other exception
 *			set pkt_reason to CMD_TRAN_ERR
 *			new pkt state is SCSA2USB_PKT_DO_COMP
 *			reset recovery syncrhonously
 *		else (no error)
 *			receive status
 *
 *	 data: (out)
 *		if stall on bulkout pipe
 *			terminate data transfers, set cmd_done
 *			clear stall on bulkout synchronously USBA
 *		else if other exception
 *			set pkt_reason to CMD_TRAN_ERR
 *			new pkt state is SCSA2USB_PKT_DO_COMP
 *			reset recovery synchronously
 *		else (no error)
 *			receive status
 *
 * Status Phase:
 *
 *	if stall (first attempt)
 *		new pkt state is SCSA2USB_PKT_PROCESS_CSW
 *		setup receiving status on bulkin
 *		if stall (second attempt)
 *			new pkt state is SCSA2USB_PKT_DO_COMP
 *			reset recovery synchronously, we are hosed.
 *		else
 *			goto check CSW
 *	else
 *		goto check CSW
 *
 * check CSW:
 *	- check length equals 13, signature, and matching tag
 *	- check status is less than or equal to 2
 *	- check residue is less than or equal to data length
 *		adjust residue based on if we got valid data
 *
 *	if not OK
 *		new pkt state is SCSA2USB_PKT_DO_COMP
 *		set pkt reason CMD_TRAN_ERR
 *		reset recovery synchronously, we are hosed
 *	else if phase error
 *		new pkt state is SCSA2USB_PKT_DO_COMP
 *		set pkt reason CMD_TRAN_ERR
 *		reset recovery synchronously
 *	else if (status < 2)
 *		if status is equal to 1
 *			set check condition
 *		if residue
 *			calculate residue from data xferred and DataResidue
 *
 *			set pkt_residue
 *		goto  SCSA2USB_PKT_DO_COMP
 *
 * The reset recovery walks sequentially thru device reset, clearing
 * stalls and pipe resets. When the reset recovery completes we return
 * to the taskq thread.
 *
 * Clearing stalls clears the stall condition, resets the pipe, and
 * then returns to the transport.
 */
int
scsa2usb_bulk_only_transport(scsa2usb_state_t *scsa2usbp, scsa2usb_cmd_t *cmd)
{
	int	rval;
	int	nretry;
	usb_bulk_req_t *req;

	ASSERT(mutex_owned(&scsa2usbp->scsa2usb_mutex));

Cmd_Phase:
	/*
	 * Start Command Phase
	 * Initialize a bulk_req_t
	 */
	req = scsa2usb_init_bulk_req(scsa2usbp, USB_BULK_CBWCMD_LEN,
	    SCSA2USB_BULK_PIPE_TIMEOUT, USB_ATTRS_PIPE_RESET, USB_FLAGS_SLEEP);

	scsa2usb_fill_in_cbw(scsa2usbp, cmd, req->bulk_data);	/* Fill CBW */
	SCSA2USB_PRINT_CDB(scsa2usbp, cmd);			/* Print CDB */

	/* Send a Bulk Command Block Wrapper (CBW) to the device */
	mutex_exit(&scsa2usbp->scsa2usb_mutex);

	ASSERT(req->bulk_timeout);
	rval = usb_pipe_bulk_xfer(scsa2usbp->scsa2usb_bulkout_pipe, req,
	    USB_FLAGS_SLEEP);
	mutex_enter(&scsa2usbp->scsa2usb_mutex);

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_bulk_only_transport: "
	    "sent cmd = 0x%x Tag = 0x%x DataXferLen = 0x%lx rval = %d",
	    cmd->cmd_cdb[SCSA2USB_OPCODE], cmd->cmd_tag, cmd->cmd_xfercount,
	    rval);

	if (rval != USB_SUCCESS) {
		scsa2usb_bulk_only_handle_error(scsa2usbp, req);

		return (TRAN_FATAL_ERROR);
	}

	/* free the data */
	SCSA2USB_FREE_MSG(req->bulk_data);
	req->bulk_data = NULL;

	/*
	 * Start Data Phase
	 * re-set timeout
	 */
	req->bulk_timeout = scsa2usb_bulk_timeout(cmd->cmd_timeout);

	/*
	 * we've not transferred any data yet; updated in
	 * scsa2usb_handle_data_done
	 */
	cmd->cmd_resid_xfercount = cmd->cmd_xfercount;

	if (cmd->cmd_xfercount) {
		/* start I/O to/from the device */
		rval = scsa2usb_handle_data_start(scsa2usbp, cmd, req);

		/* handle data returned, if any */
		scsa2usb_handle_data_done(scsa2usbp, cmd, req);

		if (rval != USB_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_MASK_SCSA,
			    scsa2usbp->scsa2usb_log_handle,
			    "data xfer phase, error =  %d, cr = %d",
			    rval, req->bulk_completion_reason);
			/*
			 * we ran into an error
			 */
			if (req->bulk_completion_reason == USB_CR_STALL) {
				if (scsa2usbp->scsa2usb_cur_pkt) {
					scsa2usbp->scsa2usb_cur_pkt->
					    pkt_reason = CMD_TRAN_ERR;
				}
			} else {
				scsa2usb_bulk_only_handle_error(scsa2usbp, req);

				return (TRAN_FATAL_ERROR);
			}
		} /* end of else */

		/* free the data */
		SCSA2USB_FREE_MSG(req->bulk_data);
		req->bulk_data = NULL;
	}

	/*
	 * Start status phase
	 * read in CSW
	 */
	for (nretry = 0; nretry < SCSA2USB_STATUS_RETRIES; nretry++) {
		rval = scsa2usb_handle_status_start(scsa2usbp, req);

		if ((rval != USB_SUCCESS) &&
		    (req->bulk_completion_reason == USB_CR_STALL)) {
			/*
			 * We ran into STALL condition here.
			 * If the condition cannot be cleared
			 * successfully, retry for limited times.
			 */
			scsa2usbp->scsa2usb_pkt_state =
			    SCSA2USB_PKT_PROCESS_CSW;
		} else {

			break;
		}
	}

	if (rval == USB_SUCCESS) {
		/* process CSW */
		rval = scsa2usb_handle_csw_result(scsa2usbp, req->bulk_data);
	} else {
		scsa2usb_bulk_only_handle_error(scsa2usbp, req);

		return (TRAN_FATAL_ERROR);
	}

	SCSA2USB_FREE_BULK_REQ(req);	/* free request */

	if ((rval == USB_SUCCESS) &&		/* CSW was ok */
	    (scsa2usbp->scsa2usb_cur_pkt->pkt_reason == CMD_CMPLT) &&
	    (cmd->cmd_xfercount != 0) &&	/* more data to xfer */
	    !cmd->cmd_done) {			/* we aren't done yet */
		scsa2usb_setup_next_xfer(scsa2usbp, cmd);
		goto Cmd_Phase;
	}

	return (rval == USB_SUCCESS ? TRAN_ACCEPT : TRAN_FATAL_ERROR);
}


/*
 * scsa2usb_fill_in_cbw:
 *	Fill in a CBW request packet. This
 *	packet is transported to the device
 */
static void
scsa2usb_fill_in_cbw(scsa2usb_state_t *scsa2usbp,
    scsa2usb_cmd_t *cmd, mblk_t *mp)
{
	int	i;
	int	len;
	uchar_t dir, *cdb = (uchar_t *)(&cmd->cmd_cdb);

	ASSERT(mutex_owned(&scsa2usbp->scsa2usb_mutex));

	*mp->b_wptr++ = CBW_MSB(CBW_SIGNATURE);	/* CBW Signature */;
	*mp->b_wptr++ = CBW_MID1(CBW_SIGNATURE);
	*mp->b_wptr++ = CBW_MID2(CBW_SIGNATURE);
	*mp->b_wptr++ = CBW_LSB(CBW_SIGNATURE);
	*mp->b_wptr++ = CBW_LSB(cmd->cmd_tag);	/* CBW Tag */
	*mp->b_wptr++ = CBW_MID2(cmd->cmd_tag);
	*mp->b_wptr++ = CBW_MID1(cmd->cmd_tag);
	*mp->b_wptr++ = CBW_MSB(cmd->cmd_tag);

	dir = cmd->cmd_dir;
	len = cmd->cmd_xfercount;
#ifdef	SCSA2USB_BULK_ONLY_TEST
	if (scsa2usb_test_case_2 && (cdb[0] == SCMD_READ_CAPACITY)) {
		/* Host expects no data. The device wants data. Hn < Di */
		scsa2usb_test_case_2 = len = 0;
		USB_DPRINTF_L1(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
		    "TEST 2: Hn < Di cdb: 0x%x len: 0x%x", cdb[0], len);
	}

	if (scsa2usb_test_case_3 && (cmd->cmd_dir == CBW_DIR_OUT)) {
		/* Host expects no data. The device wants data. Hn < Do */
		if (cdb[0] == SCMD_WRITE_G1) {
			scsa2usb_test_case_3 = len = 0;
			USB_DPRINTF_L1(DPRINT_MASK_SCSA,
			    scsa2usbp->scsa2usb_log_handle,
			    "TEST 3: Hn < Do cdb: 0x%x len:%x", cdb[0], len);
		}
	}

	if (scsa2usb_test_case_4 && (cdb[0] == SCMD_READ_G1)) {
		cdb[0] = 0x5e;
		USB_DPRINTF_L1(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
		    "TEST 4: Hi > Dn: changed cdb to 0x%x", cdb[0]);
		scsa2usb_test_case_4 = 0;
	}

	if (scsa2usb_test_case_7 && (cmd->cmd_cdb[0] == SCMD_READ_G1)) {
		len -= 0x10;
		USB_DPRINTF_L1(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
		    "TEST 7: Hi < Di cdb: 0x%x len: 0x%x", cdb[0], len);
		scsa2usb_test_case_7 = 0;
	}

	if (scsa2usb_test_case_8 && (cdb[0] == SCMD_READ_G1)) {
		dir = (dir == CBW_DIR_IN) ? CBW_DIR_OUT : dir;
		USB_DPRINTF_L1(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
		    "TEST 8: Hi <> Do cdb: 0x%x dir: 0x%x", cdb[0], dir);
	}

	if (scsa2usb_test_case_9 && (cdb[0] == SCMD_WRITE_G1)) {
		USB_DPRINTF_L1(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
		    "TEST 9: Ho <> Di (%x)", cdb[0]);
		cdb[SCSA2USB_LEN_0] = cdb[SCSA2USB_LEN_1] = 0;
		scsa2usb_test_case_9 = 0;
	}

	if (scsa2usb_test_case_10 && (cdb[0] == SCMD_WRITE_G1)) {
		dir = (dir == CBW_DIR_OUT) ? CBW_DIR_IN : dir;
		USB_DPRINTF_L1(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
		    "TEST 10: Ho <> Di cdb: 0x%x dir: 0x%x", cdb[0], dir);
	}

	/*
	 * This case occurs when the device intends to receive
	 * more data from the host than the host sends.
	 */
	if (scsa2usb_test_case_13) {
		if ((cdb[0] == SCMD_WRITE_G1) || (cdb[0] == SCMD_READ_G1)) {
			USB_DPRINTF_L1(DPRINT_MASK_SCSA,
			    scsa2usbp->scsa2usb_log_handle, "TEST 13: Ho < Do");

			len -= 30;
			scsa2usb_test_case_13 = 0;
		}
	}
#endif	/* SCSA2USB_BULK_ONLY_TEST */

	*mp->b_wptr++ = CBW_MSB(len);		/* Transfer Length */
	*mp->b_wptr++ = CBW_MID1(len);
	*mp->b_wptr++ = CBW_MID2(len);
	*mp->b_wptr++ = CBW_LSB(len);

	*mp->b_wptr++ = dir;			/* Transfer Direction */
	*mp->b_wptr++ = cmd->cmd_pkt->pkt_address.a_lun;	/* Lun # */
	*mp->b_wptr++ = cmd->cmd_actual_len;			/* CDB Len */

	/* Copy the CDB out */
	for (i = 0; i < CBW_CDB_LEN; i++) {
		*mp->b_wptr++ = *cdb++;
	}
#ifdef DUMP_CWB
{
	int len = mp->b_wptr - mp->b_rptr;
	char *buf;

	int i;

	cmn_err(CE_CONT, "CWB: len=%d\n", len);
	buf = kmem_zalloc(512, KM_SLEEP);
	for (i = 0; i < len; i++) {
		sprintf(&buf[strlen(buf)], "%02x ", mp->b_rptr[i]);
	}
	cmn_err(CE_CONT, "%s\n", buf);
	kmem_free(buf, 512);
}
#endif

}


/*
 * scsa2usb_bulk_only_handle_error:
 *	handle transport errors and start recovery
 */
static void
scsa2usb_bulk_only_handle_error(scsa2usb_state_t *scsa2usbp,
    usb_bulk_req_t *req)
{
	struct scsi_pkt *pkt = scsa2usbp->scsa2usb_cur_pkt;

	USB_DPRINTF_L2(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_bulk_only_handle_error: req = 0x%p, cr = 0x%x",
	    (void *)req, (req ? req->bulk_completion_reason : 0));

	if (req) {
		SCSA2USB_SET_PKT_DO_COMP_STATE(scsa2usbp);

		/* invoke reset recovery */
		switch (req->bulk_completion_reason) {
		case USB_CR_STALL:
			if (pkt) {
				pkt->pkt_reason = CMD_TRAN_ERR;
			}
			break;
		case USB_CR_TIMEOUT:
			if (pkt) {
				pkt->pkt_reason = CMD_TIMEOUT;
				pkt->pkt_statistics |= STAT_TIMEOUT;
			}
			break;
		case USB_CR_DEV_NOT_RESP:
			if (pkt) {
				pkt->pkt_reason = CMD_DEV_GONE;
				/* scsi_poll relies on this */
				pkt->pkt_state = STATE_GOT_BUS;
			}
			break;
		default:
			if (pkt) {
				pkt->pkt_reason = CMD_TRAN_ERR;
			}
		}
		scsa2usb_bulk_only_reset_recovery(scsa2usbp);
	}

	SCSA2USB_FREE_BULK_REQ(req);
}


/*
 * scsa2usb_handle_status_start:
 *	Receive status data
 */
static int
scsa2usb_handle_status_start(scsa2usb_state_t *scsa2usbp,
    usb_bulk_req_t *req)
{
	int rval;

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_handle_status_start: req = 0x%p", (void *)req);

	ASSERT(mutex_owned(&scsa2usbp->scsa2usb_mutex));

	/* setup up for receiving CSW */
#ifdef	SCSA2USB_BULK_ONLY_TEST
	req->bulk_attributes = 0;
#else
	req->bulk_attributes = USB_ATTRS_SHORT_XFER_OK;
#endif	/* SCSA2USB_BULK_ONLY_TEST */
	req->bulk_len = CSW_LEN;

	SCSA2USB_FREE_MSG(req->bulk_data);
	req->bulk_data = allocb_wait(req->bulk_len,
	    BPRI_LO, STR_NOSIG, NULL);

	/* Issue the request */
	mutex_exit(&scsa2usbp->scsa2usb_mutex);

	ASSERT(req->bulk_timeout);
	rval = usb_pipe_bulk_xfer(scsa2usbp->scsa2usb_bulkin_pipe, req,
	    USB_FLAGS_SLEEP);
	mutex_enter(&scsa2usbp->scsa2usb_mutex);

	USB_DPRINTF_L3(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_handle_status_start: END rval = 0x%x", rval);

	if (rval != USB_SUCCESS) {
		if (scsa2usbp->scsa2usb_pkt_state == SCSA2USB_PKT_PROCESS_CSW) {
			scsa2usb_bulk_only_reset_recovery(scsa2usbp);

			return (rval);
		}

		if (req->bulk_completion_reason == USB_CR_STALL) {
			(void) scsa2usb_clear_ept_stall(scsa2usbp,
			    scsa2usbp->scsa2usb_bulkin_ept.bEndpointAddress,
			    scsa2usbp->scsa2usb_bulkin_pipe, "bulk-in");
		}
	}

	return (rval);
}


/*
 * scsa2usb_handle_csw_result:
 *	Handle status results
 */
static int
scsa2usb_handle_csw_result(scsa2usb_state_t *scsa2usbp, mblk_t *data)
{
	int		rval = USB_SUCCESS;
	int		residue;
	char		*msg = "CSW FAILED";
	uint_t		signature, tag, status;
	usb_bulk_csw_t	csw;
	struct scsi_pkt *pkt = scsa2usbp->scsa2usb_cur_pkt;
	scsa2usb_cmd_t	*cmd = PKT2CMD(pkt);

	ASSERT(mutex_owned(&scsa2usbp->scsa2usb_mutex));

	/*
	 * This shouldn't happen. It implies the device's
	 * firmware is bad and has returned NULL CSW.
	 * return failure back.
	 */
	if (data == NULL) {
		USB_DPRINTF_L2(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
		    "scsa2usb_handle_csw_result: data == NULL");

		return (USB_FAILURE);
	}

	/* check if we got back CSW_LEN or not */
	if (MBLKL(data) != CSW_LEN) {
		USB_DPRINTF_L2(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
		    "scsa2usb_handle_csw_result: no enough data (%ld)",
		    (long)(MBLKL(data)));

		return (USB_FAILURE);
	}

	/* Read into csw */
	bcopy(data->b_rptr, &csw, CSW_LEN);

	status = csw.csw_bCSWStatus;
	signature = SCSA2USB_MK_32BIT(csw.csw_dCSWSignature3,
	    csw.csw_dCSWSignature2, csw.csw_dCSWSignature1,
	    csw.csw_dCSWSignature0);
	residue = SCSA2USB_MK_32BIT(csw.csw_dCSWDataResidue3,
	    csw.csw_dCSWDataResidue2, csw.csw_dCSWDataResidue1,
	    csw.csw_dCSWDataResidue0);
	tag = SCSA2USB_MK_32BIT(csw.csw_dCSWTag3, csw.csw_dCSWTag2,
	    csw.csw_dCSWTag1, csw.csw_dCSWTag0);

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "CSW: Signature = 0x%x Status = 0%x Tag = 0x%x Residue = 0x%x",
	    signature, status, tag,  residue);

	/* Check for abnormal errors */
	if ((signature != CSW_SIGNATURE) || (tag != cmd->cmd_tag) ||
	    (status > CSW_STATUS_PHASE_ERROR)) {

		USB_DPRINTF_L2(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
		    "CSW_ERR: Status = 0x%x, Tag = 0x%x xfercount = 0x%lx",
		    status, cmd->cmd_tag, cmd->cmd_total_xfercount);

		return (USB_FAILURE);
	}

	switch (status) {
	case CSW_STATUS_GOOD:
		/*
		 * Fail the command if the device misbehaves and
		 * gives a good status but doesn't transfer any data.
		 * Otherwise we'll get into an infinite retry loop.
		 *
		 * We test only against cmd_total_xfercount here and
		 * assume that this will not happen on a command that
		 * transfers a large amount of data and therefore may
		 * be split into separate transfers. For a large data
		 * transfer it is assumed that the device will return
		 * an error status if the transfer does not occur.
		 * this isn't quite correct because a subsequent request
		 * sense may not give a valid sense key.
		 */
		if (!cmd->cmd_done && residue &&
		    (residue == cmd->cmd_total_xfercount)) {
			*(pkt->pkt_scbp) = STATUS_CHECK;
			cmd->cmd_xfercount = 0;
			cmd->cmd_done = 1;
		} else {
			msg = "CSW GOOD";
		}
		break;
	case CSW_STATUS_FAILED:
		*(pkt->pkt_scbp) = STATUS_CHECK; /* Set check condition */
		cmd->cmd_done = 1;
		break;
	case CSW_STATUS_PHASE_ERROR:
		USB_DPRINTF_L2(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
		    "scsa2usb_handle_csw_result: Phase Error");

		/* invoke reset recovery */
		scsa2usb_bulk_only_handle_error(scsa2usbp, NULL);

		return (USB_FAILURE);
	default:	/* shouldn't happen anymore */
		USB_DPRINTF_L2(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
		    "scsa2usb_handle_csw_result: Invalid CSW");

		/* invoke reset recovery */
		scsa2usb_bulk_only_handle_error(scsa2usbp, NULL);

		return (USB_SUCCESS);
	} /* end of switch */

	/* Set resid */
	if (residue || cmd->cmd_resid_xfercount) {
		USB_DPRINTF_L2(DPRINT_MASK_SCSA,
		    scsa2usbp->scsa2usb_log_handle,
		    "total=0x%lx cmd_xfercount=0x%lx residue=0x%x "
		    "cmd_offset=0x%lx",
		    cmd->cmd_total_xfercount, cmd->cmd_xfercount,
		    residue, cmd->cmd_offset);

		/*
		 * we need to adjust using the residue and
		 * assume worst case. Some devices lie about
		 * residue. some report a residue greater than
		 * the residue we have calculated.
		 * first adjust back the total_xfercount
		 */
		cmd->cmd_total_xfercount += cmd->cmd_xfercount -
		    cmd->cmd_resid_xfercount;
		/*
		 * we need to adjust cmd_offset as well, or the data
		 * buffer for subsequent transfer may exceed the buffer
		 * boundary
		 */
		cmd->cmd_offset -= cmd->cmd_xfercount -
		    cmd->cmd_resid_xfercount;

		/*
		 * now take the min of the reported residue by
		 * the device and the requested xfer count
		 * (just in case the device reported a residue greater
		 * than our request count).
		 * then take the max of this residue and the residue
		 * that the HCD reported and subtract this from
		 * the request count. This is the actual number
		 * of valid bytes transferred during the last transfer
		 * which we now subtract from the total_xfercount
		 */
		if ((!(scsa2usbp->scsa2usb_attrs &
		    SCSA2USB_ATTRS_USE_CSW_RESIDUE)) ||
		    (residue < 0) ||
		    (residue > cmd->cmd_total_xfercount)) {
			/* some devices lie about the resid, ignore */
			cmd->cmd_total_xfercount -=
			    cmd->cmd_xfercount - cmd->cmd_resid_xfercount;
			cmd->cmd_offset +=
			    cmd->cmd_xfercount - cmd->cmd_resid_xfercount;
		} else {
			cmd->cmd_total_xfercount -=
			    cmd->cmd_xfercount -
			    max(min(residue, cmd->cmd_xfercount),
			    cmd->cmd_resid_xfercount);
			cmd->cmd_offset +=
			    cmd->cmd_xfercount -
			    max(min(residue, cmd->cmd_xfercount),
			    cmd->cmd_resid_xfercount);
			/*
			 * if HCD does not report residue while the device
			 * reports a residue equivalent to the xfercount,
			 * it is very likely the device lies about the
			 * residue. we need to stop the command, or we'll
			 * get into an infinite retry loop.
			 */
			if ((cmd->cmd_resid_xfercount == 0) &&
			    (residue == cmd->cmd_xfercount)) {
				cmd->cmd_xfercount = 0;
				cmd->cmd_done = 1;
			}
		}

		pkt->pkt_resid = cmd->cmd_total_xfercount;
	}

	USB_DPRINTF_L3(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_handle_csw_result: %s, resid: 0x%lx",
	    msg, pkt->pkt_resid);

	/* we are done and ready to callback */
	SCSA2USB_SET_PKT_DO_COMP_STATE(scsa2usbp);

	return (rval);
}


/*
 * scsa2usb_bulk_only_reset_recovery:
 *	Reset the USB device step-wise in case of errors.
 *	NOTE that the order of reset is very important.
 */
static void
scsa2usb_bulk_only_reset_recovery(scsa2usb_state_t *scsa2usbp)
{
	int		rval;
	usb_cr_t	completion_reason;
	usb_cb_flags_t	cb_flags;

	USB_DPRINTF_L2(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_bulk_only_reset_recovery: scsa2usbp = 0x%p",
	    (void *)scsa2usbp);

	ASSERT(mutex_owned(&scsa2usbp->scsa2usb_mutex));

	if (!(SCSA2USB_DEVICE_ACCESS_OK(scsa2usbp))) {

		return;
	}

	/*
	 * assume that the reset will be successful. if it isn't, retrying
	 * from target driver won't help much
	 */
	if (scsa2usbp->scsa2usb_cur_pkt) {
		scsa2usbp->scsa2usb_cur_pkt->pkt_statistics |= STAT_DEV_RESET;
	}

	/* set the reset condition */
	scsa2usbp->scsa2usb_pipe_state = SCSA2USB_PIPE_DEV_RESET;

	/* Send a sync DEVICE-RESET request to the device */
	mutex_exit(&scsa2usbp->scsa2usb_mutex);
	rval = usb_pipe_sync_ctrl_xfer(scsa2usbp->scsa2usb_dip,
	    scsa2usbp->scsa2usb_default_pipe,
	    USB_DEV_REQ_TYPE_CLASS | USB_DEV_REQ_RCPT_IF,
	    (uint8_t)BULK_ONLY_RESET,		/* bRequest */
	    0,					/* wValue */
	    scsa2usbp->scsa2usb_intfc_num,	/* wIndex */
	    0,					/* wLength */
	    NULL, 0, &completion_reason, &cb_flags, 0);
	mutex_enter(&scsa2usbp->scsa2usb_mutex);

	USB_DPRINTF_L2(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "\tbulk-only device-reset rval: %d", rval);
	if (rval != USB_SUCCESS) {
		goto exc_exit;
	}

	/* reset and clear STALL on bulk-in pipe */
	rval = scsa2usb_clear_ept_stall(scsa2usbp,
	    scsa2usbp->scsa2usb_bulkin_ept.bEndpointAddress,
	    scsa2usbp->scsa2usb_bulkin_pipe, "bulk-in");

	USB_DPRINTF_L2(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "\tbulk-in pipe clear stall: %d", rval);
	if (rval != USB_SUCCESS) {
		goto exc_exit;
	}

	/* reset and clear STALL on bulk-out pipe */
	rval = scsa2usb_clear_ept_stall(scsa2usbp,
	    scsa2usbp->scsa2usb_bulkout_ept.bEndpointAddress,
	    scsa2usbp->scsa2usb_bulkout_pipe, "bulk-out");

	USB_DPRINTF_L2(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "\tbulk-out pipe clear stall: %d", rval);

exc_exit:
	/* clear the reset condition */
	scsa2usbp->scsa2usb_pipe_state &= ~SCSA2USB_PIPE_DEV_RESET;
}


/*
 * scsa2usb_bulk_only_get_max_lun:
 *	this function returns the number of LUNs supported by the device
 */
int
scsa2usb_bulk_only_get_max_lun(scsa2usb_state_t *scsa2usbp)
{
	int		luns = 1, rval;
	mblk_t		*data = NULL;
	usb_cr_t	completion_reason;
	usb_cb_flags_t	cb_flags;

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_bulk_only_get_max_lun:");

	ASSERT(mutex_owned(&scsa2usbp->scsa2usb_mutex));

	mutex_exit(&scsa2usbp->scsa2usb_mutex);
	rval = usb_pipe_sync_ctrl_xfer(scsa2usbp->scsa2usb_dip,
	    scsa2usbp->scsa2usb_default_pipe,
	    BULK_ONLY_GET_MAXLUN_BMREQ,		/* bmRequestType */
	    BULK_ONLY_GET_MAXLUN_REQ,		/* bRequest */
	    0,					/* wValue */
	    scsa2usbp->scsa2usb_intfc_num,	/* wIndex */
	    1,					/* wLength */
	    &data, 0,
	    &completion_reason, &cb_flags, 0);
	mutex_enter(&scsa2usbp->scsa2usb_mutex);

	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
		    "get max lun failed, rval=%d cr=%d cb=0x%x data=0x%p",
		    rval, completion_reason, cb_flags, (void *)data);
	} else {
		/*
		 * This check ensures that we have valid data returned back.
		 * Otherwise we assume that device supports only one LUN.
		 */
		if (MBLKL(data) != 1) {
			USB_DPRINTF_L2(DPRINT_MASK_SCSA,
			    scsa2usbp->scsa2usb_log_handle,
			    "device reported incorrect luns (adjusting to 1)");
		} else {
			/*
			 * Set scsa2usb_n_luns to value returned by the device
			 * plus 1. (See Section 3.2)
			 */
			luns = *data->b_rptr + 1;

			/*
			 * In case a device returns incorrect LUNs
			 * which are more than 15 or negative or 0;
			 * we assume 1.
			 */
			if ((luns >= SCSA2USB_MAX_LUNS) || (luns <= 0)) {
				USB_DPRINTF_L2(DPRINT_MASK_SCSA,
				    scsa2usbp->scsa2usb_log_handle,
				    "device reported %d luns "
				    "(adjusting to 1)", luns);
				luns = 1;
			}
		}
	}

	SCSA2USB_FREE_MSG(data);	/* Free data */

	return (luns);
}
