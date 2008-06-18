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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * scsa2usb_ms_cbi.c:
 *
 * This file implements USB Mass Storage Class
 * Control Bulk Interrupt (CB/CBI) transport v1.0
 * http://www.usb.org/developers/data/devclass/usbmass-cbi10.pdf
 */
#include <sys/usb/usba/usbai_version.h>
#include <sys/scsi/scsi.h>
#include <sys/callb.h>		/* needed by scsa2usb.h */
#include <sys/strsubr.h>

#include <sys/usb/usba.h>
#include <sys/usb/usba/usba_private.h>
#include <sys/usb/usba/usba_ugen.h>

#include <sys/usb/clients/mass_storage/usb_cbi.h>
#include <sys/usb/scsa2usb/scsa2usb.h>

/*
 * Function Prototypes
 */
int		scsa2usb_cbi_transport(scsa2usb_state_t *, scsa2usb_cmd_t *);
static int	scsa2usb_handle_cbi_status(usb_intr_req_t *);
static void	scsa2usb_cbi_reset_recovery(scsa2usb_state_t *);
static void	scsa2usb_cbi_handle_error(scsa2usb_state_t *, int, usb_cr_t);
static usb_intr_req_t *scsa2usb_cbi_start_intr_polling(scsa2usb_state_t *);
void		scsa2usb_cbi_stop_intr_polling(scsa2usb_state_t *);

/* extern functions */
extern void	scsa2usb_setup_next_xfer(scsa2usb_state_t *, scsa2usb_cmd_t *);
extern int	scsa2usb_handle_data_start(scsa2usb_state_t *,
		    scsa2usb_cmd_t *, usb_bulk_req_t *);
extern void	scsa2usb_handle_data_done(scsa2usb_state_t *, scsa2usb_cmd_t *,
		    usb_bulk_req_t *);
extern usb_bulk_req_t *scsa2usb_init_bulk_req(scsa2usb_state_t *,
			    size_t, uint_t, usb_req_attrs_t, usb_flags_t);
extern int	scsa2usb_clear_ept_stall(scsa2usb_state_t *, uint_t,
		    usb_pipe_handle_t, char *);
extern void	scsa2usb_close_usb_pipes(scsa2usb_state_t *);

#ifdef DEBUG	/* debugging information */
extern void	scsa2usb_print_cdb(scsa2usb_state_t *, scsa2usb_cmd_t *);
#endif	/* DEBUG */


/*
 * scsa2usb_cbi_transport:
 *	Implements the CB/CBI state machine by these steps:
 *	a) Issues command to the device over control pipe.
 *	b) Start Data Phase if applicable
 *	c) Start Status Phase
 *
 *	returns TRAN_* values and not USB_SUCCESS/FAILURE
 *
 * scsa2usb_cbi_transport() handles the normal transitions or
 * continuation after clearing stalls or error recovery.
 *
 * Command Phase:
 *	prepare a valid command and transport it on default pipe
 *	if error on default-pipe:
 *		set pkt_reason to CMD_TRAN_ERR
 *		new pkt state is SCSA2USB_PKT_DO_COMP
 *		do reset recovery synchronously
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
 *			do reset recovery synchronously
 *		else (no error)
 *			receive status
 *
 *	 data: (out)
 *		if stall on bulkout pipe
 *			terminate data transfers
 *			clear stall on bulkout synchronously USBA
 *		else if other exception
 *			set pkt_reason to CMD_TRAN_ERR
 *			new pkt state is SCSA2USB_PKT_DO_COMP
 *			do reset recovery synchronously
 *		else (no error)
 *			receive status
 *
 * Status Phase: (on Interrupt pipe for CBI devices only)
 *	if error
 *		if stall
 *			new pkt state is SCSA2USB_PKT_DO_COMP
 *			clear stall on interrupt pipe
 *		else
 *			set pkt_reason to CMD_TRAN_ERR
 *			new pkt state is SCSA2USB_PKT_DO_COMP
 *			do reset recovery synchronously
 *	else (no error)
 *		goto read status
 *
 * read status:
 *	if not OK or phase error
 *		new pkt state is SCSA2USB_PKT_DO_COMP
 *		set pkt reason CMD_TRAN_ERR
 *		reset recovery synchronously
 *	else (status ok)
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
scsa2usb_cbi_transport(scsa2usb_state_t *scsa2usbp, scsa2usb_cmd_t *cmd)
{
	int			i, rval = TRAN_ACCEPT;
	mblk_t			*data;
	usb_cr_t		completion_reason;
	usb_cb_flags_t		cb_flags;
	usb_bulk_req_t		*data_req;
	usb_intr_req_t		*status_req;

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_cbi_transport: cmd = 0x%p", (void *)cmd);
	ASSERT(mutex_owned(&scsa2usbp->scsa2usb_mutex));

Cmd_Phase:
	if (!(SCSA2USB_DEVICE_ACCESS_OK(scsa2usbp))) {

		return (TRAN_FATAL_ERROR);
	}

	/*
	 * Start command phase (C - in CBI)
	 */
	data = allocb_wait(CBI_CLASS_CMD_LEN, BPRI_LO, STR_NOSIG, NULL);

	/* Initialize the data */
	for (i = 0; i < CBI_CLASS_CMD_LEN; i++) {
		*data->b_wptr++ = cmd->cmd_cdb[i];
	}

	SCSA2USB_PRINT_CDB(scsa2usbp, cmd);	/* print the CDB */

	/* Send the Command to the device */
	mutex_exit(&scsa2usbp->scsa2usb_mutex);
	rval = usb_pipe_sync_ctrl_xfer(scsa2usbp->scsa2usb_dip,
	    scsa2usbp->scsa2usb_default_pipe,
	    CBI_REQUEST_TYPE,			/* bmRequestType */
	    0,					/* bRequest */
	    CBI_WVALUE,				/* wValue */
	    scsa2usbp->scsa2usb_intfc_num,	/* wIndex */
	    CBI_CLASS_CMD_LEN,			/* wLength */
	    &data,				/* data */
	    USB_ATTRS_PIPE_RESET,		/* attributes */
	    &completion_reason, &cb_flags, USB_FLAGS_SLEEP);
	mutex_enter(&scsa2usbp->scsa2usb_mutex);

	USB_DPRINTF_L2(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_cbi_transport: sent cmd = 0x%x  rval = %d",
	    cmd->cmd_cdb[SCSA2USB_OPCODE], rval);

	SCSA2USB_FREE_MSG(data);	/* get rid of the data */
	if (rval != USB_SUCCESS) {
		scsa2usb_cbi_handle_error(scsa2usbp, rval, completion_reason);

		return (TRAN_FATAL_ERROR);
	}

	/*
	 * Xferred command to the device.
	 * Start data phase (B - in CBI)
	 */

	/*
	 * we've not transferred any data yet; updated in
	 * scsa2usb_handle_data_done
	 */
	cmd->cmd_resid_xfercount = 0;

	/* if data to be xferred ? */
	if (cmd->cmd_xfercount) {

		/* Initialize a bulk_req_t */
		data_req = scsa2usb_init_bulk_req(scsa2usbp, 0,
		    cmd->cmd_timeout, USB_ATTRS_PIPE_RESET, USB_FLAGS_SLEEP);

		/* start I/O to/from the device */
		rval = scsa2usb_handle_data_start(scsa2usbp, cmd,
		    data_req);
		/* handle data returned */
		scsa2usb_handle_data_done(scsa2usbp, cmd,
		    data_req);
		if (rval != USB_SUCCESS) {
			/*
			 * we ran into an error and it wasn't a STALL
			 */
			if (data_req->bulk_completion_reason == USB_CR_STALL) {
				if (scsa2usbp->scsa2usb_cur_pkt) {
					scsa2usbp->scsa2usb_cur_pkt->
					    pkt_reason = CMD_TRAN_ERR;
				}
			} else {
				scsa2usb_cbi_handle_error(scsa2usbp,
				    rval, data_req->bulk_completion_reason);

				/* get rid of req */
				SCSA2USB_FREE_BULK_REQ(data_req);

				return (TRAN_FATAL_ERROR);
			}
		}

		SCSA2USB_FREE_BULK_REQ(data_req); /* get rid of bulk_req */
	}

	/* CB devices don't do status over interrupt pipe */
	if (SCSA2USB_IS_CB(scsa2usbp)) {
		USB_DPRINTF_L2(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
		    "scsa2usb_cbi_transport: CB done rval = %d", rval);
		goto end_it;
	}

	/*
	 * Start status phase (I - in CBI)
	 */

	/* Get Status over interrupt pipe */
	if ((status_req = scsa2usb_cbi_start_intr_polling(scsa2usbp)) == NULL) {

		return (TRAN_FATAL_ERROR); /* lack of better return code */
	}

	rval = scsa2usb_handle_cbi_status(status_req);

	usb_free_intr_req(status_req);

	/* stop interrupt pipe polling (CBI only) */
	if (SCSA2USB_IS_CBI(scsa2usbp)) {
		scsa2usb_cbi_stop_intr_polling(scsa2usbp);
	}

end_it:
	if ((rval == USB_SUCCESS) &&		/* CSW was ok */
	    (scsa2usbp->scsa2usb_cur_pkt->pkt_reason == CMD_CMPLT) &&
	    (cmd->cmd_xfercount != 0) &&	/* more data to xfer */
	    !cmd->cmd_done) {			/* we aren't done yet */
		scsa2usb_setup_next_xfer(scsa2usbp, cmd);
		goto Cmd_Phase;
	} else {
		if (SCSA2USB_IS_CB(scsa2usbp)) {
			cmd->cmd_done = 1;
			SCSA2USB_SET_PKT_DO_COMP_STATE(scsa2usbp);
		}
	}

	return (rval == USB_SUCCESS ? TRAN_ACCEPT : TRAN_FATAL_ERROR);
}


/*
 * scsa2usb_cbi_handle_error:
 *	handle errors from transport that are not STALL conditions
 */
static void
scsa2usb_cbi_handle_error(scsa2usb_state_t *scsa2usbp, int rval, usb_cr_t cr)
{
	struct scsi_pkt	*pkt = scsa2usbp->scsa2usb_cur_pkt;

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_cbi_handle_error: data error %d cr = %d", rval, cr);

	SCSA2USB_SET_PKT_DO_COMP_STATE(scsa2usbp);

	/* do reset error recovery */
	switch (cr) {
	case USB_CR_STALL:
		if (pkt) {
			pkt->pkt_reason = CMD_TRAN_ERR;
			*(pkt->pkt_scbp) = STATUS_CHECK;
		}
		break;
	case USB_CR_TIMEOUT:
		if (pkt) {
			pkt->pkt_reason = CMD_TIMEOUT;
			pkt->pkt_statistics |= STAT_TIMEOUT;
		}
		break;
	case USB_CR_DEV_NOT_RESP:
		scsa2usb_cbi_stop_intr_polling(scsa2usbp);
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
		scsa2usb_cbi_reset_recovery(scsa2usbp);
	}
}


/*
 * scsa2usb_cbi_start_intr_polling:
 *	start polling asynchronously without notification
 */
static usb_intr_req_t *
scsa2usb_cbi_start_intr_polling(scsa2usb_state_t *scsa2usbp)
{
	int rval;
	usb_pipe_state_t   pipe_state;
	usb_intr_req_t *req = NULL;

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_cbi_start_intr_polling:");

	if (!SCSA2USB_IS_CBI(scsa2usbp)) {

		return (NULL);
	}

	req = usb_alloc_intr_req(scsa2usbp->scsa2usb_dip, 0, USB_FLAGS_SLEEP);
	req->intr_client_private = (usb_opaque_t)scsa2usbp;
	req->intr_attributes = USB_ATTRS_ONE_XFER | USB_ATTRS_PIPE_RESET |
	    USB_ATTRS_SHORT_XFER_OK;
	req->intr_len = scsa2usbp->scsa2usb_intr_ept.wMaxPacketSize;
	req->intr_timeout = 20;	/* arbitrary large for now */
	mutex_exit(&scsa2usbp->scsa2usb_mutex);

	if ((rval = usb_pipe_intr_xfer(scsa2usbp->scsa2usb_intr_pipe, req,
	    USB_FLAGS_SLEEP)) != USB_SUCCESS) {
		mutex_enter(&scsa2usbp->scsa2usb_mutex);
		USB_DPRINTF_L2(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
		    "polling failed rval: %d", rval);

		/* clear stall */
		if (req->intr_completion_reason == USB_CR_STALL) {
			(void) scsa2usb_clear_ept_stall(scsa2usbp,
			    scsa2usbp->scsa2usb_intr_ept.bEndpointAddress,
			    scsa2usbp->scsa2usb_intr_pipe, "intr");
		}

		/* handle other errors here */
		scsa2usb_cbi_handle_error(scsa2usbp, rval,
		    req->intr_completion_reason);
		mutex_exit(&scsa2usbp->scsa2usb_mutex);

		usb_free_intr_req(req);
		req = NULL;
	}

	rval = usb_pipe_get_state(scsa2usbp->scsa2usb_intr_pipe,
	    &pipe_state, USB_FLAGS_SLEEP);
	if (pipe_state != USB_PIPE_STATE_ACTIVE) {
		USB_DPRINTF_L2(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
		    "intr pipes state: %d, rval: %d", pipe_state, rval);
	}
	mutex_enter(&scsa2usbp->scsa2usb_mutex);

	return (req);
}


/*
 * scsa2usb_cbi_stop_intr_polling:
 *	Stop polling on interrupt pipe (for status)
 */
void
scsa2usb_cbi_stop_intr_polling(scsa2usb_state_t *scsa2usbp)
{
	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_cbi_stop_intr_polling:");

	ASSERT(mutex_owned(&scsa2usbp->scsa2usb_mutex));

	if (!SCSA2USB_IS_CBI(scsa2usbp)) {

		return;
	}

	if (scsa2usbp->scsa2usb_intr_pipe) {
		mutex_exit(&scsa2usbp->scsa2usb_mutex);
		usb_pipe_stop_intr_polling(scsa2usbp->scsa2usb_intr_pipe,
		    USB_FLAGS_SLEEP);
		mutex_enter(&scsa2usbp->scsa2usb_mutex);
	}
}


/*
 * scsa2usb_handle_cbi_status:
 *	Handle CBI status results
 */
static int
scsa2usb_handle_cbi_status(usb_intr_req_t *req)
{
	int rval = USB_SUCCESS;
	int status;
	char *msg;
	scsa2usb_cmd_t *cmd;
	scsa2usb_state_t *scsa2usbp = (scsa2usb_state_t *)
	    req->intr_client_private;

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_handle_cbi_status: req: 0x%p", (void *)req);

	ASSERT(mutex_owned(&scsa2usbp->scsa2usb_mutex));
	ASSERT(req->intr_data != NULL);

	cmd = PKT2CMD(scsa2usbp->scsa2usb_cur_pkt);
	status = *(req->intr_data->b_rptr + 1) & CBI_STATUS_MASK;

	/*
	 * CBI status contains ASC and ASCQ.
	 * SCMD_REQUEST_SENSE and SCMD_INQUIRY don't affect the sense data
	 * on CBI devices. So, we can ignore that info for these 2 commands.
	 *
	 * (See details in UFI spec section 3.5 - that says that INQUIRY,
	 * SEND_DIAG, and REQUEST_SENSE ought to be supported by any deivce
	 * irrespective).
	 */
	if ((cmd->cmd_cdb[SCSA2USB_OPCODE] == SCMD_REQUEST_SENSE) ||
	    (cmd->cmd_cdb[SCSA2USB_OPCODE] == SCMD_INQUIRY)) {
		USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
		    "scsa2usb_handle_cbi_status: CBI STATUS = (0x%x, 0x%x)",
		    *(req->intr_data->b_rptr), *(req->intr_data->b_rptr+1));

		SCSA2USB_SET_PKT_DO_COMP_STATE(scsa2usbp);

		return (USB_SUCCESS);
	}

	switch (status) {
	case CBI_STATUS_PASS:
		msg = "PASSED";
		/* non-zero command completion interrupt */
		if (*(req->intr_data->b_rptr)) {
			*(scsa2usbp->scsa2usb_cur_pkt->pkt_scbp) = STATUS_CHECK;
			cmd->cmd_done = 1;
		}
		break;
	case CBI_STATUS_FAILED:
	case CBI_STATUS_PERSISTENT_FAIL:
		msg = (status == CBI_STATUS_PERSISTENT_FAIL) ?
		    "PERSISTENT_FAILURE" : "FAILED";
		*(scsa2usbp->scsa2usb_cur_pkt->pkt_scbp) = STATUS_CHECK;
		cmd->cmd_done = 1;
		break;
	case CBI_STATUS_PHASE_ERR:
		msg = "PHASE_ERR";
		scsa2usb_cbi_reset_recovery(scsa2usbp);
		rval = USB_FAILURE;
		break;
	}

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "CBI STATUS = 0x%x %s (0x%x, 0x%x)", status, msg,
	    *(req->intr_data->b_rptr), *(req->intr_data->b_rptr+1));

	/* we are done and ready to callback */
	SCSA2USB_SET_PKT_DO_COMP_STATE(scsa2usbp);

	return (rval);
}


/*
 * scsa2usb_cbi_reset_recovery:
 *	Reset the USB device in case of errors.
 */
static void
scsa2usb_cbi_reset_recovery(scsa2usb_state_t *scsa2usbp)
{
	int		i, rval;
	mblk_t		*cdb;
	usb_cr_t	completion_reason;
	usb_cb_flags_t	cb_flags;

	USB_DPRINTF_L4(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "scsa2usb_cbi_reset_recovery: (0x%p)", (void *)scsa2usbp);

	ASSERT(mutex_owned(&scsa2usbp->scsa2usb_mutex));

	if (!(SCSA2USB_DEVICE_ACCESS_OK(scsa2usbp))) {

		return;
	}

	if (scsa2usbp->scsa2usb_cur_pkt) {
		scsa2usbp->scsa2usb_cur_pkt->pkt_statistics |= STAT_DEV_RESET;
	}

	/* Allocate an mblk for CBR */
	cdb = allocb_wait(CBI_CLASS_CMD_LEN, BPRI_LO, STR_NOSIG, NULL);

	*cdb->b_wptr++ = SCMD_SDIAG;	/* Set it to DIAG */
	*cdb->b_wptr++ = CBI_SELF_TEST;	/* Set it to reset */
	for (i = 2; i < CBI_CLASS_CMD_LEN; i++) {
		*cdb->b_wptr++ = CBI_CBR_VALUE;	/* Set it to 0xff */
	}

	scsa2usbp->scsa2usb_pipe_state = SCSA2USB_PIPE_DEV_RESET;

	/*
	 * Send a Reset request to the device
	 */
	mutex_exit(&scsa2usbp->scsa2usb_mutex);
	rval = usb_pipe_sync_ctrl_xfer(scsa2usbp->scsa2usb_dip,
	    scsa2usbp->scsa2usb_default_pipe,
	    CBI_REQUEST_TYPE,			/* bmRequestType */
	    0,					/* bRequest */
	    CBI_WVALUE,				/* wValue */
	    scsa2usbp->scsa2usb_intfc_num,	/* wIndex address */
	    CBI_CLASS_CMD_LEN,			/* wLength */
	    &cdb,				/* data to be sent */
	    0, &completion_reason, &cb_flags, 0);
	mutex_enter(&scsa2usbp->scsa2usb_mutex);

	USB_DPRINTF_L3(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "\tCBI RESET: rval = %x cr = %x", rval, completion_reason);
	if (rval != USB_SUCCESS) {
		goto exc_exit;
	}

	/* reset and clear STALL on bulk-in pipe */
	rval = scsa2usb_clear_ept_stall(scsa2usbp,
	    scsa2usbp->scsa2usb_bulkin_ept.bEndpointAddress,
	    scsa2usbp->scsa2usb_bulkin_pipe, "bulk-in");
	USB_DPRINTF_L3(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "\tclear stall on bulk-in pipe: %d", rval);
	if (rval != USB_SUCCESS) {
		goto exc_exit;
	}

	/* reset and clear STALL on bulk-out pipe */
	rval = scsa2usb_clear_ept_stall(scsa2usbp,
	    scsa2usbp->scsa2usb_bulkout_ept.bEndpointAddress,
	    scsa2usbp->scsa2usb_bulkout_pipe, "bulk-out");
	USB_DPRINTF_L3(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
	    "\tclear stall on bulk-out pipe: %d", rval);
	if (rval != USB_SUCCESS) {
		goto exc_exit;
	}

	/* reset and clear STALL on interrupt pipe */
	if (SCSA2USB_IS_CBI(scsa2usbp)) {
		rval = scsa2usb_clear_ept_stall(scsa2usbp,
		    scsa2usbp->scsa2usb_intr_ept.bEndpointAddress,
		    scsa2usbp->scsa2usb_intr_pipe, "intr");

		USB_DPRINTF_L3(DPRINT_MASK_SCSA, scsa2usbp->scsa2usb_log_handle,
		    "\tclear stall on intr pipe:  %d", rval);
	}

exc_exit:
	SCSA2USB_FREE_MSG(cdb);	/* Free the data */
	scsa2usbp->scsa2usb_pipe_state &= ~SCSA2USB_PIPE_DEV_RESET;
}
