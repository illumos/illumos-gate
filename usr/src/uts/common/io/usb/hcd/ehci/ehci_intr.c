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
 */
/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * EHCI Host Controller Driver (EHCI)
 *
 * The EHCI driver is a software driver which interfaces to the Universal
 * Serial Bus layer (USBA) and the Host Controller (HC). The interface to
 * the Host Controller is defined by the EHCI Host Controller Interface.
 *
 * This module contains the EHCI driver interrupt code, which handles all
 * Checking of status of USB transfers, error recovery and callbacks.
 */

#include <sys/usb/hcd/ehci/ehcid.h>
#include <sys/usb/hcd/ehci/ehci_xfer.h>
#include <sys/usb/hcd/ehci/ehci_util.h>

/*
 * EHCI Interrupt Handling functions.
 */
void		ehci_handle_ue(ehci_state_t		*ehcip);
void		ehci_handle_frame_list_rollover(
				ehci_state_t		*ehcip);
void		ehci_handle_endpoint_reclaimation(
				ehci_state_t		*ehcip);
void		ehci_traverse_active_qtd_list(
				ehci_state_t		*ehcip);
static ehci_qtd_t *ehci_create_done_qtd_list(
				ehci_state_t		*ehcip);
static usb_cr_t ehci_parse_error(
				ehci_state_t		*ehcip,
				ehci_qtd_t		*qtd);
usb_cr_t	ehci_check_for_error(
				ehci_state_t		*ehcip,
				ehci_pipe_private_t	*pp,
				ehci_trans_wrapper_t	*tw,
				ehci_qtd_t		*qtd,
				uint_t			ctrl);
static usb_cr_t	ehci_check_for_short_xfer(
				ehci_state_t		*ehcip,
				ehci_pipe_private_t	*pp,
				ehci_trans_wrapper_t	*tw,
				ehci_qtd_t		*qtd);
void		ehci_handle_error(
				ehci_state_t		*ehcip,
				ehci_qtd_t		*qtd,
				usb_cr_t		error);
static void	ehci_cleanup_data_underrun(
				ehci_state_t		*ehcip,
				ehci_trans_wrapper_t	*tw,
				ehci_qtd_t		*qtd);
static void	ehci_handle_normal_qtd(
				ehci_state_t		*ehcip,
				ehci_qtd_t		*qtd,
				ehci_trans_wrapper_t	*tw);
void		ehci_handle_ctrl_qtd(
				ehci_state_t		*ehcip,
				ehci_pipe_private_t	*pp,
				ehci_trans_wrapper_t	*tw,
				ehci_qtd_t		*qtd,
				void			*);
void		ehci_handle_bulk_qtd(
				ehci_state_t		*ehcip,
				ehci_pipe_private_t	*pp,
				ehci_trans_wrapper_t	*tw,
				ehci_qtd_t		*qtd,
				void			*);
void		ehci_handle_intr_qtd(
				ehci_state_t		*ehcip,
				ehci_pipe_private_t	*pp,
				ehci_trans_wrapper_t	*tw,
				ehci_qtd_t		*qtd,
				void			*);
static void	ehci_handle_one_xfer_completion(
				ehci_state_t		*ehcip,
				ehci_trans_wrapper_t	*tw);
static void	ehci_sendup_qtd_message(
				ehci_state_t		*ehcip,
				ehci_pipe_private_t	*pp,
				ehci_trans_wrapper_t	*tw,
				ehci_qtd_t		*qtd,
				usb_cr_t		error);


/*
 * Interrupt Handling functions
 */

/*
 * ehci_handle_ue:
 *
 * Handling of Unrecoverable Error interrupt (UE).
 */
void
ehci_handle_ue(ehci_state_t	*ehcip)
{
	usb_frame_number_t	before_frame_number, after_frame_number;

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	USB_DPRINTF_L3(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
	    "ehci_handle_ue: Handling of UE interrupt");

	/*
	 * First check whether current UE error occurred due to USB or
	 * due to some other subsystem. This can be verified by reading
	 * usb frame numbers before & after a delay of few milliseconds.
	 * If usb frame number read after delay is greater than the one
	 * read before delay, then, USB subsystem is fine. In this case,
	 * disable UE error interrupt and return without shutdowning the
	 * USB subsystem.
	 *
	 * Otherwise, if usb frame number read after delay is less than
	 * or equal to one read before the delay, then, current UE error
	 * occurred from USB subsystem. In this case,go ahead with actual
	 * UE error recovery procedure.
	 *
	 * Get the current usb frame number before waiting for few
	 * milliseconds.
	 */
	before_frame_number = ehci_get_current_frame_number(ehcip);

	/* Wait for few milliseconds */
	drv_usecwait(EHCI_TIMEWAIT);

	/*
	 * Get the current usb frame number after waiting for
	 * milliseconds.
	 */
	after_frame_number = ehci_get_current_frame_number(ehcip);

	USB_DPRINTF_L3(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
	    "ehci_handle_ue: Before Frame Number 0x%llx "
	    "After Frame Number 0x%llx",
	    (unsigned long long)before_frame_number,
	    (unsigned long long)after_frame_number);

	if (after_frame_number > before_frame_number) {

		/* Disable UE interrupt */
		Set_OpReg(ehci_interrupt, (Get_OpReg(ehci_interrupt) &
		    ~EHCI_INTR_HOST_SYSTEM_ERROR));

		return;
	}

	/*
	 * This UE is due to USB hardware error. Reset ehci controller
	 * and reprogram to bring it back to functional state.
	 */
	if ((ehci_do_soft_reset(ehcip)) != USB_SUCCESS) {

		USB_DPRINTF_L0(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
		    "Unrecoverable USB Hardware Error");

		/* Disable UE interrupt */
		Set_OpReg(ehci_interrupt, (Get_OpReg(ehci_interrupt) &
		    ~EHCI_INTR_HOST_SYSTEM_ERROR));

		/* Route all Root hub ports to Classic host controller */
		Set_OpReg(ehci_config_flag, EHCI_CONFIG_FLAG_CLASSIC);

		/* Set host controller soft state to error */
		ehcip->ehci_hc_soft_state = EHCI_CTLR_ERROR_STATE;
	}
}


/*
 * ehci_handle_frame_list_rollover:
 *
 * Update software based usb frame number part on every frame number
 * overflow interrupt.
 *
 * Refer ehci spec 1.0, section 2.3.2, page 21 for more details.
 *
 * NOTE: This function is also called from POLLED MODE.
 */
void
ehci_handle_frame_list_rollover(ehci_state_t *ehcip)
{
	ehcip->ehci_fno += (0x4000 -
	    (((Get_OpReg(ehci_frame_index) & 0x3FFF) ^
	    ehcip->ehci_fno) & 0x2000));

	USB_DPRINTF_L4(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
	    "ehci_handle_frame_list_rollover:"
	    "Frame Number Higher Part 0x%llx\n",
	    (unsigned long long)(ehcip->ehci_fno));
}


/*
 * ehci_handle_endpoint_reclamation:
 *
 * Reclamation of Host Controller (HC) Endpoint Descriptors (QH).
 */
void
ehci_handle_endpoint_reclaimation(ehci_state_t	*ehcip)
{
	usb_frame_number_t	current_frame_number;
	usb_frame_number_t	endpoint_frame_number;
	ehci_qh_t		*reclaim_qh;

	USB_DPRINTF_L4(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
	    "ehci_handle_endpoint_reclamation:");

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	current_frame_number = ehci_get_current_frame_number(ehcip);

	/*
	 * Deallocate all Endpoint Descriptors (QH) which are on the
	 * reclamation list. These QH's are already removed from the
	 * interrupt lattice tree.
	 */
	while (ehcip->ehci_reclaim_list) {

		reclaim_qh = ehcip->ehci_reclaim_list;

		endpoint_frame_number = (usb_frame_number_t)(uintptr_t)
		    (EHCI_LOOKUP_ID(Get_QH(reclaim_qh->qh_reclaim_frame)));

		USB_DPRINTF_L4(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
		    "ehci_handle_endpoint_reclamation:"
		    "current frame number 0x%llx endpoint frame number 0x%llx",
		    (unsigned long long)current_frame_number,
		    (unsigned long long)endpoint_frame_number);

		/*
		 * Deallocate current endpoint only if endpoint's usb frame
		 * number is less than or equal to current usb frame number.
		 *
		 * If endpoint's usb frame number is greater than the current
		 * usb frame number, ignore rest of the endpoints in the list
		 * since rest of the endpoints are inserted into the reclaim
		 * list later than the current reclaim endpoint.
		 */
		if (endpoint_frame_number > current_frame_number) {
			break;
		}

		/* Get the next endpoint from the rec. list */
		ehcip->ehci_reclaim_list = ehci_qh_iommu_to_cpu(
		    ehcip, Get_QH(reclaim_qh->qh_reclaim_next));

		/* Free 32bit ID */
		EHCI_FREE_ID((uint32_t)Get_QH(reclaim_qh->qh_reclaim_frame));

		/* Deallocate the endpoint */
		ehci_deallocate_qh(ehcip, reclaim_qh);
	}
}


/*
 * ehci_traverse_active_qtd_list:
 */
void
ehci_traverse_active_qtd_list(
	ehci_state_t		*ehcip)
{
	uint_t			state;		/* QTD state */
	ehci_qtd_t		*curr_qtd = NULL; /* QTD pointers */
	ehci_qtd_t		*next_qtd = NULL; /* QTD pointers */
	usb_cr_t		error;		/* Error from QTD */
	ehci_trans_wrapper_t	*tw = NULL;	/* Transfer wrapper */
	ehci_pipe_private_t	*pp = NULL;	/* Pipe private field */

	USB_DPRINTF_L4(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
	    "ehci_traverse_active_qtd_list:");

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	/* Sync QH and QTD pool */
	Sync_QH_QTD_Pool(ehcip);

	/* Create done qtd list */
	curr_qtd = ehci_create_done_qtd_list(ehcip);

	/* Traverse the list of transfer descriptors */
	while (curr_qtd) {
		/* Get next qtd from the active qtd list */
		next_qtd = ehci_qtd_iommu_to_cpu(ehcip,
		    Get_QTD(curr_qtd->qtd_active_qtd_next));

		/* Check for QTD state */
		state = Get_QTD(curr_qtd->qtd_state);

		USB_DPRINTF_L4(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
		    "ehci_traverse_active_qtd_list:\n\t"
		    "curr_qtd = 0x%p state = 0x%x", (void *)curr_qtd, state);

		/* Obtain the  transfer wrapper  for this QTD */
		tw = (ehci_trans_wrapper_t *)EHCI_LOOKUP_ID(
		    (uint32_t)Get_QTD(curr_qtd->qtd_trans_wrapper));

		ASSERT(tw != NULL);

		pp = tw->tw_pipe_private;

		USB_DPRINTF_L3(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
		    "ehci_traverse_active_qtd_list: "
		    "PP = 0x%p TW = 0x%p", (void *)pp, (void *)tw);

		/*
		 * A QTD that is marked as RECLAIM has already been
		 * processed by QTD timeout handler & client driver
		 * has been informed through exception callback.
		 */
		if (state != EHCI_QTD_RECLAIM) {
			/* Look at the error status */
			error = ehci_parse_error(ehcip, curr_qtd);

			if (error == USB_CR_OK) {
				ehci_handle_normal_qtd(ehcip, curr_qtd, tw);
			} else {
				/* handle the error condition */
				ehci_handle_error(ehcip, curr_qtd, error);
			}
		} else {
			USB_DPRINTF_L3(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
			    "ehci_traverse_active_qtd_list: "
			    "QTD State = %d", state);
		}

		/* Deallocate this transfer descriptor */
		ehci_deallocate_qtd(ehcip, curr_qtd);

		/*
		 * Deallocate the transfer wrapper if there are no more
		 * QTD's for the transfer wrapper.  ehci_deallocate_tw()
		 * will  not deallocate the tw for a periodic  endpoint
		 * since it will always have a QTD attached to it.
		 */
		ehci_deallocate_tw(ehcip, pp, tw);

		curr_qtd = next_qtd;
	}
}


/*
 * ehci_create_done_qtd_list:
 *
 * Create done qtd list from active qtd list.
 */
ehci_qtd_t *
ehci_create_done_qtd_list(
	ehci_state_t		*ehcip)
{
	ehci_qtd_t		*curr_qtd = NULL, *next_qtd = NULL;
	ehci_qtd_t		*done_qtd_list = NULL, *last_done_qtd = NULL;

	USB_DPRINTF_L4(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
	    "ehci_create_done_qtd_list:");

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	curr_qtd = ehcip->ehci_active_qtd_list;

	while (curr_qtd) {

		/* Get next qtd from the active qtd list */
		next_qtd = ehci_qtd_iommu_to_cpu(ehcip,
		    Get_QTD(curr_qtd->qtd_active_qtd_next));

		/* Check this QTD has been processed by Host Controller */
		if (!(Get_QTD(curr_qtd->qtd_ctrl) &
		    EHCI_QTD_CTRL_ACTIVE_XACT)) {

			/* Remove this QTD from active QTD list */
			ehci_remove_qtd_from_active_qtd_list(ehcip, curr_qtd);

			Set_QTD(curr_qtd->qtd_active_qtd_next, 0);

			if (done_qtd_list) {
				Set_QTD(last_done_qtd->qtd_active_qtd_next,
				    ehci_qtd_cpu_to_iommu(ehcip, curr_qtd));

				last_done_qtd = curr_qtd;
			} else {
				done_qtd_list = curr_qtd;
				last_done_qtd = curr_qtd;
			}
		}

		curr_qtd = next_qtd;
	}

	return (done_qtd_list);
}


/*
 * ehci_parse_error:
 *
 * Parse the result for any errors.
 */
static	usb_cr_t
ehci_parse_error(
	ehci_state_t		*ehcip,
	ehci_qtd_t		*qtd)
{
	uint_t			ctrl;
	ehci_trans_wrapper_t	*tw;
	ehci_pipe_private_t	*pp;
	uint_t			flag;
	usb_cr_t		error;

	USB_DPRINTF_L4(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
	    "ehci_parse_error:");

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	ASSERT(qtd != NULL);

	/* Obtain the transfer wrapper from the QTD */
	tw = (ehci_trans_wrapper_t *)
	    EHCI_LOOKUP_ID((uint32_t)Get_QTD(qtd->qtd_trans_wrapper));

	ASSERT(tw != NULL);

	/* Obtain the pipe private structure */
	pp = tw->tw_pipe_private;

	USB_DPRINTF_L3(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
	    "ehci_parse_error: PP 0x%p TW 0x%p", (void *)pp, (void *)tw);

	ctrl = (uint_t)Get_QTD(qtd->qtd_ctrl);

	/*
	 * Check the condition code of completed QTD and report errors
	 * if any. This checking will be done both for the general and
	 * the isochronous QTDs.
	 */
	if ((error = ehci_check_for_error(ehcip, pp, tw, qtd, ctrl)) !=
	    USB_CR_OK) {
		flag = EHCI_REMOVE_XFER_ALWAYS;
	} else {
		flag  = EHCI_REMOVE_XFER_IFLAST;
	}

	/* Stop the transfer timer */
	ehci_stop_xfer_timer(ehcip, tw, flag);

	return (error);
}


/*
 * ehci_check_for_error:
 *
 * Check for any errors.
 *
 * NOTE: This function is also called from POLLED MODE.
 */
usb_cr_t
ehci_check_for_error(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	ehci_trans_wrapper_t	*tw,
	ehci_qtd_t		*qtd,
	uint_t			ctrl)
{
	usb_cr_t		error = USB_CR_OK;
	uint_t			status, speed, mask;

	USB_DPRINTF_L4(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
	    "ehci_check_for_error: qtd = 0x%p ctrl = 0x%x",
	    (void *)qtd, ctrl);

	/*
	 * Find the usb device speed and get the corresponding
	 * error status mask.
	 */
	speed = Get_QH(pp->pp_qh->qh_ctrl) & EHCI_QH_CTRL_ED_SPEED;
	mask = (speed == EHCI_QH_CTRL_ED_HIGH_SPEED)?
	    EHCI_QTD_CTRL_HS_XACT_STATUS : EHCI_QTD_CTRL_NON_HS_XACT_STATUS;

	/* Exclude halted transaction error condition */
	status = ctrl & EHCI_QTD_CTRL_XACT_STATUS & ~EHCI_QTD_CTRL_HALTED_XACT;

	switch (status & mask) {
	case EHCI_QTD_CTRL_NO_ERROR:
		USB_DPRINTF_L4(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
		    "ehci_check_for_error: No Error");
		error = USB_CR_OK;
		break;
	case EHCI_QTD_CTRL_ACTIVE_XACT:
		USB_DPRINTF_L4(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
		    "ehci_check_for_error: Not accessed");
		error = USB_CR_NOT_ACCESSED;
		break;
	case EHCI_QTD_CTRL_HALTED_XACT:
		USB_DPRINTF_L2(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
		    "ehci_check_for_error: Halted");
		error = USB_CR_STALL;
		break;
	case EHCI_QTD_CTRL_BABBLE_DETECTED:
		USB_DPRINTF_L2(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
		    "ehci_check_for_error: Babble Detected");
		error = USB_CR_DATA_OVERRUN;
		break;
	case EHCI_QTD_CTRL_XACT_ERROR:
		/*
		 * An xacterr bit of one is not necessarily an error,
		 * the transaction might have completed successfully
		 * after some retries.
		 *
		 * Try to detect the case when the queue is halted,
		 * because the error counter was decremented from one
		 * down to zero after a transaction error.
		 */
		if (ctrl & EHCI_QTD_CTRL_HALTED_XACT && (ctrl &
		    EHCI_QTD_CTRL_ERR_COUNT_MASK) == 0) {
			USB_DPRINTF_L2(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
			    "ehci_check_for_error: Transaction Error");
			error = USB_CR_DEV_NOT_RESP;
		} else {
			USB_DPRINTF_L4(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
			    "ehci_check_for_error: No Error");
			error = USB_CR_OK;
		}
		break;
	case EHCI_QTD_CTRL_DATA_BUFFER_ERROR:
		/*
		 * Data buffer error is not necessarily an error,
		 * the transaction might have completed successfully
		 * after some retries. It can be ignored if the
		 * queue is not halted.
		 */
		if (!(ctrl & EHCI_QTD_CTRL_HALTED_XACT)) {
			USB_DPRINTF_L2(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
			    "ehci_check_for_error: Data buffer overrun or "
			    "underrun ignored");
			error = USB_CR_OK;
			break;
		}

		if (tw->tw_direction == EHCI_QTD_CTRL_IN_PID) {
			USB_DPRINTF_L2(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
			    "ehci_check_for_error: Buffer Overrun");
			error = USB_CR_BUFFER_OVERRUN;
		} else	{
			USB_DPRINTF_L2(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
			    "ehci_check_for_error: Buffer Underrun");
			error = USB_CR_BUFFER_UNDERRUN;
		}
		break;
	case EHCI_QTD_CTRL_MISSED_uFRAME:
		USB_DPRINTF_L2(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
		    "ehci_check_for_error: Missed uFrame");
		error = USB_CR_NOT_ACCESSED;
		break;
	case EHCI_QTD_CTRL_PRD_SPLIT_XACT_ERR:
		USB_DPRINTF_L2(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
		    "ehci_check_for_error: Periodic split-transaction "
		    "receives an error handshake");
		error = USB_CR_UNSPECIFIED_ERR;
		break;
	default:
		USB_DPRINTF_L2(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
		    "ehci_check_for_error: Unspecified Error");
		error = USB_CR_UNSPECIFIED_ERR;
		break;
	}

	/*
	 * Check for halted transaction error condition.
	 * Under short xfer conditions, EHCI HC will not return an error
	 * or halt the QH.  This is done manually later in
	 * ehci_check_for_short_xfer.
	 */
	if ((ctrl & EHCI_QTD_CTRL_HALTED_XACT) && (error == USB_CR_OK)) {
		USB_DPRINTF_L2(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
		    "ehci_check_for_error: Halted");
		error = USB_CR_STALL;
	}

	if (error == USB_CR_OK) {
		error = ehci_check_for_short_xfer(ehcip, pp, tw, qtd);
	}

	if (error) {
		uint_t qh_ctrl =  Get_QH(pp->pp_qh->qh_ctrl);

		USB_DPRINTF_L2(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
		    "ehci_check_for_error: Error %d Device address %d "
		    "Endpoint number %d", error,
		    (qh_ctrl & EHCI_QH_CTRL_DEVICE_ADDRESS),
		    ((qh_ctrl & EHCI_QH_CTRL_ED_NUMBER) >>
		    EHCI_QH_CTRL_ED_NUMBER_SHIFT));
	}

	return (error);
}

/*
 * ehci_check_for_short_xfer:
 *
 * Check to see if there was a short xfer condition.
 *
 * NOTE: This function is also called from POLLED MODE.
 *	 But it doesn't do anything.
 */
static usb_cr_t
ehci_check_for_short_xfer(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	ehci_trans_wrapper_t	*tw,
	ehci_qtd_t		*qtd)
{
	usb_cr_t		error = USB_CR_OK;
	usb_ep_descr_t		*eptd;
	uchar_t			attributes;
	uint32_t		residue = 0;
	usb_req_attrs_t		xfer_attrs;
	size_t			length;
	mblk_t			*mp = NULL;
	usb_opaque_t		xfer_reqp;

	USB_DPRINTF_L4(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
	    "ehci_check_for_short_xfer:");

	if (pp->pp_flag == EHCI_POLLED_MODE_FLAG) {

		return (error);
	}

	/*
	 * Check for short xfer error.	If this is a control pipe, only check
	 * if it is in the data phase.
	 */
	eptd = &pp->pp_pipe_handle->p_ep;
	attributes = eptd->bmAttributes & USB_EP_ATTR_MASK;

	switch (attributes) {
	case USB_EP_ATTR_CONTROL:
		if (Get_QTD(qtd->qtd_ctrl_phase) !=
		    EHCI_CTRL_DATA_PHASE) {

			break;
		}
		/* FALLTHROUGH */
	case USB_EP_ATTR_BULK:
	case USB_EP_ATTR_INTR:
		/*
		 * If "Total bytes of xfer" in control field of
		 * Transfer Descriptor (QTD) is not equal to zero,
		 * then, we sent/received less data from the usb
		 * device than requested. In that case, get the
		 * actual received data size.
		 */
		residue = (Get_QTD(qtd->qtd_ctrl) &
		    EHCI_QTD_CTRL_BYTES_TO_XFER) >>
		    EHCI_QTD_CTRL_BYTES_TO_XFER_SHIFT;

		break;
	case USB_EP_ATTR_ISOCH:

		break;
	}

	if (residue) {
		USB_DPRINTF_L2(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
		    "ehci_check_for_short_xfer: residue=%d direction=0x%x",
		    residue, tw->tw_direction);

		length = Get_QTD(qtd->qtd_xfer_offs) +
		    Get_QTD(qtd->qtd_xfer_len) - residue;

		if (tw->tw_direction == EHCI_QTD_CTRL_IN_PID) {
			xfer_attrs = ehci_get_xfer_attrs(ehcip, pp, tw);

			if (xfer_attrs & USB_ATTRS_SHORT_XFER_OK) {
				ehci_cleanup_data_underrun(ehcip, tw, qtd);
			} else {
				/* Halt the pipe to mirror OHCI behavior */
				Set_QH(pp->pp_qh->qh_status,
				    ((Get_QH(pp->pp_qh->qh_status) &
				    ~EHCI_QH_STS_ACTIVE) |
				    EHCI_QH_STS_HALTED));
				error = USB_CR_DATA_UNDERRUN;
			}

			USB_DPRINTF_L2(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
			    "ehci_check_for_short_xfer: requested data=%lu "
			    "received data=%lu", tw->tw_length, length);

			switch (attributes) {
			case USB_EP_ATTR_CONTROL:
			case USB_EP_ATTR_BULK:
			case USB_EP_ATTR_INTR:
				/* Save the actual received length */
				tw->tw_length = length;

				break;
			case USB_EP_ATTR_ISOCH:
			default:

				break;
			}
		} else {
			USB_DPRINTF_L2(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
			    "ehci_check_for_short_xfer: requested data=%lu "
			    "sent data=%lu", tw->tw_length, length);

			xfer_reqp = tw->tw_curr_xfer_reqp;

			switch (attributes) {
			case USB_EP_ATTR_CONTROL:

				break;
			case USB_EP_ATTR_BULK:
				mp = (mblk_t *)((usb_bulk_req_t *)
				    (xfer_reqp))->bulk_data;

				/* Increment the read pointer */
				mp->b_rptr = mp->b_rptr + length;

				break;
			case USB_EP_ATTR_INTR:
				mp = (mblk_t *)((usb_intr_req_t *)
				    (xfer_reqp))->intr_data;

				/* Increment the read pointer */
				mp->b_rptr = mp->b_rptr + length;

				break;
			case USB_EP_ATTR_ISOCH:
			default:

				break;
			}
		}
	}

	return (error);
}

/*
 * ehci_handle_error:
 *
 * Inform USBA about occurred transaction errors by calling the USBA callback
 * routine.
 */
void
ehci_handle_error(
	ehci_state_t		*ehcip,
	ehci_qtd_t		*qtd,
	usb_cr_t		error)
{
	ehci_trans_wrapper_t	*tw;
	usba_pipe_handle_data_t	*ph;
	ehci_pipe_private_t	*pp;
	ehci_qtd_t		*tw_qtd = qtd;
	uchar_t			attributes;
	usb_intr_req_t		*curr_intr_reqp;

	USB_DPRINTF_L4(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
	    "ehci_handle_error: error = 0x%x", error);

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	ASSERT(qtd != NULL);

	/* Print the values in the qtd */
	ehci_print_qtd(ehcip, qtd);

	/* Obtain the transfer wrapper from the QTD */
	tw = (ehci_trans_wrapper_t *)
	    EHCI_LOOKUP_ID((uint32_t)Get_QTD(qtd->qtd_trans_wrapper));

	ASSERT(tw != NULL);

	/* Obtain the pipe private structure */
	pp = tw->tw_pipe_private;

	ph = tw->tw_pipe_private->pp_pipe_handle;
	attributes = ph->p_ep.bmAttributes & USB_EP_ATTR_MASK;

	/*
	 * Mark all QTDs belongs to this TW as RECLAIM
	 * so that we don't process them by mistake.
	 */
	while (tw_qtd) {
		/* Set QTD state to RECLAIM */
		Set_QTD(tw_qtd->qtd_state, EHCI_QTD_RECLAIM);

		/* Get the next QTD from the wrapper */
		tw_qtd = ehci_qtd_iommu_to_cpu(ehcip,
		    Get_QTD(tw_qtd->qtd_tw_next_qtd));
	}

	/*
	 * Special error handling
	 */
	if (tw->tw_direction == EHCI_QTD_CTRL_IN_PID) {

		switch (attributes) {
		case USB_EP_ATTR_CONTROL:
			if (((ph->p_ep.bmAttributes &
			    USB_EP_ATTR_MASK) ==
			    USB_EP_ATTR_CONTROL) &&
			    (Get_QTD(qtd->qtd_ctrl_phase) ==
			    EHCI_CTRL_SETUP_PHASE)) {

				break;
			}
			/* FALLTHROUGH */
		case USB_EP_ATTR_BULK:
			/*
			 * Call ehci_sendup_qtd_message
			 * to send message to upstream.
			 */
			ehci_sendup_qtd_message(ehcip, pp, tw, qtd, error);

			return;
		case USB_EP_ATTR_INTR:
			curr_intr_reqp =
			    (usb_intr_req_t *)tw->tw_curr_xfer_reqp;

			if (curr_intr_reqp->intr_attributes &
			    USB_ATTRS_ONE_XFER) {

				ehci_handle_one_xfer_completion(ehcip, tw);
			}

			/* Decrement periodic in request count */
			pp->pp_cur_periodic_req_cnt--;
			break;
		case USB_EP_ATTR_ISOCH:
			break;
		}
	}

	ehci_hcdi_callback(ph, tw, error);

	/* Check anybody is waiting for transfers completion event */
	ehci_check_for_transfers_completion(ehcip, pp);
}

/*
 * ehci_cleanup_data_underrun:
 *
 * Cleans up resources when a short xfer occurs.  Will only do cleanup if
 * this pipe supports alternate_qtds.
 *
 * NOTE: This function is also called from POLLED MODE.
 */
static void
ehci_cleanup_data_underrun(
	ehci_state_t		*ehcip,
	ehci_trans_wrapper_t	*tw,
	ehci_qtd_t		*qtd)
{
	ehci_qtd_t		*next_qtd, *temp_qtd;

	USB_DPRINTF_L4(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
	    "ehci_cleanup_data_underrun: qtd=0x%p, tw=0x%p",
	    (void *)qtd, (void *)tw);

	/*
	 * Check if this transfer doesn't supports short_xfer or
	 * if this QTD is the last qtd in the tw.  If so there is
	 * no need for cleanup.
	 */
	if ((tw->tw_alt_qtd == NULL) || (qtd == tw->tw_qtd_tail)) {
		/* There is no need for cleanup */
		return;
	}

	/* Start removing all the unused QTDs from the TW */
	next_qtd = (ehci_qtd_t *)ehci_qtd_iommu_to_cpu(ehcip,
	    Get_QTD(qtd->qtd_tw_next_qtd));

	while (next_qtd) {
		tw->tw_num_qtds--;

		ehci_remove_qtd_from_active_qtd_list(ehcip, next_qtd);

		temp_qtd = next_qtd;

		next_qtd = ehci_qtd_iommu_to_cpu(ehcip,
		    Get_QTD(next_qtd->qtd_tw_next_qtd));

		ehci_deallocate_qtd(ehcip, temp_qtd);
	}

	ASSERT(tw->tw_num_qtds == 1);
}

/*
 * ehci_handle_normal_qtd:
 */
static void
ehci_handle_normal_qtd(
	ehci_state_t		*ehcip,
	ehci_qtd_t		*qtd,
	ehci_trans_wrapper_t	*tw)
{
	ehci_pipe_private_t	*pp;	/* Pipe private field */

	USB_DPRINTF_L4(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
	    "ehci_handle_normal_qtd:");

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));
	ASSERT(tw != NULL);

	/* Obtain the pipe private structure */
	pp = tw->tw_pipe_private;

	(*tw->tw_handle_qtd)(ehcip, pp, tw,
	    qtd, tw->tw_handle_callback_value);

	/* Check anybody is waiting for transfers completion event */
	ehci_check_for_transfers_completion(ehcip, pp);
}


/*
 * ehci_handle_ctrl_qtd:
 *
 * Handle a control Transfer Descriptor (QTD).
 */
/* ARGSUSED */
void
ehci_handle_ctrl_qtd(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	ehci_trans_wrapper_t	*tw,
	ehci_qtd_t		*qtd,
	void			*tw_handle_callback_value)
{
	usba_pipe_handle_data_t	*ph = pp->pp_pipe_handle;

	USB_DPRINTF_L4(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
	    "ehci_handle_ctrl_qtd: pp = 0x%p tw = 0x%p qtd = 0x%p state = 0x%x",
	    (void *)pp, (void *)tw, (void *)qtd, Get_QTD(qtd->qtd_ctrl_phase));

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	/*
	 * A control transfer consists of three phases:
	 *
	 * Setup
	 * Data (optional)
	 * Status
	 *
	 * There is a QTD per phase. A QTD for a given phase isn't
	 * enqueued until the previous phase is finished. EHCI
	 * spec allows more than one  control transfer on a pipe
	 * within a frame. However, we've found that some devices
	 * can't handle this.
	 */
	tw->tw_num_qtds--;
	switch (Get_QTD(qtd->qtd_ctrl_phase)) {
	case EHCI_CTRL_SETUP_PHASE:
		USB_DPRINTF_L3(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
		    "Setup complete: pp 0x%p qtd 0x%p",
		    (void *)pp, (void *)qtd);

		break;
	case EHCI_CTRL_DATA_PHASE:
		USB_DPRINTF_L3(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
		    "Data complete: pp 0x%p qtd 0x%p",
		    (void *)pp, (void *)qtd);

		break;
	case EHCI_CTRL_STATUS_PHASE:
		/*
		 * On some particular hardware, status phase is seen to
		 * finish before data phase gets timeouted. Don't handle
		 * the transfer result here if not all qtds are finished.
		 * Let the timeout handler handle it.
		 */
		if (tw->tw_num_qtds != 0) {
			USB_DPRINTF_L2(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
			    "Status complete, but the transfer is not done: "
			    "tw 0x%p, qtd 0x%p, tw_num_qtd 0x%d",
			    (void *)tw, (void *)qtd, tw->tw_num_qtds);

			ehci_print_qh(ehcip, pp->pp_qh);
			ehci_print_qtd(ehcip, qtd);

			break;
		}

		if ((tw->tw_length) &&
		    (tw->tw_direction == EHCI_QTD_CTRL_IN_PID)) {
			/*
			 * Call ehci_sendup_qtd_message
			 * to send message to upstream.
			 */
			ehci_sendup_qtd_message(ehcip,
			    pp, tw, qtd, USB_CR_OK);
		} else {
			ehci_hcdi_callback(ph, tw, USB_CR_OK);
		}

		USB_DPRINTF_L3(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
		    "Status complete: pp 0x%p qtd 0x%p",
		    (void *)pp, (void *)qtd);

		break;
	}
}


/*
 * ehci_handle_bulk_qtd:
 *
 * Handle a bulk Transfer Descriptor (QTD).
 */
/* ARGSUSED */
void
ehci_handle_bulk_qtd(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	ehci_trans_wrapper_t	*tw,
	ehci_qtd_t		*qtd,
	void			*tw_handle_callback_value)
{
	usba_pipe_handle_data_t	*ph = pp->pp_pipe_handle;
	usb_ep_descr_t		*eptd = &ph->p_ep;

	USB_DPRINTF_L4(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
	    "ehci_handle_bulk_qtd:");

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	/*
	 * Decrement the QTDs counter and check whether all the bulk
	 * data has been send or received. If QTDs counter reaches
	 * zero then inform client driver about completion current
	 * bulk request. Other wise wait for completion of other bulk
	 * QTDs or transactions on this pipe.
	 */
	if (--tw->tw_num_qtds != 0) {

		USB_DPRINTF_L3(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
		    "ehci_handle_bulk_qtd: Number of QTDs %d", tw->tw_num_qtds);

		return;
	}

	/*
	 * If this is a bulk in pipe, return the data to the client.
	 * For a bulk out pipe, there is no need to do anything.
	 */
	if ((eptd->bEndpointAddress &
	    USB_EP_DIR_MASK) == USB_EP_DIR_OUT) {

		USB_DPRINTF_L3(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
		    "ehci_handle_bulk_qtd: Bulk out pipe");

		/* Do the callback */
		ehci_hcdi_callback(ph, tw, USB_CR_OK);

		return;
	}

	/* Call ehci_sendup_qtd_message to send message to upstream */
	ehci_sendup_qtd_message(ehcip, pp, tw, qtd, USB_CR_OK);
}


/*
 * ehci_handle_intr_qtd:
 *
 * Handle a interrupt Transfer Descriptor (QTD).
 */
/* ARGSUSED */
void
ehci_handle_intr_qtd(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	ehci_trans_wrapper_t	*tw,
	ehci_qtd_t		*qtd,
	void			*tw_handle_callback_value)
{
	usb_intr_req_t		*curr_intr_reqp =
	    (usb_intr_req_t *)tw->tw_curr_xfer_reqp;
	usba_pipe_handle_data_t	*ph = pp->pp_pipe_handle;
	usb_ep_descr_t		*eptd = &ph->p_ep;
	usb_req_attrs_t		attrs;
	int			error = USB_SUCCESS;

	USB_DPRINTF_L4(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
	    "ehci_handle_intr_qtd:");

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	/* Get the interrupt xfer attributes */
	attrs = curr_intr_reqp->intr_attributes;

	/*
	 * For a Interrupt OUT pipe, we just callback and we are done
	 */
	if ((eptd->bEndpointAddress & USB_EP_DIR_MASK) == USB_EP_DIR_OUT) {

		USB_DPRINTF_L3(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
		    "ehci_handle_intr_qtd: Intr out pipe, intr_reqp=0x%p,"
		    "data=0x%p", (void *)curr_intr_reqp,
		    (void *)curr_intr_reqp->intr_data);

		/* Do the callback */
		ehci_hcdi_callback(ph, tw, USB_CR_OK);

		return;
	}

	/* Decrement number of interrupt request count */
	pp->pp_cur_periodic_req_cnt--;

	/*
	 * Check usb flag whether USB_FLAGS_ONE_XFER flag is set
	 * and if so, free duplicate request.
	 */
	if (attrs & USB_ATTRS_ONE_XFER) {
		ehci_handle_one_xfer_completion(ehcip, tw);
	}

	/* Call ehci_sendup_qtd_message to callback into client */
	ehci_sendup_qtd_message(ehcip, pp, tw, qtd, USB_CR_OK);

	/*
	 * If interrupt pipe state is still active, insert next Interrupt
	 * request into the Host Controller's Interrupt list.  Otherwise
	 * you are done.
	 */
	if ((pp->pp_state != EHCI_PIPE_STATE_ACTIVE) ||
	    (ehci_state_is_operational(ehcip) != USB_SUCCESS)) {

		return;
	}

	if ((error = ehci_allocate_intr_in_resource(ehcip, pp, tw, 0)) ==
	    USB_SUCCESS) {
		curr_intr_reqp = (usb_intr_req_t *)tw->tw_curr_xfer_reqp;

		ASSERT(curr_intr_reqp != NULL);

		tw->tw_num_qtds = 1;

		if (ehci_allocate_tds_for_tw(ehcip, pp, tw, tw->tw_num_qtds) !=
		    USB_SUCCESS) {
			ehci_deallocate_intr_in_resource(ehcip, pp, tw);
			error = USB_FAILURE;
		}
	}

	if (error != USB_SUCCESS) {
		/*
		 * Set pipe state to stop polling and error to no
		 * resource. Don't insert any more interrupt polling
		 * requests.
		 */
		pp->pp_state = EHCI_PIPE_STATE_STOP_POLLING;
		pp->pp_error = USB_CR_NO_RESOURCES;
	} else {
		ehci_insert_intr_req(ehcip, pp, tw, 0);

		/* Increment number of interrupt request count */
		pp->pp_cur_periodic_req_cnt++;

		ASSERT(pp->pp_cur_periodic_req_cnt ==
		    pp->pp_max_periodic_req_cnt);
	}
}


/*
 * ehci_handle_one_xfer_completion:
 */
static void
ehci_handle_one_xfer_completion(
	ehci_state_t		*ehcip,
	ehci_trans_wrapper_t	*tw)
{
	usba_pipe_handle_data_t	*ph = tw->tw_pipe_private->pp_pipe_handle;
	ehci_pipe_private_t	*pp = tw->tw_pipe_private;
	usb_intr_req_t		*curr_intr_reqp =
	    (usb_intr_req_t *)tw->tw_curr_xfer_reqp;

	USB_DPRINTF_L4(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
	    "ehci_handle_one_xfer_completion: tw = 0x%p", (void *)tw);

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));
	ASSERT(curr_intr_reqp->intr_attributes & USB_ATTRS_ONE_XFER);

	pp->pp_state = EHCI_PIPE_STATE_IDLE;

	/*
	 * For one xfer, we need to copy back data ptr
	 * and free current request
	 */
	((usb_intr_req_t *)(pp->pp_client_periodic_in_reqp))->
	    intr_data = ((usb_intr_req_t *)
	    (tw->tw_curr_xfer_reqp))->intr_data;

	((usb_intr_req_t *)tw->tw_curr_xfer_reqp)->intr_data = NULL;

	/* Now free duplicate current request */
	usb_free_intr_req((usb_intr_req_t *)tw-> tw_curr_xfer_reqp);

	mutex_enter(&ph->p_mutex);
	ph->p_req_count--;
	mutex_exit(&ph->p_mutex);

	/* Make client's request the current request */
	tw->tw_curr_xfer_reqp = pp->pp_client_periodic_in_reqp;
	pp->pp_client_periodic_in_reqp = NULL;
}


/*
 * ehci_sendup_qtd_message:
 *	copy data, if necessary and do callback
 */
/* ARGSUSED */
static void
ehci_sendup_qtd_message(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	ehci_trans_wrapper_t	*tw,
	ehci_qtd_t		*qtd,
	usb_cr_t		error)
{
	usb_ep_descr_t		*eptd = &pp->pp_pipe_handle->p_ep;
	usba_pipe_handle_data_t	*ph = pp->pp_pipe_handle;
	usb_opaque_t		curr_xfer_reqp = tw->tw_curr_xfer_reqp;
	size_t			skip_len = 0;
	size_t			length;
	uchar_t			*buf;
	mblk_t			*mp;

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	USB_DPRINTF_L4(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
	    "ehci_sendup_qtd_message:");

	ASSERT(tw != NULL);

	length = tw->tw_length;

	if ((eptd->bmAttributes & USB_EP_ATTR_MASK) == USB_EP_ATTR_CONTROL) {
		/* Get the correct length */
		if (((usb_ctrl_req_t *)curr_xfer_reqp)->ctrl_wLength)
			length = length - EHCI_MAX_QTD_BUF_SIZE;
		else
			length = length - SETUP_SIZE;

		/* Set the length of the buffer to skip */
		skip_len = EHCI_MAX_QTD_BUF_SIZE;
	}

	/* Copy the data into the mblk_t */
	buf = (uchar_t *)tw->tw_buf + skip_len;

	USB_DPRINTF_L4(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
	    "ehci_sendup_qtd_message: length %ld error %d", length, error);

	/* Get the message block */
	switch (eptd->bmAttributes & USB_EP_ATTR_MASK) {
	case USB_EP_ATTR_CONTROL:
		mp = ((usb_ctrl_req_t *)curr_xfer_reqp)->ctrl_data;
		break;
	case USB_EP_ATTR_BULK:
		mp = ((usb_bulk_req_t *)curr_xfer_reqp)->bulk_data;
		break;
	case USB_EP_ATTR_INTR:
		mp = ((usb_intr_req_t *)curr_xfer_reqp)->intr_data;
		break;
	case USB_EP_ATTR_ISOCH:
		/* Isoc messages must not go through this path */
		mp = NULL;
		break;
	}

	ASSERT(mp != NULL);

	if (length) {
		/*
		 * Update kstat byte counts
		 * The control endpoints don't have direction bits so in
		 * order for control stats to be counted correctly an in
		 * bit must be faked on a control read.
		 */
		if ((eptd->bmAttributes & USB_EP_ATTR_MASK) ==
		    USB_EP_ATTR_CONTROL) {
			ehci_do_byte_stats(ehcip, length,
			    eptd->bmAttributes, USB_EP_DIR_IN);
		} else {
			ehci_do_byte_stats(ehcip, length,
			    eptd->bmAttributes, eptd->bEndpointAddress);
		}

		/* Sync IO buffer */
		Sync_IO_Buffer(tw->tw_dmahandle, (skip_len + length));

		/* since we specified NEVERSWAP, we can just use bcopy */
		bcopy(buf, mp->b_rptr, length);

		/* Increment the write pointer */
		mp->b_wptr = mp->b_wptr + length;
	} else {
		USB_DPRINTF_L3(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
		    "ehci_sendup_qtd_message: Zero length packet");
	}

	ehci_hcdi_callback(ph, tw, error);
}
