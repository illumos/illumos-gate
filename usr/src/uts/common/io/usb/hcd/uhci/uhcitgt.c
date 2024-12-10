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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 */


/*
 * Universal Host Controller Driver (UHCI)
 *
 * The UHCI driver is a driver which interfaces to the Universal
 * Serial Bus Driver (USBA) and the Host Controller (HC). The interface to
 * the Host Controller is defined by the Universal Host Controller Interface.
 * This file contains the code for HCDI entry points.
 */
#include <sys/usb/hcd/uhci/uhcid.h>
#include <sys/usb/hcd/uhci/uhcitgt.h>
#include <sys/usb/hcd/uhci/uhciutil.h>
#include <sys/strsun.h>

/* function prototypes */
static int	uhci_pipe_send_isoc_data(uhci_state_t *uhcip,
			usba_pipe_handle_data_t *ph, usb_isoc_req_t *isoc_req,
			usb_flags_t usb_flags);
static int	uhci_send_intr_data(uhci_state_t *uhcip,
			usba_pipe_handle_data_t	*pipe_handle,
			usb_intr_req_t		*req,
			usb_flags_t		flags);
static int	uhci_start_periodic_pipe_polling(uhci_state_t *uhcip,
			usba_pipe_handle_data_t	*ph,
			usb_opaque_t		reqp,
			usb_flags_t		flags);
static int	uhci_stop_periodic_pipe_polling(uhci_state_t *uhcip,
			usba_pipe_handle_data_t	*ph,
			usb_flags_t		flags);
static void	uhci_update_intr_td_data_toggle(uhci_state_t *uhcip,
			uhci_pipe_private_t *pp);


/* Maximum bulk transfer size */
int uhci_bulk_transfer_size = UHCI_BULK_MAX_XFER_SIZE;

/*
 * uhci_hcdi_pipe_open:
 *	Member of HCD Ops structure and called during client specific pipe open
 *	Add the pipe to the data structure representing the device and allocate
 *	bandwidth for the pipe if it is a interrupt or isochronous endpoint.
 */
int
uhci_hcdi_pipe_open(usba_pipe_handle_data_t *ph, usb_flags_t flags)
{
	uint_t			node = 0;
	usb_addr_t		usb_addr;
	uhci_state_t		*uhcip;
	uhci_pipe_private_t	*pp;
	int			rval, error = USB_SUCCESS;

	ASSERT(ph);

	usb_addr = ph->p_usba_device->usb_addr;
	uhcip = uhci_obtain_state(ph->p_usba_device->usb_root_hub_dip);

	USB_DPRINTF_L4(PRINT_MASK_HCDI, uhcip->uhci_log_hdl,
	    "uhci_hcdi_pipe_open: addr = 0x%x, ep%d", usb_addr,
	    ph->p_ep.bEndpointAddress & USB_EP_NUM_MASK);

	sema_p(&uhcip->uhci_ocsem);

	mutex_enter(&uhcip->uhci_int_mutex);
	rval = uhci_state_is_operational(uhcip);
	mutex_exit(&uhcip->uhci_int_mutex);

	if (rval != USB_SUCCESS) {
		sema_v(&uhcip->uhci_ocsem);

		return (rval);
	}

	/*
	 * Return failure immediately for any other pipe open on the root hub
	 * except control or interrupt pipe.
	 */
	if (usb_addr == ROOT_HUB_ADDR) {
		switch (UHCI_XFER_TYPE(&ph->p_ep)) {
		case USB_EP_ATTR_CONTROL:
			USB_DPRINTF_L3(PRINT_MASK_HCDI, uhcip->uhci_log_hdl,
			    "uhci_hcdi_pipe_open: Root hub control pipe");
			break;
		case USB_EP_ATTR_INTR:
			ASSERT(UHCI_XFER_DIR(&ph->p_ep) == USB_EP_DIR_IN);

			mutex_enter(&uhcip->uhci_int_mutex);
			uhcip->uhci_root_hub.rh_intr_pipe_handle = ph;

			/*
			 * Set the state of the root hub interrupt
			 * pipe as IDLE.
			 */
			uhcip->uhci_root_hub.rh_pipe_state =
			    UHCI_PIPE_STATE_IDLE;

			ASSERT(uhcip->uhci_root_hub.rh_client_intr_req == NULL);
			uhcip->uhci_root_hub.rh_client_intr_req = NULL;

			ASSERT(uhcip->uhci_root_hub.rh_curr_intr_reqp == NULL);
			uhcip->uhci_root_hub.rh_curr_intr_reqp = NULL;

			USB_DPRINTF_L4(PRINT_MASK_HCDI, uhcip->uhci_log_hdl,
			    "uhci_hcdi_pipe_open: Root hub interrupt "
			    "pipe open succeeded");
			mutex_exit(&uhcip->uhci_int_mutex);
			sema_v(&uhcip->uhci_ocsem);

			return (USB_SUCCESS);
		default:
			USB_DPRINTF_L2(PRINT_MASK_HCDI, uhcip->uhci_log_hdl,
			    "uhci_hcdi_pipe_open: Root hub pipe open failed");
			sema_v(&uhcip->uhci_ocsem);

			return (USB_FAILURE);
		}
	}

	/*
	 * A portion of the bandwidth is reserved for the non-periodic
	 * transfers  i.e control and bulk transfers in each  of one
	 * mill second frame period & usually it will be 10% of frame
	 * period. Hence there is no need to check for the available
	 * bandwidth before adding the control or bulk endpoints.
	 *
	 * There is a need to check for the available bandwidth before
	 * adding the periodic transfers i.e interrupt & isochronous, since
	 * all these periodic transfers are guaranteed transfers. Usually,
	 * 90% of the total frame time is reserved for periodic transfers.
	 */
	if (UHCI_PERIODIC_ENDPOINT(&ph->p_ep)) {
		/* Zero Max Packet size endpoints are not supported */
		if (ph->p_ep.wMaxPacketSize == 0) {
			USB_DPRINTF_L3(PRINT_MASK_HCDI, uhcip->uhci_log_hdl,
			    "uhci_hcdi_pipe_open: Zero length packet");
			sema_v(&uhcip->uhci_ocsem);

			return (USB_FAILURE);
		}

		mutex_enter(&uhcip->uhci_int_mutex);
		mutex_enter(&ph->p_mutex);

		error = uhci_allocate_bandwidth(uhcip, ph, &node);
		if (error != USB_SUCCESS) {

			USB_DPRINTF_L2(PRINT_MASK_HCDI, uhcip->uhci_log_hdl,
			    "uhci_hcdi_pipe_open: Bandwidth allocation failed");
			mutex_exit(&ph->p_mutex);
			mutex_exit(&uhcip->uhci_int_mutex);
			sema_v(&uhcip->uhci_ocsem);

			return (error);
		}

		mutex_exit(&ph->p_mutex);
		mutex_exit(&uhcip->uhci_int_mutex);
	}

	/* Create the HCD pipe private structure */
	pp = kmem_zalloc(sizeof (uhci_pipe_private_t),
	    (flags & USB_FLAGS_SLEEP) ? KM_SLEEP : KM_NOSLEEP);
	if (pp == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_HCDI, uhcip->uhci_log_hdl,
		    "uhci_hcdi_pipe_open: pp allocation failure");

		if (UHCI_PERIODIC_ENDPOINT(&ph->p_ep)) {
			mutex_enter(&uhcip->uhci_int_mutex);
			uhci_deallocate_bandwidth(uhcip, ph);
			mutex_exit(&uhcip->uhci_int_mutex);
		}
		sema_v(&uhcip->uhci_ocsem);

		return (USB_NO_RESOURCES);
	}

	mutex_enter(&uhcip->uhci_int_mutex);
	rval = uhci_state_is_operational(uhcip);

	if (rval != USB_SUCCESS) {
		kmem_free(pp, sizeof (uhci_pipe_private_t));
		mutex_exit(&uhcip->uhci_int_mutex);
		sema_v(&uhcip->uhci_ocsem);

		return (rval);
	}
	pp->pp_node = node;	/* Store the node in the interrupt lattice */

	/* Initialize frame number */
	pp->pp_frame_num = INVALID_FRNUM;

	/* Set the state of pipe as IDLE */
	pp->pp_state = UHCI_PIPE_STATE_IDLE;

	/* Store a pointer to the pipe handle */
	pp->pp_pipe_handle = ph;

	/* Store the pointer in the pipe handle */
	mutex_enter(&ph->p_mutex);
	ph->p_hcd_private = (usb_opaque_t)pp;

	/* Store a copy of the pipe policy */
	bcopy(&ph->p_policy, &pp->pp_policy, sizeof (usb_pipe_policy_t));
	mutex_exit(&ph->p_mutex);

	/* don't check for ROOT_HUB here anymore */
	if (UHCI_XFER_TYPE(&ph->p_ep) != USB_EP_ATTR_ISOCH) {
		/* Allocate the host controller endpoint descriptor */
		pp->pp_qh = uhci_alloc_queue_head(uhcip);

		if (pp->pp_qh == NULL) {
			USB_DPRINTF_L2(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
			    "uhci_hcdi_pipe_open: QH allocation failed");

			if (UHCI_PERIODIC_ENDPOINT(&ph->p_ep)) {
				uhci_deallocate_bandwidth(uhcip, ph);
			}

			mutex_enter(&ph->p_mutex);

			/*
			 * Deallocate the hcd private portion
			 * of the pipe handle.
			 */
			kmem_free(ph->p_hcd_private,
			    sizeof (uhci_pipe_private_t));

			/*
			 * Set the private structure in the
			 * pipe handle equal to NULL.
			 */
			ph->p_hcd_private = NULL;
			mutex_exit(&ph->p_mutex);
			mutex_exit(&uhcip->uhci_int_mutex);

			sema_v(&uhcip->uhci_ocsem);

			return (USB_NO_RESOURCES);
		}

		/*
		 * Insert the endpoint onto the host controller's
		 * appropriate endpoint list. The host controller
		 * will not schedule this endpoint until there are
		 * any TD's to process.
		 */
		uhci_insert_qh(uhcip, ph);
	}

	/*
	 * Restore the data toggle from usb device structure.
	 */
	if (((ph->p_ep.bmAttributes) & USB_EP_ATTR_MASK) == USB_EP_ATTR_INTR ||
	    ((ph->p_ep.bmAttributes) & USB_EP_ATTR_MASK) == USB_EP_ATTR_BULK) {
		mutex_enter(&ph->p_mutex);

		pp->pp_data_toggle = usba_hcdi_get_data_toggle(
		    ph->p_usba_device, ph->p_ep.bEndpointAddress);
		mutex_exit(&ph->p_mutex);
	}

	mutex_exit(&uhcip->uhci_int_mutex);
	sema_v(&uhcip->uhci_ocsem);

	USB_DPRINTF_L4(PRINT_MASK_HCDI, uhcip->uhci_log_hdl,
	    "uhci_hcdi_pipe_open: ph = 0x%p", (void *)ph);

	return (USB_SUCCESS);
}


/*
 * uhci_hcdi_pipe_close:
 *	Member of HCD Ops structure and called during the client specific pipe
 *	close. Remove the pipe to the data structure representing the device
 *	deallocate bandwidth for the pipe if it is an intr or isoch endpoint.
 */
int
uhci_hcdi_pipe_close(usba_pipe_handle_data_t *ph, usb_flags_t usb_flags)
{
	usb_addr_t		usb_addr;
	uhci_state_t		*uhcip;
	usb_ep_descr_t		*eptd = &ph->p_ep;
	uhci_pipe_private_t	*pp;

	uhcip = uhci_obtain_state(ph->p_usba_device->usb_root_hub_dip);
	pp = (uhci_pipe_private_t *)ph->p_hcd_private;
	usb_addr = ph->p_usba_device->usb_addr;

	USB_DPRINTF_L4(PRINT_MASK_HCDI, uhcip->uhci_log_hdl,
	    "uhci_hcdi_pipe_close: addr = 0x%x, ep%d, flags = 0x%x", usb_addr,
	    eptd->bEndpointAddress, usb_flags);

	sema_p(&uhcip->uhci_ocsem);

	mutex_enter(&uhcip->uhci_int_mutex);

	/*
	 * Check whether the pipe is a root hub
	 */
	if (usb_addr == ROOT_HUB_ADDR) {
		switch (UHCI_XFER_TYPE(eptd)) {
		case USB_EP_ATTR_CONTROL:
			USB_DPRINTF_L3(PRINT_MASK_HCDI, uhcip->uhci_log_hdl,
			    "uhci_hcdi_pipe_close: Root hub control pipe "
			    "close succeeded");

			break;
		case USB_EP_ATTR_INTR:
			ASSERT((eptd->bEndpointAddress &
			    USB_EP_NUM_MASK) == 1);

			/* Do interrupt pipe cleanup */
			uhci_root_hub_intr_pipe_cleanup(uhcip,
			    USB_CR_PIPE_CLOSING);

			ASSERT(uhcip->uhci_root_hub.rh_pipe_state ==
			    UHCI_PIPE_STATE_IDLE);

			uhcip->uhci_root_hub.rh_intr_pipe_handle = NULL;

			USB_DPRINTF_L3(PRINT_MASK_HCDI, uhcip->uhci_log_hdl,
			    "uhci_hcdi_pipe_close: Root hub interrupt "
			    "pipe close succeeded");

			uhcip->uhci_root_hub.rh_pipe_state =
			    UHCI_PIPE_STATE_IDLE;

			mutex_exit(&uhcip->uhci_int_mutex);
			sema_v(&uhcip->uhci_ocsem);
			return (USB_SUCCESS);
		}
	} else {
		/*
		 * Stop all the transactions if it is not the root hub.
		 */
		if (UHCI_XFER_TYPE(eptd) == USB_EP_ATTR_INTR) {
			/*
			 * Stop polling on the pipe to prevent any subsequently
			 * queued tds (while we're waiting for SOF, below)
			 * from being executed
			 */
			pp->pp_state = UHCI_PIPE_STATE_IDLE;
		}

		/* Disable all outstanding tds */
		uhci_modify_td_active_bits(uhcip, pp);

		/* Prevent this queue from being executed */
		if (UHCI_XFER_TYPE(eptd) != USB_EP_ATTR_ISOCH) {
			UHCI_SET_TERMINATE_BIT(pp->pp_qh->element_ptr);
		}

		/* Wait for the next start of frame */
		(void) uhci_wait_for_sof(uhcip);

		ASSERT(eptd != NULL);

		switch (UHCI_XFER_TYPE(eptd)) {
		case USB_EP_ATTR_INTR:
			uhci_update_intr_td_data_toggle(uhcip, pp);
			/* FALLTHROUGH */
		case USB_EP_ATTR_CONTROL:
			uhci_remove_tds_tws(uhcip, ph);
			break;
		case USB_EP_ATTR_BULK:
			SetQH32(uhcip, pp->pp_qh->element_ptr,
			    TD_PADDR(pp->pp_qh->td_tailp));
			uhci_remove_bulk_tds_tws(uhcip, pp, UHCI_IN_CLOSE);
			uhci_save_data_toggle(pp);
			break;
		case USB_EP_ATTR_ISOCH:
			uhci_remove_isoc_tds_tws(uhcip, pp);
			break;
		default:
			USB_DPRINTF_L2(PRINT_MASK_HCDI, uhcip->uhci_log_hdl,
			    "uhci_hcdi_pipe_close: Unknown xfer type");
			break;
		}

		/*
		 * Remove the endoint descriptor from Host Controller's
		 * appropriate endpoint list. Isochronous pipes dont have
		 * any queue heads attached to it.
		 */
		if (UHCI_XFER_TYPE(eptd) != USB_EP_ATTR_ISOCH) {
			uhci_remove_qh(uhcip, pp);
		}

		/*
		 * Do the callback for the original client
		 * periodic IN request.
		 */
		if (pp->pp_client_periodic_in_reqp) {
			uhci_hcdi_callback(uhcip, pp, ph, NULL,
			    USB_CR_PIPE_CLOSING);
		}

		/* Deallocate bandwidth */
		if (UHCI_PERIODIC_ENDPOINT(eptd)) {
			mutex_enter(&ph->p_mutex);
			uhci_deallocate_bandwidth(uhcip, ph);
			mutex_exit(&ph->p_mutex);
		}
	}

	/* Deallocate the hcd private portion of the pipe handle.  */

	mutex_enter(&ph->p_mutex);
	kmem_free(ph->p_hcd_private, sizeof (uhci_pipe_private_t));
	ph->p_hcd_private = NULL;
	mutex_exit(&ph->p_mutex);

	USB_DPRINTF_L4(PRINT_MASK_HCDI, uhcip->uhci_log_hdl,
	    "uhci_hcdi_pipe_close: ph = 0x%p", (void *)ph);

	mutex_exit(&uhcip->uhci_int_mutex);
	sema_v(&uhcip->uhci_ocsem);

	return (USB_SUCCESS);
}


/*
 * uhci_hcdi_pipe_reset:
 */
int
uhci_hcdi_pipe_reset(usba_pipe_handle_data_t *ph, usb_flags_t usb_flags)
{
	uhci_state_t		*uhcip = uhci_obtain_state(
	    ph->p_usba_device->usb_root_hub_dip);
	uhci_pipe_private_t	*pp = (uhci_pipe_private_t *)ph->p_hcd_private;
	usb_ep_descr_t		*eptd = &ph->p_ep;
	usb_port_t		port;
	uint_t			port_status = 0;

	USB_DPRINTF_L2(PRINT_MASK_HCDI, uhcip->uhci_log_hdl,
	    "uhci_hcdi_pipe_reset: usb_flags = 0x%x", usb_flags);

	/*
	 * Under some circumstances, uhci internal hub's port
	 * may become disabled because of some errors(see UHCI HCD Spec)
	 * to make the UHCI driver robust enough, we should try to
	 * re-enable it again here because HCD has already know something
	 * bad happened.
	 */
	USB_DPRINTF_L2(PRINT_MASK_HCDI, uhcip->uhci_log_hdl,
	    "uhci_hcdi_pipe_reset: try "
	    "to enable disabled ports if necessary.");
	for (port = 0; port < uhcip->uhci_root_hub.rh_num_ports; port++) {
		port_status = Get_OpReg16(PORTSC[port]);
		if ((!(port_status & HCR_PORT_ENABLE)) &&
		    (port_status & HCR_PORT_CCS) &&
		    (!(port_status & HCR_PORT_CSC))) {
			Set_OpReg16(PORTSC[port],
			    (port_status | HCR_PORT_ENABLE));
			drv_usecwait(UHCI_ONE_MS * 2);
		}
	}

	/*
	 * Return failure immediately for any other pipe reset on the root
	 * hub except control or interrupt pipe.
	 */
	if (ph->p_usba_device->usb_addr == ROOT_HUB_ADDR) {
		switch (UHCI_XFER_TYPE(&ph->p_ep)) {
		case USB_EP_ATTR_CONTROL:
			USB_DPRINTF_L4(PRINT_MASK_HCDI, uhcip->uhci_log_hdl,
			    "uhci_hcdi_pipe_reset: Pipe reset for root"
			    "hub control pipe successful");

			break;
		case USB_EP_ATTR_INTR:
			mutex_enter(&uhcip->uhci_int_mutex);
			uhcip->uhci_root_hub.rh_pipe_state =
			    UHCI_PIPE_STATE_IDLE;

			/* Do interrupt pipe cleanup */
			uhci_root_hub_intr_pipe_cleanup(uhcip,
			    USB_CR_PIPE_RESET);

			USB_DPRINTF_L4(PRINT_MASK_HCDI, uhcip->uhci_log_hdl,
			    "uhci_hcdi_pipe_reset: Pipe reset for "
			    "root hub interrupt pipe successful");
			mutex_exit(&uhcip->uhci_int_mutex);

			break;
		default:
			USB_DPRINTF_L2(PRINT_MASK_HCDI, uhcip->uhci_log_hdl,
			    "uhci_hcdi_pipe_reset: Root hub pipe reset failed");

			return (USB_FAILURE);
		}

		return (USB_SUCCESS);
	}

	mutex_enter(&uhcip->uhci_int_mutex);

	/*
	 * Set the active bit in to INACTIVE for all the remaining TD's of
	 * this end point.  Set the active bit for the dummy td. This will
	 * generate an interrupt at the end of the frame.  After receiving
	 * the interrupt, it is safe to to manipulate the lattice.
	 */
	uhci_modify_td_active_bits(uhcip, pp);

	/* Initialize the element pointer */
	if (UHCI_XFER_TYPE(eptd) != USB_EP_ATTR_ISOCH) {
		UHCI_SET_TERMINATE_BIT(pp->pp_qh->element_ptr);
		SetQH32(uhcip, pp->pp_qh->element_ptr,
		    TD_PADDR(pp->pp_qh->td_tailp));
	}

	(void) uhci_wait_for_sof(uhcip);

	/*
	 * Save the data toggle and clear the pipe.
	 */
	switch (UHCI_XFER_TYPE(eptd)) {
	case USB_EP_ATTR_CONTROL:
	case USB_EP_ATTR_INTR:
		uhci_remove_tds_tws(uhcip, ph);
		break;
	case USB_EP_ATTR_BULK:
		SetQH32(uhcip, pp->pp_qh->element_ptr,
		    TD_PADDR(pp->pp_qh->td_tailp));
		uhci_remove_bulk_tds_tws(uhcip, pp, UHCI_IN_RESET);
		break;
	case USB_EP_ATTR_ISOCH:
		uhci_remove_isoc_tds_tws(uhcip, pp);
		break;
	default:
		USB_DPRINTF_L2(PRINT_MASK_HCDI, uhcip->uhci_log_hdl,
		    "uhci_hcdi_pipe_reset: Unknown xfer type");
		break;
	}

	/*
	 * Do the callback for the original client
	 * periodic IN request.
	 */
	if (pp->pp_client_periodic_in_reqp) {
		uhci_hcdi_callback(uhcip, pp, ph, NULL, USB_CR_PIPE_RESET);
	}

	/*
	 * Since the endpoint is stripped of Transfer Descriptors (TD),
	 * reset the state of the periodic pipe to IDLE.
	 */
	pp->pp_state = UHCI_PIPE_STATE_IDLE;

	mutex_exit(&uhcip->uhci_int_mutex);

	return (USB_SUCCESS);
}

/*
 * uhci_hcdi_pipe_reset_data_toggle:
 */
void
uhci_hcdi_pipe_reset_data_toggle(
	usba_pipe_handle_data_t	*ph)
{
	uhci_state_t		*uhcip = uhci_obtain_state(
	    ph->p_usba_device->usb_root_hub_dip);
	uhci_pipe_private_t	*pp = (uhci_pipe_private_t *)ph->p_hcd_private;

	USB_DPRINTF_L4(PRINT_MASK_HCDI, uhcip->uhci_log_hdl,
	    "uhci_hcdi_pipe_reset_data_toggle:");

	mutex_enter(&uhcip->uhci_int_mutex);

	mutex_enter(&ph->p_mutex);
	pp->pp_data_toggle = 0;
	usba_hcdi_set_data_toggle(ph->p_usba_device, ph->p_ep.bEndpointAddress,
	    pp->pp_data_toggle);
	mutex_exit(&ph->p_mutex);

	mutex_exit(&uhcip->uhci_int_mutex);

}

/*
 * uhci_hcdi_pipe_ctrl_xfer:
 */
int
uhci_hcdi_pipe_ctrl_xfer(
	usba_pipe_handle_data_t	*ph,
	usb_ctrl_req_t		*ctrl_reqp,
	usb_flags_t		flags)
{
	uhci_state_t *uhcip = uhci_obtain_state(
	    ph->p_usba_device->usb_root_hub_dip);
	uhci_pipe_private_t *pp = (uhci_pipe_private_t *)ph->p_hcd_private;
	int error;

	USB_DPRINTF_L4(PRINT_MASK_HCDI, uhcip->uhci_log_hdl,
	    "uhci_hcdi_pipe_ctrl_xfer: req=0x%p, ph=0x%p, flags=0x%x",
	    (void *)ctrl_reqp, (void *)ph, flags);

	mutex_enter(&uhcip->uhci_int_mutex);
	error = uhci_state_is_operational(uhcip);

	if (error != USB_SUCCESS) {
		mutex_exit(&uhcip->uhci_int_mutex);

		return (error);
	}

	ASSERT(pp->pp_state == UHCI_PIPE_STATE_IDLE);

	/*
	 * Check and handle root hub control request.
	 */
	if (ph->p_usba_device->usb_addr == ROOT_HUB_ADDR) {
		error = uhci_handle_root_hub_request(uhcip, ph, ctrl_reqp);
		mutex_exit(&uhcip->uhci_int_mutex);

		return (error);
	}

	/* Insert the td's on the endpoint */
	if ((error = uhci_insert_ctrl_td(uhcip, ph, ctrl_reqp, flags)) !=
	    USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_HCDI, uhcip->uhci_log_hdl,
		    "uhci_hcdi_pipe_ctrl_xfer: No resources");
	}
	mutex_exit(&uhcip->uhci_int_mutex);

	return (error);
}


/*
 * uhci_hcdi_pipe_bulk_xfer:
 */
int
uhci_hcdi_pipe_bulk_xfer(usba_pipe_handle_data_t *pipe_handle,
    usb_bulk_req_t *bulk_reqp, usb_flags_t usb_flags)
{
	int		error;
	uhci_state_t	*uhcip;

	uhcip = uhci_obtain_state(pipe_handle->p_usba_device->usb_root_hub_dip);

	USB_DPRINTF_L4(PRINT_MASK_HCDI, uhcip->uhci_log_hdl,
	    "uhci_hcdi_pipe_bulk_xfer: Flags = 0x%x", usb_flags);

	/* Check the size of bulk request */
	if (bulk_reqp->bulk_len > UHCI_BULK_MAX_XFER_SIZE) {
		USB_DPRINTF_L2(PRINT_MASK_HCDI, uhcip->uhci_log_hdl,
		    "uhci_hcdi_pipe_bulk_xfer: req size 0x%x is more than 0x%x",
		    bulk_reqp->bulk_len, UHCI_BULK_MAX_XFER_SIZE);

		return (USB_FAILURE);
	}

	mutex_enter(&uhcip->uhci_int_mutex);

	error = uhci_state_is_operational(uhcip);

	if (error != USB_SUCCESS) {
		mutex_exit(&uhcip->uhci_int_mutex);

		return (error);
	}
	/* Add the TD into the Host Controller's bulk list */
	if ((error = uhci_insert_bulk_td(uhcip, pipe_handle, bulk_reqp,
	    usb_flags)) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_HCDI, uhcip->uhci_log_hdl,
		    "uhci_hcdi_pipe_bulk_xfer: uhci_insert_bulk_td failed");
	}
	mutex_exit(&uhcip->uhci_int_mutex);

	return (error);
}


/*
 * uhci_hcdi_bulk_transfer_size:
 *	Return maximum bulk transfer size
 */
int
uhci_hcdi_bulk_transfer_size(
	usba_device_t	*usba_device,
	size_t		*size)
{
	uhci_state_t	*uhcip = uhci_obtain_state(
	    usba_device->usb_root_hub_dip);
	int		rval;

	USB_DPRINTF_L4(PRINT_MASK_HCDI, uhcip->uhci_log_hdl,
	    "uhci_hcdi_bulk_transfer_size:");

	mutex_enter(&uhcip->uhci_int_mutex);
	rval = uhci_state_is_operational(uhcip);

	if (rval != USB_SUCCESS) {
		mutex_exit(&uhcip->uhci_int_mutex);

		return (rval);
	}

	*size = uhci_bulk_transfer_size;
	mutex_exit(&uhcip->uhci_int_mutex);

	return (USB_SUCCESS);
}


/*
 * uhci_hcdi_pipe_intr_xfer:
 */
int
uhci_hcdi_pipe_intr_xfer(
	usba_pipe_handle_data_t	*ph,
	usb_intr_req_t		*req,
	usb_flags_t		flags)
{
	uhci_state_t	*uhcip = uhci_obtain_state(
	    ph->p_usba_device->usb_root_hub_dip);

	USB_DPRINTF_L4(PRINT_MASK_HCDI, uhcip->uhci_log_hdl,
	    "uhci_hcdi_pipe_intr_xfer: req=0x%p, uf=0x%x", (void *)req, flags);

	if (UHCI_XFER_DIR(&ph->p_ep) == USB_EP_DIR_IN) {

		return (uhci_start_periodic_pipe_polling(uhcip, ph,
		    (usb_opaque_t)req, flags));
	} else {

		return (uhci_send_intr_data(uhcip, ph, req, flags));
	}
}


/*
 * uhci_send_intr_data():
 *	send data to interrupt out pipe
 */
static int
uhci_send_intr_data(
	uhci_state_t		*uhcip,
	usba_pipe_handle_data_t	*pipe_handle,
	usb_intr_req_t		*req,
	usb_flags_t		flags)
{
	int	rval;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
	    "uhci_send_intr_data:");

	mutex_enter(&uhcip->uhci_int_mutex);

	rval = uhci_state_is_operational(uhcip);

	if (rval != USB_SUCCESS) {
		mutex_exit(&uhcip->uhci_int_mutex);

		return (rval);
	}

	/* Add the TD into the Host Controller's interrupt list */
	if ((rval = uhci_insert_intr_td(uhcip, pipe_handle, req, flags)) !=
	    USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_HCDI, uhcip->uhci_log_hdl,
		    "uhci_send_intr_data: No resources");
	}
	mutex_exit(&uhcip->uhci_int_mutex);

	return (rval);
}


/*
 * uhci_hcdi_pipe_stop_intr_polling()
 */
int
uhci_hcdi_pipe_stop_intr_polling(
	usba_pipe_handle_data_t *pipe_handle,
	usb_flags_t		flags)
{
	uhci_state_t *uhcip =
	    uhci_obtain_state(pipe_handle->p_usba_device->usb_root_hub_dip);
	int		rval;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
	    "uhci_hcdi_pipe_stop_intr_polling: ph = 0x%p fl = 0x%x",
	    (void *)pipe_handle, flags);
	mutex_enter(&uhcip->uhci_int_mutex);

	rval = uhci_stop_periodic_pipe_polling(uhcip, pipe_handle, flags);

	mutex_exit(&uhcip->uhci_int_mutex);

	return (rval);
}


/*
 * uhci_hcdi_get_current_frame_number
 *	Get the current frame number.
 *	Return whether the request is handled successfully.
 */
int
uhci_hcdi_get_current_frame_number(
	usba_device_t		*usba_device,
	usb_frame_number_t	*frame_number)
{
	uhci_state_t *uhcip = uhci_obtain_state(usba_device->usb_root_hub_dip);
	int		rval;

	mutex_enter(&uhcip->uhci_int_mutex);
	rval = uhci_state_is_operational(uhcip);

	if (rval != USB_SUCCESS) {
		mutex_exit(&uhcip->uhci_int_mutex);

		return (rval);
	}

	*frame_number = uhci_get_sw_frame_number(uhcip);
	mutex_exit(&uhcip->uhci_int_mutex);

	USB_DPRINTF_L4(PRINT_MASK_HCDI, uhcip->uhci_log_hdl,
	    "uhci_hcdi_get_current_frame_number: %llx",
	    (unsigned long long)(*frame_number));

	return (rval);
}


/*
 * uhci_hcdi_get_max_isoc_pkts
 *	Get the maximum number of isoc packets per USB Isoch request.
 *	Return whether the request is handled successfully.
 */
int
uhci_hcdi_get_max_isoc_pkts(
	usba_device_t	*usba_device,
	uint_t		*max_isoc_pkts_per_request)
{
	uhci_state_t *uhcip = uhci_obtain_state(usba_device->usb_root_hub_dip);
	int		rval;

	mutex_enter(&uhcip->uhci_int_mutex);
	rval = uhci_state_is_operational(uhcip);

	if (rval != USB_SUCCESS) {
		mutex_exit(&uhcip->uhci_int_mutex);

		return (rval);
	}

	*max_isoc_pkts_per_request = UHCI_MAX_ISOC_PKTS;
	mutex_exit(&uhcip->uhci_int_mutex);

	USB_DPRINTF_L4(PRINT_MASK_HCDI, uhcip->uhci_log_hdl,
	    "uhci_hcdi_get_max_isoc_pkts: 0x%x", UHCI_MAX_ISOC_PKTS);

	return (rval);
}


/*
 * uhci_hcdi_pipe_isoc_xfer:
 */
int
uhci_hcdi_pipe_isoc_xfer(
	usba_pipe_handle_data_t	*ph,
	usb_isoc_req_t		*isoc_reqp,
	usb_flags_t		flags)
{
	uhci_state_t	*uhcip;

	uhcip = uhci_obtain_state(ph->p_usba_device->usb_root_hub_dip);
	USB_DPRINTF_L4(PRINT_MASK_HCDI, uhcip->uhci_log_hdl,
	    "uhci_hcdi_pipe_isoc_xfer: req=0x%p, uf=0x%x",
	    (void *)isoc_reqp, flags);

	if (UHCI_XFER_DIR(&ph->p_ep) == USB_EP_DIR_IN) {

		return (uhci_start_periodic_pipe_polling(uhcip, ph,
		    (usb_opaque_t)isoc_reqp, flags));
	} else {

		return (uhci_pipe_send_isoc_data(uhcip, ph, isoc_reqp, flags));
	}
}


/*
 * uhci_hcdi_pipe_stop_isoc_polling()
 */
int
uhci_hcdi_pipe_stop_isoc_polling(
	usba_pipe_handle_data_t	*ph,
	usb_flags_t		flags)
{
	uhci_state_t *uhcip =
	    uhci_obtain_state(ph->p_usba_device->usb_root_hub_dip);
	int		rval;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
	    "uhci_hcdi_pipe_stop_isoc_polling: ph = 0x%p fl = 0x%x",
	    (void *)ph, flags);

	mutex_enter(&uhcip->uhci_int_mutex);
	rval = uhci_state_is_operational(uhcip);

	if (rval != USB_SUCCESS) {
		mutex_exit(&uhcip->uhci_int_mutex);

		return (rval);
	}

	rval = uhci_stop_periodic_pipe_polling(uhcip, ph, flags);

	mutex_exit(&uhcip->uhci_int_mutex);

	return (rval);
}


/*
 * uhci_start_periodic_pipe_polling:
 */
static int
uhci_start_periodic_pipe_polling(
	uhci_state_t		*uhcip,
	usba_pipe_handle_data_t	*ph,
	usb_opaque_t		in_reqp,
	usb_flags_t		flags)
{
	int			n, num_tds;
	int			error;
	usb_intr_req_t		*intr_reqp = (usb_intr_req_t *)in_reqp;
	usb_ep_descr_t		*eptd = &ph->p_ep;
	uhci_pipe_private_t	*pp = (uhci_pipe_private_t *)ph->p_hcd_private;

	USB_DPRINTF_L4(PRINT_MASK_HCDI, uhcip->uhci_log_hdl,
	    "uhci_start_periodic_pipe_polling: flags: 0x%x, ep%d",
	    flags, eptd->bEndpointAddress);

	mutex_enter(&uhcip->uhci_int_mutex);

	error = uhci_state_is_operational(uhcip);

	if (error != USB_SUCCESS) {
		mutex_exit(&uhcip->uhci_int_mutex);

		return (error);
	}

	if (ph->p_usba_device->usb_addr == ROOT_HUB_ADDR) {
		uint_t	pipe_state = uhcip->uhci_root_hub.rh_pipe_state;

		ASSERT(pipe_state == UHCI_PIPE_STATE_IDLE);
		ASSERT(UHCI_XFER_DIR(eptd) == USB_EP_DIR_IN);

		/* ONE_XFER not supported */
		ASSERT((intr_reqp->intr_attributes &
		    USB_ATTRS_ONE_XFER) == 0);
		ASSERT(uhcip->uhci_root_hub.rh_client_intr_req == NULL);
		uhcip->uhci_root_hub.rh_client_intr_req = intr_reqp;

		if ((error = uhci_root_hub_allocate_intr_pipe_resource(
		    uhcip, flags)) != USB_SUCCESS) {
			/* reset the client interrupt request pointer */
			uhcip->uhci_root_hub.rh_client_intr_req = NULL;

			mutex_exit(&uhcip->uhci_int_mutex);

			return (error);
		}

		uhcip->uhci_root_hub.rh_pipe_state = USB_PIPE_STATE_ACTIVE;

		USB_DPRINTF_L4(PRINT_MASK_HCDI, uhcip->uhci_log_hdl,
		    "uhci_start_periodic_pipe_polling: "
		    "Start intr polling for root hub successful");

		/* check if we need to send the reset data up? */
		if (uhcip->uhci_root_hub.rh_status) {
			uhci_root_hub_reset_occurred(uhcip,
			    uhcip->uhci_root_hub.rh_status - 1);

			uhcip->uhci_root_hub.rh_status = 0;
		}
		mutex_exit(&uhcip->uhci_int_mutex);

		return (error);
	}

	/* save the original client's periodic IN request */
	pp->pp_client_periodic_in_reqp = in_reqp;

	ASSERT(pp->pp_state != UHCI_PIPE_STATE_ACTIVE);
	/*
	 *
	 * This pipe is uninitialized. If it is an isoc
	 * receive request, insert four times the same
	 * request so that we do not lose any frames.
	 */
	if (UHCI_XFER_TYPE(eptd) == USB_EP_ATTR_ISOCH) {
		for (n = 0; n < 5; n++) {
			if ((error = uhci_start_isoc_receive_polling(
			    uhcip, ph, NULL, flags)) != USB_SUCCESS) {

				USB_DPRINTF_L2(PRINT_MASK_INTR,
				    uhcip->uhci_log_hdl,
				    "uhci_start_periodic_pipe_polling: "
				    "Start isoc polling failed %d", n);

				pp->pp_client_periodic_in_reqp = NULL;
				mutex_exit(&uhcip->uhci_int_mutex);

				return (error);
			}
		}
	}

	if (UHCI_XFER_TYPE(eptd) == USB_EP_ATTR_INTR) {
		if ((pp->pp_node < POLLING_FREQ_7MS) &&
		    (!(intr_reqp->intr_attributes & USB_ATTRS_ONE_XFER))) {
			num_tds = 5;
		} else {
			num_tds = 1;
		}

		/*
		 * This pipe is uninitialized.
		 * Insert a TD on the interrupt ED.
		 */
		for (n = 0; n < num_tds; n++) {
			if ((error = uhci_insert_intr_td(uhcip, ph, NULL,
			    flags)) != USB_SUCCESS) {
				USB_DPRINTF_L2(PRINT_MASK_INTR,
				    uhcip->uhci_log_hdl,
				    "uhci_start_periodic_pipe_polling: "
				    "Start polling failed");

				pp->pp_client_periodic_in_reqp = NULL;
				mutex_exit(&uhcip->uhci_int_mutex);

				return (error);
			}
		}
	}

	pp->pp_state = UHCI_PIPE_STATE_ACTIVE;

	mutex_exit(&uhcip->uhci_int_mutex);

	return (error);
}


/*
 * uhci_hcdi_periodic_pipe_stop_polling:
 */
static int
uhci_stop_periodic_pipe_polling(uhci_state_t *uhcip,
    usba_pipe_handle_data_t  *ph, usb_flags_t flags)
{
	uhci_pipe_private_t	*pp = (uhci_pipe_private_t *)ph->p_hcd_private;
	usb_ep_descr_t		*eptd = &ph->p_ep;

	USB_DPRINTF_L4(PRINT_MASK_HCDI, uhcip->uhci_log_hdl,
	    "uhci_stop_periodic_pipe_polling: flags = 0x%x", flags);

	ASSERT(mutex_owned(&uhcip->uhci_int_mutex));
	if (ph->p_usba_device->usb_addr == ROOT_HUB_ADDR) {
		ASSERT(UHCI_XFER_DIR(eptd) == USB_EP_DIR_IN);

		if (uhcip->uhci_root_hub.rh_pipe_state ==
		    UHCI_PIPE_STATE_ACTIVE) {
			uhcip->uhci_root_hub.rh_pipe_state =
			    UHCI_PIPE_STATE_IDLE;

			/* Do interrupt pipe cleanup */
			uhci_root_hub_intr_pipe_cleanup(uhcip,
			    USB_CR_STOPPED_POLLING);

			USB_DPRINTF_L4(PRINT_MASK_HCDI, uhcip->uhci_log_hdl,
			    "uhci_stop_periodic_pipe_polling: Stop intr "
			    "polling for root hub successful");

		} else {
			USB_DPRINTF_L2(PRINT_MASK_INTR, uhcip->uhci_log_hdl,
			    "uhci_stop_periodic_pipe_polling: "
			    "Intr polling for root hub is already stopped");
		}

		return (USB_SUCCESS);
	}

	if (pp->pp_state != UHCI_PIPE_STATE_ACTIVE) {
		USB_DPRINTF_L2(PRINT_MASK_INTR, uhcip->uhci_log_hdl,
		    "uhci_stop_periodic_pipe_polling: Polling already stopped");

		return (USB_SUCCESS);
	}

	/*
	 * Set the terminate bits in all the tds in the queue and
	 * in the element_ptr.
	 * Do not deallocate the bandwidth or tear down the DMA
	 */
	uhci_modify_td_active_bits(uhcip, pp);
	(void) uhci_wait_for_sof(uhcip);

	if (UHCI_XFER_TYPE(eptd) == USB_EP_ATTR_ISOCH) {
		uhci_remove_isoc_tds_tws(uhcip, pp);
		pp->pp_state = UHCI_PIPE_STATE_IDLE;
	} else {
		UHCI_SET_TERMINATE_BIT(pp->pp_qh->element_ptr);
		uhci_update_intr_td_data_toggle(uhcip, pp);
		SetQH32(uhcip, pp->pp_qh->element_ptr,
		    TD_PADDR(pp->pp_qh->td_tailp));
		uhci_remove_tds_tws(uhcip, ph);
	}

	pp->pp_state = UHCI_PIPE_STATE_IDLE;

	if (pp->pp_client_periodic_in_reqp) {
		uhci_hcdi_callback(uhcip, pp, ph, NULL, USB_CR_STOPPED_POLLING);
	}

	return (USB_SUCCESS);
}


/*
 * uhci_hcdi_pipe_send_isoc_data:
 *	Handles the isoc write request.
 */
static int
uhci_pipe_send_isoc_data(
	uhci_state_t		*uhcip,
	usba_pipe_handle_data_t	*ph,
	usb_isoc_req_t		*isoc_req,
	usb_flags_t		usb_flags)
{
	int			error;
	size_t			max_isoc_xfer_sz, length;

	USB_DPRINTF_L4(PRINT_MASK_HCDI, uhcip->uhci_log_hdl,
	    "uhci_pipe_send_isoc_data: isoc_req = %p flags = %x",
	    (void *)isoc_req, usb_flags);

	ASSERT(isoc_req->isoc_pkts_count < UHCI_MAX_ISOC_PKTS);

	/* Calculate the maximum isochronous transfer size */
	max_isoc_xfer_sz = UHCI_MAX_ISOC_PKTS * ph->p_ep.wMaxPacketSize;

	/* Check the size of isochronous request */
	ASSERT(isoc_req->isoc_data != NULL);
	length = MBLKL(isoc_req->isoc_data);

	if (length > max_isoc_xfer_sz) {
		USB_DPRINTF_L2(PRINT_MASK_HCDI, uhcip->uhci_log_hdl,
		    "uhci_pipe_send_isoc_data: Maximum isoc request size %lx "
		    "Given isoc request size %lx", max_isoc_xfer_sz, length);

		return (USB_INVALID_REQUEST);
	}


	/*
	 * Check whether we can insert these tds?
	 * At any point of time, we can insert maximum of 1024 isoc td's,
	 * size of frame list table.
	 */
	if (isoc_req->isoc_pkts_count > UHCI_MAX_ISOC_PKTS) {

		USB_DPRINTF_L2(PRINT_MASK_ISOC, uhcip->uhci_log_hdl,
		    "uhci_pipe_send_isoc_data: request too big");

		return (USB_INVALID_REQUEST);
	}

	/* Add the TD into the Host Controller's isoc list */
	mutex_enter(&uhcip->uhci_int_mutex);

	error = uhci_state_is_operational(uhcip);

	if (error != USB_SUCCESS) {
		mutex_exit(&uhcip->uhci_int_mutex);

		return (error);
	}

	if ((error = uhci_insert_isoc_td(uhcip, ph, isoc_req,
	    length, usb_flags)) != USB_SUCCESS) {

		USB_DPRINTF_L2(PRINT_MASK_ISOC, uhcip->uhci_log_hdl,
		    "uhci_pipe_send_isoc_data: Unable to insert the isoc_req,"
		    "Error = %d", error);
	}
	mutex_exit(&uhcip->uhci_int_mutex);

	return (error);
}


/*
 * uhci_update_intr_td_data_toggle
 *	Update the data toggle and save in the usba_device structure
 */
static void
uhci_update_intr_td_data_toggle(uhci_state_t *uhcip, uhci_pipe_private_t *pp)
{
	uint32_t	paddr_tail, element_ptr;
	uhci_td_t	*next_td;

	/* Find the next td that would have been executed */
	element_ptr = GetQH32(uhcip, pp->pp_qh->element_ptr) &
	    QH_ELEMENT_PTR_MASK;
	next_td = TD_VADDR(element_ptr);
	paddr_tail = TD_PADDR(pp->pp_qh->td_tailp);

	/*
	 * If element_ptr points to the dummy td, then the data toggle in
	 * pp_data_toggle is correct. Otherwise update the data toggle in
	 * the pipe private
	 */
	if (element_ptr != paddr_tail) {
		pp->pp_data_toggle = GetTD_dtogg(uhcip, next_td);
	}

	USB_DPRINTF_L4(PRINT_MASK_HCDI, uhcip->uhci_log_hdl,
	    "uhci_update_intr_td_data_toggle: "
	    "pp %p toggle %x element ptr %x ptail %x",
	    (void *)pp, pp->pp_data_toggle, element_ptr, paddr_tail);

	uhci_save_data_toggle(pp);
}
