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
 * Open Host Controller Driver (OHCI)
 *
 * The USB Open Host Controller driver is a software driver which interfaces
 * to the Universal Serial Bus layer (USBA) and the USB Open Host Controller.
 * The interface to USB Open Host Controller is defined by the OpenHCI	Host
 * Controller Interface.
 *
 * This module contains the code for root hub related functions.
 *
 * Note: ONE_XFER is not supported on root hub interrupt polling.
 */
#include <sys/usb/hcd/openhci/ohcid.h>

/* static function prototypes */
static int	ohci_handle_set_clear_port_feature(
				ohci_state_t		*ohcip,
				uchar_t 		bRequest,
				uint16_t		wValue,
				uint16_t		port);
static void	ohci_handle_port_power(ohci_state_t	*ohcip,
				uint16_t		port,
				uint_t			on);
static void	ohci_handle_port_enable(ohci_state_t	*ohcip,
				uint16_t		port,
				uint_t			on);
static void	ohci_handle_clrchng_port_enable(
				ohci_state_t		*ohcip,
				uint16_t		port);
static void	ohci_handle_port_suspend(ohci_state_t	*ohcip,
				uint16_t		port,
				uint_t			on);
static void	ohci_handle_clrchng_port_suspend(
				ohci_state_t		*ohcip,
				uint16_t		port);
static void	ohci_handle_port_reset(ohci_state_t	*ohcip,
				uint16_t		port);
static void	ohci_handle_complete_port_reset(
				ohci_state_t		*ohcip,
				uint16_t		port);
static void	ohci_handle_clear_port_connection(
				ohci_state_t		*ohcip,
				uint16_t		port);
static void	ohci_handle_clrchng_port_over_current(
				ohci_state_t		*ohcip,
				uint16_t		port);
static void	ohci_handle_get_port_status(
				ohci_state_t		*ohcip,
				uint16_t		port);
static int	ohci_handle_set_clear_hub_feature(
				ohci_state_t		*ohcip,
				uchar_t 		bRequest,
				uint16_t		wValue);
static void	ohci_handle_clrchng_hub_over_current(
				ohci_state_t		*ohcip);
static void	ohci_handle_get_hub_descriptor(
				ohci_state_t		*ohcip);
static void	ohci_handle_get_hub_status(
				ohci_state_t		*ohcip);
static void	ohci_handle_get_device_status(
				ohci_state_t		*ohcip);
static int	ohci_root_hub_allocate_intr_pipe_resource(
				ohci_state_t		*ohcip,
				usb_flags_t		flags);
static void	ohci_root_hub_intr_pipe_cleanup(
				ohci_state_t		*ohcip,
				usb_cr_t		completion_reason);
static void	ohci_root_hub_hcdi_callback(
				usba_pipe_handle_data_t	*ph,
				usb_cr_t		completion_reason);


/*
 * ohci_init_root_hub:
 *
 * Initialize the root hub
 */
int
ohci_init_root_hub(ohci_state_t	*ohcip)
{
	usb_hub_descr_t 	*root_hub_descr =
	    &ohcip->ohci_root_hub.rh_descr;
	uint_t			des_A, des_B, port_state;
	int			i, length;

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
	    "ohci_init_root_hub:");

	/* Read the descriptor registers */
	des_A = ohcip->ohci_root_hub.rh_des_A = Get_OpReg(hcr_rh_descriptorA);
	des_B = ohcip->ohci_root_hub.rh_des_B = Get_OpReg(hcr_rh_descriptorB);

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
	    "root hub descriptor A 0x%x", ohcip->ohci_root_hub.rh_des_A);

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
	    "root hub descriptor B 0x%x", ohcip->ohci_root_hub.rh_des_B);

	/* Obtain the root hub status */
	ohcip->ohci_root_hub.rh_status = Get_OpReg(hcr_rh_status);

	/*
	 * Build the hub descriptor based on HcRhDescriptorA and
	 * HcRhDescriptorB
	 */
	root_hub_descr->bDescriptorType = ROOT_HUB_DESCRIPTOR_TYPE;

	if ((des_A & HCR_RHA_NDP) > OHCI_MAX_RH_PORTS) {
		USB_DPRINTF_L2(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
		    "ohci_init_root_hub:" "Invalid no of root hub ports 0x%x",
		    des_A & HCR_RHA_NDP);

		return (USB_FAILURE);
	}

	/* Obtain the number of downstream ports */
	root_hub_descr->bNbrPorts = des_A & HCR_RHA_NDP;

	length = root_hub_descr->bNbrPorts / 8;

	if (length) {
		root_hub_descr->bDescLength = 7 + (2 * (length + 1));
	} else {
		root_hub_descr->bDescLength = ROOT_HUB_DESCRIPTOR_LENGTH;
	}

	/* Determine the Power Switching Mode */
	if (!(des_A & HCR_RHA_NPS)) {
		/*
		 * The ports are power switched. Check for either individual
		 * or gang power switching.
		 */
		if ((des_A & HCR_RHA_PSM) && (des_B & HCR_RHB_PPCM)) {
			/* each port is powered individually */
			root_hub_descr->wHubCharacteristics =
			    HUB_CHARS_INDIVIDUAL_PORT_POWER;
		} else {
			/* the ports are gang powered */
			root_hub_descr->
			    wHubCharacteristics = HUB_CHARS_GANGED_POWER;
		}

		/* Each port will start off in the POWERED_OFF mode */
		port_state = POWERED_OFF;
	} else {
		/* The ports are powered when the ctlr is powered */
		root_hub_descr->
		    wHubCharacteristics = HUB_CHARS_NO_POWER_SWITCHING;

		port_state = DISCONNECTED;
	}

	/* The root hub should never be a compound device */
	ASSERT((des_A & HCR_RHA_DT) == 0);

	/* Determine the Over-current Protection Mode */
	if (des_A & HCR_RHA_NOCP) {
		/* No over current protection */
		root_hub_descr->
		    wHubCharacteristics |= HUB_CHARS_NO_OVER_CURRENT;
	} else {
		USB_DPRINTF_L3(PRINT_MASK_ROOT_HUB,
		    ohcip->ohci_log_hdl, "OCPM =%d, PSM=%d",
		    des_A & HCR_RHA_OCPM, des_A & HCR_RHA_PSM);

		/* See if over current protection is provided */
		if (des_A & HCR_RHA_OCPM) {
			/* reported on a per port basis */
			root_hub_descr->
			    wHubCharacteristics |= HUB_CHARS_INDIV_OVER_CURRENT;
		}
	}

	/* Obtain the power on to power good time of the ports */
	root_hub_descr->bPwrOn2PwrGood = (uint32_t)
	    ((des_A & HCR_RHA_PTPGT) >> HCR_RHA_PTPGT_SHIFT);

	USB_DPRINTF_L3(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
	    "Power on to power good %d", root_hub_descr->bPwrOn2PwrGood);

	/* Indicate if the device is removable */
	root_hub_descr->DeviceRemovable = (uchar_t)des_B & HCR_RHB_DR;

	/*
	 * Fill in the port power control mask:
	 * Each bit in the  PortPowerControlMask
	 * should be set. Refer to USB 2.0, table 11-13
	 */
	root_hub_descr->PortPwrCtrlMask = (uchar_t)(des_B >> 16);

	/* Set the state of each port and initialize the status */
	for (i = 0; i < root_hub_descr->bNbrPorts; i++) {
		ohcip->ohci_root_hub.rh_port_state[i] = port_state;

		/* Turn off the power on each port for now */
		Set_OpReg(hcr_rh_portstatus[i],  HCR_PORT_CPP);

		/*
		 * Initialize each of the root hub port	status
		 * equal to zero. This initialization makes sure
		 * that all devices connected to root hub will
		 * enumerates when the first RHSC interrupt occurs
		 * since definitely there will be changes  in
		 * the root hub port status.
		 */
		ohcip->ohci_root_hub.rh_port_status[i] = 0;
	}

	return (USB_SUCCESS);
}


/*
 * ohci_load_root_hub_driver:
 *
 * Attach the root hub
 */
static usb_dev_descr_t ohci_root_hub_device_descriptor = {
	0x12,		/* bLength */
	0x01,		/* bDescriptorType, Device */
	0x110,		/* bcdUSB, v1.1 */
	0x09,		/* bDeviceClass */
	0x00,		/* bDeviceSubClass */
	0x00,		/* bDeviceProtocol */
	0x08,		/* bMaxPacketSize0 */
	0x00,		/* idVendor */
	0x00,		/* idProduct */
	0x00,		/* bcdDevice */
	0x00,		/* iManufacturer */
	0x00,		/* iProduct */
	0x00,		/* iSerialNumber */
	0x01		/* bNumConfigurations */
};

static uchar_t ohci_root_hub_config_descriptor[] = {
	/* One configuartion */
	0x09,		/* bLength */
	0x02,		/* bDescriptorType, Configuartion */
	0x19, 0x00,	/* wTotalLength */
	0x01,		/* bNumInterfaces */
	0x01,		/* bConfigurationValue */
	0x00,		/* iConfiguration */
	0x40,		/* bmAttributes */
	0x00,		/* MaxPower */

	/* One Interface */
	0x09,		/* bLength */
	0x04,		/* bDescriptorType, Interface */
	0x00,		/* bInterfaceNumber */
	0x00,		/* bAlternateSetting */
	0x01,		/* bNumEndpoints */
	0x09,		/* bInterfaceClass */
	0x01,		/* bInterfaceSubClass */
	0x00,		/* bInterfaceProtocol */
	0x00,		/* iInterface */

	/* One Endpoint (status change endpoint) */
	0x07,		/* bLength */
	0x05,		/* bDescriptorType, Endpoint */
	0x81,		/* bEndpointAddress */
	0x03,		/* bmAttributes */
	0x01, 0x00,	/* wMaxPacketSize, 1 +	(OHCI_MAX_RH_PORTS / 8) */
	0xff		/* bInterval */
};

int
ohci_load_root_hub_driver(ohci_state_t	*ohcip)
{
	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
	    "ohci_load_root_hub_driver:");

	return (usba_hubdi_bind_root_hub(ohcip->ohci_dip,
	    ohci_root_hub_config_descriptor,
	    sizeof (ohci_root_hub_config_descriptor),
	    &ohci_root_hub_device_descriptor));
}


/*
 * ohci_unload_root_hub_driver:
 */
int
ohci_unload_root_hub_driver(ohci_state_t	*ohcip)
{
	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
	    "ohci_unload_root_hub_driver:");

	return (usba_hubdi_unbind_root_hub(ohcip->ohci_dip));
}


/*
 * ohci_handle_root_hub_pipe_open:
 *
 * Handle opening of control and interrupt pipes on root hub.
 */
/* ARGSUSED */
int
ohci_handle_root_hub_pipe_open(
	usba_pipe_handle_data_t	*ph,
	usb_flags_t		usb_flags)
{
	ohci_state_t		*ohcip = ohci_obtain_state(
	    ph->p_usba_device->usb_root_hub_dip);
	usb_ep_descr_t		*eptd = &ph->p_ep;

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
	    "ohci_handle_root_hub_pipe_open: Root hub pipe open");

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	switch (eptd->bmAttributes & USB_EP_ATTR_MASK) {
	case USB_EP_ATTR_CONTROL:
		/* Save control pipe handle */
		ohcip->ohci_root_hub.rh_ctrl_pipe_handle = ph;

		/* Set state of the root hub control pipe as idle */
		ohcip->ohci_root_hub.rh_ctrl_pipe_state = OHCI_PIPE_STATE_IDLE;

		ohcip->ohci_root_hub.rh_curr_ctrl_reqp = NULL;

		USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
		    "ohci_handle_root_hub_pipe_open: Root hub control "
		    "pipe open succeeded");

		break;
	case USB_EP_ATTR_INTR:
		/* Save interrupt pipe handle */
		ohcip->ohci_root_hub.rh_intr_pipe_handle = ph;

		/* Set state of the root hub interrupt pipe as idle */
		ohcip->ohci_root_hub.rh_intr_pipe_state = OHCI_PIPE_STATE_IDLE;

		ohcip->ohci_root_hub.rh_client_intr_reqp = NULL;

		ohcip->ohci_root_hub.rh_curr_intr_reqp = NULL;

		USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
		    "ohci_handle_root_hub_pipe_open: Root hub interrupt "
		    "pipe open succeeded");

		break;
	default:
		USB_DPRINTF_L2(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
		    "ohci_handle_root_hub_pipe_open: Root hub pipe open"
		    "failed");

		return (USB_FAILURE);
	}

	ohcip->ohci_open_pipe_count++;

	return (USB_SUCCESS);
}


/*
 * ohci_handle_root_hub_pipe_close:
 *
 * Handle closing of control and interrupt pipes on root hub.
 */
/* ARGSUSED */
int
ohci_handle_root_hub_pipe_close(usba_pipe_handle_data_t	*ph)
{
	ohci_state_t		*ohcip = ohci_obtain_state(
	    ph->p_usba_device->usb_root_hub_dip);
	usb_ep_descr_t		*eptd = &ph->p_ep;

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
	    "ohci_handle_root_hub_pipe_close: Root hub pipe close");

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	switch (eptd->bmAttributes & USB_EP_ATTR_MASK) {
	case USB_EP_ATTR_CONTROL:
		ASSERT(ohcip->ohci_root_hub.
		    rh_ctrl_pipe_state != OHCI_PIPE_STATE_CLOSE);

		/* Set state of the root hub control pipe as close */
		ohcip->ohci_root_hub.rh_ctrl_pipe_state = OHCI_PIPE_STATE_CLOSE;

		/* Set root hub control pipe handle to null */
		ohcip->ohci_root_hub.rh_ctrl_pipe_handle = NULL;

		USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
		    "ohci_handle_root_hub_pipe_close: "
		    "Root hub control pipe close succeeded");
		break;
	case USB_EP_ATTR_INTR:
		ASSERT((eptd->bEndpointAddress & USB_EP_NUM_MASK) == 1);

		ASSERT(ohcip->ohci_root_hub.
		    rh_intr_pipe_state != OHCI_PIPE_STATE_CLOSE);

		/* Set state of the root hub interrupt pipe as close */
		ohcip->ohci_root_hub.rh_intr_pipe_state = OHCI_PIPE_STATE_CLOSE;

		/* Do interrupt pipe cleanup */
		ohci_root_hub_intr_pipe_cleanup(ohcip, USB_CR_PIPE_CLOSING);

		/* Set root hub interrupt pipe handle to null */
		ohcip->ohci_root_hub.rh_intr_pipe_handle = NULL;

		USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
		    "ohci_handle_root_hub_pipe_close: "
		    "Root hub interrupt pipe close succeeded");

		break;
	default:
		USB_DPRINTF_L2(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
		    "ohci_handle_root_hub_pipe_close: "
		    "Root hub pipe close failed");

		return (USB_FAILURE);
	}

	ohcip->ohci_open_pipe_count--;

	return (USB_SUCCESS);
}


/*
 * ohci_handle_root_hub_pipe_reset:
 *
 * Handle resetting of control and interrupt pipes on root hub.
 */
/* ARGSUSED */
int
ohci_handle_root_hub_pipe_reset(
	usba_pipe_handle_data_t	*ph,
	usb_flags_t		usb_flags)
{
	ohci_state_t		*ohcip = ohci_obtain_state(
	    ph->p_usba_device->usb_root_hub_dip);
	usb_ep_descr_t		*eptd = &ph->p_ep;
	int			error = USB_SUCCESS;

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
	    "ohci_handle_root_hub_pipe_reset: Root hub pipe reset");

	mutex_enter(&ohcip->ohci_int_mutex);

	switch (eptd->bmAttributes & USB_EP_ATTR_MASK) {
	case USB_EP_ATTR_CONTROL:
		ohcip->ohci_root_hub.rh_ctrl_pipe_state = OHCI_PIPE_STATE_IDLE;

		USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
		    "ohci_handle_root_hub_pipe_reset: Pipe reset"
		    "for the root hub control pipe successful");

		break;
	case USB_EP_ATTR_INTR:
		ASSERT((eptd->bEndpointAddress & USB_EP_NUM_MASK) == 1);

		if ((ohcip->ohci_root_hub.rh_client_intr_reqp) &&
		    (ohcip->ohci_root_hub.rh_intr_pipe_state !=
		    OHCI_PIPE_STATE_IDLE)) {

			ohcip->ohci_root_hub.
			    rh_intr_pipe_state = OHCI_PIPE_STATE_RESET;

			/* Do interrupt pipe cleanup */
			ohci_root_hub_intr_pipe_cleanup(
			    ohcip, USB_CR_PIPE_RESET);
		}

		ASSERT(ohcip->ohci_root_hub.
		    rh_intr_pipe_state == OHCI_PIPE_STATE_IDLE);

		USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
		    "ohci_handle_root_hub_pipe_reset: "
		    "Pipe reset for root hub interrupt pipe successful");

		break;
	default:
		USB_DPRINTF_L2(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
		    "ohci_handle_root_hub_pipe_reset: "
		    "Root hub pipe reset failed");

		error = USB_FAILURE;
		break;
	}

	mutex_exit(&ohcip->ohci_int_mutex);

	return (error);
}


/*
 * ohci_handle_root_hub_request:
 *
 * Intercept a root hub request.  Handle the  root hub request through the
 * registers
 */
/* ARGSUSED */
int
ohci_handle_root_hub_request(
	ohci_state_t		*ohcip,
	usba_pipe_handle_data_t	*ph,
	usb_ctrl_req_t		*ctrl_reqp)
{
	uchar_t			bmRequestType = ctrl_reqp->ctrl_bmRequestType;
	uchar_t			bRequest = ctrl_reqp->ctrl_bRequest;
	uint16_t		wValue = ctrl_reqp->ctrl_wValue;
	uint16_t		wIndex = ctrl_reqp->ctrl_wIndex;
	uint16_t		wLength = ctrl_reqp->ctrl_wLength;
	mblk_t			*data = ctrl_reqp->ctrl_data;
	uint16_t		port = wIndex - 1;  /* Adjust for controller */
	usb_cr_t		completion_reason;
	int			error = USB_SUCCESS;

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
	    "ohci_handle_root_hub_request: 0x%x 0x%x 0x%x 0x%x 0x%x 0x%p",
	    bmRequestType, bRequest, wValue, wIndex, wLength, (void *)data);

	mutex_enter(&ohcip->ohci_int_mutex);

	if (ohcip->ohci_root_hub.rh_ctrl_pipe_state != OHCI_PIPE_STATE_IDLE) {

		USB_DPRINTF_L2(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
		    "ohci_handle_root_hub_request: Pipe is not idle");

		mutex_exit(&ohcip->ohci_int_mutex);

		return (USB_FAILURE);
	}

	/* Save the current control request pointer */
	ohcip->ohci_root_hub.rh_curr_ctrl_reqp = ctrl_reqp;

	/* Set pipe state to active */
	ohcip->ohci_root_hub.rh_ctrl_pipe_state = OHCI_PIPE_STATE_ACTIVE;

	mutex_exit(&ohcip->ohci_int_mutex);

	switch (bmRequestType) {
	case HUB_GET_DEVICE_STATUS_TYPE:
		ohci_handle_get_device_status(ohcip);
		break;
	case HUB_HANDLE_PORT_FEATURE_TYPE:
		error = ohci_handle_set_clear_port_feature(ohcip,
		    bRequest, wValue, port);
		break;
	case HUB_GET_PORT_STATUS_TYPE:
		ohci_handle_get_port_status(ohcip, port);
		break;
	case HUB_CLASS_REQ_TYPE:
		switch (bRequest) {
		case USB_REQ_GET_STATUS:
			ohci_handle_get_hub_status(ohcip);
			break;
		case USB_REQ_GET_DESCR:
			ohci_handle_get_hub_descriptor(ohcip);
			break;
		default:
			USB_DPRINTF_L2(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
			    "ohci_handle_root_hub_request:"
			    "Unsupported request 0x%x", bRequest);

			error = USB_FAILURE;
			break;
		}
		break;
	case HUB_HANDLE_HUB_FEATURE_TYPE:
		error = ohci_handle_set_clear_hub_feature(ohcip,
		    bRequest, wValue);
		break;
	default:
		USB_DPRINTF_L2(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
		    "ohci_handle_root_hub_request: "
		    "Unsupported request 0x%x", bmRequestType);

		error = USB_FAILURE;
		break;
	}

	completion_reason = (error) ? USB_CR_NOT_SUPPORTED : USB_CR_OK;

	mutex_enter(&ohcip->ohci_int_mutex);
	ohci_root_hub_hcdi_callback(ph, completion_reason);
	mutex_exit(&ohcip->ohci_int_mutex);

	USB_DPRINTF_L2(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
	    "ohci_handle_root_hub_request: error = %d", error);

	return (USB_SUCCESS);
}


/*
 * ohci_handle_set_clear_port_feature:
 */
static int
ohci_handle_set_clear_port_feature(
	ohci_state_t		*ohcip,
	uchar_t 		bRequest,
	uint16_t		wValue,
	uint16_t		port)
{
	int			error = USB_SUCCESS;

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
	    "ohci_handle_set_clear_port_feature: 0x%x 0x%x 0x%x",
	    bRequest, wValue, port);

	switch (bRequest) {
	case USB_REQ_SET_FEATURE:
		switch (wValue) {
		case CFS_PORT_ENABLE:
			ohci_handle_port_enable(ohcip, port, 1);
			break;
		case CFS_PORT_SUSPEND:
			ohci_handle_port_suspend(ohcip, port, 1);
			break;
		case CFS_PORT_RESET:
			ohci_handle_port_reset(ohcip, port);
			break;
		case CFS_PORT_POWER:
			ohci_handle_port_power(ohcip, port, 1);
			break;
		default:
			USB_DPRINTF_L2(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
			    "ohci_handle_set_clear_port_feature: "
			    "Unsupported request 0x%x 0x%x", bRequest, wValue);

			error = USB_FAILURE;
			break;
		}
		break;
	case USB_REQ_CLEAR_FEATURE:
		switch (wValue) {
		case CFS_PORT_ENABLE:
			ohci_handle_port_enable(ohcip, port, 0);
			break;
		case CFS_C_PORT_ENABLE:
			ohci_handle_clrchng_port_enable(ohcip, port);
			break;
		case CFS_PORT_SUSPEND:
			ohci_handle_port_suspend(ohcip, port, 0);
			break;
		case CFS_C_PORT_SUSPEND:
			ohci_handle_clrchng_port_suspend(ohcip, port);
			break;
		case CFS_C_PORT_RESET:
			ohci_handle_complete_port_reset(ohcip, port);
			break;
		case CFS_PORT_POWER:
			ohci_handle_port_power(ohcip, port, 0);
			break;
		case CFS_C_PORT_CONNECTION:
			ohci_handle_clear_port_connection(ohcip, port);
			break;
		case CFS_C_PORT_OVER_CURRENT:
			ohci_handle_clrchng_port_over_current(ohcip, port);
			break;
		default:
			USB_DPRINTF_L2(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
			    "ohci_handle_set_clear_port_feature: "
			    "Unsupported request 0x%x 0x%x", bRequest, wValue);

			error = USB_FAILURE;
			break;
		}
		break;
	default:
		USB_DPRINTF_L2(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
		    "ohci_handle_set_clear_port_feature: "
		    "Unsupported request 0x%x 0x%x", bRequest, wValue);

		error = USB_FAILURE;
		break;
	}

	return (error);
}


/*
 * ohci_handle_port_power:
 *
 * Turn on a root hub port.
 */
static void
ohci_handle_port_power(
	ohci_state_t		*ohcip,
	uint16_t		port,
	uint_t			on)
{
	usb_hub_descr_t		*hub_descr;
	uint_t			port_status;
	ohci_root_hub_t		*rh;
	uint_t			p;

	mutex_enter(&ohcip->ohci_int_mutex);

	port_status = Get_OpReg(hcr_rh_portstatus[port]);
	rh = &ohcip->ohci_root_hub;
	hub_descr = &ohcip->ohci_root_hub.rh_descr;

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
	    "ohci_handle_port_power: port = 0x%x status = 0x%x on = %d",
	    port, port_status, on);

	if (on) {
		/*
		 * If the port power is ganged, enable the power through
		 * the status registers, else enable the port power.
		 */
		if ((hub_descr->wHubCharacteristics &
		    HUB_CHARS_POWER_SWITCHING_MODE) ==
		    HUB_CHARS_GANGED_POWER) {

			Set_OpReg(hcr_rh_status, HCR_RH_STATUS_LPSC);

			for (p = 0; p < hub_descr->bNbrPorts; p++) {
				rh->rh_port_status[p] = 0;
				rh->rh_port_state[p] = DISCONNECTED;
			}
		} else {
			/* See if the port power is already on */
			if (!(port_status & HCR_PORT_PPS)) {
				/* Turn the port on */
				Set_OpReg(hcr_rh_portstatus[port],
				    HCR_PORT_PPS);
			}

			rh->rh_port_status[port] = 0;
			rh->rh_port_state[port] = DISCONNECTED;
		}
	} else {
		/*
		 * If the port power is ganged, disable the power through
		 * the status registers, else disable the port power.
		 */
		if ((hub_descr->wHubCharacteristics &
		    HUB_CHARS_POWER_SWITCHING_MODE) ==
		    HUB_CHARS_GANGED_POWER) {

			Set_OpReg(hcr_rh_status, HCR_RH_STATUS_LPS);

			for (p = 0; p < hub_descr->bNbrPorts; p++) {
				rh->rh_port_status[p] = 0;
				rh->rh_port_state[p] = POWERED_OFF;
			}
		} else {
			/* See if the port power is already OFF */
			if ((port_status & HCR_PORT_PPS)) {
				/* Turn the port OFF by writing LSSA bit  */
				Set_OpReg(hcr_rh_portstatus[port],
				    HCR_PORT_LSDA);
			}

			rh->rh_port_status[port] = 0;
			rh->rh_port_state[port] = POWERED_OFF;
		}
	}

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
	    "ohci_handle_port_power done: "
	    "port = 0x%x status = 0x%x on = %d",
	    port, Get_OpReg(hcr_rh_portstatus[port]), on);

	mutex_exit(&ohcip->ohci_int_mutex);
}


/*
 * ohci_handle_port_enable:
 *
 * Handle port enable request.
 */
static void
ohci_handle_port_enable(
	ohci_state_t		*ohcip,
	uint16_t		port,
	uint_t			on)
{
	uint_t			port_status;

	mutex_enter(&ohcip->ohci_int_mutex);

	port_status = Get_OpReg(hcr_rh_portstatus[port]);

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
	    "ohci_handle_port_enable: port = 0x%x, status = 0x%x",
	    port, port_status);

	if (on) {
		/* See if the port enable is already on */
		if (!(port_status & HCR_PORT_PES)) {
			/* Enable the port */
			Set_OpReg(hcr_rh_portstatus[port], HCR_PORT_PES);
		}
	} else {
		/* See if the port enable is already off */
		if (port_status & HCR_PORT_PES) {
			/* disable the port by writing CCS bit */
			Set_OpReg(hcr_rh_portstatus[port], HCR_PORT_CCS);
		}
	}

	mutex_exit(&ohcip->ohci_int_mutex);
}


/*
 * ohci_handle_clrchng_port_enable:
 *
 * Handle clear port enable change bit.
 */
static void
ohci_handle_clrchng_port_enable(
	ohci_state_t		*ohcip,
	uint16_t		port)
{
	uint_t			port_status;

	mutex_enter(&ohcip->ohci_int_mutex);

	port_status = Get_OpReg(hcr_rh_portstatus[port]);

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
	    "ohci_handle_port_enable: port = 0x%x, status = 0x%x",
	    port, port_status);

	/* Clear the PortEnableStatusChange Bit */
	Set_OpReg(hcr_rh_portstatus[port], HCR_PORT_PESC);

	mutex_exit(&ohcip->ohci_int_mutex);
}


/*
 * ohci_handle_port_suspend:
 *
 * Handle port suspend/resume request.
 */
static void
ohci_handle_port_suspend(
	ohci_state_t		*ohcip,
	uint16_t		port,
	uint_t			on)
{
	uint_t			port_status;

	mutex_enter(&ohcip->ohci_int_mutex);

	port_status = Get_OpReg(hcr_rh_portstatus[port]);

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
	    "ohci_handle_port_suspend: port = 0x%x, status = 0x%x",
	    port, port_status);

	if (on) {
		/* Suspend the port */
		Set_OpReg(hcr_rh_portstatus[port], HCR_PORT_PSS);
	} else {
		/* To Resume, we write the POCI bit */
		Set_OpReg(hcr_rh_portstatus[port], HCR_PORT_POCI);
	}

	mutex_exit(&ohcip->ohci_int_mutex);
}


/*
 * ohci_handle_clrchng_port_suspend:
 *
 * Handle port clear port suspend change bit.
 */
static void
ohci_handle_clrchng_port_suspend(
	ohci_state_t		*ohcip,
	uint16_t		port)
{
	uint_t			port_status;

	mutex_enter(&ohcip->ohci_int_mutex);

	port_status = Get_OpReg(hcr_rh_portstatus[port]);

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
	    "ohci_handle_clrchng_port_suspend: port = 0x%x, status = 0x%x",
	    port, port_status);

	Set_OpReg(hcr_rh_portstatus[port], HCR_PORT_PSSC);

	mutex_exit(&ohcip->ohci_int_mutex);
}


/*
 * ohci_handle_port_reset:
 *
 * Perform a port reset.
 */
static void
ohci_handle_port_reset(
	ohci_state_t		*ohcip,
	uint16_t		port)
{
	uint_t			port_status;

	mutex_enter(&ohcip->ohci_int_mutex);

	port_status = Get_OpReg(hcr_rh_portstatus[port]);

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
	    "ohci_handle_port_reset: port = 0x%x status = 0x%x",
	    port, port_status);

	if (!(port_status & HCR_PORT_CCS)) {
		USB_DPRINTF_L3(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
		    "port_status & HCR_PORT_CCS == 0: "
		    "port = 0x%x status = 0x%x", port, port_status);
	}

	Set_OpReg(hcr_rh_portstatus[port], HCR_PORT_PRS);

	mutex_exit(&ohcip->ohci_int_mutex);
}


/*
 * ohci_handle_complete_port_reset:
 *
 * Perform a port reset change.
 */
static void
ohci_handle_complete_port_reset(
	ohci_state_t		*ohcip,
	uint16_t		port)
{
	uint_t			port_status;

	mutex_enter(&ohcip->ohci_int_mutex);

	port_status = Get_OpReg(hcr_rh_portstatus[port]);

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
	    "ohci_handle_complete_port_reset: port = 0x%x status = 0x%x",
	    port, port_status);

	if (!(port_status & HCR_PORT_CCS)) {
		USB_DPRINTF_L3(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
		    "port_status & HCR_PORT_CCS == 0: "
		    "port = 0x%x status = 0x%x", port, port_status);
	}

	Set_OpReg(hcr_rh_portstatus[port], HCR_PORT_PRSC);

	mutex_exit(&ohcip->ohci_int_mutex);
}


/*
 * ohci_handle_clear_port_connection:
 *
 * Perform a clear port connection.
 */
static void
ohci_handle_clear_port_connection(
	ohci_state_t		*ohcip,
	uint16_t		port)
{
	uint_t			port_status;

	mutex_enter(&ohcip->ohci_int_mutex);

	port_status = Get_OpReg(hcr_rh_portstatus[port]);

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
	    "ohci_handle_clear_port_connection: port = 0x%x"
	    "status = 0x%x", port, port_status);

	/* Clear CSC bit */
	Set_OpReg(hcr_rh_portstatus[port], HCR_PORT_CSC);

	mutex_exit(&ohcip->ohci_int_mutex);
}


/*
 * ohci_handle_clrchng_port_over_current:
 *
 * Perform a clear over current condition.
 */
static void
ohci_handle_clrchng_port_over_current(
	ohci_state_t		*ohcip,
	uint16_t		port)
{
	uint_t			port_status;

	mutex_enter(&ohcip->ohci_int_mutex);

	port_status = Get_OpReg(hcr_rh_portstatus[port]);

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
	    "ohci_handle_clrchng_port_over_current: port = 0x%x"
	    "status = 0x%x", port, port_status);

	Set_OpReg(hcr_rh_portstatus[port], HCR_PORT_OCIC);

	mutex_exit(&ohcip->ohci_int_mutex);
}


/*
 * ohci_handle_get_port_status:
 *
 * Handle a get port status request.
 */
static void
ohci_handle_get_port_status(
	ohci_state_t		*ohcip,
	uint16_t		port)
{
	usb_ctrl_req_t		*ctrl_reqp;
	mblk_t			*message;
	uint_t			new_port_status;
	uint_t			change_status;

	mutex_enter(&ohcip->ohci_int_mutex);

	ctrl_reqp = ohcip->ohci_root_hub.rh_curr_ctrl_reqp;

	/* Read the current port status and return it */
	new_port_status = Get_OpReg(hcr_rh_portstatus[port]);
	ohcip->ohci_root_hub.rh_port_status[port] = new_port_status;

	change_status = (new_port_status & HCR_PORT_CHNG_MASK) >> 16;

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
	    "ohci_handle_get_port_status: port = %d new status = 0x%x"
	    "change = 0x%x", port, new_port_status, change_status);

	message = ctrl_reqp->ctrl_data;

	ASSERT(message != NULL);

	*message->b_wptr++ = (uchar_t)new_port_status;
	*message->b_wptr++ = (uchar_t)(new_port_status >> 8);
	*message->b_wptr++ = (uchar_t)change_status;
	*message->b_wptr++ = (uchar_t)(change_status >> 8);

	/* Save the data in control request */
	ctrl_reqp->ctrl_data = message;

	mutex_exit(&ohcip->ohci_int_mutex);
}


/*
 * ohci_handle_set_clear_hub_feature:
 *
 * OHCI only implements clearing C_HUB_OVER_CURRENT feature now.
 * Other hub requests of this bmRequestType are either not
 * supported by hardware or never used.
 */
static int
ohci_handle_set_clear_hub_feature(
	ohci_state_t		*ohcip,
	uchar_t 		bRequest,
	uint16_t		wValue)
{
	int			error = USB_SUCCESS;

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
	    "ohci_handle_set_clear_hub_feature: 0x%x 0x%x",
	    bRequest, wValue);

	switch (bRequest) {
	case USB_REQ_CLEAR_FEATURE:
		if (wValue == CFS_C_HUB_OVER_CURRENT) {
			ohci_handle_clrchng_hub_over_current(ohcip);
		} else {
			USB_DPRINTF_L2(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
			    "ohci_handle_set_clear_hub_feature: "
			    "Unsupported request 0x%x 0x%x", bRequest, wValue);

			error = USB_FAILURE;
		}
		break;

	case USB_REQ_SET_FEATURE:
	default:
		USB_DPRINTF_L2(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
		    "ohci_handle_set_clear_hub_feature: "
		    "Unsupported request 0x%x 0x%x", bRequest, wValue);

		error = USB_FAILURE;
		break;
	}

	return (error);
}


/*
 * ohci_handle_clrchng_hub_over_current:
 *
 * Clear over current indicator change bit on the root hub.
 */
static void
ohci_handle_clrchng_hub_over_current(
	ohci_state_t		*ohcip)
{
	uint_t			hub_status;

	mutex_enter(&ohcip->ohci_int_mutex);

	hub_status = Get_OpReg(hcr_rh_status);

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
	    "ohci_handle_clrchng_hub_over_current: "
	    "status = 0x%x", hub_status);

	Set_OpReg(hcr_rh_status, HCR_RH_STATUS_OCIC);

	mutex_exit(&ohcip->ohci_int_mutex);
}


/*
 * ohci_handle_get_hub_descriptor:
 */
static void
ohci_handle_get_hub_descriptor(
	ohci_state_t		*ohcip)
{
	usb_ctrl_req_t		*ctrl_reqp;
	mblk_t			*message;
	usb_hub_descr_t		*root_hub_descr;
	size_t			length;
	uchar_t			raw_descr[ROOT_HUB_DESCRIPTOR_LENGTH];

	mutex_enter(&ohcip->ohci_int_mutex);

	ctrl_reqp = ohcip->ohci_root_hub.rh_curr_ctrl_reqp;
	root_hub_descr = &ohcip->ohci_root_hub.rh_descr;
	length = ctrl_reqp->ctrl_wLength;

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
	    "ohci_handle_get_hub_descriptor: Ctrl Req  = 0x%p",
	    (void *)ctrl_reqp);

	message = ctrl_reqp->ctrl_data;

	ASSERT(message != NULL);

	bzero(&raw_descr, ROOT_HUB_DESCRIPTOR_LENGTH);

	raw_descr[0] = root_hub_descr->bDescLength;
	raw_descr[1] = root_hub_descr->bDescriptorType;
	raw_descr[2] = root_hub_descr->bNbrPorts;
	raw_descr[3] = root_hub_descr->wHubCharacteristics & 0x00FF;
	raw_descr[4] = (root_hub_descr->wHubCharacteristics & 0xFF00) >> 8;
	raw_descr[5] = root_hub_descr->bPwrOn2PwrGood;
	raw_descr[6] = root_hub_descr->bHubContrCurrent;
	raw_descr[7] = root_hub_descr->DeviceRemovable;
	raw_descr[8] = root_hub_descr->PortPwrCtrlMask;

	bcopy(raw_descr, message->b_wptr, length);
	message->b_wptr += length;

	/* Save the data in control request */
	ctrl_reqp->ctrl_data = message;

	mutex_exit(&ohcip->ohci_int_mutex);
}


/*
 * ohci_handle_get_hub_status:
 *
 * Handle a get hub status request.
 */
static void
ohci_handle_get_hub_status(
	ohci_state_t		*ohcip)
{
	usb_ctrl_req_t		*ctrl_reqp;
	mblk_t			*message;
	uint_t			new_root_hub_status;

	mutex_enter(&ohcip->ohci_int_mutex);

	ctrl_reqp = ohcip->ohci_root_hub.rh_curr_ctrl_reqp;
	new_root_hub_status = Get_OpReg(hcr_rh_status);

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
	    "ohci_handle_get_hub_status: new root hub status = 0x%x",
	    new_root_hub_status);

	message = ctrl_reqp->ctrl_data;

	ASSERT(message != NULL);

	*message->b_wptr++ = (uchar_t)new_root_hub_status;
	*message->b_wptr++ = (uchar_t)(new_root_hub_status >> 8);
	*message->b_wptr++ = (uchar_t)(new_root_hub_status >> 16);
	*message->b_wptr++ = (uchar_t)(new_root_hub_status >> 24);

	/* Save the data in control request */
	ctrl_reqp->ctrl_data = message;

	mutex_exit(&ohcip->ohci_int_mutex);
}


/*
 * ohci_handle_get_device_status:
 *
 * Handle a get device status request.
 */
static void
ohci_handle_get_device_status(
	ohci_state_t		*ohcip)
{
	usb_ctrl_req_t		*ctrl_reqp;
	mblk_t			*message;
	uint16_t		dev_status;

	mutex_enter(&ohcip->ohci_int_mutex);

	ctrl_reqp = ohcip->ohci_root_hub.rh_curr_ctrl_reqp;

	/*
	 * OHCI doesn't have device status information.
	 * Simply return what is desired for the request.
	 */
	dev_status = USB_DEV_SLF_PWRD_STATUS;

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
	    "ohci_handle_get_device_status: device status = 0x%x",
	    dev_status);

	message = ctrl_reqp->ctrl_data;

	ASSERT(message != NULL);

	*message->b_wptr++ = (uchar_t)dev_status;
	*message->b_wptr++ = (uchar_t)(dev_status >> 8);

	/* Save the data in control request */
	ctrl_reqp->ctrl_data = message;

	mutex_exit(&ohcip->ohci_int_mutex);
}


/*
 * ohci_handle_root_hub_pipe_start_intr_polling:
 *
 * Handle start polling on root hub interrupt pipe.
 */
/* ARGSUSED */
int
ohci_handle_root_hub_pipe_start_intr_polling(
	usba_pipe_handle_data_t	*ph,
	usb_intr_req_t		*client_intr_reqp,
	usb_flags_t		flags)
{
	ohci_state_t		*ohcip = ohci_obtain_state(
	    ph->p_usba_device->usb_root_hub_dip);
	usb_ep_descr_t		*eptd = &ph->p_ep;
	int			error = USB_SUCCESS;
	uint_t			pipe_state;

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
	    "ohci_handle_root_hub_pipe_start_intr_polling: "
	    "Root hub pipe start polling");

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	ASSERT((eptd->bEndpointAddress & USB_EP_NUM_MASK) == 1);

	/* ONE_XFER not supported for root hub interrupt pipe */
	ASSERT((client_intr_reqp->intr_attributes & USB_ATTRS_ONE_XFER) == 0);

	/* Get root hub intr pipe state */
	pipe_state = ohcip->ohci_root_hub.rh_intr_pipe_state;

	switch (pipe_state) {
	case OHCI_PIPE_STATE_IDLE:
		ASSERT(ohcip->ohci_root_hub.rh_intr_pipe_timer_id == 0);

		/*
		 * Save the Original Client's Interrupt IN request
		 * information. We use this for final callback
		 */
		ASSERT(ohcip->ohci_root_hub.rh_client_intr_reqp == NULL);

		ohcip->ohci_root_hub.rh_client_intr_reqp = client_intr_reqp;

		error = ohci_root_hub_allocate_intr_pipe_resource(ohcip, flags);

		if (error != USB_SUCCESS) {
			/* Reset client interrupt request pointer */
			ohcip->ohci_root_hub.rh_client_intr_reqp = NULL;

			USB_DPRINTF_L2(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
			    "ohci_handle_root_hub_pipe_start_intr_polling: "
			    "No Resources");

			return (error);
		}

		USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
		    "ohci_handle_root_hub_pipe_start_intr_polling: "
		    "Start polling for root hub successful");

		break;
	case OHCI_PIPE_STATE_ACTIVE:
		USB_DPRINTF_L2(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
		    "ohci_handle_root_hub_pipe_start_intr_polling: "
		    "Polling for root hub is already in progress");

		break;
	default:
		USB_DPRINTF_L2(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
		    "ohci_handle_root_hub_pipe_start_intr_polling: "
		    "Pipe is in error state 0x%x", pipe_state);

		error = USB_FAILURE;

		break;
	}

	return (error);
}


/*
 * ohci_handle_root_hub_pipe_stop_intr_polling:
 *
 * Handle stop polling on root hub intr pipe.
 */
/* ARGSUSED */
void
ohci_handle_root_hub_pipe_stop_intr_polling(
	usba_pipe_handle_data_t	*ph,
	usb_flags_t		flags)
{
	ohci_state_t		*ohcip = ohci_obtain_state(
	    ph->p_usba_device->usb_root_hub_dip);
	usb_ep_descr_t		*eptd = &ph->p_ep;

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
	    "ohci_handle_root_hub_pipe_stop_intr_polling: "
	    "Root hub pipe stop polling");

	ASSERT((eptd->bEndpointAddress & USB_EP_NUM_MASK) == 1);

	if (ohcip->ohci_root_hub.rh_intr_pipe_state == OHCI_PIPE_STATE_ACTIVE) {

		ohcip->ohci_root_hub.rh_intr_pipe_state =
		    OHCI_PIPE_STATE_STOP_POLLING;

		/* Do interrupt pipe cleanup */
		ohci_root_hub_intr_pipe_cleanup(ohcip, USB_CR_STOPPED_POLLING);

		ASSERT(ohcip->ohci_root_hub.
		    rh_intr_pipe_state == OHCI_PIPE_STATE_IDLE);

		USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
		    "ohci_hcdi_pipe_stop_intr_polling: Stop polling for root"
		    "hub successful");
	} else {
		USB_DPRINTF_L2(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
		    "ohci_hcdi_pipe_stop_intr_polling: "
		    "Polling for root hub is already stopped");
	}
}


/*
 * ohci_root_hub_allocate_intr_pipe_resource:
 *
 * Allocate interrupt requests and initialize them.
 */
static int
ohci_root_hub_allocate_intr_pipe_resource(
	ohci_state_t		*ohcip,
	usb_flags_t		flags)
{
	usba_pipe_handle_data_t	*ph;
	size_t			length;
	usb_intr_req_t		*curr_intr_reqp;

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
	    "ohci_root_hub_allocate_intr_pipe_resource");

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	/* Get the interrupt pipe handle */
	ph = ohcip->ohci_root_hub.rh_intr_pipe_handle;

	/* Get the current interrupt request pointer */
	curr_intr_reqp = ohcip->ohci_root_hub.rh_curr_intr_reqp;

	/*
	 * If current interrupt request pointer is null,
	 * allocate new interrupt request.
	 */
	if (curr_intr_reqp == NULL) {
		ASSERT(ohcip->ohci_root_hub.rh_client_intr_reqp);

		/* Get the length of interrupt transfer */
		length = ohcip->ohci_root_hub.
		    rh_client_intr_reqp->intr_len;

		curr_intr_reqp = usba_hcdi_dup_intr_req(ph->p_dip,
		    ohcip->ohci_root_hub.rh_client_intr_reqp,
		    length, flags);

		if (curr_intr_reqp == NULL) {

			USB_DPRINTF_L2(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
			    "ohci_root_hub_allocate_intr_pipe_resource:"
			    "Interrupt request structure allocation failed");

			return (USB_NO_RESOURCES);
		}

		ohcip->ohci_root_hub.rh_curr_intr_reqp = curr_intr_reqp;

		mutex_enter(&ph->p_mutex);
		ph->p_req_count++;
		mutex_exit(&ph->p_mutex);
	}

	/* Start the timer for the root hub interrupt pipe polling */
	if (ohcip->ohci_root_hub.rh_intr_pipe_timer_id == 0) {
		ohcip->ohci_root_hub.rh_intr_pipe_timer_id =
		    timeout(ohci_handle_root_hub_status_change,
		    (void *)ohcip, drv_usectohz(OHCI_RH_POLL_TIME));

		ohcip->ohci_root_hub.
		    rh_intr_pipe_state = OHCI_PIPE_STATE_ACTIVE;
	}

	return (USB_SUCCESS);
}


/*
 * ohci_root_hub_intr_pipe_cleanup:
 *
 * Deallocate all interrupt requests and do callback
 * the original client interrupt request.
 */
static void
ohci_root_hub_intr_pipe_cleanup(
	ohci_state_t		*ohcip,
	usb_cr_t		completion_reason)
{
	usb_intr_req_t		*curr_intr_reqp;
	usb_opaque_t		client_intr_reqp;
	timeout_id_t		timer_id;
	usba_pipe_handle_data_t	*ph;

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
	    "ohci_root_hub_intr_pipe_cleanup");

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	/* Get the interrupt pipe handle */
	ph = ohcip->ohci_root_hub.rh_intr_pipe_handle;

	/* Get the interrupt timerid */
	timer_id = ohcip->ohci_root_hub.rh_intr_pipe_timer_id;

	/* Stop the root hub interrupt timer */
	if (timer_id) {
		/* Reset the timer id to zero */
		ohcip->ohci_root_hub.rh_intr_pipe_timer_id = 0;

		mutex_exit(&ohcip->ohci_int_mutex);
		(void) untimeout(timer_id);
		mutex_enter(&ohcip->ohci_int_mutex);
	}

	/* Reset the current interrupt request pointer */
	curr_intr_reqp = ohcip->ohci_root_hub.rh_curr_intr_reqp;

	/* Deallocate uncompleted interrupt request */
	if (curr_intr_reqp) {
		ohcip->ohci_root_hub.rh_curr_intr_reqp = NULL;
		usb_free_intr_req(curr_intr_reqp);

		mutex_enter(&ph->p_mutex);
		ph->p_req_count--;
		mutex_exit(&ph->p_mutex);
	}

	client_intr_reqp = (usb_opaque_t)
	    ohcip->ohci_root_hub.rh_client_intr_reqp;

	/* Callback for original client interrupt request */
	if (client_intr_reqp) {
		ohci_root_hub_hcdi_callback(ph, completion_reason);
	}
}


/*
 * ohci_handle_root_hub_status_change:
 *
 * A root hub status change interrupt will occur any time there is a change
 * in the root hub status register or one of the port status registers.
 */
void
ohci_handle_root_hub_status_change(void *arg)
{
	ohci_state_t		*ohcip = (ohci_state_t *)arg;
	usb_intr_req_t		*curr_intr_reqp;
	usb_port_mask_t		all_ports_status = 0;
	uint_t			new_root_hub_status;
	uint_t			new_port_status;
	uint_t			change_status;
	usb_hub_descr_t		*hub_descr;
	mblk_t			*message;
	size_t			length;
	usb_ep_descr_t		*eptd;
	usba_pipe_handle_data_t	*ph;
	int			i;

	mutex_enter(&ohcip->ohci_int_mutex);

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
	    "ohci_handle_root_hub_status_change: state = %d",
	    ohcip->ohci_root_hub.rh_intr_pipe_state);

	/* Get the pointer to root hub descriptor */
	hub_descr = &ohcip->ohci_root_hub.rh_descr;

	/* Get the current interrupt request pointer */
	curr_intr_reqp = ohcip->ohci_root_hub.rh_curr_intr_reqp;

	ph = ohcip->ohci_root_hub.rh_intr_pipe_handle;

	/* Check whether timeout handler is valid */
	if (ohcip->ohci_root_hub.rh_intr_pipe_timer_id) {
		/* Check host controller is in operational state */
		if ((ohci_state_is_operational(ohcip)) != USB_SUCCESS) {

			/* Reset the timer id */
			ohcip->ohci_root_hub.rh_intr_pipe_timer_id = 0;

			/* Do interrupt pipe cleanup */
			ohci_root_hub_intr_pipe_cleanup(
			    ohcip, USB_CR_HC_HARDWARE_ERR);

			mutex_exit(&ohcip->ohci_int_mutex);

			return;
		}
	} else {
		mutex_exit(&ohcip->ohci_int_mutex);

		return;
	}

	eptd = &ohcip->ohci_root_hub.rh_intr_pipe_handle->p_ep;

	new_root_hub_status = Get_OpReg(hcr_rh_status);

	/* See if the root hub status has changed */
	if (new_root_hub_status & HCR_RH_CHNG_MASK) {

		USB_DPRINTF_L3(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
		    "ohci_handle_root_hub_status_change: "
		    "Root hub status has changed!");

		all_ports_status = 1;

		/* Update root hub status */
		ohcip->ohci_root_hub.rh_status = new_root_hub_status;
	}

	/* Check each port */
	for (i = 0; i < hub_descr->bNbrPorts; i++) {
		new_port_status = Get_OpReg(hcr_rh_portstatus[i]);
		change_status = new_port_status & HCR_PORT_CHNG_MASK;

		/*
		 * If there is change in the port status then set
		 * the bit in the bitmap of changes and inform hub
		 * driver about these changes. Hub driver will take
		 * care of these changes.
		 */
		if (change_status) {

			/* See if a device was attached/detached */
			if (change_status & HCR_PORT_CSC) {
				/*
				 * Update the state depending on whether
				 * the port was attached or detached.
				 */
				if (new_port_status & HCR_PORT_CCS) {
					ohcip->ohci_root_hub.
					    rh_port_state[i] = DISABLED;

					USB_DPRINTF_L3(PRINT_MASK_ROOT_HUB,
					    ohcip->ohci_log_hdl,
					    "Port %d connected", i+1);
				} else {
					ohcip->ohci_root_hub.
					    rh_port_state[i] = DISCONNECTED;

					USB_DPRINTF_L3(PRINT_MASK_ROOT_HUB,
					    ohcip->ohci_log_hdl,
					    "Port %d disconnected", i+1);
				}
			}

			/* See if port enable status changed */
			if (change_status & HCR_PORT_PESC) {
				/*
				 * Update the state depending on whether
				 * the port was enabled or disabled.
				 */
				if (new_port_status & HCR_PORT_PES) {
					ohcip->ohci_root_hub.
					    rh_port_state[i] = ENABLED;

					USB_DPRINTF_L3(PRINT_MASK_ROOT_HUB,
					    ohcip->ohci_log_hdl,
					    "Port %d enabled", i+1);
				} else {
					ohcip->ohci_root_hub.
					    rh_port_state[i] = DISABLED;

					USB_DPRINTF_L3(PRINT_MASK_ROOT_HUB,
					    ohcip->ohci_log_hdl,
					    "Port %d disabled", i+1);
				}
			}

			all_ports_status |= 1 << (i + 1);

			/* Update the status */
			ohcip->ohci_root_hub.
			    rh_port_status[i] = new_port_status;
		}
	}

	if (ph && all_ports_status && curr_intr_reqp) {

		length = eptd->wMaxPacketSize;

		ASSERT(length != 0);

		/* Get the  message block */
		message = curr_intr_reqp->intr_data;

		ASSERT(message != NULL);

		do {
			/*
			 * check that mblk is big enough when we
			 * are writing bytes into it
			 */
			if (message->b_wptr >= message->b_datap->db_lim) {

				USB_DPRINTF_L2(PRINT_MASK_ROOT_HUB,
				    ohcip->ohci_log_hdl,
				    "ohci_handle_root_hub_status_change: "
				    "mblk data overflow.");

				break;
			}

			*message->b_wptr++ = (uchar_t)all_ports_status;
			all_ports_status >>= 8;
		} while (all_ports_status != 0);

		ohci_root_hub_hcdi_callback(ph, USB_CR_OK);
	}

	/* Reset the timer id */
	ohcip->ohci_root_hub.rh_intr_pipe_timer_id = 0;

	if (ohcip->ohci_root_hub.rh_intr_pipe_state == OHCI_PIPE_STATE_ACTIVE) {
		/*
		 * If needed, allocate new interrupt request. Also
		 * start the timer for the root hub interrupt polling.
		 */
		if ((ohci_root_hub_allocate_intr_pipe_resource(
		    ohcip, 0)) != USB_SUCCESS) {

			USB_DPRINTF_L2(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
			    "ohci_handle_root_hub_status_change: No Resources");

			/* Do interrupt pipe cleanup */
			ohci_root_hub_intr_pipe_cleanup(
			    ohcip, USB_CR_NO_RESOURCES);
		}
	}

	mutex_exit(&ohcip->ohci_int_mutex);
}


/*
 * ohci_root_hub_hcdi_callback()
 *
 * Convenience wrapper around usba_hcdi_cb() for the root hub.
 */
static void
ohci_root_hub_hcdi_callback(
	usba_pipe_handle_data_t	*ph,
	usb_cr_t		completion_reason)
{
	ohci_state_t		*ohcip = ohci_obtain_state(
	    ph->p_usba_device->usb_root_hub_dip);
	uchar_t			attributes = ph->p_ep.bmAttributes &
	    USB_EP_ATTR_MASK;
	usb_opaque_t		curr_xfer_reqp;
	uint_t			pipe_state = 0;

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ohcip->ohci_log_hdl,
	    "ohci_root_hub_hcdi_callback: ph = 0x%p, cr = 0x%x",
	    (void *)ph, completion_reason);

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	/* Set the pipe state as per completion reason */
	switch (completion_reason) {
	case USB_CR_OK:
		switch (attributes) {
		case USB_EP_ATTR_CONTROL:
			pipe_state = OHCI_PIPE_STATE_IDLE;
			break;
		case USB_EP_ATTR_INTR:
			pipe_state = ohcip->ohci_root_hub.rh_intr_pipe_state;
			break;
		}
		break;
	case USB_CR_NO_RESOURCES:
	case USB_CR_NOT_SUPPORTED:
	case USB_CR_STOPPED_POLLING:
	case USB_CR_PIPE_RESET:
	case USB_CR_HC_HARDWARE_ERR:
		/* Set pipe state to idle */
		pipe_state = OHCI_PIPE_STATE_IDLE;
		break;
	case USB_CR_PIPE_CLOSING:
		break;
	default:
		/* Set pipe state to error */
		pipe_state = OHCI_PIPE_STATE_ERROR;
		break;
	}

	switch (attributes) {
	case USB_EP_ATTR_CONTROL:
		curr_xfer_reqp = (usb_opaque_t)
		    ohcip->ohci_root_hub.rh_curr_ctrl_reqp;

		ohcip->ohci_root_hub.rh_curr_ctrl_reqp = NULL;
		ohcip->ohci_root_hub.rh_ctrl_pipe_state = pipe_state;
		break;
	case USB_EP_ATTR_INTR:
		/* if curr_intr_reqp available then use this request */
		if (ohcip->ohci_root_hub.rh_curr_intr_reqp) {
			curr_xfer_reqp = (usb_opaque_t)
			    ohcip->ohci_root_hub.rh_curr_intr_reqp;

			ohcip->ohci_root_hub.rh_curr_intr_reqp = NULL;
		} else {
			/* no current request, use client's request */
			curr_xfer_reqp = (usb_opaque_t)
			    ohcip->ohci_root_hub.rh_client_intr_reqp;

			ohcip->ohci_root_hub.rh_client_intr_reqp = NULL;
		}

		ohcip->ohci_root_hub.rh_intr_pipe_state = pipe_state;
		break;
	}

	ASSERT(curr_xfer_reqp != NULL);

	mutex_exit(&ohcip->ohci_int_mutex);
	usba_hcdi_cb(ph, curr_xfer_reqp, completion_reason);
	mutex_enter(&ohcip->ohci_int_mutex);
}
