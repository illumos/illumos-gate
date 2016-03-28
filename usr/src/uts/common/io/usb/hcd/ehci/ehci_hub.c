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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * EHCI Host Controller Driver (EHCI)
 *
 * The EHCI driver is a software driver which interfaces to the Universal
 * Serial Bus layer (USBA) and the Host Controller (HC). The interface to
 * the Host Controller is defined by the EHCI Host Controller Interface.
 *
 * This module contains the code for root hub related functions.
 *
 * NOTE:
 *
 * ONE_XFER is not supported on root hub interrupt polling
 */

#include <sys/usb/hcd/ehci/ehcid.h>
#include <sys/usb/hcd/ehci/ehci_util.h>
#include <sys/usb/usba/usba_types.h>

/* Static function prototypes */
static int	ehci_handle_set_clear_port_feature(
				ehci_state_t		*ehcip,
				uchar_t 		bRequest,
				uint16_t		wValue,
				uint16_t		port);
static void	ehci_handle_port_power(
				ehci_state_t		*ehcip,
				uint16_t		port,
				uint_t			on);
static void	ehci_handle_port_enable(
				ehci_state_t		*ehcip,
				uint16_t		port,
				uint_t			on);
static void	ehci_handle_clrchng_port_enable(
				ehci_state_t		*ehcip,
				uint16_t		port);
static void	ehci_handle_port_suspend(
				ehci_state_t		*ehcip,
				uint16_t		port,
				uint_t			on);
static void	ehci_handle_clrchng_port_suspend(
				ehci_state_t		*ehcip,
				uint16_t		port);
static void	ehci_handle_port_reset(
				ehci_state_t		*ehcip,
				uint16_t		port);
static void	ehci_root_hub_reset_occured(
				ehci_state_t		*ehcip);
static void	ehci_handle_complete_port_reset(
				ehci_state_t		*ehcip,
				uint16_t		port);
static void	ehci_handle_clear_port_connection(
				ehci_state_t		*ehcip,
				uint16_t		port);
static void	ehci_handle_clrchng_port_over_current(
				ehci_state_t		*ehcip,
				uint16_t		port);
static void	ehci_handle_get_port_status(
				ehci_state_t		*ehcip,
				uint16_t		port);
static void	ehci_handle_get_hub_descriptor(
				ehci_state_t		*ehcip);
static void	ehci_handle_get_hub_status(
				ehci_state_t		*ehcip);
static void	ehci_handle_get_device_status(
				ehci_state_t		*ehcip);
static uint_t	ehci_get_root_hub_port_status(
				ehci_state_t		*ehcip,
				uint16_t		port);
static int	ehci_is_port_owner(
				ehci_state_t		*ehcip,
				uint16_t		port);
static int	ehci_root_hub_allocate_intr_pipe_resource(
				ehci_state_t		*ehcip,
				usb_flags_t		flags);
static void	ehci_root_hub_intr_pipe_cleanup(
				ehci_state_t		*ehcip,
				usb_cr_t		completion_reason);
static void	ehci_handle_root_hub_status_change(void *arg);
static void	ehci_root_hub_hcdi_callback(
				usba_pipe_handle_data_t	*ph,
				usb_cr_t		completion_reason);


/*
 * ehci_init_root_hub:
 *
 * Initialize the root hub
 */
int
ehci_init_root_hub(ehci_state_t	*ehcip)
{
	usb_hub_descr_t		*root_hub_descr =
	    &ehcip->ehci_root_hub.rh_descr;
	uint_t			i, length, port_state;
	uint32_t		capability;

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
	    "ehci_init_root_hub:");

	/* Read the EHCI capability register */
	capability = Get_Cap(ehci_hcs_params);

	/*
	 * Build the Root hub descriptor by looking EHCI capability
	 * and operational registers.
	 */
	root_hub_descr->bDescriptorType = ROOT_HUB_DESCRIPTOR_TYPE;

	if ((capability & EHCI_HCS_NUM_PORTS) > EHCI_MAX_RH_PORTS) {

		USB_DPRINTF_L2(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
		    "ehci_init_root_hub: Invalid no of root hub ports 0x%x",
		    capability & EHCI_HCS_NUM_PORTS);

		return (USB_FAILURE);
	}

	/* Obtain the number of downstream ports */
	root_hub_descr->bNbrPorts = capability & EHCI_HCS_NUM_PORTS;

	length = root_hub_descr->bNbrPorts / 8;

	if (length) {
		root_hub_descr->bDescLength = 7 + (2 * (length + 1));
	} else {
		root_hub_descr->bDescLength = ROOT_HUB_DESCRIPTOR_LENGTH;
	}

	/*
	 * Obtain the number of Classic or Companion USB 1.1 (OHCI/UHCI)
	 * Host Controllers information.
	 */
	ehcip->ehci_root_hub.rh_companion_controllers = (capability &
	    EHCI_HCS_NUM_COMP_CTRLS) >> EHCI_HCS_NUM_COMP_CTRL_SHIFT;

	/*
	 * Determine the Power Switching Mode
	 *
	 * EHCI Specification, root hub supports either no power switching
	 * individual port power switching. Also determine the Over-current
	 * Protection Mode.
	 */
	if (capability & EHCI_HCS_PORT_POWER_CONTROL) {
		/* Each port is powered individually */
		root_hub_descr-> wHubCharacteristics =
		    HUB_CHARS_INDIVIDUAL_PORT_POWER;

		/* Assume individual overcurrent reporting */
		root_hub_descr->wHubCharacteristics |=
		    HUB_CHARS_INDIV_OVER_CURRENT;

		/* Each port will start off in the POWERED_OFF mode */
		port_state = POWERED_OFF;
	} else {
		/* The ports are powered when the ctlr is powered */
		root_hub_descr->
		    wHubCharacteristics = HUB_CHARS_NO_POWER_SWITCHING;

		/* Assume no overcurrent reporting */
		root_hub_descr->wHubCharacteristics |=
		    HUB_CHARS_NO_OVER_CURRENT;

		port_state = DISCONNECTED;
	}

	/* Look at the port indicator information */
	if (capability & EHCI_HCS_PORT_INDICATOR) {
		root_hub_descr->wHubCharacteristics |= HUB_CHARS_PORT_INDICATOR;
	}

	/*
	 * Obtain the power on to power good time of the ports.
	 *
	 * Assume: Zero for this field.
	 */
	root_hub_descr->bPwrOn2PwrGood = 2;

	USB_DPRINTF_L3(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
	    "Power on to power good %d", root_hub_descr->bPwrOn2PwrGood);

	/* Indicate if the device is removable */
	root_hub_descr->DeviceRemovable = 0;

	/* Set PortPowerControlMask to zero */
	root_hub_descr->PortPwrCtrlMask = 0;

	/* Set the state of each port and initialize the status */
	for (i = 0; i < root_hub_descr->bNbrPorts; i++) {

		/* Initilize state/status of each root hub port */
		ehcip->ehci_root_hub.rh_port_state[i] = port_state;
		ehcip->ehci_root_hub.rh_port_status[i] = 0;
	}

	return (USB_SUCCESS);
}


/*
 * ehci_load_root_hub_driver:
 *
 * Attach the root hub
 */
static usb_dev_descr_t ehci_root_hub_device_descriptor = {
	0x12,		/* bLength */
	0x01,		/* bDescriptorType, Device */
	0x200,		/* bcdUSB, v2.0 */
	0x09,		/* bDeviceClass */
	0x00,		/* bDeviceSubClass */
	0x01,		/* bDeviceProtocol */
	0x40,		/* bMaxPacketSize0 */
	0x00,		/* idVendor */
	0x00,		/* idProduct */
	0x00,		/* bcdDevice */
	0x00,		/* iManufacturer */
	0x00,		/* iProduct */
	0x00,		/* iSerialNumber */
	0x01		/* bNumConfigurations */
};

static uchar_t ehci_root_hub_config_descriptor[] = {
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
	0x01, 0x00,	/* wMaxPacketSize, 1 +	(EHCI_MAX_RH_PORTS / 8) */
	0xff		/* bInterval */
};

int
ehci_load_root_hub_driver(ehci_state_t	*ehcip)
{
	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
	    "ehci_load_root_hub_driver:");

	return (usba_hubdi_bind_root_hub(ehcip->ehci_dip,
	    ehci_root_hub_config_descriptor,
	    sizeof (ehci_root_hub_config_descriptor),
	    &ehci_root_hub_device_descriptor));
}


/*
 * ehci_unload_root_hub_driver:
 */
int
ehci_unload_root_hub_driver(ehci_state_t	*ehcip)
{
	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
	    "ehci_unload_root_hub_driver:");

	return (usba_hubdi_unbind_root_hub(ehcip->ehci_dip));
}


/*
 * ehci_handle_root_hub_pipe_open:
 *
 * Handle opening of control and interrupt pipes on root hub.
 */
/* ARGSUSED */
int
ehci_handle_root_hub_pipe_open(
	usba_pipe_handle_data_t	*ph,
	usb_flags_t		usb_flags)
{
	ehci_state_t		*ehcip = ehci_obtain_state(
	    ph->p_usba_device->usb_root_hub_dip);
	usb_ep_descr_t		*eptd = &ph->p_ep;

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
	    "ehci_handle_root_hub_pipe_open: Root hub pipe open");

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	switch (eptd->bmAttributes & USB_EP_ATTR_MASK) {
	case USB_EP_ATTR_CONTROL:
		/* Save control pipe handle */
		ehcip->ehci_root_hub.rh_ctrl_pipe_handle = ph;

		/* Set state of the root hub control pipe as idle */
		ehcip->ehci_root_hub.rh_ctrl_pipe_state = EHCI_PIPE_STATE_IDLE;

		ehcip->ehci_root_hub.rh_curr_ctrl_reqp = NULL;

		USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
		    "ehci_handle_root_hub_pipe_open: Root hub control "
		    "pipe open succeeded");

		break;
	case USB_EP_ATTR_INTR:
		/* Save interrupt pipe handle */
		ehcip->ehci_root_hub.rh_intr_pipe_handle = ph;

		/* Set state of the root hub interrupt pipe as idle */
		ehcip->ehci_root_hub.rh_intr_pipe_state = EHCI_PIPE_STATE_IDLE;

		ehcip->ehci_root_hub.rh_client_intr_reqp = NULL;

		ehcip->ehci_root_hub.rh_curr_intr_reqp = NULL;

		USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
		    "ehci_handle_root_hub_pipe_open: Root hub interrupt "
		    "pipe open succeeded");

		break;
	default:
		USB_DPRINTF_L2(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
		    "ehci_handle_root_hub_pipe_open: Root hub pipe open"
		    "failed");

		return (USB_FAILURE);
	}

	ehcip->ehci_open_pipe_count++;

	return (USB_SUCCESS);
}


/*
 * ehci_handle_root_hub_pipe_close:
 *
 * Handle closing of control and interrupt pipes on root hub.
 */
/* ARGSUSED */
int
ehci_handle_root_hub_pipe_close(usba_pipe_handle_data_t	*ph)
{
	ehci_state_t		*ehcip = ehci_obtain_state(
	    ph->p_usba_device->usb_root_hub_dip);
	usb_ep_descr_t		*eptd = &ph->p_ep;

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
	    "ehci_handle_root_hub_pipe_close: Root hub pipe close");

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	switch (eptd->bmAttributes & USB_EP_ATTR_MASK) {
	case USB_EP_ATTR_CONTROL:
		ASSERT(ehcip->ehci_root_hub.
		    rh_ctrl_pipe_state != EHCI_PIPE_STATE_CLOSE);

		/* Set state of the root hub control pipe as close */
		ehcip->ehci_root_hub.rh_ctrl_pipe_state = EHCI_PIPE_STATE_CLOSE;

		/* Set root hub control pipe handle to null */
		ehcip->ehci_root_hub.rh_ctrl_pipe_handle = NULL;

		USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
		    "ehci_handle_root_hub_pipe_close: "
		    "Root hub control pipe close succeeded");
		break;
	case USB_EP_ATTR_INTR:
		ASSERT((eptd->bEndpointAddress & USB_EP_NUM_MASK) == 1);

		ASSERT(ehcip->ehci_root_hub.
		    rh_intr_pipe_state != EHCI_PIPE_STATE_CLOSE);

		/* Set state of the root hub interrupt pipe as close */
		ehcip->ehci_root_hub.rh_intr_pipe_state = EHCI_PIPE_STATE_CLOSE;

		/* Do interrupt pipe cleanup */
		ehci_root_hub_intr_pipe_cleanup(ehcip, USB_CR_PIPE_CLOSING);

		/* Set root hub interrupt pipe handle to null */
		ehcip->ehci_root_hub.rh_intr_pipe_handle = NULL;

		USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
		    "ehci_handle_root_hub_pipe_close: "
		    "Root hub interrupt pipe close succeeded");

		break;
	default:
		USB_DPRINTF_L2(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
		    "ehci_handle_root_hub_pipe_close: "
		    "Root hub pipe close failed");

		return (USB_FAILURE);
	}

	ehcip->ehci_open_pipe_count--;

	return (USB_SUCCESS);
}


/*
 * ehci_handle_root_hub_pipe_reset:
 *
 * Handle resetting of control and interrupt pipes on root hub.
 */
/* ARGSUSED */
int
ehci_handle_root_hub_pipe_reset(
	usba_pipe_handle_data_t	*ph,
	usb_flags_t		usb_flags)
{
	ehci_state_t		*ehcip = ehci_obtain_state(
	    ph->p_usba_device->usb_root_hub_dip);
	usb_ep_descr_t		*eptd = &ph->p_ep;
	int			error = USB_SUCCESS;

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
	    "ehci_handle_root_hub_pipe_reset: Root hub pipe reset");

	mutex_enter(&ehcip->ehci_int_mutex);

	switch (eptd->bmAttributes & USB_EP_ATTR_MASK) {
	case USB_EP_ATTR_CONTROL:
		ehcip->ehci_root_hub.rh_ctrl_pipe_state = EHCI_PIPE_STATE_IDLE;

		USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
		    "ehci_handle_root_hub_pipe_reset: Pipe reset"
		    "for the root hub control pipe successful");

		break;
	case USB_EP_ATTR_INTR:
		ASSERT((eptd->bEndpointAddress & USB_EP_NUM_MASK) == 1);

		if ((ehcip->ehci_root_hub.rh_client_intr_reqp) &&
		    (ehcip->ehci_root_hub.rh_intr_pipe_state !=
		    EHCI_PIPE_STATE_IDLE)) {

			ehcip->ehci_root_hub.
			    rh_intr_pipe_state = EHCI_PIPE_STATE_RESET;

			/* Do interrupt pipe cleanup */
			ehci_root_hub_intr_pipe_cleanup(
			    ehcip, USB_CR_PIPE_RESET);
		}

		ASSERT(ehcip->ehci_root_hub.
		    rh_intr_pipe_state == EHCI_PIPE_STATE_IDLE);

		USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
		    "ehci_handle_root_hub_pipe_reset: "
		    "Pipe reset for root hub interrupt pipe successful");

		break;
	default:
		USB_DPRINTF_L2(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
		    "ehci_handle_root_hub_pipe_reset: "
		    "Root hub pipe reset failed");

		error = USB_FAILURE;
		break;
	}

	mutex_exit(&ehcip->ehci_int_mutex);

	return (error);
}


/*
 * ehci_handle_root_hub_request:
 *
 * Intercept a root hub request. Handle the  root hub request through the
 * registers
 */
/* ARGSUSED */
int
ehci_handle_root_hub_request(
	ehci_state_t		*ehcip,
	usba_pipe_handle_data_t	*ph,
	usb_ctrl_req_t		*ctrl_reqp)
{
	uchar_t			bmRequestType = ctrl_reqp->ctrl_bmRequestType;
	uchar_t			bRequest = ctrl_reqp->ctrl_bRequest;
	uint16_t		wValue = ctrl_reqp->ctrl_wValue;
	uint16_t		wIndex = ctrl_reqp->ctrl_wIndex;
	uint16_t		wLength = ctrl_reqp->ctrl_wLength;
	mblk_t			*data = ctrl_reqp->ctrl_data;
	uint16_t		port = wIndex - 1;
	usb_cr_t		completion_reason;
	int			error = USB_SUCCESS;

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
	    "ehci_handle_root_hub_request: 0x%x 0x%x 0x%x 0x%x 0x%x 0x%p",
	    bmRequestType, bRequest, wValue, wIndex, wLength, (void *)data);

	mutex_enter(&ehcip->ehci_int_mutex);

	if (ehcip->ehci_root_hub.
	    rh_ctrl_pipe_state != EHCI_PIPE_STATE_IDLE) {

		USB_DPRINTF_L2(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
		    "ehci_handle_root_hub_request: Pipe is not idle");

		mutex_exit(&ehcip->ehci_int_mutex);

		return (USB_FAILURE);
	}

	/* Save the current control request pointer */
	ehcip->ehci_root_hub.rh_curr_ctrl_reqp = ctrl_reqp;

	/* Set pipe state to active */
	ehcip->ehci_root_hub.rh_ctrl_pipe_state = EHCI_PIPE_STATE_ACTIVE;

	mutex_exit(&ehcip->ehci_int_mutex);

	switch (bmRequestType) {
	case HUB_GET_DEVICE_STATUS_TYPE:
		ehci_handle_get_device_status(ehcip);
		break;
	case HUB_HANDLE_PORT_FEATURE_TYPE:
		error = ehci_handle_set_clear_port_feature(ehcip,
		    bRequest, wValue, port);
		break;
	case HUB_GET_PORT_STATUS_TYPE:
		ehci_handle_get_port_status(ehcip, port);
		break;
	case HUB_CLASS_REQ_TYPE:
		switch (bRequest) {
		case USB_REQ_GET_STATUS:
			ehci_handle_get_hub_status(ehcip);
			break;
		case USB_REQ_GET_DESCR:
			ehci_handle_get_hub_descriptor(ehcip);
			break;
		default:
			USB_DPRINTF_L2(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
			    "ehci_handle_root_hub_request:"
			    "Unsupported request 0x%x", bRequest);

			error = USB_FAILURE;
			break;
		}
		break;
	default:
		USB_DPRINTF_L2(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
		    "ehci_handle_root_hub_request: "
		    "Unsupported request 0x%x", bmRequestType);

		error = USB_FAILURE;
		break;
	}

	completion_reason = (error) ? USB_CR_NOT_SUPPORTED : USB_CR_OK;

	mutex_enter(&ehcip->ehci_int_mutex);
	ehci_root_hub_hcdi_callback(ph, completion_reason);
	mutex_exit(&ehcip->ehci_int_mutex);

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
	    "ehci_handle_root_hub_request: error = %d", error);

	return (USB_SUCCESS);
}


/*
 * ehci_handle_set_clear_port_feature:
 */
static int
ehci_handle_set_clear_port_feature(
	ehci_state_t		*ehcip,
	uchar_t 		bRequest,
	uint16_t		wValue,
	uint16_t		port)
{
	int			error = USB_SUCCESS;

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
	    "ehci_handle_set_clear_port_feature: 0x%x 0x%x 0x%x",
	    bRequest, wValue, port);

	switch (bRequest) {
	case USB_REQ_SET_FEATURE:
		switch (wValue) {
		case CFS_PORT_ENABLE:
			ehci_handle_port_enable(ehcip, port, 1);
			break;
		case CFS_PORT_SUSPEND:
			ehci_handle_port_suspend(ehcip, port, 1);
			break;
		case CFS_PORT_RESET:
			ehci_handle_port_reset(ehcip, port);
			break;
		case CFS_PORT_POWER:
			ehci_handle_port_power(ehcip, port, 1);
			break;
		default:
			USB_DPRINTF_L2(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
			    "ehci_handle_set_clear_port_feature: "
			    "Unsupported request 0x%x 0x%x", bRequest, wValue);

			error = USB_FAILURE;
			break;
		}
		break;
	case USB_REQ_CLEAR_FEATURE:
		switch (wValue) {
		case CFS_PORT_ENABLE:
			ehci_handle_port_enable(ehcip, port, 0);
			break;
		case CFS_C_PORT_ENABLE:
			ehci_handle_clrchng_port_enable(ehcip, port);
			break;
		case CFS_PORT_SUSPEND:
			ehci_handle_port_suspend(ehcip, port, 0);
			break;
		case CFS_C_PORT_SUSPEND:
			ehci_handle_clrchng_port_suspend(ehcip, port);
			break;
		case CFS_C_PORT_RESET:
			ehci_handle_complete_port_reset(ehcip, port);
			break;
		case CFS_PORT_POWER:
			ehci_handle_port_power(ehcip, port, 0);
			break;
		case CFS_C_PORT_CONNECTION:
			ehci_handle_clear_port_connection(ehcip, port);
			break;
		case CFS_C_PORT_OVER_CURRENT:
			ehci_handle_clrchng_port_over_current(ehcip, port);
			break;
		default:
			USB_DPRINTF_L2(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
			    "ehci_handle_set_clear_port_feature: "
			    "Unsupported request 0x%x 0x%x", bRequest, wValue);

			error = USB_FAILURE;
			break;
		}
		break;
	default:
		USB_DPRINTF_L2(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
		    "ehci_handle_set_clear_port_feature: "
		    "Unsupported request 0x%x 0x%x", bRequest, wValue);

		error = USB_FAILURE;
		break;
	}

	return (error);
}


/*
 * ehci_handle_port_power:
 *
 * Turn on a root hub port.
 */
static void
ehci_handle_port_power(
	ehci_state_t		*ehcip,
	uint16_t		port,
	uint_t			on)
{
	uint_t			port_status;
	ehci_root_hub_t		*rh;

	mutex_enter(&ehcip->ehci_int_mutex);

	port_status = Get_OpReg(ehci_rh_port_status[port]) &
	    ~EHCI_RH_PORT_CLEAR_MASK;

	rh = &ehcip->ehci_root_hub;

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
	    "ehci_handle_port_power: port = 0x%x status = 0x%x on = %d",
	    port, port_status, on);

	/* Check port is owned by ehci */
	if (ehci_is_port_owner(ehcip, port) != USB_SUCCESS) {
		mutex_exit(&ehcip->ehci_int_mutex);

		return;
	}

	if (on) {
		/* See if the port power is already on */
		if (!(port_status & EHCI_RH_PORT_POWER)) {
			/* Turn the port on */
			Set_OpReg(ehci_rh_port_status[port],
			    port_status | EHCI_RH_PORT_POWER);
		}

		rh->rh_port_status[port] = 0;
		rh->rh_port_state[port] = DISCONNECTED;
	} else {
		/* See if the port power is already OFF */
		if (port_status & EHCI_RH_PORT_POWER) {
			/* Turn-off the port */
			Set_OpReg(ehci_rh_port_status[port],
			    port_status & ~EHCI_RH_PORT_POWER);
		}

		rh->rh_port_status[port] = 0;
		rh->rh_port_state[port] = POWERED_OFF;
	}

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
	    "ehci_handle_port_power done: port = 0x%x status = 0x%x on = %d",
	    port, Get_OpReg(ehci_rh_port_status[port]), on);

	mutex_exit(&ehcip->ehci_int_mutex);
}


/*
 * ehci_handle_port_enable:
 *
 * Handle port enable request.
 */
static void
ehci_handle_port_enable(
	ehci_state_t		*ehcip,
	uint16_t		port,
	uint_t			on)
{
	uint_t			port_status;

	mutex_enter(&ehcip->ehci_int_mutex);

	port_status = Get_OpReg(ehci_rh_port_status[port]) &
	    ~EHCI_RH_PORT_CLEAR_MASK;

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
	    "ehci_handle_port_enable: port = 0x%x, status = 0x%x",
	    port, port_status);

	/* Check port is owned by ehci */
	if (ehci_is_port_owner(ehcip, port) != USB_SUCCESS) {
		mutex_exit(&ehcip->ehci_int_mutex);

		return;
	}

	if (on) {
		/* See if the port enable is already on */
		if (!(port_status & EHCI_RH_PORT_ENABLE)) {
			/* Enable the port */
			Set_OpReg(ehci_rh_port_status[port],
			    port_status | EHCI_RH_PORT_ENABLE);
		}
	} else {
		/* See if the port enable is already off */
		if (port_status & EHCI_RH_PORT_ENABLE) {
			/* Disable the port */
			Set_OpReg(ehci_rh_port_status[port],
			    port_status & ~EHCI_RH_PORT_ENABLE);
		}
	}

	mutex_exit(&ehcip->ehci_int_mutex);
}


/*
 * ehci_handle_clrchng_port_enable:
 *
 * Handle clear port enable change bit.
 */
static void
ehci_handle_clrchng_port_enable(
	ehci_state_t		*ehcip,
	uint16_t		port)
{
	uint_t			port_status;

	mutex_enter(&ehcip->ehci_int_mutex);

	port_status = Get_OpReg(ehci_rh_port_status[port]) &
	    ~EHCI_RH_PORT_CLEAR_MASK;

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
	    "ehci_handle_port_enable: port = 0x%x, status = 0x%x",
	    port, port_status);

	/* Check port is owned by ehci */
	if (ehci_is_port_owner(ehcip, port) != USB_SUCCESS) {
		mutex_exit(&ehcip->ehci_int_mutex);

		return;
	}

	/* Clear the PortEnableStatusChange Bit */
	Set_OpReg(ehci_rh_port_status[port],
	    port_status | EHCI_RH_PORT_ENABLE_CHANGE);

	mutex_exit(&ehcip->ehci_int_mutex);
}


/*
 * ehci_handle_port_suspend:
 *
 * Handle port suspend/resume request.
 */
static void
ehci_handle_port_suspend(
	ehci_state_t		*ehcip,
	uint16_t		port,
	uint_t			on)
{
	uint_t			port_status;

	mutex_enter(&ehcip->ehci_int_mutex);

	port_status = Get_OpReg(ehci_rh_port_status[port]) &
	    ~EHCI_RH_PORT_CLEAR_MASK;

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
	    "ehci_handle_port_suspend: port = 0x%x, status = 0x%x",
	    port, port_status);

	/* Check port is owned by ehci */
	if (ehci_is_port_owner(ehcip, port) != USB_SUCCESS) {
		mutex_exit(&ehcip->ehci_int_mutex);

		return;
	}

	if (on) {
		/*
		 * Suspend port only if port is enabled and
		 * it is not already in suspend state.
		 */
		if ((port_status & EHCI_RH_PORT_ENABLE) &&
		    (!(port_status & EHCI_RH_PORT_SUSPEND))) {
			/* Suspend the port */
			Set_OpReg(ehci_rh_port_status[port],
			    port_status | EHCI_RH_PORT_SUSPEND);

			mutex_exit(&ehcip->ehci_int_mutex);

			/* Wait 10ms for port move to suspend state */
			delay(drv_usectohz(EHCI_PORT_SUSPEND_TIMEWAIT));

			return;
		}
	} else {
		/* Perform resume only if port is in suspend state */
		if (port_status & EHCI_RH_PORT_SUSPEND) {
			/* Resume the port */
			Set_OpReg(ehci_rh_port_status[port],
			    port_status | EHCI_RH_PORT_RESUME);
		}
	}

	mutex_exit(&ehcip->ehci_int_mutex);
}


/*
 * ehci_handle_clrchng_port_suspend:
 *
 * Handle port clear port suspend change bit.
 */
static void
ehci_handle_clrchng_port_suspend(
	ehci_state_t		*ehcip,
	uint16_t		port)
{
	uint_t			port_status;
	int			i;

	mutex_enter(&ehcip->ehci_int_mutex);

	port_status = Get_OpReg(ehci_rh_port_status[port]) &
	    ~EHCI_RH_PORT_CLEAR_MASK;

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
	    "ehci_handle_clrchng_port_suspend: port = 0x%x, "
	    "status = 0x%x", port, port_status);

	/* Check port is owned by ehci */
	if (ehci_is_port_owner(ehcip, port) != USB_SUCCESS) {
		mutex_exit(&ehcip->ehci_int_mutex);

		return;
	}

	/* Return if port is not in resume state */
	if (!(port_status & EHCI_RH_PORT_RESUME)) {
		mutex_exit(&ehcip->ehci_int_mutex);

		return;
	}

	mutex_exit(&ehcip->ehci_int_mutex);

	/* Wait for 20ms to terminate resume */
	delay(drv_usectohz(EHCI_PORT_RESUME_TIMEWAIT));

	mutex_enter(&ehcip->ehci_int_mutex);

	Set_OpReg(ehci_rh_port_status[port],
	    port_status & ~EHCI_RH_PORT_RESUME);

	mutex_exit(&ehcip->ehci_int_mutex);

	/*
	 * Wait for port to return to high speed mode. It's necessary to poll
	 * for resume completion for some high-speed devices to work correctly.
	 */
	for (i = 0; i < EHCI_PORT_RESUME_RETRY_MAX; i++) {
		delay(drv_usectohz(EHCI_PORT_RESUME_COMP_TIMEWAIT));

		mutex_enter(&ehcip->ehci_int_mutex);
		port_status = Get_OpReg(ehci_rh_port_status[port]) &
		    ~EHCI_RH_PORT_CLEAR_MASK;
		mutex_exit(&ehcip->ehci_int_mutex);

		if (!(port_status & EHCI_RH_PORT_RESUME)) {
			break;
		}
	}
}


/*
 * ehci_handle_port_reset:
 *
 * Perform a port reset.
 */
static void
ehci_handle_port_reset(
	ehci_state_t		*ehcip,
	uint16_t		port)
{
	ehci_root_hub_t		*rh;
	uint_t			port_status;
	int			i;

	mutex_enter(&ehcip->ehci_int_mutex);

	/* Get the root hub structure */
	rh = &ehcip->ehci_root_hub;

	/* Get the port status information */
	port_status = Get_OpReg(ehci_rh_port_status[port]) &
	    ~EHCI_RH_PORT_CLEAR_MASK;

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
	    "ehci_handle_port_reset: port = 0x%x status = 0x%x",
	    port, port_status);

	/* Check port is owned by ehci */
	if (ehci_is_port_owner(ehcip, port) != USB_SUCCESS) {
		mutex_exit(&ehcip->ehci_int_mutex);

		return;
	}

	if (port_status & EHCI_RH_PORT_LOW_SPEED) {
		/* Check for classic or companion host controllers */
		if (rh->rh_companion_controllers) {
			USB_DPRINTF_L3(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
			    "ehci_handle_port_reset: Low speed device "
			    "and handover this port to Companion controller");

			Set_OpReg(ehci_rh_port_status[port],
			    port_status | EHCI_RH_PORT_OWNER_CLASSIC);
		} else {
			USB_DPRINTF_L1(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
			    "Low speed device is not supported");
		}
	} else {
		Set_OpReg(ehci_rh_port_status[port],
		    ((port_status | EHCI_RH_PORT_RESET) &
		    ~EHCI_RH_PORT_ENABLE));

		mutex_exit(&ehcip->ehci_int_mutex);

		/* Wait 50ms for reset to complete */
		delay(drv_usectohz(EHCI_PORT_RESET_TIMEWAIT));

		mutex_enter(&ehcip->ehci_int_mutex);

		port_status = Get_OpReg(ehci_rh_port_status[port]) &
		    ~EHCI_RH_PORT_CLEAR_MASK;

		Set_OpReg(ehci_rh_port_status[port],
		    (port_status & ~EHCI_RH_PORT_RESET));

		mutex_exit(&ehcip->ehci_int_mutex);

		/*
		 * Wait for hardware to enable this port, if the connected
		 * usb device is high speed. It's necessary to poll for reset
		 * completion for some high-speed devices to recognized
		 * correctly.
		 */
		for (i = 0; i < EHCI_PORT_RESET_RETRY_MAX; i++) {
			delay(drv_usectohz(EHCI_PORT_RESET_COMP_TIMEWAIT));

			mutex_enter(&ehcip->ehci_int_mutex);
			port_status = Get_OpReg(ehci_rh_port_status[port]) &
			    ~EHCI_RH_PORT_CLEAR_MASK;
			mutex_exit(&ehcip->ehci_int_mutex);

			if (!(port_status & EHCI_RH_PORT_RESET)) {
				break;
			}
		}

		mutex_enter(&ehcip->ehci_int_mutex);

		port_status = Get_OpReg(ehci_rh_port_status[port]) &
		    ~EHCI_RH_PORT_CLEAR_MASK;

		/*
		 * If port is not enabled, connected device is a
		 * Full-speed usb device.
		 */
		if (!(port_status & EHCI_RH_PORT_ENABLE)) {
			/* Check for classic or companion host controllers */
			if (rh->rh_companion_controllers) {
				USB_DPRINTF_L3(PRINT_MASK_ROOT_HUB,
				    ehcip->ehci_log_hdl,
				    "ehci_handle_port_reset: Full speed device "
				    "and handover this port to Companion host "
				    "controller");

				Set_OpReg(ehci_rh_port_status[port],
				    port_status | EHCI_RH_PORT_OWNER_CLASSIC);
			} else {
				USB_DPRINTF_L1(PRINT_MASK_ROOT_HUB,
				    ehcip->ehci_log_hdl,
				    "Full speed device is not supported");
			}
		} else {
			USB_DPRINTF_L3(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
			    "ehci_handle_port_reset: High speed device ");

			port_status = Get_OpReg(ehci_rh_port_status[port]) &
			    ~EHCI_RH_PORT_CLEAR_MASK;

			/*
			 * Disable over-current, connect, and disconnect
			 * wakeup bits.
			 */
			Set_OpReg(ehci_rh_port_status[port], port_status &
			    ~(EHCI_RH_PORT_OVER_CURENT_ENABLE |
			    EHCI_RH_PORT_DISCONNECT_ENABLE |
			    EHCI_RH_PORT_CONNECT_ENABLE));

			/*
			 * The next function is only called if the interrupt
			 * pipe is polling and the USBA is ready to receive
			 * the data.
			 */
			ehcip->ehci_root_hub.
			    rh_intr_pending_status |= (1 << port);

			if (ehcip->ehci_root_hub.
			    rh_intr_pipe_state == EHCI_PIPE_STATE_ACTIVE) {

				ehci_root_hub_reset_occured(ehcip);
			}
		}
	}

	mutex_exit(&ehcip->ehci_int_mutex);
}


/*
 * ehci_root_hub_reset_occured:
 *
 * Inform the upper layer that reset has occured on the port. This is
 * required because the upper layer is expecting a an evernt immidiately
 * after doing reset. In case of OHCI, the controller gets an interrupt
 * for the change in the root hub status but in case of EHCI, we dont.
 * So, send a event to the upper layer as soon as we complete the reset.
 */
void
ehci_root_hub_reset_occured(
	ehci_state_t		*ehcip)
{
	usb_intr_req_t		*curr_intr_reqp =
	    ehcip->ehci_root_hub.rh_curr_intr_reqp;
	usb_port_mask_t		port_mask;
	usba_pipe_handle_data_t	*ph;

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
	    "ehci_root_hub_reset_occured: curr_intr_reqp = 0x%p data = 0x%p",
	    (void *)curr_intr_reqp, (void *)curr_intr_reqp->intr_data);

	/* Get the interrupt pipe handle */
	ph = ehcip->ehci_root_hub.rh_intr_pipe_handle;

	/* Get the pending status */
	port_mask = ehcip->ehci_root_hub.rh_intr_pending_status << 1;

	do {
		*curr_intr_reqp->intr_data->b_wptr++ = (uchar_t)port_mask;
		port_mask >>= 8;
	} while (port_mask != 0);

	ehci_root_hub_hcdi_callback(ph, USB_CR_OK);

	/* Reset pending status */
	ehcip->ehci_root_hub.rh_intr_pending_status = 0;

	/* If needed, allocate new interrupt request */
	if ((ehci_root_hub_allocate_intr_pipe_resource(
	    ehcip, 0)) != USB_SUCCESS) {

		/* Do interrupt pipe cleanup */
		ehci_root_hub_intr_pipe_cleanup(ehcip, USB_CR_NO_RESOURCES);
	}
}


/*
 * ehci_handle_complete_port_reset:
 *
 * Perform a port reset change.
 */
static void
ehci_handle_complete_port_reset(
	ehci_state_t		*ehcip,
	uint16_t		port)
{
	uint_t			port_status;

	mutex_enter(&ehcip->ehci_int_mutex);

	port_status = Get_OpReg(ehci_rh_port_status[port]) &
	    ~EHCI_RH_PORT_CLEAR_MASK;

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
	    "ehci_handle_complete_port_reset: port = 0x%x status = 0x%x",
	    port, port_status);

	/* Check port is owned by ehci */
	if (ehci_is_port_owner(ehcip, port) != USB_SUCCESS) {
		mutex_exit(&ehcip->ehci_int_mutex);

		return;
	}

	if (port_status & EHCI_RH_PORT_RESET) {
		Set_OpReg(ehci_rh_port_status[port],
		    port_status & ~EHCI_RH_PORT_RESET);

	}

	mutex_exit(&ehcip->ehci_int_mutex);
}


/*
 * ehci_handle_clear_port_connection:
 *
 * Perform a clear port connection.
 */
static void
ehci_handle_clear_port_connection(
	ehci_state_t		*ehcip,
	uint16_t		port)
{
	uint_t			port_status;

	mutex_enter(&ehcip->ehci_int_mutex);

	port_status = Get_OpReg(ehci_rh_port_status[port]) &
	    ~EHCI_RH_PORT_CLEAR_MASK;

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
	    "ehci_handle_clear_port_connection: port = 0x%x"
	    "status = 0x%x", port, port_status);

	Set_OpReg(ehci_rh_port_status[port],
	    port_status | EHCI_RH_PORT_CONNECT_STS_CHANGE);

	mutex_exit(&ehcip->ehci_int_mutex);
}


/*
 * ehci_handle_clrchng_port_over_current:
 *
 * Perform a clear port connection.
 */
static void
ehci_handle_clrchng_port_over_current(
	ehci_state_t		*ehcip,
	uint16_t		port)
{
	uint_t			port_status;

	mutex_enter(&ehcip->ehci_int_mutex);

	port_status = Get_OpReg(ehci_rh_port_status[port]) &
	    ~EHCI_RH_PORT_CLEAR_MASK;

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
	    "ehci_handle_clrchng_port_over_current: port = 0x%x"
	    "status = 0x%x", port, port_status);

	Set_OpReg(ehci_rh_port_status[port],
	    port_status | EHCI_RH_PORT_OVER_CURR_CHANGE);

	mutex_exit(&ehcip->ehci_int_mutex);
}


/*
 * ehci_handle_get_port_status:
 *
 * Handle a get port status request.
 */
static void
ehci_handle_get_port_status(
	ehci_state_t		*ehcip,
	uint16_t		port)
{
	usb_ctrl_req_t		*ctrl_reqp;
	mblk_t			*message;
	uint_t			new_port_status = 0;
	uint_t			change_status = 0;
	uint_t			port_status;

	mutex_enter(&ehcip->ehci_int_mutex);

	ctrl_reqp = ehcip->ehci_root_hub.rh_curr_ctrl_reqp;

	/* Get the root hub port status information */
	port_status = ehci_get_root_hub_port_status(ehcip, port);

	new_port_status = port_status & PORT_STATUS_MASK;
	change_status = (port_status >> 16) & PORT_CHANGE_MASK_2X;

	ehcip->ehci_root_hub.rh_port_status[port] = new_port_status;

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
	    "ehci_handle_get_port_status: port = %d new status = 0x%x"
	    "change = 0x%x", port, new_port_status, change_status);

	message = ctrl_reqp->ctrl_data;

	ASSERT(message != NULL);

	*message->b_wptr++ = (uchar_t)new_port_status;
	*message->b_wptr++ = (uchar_t)(new_port_status >> 8);
	*message->b_wptr++ = (uchar_t)change_status;
	*message->b_wptr++ = (uchar_t)(change_status >> 8);

	/* Save the data in control request */
	ctrl_reqp->ctrl_data = message;

	mutex_exit(&ehcip->ehci_int_mutex);
}


/*
 * ehci_handle_get_hub_descriptor:
 */
static void
ehci_handle_get_hub_descriptor(
	ehci_state_t		*ehcip)
{
	usb_ctrl_req_t		*ctrl_reqp;
	mblk_t			*message;
	usb_hub_descr_t		*root_hub_descr;
	size_t			length;
	uchar_t			raw_descr[ROOT_HUB_DESCRIPTOR_LENGTH];

	mutex_enter(&ehcip->ehci_int_mutex);

	ctrl_reqp = ehcip->ehci_root_hub.rh_curr_ctrl_reqp;
	root_hub_descr = &ehcip->ehci_root_hub.rh_descr;
	length = ctrl_reqp->ctrl_wLength;

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
	    "ehci_handle_get_hub_descriptor: Ctrl Req  = 0x%p",
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

	mutex_exit(&ehcip->ehci_int_mutex);
}


/*
 * ehci_handle_get_hub_status:
 *
 * Handle a get hub status request.
 */
static void
ehci_handle_get_hub_status(
	ehci_state_t		*ehcip)
{
	usb_ctrl_req_t		*ctrl_reqp;
	mblk_t			*message;
	uint_t			new_root_hub_status;

	mutex_enter(&ehcip->ehci_int_mutex);

	ctrl_reqp = ehcip->ehci_root_hub.rh_curr_ctrl_reqp;

	/*
	 * For EHCI, there is no overall hub status information.
	 * Only individual root hub port status information is
	 * available. So return zero for the root hub status
	 * request.
	 */
	new_root_hub_status = 0;

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
	    "ehci_handle_get_hub_status: new root hub status = 0x%x",
	    new_root_hub_status);

	message = ctrl_reqp->ctrl_data;

	ASSERT(message != NULL);

	*message->b_wptr++ = (uchar_t)new_root_hub_status;
	*message->b_wptr++ = (uchar_t)(new_root_hub_status >> 8);
	*message->b_wptr++ = (uchar_t)(new_root_hub_status >> 16);
	*message->b_wptr++ = (uchar_t)(new_root_hub_status >> 24);

	/* Save the data in control request */
	ctrl_reqp->ctrl_data = message;

	mutex_exit(&ehcip->ehci_int_mutex);
}


/*
 * ehci_handle_get_device_status:
 *
 * Handle a get device status request.
 */
static void
ehci_handle_get_device_status(
	ehci_state_t		*ehcip)
{
	usb_ctrl_req_t		*ctrl_reqp;
	mblk_t			*message;
	uint16_t		dev_status;

	mutex_enter(&ehcip->ehci_int_mutex);

	ctrl_reqp = ehcip->ehci_root_hub.rh_curr_ctrl_reqp;

	/*
	 * For EHCI, there is no device status information.
	 * Simply return what is desired for the request.
	 */
	dev_status = USB_DEV_SLF_PWRD_STATUS;

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
	    "ehci_handle_get_device_status: device status = 0x%x",
	    dev_status);

	message = ctrl_reqp->ctrl_data;

	ASSERT(message != NULL);

	*message->b_wptr++ = (uchar_t)dev_status;
	*message->b_wptr++ = (uchar_t)(dev_status >> 8);

	/* Save the data in control request */
	ctrl_reqp->ctrl_data = message;

	mutex_exit(&ehcip->ehci_int_mutex);
}


/*
 * ehci_handle_root_hub_pipe_start_intr_polling:
 *
 * Handle start polling on root hub interrupt pipe.
 */
/* ARGSUSED */
int
ehci_handle_root_hub_pipe_start_intr_polling(
	usba_pipe_handle_data_t	*ph,
	usb_intr_req_t		*client_intr_reqp,
	usb_flags_t		flags)
{
	ehci_state_t		*ehcip = ehci_obtain_state(
	    ph->p_usba_device->usb_root_hub_dip);
	usb_ep_descr_t		*eptd = &ph->p_ep;
	int			error = USB_SUCCESS;
	uint_t			pipe_state;

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
	    "ehci_handle_root_hub_pipe_start_intr_polling: "
	    "Root hub pipe start polling");

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	ASSERT((eptd->bEndpointAddress & USB_EP_NUM_MASK) == 1);

	ASSERT((client_intr_reqp->intr_attributes & USB_ATTRS_ONE_XFER) == 0);

	pipe_state = ehcip->ehci_root_hub.rh_intr_pipe_state;

	switch (pipe_state) {
	case EHCI_PIPE_STATE_IDLE:
		ASSERT(ehcip->ehci_root_hub.rh_intr_pipe_timer_id == 0);

		/*
		 * Save the Original Client's Interrupt IN request
		 * information. We use this for final callback
		 */
		ASSERT(ehcip->ehci_root_hub.rh_client_intr_reqp == NULL);
		ehcip->ehci_root_hub.rh_client_intr_reqp = client_intr_reqp;

		error = ehci_root_hub_allocate_intr_pipe_resource(ehcip, flags);

		if (error != USB_SUCCESS) {
			/* Reset client interrupt request pointer */
			ehcip->ehci_root_hub.rh_client_intr_reqp = NULL;

			USB_DPRINTF_L2(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
			    "ehci_handle_root_hub_pipe_start_intr_polling: "
			    "No Resources");

			return (error);
		}

		/* Check whether we need to send the reset data up */
		if (ehcip->ehci_root_hub.rh_intr_pending_status) {
			ehci_root_hub_reset_occured(ehcip);
		}

		USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
		    "ehci_handle_root_hub_pipe_start_intr_polling: "
		    "Start polling for root hub successful");

		break;
	case EHCI_PIPE_STATE_ACTIVE:
		USB_DPRINTF_L2(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
		    "ehci_handle_root_hub_pipe_start_intr_polling: "
		    "Polling for root hub is already in progress");

		break;
	default:
		USB_DPRINTF_L2(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
		    "ehci_handle_root_hub_pipe_start_intr_polling: "
		    "Pipe is in error state 0x%x", pipe_state);

		error = USB_FAILURE;

		break;
	}

	return (error);
}


/*
 * ehci_handle_root_hub_pipe_stop_intr_polling:
 *
 * Handle stop polling on root hub intr pipe.
 */
/* ARGSUSED */
void
ehci_handle_root_hub_pipe_stop_intr_polling(
	usba_pipe_handle_data_t	*ph,
	usb_flags_t		flags)
{
	ehci_state_t		*ehcip = ehci_obtain_state(
	    ph->p_usba_device->usb_root_hub_dip);
	usb_ep_descr_t		*eptd = &ph->p_ep;

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
	    "ehci_handle_root_hub_pipe_stop_intr_polling: "
	    "Root hub pipe stop polling");

	ASSERT((eptd->bEndpointAddress & USB_EP_NUM_MASK) == 1);

	if (ehcip->ehci_root_hub.rh_intr_pipe_state ==
	    EHCI_PIPE_STATE_ACTIVE) {

		ehcip->ehci_root_hub.rh_intr_pipe_state =
		    EHCI_PIPE_STATE_STOP_POLLING;

		/* Do interrupt pipe cleanup */
		ehci_root_hub_intr_pipe_cleanup(ehcip, USB_CR_STOPPED_POLLING);

		ASSERT(ehcip->ehci_root_hub.
		    rh_intr_pipe_state == EHCI_PIPE_STATE_IDLE);

		USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
		    "ehci_hcdi_pipe_stop_intr_polling: Stop polling for root"
		    "hub successful");
	} else {
		USB_DPRINTF_L2(PRINT_MASK_ROOT_HUB,
		    ehcip->ehci_log_hdl, "ehci_hcdi_pipe_stop_intr_polling: "
		    "Polling for root hub is already stopped");
	}
}


/*
 * ehci_get_root_hub_port_status:
 *
 * Construct root hub port status and change information
 */
static uint_t
ehci_get_root_hub_port_status(
	ehci_state_t		*ehcip,
	uint16_t		port)
{
	uint_t			new_port_status = 0;
	uint_t			change_status = 0;
	uint_t			port_status;

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	/* Read the current port status */
	port_status = Get_OpReg(ehci_rh_port_status[port]);

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
	    "ehci_get_root_hub_port_status: port %d "
	    "port status = 0x%x", port, port_status);

	/*
	 * EHCI root hub port status and control register information
	 * format is different what Hub driver wants. So EHCI driver
	 * needs to contruct the proper root hub port status information.
	 *
	 * Send all port status information only if port is owned by EHCI
	 * host controller.
	 */
	if ((port_status & EHCI_RH_PORT_OWNER) == EHCI_RH_PORT_OWNER_EHCI) {

		/* First construct port change information */
		if (port_status & EHCI_RH_PORT_ENABLE_CHANGE) {
			change_status |= PORT_CHANGE_PESC;
		}

		if (port_status & EHCI_RH_PORT_RESUME) {
			change_status |= PORT_CHANGE_PSSC;
		}

		if (port_status & EHCI_RH_PORT_OVER_CURR_CHANGE) {
			change_status |= PORT_CHANGE_OCIC;
		}

		/* Now construct port status information */
		if (port_status & EHCI_RH_PORT_CONNECT_STATUS) {
			new_port_status |= PORT_STATUS_CCS;
		}

		if (port_status & EHCI_RH_PORT_ENABLE) {
			new_port_status |=
			    (PORT_STATUS_PES | PORT_STATUS_HSDA);
		}

		if (port_status & EHCI_RH_PORT_SUSPEND) {
			new_port_status |= PORT_STATUS_PSS;
		}

		if (port_status & EHCI_RH_PORT_OVER_CURR_ACTIVE) {
			new_port_status |= PORT_STATUS_POCI;
		}

		if (port_status & EHCI_RH_PORT_RESET) {
			new_port_status |= PORT_STATUS_PRS;
		}

		if (port_status & EHCI_RH_PORT_INDICATOR) {
			new_port_status |= PORT_STATUS_PIC;
		}
	}

	/*
	 * Send the following port status and change information
	 * even if port is not owned by EHCI.
	 *
	 * Additional port change information.
	 */
	if (port_status & EHCI_RH_PORT_CONNECT_STS_CHANGE) {
		change_status |= PORT_CHANGE_CSC;
	}

	/* Additional port status information */
	if (port_status & EHCI_RH_PORT_POWER) {
		new_port_status |= PORT_STATUS_PPS;
	}

	if ((!(port_status & EHCI_RH_PORT_ENABLE)) &&
	    (port_status & EHCI_RH_PORT_LOW_SPEED)) {
		new_port_status |= PORT_STATUS_LSDA;
	}

	/*
	 * Construct complete root hub port status and change information.
	 */
	port_status = ((change_status << 16) | new_port_status);

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
	    "ehci_get_root_hub_port_status: port = %d new status = 0x%x "
	    "change status = 0x%x complete port status 0x%x", port,
	    new_port_status, change_status, port_status);

	return (port_status);
}


/*
 * ehci_is_port_owner:
 *
 * Check whether given port is owned by ehci.
 */
static int
ehci_is_port_owner(
	ehci_state_t		*ehcip,
	uint16_t		port)
{
	uint_t			port_status;

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	port_status = Get_OpReg(ehci_rh_port_status[port]) &
	    ~EHCI_RH_PORT_CLEAR_MASK;

	/*
	 * Don't perform anything if port is owned by classis host
	 * controller and return success.
	 */
	if ((port_status & EHCI_RH_PORT_OWNER) == EHCI_RH_PORT_OWNER_CLASSIC) {

		USB_DPRINTF_L2(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
		    "ehci_handle_set_clear_port_feature: "
		    "Port %d is owned by classic host controller", port);

		return (USB_FAILURE);
	}

	return (USB_SUCCESS);
}


/*
 * ehci_root_hub_allocate_intr_pipe_resource:
 *
 * Allocate interrupt requests and initialize them.
 */
static int
ehci_root_hub_allocate_intr_pipe_resource(
	ehci_state_t		*ehcip,
	usb_flags_t		flags)
{
	usba_pipe_handle_data_t	*ph;
	size_t			length;
	usb_intr_req_t		*curr_intr_reqp;

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
	    "ehci_root_hub_allocate_intr_pipe_resource");

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	/* Get the interrupt pipe handle */
	ph = ehcip->ehci_root_hub.rh_intr_pipe_handle;

	/* Get the current interrupt request pointer */
	curr_intr_reqp = ehcip->ehci_root_hub.rh_curr_intr_reqp;

	/*
	 * If current interrupt request pointer is null,
	 * allocate new interrupt request.
	 */
	if (curr_intr_reqp == NULL) {
		ASSERT(ehcip->ehci_root_hub.rh_client_intr_reqp);

		/* Get the length of interrupt transfer */
		length = ehcip->ehci_root_hub.
		    rh_client_intr_reqp->intr_len;

		curr_intr_reqp = usba_hcdi_dup_intr_req(ph->p_dip,
		    ehcip->ehci_root_hub.rh_client_intr_reqp,
		    length, flags);

		if (curr_intr_reqp == NULL) {

			USB_DPRINTF_L2(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
			    "ehci_root_hub_allocate_intr_pipe_resource:"
			    "Interrupt request structure allocation failed");

			return (USB_NO_RESOURCES);
		}

		ehcip->ehci_root_hub.rh_curr_intr_reqp = curr_intr_reqp;
		mutex_enter(&ph->p_mutex);
		ph->p_req_count++;
		mutex_exit(&ph->p_mutex);
	}

	/* Start the timer for the root hub interrupt pipe polling */
	if (ehcip->ehci_root_hub.rh_intr_pipe_timer_id == 0) {
		ehcip->ehci_root_hub.rh_intr_pipe_timer_id =
		    timeout(ehci_handle_root_hub_status_change,
		    (void *)ehcip, drv_usectohz(EHCI_RH_POLL_TIME));

		ehcip->ehci_root_hub.
		    rh_intr_pipe_state = EHCI_PIPE_STATE_ACTIVE;
	}

	return (USB_SUCCESS);
}


/*
 * ehci_root_hub_intr_pipe_cleanup:
 *
 * Deallocate all interrupt requests and do callback
 * the original client interrupt request.
 */
static void
ehci_root_hub_intr_pipe_cleanup(
	ehci_state_t		*ehcip,
	usb_cr_t		completion_reason)
{
	usb_intr_req_t		*curr_intr_reqp;
	usb_opaque_t		client_intr_reqp;
	timeout_id_t		timer_id;
	usba_pipe_handle_data_t	*ph;

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
	    "ehci_root_hub_intr_pipe_cleanup");

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	/* Get the interrupt pipe handle */
	ph = ehcip->ehci_root_hub.rh_intr_pipe_handle;

	/* Get the interrupt timerid */
	timer_id = ehcip->ehci_root_hub.rh_intr_pipe_timer_id;

	/* Stop the root hub interrupt timer */
	if (timer_id) {
		/* Reset the timer id to zero */
		ehcip->ehci_root_hub.rh_intr_pipe_timer_id = 0;

		mutex_exit(&ehcip->ehci_int_mutex);
		(void) untimeout(timer_id);
		mutex_enter(&ehcip->ehci_int_mutex);
	}

	/* Reset the current interrupt request pointer */
	curr_intr_reqp = ehcip->ehci_root_hub.rh_curr_intr_reqp;

	/* Deallocate uncompleted interrupt request */
	if (curr_intr_reqp) {
		ehcip->ehci_root_hub.rh_curr_intr_reqp = NULL;
		usb_free_intr_req(curr_intr_reqp);

		mutex_enter(&ph->p_mutex);
		ph->p_req_count--;
		mutex_exit(&ph->p_mutex);
	}

	client_intr_reqp = (usb_opaque_t)
	    ehcip->ehci_root_hub.rh_client_intr_reqp;

	/* Callback for original client interrupt request */
	if (client_intr_reqp) {
		ehci_root_hub_hcdi_callback(ph, completion_reason);
	}
}


/*
 * ehci_handle_root_hub_status_change:
 *
 * A root hub status change interrupt will occur any time there is a change
 * in the root hub status register or one of the port status registers.
 */
static void
ehci_handle_root_hub_status_change(void *arg)
{
	ehci_state_t		*ehcip = (ehci_state_t *)arg;
	usb_hub_descr_t		*root_hub_descr =
	    &ehcip->ehci_root_hub.rh_descr;
	usb_intr_req_t		*curr_intr_reqp;
	usb_port_mask_t		port_mask = 0;
	uint_t			new_port_status;
	uint_t			change_status;
	uint_t			port_status;
	mblk_t			*message;
	size_t			length;
	usb_ep_descr_t		*eptd;
	usba_pipe_handle_data_t	*ph;
	int			i;

	mutex_enter(&ehcip->ehci_int_mutex);

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
	    "ehci_handle_root_hub_status_change: state = %d",
	    ehcip->ehci_root_hub.rh_intr_pipe_state);

#if defined(__x86)
	/*
	 * When ohci are attached in ferrari 4000, SMI will reset ehci
	 * registers. If ehci registers have been reset, we must re-initialize
	 * them. During booting, this function will be called 2~3 times. When
	 * this function is called 16 times, ohci drivers have been attached
	 * and stop checking the ehci registers.
	 */
	if (ehcip->ehci_polled_root_hub_count < 16) {

		if (Get_OpReg(ehci_config_flag) == 0) {

			USB_DPRINTF_L2(PRINT_MASK_ROOT_HUB,
			    ehcip->ehci_log_hdl,
			    "ehci_handle_root_hub_status_change:"
			    " EHCI have been reset");

			/* Reinitialize the controller */
			if (ehci_init_ctlr(ehcip, EHCI_REINITIALIZATION) !=
			    DDI_SUCCESS) {
				mutex_exit(&ehcip->ehci_int_mutex);

				return;
			}
		}

		ehcip->ehci_polled_root_hub_count++;
	}
#endif	/* __x86 */

	/* Get the current interrupt request pointer */
	curr_intr_reqp = ehcip->ehci_root_hub.rh_curr_intr_reqp;

	ph = ehcip->ehci_root_hub.rh_intr_pipe_handle;

	/* Check whether timeout handler is valid */
	if (ehcip->ehci_root_hub.rh_intr_pipe_timer_id) {
		/* Check host controller is in operational state */
		if ((ehci_state_is_operational(ehcip)) != USB_SUCCESS) {
			/* Reset the timer id */
			ehcip->ehci_root_hub.rh_intr_pipe_timer_id = 0;

			/* Do interrupt pipe cleanup */
			ehci_root_hub_intr_pipe_cleanup(
			    ehcip, USB_CR_HC_HARDWARE_ERR);

			mutex_exit(&ehcip->ehci_int_mutex);

			return;
		}
	} else {
		mutex_exit(&ehcip->ehci_int_mutex);

		return;
	}

	eptd = &ehcip->ehci_root_hub.rh_intr_pipe_handle->p_ep;

	/* Check each port */
	for (i = 0; i < root_hub_descr->bNbrPorts; i++) {

		port_status = ehci_get_root_hub_port_status(ehcip, i);

		new_port_status = port_status & PORT_STATUS_MASK;
		change_status = (port_status >> 16) & PORT_CHANGE_MASK_2X;

		/*
		 * If there is change in the port status then set the bit in the
		 * bitmap of changes and inform hub driver about these changes.
		 * Hub driver will take care of these changes.
		 */
		if (change_status) {

			/* See if a device was attached/detached */
			if (change_status & PORT_CHANGE_CSC) {
				/*
				 * Update the state depending on whether
				 * the port was attached or detached.
				 */
				if (new_port_status & PORT_STATUS_CCS) {
					ehcip->ehci_root_hub.
					    rh_port_state[i] = DISABLED;

					USB_DPRINTF_L3(PRINT_MASK_ROOT_HUB,
					    ehcip->ehci_log_hdl,
					    "Port %d connected", i+1);
				} else {
					ehcip->ehci_root_hub.
					    rh_port_state[i] = DISCONNECTED;

					USB_DPRINTF_L3(PRINT_MASK_ROOT_HUB,
					    ehcip->ehci_log_hdl,
					    "Port %d disconnected", i+1);
				}
			}

			/* See if port enable status changed */
			if (change_status & PORT_CHANGE_PESC) {
				/*
				 * Update the state depending on whether
				 * the port was enabled or disabled.
				 */
				if (new_port_status & PORT_STATUS_PES) {
					ehcip->ehci_root_hub.
					    rh_port_state[i] = ENABLED;

					USB_DPRINTF_L3(PRINT_MASK_ROOT_HUB,
					    ehcip->ehci_log_hdl,
					    "Port %d enabled", i+1);
				} else {
					ehcip->ehci_root_hub.
					    rh_port_state[i] = DISABLED;

					USB_DPRINTF_L3(PRINT_MASK_ROOT_HUB,
					    ehcip->ehci_log_hdl,
					    "Port %d disabled", i+1);
				}
			}

			port_mask |= 1 << (i + 1);

			/* Update the status */
			ehcip->ehci_root_hub.
			    rh_port_status[i] = new_port_status;
		}
	}

	if (ph && port_mask && curr_intr_reqp) {
		length = eptd->wMaxPacketSize;

		ASSERT(length != 0);

		/* Get the  message block */
		message = curr_intr_reqp->intr_data;

		ASSERT(message != NULL);

		do {
			/*
			 * check that the mblk is big enough when we
			 * are writing bytes into it
			 */
			if (message->b_wptr >= message->b_datap->db_lim) {

				USB_DPRINTF_L2(PRINT_MASK_ROOT_HUB,
				    ehcip->ehci_log_hdl,
				    "ehci_handle_root_hub_status_change"
				    "mblk data overflow.");

				break;
			}
			*message->b_wptr++ = (uchar_t)port_mask;
			port_mask >>= 8;
		} while (port_mask != 0);

		ehci_root_hub_hcdi_callback(ph, USB_CR_OK);
	}

	/* Reset the timer id */
	ehcip->ehci_root_hub.rh_intr_pipe_timer_id = 0;

	if (ehcip->ehci_root_hub.rh_intr_pipe_state ==
	    EHCI_PIPE_STATE_ACTIVE) {
		/*
		 * If needed, allocate new interrupt request. Also
		 * start the timer for the root hub interrupt polling.
		 */
		if ((ehci_root_hub_allocate_intr_pipe_resource(
		    ehcip, 0)) != USB_SUCCESS) {

			USB_DPRINTF_L2(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
			    "ehci_handle_root_hub_status_change: No Resources");

			/* Do interrupt pipe cleanup */
			ehci_root_hub_intr_pipe_cleanup(
			    ehcip, USB_CR_NO_RESOURCES);
		}
	}

	mutex_exit(&ehcip->ehci_int_mutex);
}


/*
 * ehci_root_hub_hcdi_callback()
 *
 * Convenience wrapper around usba_hcdi_cb() for the root hub.
 */
static void
ehci_root_hub_hcdi_callback(
	usba_pipe_handle_data_t	*ph,
	usb_cr_t		completion_reason)
{
	ehci_state_t		*ehcip = ehci_obtain_state(
	    ph->p_usba_device->usb_root_hub_dip);
	uchar_t			attributes = ph->p_ep.bmAttributes &
	    USB_EP_ATTR_MASK;
	usb_opaque_t		curr_xfer_reqp;
	uint_t			pipe_state = 0;

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, ehcip->ehci_log_hdl,
	    "ehci_root_hub_hcdi_callback: ph = 0x%p, cr = 0x%x",
	    (void *)ph, completion_reason);

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	/* Set the pipe state as per completion reason */
	switch (completion_reason) {
	case USB_CR_OK:
		switch (attributes) {
		case USB_EP_ATTR_CONTROL:
			pipe_state = EHCI_PIPE_STATE_IDLE;
			break;
		case USB_EP_ATTR_INTR:
			pipe_state = ehcip->ehci_root_hub.
			    rh_intr_pipe_state;
			break;
		}
		break;
	case USB_CR_NO_RESOURCES:
	case USB_CR_NOT_SUPPORTED:
	case USB_CR_STOPPED_POLLING:
	case USB_CR_PIPE_RESET:
	case USB_CR_HC_HARDWARE_ERR:
		/* Set pipe state to idle */
		pipe_state = EHCI_PIPE_STATE_IDLE;
		break;
	case USB_CR_PIPE_CLOSING:
		break;
	default:
		/* Set pipe state to error */
		pipe_state = EHCI_PIPE_STATE_ERROR;
		break;
	}

	switch (attributes) {
	case USB_EP_ATTR_CONTROL:
		curr_xfer_reqp = (usb_opaque_t)
		    ehcip->ehci_root_hub.rh_curr_ctrl_reqp;

		ehcip->ehci_root_hub.rh_curr_ctrl_reqp = NULL;
		ehcip->ehci_root_hub.rh_ctrl_pipe_state = pipe_state;
		break;
	case USB_EP_ATTR_INTR:
		/* if curr_intr_reqp available then use this request */
		if (ehcip->ehci_root_hub.rh_curr_intr_reqp) {
			curr_xfer_reqp = (usb_opaque_t)ehcip->
			    ehci_root_hub.rh_curr_intr_reqp;

			ehcip->ehci_root_hub.rh_curr_intr_reqp = NULL;
		} else {
			/* no current request, use client's request */
			curr_xfer_reqp = (usb_opaque_t)
			    ehcip->ehci_root_hub.rh_client_intr_reqp;

			ehcip->ehci_root_hub.rh_client_intr_reqp = NULL;
		}
		ehcip->ehci_root_hub.rh_intr_pipe_state = pipe_state;
		break;
	}

	ASSERT(curr_xfer_reqp != NULL);

	mutex_exit(&ehcip->ehci_int_mutex);
	usba_hcdi_cb(ph, curr_xfer_reqp, completion_reason);
	mutex_enter(&ehcip->ehci_int_mutex);
}
