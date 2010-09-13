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
 * Universal Serial BUS  Host Controller Driver (UHCI)
 *
 * The UHCI driver is a driver which interfaces to the Universal
 * Serial Bus Architecture (USBA) and the Host Controller (HC). The interface to
 * the Host Controller is defined by the Universal Host Controller Interface.
 * This file contains the code for root hub related functions.
 */
#include <sys/usb/hcd/uhci/uhcid.h>
#include <sys/usb/hcd/uhci/uhci.h>
#include <sys/usb/hcd/uhci/uhcihub.h>

/*
 *  Function Prototypes
 */
static int	uhci_handle_set_clear_port_feature(
			uhci_state_t		*uhcip,
			uchar_t			bRequest,
			uint16_t		wValue,
			usb_port_t		port);
static	void	uhci_handle_port_power(
			uhci_state_t		*uhcip,
			usb_port_t		port,
			uint_t			on);
static	void	uhci_handle_port_suspend(
			uhci_state_t		*uhcip,
			usb_port_t		port,
			uint_t			on);
static	void	uhci_handle_port_enable_disable(
			uhci_state_t		*uhcip,
			usb_port_t		port,
			uint_t			on);
static	void	uhci_handle_port_reset(
			uhci_state_t		*uhcip,
			usb_port_t		port);
static	void	uhci_handle_complete_port_reset(
			uhci_state_t		*uhcip,
			usb_port_t		port);
static	void	uhci_handle_clear_port_connection(
			uhci_state_t		*uhcip,
			usb_port_t		port);
static	void	uhci_handle_get_port_status(
			uhci_state_t		*uhcip,
			usb_ctrl_req_t		*req,
			usb_port_t		port);
static	void	uhci_handle_get_hub_descriptor(
			uhci_state_t		*uhcip,
			usb_ctrl_req_t		*req);
static void	uhci_handle_get_hub_status(
			uhci_state_t		*uhcip,
			usb_ctrl_req_t		*req);
static void	uhci_handle_get_device_status(
			uhci_state_t		*uhcip,
			usb_ctrl_req_t		*req);
static uint_t	uhci_get_port_status(
			uhci_state_t		*uhcip,
			usb_port_t		port);
static	void	uhci_rh_hcdi_callback(
			uhci_state_t		*uhcip,
			usba_pipe_handle_data_t	*ph,
			usb_opaque_t		req,
			usb_cr_t		cr);

/*
 * root hub device descriptor
 */
static usb_dev_descr_t uhci_rh_dev_descr = {
	0x12,	/* Length */
	1,	/* Type */
	0x110,	/* BCD - v1.1 */
	9,	/* Class */
	0,	/* Sub class */
	0,	/* Protocol */
	8,	/* Max pkt size */
	0,	/* Vendor */
	0,	/* Product id */
	0,	/* Device release */
	0,	/* Manufacturer */
	0,	/* Product */
	0,	/* Sn */
	1	/* No of configs */
};

/*
 * root hub config descriptor
 */
static uchar_t uhci_rh_config_descr[] = {
	/* config descriptor */
	0x09,		/* bLength */
	0x02,		/* bDescriptorType, Configuration */
	0x19, 0x00,	/* wTotalLength */
	0x01,		/* bNumInterfaces */
	0x01,		/* bConfigurationValue */
	0x00,		/* iConfiguration */
	0x40,		/* bmAttributes */
	0x00,		/* MaxPower */

	/* interface descriptor */
	0x09,		/* bLength */
	0x04,		/* bDescriptorType, Interface */
	0x00,		/* bInterfaceNumber */
	0x00,		/* bAlternateSetting */
	0x01,		/* bNumEndpoints */
	0x09,		/* bInterfaceClass */
	0x01,		/* bInterfaceSubClass */
	0x00,		/* bInterfaceProtocol */
	0x00,		/* iInterface */

	/* endpoint descriptor */
	0x07,		/* bLength */
	0x05,		/* bDescriptorType, Endpoint */
	0x81,		/* bEndpointAddress */
	0x03,		/* bmAttributes */
	0x01, 0x00,	/* wMaxPacketSize, 1 +	(OHCI_MAX_RH_PORTS / 8) */
	0x20		/* bInterval */
};


/*
 * uhci_init_root_hub:
 *	Initialize the root hub
 */
int
uhci_init_root_hub(uhci_state_t *uhcip)
{
	int		i, length;
	usb_hub_descr_t	*root_hub_descr = &uhcip->uhci_root_hub.rh_descr;

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, uhcip->uhci_log_hdl,
	    "uhci_init_root_hub:");

	uhcip->uhci_root_hub.rh_num_ports = MAX_RH_PORTS;

	/*
	 * Build the hub descriptor
	 */
	root_hub_descr->bDescriptorType = ROOT_HUB_DESCRIPTOR_TYPE;
	root_hub_descr->bNbrPorts	= MAX_RH_PORTS;

	length = root_hub_descr->bNbrPorts / 8;
	if (length) {
		root_hub_descr->bDescLength = 7 + (2 * (length + 1));
	} else {
		root_hub_descr->bDescLength = ROOT_HUB_DESCRIPTOR_LENGTH;
	}

	/* Determine the Power Switching Mode */
	root_hub_descr->bPwrOn2PwrGood = 10; /* arbitrary number */
	root_hub_descr->wHubCharacteristics =
	    HUB_CHARS_NO_POWER_SWITCHING|HUB_CHARS_NO_OVER_CURRENT;

	/* Indicate if the device is removable */
	root_hub_descr->DeviceRemovable = 0x0;

	/* Fill in the port power control mask */
	root_hub_descr->PortPwrCtrlMask = 0xff;

	for (i = 0; i < uhcip->uhci_root_hub.rh_num_ports; i++) {
		uhcip->uhci_root_hub.rh_port_state[i]  = DISCONNECTED;
		uhcip->uhci_root_hub.rh_port_status[i] = 0;
		uhcip->uhci_root_hub.rh_port_changes[i] = 0;
	}

	/* Finally load the root hub driver */
	return (usba_hubdi_bind_root_hub(uhcip->uhci_dip, uhci_rh_config_descr,
	    sizeof (uhci_rh_config_descr), &uhci_rh_dev_descr));
}


/*
 * uhci_handle_root_hub_request:
 *	Intercept a root hub request.
 *	Handle the  root hub request through the registers
 */
int
uhci_handle_root_hub_request(
	uhci_state_t		*uhcip,
	usba_pipe_handle_data_t  *pipe_handle,
	usb_ctrl_req_t		*req)
{
	int		error = USB_SUCCESS;
	uint16_t	port = req->ctrl_wIndex - 1;
	usb_cr_t	completion_reason;

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, uhcip->uhci_log_hdl,
	    "uhci_handle_root_hub_request: 0x%x 0x%x 0x%x 0x%x 0x%x 0x%p",
	    req->ctrl_bmRequestType, req->ctrl_bRequest, req->ctrl_wValue,
	    req->ctrl_wIndex, req->ctrl_wLength, (void *)req->ctrl_data);

	ASSERT(mutex_owned(&uhcip->uhci_int_mutex));

	switch (req->ctrl_bmRequestType) {
	case HUB_GET_DEVICE_STATUS_TYPE:
		uhci_handle_get_device_status(uhcip, req);

		break;
	case HUB_HANDLE_PORT_FEATURE_TYPE:
		error = uhci_handle_set_clear_port_feature(uhcip,
		    req->ctrl_bRequest, req->ctrl_wValue, port);

		break;
	case HUB_GET_PORT_STATUS_TYPE:
		uhci_handle_get_port_status(uhcip, req, port);

		break;
	case HUB_CLASS_REQ_TYPE:
		switch (req->ctrl_bRequest) {
		case USB_REQ_GET_DESCR:
			uhci_handle_get_hub_descriptor(uhcip, req);

			break;
		case USB_REQ_GET_STATUS:
			uhci_handle_get_hub_status(uhcip, req);

			break;
		default:
			USB_DPRINTF_L2(PRINT_MASK_ROOT_HUB, uhcip->uhci_log_hdl,
			    "uhci_handle_root_hub_request: Unsupported "
			    "request 0x%x", req->ctrl_bmRequestType);

			break;
		}

		break;
	default:
		USB_DPRINTF_L2(PRINT_MASK_ROOT_HUB, uhcip->uhci_log_hdl,
		    "uhci_handle_root_hub_request: Unsupported request 0x%x",
		    req->ctrl_bmRequestType);

		break;
	}

	completion_reason = (error != USB_SUCCESS) ?
	    USB_CR_NOT_SUPPORTED : USB_CR_OK;

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, uhcip->uhci_log_hdl,
	    "uhci_handle_root_hub_request: error = %d", error);

	uhci_rh_hcdi_callback(uhcip, pipe_handle, (usb_opaque_t)req,
	    completion_reason);

	return (USB_SUCCESS);
}


/*
 * uhci_handle_set_clear_port_feature:
 */
static int
uhci_handle_set_clear_port_feature(
	uhci_state_t		*uhcip,
	uchar_t			bRequest,
	uint16_t		wValue,
	usb_port_t		port)
{
	int    error = USB_SUCCESS;

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, uhcip->uhci_log_hdl,
	    "uhci_handle_set_clear_port_feature: 0x%x 0x%x 0x%x",
	    bRequest, wValue, port);

	switch (bRequest) {
	case USB_REQ_SET_FEATURE:
		switch (wValue) {
		case CFS_PORT_ENABLE:
			uhci_handle_port_enable_disable(uhcip,
			    port, UHCI_ENABLE_PORT);
			break;
		case CFS_PORT_SUSPEND:
			uhci_handle_port_suspend(uhcip, port, 1);

			break;
		case CFS_PORT_RESET:
			uhci_handle_port_reset(uhcip, port);

			break;
		case CFS_PORT_POWER:
			uhci_handle_port_power(uhcip, port,
			    UHCI_ENABLE_PORT_PWR);
			break;

		default:
			USB_DPRINTF_L2(PRINT_MASK_ROOT_HUB, uhcip->uhci_log_hdl,
			    "uhci_handle_set_clear_port_feature: "
			    "Unsupported request 0x%x 0x%x", bRequest, wValue);
			error = USB_FAILURE;

			break;
		}

		break;
	case USB_REQ_CLEAR_FEATURE:
		switch (wValue) {
		case CFS_PORT_ENABLE:
			uhci_handle_port_enable_disable(uhcip,
			    port, UHCI_DISABLE_PORT);

			break;
		case CFS_C_PORT_ENABLE:
			uhci_handle_port_enable_disable(uhcip,
			    port, UHCI_CLEAR_ENDIS_BIT);

			break;
		case CFS_PORT_SUSPEND:
			uhci_handle_port_suspend(uhcip, port, 0);

			break;
		case CFS_C_PORT_RESET:
			uhci_handle_complete_port_reset(uhcip, port);

			break;
		case CFS_PORT_POWER:
			uhci_handle_port_power(uhcip, port,
			    UHCI_DISABLE_PORT_PWR);

			break;
		case CFS_C_PORT_CONNECTION:
			uhci_handle_clear_port_connection(uhcip, port);

			break;
		default:
			USB_DPRINTF_L2(PRINT_MASK_ROOT_HUB, uhcip->uhci_log_hdl,
			    "uhci_handle_set_clear_port_feature: "
			    "Unsupported request 0x%x 0x%x", bRequest, wValue);
			error = USB_FAILURE;

			break;
		}

		break;
	default:
		USB_DPRINTF_L2(PRINT_MASK_ROOT_HUB, uhcip->uhci_log_hdl,
		    "uhci_handle_set_clear_port_feature: "
		    "Unsupported request 0x%x 0x%x", bRequest, wValue);
		error = USB_FAILURE;
	}


	return (error);
}


/*
 * uhci_handle_port_suspend:
 */
static void
uhci_handle_port_suspend(
	uhci_state_t		*uhcip,
	usb_port_t		port,
	uint_t			on)
{
	uint_t	port_status = Get_OpReg16(PORTSC[port]);

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, uhcip->uhci_log_hdl,
	    "uhci_handle_port_suspend: port=%d on=%d",
	    port, on);

	if (on) {
		/* See if the port suspend is already on */
		if (!(port_status & HCR_PORT_SUSPEND)) {
			/* suspend the port */
			Set_OpReg16(PORTSC[port],
			    (port_status | HCR_PORT_SUSPEND));
		}
	} else {
		/* See if the port suspend is already off */
		if ((port_status & HCR_PORT_SUSPEND)) {
			/* resume the port */
			Set_OpReg16(PORTSC[port],
			    (port_status & ~HCR_PORT_SUSPEND));
		}
	}
}


/*
 * uhci_handle_port_power:
 *	Turn on a root hub port.  NOTE: Driver does not have any control
 *	over the power status.
 */
/* ARGSUSED */
static void
uhci_handle_port_power(
	uhci_state_t		*uhcip,
	usb_port_t		port,
	uint_t			on)
{
	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, uhcip->uhci_log_hdl,
	    "uhci_handle_port_power: nothing to do");
}


/*
 * uhci_handle_port_enable_disable:
 *	Handle port enable request.
 */
static void
uhci_handle_port_enable_disable(
	uhci_state_t		*uhcip,
	usb_port_t		port,
	uint_t			action)
{
	uint_t	port_status = Get_OpReg16(PORTSC[port]);

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, uhcip->uhci_log_hdl,
	    "uhci_handle_port_enable: port = 0x%x, status = 0x%x",
	    port, port_status);

	if (action == UHCI_ENABLE_PORT) {
		/* See if the port enable is already on */
		if (!(port_status & HCR_PORT_ENABLE)) {
			/* Enable the port */
			Set_OpReg16(PORTSC[port],
			    (port_status | HCR_PORT_ENABLE));
		}
	} else if (action == UHCI_DISABLE_PORT) {
		/* See if the port enable is already off */
		if ((port_status & HCR_PORT_ENABLE)) {
			/* Disable the port */
			Set_OpReg16(PORTSC[port],
			    (port_status & ~HCR_PORT_ENABLE));
		}
	} else {
		/* Clear the Enable/Disable change bit */
		Set_OpReg16(PORTSC[port], (port_status | HCR_PORT_ENDIS_CHG));

		/* Update software port_changes register */
		uhcip->uhci_root_hub.rh_port_changes[port] &= ~PORT_CHANGE_PESC;
	}
}


/*
 * uhci_root_hub_reset_occurred:
 *	Inform the upper layer that reset has occured on the port.
 *	This is required because the upper layer is expecting an
 *	event immediately after doing a reset. In case of OHCI
 *	the HC gets an interrupt for the change in the root hub
 *	status, but in case of UHCI we don't. So, we send an
 *	event to the upper layer as soon as we complete the reset
 *	as long as the root hub pipe is polling.
 */
void
uhci_root_hub_reset_occurred(
	uhci_state_t	*uhcip,
	uint16_t	port)
{
	usb_intr_req_t	*intr_reqp = uhcip->uhci_root_hub.rh_curr_intr_reqp;

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, uhcip->uhci_log_hdl,
	    "uhci_root_hub_reset_occurred: intr_reqp = 0x%p data = 0x%p",
	    (void *)intr_reqp, (void *)intr_reqp->intr_data);

	*intr_reqp->intr_data->b_wptr++ = (1 << (port+1));

	uhci_rh_hcdi_callback(uhcip, uhcip->uhci_root_hub.rh_intr_pipe_handle,
	    (usb_opaque_t)intr_reqp, USB_CR_OK);
}


/*
 * uhci_handle_port_reset:
 *	Perform a port reset.
 */
static void
uhci_handle_port_reset(
	uhci_state_t		*uhcip,
	usb_port_t		port)
{
	uint_t	port_status = Get_OpReg16(PORTSC[port]);

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, uhcip->uhci_log_hdl,
	    "uhci_handle_port_reset: port = 0x%x, status = 0x%x",
	    port, port_status);

	if (!(port_status & HCR_PORT_CCS)) {
		USB_DPRINTF_L3(PRINT_MASK_ROOT_HUB, uhcip->uhci_log_hdl,
		    "port_status & HCR_PORT_CCS == 0: "
		    "port = 0x%x, status = 0x%x", port, port_status);
	}

	Set_OpReg16(PORTSC[port], (port_status| HCR_PORT_RESET));

	drv_usecwait(UHCI_RESET_DELAY);

	Set_OpReg16(PORTSC[port], (port_status & ~HCR_PORT_RESET));

	drv_usecwait(UHCI_RESET_DELAY/100);

	Set_OpReg16(PORTSC[port], (port_status| HCR_PORT_ENABLE));

	/*
	 * The next function is only called if the interrupt pipe
	 * is polling and the USBA is ready to receive the
	 * data. If not, we could panic.
	 */
	if (uhcip->uhci_root_hub.rh_pipe_state != UHCI_PIPE_STATE_ACTIVE) {
		/* make a note that we need to send status back */
		uhcip->uhci_root_hub.rh_status = port + 1;
	} else {
		uhci_root_hub_reset_occurred(uhcip, port);
	}
}


/*
 * uhci_handle_complete_port_reset:
 *	Perform a port reset change.
 */
static void
uhci_handle_complete_port_reset(
	uhci_state_t		*uhcip,
	usb_port_t		port)
{
	uint_t port_status = Get_OpReg16(PORTSC[port]);

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, uhcip->uhci_log_hdl,
	    "uhci_handle_complete_port_reset: port = 0x%x status = 0x%x",
	    port, port_status);

	if (!(port_status & HCR_PORT_CCS)) {
		USB_DPRINTF_L3(PRINT_MASK_ROOT_HUB, uhcip->uhci_log_hdl,
		    "port_status & HCR_PORT_CCS == 0: "
		    "port = 0x%x, status = 0x%x", port, port_status);
	}

	Set_OpReg16(PORTSC[port], (port_status & (~ HCR_PORT_RESET)));

	/* Update software port_changes register */
	uhcip->uhci_root_hub.rh_port_changes[port] &= ~PORT_CHANGE_PRSC;
}


/*
 * uhci_handle_clear_port_connection:
 *	Perform a clear port connection.
 */
static void
uhci_handle_clear_port_connection(
	uhci_state_t		*uhcip,
	usb_port_t		port)
{
	uint_t port_status = Get_OpReg16(PORTSC[port]);

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, uhcip->uhci_log_hdl,
	    "uhci_handle_clear_port_connection: port = 0x%x status = 0x%x",
	    port, port_status);

	/* Clear CSC bit */
	Set_OpReg16(PORTSC[port], port_status | HCR_PORT_CSC);

	/* Update software port_changes register */
	uhcip->uhci_root_hub.rh_port_changes[port] &= ~PORT_CHANGE_CSC;
}


/*
 * uhci_handle_get_port_status:
 *	Handle a get port status request.
 */
static void
uhci_handle_get_port_status(
	uhci_state_t		*uhcip,
	usb_ctrl_req_t		*req,
	usb_port_t		port)
{
	uint_t		new_port_status;
	uint_t		old_port_status =
	    uhcip->uhci_root_hub.rh_port_status[port];
	uint_t		old_port_changes =
	    uhcip->uhci_root_hub.rh_port_changes[port];
	uint_t		change_status;
	usb_ctrl_req_t	*ctrl_reqp = (usb_ctrl_req_t *)req;
	uint16_t	wLength = req->ctrl_wLength;

	ASSERT(wLength == 4);
	ASSERT(ctrl_reqp->ctrl_data != NULL);

	/* Read the current port status and return it */
	new_port_status = uhci_get_port_status(uhcip, port);
	change_status	= (old_port_status ^ new_port_status) & 0xff;
	change_status	|= old_port_changes;

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, uhcip->uhci_log_hdl,
	    "uhci_handle_get_port_status:\n\t"
	    "port%d: old status = 0x%x	new status = 0x%x change = 0x%x",
	    port, old_port_status, new_port_status, change_status);

	*ctrl_reqp->ctrl_data->b_wptr++ = (uchar_t)new_port_status;
	*ctrl_reqp->ctrl_data->b_wptr++ = (uchar_t)(new_port_status >> 8);
	*ctrl_reqp->ctrl_data->b_wptr++ = (uchar_t)change_status;
	*ctrl_reqp->ctrl_data->b_wptr++ = (uchar_t)(change_status >> 8);

	/* Update the status */
	uhcip->uhci_root_hub.rh_port_status[port] = new_port_status;
	uhcip->uhci_root_hub.rh_port_changes[port] = change_status;
}


/*
 * uhci_handle_get_hub_descriptor:
 */
static void
uhci_handle_get_hub_descriptor(
	uhci_state_t		*uhcip,
	usb_ctrl_req_t		*req)
{
	uchar_t		raw_descr[ROOT_HUB_DESCRIPTOR_LENGTH];
	usb_hub_descr_t	*root_hub_descr = &uhcip->uhci_root_hub.rh_descr;

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, uhcip->uhci_log_hdl,
	    "uhci_handle_get_hub_descriptor: wLength = 0x%x",
	    req->ctrl_wLength);

	ASSERT(req->ctrl_wLength != 0);
	ASSERT(req->ctrl_data != NULL);

	bzero(&raw_descr, ROOT_HUB_DESCRIPTOR_LENGTH);

	raw_descr[0] = root_hub_descr->bDescLength;
	raw_descr[1] = root_hub_descr->bDescriptorType;
	raw_descr[2] = root_hub_descr->bNbrPorts;
	raw_descr[3] = root_hub_descr->wHubCharacteristics & 0x00ff;
	raw_descr[4] = (root_hub_descr->wHubCharacteristics & 0xff00) >> 8;
	raw_descr[5] = root_hub_descr->bPwrOn2PwrGood;
	raw_descr[6] = root_hub_descr->bHubContrCurrent;
	raw_descr[7] = root_hub_descr->DeviceRemovable;
	raw_descr[8] = root_hub_descr->PortPwrCtrlMask;

	bcopy(raw_descr, req->ctrl_data->b_wptr, req->ctrl_wLength);
	req->ctrl_data->b_wptr += req->ctrl_wLength;
}


/*
 * uhci_handle_get_hub_status:
 */
static void
uhci_handle_get_hub_status(
	uhci_state_t		*uhcip,
	usb_ctrl_req_t		*req)
{

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, uhcip->uhci_log_hdl,
	    "uhci_handle_get_hub_status: wLength = 0x%x",
	    req->ctrl_wLength);
	ASSERT(req->ctrl_wLength != 0);
	ASSERT(req->ctrl_data != NULL);

	/*
	 * A good status is always sent because there is no way that
	 * the driver can get to know about the status change of the
	 * over current or power failure of the root hub from the HC.
	 */
	bzero(req->ctrl_data->b_wptr, req->ctrl_wLength);
	req->ctrl_data->b_wptr += req->ctrl_wLength;
}


/*
 * uhci_handle_get_device_status:
 */
static void
uhci_handle_get_device_status(
	uhci_state_t		*uhcip,
	usb_ctrl_req_t		*req)
{
	uint16_t	dev_status;

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, uhcip->uhci_log_hdl,
	    "uhci_handle_get_device_status: wLength = 0x%x",
	    req->ctrl_wLength);

	ASSERT(req->ctrl_wLength != 0);
	ASSERT(req->ctrl_data != NULL);

	/*
	 * UHCI doesn't have device status information.
	 * Simply return what is desired for the request.
	 */
	dev_status = USB_DEV_SLF_PWRD_STATUS;

	*req->ctrl_data->b_wptr++ = (uchar_t)dev_status;
	*req->ctrl_data->b_wptr++ = (uchar_t)(dev_status >> 8);
}


/*
 * uhci_handle_root_hub_status_change:
 *	This function is called every 256 ms from the time out handler.
 *	It checks for the status change of the root hub and its ports.
 */
void
uhci_handle_root_hub_status_change(void *arg)
{
	usb_port_t	port;
	uint_t		old_port_status;
	uint_t		new_port_status;
	ushort_t	port_status;
	uint_t		change_status;
	uchar_t		all_ports_status = 0;
	uhci_state_t	*uhcip = (uhci_state_t *)arg;
	usb_intr_req_t	*curr_intr_reqp;

	mutex_enter(&uhcip->uhci_int_mutex);

	/* reset the timeout id */
	uhcip->uhci_timeout_id = 0;

	/* Get the current interrupt request pointer */
	curr_intr_reqp = uhcip->uhci_root_hub.rh_curr_intr_reqp;

	/* Check each port */
	for (port = 0; port < uhcip->uhci_root_hub.rh_num_ports; port++) {
		new_port_status = uhci_get_port_status(uhcip, port);
		old_port_status = uhcip->uhci_root_hub.rh_port_status[port];

		change_status = (old_port_status ^ new_port_status) & 0xff;
		change_status |= uhcip->uhci_root_hub.rh_port_changes[port];

		/* See if a device was attached/detached */
		if (change_status & PORT_STATUS_CCS) {
			all_ports_status |= 1 << (port + 1);
		}

		port_status = Get_OpReg16(PORTSC[port]);
		Set_OpReg16(PORTSC[port], port_status | HCR_PORT_ENDIS_CHG);

		uhcip->uhci_root_hub.rh_port_status[port] = new_port_status;
		uhcip->uhci_root_hub.rh_port_changes[port] = change_status;

		USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, uhcip->uhci_log_hdl,
		    "port %d old status 0x%x new status 0x%x change 0x%x\n\t"
		    "all_ports_status = 0x%x", port, old_port_status,
		    new_port_status, change_status, all_ports_status);
	}

	if (uhcip->uhci_root_hub.rh_intr_pipe_handle &&
	    all_ports_status && curr_intr_reqp &&
	    (uhcip->uhci_root_hub.rh_pipe_state == UHCI_PIPE_STATE_ACTIVE)) {

		ASSERT(curr_intr_reqp->intr_data != NULL);

		*curr_intr_reqp->intr_data->b_wptr++ = all_ports_status;

		uhci_rh_hcdi_callback(uhcip,
		    uhcip->uhci_root_hub.rh_intr_pipe_handle,
		    (usb_opaque_t)curr_intr_reqp, USB_CR_OK);
	}

	if (uhcip->uhci_root_hub.rh_pipe_state == UHCI_PIPE_STATE_ACTIVE) {
		/*
		 * If needed, allocate new interrupt request. Also
		 * start the timer for the root hub interrupt polling.
		 */
		if (uhci_root_hub_allocate_intr_pipe_resource(uhcip, 0) !=
		    USB_SUCCESS) {

			/* Do interrupt pipe cleanup */
			uhci_root_hub_intr_pipe_cleanup(uhcip,
			    USB_CR_NO_RESOURCES);
		}
	}

	mutex_exit(&uhcip->uhci_int_mutex);
}


static uint_t
uhci_get_port_status(
	uhci_state_t	*uhcip,
	usb_port_t	port)
{
	uint_t		new_port_status = PORT_STATUS_PPS;
	ushort_t	port_status = Get_OpReg16(PORTSC[port]);

	if (port_status & HCR_PORT_CCS) {
		new_port_status |= PORT_STATUS_CCS;
	}

	if (port_status & HCR_PORT_LSDA) {
		new_port_status |= PORT_STATUS_LSDA;
	}

	if (port_status & HCR_PORT_ENABLE) {
		new_port_status |= PORT_STATUS_PES;
	}

	if (port_status & HCR_PORT_SUSPEND) {
		new_port_status |= PORT_STATUS_PSS;
	}

	if (port_status & HCR_PORT_RESET) {
		new_port_status |= PORT_STATUS_PRS;
	}

	return (new_port_status);
}


/*
 * uhci_root_hub_allocate_intr_pipe_resource:
 *	Allocate interrupt requests and initialize them.
 */
int
uhci_root_hub_allocate_intr_pipe_resource(
	uhci_state_t	*uhcip,
	usb_flags_t	flags)
{
	usb_intr_req_t		*curr_intr_reqp;
	usba_pipe_handle_data_t	*ph;

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, uhcip->uhci_log_hdl,
	    "uhci_root_hub_allocate_intr_pipe_resource:");

	ASSERT(mutex_owned(&uhcip->uhci_int_mutex));

	/* Get the interrupt pipe handle */
	ph = uhcip->uhci_root_hub.rh_intr_pipe_handle;

	/* Get the current interrupt request pointer */
	curr_intr_reqp = uhcip->uhci_root_hub.rh_curr_intr_reqp;

	/*
	 * If current interrupt request pointer is null,
	 * allocate new interrupt request.
	 */
	if (curr_intr_reqp == NULL) {
		ASSERT(uhcip->uhci_root_hub.rh_client_intr_req);

		if ((curr_intr_reqp = usba_hcdi_dup_intr_req(ph->p_dip,
		    uhcip->uhci_root_hub.rh_client_intr_req,
		    uhcip->uhci_root_hub.rh_client_intr_req->intr_len,
		    flags)) == NULL) {
			USB_DPRINTF_L2(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
			    "uhci_root_hub_allocate_intr_pipe_resource:"
			    "Interrupt request structure allocation failed");

			return (USB_NO_RESOURCES);
		}

		uhcip->uhci_root_hub.rh_curr_intr_reqp = curr_intr_reqp;

		mutex_enter(&ph->p_mutex);
		ph->p_req_count++;
		mutex_exit(&ph->p_mutex);
	}

	if (uhcip->uhci_timeout_id == 0) {
		uhcip->uhci_timeout_id = timeout(
		    uhci_handle_root_hub_status_change,
		    (void *)uhcip, UHCI_256_MS);
		uhcip->uhci_root_hub.rh_pipe_state =
		    UHCI_PIPE_STATE_ACTIVE;
	}

	return (USB_SUCCESS);
}


/*
 * uhci_root_hub_intr_pipe_cleanup:
 *	Deallocate all interrupt requests and do callback
 *	the original client interrupt request.
 */
void
uhci_root_hub_intr_pipe_cleanup(uhci_state_t *uhcip, usb_cr_t cr)
{
	usb_intr_req_t		*curr_intr_reqp;
	usb_opaque_t		client_intr_reqp;
	usba_pipe_handle_data_t	*ph;
	timeout_id_t		timer_id;

	USB_DPRINTF_L4(PRINT_MASK_ROOT_HUB, uhcip->uhci_log_hdl,
	    "uhci_root_hub_intr_pipe_cleanup:");

	ASSERT(mutex_owned(&uhcip->uhci_int_mutex));

	/* Get the interrupt pipe handle */
	ph = uhcip->uhci_root_hub.rh_intr_pipe_handle;

	/* Get the interrupt timerid */
	timer_id = uhcip->uhci_timeout_id;

	/* Stop the root hub interrupt timer */
	if (timer_id) {

		/* Reset the timer id to zero */
		uhcip->uhci_timeout_id = 0;
		uhcip->uhci_root_hub.rh_pipe_state =
		    UHCI_PIPE_STATE_IDLE;

		mutex_exit(&uhcip->uhci_int_mutex);
		(void) untimeout(timer_id);
		mutex_enter(&uhcip->uhci_int_mutex);
	}

	/* Reset the current interrupt request pointer */
	curr_intr_reqp = uhcip->uhci_root_hub.rh_curr_intr_reqp;

	/* Deallocate uncompleted interrupt request */
	if (curr_intr_reqp) {
		uhcip->uhci_root_hub.rh_curr_intr_reqp = NULL;
		usb_free_intr_req(curr_intr_reqp);

		mutex_enter(&ph->p_mutex);
		ph->p_req_count--;
		mutex_exit(&ph->p_mutex);
	}

	client_intr_reqp = (usb_opaque_t)
	    uhcip->uhci_root_hub.rh_client_intr_req;

	/* Callback for original client interrupt request */
	if (client_intr_reqp) {
		uhcip->uhci_root_hub.rh_client_intr_req = NULL;
		uhci_rh_hcdi_callback(uhcip, ph,
		    (usb_opaque_t)client_intr_reqp, cr);
	}
}


/*
 * uhci_rh_hcdi_callback:
 *	Convenience wrapper around usba_hcdi_cb() for the root hub.
 */
static void
uhci_rh_hcdi_callback(
	uhci_state_t		*uhcip,
	usba_pipe_handle_data_t	*ph,
	usb_opaque_t		req,
	usb_cr_t		cr)
{
	USB_DPRINTF_L4(PRINT_MASK_HCDI, uhcip->uhci_log_hdl,
	    "uhci_rh_hcdi_callback: ph=0x%p cr=0x%x req=0x%p",
	    (void *)ph, cr, (void *)req);

	ASSERT(mutex_owned(&uhcip->uhci_int_mutex));

	switch (UHCI_XFER_TYPE(&ph->p_ep)) {
	case USB_EP_ATTR_CONTROL:

		break;
	case USB_EP_ATTR_INTR:
		if ((usb_intr_req_t *)req ==
		    uhcip->uhci_root_hub.rh_curr_intr_reqp) {
			uhcip->uhci_root_hub.rh_curr_intr_reqp = NULL;

			break;
		} else if ((usb_intr_req_t *)req ==
		    uhcip->uhci_root_hub.rh_client_intr_req) {
			uhcip->uhci_root_hub.rh_client_intr_req = NULL;

			break;
		}
		/*FALLTHRU*/
	default:
		ASSERT(req);
		break;
	}

	mutex_exit(&uhcip->uhci_int_mutex);
	usba_hcdi_cb(ph, req, cr);
	mutex_enter(&uhcip->uhci_int_mutex);
}
