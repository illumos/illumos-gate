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

/*
 * xHCI Root Hub
 *
 * Please see the big theory statement in xhci.c for more information.
 */

#include <sys/usb/hcd/xhci/xhci.h>

/*
 * The following structure and global define the default configuration that we
 * 'deliver' to USBA on behalf of our hub. However, it's worth noting that it's
 * going to take this in as an array of bytes off of the wire, whereas we're
 * declaring this as a packed C structure to make our life much, much easier.
 * It is critical that we pay attention to the endianness of anything that is
 * more than a single byte wide and write the value in the appropriate
 * endian-aware form.
 *
 * Note, we don't use the system structures for these values because they are
 * not packed, and we must be. Even though we define all members, we still use
 * C99 structure initialization to make it easier for folks to see what values
 * are what in a long array of numbers.
 *
 * The structure is laid out first with members that make up a usb_cfg_descr_t.
 * Then it has a usb_if_descr_t. After that, it has a usb_ep_descr_t and finally
 * a usb_ep_ss_comp_descr_t. Please see the original structure definitions for
 * the meaning of each member.
 *
 * Many of the values used below were derived from the USB 3.1/10.15.1 'Standard
 * Descriptors for Hub Class'.
 */
#pragma pack(1)
typedef struct xhci_dev_conf {
	/* usb_cfg_descr_t */
	uint8_t		xdc_cfg_bLength;
	uint8_t		xdc_cfg_bDescriptorType;
	uint16_t	xdc_cfg_wTotalLength;
	uint8_t		xdc_cfg_bNumInterfaces;
	uint8_t		xdc_cfg_bConfigurationValue;
	uint8_t		xdc_cfg_iConfiguration;
	uint8_t		xdc_cfg_bmAttributes;
	uint8_t		xdc_cfg_bMaxPower;
	/* usb_if_descr_t */
	uint8_t		xdc_if_bLength;
	uint8_t		xdc_if_bDescriptorType;
	uint8_t		xdc_if_bInterfaceNumber;
	uint8_t		xdc_if_bAlternateSetting;
	uint8_t		xdc_if_bNumEndpoints;
	uint8_t		xdc_if_bInterfaceClass;
	uint8_t		xdc_if_bInterfaceSubClass;
	uint8_t		xdc_if_bInterfaceProtocol;
	uint8_t		xdc_if_iInterface;
	/* usb_ep_descr_t */
	uint8_t		xdc_ep_bLength;
	uint8_t		xdc_ep_bDescriptorType;
	uint8_t		xdc_ep_bEndpointAddress;
	uint8_t		xdc_ep_bmAttributes;
	uint16_t	xdc_ep_wMaxPacketSize;
	uint8_t		xdc_ep_bInterval;
	/* usb_ep_ss_comp_descr_t */
	uint8_t		xdc_epssc_bLength;
	uint8_t		xdc_epssc_bDescriptorType;
	uint8_t		xdc_epssc_bMaxBurst;
	uint8_t		xdc_epssc_bmAttributes;
	uint16_t	xdc_epssc_wBytesPerInterval;
} xhci_dev_conf_t;
#pragma pack()

#if MAX_PORTS != 31
#error	"MAX_PORTS has changed, update xdc_ep_wMaxPacketSize"
#endif

xhci_dev_conf_t xhci_hcdi_conf = {
	.xdc_cfg_bLength = 0x9,
	.xdc_cfg_bDescriptorType = USB_DESCR_TYPE_CFG,
#if defined(_BIG_ENDIAN)
	.xdc_cfg_wTotalLength = 0x1f00,
#elif defined(_LITTLE_ENDIAN)
	.xdc_cfg_wTotalLength = 0x001f,
#else	/* !_BIG_ENDIAN && !_LITTLE_ENDIAN */
#error	"Unknown endianness"
#endif /* _BIG_ENDIAN */
	.xdc_cfg_bNumInterfaces = 0x1,
	.xdc_cfg_bConfigurationValue = 0x1,
	.xdc_cfg_iConfiguration = 0x0,
	.xdc_cfg_bmAttributes = 0x40,
	.xdc_cfg_bMaxPower = 0x0,

	.xdc_if_bLength = 0x9,
	.xdc_if_bDescriptorType = USB_DESCR_TYPE_IF,
	.xdc_if_bInterfaceNumber = 0x0,
	.xdc_if_bAlternateSetting = 0x0,
	.xdc_if_bNumEndpoints = 0x1,
	.xdc_if_bInterfaceClass = USB_CLASS_HUB,
	.xdc_if_bInterfaceSubClass = 0x0,
	.xdc_if_bInterfaceProtocol = 0x0,
	.xdc_if_iInterface = 0x0,

	.xdc_ep_bLength = 0x7,
	.xdc_ep_bDescriptorType = USB_DESCR_TYPE_EP,
	.xdc_ep_bEndpointAddress = USB_EP_DIR_IN | ROOT_HUB_ADDR,
	.xdc_ep_bmAttributes = USB_EP_ATTR_INTR,

	/*
	 * We size the endpoint's maximum packet size based on the total number
	 * of ports that exist. This allows us to ensure that we can always
	 * deliver a status bit for every port, even if we're not strictly
	 * playing by the rules and have more than 16 ports. The system defines
	 * MAX_PORTS to be 31, therefore we set this to four, so we cover it
	 * all.
	 */
#if defined(_BIG_ENDIAN)
	.xdc_ep_wMaxPacketSize = 0x0400,
#elif defined(_LITTLE_ENDIAN)
	.xdc_ep_wMaxPacketSize = 0x0004,
#else	/* !_BIG_ENDIAN && !_LITTLE_ENDIAN */
#error	"Unknown endianness"
#endif /* _BIG_ENDIAN */
	.xdc_ep_bInterval = 0x8,

	.xdc_epssc_bLength = 0x06,
	.xdc_epssc_bDescriptorType = USB_DESCR_TYPE_SS_EP_COMP,
	.xdc_epssc_bMaxBurst = 0,
	.xdc_epssc_bmAttributes = 0,
#if defined(_BIG_ENDIAN)
	.xdc_epssc_wBytesPerInterval = 0x0200
#elif defined(_LITTLE_ENDIAN)
	.xdc_epssc_wBytesPerInterval = 0x0002
#else	/* !_BIG_ENDIAN && !_LITTLE_ENDIAN */
#error	"Unknown endianness"
#endif /* _BIG_ENDIAN */
};

/*
 * This is a standard device request as defined in USB 3.1 / 9.4.5.
 */
static int
xhci_root_hub_get_device_status(xhci_t *xhcip, usb_ctrl_req_t *ucrp)
{
	uint16_t stand;
	uint32_t psm;
	uint8_t len;
	mblk_t *mp;

	ASSERT(MUTEX_HELD(&xhcip->xhci_lock));

	mp = ucrp->ctrl_data;

	/*
	 * In the case where the request write length doesn't match what we
	 * expect, we still return that this is 'OK'; however, we don't
	 * increment the length, allowing the caller to basically see that we
	 * have no data / failed it. The behavior in this case is defined to be
	 * undefined and unfortuantely there's no great return value here for
	 * EINVAL.
	 */
	switch (ucrp->ctrl_wValue) {
	case USB_GET_STATUS_STANDARD:
		if (ucrp->ctrl_wLength != USB_GET_STATUS_LEN)
			return (USB_CR_UNSPECIFIED_ERR);
		len = USB_GET_STATUS_LEN;
		stand = LE_16(USB_DEV_SLF_PWRD_STATUS);
		bcopy(&stand, mp->b_wptr, sizeof (stand));
		break;
	case USB_GET_STATUS_PTM:
		if (ucrp->ctrl_wLength != USB_GET_STATUS_PTM_LEN)
			return (USB_CR_UNSPECIFIED_ERR);
		/*
		 * We don't support the root hub, so we always return zero.
		 */
		len = USB_GET_STATUS_PTM_LEN;
		psm = 0;
		bcopy(&psm, mp->b_wptr, sizeof (psm));
		break;
	default:
		return (USB_CR_NOT_SUPPORTED);
	}

	mp->b_wptr += len;

	return (USB_CR_OK);
}

/*
 * This is a hub class specific device request as defined in USB 3.1 /
 * 11.24.2.6.
 */
static int
xhci_root_hub_get_status(xhci_t *xhcip, usb_ctrl_req_t *ucrp)
{
	const uint32_t status = 0;
	mblk_t *mp;

	ASSERT(MUTEX_HELD(&xhcip->xhci_lock));

	if (ucrp->ctrl_wLength != HUB_GET_STATUS_LEN)
		return (USB_CR_UNSPECIFIED_ERR);
	mp = ucrp->ctrl_data;

	bcopy(&status, mp->b_wptr, sizeof (status));
	mp->b_wptr += sizeof (status);

	return (USB_CR_OK);
}

/*
 * We've been asked to get the root hub's descriptor. According to USB 3.1 /
 * 10.16.2.3 we return up to a maximum number of bytes based on the actual size
 * of the request. It's not an error for it to request more or less. e.g. we
 * only return MIN(req, sizeof (desc)).
 */
static void
xhci_root_hub_get_descriptor(xhci_t *xhcip, usb_ctrl_req_t *ucrp)
{
	int len = MIN(sizeof (usb_ss_hub_descr_t), ucrp->ctrl_wLength);

	ASSERT(MUTEX_HELD(&xhcip->xhci_lock));

	/*
	 * We maintain the root hub's description in a little-endian data format
	 * regardless of the platform. This means that we don't have to try to
	 * transform any of the data that we have inside of it when we deliver
	 * it to USBA.
	 */
	bcopy(&xhcip->xhci_usba.xa_hub_descr, ucrp->ctrl_data->b_wptr, len);
	ucrp->ctrl_data->b_wptr += len;
}

static int
xhci_root_hub_handle_port_clear_feature(xhci_t *xhcip, usb_ctrl_req_t *ucrp)
{
	int feat = ucrp->ctrl_wValue;
	int port = XHCI_PS_INDPORT(ucrp->ctrl_wIndex);
	uint32_t reg;

	ASSERT(MUTEX_HELD(&xhcip->xhci_lock));

	if (port < 1 || port > xhcip->xhci_caps.xcap_max_ports)
		return (USB_CR_UNSPECIFIED_ERR);
	if (ucrp->ctrl_wLength != 0)
		return (USB_CR_UNSPECIFIED_ERR);

	reg = xhci_get32(xhcip, XHCI_R_OPER, XHCI_PORTSC(port));
	if (xhci_check_regs_acc(xhcip) != DDI_FM_OK) {
		xhci_error(xhcip, "failed to read port status register for "
		    "port %d: encountered fatal FM error, resetting device",
		    port);
		xhci_fm_runtime_reset(xhcip);
		return (USB_CR_HC_HARDWARE_ERR);
	}

	/*
	 * The port status and command register has many bits that we must
	 * preserve across writes, however, it also has bits that will be
	 * cleared when a bitwise one is written to them. As some of these
	 * write-one-to-clear bits may be set, we make sure to mask them off.
	 */
	reg &= ~XHCI_PS_CLEAR;

	switch (feat) {
	case CFS_PORT_ENABLE:
		reg |= XHCI_PS_PED;
		break;
	case CFS_PORT_POWER:
		reg &= ~XHCI_PS_PP;
		break;
	case CFS_C_PORT_CONNECTION:
		reg |= XHCI_PS_CSC;
		break;
	case CFS_C_PORT_RESET:
		reg |= XHCI_PS_PRC;
		break;
	case CFS_C_PORT_OVER_CURRENT:
		reg |= XHCI_PS_OCC;
		break;
	case CFS_C_PORT_SUSPEND:
	case CFS_C_PORT_LINK_STATE:
		reg |= XHCI_PS_PLC;
		break;
	case CFS_C_PORT_ENABLE:
		reg |= XHCI_PS_PEC;
		break;
	case CFS_C_PORT_CONFIG_ERROR:
		reg |= XHCI_PS_CEC;
		break;
	case CFS_C_BH_PORT_RESET:
		reg |= XHCI_PS_WRC;
		break;
	case CFS_PORT_SUSPEND:
	default:
		xhci_log(xhcip, "!asked to clear unsupported root hub "
		    "feature %d on port %d", feat, port);
		return (USB_CR_NOT_SUPPORTED);
	}

	xhci_put32(xhcip, XHCI_R_OPER, XHCI_PORTSC(port), reg);
	if (xhci_check_regs_acc(xhcip) != DDI_FM_OK) {
		xhci_error(xhcip, "failed to write port status register for "
		    "port %d: encountered fatal FM error, resetting device",
		    port);
		xhci_fm_runtime_reset(xhcip);
		return (USB_CR_HC_HARDWARE_ERR);
	}

	return (USB_CR_OK);
}

static int
xhci_root_hub_handle_port_set_feature(xhci_t *xhcip, usb_ctrl_req_t *ucrp)
{
	int feat = ucrp->ctrl_wValue;
	int port = XHCI_PS_INDPORT(ucrp->ctrl_wIndex);
	uint32_t val = XHCI_PS_INDVAL(ucrp->ctrl_wIndex);
	uint32_t reg;
	uintptr_t index;

	ASSERT(MUTEX_HELD(&xhcip->xhci_lock));

	if (port < 1 || port > xhcip->xhci_caps.xcap_max_ports)
		return (USB_CR_UNSPECIFIED_ERR);
	if (ucrp->ctrl_wLength != 0)
		return (USB_CR_UNSPECIFIED_ERR);

	index = XHCI_PORTSC(port);
	reg = xhci_get32(xhcip, XHCI_R_OPER, index);
	if (xhci_check_regs_acc(xhcip) != DDI_FM_OK) {
		xhci_error(xhcip, "failed to read port status register for "
		    "port %d: encountered fatal FM error, resetting device",
		    port);
		xhci_fm_runtime_reset(xhcip);
		return (USB_CR_HC_HARDWARE_ERR);
	}

	/*
	 * The port status and command register has many bits that we must
	 * preserve across writes, however, it also has bits that will be
	 * cleared when a bitwise one is written to them. As some of these
	 * write-one-to-clear bits may be set, we make sure to mask them off.
	 */
	reg &= ~XHCI_PS_CLEAR;

	switch (feat) {
	case CFS_PORT_U1_TIMEOUT:
		index = XHCI_PORTPMSC(port);
		reg = xhci_get32(xhcip, XHCI_R_OPER, index);
		if (xhci_check_regs_acc(xhcip) != DDI_FM_OK) {
			xhci_error(xhcip, "failed to read port power "
			    "management register for port %d: encountered "
			    "fatal FM error, resetting device", port);
			xhci_fm_runtime_reset(xhcip);
			return (USB_CR_HC_HARDWARE_ERR);
		}
		reg &= ~XHCI_PM3_U1TO_SET(0xff);
		reg |= XHCI_PM3_U1TO_SET(val);
		break;
	case CFS_PORT_U2_TIMEOUT:
		index = XHCI_PORTPMSC(port);
		reg = xhci_get32(xhcip, XHCI_R_OPER, index);
		if (xhci_check_regs_acc(xhcip) != DDI_FM_OK) {
			xhci_error(xhcip, "failed to read port power "
			    "management register for port %d: encountered "
			    "fatal FM error, resetting device", port);
			xhci_fm_runtime_reset(xhcip);
			return (USB_CR_HC_HARDWARE_ERR);
		}
		reg &= ~XHCI_PM3_U1TO_SET(0xff);
		reg |= XHCI_PM3_U1TO_SET(val);
		break;
	case CFS_PORT_LINK_STATE:
		reg |= XHCI_PS_PLS_SET(val);
		reg |= XHCI_PS_LWS;
		break;
	case CFS_PORT_REMOTE_WAKE_MASK:
		if (val & CFS_PRWM_CONN_ENABLE)
			reg |= XHCI_PS_WCE;
		else
			reg &= ~XHCI_PS_WCE;

		if (val & CFS_PRWM_DISCONN_ENABLE)
			reg |= XHCI_PS_WDE;
		else
			reg &= ~XHCI_PS_WDE;

		if (val & CFS_PRWM_OC_ENABLE)
			reg |= XHCI_PS_WOE;
		else
			reg &= ~XHCI_PS_WOE;
		break;
	case CFS_BH_PORT_RESET:
		reg |= XHCI_PS_WPR;
		break;
	case CFS_PORT_RESET:
		reg |= XHCI_PS_PR;
		break;
	case CFS_PORT_POWER:
		reg |= XHCI_PS_PP;
		break;
	case CFS_PORT_ENABLE:
		/*
		 * Enabling happens automatically for both USB 2 and USB 3. So
		 * there's nothing specific to set here.
		 */
		return (USB_CR_OK);
	case CFS_PORT_SUSPEND:
	default:
		xhci_log(xhcip, "!asked to set unsupported root hub "
		    "feature %d on port %d", feat, port);
		return (USB_CR_NOT_SUPPORTED);
	}

	xhci_put32(xhcip, XHCI_R_OPER, index, reg);
	if (xhci_check_regs_acc(xhcip) != DDI_FM_OK) {
		xhci_error(xhcip, "failed to write port status register for "
		    "port %d: encountered fatal FM error, resetting device",
		    port);
		xhci_fm_runtime_reset(xhcip);
		return (USB_CR_HC_HARDWARE_ERR);
	}

	return (USB_CR_OK);
}

/*
 * We've been asked to get the port's status. While there are multiple forms
 * that the port status request can take, we only support the primary one. The
 * enhanced version is only in USB 3.1.
 *
 * Note that we don't end up explicitly adding a speed value for the port,
 * because the only valid values are zero.
 */
static int
xhci_root_hub_handle_port_get_status(xhci_t *xhcip, usb_ctrl_req_t *ucrp)
{
	uint32_t reg;
	uint16_t ps, cs;
	mblk_t *mp = ucrp->ctrl_data;
	int port = XHCI_PS_INDPORT(ucrp->ctrl_wIndex);

	ASSERT(MUTEX_HELD(&xhcip->xhci_lock));

	if (port < 1 || port > xhcip->xhci_caps.xcap_max_ports)
		return (USB_CR_UNSPECIFIED_ERR);

	if (ucrp->ctrl_wValue != PORT_GET_STATUS_PORT)
		return (USB_CR_NOT_SUPPORTED);

	if (ucrp->ctrl_wLength != PORT_GET_STATUS_PORT_LEN)
		return (USB_CR_UNSPECIFIED_ERR);

	reg = xhci_get32(xhcip, XHCI_R_OPER, XHCI_PORTSC(port));
	if (xhci_check_regs_acc(xhcip) != DDI_FM_OK) {
		xhci_error(xhcip, "failed to read port status register for "
		    "port %d: encountered fatal FM error, resetting device",
		    port);
		xhci_fm_runtime_reset(xhcip);
		return (USB_CR_HC_HARDWARE_ERR);
	}

	ps = cs = 0;
	if (reg & XHCI_PS_CCS)
		ps |= PORT_STATUS_CCS;
	if (reg & XHCI_PS_PED)
		ps |= PORT_STATUS_PES;
	if (reg & XHCI_PS_OCA)
		ps |= PORT_STATUS_POCI;
	if (reg & XHCI_PS_PR)
		ps |= PORT_STATUS_PRS;

	ps |= XHCI_PS_PLS_SET(XHCI_PS_PLS_GET(reg));

	if (reg & XHCI_PS_PP)
		ps |= PORT_STATUS_PPS;

	/*
	 * While this isn't a defined part of the status, because we're not a
	 * true USB 3 hub, this is the only primary way that we can tell USBA
	 * what the actual speed of the device is. It's a bit dirty, but there's
	 * not really a great alternative at the moment.
	 */
	switch (XHCI_PS_SPEED_GET(reg)) {
	case XHCI_SPEED_FULL:
		ps |= USBA_FULL_SPEED_DEV << PORT_STATUS_SPSHIFT_SS;
		break;
	case XHCI_SPEED_LOW:
		ps |= USBA_LOW_SPEED_DEV << PORT_STATUS_SPSHIFT_SS;
		break;
	case XHCI_SPEED_HIGH:
		ps |= USBA_HIGH_SPEED_DEV << PORT_STATUS_SPSHIFT_SS;
		break;
	case XHCI_SPEED_SUPER:
	default:
		/*
		 * If we encounter something we don't know, we're going to start
		 * by assuming it is SuperSpeed, as so far all additions have
		 * been purely faster than SuperSpeed and have the same external
		 * behavior.
		 */
		ps |= USBA_SUPER_SPEED_DEV << PORT_STATUS_SPSHIFT_SS;
		break;
	}

	if (reg & XHCI_PS_CSC)
		cs |= PORT_CHANGE_CSC;
	if (reg & XHCI_PS_PEC)
		cs |= PORT_CHANGE_PESC;
	if (reg & XHCI_PS_OCC)
		cs |= PORT_CHANGE_OCIC;
	if (reg & XHCI_PS_PRC)
		cs |= PORT_CHANGE_PRSC;
	if (reg & XHCI_PS_WRC)
		cs |= PORT_CHANGE_BHPR;
	if (reg & XHCI_PS_PLC)
		cs |= PORT_CHANGE_PLSC;
	if (reg & XHCI_PS_CEC)
		cs |= PORT_CHANGE_PCE;

	cs = LE_16(cs);
	ps = LE_16(ps);
	bcopy(&ps, mp->b_wptr, sizeof (uint16_t));
	mp->b_wptr += sizeof (uint16_t);
	bcopy(&cs, mp->b_wptr, sizeof (uint16_t));
	mp->b_wptr += sizeof (uint16_t);

	return (USB_CR_OK);
}

/*
 * USBA has issued a request for the root hub. We need to determine what it's
 * asking about and then figure out how to handle it and how to respond.
 */
int
xhci_root_hub_ctrl_req(xhci_t *xhcip, usba_pipe_handle_data_t *ph,
    usb_ctrl_req_t *ucrp)
{
	int ret = USB_CR_OK;

	ASSERT(MUTEX_HELD(&xhcip->xhci_lock));

	switch (ucrp->ctrl_bmRequestType) {
	case HUB_GET_DEVICE_STATUS_TYPE:
		ret = xhci_root_hub_get_device_status(xhcip, ucrp);
		break;
	case HUB_HANDLE_PORT_FEATURE_TYPE:
		switch (ucrp->ctrl_bRequest) {
		case USB_REQ_CLEAR_FEATURE:
			ret = xhci_root_hub_handle_port_clear_feature(xhcip,
			    ucrp);
			break;
		case USB_REQ_SET_FEATURE:
			ret = xhci_root_hub_handle_port_set_feature(xhcip,
			    ucrp);
			break;
		default:
			ret = USB_CR_NOT_SUPPORTED;
			break;
		}
		break;
	case HUB_GET_PORT_STATUS_TYPE:
		ret = xhci_root_hub_handle_port_get_status(xhcip, ucrp);
		break;
	case HUB_CLASS_REQ_TYPE:
		switch (ucrp->ctrl_bRequest) {
		case USB_REQ_GET_STATUS:
			ret = xhci_root_hub_get_status(xhcip, ucrp);
			break;
		case USB_REQ_GET_DESCR:
			xhci_root_hub_get_descriptor(xhcip, ucrp);
			break;
		default:
			xhci_error(xhcip, "Unhandled hub request: 0x%x\n",
			    ucrp->ctrl_bRequest);
			ret = USB_CR_NOT_SUPPORTED;
			break;
		}
		break;
	default:
		xhci_error(xhcip, "Unhandled hub request type: %x\n",
		    ucrp->ctrl_bmRequestType);
		ret = USB_CR_NOT_SUPPORTED;
		break;
	}

	mutex_exit(&xhcip->xhci_lock);
	usba_hcdi_cb(ph, (usb_opaque_t)ucrp, ret);
	mutex_enter(&xhcip->xhci_lock);

	return (USB_SUCCESS);
}

/*
 * This function is invoked whenever the root HUBs interrupt endpoint is opened
 * or we receive an port change event notification from the hardware on the
 * event ring from an interrupt.
 *
 * If we have a registered interrupt callback requested, then we have to
 * duplicate the request so we can send it back to usba and then we generate the
 * actual status message and send it.
 */
void
xhci_root_hub_psc_callback(xhci_t *xhcip)
{
	usb_intr_req_t *req, *new;
	usba_pipe_handle_data_t *ph;
	mblk_t *mp;
	uint32_t mask;
	unsigned i;

	mask = 0;
	for (i = 0; i <= xhcip->xhci_caps.xcap_max_ports; i++) {
		uint32_t reg;

		reg = xhci_get32(xhcip, XHCI_R_OPER, XHCI_PORTSC(i));
		if ((reg & XHCI_HUB_INTR_CHANGE_MASK) != 0)
			mask |= 1UL << i;
	}

	if (xhci_check_regs_acc(xhcip) != DDI_FM_OK) {
		xhci_error(xhcip, "failed to read port status registers: "
		    "encountered fatal FM error, resetting device");
		xhci_fm_runtime_reset(xhcip);
		return;
	}
	if (mask == 0)
		return;

	mask = LE_32(mask);

	mutex_enter(&xhcip->xhci_lock);
	if (xhcip->xhci_usba.xa_intr_cb_req == NULL) {
		mutex_exit(&xhcip->xhci_lock);
		return;
	}

	ASSERT(xhcip->xhci_usba.xa_intr_cb_ph != NULL);
	req = xhcip->xhci_usba.xa_intr_cb_req;
	ph = xhcip->xhci_usba.xa_intr_cb_ph;

	new = usba_hcdi_dup_intr_req(ph->p_dip, req, req->intr_len, 0);
	if (new == NULL) {
		new = xhcip->xhci_usba.xa_intr_cb_req;
		xhcip->xhci_usba.xa_intr_cb_req = NULL;
		mutex_exit(&xhcip->xhci_lock);
		usba_hcdi_cb(ph, (usb_opaque_t)new, USB_CR_NO_RESOURCES);
		return;
	}

	/*
	 * Why yes, we do have to manually increment this for the given pipe
	 * before we deliver it. If we don't, it has no way of knowing that
	 * there's another request inbound and we'll simply blow our assertions
	 * on requests.
	 */
	mutex_enter(&ph->p_mutex);
	ph->p_req_count++;
	mutex_exit(&ph->p_mutex);

	mp = new->intr_data;
	bcopy(&mask, mp->b_wptr, sizeof (mask));
	mp->b_wptr += sizeof (mask);

	mutex_exit(&xhcip->xhci_lock);

	usba_hcdi_cb(ph, (usb_opaque_t)new, USB_CR_OK);
}

void
xhci_root_hub_intr_root_disable(xhci_t *xhcip)
{
	usba_pipe_handle_data_t *ph;
	usb_intr_req_t *uirp;

	ASSERT(MUTEX_HELD(&xhcip->xhci_lock));

	ph = xhcip->xhci_usba.xa_intr_cb_ph;
	xhcip->xhci_usba.xa_intr_cb_ph = NULL;
	ASSERT(ph != NULL);

	/*
	 * If the uirp here is NULL, it's because we ran out of resources at
	 * some point in xhci_hcdi_psc_callback().
	 */
	uirp = xhcip->xhci_usba.xa_intr_cb_req;
	xhcip->xhci_usba.xa_intr_cb_req = NULL;
	if (uirp == NULL) {
		return;
	}

	mutex_exit(&xhcip->xhci_lock);
	usba_hcdi_cb(ph, (usb_opaque_t)uirp, USB_CR_STOPPED_POLLING);
	mutex_enter(&xhcip->xhci_lock);

}

int
xhci_root_hub_intr_root_enable(xhci_t *xhcip, usba_pipe_handle_data_t *ph,
    usb_intr_req_t *uirp)
{
	ASSERT((ph->p_ep.bEndpointAddress & USB_EP_NUM_MASK) == 1);
	ASSERT((uirp->intr_attributes & USB_ATTRS_ONE_XFER) == 0);

	mutex_enter(&xhcip->xhci_lock);
	if (xhcip->xhci_state & XHCI_S_ERROR) {
		mutex_exit(&xhcip->xhci_lock);
		return (USB_HC_HARDWARE_ERROR);
	}

	if (xhcip->xhci_usba.xa_intr_cb_ph != NULL) {
		mutex_exit(&xhcip->xhci_lock);
		return (USB_BUSY);
	}

	xhcip->xhci_usba.xa_intr_cb_ph = ph;
	xhcip->xhci_usba.xa_intr_cb_req = uirp;

	/*
	 * USBA is expecting us to act like a hub and therefore whenever we open
	 * up the interrupt endpoint, we need to generate an event with
	 * information about all the currently outstanding ports with changes.
	 */
	mutex_exit(&xhcip->xhci_lock);
	xhci_root_hub_psc_callback(xhcip);

	return (USB_SUCCESS);
}

int
xhci_root_hub_fini(xhci_t *xhcip)
{
	if (usba_hubdi_unbind_root_hub(xhcip->xhci_dip) != USB_SUCCESS)
		return (DDI_FAILURE);

	return (DDI_SUCCESS);
}

static int
xhci_root_hub_fill_hub_desc(xhci_t *xhcip)
{
	int i;
	uint16_t chars;
	usb_ss_hub_descr_t *hdp = &xhcip->xhci_usba.xa_hub_descr;

	bzero(hdp, sizeof (usb_ss_hub_descr_t));

	hdp->bDescLength = sizeof (usb_ss_hub_descr_t);
	hdp->bDescriptorType = ROOT_HUB_SS_DESCRIPTOR_TYPE;
	hdp->bNbrPorts = xhcip->xhci_caps.xcap_max_ports;

	chars = 0;
	if (xhcip->xhci_caps.xcap_flags & XCAP_PPC)
		chars |= HUB_CHARS_INDIVIDUAL_PORT_POWER;
	chars |= HUB_CHARS_INDIV_OVER_CURRENT;
	hdp->wHubCharacteristics = LE_16(chars);
	hdp->bPwrOn2PwrGood = XHCI_POWER_GOOD;
	hdp->bHubContrCurrent = 0;

	/*
	 * There doesn't appear to be a good way to determine what the impact of
	 * the root hub on the link should be. However, one way to view it is
	 * because everything must transfer through here the impact doesn't
	 * really matter, as everyone is subject to it.
	 */
	hdp->bHubHdrDecLat = 0;
	hdp->wHubDelay = 0;

	for (i = 1; i < xhcip->xhci_caps.xcap_max_ports; i++) {
		uint32_t reg;

		reg = xhci_get32(xhcip, XHCI_R_OPER, XHCI_PORTSC(i));
		if (xhci_check_regs_acc(xhcip) != DDI_FM_OK) {
			xhci_error(xhcip, "encountered fatal FM error while "
			    "reading port status register %d", i);
			ddi_fm_service_impact(xhcip->xhci_dip,
			    DDI_SERVICE_LOST);
			return (EIO);
		}

		if (reg & XHCI_PS_DR)
			hdp->DeviceRemovable[i / 8] |= 1U << (i % 8);
	}

	return (0);
}


/*
 * Convert the USB PCI revision which is a uint8_t with 4-bit major and 4-bit
 * minor into a uint16_t with a 8-bit major and 8-bit minor.
 */
static uint16_t
xhci_root_vers_to_bcd(uint8_t vers)
{
	uint8_t major, minor;

	major = (vers & 0xf0) >> 4;
	minor = (vers & 0x0f);
	return ((major << 8) | minor);
}

static void
xhci_root_hub_fill_dev_desc(xhci_t *xhcip, usb_dev_descr_t *hub)
{
	hub->bLength = sizeof (usb_dev_descr_t);

	/*
	 * The descriptor type is that for a device, which is 0x1.
	 */
	hub->bDescriptorType = 0x01;
	hub->bcdUSB = xhci_root_vers_to_bcd(xhcip->xhci_caps.xcap_usb_vers);

	/*
	 * As we're trying to pretend we're a hub, we have a fixed device id of
	 * 0x09. Note, that the device protocol for a super-speed hub
	 * technically isn't registered as 0x3; however, a vast majority of
	 * systems out there fake this up to indicate that it's a USB 3.x era
	 * device. This is presumably due to the suggestions as made in USB 3.1
	 * / 10.5.1.
	 */
	hub->bDeviceClass = USB_CLASS_HUB;
	hub->bDeviceSubClass = 0x00;
	hub->bDeviceProtocol = 0x03;

	/*
	 * The only valid value for a USB 3 device is 09h as indicated in USB
	 * 3.1 / 9.6.6.
	 */
	hub->bMaxPacketSize0 = 9;

	/*
	 * We have no real identification information, so we set it all to
	 * zero.
	 */
	hub->idVendor = 0x00;
	hub->idProduct = 0x00;
	hub->bcdDevice = 0x00;
	hub->iManufacturer = 0x00;
	hub->iProduct = 0x00;
	hub->iSerialNumber = 0x00;

	/*
	 * To keep our lives simple, we only have a single piece of
	 * configuration for this device.
	 */
	hub->bNumConfigurations = 0x01;
}

/*
 * To register a root hub with the framework, we need to fake up a bunch of
 * information for usba, particularly we need to basically feed it the device
 * configuration in the form that USB expects. See section 10.15.1 for more
 * information.
 */
int
xhci_root_hub_init(xhci_t *xhcip)
{
	usb_dev_descr_t *hub = &xhcip->xhci_usba.xa_dev_descr;
	uchar_t *conf = (uchar_t *)&xhci_hcdi_conf;

	xhci_root_hub_fill_dev_desc(xhcip, hub);
	if (xhci_root_hub_fill_hub_desc(xhcip) != 0)
		return (DDI_FAILURE);

	if (usba_hubdi_bind_root_hub(xhcip->xhci_dip, conf,
	    sizeof (xhci_hcdi_conf), hub) != USB_SUCCESS)
		return (DDI_FAILURE);

	return (DDI_SUCCESS);
}
