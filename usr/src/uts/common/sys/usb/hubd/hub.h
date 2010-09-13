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

#ifndef	_SYS_USB_HUB_H
#define	_SYS_USB_HUB_H


#ifdef	__cplusplus
extern "C" {
#endif

#define	USB_DESCR_TYPE_SETUP_HUB	0x2900

/*
 * Section 11.11.2.1 allows up to 255 ports.
 * For simplicity, only a maximum of 31 ports is currently allowed
 */
#define	MAX_PORTS 31

typedef struct usb_hub_descr {
	uchar_t		bDescLength;	/* size of descriptor */
	uchar_t		bDescriptorType; /* descriptor type */
	uchar_t		bNbrPorts;	/* number of ports */
	uint16_t	wHubCharacteristics; /* hub characteristics */
	uchar_t		bPwrOn2PwrGood;	/* time in ms from the time */
				/* power on sequence begins on a port */
				/* until power is good on that port */
	uchar_t		bHubContrCurrent; /* max current requirements */
	uchar_t		DeviceRemovable;
					/* removable device attached */
	uchar_t		PortPwrCtrlMask;
					/* power control mask */
} usb_hub_descr_t;

#define	ROOT_HUB_DESCRIPTOR_LENGTH	9
#define	ROOT_HUB_DESCRIPTOR_TYPE	0x29
#define	ROOT_HUB_ADDR			0x01	/* address of root hub */

/* Values for wHubCharacteristics */
#define	HUB_CHARS_POWER_SWITCHING_MODE	0x03
#define	HUB_CHARS_GANGED_POWER		0x00
#define	HUB_CHARS_INDIVIDUAL_PORT_POWER	0x01
#define	HUB_CHARS_NO_POWER_SWITCHING	0x02
#define	HUB_CHARS_COMPOUND_DEV		0x04
#define	HUB_CHARS_GLOBAL_OVER_CURRENT	0x00
#define	HUB_CHARS_INDIV_OVER_CURRENT	0x08
#define	HUB_CHARS_NO_OVER_CURRENT	0x10
#define	HUB_CHARS_TT_THINK_TIME		0x60
#define	HUB_CHARS_TT_16FS_TIME		0x20
#define	HUB_CHARS_TT_24FS_TIME		0x40
#define	HUB_CHARS_TT_32FS_TIME		0x60
#define	HUB_CHARS_PORT_INDICATOR	0x80

/* Default Power On to Power Good time */
#define	HUB_DEFAULT_POPG	10

/* Hub Status */
#define	HUB_CHANGE_STATUS	0x01

/* Class Specific bmRequestType values Table 11-10 */
#define	HUB_HANDLE_PORT_FEATURE_TYPE	(USB_DEV_REQ_HOST_TO_DEV \
					|USB_DEV_REQ_TYPE_CLASS \
					|USB_DEV_REQ_RCPT_OTHER)

#define	HUB_GET_PORT_STATUS_TYPE	(USB_DEV_REQ_DEV_TO_HOST \
					|USB_DEV_REQ_TYPE_CLASS \
					|USB_DEV_REQ_RCPT_OTHER)

#define	HUB_CLASS_REQ_TYPE		(USB_DEV_REQ_DEV_TO_HOST \
					|USB_DEV_REQ_TYPE_CLASS)

#define	HUB_HANDLE_HUB_FEATURE_TYPE	USB_DEV_REQ_TYPE_CLASS

/* bmRequestType for getting device status */
#define	HUB_GET_DEVICE_STATUS_TYPE	(USB_DEV_REQ_DEV_TO_HOST \
					|USB_DEV_REQ_TYPE_STANDARD \
					|USB_DEV_REQ_RCPT_DEV)

/* Port Status Field Bits - Table 11-15 */
#define	PORT_STATUS_CCS		0x0001	/* port connection status */
#define	PORT_STATUS_PES		0x0002	/* port enable status */
#define	PORT_STATUS_PSS		0x0004	/* port suspend status */
#define	PORT_STATUS_POCI	0x0008	/* port over current indicator */
#define	PORT_STATUS_PRS		0x0010	/* port reset status */
#define	PORT_STATUS_PPS		0x0100	/* port power status */
#define	PORT_STATUS_LSDA	0x0200	/* low speed device */
#define	PORT_STATUS_HSDA	0x0400	/* high speed device */
#define	PORT_STATUS_PIC		0x1000	/* port indicator control */

#define	PORT_STATUS_MASK	0x171f
#define	PORT_STATUS_OK		0x103	/* connected, enabled, power */

/* Port Change Field Bits - Table 11-16 */
#define	PORT_CHANGE_CSC		0x0001	/* connect status change */
#define	PORT_CHANGE_PESC	0x0002	/* port enable change */
#define	PORT_CHANGE_PSSC	0x0004	/* port suspend change */
#define	PORT_CHANGE_OCIC	0x0008	/* over current change */
#define	PORT_CHANGE_PRSC	0x0010	/* port reset change */

#define	PORT_CHANGE_MASK	0x001f

/* Hub status Field Bits - Table 11-14 */
#define	HUB_LOCAL_POWER_STATUS	0x0001	/* state of the power supply */
#define	HUB_OVER_CURRENT	0x0002  /* global hub OC condition */

/* Hub change clear feature selectors - Table 11-15 */
#define	C_HUB_LOCAL_POWER_STATUS 0x0001 /* state of the power supply */
#define	C_HUB_OVER_CURRENT	 0x0002 /* global hub OC condition */

/* hub class feature selectors - Table 11-12 */
#define	CFS_C_HUB_LOCAL_POWER		0
#define	CFS_C_HUB_OVER_CURRENT		1
#define	CFS_PORT_CONNECTION		0
#define	CFS_PORT_ENABLE			1
#define	CFS_PORT_SUSPEND		2
#define	CFS_PORT_OVER_CURRENT		3
#define	CFS_PORT_RESET			4
#define	CFS_PORT_POWER			8
#define	CFS_PORT_LOW_SPEED		9
#define	CFS_C_PORT_CONNECTION		16
#define	CFS_C_PORT_ENABLE		17
#define	CFS_C_PORT_SUSPEND		18
#define	CFS_C_PORT_OVER_CURRENT 	19
#define	CFS_C_PORT_RESET		20

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_USB_HUB_H */
