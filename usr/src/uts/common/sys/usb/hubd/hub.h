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
 *
 * Copyright 2016 Joyent, Inc.
 */

#ifndef	_SYS_USB_HUB_H
#define	_SYS_USB_HUB_H


#ifdef	__cplusplus
extern "C" {
#endif

#define	HUBD_DEFAULT_DESC_INDEX		0

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

/*
 * In USB 3.x the format of the root hub description has changed. See USB 3.1 /
 * 10.15.12.1.
 */
#pragma pack(1)
typedef struct usb_ss_hub_descr {
	uint8_t		bDescLength;		/* size of descriptor */
	uint8_t		bDescriptorType;	/* descriptor type (0x2A) */
	uint8_t		bNbrPorts;		/* number of ports */
	uint16_t	wHubCharacteristics;	/* hub characteristics */
	uint8_t		bPwrOn2PwrGood;	/* time in 2-ms from power on */
						/* until the port is ready */
	uint8_t		bHubContrCurrent;	/* max current requirements */
	uint8_t		bHubHdrDecLat;		/* hub packet decode latency */
	uint16_t	wHubDelay;		/* Forwarding delay in ns */
	uint16_t	DeviceRemovable[32];	/* indicates per-port whether */
					/* the device is removable with one */
					/* bit per port, up to 255 ports */
} usb_ss_hub_descr_t;
#pragma pack()

#define	ROOT_HUB_DESCRIPTOR_LENGTH	9
#define	ROOT_HUB_DESCRIPTOR_TYPE	0x29
#define	ROOT_HUB_SS_DESCRIPTOR_TYPE	0x2A
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

#define	HUB_CHARS_TT_SHIFT		5

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

#define	HUB_SET_HUB_DEPTH_TYPE		(USB_DEV_REQ_HOST_TO_DEV \
					|USB_DEV_REQ_TYPE_CLASS \
					|USB_DEV_REQ_RCPT_DEV)

/* bmRequestType for getting device status */
#define	HUB_GET_DEVICE_STATUS_TYPE	(USB_DEV_REQ_DEV_TO_HOST \
					|USB_DEV_REQ_TYPE_STANDARD \
					|USB_DEV_REQ_RCPT_DEV)

/*
 * Class specific bRequest values that don't line up with standard requests. See
 * USB 3.1 / Table 10-8.
 */
#define	HUB_REQ_SET_HUB_DEPTH		12

/*
 * Port Status Field Bits. While there is overlap between the USB 2.0 and USB
 * 3.0 bits, they aren't entirely the same and some bits have different meanings
 * across different versions of USB. Common bits are shared first and then this
 * is broken down into device specific bits. The USB 3 version is in USB
 * 3.1/10.16.2.6.1. The USB 2 version is in USB 2/11.24.2.7.1.
 */
#define	PORT_STATUS_CCS		0x0001	/* port connection status */
#define	PORT_STATUS_PES		0x0002	/* port enable status */
#define	PORT_STATUS_PSS		0x0004	/* port suspend status */
#define	PORT_STATUS_POCI	0x0008	/* port over current indicator */
#define	PORT_STATUS_PRS		0x0010	/* port reset status */
#define	PORT_STATUS_PPS		0x0100	/* port power status */

/* USB 2.0 specific bits */
#define	PORT_STATUS_LSDA	0x0200	/* low speed device */
#define	PORT_STATUS_HSDA	0x0400	/* high speed device */
#define	PORT_STATUS_PIC		0x1000	/* port indicator control */

/*
 * The USB 2.0 and USB 3.0 port status bits are almost identical; however, the
 * location of the port's power indicator is different for hubs. To deal with
 * this, we have logic, hubd_status_unifornm, that transforms the USB 3 status
 * to USB 2, hence why we only have one version of these macros below.
 */
#define	PORT_STATUS_MASK	0x171f
#define	PORT_STATUS_OK		0x103	/* connected, enabled, power */

/* USB 3 Specific bits */
#define	PORT_STATUS_PPS_SS	0x0200	/* USB 3.0 port power status */
#define	PORT_STATUS_SPMASK_SS	0x1c00
#define	PORT_STATUS_SPSHIFT_SS	10

/* Port Change Field Bits - Table 11-16 */
#define	PORT_CHANGE_CSC		0x0001	/* connect status change */
#define	PORT_CHANGE_PESC	0x0002	/* port enable change */
#define	PORT_CHANGE_PSSC	0x0004	/* port suspend change */
#define	PORT_CHANGE_OCIC	0x0008	/* over current change */
#define	PORT_CHANGE_PRSC	0x0010	/* port reset change */

/*
 * USB 3.x additions. See USB 3.1/10.16.2.6.2.
 */
#define	PORT_CHANGE_BHPR	0x0020	/* warm reset (BH) */
#define	PORT_CHANGE_PLSC	0x0040	/* port link state change */
#define	PORT_CHANGE_PCE		0x0080	/* port config error */

/*
 * These represent masks for all of the change bits. Note that the USB 2 version
 * has less than the USB 3. The _2X version of the macro is maintained for
 * things that don't know about more than USB 2 (ehci).
 */
#define	PORT_CHANGE_MASK_2X	0x001f
#define	PORT_CHANGE_MASK	0x00ff

/*
 * Port status types and sizes USB 3.1/Table 10-12.
 */
#define	PORT_GET_STATUS_PORT	0x00
#define	PORT_GET_STATUS_PD	0x01
#define	PORT_GET_STATUS_EXT	0x02

#define	PORT_GET_STATUS_PORT_LEN	0x04
#define	PORT_GET_STATUS_PD_LEN		0x08
#define	PORT_GET_STATUS_EXT_LEN		0x08

/* Hub status information USB 3.1/11.24.2.6 */
#define	HUB_GET_STATUS_LEN	0x04
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
#define	CFS_PORT_LINK_STATE		5
#define	CFS_PORT_POWER			8
#define	CFS_PORT_LOW_SPEED		9
#define	CFS_C_PORT_CONNECTION		16
#define	CFS_C_PORT_ENABLE		17
#define	CFS_C_PORT_SUSPEND		18
#define	CFS_C_PORT_OVER_CURRENT 	19
#define	CFS_C_PORT_RESET		20
#define	CFS_PORT_TEST			21
#define	CFS_PORT_INDICATOR		22

/*
 * SuperSpeed specific HUB features. See USB 3.1 / 10.16.2.
 */
#define	CFS_PORT_U1_TIMEOUT		23
#define	CFS_PORT_U2_TIMEOUT		24
#define	CFS_C_PORT_LINK_STATE		25
#define	CFS_C_PORT_CONFIG_ERROR		26
#define	CFS_PORT_REMOTE_WAKE_MASK	27
#define	CFS_BH_PORT_RESET		28
#define	CFS_C_BH_PORT_RESET		29
#define	CFS_FORCE_LINKPM_ACCEPT		30

/*
 * Values for CFS_PORT_REMOTE_WAKE_MASK. See USB 3.1 / Table 10-18.
 */
#define	CFS_PRWM_CONN_ENABLE		0x01
#define	CFS_PRWM_DISCONN_ENABLE		0x02
#define	CFS_PRWM_OC_ENABLE		0x04

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_USB_HUB_H */
