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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_USB_HID_H
#define	_SYS_USB_HID_H

#include <sys/note.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	USB_DESCR_TYPE_HID	0x21
#define	USB_HID_DESCR_SIZE	10	/* Hid descriptor length */

/*
 * HID : This header file defines the interface between the hid
 * module and the hid driver.
 */

/*
 * There is an M_CTL command per class specific HID command defined in
 * section 7.2 of the specification.
 */

#define	HID_GET_REPORT		0x0001		/* receive report */
#define	HID_GET_IDLE		0x0002		/* find the idle value */
#define	HID_GET_PROTOCOL	0x0003		/* get the protocol */
#define	HID_SET_REPORT		0x0009		/* send a report to device */
#define	HID_SET_IDLE		0x000a		/* set the idle value */
#define	HID_SET_PROTOCOL	0x000b		/* set the protocol */

/*
 * Hid descriptor
 */
typedef struct usb_hid_descr {
	uchar_t		bLength;		/* Size of this descriptor */
	uchar_t		bDescriptorType;	/* HID descriptor */
	ushort_t	bcdHID;			/* HID spec release */
	uchar_t		bCountryCode;		/* Country code */
	uchar_t		bNumDescriptors;	/* No. class descriptors */
	uchar_t		bReportDescriptorType;	/* Class descr. type */
	ushort_t	wReportDescriptorLength; /* size of report descr */
} usb_hid_descr_t;

/*
 * Hid device information
 */
typedef struct hid_vid_pid {
	uint16_t	VendorId;		/* vendor ID */
	uint16_t	ProductId;		/* product ID */
} hid_vid_pid_t;

/*
 * Hid will turn the M_CTL request into a request control request on the
 * default pipe.  Hid needs the following information in the hid_req_t
 * structure.  See the details below for specific values for each command.
 * hid_req_data is a 256-byte buffer, which is used to transfer input, output
 * and feature report(hid specification 6.2.2.3 long items).
 */

#define	MAX_REPORT_DATA 256

typedef struct hid_req_struct {
	uint16_t	hid_req_version_no;	/* Version number */
	uint16_t	hid_req_wValue;		/* wValue field of request */
	uint16_t	hid_req_wLength;	/* wLength of request */
	uchar_t		hid_req_data[MAX_REPORT_DATA];	/* data for send case */
} hid_req_t;
_NOTE(SCHEME_PROTECTS_DATA("unique per call", hid_req_t))

/*
 * hid_req_wValue values HID_GET_REPORT and HID_SET_REPORT
 */
#define	REPORT_TYPE_INPUT	0x0100			/* Input report */
#define	REPORT_TYPE_OUTPUT	0x0200			/* Output report */
#define	REPORT_TYPE_FEATURE	0x0300			/* Feature report */


/*
 * hid_req_wLength value for HID_GET_IDLE and HID_SET_IDLE
 */
#define	GET_IDLE_LENGTH		0x0001
#define	SET_IDLE_LENGTH		0x0000

/*
 * hid_req_wValue values for SET_PROTOCOL
 */
#define	SET_BOOT_PROTOCOL	0x0000			/* Boot protocol */
#define	SET_REPORT_PROTOCOL	0x0001			/* Report protocol */

/*
 * return values for GET_PROTOCOL
 */
#define	BOOT_PROTOCOL		0x00		/* Returned boot protocol */
#define	REPORT_PROTOCOL		0x01		/* Returned report protocol */

/*
 * There is an additional M_CTL command for obtaining the
 * hid parser handle.  This M_CTL returns a pointer to  the handle.
 * The type of the pointer is intpr_t because this type is large enough to
 * hold any data pointer.
 */
#define	HID_GET_PARSER_HANDLE	0x0100		/* obtain parser handle */

/*
 * The M_CTL command is to get the device vendor ID and product ID.
 */
#define	HID_GET_VID_PID		0x0200		/* obtain device info */

/*
 * M_CTL commands for event notifications
 */
#define	HID_POWER_OFF		0x00DC
#define	HID_FULL_POWER		0x00DD
#define	HID_DISCONNECT_EVENT	0x00DE
#define	HID_CONNECT_EVENT	0x00DF

/*
 * To get the report descriptor,
 * This is the wValue
 */
#define	USB_CLASS_DESCR_TYPE_REPORT	0x2200


/* Version numbers */
#define	HID_VERSION_V_0		0

/*
 * HID IOCTLS
 */
#define	HIDIOC	('h'<<8)

/*
 * Each hid keyboard/mouse device instance has two streams (internal/external).
 * This pair of ioctls is used to get/set which stream the input data should
 * be sent to.
 */
#define	HIDIOCKMGDIRECT	(HIDIOC | 0)
#define	HIDIOCKMSDIRECT	(HIDIOC | 1)

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_USB_HID_H */
