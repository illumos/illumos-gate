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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_USB_USB_CDC_H
#define	_SYS_USB_USB_CDC_H


#include <sys/types.h>
#include <sys/dditypes.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * USB Communications Device Class
 */

/*
 * Class-specific descriptors
 */
#define	USB_CDC_CS_INTERFACE			0x24
#define	USB_CDC_CS_ENDPOINT			0x25

#define	USB_CDC_DESCR_TYPE_HEADER		0x00
#define	USB_CDC_DESCR_TYPE_CALL_MANAGEMENT	0x01
#define	USB_CDC_DESCR_TYPE_ACM			0x02
#define	USB_CDC_DESCR_TYPE_UNION		0x06
#define	USB_CDC_DESCR_TYPE_COUNTRY		0x07
#define	USB_CDC_DESCR_TYPE_NETWORK_TERMINAL	0x0a
#define	USB_CDC_DESCR_TYPE_ETHERNET		0x0f

/* Header Functional Descriptor */
typedef struct usb_cdc_header_descr {
	uint8_t		bFunctionalLength;
	uint8_t		bDescriptorType;
	uint8_t		bDescriptorSubtype;
	uint16_t	bcdCDC;
} usb_cdc_header_descr_t;

/* Call Management Descriptor */
typedef struct usb_cdc_call_mgmt_descr {
	uint8_t		bFunctionalLength;
	uint8_t		bDescriptorType;
	uint8_t		bDescriptorSubtype;
	uint8_t		bmCapabilities;
	uint8_t		bDataInterface;
} usb_cdc_call_mgmt_descr_t;

#define	USB_CDC_CALL_MGMT_CAP_CALL_MGMT		0x01
#define	USB_CDC_CALL_MGMT_CAP_DATA_INTERFACE	0x02

/* Abstract Control Management Descriptor */
typedef struct usb_cdc_acm_descr {
	uint8_t		bFunctionalLength;
	uint8_t		bDescriptorType;
	uint8_t		bDescriptorSubtype;
	uint8_t		bmCapabilities;
} usb_cdc_acm_descr_t;

#define	USB_CDC_ACM_CAP_COMM_FEATURE		0x01
#define	USB_CDC_ACM_CAP_SERIAL_LINE		0x02
#define	USB_CDC_ACM_CAP_SEND_BREAK		0x04
#define	USB_CDC_ACM_CAP_NETWORK_CONNECTION	0x08

/* Union Functional Descriptor */
typedef struct usb_cdc_union_descr {
	uint8_t		bFunctionalLength;
	uint8_t		bDescriptorType;
	uint8_t		bDescriptorSubtype;
	uint8_t		bMasterInterface0;
	uint8_t		bSlaveInterface0;
	/* more slave interafce may follow */
} usb_cdc_union_descr_t;

/* Ethernet Control Model Functional Descriptor */
typedef struct usb_cdc_ecm_descr {
	uint8_t		bFunctionalLength;
	uint8_t		bDescriptorType;
	uint8_t		bDescriptorSubtype;
	uint8_t		iMACAddress;
	uint32_t	bmEthernetStatistics;
	uint16_t	wMaxSegmentSize;
	uint16_t	wNumberMCFilters;
	uint8_t		bNumberPowerFilters;
} usb_cdc_ecm_descr_t;


/*
 * Class-specific requests
 */
#define	USB_CDC_REQ_SEND_ENCAPSULATED_COMMAND	0x00
#define	USB_CDC_REQ_GET_ENCAPSULATED_RESPONSE	0x01
#define	USB_CDC_REQ_SET_LINE_CODING		0x20
#define	USB_CDC_REQ_GET_LINE_CODING		0x21
#define	USB_CDC_REQ_SET_CONTROL_LINE_STATE	0x22
#define	USB_CDC_REQ_SEND_BREAK			0x23

/* Line Coding */
typedef struct usb_cdc_line_coding {
	uint32_t	dwDTERate;
	uint8_t		bCharFormat;
	uint8_t		bParityType;
	uint8_t		bDataBits;
} usb_cdc_line_coding_t;

#define	USB_CDC_LINE_CODING_LEN			7
#define	USB_CDC_ECM_LEN				13

#define	USB_CDC_STOP_BITS_1			0
#define	USB_CDC_STOP_BITS_1_5			1
#define	USB_CDC_STOP_BITS_2			2

#define	USB_CDC_PARITY_NO			0
#define	USB_CDC_PARITY_ODD			1
#define	USB_CDC_PARITY_EVEN			2
#define	USB_CDC_PARITY_MARK			3
#define	USB_CDC_PARITY_SPACE			4

#define	USB_CDC_ACM_CONTROL_DTR			0x01
#define	USB_CDC_ACM_CONTROL_RTS			0x02

#define	USB_CDC_NOTIFICATION_REQUEST_TYPE	0xa1
/*
 * Class-specific notifications
 */
#define	USB_CDC_NOTIFICATION_NETWORK_CONNECTION	0x00
#define	USB_CDC_NOTIFICATION_RESPONSE_AVAILABLE	0x01
#define	USB_CDC_NOTIFICATION_SERIAL_STATE	0x20
#define	USB_CDC_NOTIFICATION_SPEED_CHANGE	0x2a

typedef struct usb_cdc_notification {
	uint8_t		bmRequestType;
	uint8_t		bNotificationType;
	uint16_t	wValue;
	uint16_t	wIndex;
	uint16_t	wLength;
} usb_cdc_notification_t;

/* Serial State */
#define	USB_CDC_ACM_CONTROL_DCD			0x01
#define	USB_CDC_ACM_CONTROL_DSR			0x02
#define	USB_CDC_ACM_CONTROL_BREAK		0x04
#define	USB_CDC_ACM_CONTROL_RNG			0x08
#define	USB_CDC_ACM_CONTROL_FRAMING		0x10
#define	USB_CDC_ACM_CONTROL_PARITY		0x20
#define	USB_CDC_ACM_CONTROL_OVERRUN		0x40


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_USB_USB_CDC_H */
