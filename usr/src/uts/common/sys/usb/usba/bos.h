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
 * Copyright 2019 Joyent, Inc.
 */

#ifndef _SYS_USB_BOS_H
#define	_SYS_USB_BOS_H

/*
 * This header contains definitions that relate to the USB Binary Object Store.
 * While this functionality was originally introduced with WUSB, it was used in
 * USB 3.x as a way to provide additional device related information. This is
 * currently separate from the primary usbai headers as this functionality is
 * not currently used by client device drivers themselves, but only by the hub
 * driver for private functionality.
 *
 * This data is all derived from the USB 3.1 specification, Chapter 9.6.2 Binary
 * Device Object Store (BOS).
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Capability list, see USB 3.1 r1.0, Table 9-14.
 */
#define	USB_BOS_TYPE_INVALID		0x00	/* Internal, synthetic value */
#define	USB_BOS_TYPE_WUSB		0x01
#define	USB_BOS_TYPE_USB2_EXT		0x02
#define	USB_BOS_TYPE_SUPERSPEED		0x03
#define	USB_BOS_TYPE_CONTAINER		0x04
#define	USB_BOS_TYPE_PLATFORM		0x05
#define	USB_BOS_TYPE_PD_CAP		0x06
#define	USB_BOS_TYPE_BATTERY_INFO	0x07
#define	USB_BOS_TYPE_PD_CONSUMER_CAP	0x08
#define	USB_BOS_TYPE_PD_PRODUCER_CAP	0x09
#define	USB_BOS_TYPE_SUPERSPEED_PLUS	0x0a
#define	USB_BOS_TYPE_PRECISION_TIME	0x0b
#define	USB_BOS_TYPE_WUSB_EXT		0x0c

/*
 * General Binary Object Store (BOS) descriptor. This is returned at the start
 * of the BOS tree. See USB 3.1/Table 9-12.
 */
typedef struct usb_bos_descr {
	uint8_t		bLength;		/* Descriptor size */
	uint8_t		bDescriptorType;	/* Set to USB_DESCR_TYPE_BOS */
	uint16_t	wTotalLength;		/* Total length */
	uint8_t		bNumDeviceCaps;		/* Number of caps that follow */
} usb_bos_descr_t;

/*
 * This is the size of the usb_bos_descr_t in terms of packed bytes.
 */
#define	USB_BOS_PACKED_SIZE	5

/*
 * This represents a Device Capability Descriptor. bNumDeviceCaps of these
 * follow the usb_bos_descr_t. This structure is the generic header of each
 * device capability. Capability specific ones follow this. See USB 3.1/Table
 * 9-14.
 */
typedef struct usb_dev_cap_descr {
	uint8_t		bLength;		/* Descriptor size */
	uint8_t		bDescriptorType;	/* USB_TYPE_DEV_CAPABILITY */
	uint8_t		bDevCapabilityType;	/* USB_BOS_TYPE_* value */
} usb_dev_cap_descr_t;

#define	USB_DEV_CAP_PACKED_SIZE	3

/*
 * SuperSpeed devices include this descriptor to describe additional
 * capabilities that they have when operating in USB 2.0 High-Speed mode. See
 * USB 3.1/9.6.2.1 USB 2.0 Extension.
 */
typedef struct usb_bos_usb2ext {
	uint8_t		bLength;
	uint8_t		bDescriptorType;
	uint8_t		bDevCapabilityType;
	uint32_t	bmAttributes;		/* Bitfield defined below */
} usb_bos_usb2ext_t;

#define	USB_BOS_USB2EXT_PACKED_SIZE	7

#define	USB_BOS_USB2EXT_LPM	0x02

/*
 * SuperSpeed devices include this descriptor to describe various hardware
 * attributes related to basic USB 3.0 SuperSpeed functionality. See USB
 * 3.1/9.6.2.2 SuperSpeed USB Device Capability.
 */
typedef struct usb_bos_ssusb {
	uint8_t		bLength;
	uint8_t		bDescriptorType;
	uint8_t		bDevCapabilityType;
	uint8_t		bmAttributes;		/* Capability bitfield */
	uint16_t	wSpeedsSupported;	/* speed bitmap defined below */
	uint8_t		bFunctionalitySupport;	/* Minimum supported speed */
	uint8_t		bU1DevExitLat;		/* Exit latency in us */
	uint16_t	bU2DevExitLat;		/* Exit latency in us */
} usb_bos_ssusb_t;

#define	USB_BOS_SSUSB_PACKED_SIZE	10

#define	USB_BOS_SSUB_CAP_LTM	0x02

#define	USB_BOS_SSUSB_SPEED_LOW		(1 << 0)
#define	USB_BOS_SSUSB_SPEED_FULL	(1 << 1)
#define	USB_BOS_SSUSB_SPEED_HIGH	(1 << 2)
#define	USB_BOS_SSUSB_SPEED_SUPER	(1 << 3)

/*
 * This structure is used to indicate a UUID for a given device that could
 * register on multiple ports. For example, a hub that appears on both a USB 2.x
 * and USB 3.x port like a hub. This UUID allows one to know that the device is
 * the same. See USB 3.1/9.6.2.3 Container ID.
 */
typedef struct usb_bos_container {
	uint8_t		bLength;
	uint8_t		bDescriptorType;
	uint8_t		bDevCapabilityType;
	uint8_t		bReserved;
	uint8_t		ContainerId[16];
} usb_bos_container_t;

#define	USB_BOS_CONTAINER_PACKED_SIZE	20

/*
 * This structure is used to indicate a platform-specific capability. For more
 * information, see USB 3.1/9.6.2.4 Platform Descriptor.
 */
typedef struct usb_bos_platform {
	uint8_t		bLength;
	uint8_t		bDescriptorType;
	uint8_t		bDevCapabilityType;
	uint8_t		bReserved;
	uint8_t		PlatformCapabilityUUID[16];
	uint8_t		CapabilityData[];
} usb_bos_platform_t;

#define	USB_BOS_PLATFORM_MIN_PACKED_SIZE	20

/*
 * This structure is used to indicate capabilities and attributes of a
 * SuperSpeedPlus link. This describes the USB 3.1+ speed needs and minimum
 * attributes of the device. See USB 3.1/9.6.2.5 SuperSpeedPlus USB Device
 * Capability.
 */
typedef struct usb_bos_ssplus {
	uint8_t		bLength;
	uint8_t		bDescriptortype;
	uint8_t		bDevCapabilityType;
	uint8_t		bReserved;
	uint32_t	bmAttributes;
	uint16_t	wFunctionalitySupport;
	uint16_t	wReserved;
	uint32_t	bmSublinkSpeedAttr[];
} usb_bos_ssplus_t;

#define	USB_BOS_SSPLUS_MIN_PACKED_SIZE	16

/*
 * These macros take apart the bmAttributes fields.
 */
#define	USB_BOS_SSPLUS_NSSAC(x)	(((x) & 0xf) + 1)
#define	USB_BOS_SSPLUS_NSSIC(x)	((((x) & 0xf0) >> 4) + 1)

/*
 * These macros take apart the wFunctionalitySupport member.
 */
#define	USB_BOS_SSPLUS_MIN_SSAI(x)	((x) & 0x0f)
#define	USB_BOS_SSPLUS_MIN_RX_LANE(x)	(((x) >> 8) & 0xf)
#define	USB_BOS_SSPLUS_MIN_TX_LANE(x)	(((x) >> 12) & 0xf)

/*
 * These macros are used to take apart the bmSublinkSpeedAttr members. There is
 * always at least one of them that exist in each attribute; however, there
 * could be more based on the value in NSSAC.
 */
#define	USB_BOS_SSPLUS_ATTR_SSID(x)	((x) & 0xf)
#define	USB_BOS_SSPLUS_ATTR_LSE(x)	(((x) >> 4) & 0x3)
#define	USB_BOS_SSPLUS_ATTR_LSE_BITPS	0
#define	USB_BOS_SSPLUS_ATTR_LSE_KBITPS	1
#define	USB_BOS_SSPLUS_ATTR_LSE_GBITPS	2

/*
 * These two macros take apart the sublink type. bit 6 indicates whether or not
 * the links are symmetric or asymmetric. It is asymmetric if the value is set
 * to one (USB_BOS_SSPLUS_ATTR_ST_ASYM), symmetric otherwise. If it is
 * asymmetric, then bit 7 indicates whether or not it's a tx or rx link.
 */
#define	USB_BOS_SSPLUS_ATTR_ST_ASYM	(1 << 6)
#define	USB_BOS_SSPLUS_ATTR_ST_TX	(1 << 7)

#define	USB_BOS_SSPLUS_ATTR_LP(x)	(((x) >> 14) & 0x3)
#define	USB_BOS_SSPLUS_ATTR_LP_SS	0x0
#define	USB_BOS_SSPLUS_ATTR_LP_SSPLUS	0x1

#define	USB_BOS_SSPLUS_ATTR_LSM(x)	((x) >> 16)

typedef struct usb_bos_precision_time {
	uint8_t		bLength;
	uint8_t		bDescriptorType;
	uint8_t		bDevCapabilityType;
} usb_bos_precision_time_t;

#define	USB_BOS_PRECISION_TIME_PACKED_SIZE	3

/*
 * This structure serves as an internal, parsed representation of a USB bos
 * descriptor.
 */
typedef struct usb_bos {
	uint8_t ubos_length;
	uint8_t ubos_type;
	union {
		usb_bos_usb2ext_t ubos_usb2;
		usb_bos_ssusb_t	ubos_ssusb;
		usb_bos_container_t ubos_container;
		usb_bos_platform_t ubos_platform;
		usb_bos_ssplus_t ubos_ssplus;
		usb_bos_precision_time_t ubos_time;
		uint8_t	ubos_raw[256];
	} ubos_caps;
} usb_bos_t;

#ifdef __cplusplus
}
#endif

#endif /* _SYS_USB_BOS_H */
