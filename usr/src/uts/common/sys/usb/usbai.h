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
 *
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 */

#ifndef	_SYS_USB_USBAI_H
#define	_SYS_USB_USBAI_H


#ifdef	__cplusplus
extern "C" {
#endif

/* This header file is for USBA2.0 */
#define	USBA_MAJOR_VER 2
#define	USBA_MINOR_VER 0

/*
 * USBAI: Interfaces Between USBA and Client Driver
 *
 *
 * Universal USB device state management :
 *
 *	PWRED_DWN---<3----4>--ONLINE---<2-----1>-DISCONNECTED
 *	    |			 ^		     |
 *	    |			 6		     |
 *	    |			 |		     |
 *	    |			 5		     |
 *	    |			 v		     |
 *	    +----5>----------SUSPENDED----<5----7>---+
 *
 *	1 = Device Unplug
 *	2 = Original Device reconnected
 *	3 = Device idles for time T & transitions to low power state
 *	4 = Remote wakeup by device OR Application kicking off IO to device
 *	5 = Notification to save state prior to DDI_SUSPEND
 *	6 = Notification to restore state after DDI_RESUME with correct device
 *	7 = Notification to restore state after DDI_RESUME with device
 *	    disconnected or a wrong device
 *
 *	NOTE: device states 0x80 to 0xff are device specific and can be
 *		used by client drivers
 */
#define	USB_DEV_ONLINE		1	/* device is online */
#define	USB_DEV_DISCONNECTED	2	/* indicates disconnect */
#define	USB_DEV_SUSPENDED	3	/* DDI_SUSPEND operation */
#define	USB_DEV_PWRED_DOWN	4	/* indicates power off state */


/*
 * ***************************************************************************
 * USBA error and status definitions
 * ***************************************************************************
 */


/*
 * USBA function return values
 */
#define	USB_SUCCESS		0	/* call success			  */
#define	USB_FAILURE		-1	/* unspecified USBA or HCD error  */
#define	USB_NO_RESOURCES	-2	/* no resources available	  */
#define	USB_NO_BANDWIDTH	-3	/* no bandwidth available	  */
#define	USB_NOT_SUPPORTED	-4	/* function not supported by HCD  */
#define	USB_PIPE_ERROR		-5	/* error occured on the pipe	  */
#define	USB_INVALID_PIPE	-6	/* pipe handle passed is invalid  */
#define	USB_NO_FRAME_NUMBER	-7	/* frame No or ASAP not specified */
#define	USB_INVALID_START_FRAME	-8	/* starting USB frame not valid	  */
#define	USB_HC_HARDWARE_ERROR	-9	/* usb host controller error	  */
#define	USB_INVALID_REQUEST	-10	/* request had invalid values	  */
#define	USB_INVALID_CONTEXT	-11	/* sleep flag in interrupt context */
#define	USB_INVALID_VERSION	-12	/* invalid version specified	  */
#define	USB_INVALID_ARGS	-13	/* invalid func args specified	  */
#define	USB_INVALID_PERM	-14	/* privileged operation		  */
#define	USB_BUSY		-15	/* busy condition		  */


/*
 * USB request completion flags, more than one may be set.
 * The following flags are returned after a recovery action by
 * HCD or USBA (autoclearing) or callbacks from pipe_close,
 * abort, reset, or stop polling.  More than one may be set.
 *
 * For sync requests, the client should check the request structure
 * for this flag to determine what has happened.
 *
 * All callbacks are queued to preserve order.	Note that if a normal callback
 * uses a kernel thread, order is not guaranteed since each callback may use
 * its own thread.  The next request will be submitted to the
 * HCD after the threads exits.
 *
 * Exception callbacks using a kernel thread may do auto clearing and no
 * new request will be started until this thread has completed its work.
 */
typedef enum {
	USB_CB_NO_INFO		= 0x00, /* no exception */
	USB_CB_STALL_CLEARED	= 0x01,	/* func stall cleared */
	USB_CB_FUNCTIONAL_STALL	= 0x02,	/* func stall occurred */
	USB_CB_PROTOCOL_STALL	= 0x04,	/* protocal stall occurred */
	USB_CB_RESET_PIPE	= 0x10, /* pipe was reset */
	USB_CB_ASYNC_REQ_FAILED = 0x80, /* thread couldn't be started */
	USB_CB_NO_RESOURCES	= 0x100, /* no resources */
	USB_CB_SUBMIT_FAILED	= 0x200, /* req was queued then submitted */
					/* to HCD which rejected it */
	USB_CB_INTR_CONTEXT	= 0x400 /* Callback is in interrupt context. */
} usb_cb_flags_t;


/*
 * completion reason
 *
 * Set by HCD; only one can be set.
 */
typedef enum {
	USB_CR_OK		= 0,	/* no errors detected		*/
	USB_CR_CRC		= 1,	/* crc error detected		*/
	USB_CR_BITSTUFFING	= 2,	/* bit stuffing violation	*/
	USB_CR_DATA_TOGGLE_MM	= 3,	/* d/t PID did not match	*/
	USB_CR_STALL		= 4,	/* e/p returned stall PID	*/
	USB_CR_DEV_NOT_RESP	= 5,	/* device not responding	*/
	USB_CR_PID_CHECKFAILURE = 6,	/* check bits on PID failed	*/
	USB_CR_UNEXP_PID	= 7,	/* receive PID was not valid	*/
	USB_CR_DATA_OVERRUN	= 8,	/* data size exceeded		*/
	USB_CR_DATA_UNDERRUN	= 9,	/* less data received		*/
	USB_CR_BUFFER_OVERRUN	= 10,	/* memory write can't keep up	*/
	USB_CR_BUFFER_UNDERRUN	= 11,	/* buffer underrun		*/
	USB_CR_TIMEOUT		= 12,	/* command timed out		*/
	USB_CR_NOT_ACCESSED	= 13,	/* Not accessed by hardware	*/
	USB_CR_NO_RESOURCES	= 14,	/* no resources			*/
	USB_CR_UNSPECIFIED_ERR	= 15,	/* unspecified usba or hcd err	*/
	USB_CR_STOPPED_POLLING	= 16,	/* intr/isoc IN polling stopped	*/
	USB_CR_PIPE_CLOSING	= 17,	/* intr/isoc IN pipe closed	*/
	USB_CR_PIPE_RESET	= 18,	/* intr/isoc IN pipe reset	*/
	USB_CR_NOT_SUPPORTED	= 19,	/* command not supported	*/
	USB_CR_FLUSHED		= 20,	/* this request was flushed	*/
	USB_CR_HC_HARDWARE_ERR	= 21	/* usb host controller error	*/
} usb_cr_t;


/*
 * ***************************************************************************
 * General definitions, used all over
 * ***************************************************************************
 *
 *	A pipe handle is returned by usb_pipe_open() on success for
 *	all pipes except the default pipe which is accessed from
 *	the registration structure.  Placed here as forward referenced by
 *	usb_client_dev_data_t below.
 *
 *	The pipe_handle is opaque to the client driver.
 */
typedef	struct usb_pipe_handle	*usb_pipe_handle_t;

/*
 * General opaque pointer.
 */
typedef struct usb_opaque *usb_opaque_t;


/*
 * USB flags argument to USBA interfaces
 */
typedef enum {
	/* do not block until resources are available */
	USB_FLAGS_NOSLEEP		= 0x0000,
	/* block until resources are available */
	USB_FLAGS_SLEEP			= 0x0100,
	/* reserved */
	USB_FLAGS_RESERVED		= 0xFE00
} usb_flags_t;


/*
 * ***************************************************************************
 * Descriptor definitions (from USB 2.0 specification, chapter 9)
 * ***************************************************************************
 */


/*
 * USB Descriptor Management
 *
 * Standard USB descriptors:
 *
 * USB devices present their configuration information in response to
 * a GET_DESCRIPTOR request in a form which is little-endian and,
 * for multibyte integers, unaligned.  It is also position-dependent,
 * which makes non-sequential access to particular interface or
 * endpoint data inconvenient.
 * A GET_DESCRIPTOR request may yield a chunk of data that contains
 * multiple descriptor types.  For example, a GET_DESCRIPTOR request
 * for a CONFIGURATION descriptor could return the configuration
 * descriptor followed by an interface descriptor and the relevant
 * endpoint descriptors.
 *
 * usb_get_dev_data() interface provides an easy way to get all
 * the descriptors and avoids parsing standard descriptors by each
 * client driver
 *
 * usb_dev_descr:
 *	usb device descriptor, refer to	USB 2.0/9.6.1,
 */
typedef struct usb_dev_descr {
	uint8_t		bLength;	/* descriptor size		*/
	uint8_t		bDescriptorType; /* set to DEVICE		*/
	uint16_t	bcdUSB;		/* USB spec rel. number	in bcd	*/
	uint8_t		bDeviceClass;	/* class code			*/
	uint8_t		bDeviceSubClass; /* sub	class code		*/
	uint8_t		bDeviceProtocol; /* protocol code		*/
	uint8_t		bMaxPacketSize0; /* max	pkt size of e/p	0	*/
	uint16_t	idVendor;	/* vendor ID			*/
	uint16_t	idProduct;	/* product ID			*/
	uint16_t	bcdDevice;	/* device release number in bcd	*/
	uint8_t		iManufacturer;	/* manufacturing string		*/
	uint8_t		iProduct;	/* product string		*/
	uint8_t		iSerialNumber;	/* serial number string index	*/
	uint8_t		bNumConfigurations; /* #configs for device	*/
} usb_dev_descr_t;


/*
 * USB Device Qualifier Descriptor
 *
 * The device_qualifier descriptor describes information about a High
 * speed capable device that would change if the device were operating
 * at other (Full) speed. Example: if the device is currently operating
 * at Full-speed, the device_qualifier returns information about how if
 * would operate at high-speed and vice-versa.
 *
 * usb_dev_qlf_descr:
 *
 *	usb device qualifier descriptor, refer to USB 2.0/9.6.2
 */
typedef struct usb_dev_qlf_descr {
	uint8_t		bLength;	/* descriptor size		*/
	uint8_t		bDescriptorType; /* set to DEVICE		*/
	uint16_t	bcdUSB;		/* USB spec rel. number	in bcd	*/
	uint8_t		bDeviceClass;	/* class code			*/
	uint8_t		bDeviceSubClass; /* sub	class code		*/
	uint8_t		bDeviceProtocol; /* protocol code		*/
	uint8_t		bMaxPacketSize0; /* max	pkt size of e/p	0	*/
	uint8_t		bNumConfigurations; /* #configs for device	*/
	uint8_t		bReserved;	/* reserved field		*/
} usb_dev_qlf_descr_t;


/*
 * usb_cfg_descr:
 *	usb configuration descriptor, refer to USB 2.0/9.6.3
 */
typedef struct usb_cfg_descr {
	uint8_t		bLength;	/* descriptor size		*/
	uint8_t		bDescriptorType; /* set to CONFIGURATION	*/
	uint16_t	wTotalLength;	/* total length of data returned */
	uint8_t		bNumInterfaces;	/* # interfaces	in config	*/
	uint8_t		bConfigurationValue; /* arg for SetConfiguration */
	uint8_t		iConfiguration;	/* configuration string		*/
	uint8_t		bmAttributes;	/* config characteristics	*/
	uint8_t		bMaxPower;	/* max pwr consumption		*/
} usb_cfg_descr_t;

/*
 * Default configuration index setting for devices with multiple
 * configurations. Note the distinction between config index and config
 * number
 */
#define	USB_DEV_DEFAULT_CONFIG_INDEX	0

/*
 * bmAttribute values for Configuration Descriptor
 */
#define	USB_CFG_ATTR_SELFPWR		0x40
#define	USB_CFG_ATTR_REMOTE_WAKEUP	0x20
#define	USB_CFG_ATTR_BAT_PWR		0x10

/*
 * USB Other Speed Configuration Descriptor
 *
 * The other_speed_configuration descriptor describes a configuration of
 * a High speed capable device if it were operating at its other possible
 * (Full) speed and vice-versa.
 *
 * usb_other_speed_cfg_descr:
 *	usb other speed configuration descriptor, refer to USB 2.0/9.6.4
 */
typedef struct usb_other_speed_cfg_descr {
	uint8_t		bLength;	/* descriptor size		*/
	uint8_t		bDescriptorType; /* set to CONFIGURATION	*/
	uint16_t	wTotalLength;	/* total length of data returned */
	uint8_t		bNumInterfaces;	/* # interfaces	in config	*/
	uint8_t		bConfigurationValue; /* arg for SetConfiguration */
	uint8_t		iConfiguration;	/* configuration string		*/
	uint8_t		bmAttributes;	/* config characteristics	*/
	uint8_t		bMaxPower;	/* max pwr consumption		*/
} usb_other_speed_cfg_descr_t;


/*
 * usb_ia_descr:
 *	usb interface association descriptor, refer to USB 2.0 ECN(IAD)
 */
typedef  struct usb_ia_descr {
	uint8_t		bLength;		/* descriptor size	*/
	uint8_t		bDescriptorType;	/* INTERFACE_ASSOCIATION */
	uint8_t		bFirstInterface;	/* 1st interface number */
	uint8_t		bInterfaceCount;	/* number of interfaces */
	uint8_t		bFunctionClass;		/* class code		*/
	uint8_t		bFunctionSubClass;	/* sub class code	*/
	uint8_t		bFunctionProtocol;	/* protocol code	*/
	uint8_t		iFunction;		/* description string	*/
} usb_ia_descr_t;


/*
 * usb_if_descr:
 *	usb interface descriptor, refer	to USB 2.0/9.6.5
 */
typedef  struct usb_if_descr {
	uint8_t		bLength;		/* descriptor size	*/
	uint8_t		bDescriptorType;	/* set to INTERFACE	*/
	uint8_t		bInterfaceNumber;	/* interface number	*/
	uint8_t		bAlternateSetting;	/* alt. interface number */
	uint8_t		bNumEndpoints;		/* # of endpoints	*/
	uint8_t		bInterfaceClass;	/* class code		*/
	uint8_t		bInterfaceSubClass;	/* sub class code	*/
	uint8_t		bInterfaceProtocol;	/* protocol code	*/
	uint8_t		iInterface;		/* description string	*/
} usb_if_descr_t;


/*
 * usb_ep_descr:
 *	usb endpoint descriptor, refer to USB 2.0/9.6.6
 */
typedef struct usb_ep_descr {
	uint8_t		bLength;		/* descriptor size	*/
	uint8_t		bDescriptorType;	/* set to ENDPOINT	*/
	uint8_t		bEndpointAddress;	/* address of this e/p */
	uint8_t		bmAttributes;		/* transfer type	*/
	uint16_t	wMaxPacketSize;		/* maximum packet size	*/
	uint8_t		bInterval;		/* e/p polling interval */
} usb_ep_descr_t;

/*
 * bEndpointAddress masks
 */
#define	USB_EP_NUM_MASK		0x0F		/* endpoint number mask */
#define	USB_EP_DIR_MASK		0x80		/* direction mask */
#define	USB_EP_DIR_OUT		0x00		/* OUT endpoint */
#define	USB_EP_DIR_IN		0x80		/* IN endpoint */

/*
 * bmAttribute transfer types for endpoints
 */
#define	USB_EP_ATTR_MASK	0x03		/* transfer type mask */
#define	USB_EP_ATTR_CONTROL	0x00		/* control transfer */
#define	USB_EP_ATTR_ISOCH	0x01		/* isochronous transfer */
#define	USB_EP_ATTR_BULK	0x02		/* bulk transfer */
#define	USB_EP_ATTR_INTR	0x03		/* interrupt transfer */

/*
 * bmAttribute synchronization types for endpoints (isochronous only)
 */
#define	USB_EP_SYNC_MASK	0x0C		/* synchronization mask */
#define	USB_EP_SYNC_NONE	0x00		/* no synchronization */
#define	USB_EP_SYNC_ASYNC	0x04		/* asynchronous */
#define	USB_EP_SYNC_ADPT	0x08		/* adaptive */
#define	USB_EP_SYNC_SYNC	0x0C		/* synchronous */

/*
 * bmAttribute synchronization feedback types for endpoints (isochronous only)
 */
#define	USB_EP_USAGE_MASK	0x30		/* sync feedback mask */
#define	USB_EP_USAGE_DATA	0x00		/* data endpoint */
#define	USB_EP_USAGE_FEED	0x10		/* feedback endpoint */
#define	USB_EP_USAGE_IMPL	0x20		/* implicit feedback endpoint */

/*
 * wMaxPacketSize values for endpoints (isoch and interrupt, high speed only)
 */
#define	USB_EP_MAX_PKTSZ_MASK	0x03FF		/* Mask for packetsize bits */
#define	USB_EP_MAX_XACTS_MASK	0x0C00		/* Max Transactns/microframe */
#define	USB_EP_MAX_XACTS_SHIFT	10		/* Above is 10 bits from end */

/*
 * Ranges for endpoint parameter values.
 */

/* Min and Max NAK rates for high sped control endpoints. */
#define	USB_EP_MIN_HIGH_CONTROL_INTRVL	0
#define	USB_EP_MAX_HIGH_CONTROL_INTRVL	255

/* Min and Max NAK rates for high speed bulk endpoints. */
#define	USB_EP_MIN_HIGH_BULK_INTRVL	0
#define	USB_EP_MAX_HIGH_BULK_INTRVL	255

/* Min and Max polling intervals for low, full speed interrupt endpoints. */
#define	USB_EP_MIN_LOW_INTR_INTRVL	1
#define	USB_EP_MAX_LOW_INTR_INTRVL	255
#define	USB_EP_MIN_FULL_INTR_INTRVL	1
#define	USB_EP_MAX_FULL_INTR_INTRVL	255

/*
 * Min and Max polling intervals for high speed interrupt endpoints, and for
 * isochronous endpoints.
 * Note that the interval is 2**(value-1).  See Section 9.6.6 of USB 2.0 spec.
 */
#define	USB_EP_MIN_HIGH_INTR_INTRVL	1
#define	USB_EP_MAX_HIGH_INTR_INTRVL	16
#define	USB_EP_MIN_FULL_ISOCH_INTRVL	1
#define	USB_EP_MAX_FULL_ISOCH_INTRVL	16
#define	USB_EP_MIN_HIGH_ISOCH_INTRVL	1
#define	USB_EP_MAX_HIGH_ISOCH_INTRVL	16

/*
 * usb_string_descr:
 *	usb string descriptor, refer to	 USB 2.0/9.6.7
 */
typedef struct usb_string_descr {
	uint8_t		bLength;		/* descr size */
	uint8_t		bDescriptorType;	/* set to STRING */
	uint8_t		bString[1];		/* variable length unicode */
						/* encoded string	*/
} usb_string_descr_t;

#define	USB_MAXSTRINGLEN	255		/* max string descr length */

/*
 * ***************************************************************************
 * Client driver registration with USBA
 * ***************************************************************************
 *
 *	The client registers with USBA during attach in two steps
 *	using usb_client_attach() and usb_get_dev_data(). On completion, the
 *	registration data has been initialized.  Most data items are
 *	straightforward.  Among the items returned in the data is the tree of
 *	parsed descriptors, in dev_cfg;	 the number of configurations parsed,
 *	in dev_n_cfg; a pointer to the current configuration in the tree,
 *	in dev_curr_cfg; the index of the first valid interface in the
 *	tree, in dev_curr_if, and a parse level that accurately reflects what
 *	is in the tree, in dev_parse_level.
 */


/*
 * ***************************************************************************
 * Data structures used in the configuration tree
 * ***************************************************************************
 */

/*
 * Tree data structure for each configuration in the tree
 */
typedef struct usb_cfg_data {
	struct usb_cfg_descr	cfg_descr;	/* parsed config descr */
	struct usb_if_data	*cfg_if;	/* interfaces for this cfg */
						/* indexed by interface num */
	struct usb_cvs_data	*cfg_cvs;	/* class/vendor specific */
						/* descrs mod/extend cfg */
	char			*cfg_str;	/* string descriptor */
	uint_t			cfg_n_if;	/* #elements in cfg_if[] */
	uint_t			cfg_n_cvs;	/* #elements in cfg_cvs[] */
	uint_t			cfg_strsize;	/* size of string descr */
} usb_cfg_data_t;


/*
 * Tree data structure for each alternate interface set
 * in each represented configuration
 */
typedef struct usb_if_data {
	struct usb_alt_if_data	*if_alt;	/* sparse array of alts */
						/* indexed by alt setting */
	uint_t			if_n_alt;	/* #elements in if_alt[] */
} usb_if_data_t;


/*
 * Tree data structure for each alternate of each alternate interface set
 */
typedef struct usb_alt_if_data {
	usb_if_descr_t		altif_descr;	/* parsed alternate if descr */
	struct usb_ep_data	*altif_ep;	/* endpts for alt if */
						/* (not a sparse array */
	struct usb_cvs_data	*altif_cvs;	/* cvs for this alt if */
	char			*altif_str;	/* string descriptor */
	uint_t			altif_n_ep;	/* #elements in altif_ep[] */
	uint_t			altif_n_cvs;	/* #elements in  altif_cvs[] */
	uint_t			altif_strsize;	/* size of string descr */
} usb_alt_if_data_t;


/*
 * Tree data structure for each endpoint of each alternate
 */
typedef struct usb_ep_data {
	usb_ep_descr_t		ep_descr;	/* endpoint descriptor */
	struct usb_cvs_data	*ep_cvs;	/* cv mod/extending this ep */
	uint_t			ep_n_cvs;	/* #elements in ep_cvs[] */
} usb_ep_data_t;


/*
 * Tree data structure for each class/vendor specific descriptor
 */
typedef struct usb_cvs_data {
	uchar_t			*cvs_buf;	/* raw data of cvs descr */
	uint_t			cvs_buf_len;	/* cvs_buf size */
} usb_cvs_data_t;


/*
 *	Parse_level determines the extent to which the tree is built, the amount
 *	of parsing usb_client_attach() is to do.  It has the following values:
 *
 *	USB_PARSE_LVL_NONE - Build no tree.  dev_n_cfg will return 0, dev_cfg
 *			     will return NULL, the dev_curr_xxx fields will be
 *			     invalid.
 *	USB_PARSE_LVL_IF   - Parse configured interface only, if configuration#
 *			     and interface properties are set (as when different
 *			     interfaces are viewed by the OS as different device
 *			     instances). If an OS device instance is set up to
 *			     represent an entire physical device, this works
 *			     like USB_PARSE_LVL_ALL.
 *	USB_PARSE_LVL_CFG  - Parse entire configuration of configured interface
 *			     only.  This is like USB_PARSE_LVL_IF except entire
 *			     configuration is returned.
 *	USB_PARSE_LVL_ALL  - Parse entire device (all configurations), even
 *			     when driver is bound to a single interface of a
 *			     single configuration.
 */
typedef enum {
	USB_PARSE_LVL_NONE		= 0,
	USB_PARSE_LVL_IF		= 1,
	USB_PARSE_LVL_CFG		= 2,
	USB_PARSE_LVL_ALL		= 3
} usb_reg_parse_lvl_t;


/*
 * Registration data returned by usb_get_dev_data().  Configuration tree roots
 * are returned in dev_cfg array.
 */
typedef struct usb_client_dev_data {
	usb_pipe_handle_t	dev_default_ph;	/* default pipe handle */
	ddi_iblock_cookie_t	dev_iblock_cookie; /* for mutex_init's */
	struct usb_dev_descr	*dev_descr;	/* cooked device descriptor */
	char			*dev_mfg;	/* manufacturing ID */
	char			*dev_product;	/* product ID */
	char			*dev_serial;	/* serial number */
	usb_reg_parse_lvl_t	dev_parse_level; /* USB_PARSE_LVL_* flag */
	struct usb_cfg_data	*dev_cfg;	/* configs for this device */
						/* indexed by config index */
	uint_t			dev_n_cfg;	/* #elements in dev_cfg[] */
	struct usb_cfg_data	*dev_curr_cfg;	/* current cfg */
	int			dev_curr_if;	/* current interface number */
} usb_client_dev_data_t;


/*
 * ***************************************************************************
 * Device configuration descriptor tree functions
 * ***************************************************************************
 */

/*
 * usb_get_dev_data:
 *	returns initialized registration data. 	Most data items are clear.
 *	Among the items returned is the tree ofparsed descriptors in dev_cfg;
 *	and the number of configurations parsed in dev_n_cfg.
 *
 * Arguments:
 *	dip		- pointer to devinfo node of the client
 *	dev_data	- return registration data at this address
 *	parse_level	- See above
 *	flags		- None used
 *
 * Return Values:
 *	USB_SUCCESS		- usb_register_client succeeded
 *	USB_INVALID_ARGS	- received null dip or reg argument
 *	USB_INVALID_CONTEXT	- called with sleep from callback context
 *	USB_FAILURE		- bad descriptor info or other internal failure
 *
 * Notes:
 * 	1) The non-standard USB descriptors are returned in RAW format.
 *
 *	2) The registration data is unshared. Each client receives its own copy.
 *	(The default control pipe may be shared, even though its tree
 *	description will be unique per device.)
 *
 */
int usb_get_dev_data(
	dev_info_t			*dip,
	usb_client_dev_data_t		**dev_data,
	usb_reg_parse_lvl_t		parse_level,
	usb_flags_t			flags);

/*
 * usb_free_dev_data:
 * undoes what usb_get_dev_data() set up.  It releases
 * memory for all strings, descriptors, and trees set up by usb_get_dev_data().
 *
 * Arguments:
 *	dip		- pointer to devinfo node of the client
 *	dev_data	- pointer to registration data containing the tree.
 */
void usb_free_dev_data(
	dev_info_t			*dip,
	usb_client_dev_data_t		*dev_data);

/*
 * usb_free_descr_tree:
 *	Take down the configuration tree while leaving the rest	of the
 *	registration intact.  This can be used, for example, after attach has
 *	copied any descriptors it needs from the tree, but the rest of the
 *	registration data needs to remain intact.
 *
 *	The following usb_client_dev_data_t fields will be modified:
 *		dev_cfg will be NULL
 *		dev_n_cfg will be 0
 *		dev_curr_cfg_ndx and dev_curr_if will be invalid
 *		dev_parse_level will be USB_REG_DESCR_NONE
 *
 * Arguments:
 *	dip		- pointer to devinfo node of the client
 *	dev_data	- pointer to registration data containing the tree.
 */
void usb_free_descr_tree(
	dev_info_t			*dip,
	usb_client_dev_data_t		*dev_data);


/*
 * usb_print_descr_tree:
 *	Dump to the screen a descriptor tree as returned by
 *	usbai_register_client.
 *
 * Arguments:
 *	dip		- pointer to devinfo of the client
 *	dev_data	- pointer to registration area containing the tree
 *
 * Returns:
 *	USB_SUCCESS		- tree successfully dumped
 *	USB_INVALID_CONTEXT	- called from callback context
 *	USB_INVALID_ARGS	- bad arguments given
 */
int usb_print_descr_tree(
	dev_info_t		*dip,
	usb_client_dev_data_t	*dev_data);


/*
 * ***************************************************************************
 * Registration and versioning
 * ***************************************************************************
 */


/*
 * USBA client drivers are required to define USBDRV_MAJOR_VER
 * USBDRV_MINOR_VER and pass USBDRV_VERSION as the version
 * number to usb_client_attach
 */
#if !defined(USBA_MAJOR_VER) || !defined(USBA_MINOR_VER)
#error incorrect USBA header
#endif

/*
 * Driver major version must be the same as USBA major version, and
 * driver minor version must be <= USBA minor version
 */
#if !defined(USBA_FRAMEWORK)
#if defined(USBDRV_MAJOR_VER) && defined(USBDRV_MINOR_VER)

#if (USBDRV_MAJOR_VER != USBA_MAJOR_VER)
#error USBA and driver major versions do not match
#endif
#if (USBDRV_MINOR_VER > USBA_MINOR_VER)
#error USBA and driver minor versions do not match
#endif

#endif
#endif

#define	USBA_MAKE_VER(major, minor) ((major) << 8 | (minor))
#define	USBA_GET_MAJOR(ver) ((ver) >> 8)
#define	USBA_GET_MINOR(ver) ((ver) & 0xff)

#define	USBDRV_VERSION	USBA_MAKE_VER(USBDRV_MAJOR_VER, USBDRV_MINOR_VER)


/*
 * usb_client_attach:
 *
 * Arguments:
 *	dip		- pointer to devinfo node of the client
 *	version 	- USBA registration version number
 *	flags		- None used
 *
 * Return Values:
 *	USB_SUCCESS		- attach succeeded
 *	USB_INVALID_ARGS	- received null dip or reg argument
 *	USB_INVALID_CONTEXT	- called with sleep from callback context
 *				  or not at attach time
 *	USB_INVALID_VERSION	- version argument is incorrect.
 *	USB_FAILURE		- other internal failure
 */
int usb_client_attach(
	dev_info_t			*dip,
	uint_t				version,
	usb_flags_t			flags);

/*
 * usb_client_detach:
 *
 * Arguments:
 *	dip		- pointer to devinfo node of the client
 *	dev_data	- pointer to data to free. may be NULL
 */
void usb_client_detach(
	dev_info_t			*dip,
	struct usb_client_dev_data	*dev_data);

/*
 * ***************************************************************************
 * Functions for parsing / retrieving data from the descriptor tree
 * ***************************************************************************
 */

/*
 * Function for unpacking any kind of little endian data, usually desriptors
 *
 * Arguments:
 *	format		- string indicating the format in c, s, w, eg. "2c4ws"
 *			  which describes 2 bytes, 4 int, one short.
 *			  The number prefix parses the number of items of
 *			  the following type.
 *	data		- pointer to the LE data buffer
 *	datalen		- length of the data
 *	structure	- pointer to return structure where the unpacked data
 *			  will be written
 *	structlen	- length of the return structure
 *
 * return value:
 *	total number of bytes of the original data that was unpacked
 *	or USB_PARSE_ERROR
 */
#define	USB_PARSE_ERROR	0

size_t usb_parse_data(
	char			*format,
	uchar_t 		*data,
	size_t			datalen,
	void			*structure,
	size_t			structlen);

/*
 * usb_lookup_ep_data:
 *	Function to get specific endpoint data
 *	This function will not access the device.
 *
 * Arguments:
 *	dip		- pointer to dev info
 *	dev_datap	- pointer to registration data
 *	interface	- requested interface
 *	alternate	- requested alternate
 *	skip		- number of endpoints which match the requested type and
 *			  direction to skip before finding one to retrieve
 *	type		- endpoint type
 *	direction	- endpoint direction: USB_EP_DIR_IN/OUT or none
 *
 * Return Values:
 *	NULL or an endpoint data pointer
 */
usb_ep_data_t *usb_lookup_ep_data(
	dev_info_t		*dip,
	usb_client_dev_data_t	*dev_datap,
	uint_t			interface,
	uint_t			alternate,
	uint_t			skip,
	uint_t			type,
	uint_t			direction);


/* Language ID for string descriptors. */
#define	USB_LANG_ID		0x0409		/* English, US */

/*
 * usb_get_string_descr:
 *	Reads the string descriptor.  This function access the device and
 *	blocks.
 *
 * Arguments:
 *	dip		- pointer to devinfo of the client.
 *	langid		- LANGID to read different LOCALEs.
 *	index		- index to the string.
 *	buf		- user provided buffer for string descriptor.
 *	buflen		- user provided length of the buffer.
 *
 * Return Values:
 *	USB_SUCCESS	- descriptor is valid.
 *	USB_FAILURE	- full descriptor could not be retrieved.
 */
int usb_get_string_descr(
	dev_info_t		*dip,
	uint16_t		langid,
	uint8_t			index,
	char			*buf,
	size_t			buflen);


/*
 * ***************************************************************************
 * Addressing utility functions
 * ***************************************************************************
 */

/*
 * usb_get_addr returns the current usb address, mostly for debugging
 * purposes. The address may change after hotremove/insert.
 * This address will not change on a disconnect/reconnect of open device.
 */
int usb_get_addr(dev_info_t *dip);


/*
 * usb_get_if_number returns USB_COMBINED_NODE or USB_DEVICE_NODE
 * if the driver is responsible for the entire device.
 * Otherwise it returns the interface number.
 */
#define	USB_COMBINED_NODE	-1
#define	USB_DEVICE_NODE		-2

int usb_get_if_number(
	dev_info_t		*dip);

boolean_t usb_owns_device(
	dev_info_t		*dip);


/*
 * ***************************************************************************
 * Pipe	Management definitions and functions
 * ***************************************************************************
 */


/*
 *
 * usb_pipe_state:
 *
 * PIPE_STATE_IDLE:
 *	The pipe's policy is set, but the pipe currently isn't transferring
 *	data.
 *
 * PIPE_STATE_ACTIVE:
 *	The pipe's policy has been set, and the pipe is able to transmit data.
 *	When a control or bulk pipe is opened, the pipe's state is
 *	automatically set to PIPE_STATE_ACTIVE.  For an interrupt or
 *	isochronous pipe, the pipe state becomes PIPE_STATE_ACTIVE once
 *	the polling on the pipe has been initiated.
 *
 * PIPE_STATE_ERROR:
 *	The device has generated a error on the pipe.  The client driver
 *	must call usb_pipe_reset() to clear any leftover state that's associated
 *	with the pipe, clear the data toggle, and reset the state of the pipe.
 *
 *	Calling usb_pipe_reset() on a control or bulk pipe resets the state to
 *	PIPE_STATE_ACTIVE.  Calling usb_pipe_reset() on an interrupt or
 *	isochronous pipe, resets the state to PIPE_STATE_IDLE.
 *
 * State Diagram for Bulk/Control
 *
 *			+-<--normal completion------------------<-------^
 *			|						|
 *			V						|
 * usb_pipe_open-->[PIPE_STATE_IDLE]-usb_pipe_*_xfer->[PIPE_STATE_ACTIVE]
 *			^						|
 *			|						v
 *			- usb_pipe_reset<-[PIPE_STATE_ERROR]<-device error
 *
 * State Diagram for Interrupt/Isochronous IN
 *
 *			+-<--usb_pipe_stop_isoc/intr_polling----<-------^
 *			|						|
 *			V						|
 * usb_pipe_open-->[PIPE_STATE_IDLE]-usb_pipe_*_xfer->[PIPE_STATE_ACTIVE]
 *			^						|
 *			|						v
 *			+ usb_pipe_reset<-[PIPE_STATE_ERROR]<-device error
 *
 * State Diagram for Interrupt/Isochronous OUT
 *
 *			+-<--normal completion------------------<-------^
 *			|						|
 *			V						|
 * usb_pipe_open-->[PIPE_STATE_IDLE]-usb_pipe_*_xfer->[PIPE_STATE_ACTIVE]
 *			^						|
 *			|						v
 *			+ usb_pipe_reset<-[PIPE_STATE_ERROR]<-device error
 *
 *
 * The following table indicates which operations are allowed with each
 * pipe state:
 *
 * -------------------------------------------------------------------------+
 * ctrl/bulk	| idle	| active     | error  | sync closing | async closing|
 * -------------------------------------------------------------------------+
 * pipe xfer	|  OK	|queue (USBA)| reject | reject	     | reject	    |
 * pipe reset	| no-op | OK	     |	OK    | reject	     | reject	    |
 * pipe close	|  OK	| wait&close |	OK    | no-op	     | no-op	    |
 * -------------------------------------------------------------------------+
 *
 * -------------------------------------------------------------------------+
 * intr/isoc IN | idle	| active     | error  | sync closing | async closing|
 * -------------------------------------------------------------------------+
 * pipe xfer	|  OK	| reject     | reject | reject	     | reject	    |
 * pipe stoppoll| no-op | OK	     | no-op  | reject	     | reject	    |
 * pipe reset	| no-op | OK	     |	OK    | reject	     | reject	    |
 * pipe close	|  OK	| wait&close |	OK    | no-op	     | no-op	    |
 * -------------------------------------------------------------------------+
 *
 * -------------------------------------------------------------------------+
 * intr/isoc OUT| idle	| active     | error  | sync closing | async closing|
 * -------------------------------------------------------------------------+
 * pipe xfer	|  OK	|queue (HCD) | reject | reject	     | reject	    |
 * pipe stoppoll| reject| reject     | reject | reject	     | reject	    |
 * pipe reset	| no-op | OK	     |	OK    | reject	     | reject	    |
 * pipe close	|  OK	| wait&close |	OK    | no-op	     | no-op	    |
 * -------------------------------------------------------------------------+
 */
typedef enum {
	USB_PIPE_STATE_CLOSED		= 0,
	USB_PIPE_STATE_IDLE		= 1,
	USB_PIPE_STATE_ACTIVE		= 2,
	USB_PIPE_STATE_ERROR		= 3,
	USB_PIPE_STATE_CLOSING		= 4
} usb_pipe_state_t;


/*
 * pipe state control:
 *
 * return values:
 *	USB_SUCCESS	 - success
 *	USB_FAILURE	 - unspecified failure
 */
int usb_pipe_get_state(
	usb_pipe_handle_t	pipe_handle,
	usb_pipe_state_t	*pipe_state,
	usb_flags_t		flags);


/*
 * usb_pipe_policy
 *
 *	Pipe policy specifies how a pipe to an endpoint	should be used
 *	by the client driver and the HCD.
 */
typedef struct usb_pipe_policy {
	/*
	 * This is a hint indicating how many asynchronous operations
	 * requiring a kernel thread will be concurrently active.
	 * Allow at least one for synch exception callback handling
	 * and another for asynchronous closing of pipes.
	 */
	uchar_t		pp_max_async_reqs;
} usb_pipe_policy_t;


/*
 * usb_pipe_open():
 *
 * Before using any pipe including the default pipe, it must be opened.
 * On success, a pipe handle is returned for use in other usb_pipe_*()
 * functions.
 *
 * The default pipe can only be opened by the hub driver.
 *
 * For isochronous and interrupt pipes, bandwidth has been allocated and
 * guaranteed.
 *
 * Only the default pipe can be shared.  All other control pipes are
 * excusively opened by default.  A pipe policy and endpoint descriptor
 * must always be provided except for default pipe.
 *
 * Arguments:
 *	dip		- devinfo ptr.
 *	ep		- endpoint descriptor pointer.
 *	pipe_policy	- pointer to pipe policy which provides hints on how
 *			  the pipe will be used.
 *	flags		- USB_FLAGS_SLEEP wait for resources to become
 *			  available.
 *	pipe_handle	- a pipe handle pointer.  on a successful open,
 *			  a pipe_handle is returned in this pointer.
 *
 * Return values:
 *	USB_SUCCESS	 - open succeeded.
 *	USB_FAILURE	 - unspecified open failure or pipe is already open.
 *	USB_NO_RESOURCES - no resources were available to complete the open.
 *	USB_NO_BANDWIDTH - no bandwidth available (isoc/intr pipes).
 *	USB_*		 - refer to list of all possible return values in
 *			   this file
 */
int usb_pipe_open(
	dev_info_t		*dip,
	usb_ep_descr_t		*ep,
	usb_pipe_policy_t	*pipe_policy,
	usb_flags_t		flags,
	usb_pipe_handle_t	*pipe_handle);


/*
 * usb_pipe_close():
 *
 * Closes the pipe, releases resources and frees the pipe_handle.
 * Automatic polling, if active,  will be terminated.
 *
 * Arguments:
 *	dip		- devinfo ptr.
 *	pipe_handle	- pipe handle.
 *	flags		- USB_FLAGS_SLEEP:
 *				wait for resources, pipe
 *				to become free, and all callbacks completed.
 *	cb		- If USB_FLAGS_SLEEP has not been specified, a
 *			  callback will be performed.
 *	cb_arg		- the 2nd argument of the callback. Note that the
 *			  pipehandle will be zeroed and therefore not passed.
 *
 * Notes:
 *
 * Pipe close always succeeds regardless whether USB_FLAGS_SLEEP has been
 * specified or not.  An async close will always succeed if the hint in the
 * pipe policy has been correct about the max number of async requests
 * required.
 * In the unlikely event that no async requests can be queued, this
 * function will continue retrying before returning
 *
 * USBA prevents the client from submitting subsequent requests to a pipe
 * that is being closed.
 * Additional usb_pipe_close() requests on the same pipe causes USBA to
 * wait for the previous close(s) to complete.
 *
 * The pipe will not be destroyed until all activity on the pipe has
 * been drained, including outstanding request callbacks, async requests,
 * and other usb_pipe_*() calls.
 *
 * Calling usb_pipe_close() from a deferred callback (in kernel context)
 * with USB_FLAGS_SLEEP set, will cause deadlock
 */
void usb_pipe_close(
	dev_info_t		*dip,
	usb_pipe_handle_t	pipe_handle,
	usb_flags_t		flags,
	void			(*cb)(
				    usb_pipe_handle_t	ph,
				    usb_opaque_t	arg,	/* cb arg */
				    int			rval,
				    usb_cb_flags_t	flags),
	usb_opaque_t		cb_arg);


/*
 * usb_pipe_drain_reqs
 *	this function blocks until there are no more requests
 *	owned by this dip on the pipe
 *
 * Arguments:
 *	dip		- devinfo pointer
 *	pipe_handle	- opaque pipe handle
 *	timeout 	- timeout in seconds
 *	flags		- USB_FLAGS_SLEEP:
 *				wait for completion.
 *	cb		- if USB_FLAGS_SLEEP has not been specified
 *			  this callback function will be called on
 *			  completion. This callback may be NULL
 *			  and no notification of completion will then
 *			  be provided.
 *	cb_arg		- 2nd argument to callback function.
 *
 * callback and callback_arg should be NULL if USB_FLAGS_SLEEP has
 * been specified
 *
 * Returns:
 *	USB_SUCCESS	- pipe successfully reset or request queued
 *	USB_FAILURE	- timeout
 *	USB_INVALID_PIPE - pipe is invalid or already closed
 *	USB_INVALID_CONTEXT - called from interrupt context
 *	USB_INVALID_ARGS - invalid arguments
 *	USB_*		- refer to return values defines in this file
 */
int usb_pipe_drain_reqs(
	dev_info_t		*dip,
	usb_pipe_handle_t	pipe_handle,
	uint_t			time,
	usb_flags_t		flags,
	void			(*cb)(
				    usb_pipe_handle_t	ph,
				    usb_opaque_t	arg,	/* cb arg */
				    int			rval,
				    usb_cb_flags_t	flags),
	usb_opaque_t		cb_arg);


/*
 * Resetting a pipe: Refer to USB 2.0/10.5.2.2
 *	The pipe's requests are retired and the pipe is cleared.  The host state
 *	is moved to active. If the reflected endpoint state needs to be changed,
 *	that must be explicitly requested by the client driver.  The reset
 *	completes after all request callbacks have been completed.
 *
 * Arguments:
 *	dip		- devinfo pointer.
 *	pipe_handle	- pipe handle.
 *	flags		- USB_FLAGS_SLEEP:
 *				wait for completion.
 *	cb		- if USB_FLAGS_SLEEP has not been specified
 *			  this callback function will be called on
 *			  completion. This callback may be NULL
 *			  and no notification of completion will then
 *			  be provided.
 *	cb_arg		- 2nd argument to callback function.
 *
 * callback and callback_arg should be NULL if USB_FLAGS_SLEEP has
 * been specified
 *
 * Note: Completion notification may be *before* all async request threads
 *	have completed but *after* all immediate callbacks have completed.
 */
void usb_pipe_reset(
	dev_info_t		*dip,
	usb_pipe_handle_t	pipe_handle,
	usb_flags_t		usb_flags,
	void			(*cb)(
					usb_pipe_handle_t ph,
					usb_opaque_t	arg,
					int		rval,
					usb_cb_flags_t	flags),
	usb_opaque_t		cb_arg);


/*
 * The client driver can store a private data pointer in the
 * pipe_handle.
 *
 * return values:
 *	USB_SUCCESS	 - success
 *	USB_FAILURE	 - unspecified failure
 */
int usb_pipe_set_private(
	usb_pipe_handle_t	pipe_handle,
	usb_opaque_t		data);


usb_opaque_t usb_pipe_get_private(
	usb_pipe_handle_t	pipe_handle);


/*
 * ***************************************************************************
 * Transfer request definitions and functions
 * ***************************************************************************
 */


/*
 * USB xfer request attributes.
 * Set by the client driver, more than one may be set
 *
 * SHORT_XFER_OK if less data is transferred than specified, no error is
 *		returned.
 * AUTOCLEARING	if there is an exception, the pipe will be reset first
 *		and a functional stall cleared before a callback is done.
 * PIPE_RESET	if there is an exception, the pipe will be reset only
 * ONE_XFER	polling will automatically stop on the first callback.
 * ISOC_START_FRAME use startframe specified.
 * USB_ATTRS_ISOC_XFER_ASAP let the host controller decide on the first
 *		available frame.
 *
 * USB_ATTRS_ISOC_START_FRAME and USB_ATTRS_ISOC_XFER_ASAP are mutually
 * exclusive
 *
 * combinations of flag and attributes:
 *
 * usb_flags	usb_req_attrs			semantics
 * ---------------------------------------------------------
 * SLEEP	USB_ATTRS_SHORT_XFER_OK		legal for IN pipes
 * SLEEP	USB_ATTRS_AUTOCLEARING		legal
 * SLEEP	USB_ATTRS_PIPE_RESET		legal
 * SLEEP	USB_ATTRS_ONE_XFER		legal for interrupt IN pipes
 * SLEEP	USB_ATTRS_ISOC_START_FRAME	illegal
 * SLEEP	USB_ATTRS_ISOC_XFER_ASAP	illegal
 *
 * noSLEEP	USB_ATTRS_SHORT_XFER_OK		legal for all IN pipes
 * noSLEEP	USB_ATTRS_AUTOCLEARING		legal
 * noSLEEP	USB_ATTRS_PIPE_RESET		legal
 * noSLEEP	USB_ATTRS_ONE_XFER		legal
 * noSLEEP	USB_ATTRS_ISOC_START_FRAME	legal
 * noSLEEP	USB_ATTRS_ISOC_XFER_ASAP	legal
 */
typedef enum {
	USB_ATTRS_NONE			= 0,

	/* only ctrl/bulk/intr IN pipes */
	USB_ATTRS_SHORT_XFER_OK		= 0x01,	/* short data xfer is ok */
	USB_ATTRS_PIPE_RESET		= 0x02,	/* reset pipe only on exc */
	USB_ATTRS_AUTOCLEARING		= 0x12, /* autoclear STALLs */

	/* intr pipes only: one poll with data */
	USB_ATTRS_ONE_XFER		= 0x100,

	/* only for isoch pipe */
	USB_ATTRS_ISOC_START_FRAME	= 0x200, /* Starting frame# specified */
	USB_ATTRS_ISOC_XFER_ASAP	= 0x400	/* HCD decides START_FRAME#  */
} usb_req_attrs_t;


/*
 * Note: client drivers are required to provide data buffers (mblks) for most
 * requests
 *			IN		OUT
 * ctlr request		if wLength > 0	if wLength > 0
 * bulk request		yes		yes
 * intr request		no		yes
 * isoc request		no		yes
 */

/*
 * ===========================================================================
 * USB control request management
 * ===========================================================================
 */

/*
 * A client driver allocates and uses the usb_ctrl_req_t for all control
 * pipe requests.
 *
 * Direction of the xfer will be determined based on the bmRequestType.
 *
 * NULL callbacks are permitted, timeout = 0 indicates infinite timeout.
 * All timeouts are in seconds.
 *
 * All fields are initialized by client except for data on IN request
 * in which case the client is responsible for deallocating.
 *
 * Control requests may be reused.  The client driver is responsible
 * for reinitializing some fields, eg data read/write pointers.
 *
 * Control requests can be queued.
 */
typedef struct usb_ctrl_req {
	uint8_t		ctrl_bmRequestType; /* characteristics of request */
	uint8_t		ctrl_bRequest;	/* specific request		*/
	uint16_t	ctrl_wValue;	/* varies according to request	*/
	uint16_t	ctrl_wIndex;	/* index or offset		*/
	uint16_t	ctrl_wLength;	/* number of bytes to xfer	*/

	mblk_t		*ctrl_data;	/* the data for the data phase	*/
					/* IN: allocated by HCD		*/
					/* OUT: allocated by client	*/
	uint_t		ctrl_timeout;	/* how long before HCD retires req */
	usb_opaque_t	ctrl_client_private; /* for client private info	*/
	usb_req_attrs_t ctrl_attributes; /* attributes for this req */

	/*
	 * callback function for control pipe requests
	 *
	 * a normal callback will be done upon:
	 *	- successful completion of a control pipe request
	 *
	 * callback arguments are:
	 *	- the pipe_handle
	 *	- usb_ctrl_req_t pointer
	 */
	void		(*ctrl_cb)(usb_pipe_handle_t ph,
				struct usb_ctrl_req *req);

	/*
	 * exception callback function for control pipe
	 *
	 * a exception callback will be done upon:
	 *	- an exception/error (all types)
	 *	- partial xfer of data unless SHORT_XFER_OK has been set
	 *
	 * callback arguments are:
	 *	- the pipe_handle
	 *	- usb_ctrl_req_t pointer
	 *
	 * if USB_ATTRS_AUTOCLEARING was set, autoclearing will be attempted
	 * and usb_cb_flags_t in usb_ctrl_req may indicate what was done
	 */
	void		(*ctrl_exc_cb)(usb_pipe_handle_t ph,
				struct usb_ctrl_req *req);

	/* set by USBA/HCD on completion */
	usb_cr_t	ctrl_completion_reason;	/* set by HCD */
	usb_cb_flags_t	ctrl_cb_flags;  /* Callback context / handling flgs */
} usb_ctrl_req_t;


/*
 * In the setup packet, the descriptor type is passed in the high byte of the
 * wValue field.
 * descriptor types:
 */
#define	USB_DESCR_TYPE_SETUP_DEV		0x0100
#define	USB_DESCR_TYPE_SETUP_CFG		0x0200
#define	USB_DESCR_TYPE_SETUP_STRING		0x0300
#define	USB_DESCR_TYPE_SETUP_IF			0x0400
#define	USB_DESCR_TYPE_SETUP_EP			0x0500
#define	USB_DESCR_TYPE_SETUP_DEV_QLF		0x0600
#define	USB_DESCR_TYPE_SETUP_OTHER_SPEED_CFG	0x0700
#define	USB_DESCR_TYPE_SETUP_IF_PWR		0x0800

#define	USB_DESCR_TYPE_DEV			0x01
#define	USB_DESCR_TYPE_CFG			0x02
#define	USB_DESCR_TYPE_STRING			0x03
#define	USB_DESCR_TYPE_IF			0x04
#define	USB_DESCR_TYPE_EP			0x05
#define	USB_DESCR_TYPE_DEV_QLF			0x06
#define	USB_DESCR_TYPE_OTHER_SPEED_CFG		0x07
#define	USB_DESCR_TYPE_IF_PWR			0x08
#define	USB_DESCR_TYPE_IA			0x0B

#define	USB_DESCR_TYPE_WA			0x21
#define	USB_DESCR_TYPE_RPIPE			0x22

/* Wireless USB extension, refer to WUSB 1.0/7.4 */
#define	USB_DESCR_TYPE_SECURITY			0x0c
#define	USB_DESCR_TYPE_KEY			0x0d
#define	USB_DESCR_TYPE_ENCRYPTION		0x0e
#define	USB_DESCR_TYPE_BOS			0x0f
#define	USB_DESCR_TYPE_DEV_CAPABILITY		0x10
#define	USB_DESCR_TYPE_WIRELESS_EP_COMP		0x11

#define	USB_WA_DESCR_SIZE			14
#define	USB_RPIPE_DESCR_SIZE			28

/*
 * device request type
 */
#define	USB_DEV_REQ_HOST_TO_DEV		0x00
#define	USB_DEV_REQ_DEV_TO_HOST		0x80
#define	USB_DEV_REQ_DIR_MASK		0x80

#define	USB_DEV_REQ_TYPE_STANDARD	0x00
#define	USB_DEV_REQ_TYPE_CLASS		0x20
#define	USB_DEV_REQ_TYPE_VENDOR		0x40
#define	USB_DEV_REQ_TYPE_MASK		0x60

#define	USB_DEV_REQ_RCPT_DEV		0x00
#define	USB_DEV_REQ_RCPT_IF		0x01
#define	USB_DEV_REQ_RCPT_EP		0x02
#define	USB_DEV_REQ_RCPT_OTHER		0x03
#define	USB_DEV_REQ_RCPT_MASK		0x03

/* Wire adapter class extension for request recipient */
#define	USB_DEV_REQ_RCPT_PORT		0x04
#define	USB_DEV_REQ_RCPT_RPIPE		0x05

/*
 * device request
 */
#define	USB_REQ_GET_STATUS		0x00
#define	USB_REQ_CLEAR_FEATURE		0x01
#define	USB_REQ_SET_FEATURE		0x03
#define	USB_REQ_SET_ADDRESS		0x05
#define	USB_REQ_GET_DESCR		0x06
#define	USB_REQ_SET_DESCR		0x07
#define	USB_REQ_GET_CFG			0x08
#define	USB_REQ_SET_CFG			0x09
#define	USB_REQ_GET_IF			0x0a
#define	USB_REQ_SET_IF			0x0b
#define	USB_REQ_SYNC_FRAME		0x0c
/* Wireless USB extension, refer to WUSB 1.0/7.3.1 */
#define	USB_REQ_SET_ENCRYPTION		0x0d
#define	USB_REQ_GET_ENCRYPTION		0x0e
#define	USB_REQ_RPIPE_ABORT		0x0e
#define	USB_REQ_SET_HANDSHAKE		0x0f
#define	USB_REQ_RPIPE_RESET		0x0f
#define	USB_REQ_GET_HANDSHAKE		0x10
#define	USB_REQ_SET_CONNECTION		0x11
#define	USB_REQ_SET_SECURITY_DATA	0x12
#define	USB_REQ_GET_SECURITY_DATA	0x13
#define	USB_REQ_SET_WUSB_DATA		0x14
#define	USB_REQ_LOOPBACK_DATA_WRITE	0x15
#define	USB_REQ_LOOPBACK_DATA_READ	0x16
#define	USB_REQ_SET_INTERFACE_DS	0x17

/* language ID for string descriptors */
#define	USB_LANG_ID			0x0409

/*
 * Standard Feature Selectors
 */
#define	USB_EP_HALT			0x0000
#define	USB_DEV_REMOTE_WAKEUP		0x0001
#define	USB_DEV_TEST_MODE		0x0002
/* Wireless USB extension, refer to WUSB 1.0/7.3.1 */
#define	USB_DEV_WUSB			0x0003


/*
 * Allocate usb control request
 *
 * Arguments:
 *	dip	- dev_info pointer of the client driver
 *	len	- length of "data" for this control request.
 *		  if 0, no mblk is alloc'ed
 *	flags	- USB_FLAGS_SLEEP: Sleep if resources are not available
 *
 * Return Values:
 *	usb_ctrl_req_t pointer on success, NULL on failure
 *
 * Implementation NOTE: the dip allows checking on detach for memory leaks
 */
usb_ctrl_req_t *usb_alloc_ctrl_req(
	dev_info_t		*dip,
	size_t			len,
	usb_flags_t		flags);


/*
 * free USB control request
 */
void usb_free_ctrl_req(
	usb_ctrl_req_t	*reqp);


/*
 * usb_pipe_ctrl_xfer();
 *	Client driver calls this function to issue the control
 *	request to the USBA which will queue or transport it to the device
 *
 * Arguments:
 *	pipe_handle	- control pipe pipehandle (obtained via usb_pipe_open()
 *	reqp		- pointer to control request
 *	flags		- USB_FLAGS_SLEEP:
 *				wait for the request to complete
 *
 * Return values:
 *	USB_SUCCESS	- successfully queued (no sleep) or successfully
 *			  completed (with sleep specified)
 *	USB_FAILURE	- failure
 *	USB_NO_RESOURCES - no resources
 */
int usb_pipe_ctrl_xfer(usb_pipe_handle_t pipe_handle,
	usb_ctrl_req_t	*reqp,
	usb_flags_t		flags);


/*
 * ---------------------------------------------------------------------------
 * Wrapper function which allocates and deallocates a request structure, and
 * performs a control transfer.
 * ---------------------------------------------------------------------------
 */

/*
 * Setup arguments for usb_pipe_ctrl_xfer_wait:
 *
 *	bmRequestType	- characteristics of request
 *	bRequest	- specific request
 *	wValue		- varies according to request
 *	wIndex		- index or offset
 *	wLength		- number of bytes to xfer
 *	attrs		- required request attributes
 *	data		- pointer to pointer to data
 *				IN: HCD will allocate data
 *				OUT: clients driver allocates data
 */
typedef struct usb_ctrl_setup {
	uchar_t		bmRequestType;
	uchar_t		bRequest;
	uint16_t	wValue;
	uint16_t	wIndex;
	uint16_t	wLength;
	usb_req_attrs_t	attrs;
} usb_ctrl_setup_t;


/*
 * usb_pipe_ctrl_xfer_wait():
 *	for simple synchronous control transactions this wrapper function
 *	will perform the allocation, xfer, and deallocation.
 *	USB_ATTRS_AUTOCLEARING will be enabled
 *
 * Arguments:
 *	pipe_handle	- control pipe pipehandle (obtained via usb_pipe_open())
 *	setup		- contains pointer to client's devinfo,
 *			  setup descriptor params, attributes and data
 *	completion_reason - completion status.
 *	cb_flags	- request completions flags.
 *	flags		- none.
 *
 * Return Values:
 *	USB_SUCCESS	- request successfully executed.
 *	USB_FAILURE	- request failed.
 *	USB_*		- refer to list of all possible return values in
 *			  this file
 *
 * NOTES:
 * - in the case of failure, the client should check completion_reason and
 *   and cb_flags and determine further recovery action
 * - the client should check data and if non-zero, free the data on
 *   completion
 */
int usb_pipe_ctrl_xfer_wait(
	usb_pipe_handle_t	pipe_handle,
	usb_ctrl_setup_t	*setup,
	mblk_t			**data,
	usb_cr_t		*completion_reason,
	usb_cb_flags_t		*cb_flags,
	usb_flags_t		flags);


/*
 * ---------------------------------------------------------------------------
 * Some utility defines and wrapper functions for standard control requests.
 * ---------------------------------------------------------------------------
 */

/*
 *
 * Status bits returned by a usb_get_status().
 */
#define	USB_DEV_SLF_PWRD_STATUS	1	/* Supports Self Power	 */
#define	USB_DEV_RWAKEUP_STATUS	2	/* Remote Wakeup Enabled */
#define	USB_DEV_BAT_PWRD_STATUS	4	/* Battery Powered */
#define	USB_EP_HALT_STATUS	1	/* Endpoint is Halted	 */
#define	USB_IF_STATUS		0	/* Interface Status is 0 */

/* length of data returned by USB_REQ_GET_STATUS */
#define	USB_GET_STATUS_LEN		2

/*
 * wrapper function returning status of device, interface, or endpoint
 *
 * Arguments:
 *	dip		- devinfo pointer.
 *	ph		- pipe handle
 *	type		- bmRequestType to be used
 *	what		- 0 for device, otherwise interface or ep number
 *	status		- pointer to returned status.
 *	flags		- USB_FLAGS_SLEEP (mandatory)
 *
 * Return Values:
 *	valid usb_status_t	or USB_FAILURE
 *
 */
int usb_get_status(
	dev_info_t		*dip,
	usb_pipe_handle_t	ph,
	uint_t			type,	/* bmRequestType */
	uint_t			what,	/* 0, interface, endpoint number */
	uint16_t		*status,
	usb_flags_t		flags);


/*
 * function for clearing feature of device, interface, or endpoint
 *
 * Arguments:
 *	dip		- devinfo pointer.
 *	type		- bmRequestType to be used
 *	feature		- feature to be cleared
 *	what		- 0 for device, otherwise interface or ep number
 *	flags		- USB_FLAGS_SLEEP (mandatory)
 *	cb		- if USB_FLAGS_SLEEP has not been specified
 *			  this callback function will be called on
 *			  completion. This callback may be NULL
 *			  and no notification of completion will then
 *			  be provided.
 *	cb_arg		- 2nd argument to callback function.
 *
 * Return Values:
 *	USB_SUCCESS	clearing feature succeeded
 *	USB_FAILURE	clearing feature failed
 *	USB_*		refer to list of all possible return values in
 *			this file
 */
int usb_clr_feature(
	dev_info_t		*dip,
	uint_t			type,	/* bmRequestType */
	uint_t			feature,
	uint_t			what,	/* 0, interface, endpoint number */
	usb_flags_t		flags,
	void			(*cb)(
					usb_pipe_handle_t ph,
					usb_opaque_t	arg,
					int		rval,
					usb_cb_flags_t	flags),
	usb_opaque_t		cb_arg);


/*
 * usb_set_cfg():
 *	Sets the configuration.  Use this function with caution as
 *	the framework is normally responsible for configuration changes.
 *	Changing configuration will fail if pipes are still open or
 *	when invoked from a driver bound to an interface on a composite
 *	device. This function access the device and blocks.
 *
 * Arguments:
 *	dip		- devinfo pointer.
 *	cfg_index	- Index of configuration to set.  Corresponds to
 *			  index in the usb_client_dev_data_t tree of
 *			  configurations.  See usb_client_dev_data_t(9F).
 *	usb_flags	- USB_FLAGS_SLEEP:
 *				wait for completion.
 *	cb		- if USB_FLAGS_SLEEP has not been specified
 *			  this callback function will be called on
 *			  completion. This callback may be NULL
 *			  and no notification of completion will then
 *			  be provided.
 *	cb_arg		- 2nd argument to callback function.
 *
 * callback and callback_arg should be NULL if USB_FLAGS_SLEEP has
 * been specified
 *
 * Return Values:
 *	USB_SUCCESS:	new configuration was set or async request
 *			submitted successfully.
 *	USB_FAILURE:	new configuration could not be set because
 *			it may been illegal configuration or this
 *			caller was not allowed to change configs or
 *			pipes were still open or async request
 *			could not be submitted.
 *	USB_*		refer to list of all possible return values in
 *			this file
 *
 * the pipe handle argument in the callback will be the default pipe handle
 */
int usb_set_cfg(
	dev_info_t		*dip,
	uint_t			cfg_index,
	usb_flags_t		usb_flags,
	void			(*cb)(
					usb_pipe_handle_t ph,
					usb_opaque_t	arg,
					int		rval,
					usb_cb_flags_t	flags),
	usb_opaque_t		cb_arg);


/*
 * usb_get_cfg:
 *	dip		- pointer to devinfo node
 *	cfgval		- pointer to cfgval
 *	usb_flags	- none, will always block
 *
 * return values:
 *	USB_SUCCESS	- current cfg value is returned to cfgval
 *	USB_*		- refer to list of all possible return values in
 *			  this file
 */
int usb_get_cfg(
	dev_info_t		*dip,
	uint_t			*cfgval,
	usb_flags_t		usb_flags);


/*
 * The following functions set or get the alternate interface
 * setting.
 *
 * usb_set_alt_if:
 *	dip		- pointer to devinfo node
 *	interface	- interface
 *	alt_number	- alternate to set to
 *	usb_flags	- USB_FLAGS_SLEEP:
 *				wait for completion.
 *	cb		- if USB_FLAGS_SLEEP has not been specified
 *			  this callback function will be called on
 *			  completion. This callback may be NULL
 *			  and no notification of completion will then
 *			  be provided.
 *	cb_arg		- 2nd argument to callback function.
 *
 * callback and callback_arg should be NULL if USB_FLAGS_SLEEP has
 * been specified
 *
 * the pipe handle argument in the callback will be the default pipe handle
 *
 * return values:
 *	USB_SUCCESS:	alternate was set or async request was
 *			submitted.
 *	USB_FAILURE:	alternate could not be set because pipes
 *			were still open or some access error occurred
 *			or an invalid alt if value was passed or
 *			async request could not be submitted
 *	USB_INVALID_PERM the driver does not own the device or the interface
 *	USB_*		refer to list of all possible return values in
 *			this file
 */
int usb_set_alt_if(
	dev_info_t		*dip,
	uint_t			interface,
	uint_t			alt_number,
	usb_flags_t		usb_flags,
	void			(*cb)(
					usb_pipe_handle_t ph,
					usb_opaque_t	arg,
					int		rval,
					usb_cb_flags_t	flags),
	usb_opaque_t		cb_arg);



/* flags must be USB_FLAGS_SLEEP, and this function will block */
int usb_get_alt_if(
	dev_info_t		*dip,
	uint_t			if_number,
	uint_t			*alt_number,
	usb_flags_t		flags);


/*
 * ===========================================================================
 * USB bulk request management
 * ===========================================================================
 */

/*
 * A client driver allocates/uses the usb_bulk_req_t for bulk pipe xfers.
 *
 * NOTES:
 * - bulk pipe sharing is not supported
 * - semantics of combinations of flag and attributes:
 *
 * flags     Type  attributes	data	timeout semantics
 * ----------------------------------------------------------------
 *  x	      x    x		== NULL    x	   illegal
 *
 * no sleep  IN    x		!= NULL    0	   fill buffer, no timeout
 *						   callback when xfer-len has
 *						   been xferred
 * no sleep  IN    x		!= NULL    > 0	   fill buffer, with timeout
 *						   callback when xfer-len has
 *						   been xferred
 *
 * sleep     IN    x		!= NULL    0	   fill buffer, no timeout
 *						   unblock when xfer-len has
 *						   been xferred
 *						   no callback
 * sleep     IN    x		!= NULL    > 0	   fill buffer, with timeout
 *						   unblock when xfer-len has
 *						   been xferred or timeout
 *						   no callback
 *
 *  X	     OUT SHORT_XFER_OK	  x	   x	   illegal
 *
 * no sleep  OUT   x		!= NULL    0	   empty buffer, no timeout
 *						   callback when xfer-len has
 *						   been xferred
 * no sleep  OUT   x		!= NULL    > 0	   empty buffer, with timeout
 *						   callback when xfer-len has
 *						   been xferred or timeout
 *
 * sleep     OUT   x		!= NULL    0	   empty buffer, no timeout
 *						   unblock when xfer-len has
 *						   been xferred
 *						   no callback
 * sleep     OUT   x		!= NULL    > 0	   empty buffer, with timeout
 *						   unblock when xfer-len has
 *						   been xferred or timeout
 *						   no callback
 *
 * - bulk_len and bulk_data must be > 0.  SHORT_XFER_OK is not applicable.
 *
 * - multiple bulk requests can be queued
 *
 * - Splitting large Bulk xfer:
 * The HCD driver, due to internal constraints, can only do a limited size bulk
 * data xfer per request.  The current limitations are 32K for UHCI and 128K
 * for OHCI.  So, a client driver may first determine this limitation (by
 * calling the USBA interface usb_pipe_bulk_transfer_size()); and restrict
 * itself to doing xfers in multiples of this fixed size.  This forces a client
 * driver to do data xfers in a loop for a large request, splitting it into
 * multiple chunks of fixed size.
 */
typedef struct usb_bulk_req {
	uint_t		bulk_len;	/* number of bytes to xfer	*/
	mblk_t		*bulk_data;	/* the data for the data phase	*/
					/* IN: allocated by HCD		*/
					/* OUT: allocated by client	*/
	uint_t		bulk_timeout;	/* xfer timeout value in secs	*/
	usb_opaque_t	bulk_client_private; /* Client specific information */
	usb_req_attrs_t bulk_attributes; /* xfer-attributes	*/

	/* Normal Callback function (For synch xfers) */
	void		(*bulk_cb)(usb_pipe_handle_t ph,
				struct usb_bulk_req *req);

	/* Exception Callback function (For asynch xfers) */
	void		(*bulk_exc_cb)(usb_pipe_handle_t ph,
				struct usb_bulk_req *req);

	/* set by USBA/HCD on completion */
	usb_cr_t	bulk_completion_reason;	/* set by HCD		*/
	usb_cb_flags_t	bulk_cb_flags;  /* Callback context / handling flgs */
} usb_bulk_req_t;


/*
 * Allocate/free usb bulk request
 *
 * Arguments:
 *	dip		- pointer to dev_info_t of the client driver
 *	len		- 0 or length of mblk to be allocated
 *	flags		- USB_FLAGS_SLEEP:
 *				wait for resources
 *
 * Return Values:
 *	usb_bulk_req_t on success, NULL on failure
 */
usb_bulk_req_t *usb_alloc_bulk_req(
	dev_info_t		*dip,
	size_t			len,
	usb_flags_t		flags);


void usb_free_bulk_req(
	usb_bulk_req_t	*reqp);


/*
 * usb_pipe_bulk_xfer():
 *
 * Client drivers call this function to issue the bulk xfer to the USBA
 * which will queue or transfer it to the device
 *
 * Arguments:
 *	pipe_handle	- bulk pipe handle (obtained via usb_pipe_open()
 *	reqp		- pointer to bulk data xfer request (IN or OUT)
 *	flags		- USB_FLAGS_SLEEP:
 *				wait for the request to complete
 *
 * Return Values:
 *	USB_SUCCESS	- success
 *	USB_FAILURE	- unspecified failure
 *	USB_NO_RESOURCES - no resources
 *
 */
int usb_pipe_bulk_xfer(
	usb_pipe_handle_t	pipe_handle,
	usb_bulk_req_t		*reqp,
	usb_flags_t		flags);

/* Get maximum bulk transfer size */
int usb_pipe_get_max_bulk_transfer_size(
	dev_info_t		*dip,
	size_t			*size);


/*
 * ===========================================================================
 * USB interrupt pipe request management
 * ===========================================================================
 */

/*
 * A client driver allocates and uses the usb_intr_req_t for
 * all interrupt pipe transfers.
 *
 * USB_FLAGS_SLEEP indicates here just to wait for resources except
 * for ONE_XFER where we also wait for completion
 *
 * semantics flags and attribute combinations:
 *
 * Notes:
 * none attributes indicates neither ONE_XFER nor SHORT_XFER_OK
 *
 * flags     Type  attributes	   data    timeout semantics
 * ----------------------------------------------------------------
 *  x	     IN      x		   != NULL  x	    illegal
 *  x	     IN   ONE_XFER=0	   x	   !=0	    illegal
 *
 *  x	     IN   ONE_XFER=0	   NULL     0	   continuous polling,
 *						   many callbacks
 *						   request is returned on
 *						   stop polling
 *
 * no sleep  IN   ONE_XFER	   NULL     0	   one time poll, no timeout,
 *						   one callback
 * no sleep  IN   ONE_XFER	   NULL    !=0	   one time poll, with
 *						   timeout, one callback
 *
 * sleep     IN   ONE_XFER	   NULL     0	   one time poll, no timeout,
 *						   no callback,
 *						   block for completion
 * sleep     IN   ONE_XFER	   NULL    !=0	   one time poll, with timeout,
 *						   no callback
 *						   block for completion
 *
 *  x	     OUT     x		   NULL    x	   illegal
 *  x	     OUT  ONE_XFER	   x	   x	   illegal
 *  x	     OUT  SHORT_XFER_OK    x	   x	   illegal
 *
 *  x	     OUT   none		   != NULL 0	   xfer until data exhausted,
 *						   no timeout,	one callback
 *  x	     OUT   none		   != NULL !=0	   xfer until data exhausted,
 *						   with timeout, one callback
 *
 * - Reads (IN):
 *
 * The client driver does *not* provide a data buffer.
 * By default, a READ request would mean continuous polling for data IN. The
 * HCD typically reads "wMaxPacketSize" amount of 'periodic data'. A client
 * driver may force the HCD to read instead intr_len
 * amount of 'periodic data' (See section 1).
 *
 * The HCD issues a callback to the client after each polling interval if
 * it has read in some data. Note that the amount of data read IN is either
 * intr_len or 'wMaxPacketSize' in length.
 *
 * Normally, the HCD keeps polling interrupt pipe forever even if there is
 * no data to be read IN.  A client driver may stop this polling by
 * calling usb_pipe_stop_intr_polling().
 *
 * If a client driver chooses to pass USB_ATTRS_ONE_XFER as
 * 'xfer_attributes' the HCD will poll for data until some data is received.
 * HCD reads in the data and does a callback and stops polling for any more
 * data.  In this case, the client driver need not explicitly call
 * usb_pipe_stop_intr_polling().
 *
 * When continuous polling is stopped, the original request is returned with
 * USB_CR_STOPPED_POLLING.
 *
 * - Writes (OUT):
 *
 * A client driver provides the data buffer, and data, needed for intr write.
 * There is no continuous write mode, a la  read (See previous section).
 * The USB_ATTRS_ONE_XFER attribute is illegal.
 * By default USBA keeps writing intr data until the provided data buffer
 * has been written out. The HCD does ONE callback to the client driver.
 * Queueing is supported.
 * Max size is 8k
 */
typedef struct usb_intr_req {
	uint_t		intr_len;	/* OUT: size of total xfer */
					/* IN : packet size */
	mblk_t		*intr_data;	/* the data for the data phase	*/
					/* IN: allocated by HCD		*/
					/* OUT: allocated by client	*/
	usb_opaque_t	intr_client_private; /* Client specific information  */
	uint_t		intr_timeout;	/* only with ONE TIME POLL, in secs */
	usb_req_attrs_t	intr_attributes;

	/* Normal callback function (For synch transfers) */
	void		(*intr_cb)(usb_pipe_handle_t ph,
				struct usb_intr_req *req);

	/* Exception callback function (For asynch transfers) */
	void		(*intr_exc_cb)(usb_pipe_handle_t ph,
				struct usb_intr_req *req);

	/* set by USBA/HCD on completion */
	usb_cr_t	intr_completion_reason;	/* set by HCD */
	usb_cb_flags_t	intr_cb_flags;  /* Callback context / handling flgs */
} usb_intr_req_t;


/*
 * Allocate/free usb interrupt pipe request
 *
 * Arguments:
 *	dip		- pointer to dev_info_t of the client driver
 *	reqp		- pointer to request structure
 *	len		- 0 or length of mblk for this interrupt request
 *	flags		- USB_FLAGS_SLEEP:
 *				Sleep if resources are not available
 *
 * Return Values:
 *	usb_intr_req_t on success, NULL on failure
 */
usb_intr_req_t *usb_alloc_intr_req(
	dev_info_t		*dip,
	size_t			len,
	usb_flags_t		flags);


void usb_free_intr_req(
	usb_intr_req_t	*reqp);


/*
 * usb_pipe_intr_xfer():
 *
 * Client drivers call this function to issue the intr xfer to USBA/HCD
 * which starts polling the device
 *
 * Arguments:
 *	pipe_handle	- interrupt pipe handle (obtained via usb_pipe_open()
 *	reqp		- pointer tothe interrupt pipe xfer request (IN or OUT)
 *	flags		- USB_FLAGS_SLEEP:
 *				wait for resources to be available
 *
 * return values:
 *	USB_SUCCESS	- success
 *	USB_FAILURE	- unspecified failure
 *	USB_NO_RESOURCES  - no resources
 *
 * NOTE: start polling on an IN pipe that is already being polled is a NOP.
 *	 We don't queue requests on OUT pipe
 */
int usb_pipe_intr_xfer(
	usb_pipe_handle_t	pipe_handle,
	usb_intr_req_t		*req,
	usb_flags_t		flags);


/*
 * usb_pipe_stop_intr_polling():
 *
 * Client drivers call this function to stop the automatic data-in/out transfers
 * without closing the pipe.
 *
 * If USB_FLAGS_SLEEP  has been specified then this function will block until
 * polling has been stopped and all callbacks completed. If USB_FLAGS_SLEEP
 * has NOT been specified then polling is terminated when the original
 * request that started the polling has been returned with
 * USB_CR_STOPPED_POLLING
 *
 * Stop polling should never fail.
 *
 * Args:-
 *	pipe_handle	- interrupt pipe handle (obtained via usb_pipe_open()).
 *	flags		- USB_FLAGS_SLEEP:
 *				wait for the resources to be available.
 */
void usb_pipe_stop_intr_polling(
	usb_pipe_handle_t	pipe_handle,
	usb_flags_t		flags);


/*
 * ===========================================================================
 * USB isochronous xfer management
 * ===========================================================================
 */

/*
 * The usb frame number is an absolute number since boot and incremented
 * every 1 ms.
 */
typedef	uint64_t	usb_frame_number_t;

/*
 * USB ischronous packet descriptor
 *
 * An array of structures of type usb_isoc_pkt_descr_t must be allocated and
 * initialized by the client driver using usb_alloc_isoc_req(). The client
 * driver must set isoc_pkt_length in each packet descriptor before submitting
 * the request.
 */
typedef struct usb_isoc_pkt_descr {
	/*
	 * Set by the client driver, for all isochronous requests, to the
	 * number of bytes to transfer in a frame.
	 */
	ushort_t	isoc_pkt_length;

	/*
	 * Set by HCD to actual number of bytes sent/received in frame.
	 */
	ushort_t	isoc_pkt_actual_length;

	/*
	 * Per frame status set by HCD both for the isochronous IN and OUT
	 * requests.  If any status is non-zero then isoc_error_count in the
	 * isoc_req will be non-zero.
	 */
	usb_cr_t	isoc_pkt_status;
} usb_isoc_pkt_descr_t;


/*
 * USB isochronous request
 *
 * The client driver allocates the usb_isoc_req_t before sending an
 * isochronous requests.
 *
 * USB_FLAGS_SLEEP indicates here just to wait for resources but not
 * to wait for completion
 *
 * Semantics of various combinations for data xfers:
 *
 * Note: attributes considered in this table are ONE_XFER, START_FRAME,
 *	XFER_ASAP, SHORT_XFER
 *
 *
 * flags     Type  attributes		   data    semantics
 * ---------------------------------------------------------------------
 * x	     x	   x			NULL	   illegal
 *
 * x	     x	   ONE_XFER		 x	   illegal
 *
 * x	     IN    x			!=NULL	   continuous polling,
 *						   many callbacks
 *
 * x	     IN    ISOC_START_FRAME	!=NULL	   invalid if Current_frame# >
 *						   "isoc_frame_no"
 * x	     IN    ISOC_XFER_ASAP	!=NULL	   "isoc_frame_no" ignored.
 *						   HCD determines when to
 *						   insert xfer
 *
 * x	     OUT   ONE_XFER		x	   illegal
 * x	     OUT   SHORT_XFER_OK	x	   illegal
 *
 * x	     OUT   ISOC_START_FRAME	!=NULL	   invalid if Current_frame# >
 *						   "isoc_frame_no"
 * x	     OUT   ISOC_XFER_ASAP	!=NULL	   "isoc_frame_no" ignored.
 *						    HCD determines when to
 *						   insert xfer
 */
typedef struct usb_isoc_req {
	/*
	 * Starting frame number will be set by the client driver in which
	 * to begin this request. This frame number is used to synchronize
	 * requests queued to different isochronous pipes. The frame number
	 * is optional and client driver can skip starting frame number by
	 * setting USB_ISOC_ATTRS_ASAP. In this case, HCD will decide starting
	 * frame number for this isochronous request.  If this field is 0,
	 * then this indicates an invalid frame number.
	 */
	usb_frame_number_t	isoc_frame_no;

	/*
	 * Number of isochronous data packets.
	 * The first field is set by client  driver and may not exceed
	 * the maximum number of entries in the usb isochronous packet
	 * descriptors.
	 */
	ushort_t		isoc_pkts_count;

	/*
	 * The sum of all pkt lengths in the isoc request. Recommend to
	 * set it to zero, so the sum of isoc_pkt_length in the
	 * isoc_pkt_descr list will be used automatically and no check
	 * will be apply to this element.
	 */
	ushort_t		isoc_pkts_length;

	/*
	 * This field will be set by HCD and this field indicates the number
	 * of packets that completed with errors.
	 */
	ushort_t		isoc_error_count;

	/*
	 * Attributes specific to particular usb isochronous request.
	 * Supported values are: USB_ATTRS_ISOC_START_FRAME,
	 * USB_ATTRS_ISOC_XFER_ASAP.
	 */
	usb_req_attrs_t 	isoc_attributes;

	/*
	 * Isochronous OUT:
	 *	allocated and set by client driver, freed and zeroed by HCD
	 *	on successful completion
	 * Isochronous IN:
	 *	allocated and set by HCD, freed by client driver
	 */
	mblk_t			*isoc_data;

	/*
	 * The client driver specific private information.
	 */
	usb_opaque_t		isoc_client_private;

	/*
	 * Isochronous OUT:
	 *	must be allocated & initialized by client driver
	 * Isochronous IN:
	 *	must be allocated by client driver
	 */
	struct usb_isoc_pkt_descr *isoc_pkt_descr;

	/* Normal callback function (For synch transfers) */
	void			(*isoc_cb)(usb_pipe_handle_t ph,
					struct usb_isoc_req *req);

	/* Exception callback function (For asynch transfers) */
	void			(*isoc_exc_cb)(usb_pipe_handle_t ph,
					struct usb_isoc_req *req);

	/* set by USBA/HCD on completion */
	usb_cr_t		isoc_completion_reason;	/* set by HCD */
					/* Callback context / handling flgs */
	usb_cb_flags_t		isoc_cb_flags;
} usb_isoc_req_t;


/*
 * Allocate/free usb isochronous resources
 *
 * isoc_pkts_count must be > 0
 *
 * Arguments:
 *	dip		- client driver's devinfo pointer
 *	isoc_pkts_count - number of pkts required
 *	len		- 0 or size of mblk to allocate
 *	flags		- USB_FLAGS_SLEEP:
 *				wait for resources
 *
 * Return Values:
 *	usb_isoc_req pointer or NULL
 */
usb_isoc_req_t *usb_alloc_isoc_req(
	dev_info_t		*dip,
	uint_t			isoc_pkts_count,
	size_t			len,
	usb_flags_t		flags);

void	usb_free_isoc_req(
	usb_isoc_req_t		*usb_isoc_req);

/*
 * Returns current usb frame number.
 */
usb_frame_number_t usb_get_current_frame_number(
	dev_info_t		*dip);

/*
 * Get maximum isochronous packets per usb isochronous request
 */
uint_t usb_get_max_pkts_per_isoc_request(
	dev_info_t		*dip);

/*
 * usb_pipe_isoc_xfer()
 *
 * Client drivers call this to issue the isoch xfer (IN and OUT) to the USBA
 * which starts polling the device.
 *
 * Arguments:
 *	pipe_handle	- isoc pipe handle (obtained via usb_pipe_open().
 *	reqp		- pointer to the isochronous pipe IN xfer request
 *			  allocated by the client driver.
 *	flags		- USB_FLAGS_SLEEP:
 *				wait for the resources to be available.
 *
 * return values:
 *	USB_SUCCESS	- success.
 *	USB_FAILURE	- unspecified failure.
 *	USB_NO_RESOURCES  - no resources.
 *	USB_NO_FRAME_NUMBER - START_FRAME, ASAP flags not specified.
 *	USB_INVALID_START_FRAME	- Starting USB frame number invalid.
 *
 * Notes:
 * - usb_pipe_isoc_xfer on an IN pipe that is already being polled is a NOP.
 * - requests can be queued on an OUT pipe.
 */
int usb_pipe_isoc_xfer(
	usb_pipe_handle_t	pipe_handle,
	usb_isoc_req_t		*reqp,
	usb_flags_t		flags);

/*
 * usb_pipe_stop_isoc_polling():
 *
 * Client drivers call this function to stop the automatic data-in/out
 * transfers without closing the isoc pipe.
 *
 * If USB_FLAGS_SLEEP  has been specified then this function will block until
 * polling has been stopped and all callbacks completed. If USB_FLAGS_SLEEP
 * has NOT been specified then polling is terminated when the original
 * request that started the polling has been returned with
 * USB_CR_STOPPED_POLLING
 *
 * Stop polling should never fail.
 *
 * Arguments:
 *	pipe_handle	- isoc pipe handle (obtained via usb_pipe_open().
 *	flags		- USB_FLAGS_SLEEP:
 *				wait for polling to be stopped and all
 *				callbacks completed.
 */
void usb_pipe_stop_isoc_polling(
	usb_pipe_handle_t	pipe_handle,
	usb_flags_t		flags);

/*
 * ***************************************************************************
 * USB device power management:
 * ***************************************************************************
 */

/*
 *
 * As any usb device will have a max of 4 possible power states
 * the #define	for them are provided below with mapping to the
 * corresponding OS power levels.
 */
#define	USB_DEV_PWR_D0		USB_DEV_OS_FULL_PWR
#define	USB_DEV_PWR_D1		5
#define	USB_DEV_PWR_D2		6
#define	USB_DEV_PWR_D3		USB_DEV_OS_PWR_OFF

#define	USB_DEV_OS_PWR_0	0
#define	USB_DEV_OS_PWR_1	1
#define	USB_DEV_OS_PWR_2	2
#define	USB_DEV_OS_PWR_3	3
#define	USB_DEV_OS_PWR_OFF	USB_DEV_OS_PWR_0
#define	USB_DEV_OS_FULL_PWR	USB_DEV_OS_PWR_3

/* Bit Masks for Power States */
#define	USB_DEV_OS_PWRMASK_D0	1
#define	USB_DEV_OS_PWRMASK_D1	2
#define	USB_DEV_OS_PWRMASK_D2	4
#define	USB_DEV_OS_PWRMASK_D3	8

/* conversion for OS to Dx levels */
#define	USB_DEV_OS_PWR2USB_PWR(l)	(USB_DEV_OS_FULL_PWR - (l))

/* from OS level to Dx mask */
#define	USB_DEV_PWRMASK(l)	(1 << (USB_DEV_OS_FULL_PWR - (l)))

/* Macro to check valid power level */
#define	USB_DEV_PWRSTATE_OK(state, level) \
		(((state) & USB_DEV_PWRMASK((level))) == 0)

int usb_handle_remote_wakeup(
	dev_info_t	*dip,
	int		cmd);

/* argument to usb_handle_remote wakeup function */
#define	USB_REMOTE_WAKEUP_ENABLE	1
#define	USB_REMOTE_WAKEUP_DISABLE	2

int usb_create_pm_components(
	dev_info_t	*dip,
	uint_t		*pwrstates);

/*
 * ***************************************************************************
 * System event registration
 * ***************************************************************************
 */

/* Functions for registering hotplug callback functions. */

int usb_register_hotplug_cbs(
	dev_info_t	*dip,
	int		(*disconnect_event_handler)(dev_info_t *dip),
	int		(*reconnect_event_handler)(dev_info_t *dip));

void usb_unregister_hotplug_cbs(dev_info_t *dip);

/*
 *	Reset_level determines the extent to which the device is reset,
 *	It has the following values:
 *
 *	USB_RESET_LVL_REATTACH	- The device is reset, the original driver is
 *				  detached and a new driver attaching process
 *				  is started according to the updated
 *				  compatible name. This reset level applies to
 *				  the firmware download with the descriptors
 *				  changing, or other situations in which the
 *				  device needs to be reenumerated.
 *
 *	USB_RESET_LVL_DEFAULT	- Default reset level. The device is reset, all
 *				  error status is cleared, the device state
 *				  machines and registers are also cleared and
 *				  need to be reinitialized in the driver. The
 *				  current driver remains attached. This reset
 *				  level applies to hardware error recovery, or
 *				  firmware download without descriptors
 *				  changing.
 */
typedef enum {
	USB_RESET_LVL_REATTACH		= 0,
	USB_RESET_LVL_DEFAULT		= 1
} usb_dev_reset_lvl_t;

/*
 * usb_reset_device:
 *
 * Client drivers call this function to request hardware reset for themselves,
 * which may be required in some situations such as:
 *
 * 1) Some USB devices need the driver to upload firmware into devices' RAM
 *    and initiate a hardware reset in order to activate the new firmware.
 * 2) Hardware reset may help drivers to recover devices from an error state
 *    caused by physical or firmware defects.
 *
 * Arguments:
 *	dip		    - pointer to devinfo of the client
 *	reset_level	    - see above
 *
 * Return values:
 *	USB_SUCCESS	    - With USB_RESET_LVL_DEFAULT: the device was reset
 *			      successfully.
 *			    - With USB_RESET_LVL_REATTACH: reenumeration was
 *			      started successfully or a previous reset is still
 *			      in progress.
 *	USB_FAILURE	    - The state of the device's parent hub is invalid
 *			      (disconnected or suspended).
 *			    - Called when the driver being detached.
 *			    - The device failed to be reset with
 *			      USB_RESET_LVL_DEFAULT specified.
 *			    - Reenumeration failed to start up with
 *			    - USB_RESET_LVL_REATTACH specified.
 *	USB_INVALID_ARGS    - Invalid arguments.
 *	USB_INVALID_PERM    - The driver of the dip doesn't own entire device.
 *	USB_BUSY	    - One or more pipes other than the default control
 *			      pipe are open on the device with
 *			      USB_RESET_LVL_DEFAULT specified.
 *	USB_INVALID_CONTEXT - Called from interrupt context with
 *			      USB_RESET_LVL_DEFAULT specified.
 */

int usb_reset_device(
	dev_info_t 		*dip,
	usb_dev_reset_lvl_t	reset_level);


/*
 * **************************************************************************
 * USB device driver registration and callback functions remaining
 * Contracted Project Private (for VirtualBox USB Device Capture)
 * **************************************************************************
 */

/*
 * getting the device strings of manufacturer, product and serial number
 */
typedef struct usb_dev_str {
	char	*usb_mfg;	/* manufacturer string */
	char	*usb_product;	/* product string */
	char	*usb_serialno;	/* serial number string */
} usb_dev_str_t;

/*
 * It is the callback function type for capture driver.
 * Arguments:
 *	dev_descr	- pointer to device descriptor
 *	dev_str		- pointer to device strings
 *	path		- pointer to device physical path
 *	bus		- USB bus address
 *	port		- USB port number
 *	drv		- capture driver name.
 *			  It is returned by the callback func.
 * Return Values:
 *      USB_SUCCESS     - VirtualBox will capture the device
 *      USB_FAILURE     - VirtualBox will not capture the device
 */
typedef int (*usb_dev_driver_callback_t)(
	usb_dev_descr_t	*dev_descr,
	usb_dev_str_t	*dev_str,
	char		*path,
	int		bus,
	int		port,
	char		**drv,
	void		*reserved);

/*
 * Register the callback function in the usba.
 * Argument:
 *	dip		- client driver's devinfo pointer
 *	cb		- callback function
 *
 * Return Values:
 *	USB_SUCCESS	- the registeration was successful
 *	USB_FAILURE	- the registeration failed
 */
int usb_register_dev_driver(
	dev_info_t			*dip,
	usb_dev_driver_callback_t	cb);

/*
 * Unregister the callback function in the usba.
 */
void usb_unregister_dev_driver(dev_info_t *dip);


/*
 * ***************************************************************************
 * USB Device and interface class, subclass and protocol codes
 * ***************************************************************************
 */

/*
 * Available device and interface class codes.
 * Those which are device class codes are noted.
 */

#define	USB_CLASS_AUDIO		1
#define	USB_CLASS_COMM		2	/* Communication device class and */
#define	USB_CLASS_CDC_CTRL	2	/* CDC-control iface class, also 2 */
#define	USB_CLASS_HID		3
#define	USB_CLASS_PHYSICAL	5
#define	USB_CLASS_IMAGE		6
#define	USB_CLASS_PRINTER	7
#define	USB_CLASS_MASS_STORAGE	8
#define	USB_CLASS_HUB		9	/* Device class */
#define	USB_CLASS_CDC_DATA	10
#define	USB_CLASS_CCID		11
#define	USB_CLASS_SECURITY	13
#define	USB_CLASS_VIDEO		14
#define	USB_CLASS_DIAG		220	/* Device class */
#define	USB_CLASS_WIRELESS	224
#define	USB_CLASS_MISC		239	/* Device class */
#define	USB_CLASS_APP		254
#define	USB_CLASS_VENDOR_SPEC	255	/* Device class */

#define	USB_CLASS_PER_INTERFACE	0	/* Class info is at interface level */

/* Audio subclass. */
#define	USB_SUBCLS_AUD_CONTROL		0x01
#define	USB_SUBCLS_AUD_STREAMING	0x02
#define	USB_SUBCLS_AUD_MIDI_STREAMING	0x03

/* Comms  subclass. */
#define	USB_SUBCLS_CDCC_DIRECT_LINE	0x01
#define	USB_SUBCLS_CDCC_ABSTRCT_CTRL	0x02
#define	USB_SUBCLS_CDCC_PHONE_CTRL	0x03
#define	USB_SUBCLS_CDCC_MULTCNL_ISDN	0x04
#define	USB_SUBCLS_CDCC_ISDN		0x05
#define	USB_SUBCLS_CDCC_ETHERNET	0x06
#define	USB_SUBCLS_CDCC_ATM_NETWORK	0x07

/* HID subclass and protocols. */
#define	USB_SUBCLS_HID_1		1

#define	USB_PROTO_HID_KEYBOARD		0x01	/* legacy keyboard */
#define	USB_PROTO_HID_MOUSE		0x02	/* legacy mouse */

/* Printer subclass and protocols. */
#define	USB_SUBCLS_PRINTER_1		1

#define	USB_PROTO_PRINTER_UNI		0x01	/* Unidirectional interface */
#define	USB_PROTO_PRINTER_BI		0x02	/* Bidirectional interface */

/* Mass storage subclasses and protocols. */
#define	USB_SUBCLS_MS_RBC_T10		0x1	/* flash */
#define	USB_SUBCLS_MS_SFF8020I		0x2	/* CD-ROM */
#define	USB_SUBCLS_MS_QIC_157		0x3	/* tape */
#define	USB_SUBCLS_MS_UFI		0x4	/* USB Floppy Disk Drive   */
#define	USB_SUBCLS_MS_SFF8070I		0x5	/* floppy */
#define	USB_SUBCLS_MS_SCSI		0x6	/* transparent scsi */

#define	USB_PROTO_MS_CBI_WC		0x00	/* USB CBI Proto w/cmp intr */
#define	USB_PROTO_MS_CBI		0x01    /* USB CBI Protocol */
#define	USB_PROTO_MS_ISD_1999_SILICN	0x02    /* ZIP Protocol */
#define	USB_PROTO_MS_BULK_ONLY		0x50    /* USB Bulk Only Protocol */

/* Application subclasses. */
#define	USB_SUBCLS_APP_FIRMWARE		0x01	/* app spec f/w subclass */
#define	USB_SUBCLS_APP_IRDA		0x02	/* app spec IrDa subclass */
#define	USB_SUBCLS_APP_TEST		0x03	/* app spec test subclass */

/* Video subclasses */
#define	USB_SUBCLS_VIDEO_CONTROL	0x01	/* video control */
#define	USB_SUBCLS_VIDEO_STREAM		0x02	/* video stream */
#define	USB_SUBCLS_VIDEO_COLLECTION	0x03	/* video interface collection */

/* Wireless controller subclasses and protocols, refer to WUSB 1.0 chapter 8 */
#define	USB_SUBCLS_WUSB_1		0x01	/* RF controller */
#define	USB_SUBCLS_WUSB_2		0x02	/* Wireless adapter */
#define	USB_PROTO_WUSB_HWA		0x01	/* host wire adapter */
#define	USB_PROTO_WUSB_DWA		0x02	/* device wire adapter */
#define	USB_PROTO_WUSB_DWA_ISO		0x03	/* device wire adapter isoc */
#define	USB_PROTO_WUSB_RC		0x02	/* UWB radio controller */

/* Association subclass and protocol, Association Model Supplement to WUSB1.0 */
#define	USB_SUBCLS_CBAF			0x03	/* cable association */
#define	USB_PROTO_CBAF			0x01	/* CBAF protocol */

/* Misc subclasses and protocols, refer to WUSB 1.0 chapter 8 */
#define	USB_SUBCLS_MISC_COMMON		0x02	/* common class */
#define	USB_PROTO_MISC_WA		0x02	/* multifunction wire adapter */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_USB_USBAI_H */
