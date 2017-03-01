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

#ifndef _SYS_USB_HIDVAR_H
#define	_SYS_USB_HIDVAR_H


#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/usb/usba/usbai_private.h>

/*
 * HID : This header file contains the internal structures
 * and variable definitions used in hid driver.
 */

/*
 * HID USB device state management :
 *
 *	ONLINE-----1--->SUSPENDED----2---->ONLINE
 *	  |
 *	  +-----3--->DISCONNECTED----4----->ONLINE
 *	  |
 *	  +-----7--->POWERED DOWN----8----->POWER CHANGE---9--->ONLINE
 *						|
 *						+---3--->DISCONNECTED
 *
 *	POWERED DOWN----1--->SUSPENDED------2----->POWERED DOWN
 *	  |		      |     ^
 *	  |		      5     |
 *	  |		      |     6
 *	  |		      v     |
 *	  +---------3----->DISCONNECTED-------4----->POWERED DOWN
 *
 *	1 = CPR SUSPEND
 *	2 = CPR RESUME (with original device)
 *	3 = Device Unplug
 *	4 = Original Device Plugged in
 *	5 = CPR RESUME (with device disconnected or with a wrong device)
 *	6 = CPR SUSPEND on a disconnected device
 *	7 = Device idles for time T & transitions to low power state
 *	8 = Remote wakeup by device OR Application kicking off IO to device
 *          This results in a Transistion state till PM calls the power
 *	    entry point to raise the power level of the device
 *	9 = Device entry point called to raise power level of the device
 *
 */


/* Boot Interface Subclass for HID devices */
#define	BOOT_INTERFACE		0x01

/* Boot protocol values for keyboard and mouse */
#define	KEYBOARD_PROTOCOL	0x01		/* legacy keyboard */
#define	MOUSE_PROTOCOL		0x02		/* legacy mouse */
#define	NONE_PROTOCOL		0
/*
 * If the hid descriptor is not valid, the following values are
 * used.
 */
#define	USBKPSZ 		8	/* keyboard packet size */
#define	USBMSSZ 		3	/* mouse packet size */
#define	USB_KB_HID_DESCR_LENGTH 0x3f 	/* keyboard Report descr length */
#define	USB_MS_HID_DESCR_LENGTH 0x32 	/* mouse Report descr length */

/*
 * Flags for the default pipe.
 */
#define	HID_DEFAULT_PIPE_BUSY	0x01

/*
 * Hid interrupt pipe states. Interrupt pipe
 * can be in only one of these states :
 *
 *	open--1-->data_transferring--1-->open
 *	 |
 *	 |----2---->closed
 *
 *	1 = interrupt pipe callback
 *	2 = hid_close
 */
#define	HID_INTERRUPT_PIPE_CLOSED 0x00 /* Int. pipe is closed */
#define	HID_INTERRUPT_PIPE_OPEN	0x01 /* Int. pipe is opened */

/* HID mctl processing return codes */
#define	HID_SUCCESS	0	/* mctl processed successfully */
#define	HID_INPROGRESS	1	/* mctl queued/deferred for execution */
#define	HID_ENQUEUE	2	/* mctl queued/deferred for execution */
#define	HID_FAILURE	-1	/* mctl processing failed */

/* Data is being sent up */
#define	HID_INTERRUPT_PIPE_DATA_TRANSFERRING	0x03

/* Attach/detach states */
#define	HID_LOCK_INIT		0x01	/* Initial attach state */
#define	HID_MINOR_NODES		0x02 	/* Set after minor node is created */

/* HID Protocol Requests */
#define	SET_IDLE 		0x0a 	/* bRequest value to set idle request */
#define	DURATION 		(0<<8) 	/* no. of repeat reports (HID 7.2.4) */
#define	SET_PROTOCOL 		0x0b 	/* bRequest value for boot protocol */

/* Hid PM scheme */
typedef enum {
	HID_PM_ACTIVITY,	/* device is power managed by idleness */
	HID_PM_OPEN_CLOSE,	/* device is busy on open, idle on close */
	HID_PM_APPLICATION	/* device is power managed by application */
} hid_pm_scheme_t;

typedef struct hid_power {

	void			*hid_state;	/* points back to hid_state */

	int			hid_pm_busy;	/* device busy accounting */

	hid_pm_scheme_t		hid_pm_strategy;	/* device PM */

	uint8_t			hid_wakeup_enabled;

	/* this is the bit mask of the power states that device has */
	uint8_t			hid_pwr_states;

	/* wakeup and power transistion capabilites of an interface */
	uint8_t			hid_pm_capabilities;

	/* flag to indicate if driver is about to raise power level */
	boolean_t		hid_raise_power;

	/* current power level the device is in */
	uint8_t			hid_current_power;

	/* mblk indicating that the device has powered up */
	mblk_t			*hid_pm_pwrup;
} hid_power_t;

_NOTE(DATA_READABLE_WITHOUT_LOCK(hid_power_t::hid_state))
_NOTE(DATA_READABLE_WITHOUT_LOCK(hid_power_t::hid_pm_strategy))
_NOTE(DATA_READABLE_WITHOUT_LOCK(hid_power_t::hid_wakeup_enabled))
_NOTE(DATA_READABLE_WITHOUT_LOCK(hid_power_t::hid_pwr_states))
_NOTE(DATA_READABLE_WITHOUT_LOCK(hid_power_t::hid_pm_capabilities))


typedef struct hid_state {
	dev_info_t		*hid_dip;	/* per-device info handle */
	kmutex_t		hid_mutex;	/* for general locking */
	int			hid_instance;	/* instance number */

	/* Attach/detach flags */
	int			hid_attach_flags;

	/* device state flag */
	int			hid_dev_state;

	/* outstanding requests on the default pipe */
	int			hid_default_pipe_req;

	hid_power_t		*hid_pm;	/* ptr to power struct */

	usb_client_dev_data_t	*hid_dev_data;	/* ptr to usb reg struct */

	usb_dev_descr_t		*hid_dev_descr;	/* device descriptor. */

	/* hid driver is attached to this interface */
	int			hid_interfaceno;

	usb_if_descr_t		hid_if_descr;		/* interface descr */
	usb_hid_descr_t		hid_hid_descr;		/* hid descriptor */
	usb_ep_xdescr_t		hid_ep_intr_xdescr;	/* ep extended desc */
	hidparser_handle_t	hid_report_descr;	/* report descr */

	usb_pipe_handle_t	hid_default_pipe;	/* default pipe */
	usb_pipe_handle_t	hid_interrupt_pipe;	/* intr pipe handle */

	int			hid_packet_size;	/* data packet size */

	/* Pipe policy for the interrupt pipe is saved here */
	usb_pipe_policy_t	hid_intr_pipe_policy;

	/*
	 * This field is only used if the device provides polled input
	 * This is state information for the usba layer.
	 */
	usb_console_info_t	hid_polled_console_info;

	/*
	 * This is the buffer that the raw characters are stored in.
	 * for polled mode.
	 */
	uchar_t			*hid_polled_raw_buf;

	/* handle for outputting messages */
	usb_log_handle_t	hid_log_handle;

	queue_t			*hid_internal_rq;
	queue_t			*hid_external_rq;
	/* which one of the above 2 streams gets the input */
	queue_t			*hid_inuse_rq;
	int			hid_internal_flag;	/* see below */
	int			hid_external_flag;	/* see below */
} hid_state_t;

/* warlock directives, stable data */
_NOTE(MUTEX_PROTECTS_DATA(hid_state_t::hid_mutex, hid_state_t))
_NOTE(MUTEX_PROTECTS_DATA(hid_state_t::hid_mutex, hid_power_t))
_NOTE(DATA_READABLE_WITHOUT_LOCK(hid_state_t::hid_dip))
_NOTE(DATA_READABLE_WITHOUT_LOCK(hid_state_t::hid_pm))
_NOTE(DATA_READABLE_WITHOUT_LOCK(hid_state_t::hid_dev_data))
_NOTE(DATA_READABLE_WITHOUT_LOCK(hid_state_t::hid_instance))
_NOTE(DATA_READABLE_WITHOUT_LOCK(hid_state_t::hid_interrupt_pipe))
_NOTE(DATA_READABLE_WITHOUT_LOCK(hid_state_t::hid_ep_intr_descr))
_NOTE(DATA_READABLE_WITHOUT_LOCK(hid_state_t::hid_default_pipe))
_NOTE(DATA_READABLE_WITHOUT_LOCK(hid_state_t::hid_log_handle))
_NOTE(DATA_READABLE_WITHOUT_LOCK(hid_state_t::hid_if_descr))
_NOTE(DATA_READABLE_WITHOUT_LOCK(hid_state_t::hid_dev_data))
_NOTE(DATA_READABLE_WITHOUT_LOCK(hid_state_t::hid_dev_descr))
_NOTE(SCHEME_PROTECTS_DATA("stable data", usb_ep_descr))


/*
 * The hid_polled_console_info field is a handle from usba.  The
 * handle is used when the kernel is in the single thread mode
 * so the field is tagged with this note.
 */
_NOTE(SCHEME_PROTECTS_DATA("unique per call", 
				hid_state_t::hid_polled_console_info))

/*
 * structure for argument for callback routine for async
 * data transfer through default pipe.
 */
typedef struct hid_default_pipe_argument {
	/* Pointer to the write queue from which the message comes from */
	queue_t		*hid_default_pipe_arg_queue;

	/* Message to be sent up to the stream */
	struct iocblk	hid_default_pipe_arg_mctlmsg;

	/* Pointer to the original mblk_t received from hid_wput() */
	mblk_t		*hid_default_pipe_arg_mblk;

	/* Request that caused this callback to happen */
	uchar_t		hid_default_pipe_arg_bRequest;

} hid_default_pipe_arg_t;

/*
 * An instance of this structure is created per command down to the
 * device.  The control callback is not executed until the call is
 * made into usba, so there is no danger of a callback happening when
 * the fields of the structure are being set.
 */
_NOTE(SCHEME_PROTECTS_DATA("unique per call", hid_default_pipe_arg_t))

/*
 * An instance of this structure is created per command down to the
 * device.  The callback is not executed until the call is
 * made into usba, so there is no danger of a callback happening when
 * the fields of the structure are being set.
 */

/* Value for hid_[internal|external]_flag */
#define	HID_STREAMS_OPEN	0x00000001	/* Streams are open */
#define	HID_STREAMS_DISMANTLING	0x00000002	/* In hid_close() */

#define	HID_STREAMS_FLAG(q, hidp) ((q) == (hidp)->hid_internal_rq ? \
	(hidp)->hid_internal_flag : (hidp)->hid_external_flag)

#define	HID_IS_OPEN(hidp)	(((hidp)->hid_internal_flag == \
	HID_STREAMS_OPEN) || ((hidp)->hid_external_flag == HID_STREAMS_OPEN))

#define	HID_BAD_DESCR		0x01		/* Bad hid report descriptor */

#define	HID_MINOR_NAME_LEN	20	/* Max length of minor_name string */

/* hid_close will wait 60 secons for callbacks to be over */
#define	HID_CLOSE_WAIT_TIMEOUT	10

/* define a timeout for draining requests on the default control pipe */
#define	HID_DEFAULT_PIPE_DRAIN_TIMEOUT	5

/* To support PM on SUN mice of later revisions */
#define	HID_SUN_MOUSE_VENDOR_ID	0x0430
#define	HID_SUN_MOUSE_PROD_ID	0x0100
#define	HID_SUN_MOUSE_BCDDEVICE	0x0105	/* and later revisions */


/*
 * Debug message Masks
 */
#define	PRINT_MASK_ATTA		0x00000001
#define	PRINT_MASK_OPEN 	0x00000002
#define	PRINT_MASK_CLOSE	0x00000004
#define	PRINT_MASK_EVENTS	0x00000008
#define	PRINT_MASK_PM		0x00000010
#define	PRINT_MASK_ALL		0xFFFFFFFF

/*
 * Define states local to hid driver
 */
#define	USB_DEV_HID_POWER_CHANGE 0x80

/* define for retrying control requests */
#define	HID_RETRY	10

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_USB_HIDVAR_H */
