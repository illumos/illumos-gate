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

#ifndef _SYS_USB_USBSACM_H
#define	_SYS_USB_USBSACM_H


#include <sys/types.h>
#include <sys/dditypes.h>
#include <sys/note.h>

#include <sys/usb/clients/usbser/usbser_dsdi.h>

#ifdef	__cplusplus
extern "C" {
#endif


typedef struct usbsacm_port usbsacm_port_t;
typedef struct usbsacm_state usbsacm_state_t;


/*
 * PM support
 */
typedef struct usbsacm_power {
	uint8_t		pm_wakeup_enabled;	/* remote wakeup enabled */
	uint8_t		pm_pwr_states;	/* bit mask of power states */
	boolean_t	pm_raise_power;	/* driver is about to raise power */
	uint8_t		pm_cur_power;	/* current power level */
	uint_t		pm_busy_cnt;	/* number of set_busy requests */
} usbsacm_pm_t;


/*
 * per bulk in/out structure
 */
struct usbsacm_port {
	kmutex_t		acm_port_mutex;		/* structure lock */
	usbsacm_state_t		*acm_device;		/* back pointer */
	usb_pipe_handle_t	acm_bulkin_ph;		/* in pipe hdl */
	int			acm_bulkin_state;	/* in pipe state */
	usb_pipe_handle_t	acm_bulkout_ph;		/* out pipe hdl */
	int			acm_bulkout_state;	/* out pipe state */
	usb_pipe_handle_t	acm_intr_ph;		/* intr pipe hdl */
	int			acm_intr_state;		/* intr pipe state */
	usb_ep_descr_t		acm_intr_ep_descr;	/* ep descriptor */
	int			acm_ctrl_if_no;		/* control interface */
	int			acm_data_if_no;		/* data interface */
	int			acm_data_port_no;	/* which data port */
	ds_cb_t			acm_cb;			/* DSD callbacks */
	mblk_t			*acm_rx_mp;		/* rx data */
	mblk_t			*acm_tx_mp;		/* tx data */
	kcondvar_t		acm_tx_cv;		/* tx completion */
	uint8_t			acm_mctlout;		/* controls out */
	uint8_t			acm_mctlin;		/* controls in */
	int			acm_cap;		/* port capabilities */
	usb_cdc_line_coding_t	acm_line_coding;	/* port line coding */
	int			acm_port_state;		/* port state */
	size_t			acm_bulkin_size;	/* bulkin xfer size */
};

_NOTE(MUTEX_PROTECTS_DATA(usbsacm_port::acm_port_mutex, usbsacm_port))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usbsacm_port::{
	acm_device
	acm_cb.cb_rx
	acm_cb.cb_tx
	acm_cb.cb_arg
	acm_bulkin_ph
	acm_bulkout_ph
	acm_intr_ph
	acm_ctrl_if_no
	acm_data_if_no
	acm_data_port_no
	acm_port_state
}))

struct usbsacm_state {
	kmutex_t		acm_mutex;		/* structure lock */
	dev_info_t		*acm_dip;		/* device info */
	usb_client_dev_data_t	*acm_dev_data;		/* registration data */
	usb_event_t		*acm_usb_events;	/* usb events */
	usb_pipe_handle_t	acm_def_ph;		/* default pipe hdl */
	usb_log_handle_t	acm_lh;			/* USBA log handle */
	int			acm_dev_state;		/* USB device state */
	size_t			acm_xfer_sz;		/* bulk xfer size */
	boolean_t		acm_compatibility;	/* if conform to spec */
	usbsacm_port_t		*acm_ports;		/* per port structs */
	int			acm_port_cnt;		/* port number */
	usbsacm_pm_t		*acm_pm;		/* PM support */
};

_NOTE(MUTEX_PROTECTS_DATA(usbsacm_state::acm_mutex, usbsacm_state))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usbsacm_state::{
	acm_dip
	acm_dev_data
	acm_usb_events
	acm_def_ph
	acm_lh
	acm_dev_state
	acm_xfer_sz
	acm_compatibility
	acm_ports
	acm_port_cnt
	acm_pm
}))

/* port state */
enum {
	USBSACM_PORT_CLOSED,			/* port is closed */
	USBSACM_PORT_OPEN,			/* port is open */
	USBSACM_PORT_CLOSING
};

/* pipe state */
enum {
	USBSACM_PIPE_CLOSED,			/* pipe is closed */
	USBSACM_PIPE_IDLE,			/* open but no requests */
	USBSACM_PIPE_BUSY,			/* servicing request */
	USBSACM_PIPE_CLOSING			/* pipe is closing */
};

/* various tunables */
enum {
	USBSACM_BULKOUT_TIMEOUT		= 15,	/* bulkout timeout */
	USBSACM_BULKIN_TIMEOUT		= 0	/* bulkin timeout */
};

/* hardware definitions */
enum {
	USBSACM_REQ_OUT	= USB_DEV_REQ_TYPE_CLASS| USB_DEV_REQ_HOST_TO_DEV,
	USBSACM_REQ_IN	= USB_DEV_REQ_TYPE_CLASS | USB_DEV_REQ_DEV_TO_HOST,
	USBSACM_REQ_WRITE_IF		= USBSACM_REQ_OUT | USB_DEV_REQ_RCPT_IF,
	USBSACM_REQ_READ_IF		= USBSACM_REQ_IN | USB_DEV_REQ_RCPT_IF
};

#define	PRINT_MASK_ATTA		0x00000001
#define	PRINT_MASK_CLOSE	0x00000002
#define	PRINT_MASK_OPEN		0x00000004
#define	PRINT_MASK_EVENTS	0x00000008
#define	PRINT_MASK_PM		0x00000010
#define	PRINT_MASK_CB		0x00000020
#define	PRINT_MASK_ALL		0xFFFFFFFF


#define	NELEM(a)	(sizeof (a) / sizeof (*(a)))


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_USB_USBSACM_H */
