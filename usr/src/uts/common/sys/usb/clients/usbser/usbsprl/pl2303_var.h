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

#ifndef _SYS_USB_USBSER_PL2303_VAR_H
#define	_SYS_USB_USBSER_PL2303_VAR_H


/*
 * USB PL2303 definitions
 */

#include <sys/types.h>
#include <sys/dditypes.h>
#include <sys/note.h>

#include <sys/usb/clients/usbser/usbser_dsdi.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * PM support
 */
typedef struct pl2303_power {
	uint8_t		pm_wakeup_enabled;	/* remote wakeup enabled */
	uint8_t		pm_pwr_states;	/* bit mask of power states */
	boolean_t	pm_raise_power;	/* driver is about to raise power */
	uint8_t		pm_cur_power;	/* current power level */
	uint_t		pm_busy_cnt;	/* number of set_busy requests */
} pl2303_pm_t;


/*
 * From device driver's perspective, there is no difference
 * between PL-2303HX(Chip A) and PL-2303X chips, so PL-2303X will
 * stand for two chiptypes
 */
enum pl2303_chip {
	pl2303_H,		/* PL-2303H chip */
	pl2303_X,		/* PL-2303X chip or PL-2303HX(Chip A) */
	pl2303_HX_CHIP_D,	/* PL-2303HX(Chip D) */
	pl2303_UNKNOWN		/* Unknown chip type */
};

/*
 * per device state structure
 */
typedef struct pl2303_state {
	kmutex_t		pl_mutex;		/* structure lock */
	dev_info_t		*pl_dip;		/* device info */
	int			pl_dev_flags;		/* device flags */
	int			pl_port_state;		/* port state */
	int			pl_port_flags;		/* port flags */
	ds_cb_t			pl_cb;			/* DSD callbacks */
	/*
	 * USBA
	 */
	usb_client_dev_data_t	*pl_dev_data;		/* registration data */
	usb_event_t		*pl_usb_events;		/* usb events */
	usb_pipe_handle_t	pl_def_ph;		/* default pipe hdl */
	usb_pipe_handle_t	pl_bulkin_ph;		/* in pipe hdl */
	int			pl_bulkin_state;	/* in pipe state */
	usb_pipe_handle_t	pl_bulkout_ph;		/* in pipe hdl */
	int			pl_bulkout_state;	/* out pipe state */
	usb_log_handle_t	pl_lh;			/* USBA log handle */
	int			pl_dev_state;		/* USB device state */
	size_t			pl_xfer_sz;		/* HCI bulk xfer size */
	pl2303_pm_t		*pl_pm;			/* PM support */
	/*
	 * data receipt and transmit
	 */
	mblk_t			*pl_rx_mp;		/* rx data */
	mblk_t			*pl_tx_mp;		/* tx data */
	kcondvar_t		pl_tx_cv;		/* tx completion */
	/*
	 * other
	 */
	uint8_t			pl_mctl;		/* modem controls */
	enum pl2303_chip	pl_chiptype;		/* chip type */
} pl2303_state_t;

_NOTE(MUTEX_PROTECTS_DATA(pl2303_state::pl_mutex, pl2303_state))
_NOTE(DATA_READABLE_WITHOUT_LOCK(pl2303_state::{
	pl_dip
	pl_dev_data
	pl_usb_events
	pl_def_ph
	pl_lh
	pl_xfer_sz
	pl_pm
	pl_port_state
	pl_cb.cb_rx
	pl_cb.cb_tx
	pl_cb.cb_arg
	pl_bulkin_ph
	pl_bulkout_ph
	pl_chiptype
}))


/* port state */
enum {
	PL2303_PORT_CLOSED,			/* port is closed */
	PL2303_PORT_OPEN,			/* port is open */
	PL2303_PORT_CLOSING
};

/* port flags */
enum {
	PL2303_PORT_TX_STOPPED	= 0x0001	/* transmit not allowed */
};

/* pipe state */
enum {
	PL2303_PIPE_CLOSED,			/* pipe is closed */
	PL2303_PIPE_IDLE,			/* open but no requests */
	PL2303_PIPE_BUSY			/* servicing request */
};

/* various tunables */
enum {
	PL2303_BULKOUT_TIMEOUT		= 15,	/* bulkout timeout */
	PL2303_BULKIN_TIMEOUT		= 15,	/* bulkin timeout */
	PL2303_XFER_SZ_MAX		= 64,	/* max xfer size */
	PL2303_CLEANUP_LEVEL_MAX	= 6	/* cleanup level */
};


/*
 * debug printing masks
 */
#define	DPRINT_ATTACH		0x00000001
#define	DPRINT_OPEN		0x00000002
#define	DPRINT_CLOSE		0x00000004
#define	DPRINT_DEF_PIPE		0x00000010
#define	DPRINT_IN_PIPE		0x00000020
#define	DPRINT_OUT_PIPE		0x00000040
#define	DPRINT_IN_DATA		0x00000400
#define	DPRINT_OUT_DATA		0x00000800
#define	DPRINT_CTLOP		0x00001000
#define	DPRINT_HOTPLUG		0x00002000
#define	DPRINT_PM		0x00004000
#define	DPRINT_MASK_ALL		0xFFFFFFFF


/*
 * misc macros
 */
#define	NELEM(a)	(sizeof (a) / sizeof (*(a)))

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_USB_USBSER_PL2303_VAR_H */
