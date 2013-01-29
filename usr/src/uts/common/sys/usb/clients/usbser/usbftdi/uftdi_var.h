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
/*
 * Copyright 2013 Hans Rosenfeld <rosenfeld@grumpf.hope-2000.org>
 */

#ifndef _USBSER_USBFTDI_UFTDI_VAR_H
#define	_USBSER_USBFTDI_UFTDI_VAR_H

/*
 * USB UFTDI definitions
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
typedef struct uftdi_pm {
	uint8_t		pm_wakeup_enabled;	/* remote wakeup enabled */
	uint8_t		pm_pwr_states;	/* bit mask of power states */
	boolean_t	pm_raise_power;	/* driver is about to raise power */
	uint8_t		pm_cur_power;	/* current power level */
	uint_t		pm_busy_cnt;	/* number of set_busy requests */
} uftdi_pm_t;

typedef struct uftdi_regs {
	uint16_t	ur_baud;
	uint16_t	ur_data;
	uint16_t	ur_flowval;
	uint16_t	ur_flowidx;
} uftdi_regs_t;

_NOTE(SCHEME_PROTECTS_DATA("uftdi_regs", uftdi_regs))

/*
 * per device state structure
 */
typedef struct uftdi_state {
	kmutex_t		uf_lock;		/* structure lock */
	dev_info_t		*uf_dip;		/* device info */
	int			uf_dev_flags;		/* device flags */
	int			uf_hwport;		/* hw port number */
	int			uf_port_state;		/* port state */
	int			uf_port_flags;		/* port flags */
	ds_cb_t			uf_cb;			/* DSD callbacks */

	/*
	 * USBA
	 */
	usb_client_dev_data_t	*uf_dev_data;		/* registration data */
	usb_event_t		*uf_usb_events;		/* usb events */
	usb_pipe_handle_t	uf_def_ph;		/* default pipe hdl */
	usb_pipe_handle_t	uf_bulkin_ph;		/* in pipe hdl */
	int			uf_bulkin_state;	/* in pipe state */
	usb_pipe_handle_t	uf_bulkout_ph;		/* in pipe hdl */
	int			uf_bulkout_state;	/* out pipe state */
	usb_log_handle_t	uf_lh;			/* USBA log handle */
	int			uf_dev_state;		/* USB device state */
	size_t			uf_ibuf_sz;		/* input buffer size */
	size_t			uf_obuf_sz;		/* output buffer size */

	uftdi_pm_t		*uf_pm;			/* PM support */

	/*
	 * data receive and transmit
	 */
	mblk_t			*uf_rx_mp;		/* rx data */
	mblk_t			*uf_tx_mp;		/* tx data */
	kcondvar_t		uf_tx_cv;		/* tx completion */

	/*
	 * soft registers
	 */
	uftdi_regs_t		uf_softr;	/* config registers */
	uint16_t		uf_mctl;	/* modem control */
	uint8_t			uf_msr;		/* modem status */
	uint8_t			uf_lsr;		/* line status register */

} uftdi_state_t;

_NOTE(MUTEX_PROTECTS_DATA(uftdi_state::uf_lock, uftdi_state))
_NOTE(DATA_READABLE_WITHOUT_LOCK(uftdi_state::{
	uf_dip
	uf_dev_data
	uf_usb_events
	uf_def_ph
	uf_lh
	uf_ibuf_sz
	uf_obuf_sz
	uf_pm
	uf_port_state
	uf_cb
	uf_bulkin_ph
	uf_bulkout_ph
	uf_hwport
}))

/* port state */
enum {
	UFTDI_PORT_CLOSED,			/* port is closed */
	UFTDI_PORT_OPEN,			/* port is open */
	UFTDI_PORT_CLOSING
};

/* port flags */
enum {
	UFTDI_PORT_TX_STOPPED	= 0x0001	/* transmit not allowed */
};

/* pipe state */
enum {
	UFTDI_PIPE_CLOSED,			/* pipe is closed */
	UFTDI_PIPE_IDLE,			/* open but no requests */
	UFTDI_PIPE_BUSY			/* servicing request */
};

/* various numbers */
enum {
	UFTDI_BULKOUT_TIMEOUT		= 15,	/* bulkout timeout */
	UFTDI_BULKIN_TIMEOUT		= 15,	/* bulkin timeout */
	UFTDI_XFER_SZ_MAX		= 64,	/* max xfer size */
	UFTDI_CLEANUP_LEVEL_MAX	= 6	/* cleanup level */
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

#ifdef	__cplusplus
}
#endif

#endif	/* _USBSER_USBFTDI_UFTDI_VAR_H */
