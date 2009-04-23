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

#ifndef _SYS_USB_HWARC_H
#define	_SYS_USB_HWARC_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/usb/usba/usbai_private.h>
#include <sys/uwb/uwbai.h>

/* Power Management support */
typedef struct hwarc_power {

	void			*hrc_state;		/* Hwarc state */
	uint8_t			hrc_pwr_states;		/* Hwarc power state */
	int			hrc_pm_busy;		/* Hwarc busy counter */

	uint8_t			hrc_pm_capabilities;	/* PM capabilities */
	uint8_t			hrc_current_power; 	/* Hwarc power value */

	uint8_t			hrc_wakeup_enabled;	/* Remote Wakeup */
} hwarc_power_t;

/* Hwarc State structure */
typedef struct hwarc_state {
	dev_info_t		*hrc_dip;		/* Dip of Hwarc */

	usb_client_dev_data_t	*hrc_reg;		/* Usb dev data */
	usb_if_data_t		*hrc_if_descr;  	/* Interface descr */

	usb_pipe_handle_t	hrc_default_ph; 	/* Default pipe */
	usb_ep_descr_t		hrc_intr_ep_descr;	/* Inter ep descr */
	usb_pipe_handle_t	hrc_intr_ph;		/* Inter pipe hdl */
	char			*hrc_devinst;		/* Device instance */

	int			hrc_dev_state; 		/* USB device state */
	uint_t			hrc_open_count;

	kmutex_t		hrc_mutex;		/* Global hwarc mutex */

	kcondvar_t		hrc_serial_cv;		/* Serial access cond */
	boolean_t		hrc_serial_inuse;	/* Serial access flag */


	boolean_t		hrc_locks_initialized;  /* Init status flag */

	hwarc_power_t		*hrc_pm; 		/* PM state of hwarc */

	usb_log_handle_t	hrc_log_hdl; 		/* Hwarc log handle */
	uwb_dev_handle_t	hrc_dev_hdl;		/* Uwb dev handle */
} hwarc_state_t;

_NOTE(MUTEX_PROTECTS_DATA(hwarc_state_t::hrc_mutex, hwarc_state_t))
_NOTE(DATA_READABLE_WITHOUT_LOCK(hwarc_state_t::{
	hrc_dev_hdl
	hrc_dev_state
	hrc_intr_ep_descr
	hrc_default_ph
	hrc_reg
	hrc_intr_ph
	hrc_log_hdl
	hrc_dip
	hrc_if_descr

}))


#define	USB_DEV_DESCR_SIZE	18		/* Hwarc device descr size */


#define	HWA_EXEC_RC_CMD 	40 		/* UWB Radio cmd request code */

#define	HWARC_SER_NOSIG		B_FALSE		/* Hwarc serialization */
#define	HWARC_SER_SIG		B_TRUE

#define	HWARC_SET_IF		0x21		/* Hwarc bmRequestType */
#define	HWARC_GET_IF		0xA1


/* HWARC masks for debug printing */
#define	PRINT_MASK_ATTA		0x00000001
#define	PRINT_MASK_OPEN 	0x00000002
#define	PRINT_MASK_CLOSE	0x00000004
#define	PRINT_MASK_READ		0x00000008
#define	PRINT_MASK_IOCTL	0x00000010
#define	PRINT_MASK_PM		0x00000020
#define	PRINT_MASK_CB		0x00000040
#define	PRINT_MASK_HOTPLUG	0x00000080
#define	PRINT_MASK_DEVCTRL	0x00000100
#define	PRINT_MASK_DEVMAP	0x00000200
#define	PRINT_MASK_ALL		0xFFFFFFFF

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_USB_HWARC_H */
