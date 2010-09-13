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
 * WUSB cable association driver private data structures and definitions.
 */
#ifndef _SYS_USB_WUSB_CA_PRIV_H
#define	_SYS_USB_WUSB_CA_PRIV_H


#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/usb/usba/usbai_private.h>

/*
 * Power Management support
 */
typedef struct wusb_ca_power  {

	void		*wusb_ca_state;	/* points back to wusb_ca_state */
	uint8_t		wusb_ca_pwr_states; /* bit mask of device pwr states */
	int		wusb_ca_pm_busy;

	/* wakeup and power transistion capabilites of an interface */
	uint8_t		wusb_ca_pm_capabilities;

	/* flag to indicate if driver is about to raise power level */
	boolean_t	wusb_ca_raise_power;

	uint8_t		wusb_ca_current_power;
	uint8_t		wusb_ca_remote_wakeup;
} wusb_ca_power_t;


/*
 * State structure
 */
typedef struct wusb_ca_state {
	dev_info_t		*wusb_ca_dip;	/* per-device info handle */
	usb_client_dev_data_t	*wusb_ca_reg;	/* registration data */
	char			*wusb_ca_devinst;	/* Dev and instance */
	int			wusb_ca_dev_state; /* USB device states. */
	int			wusb_ca_drv_state; /* driver states. */
	kmutex_t		wusb_ca_mutex;
	kcondvar_t		wusb_ca_serial_cv;
	boolean_t		wusb_ca_serial_inuse;
	boolean_t		wusb_ca_locks_initialized;
	wusb_ca_power_t		*wusb_ca_pm;
	usb_log_handle_t	wusb_ca_log_hdl;
} wusb_ca_state_t;

_NOTE(MUTEX_PROTECTS_DATA(wusb_ca_state::wusb_ca_mutex, wusb_ca_state))

_NOTE(DATA_READABLE_WITHOUT_LOCK(wusb_ca_state_t::{
	wusb_ca_log_hdl
	wusb_ca_dip
	wusb_ca_reg
}))
/* Macros */
#define	WUSB_CA_OPEN		0x00000001

#define	WUSB_CA_REQUEST_SIZE	65535	/* Read request size maximum */
#define	USB_DEV_DESCR_SIZE	18	/* device descr size */

/* Other */
#define	WUSB_CA_DRAIN_TMO	15

/* For serialization. */
#define	WUSB_CA_SER_NOSIG	B_FALSE
#define	WUSB_CA_SER_SIG		B_TRUE

/* For logging. */
#define	WUSB_CA_LOG_LOG		1
#define	WUSB_CA_LOG_CONSOLE	0

#define	PRINT_MASK_ALL		0xFFFFFFFF
#define	PRINT_MASK_ATTA		0x00000001
#define	PRINT_MASK_CLOSE	0x00000002
#define	PRINT_MASK_OPEN		0x00000004
#define	PRINT_MASK_EVENTS	0x00000008
#define	PRINT_MASK_PM		0x00000010
#define	PRINT_MASK_CB		0x00000020
#define	PRINT_MASK_CPR		0x00000040

int wusb_cbaf_get_asso_info(wusb_ca_state_t *, intptr_t, int);
int wusb_cbaf_get_asso_reqs(wusb_ca_state_t *, intptr_t, int);
int wusb_cbaf_set_host_info(wusb_ca_state_t *, intptr_t, int);
int wusb_cbaf_get_device_info(wusb_ca_state_t *, intptr_t, int);
int wusb_cbaf_set_connection(wusb_ca_state_t *, intptr_t, int);
int wusb_cbaf_set_failure(wusb_ca_state_t *, intptr_t, int);


#ifdef __cplusplus
}
#endif

#endif	/* _SYS_USB_WUSB_CA_PRIV_H */
