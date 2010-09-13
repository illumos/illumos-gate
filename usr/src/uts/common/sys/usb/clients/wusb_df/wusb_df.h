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

#ifndef _SYS_USB_WUSB_DF_H
#define	_SYS_USB_WUSB_DF_H


#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/usb/usba/usbai_private.h>

/*
 * Power Management support
 */
typedef struct wusb_df_power  {

	void		*wusb_df_state;	/* points back to wusb_df_state */
	uint8_t		wusb_df_pwr_states; /* bit mask of device pwr states */
	int		wusb_df_pm_busy;
	uint8_t		wusb_df_wakeup_enabled;

	/* wakeup and power transistion capabilites of an interface */
	uint8_t		wusb_df_pm_capabilities;


	uint8_t		wusb_df_current_power;
} wusb_df_power_t;


/*
 * State structure
 */
typedef struct wusb_df_state {
	dev_info_t		*wusb_df_dip;	/* per-device info handle */
	usb_client_dev_data_t	*wusb_df_reg;	/* registration data */
	usb_ep_descr_t		wusb_df_intr_ep_descr;	/* Intr ep descr */
	usb_pipe_handle_t	wusb_df_intr_ph;	/* Intr pipe handle.  */
	char			*wusb_df_devinst;	/* Dev and instance */
	int			wusb_df_dev_state; /* USB device states. */
	kmutex_t		wusb_df_mutex;
	kcondvar_t		wusb_df_serial_cv;
	boolean_t		wusb_df_serial_inuse;
	boolean_t		wusb_df_locks_initialized;
	wusb_df_power_t		*wusb_df_pm;
	usb_log_handle_t	wusb_df_log_hdl;
} wusb_df_state_t;

_NOTE(MUTEX_PROTECTS_DATA(wusb_df_state::wusb_df_mutex, wusb_df_state))

_NOTE(DATA_READABLE_WITHOUT_LOCK(wusb_df_state_t::{
	wusb_df_log_hdl
	wusb_df_intr_ph
	wusb_df_dip
	wusb_df_reg
}))
/* Macros */

#define	WUSB_DF_REQUEST_SIZE	65535	/* Read request size maximum */
#define	USB_DEV_DESCR_SIZE	18	/* device descr size */


/* For serialization. */
#define	WUSB_DF_SER_NOSIG	B_FALSE
#define	WUSB_DF_SER_SIG		B_TRUE

/* For logging. */

#define	PRINT_MASK_ALL		0xFFFFFFFF
#define	PRINT_MASK_ATTA		0x00000001
#define	PRINT_MASK_PM		0x00000010
#define	PRINT_MASK_CB		0x00000020
#define	PRINT_MASK_CPR		0x00000040

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_USB_WUSB_DF_H */
