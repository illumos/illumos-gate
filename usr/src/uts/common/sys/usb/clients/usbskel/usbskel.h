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

#ifndef _SYS_USB_USBSKEL_H
#define	_SYS_USB_USBSKEL_H


#ifdef	__cplusplus
extern "C" {
#endif


/*
 * Power Management support
 */
typedef struct usbskel_power  {

	void		*usbskel_state;	/* points back to usbskel_state */
	uint8_t		usbskel_pwr_states; /* bit mask of device pwr states */
	int		usbskel_pm_busy;

	/* wakeup and power transistion capabilites of an interface */
	uint8_t		usbskel_pm_capabilities;

	/* flag to indicate if driver is about to raise power level */
	boolean_t	usbskel_raise_power;

	uint8_t		usbskel_current_power;
} usbskel_power_t;


/*
 * State structure
 */
typedef struct usbskel_state {
	dev_info_t		*usbskel_dip;	/* per-device info handle */
	usb_client_dev_data_t	*usbskel_reg;	/* registration data */
	usb_ep_descr_t		usbskel_intr_ep_descr;	/* Intr ep descr */
	usb_pipe_handle_t	usbskel_intr_ph;	/* Intr pipe handle.  */
	char			*usbskel_devinst;	/* Dev and instance */
	int			usbskel_dev_state; /* USB device states. */
	int			usbskel_drv_state; /* driver states. */
	kmutex_t		usbskel_mutex;
	kcondvar_t		usbskel_serial_cv;
	boolean_t		usbskel_serial_inuse;
	boolean_t		usbskel_locks_initialized;
	usbskel_power_t		*usbskel_pm;
} usbskel_state_t;


/* Macros */
#define	USBSKEL_OPEN		0x00000001

#define	USBSKEL_REQUEST_SIZE	65535	/* Read request size maximum */
#define	USB_DEV_DESCR_SIZE	18	/* device descr size */

/* Other */
#define	USBSKEL_DRAIN_TMO	15

/* For serialization. */
#define	USBSKEL_SER_NOSIG	B_FALSE
#define	USBSKEL_SER_SIG		B_TRUE

/* For logging. */
#define	USBSKEL_LOG_LOG		1
#define	USBSKEL_LOG_CONSOLE	0

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_USB_USBSKEL_H */
