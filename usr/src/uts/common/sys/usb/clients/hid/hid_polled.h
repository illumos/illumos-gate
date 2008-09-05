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
/*
 * HID : This header file defines  project private interfaces between
 * the USB keyboard module (usbkbm) and hid.
 */

#ifndef _SYS_USB_HID_POLLED_H
#define	_SYS_USB_HID_POLLED_H


#ifdef	__cplusplus
extern "C" {
#endif


/*
 * These are project private interfaces between the USB keyboard
 * module (usbkbm) and hid.
 */

/*
 * These two messages are sent from usbkbm to hid to get and
 * release the hid_polled_input_callback structure.
 */
#define	HID_OPEN_POLLED_INPUT		0x1001
#define	HID_CLOSE_POLLED_INPUT	0x1002

/*
 * The version of this structure.  Increment this value if you change
 * the structure.
 */
#define	HID_POLLED_INPUT_V0		0

/*
 * Opaque handle.
 */
typedef struct hid_polled_handle	*hid_polled_handle_t;

typedef struct hid_polled_input_callback {

	/*
	 * Structure version.
	 */
	unsigned		hid_polled_version;

	/*
	 * This routine is called when we are entering polled mode.
	 */
	int		(*hid_polled_input_enter)(hid_polled_handle_t);

	/*
	 * This is the routine used to read characters in polled mode.
	 */
	int		(*hid_polled_read)(hid_polled_handle_t,
					    uchar_t **);

	/*
	 * This routine is called when we are exiting polled mode.
	 */
	int		(*hid_polled_input_exit)(hid_polled_handle_t);

	/*
	 * Only one hid instance is allowed to be the console input
	 */
	int			hid_polled_instance;

	/*
	 * Opaque handle used by hid.
	 */
	hid_polled_handle_t	hid_polled_input_handle;
} hid_polled_input_callback_t;

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_USB_HID_POLLED_H */
