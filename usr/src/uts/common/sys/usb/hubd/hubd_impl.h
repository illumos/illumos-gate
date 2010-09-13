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

#ifndef	_SYS_USB_HUBD_IMPL_H
#define	_SYS_USB_HUBD_IMPL_H


#ifdef	__cplusplus
extern "C" {
#endif


/*
 * This file contains info for devctls issued by USB cfgadm plugin.
 * The only devctl of interest is DEVCTL_AP_CONTROL which uses
 * these defines and data structures.
 */

/*
 * The following are sub-commands to DEVCTL_AP_CONTROL.
 * Only exception in this list are sub-commands USB_DESCR_TYPE_DEVICE
 * and USB_DESCR_TYPE_STRING. Since these are defined in sys/usb/usbai.h
 * we are not re-defining them here.
 */
#define	HUBD_GET_CFGADM_NAME		0x10	/* get driver's name */
#define	HUBD_GET_CURRENT_CONFIG		0x20	/* get current config index */
#define	HUBD_GET_DEVICE_PATH		0x40	/* get /devices path */
#define	HUBD_REFRESH_DEVDB		0x80	/* refresh USB device DB */

/*
 * With USB_DESCR_TYPE_STRING sub-command, these are the various
 * string sub-options.
 */
#define	HUBD_MFG_STR		1		/* get manufacturer string */
#define	HUBD_PRODUCT_STR	2		/* get product-id string */
#define	HUBD_SERIALNO_STR	3		/* get serial-no-id string */
#define	HUBD_CFG_DESCR_STR	4		/* get config descr string */


typedef struct hubd_ioctl_data {
	uint_t		cmd;			/* one of the above commands */
	uint_t		port;			/* port of (root)hub */
	uint_t		get_size;		/* get size/data flag */
	caddr_t		buf;			/* data buffer */
	uint_t		bufsiz;			/* data buffer size */
	uint_t		misc_arg;		/* reserved */
} hubd_ioctl_data_t;

/* For 32-bit app/64-bit kernel */
typedef struct hubd_ioctl_data_32 {
	uint32_t	cmd;			/* one of the above commands */
	uint32_t	port;			/* port of (root)hub */
	uint32_t	get_size;		/* get size/data flag */
	caddr32_t	buf;			/* data buffer */
	uint32_t	bufsiz;			/* data buffer size */
	uint32_t	misc_arg;		/* reserved */
} hubd_ioctl_data_32_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_USB_HUBD_IMPL_H */
