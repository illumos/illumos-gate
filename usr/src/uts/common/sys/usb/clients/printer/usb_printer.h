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

#ifndef _SYS_USB_PRINTER_H
#define	_SYS_USB_PRINTER_H


#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This header file contains generic printer class spec (1.0) information
 */

/*
 * Printer class descriptor type
 */
#define	USB_PRINTER_DESCR_TYPE	0x21


/*
 * Printer class specific commands sent to the device
 */
#define	USB_PRINTER_GET_DEVICE_ID	0x00 /* Get IEEE-1284 compatible ID */
#define	USB_PRINTER_GET_PORT_STATUS	0x01 /* Returns current status */
					/* Flushes buffers of Bulk out pipe */
#define	USB_PRINTER_SOFT_RESET		0x02
#define	USB_PRINTER_CLEAR_FEATURE	0x01	/* Clear a stall */

/*
 * Port status values, see Table 3 of the specification
 */
#define	USB_PRINTER_PORT_NO_ERROR	0x0008	/* No Error */
#define	USB_PRINTER_PORT_NO_SELECT	0x0010	/* Selected */
#define	USB_PRINTER_PORT_EMPTY		0x0020	/* Paper Empty */

/*
 * Application error state
 */
#define	USB_PRINTER_ERR_ERR		0x0001	/* Error */
#define	USB_PRINTER_SLCT_ERR		0x0002	/* Selected */
#define	USB_PRINTER_PE_ERR		0x0004	/* Paper Empty */

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_USB_PRINTER_H */
