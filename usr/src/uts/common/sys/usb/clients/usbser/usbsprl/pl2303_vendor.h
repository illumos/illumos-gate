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

#ifndef _SYS_USB_USBSER_PL2303_VENDOR_H
#define	_SYS_USB_USBSER_PL2303_VENDOR_H


/*
 * Prolific PL2303 vendor-specific variables
 */

#ifdef	__cplusplus
extern "C" {
#endif


/*
 * Prolific PL2303 Revision Numbers
 */

#define	PROLIFIC_REV_H				0x0202
#define	PROLIFIC_REV_X				0x0300
#define	PROLIFIC_REV_HX_CHIP_D			0x0400
#define	PROLIFIC_REV_1				0x0001

/*
 * Vendor-specific Requests
 */
#define	PL2303_SET_LINE_CODING_REQUEST_TYPE	0x21
#define	PL2303_SET_LINE_CODING_REQUEST		0x20
#define	PL2303_SET_LINE_CODING_LENGTH		0x07

#define	PL2303_GET_LINE_CODING_REQUEST_TYPE	0xa1
#define	PL2303_GET_LINE_CODING_REQUEST		0x21
#define	PL2303_GET_LINE_CODING_LENGTH		0x07

#define	PL2303_SET_CONTROL_REQUEST_TYPE		0x21
#define	PL2303_SET_CONTROL_REQUEST		0x22
#define	PL2303_SET_CONTROL_LENGTH		0x00
#define	PL2303_CONTROL_DTR			0x01
#define	PL2303_CONTROL_RTS			0x02

#define	PL2303_BREAK_REQUEST_TYPE		0x21
#define	PL2303_BREAK_REQUEST			0x23
#define	PL2303_BREAK_LENGTH			0X00
#define	PL2303_BREAK_ON				0xffff
#define	PL2303_BREAK_OFF			0x0000

#define	PL2303_VENDOR_WRITE_REQUEST_TYPE	0x40
#define	PL2303_VENDOR_WRITE_REQUEST		0x01
#define	PL2303_VENDOR_WRITE_LENGTH		0x00

#define	PL2303_VENDOR_READ_REQUEST_TYPE		0xc0
#define	PL2303_VENDOR_READ_REQUEST		0x01
#define	PL2303_VENDOR_READ_LENGTH		0x01

/*
 * Cmds of setting XON/XOFF symbol
 */
#define	SET_XONXOFF				0x05

/*
 * Device Configuration Registers (DCR0, DCR1, DCR2)
 */
#define	SET_DCR0				0x00
#define	GET_DCR0				0x80
#define	DCR0_INIT				0x01
#define	DCR0_INIT_H				0x41
#define	DCR0_INIT_X				0x61

#define	SET_DCR1				0x01
#define	GET_DCR1				0x81
#define	DCR1_INIT_H				0x80
#define	DCR1_INIT_X				0x00

#define	SET_DCR2				0x02
#define	GET_DCR2				0x82
#define	DCR2_INIT_H				0x24
#define	DCR2_INIT_X				0x44

/*
 * On-chip Date Buffers:
 */
#define	RESET_DOWNSTREAM_DATA_PIPE		0x08
#define	RESET_UPSTREAM_DATA_PIPE		0x09


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_USB_USBSER_PL2303_VENDOR_H */
