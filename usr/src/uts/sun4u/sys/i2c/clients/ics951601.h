/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 1999-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_ICS951601_H
#define	_ICS951601_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Header file for ICS951601, a general purpose PCI clock generator
 * and an I2C client.
 */

/*
 * Clock numbers needed by the driver to uniquely identify a clock.
 */
#define	ICS951601_PCI2B_2	0x580
#define	ICS951601_PCI2B_1	0x540
#define	ICS951601_PCI2B_0	0x520
#define	ICS951601_PCI2A_2	0x480
#define	ICS951601_PCI2A_1	0x440
#define	ICS951601_PCI2A_0	0x420
#define	ICS951601_PCI1B_2	0x410
#define	ICS951601_PCI1B_1	0x408
#define	ICS951601_PCI1B_0	0x404
#define	ICS951601_PCI1A_7	0x380
#define	ICS951601_PCI1A_6	0x340
#define	ICS951601_PCI1A_5	0x320
#define	ICS951601_PCI1A_4	0x310
#define	ICS951601_PCI1A_3	0x308
#define	ICS951601_PCI1A_2	0x304
#define	ICS951601_PCI1A_1	0x302
#define	ICS951601_PCI1A_0	0x301

/*
 * The actions which are supported for a given clock.
 */
#define	ICS951601_READ_CLOCK		0x1000
#define	ICS951601_MODIFY_CLOCK		0x2000

/*
 * The possible values for any clock
 */
#define	ICS951601_CLOCK_SET	1
#define	ICS951601_CLOCK_CLEAR	0

/*
 * Open and close system calls.
 *
 *	0 on success
 *	-1 on error, errno is set:
 *	ENXIO	- Device not found or not available
 *	EBUSY	- The channel is in use by another
 *	EPERM	- Permission denied - not super user
 */
#ifdef	__cplusplus
}
#endif

#endif	/* _ICS951601_H */
