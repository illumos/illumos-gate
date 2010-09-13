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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_PCF8591_H
#define	_PCF8591_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	PCF8591_IOCTL 		('P' << 8)

#define	PCF8591_SET_IPMODE	(PCF8591_IOCTL | 0)	/* (uchar_t *) */

#define	PCF8591_4SINGLE		0x00
#define	PCF8591_3DIFF		0x01
#define	PCF8591_MIXED		0x02
#define	PCF8591_2DIFF		0x03

#ifdef	__cplusplus
}
#endif

#endif	/* _PCF8591_H */
