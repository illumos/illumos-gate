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

#ifndef	_ADM1031_H
#define	_ADM1031_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains the commands required to read & write to the internal
 * registers of ADM1031.
 */

#ifdef	__cplusplus
extern "C" {
#endif



#define	ADM1031_PVT_BASE_IOCTL		(I2C_PVT_BASE_IOCTL + 10)

#define	ADM1031_MANUAL_MODE		0
#define	ADM1031_AUTO_MODE		1

/*
 * Commands to be used to access and modify the control
 * registers of adm1031.
 */
#define	ADM1031_GET_STATUS_1		(ADM1031_PVT_BASE_IOCTL + 1)
#define	ADM1031_GET_STATUS_2		(ADM1031_PVT_BASE_IOCTL + 2)
#define	ADM1031_GET_DEVICE_ID		(ADM1031_PVT_BASE_IOCTL + 3)
#define	ADM1031_GET_CONFIG_1		(ADM1031_PVT_BASE_IOCTL + 4)
#define	ADM1031_GET_CONFIG_2		(ADM1031_PVT_BASE_IOCTL + 5)
#define	ADM1031_SET_CONFIG_1		(ADM1031_PVT_BASE_IOCTL + 34)
#define	ADM1031_SET_CONFIG_2		(ADM1031_PVT_BASE_IOCTL + 35)


/*
 * Commands to be used for all fan nodes.
 */
#define	ADM1031_GET_FAN_FEATURE		(ADM1031_PVT_BASE_IOCTL + 6)
#define	ADM1031_GET_FAN_CONFIG		(ADM1031_PVT_BASE_IOCTL + 8)
#define	ADM1031_GET_FAN_LOW_LIMIT	(ADM1031_PVT_BASE_IOCTL + 9)


#define	ADM1031_SET_FAN_FEATURE		(ADM1031_PVT_BASE_IOCTL + 36)
#define	ADM1031_SET_FAN_FILTER		(ADM1031_PVT_BASE_IOCTL + 38)
#define	ADM1031_SET_FAN_LOW_LIMIT	(ADM1031_PVT_BASE_IOCTL + 39)

/*
 * Commands to be used for all temperature nodes.
 */
#define	ADM1031_GET_TEMP_MIN_RANGE	(ADM1031_PVT_BASE_IOCTL + 11)
#define	ADM1031_GET_EXTD_TEMP_RESL	(ADM1031_PVT_BASE_IOCTL + 14)
#define	ADM1031_GET_TEMP_OFFSET		(ADM1031_PVT_BASE_IOCTL + 15)
#define	ADM1031_GET_TEMP_HIGH_LIMIT	(ADM1031_PVT_BASE_IOCTL + 18)
#define	ADM1031_GET_TEMP_LOW_LIMIT	(ADM1031_PVT_BASE_IOCTL + 21)
#define	ADM1031_GET_TEMP_THERM_LIMIT	(ADM1031_PVT_BASE_IOCTL + 24)


#define	ADM1031_SET_TEMP_MIN_RANGE	(ADM1031_PVT_BASE_IOCTL + 41)
#define	ADM1031_SET_TEMP_OFFSET		(ADM1031_PVT_BASE_IOCTL + 45)
#define	ADM1031_SET_TEMP_HIGH_LIMIT	(ADM1031_PVT_BASE_IOCTL + 48)
#define	ADM1031_SET_TEMP_LOW_LIMIT	(ADM1031_PVT_BASE_IOCTL + 51)
#define	ADM1031_SET_TEMP_THERM_LIMIT	(ADM1031_PVT_BASE_IOCTL + 54)


/*
 * Commands to be used for accessing and modifying
 * the internal registers of adm1031.
 */
#define	ADM1031_INTERRUPT_WAIT		(ADM1031_PVT_BASE_IOCTL + 27)
#define	ADM1031_GET_MONITOR_MODE	(ADM1031_PVT_BASE_IOCTL + 28)
#define	ADM1031_SET_MONITOR_MODE	(ADM1031_PVT_BASE_IOCTL + 29)

#ifdef	__cplusplus
}
#endif

#endif	/* _ADM1031_H */
