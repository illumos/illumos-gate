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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_PIC16F819_REG_H
#define	_PIC16F819_REG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	PIC16F819_FAN_PERIOD_MSB_REGISTER	3
#define	PIC16F819_FAN_PERIOD_LSB_REGISTER	2
#define	PIC16F819_STATUS_REGISTER		1
#define	PIC16F819_COMMAND_REGISTER		0
#define	PIC16F819_DEBUG_REGISTER		9
#define	PIC16F819_FAN_STATUS_MASK		0x7
#define	PIC16F819_FAN_FAULT			0x1
#define	PIC16F819_FAN_FAULT_CLEAR		0x4
#define	PIC16F819_SW_AWARE_MODE			0x2
#define	PIC16F819_FAN_FAULT_LATCHED		0x2
#define	PIC16F819_FAN_FAILED			0x8

/*
 * The actual formula is ((CLK_FREQ * 60)/ (tach period * 4)
 * tach period is multiplied by 4 because we get 4 tach pulses per
 * revolution.
 * tach period is the number of clks we count per tach pulse.
 */
#define	PIC16F819_FAN_TACH_TO_RPM(tach)	\
	((327000 * 15)/tach)

#define	MAX_RETRIES_FOR_PIC16F819_REG_READ	5

#ifdef	__cplusplus
}
#endif

#endif	/* _PIC16F819_REG_H */
