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

#ifndef	_HPC3130_H
#define	_HPC3130_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	HPC3130_IOCTL			('H' << 8)

#define	HPC3130_GET_STATUS		(HPC3130_IOCTL | 0)  /* (uint8_t *) */
#define	HPC3130_SET_STATUS		(HPC3130_IOCTL | 1)  /* (uint8_t *) */
#define	HPC3130_GET_CONTROL		(HPC3130_IOCTL | 2)  /* (uint8_t *) */
#define	HPC3130_SET_CONTROL		(HPC3130_IOCTL | 3)  /* (uint8_t *) */
#define	HPC3130_GET_EVENT_STATUS	(HPC3130_IOCTL | 4)  /* (uint8_t *) */
#define	HPC3130_SET_EVENT_STATUS	(HPC3130_IOCTL | 5)  /* (uint8_t *) */
#define	HPC3130_GET_EVENT_ENABLE	(HPC3130_IOCTL | 6)  /* (uint8_t *) */
#define	HPC3130_SET_EVENT_ENABLE	(HPC3130_IOCTL | 7)  /* (uint8_t *) */
#define	HPC3130_GET_GENERAL_CONFIG	(HPC3130_IOCTL | 8)  /* (uint8_t *) */
#define	HPC3130_SET_GENERAL_CONFIG	(HPC3130_IOCTL | 9)  /* (uint8_t *) */
#define	HPC3130_GET_INDICATOR_CONTROL	(HPC3130_IOCTL | 10) /* (uint8_t *) */
#define	HPC3130_SET_INDICATOR_CONTROL	(HPC3130_IOCTL | 11) /* (uint8_t *) */
#define	HPC3130_ENABLE_SLOT_CONTROL	(HPC3130_IOCTL | 12) /* none */
#define	HPC3130_DISABLE_SLOT_CONTROL	(HPC3130_IOCTL | 13) /* none */

#define	HPC3130_SLOT_CONTROL_ENABLE	1
#define	HPC3130_SLOT_CONTROL_DISABLE	0

#define	HPC3130_GENERAL_CONFIG_REG(SLOT)	(0x00 + ((SLOT) * 8))
#define	HPC3130_HP_STATUS_REG(SLOT)		(0x01 + ((SLOT) * 8))
#define	HPC3130_HP_CONTROL_REG(SLOT)		(0x02 + ((SLOT) * 8))
#define	HPC3130_ATTENTION_INDICATOR(SLOT)	(0x03 + ((SLOT) * 8))
#define	HPC3130_INTERRUPT_STATUS_REG(SLOT)	(0x06 + ((SLOT) * 8))
#define	HPC3130_INTERRUPT_ENABLE_REG(SLOT)	(0x07 + ((SLOT) * 8))

#ifdef	__cplusplus
}
#endif

#endif	/* _HPC3130_H */
