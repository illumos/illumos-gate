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

#ifndef _GRFANS_H
#define	_GRFANS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	UNKNOWN_OUT	-1

#define	MINOR_TO_DEVINST(x) ((x & 0xf00) >> 8)
#define	MINOR_TO_CHANNEL(x) (x & 0x00f)

#define	CPU_FAN_CHANNEL		0x0
#define	SYSTEM_FAN_CHANNEL	0x1

#define	CHANNEL_TO_MINOR(x) (x)
#define	DEVINST_TO_MINOR(x) (x << 8)

#define	FANS_NODE_TYPE "ddi_env:fan"

#define	CPU_FAN_0	0x01
#define	CPU_FAN_25	0x05
#define	CPU_FAN_50	0x09
#define	CPU_FAN_75	0x0d
#define	CPU_FAN_100	0x00

#define	CPU_FAN_MASK	0x0d

#define	SYS_FAN_OFF	0x02
#define	SYS_FAN_ON	0x00

struct grfans_unit {
	kmutex_t	mutex;
	uint8_t		flags;
	int8_t		sysfan_output;
	int8_t		cpufan_output;
	uint16_t	oflag[2];
	ddi_acc_handle_t cpufan_rhandle;
	ddi_acc_handle_t sysfan_rhandle;
	uint8_t		*cpufan_reg;
	uint8_t		*sysfan_reg;
};

#ifdef	__cplusplus
}
#endif

#endif /* _GRFANS_H */
