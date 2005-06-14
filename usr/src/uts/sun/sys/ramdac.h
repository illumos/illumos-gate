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
 * Copyright (c) 1991, by Sun Microsystems, Inc.
 */

#ifndef	_SYS_RAMDAC_H
#define	_SYS_RAMDAC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SunOS-4.1 1.2 */

#include <sys/pixrect.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	RAMDAC_READMASK		04
#define	RAMDAC_BLINKMASK	05
#define	RAMDAC_COMMAND		06
#define	RAMDAC_CTRLTEST		07

/* 3 Brooktree ramdac 457 or 458 packed in a 32-bit register */
/* fbunit defined in <pixrect/pixrect.h> */
struct ramdac {
	union fbunit    addr_reg,	/* address register */
			lut_data,	/* lut data port */
			command,	/* command/control port */
			overlay;	/* overlay lut port */
};

#define	ASSIGN_LUT(lut, value) (lut).packed = (value & 0xff) | \
	((value & 0xff) << 8) | ((value & 0xff) << 16)
/*
 * when "ctrl/test" is selected, the least significant 3 bits control
 * which channel this ramdac is controlling.
 *
 * select 4:1 multiplexing to make enable/overlay possible, also makes
 * the overlay transparent and display the overlay plane only.
 *
 * enable read and write to all planes
 *
 * no blinking
 */

#define	INIT_BT458(lut)   {					\
	ASSIGN_LUT((lut)->addr_reg, 0);				\
	ASSIGN_LUT((lut)->addr_reg, RAMDAC_CTRLTEST);		\
	ASSIGN_LUT((lut)->command, 04);				\
	ASSIGN_LUT((lut)->addr_reg, RAMDAC_COMMAND);		\
	ASSIGN_LUT((lut)->command, 0x43);			\
	ASSIGN_LUT((lut)->addr_reg, RAMDAC_READMASK);		\
	ASSIGN_LUT((lut)->command, 0xff);			\
	ASSIGN_LUT((lut)->addr_reg, RAMDAC_BLINKMASK);		\
	ASSIGN_LUT((lut)->command, 0);				\
	}

#define	INIT_OCMAP(omap) {					\
	(omap)[0].packed =  0x000000;				\
	(omap)[1].packed =  0xffffff;				\
	(omap)[2].packed =  0x00ff00;				\
	(omap)[3].packed =  0x000000;				\
	}

#define	INIT_CMAP(cmap, size)   {				\
	register int    idx;					\
	for (idx = 0; idx < size; idx++)			\
		ASSIGN_LUT((cmap)[idx], idx);			\
	}

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_RAMDAC_H */
