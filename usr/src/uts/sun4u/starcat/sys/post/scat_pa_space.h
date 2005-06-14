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
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SCAT_PA_SPACE_H
#define	_SCAT_PA_SPACE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains definitions related to the Starcat
 * physical address space.
 */

/*
 * POST DEVELOPERS:
 * This file is copied to the OS workspace, and thus must abide by the OS
 * coding standards.  This file must always pass cstyle and hdrchk.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	STARCAT_DEVICE_CONFIG	(0x40000000000ull)

#define	EXP_PA_ADDR(exp)	(exp << 28)

	/*
	 * Useful to translate an sram or fprom offset to an address
	 * that a host processor would use to reach it.
	 */
#define	BOOTBUS_PA_BASE		0x7FFF0000000ull

	/* See bbc.h for sizes */
#define	BOOTBUS_FPROM_PA_BASE	(BOOTBUS_PA_BASE + 0)
#define	BOOTBUS_SRAM_PA_BASE	(BOOTBUS_PA_BASE + 0x900000u)

	/*
	 * Cacheable Physical Memory Addresses in Starcat are assigned
	 * to expanders in 128 GByte slices, based on PA[41:37].
	 * The slice to exp mapping is not always 1-1, swaps may occur
	 * as a result of some DR or POST operations.
	 * The map is maintained in the PCD.
	 * The slice number will always be a valid expander board
	 * number in [0,17], but it may not reside on that expander.
	 * The PA in these macros is 64-bit, the slice is 8 bit, unsigned.
	 */
#define	PA_2_SLICE128G(pa)		(((uint8_t)((pa) >> 37)) & 0x1Fu)
#define	SLICE128G_2_PA_BASE(slice)	(((uint64_t)((slice) & 0x1F)) << 37)


#ifdef __cplusplus
}
#endif

#endif	/* !_SCAT_PA_SPACE_H */
