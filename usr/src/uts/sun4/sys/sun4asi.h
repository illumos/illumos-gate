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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_SUN4ASI_H
#define	_SYS_SUN4ASI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * alternate address space identifiers
 *
 * 0x00 - 0x7F are privileged or hyperprivileged
 * 0x80 - 0xFF can be used by users
 */

/*
 * ASIs common to all UltraSPARC processors in the sun4 machine classes.
 */
#define	ASI_MEM			0x14	/* memory (e$, no d$) */
#define	ASI_IO			0x15	/* I/O (uncached, side effect) */
#define	ASI_MEML		0x1C	/* memory little */
#define	ASI_IOL			0x1D	/* I/O little */

#define	ASI_PST8_P		0xC0	/* primary 8bit partial store */
#define	ASI_PST8_S		0xC1	/* secondary 8bit partial store */
#define	ASI_PST16_P		0xC2	/* primary 16bit partial store */
#define	ASI_PST16_S		0xC3	/* secondary 16bit partial store */
#define	ASI_PST32_P		0xC4	/* primary 32bit partial store */
#define	ASI_PST32_S		0xC5	/* secondary 32bit partial store */
#define	ASI_PST8_PL		0xC8	/* primary 8bit partial little */
#define	ASI_PST8_SL		0xC9	/* secondary 8bit partial little */
#define	ASI_PST16_PL		0xCA	/* primary 16bit partial little */
#define	ASI_PST16_SL		0xCB	/* secondary 16bit partial little */
#define	ASI_PST32_PL		0xCC	/* primary 32bit partial little */
#define	ASI_PST32_SL		0xCD	/* secondary 32bit partial little */

#define	ASI_FL8_P		0xD0	/* primary 8bit floating store */
#define	ASI_FL8_S		0xD1	/* secondary 8bit floating store */
#define	ASI_FL16_P		0xD2	/* primary 16bit floating store */
#define	ASI_FL16_S		0xD3	/* secondary 16bit floating store */
#define	ASI_FL8_PL		0xD8	/* primary 8bit floating little */
#define	ASI_FL8_SL		0xD9	/* secondary 8bit floating little */
#define	ASI_FL16_PL		0xDA	/* primary 16bit floating little */
#define	ASI_FL16_SL		0xDB	/* secondary 16bit floating little */

#define	ASI_BLK_COMMIT_P	0xE0	/* block commit primary */
#define	ASI_BLK_COMMIT_S	0xE1	/* block commit secondary */
#define	ASI_BLK_P		0xF0	/* block primary */
#define	ASI_BLK_S		0xF1	/* block secondary */
#define	ASI_BLK_PL		0xF8	/* block primary little */
#define	ASI_BLK_SL		0xF9	/* block secondary little */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SUN4ASI_H */
