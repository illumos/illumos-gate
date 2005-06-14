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
 * Copyright (c) 1989, 1995 by Sun Microsystems, Inc.
 * All Rights Reserved.
 */

#ifndef	_SYS_REG_H
#define	_SYS_REG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This file only exists for v7 backwards compatibility.
 * Kernel code should not include it.
 */
#ifdef _KERNEL
#error Kernel include of reg.h
#else

#include <sys/regset.h>

/*
 * NWINDOW is obsolete; it exists only for existing application compatibility.
 */
#define	NWINDOW		7

/*
 * Location of the users' stored registers relative to R0.
 * Used as an index into a gregset_t array.
 */
#define	PSR	(0)
#define	PC	(1)
#define	nPC	(2)
#define	Y	(3)
#define	G1	(4)
#define	G2	(5)
#define	G3	(6)
#define	G4	(7)
#define	G5	(8)
#define	G6	(9)
#define	G7	(10)
#define	O0	(11)
#define	O1	(12)
#define	O2	(13)
#define	O3	(14)
#define	O4	(15)
#define	O5	(16)
#define	O6	(17)
#define	O7	(18)

/*
 * The following defines are for portability.
 */
#define	PS	PSR
#define	SP	O6
#define	R0	O0
#define	R1	O1

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_REG_H */
