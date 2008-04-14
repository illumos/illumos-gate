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
 * Copyright 2008 Sun Microsystems, Inc.
 * All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _CHEETAH_SDC_H
#define	_CHEETAH_SDC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *  TARGET_REG: The register that is being tested
 *  TEMP_REG:	The register that is used for the random
 *		instructions. This must be a odd register.
 *		The fault does not occur if even registers
 *		are used.
 *  CHECK_REG1:	The register to which the contents of the
 *		TARGET_REG will be moved.
 *  CHECK_REG2:	Same as CHECK_REG1.
 */

#ifdef __cplusplus
extern "C" {
#endif

/* Global Registers */

#ifdef	GLOBALS
#define	TEMP_REG	l1
#define	CHECK_REG1	o0
#define	CHECK_REG2	o1
#endif

#ifdef	G1
#define	TARGET_REG	g1
#endif

#ifdef	G2
#define	TARGET_REG	g2
.register	%g2, #scratch
#endif

#ifdef	G3
#define	TARGET_REG	g3
.register	%g3, #scratch
#endif

#ifdef	G4
#define	TARGET_REG	g4
#endif


/* Local Registers */

#ifdef	LOCALS
#define	TEMP_REG	o3
#define	CHECK_REG1	o0
#define	CHECK_REG2	o1
#endif

#ifdef	L0
#define	TARGET_REG	l0
#endif

#ifdef	L1
#define	TARGET_REG	l1
#endif

#ifdef	L2
#define	TARGET_REG	l2
#endif

#ifdef	L3
#define	TARGET_REG	l3
#endif

#ifdef	L4
#define	TARGET_REG	l4
#endif

#ifdef	L5
#define	TARGET_REG	l5
#endif

#ifdef	L6
#define	TARGET_REG	l6
#endif

#ifdef	L7
#define	TARGET_REG	l7
#endif


/* Out Registers */

#ifdef	OUTS
#define	TEMP_REG	l3
#define	CHECK_REG1	l0
#define	CHECK_REG2	l1
#endif

#ifdef	O0
#define	TARGET_REG	o0
#endif

#ifdef	O1
#define	TARGET_REG	o1
#endif

#ifdef	O2
#define	TARGET_REG	o2
#endif

#ifdef	O3
#define	TARGET_REG	o3
#endif

#ifdef	O4
#define	TARGET_REG	o4
#endif

#ifdef	O5
#define	TARGET_REG	o5
#endif

/* %o6 not tested as it is the %sp */

#ifdef	O7
#define	TARGET_REG	o7
#endif

#ifdef __cplusplus
}
#endif

#endif /* _CHEETAH_SDC_H */
