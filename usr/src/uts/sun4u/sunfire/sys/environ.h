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
 * Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_ENVIRON_H
#define	_SYS_ENVIRON_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* useful debugging stuff */
#define	ENVIRON_ATTACH_DEBUG	0x1
#define	ENVIRON_INTERRUPT_DEBUG	0x2
#define	ENVIRON_REGISTERS_DEBUG	0x4

/*
 * OBP supplies us with 1 register set for the environment node
 *
 * It is:
 * 	0	Temperature register
 */

#if defined(_KERNEL)

/* Structures used in the driver to manage the hardware */
struct environ_soft_state {
	dev_info_t *dip;		/* dev info of myself */
	dev_info_t *pdip;		/* dev info of parent */
	struct environ_soft_state *next;
	int board;			/* Board number for this FHC */
	volatile uchar_t *temp_reg;	/* VA of temperature register */
	struct temp_stats tempstat;	/* in memory storage of temperature */
	kstat_t *environ_ksp;		/* kstat pointer for temperature */
	kstat_t *environ_oksp;		/* kstat pointer for temp override */
};

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ENVIRON_H */
