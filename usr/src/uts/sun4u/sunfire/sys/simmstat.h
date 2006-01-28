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

#ifndef	_SYS_SIMMSTAT_H
#define	_SYS_SIMMSTAT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* useful debugging stuff */
#define	SIMMSTAT_ATTACH_DEBUG		0x1
#define	SIMMSTAT_REGISTERS_DEBUG	0x2

/*
 * OBP supplies us with 1 register set for the simm-staus node, so
 * we do not need multiple register set number defines and
 * register offsets.
 */

/* Use predefined strings to name the kstats from this driver. */
#define	SIMMSTAT_KSTAT_NAME	"simm-status"

/* Number of SIMM slots in Sunfire System Board */
#define	SIMM_COUNT		16

#if defined(_KERNEL)

struct simmstat_soft_state {
	dev_info_t *dip;	/* dev info of myself */
	dev_info_t *pdip;	/* dev info of my parent */
	int board;		/* Board number for this FHC */
	/* Mapped addresses of registers */
	volatile uchar_t *simmstat_base; /* base of simmstatus registers */
	kstat_t *simmstat_ksp;
};

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SIMMSTAT_H */
