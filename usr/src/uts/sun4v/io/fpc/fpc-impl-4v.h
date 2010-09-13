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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_FPC_IMPL_4V_H
#define	_FPC_IMPL_4V_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef _ASM

typedef uint64_t devhandle_t;

#define	DEVHDLE_MASK    0xFFFFFFF

extern int fpc_get_fire_perfreg(devhandle_t dev_hdl, int regid, uint64_t *data);
extern int fpc_set_fire_perfreg(devhandle_t dev_hdl, int regid, uint64_t data);

#endif /* _ASM */


/*
 * Fire performance counter fasttraps.
 *
 * These are in the HSVC_GROUP_FIRE_PERF hypervisor group of functionality.
 */
#define	FIRE_GET_PERFREG	0x120
#define	FIRE_SET_PERFREG	0x121

/*
 * Performance counter register definitions.
 */
#define	HVIO_FIRE_PERFREG_JBC_SEL	0
#define	HVIO_FIRE_PERFREG_JBC_CNT0	1
#define	HVIO_FIRE_PERFREG_JBC_CNT1	2
#define	HVIO_FIRE_PERFREG_PCIE_IMU_SEL	3
#define	HVIO_FIRE_PERFREG_PCIE_IMU_CNT0	4
#define	HVIO_FIRE_PERFREG_PCIE_IMU_CNT1	5
#define	HVIO_FIRE_PERFREG_PCIE_MMU_SEL	6
#define	HVIO_FIRE_PERFREG_PCIE_MMU_CNT0	7
#define	HVIO_FIRE_PERFREG_PCIE_MMU_CNT1	8
#define	HVIO_FIRE_PERFREG_PCIE_TLU_SEL	9
#define	HVIO_FIRE_PERFREG_PCIE_TLU_CNT0	10
#define	HVIO_FIRE_PERFREG_PCIE_TLU_CNT1	11
#define	HVIO_FIRE_PERFREG_PCIE_TLU_CNT2	12
#define	HVIO_FIRE_PERFREG_PCIE_LNK_SEL	13
#define	HVIO_FIRE_PERFREG_PCIE_LNK_CNT1	14
#define	HVIO_FIRE_PERFREG_PCIE_LNK_CNT2	15

#ifdef	__cplusplus
}
#endif

#endif	/* _FPC_IMPL_4V_H */
