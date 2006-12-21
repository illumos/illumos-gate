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

#ifndef	_N2PIUPC_ACC_H
#define	_N2PIUPC_ACC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Hypervisor and function definitions needed to access the device.
 */

#ifdef	__cplusplus
extern "C" {
#endif


#ifndef _ASM

#include <sys/types.h>
#include <sys/hypervisor_api.h>

typedef uint64_t cntr_handle_t;

extern int n2piupc_get_perfreg(cntr_handle_t handle, int regid, uint64_t *data);
extern int n2piupc_set_perfreg(cntr_handle_t handle, int regid, uint64_t data);

#endif /* _ASM */


/*
 * N2 PIU API hypervisor group number.
 */
#define	N2PIU_PERF_COUNTER_GROUP_ID	0x0203

/*
 * N2 PIU performance counter fasttraps.
 */
#define	N2PIU_GET_PERFREG	0x140
#define	N2PIU_SET_PERFREG	0x141

/*
 * Performance counter register definitions.
 */
#define	HVIO_N2PIU_PERFREG_IMU_SEL	0
#define	HVIO_N2PIU_PERFREG_IMU_CNT0	1
#define	HVIO_N2PIU_PERFREG_IMU_CNT1	2
#define	HVIO_N2PIU_PERFREG_MMU_SEL	3
#define	HVIO_N2PIU_PERFREG_MMU_CNT0	4
#define	HVIO_N2PIU_PERFREG_MMU_CNT1	5
#define	HVIO_N2PIU_PERFREG_PEU_SEL	6
#define	HVIO_N2PIU_PERFREG_PEU_CNT0	7
#define	HVIO_N2PIU_PERFREG_PEU_CNT1	8
#define	HVIO_N2PIU_PERFREG_PEU_CNT2	9
#define	HVIO_N2PIU_PERFREG_BITERR_CNT1	10
#define	HVIO_N2PIU_PERFREG_BITERR_CNT2	11

#define	HVIO_N2PIU_PERFREG_NUM_REGS	(HVIO_N2PIU_PERFREG_BITERR_CNT2 + 1)

#ifdef	__cplusplus
}
#endif

#endif	/* _N2PIUPC_ACC_H */
