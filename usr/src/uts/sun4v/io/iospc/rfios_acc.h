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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_RFIOS_ACC_H
#define	_RFIOS_ACC_H

/*
 * Hypervisor and function definitions needed to access the device.
 * Defined by FWARC 2008/613.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef _ASM

#include <sys/types.h>
#include <sys/hypervisor_api.h>

typedef uint64_t cntr_handle_t;

extern int rfiospc_get_perfreg(cntr_handle_t handle, int regid, uint64_t *data);
extern int rfiospc_set_perfreg(cntr_handle_t handle, int regid, uint64_t data);

#endif /* _ASM */

/*
 * RF IOS API hypervisor group number.
 */
#define	RF_PERF_COUNTER_GROUP_ID	0x020a

/*
 * RF IOS performance counter fasttraps.
 */

#define	RFIOS_GET_PERFREG	0x165
#define	RFIOS_SET_PERFREG	0x166

/*
 * Performance counter register definitions.
 */

#define	HVIO_RFIOS_PERFREG_PEX_SEL	0
#define	HVIO_RFIOS_PERFREG_PEX_CNT0	1
#define	HVIO_RFIOS_PERFREG_PEX_CNT1	2
#define	HVIO_RFIOS_PERFREG_ATU_SEL	3
#define	HVIO_RFIOS_PERFREG_ATU_CNT0	4
#define	HVIO_RFIOS_PERFREG_ATU_CNT1	5
#define	HVIO_RFIOS_PERFREG_IMU_SEL	6
#define	HVIO_RFIOS_PERFREG_IMU_CNT0	7
#define	HVIO_RFIOS_PERFREG_IMU_CNT1	8
#define	HVIO_RFIOS_PERFREG_NPU_SEL	9
#define	HVIO_RFIOS_PERFREG_NPU_CNT0	10
#define	HVIO_RFIOS_PERFREG_NPU_CNT1	11
#define	HVIO_RFIOS_PERFREG_PEU0_SEL	12
#define	HVIO_RFIOS_PERFREG_PEU0_CNT0	13
#define	HVIO_RFIOS_PERFREG_PEU0_CNT1	14
#define	HVIO_RFIOS_PERFREG_PEU1_SEL	15
#define	HVIO_RFIOS_PERFREG_PEU1_CNT0	16
#define	HVIO_RFIOS_PERFREG_PEU1_CNT1	17

#ifdef	__cplusplus
}
#endif

#endif	/* _RFIOS_ACC_H */
