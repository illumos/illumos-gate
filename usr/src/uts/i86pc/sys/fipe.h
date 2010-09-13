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
 * Copyright (c) 2009, Intel Corporation.
 * All rights reserved.
 */

#ifndef	_SYS_FIPE_H
#define	_SYS_FIPE_H

#include <sys/types.h>
#include <sys/sunddi.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Device property name for default power management policy. */
#define	FIPE_PROP_PM_POLICY		"fipe_pm_policy"

#define	FIPE_IOC_CODE			('F' << 8)
#define	FIPE_IOCTL_START		(FIPE_IOC_CODE | 0x1)
#define	FIPE_IOCTL_STOP			(FIPE_IOC_CODE | 0x2)
#define	FIPE_IOCTL_GET_PMPOLICY		(FIPE_IOC_CODE | 0x3)
#define	FIPE_IOCTL_SET_PMPOLICY		(FIPE_IOC_CODE | 0x4)

typedef enum {
	FIPE_PM_POLICY_DISABLE = 0,
	FIPE_PM_POLICY_PERFORMANCE = 1,
	FIPE_PM_POLICY_BALANCE = 2,
	FIPE_PM_POLICY_POWERSAVE = 3,
	FIPE_PM_POLICY_MAX
} fipe_pm_policy_t;

#ifdef _KERNEL

extern int fipe_init(dev_info_t *dip);
extern int fipe_fini(void);
extern int fipe_start(void);
extern int fipe_stop(void);
extern int fipe_suspend(void);
extern int fipe_resume(void);
extern int fipe_set_pmpolicy(fipe_pm_policy_t policy);
extern fipe_pm_policy_t fipe_get_pmpolicy(void);

#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_FIPE_H */
