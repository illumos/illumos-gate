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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_CPUDRV_PLAT_H
#define	_SYS_CPUDRV_PLAT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/cpuvar.h>
#include <sys/cpupm.h>
#include <sys/cpu_acpi.h>

#ifdef  __cplusplus
extern "C" {
#endif

/*
 * We currently refuse to power manage if the CPU in not ready to
 * take cross calls (cross calls fail silently if CPU is not ready
 * for it).
 */
extern cpuset_t cpu_ready_set;
#define	CPUDRV_PM_XCALL_IS_READY(cpuid) CPU_IN_SET(cpu_ready_set, (cpuid))

/*
 * An error attaching any of the devices results in disabling
 * CPU power management.
 */
#define	CPUDRV_PM_DISABLE() cpupm_enable(B_FALSE)

/*
 * We're about to exit the _PPC thread so reset tag.
 */
#define	CPUDRV_PM_RESET_THROTTLE_THREAD(cpupm) { \
	if (curthread == cpupm->pm_throttle_thread) \
		cpupm->pm_throttle_thread = NULL; \
}

/*
 * Install a _PPC change notification handler.
 */
#define	CPUDRV_PM_INSTALL_TOPSPEED_CHANGE_HANDLER(cpudsp, dip) \
	cpu_acpi_install_ppc_handler(cpudsp->acpi_handle, \
	    cpudrv_pm_ppc_notify_handler, dip);

/*
 * Redefine the topspeed.
 */
#define	CPUDRV_PM_REDEFINE_TOPSPEED(dip) cpudrv_pm_redefine_topspeed(dip)

/*
 * Set callbacks so that PPM can callback into CPUDRV
 */
#define	CPUDRV_PM_SET_PPM_CALLBACKS() { \
	cpupm_get_topspeed = cpudrv_pm_get_topspeed; \
	cpupm_set_topspeed = cpudrv_pm_set_topspeed; \
}

/*
 * ACPI provides the supported speeds.
 */
#define	CPUDRV_PM_GET_SPEEDS(cpudsp, speeds, nspeeds) \
	nspeeds = cpu_acpi_get_speeds(cpudsp->acpi_handle, &speeds);
#define	CPUDRV_PM_FREE_SPEEDS(speeds, nspeeds) \
	cpu_acpi_free_speeds(speeds, nspeeds);

/*
 * Convert speed to Hz.
 */
#define	CPUDRV_PM_SPEED_HZ(unused, mhz) ((uint64_t)mhz * 1000000)

/*
 * Compute the idle cnt percentage for a given speed.
 */
#define	CPUDRV_PM_IDLE_CNT_PERCENT(hwm, speeds, i) \
	(100 - (((100 - hwm) * speeds[0]) / speeds[i]))

/*
 * Compute the user cnt percentage for a given speed.
 */
#define	CPUDRV_PM_USER_CNT_PERCENT(hwm, speeds, i) \
	((hwm * speeds[i]) / speeds[i - 1]);

/*
 * pm-components property defintions for this platform.
 *
 * Fully constructed pm-components property should be an array of
 * strings that look something like:
 *
 * pmc[0] = "NAME=CPU Speed"
 * pmc[1] = "1=2800MHz"
 * pmc[2] = "2=3200MHz"
 *
 * The amount of memory needed for each string is:
 * 	digits for power level + '=' +  digits for freq + 'MHz' + '\0'
 */
#define	CPUDRV_PM_COMP_SIZE() \
	(CPUDRV_PM_COMP_MAX_DIG + 1 + CPUDRV_PM_COMP_MAX_DIG + 3 + 1);
#define	CPUDRV_PM_COMP_SPEED(cpupm, cur_spd) cur_spd->speed;
#define	CPUDRV_PM_COMP_SPRINT(pmc, cpupm, cur_spd, comp_spd) \
	(void) sprintf(pmc, "%d=%dMHz", cur_spd->pm_level, comp_spd);

extern void cpudrv_pm_set_topspeed(void *, int);
extern int cpudrv_pm_get_topspeed(void *);
extern void cpudrv_pm_redefine_topspeed(void *);
extern void cpudrv_pm_ppc_notify_handler(ACPI_HANDLE, UINT32, void *);

#ifdef  __cplusplus
}
#endif

#endif /* _SYS_CPUDRV_PLAT_H */
