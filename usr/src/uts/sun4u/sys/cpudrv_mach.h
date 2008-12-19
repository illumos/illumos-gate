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

#ifndef _SYS_CPUDRV_MACH_H
#define	_SYS_CPUDRV_MACH_H

#include <sys/cpu_module.h>
#include <sys/cpudrv.h>

#ifdef  __cplusplus
extern "C" {
#endif

/*
 * We currently refuse to power manage if the CPU in not ready to
 * take cross calls (cross calls fail silently if CPU is not ready
 * for it).
 */
#define	CPUDRV_PM_XCALL_IS_READY(cpuid) (CPU_XCALL_READY(cpuid))

/*
 * If a failure occurs during attach(), then CPU power management
 * is disabled.
 */
extern boolean_t cpudrv_enabled;

#define	CPUDRV_PM_DISABLE() (cpudrv_enabled = B_FALSE)

#define	CPUDRV_PM_DISABLED() (!cpudrv_enabled)

#define	CPUDRV_PM_POWER_ENABLED(cpudsp) cpudrv_pm_enabled()

/*
 * Currently, there is no governor on sun4u,
 */
#define	CPUDRV_PM_RESET_GOVERNOR_THREAD(cpupm)

/*
 * Currently, there is no need for a handler on sun4u.
 */
#define	CPUDRV_PM_INSTALL_MAX_CHANGE_HANDLER(cpudsp, dip)

/*
 * Topspeed is always the head speed.
 */
#define	CPUDRV_PM_TOPSPEED(cpupm)	(cpupm)->head_spd

/*
 * There is no notion of changing topspeed on sun4u.
 */
#define	CPUDRV_PM_REDEFINE_TOPSPEED(dip)

/*
 * There are no PPM callbacks for sun4u.
 */
#define	CPUDRV_PM_SET_PPM_CALLBACKS()

/*
 * clock-divisors property tells the supported speeds
 * as divisors of the normal speed. Divisors are in increasing
 * order starting with 1 (for normal speed). For example, a
 * property value of "1, 2, 32" represents full, 1/2 and 1/32
 * speeds.
 */
#define	CPUDRV_PM_GET_SPEEDS(cpudsp, speeds, nspeeds) { \
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, cpudsp->dip, \
	    DDI_PROP_DONTPASS, "clock-divisors", &speeds, \
	    &nspeeds) != DDI_PROP_SUCCESS) { \
		DPRINTF(D_PM_INIT, ("cpudrv_pm_init: instance %d: " \
		    "clock-divisors property not defined\n", \
				    ddi_get_instance(cpudsp->dip))); \
		return (DDI_FAILURE); \
	} \
}
#define	CPUDRV_PM_FREE_SPEEDS(speeds, unused) ddi_prop_free(speeds);

/*
 * Convert speed to Hz.
 */
#define	CPUDRV_PM_SPEED_HZ(mhz, divisor) (((uint64_t)mhz * 1000000) / divisor)

/*
 * Compute the idle cnt percentage for a given speed.
 */
#define	CPUDRV_PM_IDLE_CNT_PERCENT(hwm, speeds, i) \
	(100 - ((100 - hwm) * speeds[i]))

/*
 * Compute the user cnt percentage for a given speed.
 */
#define	CPUDRV_PM_USER_CNT_PERCENT(hwm, speeds, i) \
	((hwm * speeds[i - 1]) / speeds[i])

/*
 * pm-components property defintions for sun4u.
 *
 * Fully constructed pm-components property should be an array of
 * strings that look something like:
 *
 * pmc[0] = "NAME=CPU Speed"
 * pmc[1] = "1=1/32 of Normal"
 * pmc[2] = "2=1/2 of Normal"
 * pmc[3] = "3=Normal"
 *
 * The amount of memory needed for each string is:
 *      digits for power level + '=' + '1/' + digits for speed +
 *      description text + '\0'
 */
#define	CPUDRV_PM_COMP_NORMAL "Normal"
#define	CPUDRV_PM_COMP_OTHER " of Normal"
#define	CPUDRV_PM_COMP_SIZE() \
	(CPUDRV_PM_COMP_MAX_DIG + 1 + 2 + CPUDRV_PM_COMP_MAX_DIG + \
	    sizeof (CPUDRV_PM_COMP_OTHER) + 1);
#define	CPUDRV_PM_COMP_SPEED(cpupm, cur_spd) \
	((cur_spd == cpupm->head_spd) ? cur_spd->pm_level : cur_spd->speed)
#define	CPUDRV_PM_COMP_SPRINT(pmc, cpupm, cur_spd, comp_spd) { \
	if (cur_spd == cpupm->head_spd) \
		(void) sprintf(pmc, "%d=%s", comp_spd, CPUDRV_PM_COMP_NORMAL);\
	else \
		(void) sprintf(pmc, "%d=1/%d%s", cur_spd->pm_level, \
		    comp_spd, CPUDRV_PM_COMP_OTHER); \
}

extern boolean_t cpudrv_pm_enabled(void);

#ifdef  __cplusplus
}
#endif

#endif /* _SYS_CPUDRV_MACH_H */
