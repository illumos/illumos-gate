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

#ifndef _SYS_CPUDRV_MACH_H
#define	_SYS_CPUDRV_MACH_H

#include <sys/cpuvar.h>
#include <sys/cpupm.h>
#include <sys/cpu_acpi.h>
#include <sys/cpudrv.h>
#include <sys/ksynch.h>

#ifdef  __cplusplus
extern "C" {
#endif

/*
 * We currently refuse to power manage if the CPU in not ready to
 * take cross calls (cross calls fail silently if CPU is not ready
 * for it).
 */
extern cpuset_t cpu_ready_set;
#define	CPUDRV_XCALL_IS_READY(cpuid) CPU_IN_SET(cpu_ready_set, (cpuid))

/*
 * We're about to exit the _PPC thread so reset tag.
 */
#define	CPUDRV_RESET_GOVERNOR_THREAD(cpupm) { \
	if (curthread == cpupm->pm_governor_thread) \
		cpupm->pm_governor_thread = NULL; \
}

/*
 * The current top speed as defined by the _PPC.
 */
#define	CPUDRV_TOPSPEED(cpupm)	(cpupm)->top_spd

/*
 * Install a _PPC/_TPC change notification handler.
 */
#define	CPUDRV_INSTALL_MAX_CHANGE_HANDLER(cpudsp) \
	cpudrv_install_notify_handler(cpudsp);

/*
 * Uninstall _PPC/_TPC change notification handler.
 */
#define	CPUDRV_UNINSTALL_MAX_CHANGE_HANDLER(cpudsp) \
	cpudrv_uninstall_notify_handler(cpudsp);

/*
 * Redefine the topspeed.
 */
#define	CPUDRV_REDEFINE_TOPSPEED(dip) cpudrv_redefine_topspeed(dip)

/*
 * Set callbacks so that PPM can callback into CPUDRV
 */
#define	CPUDRV_SET_PPM_CALLBACKS() { \
	cpupm_get_topspeed_callb = cpudrv_get_topspeed; \
	cpupm_set_topspeed_callb = cpudrv_set_topspeed; \
}

/*
 * ACPI provides the supported speeds.
 */
#define	CPUDRV_GET_SPEEDS(cpudsp, speeds, nspeeds) \
	nspeeds = cpudrv_get_speeds(cpudsp, &speeds);
#define	CPUDRV_FREE_SPEEDS(speeds, nspeeds) \
	cpudrv_free_speeds(speeds, nspeeds);

/*
 * ACPI provides the supported C-states.
 */
#define	CPUDRV_GET_MAX_CSTATES(handle) \
	cpu_acpi_get_max_cstates(handle);

/*
 * Compute the idle cnt percentage for a given speed.
 */
#define	CPUDRV_IDLE_CNT_PERCENT(hwm, speeds, i) \
	(100 - (((100 - hwm) * speeds[0]) / speeds[i]))

/*
 * Compute the user cnt percentage for a given speed.
 */
#define	CPUDRV_USER_CNT_PERCENT(hwm, speeds, i) \
	((hwm * speeds[i]) / speeds[i - 1]);

/*
 * pm-components property defintions for this machine type.
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
#define	CPUDRV_COMP_SIZE() \
	(CPUDRV_COMP_MAX_DIG + 1 + CPUDRV_COMP_MAX_DIG + 3 + 1);
#define	CPUDRV_COMP_SPEED(cpupm, cur_spd) cur_spd->speed;
#define	CPUDRV_COMP_SPRINT(pmc, cpupm, cur_spd, comp_spd) \
	(void) sprintf(pmc, "%d=%dMHz", cur_spd->pm_level, comp_spd);

extern void cpudrv_set_topspeed(void *, int);
extern int cpudrv_get_topspeed(void *);
extern int cpudrv_get_topthrottle(cpu_t *);
extern void cpudrv_manage_throttling(void *);
extern void cpudrv_install_notify_handler(cpudrv_devstate_t *);
extern void cpudrv_uninstall_notify_handler(cpudrv_devstate_t *);
extern void cpudrv_redefine_topspeed(void *);
extern uint_t cpudrv_get_speeds(cpudrv_devstate_t *, int **);
extern void cpudrv_free_speeds(int *, uint_t);

#ifdef  __cplusplus
}
#endif

#endif /* _SYS_CPUDRV_MACH_H */
