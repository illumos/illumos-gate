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
#define	CPUDRV_PM_XCALL_IS_READY(cpuid) CPU_IN_SET(cpu_ready_set, (cpuid))

/*
 * An error attaching any of the devices results in disabling
 * CPU power management.
 */
#define	CPUDRV_PM_DISABLE() cpupm_disable(CPUPM_ALL_STATES)

/*
 * If no power management states are enabled, then CPU power
 * management is disabled.
 */
#define	CPUDRV_PM_DISABLED() \
	(!cpupm_is_enabled(CPUPM_P_STATES) && !cpupm_is_enabled(CPUPM_T_STATES))

/*
 * Is P-state management enabled?
 */
#define	CPUDRV_PM_POWER_ENABLED(cpudsp) \
	(((cpudrv_mach_state_t *)cpudsp->mach_state)->caps & CPUDRV_P_STATES)

/*
 * We're about to exit the _PPC thread so reset tag.
 */
#define	CPUDRV_PM_RESET_GOVERNOR_THREAD(cpupm) { \
	if (curthread == cpupm->pm_governor_thread) \
		cpupm->pm_governor_thread = NULL; \
}

/*
 * The current top speed as defined by the _PPC.
 */
#define	CPUDRV_PM_TOPSPEED(cpupm)	(cpupm)->top_spd

/*
 * Install a _PPC/_TPC change notification handler.
 */
#define	CPUDRV_PM_INSTALL_MAX_CHANGE_HANDLER(cpudsp, dip) \
	cpudrv_pm_install_notify_handler(cpudsp, dip);

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
	nspeeds = cpudrv_pm_get_speeds(cpudsp, &speeds);
#define	CPUDRV_PM_FREE_SPEEDS(speeds, nspeeds) \
	cpudrv_pm_free_speeds(speeds, nspeeds);

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
#define	CPUDRV_PM_COMP_SIZE() \
	(CPUDRV_PM_COMP_MAX_DIG + 1 + CPUDRV_PM_COMP_MAX_DIG + 3 + 1);
#define	CPUDRV_PM_COMP_SPEED(cpupm, cur_spd) cur_spd->speed;
#define	CPUDRV_PM_COMP_SPRINT(pmc, cpupm, cur_spd, comp_spd) \
	(void) sprintf(pmc, "%d=%dMHz", cur_spd->pm_level, comp_spd);

/*
 * T-State domain list
 */
typedef struct cpudrv_tstate_domain_node {
	struct cpudrv_tstate_domain_node	*tdn_next;
	struct cpudrv_tstate_domain		*tdn_domain;
	cpudrv_devstate_t			*tdn_cpudsp;
} cpudrv_tstate_domain_node_t;

typedef struct cpudrv_tstate_domain {
	struct cpudrv_tstate_domain	*td_next;
	cpudrv_tstate_domain_node_t	*td_node;
	uint32_t			td_domain;
	uint32_t			td_type;
	kmutex_t			td_lock;
} cpudrv_tstate_domain_t;

extern cpudrv_tstate_domain_t *cpudrv_tstate_domains;

/*
 * Different processor families have their own technologies for supporting
 * CPU power management (i.e., Intel has Enhanced SpeedStep for some of it's
 * processors and AMD has PowerNow! for some of it's processors). We support
 * these different technologies via modules that export the interfaces
 * described below.
 *
 * If a module implements the technology that should be used to manage
 * the current CPU device, then the cpups_init() module should return
 * succesfully (i.e., return code of 0) and perform any initialization
 * such that future power transistions can be performed by calling
 * the cpups_power() interface(). And the cpups_fini() interface can be
 * used to free any resources allocated by cpups_init().
 */
typedef struct cpudrv_pstate_ops {
	char	*cpups_label;
	int	(*cpups_init)(cpudrv_devstate_t *);
	void	(*cpups_fini)(cpudrv_devstate_t *);
	int	(*cpups_power)(cpudrv_devstate_t *, uint32_t);
} cpudrv_pstate_ops_t;

/*
 * T-state support.
 */
typedef struct cpudrv_tstate_ops {
	char	*cputs_label;
	int	(*cputs_init)(cpudrv_devstate_t *);
	void	(*cputs_fini)(cpudrv_devstate_t *);
	int	(*cputs_throttle)(cpudrv_devstate_t *,  uint32_t);
} cpudrv_tstate_ops_t;

typedef struct cpudrv_mach_state {
	void			*acpi_handle;
	cpudrv_pstate_ops_t	*cpupm_pstate_ops;
	cpudrv_tstate_ops_t	*cpupm_tstate_ops;
	cpudrv_tstate_domain_node_t *tstate_domain_node;
	uint32_t		pstate;
	uint32_t		tstate;
	uint32_t		caps;
} cpudrv_mach_state_t;

#define	CPUDRV_NO_STATES	0x00
#define	CPUDRV_P_STATES		0x01
#define	CPUDRV_T_STATES		0x02

extern uint_t cpudrv_pm_get_speeds(cpudrv_devstate_t *, int **);
extern void cpudrv_pm_free_speeds(int *, uint_t);
extern void cpudrv_pm_set_topspeed(void *, int);
extern int cpudrv_pm_get_topspeed(void *);
extern void cpudrv_pm_redefine_topspeed(void *);
extern void cpudrv_pm_install_notify_handler(cpudrv_devstate_t *, dev_info_t *);
#ifdef  __cplusplus
}
#endif

#endif /* _SYS_CPUDRV_MACH_H */
