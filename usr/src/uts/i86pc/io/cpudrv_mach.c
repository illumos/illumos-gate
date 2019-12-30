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
/*
 * Copyright (c) 2009,  Intel Corporation.
 * All Rights Reserved.
 */

/*
 * CPU power management driver support for i86pc.
 */

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cpupm.h>
#include <sys/cpudrv_mach.h>
#include <sys/machsystm.h>
#include <sys/cpu_pm.h>
#include <sys/cpuvar.h>
#include <sys/sdt.h>
#include <sys/cpu_idle.h>

/*
 * Note that our driver numbers the power levels from lowest to
 * highest starting at 1 (i.e., the lowest power level is 1 and
 * the highest power level is cpupm->num_spd). The x86 modules get
 * their power levels from ACPI which numbers power levels from
 * highest to lowest starting at 0 (i.e., the lowest power level
 * is (cpupm->num_spd - 1) and the highest power level is 0). So to
 * map one of our driver power levels to one understood by ACPI we
 * simply subtract our driver power level from cpupm->num_spd. Likewise,
 * to map an ACPI power level to the proper driver power level, we
 * subtract the ACPI power level from cpupm->num_spd.
 */
#define	PM_2_PLAT_LEVEL(cpupm, pm_level) (cpupm->num_spd - pm_level)
#define	PLAT_2_PM_LEVEL(cpupm, plat_level) (cpupm->num_spd - plat_level)

/*
 * Change CPU speed using interface provided by module.
 */
int
cpudrv_change_speed(cpudrv_devstate_t *cpudsp, cpudrv_pm_spd_t *new_spd)
{
	cpu_t *cp = cpudsp->cp;
	cpupm_mach_state_t *mach_state =
	    (cpupm_mach_state_t *)cp->cpu_m.mcpu_pm_mach_state;
	cpudrv_pm_t *cpupm;
	cpuset_t set;
	uint32_t plat_level;

	if (!(mach_state->ms_caps & CPUPM_P_STATES))
		return (DDI_FAILURE);
	ASSERT(mach_state->ms_pstate.cma_ops != NULL);
	cpupm = &(cpudsp->cpudrv_pm);
	plat_level = PM_2_PLAT_LEVEL(cpupm, new_spd->pm_level);
	CPUSET_ONLY(set, cp->cpu_id);
	mach_state->ms_pstate.cma_ops->cpus_change(set, plat_level);

	return (DDI_SUCCESS);
}

/*
 * Determine the cpu_id for the CPU device.
 */
boolean_t
cpudrv_get_cpu_id(dev_info_t *dip,  processorid_t *cpu_id)
{
	return ((*cpu_id = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "reg", -1)) != -1);

}

boolean_t
cpudrv_is_enabled(cpudrv_devstate_t *cpudsp)
{
	cpupm_mach_state_t *mach_state;

	if (!cpupm_is_enabled(CPUPM_P_STATES) || !cpudrv_enabled)
		return (B_FALSE);

	/*
	 * Only check the instance specific setting it exists.
	 */
	if (cpudsp != NULL && cpudsp->cp != NULL &&
	    cpudsp->cp->cpu_m.mcpu_pm_mach_state != NULL) {
		mach_state =
		    (cpupm_mach_state_t *)cpudsp->cp->cpu_m.mcpu_pm_mach_state;
		return (mach_state->ms_caps & CPUPM_P_STATES);
	}

	return (B_TRUE);
}

/*
 * Is the current thread the thread that is handling the
 * PPC change notification?
 */
boolean_t
cpudrv_is_governor_thread(cpudrv_pm_t *cpupm)
{
	return (curthread == cpupm->pm_governor_thread);
}

/*
 * This routine changes the top speed to which the CPUs can transition by:
 *
 * - Resetting the up_spd for all speeds lower than the new top speed
 *   to point to the new top speed.
 * - Updating the framework with a new "normal" (maximum power) for this
 *   device.
 */
void
cpudrv_set_topspeed(void *ctx, int plat_level)
{
	cpudrv_devstate_t *cpudsp;
	cpudrv_pm_t *cpupm;
	cpudrv_pm_spd_t	*spd;
	cpudrv_pm_spd_t	*top_spd;
	dev_info_t *dip;
	int pm_level;
	int instance;
	int i;

	top_spd = NULL;
	dip = ctx;
	instance = ddi_get_instance(dip);
	cpudsp = ddi_get_soft_state(cpudrv_state, instance);
	ASSERT(cpudsp != NULL);

	mutex_enter(&cpudsp->lock);
	cpupm = &(cpudsp->cpudrv_pm);
	pm_level = PLAT_2_PM_LEVEL(cpupm, plat_level);
	for (i = 0, spd = cpupm->head_spd; spd; i++, spd = spd->down_spd) {
		/*
		 * Don't mess with speeds that are higher than the new
		 * top speed. They should be out of range anyway.
		 */
		if (spd->pm_level > pm_level)
			continue;
		/*
		 * This is the new top speed.
		 */
		if (spd->pm_level == pm_level)
			top_spd = spd;

		spd->up_spd = top_spd;
	}
	cpupm->top_spd = top_spd;

	cpupm->pm_governor_thread = curthread;

	mutex_exit(&cpudsp->lock);

	(void) pm_update_maxpower(dip, 0, top_spd->pm_level);
}

/*
 * This routine reads the ACPI _PPC object. It's accessed as a callback
 * by the ppm driver whenever a _PPC change notification is received.
 */
int
cpudrv_get_topspeed(void *ctx)
{
	cpu_t *cp;
	cpudrv_devstate_t *cpudsp;
	dev_info_t *dip;
	int instance;
	int plat_level;

	dip = ctx;
	instance = ddi_get_instance(dip);
	cpudsp = ddi_get_soft_state(cpudrv_state, instance);
	ASSERT(cpudsp != NULL);
	cp = cpudsp->cp;
	plat_level = cpupm_get_top_speed(cp);

	return (plat_level);
}


/*
 * This notification handler is called whenever the ACPI _PPC
 * object changes. The _PPC is a sort of governor on power levels.
 * It sets an upper threshold on which, _PSS defined, power levels
 * are usuable. The _PPC value is dynamic and may change as properties
 * (i.e., thermal or AC source) of the system change.
 */
/* ARGSUSED */
static void
cpudrv_notify_handler(ACPI_HANDLE obj, UINT32 val, void *ctx)
{
	cpu_t			*cp;
	cpupm_mach_state_t	*mach_state;
	cpudrv_devstate_t	*cpudsp;
	dev_info_t		*dip;
	int			instance;
	extern pm_cpupm_t	cpupm;

	dip = ctx;
	instance = ddi_get_instance(dip);
	cpudsp = ddi_get_soft_state(cpudrv_state, instance);
	if (cpudsp == NULL)
		return;
	cp = cpudsp->cp;
	mach_state = (cpupm_mach_state_t *)cp->cpu_m.mcpu_pm_mach_state;
	if (mach_state == NULL)
		return;

	/*
	 * We only handle _PPC change notifications.
	 */
	if (!PM_EVENT_CPUPM && val == CPUPM_PPC_CHANGE_NOTIFICATION &&
	    mach_state->ms_caps & CPUPM_P_STATES)
		cpudrv_redefine_topspeed(ctx);
}

void
cpudrv_install_notify_handler(cpudrv_devstate_t *cpudsp)
{
	cpu_t *cp = cpudsp->cp;
	cpupm_add_notify_handler(cp, cpudrv_notify_handler,
	    cpudsp->dip);
}

void
cpudrv_uninstall_notify_handler(cpudrv_devstate_t *cpudsp)
{
	cpu_t *cp = cpudsp->cp;
	cpupm_notification_t *entry, **next;

	ASSERT(cp != NULL);
	cpupm_mach_state_t *mach_state =
	    (cpupm_mach_state_t *)cp->cpu_m.mcpu_pm_mach_state;

	mutex_enter(&mach_state->ms_lock);
	if (mach_state->ms_handlers == NULL) {
		mutex_exit(&mach_state->ms_lock);
		return;
	}

	for (next = &mach_state->ms_handlers; (entry = *next) != NULL; ) {
		if (entry->nq_handler != cpudrv_notify_handler) {
			next = &entry->nq_next;
			continue;
		}
		*next = entry->nq_next;
		kmem_free(entry, sizeof (cpupm_notification_t));
	}
	mutex_exit(&mach_state->ms_lock);
}

void
cpudrv_redefine_topspeed(void *ctx)
{
	/*
	 * This should never happen, unless ppm does not get loaded.
	 */
	if (cpupm_redefine_topspeed == NULL) {
		cmn_err(CE_WARN, "cpudrv_redefine_topspeed: "
		    "cpupm_redefine_topspeed has not been initialized - "
		    "ignoring notification");
		return;
	}

	/*
	 * ppm callback needs to handle redefinition for all CPUs in
	 * the domain.
	 */
	(*cpupm_redefine_topspeed)(ctx);
}

boolean_t
cpudrv_mach_init(cpudrv_devstate_t *cpudsp)
{
	cpupm_mach_state_t *mach_state;
	int topspeed;

	ASSERT(cpudsp->cp);

	mach_state = (cpupm_mach_state_t *)
	    (cpudsp->cp->cpu_m.mcpu_pm_mach_state);
	mach_state->ms_dip = cpudsp->dip;
	/*
	 * allocate ppm CPU domain and initialize the topspeed
	 * only if P-states are enabled.
	 */
	if (cpudrv_power_ready(cpudsp->cp)) {
		(*cpupm_ppm_alloc_pstate_domains)(cpudsp->cp);
		topspeed = cpudrv_get_topspeed(cpudsp->dip);
		cpudrv_set_topspeed(cpudsp->dip, topspeed);
	}

	return (B_TRUE);
}

boolean_t
cpudrv_mach_fini(cpudrv_devstate_t *cpudsp)
{
	/*
	 * return TRUE if cpu pointer is NULL
	 */
	if (cpudsp->cp == NULL)
		return (B_TRUE);
	/*
	 * free ppm cpu pstate domains only if
	 * P-states are enabled
	 */
	if (cpudrv_power_ready(cpudsp->cp)) {
		(*cpupm_ppm_free_pstate_domains)(cpudsp->cp);
	}

	return (B_TRUE);
}

uint_t
cpudrv_get_speeds(cpudrv_devstate_t *cpudsp, int **speeds)
{
	/*
	 * return nspeeds = 0 if can't get cpu_t
	 */
	if (cpudrv_get_cpu(cpudsp) != DDI_SUCCESS)
		return (0);

	return (cpupm_get_speeds(cpudsp->cp, speeds));
}

void
cpudrv_free_speeds(int *speeds, uint_t nspeeds)
{
	cpupm_free_speeds(speeds, nspeeds);
}

boolean_t
cpudrv_power_ready(cpu_t *cp)
{
	return (cpupm_power_ready(cp));
}

/* ARGSUSED */
void
cpudrv_set_supp_freqs(cpudrv_devstate_t *cpudsp)
{
}
