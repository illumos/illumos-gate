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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * CPU power management driver platform support.
 */

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cpupm.h>
#include <sys/cpudrv_plat.h>
#include <sys/cpudrv.h>
#include <sys/speedstep.h>
#include <sys/pwrnow.h>
#include <sys/machsystm.h>

/*
 * Different processor families have their own technologies for supporting
 * CPU power management (i.e., Intel has Enhanced SpeedStep for some of it's
 * processors and AMD has PowerNow! for some of it's processors). We support
 * these different technologies via modules that export the interfaces
 * described below.
 *
 * If a module implements the technology that should be used to manage
 * the current CPU device, then the cpum_init() module should return
 * succesfully (i.e., return code of 0) and perform any initialization
 * such that future power transistions can be performed by calling
 * the cpum_power() interface(). And the cpum_fini() interface can be
 * used to free any resources allocated by cpum_init().
 */
struct cpudrv_module_ops {
	char	*cm_label;
	int	(*cpum_init)(cpudrv_devstate_t *);
	void	(*cpum_fini)(cpudrv_devstate_t *);
	int	(*cpum_power)(cpudrv_devstate_t *, uint32_t);
};

/*
 * Interfaces for modules implementing Intel's Enhanced SpeedStep.
 */
static struct cpudrv_module_ops speedstep_ops = {
	"Enhanced SpeedStep Technology",
	speedstep_init,
	speedstep_fini,
	speedstep_power,
};

/*
 * Interfaces for modules implementing AMD's PowerNow!.
 */
static struct cpudrv_module_ops pwrnow_ops = {
	"PowerNow! Technology",
	pwrnow_init,
	pwrnow_fini,
	pwrnow_power
};

/*
 * Table of supported modules.
 */
static struct cpudrv_module_ops *cpudrv_module_ops_table[] = {
	&speedstep_ops,
	&pwrnow_ops,
	NULL
};
static struct cpudrv_module_ops **cpumops;

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
cpudrv_pm_change_speed(cpudrv_devstate_t *cpudsp, cpudrv_pm_spd_t *new_spd)
{
	cpudrv_pm_t		*cpupm;
	uint32_t	plat_level;
	int		ret;

	cpupm = &(cpudsp->cpudrv_pm);
	plat_level = PM_2_PLAT_LEVEL(cpupm, new_spd->pm_level);
	ret = (*cpumops)->cpum_power(cpudsp, plat_level);
	if (ret != 0)
		return (DDI_FAILURE);
	return (DDI_SUCCESS);
}

/*
 * Determine the cpu_id for the CPU device.
 */
boolean_t
cpudrv_pm_get_cpu_id(dev_info_t *dip,  processorid_t *cpu_id)
{
	return ((*cpu_id = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "reg", -1)) != -1);

}

/*
 * All CPU instances have been initialized successfully.
 */
boolean_t
cpudrv_pm_all_instances_ready(void)
{
	return (cpupm_is_ready());
}

/*
 * Is the current thread the thread that is handling the
 * PPC change notification?
 */
boolean_t
cpudrv_pm_is_throttle_thread(cpudrv_pm_t *cpupm)
{
	return (curthread == cpupm->pm_throttle_thread);
}

/*
 * See if a module exists for managing power for this CPU.
 */
boolean_t
cpudrv_pm_init_module(cpudrv_devstate_t *cpudsp)
{
	/*
	 * Loop through the CPU management module table and see if
	 * any of the modules implement CPU power management
	 * for this CPU.
	 */
	for (cpumops = cpudrv_module_ops_table; *cpumops != NULL; cpumops++) {
		if ((*cpumops)->cpum_init(cpudsp) == 0)
			break;
	}

	/*
	 * Nope, we can't power manage this CPU.
	 */
	if (*cpumops == NULL) {
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Free any resources associated with the power management module.
 */
void
cpudrv_pm_free_module(cpudrv_devstate_t *cpudsp)
{
	(*cpumops)->cpum_fini(cpudsp);
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
cpudrv_pm_set_topspeed(void *ctx, int plat_level)
{
	cpudrv_devstate_t	*cpudsp;
	cpudrv_pm_t		*cpupm;
	cpudrv_pm_spd_t	*spd;
	cpudrv_pm_spd_t	*top_spd;
	dev_info_t	*dip;
	int		pm_level;
	int		instance;
	int		i;

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
	cpupm->targ_spd = top_spd;

	cpupm->pm_throttle_thread = curthread;

	mutex_exit(&cpudsp->lock);

	if (pm_update_maxpower(dip, 0, top_spd->pm_level) == DDI_SUCCESS)
		cmn_err(CE_NOTE, "!cpudrv_pm_set_topspeed: instance %d: has "
		    "new max power of %d MHz", instance, top_spd->speed);
}

/*
 * This routine reads the ACPI _PPC object. It's accessed as a callback
 * by the ppm driver whenever a _PPC change notification is received.
 */
int
cpudrv_pm_get_topspeed(void *ctx)
{
	cpu_acpi_handle_t handle;
	cpudrv_devstate_t	*cpudsp;
	dev_info_t	*dip;
	int		instance;
	int		plat_level;

	dip = ctx;
	instance = ddi_get_instance(dip);
	cpudsp = ddi_get_soft_state(cpudrv_state, instance);
	ASSERT(cpudsp != NULL);
	handle = cpudsp->acpi_handle;

	cpu_acpi_cache_ppc(handle);
	plat_level = CPU_ACPI_PPC(handle);
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
void
cpudrv_pm_ppc_notify_handler(ACPI_HANDLE obj, UINT32 val, void *ctx)
{
	cpudrv_pm_redefine_topspeed(ctx);
}

void
cpudrv_pm_redefine_topspeed(void *ctx)
{
	/*
	 * This should never happen, unless ppm does not get loaded.
	 */
	if (cpupm_redefine_topspeed == NULL) {
		cmn_err(CE_WARN, "cpudrv_pm_redefine_topspeed: "
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
