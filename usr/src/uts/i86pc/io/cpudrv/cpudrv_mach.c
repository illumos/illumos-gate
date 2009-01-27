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
 * CPU power management driver support for i86pc.
 */

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cpupm.h>
#include <sys/cpudrv_mach.h>
#include <sys/machsystm.h>

/*
 * Constants used by the Processor Device Notification handler
 * that identify what kind of change has occurred. We currently
 * only handle PPC_CHANGE_NOTIFICATION. The other two are
 * ignored.
 */
#define	PPC_CHANGE_NOTIFICATION	0x80
#define	CST_CHANGE_NOTIFICATION	0x81
#define	TPC_CHANGE_NOTIFICATION	0x82

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

extern boolean_t cpudrv_intel_init(cpudrv_devstate_t *);
extern boolean_t cpudrv_amd_init(cpudrv_devstate_t *);

typedef struct cpudrv_mach_vendor {
	boolean_t	(*cpuv_init)(cpudrv_devstate_t *);
} cpudrv_mach_vendor_t;

/*
 * Table of supported vendors.
 */
static cpudrv_mach_vendor_t cpudrv_vendors[] = {
	cpudrv_intel_init,
	cpudrv_amd_init,
	NULL
};

uint_t
cpudrv_pm_get_speeds(cpudrv_devstate_t *cpudsp, int **speeds)
{
	cpudrv_mach_state_t *mach_state = cpudsp->mach_state;
	return (cpu_acpi_get_speeds(mach_state->acpi_handle, speeds));
}

void
cpudrv_pm_free_speeds(int *speeds, uint_t nspeeds)
{
	cpu_acpi_free_speeds(speeds, nspeeds);
}

/*
 * Change CPU speed using interface provided by module.
 */
int
cpudrv_pm_change_speed(cpudrv_devstate_t *cpudsp, cpudrv_pm_spd_t *new_spd)
{
	cpudrv_mach_state_t	*mach_state = cpudsp->mach_state;
	cpudrv_pm_t		*cpupm;
	uint32_t		plat_level;
	int			ret;

	if (!(mach_state->caps & CPUDRV_P_STATES))
		return (DDI_FAILURE);
	ASSERT(mach_state->cpupm_pstate_ops != NULL);
	cpupm = &(cpudsp->cpudrv_pm);
	plat_level = PM_2_PLAT_LEVEL(cpupm, new_spd->pm_level);
	ret = mach_state->cpupm_pstate_ops->cpups_power(cpudsp, plat_level);
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
cpudrv_pm_power_ready(void)
{
	return (cpupm_is_enabled(CPUPM_P_STATES) && cpupm_is_ready());
}

/*
 * All CPU instances have been initialized successfully.
 */
boolean_t
cpudrv_pm_throttle_ready(void)
{
	return (cpupm_is_enabled(CPUPM_T_STATES) && cpupm_is_ready());
}

/*
 * Is the current thread the thread that is handling the
 * PPC change notification?
 */
boolean_t
cpudrv_pm_is_governor_thread(cpudrv_pm_t *cpupm)
{
	return (curthread == cpupm->pm_governor_thread);
}

/*
 * Initialize the machine.
 * See if a module exists for managing power for this CPU.
 */
boolean_t
cpudrv_mach_pm_init(cpudrv_devstate_t *cpudsp)
{
	cpudrv_mach_vendor_t *vendors;
	cpudrv_mach_state_t *mach_state;
	int ret;

	mach_state = cpudsp->mach_state =
	    kmem_zalloc(sizeof (cpudrv_mach_state_t), KM_SLEEP);
	mach_state->caps = CPUDRV_NO_STATES;

	mach_state->acpi_handle = cpu_acpi_init(cpudsp->dip);
	if (mach_state->acpi_handle == NULL) {
		cpudrv_mach_pm_free(cpudsp);
		cmn_err(CE_WARN, "!cpudrv_mach_pm_init: instance %d: "
		    "unable to get ACPI handle",
		    ddi_get_instance(cpudsp->dip));
		cmn_err(CE_NOTE, "!CPU power management will not function.");
		return (B_FALSE);
	}

	/*
	 * Loop through the CPU management module table and see if
	 * any of the modules implement CPU power management
	 * for this CPU.
	 */
	for (vendors = cpudrv_vendors; vendors->cpuv_init != NULL; vendors++) {
		if (vendors->cpuv_init(cpudsp))
			break;
	}

	/*
	 * Nope, we can't power manage this CPU.
	 */
	if (vendors == NULL) {
		cpudrv_mach_pm_free(cpudsp);
		return (B_FALSE);
	}

	/*
	 * If P-state support exists for this system, then initialize it.
	 */
	if (mach_state->cpupm_pstate_ops != NULL) {
		ret = mach_state->cpupm_pstate_ops->cpups_init(cpudsp);
		if (ret != 0) {
			cmn_err(CE_WARN, "!cpudrv_mach_pm_init: instance %d:"
			    " unable to initialize P-state support",
			    ddi_get_instance(cpudsp->dip));
			mach_state->cpupm_pstate_ops = NULL;
			cpupm_disable(CPUPM_P_STATES);
		} else {
			mach_state->caps |= CPUDRV_P_STATES;
		}
	}

	if (mach_state->cpupm_tstate_ops != NULL) {
		ret = mach_state->cpupm_tstate_ops->cputs_init(cpudsp);
		if (ret != 0) {
			cmn_err(CE_WARN, "!cpudrv_mach_pm_init: instance %d:"
			    " unable to initialize T-state support",
			    ddi_get_instance(cpudsp->dip));
			mach_state->cpupm_tstate_ops = NULL;
			cpupm_disable(CPUPM_T_STATES);
		} else {
			mach_state->caps |= CPUDRV_T_STATES;
		}
	}

	if (mach_state->caps == CPUDRV_NO_STATES) {
		cpudrv_mach_pm_free(cpudsp);
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Free any resources allocated by cpudrv_mach_pm_init().
 */
void
cpudrv_mach_pm_free(cpudrv_devstate_t *cpudsp)
{
	cpudrv_mach_state_t *mach_state = cpudsp->mach_state;

	if (mach_state == NULL)
		return;
	if (mach_state->cpupm_pstate_ops != NULL) {
		mach_state->cpupm_pstate_ops->cpups_fini(cpudsp);
		mach_state->cpupm_pstate_ops = NULL;
	}

	if (mach_state->cpupm_tstate_ops != NULL) {
		mach_state->cpupm_tstate_ops->cputs_fini(cpudsp);
		mach_state->cpupm_tstate_ops = NULL;
	}

	if (mach_state->acpi_handle != NULL) {
		cpu_acpi_fini(mach_state->acpi_handle);
		mach_state->acpi_handle = NULL;
	}

	kmem_free(mach_state, sizeof (cpudrv_mach_state_t));
	cpudsp->mach_state = NULL;
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
cpudrv_pm_get_topspeed(void *ctx)
{
	cpudrv_mach_state_t	*mach_state;
	cpu_acpi_handle_t	handle;
	cpudrv_devstate_t	*cpudsp;
	cpudrv_pm_t		*cpupm;
	dev_info_t		*dip;
	int			instance;
	int			plat_level;
	int			max_level;

	dip = ctx;
	instance = ddi_get_instance(dip);
	cpudsp = ddi_get_soft_state(cpudrv_state, instance);
	ASSERT(cpudsp != NULL);
	cpupm = &(cpudsp->cpudrv_pm);
	mach_state = cpudsp->mach_state;
	handle = mach_state->acpi_handle;

	cpu_acpi_cache_ppc(handle);
	plat_level = CPU_ACPI_PPC(handle);
	max_level = cpupm->num_spd - 1;
	if ((plat_level < 0) || (plat_level > max_level)) {
		cmn_err(CE_NOTE, "!cpudrv_pm_get_topspeed: instance %d: "
		    "_PPC out of range %d", instance, plat_level);

		plat_level = 0;
	}
	return (plat_level);
}

/*
 * This routine reads the ACPI _TPC object. It's accessed as a callback
 * by the cpu driver whenever a _TPC change notification is received.
 */
int
cpudrv_pm_get_topthrottle(cpudrv_devstate_t *cpudsp)
{
	cpudrv_mach_state_t	*mach_state;
	cpu_acpi_handle_t	handle;
	int			throtl_level;

	mach_state = cpudsp->mach_state;
	handle = mach_state->acpi_handle;

	cpu_acpi_cache_tpc(handle);
	throtl_level = CPU_ACPI_TPC(handle);
	return (throtl_level);
}

/*
 * Take care of CPU throttling when _TPC notification arrives
 */
void
cpudrv_pm_throttle_instance(cpudrv_devstate_t *cpudsp)
{
	cpudrv_mach_state_t	*mach_state;
	uint32_t		new_level;
	int			ret;

	ASSERT(cpudsp != NULL);
	mach_state = cpudsp->mach_state;
	if (!(mach_state->caps & CPUDRV_T_STATES))
		return;
	ASSERT(mach_state->cpupm_tstate_ops != NULL);

	/*
	 * Get the new T-State support level
	 */
	new_level = cpudrv_pm_get_topthrottle(cpudsp);

	/*
	 * Change the cpu throttling to the new level
	 */
	ret = mach_state->cpupm_tstate_ops->cputs_throttle(cpudsp, new_level);
	if (ret != 0) {
		cmn_err(CE_WARN, "Cannot change the cpu throttling to the new"
		    " level: %d, Instance: %d", new_level, cpudsp->cpu_id);
	}
}

/*
 * Take care of CPU throttling when _TPC notification arrives
 */
void
cpudrv_pm_manage_throttling(void *ctx)
{
	cpudrv_devstate_t		*cpudsp;
	cpudrv_mach_state_t		*mach_state;
	cpudrv_tstate_domain_t		*domain;
	cpudrv_tstate_domain_node_t	*domain_node;
	int				instance;
	boolean_t			is_ready;

	instance = ddi_get_instance((dev_info_t *)ctx);
	cpudsp = ddi_get_soft_state(cpudrv_state, instance);
	ASSERT(cpudsp != NULL);

	/*
	 * We currently refuse to power manage if the CPU is not ready to
	 * take cross calls (cross calls fail silently if CPU is not ready
	 * for it).
	 *
	 * Additionally, for x86 platforms we cannot power manage
	 * any one instance, until all instances have been initialized.
	 * That's because we don't know what the CPU domains look like
	 * until all instances have been initialized.
	 */
	is_ready = CPUDRV_PM_XCALL_IS_READY(cpudsp->cpu_id);
	if (!is_ready) {
		DPRINTF(D_POWER, ("cpudrv_power: instance %d: "
		    "CPU not ready for x-calls\n", instance));
	} else if (!(is_ready = cpudrv_pm_throttle_ready())) {
		DPRINTF(D_POWER, ("cpudrv_power: instance %d: "
		    "waiting for all CPUs to be ready\n", instance));
	}
	if (!is_ready) {
		return;
	}

	mach_state = cpudsp->mach_state;
	domain_node = mach_state->tstate_domain_node;
	domain = domain_node->tdn_domain;

	switch (domain->td_type) {
	case CPU_ACPI_SW_ANY:
		/*
		 * Just throttle the current instance and all other instances
		 * under the same domain will get throttled to the same level
		 */
		cpudrv_pm_throttle_instance(cpudsp);
		break;
	case CPU_ACPI_HW_ALL:
	case CPU_ACPI_SW_ALL:
		/*
		 * Along with the current instance, throttle all the CPU's that
		 * belong to the same domain
		 */
		mutex_enter(&domain->td_lock);
		for (domain_node = domain->td_node; domain_node != NULL;
		    domain_node = domain_node->tdn_next)
			cpudrv_pm_throttle_instance(domain_node->tdn_cpudsp);
		mutex_exit(&domain->td_lock);
		break;

	default:
		cmn_err(CE_WARN, "Not a valid coordination type (%x) to"
		    " throttle cpu", domain->td_domain);
		break;
	}
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
cpudrv_pm_notify_handler(ACPI_HANDLE obj, UINT32 val, void *ctx)
{
	/*
	 * We only handle _PPC change notifications.
	 */
	if (val == PPC_CHANGE_NOTIFICATION)
		cpudrv_pm_redefine_topspeed(ctx);
	else if (val == TPC_CHANGE_NOTIFICATION) {
		cpudrv_pm_manage_throttling(ctx);
	}
}

void
cpudrv_pm_install_notify_handler(cpudrv_devstate_t *cpudsp, dev_info_t *dip)
{
	cpudrv_mach_state_t *mach_state = cpudsp->mach_state;
	cpu_acpi_install_notify_handler(mach_state->acpi_handle,
	    cpudrv_pm_notify_handler, dip);
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
