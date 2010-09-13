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
 * Copyright (c) 2009, Intel Corporation.
 * All rights reserved.
 */

#include <sys/cpu_pm.h>
#include <sys/x86_archext.h>
#include <sys/sdt.h>
#include <sys/spl.h>
#include <sys/machsystm.h>
#include <sys/archsystm.h>
#include <sys/hpet.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include <sys/cpupm.h>
#include <sys/cpu_idle.h>
#include <sys/cpu_acpi.h>
#include <sys/cpupm_throttle.h>
#include <sys/dtrace.h>
#include <sys/note.h>

/*
 * This callback is used to build the PPM CPU domains once
 * a CPU device has been started. The callback is initialized
 * by the PPM driver to point to a routine that will build the
 * domains.
 */
void (*cpupm_ppm_alloc_pstate_domains)(cpu_t *);

/*
 * This callback is used to remove CPU from the PPM CPU domains
 * when the cpu driver is detached. The callback is initialized
 * by the PPM driver to point to a routine that will remove CPU
 * from the domains.
 */
void (*cpupm_ppm_free_pstate_domains)(cpu_t *);

/*
 * This callback is used to redefine the topspeed for a CPU device.
 * Since all CPUs in a domain should have identical properties, this
 * callback is initialized by the PPM driver to point to a routine
 * that will redefine the topspeed for all devices in a CPU domain.
 * This callback is exercised whenever an ACPI _PPC change notification
 * is received by the CPU driver.
 */
void (*cpupm_redefine_topspeed)(void *);

/*
 * This callback is used by the PPM driver to call into the CPU driver
 * to find a CPU's current topspeed (i.e., it's current ACPI _PPC value).
 */
void (*cpupm_set_topspeed_callb)(void *, int);

/*
 * This callback is used by the PPM driver to call into the CPU driver
 * to set a new topspeed for a CPU.
 */
int (*cpupm_get_topspeed_callb)(void *);

static void cpupm_event_notify_handler(ACPI_HANDLE, UINT32, void *);
static void cpupm_free_notify_handlers(cpu_t *);
static void cpupm_power_manage_notifications(void *);

/*
 * Until proven otherwise, all power states are manageable.
 */
static uint32_t cpupm_enabled = CPUPM_ALL_STATES;

cpupm_state_domains_t *cpupm_pstate_domains = NULL;
cpupm_state_domains_t *cpupm_tstate_domains = NULL;
cpupm_state_domains_t *cpupm_cstate_domains = NULL;

/*
 * c-state tunables
 *
 * cpupm_cs_sample_interval is the length of time we wait before
 * recalculating c-state statistics.  When a CPU goes idle it checks
 * to see if it has been longer than cpupm_cs_sample_interval since it last
 * caculated which C-state to go to.
 *
 * cpupm_cs_idle_cost_tunable is the ratio of time CPU spends executing + idle
 * divided by time spent in the idle state transitions.
 * A value of 10 means the CPU will not spend more than 1/10 of its time
 * in idle latency.  The worst case performance will be 90% of non Deep C-state
 * kernel.
 *
 * cpupm_cs_idle_save_tunable is how long we must stay in a deeper C-state
 * before it is worth going there.  Expressed as a multiple of latency.
 */
uint32_t cpupm_cs_sample_interval = 100*1000*1000;	/* 100 milliseconds */
uint32_t cpupm_cs_idle_cost_tunable = 10;	/* work time / latency cost */
uint32_t cpupm_cs_idle_save_tunable = 2;	/* idle power savings */
uint16_t cpupm_C2_idle_pct_tunable = 70;
uint16_t cpupm_C3_idle_pct_tunable = 80;

#ifndef __xpv
extern boolean_t cpupm_intel_init(cpu_t *);
extern boolean_t cpupm_amd_init(cpu_t *);

typedef struct cpupm_vendor {
	boolean_t	(*cpuv_init)(cpu_t *);
} cpupm_vendor_t;

/*
 * Table of supported vendors.
 */
static cpupm_vendor_t cpupm_vendors[] = {
	cpupm_intel_init,
	cpupm_amd_init,
	NULL
};
#endif

/*
 * Initialize the machine.
 * See if a module exists for managing power for this CPU.
 */
/*ARGSUSED*/
void
cpupm_init(cpu_t *cp)
{
#ifndef __xpv
	cpupm_vendor_t *vendors;
	cpupm_mach_state_t *mach_state;
	struct machcpu *mcpu = &(cp->cpu_m);
	static boolean_t first = B_TRUE;
	int *speeds;
	uint_t nspeeds;
	int ret;

	mach_state = cp->cpu_m.mcpu_pm_mach_state =
	    kmem_zalloc(sizeof (cpupm_mach_state_t), KM_SLEEP);
	mach_state->ms_caps = CPUPM_NO_STATES;
	mutex_init(&mach_state->ms_lock, NULL, MUTEX_DRIVER, NULL);

	mach_state->ms_acpi_handle = cpu_acpi_init(cp);
	if (mach_state->ms_acpi_handle == NULL) {
		cpupm_fini(cp);
		cmn_err(CE_WARN, "!cpupm_init: processor %d: "
		    "unable to get ACPI handle", cp->cpu_id);
		cmn_err(CE_NOTE, "!CPU power management will not function.");
		CPUPM_DISABLE();
		first = B_FALSE;
		return;
	}

	/*
	 * Loop through the CPU management module table and see if
	 * any of the modules implement CPU power management
	 * for this CPU.
	 */
	for (vendors = cpupm_vendors; vendors->cpuv_init != NULL; vendors++) {
		if (vendors->cpuv_init(cp))
			break;
	}

	/*
	 * Nope, we can't power manage this CPU.
	 */
	if (vendors == NULL) {
		cpupm_fini(cp);
		CPUPM_DISABLE();
		first = B_FALSE;
		return;
	}

	/*
	 * If P-state support exists for this system, then initialize it.
	 */
	if (mach_state->ms_pstate.cma_ops != NULL) {
		ret = mach_state->ms_pstate.cma_ops->cpus_init(cp);
		if (ret != 0) {
			mach_state->ms_pstate.cma_ops = NULL;
			cpupm_disable(CPUPM_P_STATES);
		} else {
			nspeeds = cpupm_get_speeds(cp, &speeds);
			if (nspeeds == 0) {
				cmn_err(CE_NOTE, "!cpupm_init: processor %d:"
				    " no speeds to manage", cp->cpu_id);
			} else {
				cpupm_set_supp_freqs(cp, speeds, nspeeds);
				cpupm_free_speeds(speeds, nspeeds);
				mach_state->ms_caps |= CPUPM_P_STATES;
			}
		}
	} else {
		cpupm_disable(CPUPM_P_STATES);
	}

	if (mach_state->ms_tstate.cma_ops != NULL) {
		ret = mach_state->ms_tstate.cma_ops->cpus_init(cp);
		if (ret != 0) {
			mach_state->ms_tstate.cma_ops = NULL;
			cpupm_disable(CPUPM_T_STATES);
		} else {
			mach_state->ms_caps |= CPUPM_T_STATES;
		}
	} else {
		cpupm_disable(CPUPM_T_STATES);
	}

	/*
	 * If C-states support exists for this system, then initialize it.
	 */
	if (mach_state->ms_cstate.cma_ops != NULL) {
		ret = mach_state->ms_cstate.cma_ops->cpus_init(cp);
		if (ret != 0) {
			mach_state->ms_cstate.cma_ops = NULL;
			mcpu->max_cstates = CPU_ACPI_C1;
			cpupm_disable(CPUPM_C_STATES);
			idle_cpu = non_deep_idle_cpu;
			disp_enq_thread = non_deep_idle_disp_enq_thread;
		} else if (cpu_deep_cstates_supported()) {
			mcpu->max_cstates = cpu_acpi_get_max_cstates(
			    mach_state->ms_acpi_handle);
			if (mcpu->max_cstates > CPU_ACPI_C1) {
				(void) cstate_timer_callback(
				    CST_EVENT_MULTIPLE_CSTATES);
				cp->cpu_m.mcpu_idle_cpu = cpu_acpi_idle;
				mcpu->mcpu_idle_type = CPU_ACPI_C1;
				disp_enq_thread = cstate_wakeup;
			} else {
				(void) cstate_timer_callback(
				    CST_EVENT_ONE_CSTATE);
			}
			mach_state->ms_caps |= CPUPM_C_STATES;
		} else {
			mcpu->max_cstates = CPU_ACPI_C1;
			idle_cpu = non_deep_idle_cpu;
			disp_enq_thread = non_deep_idle_disp_enq_thread;
		}
	} else {
		cpupm_disable(CPUPM_C_STATES);
	}


	if (mach_state->ms_caps == CPUPM_NO_STATES) {
		cpupm_fini(cp);
		CPUPM_DISABLE();
		first = B_FALSE;
		return;
	}

	if ((mach_state->ms_caps & CPUPM_T_STATES) ||
	    (mach_state->ms_caps & CPUPM_P_STATES) ||
	    (mach_state->ms_caps & CPUPM_C_STATES)) {
		if (first) {
			acpica_write_cpupm_capabilities(
			    mach_state->ms_caps & CPUPM_P_STATES,
			    mach_state->ms_caps & CPUPM_C_STATES);
		}
		if (mach_state->ms_caps & CPUPM_T_STATES) {
			cpupm_throttle_manage_notification(cp);
		}
		if (mach_state->ms_caps & CPUPM_C_STATES) {
			cpuidle_manage_cstates(cp);
		}
		if (mach_state->ms_caps & CPUPM_P_STATES) {
			cpupm_power_manage_notifications(cp);
		}
		cpupm_add_notify_handler(cp, cpupm_event_notify_handler, cp);
	}
	first = B_FALSE;
#endif
}

/*
 * Free any resources allocated during cpupm initialization or cpupm start.
 */
/*ARGSUSED*/
void
cpupm_free(cpu_t *cp, boolean_t cpupm_stop)
{
#ifndef __xpv
	cpupm_mach_state_t *mach_state =
	    (cpupm_mach_state_t *)cp->cpu_m.mcpu_pm_mach_state;

	if (mach_state == NULL)
		return;

	if (mach_state->ms_pstate.cma_ops != NULL) {
		if (cpupm_stop)
			mach_state->ms_pstate.cma_ops->cpus_stop(cp);
		else
			mach_state->ms_pstate.cma_ops->cpus_fini(cp);
		mach_state->ms_pstate.cma_ops = NULL;
	}

	if (mach_state->ms_tstate.cma_ops != NULL) {
		if (cpupm_stop)
			mach_state->ms_tstate.cma_ops->cpus_stop(cp);
		else
			mach_state->ms_tstate.cma_ops->cpus_fini(cp);
		mach_state->ms_tstate.cma_ops = NULL;
	}

	if (mach_state->ms_cstate.cma_ops != NULL) {
		if (cpupm_stop)
			mach_state->ms_cstate.cma_ops->cpus_stop(cp);
		else
			mach_state->ms_cstate.cma_ops->cpus_fini(cp);

		mach_state->ms_cstate.cma_ops = NULL;
	}

	cpupm_free_notify_handlers(cp);

	if (mach_state->ms_acpi_handle != NULL) {
		cpu_acpi_fini(mach_state->ms_acpi_handle);
		mach_state->ms_acpi_handle = NULL;
	}

	mutex_destroy(&mach_state->ms_lock);
	kmem_free(mach_state, sizeof (cpupm_mach_state_t));
	cp->cpu_m.mcpu_pm_mach_state = NULL;
#endif
}

void
cpupm_fini(cpu_t *cp)
{
	/*
	 * call (*cpus_fini)() ops to release the cpupm resource
	 * in the P/C/T-state driver
	 */
	cpupm_free(cp, B_FALSE);
}

void
cpupm_start(cpu_t *cp)
{
	cpupm_init(cp);
}

void
cpupm_stop(cpu_t *cp)
{
	/*
	 * call (*cpus_stop)() ops to reclaim the cpupm resource
	 * in the P/C/T-state driver
	 */
	cpupm_free(cp, B_TRUE);
}

/*
 * If A CPU has started and at least one power state is manageable,
 * then the CPU is ready for power management.
 */
boolean_t
cpupm_is_ready(cpu_t *cp)
{
#ifndef __xpv
	cpupm_mach_state_t *mach_state =
	    (cpupm_mach_state_t *)cp->cpu_m.mcpu_pm_mach_state;
	uint32_t cpupm_caps = mach_state->ms_caps;

	if (cpupm_enabled == CPUPM_NO_STATES)
		return (B_FALSE);

	if ((cpupm_caps & CPUPM_T_STATES) ||
	    (cpupm_caps & CPUPM_P_STATES) ||
	    (cpupm_caps & CPUPM_C_STATES))

		return (B_TRUE);
	return (B_FALSE);
#else
	_NOTE(ARGUNUSED(cp));
	return (B_FALSE);
#endif
}

boolean_t
cpupm_is_enabled(uint32_t state)
{
	return ((cpupm_enabled & state) == state);
}

/*
 * By default, all states are enabled.
 */
void
cpupm_disable(uint32_t state)
{

	if (state & CPUPM_P_STATES) {
		cpupm_free_domains(&cpupm_pstate_domains);
	}
	if (state & CPUPM_T_STATES) {
		cpupm_free_domains(&cpupm_tstate_domains);
	}
	if (state & CPUPM_C_STATES) {
		cpupm_free_domains(&cpupm_cstate_domains);
	}
	cpupm_enabled &= ~state;
}

/*
 * Allocate power domains for C,P and T States
 */
void
cpupm_alloc_domains(cpu_t *cp, int state)
{
	cpupm_mach_state_t *mach_state =
	    (cpupm_mach_state_t *)(cp->cpu_m.mcpu_pm_mach_state);
	cpu_acpi_handle_t handle = mach_state->ms_acpi_handle;
	cpupm_state_domains_t **dom_ptr;
	cpupm_state_domains_t *dptr;
	cpupm_state_domains_t **mach_dom_state_ptr;
	uint32_t domain;
	uint32_t type;

	switch (state) {
	case CPUPM_P_STATES:
		if (CPU_ACPI_IS_OBJ_CACHED(handle, CPU_ACPI_PSD_CACHED)) {
			domain = CPU_ACPI_PSD(handle).sd_domain;
			type = CPU_ACPI_PSD(handle).sd_type;
		} else {
			if (MUTEX_HELD(&cpu_lock)) {
				domain = cpuid_get_chipid(cp);
			} else {
				mutex_enter(&cpu_lock);
				domain = cpuid_get_chipid(cp);
				mutex_exit(&cpu_lock);
			}
			type = CPU_ACPI_HW_ALL;
		}
		dom_ptr = &cpupm_pstate_domains;
		mach_dom_state_ptr = &mach_state->ms_pstate.cma_domain;
		break;
	case CPUPM_T_STATES:
		if (CPU_ACPI_IS_OBJ_CACHED(handle, CPU_ACPI_TSD_CACHED)) {
			domain = CPU_ACPI_TSD(handle).sd_domain;
			type = CPU_ACPI_TSD(handle).sd_type;
		} else {
			if (MUTEX_HELD(&cpu_lock)) {
				domain = cpuid_get_chipid(cp);
			} else {
				mutex_enter(&cpu_lock);
				domain = cpuid_get_chipid(cp);
				mutex_exit(&cpu_lock);
			}
			type = CPU_ACPI_HW_ALL;
		}
		dom_ptr = &cpupm_tstate_domains;
		mach_dom_state_ptr = &mach_state->ms_tstate.cma_domain;
		break;
	case CPUPM_C_STATES:
		if (CPU_ACPI_IS_OBJ_CACHED(handle, CPU_ACPI_CSD_CACHED)) {
			domain = CPU_ACPI_CSD(handle).sd_domain;
			type = CPU_ACPI_CSD(handle).sd_type;
		} else {
			if (MUTEX_HELD(&cpu_lock)) {
				domain = cpuid_get_coreid(cp);
			} else {
				mutex_enter(&cpu_lock);
				domain = cpuid_get_coreid(cp);
				mutex_exit(&cpu_lock);
			}
			type = CPU_ACPI_HW_ALL;
		}
		dom_ptr = &cpupm_cstate_domains;
		mach_dom_state_ptr = &mach_state->ms_cstate.cma_domain;
		break;
	default:
		return;
	}

	for (dptr = *dom_ptr; dptr != NULL; dptr = dptr->pm_next) {
		if (dptr->pm_domain == domain)
			break;
	}

	/* new domain is created and linked at the head */
	if (dptr == NULL) {
		dptr = kmem_zalloc(sizeof (cpupm_state_domains_t), KM_SLEEP);
		dptr->pm_domain = domain;
		dptr->pm_type = type;
		dptr->pm_next = *dom_ptr;
		mutex_init(&dptr->pm_lock, NULL, MUTEX_SPIN,
		    (void *)ipltospl(DISP_LEVEL));
		CPUSET_ZERO(dptr->pm_cpus);
		*dom_ptr = dptr;
	}
	CPUSET_ADD(dptr->pm_cpus, cp->cpu_id);
	*mach_dom_state_ptr = dptr;
}

/*
 * Free C, P or T state power domains
 */
void
cpupm_free_domains(cpupm_state_domains_t **dom_ptr)
{
	cpupm_state_domains_t *this_domain, *next_domain;

	this_domain = *dom_ptr;
	while (this_domain != NULL) {
		next_domain = this_domain->pm_next;
		mutex_destroy(&this_domain->pm_lock);
		kmem_free((void *)this_domain,
		    sizeof (cpupm_state_domains_t));
		this_domain = next_domain;
	}
	*dom_ptr = NULL;
}

/*
 * Remove CPU from C, P or T state power domains
 */
void
cpupm_remove_domains(cpu_t *cp, int state, cpupm_state_domains_t **dom_ptr)
{
	cpupm_mach_state_t *mach_state =
	    (cpupm_mach_state_t *)(cp->cpu_m.mcpu_pm_mach_state);
	cpupm_state_domains_t *dptr;
	uint32_t pm_domain;

	ASSERT(mach_state);

	switch (state) {
	case CPUPM_P_STATES:
		pm_domain = mach_state->ms_pstate.cma_domain->pm_domain;
		break;
	case CPUPM_T_STATES:
		pm_domain = mach_state->ms_tstate.cma_domain->pm_domain;
		break;
	case CPUPM_C_STATES:
		pm_domain = mach_state->ms_cstate.cma_domain->pm_domain;
		break;
	default:
		return;
	}

	/*
	 * Find the CPU C, P or T state power domain
	 */
	for (dptr = *dom_ptr; dptr != NULL; dptr = dptr->pm_next) {
		if (dptr->pm_domain == pm_domain)
			break;
	}

	/*
	 * return if no matched domain found
	 */
	if (dptr == NULL)
		return;

	/*
	 * We found one matched power domain, remove CPU from its cpuset.
	 * pm_lock(spin lock) here to avoid the race conditions between
	 * event change notification and cpu remove.
	 */
	mutex_enter(&dptr->pm_lock);
	if (CPU_IN_SET(dptr->pm_cpus, cp->cpu_id))
		CPUSET_DEL(dptr->pm_cpus, cp->cpu_id);
	mutex_exit(&dptr->pm_lock);
}

void
cpupm_alloc_ms_cstate(cpu_t *cp)
{
	cpupm_mach_state_t *mach_state;
	cpupm_mach_acpi_state_t *ms_cstate;

	mach_state = (cpupm_mach_state_t *)(cp->cpu_m.mcpu_pm_mach_state);
	ms_cstate = &mach_state->ms_cstate;
	ASSERT(ms_cstate->cma_state.cstate == NULL);
	ms_cstate->cma_state.cstate = kmem_zalloc(sizeof (cma_c_state_t),
	    KM_SLEEP);
	ms_cstate->cma_state.cstate->cs_next_cstate = CPU_ACPI_C1;
}

void
cpupm_free_ms_cstate(cpu_t *cp)
{
	cpupm_mach_state_t *mach_state =
	    (cpupm_mach_state_t *)(cp->cpu_m.mcpu_pm_mach_state);
	cpupm_mach_acpi_state_t *ms_cstate = &mach_state->ms_cstate;

	if (ms_cstate->cma_state.cstate != NULL) {
		kmem_free(ms_cstate->cma_state.cstate, sizeof (cma_c_state_t));
		ms_cstate->cma_state.cstate = NULL;
	}
}

void
cpupm_state_change(cpu_t *cp, int level, int state)
{
	cpupm_mach_state_t	*mach_state =
	    (cpupm_mach_state_t *)(cp->cpu_m.mcpu_pm_mach_state);
	cpupm_state_ops_t	*state_ops;
	cpupm_state_domains_t  	*state_domain;
	cpuset_t		set;

	DTRACE_PROBE2(cpupm__state__change, cpu_t *, cp, int, level);

	if (mach_state == NULL) {
		return;
	}

	switch (state) {
	case CPUPM_P_STATES:
		state_ops = mach_state->ms_pstate.cma_ops;
		state_domain = mach_state->ms_pstate.cma_domain;
		break;
	case CPUPM_T_STATES:
		state_ops = mach_state->ms_tstate.cma_ops;
		state_domain = mach_state->ms_tstate.cma_domain;
		break;
	default:
		break;
	}

	switch (state_domain->pm_type) {
	case CPU_ACPI_SW_ANY:
		/*
		 * A request on any CPU in the domain transitions the domain
		 */
		CPUSET_ONLY(set, cp->cpu_id);
		state_ops->cpus_change(set, level);
		break;
	case CPU_ACPI_SW_ALL:
		/*
		 * All CPUs in the domain must request the transition
		 */
	case CPU_ACPI_HW_ALL:
		/*
		 * P/T-state transitions are coordinated by the hardware
		 * For now, request the transition on all CPUs in the domain,
		 * but looking ahead we can probably be smarter about this.
		 */
		mutex_enter(&state_domain->pm_lock);
		state_ops->cpus_change(state_domain->pm_cpus, level);
		mutex_exit(&state_domain->pm_lock);
		break;
	default:
		cmn_err(CE_NOTE, "Unknown domain coordination type: %d",
		    state_domain->pm_type);
	}
}

/*
 * CPU PM interfaces exposed to the CPU power manager
 */
/*ARGSUSED*/
id_t
cpupm_plat_domain_id(cpu_t *cp, cpupm_dtype_t type)
{
	cpupm_mach_state_t	*mach_state =
	    (cpupm_mach_state_t *)(cp->cpu_m.mcpu_pm_mach_state);

	if ((mach_state == NULL) || (!cpupm_is_enabled(CPUPM_P_STATES) &&
	    !cpupm_is_enabled(CPUPM_C_STATES))) {
		return (CPUPM_NO_DOMAIN);
	}
	if (type == CPUPM_DTYPE_ACTIVE) {
		/*
		 * Return P-State domain for the specified CPU
		 */
		if (mach_state->ms_pstate.cma_domain) {
			return (mach_state->ms_pstate.cma_domain->pm_domain);
		}
	} else if (type == CPUPM_DTYPE_IDLE) {
		/*
		 * Return C-State domain for the specified CPU
		 */
		if (mach_state->ms_cstate.cma_domain) {
			return (mach_state->ms_cstate.cma_domain->pm_domain);
		}
	}
	return (CPUPM_NO_DOMAIN);
}

/*ARGSUSED*/
uint_t
cpupm_plat_state_enumerate(cpu_t *cp, cpupm_dtype_t type,
    cpupm_state_t *states)
{
	int	*speeds;
	uint_t	nspeeds, i;

	/*
	 * Idle domain support unimplemented
	 */
	if (type != CPUPM_DTYPE_ACTIVE) {
		return (0);
	}
	nspeeds = cpupm_get_speeds(cp, &speeds);

	/*
	 * If the caller passes NULL for states, just return the
	 * number of states.
	 */
	if (states != NULL) {
		for (i = 0; i < nspeeds; i++) {
			states[i].cps_speed = speeds[i];
			states[i].cps_handle = (cpupm_handle_t)i;
		}
	}
	cpupm_free_speeds(speeds, nspeeds);
	return (nspeeds);
}

/*ARGSUSED*/
int
cpupm_plat_change_state(cpu_t *cp, cpupm_state_t *state)
{
	if (!cpupm_is_ready(cp))
		return (-1);

	cpupm_state_change(cp, (int)state->cps_handle, CPUPM_P_STATES);

	return (0);
}

/*ARGSUSED*/
/*
 * Note: It is the responsibility of the users of
 * cpupm_get_speeds() to free the memory allocated
 * for speeds using cpupm_free_speeds()
 */
uint_t
cpupm_get_speeds(cpu_t *cp, int **speeds)
{
#ifndef __xpv
	cpupm_mach_state_t *mach_state =
	    (cpupm_mach_state_t *)cp->cpu_m.mcpu_pm_mach_state;
	return (cpu_acpi_get_speeds(mach_state->ms_acpi_handle, speeds));
#else
	return (0);
#endif
}

/*ARGSUSED*/
void
cpupm_free_speeds(int *speeds, uint_t nspeeds)
{
#ifndef __xpv
	cpu_acpi_free_speeds(speeds, nspeeds);
#endif
}

/*
 * All CPU instances have been initialized successfully.
 */
boolean_t
cpupm_power_ready(cpu_t *cp)
{
	return (cpupm_is_enabled(CPUPM_P_STATES) && cpupm_is_ready(cp));
}

/*
 * All CPU instances have been initialized successfully.
 */
boolean_t
cpupm_throttle_ready(cpu_t *cp)
{
	return (cpupm_is_enabled(CPUPM_T_STATES) && cpupm_is_ready(cp));
}

/*
 * All CPU instances have been initialized successfully.
 */
boolean_t
cpupm_cstate_ready(cpu_t *cp)
{
	return (cpupm_is_enabled(CPUPM_C_STATES) && cpupm_is_ready(cp));
}

void
cpupm_notify_handler(ACPI_HANDLE obj, UINT32 val, void *ctx)
{
	cpu_t *cp = ctx;
	cpupm_mach_state_t *mach_state =
	    (cpupm_mach_state_t *)(cp->cpu_m.mcpu_pm_mach_state);
	cpupm_notification_t *entry;

	mutex_enter(&mach_state->ms_lock);
	for (entry =  mach_state->ms_handlers; entry != NULL;
	    entry = entry->nq_next) {
		entry->nq_handler(obj, val, entry->nq_ctx);
	}
	mutex_exit(&mach_state->ms_lock);
}

/*ARGSUSED*/
void
cpupm_add_notify_handler(cpu_t *cp, CPUPM_NOTIFY_HANDLER handler, void *ctx)
{
#ifndef __xpv
	cpupm_mach_state_t *mach_state =
	    (cpupm_mach_state_t *)cp->cpu_m.mcpu_pm_mach_state;
	cpupm_notification_t *entry;

	entry = kmem_zalloc(sizeof (cpupm_notification_t), KM_SLEEP);
	entry->nq_handler = handler;
	entry->nq_ctx = ctx;
	mutex_enter(&mach_state->ms_lock);
	if (mach_state->ms_handlers == NULL) {
		entry->nq_next = NULL;
		mach_state->ms_handlers = entry;
		cpu_acpi_install_notify_handler(mach_state->ms_acpi_handle,
		    cpupm_notify_handler, cp);

	} else {
		entry->nq_next = mach_state->ms_handlers;
		mach_state->ms_handlers = entry;
	}
	mutex_exit(&mach_state->ms_lock);
#endif
}

/*ARGSUSED*/
static void
cpupm_free_notify_handlers(cpu_t *cp)
{
#ifndef __xpv
	cpupm_mach_state_t *mach_state =
	    (cpupm_mach_state_t *)cp->cpu_m.mcpu_pm_mach_state;
	cpupm_notification_t *entry;
	cpupm_notification_t *next;

	mutex_enter(&mach_state->ms_lock);
	if (mach_state->ms_handlers == NULL) {
		mutex_exit(&mach_state->ms_lock);
		return;
	}
	if (mach_state->ms_acpi_handle != NULL) {
		cpu_acpi_remove_notify_handler(mach_state->ms_acpi_handle,
		    cpupm_notify_handler);
	}
	entry = mach_state->ms_handlers;
	while (entry != NULL) {
		next = entry->nq_next;
		kmem_free(entry, sizeof (cpupm_notification_t));
		entry = next;
	}
	mach_state->ms_handlers = NULL;
	mutex_exit(&mach_state->ms_lock);
#endif
}

/*
 * Get the current max speed from the ACPI _PPC object
 */
/*ARGSUSED*/
int
cpupm_get_top_speed(cpu_t *cp)
{
#ifndef __xpv
	cpupm_mach_state_t 	*mach_state;
	cpu_acpi_handle_t 	handle;
	int 			plat_level;
	uint_t			nspeeds;
	int			max_level;

	mach_state =
	    (cpupm_mach_state_t *)cp->cpu_m.mcpu_pm_mach_state;
	handle = mach_state->ms_acpi_handle;

	cpu_acpi_cache_ppc(handle);
	plat_level = CPU_ACPI_PPC(handle);

	nspeeds = CPU_ACPI_PSTATES_COUNT(handle);

	max_level = nspeeds - 1;
	if ((plat_level < 0) || (plat_level > max_level)) {
		cmn_err(CE_NOTE, "!cpupm_get_top_speed: CPU %d: "
		    "_PPC out of range %d", cp->cpu_id, plat_level);
		plat_level = 0;
	}

	return (plat_level);
#else
	return (0);
#endif
}

/*
 * This notification handler is called whenever the ACPI _PPC
 * object changes. The _PPC is a sort of governor on power levels.
 * It sets an upper threshold on which, _PSS defined, power levels
 * are usuable. The _PPC value is dynamic and may change as properties
 * (i.e., thermal or AC source) of the system change.
 */

static void
cpupm_power_manage_notifications(void *ctx)
{
	cpu_t			*cp = ctx;
	int			top_speed;

	top_speed = cpupm_get_top_speed(cp);
	cpupm_redefine_max_activepwr_state(cp, top_speed);
}

/* ARGSUSED */
static void
cpupm_event_notify_handler(ACPI_HANDLE obj, UINT32 val, void *ctx)
{
#ifndef __xpv

	cpu_t *cp = ctx;
	cpupm_mach_state_t *mach_state =
	    (cpupm_mach_state_t *)(cp->cpu_m.mcpu_pm_mach_state);

	if (mach_state == NULL)
		return;

	/*
	 * Currently, we handle _TPC,_CST and _PPC change notifications.
	 */
	if (val == CPUPM_TPC_CHANGE_NOTIFICATION &&
	    mach_state->ms_caps & CPUPM_T_STATES) {
		cpupm_throttle_manage_notification(ctx);
	} else if (val == CPUPM_CST_CHANGE_NOTIFICATION &&
	    mach_state->ms_caps & CPUPM_C_STATES) {
		cpuidle_manage_cstates(ctx);
	} else if (val == CPUPM_PPC_CHANGE_NOTIFICATION &&
	    mach_state->ms_caps & CPUPM_P_STATES) {
		cpupm_power_manage_notifications(ctx);
	}
#endif
}

/*
 * Update cpupm cstate data each time CPU exits idle.
 */
void
cpupm_wakeup_cstate_data(cma_c_state_t *cs_data, hrtime_t end)
{
	cs_data->cs_idle_exit = end;
}

/*
 * Determine next cstate based on cpupm data.
 * Update cpupm cstate data each time CPU goes idle.
 * Do as much as possible in the idle state bookkeeping function because the
 * performance impact while idle is minimal compared to in the wakeup function
 * when there is real work to do.
 */
uint32_t
cpupm_next_cstate(cma_c_state_t *cs_data, cpu_acpi_cstate_t *cstates,
    uint32_t cs_count, hrtime_t start)
{
	hrtime_t duration;
	hrtime_t ave_interval;
	hrtime_t ave_idle_time;
	uint32_t i, smpl_cnt;

	duration = cs_data->cs_idle_exit - cs_data->cs_idle_enter;
	scalehrtime(&duration);
	cs_data->cs_idle += duration;
	cs_data->cs_idle_enter = start;

	smpl_cnt = ++cs_data->cs_cnt;
	cs_data->cs_smpl_len = start - cs_data->cs_smpl_start;
	scalehrtime(&cs_data->cs_smpl_len);
	if (cs_data->cs_smpl_len > cpupm_cs_sample_interval) {
		cs_data->cs_smpl_idle = cs_data->cs_idle;
		cs_data->cs_idle = 0;
		cs_data->cs_smpl_idle_pct = ((100 * cs_data->cs_smpl_idle) /
		    cs_data->cs_smpl_len);

		cs_data->cs_smpl_start = start;
		cs_data->cs_cnt = 0;

		/*
		 * Strand level C-state policy
		 * The cpu_acpi_cstate_t *cstates array is not required to
		 * have an entry for both CPU_ACPI_C2 and CPU_ACPI_C3.
		 * There are cs_count entries in the cstates array.
		 * cs_data->cs_next_cstate contains the index of the next
		 * C-state this CPU should enter.
		 */
		ASSERT(cstates[0].cs_type == CPU_ACPI_C1);

		/*
		 * Will CPU be idle long enough to save power?
		 */
		ave_idle_time = (cs_data->cs_smpl_idle / smpl_cnt) / 1000;
		for (i = 1; i < cs_count; ++i) {
			if (ave_idle_time < (cstates[i].cs_latency *
			    cpupm_cs_idle_save_tunable)) {
				cs_count = i;
				DTRACE_PROBE2(cpupm__next__cstate, cpu_t *,
				    CPU, int, i);
			}
		}

		/*
		 * Wakeup often (even when non-idle time is very short)?
		 * Some producer/consumer type loads fall into this category.
		 */
		ave_interval = (cs_data->cs_smpl_len / smpl_cnt) / 1000;
		for (i = 1; i < cs_count; ++i) {
			if (ave_interval <= (cstates[i].cs_latency *
			    cpupm_cs_idle_cost_tunable)) {
				cs_count = i;
				DTRACE_PROBE2(cpupm__next__cstate, cpu_t *,
				    CPU, int, (CPU_MAX_CSTATES + i));
			}
		}

		/*
		 * Idle percent
		 */
		for (i = 1; i < cs_count; ++i) {
			switch (cstates[i].cs_type) {
			case CPU_ACPI_C2:
				if (cs_data->cs_smpl_idle_pct <
				    cpupm_C2_idle_pct_tunable) {
					cs_count = i;
					DTRACE_PROBE2(cpupm__next__cstate,
					    cpu_t *, CPU, int,
					    ((2 * CPU_MAX_CSTATES) + i));
				}
				break;

			case CPU_ACPI_C3:
				if (cs_data->cs_smpl_idle_pct <
				    cpupm_C3_idle_pct_tunable) {
					cs_count = i;
					DTRACE_PROBE2(cpupm__next__cstate,
					    cpu_t *, CPU, int,
					    ((2 * CPU_MAX_CSTATES) + i));
				}
				break;
			}
		}

		cs_data->cs_next_cstate = cs_count - 1;
	}

	return (cs_data->cs_next_cstate);
}
