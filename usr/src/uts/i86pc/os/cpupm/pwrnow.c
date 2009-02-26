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

#include <sys/x86_archext.h>
#include <sys/machsystm.h>
#include <sys/x_call.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include <sys/pwrnow.h>
#include <sys/cpu_acpi.h>
#include <sys/cpupm.h>
#include <sys/dtrace.h>
#include <sys/sdt.h>

static int pwrnow_init(cpu_t *);
static void pwrnow_fini(cpu_t *);
static void pwrnow_power(cpuset_t, uint32_t);

/*
 * Interfaces for modules implementing AMD's PowerNow!.
 */
cpupm_state_ops_t pwrnow_ops = {
	"PowerNow! Technology",
	pwrnow_init,
	pwrnow_fini,
	pwrnow_power
};

/*
 * Error returns
 */
#define	PWRNOW_RET_SUCCESS		0x00
#define	PWRNOW_RET_NO_PM		0x01
#define	PWRNOW_RET_UNSUP_STATE		0x02
#define	PWRNOW_RET_TRANS_INCOMPLETE	0x03

#define	PWRNOW_LATENCY_WAIT		10

/*
 * MSR registers for changing and reading processor power state.
 */
#define	PWRNOW_PERF_CTL_MSR		0xC0010062
#define	PWRNOW_PERF_STATUS_MSR		0xC0010063

#define	AMD_CPUID_PSTATE_HARDWARE	(1<<7)
#define	AMD_CPUID_TSC_CONSTANT		(1<<8)

/*
 * Debugging support
 */
#ifdef	DEBUG
volatile int pwrnow_debug = 0;
#define	PWRNOW_DEBUG(arglist) if (pwrnow_debug) printf arglist;
#else
#define	PWRNOW_DEBUG(arglist)
#endif

/*
 * Write the ctrl register.
 */
static void
write_ctrl(cpu_acpi_handle_t handle, uint32_t ctrl)
{
	cpu_acpi_pct_t *pct_ctrl;
	uint64_t reg;

	pct_ctrl = CPU_ACPI_PCT_CTRL(handle);

	switch (pct_ctrl->cr_addrspace_id) {
	case ACPI_ADR_SPACE_FIXED_HARDWARE:
		reg = ctrl;
		wrmsr(PWRNOW_PERF_CTL_MSR, reg);
		break;

	default:
		DTRACE_PROBE1(pwrnow_ctrl_unsupported_type, uint8_t,
		    pct_ctrl->cr_addrspace_id);
		return;
	}

	DTRACE_PROBE1(pwrnow_ctrl_write, uint32_t, ctrl);
}

/*
 * Transition the current processor to the requested state.
 */
static void
pwrnow_pstate_transition(uint32_t req_state)
{
	cpupm_mach_state_t *mach_state =
	    (cpupm_mach_state_t *)CPU->cpu_m.mcpu_pm_mach_state;
	cpu_acpi_handle_t handle = mach_state->ms_acpi_handle;
	cpu_acpi_pstate_t *req_pstate;
	uint32_t ctrl;

	req_pstate = (cpu_acpi_pstate_t *)CPU_ACPI_PSTATES(handle);
	req_pstate += req_state;

	DTRACE_PROBE1(pwrnow_transition_freq, uint32_t,
	    CPU_ACPI_FREQ(req_pstate));

	/*
	 * Initiate the processor p-state change.
	 */
	ctrl = CPU_ACPI_PSTATE_CTRL(req_pstate);
	write_ctrl(handle, ctrl);

	mach_state->ms_pstate.cma_state.pstate = req_state;
	cpu_set_curr_clock((uint64_t)CPU_ACPI_FREQ(req_pstate) * 1000000);
}

static void
pwrnow_power(cpuset_t set, uint32_t req_state)
{
	/*
	 * If thread is already running on target CPU then just
	 * make the transition request. Otherwise, we'll need to
	 * make a cross-call.
	 */
	kpreempt_disable();
	if (CPU_IN_SET(set, CPU->cpu_id)) {
		pwrnow_pstate_transition(req_state);
		CPUSET_DEL(set, CPU->cpu_id);
	}
	if (!CPUSET_ISNULL(set)) {
		xc_call((xc_arg_t)req_state, NULL, NULL, X_CALL_HIPRI,
		    set, (xc_func_t)pwrnow_pstate_transition);
	}
	kpreempt_enable();
}

/*
 * Validate that this processor supports PowerNow! and if so,
 * get the P-state data from ACPI and cache it.
 */
static int
pwrnow_init(cpu_t *cp)
{
	cpupm_mach_state_t *mach_state =
	    (cpupm_mach_state_t *)cp->cpu_m.mcpu_pm_mach_state;
	cpu_acpi_handle_t handle = mach_state->ms_acpi_handle;
	cpu_acpi_pct_t *pct_stat;

	PWRNOW_DEBUG(("pwrnow_init: processor %d\n", cp->cpu_id));

	/*
	 * Cache the P-state specific ACPI data.
	 */
	if (cpu_acpi_cache_pstate_data(handle) != 0) {
		PWRNOW_DEBUG(("Failed to cache ACPI data\n"));
		pwrnow_fini(cp);
		return (PWRNOW_RET_NO_PM);
	}

	pct_stat = CPU_ACPI_PCT_STATUS(handle);
	switch (pct_stat->cr_addrspace_id) {
	case ACPI_ADR_SPACE_FIXED_HARDWARE:
		PWRNOW_DEBUG(("Transitions will use fixed hardware\n"));
		break;
	default:
		cmn_err(CE_WARN, "!_PCT configured for unsupported "
		    "addrspace = %d.", pct_stat->cr_addrspace_id);
		cmn_err(CE_NOTE, "!CPU power management will not function.");
		pwrnow_fini(cp);
		return (PWRNOW_RET_NO_PM);
	}

	cpupm_alloc_domains(cp, CPUPM_P_STATES);

	PWRNOW_DEBUG(("Processor %d succeeded.\n", cp->cpu_id))
	return (PWRNOW_RET_SUCCESS);
}

/*
 * Free resources allocated by pwrnow_init().
 */
static void
pwrnow_fini(cpu_t *cp)
{
	cpupm_mach_state_t *mach_state =
	    (cpupm_mach_state_t *)(cp->cpu_m.mcpu_pm_mach_state);
	cpu_acpi_handle_t handle = mach_state->ms_acpi_handle;

	cpupm_free_domains(&cpupm_pstate_domains);
	cpu_acpi_free_pstate_data(handle);
}

boolean_t
pwrnow_supported()
{
	struct cpuid_regs cpu_regs;

	/* Required features */
	if (!(x86_feature & X86_CPUID) ||
	    !(x86_feature & X86_MSR)) {
		PWRNOW_DEBUG(("No CPUID or MSR support."));
		return (B_FALSE);
	}

	/*
	 * Get the Advanced Power Management Information.
	 */
	cpu_regs.cp_eax = 0x80000007;
	(void) __cpuid_insn(&cpu_regs);

	/*
	 * We currently only support CPU power management of
	 * processors that are P-state TSC invariant
	 */
	if (!(cpu_regs.cp_edx & AMD_CPUID_TSC_CONSTANT)) {
		PWRNOW_DEBUG(("No support for CPUs that are not P-state "
		    "TSC invariant.\n"));
		return (B_FALSE);
	}

	/*
	 * We only support the "Fire and Forget" style of PowerNow! (i.e.,
	 * single MSR write to change speed).
	 */
	if (!(cpu_regs.cp_edx & AMD_CPUID_PSTATE_HARDWARE)) {
		PWRNOW_DEBUG(("Hardware P-State control is not supported.\n"));
		return (B_FALSE);
	}
	return (B_TRUE);
}
