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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright (c) 2009,  Intel Corporation.
 * All Rights Reserved.
 */

#include <sys/x86_archext.h>
#include <sys/machsystm.h>
#include <sys/archsystm.h>
#include <sys/x_call.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include <sys/speedstep.h>
#include <sys/cpu_acpi.h>
#include <sys/cpupm.h>
#include <sys/dtrace.h>
#include <sys/sdt.h>

static int speedstep_init(cpu_t *);
static void speedstep_fini(cpu_t *);
static void speedstep_power(cpuset_t, uint32_t);
static void speedstep_stop(cpu_t *);
static boolean_t speedstep_turbo_supported(void);

/*
 * Interfaces for modules implementing Intel's Enhanced SpeedStep.
 */
cpupm_state_ops_t speedstep_ops = {
	"Enhanced SpeedStep Technology",
	speedstep_init,
	speedstep_fini,
	speedstep_power,
	speedstep_stop
};

/*
 * Error returns
 */
#define	ESS_RET_SUCCESS		0x00
#define	ESS_RET_NO_PM		0x01
#define	ESS_RET_UNSUP_STATE	0x02

/*
 * MSR registers for changing and reading processor power state.
 */
#define	IA32_PERF_STAT_MSR		0x198
#define	IA32_PERF_CTL_MSR		0x199

#define	IA32_CPUID_TSC_CONSTANT		0xF30
#define	IA32_MISC_ENABLE_MSR		0x1A0
#define	IA32_MISC_ENABLE_EST		(1<<16)
#define	IA32_MISC_ENABLE_CXE		(1<<25)

#define	CPUID_TURBO_SUPPORT		(1 << 1)

/*
 * Debugging support
 */
#ifdef	DEBUG
volatile int ess_debug = 0;
#define	ESSDEBUG(arglist) if (ess_debug) printf arglist;
#else
#define	ESSDEBUG(arglist)
#endif

/*
 * Write the ctrl register. How it is written, depends upon the _PCT
 * APCI object value.
 */
static void
write_ctrl(cpu_acpi_handle_t handle, uint32_t ctrl)
{
	cpu_acpi_pct_t *pct_ctrl;
	uint64_t reg;

	pct_ctrl = CPU_ACPI_PCT_CTRL(handle);

	switch (pct_ctrl->cr_addrspace_id) {
	case ACPI_ADR_SPACE_FIXED_HARDWARE:
		/*
		 * Read current power state because reserved bits must be
		 * preserved, compose new value, and write it.
		 */
		reg = rdmsr(IA32_PERF_CTL_MSR);
		reg &= ~((uint64_t)0xFFFF);
		reg |= ctrl;
		wrmsr(IA32_PERF_CTL_MSR, reg);
		break;

	case ACPI_ADR_SPACE_SYSTEM_IO:
		(void) cpu_acpi_write_port(pct_ctrl->cr_address, ctrl,
		    pct_ctrl->cr_width);
		break;

	default:
		DTRACE_PROBE1(ess_ctrl_unsupported_type, uint8_t,
		    pct_ctrl->cr_addrspace_id);
		return;
	}

	DTRACE_PROBE1(ess_ctrl_write, uint32_t, ctrl);
}

/*
 * Transition the current processor to the requested state.
 */
void
speedstep_pstate_transition(uint32_t req_state)
{
	cpupm_mach_state_t *mach_state =
	    (cpupm_mach_state_t *)CPU->cpu_m.mcpu_pm_mach_state;
	cpu_acpi_handle_t handle = mach_state->ms_acpi_handle;
	cpu_acpi_pstate_t *req_pstate;
	uint32_t ctrl;

	req_pstate = (cpu_acpi_pstate_t *)CPU_ACPI_PSTATES(handle);
	req_pstate += req_state;

	DTRACE_PROBE1(ess_transition, uint32_t, CPU_ACPI_FREQ(req_pstate));

	/*
	 * Initiate the processor p-state change.
	 */
	ctrl = CPU_ACPI_PSTATE_CTRL(req_pstate);
	write_ctrl(handle, ctrl);

	if (mach_state->ms_turbo != NULL)
		cpupm_record_turbo_info(mach_state->ms_turbo,
		    mach_state->ms_pstate.cma_state.pstate, req_state);

	mach_state->ms_pstate.cma_state.pstate = req_state;
	cpu_set_curr_clock(((uint64_t)CPU_ACPI_FREQ(req_pstate) * 1000000));
}

static void
speedstep_power(cpuset_t set, uint32_t req_state)
{
	/*
	 * If thread is already running on target CPU then just
	 * make the transition request. Otherwise, we'll need to
	 * make a cross-call.
	 */
	kpreempt_disable();
	if (CPU_IN_SET(set, CPU->cpu_id)) {
		speedstep_pstate_transition(req_state);
		CPUSET_DEL(set, CPU->cpu_id);
	}
	if (!CPUSET_ISNULL(set)) {
		xc_call((xc_arg_t)req_state, NULL, NULL, CPUSET2BV(set),
		    (xc_func_t)speedstep_pstate_transition);
	}
	kpreempt_enable();
}

/*
 * Validate that this processor supports Speedstep and if so,
 * get the P-state data from ACPI and cache it.
 */
static int
speedstep_init(cpu_t *cp)
{
	cpupm_mach_state_t *mach_state =
	    (cpupm_mach_state_t *)cp->cpu_m.mcpu_pm_mach_state;
	cpu_acpi_handle_t handle = mach_state->ms_acpi_handle;
	cpu_acpi_pct_t *pct_stat;
	static int logged = 0;

	ESSDEBUG(("speedstep_init: processor %d\n", cp->cpu_id));

	/*
	 * Cache the P-state specific ACPI data.
	 */
	if (cpu_acpi_cache_pstate_data(handle) != 0) {
		if (!logged) {
			cmn_err(CE_NOTE, "!SpeedStep support is being "
			    "disabled due to errors parsing ACPI P-state "
			    "objects exported by BIOS.");
			logged = 1;
		}
		speedstep_fini(cp);
		return (ESS_RET_NO_PM);
	}

	pct_stat = CPU_ACPI_PCT_STATUS(handle);
	switch (pct_stat->cr_addrspace_id) {
	case ACPI_ADR_SPACE_FIXED_HARDWARE:
		ESSDEBUG(("Transitions will use fixed hardware\n"));
		break;
	case ACPI_ADR_SPACE_SYSTEM_IO:
		ESSDEBUG(("Transitions will use system IO\n"));
		break;
	default:
		cmn_err(CE_WARN, "!_PCT conifgured for unsupported "
		    "addrspace = %d.", pct_stat->cr_addrspace_id);
		cmn_err(CE_NOTE, "!CPU power management will not function.");
		speedstep_fini(cp);
		return (ESS_RET_NO_PM);
	}

	cpupm_alloc_domains(cp, CPUPM_P_STATES);

	if (speedstep_turbo_supported())
		mach_state->ms_turbo = cpupm_turbo_init(cp);

	ESSDEBUG(("Processor %d succeeded.\n", cp->cpu_id))
	return (ESS_RET_SUCCESS);
}

/*
 * Free resources allocated by speedstep_init().
 */
static void
speedstep_fini(cpu_t *cp)
{
	cpupm_mach_state_t *mach_state =
	    (cpupm_mach_state_t *)(cp->cpu_m.mcpu_pm_mach_state);
	cpu_acpi_handle_t handle = mach_state->ms_acpi_handle;

	cpupm_free_domains(&cpupm_pstate_domains);
	cpu_acpi_free_pstate_data(handle);

	if (mach_state->ms_turbo != NULL)
		cpupm_turbo_fini(mach_state->ms_turbo);
	mach_state->ms_turbo = NULL;
}

static void
speedstep_stop(cpu_t *cp)
{
	cpupm_mach_state_t *mach_state =
	    (cpupm_mach_state_t *)(cp->cpu_m.mcpu_pm_mach_state);
	cpu_acpi_handle_t handle = mach_state->ms_acpi_handle;

	cpupm_remove_domains(cp, CPUPM_P_STATES, &cpupm_pstate_domains);
	cpu_acpi_free_pstate_data(handle);

	if (mach_state->ms_turbo != NULL)
		cpupm_turbo_fini(mach_state->ms_turbo);
	mach_state->ms_turbo = NULL;
}

boolean_t
speedstep_supported(uint_t family, uint_t model)
{
	struct cpuid_regs cpu_regs;

	/* Required features */
	if (!is_x86_feature(x86_featureset, X86FSET_CPUID) ||
	    !is_x86_feature(x86_featureset, X86FSET_MSR)) {
		return (B_FALSE);
	}

	/*
	 * We only support family/model combinations which
	 * are P-state TSC invariant.
	 */
	if (!((family == 0xf && model >= 0x3) ||
	    (family == 0x6 && model >= 0xe))) {
		return (B_FALSE);
	}

	/*
	 * Enhanced SpeedStep supported?
	 */
	cpu_regs.cp_eax = 0x1;
	(void) __cpuid_insn(&cpu_regs);
	if (!(cpu_regs.cp_ecx & CPUID_INTC_ECX_EST)) {
		return (B_FALSE);
	}

	return (B_TRUE);
}

boolean_t
speedstep_turbo_supported(void)
{
	struct cpuid_regs cpu_regs;

	/* Required features */
	if (!is_x86_feature(x86_featureset, X86FSET_CPUID) ||
	    !is_x86_feature(x86_featureset, X86FSET_MSR)) {
		return (B_FALSE);
	}

	/*
	 * turbo mode supported?
	 */
	cpu_regs.cp_eax = 0x6;
	(void) __cpuid_insn(&cpu_regs);
	if (!(cpu_regs.cp_eax & CPUID_TURBO_SUPPORT)) {
		return (B_FALSE);
	}

	return (B_TRUE);
}
