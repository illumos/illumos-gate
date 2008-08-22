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

#include <sys/x86_archext.h>
#include <sys/machsystm.h>
#include <sys/x_call.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include <sys/cpudrv_mach.h>
#include <sys/speedstep.h>
#include <sys/cpu_acpi.h>
#include <sys/cpupm.h>
#include <sys/dtrace.h>
#include <sys/sdt.h>

static int speedstep_init(cpudrv_devstate_t *);
static void speedstep_fini(cpudrv_devstate_t *);
static int speedstep_power(cpudrv_devstate_t *, uint32_t);

/*
 * Interfaces for modules implementing Intel's Enhanced SpeedStep.
 */
cpudrv_pstate_ops_t speedstep_ops = {
	"Enhanced SpeedStep Technology",
	speedstep_init,
	speedstep_fini,
	speedstep_power
};

/*
 * Error returns
 */
#define	ESS_RET_SUCCESS		0x00
#define	ESS_RET_NO_PM		0x01
#define	ESS_RET_UNSUP_STATE	0x02

/*
 * Intel docs indicate that maximum latency of P-state changes should
 * be on the order of 10mS. When waiting, wait in 100uS increments.
 */
#define	ESS_MAX_LATENCY_MICROSECS	10000
#define	ESS_LATENCY_WAIT		100

/*
 * The SpeedStep related Processor Driver Capabilities (_PDC).
 * See Intel Processor Vendor-Specific ACPI Interface Specification
 * for details.
 */
#define	ESS_PDC_REVISION		0x1
#define	ESS_PDC_PS_MSR			(1<<0)
#define	ESS_PDC_IO_BEFORE_HALT		(1<<1)
#define	ESS_PDC_MP			(1<<3)
#define	ESS_PDC_PSD			(1<<5)

/*
 * MSR registers for changing and reading processor power state.
 */
#define	IA32_PERF_STAT_MSR		0x198
#define	IA32_PERF_CTL_MSR		0x199

#define	IA32_CPUID_TSC_CONSTANT		0xF30
#define	IA32_MISC_ENABLE_MSR		0x1A0
#define	IA32_MISC_ENABLE_EST		(1<<16)
#define	IA32_MISC_ENABLE_CXE		(1<<25)
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
 * Note that SpeedStep support requires the following _PDC bits be
 * enabled so that ACPI returns the proper objects. The requirement
 * that ESS_PDC_IO_BEFORE_HALT be enabled probably seems strange.
 * Unfortunately, the _PDC bit for this feature has been historically
 * misassociated with SpeedStep support and some BIOS implementations
 * erroneously check this bit when evaluating _PSS methods. Enabling
 * this bit is our only option as the likelihood of a BIOS fix on all
 * affected platforms is not very good.
 */
uint32_t ess_pdccap = ESS_PDC_PS_MSR | ESS_PDC_IO_BEFORE_HALT |
    ESS_PDC_MP | ESS_PDC_PSD;

/*
 * Read the status register. How it is read, depends upon the _PCT
 * APCI object value.
 */
static int
read_status(cpu_acpi_handle_t handle, uint32_t *stat)
{
	cpu_acpi_pct_t *pct_stat;
	uint64_t reg;
	int ret = 0;

	pct_stat = CPU_ACPI_PCT_STATUS(handle);

	switch (pct_stat->cr_addrspace_id) {
	case ACPI_ADR_SPACE_FIXED_HARDWARE:
		reg = rdmsr(IA32_PERF_STAT_MSR);
		*stat = reg & 0x1E;
		ret = 0;
		break;

	case ACPI_ADR_SPACE_SYSTEM_IO:
		ret = cpu_acpi_read_port(pct_stat->cr_address, stat,
		    pct_stat->cr_width);
		break;

	default:
		DTRACE_PROBE1(ess_status_unsupported_type, uint8_t,
		    pct_stat->cr_addrspace_id);
		return (-1);
	}

	DTRACE_PROBE1(ess_status_read, uint32_t, *stat);
	DTRACE_PROBE1(ess_status_read_err, int, ret);

	return (ret);
}

/*
 * Write the ctrl register. How it is written, depends upon the _PCT
 * APCI object value.
 */
static int
write_ctrl(cpu_acpi_handle_t handle, uint32_t ctrl)
{
	cpu_acpi_pct_t *pct_ctrl;
	uint64_t reg;
	int ret = 0;

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
		ret = 0;
		break;

	case ACPI_ADR_SPACE_SYSTEM_IO:
		ret = cpu_acpi_write_port(pct_ctrl->cr_address, ctrl,
		    pct_ctrl->cr_width);
		break;

	default:
		DTRACE_PROBE1(ess_ctrl_unsupported_type, uint8_t,
		    pct_ctrl->cr_addrspace_id);
		return (-1);
	}

	DTRACE_PROBE1(ess_ctrl_write, uint32_t, ctrl);
	DTRACE_PROBE1(ess_ctrl_write_err, int, ret);

	return (ret);
}

/*
 * Transition the current processor to the requested state.
 */
void
speedstep_pstate_transition(int *ret, cpudrv_devstate_t *cpudsp,
    uint32_t req_state)
{
	cpudrv_mach_state_t *mach_state = cpudsp->mach_state;
	cpu_acpi_handle_t handle = mach_state->acpi_handle;
	cpu_acpi_pstate_t *req_pstate;
	uint32_t ctrl;
	uint32_t stat;
	int i;

	req_pstate = (cpu_acpi_pstate_t *)CPU_ACPI_PSTATES(handle);
	req_pstate += req_state;
	DTRACE_PROBE1(ess_transition, uint32_t, CPU_ACPI_FREQ(req_pstate));

	/*
	 * Initiate the processor p-state change.
	 */
	ctrl = CPU_ACPI_PSTATE_CTRL(req_pstate);
	if (write_ctrl(handle, ctrl) != 0) {
		*ret = ESS_RET_UNSUP_STATE;
		return;
	}

	/* Wait until switch is complete, but bound the loop just in case. */
	for (i = CPU_ACPI_PSTATE_TRANSLAT(req_pstate) * 2; i >= 0;
	    i -= ESS_LATENCY_WAIT) {
		if (read_status(handle, &stat) == 0 &&
		    CPU_ACPI_PSTATE_STAT(req_pstate) == stat)
			break;
		drv_usecwait(ESS_LATENCY_WAIT);
	}
	if (i >= ESS_MAX_LATENCY_MICROSECS) {
		DTRACE_PROBE(ess_transition_incomplete);
	}

	mach_state->pstate = req_state;
	CPU->cpu_curr_clock =
	    (((uint64_t)CPU_ACPI_FREQ(req_pstate) * 1000000));
	*ret = ESS_RET_SUCCESS;
}

static int
speedstep_power(cpudrv_devstate_t *cpudsp, uint32_t req_state)
{
	cpuset_t cpus;
	int ret;

	/*
	 * If thread is already running on target CPU then just
	 * make the transition request. Otherwise, we'll need to
	 * make a cross-call.
	 */
	kpreempt_disable();
	if (cpudsp->cpu_id == CPU->cpu_id) {
		speedstep_pstate_transition(&ret, cpudsp, req_state);
	} else {
		CPUSET_ONLY(cpus, cpudsp->cpu_id);
		xc_call((xc_arg_t)&ret, (xc_arg_t)cpudsp, (xc_arg_t)req_state,
		    X_CALL_HIPRI, cpus, (xc_func_t)speedstep_pstate_transition);
	}
	kpreempt_enable();

	return (ret);
}

/*
 * Validate that this processor supports Speedstep and if so,
 * get the P-state data from ACPI and cache it.
 */
static int
speedstep_init(cpudrv_devstate_t *cpudsp)
{
	cpudrv_mach_state_t *mach_state = cpudsp->mach_state;
	cpu_acpi_handle_t handle = mach_state->acpi_handle;
	cpu_acpi_pct_t *pct_stat;
	cpu_t *cp;
	int dependency;

	ESSDEBUG(("speedstep_init: instance %d\n",
	    ddi_get_instance(cpudsp->dip)));

	/*
	 * Cache the P-state specific ACPI data.
	 */
	if (cpu_acpi_cache_pstate_data(handle) != 0) {
		ESSDEBUG(("Failed to cache ACPI data\n"));
		speedstep_fini(cpudsp);
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
		speedstep_fini(cpudsp);
		return (ESS_RET_NO_PM);
	}

	if (CPU_ACPI_IS_OBJ_CACHED(handle, CPU_ACPI_PSD_CACHED))
		dependency = CPU_ACPI_PSD(handle).sd_domain;
	else {
		mutex_enter(&cpu_lock);
		cp = cpu[CPU->cpu_id];
		dependency = cpuid_get_chipid(cp);
		mutex_exit(&cpu_lock);
	}
	cpupm_add_cpu2dependency(cpudsp->dip, dependency);

	ESSDEBUG(("Instance %d succeeded.\n", ddi_get_instance(cpudsp->dip)));
	return (ESS_RET_SUCCESS);
}

/*
 * Free resources allocated by speedstep_init().
 */
static void
speedstep_fini(cpudrv_devstate_t *cpudsp)
{
	cpudrv_mach_state_t *mach_state = cpudsp->mach_state;
	cpu_acpi_handle_t handle = mach_state->acpi_handle;

	cpupm_free_cpu_dependencies();
	cpu_acpi_free_pstate_data(handle);
}

boolean_t
speedstep_supported(uint_t family, uint_t model)
{
	struct cpuid_regs cpu_regs;
	uint64_t reg;

	/* Required features */
	if (!(x86_feature & X86_CPUID) ||
	    !(x86_feature & X86_MSR)) {
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

	/*
	 * If Enhanced SpeedStep has not been enabled on the system,
	 * then we probably should not override the BIOS setting.
	 */
	reg = rdmsr(IA32_MISC_ENABLE_MSR);
	if (! (reg & IA32_MISC_ENABLE_EST)) {
		cmn_err(CE_NOTE, "!Enhanced Intel SpeedStep not enabled.");
		cmn_err(CE_NOTE, "!CPU power management will not function.");
		return (B_FALSE);
	}

	return (B_TRUE);
}
