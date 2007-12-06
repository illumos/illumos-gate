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

typedef struct pwrnow_state {
	uint32_t pn_state;
} pwrnow_state_t;

/*
 * Read the status register.
 */
static int
read_status(cpu_acpi_handle_t handle, uint32_t *stat)
{
	cpu_acpi_pct_t *pct_stat;
	uint64_t reg;
	int ret = 0;

	pct_stat = CPU_ACPI_PCT_STATUS(handle);

	switch (pct_stat->pc_addrspace_id) {
	case ACPI_ADR_SPACE_FIXED_HARDWARE:
		reg = rdmsr(PWRNOW_PERF_STATUS_MSR);
		*stat = reg & 0xFFFFFFFF;
		ret = 0;
		break;

	default:
		DTRACE_PROBE1(pwrnow_status_unsupported_type, uint8_t,
		    pct_stat->pc_addrspace_id);
		return (-1);
	}

	DTRACE_PROBE1(pwrnow_status_read, uint32_t, *stat);
	DTRACE_PROBE1(pwrnow_status_read_err, int, ret);

	return (ret);
}

/*
 * Write the ctrl register.
 */
static int
write_ctrl(cpu_acpi_handle_t handle, uint32_t ctrl)
{
	cpu_acpi_pct_t *pct_ctrl;
	uint64_t reg;
	int ret = 0;

	pct_ctrl = CPU_ACPI_PCT_CTRL(handle);

	switch (pct_ctrl->pc_addrspace_id) {
	case ACPI_ADR_SPACE_FIXED_HARDWARE:
		reg = ctrl;
		wrmsr(PWRNOW_PERF_CTL_MSR, reg);
		ret = 0;
		break;

	default:
		DTRACE_PROBE1(pwrnow_ctrl_unsupported_type, uint8_t,
		    pct_ctrl->pc_addrspace_id);
		return (-1);
	}

	DTRACE_PROBE1(pwrnow_ctrl_write, uint32_t, ctrl);
	DTRACE_PROBE1(pwrnow_ctrl_write_err, int, ret);

	return (ret);
}

/*
 * Transition the current processor to the requested state.
 */
void
pwrnow_pstate_transition(int *ret, cpudrv_devstate_t *cpudsp,
    uint32_t req_state)
{
	pwrnow_state_t *pwrnow_state = cpudsp->module_state;
	cpu_acpi_handle_t handle = cpudsp->acpi_handle;
	cpu_acpi_pstate_t *req_pstate;
	uint32_t ctrl;
	uint32_t stat;
	cpu_t *cp;
	int i;

	req_pstate = CPU_ACPI_PSTATE(handle, req_state);
	DTRACE_PROBE1(pwrnow_transition_freq, uint32_t,
	    CPU_ACPI_FREQ(req_pstate));

	/*
	 * Initiate the processor p-state change.
	 */
	ctrl = CPU_ACPI_CTRL(req_pstate);
	if (write_ctrl(handle, ctrl) != 0) {
		*ret = PWRNOW_RET_UNSUP_STATE;
		return;
	}

	/* Wait until switch is complete, but bound the loop just in case. */
	for (i = CPU_ACPI_TRANSLAT(req_pstate) * 2; i >= 0;
	    i -= PWRNOW_LATENCY_WAIT) {
		if (read_status(handle, &stat) == 0 &&
		    CPU_ACPI_STAT(req_pstate) == stat)
				break;
		drv_usecwait(PWRNOW_LATENCY_WAIT);
	}

	if (CPU_ACPI_STAT(req_pstate) != stat) {
		DTRACE_PROBE(pwrnow_transition_incomplete);
		*ret = PWRNOW_RET_TRANS_INCOMPLETE;
		return;
	}

	pwrnow_state->pn_state = req_state;
	cp = cpu[CPU->cpu_id];
	cp->cpu_curr_clock = ((uint64_t)
	    CPU_ACPI_FREQ(req_pstate) * 1000000);

	*ret = PWRNOW_RET_SUCCESS;
}

int
pwrnow_power(cpudrv_devstate_t *cpudsp, uint32_t req_state)
{
	cpuset_t cpus;
	int ret;

	CPUSET_ONLY(cpus, cpudsp->cpu_id);

	kpreempt_disable();
	xc_call((xc_arg_t)&ret, (xc_arg_t)cpudsp, (xc_arg_t)req_state,
	    X_CALL_HIPRI, cpus, (xc_func_t)pwrnow_pstate_transition);
	kpreempt_enable();

	return (ret);
}

/*
 * Validate that this processor supports PowerNow! and if so,
 * get the P-state data from ACPI and cache it.
 */
int
pwrnow_init(cpudrv_devstate_t *cpudsp)
{
	pwrnow_state_t *pwrnow_state;
	cpu_acpi_handle_t handle;
	cpu_acpi_pct_t *pct_stat;
	uint_t family;
	struct cpuid_regs cpu_regs;
	cpu_t *cp;
	int domain;

	PWRNOW_DEBUG(("pwrnow_init: instance %d\n",
	    ddi_get_instance(cpudsp->dip)));

	/* AMD w/ CPUID support and rdmsr/wrmsr? */
	if (x86_vendor != X86_VENDOR_AMD ||
	    !(x86_feature & X86_CPUID) ||
	    !(x86_feature & X86_MSR)) {
		PWRNOW_DEBUG(("Either not AMD or feature not supported.\n"));
		return (PWRNOW_RET_NO_PM);
	}

	/*
	 * Get the Advanced Power Management Information.
	 */
	cpu_regs.cp_eax = 0x80000007;
	(void) __cpuid_insn(&cpu_regs);
	if (!(cpu_regs.cp_edx & AMD_CPUID_TSC_CONSTANT)) {
		PWRNOW_DEBUG(("No support for CPUs that are not P-state "
		    "TSC invariant.\n"));
		return (PWRNOW_RET_NO_PM);
	}
	if (!(cpu_regs.cp_edx & AMD_CPUID_PSTATE_HARDWARE)) {
		PWRNOW_DEBUG(("Hardware P-State control is not supported.\n"));
		return (PWRNOW_RET_NO_PM);
	}

	/*
	 * Just greyhound at this point.
	 */
	family = cpuid_getfamily(CPU);
	if (family != 0x10) {
		PWRNOW_DEBUG(("CPUPM currently only supported for 0x10.\n"));
		return (PWRNOW_RET_NO_PM);
	}

	/*
	 * PowerNow! requires ACPI support. Get a handle
	 * to the correct processor object for this dip.
	 */
	handle = cpudsp->acpi_handle = cpu_acpi_init(cpudsp->dip);
	if (handle == NULL) {
		cmn_err(CE_WARN, "!pwrnow_init: instance %d: "
		    "unable to get ACPI handle",
		    ddi_get_instance(cpudsp->dip));
		cmn_err(CE_NOTE, "!CPU power management will not function.");
		return (PWRNOW_RET_NO_PM);
	}

	if (cpu_acpi_cache_data(handle) != 0) {
		PWRNOW_DEBUG(("Failed to cache ACPI data\n"));
		cpu_acpi_fini(handle);
		return (PWRNOW_RET_NO_PM);
	}

	pct_stat = CPU_ACPI_PCT_STATUS(handle);
	switch (pct_stat->pc_addrspace_id) {
	case ACPI_ADR_SPACE_FIXED_HARDWARE:
		PWRNOW_DEBUG(("Transitions will use fixed hardware\n"));
		break;
	default:
		cmn_err(CE_WARN, "!_PCT configured for unsupported "
		    "addrspace = %d.", pct_stat->pc_addrspace_id);
		cmn_err(CE_NOTE, "!CPU power management will not function.");
		cpu_acpi_fini(handle);
		return (PWRNOW_RET_NO_PM);
	}

	if (CPU_ACPI_IS_OBJ_CACHED(handle, CPU_ACPI_PSD_CACHED))
		domain = CPU_ACPI_PSD(handle).pd_domain;
	else {
		cp = cpu[CPU->cpu_id];
		domain = cpuid_get_chipid(cp);
	}
	cpupm_add_cpu2dependency(cpudsp->dip, domain);

	pwrnow_state = kmem_zalloc(sizeof (pwrnow_state_t), KM_SLEEP);
	pwrnow_state->pn_state = NULL;
	cpudsp->module_state = pwrnow_state;

	PWRNOW_DEBUG(("Instance %d succeeded.\n",
	    ddi_get_instance(cpudsp->dip)));
	return (PWRNOW_RET_SUCCESS);
}

/*
 * Free resources allocated by pwrnow_init().
 */
void
pwrnow_fini(cpudrv_devstate_t *cpudsp)
{
	cpu_acpi_fini(cpudsp->acpi_handle);
	kmem_free(cpudsp->module_state, sizeof (pwrnow_state_t));
}
