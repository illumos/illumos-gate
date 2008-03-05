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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/x86_archext.h>
#include <sys/machsystm.h>
#include <sys/x_call.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include <sys/speedstep.h>
#include <sys/cpu_acpi.h>
#include <sys/cpupm.h>
#include <sys/dtrace.h>
#include <sys/sdt.h>

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

typedef struct speedstep_state {
	uint32_t ss_state;
} speedstep_state_t;

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

	switch (pct_stat->pc_addrspace_id) {
	case ACPI_ADR_SPACE_FIXED_HARDWARE:
		reg = rdmsr(IA32_PERF_STAT_MSR);
		*stat = reg & 0xFFFF;
		ret = 0;
		break;

	case ACPI_ADR_SPACE_SYSTEM_IO:
		ret = cpu_acpi_read_port(pct_stat->pc_address, stat,
		    pct_stat->pc_width);
		break;

	default:
		DTRACE_PROBE1(ess_status_unsupported_type, uint8_t,
		    pct_stat->pc_addrspace_id);
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

	switch (pct_ctrl->pc_addrspace_id) {
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
		ret = cpu_acpi_write_port(pct_ctrl->pc_address, ctrl,
		    pct_ctrl->pc_width);
		break;

	default:
		DTRACE_PROBE1(ess_ctrl_unsupported_type, uint8_t,
		    pct_ctrl->pc_addrspace_id);
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
	speedstep_state_t *speedstep_state = cpudsp->module_state;
	cpu_acpi_handle_t handle = cpudsp->acpi_handle;
	cpu_acpi_pstate_t *req_pstate;
	uint32_t ctrl;
	uint32_t stat;
	int i;

	req_pstate = CPU_ACPI_PSTATE(handle, req_state);
	DTRACE_PROBE1(ess_transition, uint32_t, CPU_ACPI_FREQ(req_pstate));

	/*
	 * Initiate the processor p-state change.
	 */
	ctrl = CPU_ACPI_CTRL(req_pstate);
	if (write_ctrl(handle, ctrl) != 0) {
		*ret = ESS_RET_UNSUP_STATE;
		return;
	}

	/* Wait until switch is complete, but bound the loop just in case. */
	for (i = 0; i < ESS_MAX_LATENCY_MICROSECS; i += ESS_LATENCY_WAIT) {
		if (read_status(handle, &stat) == 0 &&
		    CPU_ACPI_STAT(req_pstate) == stat)
			break;
		drv_usecwait(ESS_LATENCY_WAIT);
	}
	if (i >= ESS_MAX_LATENCY_MICROSECS) {
		DTRACE_PROBE(ess_transition_incomplete);
	}

	speedstep_state->ss_state = req_state;
	CPU->cpu_curr_clock =
	    (((uint64_t)CPU_ACPI_FREQ(req_pstate) * 1000000));
	*ret = ESS_RET_SUCCESS;
}

int
speedstep_power(cpudrv_devstate_t *cpudsp, uint32_t req_state)
{
	cpuset_t cpus;
	int ret;

	CPUSET_ONLY(cpus, cpudsp->cpu_id);

	kpreempt_disable();
	xc_call((xc_arg_t)&ret, (xc_arg_t)cpudsp, (xc_arg_t)req_state,
	    X_CALL_HIPRI, cpus, (xc_func_t)speedstep_pstate_transition);
	kpreempt_enable();

	return (ret);
}

/*
 * Validate that this processor supports Speedstep and if so,
 * get the P-state data from ACPI and cache it.
 */
int
speedstep_init(cpudrv_devstate_t *cpudsp)
{
	speedstep_state_t *speedstep_state;
	cpu_acpi_handle_t handle;
	cpu_acpi_pct_t *pct_stat;
	uint64_t reg;
	uint_t family;
	uint_t model;
	struct cpuid_regs cpu_regs;
	cpu_t *cp;
	int dependency;

	ESSDEBUG(("speedstep_init: instance %d\n",
	    ddi_get_instance(cpudsp->dip)));

	/* Intel w/ CPUID support and rdmsr/wrmsr? */
	if (x86_vendor != X86_VENDOR_Intel ||
	    !(x86_feature & X86_CPUID) ||
	    !(x86_feature & X86_MSR)) {
		ESSDEBUG(("Either not Intel or feature not supported.\n"));
		return (ESS_RET_NO_PM);
	}

	/*
	 * Enhanced Speedstep supported?
	 */
	cpu_regs.cp_eax = 0x1;
	(void) __cpuid_insn(&cpu_regs);
	if (!(cpu_regs.cp_ecx & CPUID_INTC_ECX_EST)) {
		ESSDEBUG(("Enhanced Speedstep not supported.\n"));
		return (ESS_RET_NO_PM);
	}

	family = cpuid_getfamily(CPU);
	model = cpuid_getmodel(CPU);
	if (!((family == 0xf && model >= 0x3) ||
	    (family == 0x6 && model >= 0xe))) {
		ESSDEBUG(("Variant TSC not supported.\n"));
		return (ESS_RET_NO_PM);
	}

	/*
	 * If Enhanced Speedstep has not been enabled on the system,
	 * then we probably should not override the BIOS setting.
	 */
	reg = rdmsr(IA32_MISC_ENABLE_MSR);
	if (! (reg & IA32_MISC_ENABLE_EST)) {
		cmn_err(CE_NOTE, "!Enhanced Intel SpeedStep not enabled.");
		cmn_err(CE_NOTE, "!CPU power management will not function.");
		return (ESS_RET_NO_PM);
	}

	/*
	 * Enhanced Speedstep requires ACPI support. Get a handle
	 * to the correct processor object for this dip.
	 */
	handle = cpudsp->acpi_handle = cpu_acpi_init(cpudsp->dip);
	if (handle == NULL) {
		cmn_err(CE_WARN, "!speedstep_init: instance %d: "
		    "unable to get ACPI handle",
		    ddi_get_instance(cpudsp->dip));

		cmn_err(CE_NOTE, "!CPU power management will not function.");
		return (ESS_RET_NO_PM);
	}

	/*
	 * _PDC support is optional and the driver should
	 * function even if the _PDC write fails.
	 */
	if (cpu_acpi_write_pdc(handle, ESS_PDC_REVISION, 1,
	    &ess_pdccap) != 0)
		ESSDEBUG(("Failed to write PDC\n"));

	if (cpu_acpi_cache_data(handle) != 0) {
		ESSDEBUG(("Failed to cache ACPI data\n"));
		cpu_acpi_fini(handle);
		return (ESS_RET_NO_PM);
	}

	pct_stat = CPU_ACPI_PCT_STATUS(handle);
	switch (pct_stat->pc_addrspace_id) {
	case ACPI_ADR_SPACE_FIXED_HARDWARE:
		ESSDEBUG(("Transitions will use fixed hardware\n"));
		break;
	case ACPI_ADR_SPACE_SYSTEM_IO:
		ESSDEBUG(("Transitions will use system IO\n"));
		break;
	default:
		cmn_err(CE_WARN, "!_PCT conifgured for unsupported "
		    "addrspace = %d.", pct_stat->pc_addrspace_id);
		cmn_err(CE_NOTE, "!CPU power management will not function.");
		cpu_acpi_fini(handle);
		return (ESS_RET_NO_PM);
	}

	if (CPU_ACPI_IS_OBJ_CACHED(handle, CPU_ACPI_PSD_CACHED))
		dependency = CPU_ACPI_PSD(handle).pd_domain;
	else {
		mutex_enter(&cpu_lock);
		cp = cpu[CPU->cpu_id];
		dependency = cpuid_get_chipid(cp);
		mutex_exit(&cpu_lock);
	}
	cpupm_add_cpu2dependency(cpudsp->dip, dependency);

	speedstep_state = kmem_zalloc(sizeof (speedstep_state_t), KM_SLEEP);
	speedstep_state->ss_state = NULL;
	cpudsp->module_state = speedstep_state;

	ESSDEBUG(("Instance %d succeeded.\n", ddi_get_instance(cpudsp->dip)));
	return (ESS_RET_SUCCESS);
}

/*
 * Free resources allocated by speedstep_init().
 */
void
speedstep_fini(cpudrv_devstate_t *cpudsp)
{
	cpu_acpi_fini(cpudsp->acpi_handle);
	kmem_free(cpudsp->module_state, sizeof (speedstep_state_t));
}
