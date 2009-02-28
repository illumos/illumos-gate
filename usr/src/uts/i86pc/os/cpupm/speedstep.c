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
#include <sys/archsystm.h>
#include <sys/x_call.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include <sys/speedstep.h>
#include <sys/cpu_acpi.h>
#include <sys/cpupm.h>
#include <sys/dtrace.h>
#include <sys/sdt.h>

/*
 * turbo related structure definitions
 */
typedef struct cpupm_turbo_info {
	kstat_t		*turbo_ksp;		/* turbo kstat */
	int		in_turbo;		/* in turbo? */
	int		turbo_supported;	/* turbo flag */
	uint64_t	t_mcnt;			/* turbo mcnt */
	uint64_t	t_acnt;			/* turbo acnt */
} cpupm_turbo_info_t;

typedef struct turbo_kstat_s {
	struct kstat_named	turbo_supported;	/* turbo flag */
	struct kstat_named	t_mcnt;			/* IA32_MPERF_MSR */
	struct kstat_named	t_acnt;			/* IA32_APERF_MSR */
} turbo_kstat_t;

static int speedstep_init(cpu_t *);
static void speedstep_fini(cpu_t *);
static void speedstep_power(cpuset_t, uint32_t);
static boolean_t turbo_supported(void);
static int turbo_kstat_update(kstat_t *, int);
static void get_turbo_info(cpupm_turbo_info_t *);
static void reset_turbo_info(void);
static void record_turbo_info(cpupm_turbo_info_t *, uint32_t, uint32_t);
static void update_turbo_info(cpupm_turbo_info_t *);

/*
 * Interfaces for modules implementing Intel's Enhanced SpeedStep.
 */
cpupm_state_ops_t speedstep_ops = {
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
 * MSR registers for changing and reading processor power state.
 */
#define	IA32_PERF_STAT_MSR		0x198
#define	IA32_PERF_CTL_MSR		0x199

#define	IA32_CPUID_TSC_CONSTANT		0xF30
#define	IA32_MISC_ENABLE_MSR		0x1A0
#define	IA32_MISC_ENABLE_EST		(1<<16)
#define	IA32_MISC_ENABLE_CXE		(1<<25)

#define	CPUID_TURBO_SUPPORT		(1 << 1)
#define	CPU_ACPI_P0			0
#define	CPU_IN_TURBO			1

/*
 * MSR for hardware coordination feedback mechanism
 *   - IA32_MPERF: increments in proportion to a fixed frequency
 *   - IA32_APERF: increments in proportion to actual performance
 */
#define	IA32_MPERF_MSR			0xE7
#define	IA32_APERF_MSR			0xE8

/*
 * Debugging support
 */
#ifdef	DEBUG
volatile int ess_debug = 0;
#define	ESSDEBUG(arglist) if (ess_debug) printf arglist;
#else
#define	ESSDEBUG(arglist)
#endif

static kmutex_t turbo_mutex;

turbo_kstat_t turbo_kstat = {
	{ "turbo_supported",	KSTAT_DATA_UINT32 },
	{ "turbo_mcnt",		KSTAT_DATA_UINT64 },
	{ "turbo_acnt",		KSTAT_DATA_UINT64 },
};

/*
 * kstat update function of the turbo mode info
 */
static int
turbo_kstat_update(kstat_t *ksp, int flag)
{
	cpupm_turbo_info_t *turbo_info = ksp->ks_private;

	if (flag == KSTAT_WRITE) {
		return (EACCES);
	}

	/*
	 * update the count in case CPU is in the turbo
	 * mode for a long time
	 */
	if (turbo_info->in_turbo == CPU_IN_TURBO)
		update_turbo_info(turbo_info);

	turbo_kstat.turbo_supported.value.ui32 =
	    turbo_info->turbo_supported;
	turbo_kstat.t_mcnt.value.ui64 = turbo_info->t_mcnt;
	turbo_kstat.t_acnt.value.ui64 = turbo_info->t_acnt;

	return (0);
}

/*
 * Get count of MPERF/APERF MSR
 */
static void
get_turbo_info(cpupm_turbo_info_t *turbo_info)
{
	ulong_t		iflag;
	uint64_t	mcnt, acnt;

	iflag = intr_clear();
	mcnt = rdmsr(IA32_MPERF_MSR);
	acnt = rdmsr(IA32_APERF_MSR);
	turbo_info->t_mcnt += mcnt;
	turbo_info->t_acnt += acnt;
	intr_restore(iflag);
}

/*
 * Clear MPERF/APERF MSR
 */
static void
reset_turbo_info(void)
{
	ulong_t		iflag;

	iflag = intr_clear();
	wrmsr(IA32_MPERF_MSR, 0);
	wrmsr(IA32_APERF_MSR, 0);
	intr_restore(iflag);
}

/*
 * sum up the count of one CPU_ACPI_P0 transition
 */
static void
record_turbo_info(cpupm_turbo_info_t *turbo_info,
    uint32_t cur_state, uint32_t req_state)
{
	if (!turbo_info->turbo_supported)
		return;
	/*
	 * enter P0 state
	 */
	if (req_state == CPU_ACPI_P0) {
		reset_turbo_info();
		turbo_info->in_turbo = CPU_IN_TURBO;
	}
	/*
	 * Leave P0 state
	 */
	else if (cur_state == CPU_ACPI_P0) {
		turbo_info->in_turbo = 0;
		get_turbo_info(turbo_info);
	}
}

/*
 * update the sum of counts and clear MSRs
 */
static void
update_turbo_info(cpupm_turbo_info_t *turbo_info)
{
	ulong_t		iflag;
	uint64_t	mcnt, acnt;

	iflag = intr_clear();
	mcnt = rdmsr(IA32_MPERF_MSR);
	acnt = rdmsr(IA32_APERF_MSR);
	wrmsr(IA32_MPERF_MSR, 0);
	wrmsr(IA32_APERF_MSR, 0);
	turbo_info->t_mcnt += mcnt;
	turbo_info->t_acnt += acnt;
	intr_restore(iflag);
}

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
	cpupm_turbo_info_t *turbo_info =
	    (cpupm_turbo_info_t *)(mach_state->ms_vendor);

	req_pstate = (cpu_acpi_pstate_t *)CPU_ACPI_PSTATES(handle);
	req_pstate += req_state;

	DTRACE_PROBE1(ess_transition, uint32_t, CPU_ACPI_FREQ(req_pstate));

	/*
	 * Initiate the processor p-state change.
	 */
	ctrl = CPU_ACPI_PSTATE_CTRL(req_pstate);
	write_ctrl(handle, ctrl);

	if (turbo_info)
		record_turbo_info(turbo_info,
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
		xc_call((xc_arg_t)req_state, NULL, NULL, X_CALL_HIPRI, set,
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
	cpupm_turbo_info_t *turbo_info;

	ESSDEBUG(("speedstep_init: processor %d\n", cp->cpu_id));

	/*
	 * Cache the P-state specific ACPI data.
	 */
	if (cpu_acpi_cache_pstate_data(handle) != 0) {
		ESSDEBUG(("Failed to cache ACPI data\n"));
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

	if (!turbo_supported()) {
		mach_state->ms_vendor = NULL;
		goto ess_ret_success;
	}
	/*
	 * turbo mode supported
	 */
	turbo_info = mach_state->ms_vendor =
	    kmem_zalloc(sizeof (cpupm_turbo_info_t), KM_SLEEP);
	turbo_info->turbo_supported = 1;
	turbo_info->turbo_ksp = kstat_create("turbo", cp->cpu_id,
	    "turbo", "misc", KSTAT_TYPE_NAMED,
	    sizeof (turbo_kstat) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL);

	if (turbo_info->turbo_ksp == NULL) {
		cmn_err(CE_NOTE, "kstat_create(turbo) fail");
	} else {
		turbo_info->turbo_ksp->ks_data = &turbo_kstat;
		turbo_info->turbo_ksp->ks_lock = &turbo_mutex;
		turbo_info->turbo_ksp->ks_update = turbo_kstat_update;
		turbo_info->turbo_ksp->ks_data_size += MAXNAMELEN;
		turbo_info->turbo_ksp->ks_private = turbo_info;

		kstat_install(turbo_info->turbo_ksp);
	}

ess_ret_success:

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
	cpupm_turbo_info_t *turbo_info =
	    (cpupm_turbo_info_t *)(mach_state->ms_vendor);

	cpupm_free_domains(&cpupm_pstate_domains);
	cpu_acpi_free_pstate_data(handle);

	if (turbo_info) {
		if (turbo_info->turbo_ksp != NULL)
			kstat_delete(turbo_info->turbo_ksp);
		kmem_free(turbo_info, sizeof (cpupm_turbo_info_t));
	}
}

boolean_t
speedstep_supported(uint_t family, uint_t model)
{
	struct cpuid_regs cpu_regs;

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

	return (B_TRUE);
}

boolean_t
turbo_supported(void)
{
	struct cpuid_regs cpu_regs;

	/* Required features */
	if (!(x86_feature & X86_CPUID) ||
	    !(x86_feature & X86_MSR)) {
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
