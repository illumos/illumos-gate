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
#include <sys/cpu_acpi.h>
#include <sys/cpupm_throttle.h>
#include <sys/dtrace.h>
#include <sys/sdt.h>

static int cpupm_throttle_init(cpu_t *);
static void cpupm_throttle_fini(cpu_t *);
static void cpupm_throttle(cpuset_t,  uint32_t);
static void cpupm_throttle_stop(cpu_t *);

cpupm_state_ops_t cpupm_throttle_ops = {
	"Generic ACPI T-state Support",
	cpupm_throttle_init,
	cpupm_throttle_fini,
	cpupm_throttle,
	cpupm_throttle_stop
};

/*
 * Error returns
 */
#define	THROTTLE_RET_SUCCESS		0x00
#define	THROTTLE_RET_INCOMPLETE_DATA	0x01
#define	THROTTLE_RET_UNSUP_STATE	0x02
#define	THROTTLE_RET_TRANS_INCOMPLETE	0x03

#define	THROTTLE_LATENCY_WAIT		1

/*
 * MSR register for clock modulation
 */
#define	IA32_CLOCK_MODULATION_MSR	0x19A

/*
 * Debugging support
 */
#ifdef  DEBUG
volatile int cpupm_throttle_debug = 0;
#define	CTDEBUG(arglist) if (cpupm_throttle_debug) printf arglist;
#else
#define	CTDEBUG(arglist)
#endif

/*
 * Write the _PTC ctrl register. How it is written, depends upon the _PTC
 * APCI object value.
 */
static int
write_ctrl(cpu_acpi_handle_t handle, uint32_t ctrl)
{
	cpu_acpi_ptc_t *ptc_ctrl;
	uint64_t reg;
	int ret = 0;

	ptc_ctrl = CPU_ACPI_PTC_CTRL(handle);

	switch (ptc_ctrl->cr_addrspace_id) {
	case ACPI_ADR_SPACE_FIXED_HARDWARE:
		/*
		 * Read current thermal state because reserved bits must be
		 * preserved, compose new value, and write it.The writable
		 * bits are 4:1 (1 to 4).
		 * Bits 3:1 => On-Demand Clock Modulation Duty Cycle
		 * Bit  4   => On-Demand Clock Modulation Enable
		 * Left shift ctrl by 1 to allign with bits 1-4 of MSR
		 */
		reg = rdmsr(IA32_CLOCK_MODULATION_MSR);
		reg &= ~((uint64_t)0x1E);
		reg |= ctrl;
		wrmsr(IA32_CLOCK_MODULATION_MSR, reg);
		break;

	case ACPI_ADR_SPACE_SYSTEM_IO:
		ret = cpu_acpi_write_port(ptc_ctrl->cr_address, ctrl,
		    ptc_ctrl->cr_width);
		break;

	default:
		DTRACE_PROBE1(throttle_ctrl_unsupported_type, uint8_t,
		    ptc_ctrl->cr_addrspace_id);

		ret = -1;
	}

	DTRACE_PROBE1(throttle_ctrl_write, uint32_t, ctrl);
	DTRACE_PROBE1(throttle_ctrl_write_err, int, ret);

	return (ret);
}

static int
read_status(cpu_acpi_handle_t handle, uint32_t *stat)
{
	cpu_acpi_ptc_t *ptc_stat;
	uint64_t reg;
	int ret = 0;

	ptc_stat = CPU_ACPI_PTC_STATUS(handle);

	switch (ptc_stat->cr_addrspace_id) {
	case ACPI_ADR_SPACE_FIXED_HARDWARE:
		reg = rdmsr(IA32_CLOCK_MODULATION_MSR);
		*stat = reg & 0x1E;
		ret = 0;
		break;

	case ACPI_ADR_SPACE_SYSTEM_IO:
		ret = cpu_acpi_read_port(ptc_stat->cr_address, stat,
		    ptc_stat->cr_width);
		break;

	default:
		DTRACE_PROBE1(throttle_status_unsupported_type, uint8_t,
		    ptc_stat->cr_addrspace_id);

		return (-1);
	}

	DTRACE_PROBE1(throttle_status_read, uint32_t, *stat);
	DTRACE_PROBE1(throttle_status_read_err, int, ret);

	return (ret);
}

/*
 * Transition the current processor to the requested throttling state.
 */
static void
cpupm_tstate_transition(uint32_t req_state)
{
	cpupm_mach_state_t *mach_state =
	    (cpupm_mach_state_t *)CPU->cpu_m.mcpu_pm_mach_state;
	cpu_acpi_handle_t handle = mach_state->ms_acpi_handle;
	cpu_acpi_tstate_t *req_tstate;
	uint32_t ctrl;
	uint32_t stat;
	int i;

	req_tstate = (cpu_acpi_tstate_t *)CPU_ACPI_TSTATES(handle);
	req_tstate += req_state;
	DTRACE_PROBE1(throttle_transition, uint32_t,
	    CPU_ACPI_FREQPER(req_tstate));

	/*
	 * Initiate the processor t-state change.
	 */
	ctrl = CPU_ACPI_TSTATE_CTRL(req_tstate);
	if (write_ctrl(handle, ctrl) != 0) {
		return;
	}

	/*
	 * If status is zero, then transition is synchronous and
	 * no status value comparison is required.
	 */
	if (CPU_ACPI_TSTATE_STAT(req_tstate) == 0) {
		return;
	}

	/* Wait until switch is complete, but bound the loop just in case. */
	for (i = CPU_ACPI_TSTATE_TRANSLAT(req_tstate) * 2; i >= 0;
	    i -= THROTTLE_LATENCY_WAIT) {
		if (read_status(handle, &stat) == 0 &&
		    CPU_ACPI_TSTATE_STAT(req_tstate) == stat)
			break;
		drv_usecwait(THROTTLE_LATENCY_WAIT);
	}

	if (CPU_ACPI_TSTATE_STAT(req_tstate) != stat) {
		DTRACE_PROBE(throttle_transition_incomplete);
	}
}

static void
cpupm_throttle(cpuset_t set,  uint32_t throtl_lvl)
{
	/*
	 * If thread is already running on target CPU then just
	 * make the transition request. Otherwise, we'll need to
	 * make a cross-call.
	 */
	kpreempt_disable();
	if (CPU_IN_SET(set, CPU->cpu_id)) {
		cpupm_tstate_transition(throtl_lvl);
		CPUSET_DEL(set, CPU->cpu_id);
	}
	if (!CPUSET_ISNULL(set)) {
		xc_call((xc_arg_t)throtl_lvl, NULL, NULL,
		    CPUSET2BV(set), (xc_func_t)cpupm_tstate_transition);
	}
	kpreempt_enable();
}

static int
cpupm_throttle_init(cpu_t *cp)
{
	cpupm_mach_state_t *mach_state =
	    (cpupm_mach_state_t *)cp->cpu_m.mcpu_pm_mach_state;
	cpu_acpi_handle_t handle = mach_state->ms_acpi_handle;
	cpu_acpi_ptc_t *ptc_stat;
	int ret;

	if ((ret = cpu_acpi_cache_tstate_data(handle)) != 0) {
		if (ret < 0)
			cmn_err(CE_NOTE,
			    "!Support for CPU throttling is being "
			    "disabled due to errors parsing ACPI T-state "
			    "objects exported by BIOS.");
		cpupm_throttle_fini(cp);
		return (THROTTLE_RET_INCOMPLETE_DATA);
	}

	/*
	 * Check the address space used for transitions
	 */
	ptc_stat = CPU_ACPI_PTC_STATUS(handle);
	switch (ptc_stat->cr_addrspace_id) {
	case ACPI_ADR_SPACE_FIXED_HARDWARE:
		CTDEBUG(("T-State transitions will use fixed hardware\n"));
		break;
	case ACPI_ADR_SPACE_SYSTEM_IO:
		CTDEBUG(("T-State transitions will use System IO\n"));
		break;
	default:
		cmn_err(CE_NOTE, "!_PTC configured for unsupported "
		    "address space type = %d.", ptc_stat->cr_addrspace_id);
		return (THROTTLE_RET_INCOMPLETE_DATA);
	}

	cpupm_alloc_domains(cp, CPUPM_T_STATES);

	return (THROTTLE_RET_SUCCESS);
}

static void
cpupm_throttle_fini(cpu_t *cp)
{
	cpupm_mach_state_t *mach_state =
	    (cpupm_mach_state_t *)cp->cpu_m.mcpu_pm_mach_state;
	cpu_acpi_handle_t handle = mach_state->ms_acpi_handle;

	cpupm_free_domains(&cpupm_tstate_domains);
	cpu_acpi_free_tstate_data(handle);
}

static void
cpupm_throttle_stop(cpu_t *cp)
{
	cpupm_mach_state_t *mach_state =
	    (cpupm_mach_state_t *)cp->cpu_m.mcpu_pm_mach_state;
	cpu_acpi_handle_t handle = mach_state->ms_acpi_handle;

	cpupm_remove_domains(cp, CPUPM_T_STATES, &cpupm_tstate_domains);
	cpu_acpi_free_tstate_data(handle);
}

/*
 * This routine reads the ACPI _TPC object. It's accessed as a callback
 * by the cpu driver whenever a _TPC change notification is received.
 */
static int
cpupm_throttle_get_max(processorid_t cpu_id)
{
	cpu_t			*cp = cpu[cpu_id];
	cpupm_mach_state_t 	*mach_state =
	    (cpupm_mach_state_t *)(cp->cpu_m.mcpu_pm_mach_state);
	cpu_acpi_handle_t	handle;
	int			throtl_level;
	int			max_throttle_lvl;
	uint_t			num_throtl;

	if (mach_state == NULL) {
		return (-1);
	}

	handle = mach_state->ms_acpi_handle;
	ASSERT(handle != NULL);

	cpu_acpi_cache_tpc(handle);
	throtl_level = CPU_ACPI_TPC(handle);

	num_throtl = CPU_ACPI_TSTATES_COUNT(handle);

	max_throttle_lvl = num_throtl - 1;
	if ((throtl_level < 0) || (throtl_level > max_throttle_lvl)) {
		cmn_err(CE_NOTE, "!cpupm_throttle_get_max: CPU %d: "
		    "_TPC out of range %d", cp->cpu_id, throtl_level);
		throtl_level = 0;
	}

	return (throtl_level);
}

/*
 * Take care of CPU throttling when _TPC notification arrives
 */
void
cpupm_throttle_manage_notification(void *ctx)
{
	cpu_t			*cp = ctx;
	processorid_t		cpu_id = cp->cpu_id;
	cpupm_mach_state_t	*mach_state =
	    (cpupm_mach_state_t *)cp->cpu_m.mcpu_pm_mach_state;
	boolean_t		is_ready;
	int			new_level;

	if (mach_state == NULL) {
		return;
	}

	/*
	 * We currently refuse to power-manage if the CPU is not ready to
	 * take cross calls (cross calls fail silently if CPU is not ready
	 * for it).
	 *
	 * Additionally, for x86 platforms we cannot power-manage an instance,
	 * until it has been initialized.
	 */
	is_ready = (cp->cpu_flags & CPU_READY) && cpupm_throttle_ready(cp);
	if (!is_ready)
		return;

	if (!(mach_state->ms_caps & CPUPM_T_STATES))
		return;
	ASSERT(mach_state->ms_tstate.cma_ops != NULL);

	/*
	 * Get the new T-State support level
	 */
	new_level = cpupm_throttle_get_max(cpu_id);

	cpupm_state_change(cp, new_level, CPUPM_T_STATES);
}
