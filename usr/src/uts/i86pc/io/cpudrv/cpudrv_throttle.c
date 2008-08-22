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
#include <sys/cpu_acpi.h>
#include <sys/cpudrv_throttle.h>
#include <sys/dtrace.h>
#include <sys/sdt.h>

static int cpudrv_throttle_init(cpudrv_devstate_t *);
static void cpudrv_throttle_fini(cpudrv_devstate_t *);
static int cpudrv_throttle(cpudrv_devstate_t *,  uint32_t);

cpudrv_tstate_ops_t cpudrv_throttle_ops = {
	"Generic ACPI T-state Support",
	cpudrv_throttle_init,
	cpudrv_throttle_fini,
	cpudrv_throttle
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
volatile int cpudrv_throttle_debug = 0;
#define	CTDEBUG(arglist) if (cpudrv_throttle_debug) printf arglist;
#else
#define	CTDEBUG(arglist)
#endif

cpudrv_tstate_domain_t *cpudrv_tstate_domains = NULL;

/*
 * Allocate a new domain node.
 */
static void
cpudrv_alloc_tstate_domain(cpudrv_devstate_t *cpudsp)
{
	cpudrv_mach_state_t *mach_state = cpudsp->mach_state;
	cpu_acpi_handle_t handle = mach_state->acpi_handle;
	cpudrv_tstate_domain_t *dptr;
	cpudrv_tstate_domain_node_t *nptr;
	uint32_t domain;
	uint32_t type;
	cpu_t *cp;

	if (CPU_ACPI_IS_OBJ_CACHED(handle, CPU_ACPI_TSD_CACHED)) {
		domain = CPU_ACPI_TSD(handle).sd_domain;
		type = CPU_ACPI_TSD(handle).sd_type;
	} else {
		mutex_enter(&cpu_lock);
		cp = cpu[CPU->cpu_id];
		domain = cpuid_get_chipid(cp);
		mutex_exit(&cpu_lock);
		type = CPU_ACPI_SW_ALL;
	}

	for (dptr = cpudrv_tstate_domains; dptr != NULL;
	    dptr = dptr->td_next) {
		if (dptr->td_domain == domain)
			break;
	}

	/* new domain is created and linked at the head */
	if (dptr == NULL) {
		dptr = kmem_zalloc(sizeof (cpudrv_tstate_domain_t), KM_SLEEP);
		dptr->td_domain = domain;
		dptr->td_type = type;
		dptr->td_next = cpudrv_tstate_domains;
		mutex_init(&dptr->td_lock, NULL, MUTEX_DRIVER, NULL);
		cpudrv_tstate_domains = dptr;
	}

	/* new domain node is created and linked at the head of the domain */
	nptr = kmem_zalloc(sizeof (cpudrv_tstate_domain_node_t), KM_SLEEP);
	nptr->tdn_cpudsp = cpudsp;
	nptr->tdn_domain = dptr;
	nptr->tdn_next = dptr->td_node;
	dptr->td_node = nptr;
	mach_state->tstate_domain_node = nptr;
}

static void
cpudrv_free_tstate_domains()
{
	cpudrv_tstate_domain_t *this_domain, *next_domain;
	cpudrv_tstate_domain_node_t *this_node, *next_node;

	this_domain = cpudrv_tstate_domains;
	while (this_domain != NULL) {
		next_domain = this_domain->td_next;

		/* discard CPU node chain */
		this_node = this_domain->td_node;
		while (this_node != NULL) {
			next_node = this_node->tdn_next;
			kmem_free((void *)this_node,
			    sizeof (cpudrv_tstate_domain_node_t));
			this_node = next_node;
		}
		mutex_destroy(&this_domain->td_lock);
		kmem_free((void *)this_domain,
		    sizeof (cpudrv_tstate_domain_t));
		this_domain = next_domain;
	}
	cpudrv_tstate_domains = NULL;
}

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
cpudrv_tstate_transition(int *ret, cpudrv_devstate_t *cpudsp,
    uint32_t req_state)
{
	cpudrv_mach_state_t *mach_state = cpudsp->mach_state;
	cpu_acpi_handle_t handle = mach_state->acpi_handle;
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
		*ret = THROTTLE_RET_UNSUP_STATE;
		return;
	}

	/*
	 * If status is zero, then transition is synchronous and
	 * no status value comparison is required.
	 */
	if (CPU_ACPI_TSTATE_STAT(req_tstate) == 0) {
		*ret = THROTTLE_RET_SUCCESS;
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
		*ret = THROTTLE_RET_TRANS_INCOMPLETE;
	} else {
		*ret = THROTTLE_RET_SUCCESS;
	}
}

static int
cpudrv_throttle(cpudrv_devstate_t *cpudsp,  uint32_t throtl_lvl)
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
		cpudrv_tstate_transition(&ret, cpudsp, throtl_lvl);
	} else {
		CPUSET_ONLY(cpus, cpudsp->cpu_id);
		xc_call((xc_arg_t)&ret, (xc_arg_t)cpudsp, (xc_arg_t)throtl_lvl,
		    X_CALL_HIPRI, cpus, (xc_func_t)cpudrv_tstate_transition);
	}
	kpreempt_enable();

	return (ret);
}

static int
cpudrv_throttle_init(cpudrv_devstate_t *cpudsp)
{
	cpudrv_mach_state_t *mach_state = cpudsp->mach_state;
	cpu_acpi_handle_t handle = mach_state->acpi_handle;
	cpu_acpi_ptc_t *ptc_stat;

	if (cpu_acpi_cache_tstate_data(handle) != 0) {
		CTDEBUG(("Failed to cache T-state ACPI data\n"));
		cpudrv_throttle_fini(cpudsp);
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
		cmn_err(CE_WARN, "!_PTC conifgured for unsupported "
		    "address space type = %d.", ptc_stat->cr_addrspace_id);
		return (THROTTLE_RET_INCOMPLETE_DATA);
	}

	cpudrv_alloc_tstate_domain(cpudsp);

	return (THROTTLE_RET_SUCCESS);
}

static void
cpudrv_throttle_fini(cpudrv_devstate_t *cpudsp)
{
	cpudrv_mach_state_t *mach_state = cpudsp->mach_state;
	cpu_acpi_handle_t handle = mach_state->acpi_handle;

	cpudrv_free_tstate_domains();
	cpu_acpi_free_tstate_data(handle);
}
