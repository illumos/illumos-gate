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

#include <sys/machsystm.h>
#include <sys/archsystm.h>
#include <sys/prom_plat.h>
#include <sys/promif.h>
#include <sys/vm.h>
#include <sys/cpu.h>
#include <sys/atomic.h>
#include <sys/cpupart.h>
#include <sys/disp.h>
#include <sys/hypervisor_api.h>
#include <sys/traptrace.h>
#include <sys/modctl.h>
#include <sys/ldoms.h>
#include <sys/cpu_module.h>
#include <sys/mutex_impl.h>
#include <vm/vm_dep.h>
#include <sys/sdt.h>

#ifdef TRAPTRACE
int mach_htraptrace_enable = 1;
#else
int mach_htraptrace_enable = 0;
#endif
int htrap_tr0_inuse = 0;
extern char htrap_tr0[];	/* prealloc buf for boot cpu */

caddr_t	mmu_fault_status_area;

extern void sfmmu_set_tsbs(void);
/*
 * CPU IDLE optimization variables/routines
 */
static int enable_halt_idle_cpus = 1;

/*
 * Defines for the idle_state_transition DTrace probe
 *
 * The probe fires when the CPU undergoes an idle state change (e.g. hv yield)
 * The agument passed is the state to which the CPU is transitioning.
 *
 * The states are defined here.
 */
#define	IDLE_STATE_NORMAL 0
#define	IDLE_STATE_YIELDED 1

#define	SUN4V_CLOCK_TICK_THRESHOLD	64
#define	SUN4V_CLOCK_TICK_NCPUS		64

extern int	clock_tick_threshold;
extern int	clock_tick_ncpus;

void
setup_trap_table(void)
{
	caddr_t mmfsa_va;
	extern	 caddr_t mmu_fault_status_area;
	mmfsa_va =
	    mmu_fault_status_area + (MMFSA_SIZE * CPU->cpu_id);

	intr_init(CPU);		/* init interrupt request free list */
	setwstate(WSTATE_KERN);
	set_mmfsa_scratchpad(mmfsa_va);
	prom_set_mmfsa_traptable(&trap_table, va_to_pa(mmfsa_va));
	sfmmu_set_tsbs();
}

void
phys_install_has_changed(void)
{

}

/*
 * Halt the present CPU until awoken via an interrupt
 */
static void
cpu_halt(void)
{
	cpu_t *cpup = CPU;
	processorid_t cpun = cpup->cpu_id;
	cpupart_t *cp = cpup->cpu_part;
	int hset_update = 1;
	volatile int *p = &cpup->cpu_disp->disp_nrunnable;
	uint_t s;

	/*
	 * If this CPU is online, and there's multiple CPUs
	 * in the system, then we should notate our halting
	 * by adding ourselves to the partition's halted CPU
	 * bitmap. This allows other CPUs to find/awaken us when
	 * work becomes available.
	 */
	if (CPU->cpu_flags & CPU_OFFLINE || ncpus == 1)
		hset_update = 0;

	/*
	 * Add ourselves to the partition's halted CPUs bitmask
	 * and set our HALTED flag, if necessary.
	 *
	 * When a thread becomes runnable, it is placed on the queue
	 * and then the halted cpuset is checked to determine who
	 * (if anyone) should be awoken. We therefore need to first
	 * add ourselves to the halted cpuset, and then check if there
	 * is any work available.
	 */
	if (hset_update) {
		cpup->cpu_disp_flags |= CPU_DISP_HALTED;
		membar_producer();
		CPUSET_ATOMIC_ADD(cp->cp_mach->mc_haltset, cpun);
	}

	/*
	 * Check to make sure there's really nothing to do.
	 * Work destined for this CPU may become available after
	 * this check. We'll be notified through the clearing of our
	 * bit in the halted CPU bitmask, and a poke.
	 */
	if (disp_anywork()) {
		if (hset_update) {
			cpup->cpu_disp_flags &= ~CPU_DISP_HALTED;
			CPUSET_ATOMIC_DEL(cp->cp_mach->mc_haltset, cpun);
		}
		return;
	}

	/*
	 * We're on our way to being halted.  Wait until something becomes
	 * runnable locally or we are awaken (i.e. removed from the halt set).
	 * Note that the call to hv_cpu_yield() can return even if we have
	 * nothing to do.
	 *
	 * Disable interrupts now, so that we'll awaken immediately
	 * after halting if someone tries to poke us between now and
	 * the time we actually halt.
	 *
	 * We check for the presence of our bit after disabling interrupts.
	 * If it's cleared, we'll return. If the bit is cleared after
	 * we check then the poke will pop us out of the halted state.
	 * Also, if the offlined CPU has been brought back on-line, then
	 * we return as well.
	 *
	 * The ordering of the poke and the clearing of the bit by cpu_wakeup
	 * is important.
	 * cpu_wakeup() must clear, then poke.
	 * cpu_halt() must disable interrupts, then check for the bit.
	 *
	 * The check for anything locally runnable is here for performance
	 * and isn't needed for correctness. disp_nrunnable ought to be
	 * in our cache still, so it's inexpensive to check, and if there
	 * is anything runnable we won't have to wait for the poke.
	 *
	 */
	s = disable_vec_intr();
	while (*p == 0 &&
	    ((hset_update && CPU_IN_SET(cp->cp_mach->mc_haltset, cpun)) ||
	    (!hset_update && (CPU->cpu_flags & CPU_OFFLINE)))) {

		DTRACE_PROBE1(idle__state__transition,
		    uint_t, IDLE_STATE_YIELDED);
		(void) hv_cpu_yield();
		DTRACE_PROBE1(idle__state__transition,
		    uint_t, IDLE_STATE_NORMAL);

		enable_vec_intr(s);
		s = disable_vec_intr();
	}

	/*
	 * We're no longer halted
	 */
	enable_vec_intr(s);
	if (hset_update) {
		cpup->cpu_disp_flags &= ~CPU_DISP_HALTED;
		CPUSET_ATOMIC_DEL(cp->cp_mach->mc_haltset, cpun);
	}
}

/*
 * If "cpu" is halted, then wake it up clearing its halted bit in advance.
 * Otherwise, see if other CPUs in the cpu partition are halted and need to
 * be woken up so that they can steal the thread we placed on this CPU.
 * This function is only used on MP systems.
 */
static void
cpu_wakeup(cpu_t *cpu, int bound)
{
	uint_t		cpu_found;
	int		result;
	cpupart_t	*cp;

	cp = cpu->cpu_part;
	if (CPU_IN_SET(cp->cp_mach->mc_haltset, cpu->cpu_id)) {
		/*
		 * Clear the halted bit for that CPU since it will be
		 * poked in a moment.
		 */
		CPUSET_ATOMIC_DEL(cp->cp_mach->mc_haltset, cpu->cpu_id);
		/*
		 * We may find the current CPU present in the halted cpuset
		 * if we're in the context of an interrupt that occurred
		 * before we had a chance to clear our bit in cpu_halt().
		 * Poking ourself is obviously unnecessary, since if
		 * we're here, we're not halted.
		 */
		if (cpu != CPU)
			poke_cpu(cpu->cpu_id);
		return;
	} else {
		/*
		 * This cpu isn't halted, but it's idle or undergoing a
		 * context switch. No need to awaken anyone else.
		 */
		if (cpu->cpu_thread == cpu->cpu_idle_thread ||
		    cpu->cpu_disp_flags & CPU_DISP_DONTSTEAL)
			return;
	}

	/*
	 * No need to wake up other CPUs if the thread we just enqueued
	 * is bound.
	 */
	if (bound)
		return;

	/*
	 * See if there's any other halted CPUs. If there are, then
	 * select one, and awaken it.
	 * It's possible that after we find a CPU, somebody else
	 * will awaken it before we get the chance.
	 * In that case, look again.
	 */
	do {
		CPUSET_FIND(cp->cp_mach->mc_haltset, cpu_found);
		if (cpu_found == CPUSET_NOTINSET)
			return;

		ASSERT(cpu_found >= 0 && cpu_found < NCPU);
		CPUSET_ATOMIC_XDEL(cp->cp_mach->mc_haltset, cpu_found, result);
	} while (result < 0);

	if (cpu_found != CPU->cpu_id)
		poke_cpu(cpu_found);
}

void
mach_cpu_halt_idle()
{
	if (enable_halt_idle_cpus) {
		idle_cpu = cpu_halt;
		disp_enq_thread = cpu_wakeup;
	}
}

int
ndata_alloc_mmfsa(struct memlist *ndata)
{
	size_t	size;

	size = MMFSA_SIZE * max_ncpus;
	mmu_fault_status_area = ndata_alloc(ndata, size, ecache_alignsize);
	if (mmu_fault_status_area == NULL)
		return (-1);
	return (0);
}

void
mach_memscrub(void)
{
	/* no memscrub support for sun4v for now */
}

void
mach_fpras()
{
	/* no fpras support for sun4v for now */
}

void
mach_hw_copy_limit(void)
{
	/* HW copy limits set by individual CPU module */
}

/*
 * We need to enable soft ring functionality on Niagara platform since
 * one strand can't handle interrupts for a 1Gb NIC. Set the tunable
 * ip_squeue_soft_ring by default on this platform. We can also set
 * ip_threads_per_cpu to track number of threads per core. The variables
 * themselves are defined in space.c and used by IP module
 */
extern uint_t ip_threads_per_cpu;
extern boolean_t ip_squeue_soft_ring;
void
startup_platform(void)
{
	ip_squeue_soft_ring = B_TRUE;
	if (clock_tick_threshold == 0)
		clock_tick_threshold = SUN4V_CLOCK_TICK_THRESHOLD;
	if (clock_tick_ncpus == 0)
		clock_tick_ncpus = SUN4V_CLOCK_TICK_NCPUS;
	/* set per-platform constants for mutex_backoff */
	mutex_backoff_base = 1;
	mutex_cap_factor = 4;
	if (l2_cache_node_count() > 1) {
		/* VF for example */
		mutex_backoff_base = 2;
		mutex_cap_factor = 16;
	}
}

/*
 * This function sets up hypervisor traptrace buffer
 * This routine is called by the boot cpu only
 */
void
mach_htraptrace_setup(int cpuid)
{
	TRAP_TRACE_CTL	*ctlp;
	int bootcpuid = getprocessorid(); /* invoked on boot cpu only */

	if (mach_htraptrace_enable && ((cpuid != bootcpuid) ||
	    !htrap_tr0_inuse)) {
		ctlp = &trap_trace_ctl[cpuid];
		ctlp->d.hvaddr_base = (cpuid == bootcpuid) ? htrap_tr0 :
		    contig_mem_alloc_align(HTRAP_TSIZE, HTRAP_TSIZE);
		if (ctlp->d.hvaddr_base == NULL) {
			ctlp->d.hlimit = 0;
			ctlp->d.hpaddr_base = NULL;
			cmn_err(CE_WARN, "!cpu%d: failed to allocate HV "
			    "traptrace buffer", cpuid);
		} else {
			ctlp->d.hlimit = HTRAP_TSIZE;
			ctlp->d.hpaddr_base = va_to_pa(ctlp->d.hvaddr_base);
		}
	}
}

/*
 * This function enables or disables the hypervisor traptracing
 */
void
mach_htraptrace_configure(int cpuid)
{
	uint64_t ret;
	uint64_t prev_buf, prev_bufsize;
	uint64_t prev_enable;
	uint64_t size;
	TRAP_TRACE_CTL	*ctlp;

	ctlp = &trap_trace_ctl[cpuid];
	if (mach_htraptrace_enable) {
		if ((ctlp->d.hvaddr_base != NULL) &&
		    ((ctlp->d.hvaddr_base != htrap_tr0) ||
		    (!htrap_tr0_inuse))) {
			ret = hv_ttrace_buf_info(&prev_buf, &prev_bufsize);
			if ((ret == H_EOK) && (prev_bufsize != 0)) {
				cmn_err(CE_CONT,
				    "!cpu%d: previous HV traptrace buffer of "
				    "size 0x%lx at address 0x%lx", cpuid,
				    prev_bufsize, prev_buf);
			}

			ret = hv_ttrace_buf_conf(ctlp->d.hpaddr_base,
			    ctlp->d.hlimit /
			    (sizeof (struct htrap_trace_record)), &size);
			if (ret == H_EOK) {
				ret = hv_ttrace_enable(\
				    (uint64_t)TRAP_TENABLE_ALL, &prev_enable);
				if (ret != H_EOK) {
					cmn_err(CE_WARN,
					    "!cpu%d: HV traptracing not "
					    "enabled, ta: 0x%x returned error: "
					    "%ld", cpuid, TTRACE_ENABLE, ret);
				} else {
					if (ctlp->d.hvaddr_base == htrap_tr0)
						htrap_tr0_inuse = 1;
				}
			} else {
				cmn_err(CE_WARN,
				    "!cpu%d: HV traptrace buffer not "
				    "configured, ta: 0x%x returned error: %ld",
				    cpuid, TTRACE_BUF_CONF, ret);
			}
			/*
			 * set hvaddr_base to NULL when traptrace buffer
			 * registration fails
			 */
			if (ret != H_EOK) {
				ctlp->d.hvaddr_base = NULL;
				ctlp->d.hlimit = 0;
				ctlp->d.hpaddr_base = NULL;
			}
		}
	} else {
		ret = hv_ttrace_buf_info(&prev_buf, &prev_bufsize);
		if ((ret == H_EOK) && (prev_bufsize != 0)) {
			ret = hv_ttrace_enable((uint64_t)TRAP_TDISABLE_ALL,
			    &prev_enable);
			if (ret == H_EOK) {
				if (ctlp->d.hvaddr_base == htrap_tr0)
					htrap_tr0_inuse = 0;
				ctlp->d.hvaddr_base = NULL;
				ctlp->d.hlimit = 0;
				ctlp->d.hpaddr_base = NULL;
			} else
				cmn_err(CE_WARN,
				    "!cpu%d: HV traptracing is not disabled, "
				    "ta: 0x%x returned error: %ld",
				    cpuid, TTRACE_ENABLE, ret);
		}
	}
}

/*
 * This function cleans up the hypervisor traptrace buffer
 */
void
mach_htraptrace_cleanup(int cpuid)
{
	if (mach_htraptrace_enable) {
		TRAP_TRACE_CTL *ctlp;
		caddr_t httrace_buf_va;

		ASSERT(cpuid < max_ncpus);
		ctlp = &trap_trace_ctl[cpuid];
		httrace_buf_va = ctlp->d.hvaddr_base;
		if (httrace_buf_va == htrap_tr0) {
			bzero(httrace_buf_va, HTRAP_TSIZE);
		} else if (httrace_buf_va != NULL) {
			contig_mem_free(httrace_buf_va, HTRAP_TSIZE);
		}
		ctlp->d.hvaddr_base = NULL;
		ctlp->d.hlimit = 0;
		ctlp->d.hpaddr_base = NULL;
	}
}

/*
 * Load any required machine class (sun4v) specific drivers.
 */
void
load_mach_drivers(void)
{
	/*
	 * We don't want to load these LDOMs-specific
	 * modules if domaining is not supported.  Also,
	 * we must be able to run on non-LDOMs firmware.
	 */
	if (!domaining_supported())
		return;

	/*
	 * Load the core domain services module
	 */
	if (modload("misc", "ds") == -1)
		cmn_err(CE_NOTE, "!'ds' module failed to load");

	/*
	 * Load the rest of the domain services
	 */
	if (modload("misc", "fault_iso") == -1)
		cmn_err(CE_NOTE, "!'fault_iso' module failed to load");

	if (modload("misc", "platsvc") == -1)
		cmn_err(CE_NOTE, "!'platsvc' module failed to load");

	if (domaining_enabled() && modload("misc", "dr_cpu") == -1)
		cmn_err(CE_NOTE, "!'dr_cpu' module failed to load");

	/*
	 * Attempt to attach any virtual device servers. These
	 * drivers must be loaded at start of day so that they
	 * can respond to any updates to the machine description.
	 *
	 * Since it is quite likely that a domain will not support
	 * one or more of these servers, failures are ignored.
	 */

	/* virtual disk server */
	(void) i_ddi_attach_hw_nodes("vds");

	/* virtual network switch */
	(void) i_ddi_attach_hw_nodes("vsw");

	/* virtual console concentrator */
	(void) i_ddi_attach_hw_nodes("vcc");
}
