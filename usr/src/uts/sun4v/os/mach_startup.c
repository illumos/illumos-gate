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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/machsystm.h>
#include <sys/archsystm.h>
#include <sys/prom_plat.h>
#include <sys/promif.h>
#include <sys/vm.h>
#include <sys/cpu.h>
#include <sys/bitset.h>
#include <sys/cpupart.h>
#include <sys/disp.h>
#include <sys/hypervisor_api.h>
#include <sys/traptrace.h>
#include <sys/modctl.h>
#include <sys/ldoms.h>
#include <sys/cpu_module.h>
#include <sys/mutex_impl.h>
#include <sys/rwlock.h>
#include <sys/sdt.h>
#include <sys/cmt.h>
#include <vm/vm_dep.h>

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

uint_t cp_haltset_fanout = 3;

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
	processorid_t cpu_sid = cpup->cpu_seqid;
	cpupart_t *cp = cpup->cpu_part;
	int hset_update = 1;
	volatile int *p = &cpup->cpu_disp->disp_nrunnable;
	uint_t s;

	/*
	 * If this CPU is online then we should notate our halting
	 * by adding ourselves to the partition's halted CPU
	 * bitset. This allows other CPUs to find/awaken us when
	 * work becomes available.
	 */
	if (CPU->cpu_flags & CPU_OFFLINE)
		hset_update = 0;

	/*
	 * Add ourselves to the partition's halted CPUs bitset
	 * and set our HALTED flag, if necessary.
	 *
	 * When a thread becomes runnable, it is placed on the queue
	 * and then the halted cpu bitset is checked to determine who
	 * (if anyone) should be awoken. We therefore need to first
	 * add ourselves to the halted bitset, and then check if there
	 * is any work available.  The order is important to prevent a race
	 * that can lead to work languishing on a run queue somewhere while
	 * this CPU remains halted.
	 *
	 * Either the producing CPU will see we're halted and will awaken us,
	 * or this CPU will see the work available in disp_anywork()
	 */
	if (hset_update) {
		cpup->cpu_disp_flags |= CPU_DISP_HALTED;
		membar_producer();
		bitset_atomic_add(&cp->cp_haltset, cpu_sid);
	}

	/*
	 * Check to make sure there's really nothing to do.
	 * Work destined for this CPU may become available after
	 * this check. We'll be notified through the clearing of our
	 * bit in the halted CPU bitset, and a poke.
	 */
	if (disp_anywork()) {
		if (hset_update) {
			cpup->cpu_disp_flags &= ~CPU_DISP_HALTED;
			bitset_atomic_del(&cp->cp_haltset, cpu_sid);
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
	 * Any interrupt will awaken the cpu from halt. Looping here
	 * will filter spurious interrupts that wake us up, but don't
	 * represent a need for us to head back out to idle().  This
	 * will enable the idle loop to be more efficient and sleep in
	 * the processor pipeline for a larger percent of the time,
	 * which returns useful cycles to the peer hardware strand
	 * that shares the pipeline.
	 */
	s = disable_vec_intr();
	while (*p == 0 &&
	    ((hset_update && bitset_in_set(&cp->cp_haltset, cpu_sid)) ||
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
		bitset_atomic_del(&cp->cp_haltset, cpu_sid);
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
	processorid_t	cpu_sid;
	cpupart_t	*cp;

	cp = cpu->cpu_part;
	cpu_sid = cpu->cpu_seqid;
	if (bitset_in_set(&cp->cp_haltset, cpu_sid)) {
		/*
		 * Clear the halted bit for that CPU since it will be
		 * poked in a moment.
		 */
		bitset_atomic_del(&cp->cp_haltset, cpu_sid);
		/*
		 * We may find the current CPU present in the halted cpu bitset
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
	 * No need to wake up other CPUs if this is for a bound thread.
	 */
	if (bound)
		return;

	/*
	 * The CPU specified for wakeup isn't currently halted, so check
	 * to see if there are any other halted CPUs in the partition,
	 * and if there are then awaken one.
	 */
	do {
		cpu_found = bitset_find(&cp->cp_haltset);
		if (cpu_found == (uint_t)-1)
			return;
	} while (bitset_atomic_test_and_del(&cp->cp_haltset, cpu_found) < 0);

	if (cpu_found != CPU->cpu_seqid)
		poke_cpu(cpu_seq[cpu_found]->cpu_id);
}

void
mach_cpu_halt_idle(void)
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
 * We need to enable soft ring functionality on Niagara platforms since
 * one strand can't handle interrupts for a 1Gb NIC. So set the tunable
 * mac_soft_ring_enable by default on this platform.
 * mac_soft_ring_enable variable is defined in space.c and used by MAC
 * module. This tunable in concert with mac_soft_ring_count (declared
 * in mac.h) will configure the number of fanout soft rings for a link.
 */
extern boolean_t mac_soft_ring_enable;
void
startup_platform(void)
{
	mac_soft_ring_enable = B_TRUE;
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
		mutex_cap_factor = 64;
	}
	rw_lock_backoff = default_lock_backoff;
	rw_lock_delay = default_lock_delay;
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
			ctlp->d.hpaddr_base = 0;
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
				ctlp->d.hpaddr_base = 0;
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
				ctlp->d.hpaddr_base = 0;
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
		ctlp->d.hpaddr_base = 0;
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

	if (modload("misc", "dr_io") == -1)
		cmn_err(CE_NOTE, "!'dr_io' module failed to load");

	if (modload("misc", "dr_mem") == -1)
		cmn_err(CE_NOTE, "!'dr_mem' module failed to load");

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

void
set_platform_defaults(void)
{
	/*
	 * Allow at most one context domain per 8 CPUs, which is ample for
	 * good performance.  Do not make this too large, because it
	 * increases the space consumed in the per-process sfmmu structure.
	 */
	if (max_mmu_ctxdoms == 0)
		max_mmu_ctxdoms = (NCPU + 7) / 8;
}
