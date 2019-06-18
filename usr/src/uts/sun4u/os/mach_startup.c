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
 * Copyright (c) 1993, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2019 Peter Tribble.
 */

#include <sys/machsystm.h>
#include <sys/archsystm.h>
#include <sys/vm.h>
#include <sys/cpu.h>
#include <sys/cpupart.h>
#include <sys/cmt.h>
#include <sys/bitset.h>
#include <sys/reboot.h>
#include <sys/kdi.h>
#include <sys/bootconf.h>
#include <sys/memlist_plat.h>
#include <sys/memlist_impl.h>
#include <sys/prom_plat.h>
#include <sys/prom_isa.h>
#include <sys/autoconf.h>
#include <sys/intreg.h>
#include <sys/ivintr.h>
#include <sys/fpu/fpusystm.h>
#include <sys/iommutsb.h>
#include <vm/vm_dep.h>
#include <vm/seg_kmem.h>
#include <vm/seg_kpm.h>
#include <vm/seg_map.h>
#include <vm/seg_kp.h>
#include <sys/sysconf.h>
#include <vm/hat_sfmmu.h>
#include <sys/kobj.h>
#include <sys/sun4asi.h>
#include <sys/clconf.h>
#include <sys/platform_module.h>
#include <sys/panic.h>
#include <sys/cpu_sgnblk_defs.h>
#include <sys/clock.h>
#include <sys/fpras_impl.h>
#include <sys/prom_debug.h>
#include <sys/traptrace.h>
#include <sys/memnode.h>
#include <sys/mem_cage.h>

/*
 * fpRAS implementation structures.
 */
struct fpras_chkfn *fpras_chkfnaddrs[FPRAS_NCOPYOPS];
struct fpras_chkfngrp *fpras_chkfngrps;
struct fpras_chkfngrp *fpras_chkfngrps_base;
int fpras_frequency = -1;
int64_t fpras_interval = -1;

/*
 * Increase unix symbol table size as a work around for 6828121
 */
int alloc_mem_bermuda_triangle;

/*
 * Halt idling cpus optimization
 *
 * This optimation is only enabled in platforms that have
 * the CPU halt support. The cpu_halt_cpu() support is provided
 * in the cpu module and it is referenced here with a pragma weak.
 * The presence of this routine automatically enable the halt idling
 * cpus functionality if the global switch enable_halt_idle_cpus
 * is set (default is set).
 *
 */
#pragma weak	cpu_halt_cpu
extern void	cpu_halt_cpu();

/*
 * Defines for the idle_state_transition DTrace probe
 *
 * The probe fires when the CPU undergoes an idle state change (e.g. halting)
 * The agument passed is the state to which the CPU is transitioning.
 *
 * The states are defined here.
 */
#define	IDLE_STATE_NORMAL 0
#define	IDLE_STATE_HALTED 1

int		enable_halt_idle_cpus = 1; /* global switch */

uint_t cp_haltset_fanout = 3;

void
setup_trap_table(void)
{
	intr_init(CPU);			/* init interrupt request free list */
	setwstate(WSTATE_KERN);
	prom_set_traptable(&trap_table);
}

void
mach_fpras()
{
	if (fpras_implemented && !fpras_disable) {
		int i;
		struct fpras_chkfngrp *fcgp;
		size_t chkfngrpsallocsz;

		/*
		 * Note that we size off of NCPU and setup for
		 * all those possibilities regardless of whether
		 * the cpu id is present or not.  We do this so that
		 * we don't have any construction or destruction
		 * activity to perform at DR time, and it's not
		 * costly in memory.  We require block alignment.
		 */
		chkfngrpsallocsz = NCPU * sizeof (struct fpras_chkfngrp);
		fpras_chkfngrps_base = kmem_alloc(chkfngrpsallocsz, KM_SLEEP);
		if (IS_P2ALIGNED((uintptr_t)fpras_chkfngrps_base, 64)) {
			fpras_chkfngrps = fpras_chkfngrps_base;
		} else {
			kmem_free(fpras_chkfngrps_base, chkfngrpsallocsz);
			chkfngrpsallocsz += 64;
			fpras_chkfngrps_base = kmem_alloc(chkfngrpsallocsz,
			    KM_SLEEP);
			fpras_chkfngrps = (struct fpras_chkfngrp *)
			    P2ROUNDUP((uintptr_t)fpras_chkfngrps_base, 64);
		}

		/*
		 * Copy our check function into place for each copy operation
		 * and each cpu id.
		 */
		fcgp = &fpras_chkfngrps[0];
		for (i = 0; i < FPRAS_NCOPYOPS; ++i)
			bcopy((void *)fpras_chkfn_type1, &fcgp->fpras_fn[i],
			    sizeof (struct fpras_chkfn));
		for (i = 1; i < NCPU; ++i)
			*(&fpras_chkfngrps[i]) = *fcgp;

		/*
		 * At definition fpras_frequency is set to -1, and it will
		 * still have that value unless changed in /etc/system (not
		 * strictly supported, but not preventable).  The following
		 * both sets the default and sanity checks anything from
		 * /etc/system.
		 */
		if (fpras_frequency < 0)
			fpras_frequency = FPRAS_DEFAULT_FREQUENCY;

		/*
		 * Now calculate fpras_interval.  When fpras_interval
		 * becomes non-negative fpras checks will commence
		 * (copies before this point in boot will bypass fpras).
		 * Our stores of instructions must be visible; no need
		 * to flush as they're never been executed before.
		 */
		membar_producer();
		fpras_interval = (fpras_frequency == 0) ?
		    0 : sys_tick_freq / fpras_frequency;
	}
}

void
mach_hw_copy_limit(void)
{
	if (!fpu_exists) {
		use_hw_bcopy = 0;
		hw_copy_limit_1 = 0;
		hw_copy_limit_2 = 0;
		hw_copy_limit_4 = 0;
		hw_copy_limit_8 = 0;
		use_hw_bzero = 0;
	}
}

void
load_tod_module()
{
	/*
	 * Load tod driver module for the tod part found on this system.
	 * Recompute the cpu frequency/delays based on tod as tod part
	 * tends to keep time more accurately.
	 */
	if (tod_module_name == NULL || modload("tod", tod_module_name) == -1)
		halt("Can't load tod module");
}

void
mach_memscrub(void)
{
	/*
	 * Startup memory scrubber, if not running fpu emulation code.
	 */

#ifndef _HW_MEMSCRUB_SUPPORT
	if (fpu_exists) {
		if (memscrub_init()) {
			cmn_err(CE_WARN,
			    "Memory scrubber failed to initialize");
		}
	}
#endif /* _HW_MEMSCRUB_SUPPORT */
}

/*
 * Halt the present CPU until awoken via an interrupt.
 * This routine should only be invoked if cpu_halt_cpu()
 * exists and is supported, see mach_cpu_halt_idle()
 */
void
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
		    uint_t, IDLE_STATE_HALTED);
		(void) cpu_halt_cpu();
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
 * This function should only be invoked if cpu_halt_cpu()
 * exists and is supported, see mach_cpu_halt_idle()
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
	 *
	 * If possible, try to select a CPU close to the target, since this
	 * will likely trigger a migration.
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
		if (&cpu_halt_cpu) {
			idle_cpu = cpu_halt;
			disp_enq_thread = cpu_wakeup;
		}
	}
}

/*ARGSUSED*/
int
cpu_intrq_setup(struct cpu *cp)
{
	/* Interrupt mondo queues not applicable to sun4u */
	return (0);
}

/*ARGSUSED*/
void
cpu_intrq_cleanup(struct cpu *cp)
{
	/* Interrupt mondo queues not applicable to sun4u */
}

/*ARGSUSED*/
void
cpu_intrq_register(struct cpu *cp)
{
	/* Interrupt/error queues not applicable to sun4u */
}

/*ARGSUSED*/
void
mach_htraptrace_setup(int cpuid)
{
	/* Setup hypervisor traptrace buffer, not applicable to sun4u */
}

/*ARGSUSED*/
void
mach_htraptrace_configure(int cpuid)
{
	/* enable/ disable hypervisor traptracing, not applicable to sun4u */
}

/*ARGSUSED*/
void
mach_htraptrace_cleanup(int cpuid)
{
	/* cleanup hypervisor traptrace buffer, not applicable to sun4u */
}

void
mach_descrip_startup_init(void)
{
	/*
	 * Only for sun4v.
	 * Initialize Machine description framework during startup.
	 */
}
void
mach_descrip_startup_fini(void)
{
	/*
	 * Only for sun4v.
	 * Clean up Machine Description framework during startup.
	 */
}

void
mach_descrip_init(void)
{
	/*
	 * Only for sun4v.
	 * Initialize Machine description framework.
	 */
}

void
hsvc_setup(void)
{
	/* Setup hypervisor services, not applicable to sun4u */
}

void
load_mach_drivers(void)
{
	/* Currently no machine class (sun4u) specific drivers to load */
}

/*
 * Find a physically contiguous area of twice the largest ecache size
 * to be used while doing displacement flush of ecaches.
 */
uint64_t
ecache_flush_address(void)
{
	struct memlist *pmem;
	uint64_t flush_size;
	uint64_t ret_val;

	flush_size = ecache_size * 2;
	for (pmem = phys_install; pmem; pmem = pmem->ml_next) {
		ret_val = P2ROUNDUP(pmem->ml_address, ecache_size);
		if (ret_val + flush_size <= pmem->ml_address + pmem->ml_size)
			return (ret_val);
	}
	return ((uint64_t)-1);
}

/*
 * Called with the memlist lock held to say that phys_install has
 * changed.
 */
void
phys_install_has_changed(void)
{
	/*
	 * Get the new address into a temporary just in case panicking
	 * involves use of ecache_flushaddr.
	 */
	uint64_t new_addr;

	new_addr = ecache_flush_address();
	if (new_addr == (uint64_t)-1) {
		cmn_err(CE_PANIC,
		    "ecache_flush_address(): failed, ecache_size=%x",
		    ecache_size);
		/*NOTREACHED*/
	}
	ecache_flushaddr = new_addr;
	membar_producer();
}
