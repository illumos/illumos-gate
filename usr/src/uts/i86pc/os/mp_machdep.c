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

#define	PSMI_1_6
#include <sys/smp_impldefs.h>
#include <sys/psm.h>
#include <sys/psm_modctl.h>
#include <sys/pit.h>
#include <sys/cmn_err.h>
#include <sys/strlog.h>
#include <sys/clock.h>
#include <sys/debug.h>
#include <sys/rtc.h>
#include <sys/x86_archext.h>
#include <sys/cpupart.h>
#include <sys/cpuvar.h>
#include <sys/cmt.h>
#include <sys/cpu.h>
#include <sys/disp.h>
#include <sys/archsystm.h>
#include <sys/machsystm.h>
#include <sys/sysmacros.h>
#include <sys/memlist.h>
#include <sys/param.h>
#include <sys/promif.h>
#if defined(__xpv)
#include <sys/hypervisor.h>
#endif
#include <sys/mach_intr.h>
#include <vm/hat_i86.h>
#include <sys/kdi_machimpl.h>
#include <sys/sdt.h>

#define	OFFSETOF(s, m)		(size_t)(&(((s *)0)->m))

/*
 *	Local function prototypes
 */
static int mp_disable_intr(processorid_t cpun);
static void mp_enable_intr(processorid_t cpun);
static void mach_init();
static void mach_picinit();
static int machhztomhz(uint64_t cpu_freq_hz);
static uint64_t mach_getcpufreq(void);
static void mach_fixcpufreq(void);
static int mach_clkinit(int, int *);
static void mach_smpinit(void);
static int mach_softlvl_to_vect(int ipl);
static void mach_get_platform(int owner);
static void mach_construct_info();
static int mach_translate_irq(dev_info_t *dip, int irqno);
static int mach_intr_ops(dev_info_t *, ddi_intr_handle_impl_t *,
    psm_intr_op_t, int *);
static void mach_notify_error(int level, char *errmsg);
static hrtime_t dummy_hrtime(void);
static void dummy_scalehrtime(hrtime_t *);
static void cpu_idle(void);
static void cpu_wakeup(cpu_t *, int);
#ifndef __xpv
static void cpu_idle_mwait(void);
static void cpu_wakeup_mwait(cpu_t *, int);
#endif
/*
 *	External reference functions
 */
extern void return_instr();
extern uint64_t freq_tsc(uint32_t *);
#if defined(__i386)
extern uint64_t freq_notsc(uint32_t *);
#endif
extern void pc_gethrestime(timestruc_t *);
extern int cpuid_get_coreid(cpu_t *);
extern int cpuid_get_chipid(cpu_t *);

/*
 *	PSM functions initialization
 */
void (*psm_shutdownf)(int, int)	= (void (*)(int, int))return_instr;
void (*psm_preshutdownf)(int, int) = (void (*)(int, int))return_instr;
void (*psm_notifyf)(int)	= (void (*)(int))return_instr;
void (*psm_set_idle_cpuf)(int)	= (void (*)(int))return_instr;
void (*psm_unset_idle_cpuf)(int) = (void (*)(int))return_instr;
void (*psminitf)()		= mach_init;
void (*picinitf)() 		= return_instr;
int (*clkinitf)(int, int *) 	= (int (*)(int, int *))return_instr;
int (*ap_mlsetup)() 		= (int (*)(void))return_instr;
void (*send_dirintf)() 		= return_instr;
void (*setspl)(int)		= (void (*)(int))return_instr;
int (*addspl)(int, int, int, int) = (int (*)(int, int, int, int))return_instr;
int (*delspl)(int, int, int, int) = (int (*)(int, int, int, int))return_instr;
void (*kdisetsoftint)(int, struct av_softinfo *)=
	(void (*)(int, struct av_softinfo *))return_instr;
void (*setsoftint)(int, struct av_softinfo *)=
	(void (*)(int, struct av_softinfo *))return_instr;
int (*slvltovect)(int)		= (int (*)(int))return_instr;
int (*setlvl)(int, int *)	= (int (*)(int, int *))return_instr;
void (*setlvlx)(int, int)	= (void (*)(int, int))return_instr;
int (*psm_disable_intr)(int)	= mp_disable_intr;
void (*psm_enable_intr)(int)	= mp_enable_intr;
hrtime_t (*gethrtimef)(void)	= dummy_hrtime;
hrtime_t (*gethrtimeunscaledf)(void)	= dummy_hrtime;
void (*scalehrtimef)(hrtime_t *)	= dummy_scalehrtime;
int (*psm_translate_irq)(dev_info_t *, int) = mach_translate_irq;
void (*gethrestimef)(timestruc_t *) = pc_gethrestime;
void (*psm_notify_error)(int, char *) = (void (*)(int, char *))NULL;
int (*psm_get_clockirq)(int) = NULL;
int (*psm_get_ipivect)(int, int) = NULL;

int (*psm_clkinit)(int) = NULL;
void (*psm_timer_reprogram)(hrtime_t) = NULL;
void (*psm_timer_enable)(void) = NULL;
void (*psm_timer_disable)(void) = NULL;
void (*psm_post_cyclic_setup)(void *arg) = NULL;
int (*psm_intr_ops)(dev_info_t *, ddi_intr_handle_impl_t *, psm_intr_op_t,
    int *) = mach_intr_ops;
int (*psm_state)(psm_state_request_t *) = (int (*)(psm_state_request_t *))
    return_instr;

void (*notify_error)(int, char *) = (void (*)(int, char *))return_instr;
void (*hrtime_tick)(void)	= return_instr;

/*
 * True if the generic TSC code is our source of hrtime, rather than whatever
 * the PSM can provide.
 */
#ifdef __xpv
int tsc_gethrtime_enable = 0;
#else
int tsc_gethrtime_enable = 1;
#endif
int tsc_gethrtime_initted = 0;

/*
 * True if the hrtime implementation is "hires"; namely, better than microdata.
 */
int gethrtime_hires = 0;

/*
 * Local Static Data
 */
static struct psm_ops mach_ops;
static struct psm_ops *mach_set[4] = {&mach_ops, NULL, NULL, NULL};
static ushort_t mach_ver[4] = {0, 0, 0, 0};

/*
 * If non-zero, idle cpus will become "halted" when there's
 * no work to do.
 */
int	idle_cpu_use_hlt = 1;

#ifndef __xpv
/*
 * If non-zero, idle cpus will use mwait if available to halt instead of hlt.
 */
int	idle_cpu_prefer_mwait = 1;
#endif

/*ARGSUSED*/
int
pg_plat_hw_shared(cpu_t *cp, pghw_type_t hw)
{
	switch (hw) {
	case PGHW_IPIPE:
		if (x86_feature & (X86_HTT)) {
			/*
			 * Hyper-threading is SMT
			 */
			return (1);
		} else {
			return (0);
		}
	case PGHW_CHIP:
		if (x86_feature & (X86_CMP|X86_HTT))
			return (1);
		else
			return (0);
	case PGHW_CACHE:
		if (cpuid_get_ncpu_sharing_last_cache(cp) > 1)
			return (1);
		else
			return (0);
	default:
		return (0);
	}
}

/*
 * Compare two CPUs and see if they have a pghw_type_t sharing relationship
 * If pghw_type_t is an unsupported hardware type, then return -1
 */
int
pg_plat_cpus_share(cpu_t *cpu_a, cpu_t *cpu_b, pghw_type_t hw)
{
	id_t pgp_a, pgp_b;

	pgp_a = pg_plat_hw_instance_id(cpu_a, hw);
	pgp_b = pg_plat_hw_instance_id(cpu_b, hw);

	if (pgp_a == -1 || pgp_b == -1)
		return (-1);

	return (pgp_a == pgp_b);
}

/*
 * Return a physical instance identifier for known hardware sharing
 * relationships
 */
id_t
pg_plat_hw_instance_id(cpu_t *cpu, pghw_type_t hw)
{
	switch (hw) {
	case PGHW_IPIPE:
		return (cpuid_get_coreid(cpu));
	case PGHW_CACHE:
		return (cpuid_get_last_lvl_cacheid(cpu));
	case PGHW_CHIP:
		return (cpuid_get_chipid(cpu));
	default:
		return (-1);
	}
}

int
pg_plat_hw_level(pghw_type_t hw)
{
	int i;
	static pghw_type_t hw_hier[] = {
		PGHW_IPIPE,
		PGHW_CACHE,
		PGHW_CHIP,
		PGHW_NUM_COMPONENTS
	};

	for (i = 0; hw_hier[i] != PGHW_NUM_COMPONENTS; i++) {
		if (hw_hier[i] == hw)
			return (i);
	}
	return (-1);
}

/*
 * Return 1 if CMT load balancing policies should be
 * implemented across instances of the specified hardware
 * sharing relationship.
 */
int
pg_plat_cmt_load_bal_hw(pghw_type_t hw)
{
	if (hw == PGHW_IPIPE ||
	    hw == PGHW_FPU ||
	    hw == PGHW_CHIP ||
	    hw == PGHW_CACHE)
		return (1);
	else
		return (0);
}


/*
 * Return 1 if thread affinity polices should be implemented
 * for instances of the specifed hardware sharing relationship.
 */
int
pg_plat_cmt_affinity_hw(pghw_type_t hw)
{
	if (hw == PGHW_CACHE)
		return (1);
	else
		return (0);
}

id_t
pg_plat_get_core_id(cpu_t *cpu)
{
	return ((id_t)cpuid_get_coreid(cpu));
}

void
cmp_set_nosteal_interval(void)
{
	/* Set the nosteal interval (used by disp_getbest()) to 100us */
	nosteal_nsec = 100000UL;
}

/*
 * Routine to ensure initial callers to hrtime gets 0 as return
 */
static hrtime_t
dummy_hrtime(void)
{
	return (0);
}

/* ARGSUSED */
static void
dummy_scalehrtime(hrtime_t *ticks)
{}

/*
 * Idle the present CPU until awoken via an interrupt
 */
static void
cpu_idle(void)
{
	cpu_t		*cpup = CPU;
	processorid_t	cpun = cpup->cpu_id;
	cpupart_t	*cp = cpup->cpu_part;
	int		hset_update = 1;

	/*
	 * If this CPU is online, and there's multiple CPUs
	 * in the system, then we should notate our halting
	 * by adding ourselves to the partition's halted CPU
	 * bitmap. This allows other CPUs to find/awaken us when
	 * work becomes available.
	 */
	if (cpup->cpu_flags & CPU_OFFLINE || ncpus == 1)
		hset_update = 0;

	/*
	 * Add ourselves to the partition's halted CPUs bitmask
	 * and set our HALTED flag, if necessary.
	 *
	 * When a thread becomes runnable, it is placed on the queue
	 * and then the halted cpuset is checked to determine who
	 * (if anyone) should be awoken. We therefore need to first
	 * add ourselves to the halted cpuset, and and then check if there
	 * is any work available.
	 *
	 * Note that memory barriers after updating the HALTED flag
	 * are not necessary since an atomic operation (updating the bitmap)
	 * immediately follows. On x86 the atomic operation acts as a
	 * memory barrier for the update of cpu_disp_flags.
	 */
	if (hset_update) {
		cpup->cpu_disp_flags |= CPU_DISP_HALTED;
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
	 * We're on our way to being halted.
	 *
	 * Disable interrupts now, so that we'll awaken immediately
	 * after halting if someone tries to poke us between now and
	 * the time we actually halt.
	 *
	 * We check for the presence of our bit after disabling interrupts.
	 * If it's cleared, we'll return. If the bit is cleared after
	 * we check then the poke will pop us out of the halted state.
	 *
	 * This means that the ordering of the poke and the clearing
	 * of the bit by cpu_wakeup is important.
	 * cpu_wakeup() must clear, then poke.
	 * cpu_idle() must disable interrupts, then check for the bit.
	 */
	cli();

	if (hset_update && !CPU_IN_SET(cp->cp_mach->mc_haltset, cpun)) {
		cpup->cpu_disp_flags &= ~CPU_DISP_HALTED;
		sti();
		return;
	}

	/*
	 * The check for anything locally runnable is here for performance
	 * and isn't needed for correctness. disp_nrunnable ought to be
	 * in our cache still, so it's inexpensive to check, and if there
	 * is anything runnable we won't have to wait for the poke.
	 */
	if (cpup->cpu_disp->disp_nrunnable != 0) {
		if (hset_update) {
			cpup->cpu_disp_flags &= ~CPU_DISP_HALTED;
			CPUSET_ATOMIC_DEL(cp->cp_mach->mc_haltset, cpun);
		}
		sti();
		return;
	}

	mach_cpu_idle();

	/*
	 * We're no longer halted
	 */
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
		 * before we had a chance to clear our bit in cpu_idle().
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

#ifndef __xpv
/*
 * Idle the present CPU until awoken via touching its monitored line
 */
static void
cpu_idle_mwait(void)
{
	volatile uint32_t	*mcpu_mwait = CPU->cpu_m.mcpu_mwait;
	cpu_t			*cpup = CPU;
	processorid_t		cpun = cpup->cpu_id;
	cpupart_t		*cp = cpup->cpu_part;
	int			hset_update = 1;

	/*
	 * Set our mcpu_mwait here, so we can tell if anyone trys to
	 * wake us between now and when we call mwait.  No other cpu will
	 * attempt to set our mcpu_mwait until we add ourself to the haltset.
	 */
	*mcpu_mwait = MWAIT_HALTED;

	/*
	 * If this CPU is online, and there's multiple CPUs
	 * in the system, then we should notate our halting
	 * by adding ourselves to the partition's halted CPU
	 * bitmap. This allows other CPUs to find/awaken us when
	 * work becomes available.
	 */
	if (cpup->cpu_flags & CPU_OFFLINE || ncpus == 1)
		hset_update = 0;

	/*
	 * Add ourselves to the partition's halted CPUs bitmask
	 * and set our HALTED flag, if necessary.
	 *
	 * When a thread becomes runnable, it is placed on the queue
	 * and then the halted cpuset is checked to determine who
	 * (if anyone) should be awoken. We therefore need to first
	 * add ourselves to the halted cpuset, and and then check if there
	 * is any work available.
	 *
	 * Note that memory barriers after updating the HALTED flag
	 * are not necessary since an atomic operation (updating the bitmap)
	 * immediately follows. On x86 the atomic operation acts as a
	 * memory barrier for the update of cpu_disp_flags.
	 */
	if (hset_update) {
		cpup->cpu_disp_flags |= CPU_DISP_HALTED;
		CPUSET_ATOMIC_ADD(cp->cp_mach->mc_haltset, cpun);
	}

	/*
	 * Check to make sure there's really nothing to do.
	 * Work destined for this CPU may become available after
	 * this check. We'll be notified through the clearing of our
	 * bit in the halted CPU bitmask, and a write to our mcpu_mwait.
	 *
	 * disp_anywork() checks disp_nrunnable, so we do not have to later.
	 */
	if (disp_anywork()) {
		if (hset_update) {
			cpup->cpu_disp_flags &= ~CPU_DISP_HALTED;
			CPUSET_ATOMIC_DEL(cp->cp_mach->mc_haltset, cpun);
		}
		return;
	}

	/*
	 * We're on our way to being halted.
	 * To avoid a lost wakeup, arm the monitor before checking if another
	 * cpu wrote to mcpu_mwait to wake us up.
	 */
	i86_monitor(mcpu_mwait, 0, 0);
	if (*mcpu_mwait == MWAIT_HALTED) {
		DTRACE_PROBE1(idle__state__transition, uint_t, IDLE_STATE_C1);

		tlb_going_idle();
		i86_mwait(0, 0);
		tlb_service();

		DTRACE_PROBE1(idle__state__transition, uint_t, IDLE_STATE_C0);
	}

	/*
	 * We're no longer halted
	 */
	if (hset_update) {
		cpup->cpu_disp_flags &= ~CPU_DISP_HALTED;
		CPUSET_ATOMIC_DEL(cp->cp_mach->mc_haltset, cpun);
	}
}

/*
 * If "cpu" is halted in mwait, then wake it up clearing its halted bit in
 * advance.  Otherwise, see if other CPUs in the cpu partition are halted and
 * need to be woken up so that they can steal the thread we placed on this CPU.
 * This function is only used on MP systems.
 */
static void
cpu_wakeup_mwait(cpu_t *cp, int bound)
{
	cpupart_t	*cpu_part;
	uint_t		cpu_found;
	int		result;

	cpu_part = cp->cpu_part;

	/*
	 * Clear the halted bit for that CPU since it will be woken up
	 * in a moment.
	 */
	if (CPU_IN_SET(cpu_part->cp_mach->mc_haltset, cp->cpu_id)) {
		/*
		 * Clear the halted bit for that CPU since it will be
		 * poked in a moment.
		 */
		CPUSET_ATOMIC_DEL(cpu_part->cp_mach->mc_haltset, cp->cpu_id);
		/*
		 * We may find the current CPU present in the halted cpuset
		 * if we're in the context of an interrupt that occurred
		 * before we had a chance to clear our bit in cpu_idle().
		 * Waking ourself is obviously unnecessary, since if
		 * we're here, we're not halted.
		 *
		 * monitor/mwait wakeup via writing to our cache line is
		 * harmless and less expensive than always checking if we
		 * are waking ourself which is an uncommon case.
		 */
		MWAIT_WAKEUP(cp);	/* write to monitored line */
		return;
	} else {
		/*
		 * This cpu isn't halted, but it's idle or undergoing a
		 * context switch. No need to awaken anyone else.
		 */
		if (cp->cpu_thread == cp->cpu_idle_thread ||
		    cp->cpu_disp_flags & CPU_DISP_DONTSTEAL)
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
		CPUSET_FIND(cpu_part->cp_mach->mc_haltset, cpu_found);
		if (cpu_found == CPUSET_NOTINSET)
			return;

		ASSERT(cpu_found >= 0 && cpu_found < NCPU);
		CPUSET_ATOMIC_XDEL(cpu_part->cp_mach->mc_haltset, cpu_found,
		    result);
	} while (result < 0);

	/*
	 * Do not check if cpu_found is ourself as monitor/mwait wakeup is
	 * cheap.
	 */
	MWAIT_WAKEUP(cpu[cpu_found]);	/* write to monitored line */
}
#endif

void (*cpu_pause_handler)(volatile char *) = NULL;

static int
mp_disable_intr(int cpun)
{
	/*
	 * switch to the offline cpu
	 */
	affinity_set(cpun);
	/*
	 * raise ipl to just below cross call
	 */
	splx(XC_MED_PIL-1);
	/*
	 *	set base spl to prevent the next swtch to idle from
	 *	lowering back to ipl 0
	 */
	CPU->cpu_intr_actv |= (1 << (XC_MED_PIL-1));
	set_base_spl();
	affinity_clear();
	return (DDI_SUCCESS);
}

static void
mp_enable_intr(int cpun)
{
	/*
	 * switch to the online cpu
	 */
	affinity_set(cpun);
	/*
	 * clear the interrupt active mask
	 */
	CPU->cpu_intr_actv &= ~(1 << (XC_MED_PIL-1));
	set_base_spl();
	(void) spl0();
	affinity_clear();
}

static void
mach_get_platform(int owner)
{
	void		**srv_opsp;
	void		**clt_opsp;
	int		i;
	int		total_ops;

	/* fix up psm ops */
	srv_opsp = (void **)mach_set[0];
	clt_opsp = (void **)mach_set[owner];
	if (mach_ver[owner] == (ushort_t)PSM_INFO_VER01)
		total_ops = sizeof (struct psm_ops_ver01) /
		    sizeof (void (*)(void));
	else if (mach_ver[owner] == (ushort_t)PSM_INFO_VER01_1)
		/* no psm_notify_func */
		total_ops = OFFSETOF(struct psm_ops, psm_notify_func) /
		    sizeof (void (*)(void));
	else if (mach_ver[owner] == (ushort_t)PSM_INFO_VER01_2)
		/* no psm_timer funcs */
		total_ops = OFFSETOF(struct psm_ops, psm_timer_reprogram) /
		    sizeof (void (*)(void));
	else if (mach_ver[owner] == (ushort_t)PSM_INFO_VER01_3)
		/* no psm_preshutdown function */
		total_ops = OFFSETOF(struct psm_ops, psm_preshutdown) /
		    sizeof (void (*)(void));
	else if (mach_ver[owner] == (ushort_t)PSM_INFO_VER01_4)
		/* no psm_preshutdown function */
		total_ops = OFFSETOF(struct psm_ops, psm_intr_ops) /
		    sizeof (void (*)(void));
	else
		total_ops = sizeof (struct psm_ops) / sizeof (void (*)(void));

	/*
	 * Save the version of the PSM module, in case we need to
	 * bahave differently based on version.
	 */
	mach_ver[0] = mach_ver[owner];

	for (i = 0; i < total_ops; i++)
		if (clt_opsp[i] != NULL)
			srv_opsp[i] = clt_opsp[i];
}

static void
mach_construct_info()
{
	struct psm_sw *swp;
	int	mach_cnt[PSM_OWN_OVERRIDE+1] = {0};
	int	conflict_owner = 0;

	if (psmsw->psw_forw == psmsw)
		panic("No valid PSM modules found");
	mutex_enter(&psmsw_lock);
	for (swp = psmsw->psw_forw; swp != psmsw; swp = swp->psw_forw) {
		if (!(swp->psw_flag & PSM_MOD_IDENTIFY))
			continue;
		mach_set[swp->psw_infop->p_owner] = swp->psw_infop->p_ops;
		mach_ver[swp->psw_infop->p_owner] = swp->psw_infop->p_version;
		mach_cnt[swp->psw_infop->p_owner]++;
	}
	mutex_exit(&psmsw_lock);

	mach_get_platform(PSM_OWN_SYS_DEFAULT);

	/* check to see are there any conflicts */
	if (mach_cnt[PSM_OWN_EXCLUSIVE] > 1)
		conflict_owner = PSM_OWN_EXCLUSIVE;
	if (mach_cnt[PSM_OWN_OVERRIDE] > 1)
		conflict_owner = PSM_OWN_OVERRIDE;
	if (conflict_owner) {
		/* remove all psm modules except uppc */
		cmn_err(CE_WARN,
		    "Conflicts detected on the following PSM modules:");
		mutex_enter(&psmsw_lock);
		for (swp = psmsw->psw_forw; swp != psmsw; swp = swp->psw_forw) {
			if (swp->psw_infop->p_owner == conflict_owner)
				cmn_err(CE_WARN, "%s ",
				    swp->psw_infop->p_mach_idstring);
		}
		mutex_exit(&psmsw_lock);
		cmn_err(CE_WARN,
		    "Setting the system back to SINGLE processor mode!");
		cmn_err(CE_WARN,
		    "Please edit /etc/mach to remove the invalid PSM module.");
		return;
	}

	if (mach_set[PSM_OWN_EXCLUSIVE])
		mach_get_platform(PSM_OWN_EXCLUSIVE);

	if (mach_set[PSM_OWN_OVERRIDE])
		mach_get_platform(PSM_OWN_OVERRIDE);
}

static void
mach_init()
{
	struct psm_ops  *pops;

	mach_construct_info();

	pops = mach_set[0];

	/* register the interrupt and clock initialization rotuines */
	picinitf = mach_picinit;
	clkinitf = mach_clkinit;
	psm_get_clockirq = pops->psm_get_clockirq;

	/* register the interrupt setup code */
	slvltovect = mach_softlvl_to_vect;
	addspl	= pops->psm_addspl;
	delspl	= pops->psm_delspl;

	if (pops->psm_translate_irq)
		psm_translate_irq = pops->psm_translate_irq;
	if (pops->psm_intr_ops)
		psm_intr_ops = pops->psm_intr_ops;

#if defined(PSMI_1_2) || defined(PSMI_1_3) || defined(PSMI_1_4)
	/*
	 * Time-of-day functionality now handled in TOD modules.
	 * (Warn about PSM modules that think that we're going to use
	 * their ops vectors.)
	 */
	if (pops->psm_tod_get)
		cmn_err(CE_WARN, "obsolete psm_tod_get op %p",
		    (void *)pops->psm_tod_get);

	if (pops->psm_tod_set)
		cmn_err(CE_WARN, "obsolete psm_tod_set op %p",
		    (void *)pops->psm_tod_set);
#endif

	if (pops->psm_notify_error) {
		psm_notify_error = mach_notify_error;
		notify_error = pops->psm_notify_error;
	}

	(*pops->psm_softinit)();

	/*
	 * Initialize the dispatcher's function hooks
	 * to enable CPU halting when idle.
	 * Do not use monitor/mwait if idle_cpu_use_hlt is not set(spin idle)
	 * or idle_cpu_prefer_mwait is not set.
	 * Allocate monitor/mwait buffer for cpu0.
	 */
	if (idle_cpu_use_hlt) {
		idle_cpu = cpu_idle;
#ifndef __xpv
		if ((x86_feature & X86_MWAIT) && idle_cpu_prefer_mwait) {
			CPU->cpu_m.mcpu_mwait = cpuid_mwait_alloc(CPU);
			/*
			 * Protect ourself from insane mwait size.
			 */
			if (CPU->cpu_m.mcpu_mwait == NULL) {
#ifdef DEBUG
				cmn_err(CE_NOTE, "Using hlt idle.  Cannot "
				    "handle cpu 0 mwait size.");
#endif
				idle_cpu_prefer_mwait = 0;
				idle_cpu = cpu_idle;
			} else {
				idle_cpu = cpu_idle_mwait;
			}
		} else {
			idle_cpu = cpu_idle;
		}
#endif
	}

	mach_smpinit();
}

static void
mach_smpinit(void)
{
	struct psm_ops  *pops;
	processorid_t cpu_id;
	int cnt;
	cpuset_t cpumask;

	pops = mach_set[0];

	cpu_id = -1;
	cpu_id = (*pops->psm_get_next_processorid)(cpu_id);
	for (cnt = 0, CPUSET_ZERO(cpumask); cpu_id != -1; cnt++) {
		CPUSET_ADD(cpumask, cpu_id);
		cpu_id = (*pops->psm_get_next_processorid)(cpu_id);
	}

	mp_cpus = cpumask;

	/* MP related routines */
	ap_mlsetup = pops->psm_post_cpu_start;
	send_dirintf = pops->psm_send_ipi;

	/* optional MP related routines */
	if (pops->psm_shutdown)
		psm_shutdownf = pops->psm_shutdown;
	if (pops->psm_preshutdown)
		psm_preshutdownf = pops->psm_preshutdown;
	if (pops->psm_notify_func)
		psm_notifyf = pops->psm_notify_func;
	if (pops->psm_set_idlecpu)
		psm_set_idle_cpuf = pops->psm_set_idlecpu;
	if (pops->psm_unset_idlecpu)
		psm_unset_idle_cpuf = pops->psm_unset_idlecpu;

	psm_clkinit = pops->psm_clkinit;

	if (pops->psm_timer_reprogram)
		psm_timer_reprogram = pops->psm_timer_reprogram;

	if (pops->psm_timer_enable)
		psm_timer_enable = pops->psm_timer_enable;

	if (pops->psm_timer_disable)
		psm_timer_disable = pops->psm_timer_disable;

	if (pops->psm_post_cyclic_setup)
		psm_post_cyclic_setup = pops->psm_post_cyclic_setup;

	if (pops->psm_state)
		psm_state = pops->psm_state;

	/* check for multiple cpu's */
	if (cnt < 2)
		return;

	/* check for MP platforms */
	if (pops->psm_cpu_start == NULL)
		return;

	/*
	 * Set the dispatcher hook to enable cpu "wake up"
	 * when a thread becomes runnable.
	 */
	if (idle_cpu_use_hlt) {
		disp_enq_thread = cpu_wakeup;
#ifndef __xpv
		if ((x86_feature & X86_MWAIT) && idle_cpu_prefer_mwait)
			disp_enq_thread = cpu_wakeup_mwait;
#endif
	}

	if (pops->psm_disable_intr)
		psm_disable_intr = pops->psm_disable_intr;
	if (pops->psm_enable_intr)
		psm_enable_intr  = pops->psm_enable_intr;

	psm_get_ipivect = pops->psm_get_ipivect;

	(void) add_avintr((void *)NULL, XC_HI_PIL, xc_serv, "xc_hi_intr",
	    (*pops->psm_get_ipivect)(XC_HI_PIL, PSM_INTR_IPI_HI),
	    (caddr_t)X_CALL_HIPRI, NULL, NULL, NULL);
	(void) add_avintr((void *)NULL, XC_MED_PIL, xc_serv, "xc_med_intr",
	    (*pops->psm_get_ipivect)(XC_MED_PIL, PSM_INTR_IPI_LO),
	    (caddr_t)X_CALL_MEDPRI, NULL, NULL, NULL);

	(void) (*pops->psm_get_ipivect)(XC_CPUPOKE_PIL, PSM_INTR_POKE);
}

static void
mach_picinit()
{
	struct psm_ops  *pops;

	pops = mach_set[0];

	/* register the interrupt handlers */
	setlvl = pops->psm_intr_enter;
	setlvlx = pops->psm_intr_exit;

	/* initialize the interrupt hardware */
	(*pops->psm_picinit)();

	/* set interrupt mask for current ipl */
	setspl = pops->psm_setspl;
	cli();
	setspl(CPU->cpu_pri);
}

uint_t	cpu_freq;	/* MHz */
uint64_t cpu_freq_hz;	/* measured (in hertz) */

#define	MEGA_HZ		1000000

#ifdef __xpv

int xpv_cpufreq_workaround = 1;
int xpv_cpufreq_verbose = 0;

#else	/* __xpv */

static uint64_t
mach_calchz(uint32_t pit_counter, uint64_t *processor_clks)
{
	uint64_t cpu_hz;

	if ((pit_counter == 0) || (*processor_clks == 0) ||
	    (*processor_clks > (((uint64_t)-1) / PIT_HZ)))
		return (0);

	cpu_hz = ((uint64_t)PIT_HZ * *processor_clks) / pit_counter;

	return (cpu_hz);
}

#endif	/* __xpv */

static uint64_t
mach_getcpufreq(void)
{
#if defined(__xpv)
	vcpu_time_info_t *vti = &CPU->cpu_m.mcpu_vcpu_info->time;
	uint64_t cpu_hz;

	/*
	 * During dom0 bringup, it was noted that on at least one older
	 * Intel HT machine, the hypervisor initially gives a tsc_to_system_mul
	 * value that is quite wrong (the 3.06GHz clock was reported
	 * as 4.77GHz)
	 *
	 * The curious thing is, that if you stop the kernel at entry,
	 * breakpoint here and inspect the value with kmdb, the value
	 * is correct - but if you don't stop and simply enable the
	 * printf statement (below), you can see the bad value printed
	 * here.  Almost as if something kmdb did caused the hypervisor to
	 * figure it out correctly.  And, note that the hypervisor
	 * eventually -does- figure it out correctly ... if you look at
	 * the field later in the life of dom0, it is correct.
	 *
	 * For now, on dom0, we employ a slightly cheesy workaround of
	 * using the DOM0_PHYSINFO hypercall.
	 */
	if (DOMAIN_IS_INITDOMAIN(xen_info) && xpv_cpufreq_workaround) {
		xen_sysctl_t op0, *op = &op0;

		op->cmd = XEN_SYSCTL_physinfo;
		op->interface_version = XEN_SYSCTL_INTERFACE_VERSION;
		if (HYPERVISOR_sysctl(op) != 0)
			panic("physinfo op refused");

		cpu_hz = 1000 * (uint64_t)op->u.physinfo.cpu_khz;
	} else {
		cpu_hz = (UINT64_C(1000000000) << 32) / vti->tsc_to_system_mul;

		if (vti->tsc_shift < 0)
			cpu_hz <<= -vti->tsc_shift;
		else
			cpu_hz >>= vti->tsc_shift;
	}

	if (xpv_cpufreq_verbose)
		printf("mach_getcpufreq: system_mul 0x%x, shift %d, "
		    "cpu_hz %" PRId64 "Hz\n",
		    vti->tsc_to_system_mul, vti->tsc_shift, cpu_hz);

	return (cpu_hz);
#else	/* __xpv */
	uint32_t pit_counter;
	uint64_t processor_clks;

	if (x86_feature & X86_TSC) {
		/*
		 * We have a TSC. freq_tsc() knows how to measure the number
		 * of clock cycles sampled against the PIT.
		 */
		ulong_t flags = clear_int_flag();
		processor_clks = freq_tsc(&pit_counter);
		restore_int_flag(flags);
		return (mach_calchz(pit_counter, &processor_clks));
	} else if (x86_vendor == X86_VENDOR_Cyrix || x86_type == X86_TYPE_P5) {
#if defined(__amd64)
		panic("mach_getcpufreq: no TSC!");
#elif defined(__i386)
		/*
		 * We are a Cyrix based on a 6x86 core or an Intel Pentium
		 * for which freq_notsc() knows how to measure the number of
		 * elapsed clock cycles sampled against the PIT
		 */
		ulong_t flags = clear_int_flag();
		processor_clks = freq_notsc(&pit_counter);
		restore_int_flag(flags);
		return (mach_calchz(pit_counter, &processor_clks));
#endif	/* __i386 */
	}

	/* We do not know how to calculate cpu frequency for this cpu. */
	return (0);
#endif	/* __xpv */
}

/*
 * If the clock speed of a cpu is found to be reported incorrectly, do not add
 * to this array, instead improve the accuracy of the algorithm that determines
 * the clock speed of the processor or extend the implementation to support the
 * vendor as appropriate. This is here only to support adjusting the speed on
 * older slower processors that mach_fixcpufreq() would not be able to account
 * for otherwise.
 */
static int x86_cpu_freq[] = { 60, 75, 80, 90, 120, 160, 166, 175, 180, 233 };

/*
 * On fast processors the clock frequency that is measured may be off by
 * a few MHz from the value printed on the part. This is a combination of
 * the factors that for such fast parts being off by this much is within
 * the tolerances for manufacture and because of the difficulties in the
 * measurement that can lead to small error. This function uses some
 * heuristics in order to tweak the value that was measured to match what
 * is most likely printed on the part.
 *
 * Some examples:
 * 	AMD Athlon 1000 mhz measured as 998 mhz
 * 	Intel Pentium III Xeon 733 mhz measured as 731 mhz
 * 	Intel Pentium IV 1500 mhz measured as 1495mhz
 *
 * If in the future this function is no longer sufficient to correct
 * for the error in the measurement, then the algorithm used to perform
 * the measurement will have to be improved in order to increase accuracy
 * rather than adding horrible and questionable kludges here.
 *
 * This is called after the cyclics subsystem because of the potential
 * that the heuristics within may give a worse estimate of the clock
 * frequency than the value that was measured.
 */
static void
mach_fixcpufreq(void)
{
	uint32_t freq, mul, near66, delta66, near50, delta50, fixed, delta, i;

	freq = (uint32_t)cpu_freq;

	/*
	 * Find the nearest integer multiple of 200/3 (about 66) MHz to the
	 * measured speed taking into account that the 667 MHz parts were
	 * the first to round-up.
	 */
	mul = (uint32_t)((3 * (uint64_t)freq + 100) / 200);
	near66 = (uint32_t)((200 * (uint64_t)mul + ((mul >= 10) ? 1 : 0)) / 3);
	delta66 = (near66 > freq) ? (near66 - freq) : (freq - near66);

	/* Find the nearest integer multiple of 50 MHz to the measured speed */
	mul = (freq + 25) / 50;
	near50 = mul * 50;
	delta50 = (near50 > freq) ? (near50 - freq) : (freq - near50);

	/* Find the closer of the two */
	if (delta66 < delta50) {
		fixed = near66;
		delta = delta66;
	} else {
		fixed = near50;
		delta = delta50;
	}

	if (fixed > INT_MAX)
		return;

	/*
	 * Some older parts have a core clock frequency that is not an
	 * integral multiple of 50 or 66 MHz. Check if one of the old
	 * clock frequencies is closer to the measured value than any
	 * of the integral multiples of 50 an 66, and if so set fixed
	 * and delta appropriately to represent the closest value.
	 */
	i = sizeof (x86_cpu_freq) / sizeof (int);
	while (i > 0) {
		i--;

		if (x86_cpu_freq[i] <= freq) {
			mul = freq - x86_cpu_freq[i];

			if (mul < delta) {
				fixed = x86_cpu_freq[i];
				delta = mul;
			}

			break;
		}

		mul = x86_cpu_freq[i] - freq;

		if (mul < delta) {
			fixed = x86_cpu_freq[i];
			delta = mul;
		}
	}

	/*
	 * Set a reasonable maximum for how much to correct the measured
	 * result by. This check is here to prevent the adjustment made
	 * by this function from being more harm than good. It is entirely
	 * possible that in the future parts will be made that are not
	 * integral multiples of 66 or 50 in clock frequency or that
	 * someone may overclock a part to some odd frequency. If the
	 * measured value is farther from the corrected value than
	 * allowed, then assume the corrected value is in error and use
	 * the measured value.
	 */
	if (6 < delta)
		return;

	cpu_freq = (int)fixed;
}


static int
machhztomhz(uint64_t cpu_freq_hz)
{
	uint64_t cpu_mhz;

	/* Round to nearest MHZ */
	cpu_mhz = (cpu_freq_hz + (MEGA_HZ / 2)) / MEGA_HZ;

	if (cpu_mhz > INT_MAX)
		return (0);

	return ((int)cpu_mhz);

}


static int
mach_clkinit(int preferred_mode, int *set_mode)
{
	struct psm_ops  *pops;
	int resolution;

	pops = mach_set[0];

	cpu_freq_hz = mach_getcpufreq();

	cpu_freq = machhztomhz(cpu_freq_hz);

	if (!(x86_feature & X86_TSC) || (cpu_freq == 0))
		tsc_gethrtime_enable = 0;

#ifndef __xpv
	if (tsc_gethrtime_enable) {
		tsc_hrtimeinit(cpu_freq_hz);
	} else
#endif
	{
		if (pops->psm_hrtimeinit)
			(*pops->psm_hrtimeinit)();
		gethrtimef = pops->psm_gethrtime;
		gethrtimeunscaledf = gethrtimef;
		/* scalehrtimef will remain dummy */
	}

	mach_fixcpufreq();

	if (mach_ver[0] >= PSM_INFO_VER01_3) {
		if (preferred_mode == TIMER_ONESHOT) {

			resolution = (*pops->psm_clkinit)(0);
			if (resolution != 0)  {
				*set_mode = TIMER_ONESHOT;
				return (resolution);
			}
		}

		/*
		 * either periodic mode was requested or could not set to
		 * one-shot mode
		 */
		resolution = (*pops->psm_clkinit)(hz);
		/*
		 * psm should be able to do periodic, so we do not check
		 * for return value of psm_clkinit here.
		 */
		*set_mode = TIMER_PERIODIC;
		return (resolution);
	} else {
		/*
		 * PSMI interface prior to PSMI_3 does not define a return
		 * value for psm_clkinit, so the return value is ignored.
		 */
		(void) (*pops->psm_clkinit)(hz);
		*set_mode = TIMER_PERIODIC;
		return (nsec_per_tick);
	}
}


/*ARGSUSED*/
static int
mach_softlvl_to_vect(int ipl)
{
	setsoftint = av_set_softint_pending;
	kdisetsoftint = kdi_av_set_softint_pending;

	return (PSM_SV_SOFTWARE);
}

#ifdef DEBUG
/*
 * This is here to allow us to simulate cpus that refuse to start.
 */
cpuset_t cpufailset;
#endif

int
mach_cpu_start(struct cpu *cp, void *ctx)
{
	struct psm_ops *pops = mach_set[0];
	processorid_t id = cp->cpu_id;

#ifdef DEBUG
	if (CPU_IN_SET(cpufailset, id))
		return (0);
#endif
	return ((*pops->psm_cpu_start)(id, ctx));
}

int
mach_cpuid_start(processorid_t id, void *ctx)
{
	struct psm_ops *pops = mach_set[0];

#ifdef DEBUG
	if (CPU_IN_SET(cpufailset, id))
		return (0);
#endif
	return ((*pops->psm_cpu_start)(id, ctx));
}

/*ARGSUSED*/
static int
mach_translate_irq(dev_info_t *dip, int irqno)
{
	return (irqno);	/* default to NO translation */
}

static void
mach_notify_error(int level, char *errmsg)
{
	/*
	 * SL_FATAL is pass in once panicstr is set, deliver it
	 * as CE_PANIC.  Also, translate SL_ codes back to CE_
	 * codes for the psmi handler
	 */
	if (level & SL_FATAL)
		(*notify_error)(CE_PANIC, errmsg);
	else if (level & SL_WARN)
		(*notify_error)(CE_WARN, errmsg);
	else if (level & SL_NOTE)
		(*notify_error)(CE_NOTE, errmsg);
	else if (level & SL_CONSOLE)
		(*notify_error)(CE_CONT, errmsg);
}

/*
 * It provides the default basic intr_ops interface for the new DDI
 * interrupt framework if the PSM doesn't have one.
 *
 * Input:
 * dip     - pointer to the dev_info structure of the requested device
 * hdlp    - pointer to the internal interrupt handle structure for the
 *	     requested interrupt
 * intr_op - opcode for this call
 * result  - pointer to the integer that will hold the result to be
 *	     passed back if return value is PSM_SUCCESS
 *
 * Output:
 * return value is either PSM_SUCCESS or PSM_FAILURE
 */
static int
mach_intr_ops(dev_info_t *dip, ddi_intr_handle_impl_t *hdlp,
    psm_intr_op_t intr_op, int *result)
{
	struct intrspec *ispec;

	switch (intr_op) {
	case PSM_INTR_OP_CHECK_MSI:
		*result = hdlp->ih_type & ~(DDI_INTR_TYPE_MSI |
		    DDI_INTR_TYPE_MSIX);
		break;
	case PSM_INTR_OP_ALLOC_VECTORS:
		if (hdlp->ih_type == DDI_INTR_TYPE_FIXED)
			*result = 1;
		else
			*result = 0;
		break;
	case PSM_INTR_OP_FREE_VECTORS:
		break;
	case PSM_INTR_OP_NAVAIL_VECTORS:
		if (hdlp->ih_type == DDI_INTR_TYPE_FIXED)
			*result = 1;
		else
			*result = 0;
		break;
	case PSM_INTR_OP_XLATE_VECTOR:
		ispec = ((ihdl_plat_t *)hdlp->ih_private)->ip_ispecp;
		*result = psm_translate_irq(dip, ispec->intrspec_vec);
		break;
	case PSM_INTR_OP_GET_CAP:
		*result = 0;
		break;
	case PSM_INTR_OP_GET_PENDING:
	case PSM_INTR_OP_CLEAR_MASK:
	case PSM_INTR_OP_SET_MASK:
	case PSM_INTR_OP_GET_SHARED:
	case PSM_INTR_OP_SET_PRI:
	case PSM_INTR_OP_SET_CAP:
	case PSM_INTR_OP_SET_CPU:
	case PSM_INTR_OP_GET_INTR:
	default:
		return (PSM_FAILURE);
	}
	return (PSM_SUCCESS);
}
/*
 * Return 1 if CMT load balancing policies should be
 * implemented across instances of the specified hardware
 * sharing relationship.
 */
int
pg_cmt_load_bal_hw(pghw_type_t hw)
{
	if (hw == PGHW_IPIPE ||
	    hw == PGHW_FPU ||
	    hw == PGHW_CHIP)
		return (1);
	else
		return (0);
}
/*
 * Return 1 if thread affinity polices should be implemented
 * for instances of the specifed hardware sharing relationship.
 */
int
pg_cmt_affinity_hw(pghw_type_t hw)
{
	if (hw == PGHW_CACHE)
		return (1);
	else
		return (0);
}
