/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2019 Joyent, Inc.
 */

/*
 * SMT exclusion: prevent a sibling in a hyper-threaded core from running in VMX
 * non-root guest mode, when certain threads are running on the other sibling.
 * This avoids speculation-based information leaks such as L1TF being available
 * to the untrusted guest.  The stance we take is that threads from the same
 * zone as the guest VPCU thread are considered safe to run alongside, but all
 * other threads (except the idle thread), and all interrupts, are unsafe.  Note
 * that due to the implementation here, there are significant sections of e.g.
 * the dispatcher code that can run concurrently with a guest, until the thread
 * reaches smt_mark().  This code assumes there are only two SMT threads per
 * core.
 *
 * The entry points are as follows:
 *
 * smt_mark_as_vcpu()
 *
 * All threads that enter guest mode (i.e. VCPU threads) need to call this at
 * least once, which sets TS_VCPU in ->t_schedflag.
 *
 * smt_mark()
 *
 * A new ->cpu_thread is now curthread (although interrupt threads have their
 * own separate handling).  After preventing any interrupts, we will take our
 * own CPU's spinlock and update our own state in mcpu_smt.
 *
 * If our sibling is poisoned (i.e. in guest mode or the little bit of code
 * around it), and we're not compatible (that is, same zone ID, or the idle
 * thread), then we need to smt_kick() that sibling.  smt_kick() itself waits
 * for the sibling to call smt_release(), and it will not re-enter guest mode
 * until allowed.
 *
 * Note that we ignore the fact a process can change its zone ID: poisoning
 * threads never do so, and we can ignore the other cases.
 *
 * smt_acquire()
 *
 * We are a VCPU thread about to start guest execution.  Interrupts are
 * disabled.  We must have already run smt_mark() to be in this code, so there's
 * no need to take our *own* spinlock in order to mark ourselves as CM_POISONED.
 * Instead, we take our sibling's lock to also mark ourselves as poisoned in the
 * sibling cpu_smt_t.  This is so smt_mark() will only ever need to look at its
 * local mcpu_smt.
 *
 * We'll loop here for up to smt_acquire_wait_time microseconds; this is mainly
 * to wait out any sibling interrupt: many of them will complete quicker than
 * this.
 *
 * Finally, if we succeeded in acquiring the core, we'll flush the L1 cache as
 * mitigation against L1TF: no incompatible thread will now be able to populate
 * the L1 cache until *we* smt_release().
 *
 * smt_release()
 *
 * Simply unpoison ourselves similarly to smt_acquire(); smt_kick() will wait
 * for this to happen if needed.
 *
 * smt_begin_intr()
 *
 * In an interrupt prolog.  We're either a hilevel interrupt, or a pinning
 * interrupt.  In both cases, we mark our interrupt depth, and potentially
 * smt_kick().  This enforces exclusion, but doesn't otherwise modify
 * ->cs_state: we want the dispatcher code to essentially ignore interrupts.
 *
 * smt_end_intr()
 *
 * In an interrupt epilogue *or* thread_unpin().  In the first case, we never
 * slept, and we can simply decrement our counter.  In the second case, we're an
 * interrupt thread about to sleep: we'll still just decrement our counter, and
 * henceforth treat the thread as a normal thread when it next gets scheduled,
 * until it finally gets to its epilogue.
 *
 * smt_mark_unsafe() / smt_mark_safe()
 *
 * Mark the current thread as temporarily unsafe (guests should not be executing
 * while a sibling is marked unsafe).  This can be used for a thread that's
 * otherwise considered safe, if it needs to handle potentially sensitive data.
 * Right now, this means certain I/O handling operations that reach down into
 * the networking and ZFS sub-systems.
 *
 * smt_should_run(thread, cpu)
 *
 * This is used by the dispatcher when making scheduling decisions: if the
 * sibling is compatible with the given thread, we return B_TRUE. This is
 * essentially trying to guess if any subsequent smt_acquire() will fail, by
 * peeking at the sibling CPU's state.  The peek is racy, but if we get things
 * wrong, the "only" consequence is that smt_acquire() may lose.
 *
 * smt_adjust_cpu_score()
 *
 * Used when scoring other CPUs in disp_lowpri_cpu().  If we shouldn't run here,
 * we'll add a small penalty to the score.  This also makes sure a VCPU thread
 * migration behaves properly.
 *
 * smt_init() / smt_late_init()
 *
 * Set up SMT handling. If smt_boot_disable is set, smt_late_init(), which runs
 * late enough to be able to do so, will offline and mark CPU_DISABLED all the
 * siblings. smt_disable() can also be called after boot via psradm -Ha.
 */

#include <sys/archsystm.h>
#include <sys/disp.h>
#include <sys/cmt.h>
#include <sys/systm.h>
#include <sys/cpu.h>
#include <sys/var.h>
#include <sys/xc_levels.h>
#include <sys/cmn_err.h>
#include <sys/sysmacros.h>
#include <sys/x86_archext.h>
#include <sys/esunddi.h>
#include <sys/promif.h>
#include <sys/policy.h>
#include <sys/smt.h>

#define	CS_SHIFT (8)
#define	CS_MASK ((1 << CS_SHIFT) - 1)
#define	CS_MARK(s) ((s) & CS_MASK)
#define	CS_ZONE(s) ((s) >> CS_SHIFT)
#define	CS_MK(s, z) ((s) | (z << CS_SHIFT))

typedef enum cs_mark {
	CM_IDLE = 0,	/* running CPU idle thread */
	CM_THREAD,	/* running general non-VCPU thread */
	CM_UNSAFE,	/* running ->t_unsafe thread */
	CM_VCPU,	/* running VCPU thread */
	CM_POISONED	/* running in guest */
} cs_mark_t;

/* Double-check our false-sharing padding. */
CTASSERT(offsetof(cpu_smt_t, cs_sib) == 64);
CTASSERT(CM_IDLE == 0);
CTASSERT(CM_POISONED < (1 << CS_SHIFT));
CTASSERT(CM_POISONED > CM_VCPU);
CTASSERT(CM_VCPU > CM_UNSAFE);

static uint_t empty_pil = XC_CPUPOKE_PIL;

/*
 * If disabled, no SMT exclusion is performed, and system is potentially
 * vulnerable to L1TF if hyper-threading is enabled, and we don't have the "not
 * vulnerable" CPUID bit.
 */
int smt_exclusion = 1;

/*
 * How long smt_acquire() will spin trying to acquire the core, in
 * micro-seconds.  This is enough time to wait out a significant proportion of
 * interrupts.
 */
clock_t smt_acquire_wait_time = 64;

/*
 * Did we request a disable of SMT at boot time?
 */
int smt_boot_disable;

/*
 * Whether SMT is enabled.
 */
int smt_enabled = 1;

/*
 * We're adding an interrupt handler of some kind at the given PIL.  If this
 * happens to be the same PIL as XC_CPUPOKE_PIL, then we need to disable our
 * pil_needs_kick() optimization, as there is now potentially an unsafe
 * interrupt handler at that PIL.  This typically won't occur, so we're not that
 * careful about what's actually getting added, which CPU it's on, or if it gets
 * removed.  This also presumes that softints can't cover our empty_pil.
 */
void
smt_intr_alloc_pil(uint_t pil)
{
	ASSERT(pil <= PIL_MAX);

	if (empty_pil == pil)
		empty_pil = PIL_MAX + 1;
}

/*
 * If our sibling is also a VCPU thread from a different zone, we need one of
 * them to give up, otherwise they will just battle each other for exclusion
 * until they exhaust their quantum.
 *
 * We arbitrate between them by dispatch priority: clearly, a higher-priority
 * thread deserves to win the acquisition.  However, under CPU load, it'll be
 * very common to see both threads with ->t_pri == 1.  If so, we'll break the
 * tie by cpu_id (which is hopefully arbitrary enough).
 *
 * If we lose, the VMM code will take this as a hint to call
 * thread_affinity_set(CPU_BEST), which will likely migrate the VCPU thread
 * somewhere else.
 *
 * Note that all of this state examination is racy, as we don't own any locks
 * here.
 */
static boolean_t
yield_to_vcpu(cpu_t *sib, zoneid_t zoneid)
{
	cpu_smt_t *sibsmt = &sib->cpu_m.mcpu_smt;
	uint64_t sibstate = sibsmt->cs_state;

	/*
	 * If we're likely just waiting for an interrupt, don't yield.
	 */
	if (sibsmt->cs_intr_depth != 0)
		return (B_FALSE);

	/*
	 * We're only interested in VCPUs from a different zone.
	 */
	if (CS_MARK(sibstate) < CM_VCPU || CS_ZONE(sibstate) == zoneid)
		return (B_FALSE);

	if (curthread->t_pri < sib->cpu_dispatch_pri)
		return (B_TRUE);

	if (curthread->t_pri == sib->cpu_dispatch_pri &&
	    CPU->cpu_id < sib->cpu_id)
		return (B_TRUE);

	return (B_FALSE);
}

static inline boolean_t
sibling_compatible(cpu_smt_t *sibsmt, zoneid_t zoneid)
{
	uint64_t sibstate = sibsmt->cs_state;

	if (sibsmt->cs_intr_depth != 0)
		return (B_FALSE);

	if (CS_MARK(sibstate) == CM_UNSAFE)
		return (B_FALSE);

	if (CS_MARK(sibstate) == CM_IDLE)
		return (B_TRUE);

	return (CS_ZONE(sibstate) == zoneid);
}

int
smt_acquire(void)
{
	clock_t wait = smt_acquire_wait_time;
	cpu_smt_t *smt = &CPU->cpu_m.mcpu_smt;
	zoneid_t zoneid = getzoneid();
	cpu_smt_t *sibsmt;
	int ret = 0;

	ASSERT(!interrupts_enabled());

	if (smt->cs_sib == NULL) {
		/* For the "sequential" L1TF case. */
		spec_uarch_flush();
		return (1);
	}

	sibsmt = &smt->cs_sib->cpu_m.mcpu_smt;

	/* A VCPU thread should never change zone. */
	ASSERT3U(CS_ZONE(smt->cs_state), ==, zoneid);
	ASSERT3U(CS_MARK(smt->cs_state), ==, CM_VCPU);
	ASSERT3U(zoneid, !=, GLOBAL_ZONEID);
	ASSERT3U(curthread->t_preempt, >=, 1);
	ASSERT(curthread->t_schedflag & TS_VCPU);

	while (ret == 0 && wait > 0) {

		if (yield_to_vcpu(smt->cs_sib, zoneid)) {
			ret = -1;
			break;
		}

		if (sibling_compatible(sibsmt, zoneid)) {
			lock_set(&sibsmt->cs_lock);

			if (sibling_compatible(sibsmt, zoneid)) {
				smt->cs_state = CS_MK(CM_POISONED, zoneid);
				sibsmt->cs_sibstate = CS_MK(CM_POISONED,
				    zoneid);
				membar_enter();
				ret = 1;
			}

			lock_clear(&sibsmt->cs_lock);
		} else {
			drv_usecwait(10);
			wait -= 10;
		}
	}

	DTRACE_PROBE4(smt__acquire, int, ret, uint64_t, sibsmt->cs_state,
	    uint64_t, sibsmt->cs_intr_depth, clock_t, wait);

	if (ret == 1)
		spec_uarch_flush();

	return (ret);
}

void
smt_release(void)
{
	cpu_smt_t *smt = &CPU->cpu_m.mcpu_smt;
	zoneid_t zoneid = getzoneid();
	cpu_smt_t *sibsmt;

	ASSERT(!interrupts_enabled());

	if (smt->cs_sib == NULL)
		return;

	ASSERT3U(zoneid, !=, GLOBAL_ZONEID);
	ASSERT3U(CS_ZONE(smt->cs_state), ==, zoneid);
	ASSERT3U(CS_MARK(smt->cs_state), ==, CM_POISONED);
	ASSERT3U(curthread->t_preempt, >=, 1);

	sibsmt = &smt->cs_sib->cpu_m.mcpu_smt;

	lock_set(&sibsmt->cs_lock);

	smt->cs_state = CS_MK(CM_VCPU, zoneid);
	sibsmt->cs_sibstate = CS_MK(CM_VCPU, zoneid);
	membar_producer();

	lock_clear(&sibsmt->cs_lock);
}

static void
smt_kick(cpu_smt_t *smt, zoneid_t zoneid)
{
	uint64_t sibstate;

	ASSERT(LOCK_HELD(&smt->cs_lock));
	ASSERT(!interrupts_enabled());

	poke_cpu(smt->cs_sib->cpu_id);

	membar_consumer();
	sibstate = smt->cs_sibstate;

	if (CS_MARK(sibstate) != CM_POISONED || CS_ZONE(sibstate) == zoneid)
		return;

	lock_clear(&smt->cs_lock);

	/*
	 * Spin until we can see the sibling has been kicked out or is otherwise
	 * OK.
	 */
	for (;;) {
		membar_consumer();
		sibstate = smt->cs_sibstate;

		if (CS_MARK(sibstate) != CM_POISONED ||
		    CS_ZONE(sibstate) == zoneid)
			break;

		SMT_PAUSE();
	}

	lock_set(&smt->cs_lock);
}

static boolean_t
pil_needs_kick(uint_t pil)
{
	return (pil != empty_pil);
}

void
smt_begin_intr(uint_t pil)
{
	ulong_t flags;
	cpu_smt_t *smt;

	ASSERT(pil <= PIL_MAX);

	flags = intr_clear();
	smt = &CPU->cpu_m.mcpu_smt;

	if (smt->cs_sib == NULL) {
		intr_restore(flags);
		return;
	}

	if (atomic_inc_64_nv(&smt->cs_intr_depth) == 1 && pil_needs_kick(pil)) {
		lock_set(&smt->cs_lock);

		membar_consumer();

		if (CS_MARK(smt->cs_sibstate) == CM_POISONED)
			smt_kick(smt, GLOBAL_ZONEID);

		lock_clear(&smt->cs_lock);
	}

	intr_restore(flags);
}

void
smt_end_intr(void)
{
	ulong_t flags;
	cpu_smt_t *smt;

	flags = intr_clear();
	smt = &CPU->cpu_m.mcpu_smt;

	if (smt->cs_sib == NULL) {
		intr_restore(flags);
		return;
	}

	ASSERT3U(smt->cs_intr_depth, >, 0);
	atomic_dec_64(&smt->cs_intr_depth);

	intr_restore(flags);
}

static inline boolean_t
smt_need_kick(cpu_smt_t *smt, zoneid_t zoneid)
{
	membar_consumer();

	if (CS_MARK(smt->cs_sibstate) != CM_POISONED)
		return (B_FALSE);

	if (CS_MARK(smt->cs_state) == CM_UNSAFE)
		return (B_TRUE);

	return (CS_ZONE(smt->cs_sibstate) != zoneid);
}

void
smt_mark(void)
{
	zoneid_t zoneid = getzoneid();
	kthread_t *t = curthread;
	ulong_t flags;
	cpu_smt_t *smt;
	cpu_t *cp;

	flags = intr_clear();

	cp = CPU;
	smt = &cp->cpu_m.mcpu_smt;

	if (smt->cs_sib == NULL) {
		intr_restore(flags);
		return;
	}

	lock_set(&smt->cs_lock);

	/*
	 * If we were a nested interrupt and went through the resume_from_intr()
	 * path, we can now be resuming to a pinning interrupt thread; in which
	 * case, skip marking, until we later resume to a "real" thread.
	 */
	if (smt->cs_intr_depth > 0) {
		ASSERT3P(t->t_intr, !=, NULL);

		if (smt_need_kick(smt, zoneid))
			smt_kick(smt, zoneid);
		goto out;
	}

	if (t == t->t_cpu->cpu_idle_thread) {
		ASSERT3U(zoneid, ==, GLOBAL_ZONEID);
		smt->cs_state = CS_MK(CM_IDLE, zoneid);
	} else {
		uint64_t state = CM_THREAD;

		if (t->t_unsafe)
			state = CM_UNSAFE;
		else if (t->t_schedflag & TS_VCPU)
			state = CM_VCPU;

		smt->cs_state = CS_MK(state, zoneid);

		if (smt_need_kick(smt, zoneid))
			smt_kick(smt, zoneid);
	}

out:
	membar_producer();
	lock_clear(&smt->cs_lock);
	intr_restore(flags);
}

void
smt_begin_unsafe(void)
{
	curthread->t_unsafe++;
	smt_mark();
}

void
smt_end_unsafe(void)
{
	ASSERT3U(curthread->t_unsafe, >, 0);
	curthread->t_unsafe--;
	smt_mark();
}

void
smt_mark_as_vcpu(void)
{
	thread_lock(curthread);
	curthread->t_schedflag |= TS_VCPU;
	smt_mark();
	thread_unlock(curthread);
}

boolean_t
smt_should_run(kthread_t *t, cpu_t *cp)
{
	uint64_t sibstate;
	cpu_t *sib;

	if (t == t->t_cpu->cpu_idle_thread)
		return (B_TRUE);

	if ((sib = cp->cpu_m.mcpu_smt.cs_sib) == NULL)
		return (B_TRUE);

	sibstate = sib->cpu_m.mcpu_smt.cs_state;

	if ((t->t_schedflag & TS_VCPU)) {
		if (CS_MARK(sibstate) == CM_IDLE)
			return (B_TRUE);
		if (CS_MARK(sibstate) == CM_UNSAFE)
			return (B_FALSE);
		return (CS_ZONE(sibstate) == ttozone(t)->zone_id);
	}

	if (CS_MARK(sibstate) < CM_VCPU)
		return (B_TRUE);

	return (CS_ZONE(sibstate) == ttozone(t)->zone_id);
}

pri_t
smt_adjust_cpu_score(kthread_t *t, struct cpu *cp, pri_t score)
{
	if (smt_should_run(t, cp))
		return (score);

	/*
	 * If we're a VCPU thread scoring our current CPU, we are most likely
	 * asking to be rescheduled elsewhere after losing smt_acquire().  In
	 * this case, the current CPU is not a good choice, most likely, and we
	 * should go elsewhere.
	 */
	if ((t->t_schedflag & TS_VCPU) && cp == t->t_cpu && score < 0)
		return ((v.v_maxsyspri + 1) * 2);

	return (score + 1);
}

static void
set_smt_prop(void)
{
	(void) e_ddi_prop_update_string(DDI_DEV_T_NONE, ddi_root_node(),
	    "smt_enabled", smt_enabled ? "true" : "false");
}

static cpu_t *
smt_find_sibling(cpu_t *cp)
{
	for (uint_t i = 0; i < GROUP_SIZE(&cp->cpu_pg->cmt_pgs); i++) {
		pg_cmt_t *pg = GROUP_ACCESS(&cp->cpu_pg->cmt_pgs, i);
		group_t *cg = &pg->cmt_pg.pghw_pg.pg_cpus;

		if (pg->cmt_pg.pghw_hw != PGHW_IPIPE)
			continue;

		if (GROUP_SIZE(cg) == 1)
			break;

		if (GROUP_SIZE(cg) != 2) {
			panic("%u SMT threads unsupported", GROUP_SIZE(cg));
		}

		if (GROUP_ACCESS(cg, 0) != cp)
			return (GROUP_ACCESS(cg, 0));

		VERIFY3P(GROUP_ACCESS(cg, 1), !=, cp);

		return (GROUP_ACCESS(cg, 1));
	}

	return (NULL);
}

/*
 * Offline all siblings and mark as CPU_DISABLED. Note that any siblings that
 * can't be offlined (if it would leave an empty partition, or it's a spare, or
 * whatever) will fail the whole operation.
 */
int
smt_disable(void)
{
	int error = 0;

	ASSERT(MUTEX_HELD(&cpu_lock));

	if (secpolicy_ponline(CRED()) != 0)
		return (EPERM);

	if (!smt_enabled)
		return (0);

	for (size_t i = 0; i < NCPU; i++) {
		cpu_t *sib;
		cpu_t *cp;

		if ((cp = cpu_get(i)) == NULL)
			continue;

		/* NB: we don't necessarily have .mcpu_smt to use here. */
		if ((sib = smt_find_sibling(cp)) == NULL)
			continue;

		if (cp->cpu_id < sib->cpu_id)
			continue;

		if (cp->cpu_flags & CPU_DISABLED) {
			VERIFY(cp->cpu_flags & CPU_OFFLINE);
			continue;
		}

		if (cp->cpu_flags & (CPU_FAULTED | CPU_SPARE)) {
			error = EINVAL;
			break;
		}

		if ((cp->cpu_flags & (CPU_READY | CPU_OFFLINE)) != CPU_READY) {
			cp->cpu_flags |= CPU_DISABLED;
			continue;
		}

		if ((error = cpu_offline(cp, CPU_FORCED)) != 0)
			break;

		cp->cpu_flags |= CPU_DISABLED;
		cpu_set_state(cp);
	}

	if (error != 0)
		return (error);

	smt_enabled = 0;
	set_smt_prop();
	cmn_err(CE_NOTE, "!SMT / hyper-threading explicitly disabled.");
	return (0);
}

boolean_t
smt_can_enable(cpu_t *cp, int flags)
{
	VERIFY(cp->cpu_flags & CPU_DISABLED);

	return (!smt_boot_disable && (flags & CPU_FORCED));
}

/*
 * If we force-onlined a CPU_DISABLED CPU, then we can no longer consider the
 * system to be SMT-disabled in toto.
 */
void
smt_force_enabled(void)
{
	VERIFY(!smt_boot_disable);

	if (!smt_enabled)
		cmn_err(CE_NOTE, "!Disabled SMT sibling forced on-line.");

	smt_enabled = 1;
	set_smt_prop();
}

/*
 * Initialize SMT links.  We have to be careful here not to race with
 * smt_begin/end_intr(), which also complicates trying to do this initialization
 * from a cross-call; hence the slightly odd approach below.
 *
 * If we're going to disable SMT via smt_late_init(), we will avoid paying the
 * price here at all (we can't do it here since we're still too early in
 * main()).
 */
void
smt_init(void)
{
	boolean_t found_sibling = B_FALSE;
	cpu_t *scp = CPU;
	cpu_t *cp = scp;
	ulong_t flags;

	if (!smt_exclusion || smt_boot_disable)
		return;

	mutex_enter(&cpu_lock);

	do {
		thread_affinity_set(curthread, cp->cpu_id);
		flags = intr_clear();

		cp->cpu_m.mcpu_smt.cs_intr_depth = 0;
		cp->cpu_m.mcpu_smt.cs_state = CS_MK(CM_THREAD, GLOBAL_ZONEID);
		cp->cpu_m.mcpu_smt.cs_sibstate = CS_MK(CM_THREAD,
		    GLOBAL_ZONEID);
		ASSERT3P(cp->cpu_m.mcpu_smt.cs_sib, ==, NULL);
		cp->cpu_m.mcpu_smt.cs_sib = smt_find_sibling(cp);

		if (cp->cpu_m.mcpu_smt.cs_sib != NULL)
			found_sibling = B_TRUE;

		intr_restore(flags);
		thread_affinity_clear(curthread);
	} while ((cp = cp->cpu_next_onln) != scp);

	mutex_exit(&cpu_lock);

	if (!found_sibling)
		smt_enabled = 0;
}

void
smt_late_init(void)
{
	int err;

	if (smt_boot_disable) {
		int err;

		mutex_enter(&cpu_lock);

		err = smt_disable();

		/*
		 * We're early enough in boot that nothing should have stopped
		 * us from offlining the siblings. As we didn't prepare our
		 * L1TF mitigation in this case, we need to panic.
		 */
		if (err) {
			cmn_err(CE_PANIC, "smt_disable() failed with %d", err);
		}

		mutex_exit(&cpu_lock);
	}

	if (smt_enabled)
		cmn_err(CE_NOTE, "!SMT enabled\n");

	set_smt_prop();
}
