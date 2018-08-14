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
 * Copyright 2018 Joyent, Inc.
 */

/*
 * HT exclusion: prevent a sibling in a hyper-threaded core from running in VMX
 * non-root guest mode, when certain threads are running on the other sibling.
 * This avoids speculation-based information leaks such as L1TF being available
 * to the untrusted guest.  The stance we take is that threads from the same
 * zone as the guest VPCU thread are considered safe to run alongside, but all
 * other threads (except the idle thread), and all interrupts, are unsafe.  Note
 * that due to the implementation here, there are significant sections of e.g.
 * the dispatcher code that can run concurrently with a guest, until the thread
 * reaches ht_mark().  This code assumes there are only two HT threads per core.
 *
 * The entry points are as follows:
 *
 * ht_mark_as_vcpu()
 *
 * All threads that enter guest mode (i.e. VCPU threads) need to call this at
 * least once, which sets TS_VCPU in ->t_schedflag.
 *
 * ht_mark()
 *
 * A new ->cpu_thread is now curthread (although interrupt threads have their
 * own separate handling).  After preventing any interrupts, we will take our
 * own CPU's spinlock and update our own state in mcpu_ht.
 *
 * If our sibling is poisoned (i.e. in guest mode or the little bit of code
 * around it), and we're not compatible (that is, same zone ID, or the idle
 * thread), then we need to ht_kick() that sibling.  ht_kick() itself waits for
 * the sibling to call ht_release(), and it will not re-enter guest mode until
 * allowed.
 *
 * Note that we ignore the fact a process can change its zone ID: poisoning
 * threads never do so, and we can ignore the other cases.
 *
 * ht_acquire()
 *
 * We are a VCPU thread about to start guest execution.  Interrupts are
 * disabled.  We must have already run ht_mark() to be in this code, so there's
 * no need to take our *own* spinlock in order to mark ourselves as CM_POISONED.
 * Instead, we take our sibling's lock to also mark ourselves as poisoned in the
 * sibling cpu_ht_t.  This is so ht_mark() will only ever need to look at its
 * local mcpu_ht.
 *
 * We'll loop here for up to ht_acquire_wait_time microseconds; this is mainly
 * to wait out any sibling interrupt: many of them will complete quicker than
 * this.
 *
 * Finally, if we succeeded in acquiring the core, we'll flush the L1 cache as
 * mitigation against L1TF: no incompatible thread will now be able to populate
 * the L1 cache until *we* ht_release().
 *
 * ht_release()
 *
 * Simply unpoison ourselves similarly to ht_acquire(); ht_kick() will wait for
 * this to happen if needed.
 *
 * ht_begin_intr()
 *
 * In an interrupt prolog.  We're either a hilevel interrupt, or a pinning
 * interrupt.  In both cases, we mark our interrupt depth, and potentially
 * ht_kick().  This enforces exclusion, but doesn't otherwise modify ->ch_state:
 * we want the dispatcher code to essentially ignore interrupts.
 *
 * ht_end_intr()
 *
 * In an interrupt epilogue *or* thread_unpin().  In the first case, we never
 * slept, and we can simply decrement our counter.  In the second case, we're an
 * interrupt thread about to sleep: we'll still just decrement our counter, and
 * henceforth treat the thread as a normal thread when it next gets scheduled,
 * until it finally gets to its epilogue.
 *
 * ht_mark_unsafe() / ht_mark_safe()
 *
 * Mark the current thread as temporarily unsafe (guests should not be executing
 * while a sibling is marked unsafe).  This can be used for a thread that's
 * otherwise considered safe, if it needs to handle potentially sensitive data.
 * Right now, this means certain I/O handling operations that reach down into
 * the networking and ZFS sub-systems.
 *
 * ht_should_run(thread, cpu)
 *
 * This is used by the dispatcher when making scheduling decisions: if the
 * sibling is compatible with the given thread, we return B_TRUE. This is
 * essentially trying to guess if any subsequent ht_acquire() will fail, by
 * peeking at the sibling CPU's state.  The peek is racy, but if we get things
 * wrong, the "only" consequence is that ht_acquire() may lose.
 *
 * ht_adjust_cpu_score()
 *
 * Used when scoring other CPUs in disp_lowpri_cpu().  If we shouldn't run here,
 * we'll add a small penalty to the score.  This also makes sure a VCPU thread
 * migration behaves properly.
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

#define	CS_SHIFT (8)
#define	CS_MASK ((1 << CS_SHIFT) - 1)
#define	CS_MARK(s) ((s) & CS_MASK)
#define	CS_ZONE(s) ((s) >> CS_SHIFT)
#define	CS_MK(s, z) ((s) | (z << CS_SHIFT))

typedef enum ch_mark {
	CM_IDLE = 0,	/* running CPU idle thread */
	CM_THREAD,	/* running general non-VCPU thread */
	CM_UNSAFE,	/* running ->t_unsafe thread */
	CM_VCPU,	/* running VCPU thread */
	CM_POISONED	/* running in guest */
} ch_mark_t;

/* Double-check our false-sharing padding. */
CTASSERT(offsetof(cpu_ht_t, ch_sib) == 64);
CTASSERT(CM_IDLE == 0);
CTASSERT(CM_POISONED < (1 << CS_SHIFT));
CTASSERT(CM_POISONED > CM_VCPU);
CTASSERT(CM_VCPU > CM_UNSAFE);

/*
 * If disabled, no HT exclusion is performed, and system is potentially
 * vulnerable to L1TF if hyper-threading is enabled, and we don't have the "not
 * vulnerable" CPUID bit.
 */
int ht_exclusion = 1;

/*
 * How long ht_acquire() will spin trying to acquire the core, in micro-seconds.
 * This is enough time to wait out a significant proportion of interrupts.
 */
clock_t ht_acquire_wait_time = 64;

static cpu_t *
ht_find_sibling(cpu_t *cp)
{
	for (uint_t i = 0; i < GROUP_SIZE(&cp->cpu_pg->cmt_pgs); i++) {
		pg_cmt_t *pg = GROUP_ACCESS(&cp->cpu_pg->cmt_pgs, i);
		group_t *cg = &pg->cmt_pg.pghw_pg.pg_cpus;

		if (pg->cmt_pg.pghw_hw != PGHW_IPIPE)
			continue;

		if (GROUP_SIZE(cg) == 1)
			break;

		VERIFY3U(GROUP_SIZE(cg), ==, 2);

		if (GROUP_ACCESS(cg, 0) != cp)
			return (GROUP_ACCESS(cg, 0));

		VERIFY3P(GROUP_ACCESS(cg, 1), !=, cp);

		return (GROUP_ACCESS(cg, 1));
	}

	return (NULL);
}

/*
 * Initialize HT links.  We have to be careful here not to race with
 * ht_begin/end_intr(), which also complicates trying to do this initialization
 * from a cross-call; hence the slightly odd approach below.
 */
void
ht_init(void)
{
	cpu_t *scp = CPU;
	cpu_t *cp = scp;
	ulong_t flags;

	if (!ht_exclusion)
		return;

	mutex_enter(&cpu_lock);

	do {
		thread_affinity_set(curthread, cp->cpu_id);
		flags = intr_clear();

		cp->cpu_m.mcpu_ht.ch_intr_depth = 0;
		cp->cpu_m.mcpu_ht.ch_state = CS_MK(CM_THREAD, GLOBAL_ZONEID);
		cp->cpu_m.mcpu_ht.ch_sibstate = CS_MK(CM_THREAD, GLOBAL_ZONEID);
		ASSERT3P(cp->cpu_m.mcpu_ht.ch_sib, ==, NULL);
		cp->cpu_m.mcpu_ht.ch_sib = ht_find_sibling(cp);

		intr_restore(flags);
		thread_affinity_clear(curthread);
	} while ((cp = cp->cpu_next_onln) != scp);

	mutex_exit(&cpu_lock);
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
	cpu_ht_t *sibht = &sib->cpu_m.mcpu_ht;
	uint64_t sibstate = sibht->ch_state;

	/*
	 * If we're likely just waiting for an interrupt, don't yield.
	 */
	if (sibht->ch_intr_depth != 0)
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
sibling_compatible(cpu_ht_t *sibht, zoneid_t zoneid)
{
	uint64_t sibstate = sibht->ch_state;

	if (sibht->ch_intr_depth != 0)
		return (B_FALSE);

	if (CS_MARK(sibstate) == CM_UNSAFE)
		return (B_FALSE);

	if (CS_MARK(sibstate) == CM_IDLE)
		return (B_TRUE);

	return (CS_ZONE(sibstate) == zoneid);
}

int
ht_acquire(void)
{
	clock_t wait = ht_acquire_wait_time;
	cpu_ht_t *ht = &CPU->cpu_m.mcpu_ht;
	zoneid_t zoneid = getzoneid();
	cpu_ht_t *sibht;
	int ret = 0;

	ASSERT(!interrupts_enabled());

	if (ht->ch_sib == NULL) {
		/* For the "sequential" L1TF case. */
		spec_l1d_flush();
		return (1);
	}

	sibht = &ht->ch_sib->cpu_m.mcpu_ht;

	/* A VCPU thread should never change zone. */
	ASSERT3U(CS_ZONE(ht->ch_state), ==, zoneid);
	ASSERT3U(CS_MARK(ht->ch_state), ==, CM_VCPU);
	ASSERT3U(zoneid, !=, GLOBAL_ZONEID);
	ASSERT3U(curthread->t_preempt, >=, 1);
	ASSERT(curthread->t_schedflag & TS_VCPU);

	while (ret == 0 && wait > 0) {

		if (yield_to_vcpu(ht->ch_sib, zoneid)) {
			ret = -1;
			break;
		}

		if (sibling_compatible(sibht, zoneid)) {
			lock_set(&sibht->ch_lock);

			if (sibling_compatible(sibht, zoneid)) {
				ht->ch_state = CS_MK(CM_POISONED, zoneid);
				sibht->ch_sibstate = CS_MK(CM_POISONED, zoneid);
				membar_enter();
				ret = 1;
			}

			lock_clear(&sibht->ch_lock);
		} else {
			drv_usecwait(10);
			wait -= 10;
		}
	}

	DTRACE_PROBE4(ht__acquire, int, ret, uint64_t, sibht->ch_state,
	    uint64_t, sibht->ch_intr_depth, clock_t, wait);

	if (ret == 1)
		spec_l1d_flush();

	return (ret);
}

void
ht_release(void)
{
	cpu_ht_t *ht = &CPU->cpu_m.mcpu_ht;
	zoneid_t zoneid = getzoneid();
	cpu_ht_t *sibht;

	ASSERT(!interrupts_enabled());

	if (ht->ch_sib == NULL)
		return;

	ASSERT3U(zoneid, !=, GLOBAL_ZONEID);
	ASSERT3U(CS_ZONE(ht->ch_state), ==, zoneid);
	ASSERT3U(CS_MARK(ht->ch_state), ==, CM_POISONED);
	ASSERT3U(curthread->t_preempt, >=, 1);

	sibht = &ht->ch_sib->cpu_m.mcpu_ht;

	lock_set(&sibht->ch_lock);

	ht->ch_state = CS_MK(CM_VCPU, zoneid);
	sibht->ch_sibstate = CS_MK(CM_VCPU, zoneid);
	membar_producer();

	lock_clear(&sibht->ch_lock);
}

static void
ht_kick(cpu_ht_t *ht, zoneid_t zoneid)
{
	uint64_t sibstate;

	ASSERT(LOCK_HELD(&ht->ch_lock));
	ASSERT(!interrupts_enabled());

	poke_cpu(ht->ch_sib->cpu_id);

	for (;;) {
		membar_consumer();
		sibstate = ht->ch_sibstate;

		if (CS_MARK(sibstate) != CM_POISONED ||
		    CS_ZONE(sibstate) == zoneid)
			return;

		lock_clear(&ht->ch_lock);

		for (;;) {
			membar_consumer();
			sibstate = ht->ch_sibstate;

			if (CS_MARK(sibstate) != CM_POISONED ||
			    CS_ZONE(sibstate) == zoneid) {
				lock_set(&ht->ch_lock);
				return;
			}

			SMT_PAUSE();
		}

		lock_set(&ht->ch_lock);
	}
}

/*
 * FIXME: do we need a callback in case somebody installs a handler at this PIL
 * ever?
 */
static boolean_t
pil_needs_kick(uint_t pil)
{
	return (pil != XC_CPUPOKE_PIL);
}

void
ht_begin_intr(uint_t pil)
{
	ulong_t flags;
	cpu_ht_t *ht;

	flags = intr_clear();
	ht = &CPU->cpu_m.mcpu_ht;

	if (ht->ch_sib == NULL) {
		intr_restore(flags);
		return;
	}

	if (atomic_inc_64_nv(&ht->ch_intr_depth) == 1 && pil_needs_kick(pil)) {
		lock_set(&ht->ch_lock);

		membar_consumer();

		if (CS_MARK(ht->ch_sibstate) == CM_POISONED)
			ht_kick(ht, GLOBAL_ZONEID);

		lock_clear(&ht->ch_lock);
	}

	intr_restore(flags);
}

void
ht_end_intr(void)
{
	ulong_t flags;
	cpu_ht_t *ht;

	flags = intr_clear();
	ht = &CPU->cpu_m.mcpu_ht;

	if (ht->ch_sib == NULL) {
		intr_restore(flags);
		return;
	}

	ASSERT3U(ht->ch_intr_depth, >, 0);
	atomic_dec_64(&ht->ch_intr_depth);

	intr_restore(flags);
}

static inline boolean_t
ht_need_kick(cpu_ht_t *ht, zoneid_t zoneid)
{
	membar_consumer();

	if (CS_MARK(ht->ch_sibstate) != CM_POISONED)
		return (B_FALSE);

	if (CS_MARK(ht->ch_state) == CM_UNSAFE)
		return (B_TRUE);

	return (CS_ZONE(ht->ch_sibstate) != zoneid);
}

void
ht_mark(void)
{
	zoneid_t zoneid = getzoneid();
	kthread_t *t = curthread;
	ulong_t flags;
	cpu_ht_t *ht;
	cpu_t *cp;

	flags = intr_clear();

	cp = CPU;
	ht = &cp->cpu_m.mcpu_ht;

	if (ht->ch_sib == NULL) {
		intr_restore(flags);
		return;
	}

	lock_set(&ht->ch_lock);

	/*
	 * If we were a nested interrupt and went through the resume_from_intr()
	 * path, we can now be resuming to a pinning interrupt thread; in which
	 * case, skip marking, until we later resume to a "real" thread.
	 */
	if (ht->ch_intr_depth > 0) {
		ASSERT3P(t->t_intr, !=, NULL);

		if (ht_need_kick(ht, zoneid))
			ht_kick(ht, zoneid);
		goto out;
	}

	if (t == t->t_cpu->cpu_idle_thread) {
		ASSERT3U(zoneid, ==, GLOBAL_ZONEID);
		ht->ch_state = CS_MK(CM_IDLE, zoneid);
	} else {
		uint64_t state = CM_THREAD;

		if (t->t_unsafe)
			state = CM_UNSAFE;
		else if (t->t_schedflag & TS_VCPU)
			state = CM_VCPU;

		ht->ch_state = CS_MK(state, zoneid);

		if (ht_need_kick(ht, zoneid))
			ht_kick(ht, zoneid);
	}

out:
	membar_producer();
	lock_clear(&ht->ch_lock);
	intr_restore(flags);
}

void
ht_begin_unsafe(void)
{
	curthread->t_unsafe++;
	ht_mark();
}

void
ht_end_unsafe(void)
{
	ASSERT3U(curthread->t_unsafe, >, 0);
	curthread->t_unsafe--;
	ht_mark();
}

void
ht_mark_as_vcpu(void)
{
	thread_lock(curthread);
	curthread->t_schedflag |= TS_VCPU;
	ht_mark();
	thread_unlock(curthread);
}

boolean_t
ht_should_run(kthread_t *t, cpu_t *cp)
{
	uint64_t sibstate;
	cpu_t *sib;

	if (t == t->t_cpu->cpu_idle_thread)
		return (B_TRUE);

	if ((sib = cp->cpu_m.mcpu_ht.ch_sib) == NULL)
		return (B_TRUE);

	sibstate = sib->cpu_m.mcpu_ht.ch_state;

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
ht_adjust_cpu_score(kthread_t *t, struct cpu *cp, pri_t score)
{
	cpu_t *sib;

	if (ht_should_run(t, cp))
		return (score);

	/*
	 * If we're a VCPU thread scoring our current CPU, we are most likely
	 * asking to be rescheduled elsewhere after losing ht_acquire().  In
	 * this case, the current CPU is not a good choice, most likely, and we
	 * should go elsewhere.
	 */
	if ((t->t_schedflag & TS_VCPU) && cp == t->t_cpu && score < 0)
		return ((v.v_maxsyspri + 1) * 2);

	return (score + 1);
}
