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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <sys/cpuvar.h>
#include <sys/thread.h>
#include <sys/debug.h>
#include <sys/msacct.h>
#include <sys/time.h>
#include <sys/zone.h>

/*
 * Mega-theory block comment:
 *
 * Microstate accounting uses finite states and the transitions between these
 * states to measure timing and accounting information.  The state information
 * is presently tracked for threads (via microstate accounting) and cpus (via
 * cpu microstate accounting).  In each case, these accounting mechanisms use
 * states and transitions to measure time spent in each state instead of
 * clock-based sampling methodologies.
 *
 * For microstate accounting:
 * state transitions are accomplished by calling new_mstate() to switch between
 * states.  Transitions from a sleeping state (LMS_SLEEP and LMS_STOPPED) occur
 * by calling restore_mstate() which restores a thread to its previously running
 * state.  This code is primarialy executed by the dispatcher in disp() before
 * running a process that was put to sleep.  If the thread was not in a sleeping
 * state, this call has little effect other than to update the count of time the
 * thread has spent waiting on run-queues in its lifetime.
 *
 * For cpu microstate accounting:
 * Cpu microstate accounting is similar to the microstate accounting for threads
 * but it tracks user, system, and idle time for cpus.  Cpu microstate
 * accounting does not track interrupt times as there is a pre-existing
 * interrupt accounting mechanism for this purpose.  Cpu microstate accounting
 * tracks time that user threads have spent active, idle, or in the system on a
 * given cpu.  Cpu microstate accounting has fewer states which allows it to
 * have better defined transitions.  The states transition in the following
 * order:
 *
 *  CMS_USER <-> CMS_SYSTEM <-> CMS_IDLE
 *
 * In order to get to the idle state, the cpu microstate must first go through
 * the system state, and vice-versa for the user state from idle.  The switching
 * of the microstates from user to system is done as part of the regular thread
 * microstate accounting code, except for the idle state which is switched by
 * the dispatcher before it runs the idle loop.
 *
 * Cpu percentages:
 * Cpu percentages are now handled by and based upon microstate accounting
 * information (the same is true for load averages).  The routines which handle
 * the growing/shrinking and exponentiation of cpu percentages have been moved
 * here as it now makes more sense for them to be generated from the microstate
 * code.  Cpu percentages are generated similarly to the way they were before;
 * however, now they are based upon high-resolution timestamps and the
 * timestamps are modified at various state changes instead of during a clock()
 * interrupt.  This allows us to generate more accurate cpu percentages which
 * are also in-sync with microstate data.
 */

/*
 * Initialize the microstate level and the
 * associated accounting information for an LWP.
 */
void
init_mstate(
	kthread_t	*t,
	int		init_state)
{
	struct mstate *ms;
	klwp_t *lwp;
	hrtime_t curtime;

	ASSERT(init_state != LMS_WAIT_CPU);
	ASSERT((unsigned)init_state < NMSTATES);

	if ((lwp = ttolwp(t)) != NULL) {
		ms = &lwp->lwp_mstate;
		curtime = gethrtime_unscaled();
		ms->ms_prev = LMS_SYSTEM;
		ms->ms_start = curtime;
		ms->ms_term = 0;
		ms->ms_state_start = curtime;
		t->t_mstate = init_state;
		t->t_waitrq = 0;
		t->t_hrtime = curtime;
		if ((t->t_proc_flag & TP_MSACCT) == 0)
			t->t_proc_flag |= TP_MSACCT;
		bzero((caddr_t)&ms->ms_acct[0], sizeof (ms->ms_acct));
	}
}

/*
 * Initialize the microstate level and associated accounting information
 * for the specified cpu
 */

void
init_cpu_mstate(
	cpu_t *cpu,
	int init_state)
{
	ASSERT(init_state != CMS_DISABLED);

	cpu->cpu_mstate = init_state;
	cpu->cpu_mstate_start = gethrtime_unscaled();
	cpu->cpu_waitrq = 0;
	bzero((caddr_t)&cpu->cpu_acct[0], sizeof (cpu->cpu_acct));
}

/*
 * sets cpu state to OFFLINE.  We don't actually track this time,
 * but it serves as a useful placeholder state for when we're not
 * doing anything.
 */

void
term_cpu_mstate(struct cpu *cpu)
{
	ASSERT(cpu->cpu_mstate != CMS_DISABLED);
	cpu->cpu_mstate = CMS_DISABLED;
	cpu->cpu_mstate_start = 0;
}

/* NEW_CPU_MSTATE comments inline in new_cpu_mstate below. */

#define	NEW_CPU_MSTATE(state)						\
	gen = cpu->cpu_mstate_gen;					\
	cpu->cpu_mstate_gen = 0;					\
	/* Need membar_producer() here if stores not ordered / TSO */	\
	cpu->cpu_acct[cpu->cpu_mstate] += curtime - cpu->cpu_mstate_start; \
	cpu->cpu_mstate = state;					\
	cpu->cpu_mstate_start = curtime;				\
	/* Need membar_producer() here if stores not ordered / TSO */	\
	cpu->cpu_mstate_gen = (++gen == 0) ? 1 : gen;

void
new_cpu_mstate(int cmstate, hrtime_t curtime)
{
	cpu_t *cpu = CPU;
	uint16_t gen;

	ASSERT(cpu->cpu_mstate != CMS_DISABLED);
	ASSERT(cmstate < NCMSTATES);
	ASSERT(cmstate != CMS_DISABLED);

	/*
	 * This function cannot be re-entrant on a given CPU. As such,
	 * we ASSERT and panic if we are called on behalf of an interrupt.
	 * The one exception is for an interrupt which has previously
	 * blocked. Such an interrupt is being scheduled by the dispatcher
	 * just like a normal thread, and as such cannot arrive here
	 * in a re-entrant manner.
	 */

	ASSERT(!CPU_ON_INTR(cpu) && curthread->t_intr == NULL);
	ASSERT(curthread->t_preempt > 0 || curthread == cpu->cpu_idle_thread);

	/*
	 * LOCKING, or lack thereof:
	 *
	 * Updates to CPU mstate can only be made by the CPU
	 * itself, and the above check to ignore interrupts
	 * should prevent recursion into this function on a given
	 * processor. i.e. no possible write contention.
	 *
	 * However, reads of CPU mstate can occur at any time
	 * from any CPU. Any locking added to this code path
	 * would seriously impact syscall performance. So,
	 * instead we have a best-effort protection for readers.
	 * The reader will want to account for any time between
	 * cpu_mstate_start and the present time. This requires
	 * some guarantees that the reader is getting coherent
	 * information.
	 *
	 * We use a generation counter, which is set to 0 before
	 * we start making changes, and is set to a new value
	 * after we're done. Someone reading the CPU mstate
	 * should check for the same non-zero value of this
	 * counter both before and after reading all state. The
	 * important point is that the reader is not a
	 * performance-critical path, but this function is.
	 *
	 * The ordering of writes is critical. cpu_mstate_gen must
	 * be visibly zero on all CPUs before we change cpu_mstate
	 * and cpu_mstate_start. Additionally, cpu_mstate_gen must
	 * not be restored to oldgen+1 until after all of the other
	 * writes have become visible.
	 *
	 * Normally one puts membar_producer() calls to accomplish
	 * this. Unfortunately this routine is extremely performance
	 * critical (esp. in syscall_mstate below) and we cannot
	 * afford the additional time, particularly on some x86
	 * architectures with extremely slow sfence calls. On a
	 * CPU which guarantees write ordering (including sparc, x86,
	 * and amd64) this is not a problem. The compiler could still
	 * reorder the writes, so we make the four cpu fields
	 * volatile to prevent this.
	 *
	 * TSO warning: should we port to a non-TSO (or equivalent)
	 * CPU, this will break.
	 *
	 * The reader stills needs the membar_consumer() calls because,
	 * although the volatiles prevent the compiler from reordering
	 * loads, the CPU can still do so.
	 */

	NEW_CPU_MSTATE(cmstate);
}

/*
 * Return an aggregation of user and system CPU time consumed by
 * the specified thread in scaled nanoseconds.
 */
hrtime_t
mstate_thread_onproc_time(kthread_t *t)
{
	hrtime_t aggr_time;
	hrtime_t now;
	hrtime_t waitrq;
	hrtime_t state_start;
	struct mstate *ms;
	klwp_t *lwp;
	int	mstate;

	ASSERT(THREAD_LOCK_HELD(t));

	if ((lwp = ttolwp(t)) == NULL)
		return (0);

	mstate = t->t_mstate;
	waitrq = t->t_waitrq;
	ms = &lwp->lwp_mstate;
	state_start = ms->ms_state_start;

	aggr_time = ms->ms_acct[LMS_USER] +
	    ms->ms_acct[LMS_SYSTEM] + ms->ms_acct[LMS_TRAP];

	now = gethrtime_unscaled();

	/*
	 * NOTE: gethrtime_unscaled on X86 taken on different CPUs is
	 * inconsistent, so it is possible that now < state_start.
	 */
	if (mstate == LMS_USER || mstate == LMS_SYSTEM || mstate == LMS_TRAP) {
		/* if waitrq is zero, count all of the time. */
		if (waitrq == 0) {
			waitrq = now;
		}

		if (waitrq > state_start) {
			aggr_time += waitrq - state_start;
		}
	}

	scalehrtime(&aggr_time);
	return (aggr_time);
}

/*
 * Return the amount of onproc and runnable time this thread has experienced.
 *
 * Because the fields we read are not protected by locks when updated
 * by the thread itself, this is an inherently racey interface.  In
 * particular, the ASSERT(THREAD_LOCK_HELD(t)) doesn't guarantee as much
 * as it might appear to.
 *
 * The implication for users of this interface is that onproc and runnable
 * are *NOT* monotonically increasing; they may temporarily be larger than
 * they should be.
 */
void
mstate_systhread_times(kthread_t *t, hrtime_t *onproc, hrtime_t *runnable)
{
	struct mstate	*const	ms = &ttolwp(t)->lwp_mstate;

	int		mstate;
	hrtime_t	now;
	hrtime_t	state_start;
	hrtime_t	waitrq;
	hrtime_t	aggr_onp;
	hrtime_t	aggr_run;

	ASSERT(THREAD_LOCK_HELD(t));
	ASSERT(t->t_procp->p_flag & SSYS);
	ASSERT(ttolwp(t) != NULL);

	/* shouldn't be any non-SYSTEM on-CPU time */
	ASSERT(ms->ms_acct[LMS_USER] == 0);
	ASSERT(ms->ms_acct[LMS_TRAP] == 0);

	mstate = t->t_mstate;
	waitrq = t->t_waitrq;
	state_start = ms->ms_state_start;

	aggr_onp = ms->ms_acct[LMS_SYSTEM];
	aggr_run = ms->ms_acct[LMS_WAIT_CPU];

	now = gethrtime_unscaled();

	/* if waitrq == 0, then there is no time to account to TS_RUN */
	if (waitrq == 0)
		waitrq = now;

	/* If there is system time to accumulate, do so */
	if (mstate == LMS_SYSTEM && state_start < waitrq)
		aggr_onp += waitrq - state_start;

	if (waitrq < now)
		aggr_run += now - waitrq;

	scalehrtime(&aggr_onp);
	scalehrtime(&aggr_run);

	*onproc = aggr_onp;
	*runnable = aggr_run;
}

/*
 * Return an aggregation of microstate times in scaled nanoseconds (high-res
 * time).  This keeps in mind that p_acct is already scaled, and ms_acct is
 * not.
 */
hrtime_t
mstate_aggr_state(proc_t *p, int a_state)
{
	struct mstate *ms;
	kthread_t *t;
	klwp_t *lwp;
	hrtime_t aggr_time;
	hrtime_t scaledtime;

	ASSERT(MUTEX_HELD(&p->p_lock));
	ASSERT((unsigned)a_state < NMSTATES);

	aggr_time = p->p_acct[a_state];
	if (a_state == LMS_SYSTEM)
		aggr_time += p->p_acct[LMS_TRAP];

	t = p->p_tlist;
	if (t == NULL)
		return (aggr_time);

	do {
		if (t->t_proc_flag & TP_LWPEXIT)
			continue;

		lwp = ttolwp(t);
		ms = &lwp->lwp_mstate;
		scaledtime = ms->ms_acct[a_state];
		scalehrtime(&scaledtime);
		aggr_time += scaledtime;
		if (a_state == LMS_SYSTEM) {
			scaledtime = ms->ms_acct[LMS_TRAP];
			scalehrtime(&scaledtime);
			aggr_time += scaledtime;
		}
	} while ((t = t->t_forw) != p->p_tlist);

	return (aggr_time);
}


void
syscall_mstate(int fromms, int toms)
{
	kthread_t *t = curthread;
	zone_t *z = ttozone(t);
	struct mstate *ms;
	hrtime_t *mstimep;
	hrtime_t curtime;
	klwp_t *lwp;
	hrtime_t newtime;
	cpu_t *cpu;
	uint16_t gen;

	if ((lwp = ttolwp(t)) == NULL)
		return;

	ASSERT(fromms < NMSTATES);
	ASSERT(toms < NMSTATES);

	ms = &lwp->lwp_mstate;
	mstimep = &ms->ms_acct[fromms];
	curtime = gethrtime_unscaled();
	newtime = curtime - ms->ms_state_start;
	while (newtime < 0) {
		curtime = gethrtime_unscaled();
		newtime = curtime - ms->ms_state_start;
	}
	*mstimep += newtime;
	if (fromms == LMS_USER)
		atomic_add_64(&z->zone_utime, newtime);
	else if (fromms == LMS_SYSTEM)
		atomic_add_64(&z->zone_stime, newtime);
	t->t_mstate = toms;
	ms->ms_state_start = curtime;
	ms->ms_prev = fromms;
	kpreempt_disable(); /* don't change CPU while changing CPU's state */
	cpu = CPU;
	ASSERT(cpu == t->t_cpu);
	if ((toms != LMS_USER) && (cpu->cpu_mstate != CMS_SYSTEM)) {
		NEW_CPU_MSTATE(CMS_SYSTEM);
	} else if ((toms == LMS_USER) && (cpu->cpu_mstate != CMS_USER)) {
		NEW_CPU_MSTATE(CMS_USER);
	}
	kpreempt_enable();
}

#undef NEW_CPU_MSTATE

/*
 * The following is for computing the percentage of cpu time used recently
 * by an lwp.  The function cpu_decay() is also called from /proc code.
 *
 * exp_x(x):
 * Given x as a 64-bit non-negative scaled integer of arbitrary magnitude,
 * Return exp(-x) as a 64-bit scaled integer in the range [0 .. 1].
 *
 * Scaling for 64-bit scaled integer:
 * The binary point is to the right of the high-order bit
 * of the low-order 32-bit word.
 */

#define	LSHIFT	31
#define	LSI_ONE	((uint32_t)1 << LSHIFT)	/* 32-bit scaled integer 1 */

#ifdef DEBUG
uint_t expx_cnt = 0;	/* number of calls to exp_x() */
uint_t expx_mul = 0;	/* number of long multiplies in exp_x() */
#endif

static uint64_t
exp_x(uint64_t x)
{
	int i;
	uint64_t ull;
	uint32_t ui;

#ifdef DEBUG
	expx_cnt++;
#endif
	/*
	 * By the formula:
	 *	exp(-x) = exp(-x/2) * exp(-x/2)
	 * we keep halving x until it becomes small enough for
	 * the following approximation to be accurate enough:
	 *	exp(-x) = 1 - x
	 * We reduce x until it is less than 1/4 (the 2 in LSHIFT-2 below).
	 * Our final error will be smaller than 4% .
	 */

	/*
	 * Use a uint64_t for the initial shift calculation.
	 */
	ull = x >> (LSHIFT-2);

	/*
	 * Short circuit:
	 * A number this large produces effectively 0 (actually .005).
	 * This way, we will never do more than 5 multiplies.
	 */
	if (ull >= (1 << 5))
		return (0);

	ui = ull;	/* OK.  Now we can use a uint_t. */
	for (i = 0; ui != 0; i++)
		ui >>= 1;

	if (i != 0) {
#ifdef DEBUG
		expx_mul += i;	/* seldom happens */
#endif
		x >>= i;
	}

	/*
	 * Now we compute 1 - x and square it the number of times
	 * that we halved x above to produce the final result:
	 */
	x = LSI_ONE - x;
	while (i--)
		x = (x * x) >> LSHIFT;

	return (x);
}

/*
 * Given the old percent cpu and a time delta in nanoseconds,
 * return the new decayed percent cpu:  pct * exp(-tau),
 * where 'tau' is the time delta multiplied by a decay factor.
 * We have chosen the decay factor (cpu_decay_factor in param.c)
 * to make the decay over five seconds be approximately 20%.
 *
 * 'pct' is a 32-bit scaled integer <= 1
 * The binary point is to the right of the high-order bit
 * of the 32-bit word.
 */
static uint32_t
cpu_decay(uint32_t pct, hrtime_t nsec)
{
	uint64_t delta = (uint64_t)nsec;

	delta /= cpu_decay_factor;
	return ((pct * exp_x(delta)) >> LSHIFT);
}

/*
 * Given the old percent cpu and a time delta in nanoseconds,
 * return the new grown percent cpu:  1 - ( 1 - pct ) * exp(-tau)
 */
static uint32_t
cpu_grow(uint32_t pct, hrtime_t nsec)
{
	return (LSI_ONE - cpu_decay(LSI_ONE - pct, nsec));
}


/*
 * Defined to determine whether a lwp is still on a processor.
 */

#define	T_ONPROC(kt)	\
	((kt)->t_mstate < LMS_SLEEP)
#define	T_OFFPROC(kt)	\
	((kt)->t_mstate >= LMS_SLEEP)

uint_t
cpu_update_pct(kthread_t *t, hrtime_t newtime)
{
	hrtime_t delta;
	hrtime_t hrlb;
	uint_t pctcpu;
	uint_t npctcpu;

	/*
	 * This routine can get called at PIL > 0, this *has* to be
	 * done atomically. Holding locks here causes bad things to happen.
	 * (read: deadlock).
	 */

	do {
		if (T_ONPROC(t) && t->t_waitrq == 0) {
			hrlb = t->t_hrtime;
			delta = newtime - hrlb;
			if (delta < 0) {
				newtime = gethrtime_unscaled();
				delta = newtime - hrlb;
			}
			t->t_hrtime = newtime;
			scalehrtime(&delta);
			pctcpu = t->t_pctcpu;
			npctcpu = cpu_grow(pctcpu, delta);
		} else {
			hrlb = t->t_hrtime;
			delta = newtime - hrlb;
			if (delta < 0) {
				newtime = gethrtime_unscaled();
				delta = newtime - hrlb;
			}
			t->t_hrtime = newtime;
			scalehrtime(&delta);
			pctcpu = t->t_pctcpu;
			npctcpu = cpu_decay(pctcpu, delta);
		}
	} while (cas32(&t->t_pctcpu, pctcpu, npctcpu) != pctcpu);

	return (npctcpu);
}

/*
 * Change the microstate level for the LWP and update the
 * associated accounting information.  Return the previous
 * LWP state.
 */
int
new_mstate(kthread_t *t, int new_state)
{
	struct mstate *ms;
	unsigned state;
	hrtime_t *mstimep;
	hrtime_t curtime;
	hrtime_t newtime;
	hrtime_t oldtime;
	hrtime_t ztime;
	hrtime_t origstart;
	klwp_t *lwp;
	zone_t *z;

	ASSERT(new_state != LMS_WAIT_CPU);
	ASSERT((unsigned)new_state < NMSTATES);
	ASSERT(t == curthread || THREAD_LOCK_HELD(t));

	/*
	 * Don't do microstate processing for threads without a lwp (kernel
	 * threads).  Also, if we're an interrupt thread that is pinning another
	 * thread, our t_mstate hasn't been initialized.  We'd be modifying the
	 * microstate of the underlying lwp which doesn't realize that it's
	 * pinned.  In this case, also don't change the microstate.
	 */
	if (((lwp = ttolwp(t)) == NULL) || t->t_intr)
		return (LMS_SYSTEM);

	curtime = gethrtime_unscaled();

	/* adjust cpu percentages before we go any further */
	(void) cpu_update_pct(t, curtime);

	ms = &lwp->lwp_mstate;
	state = t->t_mstate;
	origstart = ms->ms_state_start;
	do {
		switch (state) {
		case LMS_TFAULT:
		case LMS_DFAULT:
		case LMS_KFAULT:
		case LMS_USER_LOCK:
			mstimep = &ms->ms_acct[LMS_SYSTEM];
			break;
		default:
			mstimep = &ms->ms_acct[state];
			break;
		}
		ztime = newtime = curtime - ms->ms_state_start;
		if (newtime < 0) {
			curtime = gethrtime_unscaled();
			oldtime = *mstimep - 1; /* force CAS to fail */
			continue;
		}
		oldtime = *mstimep;
		newtime += oldtime;
		t->t_mstate = new_state;
		ms->ms_state_start = curtime;
	} while (cas64((uint64_t *)mstimep, oldtime, newtime) != oldtime);

	/*
	 * When the system boots the initial startup thread will have a
	 * ms_state_start of 0 which would add a huge system time to the global
	 * zone.  We want to skip aggregating that initial bit of work.
	 */
	if (origstart != 0) {
		z = ttozone(t);
		if (state == LMS_USER)
			atomic_add_64(&z->zone_utime, ztime);
		else if (state == LMS_SYSTEM)
			atomic_add_64(&z->zone_stime, ztime);
	}

	/*
	 * Remember the previous running microstate.
	 */
	if (state != LMS_SLEEP && state != LMS_STOPPED)
		ms->ms_prev = state;

	/*
	 * Switch CPU microstate if appropriate
	 */

	kpreempt_disable(); /* MUST disable kpreempt before touching t->cpu */
	ASSERT(t->t_cpu == CPU);
	if (!CPU_ON_INTR(t->t_cpu) && curthread->t_intr == NULL) {
		if (new_state == LMS_USER && t->t_cpu->cpu_mstate != CMS_USER)
			new_cpu_mstate(CMS_USER, curtime);
		else if (new_state != LMS_USER &&
		    t->t_cpu->cpu_mstate != CMS_SYSTEM)
			new_cpu_mstate(CMS_SYSTEM, curtime);
	}
	kpreempt_enable();

	return (ms->ms_prev);
}

/*
 * Restore the LWP microstate to the previous runnable state.
 * Called from disp() with the newly selected lwp.
 */
void
restore_mstate(kthread_t *t)
{
	struct mstate *ms;
	hrtime_t *mstimep;
	klwp_t *lwp;
	hrtime_t curtime;
	hrtime_t waitrq;
	hrtime_t newtime;
	hrtime_t oldtime;
	hrtime_t waittime;
	zone_t *z;

	/*
	 * Don't call restore mstate of threads without lwps.  (Kernel threads)
	 *
	 * threads with t_intr set shouldn't be in the dispatcher, so assert
	 * that nobody here has t_intr.
	 */
	ASSERT(t->t_intr == NULL);

	if ((lwp = ttolwp(t)) == NULL)
		return;

	curtime = gethrtime_unscaled();
	(void) cpu_update_pct(t, curtime);
	ms = &lwp->lwp_mstate;
	ASSERT((unsigned)t->t_mstate < NMSTATES);
	do {
		switch (t->t_mstate) {
		case LMS_SLEEP:
			/*
			 * Update the timer for the current sleep state.
			 */
			ASSERT((unsigned)ms->ms_prev < NMSTATES);
			switch (ms->ms_prev) {
			case LMS_TFAULT:
			case LMS_DFAULT:
			case LMS_KFAULT:
			case LMS_USER_LOCK:
				mstimep = &ms->ms_acct[ms->ms_prev];
				break;
			default:
				mstimep = &ms->ms_acct[LMS_SLEEP];
				break;
			}
			/*
			 * Return to the previous run state.
			 */
			t->t_mstate = ms->ms_prev;
			break;
		case LMS_STOPPED:
			mstimep = &ms->ms_acct[LMS_STOPPED];
			/*
			 * Return to the previous run state.
			 */
			t->t_mstate = ms->ms_prev;
			break;
		case LMS_TFAULT:
		case LMS_DFAULT:
		case LMS_KFAULT:
		case LMS_USER_LOCK:
			mstimep = &ms->ms_acct[LMS_SYSTEM];
			break;
		default:
			mstimep = &ms->ms_acct[t->t_mstate];
			break;
		}
		waitrq = t->t_waitrq;	/* hopefully atomic */
		if (waitrq == 0) {
			waitrq = curtime;
		}
		t->t_waitrq = 0;
		newtime = waitrq - ms->ms_state_start;
		if (newtime < 0) {
			curtime = gethrtime_unscaled();
			oldtime = *mstimep - 1; /* force CAS to fail */
			continue;
		}
		oldtime = *mstimep;
		newtime += oldtime;
	} while (cas64((uint64_t *)mstimep, oldtime, newtime) != oldtime);

	/*
	 * Update the WAIT_CPU timer and per-cpu waitrq total.
	 */
	z = ttozone(t);
	waittime = curtime - waitrq;
	ms->ms_acct[LMS_WAIT_CPU] += waittime;
	atomic_add_64(&z->zone_wtime, waittime);
	CPU->cpu_waitrq += waittime;
	ms->ms_state_start = curtime;
}

/*
 * Copy lwp microstate accounting and resource usage information
 * to the process.  (lwp is terminating)
 */
void
term_mstate(kthread_t *t)
{
	struct mstate *ms;
	proc_t *p = ttoproc(t);
	klwp_t *lwp = ttolwp(t);
	int i;
	hrtime_t tmp;

	ASSERT(MUTEX_HELD(&p->p_lock));

	ms = &lwp->lwp_mstate;
	(void) new_mstate(t, LMS_STOPPED);
	ms->ms_term = ms->ms_state_start;
	tmp = ms->ms_term - ms->ms_start;
	scalehrtime(&tmp);
	p->p_mlreal += tmp;
	for (i = 0; i < NMSTATES; i++) {
		tmp = ms->ms_acct[i];
		scalehrtime(&tmp);
		p->p_acct[i] += tmp;
	}
	p->p_ru.minflt   += lwp->lwp_ru.minflt;
	p->p_ru.majflt   += lwp->lwp_ru.majflt;
	p->p_ru.nswap    += lwp->lwp_ru.nswap;
	p->p_ru.inblock  += lwp->lwp_ru.inblock;
	p->p_ru.oublock  += lwp->lwp_ru.oublock;
	p->p_ru.msgsnd   += lwp->lwp_ru.msgsnd;
	p->p_ru.msgrcv   += lwp->lwp_ru.msgrcv;
	p->p_ru.nsignals += lwp->lwp_ru.nsignals;
	p->p_ru.nvcsw    += lwp->lwp_ru.nvcsw;
	p->p_ru.nivcsw   += lwp->lwp_ru.nivcsw;
	p->p_ru.sysc	 += lwp->lwp_ru.sysc;
	p->p_ru.ioch	 += lwp->lwp_ru.ioch;
	p->p_defunct++;
}
