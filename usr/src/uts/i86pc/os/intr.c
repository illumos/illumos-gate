/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/cpuvar.h>
#include <sys/regset.h>
#include <sys/psw.h>
#include <sys/types.h>
#include <sys/thread.h>
#include <sys/systm.h>
#include <sys/segments.h>
#include <sys/pcb.h>
#include <sys/trap.h>
#include <sys/ftrace.h>
#include <sys/traptrace.h>
#include <sys/clock.h>
#include <sys/panic.h>
#include <sys/disp.h>
#include <vm/seg_kp.h>
#include <sys/stack.h>
#include <sys/sysmacros.h>
#include <sys/cmn_err.h>
#include <sys/kstat.h>
#include <sys/smp_impldefs.h>
#include <sys/pool_pset.h>
#include <sys/zone.h>
#include <sys/bitmap.h>

#if defined(__amd64)

#if defined(__lint)
/*
 * atomic_btr32() is a gcc __inline__ function, defined in <asm/bitmap.h>
 * For lint purposes, define it here.
 */
uint_t
atomic_btr32(uint32_t *pending, uint_t pil)
{
	return (*pending &= ~(1 << pil));
}
#else

extern uint_t atomic_btr32(uint32_t *pending, uint_t pil);

#endif

/*
 * This code is amd64-only for now, but as time permits, we should
 * use this on i386 too.
 */

/*
 * Some questions to ponder:
 * -	in several of these routines, we make multiple calls to tsc_read()
 *	without invoking functions .. couldn't we just reuse the same
 *	timestamp sometimes?
 * -	if we have the inline, we can probably make set_base_spl be a
 *	C routine too.
 */

static uint_t
bsrw_insn(uint16_t mask)
{
	uint_t index = sizeof (mask) * NBBY - 1;

	ASSERT(mask != 0);

	while ((mask & (1 << index)) == 0)
		index--;
	return (index);
}

/*
 * Do all the work necessary to set up the cpu and thread structures
 * to dispatch a high-level interrupt.
 *
 * Returns 0 if we're -not- already on the high-level interrupt stack,
 * (and *must* switch to it), non-zero if we are already on that stack.
 *
 * Called with interrupts masked.
 * The 'pil' is already set to the appropriate level for rp->r_trapno.
 */
int
hilevel_intr_prolog(struct cpu *cpu, uint_t pil, uint_t oldpil, struct regs *rp)
{
	struct machcpu *mcpu = &cpu->cpu_m;
	uint_t mask;
	hrtime_t intrtime;

	ASSERT(pil > LOCK_LEVEL);

	if (pil == CBE_HIGH_PIL) {
		cpu->cpu_profile_pil = oldpil;
		if (USERMODE(rp->r_cs)) {
			cpu->cpu_profile_pc = 0;
			cpu->cpu_profile_upc = rp->r_pc;
		} else {
			cpu->cpu_profile_pc = rp->r_pc;
			cpu->cpu_profile_upc = 0;
		}
	}

	mask = cpu->cpu_intr_actv & CPU_INTR_ACTV_HIGH_LEVEL_MASK;
	if (mask != 0) {
		int nestpil;

		/*
		 * We have interrupted another high-level interrupt.
		 * Load starting timestamp, compute interval, update
		 * cumulative counter.
		 */
		nestpil = bsrw_insn((uint16_t)mask);
		ASSERT(nestpil < pil);
		intrtime = tsc_read() -
		    mcpu->pil_high_start[nestpil - (LOCK_LEVEL + 1)];
		mcpu->intrstat[nestpil][0] += intrtime;
		cpu->cpu_intracct[cpu->cpu_mstate] += intrtime;
		/*
		 * Another high-level interrupt is active below this one, so
		 * there is no need to check for an interrupt thread.  That
		 * will be done by the lowest priority high-level interrupt
		 * active.
		 */
	} else {
		kthread_t *t = cpu->cpu_thread;

		/*
		 * See if we are interrupting a low-level interrupt thread.
		 * If so, account for its time slice only if its time stamp
		 * is non-zero.
		 */
		if ((t->t_flag & T_INTR_THREAD) != 0 && t->t_intr_start != 0) {
			intrtime = tsc_read() - t->t_intr_start;
			mcpu->intrstat[t->t_pil][0] += intrtime;
			cpu->cpu_intracct[cpu->cpu_mstate] += intrtime;
			t->t_intr_start = 0;
		}
	}

	/*
	 * Store starting timestamp in CPU structure for this PIL.
	 */
	mcpu->pil_high_start[pil - (LOCK_LEVEL + 1)] = tsc_read();

	ASSERT((cpu->cpu_intr_actv & (1 << pil)) == 0);

	if (pil == 15) {
		/*
		 * To support reentrant level 15 interrupts, we maintain a
		 * recursion count in the top half of cpu_intr_actv.  Only
		 * when this count hits zero do we clear the PIL 15 bit from
		 * the lower half of cpu_intr_actv.
		 */
		uint16_t *refcntp = (uint16_t *)&cpu->cpu_intr_actv + 1;
		(*refcntp)++;
	}

	mask = cpu->cpu_intr_actv;

	cpu->cpu_intr_actv |= (1 << pil);

	return (mask & CPU_INTR_ACTV_HIGH_LEVEL_MASK);
}

/*
 * Does most of the work of returning from a high level interrupt.
 *
 * Returns 0 if there are no more high level interrupts (in which
 * case we must switch back to the interrupted thread stack) or
 * non-zero if there are more (in which case we should stay on it).
 *
 * Called with interrupts masked
 */
int
hilevel_intr_epilog(struct cpu *cpu, uint_t pil, uint_t oldpil, uint_t vecnum)
{
	struct machcpu *mcpu = &cpu->cpu_m;
	uint_t mask;
	hrtime_t intrtime;

	ASSERT(mcpu->mcpu_pri == pil);

	cpu->cpu_stats.sys.intr[pil - 1]++;

	ASSERT(cpu->cpu_intr_actv & (1 << pil));

	if (pil == 15) {
		/*
		 * To support reentrant level 15 interrupts, we maintain a
		 * recursion count in the top half of cpu_intr_actv.  Only
		 * when this count hits zero do we clear the PIL 15 bit from
		 * the lower half of cpu_intr_actv.
		 */
		uint16_t *refcntp = (uint16_t *)&cpu->cpu_intr_actv + 1;

		ASSERT(*refcntp > 0);

		if (--(*refcntp) == 0)
			cpu->cpu_intr_actv &= ~(1 << pil);
	} else {
		cpu->cpu_intr_actv &= ~(1 << pil);
	}

	ASSERT(mcpu->pil_high_start[pil - (LOCK_LEVEL + 1)] != 0);

	intrtime = tsc_read() - mcpu->pil_high_start[pil - (LOCK_LEVEL + 1)];
	mcpu->intrstat[pil][0] += intrtime;
	cpu->cpu_intracct[cpu->cpu_mstate] += intrtime;

	/*
	 * Check for lower-pil nested high-level interrupt beneath
	 * current one.  If so, place a starting timestamp in its
	 * pil_high_start entry.
	 */
	mask = cpu->cpu_intr_actv & CPU_INTR_ACTV_HIGH_LEVEL_MASK;
	if (mask != 0) {
		int nestpil;

		/*
		 * find PIL of nested interrupt
		 */
		nestpil = bsrw_insn((uint16_t)mask);
		ASSERT(nestpil < pil);
		mcpu->pil_high_start[nestpil - (LOCK_LEVEL + 1)] = tsc_read();
		/*
		 * (Another high-level interrupt is active below this one,
		 * so there is no need to check for an interrupt
		 * thread.  That will be done by the lowest priority
		 * high-level interrupt active.)
		 */
	} else {
		/*
		 * Check to see if there is a low-level interrupt active.
		 * If so, place a starting timestamp in the thread
		 * structure.
		 */
		kthread_t *t = cpu->cpu_thread;

		if (t->t_flag & T_INTR_THREAD)
			t->t_intr_start = tsc_read();
	}

	mcpu->mcpu_pri = oldpil;
	(void) (*setlvlx)(oldpil, vecnum);

	return (cpu->cpu_intr_actv & CPU_INTR_ACTV_HIGH_LEVEL_MASK);
}

/*
 * Set up the cpu, thread and interrupt thread structures for
 * executing an interrupt thread.  The new stack pointer of the
 * interrupt thread (which *must* be switched to) is returned.
 */
caddr_t
intr_thread_prolog(struct cpu *cpu, caddr_t stackptr, uint_t pil)
{
	struct machcpu *mcpu = &cpu->cpu_m;
	kthread_t *t, *volatile it;

	ASSERT(pil > 0);
	ASSERT((cpu->cpu_intr_actv & (1 << pil)) == 0);
	cpu->cpu_intr_actv |= (1 << pil);

	/*
	 * Get set to run an interrupt thread.
	 * There should always be an interrupt thread, since we
	 * allocate one for each level on each CPU.
	 *
	 * Note that the code in kcpc_overflow_intr -relies- on the
	 * ordering of events here - in particular that t->t_lwp of
	 * the interrupt thread is set to the pinned thread *before*
	 * curthread is changed.
	 */
	t = cpu->cpu_thread;
	if (t->t_flag & T_INTR_THREAD) {
		hrtime_t intrtime = tsc_read() - t->t_intr_start;
		mcpu->intrstat[t->t_pil][0] += intrtime;
		cpu->cpu_intracct[cpu->cpu_mstate] += intrtime;
		t->t_intr_start = 0;
	}

	ASSERT(SA((uintptr_t)stackptr) == (uintptr_t)stackptr);

	t->t_sp = (uintptr_t)stackptr;	/* mark stack in curthread for resume */

	/*
	 * unlink the interrupt thread off the cpu
	 */
	it = cpu->cpu_intr_thread;
	cpu->cpu_intr_thread = it->t_link;
	it->t_intr = t;
	it->t_lwp = t->t_lwp;

	/*
	 * (threads on the interrupt thread free list could have state
	 * preset to TS_ONPROC, but it helps in debugging if
	 * they're TS_FREE.)
	 */
	it->t_state = TS_ONPROC;

	cpu->cpu_thread = it;		/* new curthread on this cpu */
	it->t_pil = (uchar_t)pil;
	it->t_pri = intr_pri + (pri_t)pil;
	it->t_intr_start = tsc_read();

	return (it->t_stk);
}


#ifdef DEBUG
int intr_thread_cnt;
#endif

/*
 * Called with interrupts disabled
 */
void
intr_thread_epilog(struct cpu *cpu, uint_t vec, uint_t oldpil)
{
	struct machcpu *mcpu = &cpu->cpu_m;
	kthread_t *t;
	kthread_t *it = cpu->cpu_thread;	/* curthread */
	uint_t pil, basespl;
	hrtime_t intrtime;

	pil = it->t_pil;
	cpu->cpu_stats.sys.intr[pil - 1]++;

	ASSERT(it->t_intr_start != 0);
	intrtime = tsc_read() - it->t_intr_start;
	mcpu->intrstat[pil][0] += intrtime;
	cpu->cpu_intracct[cpu->cpu_mstate] += intrtime;

	ASSERT(cpu->cpu_intr_actv & (1 << pil));
	cpu->cpu_intr_actv &= ~(1 << pil);

	/*
	 * If there is still an interrupted thread underneath this one
	 * then the interrupt was never blocked and the return is
	 * fairly simple.  Otherwise it isn't.
	 */
	if ((t = it->t_intr) == NULL) {
		/*
		 * The interrupted thread is no longer pinned underneath
		 * the interrupt thread.  This means the interrupt must
		 * have blocked, and the interrupted thread has been
		 * unpinned, and has probably been running around the
		 * system for a while.
		 *
		 * Since there is no longer a thread under this one, put
		 * this interrupt thread back on the CPU's free list and
		 * resume the idle thread which will dispatch the next
		 * thread to run.
		 */
#ifdef DEBUG
		intr_thread_cnt++;
#endif
		cpu->cpu_stats.sys.intrblk++;
		/*
		 * Set CPU's base SPL based on active interrupts bitmask
		 */
		set_base_spl();
		basespl = cpu->cpu_base_spl;
		mcpu->mcpu_pri = basespl;
		(*setlvlx)(basespl, vec);
		(void) splhigh();
		it->t_state = TS_FREE;
		/*
		 * Return interrupt thread to pool
		 */
		it->t_link = cpu->cpu_intr_thread;
		cpu->cpu_intr_thread = it;
		swtch();
		/*NOTREACHED*/
	}

	/*
	 * Return interrupt thread to the pool
	 */
	it->t_link = cpu->cpu_intr_thread;
	cpu->cpu_intr_thread = it;
	it->t_state = TS_FREE;

	basespl = cpu->cpu_base_spl;
	pil = MAX(oldpil, basespl);
	mcpu->mcpu_pri = pil;
	(*setlvlx)(pil, vec);
	t->t_intr_start = tsc_read();
	cpu->cpu_thread = t;
}

/*
 * Called with interrupts disabled by an interrupt thread to determine
 * how much time has elapsed. See interrupt.s:intr_get_time() for detailed
 * theory of operation.
 */
uint64_t
intr_thread_get_time(struct cpu *cpu)
{
	struct machcpu *mcpu = &cpu->cpu_m;
	kthread_t *t = cpu->cpu_thread;
	uint64_t time, delta, ret;
	uint_t pil = t->t_pil;

	ASSERT((cpu->cpu_intr_actv & CPU_INTR_ACTV_HIGH_LEVEL_MASK) == 0);
	ASSERT(t->t_flag & T_INTR_THREAD);
	ASSERT(pil != 0);
	ASSERT(t->t_intr_start != 0);

	time = tsc_read();
	delta = time - t->t_intr_start;
	t->t_intr_start = time;

	time = mcpu->intrstat[pil][0] + delta;
	ret = time - mcpu->intrstat[pil][1];
	mcpu->intrstat[pil][0] = time;
	mcpu->intrstat[pil][1] = time;

	return (ret);
}

caddr_t
dosoftint_prolog(
	struct cpu *cpu,
	caddr_t stackptr,
	uint32_t st_pending,
	uint_t oldpil)
{
	kthread_t *t, *volatile it;
	struct machcpu *mcpu = &cpu->cpu_m;
	uint_t pil;

top:
	ASSERT(st_pending == mcpu->mcpu_softinfo.st_pending);

	pil = bsrw_insn((uint16_t)st_pending);
	if (pil <= oldpil || pil <= cpu->cpu_base_spl)
		return (0);

	/*
	 * XX64	Sigh.
	 *
	 * This is a transliteration of the i386 assembler code for
	 * soft interrupts.  One question is "why does this need
	 * to be atomic?"  One possible race is -other- processors
	 * posting soft interrupts to us in set_pending() i.e. the
	 * CPU might get preempted just after the address computation,
	 * but just before the atomic transaction, so another CPU would
	 * actually set the original CPU's st_pending bit.  However,
	 * it looks like it would be simpler to disable preemption there.
	 * Are there other races for which preemption control doesn't work?
	 *
	 * The i386 assembler version -also- checks to see if the bit
	 * being cleared was actually set; if it wasn't, it rechecks
	 * for more.  This seems a bit strange, as the only code that
	 * ever clears the bit is -this- code running with interrupts
	 * disabled on -this- CPU.  This code would probably be cheaper:
	 *
	 * atomic_and_32((uint32_t *)&mcpu->mcpu_softinfo.st_pending,
	 *   ~(1 << pil));
	 *
	 * and t->t_preempt--/++ around set_pending() even cheaper,
	 * but at this point, correctness is critical, so we slavishly
	 * emulate the i386 port.
	 */
	if (atomic_btr32((uint32_t *)&mcpu->mcpu_softinfo.st_pending, pil)
	    == 0) {
		st_pending = mcpu->mcpu_softinfo.st_pending;
		goto top;
	}

	mcpu->mcpu_pri = pil;
	(*setspl)(pil);

	/*
	 * Get set to run interrupt thread.
	 * There should always be an interrupt thread since we
	 * allocate one for each level on the CPU.
	 */
	it = cpu->cpu_intr_thread;
	cpu->cpu_intr_thread = it->t_link;

	/*
	 * Note that the code in kcpc_overflow_intr -relies- on the
	 * ordering of events here - in particular that t->t_lwp of
	 * the interrupt thread is set to the pinned thread *before*
	 * curthread is changed
	 */
	t = cpu->cpu_thread;
	if (t->t_flag & T_INTR_THREAD) {
		hrtime_t intrtime = tsc_read() - t->t_intr_start;
		mcpu->intrstat[pil][0] += intrtime;
		cpu->cpu_intracct[cpu->cpu_mstate] += intrtime;
	}
	it->t_lwp = t->t_lwp;
	it->t_state = TS_ONPROC;

	/*
	 * Push interrupted thread onto list from new thread.
	 * Set the new thread as the current one.
	 * Set interrupted thread's T_SP because if it is the idle thread,
	 * resume() may use that stack between threads.
	 */

	ASSERT(SA((uintptr_t)stackptr) == (uintptr_t)stackptr);
	t->t_sp = (uintptr_t)stackptr;

	it->t_intr = t;
	cpu->cpu_thread = it;

	/*
	 * Set bit for this pil in CPU's interrupt active bitmask.
	 */
	ASSERT((cpu->cpu_intr_actv & (1 << pil)) == 0);
	cpu->cpu_intr_actv |= (1 << pil);

	/*
	 * Initialize thread priority level from intr_pri
	 */
	it->t_pil = (uchar_t)pil;
	it->t_pri = (pri_t)pil + intr_pri;
	it->t_intr_start = tsc_read();

	return (it->t_stk);
}

void
dosoftint_epilog(struct cpu *cpu, uint_t oldpil)
{
	struct machcpu *mcpu = &cpu->cpu_m;
	kthread_t *t, *it;
	uint_t pil, basespl;
	hrtime_t intrtime;

	it = cpu->cpu_thread;
	pil = it->t_pil;

	cpu->cpu_stats.sys.intr[pil - 1]++;

	ASSERT(cpu->cpu_intr_actv & (1 << pil));
	cpu->cpu_intr_actv &= ~(1 << pil);
	intrtime = tsc_read() - it->t_intr_start;
	mcpu->intrstat[pil][0] += intrtime;
	cpu->cpu_intracct[cpu->cpu_mstate] += intrtime;

	/*
	 * If there is still an interrupted thread underneath this one
	 * then the interrupt was never blocked and the return is
	 * fairly simple.  Otherwise it isn't.
	 */
	if ((t = it->t_intr) == NULL) {
		/*
		 * Put thread back on the interrupt thread list.
		 * This was an interrupt thread, so set CPU's base SPL.
		 */
		set_base_spl();
		it->t_state = TS_FREE;
		it->t_link = cpu->cpu_intr_thread;
		cpu->cpu_intr_thread = it;
		(void) splhigh();
		swtch();
		/*NOTREACHED*/
	}
	it->t_link = cpu->cpu_intr_thread;
	cpu->cpu_intr_thread = it;
	it->t_state = TS_FREE;
	cpu->cpu_thread = t;
	if (t->t_flag & T_INTR_THREAD)
		t->t_intr_start = tsc_read();
	basespl = cpu->cpu_base_spl;
	pil = MAX(oldpil, basespl);
	mcpu->mcpu_pri = pil;
	(*setspl)(pil);
}

/*
 * Make the interrupted thread 'to' be runnable.
 *
 * Since t->t_sp has already been saved, t->t_pc is all
 * that needs to be set in this function.
 *
 * Returns the interrupt level of the interrupt thread.
 */
int
intr_passivate(
	kthread_t *it,		/* interrupt thread */
	kthread_t *t)		/* interrupted thread */
{
	extern void _sys_rtt();

	ASSERT(it->t_flag & T_INTR_THREAD);
	ASSERT(SA(t->t_sp) == t->t_sp);

	t->t_pc = (uintptr_t)_sys_rtt;
	return (it->t_pil);
}

#endif	/* __amd64 */

/*
 * Allocate threads and stacks for interrupt handling.
 */
#define	NINTR_THREADS	(LOCK_LEVEL-1)	/* number of interrupt threads */

void
init_intr_threads(struct cpu *cp)
{
	int i;

	for (i = 0; i < NINTR_THREADS; i++)
		thread_create_intr(cp);

	cp->cpu_intr_stack = (caddr_t)segkp_get(segkp, INTR_STACK_SIZE,
		KPD_HASREDZONE | KPD_NO_ANON | KPD_LOCKED) +
		INTR_STACK_SIZE - SA(MINFRAME);
}

/*
 * Create interrupt kstats for this CPU.
 */
void
cpu_create_intrstat(cpu_t *cp)
{
	int		i;
	kstat_t		*intr_ksp;
	kstat_named_t	*knp;
	char		name[KSTAT_STRLEN];
	zoneid_t	zoneid;

	ASSERT(MUTEX_HELD(&cpu_lock));

	if (pool_pset_enabled())
		zoneid = GLOBAL_ZONEID;
	else
		zoneid = ALL_ZONES;

	intr_ksp = kstat_create_zone("cpu", cp->cpu_id, "intrstat", "misc",
	    KSTAT_TYPE_NAMED, PIL_MAX * 2, NULL, zoneid);

	/*
	 * Initialize each PIL's named kstat
	 */
	if (intr_ksp != NULL) {
		intr_ksp->ks_update = cpu_kstat_intrstat_update;
		knp = (kstat_named_t *)intr_ksp->ks_data;
		intr_ksp->ks_private = cp;
		for (i = 0; i < PIL_MAX; i++) {
			(void) snprintf(name, KSTAT_STRLEN, "level-%d-time",
			    i + 1);
			kstat_named_init(&knp[i * 2], name, KSTAT_DATA_UINT64);
			(void) snprintf(name, KSTAT_STRLEN, "level-%d-count",
			    i + 1);
			kstat_named_init(&knp[(i * 2) + 1], name,
			    KSTAT_DATA_UINT64);
		}
		kstat_install(intr_ksp);
	}
}

/*
 * Delete interrupt kstats for this CPU.
 */
void
cpu_delete_intrstat(cpu_t *cp)
{
	kstat_delete_byname_zone("cpu", cp->cpu_id, "intrstat", ALL_ZONES);
}

/*
 * Convert interrupt statistics from CPU ticks to nanoseconds and
 * update kstat.
 */
int
cpu_kstat_intrstat_update(kstat_t *ksp, int rw)
{
	kstat_named_t	*knp = ksp->ks_data;
	cpu_t		*cpup = (cpu_t *)ksp->ks_private;
	int		i;
	hrtime_t	hrt;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	for (i = 0; i < PIL_MAX; i++) {
		hrt = (hrtime_t)cpup->cpu_m.intrstat[i + 1][0];
		tsc_scalehrtime(&hrt);
		knp[i * 2].value.ui64 = (uint64_t)hrt;
		knp[(i * 2) + 1].value.ui64 = cpup->cpu_stats.sys.intr[i];
	}

	return (0);
}

/*
 * An interrupt thread is ending a time slice, so compute the interval it
 * ran for and update the statistic for its PIL.
 */
void
cpu_intr_swtch_enter(kthread_id_t t)
{
	uint64_t	interval;
	uint64_t	start;
	cpu_t		*cpu;

	ASSERT((t->t_flag & T_INTR_THREAD) != 0);
	ASSERT(t->t_pil > 0 && t->t_pil <= LOCK_LEVEL);

	/*
	 * We could be here with a zero timestamp. This could happen if:
	 * an interrupt thread which no longer has a pinned thread underneath
	 * it (i.e. it blocked at some point in its past) has finished running
	 * its handler. intr_thread() updated the interrupt statistic for its
	 * PIL and zeroed its timestamp. Since there was no pinned thread to
	 * return to, swtch() gets called and we end up here.
	 *
	 * Note that we use atomic ops below (cas64 and atomic_add_64), which
	 * we don't use in the functions above, because we're not called
	 * with interrupts blocked, but the epilog/prolog functions are.
	 */
	if (t->t_intr_start) {
		do {
			start = t->t_intr_start;
			interval = tsc_read() - start;
		} while (cas64(&t->t_intr_start, start, 0) != start);
		cpu = CPU;
		cpu->cpu_m.intrstat[t->t_pil][0] += interval;

		atomic_add_64((uint64_t *)&cpu->cpu_intracct[cpu->cpu_mstate],
		    interval);
	} else
		ASSERT(t->t_intr == NULL);
}

/*
 * An interrupt thread is returning from swtch(). Place a starting timestamp
 * in its thread structure.
 */
void
cpu_intr_swtch_exit(kthread_id_t t)
{
	uint64_t ts;

	ASSERT((t->t_flag & T_INTR_THREAD) != 0);
	ASSERT(t->t_pil > 0 && t->t_pil <= LOCK_LEVEL);

	do {
		ts = t->t_intr_start;
	} while (cas64(&t->t_intr_start, ts, tsc_read()) != ts);
}
