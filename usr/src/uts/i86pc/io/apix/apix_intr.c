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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2018 Western Digital Corporation.  All rights reserved.
 */

#include <sys/cpuvar.h>
#include <sys/cpu_event.h>
#include <sys/param.h>
#include <sys/cmn_err.h>
#include <sys/t_lock.h>
#include <sys/kmem.h>
#include <sys/machlock.h>
#include <sys/systm.h>
#include <sys/archsystm.h>
#include <sys/atomic.h>
#include <sys/sdt.h>
#include <sys/processor.h>
#include <sys/time.h>
#include <sys/psm.h>
#include <sys/smp_impldefs.h>
#include <sys/cram.h>
#include <sys/apic.h>
#include <sys/pit.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/pci.h>
#include <sys/promif.h>
#include <sys/x86_archext.h>
#include <sys/cpc_impl.h>
#include <sys/uadmin.h>
#include <sys/panic.h>
#include <sys/debug.h>
#include <sys/trap.h>
#include <sys/machsystm.h>
#include <sys/sysmacros.h>
#include <sys/rm_platter.h>
#include <sys/privregs.h>
#include <sys/note.h>
#include <sys/pci_intr_lib.h>
#include <sys/spl.h>
#include <sys/clock.h>
#include <sys/dditypes.h>
#include <sys/sunddi.h>
#include <sys/x_call.h>
#include <sys/reboot.h>
#include <vm/hat_i86.h>
#include <sys/stack.h>
#include <sys/apix.h>

static void apix_post_hardint(int);

/*
 * Insert an vector into the tail of the interrupt pending list
 */
static __inline__ void
apix_insert_pending_av(apix_impl_t *apixp, struct autovec *avp, int ipl)
{
	struct autovec **head = apixp->x_intr_head;
	struct autovec **tail = apixp->x_intr_tail;

	avp->av_ipl_link = NULL;
	if (tail[ipl] == NULL) {
		head[ipl] = tail[ipl] = avp;
		return;
	}

	tail[ipl]->av_ipl_link = avp;
	tail[ipl] = avp;
}

/*
 * Remove and return an vector from the head of hardware interrupt
 * pending list.
 */
static __inline__ struct autovec *
apix_remove_pending_av(apix_impl_t *apixp, int ipl)
{
	struct cpu *cpu = CPU;
	struct autovec **head = apixp->x_intr_head;
	struct autovec **tail = apixp->x_intr_tail;
	struct autovec *avp = head[ipl];

	if (avp == NULL)
		return (NULL);

	if (avp->av_vector != NULL && avp->av_prilevel < cpu->cpu_base_spl) {
		/*
		 * If there is blocked higher level interrupts, return
		 * NULL to quit handling of current IPL level.
		 */
		apixp->x_intr_pending |= (1 << avp->av_prilevel);
		return (NULL);
	}

	avp->av_flags &= ~AV_PENTRY_PEND;
	avp->av_flags |= AV_PENTRY_ONPROC;
	head[ipl] = avp->av_ipl_link;
	avp->av_ipl_link = NULL;

	if (head[ipl] == NULL)
		tail[ipl] = NULL;

	return (avp);
}

/*
 * add_pending_hardint:
 *
 * Add hardware interrupts to the interrupt pending list.
 */
static void
apix_add_pending_hardint(int vector)
{
	uint32_t cpuid = psm_get_cpu_id();
	apix_impl_t *apixp = apixs[cpuid];
	apix_vector_t *vecp = apixp->x_vectbl[vector];
	struct autovec *p, *prevp = NULL;
	int ipl;

	/*
	 * The MSI interrupt not supporting per-vector masking could
	 * be triggered on a false vector as a result of rebinding
	 * operation cannot programme MSI address & data atomically.
	 * Add ISR of this interrupt to the pending list for such
	 * suspicious interrupt.
	 */
	APIX_DO_FAKE_INTR(cpuid, vector);
	if (vecp == NULL)
		return;

	for (p = vecp->v_autovect; p != NULL; p = p->av_link) {
		if (p->av_vector == NULL)
			continue;	/* skip freed entry */

		ipl = p->av_prilevel;
		prevp = p;

		/* set pending at specified priority level */
		apixp->x_intr_pending |= (1 << ipl);

		if (p->av_flags & AV_PENTRY_PEND)
			continue;	/* already in the pending list */
		p->av_flags |= AV_PENTRY_PEND;

		/* insert into pending list by it original IPL */
		apix_insert_pending_av(apixp, p, ipl);
	}

	/* last one of the linked list */
	if (prevp && ((prevp->av_flags & AV_PENTRY_LEVEL) != 0))
		prevp->av_flags |= (vector & AV_PENTRY_VECTMASK);
}

/*
 * Walk pending hardware interrupts at given priority level, invoking
 * each interrupt handler as we go.
 */
extern uint64_t intr_get_time(void);

static void
apix_dispatch_pending_autovect(uint_t ipl)
{
	uint32_t cpuid = psm_get_cpu_id();
	apix_impl_t *apixp = apixs[cpuid];
	struct autovec *av;

	while ((av = apix_remove_pending_av(apixp, ipl)) != NULL) {
		uint_t r;
		uint_t (*intr)() = av->av_vector;
		caddr_t arg1 = av->av_intarg1;
		caddr_t arg2 = av->av_intarg2;
		dev_info_t *dip = av->av_dip;
		uchar_t vector = av->av_flags & AV_PENTRY_VECTMASK;

		if (intr == NULL)
			continue;

		/* Don't enable interrupts during x-calls */
		if (ipl != XC_HI_PIL)
			sti();

		DTRACE_PROBE4(interrupt__start, dev_info_t *, dip,
		    void *, intr, caddr_t, arg1, caddr_t, arg2);
		r = (*intr)(arg1, arg2);
		DTRACE_PROBE4(interrupt__complete, dev_info_t *, dip,
		    void *, intr, caddr_t, arg1, uint_t, r);

		if (av->av_ticksp && av->av_prilevel <= LOCK_LEVEL)
			atomic_add_64(av->av_ticksp, intr_get_time());

		cli();

		if (vector) {
			if ((av->av_flags & AV_PENTRY_PEND) == 0)
				av->av_flags &= ~AV_PENTRY_VECTMASK;

			apix_post_hardint(vector);
		}

		/* mark it as idle */
		av->av_flags &= ~AV_PENTRY_ONPROC;
	}
}

static caddr_t
apix_do_softint_prolog(struct cpu *cpu, uint_t pil, uint_t oldpil,
    caddr_t stackptr)
{
	kthread_t *t, *volatile it;
	struct machcpu *mcpu = &cpu->cpu_m;
	hrtime_t now;

	UNREFERENCED_1PARAMETER(oldpil);
	ASSERT(pil > mcpu->mcpu_pri && pil > cpu->cpu_base_spl);

	atomic_and_32((uint32_t *)&mcpu->mcpu_softinfo.st_pending, ~(1 << pil));

	mcpu->mcpu_pri = pil;

	now = tsc_read();

	/*
	 * Get set to run interrupt thread.
	 * There should always be an interrupt thread since we
	 * allocate one for each level on the CPU.
	 */
	it = cpu->cpu_intr_thread;
	ASSERT(it != NULL);
	cpu->cpu_intr_thread = it->t_link;

	/* t_intr_start could be zero due to cpu_intr_swtch_enter. */
	t = cpu->cpu_thread;
	if ((t->t_flag & T_INTR_THREAD) && t->t_intr_start != 0) {
		hrtime_t intrtime = now - t->t_intr_start;
		mcpu->intrstat[pil][0] += intrtime;
		cpu->cpu_intracct[cpu->cpu_mstate] += intrtime;
		t->t_intr_start = 0;
	}

	/*
	 * Note that the code in kcpc_overflow_intr -relies- on the
	 * ordering of events here - in particular that t->t_lwp of
	 * the interrupt thread is set to the pinned thread *before*
	 * curthread is changed.
	 */
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
	it->t_intr_start = now;

	return (it->t_stk);
}

static void
apix_do_softint_epilog(struct cpu *cpu, uint_t oldpil)
{
	struct machcpu *mcpu = &cpu->cpu_m;
	kthread_t *t, *it;
	uint_t pil, basespl;
	hrtime_t intrtime;
	hrtime_t now = tsc_read();

	it = cpu->cpu_thread;
	pil = it->t_pil;

	cpu->cpu_stats.sys.intr[pil - 1]++;

	ASSERT(cpu->cpu_intr_actv & (1 << pil));
	cpu->cpu_intr_actv &= ~(1 << pil);

	intrtime = now - it->t_intr_start;
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
		/* mcpu->mcpu_pri = cpu->cpu_base_spl; */

		/*
		 * If there are pending interrupts, send a softint to
		 * re-enter apix_do_interrupt() and get them processed.
		 */
		if (apixs[cpu->cpu_id]->x_intr_pending)
			siron();

		it->t_state = TS_FREE;
		it->t_link = cpu->cpu_intr_thread;
		cpu->cpu_intr_thread = it;
		(void) splhigh();
		sti();
		swtch();
		/*NOTREACHED*/
		panic("dosoftint_epilog: swtch returned");
	}
	it->t_link = cpu->cpu_intr_thread;
	cpu->cpu_intr_thread = it;
	it->t_state = TS_FREE;
	cpu->cpu_thread = t;
	if (t->t_flag & T_INTR_THREAD)
		t->t_intr_start = now;
	basespl = cpu->cpu_base_spl;
	pil = MAX(oldpil, basespl);
	mcpu->mcpu_pri = pil;
}

/*
 * Dispatch a soft interrupt
 */
static void
apix_dispatch_softint(uint_t oldpil, uint_t arg2)
{
	struct cpu *cpu = CPU;

	UNREFERENCED_1PARAMETER(arg2);

	sti();
	av_dispatch_softvect((int)cpu->cpu_thread->t_pil);
	cli();

	/*
	 * Must run softint_epilog() on the interrupt thread stack, since
	 * there may not be a return from it if the interrupt thread blocked.
	 */
	apix_do_softint_epilog(cpu, oldpil);
}

/*
 * Deliver any softints the current interrupt priority allows.
 * Called with interrupts disabled.
 */
int
apix_do_softint(struct regs *regs)
{
	struct cpu *cpu = CPU;
	int oldipl;
	int newipl;
	volatile uint16_t pending;
	caddr_t newsp;

	while ((pending = cpu->cpu_softinfo.st_pending) != 0) {
		newipl = bsrw_insn(pending);
		oldipl = cpu->cpu_pri;
		if (newipl <= oldipl || newipl <= cpu->cpu_base_spl)
			return (-1);

		newsp = apix_do_softint_prolog(cpu, newipl, oldipl,
		    (caddr_t)regs);
		ASSERT(newsp != NULL);
		switch_sp_and_call(newsp, apix_dispatch_softint, oldipl, 0);
	}

	return (0);
}

static int
apix_hilevel_intr_prolog(struct cpu *cpu, uint_t pil, uint_t oldpil,
    struct regs *rp)
{
	struct machcpu *mcpu = &cpu->cpu_m;
	hrtime_t intrtime;
	hrtime_t now = tsc_read();
	apix_impl_t *apixp = apixs[cpu->cpu_id];
	uint_t mask;

	ASSERT(pil > mcpu->mcpu_pri && pil > cpu->cpu_base_spl);

	if (pil == CBE_HIGH_PIL) {	/* 14 */
		cpu->cpu_profile_pil = oldpil;
		if (USERMODE(rp->r_cs)) {
			cpu->cpu_profile_pc = 0;
			cpu->cpu_profile_upc = rp->r_pc;
			cpu->cpu_cpcprofile_pc = 0;
			cpu->cpu_cpcprofile_upc = rp->r_pc;
		} else {
			cpu->cpu_profile_pc = rp->r_pc;
			cpu->cpu_profile_upc = 0;
			cpu->cpu_cpcprofile_pc = rp->r_pc;
			cpu->cpu_cpcprofile_upc = 0;
		}
	}

	mcpu->mcpu_pri = pil;

	mask = cpu->cpu_intr_actv & CPU_INTR_ACTV_HIGH_LEVEL_MASK;
	if (mask != 0) {
		int nestpil;

		/*
		 * We have interrupted another high-level interrupt.
		 * Load starting timestamp, compute interval, update
		 * cumulative counter.
		 */
		nestpil = bsrw_insn((uint16_t)mask);
		intrtime = now -
		    mcpu->pil_high_start[nestpil - (LOCK_LEVEL + 1)];
		mcpu->intrstat[nestpil][0] += intrtime;
		cpu->cpu_intracct[cpu->cpu_mstate] += intrtime;
	} else {
		kthread_t *t = cpu->cpu_thread;

		/*
		 * See if we are interrupting a low-level interrupt thread.
		 * If so, account for its time slice only if its time stamp
		 * is non-zero.
		 */
		if ((t->t_flag & T_INTR_THREAD) != 0 && t->t_intr_start != 0) {
			intrtime = now - t->t_intr_start;
			mcpu->intrstat[t->t_pil][0] += intrtime;
			cpu->cpu_intracct[cpu->cpu_mstate] += intrtime;
			t->t_intr_start = 0;
		}
	}

	/* store starting timestamp in CPu structure for this IPL */
	mcpu->pil_high_start[pil - (LOCK_LEVEL + 1)] = now;

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

	cpu->cpu_intr_actv |= (1 << pil);
	/* clear pending ipl level bit */
	apixp->x_intr_pending &= ~(1 << pil);

	return (mask);
}

static int
apix_hilevel_intr_epilog(struct cpu *cpu, uint_t oldpil)
{
	struct machcpu *mcpu = &cpu->cpu_m;
	uint_t mask, pil;
	hrtime_t intrtime;
	hrtime_t now = tsc_read();

	pil = mcpu->mcpu_pri;
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

	intrtime = now - mcpu->pil_high_start[pil - (LOCK_LEVEL + 1)];
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
		mcpu->pil_high_start[nestpil - (LOCK_LEVEL + 1)] = now;
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
			t->t_intr_start = now;
	}

	mcpu->mcpu_pri = oldpil;
	if (pil < CBE_HIGH_PIL)
		(void) (*setlvlx)(oldpil, 0);

	return (mask);
}

/*
 * Dispatch a hilevel interrupt (one above LOCK_LEVEL)
 */
static void
apix_dispatch_pending_hilevel(uint_t ipl, uint_t arg2)
{
	UNREFERENCED_1PARAMETER(arg2);

	apix_dispatch_pending_autovect(ipl);
}

static __inline__ int
apix_do_pending_hilevel(struct cpu *cpu, struct regs *rp)
{
	volatile uint16_t pending;
	uint_t newipl, oldipl;
	caddr_t newsp;

	while ((pending = HILEVEL_PENDING(cpu)) != 0) {
		newipl = bsrw_insn(pending);
		ASSERT(newipl > LOCK_LEVEL && newipl > cpu->cpu_base_spl);
		oldipl = cpu->cpu_pri;
		if (newipl <= oldipl)
			return (-1);

		/*
		 * High priority interrupts run on this cpu's interrupt stack.
		 */
		if (apix_hilevel_intr_prolog(cpu, newipl, oldipl, rp) == 0) {
			newsp = cpu->cpu_intr_stack;
			switch_sp_and_call(newsp, apix_dispatch_pending_hilevel,
			    newipl, 0);
		} else {	/* already on the interrupt stack */
			apix_dispatch_pending_hilevel(newipl, 0);
		}
		(void) apix_hilevel_intr_epilog(cpu, oldipl);
	}

	return (0);
}

/*
 * Get an interrupt thread and swith to it. It's called from do_interrupt().
 * The IF flag is cleared and thus all maskable interrupts are blocked at
 * the time of calling.
 */
static caddr_t
apix_intr_thread_prolog(struct cpu *cpu, uint_t pil, caddr_t stackptr)
{
	apix_impl_t *apixp = apixs[cpu->cpu_id];
	struct machcpu *mcpu = &cpu->cpu_m;
	hrtime_t now = tsc_read();
	kthread_t *t, *volatile it;

	ASSERT(pil > mcpu->mcpu_pri && pil > cpu->cpu_base_spl);

	apixp->x_intr_pending &= ~(1 << pil);
	ASSERT((cpu->cpu_intr_actv & (1 << pil)) == 0);
	cpu->cpu_intr_actv |= (1 << pil);
	mcpu->mcpu_pri = pil;

	/*
	 * Get set to run interrupt thread.
	 * There should always be an interrupt thread since we
	 * allocate one for each level on the CPU.
	 */
	/* t_intr_start could be zero due to cpu_intr_swtch_enter. */
	t = cpu->cpu_thread;
	if ((t->t_flag & T_INTR_THREAD) && t->t_intr_start != 0) {
		hrtime_t intrtime = now - t->t_intr_start;
		mcpu->intrstat[pil][0] += intrtime;
		cpu->cpu_intracct[cpu->cpu_mstate] += intrtime;
		t->t_intr_start = 0;
	}

	/*
	 * Push interrupted thread onto list from new thread.
	 * Set the new thread as the current one.
	 * Set interrupted thread's T_SP because if it is the idle thread,
	 * resume() may use that stack between threads.
	 */

	ASSERT(SA((uintptr_t)stackptr) == (uintptr_t)stackptr);

	t->t_sp = (uintptr_t)stackptr;	/* mark stack in curthread for resume */

	/*
	 * Note that the code in kcpc_overflow_intr -relies- on the
	 * ordering of events here - in particular that t->t_lwp of
	 * the interrupt thread is set to the pinned thread *before*
	 * curthread is changed.
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

	cpu->cpu_thread = it;

	/*
	 * Initialize thread priority level from intr_pri
	 */
	it->t_pil = (uchar_t)pil;
	it->t_pri = (pri_t)pil + intr_pri;
	it->t_intr_start = now;

	return (it->t_stk);
}

static void
apix_intr_thread_epilog(struct cpu *cpu, uint_t oldpil)
{
	struct machcpu *mcpu = &cpu->cpu_m;
	kthread_t *t, *it = cpu->cpu_thread;
	uint_t pil, basespl;
	hrtime_t intrtime;
	hrtime_t now = tsc_read();

	pil = it->t_pil;
	cpu->cpu_stats.sys.intr[pil - 1]++;

	ASSERT(cpu->cpu_intr_actv & (1 << pil));
	cpu->cpu_intr_actv &= ~(1 << pil);

	ASSERT(it->t_intr_start != 0);
	intrtime = now - it->t_intr_start;
	mcpu->intrstat[pil][0] += intrtime;
	cpu->cpu_intracct[cpu->cpu_mstate] += intrtime;

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
		cpu->cpu_stats.sys.intrblk++;

		/*
		 * Put thread back on the interrupt thread list.
		 * This was an interrupt thread, so set CPU's base SPL.
		 */
		set_base_spl();
		basespl = cpu->cpu_base_spl;
		mcpu->mcpu_pri = basespl;
		(*setlvlx)(basespl, 0);

		/*
		 * If there are pending interrupts, send a softint to
		 * re-enter apix_do_interrupt() and get them processed.
		 */
		if (apixs[cpu->cpu_id]->x_intr_pending)
			siron();

		it->t_state = TS_FREE;
		/*
		 * Return interrupt thread to pool
		 */
		it->t_link = cpu->cpu_intr_thread;
		cpu->cpu_intr_thread = it;

		(void) splhigh();
		sti();
		swtch();
		/*NOTREACHED*/
		panic("dosoftint_epilog: swtch returned");
	}

	/*
	 * Return interrupt thread to the pool
	 */
	it->t_link = cpu->cpu_intr_thread;
	cpu->cpu_intr_thread = it;
	it->t_state = TS_FREE;

	cpu->cpu_thread = t;
	if (t->t_flag & T_INTR_THREAD)
		t->t_intr_start = now;
	basespl = cpu->cpu_base_spl;
	mcpu->mcpu_pri = MAX(oldpil, basespl);
	(*setlvlx)(mcpu->mcpu_pri, 0);
}


static void
apix_dispatch_pending_hardint(uint_t oldpil, uint_t arg2)
{
	struct cpu *cpu = CPU;

	UNREFERENCED_1PARAMETER(arg2);

	apix_dispatch_pending_autovect((int)cpu->cpu_thread->t_pil);

	/*
	 * Must run intr_thread_epilog() on the interrupt thread stack, since
	 * there may not be a return from it if the interrupt thread blocked.
	 */
	apix_intr_thread_epilog(cpu, oldpil);
}

static __inline__ int
apix_do_pending_hardint(struct cpu *cpu, struct regs *rp)
{
	volatile uint16_t pending;
	uint_t newipl, oldipl;
	caddr_t newsp;

	while ((pending = LOWLEVEL_PENDING(cpu)) != 0) {
		newipl = bsrw_insn(pending);
		ASSERT(newipl <= LOCK_LEVEL);
		oldipl = cpu->cpu_pri;
		if (newipl <= oldipl || newipl <= cpu->cpu_base_spl)
			return (-1);

		/*
		 * Run this interrupt in a separate thread.
		 */
		newsp = apix_intr_thread_prolog(cpu, newipl, (caddr_t)rp);
		ASSERT(newsp != NULL);
		switch_sp_and_call(newsp, apix_dispatch_pending_hardint,
		    oldipl, 0);
	}

	return (0);
}

/*
 * Unmask level triggered interrupts
 */
static void
apix_post_hardint(int vector)
{
	apix_vector_t *vecp = xv_vector(psm_get_cpu_id(), vector);
	int irqno = vecp->v_inum;

	ASSERT(vecp->v_type == APIX_TYPE_FIXED && apic_level_intr[irqno]);

	apix_level_intr_post_dispatch(irqno);
}

static void
apix_dispatch_by_vector(uint_t vector)
{
	struct cpu *cpu = CPU;
	apix_vector_t *vecp = xv_vector(cpu->cpu_id, vector);
	struct autovec *avp;
	uint_t r, (*intr)();
	caddr_t arg1, arg2;
	dev_info_t *dip;

	if (vecp == NULL ||
	    (avp = vecp->v_autovect) == NULL || avp->av_vector == NULL)
		return;

	avp->av_flags |= AV_PENTRY_ONPROC;
	intr = avp->av_vector;
	arg1 = avp->av_intarg1;
	arg2 = avp->av_intarg2;
	dip = avp->av_dip;

	if (avp->av_prilevel != XC_HI_PIL)
		sti();

	DTRACE_PROBE4(interrupt__start, dev_info_t *, dip,
	    void *, intr, caddr_t, arg1, caddr_t, arg2);
	r = (*intr)(arg1, arg2);
	DTRACE_PROBE4(interrupt__complete, dev_info_t *, dip,
	    void *, intr, caddr_t, arg1, uint_t, r);

	cli();
	avp->av_flags &= ~AV_PENTRY_ONPROC;
}


static void
apix_dispatch_hilevel(uint_t vector, uint_t arg2)
{
	UNREFERENCED_1PARAMETER(arg2);

	apix_dispatch_by_vector(vector);
}

static void
apix_dispatch_lowlevel(uint_t vector, uint_t oldipl)
{
	struct cpu *cpu = CPU;

	apix_dispatch_by_vector(vector);

	/*
	 * Must run intr_thread_epilog() on the interrupt thread stack, since
	 * there may not be a return from it if the interrupt thread blocked.
	 */
	apix_intr_thread_epilog(cpu, oldipl);
}

/*
 * Interrupt service routine, called with interrupts disabled.
 */
void
apix_do_interrupt(struct regs *rp, trap_trace_rec_t *ttp)
{
	struct cpu *cpu = CPU;
	int vector = rp->r_trapno, newipl, oldipl = cpu->cpu_pri, ret;
	apix_vector_t *vecp = NULL;

#ifdef TRAPTRACE
	ttp->ttr_marker = TT_INTERRUPT;
	ttp->ttr_cpuid = cpu->cpu_id;
	ttp->ttr_ipl = 0xff;
	ttp->ttr_pri = (uchar_t)oldipl;
	ttp->ttr_spl = cpu->cpu_base_spl;
	ttp->ttr_vector = 0xff;
#endif	/* TRAPTRACE */

	cpu_idle_exit(CPU_IDLE_CB_FLAG_INTR);

	++*(uint16_t *)&cpu->cpu_m.mcpu_istamp;

	/*
	 * If it's a softint go do it now.
	 */
	if (rp->r_trapno == T_SOFTINT) {
		/*
		 * It might be the case that when an interrupt is triggered,
		 * the spl is raised to high by splhigh(). Later when do_splx()
		 * is called to restore the spl, both hardware and software
		 * interrupt pending flags are check and an SOFTINT is faked
		 * accordingly.
		 */
		(void) apix_do_pending_hilevel(cpu, rp);
		(void) apix_do_pending_hardint(cpu, rp);
		(void) apix_do_softint(rp);
		ASSERT(!interrupts_enabled());
#ifdef TRAPTRACE
		ttp->ttr_vector = T_SOFTINT;
#endif
		/*
		 * We need to check again for pending interrupts that may have
		 * arrived while the softint was running.
		 */
		goto do_pending;
	}

	/*
	 * Send EOI to local APIC
	 */
	newipl = (*setlvl)(oldipl, (int *)&rp->r_trapno);
#ifdef TRAPTRACE
	ttp->ttr_ipl = (uchar_t)newipl;
#endif	/* TRAPTRACE */

	/*
	 * Bail if it is a spurious interrupt
	 */
	if (newipl == -1)
		return;

	vector = rp->r_trapno;
	vecp = xv_vector(cpu->cpu_id, vector);
#ifdef TRAPTRACE
	ttp->ttr_vector = (short)vector;
#endif	/* TRAPTRACE */

	/*
	 * Direct dispatch for IPI, MSI, MSI-X
	 */
	if (vecp && vecp->v_type != APIX_TYPE_FIXED &&
	    newipl > MAX(oldipl, cpu->cpu_base_spl)) {
		caddr_t newsp;

		if (INTR_PENDING(apixs[cpu->cpu_id], newipl)) {
			/*
			 * There are already vectors pending at newipl,
			 * queue this one and fall through to process
			 * all pending.
			 */
			apix_add_pending_hardint(vector);
		} else if (newipl > LOCK_LEVEL) {
			if (apix_hilevel_intr_prolog(cpu, newipl, oldipl, rp)
			    == 0) {
				newsp = cpu->cpu_intr_stack;
				switch_sp_and_call(newsp, apix_dispatch_hilevel,
				    vector, 0);
			} else {
				apix_dispatch_hilevel(vector, 0);
			}
			(void) apix_hilevel_intr_epilog(cpu, oldipl);
		} else {
			newsp = apix_intr_thread_prolog(cpu, newipl,
			    (caddr_t)rp);
			switch_sp_and_call(newsp, apix_dispatch_lowlevel,
			    vector, oldipl);
		}
	} else {
		/* Add to per-pil pending queue */
		apix_add_pending_hardint(vector);
		if (newipl <= MAX(oldipl, cpu->cpu_base_spl) ||
		    !apixs[cpu->cpu_id]->x_intr_pending)
			return;
	}

do_pending:
	if (apix_do_pending_hilevel(cpu, rp) < 0)
		return;

	do {
		ret = apix_do_pending_hardint(cpu, rp);

		/*
		 * Deliver any pending soft interrupts.
		 */
		(void) apix_do_softint(rp);
	} while (!ret && LOWLEVEL_PENDING(cpu));
}
