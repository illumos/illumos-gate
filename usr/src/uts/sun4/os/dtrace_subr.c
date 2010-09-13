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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/dtrace.h>
#include <sys/fasttrap.h>
#include <sys/x_call.h>
#include <sys/atomic.h>
#include <sys/machsystm.h>

static void
dtrace_xcall_func(uint64_t arg1, uint64_t arg2)
{
	(*(dtrace_xcall_t)arg1)((void *)(arg2));
}

void
dtrace_xcall(processorid_t cpu, dtrace_xcall_t func, void *arg)
{
	if (cpu == DTRACE_CPUALL) {
		xc_all(dtrace_xcall_func, (uint64_t)func, (uint64_t)arg);
	} else {
		xc_one(cpu, dtrace_xcall_func, (uint64_t)func, (uint64_t)arg);
	}
}

/*ARGSUSED*/
static void
dtrace_sync_func(uint64_t arg1, uint64_t arg2)
{
	membar_consumer();
}

void
dtrace_sync(void)
{
	membar_producer();
	xc_all(dtrace_sync_func, 0, 0);
}

void
dtrace_toxic_ranges(void (*func)(uintptr_t base, uintptr_t limit))
{
	(*func)(PIOMAPBASE, PIOMAPBASE + PIOMAPSIZE);
	(*func)(OFW_START_ADDR, OFW_END_ADDR);

	if (hole_end > hole_start)
		(*func)((uintptr_t)hole_start, (uintptr_t)hole_end);
}

int (*dtrace_pid_probe_ptr)(struct regs *);

void
dtrace_pid_probe(struct regs *rp)
{
	krwlock_t *rwp = &CPU->cpu_ft_lock;
	uint32_t instr;

	/*
	 * This trap should only be invoked if there's a corresponding
	 * enabled dtrace probe. If there isn't, send SIGILL as though
	 * the process had executed an invalid trap instruction.
	 */
	rw_enter(rwp, RW_READER);
	if (dtrace_pid_probe_ptr != NULL && (*dtrace_pid_probe_ptr)(rp) == 0) {
		rw_exit(rwp);
		return;
	}
	rw_exit(rwp);

	/*
	 * It is possible that we were preempted after entering the kernel,
	 * and the tracepoint was removed. If it appears that the process hit
	 * our reserved trap instruction, we call send SIGILL just as though
	 * the user had executed an unused trap instruction.
	 */
	if (fuword32((void *)rp->r_pc, &instr) != 0 ||
	    instr == FASTTRAP_INSTR) {
		sigqueue_t *sqp = kmem_zalloc(sizeof (sigqueue_t), KM_SLEEP);
		proc_t *p = curproc;

		sqp->sq_info.si_signo = SIGILL;
		sqp->sq_info.si_code = ILL_ILLTRP;
		sqp->sq_info.si_addr = (caddr_t)rp->r_pc;
		sqp->sq_info.si_trapno = 0x38;

		mutex_enter(&p->p_lock);
		sigaddqa(p, curthread, sqp);
		mutex_exit(&p->p_lock);
		aston(curthread);
	}
}

int (*dtrace_return_probe_ptr)(struct regs *);

void
dtrace_return_probe(struct regs *rp)
{
	krwlock_t *rwp;
	uintptr_t npc = curthread->t_dtrace_npc;
	uint8_t step = curthread->t_dtrace_step;
	uint8_t ret = curthread->t_dtrace_ret;

	if (curthread->t_dtrace_ast) {
		aston(curthread);
		curthread->t_sig_check = 1;
	}

	/*
	 * Clear all user tracing flags.
	 */
	curthread->t_dtrace_ft = 0;

	/*
	 * If we weren't expecting to take a return probe trap, kill the
	 * process as though it had just executed an unassigned trap
	 * instruction.
	 */
	if (step == 0) {
		tsignal(curthread, SIGILL);
		return;
	}

	ASSERT(rp->r_npc == rp->r_pc + 4);

	/*
	 * If we hit this trap unrelated to a return probe, we're just here
	 * to reset the AST flag since we deferred a signal until after we
	 * logically single-stepped the instruction we copied out.
	 */
	if (ret == 0) {
		rp->r_pc = npc;
		rp->r_npc = npc + 4;
		return;
	}

	/*
	 * We need to wait until after we've called the dtrace_return_probe_ptr
	 * function pointer to set %pc and %npc.
	 */
	rwp = &CPU->cpu_ft_lock;
	rw_enter(rwp, RW_READER);
	if (dtrace_return_probe_ptr != NULL)
		(void) (*dtrace_return_probe_ptr)(rp);
	rw_exit(rwp);
	rp->r_pc = npc;
	rp->r_npc = npc + 4;
}

void
dtrace_safe_synchronous_signal(void)
{
	kthread_t *t = curthread;
	struct regs *rp = lwptoregs(ttolwp(t));

	ASSERT(t->t_dtrace_on);

	/*
	 * If we're not actively tracing an instruction, turn off tracing
	 * flags. If the instruction we copied out caused a synchronous
	 * trap, reset the pc and npc back to their original values and turn
	 * off the flags.
	 */
	if (rp->r_pc != t->t_dtrace_scrpc && rp->r_pc != t->t_dtrace_astpc &&
	    rp->r_npc != t->t_dtrace_astpc) {
		t->t_dtrace_ft = 0;
	} else if (rp->r_pc == t->t_dtrace_scrpc) {
		rp->r_pc = t->t_dtrace_pc;
		rp->r_npc = t->t_dtrace_npc;
		t->t_dtrace_ft = 0;
	}
}

int
dtrace_safe_defer_signal(void)
{
	kthread_t *t = curthread;
	struct regs *rp = lwptoregs(ttolwp(t));

	ASSERT(t->t_dtrace_on);

	/*
	 * If we're not actively tracing an instruction, turn off tracing
	 * flags.
	 */
	if (rp->r_pc != t->t_dtrace_scrpc && rp->r_pc != t->t_dtrace_astpc &&
	    rp->r_npc != t->t_dtrace_astpc) {
		t->t_dtrace_ft = 0;
		return (0);
	}

	/*
	 * Otherwise, make sure we'll return to the kernel after executing
	 * the instruction we copied out.
	 */
	if (!t->t_dtrace_step) {
		ASSERT(rp->r_pc == t->t_dtrace_scrpc);
		rp->r_npc = t->t_dtrace_astpc;
		t->t_dtrace_step = 1;
	}

	t->t_dtrace_ast = 1;

	return (1);
}

/*
 * Additional artificial frames for the machine type. For SPARC, we're already
 * accounted for, so return 0.
 */
int
dtrace_mach_aframes(void)
{
	return (0);
}
