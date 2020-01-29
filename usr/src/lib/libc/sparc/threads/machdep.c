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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include "lint.h"
#include "thr_uberdata.h"
#include <procfs.h>
#include <setjmp.h>
#include <sys/fsr.h>
#include "sigjmp_struct.h"

extern int getlwpstatus(thread_t, lwpstatus_t *);
extern int putlwpregs(thread_t, prgregset_t);

/* ARGSUSED2 */
void *
setup_top_frame(void *stk, size_t stksize, ulwp_t *ulwp)
{
	uintptr_t stack;
	char frame[SA(MINFRAME)];

	/*
	 * Top-of-stack must be rounded down to STACK_ALIGN and
	 * there must be a minimum frame for the register window.
	 */
	stack = (((uintptr_t)stk + stksize) & ~(STACK_ALIGN - 1)) -
	    SA(MINFRAME);

	/*
	 * This will return NULL if the kernel cannot allocate
	 * a page for the top page of the stack.  This will cause
	 * thr_create(), pthread_create() or pthread_attr_setstack()
	 * to fail, passing the problem up to the application.
	 */
	(void) memset(frame, 0, sizeof (frame));
	if (uucopy(frame, (void *)stack, sizeof (frame)) == 0)
		return ((void *)stack);
	return (NULL);
}

int
setup_context(ucontext_t *ucp, void *(*func)(ulwp_t *),
    ulwp_t *ulwp, caddr_t stk, size_t stksize)
{
	uintptr_t stack;

	/* clear the context */
	(void) memset(ucp, 0, sizeof (*ucp));

	/*
	 * Clear the top stack frame.
	 * If this fails, pass the problem up to the application.
	 */
	stack = (uintptr_t)setup_top_frame(stk, stksize, ulwp);
	if (stack == (uintptr_t)NULL)
		return (ENOMEM);

	/* fill in registers of interest */
	ucp->uc_flags |= UC_CPU;
	ucp->uc_mcontext.gregs[REG_PC] = (greg_t)func;
	ucp->uc_mcontext.gregs[REG_nPC] = (greg_t)func + 4;
	ucp->uc_mcontext.gregs[REG_O0] = (greg_t)ulwp;
	ucp->uc_mcontext.gregs[REG_SP] = (greg_t)(stack - STACK_BIAS);
	ucp->uc_mcontext.gregs[REG_O7] = (greg_t)_lwp_start;
	ucp->uc_mcontext.gregs[REG_G7] = (greg_t)ulwp;

	return (0);
}

/*
 * Machine-dependent startup code for a newly-created thread.
 */
void *
_thrp_setup(ulwp_t *self)
{
	extern void _setfsr(greg_t *);

	if (self->ul_fpuenv.fpu_en)
		_setfsr(&self->ul_fpuenv.fsr);

	self->ul_ustack.ss_sp = (void *)(self->ul_stktop - self->ul_stksiz);
	self->ul_ustack.ss_size = self->ul_stksiz;
	self->ul_ustack.ss_flags = 0;
	(void) setustack(&self->ul_ustack);

	update_sched(self);
	tls_setup();

	/* signals have been deferred until now */
	sigon(self);

	if (self->ul_cancel_pending == 2 && !self->ul_cancel_disabled)
		return (NULL);	/* cancelled by pthread_create() */
	return (self->ul_startpc(self->ul_startarg));
}

void
_fpinherit(ulwp_t *ulwp)
{
	extern void _getfsr(greg_t *);
	int fpu_enabled;

#ifdef __sparcv9
	extern greg_t _getfprs();
	fpu_enabled = _getfprs() & FPRS_FEF;
#else
	extern psw_t _getpsr();
	fpu_enabled = _getpsr() & PSR_EF;
#endif /* __sparcv9 */

	if (fpu_enabled) {
		_getfsr(&ulwp->ul_fpuenv.fsr);
		ulwp->ul_fpuenv.fpu_en = 1;
	} else {
		ulwp->ul_fpuenv.fpu_en = 0;
	}
}

void
getgregs(ulwp_t *ulwp, gregset_t rs)
{
	lwpstatus_t status;

	if (getlwpstatus(ulwp->ul_lwpid, &status) == 0) {
		rs[REG_PC] = status.pr_reg[R_PC];
		rs[REG_O6] = status.pr_reg[R_O6];
		rs[REG_O7] = status.pr_reg[R_O7];
		rs[REG_G1] = status.pr_reg[R_G1];
		rs[REG_G2] = status.pr_reg[R_G2];
		rs[REG_G3] = status.pr_reg[R_G3];
		rs[REG_G4] = status.pr_reg[R_G4];
	} else {
		rs[REG_PC] = 0;
		rs[REG_O6] = 0;
		rs[REG_O7] = 0;
		rs[REG_G1] = 0;
		rs[REG_G2] = 0;
		rs[REG_G3] = 0;
		rs[REG_G4] = 0;
	}
}

void
setgregs(ulwp_t *ulwp, gregset_t rs)
{
	lwpstatus_t status;

	if (getlwpstatus(ulwp->ul_lwpid, &status) == 0) {
		status.pr_reg[R_PC] = rs[REG_PC];
		status.pr_reg[R_O6] = rs[REG_O6];
		status.pr_reg[R_O7] = rs[REG_O7];
		status.pr_reg[R_G1] = rs[REG_G1];
		status.pr_reg[R_G2] = rs[REG_G2];
		status.pr_reg[R_G3] = rs[REG_G3];
		status.pr_reg[R_G4] = rs[REG_G4];
		(void) putlwpregs(ulwp->ul_lwpid, status.pr_reg);
	}
}

int
__csigsetjmp(sigjmp_buf env, int savemask)
{
	sigjmp_struct_t *bp = (sigjmp_struct_t *)env;
	ulwp_t *self = curthread;

	/*
	 * bp->sjs_sp, bp->sjs_pc, bp->sjs_fp and bp->sjs_i7 are already set.
	 * Also, if we are running in 64-bit mode (__sparcv9),
	 * then bp->sjs_asi and bp->sjs_fprs are already set.
	 */
	bp->sjs_flags = JB_FRAMEPTR;
	bp->sjs_uclink = self->ul_siglink;
	if (self->ul_ustack.ss_flags & SS_ONSTACK)
		bp->sjs_stack = self->ul_ustack;
	else {
		bp->sjs_stack.ss_sp =
		    (void *)(self->ul_stktop - self->ul_stksiz);
		bp->sjs_stack.ss_size = self->ul_stksiz;
		bp->sjs_stack.ss_flags = 0;
	}
	if (savemask) {
		bp->sjs_flags |= JB_SAVEMASK;
		enter_critical(self);
		bp->sjs_sigmask = self->ul_sigmask;
		exit_critical(self);
	}

	return (0);
}
