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

#include "lint.h"
#include "thr_uberdata.h"
#include <procfs.h>
#include <ucontext.h>
#include <setjmp.h>

extern int getlwpstatus(thread_t, lwpstatus_t *);
extern int putlwpregs(thread_t, prgregset_t);

int
setup_context(ucontext_t *ucp, void *(*func)(ulwp_t *),
	ulwp_t *ulwp, caddr_t stk, size_t stksize)
{
	uint64_t *stack;

	/* clear the context */
	(void) memset(ucp, 0, sizeof (*ucp));

	/* setup to store the current thread pointer in %fs */
	ucp->uc_mcontext.gregs[REG_FSBASE] = (greg_t)ulwp;
	ucp->uc_mcontext.gregs[REG_FS] = 0; /* null selector indicates fsbase */

	/* all contexts should have a valid data segment descriptor for %ss */
	ucp->uc_mcontext.gregs[REG_SS] = UDS_SEL;

	/* top-of-stack must be rounded down to STACK_ALIGN */
	stack = (uint64_t *)(((uintptr_t)stk + stksize) & ~(STACK_ALIGN-1));

	/* set up top stack frame */
	*--stack = 0;
	*--stack = 0;
	*--stack = (uint64_t)_lwp_start;

	/* fill in registers of interest */
	ucp->uc_flags |= UC_CPU;
	ucp->uc_mcontext.gregs[REG_RDI] = (greg_t)ulwp;
	ucp->uc_mcontext.gregs[REG_RIP] = (greg_t)func;
	ucp->uc_mcontext.gregs[REG_RSP] = (greg_t)stack;
	ucp->uc_mcontext.gregs[REG_RBP] = (greg_t)(stack+1);

	return (0);
}

/*
 * Machine-dependent startup code for a newly-created thread.
 */
void *
_thr_setup(ulwp_t *self)
{
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
	ulwp->ul_fpuenv.ftag = 0xffffffff;
}

void
getgregs(ulwp_t *ulwp, gregset_t rs)
{
	lwpstatus_t status;

	if (getlwpstatus(ulwp->ul_lwpid, &status) == 0) {
		rs[REG_RBX] = status.pr_reg[REG_RBX];
		rs[REG_R12] = status.pr_reg[REG_R12];
		rs[REG_R13] = status.pr_reg[REG_R13];
		rs[REG_R14] = status.pr_reg[REG_R14];
		rs[REG_R15] = status.pr_reg[REG_R15];
		rs[REG_RBP] = status.pr_reg[REG_RBP];
		rs[REG_RSP] = status.pr_reg[REG_RSP];
		rs[REG_RIP] = status.pr_reg[REG_RIP];
	} else {
		rs[REG_RBX] = 0;
		rs[REG_R12] = 0;
		rs[REG_R13] = 0;
		rs[REG_R14] = 0;
		rs[REG_R15] = 0;
		rs[REG_RBP] = 0;
		rs[REG_RSP] = 0;
		rs[REG_RIP] = 0;
	}
}

void
setgregs(ulwp_t *ulwp, gregset_t rs)
{
	lwpstatus_t status;

	if (getlwpstatus(ulwp->ul_lwpid, &status) == 0) {
		status.pr_reg[REG_RBX] = rs[REG_RBX];
		status.pr_reg[REG_R12] = rs[REG_R12];
		status.pr_reg[REG_R13] = rs[REG_R13];
		status.pr_reg[REG_R14] = rs[REG_R14];
		status.pr_reg[REG_R15] = rs[REG_R15];
		status.pr_reg[REG_RBP] = rs[REG_RBP];
		status.pr_reg[REG_RSP] = rs[REG_RSP];
		status.pr_reg[REG_RIP] = rs[REG_RIP];
		(void) putlwpregs(ulwp->ul_lwpid, status.pr_reg);
	}
}

int
__csigsetjmp(sigjmp_buf env, int savemask, gregset_t rs)
{
	/* LINTED alignment */
	ucontext_t *ucp = (ucontext_t *)env;
	ulwp_t *self = curthread;

	ucp->uc_link = self->ul_siglink;
	if (self->ul_ustack.ss_flags & SS_ONSTACK)
		ucp->uc_stack = self->ul_ustack;
	else {
		ucp->uc_stack.ss_sp =
		    (void *)(self->ul_stktop - self->ul_stksiz);
		ucp->uc_stack.ss_size = self->ul_stksiz;
		ucp->uc_stack.ss_flags = 0;
	}
	ucp->uc_flags = UC_STACK | UC_CPU;
	if (savemask) {
		ucp->uc_flags |= UC_SIGMASK;
		enter_critical(self);
		ucp->uc_sigmask = self->ul_sigmask;
		exit_critical(self);
	}
	(void) memcpy(ucp->uc_mcontext.gregs, rs, _NGREG * sizeof (greg_t));

	return (0);
}
