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
	static int initialized;
	static greg_t fs, es, ds, cs, ss;

	uint32_t *stack;

	if (!initialized) {
		ucontext_t uc;

		/* do this once to load the segment registers */
		uc.uc_flags = UC_CPU;
		(void) __getcontext_syscall(&uc);
		fs = uc.uc_mcontext.gregs[FS];
		es = uc.uc_mcontext.gregs[ES];
		ds = uc.uc_mcontext.gregs[DS];
		cs = uc.uc_mcontext.gregs[CS];
		ss = uc.uc_mcontext.gregs[SS];
		initialized = 1;
	}
	/* clear the context and set the segment registers */
	(void) _memset(ucp, 0, sizeof (*ucp));
	ucp->uc_mcontext.gregs[FS] = fs;
	ucp->uc_mcontext.gregs[ES] = es;
	ucp->uc_mcontext.gregs[DS] = ds;
	ucp->uc_mcontext.gregs[CS] = cs;
	ucp->uc_mcontext.gregs[SS] = ss;

	/*
	 * Yuck.
	 * Use unused kernel pointer field in ucontext
	 * to pass down self pointer and set %gs selector
	 * value so __lwp_create() can setup %gs atomically.
	 * Without this we would need to block all signals
	 * and directly call __lwp_setprivate() in _thr_setup
	 * on the other side of __lwp_create().
	 */
	ucp->uc_mcontext.gregs[ESP] = (greg_t)ulwp;
	ucp->uc_mcontext.gregs[GS] = (greg_t)LWPGS_SEL;

	/* top-of-stack must be rounded down to STACK_ALIGN */
	stack = (uint32_t *)(((uintptr_t)stk + stksize) & ~(STACK_ALIGN-1));

	/* set up top stack frame */
	*--stack = 0;
	*--stack = 0;
	*--stack = (uint32_t)ulwp;
	*--stack = (uint32_t)_lwp_start;

	/* fill in registers of interest */
	ucp->uc_flags |= UC_CPU;
	ucp->uc_mcontext.gregs[EIP] = (greg_t)func;
	ucp->uc_mcontext.gregs[UESP] = (greg_t)stack;
	ucp->uc_mcontext.gregs[EBP] = (greg_t)(stack+2);

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
	(void) _private_setustack(&self->ul_ustack);

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
		rs[EIP] = status.pr_reg[EIP];
		rs[EDI] = status.pr_reg[EDI];
		rs[ESI] = status.pr_reg[ESI];
		rs[EBP] = status.pr_reg[EBP];
		rs[EBX] = status.pr_reg[EBX];
		rs[UESP] = status.pr_reg[UESP];
	} else {
		rs[EIP] = 0;
		rs[EDI] = 0;
		rs[ESI] = 0;
		rs[EBP] = 0;
		rs[EBX] = 0;
		rs[UESP] = 0;
	}
}

void
setgregs(ulwp_t *ulwp, gregset_t rs)
{
	lwpstatus_t status;

	if (getlwpstatus(ulwp->ul_lwpid, &status) == 0) {
		status.pr_reg[EIP] = rs[EIP];
		status.pr_reg[EDI] = rs[EDI];
		status.pr_reg[ESI] = rs[ESI];
		status.pr_reg[EBP] = rs[EBP];
		status.pr_reg[EBX] = rs[EBX];
		status.pr_reg[UESP] = rs[UESP];
		(void) putlwpregs(ulwp->ul_lwpid, status.pr_reg);
	}
}

int
__csigsetjmp(greg_t cs, greg_t ss, greg_t gs,
	greg_t fs, greg_t es, greg_t ds,
	greg_t edi, greg_t esi, greg_t ebp, greg_t esp,
	greg_t ebx, greg_t edx, greg_t ecx, greg_t eax, greg_t eip,
	sigjmp_buf env, int savemask)
{
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
	ucp->uc_mcontext.gregs[GS] = gs;
	ucp->uc_mcontext.gregs[FS] = fs;
	ucp->uc_mcontext.gregs[ES] = es;
	ucp->uc_mcontext.gregs[DS] = ds;
	ucp->uc_mcontext.gregs[EDI] = edi;
	ucp->uc_mcontext.gregs[ESI] = esi;
	ucp->uc_mcontext.gregs[EBP] = ebp;
	ucp->uc_mcontext.gregs[ESP] = esp + 4;
	ucp->uc_mcontext.gregs[EBX] = ebx;
	ucp->uc_mcontext.gregs[EDX] = edx;
	ucp->uc_mcontext.gregs[ECX] = ecx;
	ucp->uc_mcontext.gregs[EAX] = eax;
	ucp->uc_mcontext.gregs[TRAPNO] = 0;
	ucp->uc_mcontext.gregs[ERR] = 0;
	ucp->uc_mcontext.gregs[EIP] = eip;
	ucp->uc_mcontext.gregs[CS] = cs;
	ucp->uc_mcontext.gregs[EFL] = 0;
	ucp->uc_mcontext.gregs[UESP] = esp + 4;
	ucp->uc_mcontext.gregs[SS] = ss;

	return (0);
}
