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

#include "thr_uberdata.h"
#include <procfs.h>
#include <ucontext.h>
#include <setjmp.h>

/*
 * The stack needs to be 16-byte aligned with a 4-byte bias.  See comment in
 * lib/libc/i386/gen/makectxt.c.
 *
 * Note: If you change it, you need to change it in the following files as
 * well:
 *
 *  - lib/libc/i386/gen/makectxt.c
 *  - lib/common/i386/crti.s
 *  - lib/common/i386/crt1.s
 */
#undef	STACK_ALIGN
#define	STACK_ALIGN	16

extern int getlwpstatus(thread_t, lwpstatus_t *);
extern int putlwpregs(thread_t, prgregset_t);

void *
setup_top_frame(void *stk, size_t stksize, ulwp_t *ulwp)
{
	uint32_t *stack;
	struct {
		uint32_t	rpc;
		uint32_t	arg;
		uint32_t	pad;
		uint32_t	fp;
		uint32_t	pc;
	} frame;

	/*
	 * Top-of-stack must be rounded down to STACK_ALIGN and
	 * there must be a minimum frame.  Note: 'frame' is not a true
	 * stack frame (see <sys/frame.h>) but a construction made here to
	 * make it look like _lwp_start called the thread start function
	 * with a 16-byte aligned stack pointer (the address of frame.arg
	 * is the address that muet be aligned on a 16-byte boundary).
	 */
	stack = (uint32_t *)(((uintptr_t)stk + stksize) & ~(STACK_ALIGN-1));

	/*
	 * This will return NULL if the kernel cannot allocate
	 * a page for the top page of the stack.  This will cause
	 * thr_create(), pthread_create() or pthread_attr_setstack()
	 * to fail, passing the problem up to the application.
	 */
	stack -= 5;	/* make the address of frame.arg be 16-byte aligned */
	frame.pc = 0;
	frame.fp = 0;	/* initial address for %ebp (see EBP below) */
	frame.pad = 0;
	frame.arg = (uint32_t)ulwp;
	frame.rpc = (uint32_t)_lwp_start;
	if (uucopy(&frame, (void *)stack, sizeof (frame)) == 0)
		return (stack);
	return (NULL);
}

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
		(void) __getcontext(&uc);
		fs = uc.uc_mcontext.gregs[FS];
		es = uc.uc_mcontext.gregs[ES];
		ds = uc.uc_mcontext.gregs[DS];
		cs = uc.uc_mcontext.gregs[CS];
		ss = uc.uc_mcontext.gregs[SS];
		initialized = 1;
	}
	/* clear the context and set the segment registers */
	(void) memset(ucp, 0, sizeof (*ucp));
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
	 * and directly call ___lwp_private() in _thrp_setup
	 * on the other side of __lwp_create().
	 */
	ucp->uc_mcontext.gregs[ESP] = (greg_t)ulwp;
	ucp->uc_mcontext.gregs[GS] = (greg_t)LWPGS_SEL;

	/*
	 * Setup the top stack frame.
	 * If this fails, pass the problem up to the application.
	 */
	if ((stack = setup_top_frame(stk, stksize, ulwp)) == NULL)
		return (ENOMEM);

	/* fill in registers of interest */
	ucp->uc_flags |= UC_CPU;
	ucp->uc_mcontext.gregs[EIP] = (greg_t)func;
	ucp->uc_mcontext.gregs[UESP] = (greg_t)stack;
	ucp->uc_mcontext.gregs[EBP] = (greg_t)(stack + 3);

	return (0);
}

/*
 * Machine-dependent startup code for a newly-created thread.
 */
void *
_thrp_setup(ulwp_t *self)
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

void
smt_pause(void)
{
	SMT_PAUSE();
}
