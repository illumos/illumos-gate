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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#include <sys/param.h>
#include <sys/types.h>
#include <sys/vmparam.h>
#include <sys/systm.h>
#include <sys/signal.h>
#include <sys/stack.h>
#include <sys/regset.h>
#include <sys/privregs.h>
#include <sys/frame.h>
#include <sys/proc.h>
#include <sys/brand.h>
#include <sys/psw.h>
#include <sys/ucontext.h>
#include <sys/asm_linkage.h>
#include <sys/errno.h>
#include <sys/archsystm.h>
#include <sys/schedctl.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>

/*
 * Save user context.
 */
void
savecontext(ucontext_t *ucp, const k_sigset_t *mask)
{
	proc_t *p = ttoproc(curthread);
	klwp_t *lwp = ttolwp(curthread);
	struct regs *rp = lwptoregs(lwp);

	/*
	 * We unconditionally assign to every field through the end
	 * of the gregs, but we need to bzero() everything -after- that
	 * to avoid having any kernel stack garbage escape to userland.
	 */
	bzero(&ucp->uc_mcontext.fpregs, sizeof (ucontext_t) -
	    offsetof(ucontext_t, uc_mcontext.fpregs));

	ucp->uc_flags = UC_ALL;
	ucp->uc_link = (struct ucontext *)lwp->lwp_oldcontext;

	/*
	 * Try to copyin() the ustack if one is registered. If the stack
	 * has zero size, this indicates that stack bounds checking has
	 * been disabled for this LWP. If stack bounds checking is disabled
	 * or the copyin() fails, we fall back to the legacy behavior.
	 */
	if (lwp->lwp_ustack == NULL ||
	    copyin((void *)lwp->lwp_ustack, &ucp->uc_stack,
	    sizeof (ucp->uc_stack)) != 0 ||
	    ucp->uc_stack.ss_size == 0) {

		if (lwp->lwp_sigaltstack.ss_flags == SS_ONSTACK) {
			ucp->uc_stack = lwp->lwp_sigaltstack;
		} else {
			ucp->uc_stack.ss_sp = p->p_usrstack - p->p_stksize;
			ucp->uc_stack.ss_size = p->p_stksize;
			ucp->uc_stack.ss_flags = 0;
		}
	}

	/*
	 * If either the trace flag or REQUEST_STEP is set,
	 * arrange for single-stepping and turn off the trace flag.
	 */
	if ((rp->r_ps & PS_T) || (lwp->lwp_pcb.pcb_flags & REQUEST_STEP)) {
		/*
		 * Clear PS_T so that saved user context won't have trace
		 * flag set.
		 */
		rp->r_ps &= ~PS_T;

		if (!(lwp->lwp_pcb.pcb_flags & REQUEST_NOSTEP)) {
			lwp->lwp_pcb.pcb_flags |= DEBUG_PENDING;
			/*
			 * trap() always checks DEBUG_PENDING before
			 * checking for any pending signal. This at times
			 * can potentially lead to DEBUG_PENDING not being
			 * honoured. (for eg: the lwp is stopped by
			 * stop_on_fault() called from trap(), after being
			 * awakened it might see a pending signal and call
			 * savecontext(), however on the way back to userland
			 * there is no place it can be detected). Hence in
			 * anticipation of such occassions, set AST flag for
			 * the thread which will make the thread take an
			 * excursion through trap() where it will be handled
			 * appropriately.
			 */
			aston(curthread);
		}
	}

	getgregs(lwp, ucp->uc_mcontext.gregs);
	if (lwp->lwp_pcb.pcb_fpu.fpu_flags & FPU_EN)
		getfpregs(lwp, &ucp->uc_mcontext.fpregs);
	else
		ucp->uc_flags &= ~UC_FPU;

	sigktou(mask, &ucp->uc_sigmask);
}

/*
 * Restore user context.
 */
void
restorecontext(ucontext_t *ucp)
{
	kthread_t *t = curthread;
	klwp_t *lwp = ttolwp(t);

	lwp->lwp_oldcontext = (uintptr_t)ucp->uc_link;

	if (ucp->uc_flags & UC_STACK) {
		if (ucp->uc_stack.ss_flags == SS_ONSTACK)
			lwp->lwp_sigaltstack = ucp->uc_stack;
		else
			lwp->lwp_sigaltstack.ss_flags &= ~SS_ONSTACK;
	}

	if (ucp->uc_flags & UC_CPU) {
		/*
		 * If the trace flag is set, mark the lwp to take a
		 * single-step trap on return to user level (below).
		 * The x86 lcall interface and sysenter has already done this,
		 * and turned off the flag, but amd64 syscall interface has not.
		 */
		if (lwptoregs(lwp)->r_ps & PS_T)
			lwp->lwp_pcb.pcb_flags |= DEBUG_PENDING;
		setgregs(lwp, ucp->uc_mcontext.gregs);
		lwp->lwp_eosys = JUSTRETURN;
		t->t_post_sys = 1;
		aston(curthread);
	}

	if (ucp->uc_flags & UC_FPU)
		setfpregs(lwp, &ucp->uc_mcontext.fpregs);

	if (ucp->uc_flags & UC_SIGMASK) {
		/*
		 * We don't need to acquire p->p_lock here;
		 * we are manipulating thread-private data.
		 */
		schedctl_finish_sigblock(t);
		sigutok(&ucp->uc_sigmask, &t->t_hold);
		if (sigcheck(ttoproc(t), t))
			t->t_sig_check = 1;
	}
}


int
getsetcontext(int flag, void *arg)
{
	ucontext_t uc;
	ucontext_t *ucp;
	klwp_t *lwp = ttolwp(curthread);
	stack_t dummy_stk;

	/*
	 * In future releases, when the ucontext structure grows,
	 * getcontext should be modified to only return the fields
	 * specified in the uc_flags.  That way, the structure can grow
	 * and still be binary compatible will all .o's which will only
	 * have old fields defined in uc_flags
	 */

	switch (flag) {
	default:
		return (set_errno(EINVAL));

	case GETCONTEXT:
		schedctl_finish_sigblock(curthread);
		savecontext(&uc, &curthread->t_hold);
		if (uc.uc_flags & UC_SIGMASK)
			SIGSET_NATIVE_TO_BRAND(&uc.uc_sigmask);
		if (copyout(&uc, arg, sizeof (uc)))
			return (set_errno(EFAULT));
		return (0);

	case SETCONTEXT:
		ucp = arg;
		if (ucp == NULL)
			exit(CLD_EXITED, 0);
		/*
		 * Don't copyin filler or floating state unless we need it.
		 * The ucontext_t struct and fields are specified in the ABI.
		 */
		if (copyin(ucp, &uc, sizeof (ucontext_t) -
		    sizeof (uc.uc_filler) -
		    sizeof (uc.uc_mcontext.fpregs))) {
			return (set_errno(EFAULT));
		}
		if (uc.uc_flags & UC_SIGMASK)
			SIGSET_BRAND_TO_NATIVE(&uc.uc_sigmask);

		if ((uc.uc_flags & UC_FPU) &&
		    copyin(&ucp->uc_mcontext.fpregs, &uc.uc_mcontext.fpregs,
		    sizeof (uc.uc_mcontext.fpregs))) {
			return (set_errno(EFAULT));
		}

		restorecontext(&uc);

		if ((uc.uc_flags & UC_STACK) && (lwp->lwp_ustack != 0))
			(void) copyout(&uc.uc_stack, (stack_t *)lwp->lwp_ustack,
			    sizeof (uc.uc_stack));
		return (0);

	case GETUSTACK:
		if (copyout(&lwp->lwp_ustack, arg, sizeof (caddr_t)))
			return (set_errno(EFAULT));
		return (0);

	case SETUSTACK:
		if (copyin(arg, &dummy_stk, sizeof (dummy_stk)))
			return (set_errno(EFAULT));
		lwp->lwp_ustack = (uintptr_t)arg;
		return (0);
	}
}

#ifdef _SYSCALL32_IMPL

/*
 * Save user context for 32-bit processes.
 */
void
savecontext32(ucontext32_t *ucp, const k_sigset_t *mask)
{
	proc_t *p = ttoproc(curthread);
	klwp_t *lwp = ttolwp(curthread);
	struct regs *rp = lwptoregs(lwp);

	bzero(&ucp->uc_mcontext.fpregs, sizeof (ucontext32_t) -
	    offsetof(ucontext32_t, uc_mcontext.fpregs));

	ucp->uc_flags = UC_ALL;
	ucp->uc_link = (caddr32_t)lwp->lwp_oldcontext;

	if (lwp->lwp_ustack == NULL ||
	    copyin((void *)lwp->lwp_ustack, &ucp->uc_stack,
	    sizeof (ucp->uc_stack)) != 0 ||
	    ucp->uc_stack.ss_size == 0) {

		if (lwp->lwp_sigaltstack.ss_flags == SS_ONSTACK) {
			ucp->uc_stack.ss_sp =
			    (caddr32_t)(uintptr_t)lwp->lwp_sigaltstack.ss_sp;
			ucp->uc_stack.ss_size =
			    (size32_t)lwp->lwp_sigaltstack.ss_size;
			ucp->uc_stack.ss_flags = SS_ONSTACK;
		} else {
			ucp->uc_stack.ss_sp = (caddr32_t)(uintptr_t)
			    (p->p_usrstack - p->p_stksize);
			ucp->uc_stack.ss_size = (size32_t)p->p_stksize;
			ucp->uc_stack.ss_flags = 0;
		}
	}

	/*
	 * If either the trace flag or REQUEST_STEP is set, arrange
	 * for single-stepping and turn off the trace flag.
	 */
	if ((rp->r_ps & PS_T) || (lwp->lwp_pcb.pcb_flags & REQUEST_STEP)) {
		/*
		 * Clear PS_T so that saved user context won't have trace
		 * flag set.
		 */
		rp->r_ps &= ~PS_T;

		if (!(lwp->lwp_pcb.pcb_flags & REQUEST_NOSTEP)) {
			lwp->lwp_pcb.pcb_flags |= DEBUG_PENDING;
			/*
			 * See comments in savecontext().
			 */
			aston(curthread);
		}
	}

	getgregs32(lwp, ucp->uc_mcontext.gregs);
	if (lwp->lwp_pcb.pcb_fpu.fpu_flags & FPU_EN)
		getfpregs32(lwp, &ucp->uc_mcontext.fpregs);
	else
		ucp->uc_flags &= ~UC_FPU;

	sigktou(mask, &ucp->uc_sigmask);
}

int
getsetcontext32(int flag, void *arg)
{
	ucontext32_t uc;
	ucontext_t ucnat;
	ucontext32_t *ucp;
	klwp_t *lwp = ttolwp(curthread);
	caddr32_t ustack32;
	stack32_t dummy_stk32;

	switch (flag) {
	default:
		return (set_errno(EINVAL));

	case GETCONTEXT:
		schedctl_finish_sigblock(curthread);
		savecontext32(&uc, &curthread->t_hold);
		if (uc.uc_flags & UC_SIGMASK)
			SIGSET_NATIVE_TO_BRAND(&uc.uc_sigmask);
		if (copyout(&uc, arg, sizeof (uc)))
			return (set_errno(EFAULT));
		return (0);

	case SETCONTEXT:
		ucp = arg;
		if (ucp == NULL)
			exit(CLD_EXITED, 0);
		if (copyin(ucp, &uc, sizeof (uc) -
		    sizeof (uc.uc_filler) -
		    sizeof (uc.uc_mcontext.fpregs))) {
			return (set_errno(EFAULT));
		}
		if (uc.uc_flags & UC_SIGMASK)
			SIGSET_BRAND_TO_NATIVE(&uc.uc_sigmask);
		if ((uc.uc_flags & UC_FPU) &&
		    copyin(&ucp->uc_mcontext.fpregs, &uc.uc_mcontext.fpregs,
		    sizeof (uc.uc_mcontext.fpregs))) {
			return (set_errno(EFAULT));
		}

		ucontext_32ton(&uc, &ucnat);
		restorecontext(&ucnat);

		if ((uc.uc_flags & UC_STACK) && (lwp->lwp_ustack != 0))
			(void) copyout(&uc.uc_stack,
			    (stack32_t *)lwp->lwp_ustack, sizeof (uc.uc_stack));
		return (0);

	case GETUSTACK:
		ustack32 = (caddr32_t)lwp->lwp_ustack;
		if (copyout(&ustack32, arg, sizeof (ustack32)))
			return (set_errno(EFAULT));
		return (0);

	case SETUSTACK:
		if (copyin(arg, &dummy_stk32, sizeof (dummy_stk32)))
			return (set_errno(EFAULT));
		lwp->lwp_ustack = (uintptr_t)arg;
		return (0);
	}
}

#endif	/* _SYSCALL32_IMPL */
