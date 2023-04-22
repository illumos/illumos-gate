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
 * Copyright 2015 Joyent, Inc.
 */
/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright 2023 Oxide Computer Company
 */

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
#include <sys/sdt.h>

/*
 * This is a wrapper around copyout_noerr that returns a guaranteed error code.
 * Because we're using copyout_noerr(), we need to bound the time we're under an
 * on_fault/no_fault and attempt to do so only while we're actually copying data
 * out. The main reason for this is because we're being called back from the
 * FPU, which is being held with a kpreempt_disable() and related, we can't use
 * a larger on_fault()/no_fault() as that would both hide legitimate errors we
 * make, masquerading as user issues, and it gets trickier to reason about the
 * correct restoration of our state.
 */
static int
savecontext_copyout(const void *kaddr, void *uaddr, size_t size)
{
	label_t ljb;
	if (!on_fault(&ljb)) {
		copyout_noerr(kaddr, uaddr, size);
		no_fault();
		return (0);
	} else {
		no_fault();
		return (EFAULT);
	}
}

/*
 * Save user context.
 *
 * ucp is itself always a pointer to the kernel's copy of a ucontext_t. In the
 * traditional version of this (when flags is 0), then we just write and fill
 * out all of the ucontext_t without any care for what was there ahead of this.
 * Our callers are responsible for coyping out that state if required. When
 * there is extended state to deal with (flags include SAVECTXT_F_EXTD), our
 * callers will have already copied in and pre-populated the structure with
 * values from userland. When those pointers are non-zero then we will copy out
 * that extended state directly to the user pointer. Currently this is only done
 * for uc_xsave. Even when we perform this, the rest of the structure stays as
 * is.
 *
 * We allow the copying to happen in two different ways mostly because this is
 * also used in the signal handling context where we must be much more careful
 * about how to copy out data.
 */
int
savecontext(ucontext_t *ucp, const k_sigset_t *mask, savecontext_flags_t flags)
{
	proc_t *p = ttoproc(curthread);
	klwp_t *lwp = ttolwp(curthread);
	struct regs *rp = lwptoregs(lwp);
	boolean_t need_xsave = B_FALSE;
	boolean_t fpu_en;
	long user_xsave = 0;
	int ret;

	VERIFY0(flags & ~(SAVECTXT_F_EXTD | SAVECTXT_F_ONFAULT));

	/*
	 * We unconditionally assign to every field through the end
	 * of the gregs, but we need to bzero() everything -after- that
	 * to avoid having any kernel stack garbage escape to userland.
	 *
	 * If we have been asked to save extended state, then we must make sure
	 * that we don't clobber that value. We must also determine if the
	 * processor has xsave state. If it does not, then we just simply honor
	 * the pointer, but do not write anything out and do not set the flag.
	 */
	if ((flags & SAVECTXT_F_EXTD) != 0) {
		user_xsave = ucp->uc_xsave;
		if (fpu_xsave_enabled() && user_xsave != 0) {
			need_xsave = B_TRUE;
		}
	} else {
		/*
		 * The only other flag that we have right now is about modifying
		 * the copyout behavior when we're copying out extended
		 * information. If it's not here, we should not do anything.
		 */
		VERIFY0(flags);
	}
	bzero(&ucp->uc_mcontext.fpregs, sizeof (ucontext_t) -
	    offsetof(ucontext_t, uc_mcontext.fpregs));
	ucp->uc_xsave = user_xsave;

	ucp->uc_flags = UC_ALL;
	ucp->uc_link = (struct ucontext *)lwp->lwp_oldcontext;

	/*
	 * Try to copyin() the ustack if one is registered. If the stack
	 * has zero size, this indicates that stack bounds checking has
	 * been disabled for this LWP. If stack bounds checking is disabled
	 * or the copyin() fails, we fall back to the legacy behavior.
	 */
	if (lwp->lwp_ustack == (uintptr_t)NULL ||
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
			 * anticipation of such occasions, set AST flag for
			 * the thread which will make the thread take an
			 * excursion through trap() where it will be handled
			 * appropriately.
			 */
			aston(curthread);
		}
	}

	getgregs(lwp, ucp->uc_mcontext.gregs);
	fpu_en = (lwp->lwp_pcb.pcb_fpu.fpu_flags & FPU_EN) != 0;
	if (fpu_en)
		getfpregs(lwp, &ucp->uc_mcontext.fpregs);
	else
		ucp->uc_flags &= ~UC_FPU;

	if (mask != NULL) {
		/*
		 * Save signal mask.
		 */
		sigktou(mask, &ucp->uc_sigmask);
	} else {
		ucp->uc_flags &= ~UC_SIGMASK;
		bzero(&ucp->uc_sigmask, sizeof (ucp->uc_sigmask));
	}

	if (PROC_IS_BRANDED(p) && BROP(p)->b_savecontext != NULL) {
		/*
		 * Allow the brand the chance to modify the context we
		 * saved:
		 */
		BROP(p)->b_savecontext(ucp);
	}

	/*
	 * Determine if we need to get the rest of the xsave context out here.
	 * If the thread doesn't actually have the FPU enabled, then we don't
	 * actually need to do this. We also don't have to if it wasn't
	 * requested.
	 */
	if (!need_xsave || !fpu_en) {
		return (0);
	}

	ucp->uc_flags |= UC_XSAVE;

	/*
	 * While you might be asking why and contemplating despair, just know
	 * that some things need to just be done in the face of signal (half the
	 * reason this function exists). Basically when in signal context we
	 * can't trigger watch points. This means we need to tell the FPU copy
	 * logic to actually use the on_fault/no_fault and the non-error form of
	 * copyout (which still checks if it's a user address at least).
	 */
	if ((flags & SAVECTXT_F_ONFAULT) != 0) {
		ret = fpu_signal_copyout(lwp, ucp->uc_xsave,
		    savecontext_copyout);
	} else {
		ret = fpu_signal_copyout(lwp, ucp->uc_xsave, copyout);
	}

	return (ret);
}

/*
 * Restore user context.
 */
void
restorecontext(ucontext_t *ucp)
{
	kthread_t *t = curthread;
	klwp_t *lwp = ttolwp(t);
	proc_t *p = lwptoproc(lwp);

	if (PROC_IS_BRANDED(p) && BROP(p)->b_restorecontext != NULL) {
		/*
		 * Allow the brand the chance to modify the context before
		 * we restore it:
		 */
		BROP(p)->b_restorecontext(ucp);
	}

	DTRACE_PROBE3(oldcontext__set, klwp_t *, lwp,
	    uintptr_t, lwp->lwp_oldcontext,
	    uintptr_t, (uintptr_t)ucp->uc_link);
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

	/*
	 * The logic to copy in the ucontex_t takes care of combining the UC_FPU
	 * and UC_XSAVE, so at this point only one of them should be set, if
	 * any.
	 */
	if (ucp->uc_flags & UC_XSAVE) {
		ASSERT0(ucp->uc_flags & UC_FPU);
		ASSERT3U((uintptr_t)ucp->uc_xsave, >=, _kernelbase);
		fpu_set_xsave(lwp, (const void *)ucp->uc_xsave);
	} else if (ucp->uc_flags & UC_FPU) {
		setfpregs(lwp, &ucp->uc_mcontext.fpregs);
	}

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
	void *fpu = NULL;
	stack_t dummy_stk;
	proc_t *p = lwptoproc(lwp);
	int ret;

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
		ret = savecontext(&uc, &curthread->t_hold, SAVECTXT_F_NONE);
		if (ret != 0)
			return (set_errno(ret));
		if (uc.uc_flags & UC_SIGMASK)
			SIGSET_NATIVE_TO_BRAND(&uc.uc_sigmask);
		if (copyout(&uc, arg, sizeof (uc)))
			return (set_errno(EFAULT));
		return (0);

	/*
	 * In the case of GETCONTEXT_EXTD, we've theoretically been given all
	 * the required pointers of the appropriate length by libc in the
	 * ucontext_t. We must first copyin the offsets that we care about to
	 * seed the known extensions. Right now that is just the uc_xsave
	 * member. As we are setting uc_flags, we only look at the members we
	 * need to care about.
	 *
	 * The main reason that we have a different entry point is that we don't
	 * want to assume that callers have always properly zeroed their
	 * ucontext_t ahead of calling into libc. In fact, it often is just
	 * declared on the stack so we can't assume that at all. Instead,
	 * getcontext_extd does require that.
	 */
	case GETCONTEXT_EXTD:
		schedctl_finish_sigblock(curthread);
		ucp = arg;
		if (copyin(&ucp->uc_xsave, &uc.uc_xsave,
		    sizeof (uc.uc_xsave)) != 0) {
			return (set_errno(EFAULT));
		}
		ret = savecontext(&uc, &curthread->t_hold, SAVECTXT_F_EXTD);
		if (ret != 0)
			return (set_errno(ret));
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
		if (copyin(ucp, &uc, offsetof(ucontext_t, uc_filler) -
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

		/*
		 * If this is a branded process, copy in the brand-private
		 * data:
		 */
		if (PROC_IS_BRANDED(p) && copyin(&ucp->uc_brand_data,
		    &uc.uc_brand_data, sizeof (uc.uc_brand_data)) != 0) {
			return (set_errno(EFAULT));
		}

		uc.uc_xsave = 0;
		if ((uc.uc_flags & UC_XSAVE) != 0) {
			int ret;

			if (copyin(&ucp->uc_xsave, &uc.uc_xsave,
			    sizeof (uc.uc_xsave)) != 0) {
				return (set_errno(EFAULT));
			}

			ret = fpu_signal_copyin(lwp, &uc);
			if (ret != 0) {
				return (set_errno(ret));
			}
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
int
savecontext32(ucontext32_t *ucp, const k_sigset_t *mask,
    savecontext_flags_t flags)
{
	proc_t *p = ttoproc(curthread);
	klwp_t *lwp = ttolwp(curthread);
	struct regs *rp = lwptoregs(lwp);
	boolean_t need_xsave = B_FALSE;
	boolean_t fpu_en;
	int32_t user_xsave = 0;
	uintptr_t uaddr;
	int ret;

	/*
	 * See savecontext for an explanation of this.
	 */
	if ((flags & SAVECTXT_F_EXTD) != 0) {
		user_xsave = ucp->uc_xsave;
		if (fpu_xsave_enabled() && user_xsave != 0) {
			need_xsave = B_TRUE;
		}
	} else {
		VERIFY0(flags);
	}
	bzero(&ucp->uc_mcontext.fpregs, sizeof (ucontext32_t) -
	    offsetof(ucontext32_t, uc_mcontext.fpregs));
	ucp->uc_xsave = user_xsave;

	ucp->uc_flags = UC_ALL;
	ucp->uc_link = (caddr32_t)lwp->lwp_oldcontext;

	if (lwp->lwp_ustack == (uintptr_t)NULL ||
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
	fpu_en = (lwp->lwp_pcb.pcb_fpu.fpu_flags & FPU_EN) != 0;
	if (fpu_en)
		getfpregs32(lwp, &ucp->uc_mcontext.fpregs);
	else
		ucp->uc_flags &= ~UC_FPU;

	if (mask != NULL) {
		/*
		 * Save signal mask.
		 */
		sigktou(mask, &ucp->uc_sigmask);
	} else {
		ucp->uc_flags &= ~UC_SIGMASK;
		bzero(&ucp->uc_sigmask, sizeof (ucp->uc_sigmask));
	}

	if (PROC_IS_BRANDED(p) && BROP(p)->b_savecontext32 != NULL) {
		/*
		 * Allow the brand the chance to modify the context we
		 * saved:
		 */
		BROP(p)->b_savecontext32(ucp);
	}

	if (!need_xsave || !fpu_en) {
		return (0);
	}

	ucp->uc_flags |= UC_XSAVE;

	/*
	 * Due to not wanting to change or break programs, the filler in the
	 * ucontext_t was always declared as a long, which is signed. Because
	 * this is the 32-bit version, this is an int32_t. We cannot directly go
	 * to a uintptr_t otherwise we might get sign extension, so we first
	 * have to go through a uint32_t and then a uintptr_t. Otherwise, see
	 * savecontext().
	 */
	uaddr = (uintptr_t)(uint32_t)ucp->uc_xsave;
	if ((flags & SAVECTXT_F_ONFAULT) != 0) {
		ret = fpu_signal_copyout(lwp, uaddr, savecontext_copyout);
	} else {
		ret = fpu_signal_copyout(lwp, uaddr, copyout);
	}

	return (ret);
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
	proc_t *p = lwptoproc(lwp);
	int ret;

	switch (flag) {
	default:
		return (set_errno(EINVAL));

	case GETCONTEXT:
		schedctl_finish_sigblock(curthread);
		ret = savecontext32(&uc, &curthread->t_hold, SAVECTXT_F_NONE);
		if (ret != 0)
			return (set_errno(ret));
		if (uc.uc_flags & UC_SIGMASK)
			SIGSET_NATIVE_TO_BRAND(&uc.uc_sigmask);
		if (copyout(&uc, arg, sizeof (uc)))
			return (set_errno(EFAULT));
		return (0);

	/*
	 * See getsetcontext() for an explanation of what is going on here.
	 */
	case GETCONTEXT_EXTD:
		schedctl_finish_sigblock(curthread);
		ucp = arg;
		if (copyin(&ucp->uc_xsave, &uc.uc_xsave,
		    sizeof (uc.uc_xsave)) != 0) {
			return (set_errno(EFAULT));
		}
		ret = savecontext32(&uc, &curthread->t_hold, SAVECTXT_F_EXTD);
		if (ret != 0)
			return (set_errno(ret));
		if (uc.uc_flags & UC_SIGMASK)
			SIGSET_NATIVE_TO_BRAND(&uc.uc_sigmask);
		if (copyout(&uc, arg, sizeof (uc)))
			return (set_errno(EFAULT));
		return (0);

	case SETCONTEXT:
		ucp = arg;
		if (ucp == NULL)
			exit(CLD_EXITED, 0);
		if (copyin(ucp, &uc, offsetof(ucontext32_t, uc_filler) -
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

		/*
		 * If this is a branded process, copy in the brand-private
		 * data:
		 */
		if (PROC_IS_BRANDED(p) && copyin(&ucp->uc_brand_data,
		    &uc.uc_brand_data, sizeof (uc.uc_brand_data)) != 0) {
			return (set_errno(EFAULT));
		}

		uc.uc_xsave = 0;
		if ((uc.uc_flags & UC_XSAVE) != 0 &&
		    copyin(&ucp->uc_xsave, &uc.uc_xsave,
		    sizeof (uc.uc_xsave)) != 0) {
			return (set_errno(EFAULT));
		}

		ucontext_32ton(&uc, &ucnat);

		if ((ucnat.uc_flags & UC_XSAVE) != 0) {
			int ret = fpu_signal_copyin(lwp, &ucnat);
			if (ret != 0) {
				return (set_errno(ret));
			}
		}

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
