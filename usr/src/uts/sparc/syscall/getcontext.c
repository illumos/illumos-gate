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
#include <sys/frame.h>
#include <sys/proc.h>
#include <sys/brand.h>
#include <sys/ucontext.h>
#include <sys/asm_linkage.h>
#include <sys/kmem.h>
#include <sys/errno.h>
#include <sys/archsystm.h>
#include <sys/fpu/fpusystm.h>
#include <sys/debug.h>
#include <sys/model.h>
#include <sys/cmn_err.h>
#include <sys/sysmacros.h>
#include <sys/privregs.h>
#include <sys/schedctl.h>


/*
 * Save user context.
 */
void
savecontext(ucontext_t *ucp, const k_sigset_t *mask)
{
	proc_t *p = ttoproc(curthread);
	klwp_t *lwp = ttolwp(curthread);

	/*
	 * We assign to every field through uc_mcontext.fpregs.fpu_en,
	 * but we have to bzero() everything after that.
	 */
	bzero(&ucp->uc_mcontext.fpregs.fpu_en, sizeof (ucontext_t) -
	    offsetof(ucontext_t, uc_mcontext.fpregs.fpu_en));
	/*
	 * There are unused holes in the ucontext_t structure, zero-fill
	 * them so that we don't expose kernel data to the user.
	 */
	(&ucp->uc_flags)[1] = 0;
	(&ucp->uc_stack.ss_flags)[1] = 0;

	/*
	 * Flushing the user windows isn't strictly necessary; we do
	 * it to maintain backward compatibility.
	 */
	(void) flush_user_windows_to_stack(NULL);

	ucp->uc_flags = UC_ALL;
	ucp->uc_link = (ucontext_t *)lwp->lwp_oldcontext;

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

	getgregs(lwp, ucp->uc_mcontext.gregs);
	getasrs(lwp, ucp->uc_mcontext.asrs);

	getfpregs(lwp, &ucp->uc_mcontext.fpregs);
	getfpasrs(lwp, ucp->uc_mcontext.asrs);
	if (ucp->uc_mcontext.fpregs.fpu_en == 0)
		ucp->uc_flags &= ~UC_FPU;
	ucp->uc_mcontext.gwins = (gwindows_t *)NULL;

	/*
	 * Save signal mask.
	 */
	sigktou(mask, &ucp->uc_sigmask);
}


void
restorecontext(ucontext_t *ucp)
{
	kthread_t *t = curthread;
	klwp_t *lwp = ttolwp(t);
	mcontext_t *mcp = &ucp->uc_mcontext;
	model_t model = lwp_getdatamodel(lwp);

	(void) flush_user_windows_to_stack(NULL);
	if (lwp->lwp_pcb.pcb_xregstat != XREGNONE)
		xregrestore(lwp, 0);

	lwp->lwp_oldcontext = (uintptr_t)ucp->uc_link;

	if (ucp->uc_flags & UC_STACK) {
		if (ucp->uc_stack.ss_flags == SS_ONSTACK)
			lwp->lwp_sigaltstack = ucp->uc_stack;
		else
			lwp->lwp_sigaltstack.ss_flags &= ~SS_ONSTACK;
	}

	if (ucp->uc_flags & UC_CPU) {
		if (mcp->gwins != 0)
			setgwins(lwp, mcp->gwins);
		setgregs(lwp, mcp->gregs);
		if (model == DATAMODEL_LP64)
			setasrs(lwp, mcp->asrs);
		else
			xregs_setgregs(lwp, xregs_getptr(lwp, ucp));
	}

	if (ucp->uc_flags & UC_FPU) {
		fpregset_t *fp = &ucp->uc_mcontext.fpregs;

		setfpregs(lwp, fp);
		if (model == DATAMODEL_LP64)
			setfpasrs(lwp, mcp->asrs);
		else
			xregs_setfpregs(lwp, xregs_getptr(lwp, ucp));
		run_fpq(lwp, fp);
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
	struct _fq fpu_q[MAXFPQ]; /* to hold floating queue */
	fpregset_t *fpp;
	gwindows_t *gwin = NULL;	/* to hold windows */
	caddr_t xregs = NULL;
	int xregs_size = 0;
	extern int nwindows;
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
		/*
		 * When using floating point it should not be possible to
		 * get here with a fpu_qcnt other than zero since we go
		 * to great pains to handle all outstanding FP exceptions
		 * before any system call code gets executed. However we
		 * clear fpu_q and fpu_qcnt here before copyout anyway -
		 * this will prevent us from interpreting the garbage we
		 * get back (when FP is not enabled) as valid queue data on
		 * a later setcontext(2).
		 */
		uc.uc_mcontext.fpregs.fpu_qcnt = 0;
		uc.uc_mcontext.fpregs.fpu_q = (struct _fq *)NULL;

		if (copyout(&uc, arg, sizeof (ucontext_t)))
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
		    sizeof (uc.uc_mcontext.fpregs) -
		    sizeof (uc.uc_mcontext.xrs) -
		    sizeof (uc.uc_mcontext.asrs) -
		    sizeof (uc.uc_mcontext.filler))) {
			return (set_errno(EFAULT));
		}
		if (uc.uc_flags & UC_SIGMASK)
			SIGSET_BRAND_TO_NATIVE(&uc.uc_sigmask);
		if (copyin(&ucp->uc_mcontext.xrs, &uc.uc_mcontext.xrs,
		    sizeof (uc.uc_mcontext.xrs))) {
			return (set_errno(EFAULT));
		}
		fpp = &uc.uc_mcontext.fpregs;
		if (uc.uc_flags & UC_FPU) {
			/*
			 * Need to copyin floating point state
			 */
			if (copyin(&ucp->uc_mcontext.fpregs,
			    &uc.uc_mcontext.fpregs,
			    sizeof (uc.uc_mcontext.fpregs)))
				return (set_errno(EFAULT));
			/* if floating queue not empty */
			if ((fpp->fpu_q) && (fpp->fpu_qcnt)) {
				if (fpp->fpu_qcnt > MAXFPQ ||
				    fpp->fpu_q_entrysize <= 0 ||
				    fpp->fpu_q_entrysize > sizeof (struct _fq))
					return (set_errno(EINVAL));
				if (copyin(fpp->fpu_q, fpu_q,
				    fpp->fpu_qcnt * fpp->fpu_q_entrysize))
					return (set_errno(EFAULT));
				fpp->fpu_q = fpu_q;
			} else {
				fpp->fpu_qcnt = 0; /* avoid confusion later */
			}
		} else {
			fpp->fpu_qcnt = 0;
		}
		if (uc.uc_mcontext.gwins) {	/* if windows in context */
			size_t gwin_size;

			/*
			 * We do the same computation here to determine
			 * how many bytes of gwindows_t to copy in that
			 * is also done in sendsig() to decide how many
			 * bytes to copy out.  We just *know* that wbcnt
			 * is the first element of the structure.
			 */
			gwin = kmem_zalloc(sizeof (gwindows_t), KM_SLEEP);
			if (copyin(uc.uc_mcontext.gwins,
			    &gwin->wbcnt, sizeof (gwin->wbcnt))) {
				kmem_free(gwin, sizeof (gwindows_t));
				return (set_errno(EFAULT));
			}
			if (gwin->wbcnt < 0 || gwin->wbcnt > nwindows) {
				kmem_free(gwin, sizeof (gwindows_t));
				return (set_errno(EINVAL));
			}
			gwin_size = gwin->wbcnt * sizeof (struct rwindow) +
			    SPARC_MAXREGWINDOW * sizeof (int *) + sizeof (long);
			if (gwin_size > sizeof (gwindows_t) ||
			    copyin(uc.uc_mcontext.gwins, gwin, gwin_size)) {
				kmem_free(gwin, sizeof (gwindows_t));
				return (set_errno(EFAULT));
			}
			uc.uc_mcontext.gwins = gwin;
		}

		/*
		 * get extra register state or asrs if any exists
		 * there is no extra register state for _LP64 user programs
		 */
		xregs_clrptr(lwp, &uc);
		if (copyin(&ucp->uc_mcontext.asrs, &uc.uc_mcontext.asrs,
		    sizeof (asrset_t))) {
			/* Free up gwin structure if used */
			if (gwin)
				kmem_free(gwin, sizeof (gwindows_t));
			return (set_errno(EFAULT));
		}

		restorecontext(&uc);

		if ((uc.uc_flags & UC_STACK) && (lwp->lwp_ustack != 0)) {
			(void) copyout(&uc.uc_stack, (stack_t *)lwp->lwp_ustack,
			    sizeof (stack_t));
		}

		/*
		 * free extra register state area
		 */
		if (xregs_size)
			kmem_free(xregs, xregs_size);

		if (gwin)
			kmem_free(gwin, sizeof (gwindows_t));

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
savecontext32(ucontext32_t *ucp, const k_sigset_t *mask, struct fq32 *dfq)
{
	proc_t *p = ttoproc(curthread);
	klwp_t *lwp = ttolwp(curthread);
	fpregset_t fpregs;

	/*
	 * We assign to every field through uc_mcontext.fpregs.fpu_en,
	 * but we have to bzero() everything after that.
	 */
	bzero(&ucp->uc_mcontext.fpregs.fpu_en, sizeof (ucontext32_t) -
	    offsetof(ucontext32_t, uc_mcontext.fpregs.fpu_en));
	/*
	 * There is an unused hole in the ucontext32_t structure; zero-fill
	 * it so that we don't expose kernel data to the user.
	 */
	(&ucp->uc_stack.ss_flags)[1] = 0;

	/*
	 * Flushing the user windows isn't strictly necessary; we do
	 * it to maintain backward compatibility.
	 */
	(void) flush_user_windows_to_stack(NULL);

	ucp->uc_flags = UC_ALL;
	ucp->uc_link = (caddr32_t)lwp->lwp_oldcontext;

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
			ucp->uc_stack.ss_sp =
			    (caddr32_t)(uintptr_t)lwp->lwp_sigaltstack.ss_sp;
			ucp->uc_stack.ss_size =
			    (size32_t)lwp->lwp_sigaltstack.ss_size;
			ucp->uc_stack.ss_flags = SS_ONSTACK;
		} else {
			ucp->uc_stack.ss_sp =
			    (caddr32_t)(uintptr_t)p->p_usrstack - p->p_stksize;
			ucp->uc_stack.ss_size =
			    (size32_t)p->p_stksize;
			ucp->uc_stack.ss_flags = 0;
		}
	}

	getgregs32(lwp, ucp->uc_mcontext.gregs);
	getfpregs(lwp, &fpregs);
	fpuregset_nto32(&fpregs, &ucp->uc_mcontext.fpregs, dfq);

	if (ucp->uc_mcontext.fpregs.fpu_en == 0)
		ucp->uc_flags &= ~UC_FPU;
	ucp->uc_mcontext.gwins = (caddr32_t)NULL;

	/*
	 * Save signal mask (the 32- and 64-bit sigset_t structures are
	 * identical).
	 */
	sigktou(mask, (sigset_t *)&ucp->uc_sigmask);
}

int
getsetcontext32(int flag, void *arg)
{
	ucontext32_t uc;
	ucontext_t   ucnat;
	struct _fq fpu_qnat[MAXFPQ]; /* to hold "native" floating queue */
	struct fq32 fpu_q[MAXFPQ]; /* to hold 32 bit floating queue */
	fpregset32_t *fpp;
	gwindows32_t *gwin = NULL;	/* to hold windows */
	caddr_t xregs;
	int xregs_size = 0;
	extern int nwindows;
	klwp_t *lwp = ttolwp(curthread);
	ucontext32_t *ucp;
	uint32_t ustack32;
	stack32_t dummy_stk32;

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
		savecontext32(&uc, &curthread->t_hold, NULL);
		if (uc.uc_flags & UC_SIGMASK)
			SIGSET_NATIVE_TO_BRAND(&uc.uc_sigmask);
		/*
		 * When using floating point it should not be possible to
		 * get here with a fpu_qcnt other than zero since we go
		 * to great pains to handle all outstanding FP exceptions
		 * before any system call code gets executed. However we
		 * clear fpu_q and fpu_qcnt here before copyout anyway -
		 * this will prevent us from interpreting the garbage we
		 * get back (when FP is not enabled) as valid queue data on
		 * a later setcontext(2).
		 */
		uc.uc_mcontext.fpregs.fpu_qcnt = 0;
		uc.uc_mcontext.fpregs.fpu_q = (caddr32_t)NULL;

		if (copyout(&uc, arg, sizeof (ucontext32_t)))
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
		if (copyin(ucp, &uc, sizeof (uc) - sizeof (uc.uc_filler) -
		    sizeof (uc.uc_mcontext.fpregs) -
		    sizeof (uc.uc_mcontext.xrs) -
		    sizeof (uc.uc_mcontext.filler))) {
			return (set_errno(EFAULT));
		}
		if (uc.uc_flags & UC_SIGMASK)
			SIGSET_BRAND_TO_NATIVE(&uc.uc_sigmask);
		if (copyin(&ucp->uc_mcontext.xrs, &uc.uc_mcontext.xrs,
		    sizeof (uc.uc_mcontext.xrs))) {
			return (set_errno(EFAULT));
		}
		fpp = &uc.uc_mcontext.fpregs;
		if (uc.uc_flags & UC_FPU) {
			/*
			 * Need to copyin floating point state
			 */
			if (copyin(&ucp->uc_mcontext.fpregs,
			    &uc.uc_mcontext.fpregs,
			    sizeof (uc.uc_mcontext.fpregs)))
				return (set_errno(EFAULT));
			/* if floating queue not empty */
			if ((fpp->fpu_q) && (fpp->fpu_qcnt)) {
				if (fpp->fpu_qcnt > MAXFPQ ||
				    fpp->fpu_q_entrysize <= 0 ||
				    fpp->fpu_q_entrysize > sizeof (struct fq32))
					return (set_errno(EINVAL));
				if (copyin((void *)(uintptr_t)fpp->fpu_q, fpu_q,
				    fpp->fpu_qcnt * fpp->fpu_q_entrysize))
					return (set_errno(EFAULT));
			} else {
				fpp->fpu_qcnt = 0; /* avoid confusion later */
			}
		} else {
			fpp->fpu_qcnt = 0;
		}

		if (uc.uc_mcontext.gwins) {	/* if windows in context */
			size_t gwin_size;

			/*
			 * We do the same computation here to determine
			 * how many bytes of gwindows_t to copy in that
			 * is also done in sendsig() to decide how many
			 * bytes to copy out.  We just *know* that wbcnt
			 * is the first element of the structure.
			 */
			gwin = kmem_zalloc(sizeof (gwindows32_t), KM_SLEEP);
			if (copyin((void *)(uintptr_t)uc.uc_mcontext.gwins,
			    &gwin->wbcnt, sizeof (gwin->wbcnt))) {
				kmem_free(gwin, sizeof (gwindows32_t));
				return (set_errno(EFAULT));
			}
			if (gwin->wbcnt < 0 || gwin->wbcnt > nwindows) {
				kmem_free(gwin, sizeof (gwindows32_t));
				return (set_errno(EINVAL));
			}
			gwin_size = gwin->wbcnt * sizeof (struct rwindow32) +
			    SPARC_MAXREGWINDOW * sizeof (caddr32_t) +
			    sizeof (int32_t);
			if (gwin_size > sizeof (gwindows32_t) ||
			    copyin((void *)(uintptr_t)uc.uc_mcontext.gwins,
			    gwin, gwin_size)) {
				kmem_free(gwin, sizeof (gwindows32_t));
				return (set_errno(EFAULT));
			}
			/* restorecontext() should ignore this */
			uc.uc_mcontext.gwins = (caddr32_t)0;
		}

		ucontext_32ton(&uc, &ucnat, fpu_q, fpu_qnat);

		/*
		 * get extra register state if any exists
		 */
		if (xregs_hasptr32(lwp, &uc) &&
		    ((xregs_size = xregs_getsize(curproc)) > 0)) {
			xregs = kmem_zalloc(xregs_size, KM_SLEEP);
			if (copyin((void *)(uintptr_t)xregs_getptr32(lwp, &uc),
			    xregs, xregs_size)) {
				kmem_free(xregs, xregs_size);
				if (gwin)
					kmem_free(gwin, sizeof (gwindows32_t));
				return (set_errno(EFAULT));
			}
			xregs_setptr(lwp, &ucnat, xregs);
		} else {
			xregs_clrptr(lwp, &ucnat);
		}

		restorecontext(&ucnat);

		if ((uc.uc_flags & UC_STACK) && (lwp->lwp_ustack != 0)) {
			(void) copyout(&uc.uc_stack,
			    (stack32_t *)lwp->lwp_ustack, sizeof (stack32_t));
		}

		if (gwin)
			setgwins32(lwp, gwin);

		/*
		 * free extra register state area
		 */
		if (xregs_size)
			kmem_free(xregs, xregs_size);

		if (gwin)
			kmem_free(gwin, sizeof (gwindows32_t));

		return (0);

	case GETUSTACK:
		ustack32 = (uint32_t)lwp->lwp_ustack;
		if (copyout(&ustack32, arg, sizeof (caddr32_t)))
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
