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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc. */
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T   */
/*		All Rights Reserved				*/

/*	Copyright (c) 1987, 1988 Microsoft Corporation		*/
/*		All Rights Reserved				*/

/*
 * Copyright (c) 2009, Intel Corporation.
 * All rights reserved.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/signal.h>
#include <sys/regset.h>
#include <sys/privregs.h>
#include <sys/psw.h>
#include <sys/trap.h>
#include <sys/fault.h>
#include <sys/systm.h>
#include <sys/user.h>
#include <sys/file.h>
#include <sys/proc.h>
#include <sys/pcb.h>
#include <sys/lwp.h>
#include <sys/cpuvar.h>
#include <sys/thread.h>
#include <sys/disp.h>
#include <sys/fp.h>
#include <sys/siginfo.h>
#include <sys/archsystm.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/x86_archext.h>
#include <sys/sysmacros.h>
#include <sys/cmn_err.h>

/* Legacy fxsave layout + xsave header + ymm */
#define	AVX_XSAVE_SIZE		(512 + 64 + 256)

/*CSTYLED*/
#pragma	align 16 (sse_initial)

/*
 * Initial kfpu state for SSE/SSE2 used by fpinit()
 */
const struct fxsave_state sse_initial = {
	FPU_CW_INIT,	/* fx_fcw */
	0,		/* fx_fsw */
	0,		/* fx_fctw */
	0,		/* fx_fop */
#if defined(__amd64)
	0,		/* fx_rip */
	0,		/* fx_rdp */
#else
	0,		/* fx_eip */
	0,		/* fx_cs */
	0,		/* __fx_ign0 */
	0,		/* fx_dp */
	0,		/* fx_ds */
	0,		/* __fx_ign1 */
#endif /* __amd64 */
	SSE_MXCSR_INIT	/* fx_mxcsr */
	/* rest of structure is zero */
};

/*CSTYLED*/
#pragma	align 64 (avx_initial)

/*
 * Initial kfpu state for AVX used by fpinit()
 */
const struct xsave_state avx_initial = {
	/*
	 * The definition below needs to be identical with sse_initial
	 * defined above.
	 */
	{
		FPU_CW_INIT,	/* fx_fcw */
		0,		/* fx_fsw */
		0,		/* fx_fctw */
		0,		/* fx_fop */
#if defined(__amd64)
		0,		/* fx_rip */
		0,		/* fx_rdp */
#else
		0,		/* fx_eip */
		0,		/* fx_cs */
		0,		/* __fx_ign0 */
		0,		/* fx_dp */
		0,		/* fx_ds */
		0,		/* __fx_ign1 */
#endif /* __amd64 */
		SSE_MXCSR_INIT	/* fx_mxcsr */
		/* rest of structure is zero */
	},
	/*
	 * bit0 = 1 for XSTATE_BV to indicate that legacy fields are valid,
	 * and CPU should initialize XMM/YMM.
	 */
	1,
	{0, 0}	/* These 2 bytes must be zero */
	/* rest of structure is zero */
};

/*
 * mxcsr_mask value (possibly reset in fpu_probe); used to avoid
 * the #gp exception caused by setting unsupported bits in the
 * MXCSR register
 */
uint32_t sse_mxcsr_mask = SSE_MXCSR_MASK_DEFAULT;

/*
 * Initial kfpu state for x87 used by fpinit()
 */
const struct fnsave_state x87_initial = {
	FPU_CW_INIT,	/* f_fcw */
	0,		/* __f_ign0 */
	0,		/* f_fsw */
	0,		/* __f_ign1 */
	0xffff,		/* f_ftw */
	/* rest of structure is zero */
};

#if defined(__amd64)
/*
 * This vector is patched to xsave_ctxt() if we discover we have an
 * XSAVE-capable chip in fpu_probe.
 */
void (*fpsave_ctxt)(void *) = fpxsave_ctxt;
#elif defined(__i386)
/*
 * This vector is patched to fpxsave_ctxt() if we discover we have an
 * SSE-capable chip in fpu_probe(). It is patched to xsave_ctxt
 * if we discover we have an XSAVE-capable chip in fpu_probe.
 */
void (*fpsave_ctxt)(void *) = fpnsave_ctxt;
#endif

static int fpe_sicode(uint_t);
static int fpe_simd_sicode(uint_t);

/*
 * Copy the state of parent lwp's floating point context into the new lwp.
 * Invoked for both fork() and lwp_create().
 *
 * Note that we inherit -only- the control state (e.g. exception masks,
 * rounding, precision control, etc.); the FPU registers are otherwise
 * reset to their initial state.
 */
static void
fp_new_lwp(kthread_id_t t, kthread_id_t ct)
{
	struct fpu_ctx *fp;		/* parent fpu context */
	struct fpu_ctx *cfp;		/* new fpu context */
	struct fxsave_state *fx, *cfx;
#if defined(__i386)
	struct fnsave_state *fn, *cfn;
#endif
	struct xsave_state *cxs;

	ASSERT(fp_kind != FP_NO);

	fp = &t->t_lwp->lwp_pcb.pcb_fpu;
	cfp = &ct->t_lwp->lwp_pcb.pcb_fpu;

	/*
	 * If the parent FPU state is still in the FPU hw then save it;
	 * conveniently, fp_save() already does this for us nicely.
	 */
	fp_save(fp);

	cfp->fpu_flags = FPU_EN | FPU_VALID;
	cfp->fpu_regs.kfpu_status = 0;
	cfp->fpu_regs.kfpu_xstatus = 0;

	switch (fp_save_mech) {
#if defined(__i386)
	case FP_FNSAVE:
		fn = &fp->fpu_regs.kfpu_u.kfpu_fn;
		cfn = &cfp->fpu_regs.kfpu_u.kfpu_fn;
		bcopy(&x87_initial, cfn, sizeof (*cfn));
		cfn->f_fcw = fn->f_fcw;
		break;
#endif
	case FP_FXSAVE:
		fx = &fp->fpu_regs.kfpu_u.kfpu_fx;
		cfx = &cfp->fpu_regs.kfpu_u.kfpu_fx;
		bcopy(&sse_initial, cfx, sizeof (*cfx));
		cfx->fx_mxcsr = fx->fx_mxcsr & ~SSE_MXCSR_EFLAGS;
		cfx->fx_fcw = fx->fx_fcw;
		break;

	case FP_XSAVE:
		cfp->fpu_xsave_mask = fp->fpu_xsave_mask;

		fx = &fp->fpu_regs.kfpu_u.kfpu_xs.xs_fxsave;
		cxs = &cfp->fpu_regs.kfpu_u.kfpu_xs;
		cfx = &cxs->xs_fxsave;

		bcopy(&avx_initial, cxs, sizeof (*cxs));
		cfx->fx_mxcsr = fx->fx_mxcsr & ~SSE_MXCSR_EFLAGS;
		cfx->fx_fcw = fx->fx_fcw;
		cxs->xs_xstate_bv |= (get_xcr(XFEATURE_ENABLED_MASK) &
		    XFEATURE_FP_ALL);
		break;
	default:
		panic("Invalid fp_save_mech");
		/*NOTREACHED*/
	}

	installctx(ct, cfp,
	    fpsave_ctxt, NULL, fp_new_lwp, fp_new_lwp, NULL, fp_free);
	/*
	 * Now, when the new lwp starts running, it will take a trap
	 * that will be handled inline in the trap table to cause
	 * the appropriate f*rstor instruction to load the save area we
	 * constructed above directly into the hardware.
	 */
}

/*
 * Free any state associated with floating point context.
 * Fp_free can be called in three cases:
 * 1) from reaper -> thread_free -> ctxfree -> fp_free
 *	fp context belongs to a thread on deathrow
 *	nothing to do,  thread will never be resumed
 *	thread calling ctxfree is reaper
 *
 * 2) from exec -> ctxfree -> fp_free
 *	fp context belongs to the current thread
 *	must disable fpu, thread calling ctxfree is curthread
 *
 * 3) from restorecontext -> setfpregs -> fp_free
 *	we have a modified context in the memory (lwp->pcb_fpu)
 *	disable fpu and release the fp context for the CPU
 *
 */
/*ARGSUSED*/
void
fp_free(struct fpu_ctx *fp, int isexec)
{
	ASSERT(fp_kind != FP_NO);

	if (fp->fpu_flags & FPU_VALID)
		return;

	kpreempt_disable();
	/*
	 * We want to do fpsave rather than fpdisable so that we can
	 * keep the fpu_flags as FPU_VALID tracking the CR0_TS bit
	 */
	fp->fpu_flags |= FPU_VALID;
	/* If for current thread disable FP to track FPU_VALID */
	if (curthread->t_lwp && fp == &curthread->t_lwp->lwp_pcb.pcb_fpu) {
		/* Clear errors if any to prevent frstor from complaining */
		(void) fperr_reset();
		if (fp_kind & __FP_SSE)
			(void) fpxerr_reset();
		fpdisable();
	}
	kpreempt_enable();
}

/*
 * Store the floating point state and disable the floating point unit.
 */
void
fp_save(struct fpu_ctx *fp)
{
	ASSERT(fp_kind != FP_NO);

	kpreempt_disable();
	if (!fp || fp->fpu_flags & FPU_VALID) {
		kpreempt_enable();
		return;
	}
	ASSERT(curthread->t_lwp && fp == &curthread->t_lwp->lwp_pcb.pcb_fpu);

	switch (fp_save_mech) {
#if defined(__i386)
	case FP_FNSAVE:
		fpsave(&fp->fpu_regs.kfpu_u.kfpu_fn);
		break;
#endif
	case FP_FXSAVE:
		fpxsave(&fp->fpu_regs.kfpu_u.kfpu_fx);
		break;

	case FP_XSAVE:
		xsave(&fp->fpu_regs.kfpu_u.kfpu_xs, fp->fpu_xsave_mask);
		break;
	default:
		panic("Invalid fp_save_mech");
		/*NOTREACHED*/
	}

	fp->fpu_flags |= FPU_VALID;
	kpreempt_enable();
}

/*
 * Restore the FPU context for the thread:
 * The possibilities are:
 *	1. No active FPU context: Load the new context into the FPU hw
 *	   and enable the FPU.
 */
void
fp_restore(struct fpu_ctx *fp)
{
	switch (fp_save_mech) {
#if defined(__i386)
	case FP_FNSAVE:
		fprestore(&fp->fpu_regs.kfpu_u.kfpu_fn);
		break;
#endif
	case FP_FXSAVE:
		fpxrestore(&fp->fpu_regs.kfpu_u.kfpu_fx);
		break;

	case FP_XSAVE:
		xrestore(&fp->fpu_regs.kfpu_u.kfpu_xs, fp->fpu_xsave_mask);
		break;
	default:
		panic("Invalid fp_save_mech");
		/*NOTREACHED*/
	}

	fp->fpu_flags &= ~FPU_VALID;
}


/*
 * Seeds the initial state for the current thread.  The possibilities are:
 *      1. Another process has modified the FPU state before we have done any
 *         initialization: Load the FPU state from the LWP state.
 *      2. The FPU state has not been externally modified:  Load a clean state.
 */
static void
fp_seed(void)
{
	struct fpu_ctx *fp = &ttolwp(curthread)->lwp_pcb.pcb_fpu;

	ASSERT(curthread->t_preempt >= 1);
	ASSERT((fp->fpu_flags & FPU_EN) == 0);

	/*
	 * Always initialize a new context and initialize the hardware.
	 */
	if (fp_save_mech == FP_XSAVE) {
		fp->fpu_xsave_mask = get_xcr(XFEATURE_ENABLED_MASK) &
		    XFEATURE_FP_ALL;
	}

	installctx(curthread, fp,
	    fpsave_ctxt, NULL, fp_new_lwp, fp_new_lwp, NULL, fp_free);
	fpinit();

	/*
	 * If FPU_VALID is set, it means someone has modified registers via
	 * /proc.  In this case, restore the current lwp's state.
	 */
	if (fp->fpu_flags & FPU_VALID)
		fp_restore(fp);

	ASSERT((fp->fpu_flags & FPU_VALID) == 0);
	fp->fpu_flags = FPU_EN;
}

/*
 * This routine is called from trap() when User thread takes No Extension
 * Fault. The possiblities are:
 *	1. User thread has executed a FP instruction for the first time.
 *	   Save current FPU context if any. Initialize FPU, setup FPU
 *	   context for the thread and enable FP hw.
 *	2. Thread's pcb has a valid FPU state: Restore the FPU state and
 *	   enable FP hw.
 *
 * Note that case #2 is inlined in the trap table.
 */
int
fpnoextflt(struct regs *rp)
{
	struct fpu_ctx *fp = &ttolwp(curthread)->lwp_pcb.pcb_fpu;

#if !defined(__lint)
	ASSERT(sizeof (struct fxsave_state) == 512 &&
	    sizeof (struct fnsave_state) == 108);
	ASSERT((offsetof(struct fxsave_state, fx_xmm[0]) & 0xf) == 0);

	ASSERT(sizeof (struct xsave_state) >= AVX_XSAVE_SIZE);

#if defined(__i386)
	ASSERT(sizeof (struct fpu) == sizeof (struct __old_fpu));
#endif	/* __i386 */
#endif	/* !__lint */

	/*
	 * save area MUST be 16-byte aligned, else will page fault
	 */
	ASSERT(((uintptr_t)(&fp->fpu_regs.kfpu_u.kfpu_fx) & 0xf) == 0);

	kpreempt_disable();
	/*
	 * Now we can enable the interrupts.
	 * (NOTE: fp-no-coprocessor comes thru interrupt gate)
	 */
	sti();

	if (!fpu_exists) { /* check for FPU hw exists */
		if (fp_kind == FP_NO) {
			uint32_t inst;

			/*
			 * When the system has no floating point support,
			 * i.e. no FP hardware and no emulator, skip the
			 * two kinds of FP instruction that occur in
			 * fpstart.  Allows processes that do no real FP
			 * to run normally.
			 */
			if (fuword32((void *)rp->r_pc, &inst) != -1 &&
			    ((inst & 0xFFFF) == 0x7dd9 ||
			    (inst & 0xFFFF) == 0x6dd9)) {
				rp->r_pc += 3;
				kpreempt_enable();
				return (0);
			}
		}

		/*
		 * If we have neither a processor extension nor
		 * an emulator, kill the process OR panic the kernel.
		 */
		kpreempt_enable();
		return (1); /* error */
	}

#if !defined(__xpv)	/* XXPV	Is this ifdef needed now? */
	/*
	 * A paranoid cross-check: for the SSE case, ensure that %cr4 is
	 * configured to enable fully fledged (%xmm) fxsave/fxrestor on
	 * this CPU.  For the non-SSE case, ensure that it isn't.
	 */
	ASSERT(((fp_kind & __FP_SSE) &&
	    (getcr4() & CR4_OSFXSR) == CR4_OSFXSR) ||
	    (!(fp_kind & __FP_SSE) &&
	    (getcr4() & (CR4_OSXMMEXCPT|CR4_OSFXSR)) == 0));
#endif

	if (fp->fpu_flags & FPU_EN) {
		/* case 2 */
		fp_restore(fp);
	} else {
		/* case 1 */
		fp_seed();
	}
	kpreempt_enable();
	return (0);
}


/*
 * Handle a processor extension overrun fault
 * Returns non zero for error.
 *
 * XXX	Shouldn't this just be abolished given that we're not supporting
 *	anything prior to Pentium?
 */

/* ARGSUSED */
int
fpextovrflt(struct regs *rp)
{
#if !defined(__xpv)		/* XXPV	Do we need this ifdef either */
	ulong_t cur_cr0;

	ASSERT(fp_kind != FP_NO);

	cur_cr0 = getcr0();
	fpinit();		/* initialize the FPU hardware */
	setcr0(cur_cr0);
#endif
	sti();
	return (1); 		/* error, send SIGSEGV signal to the thread */
}

/*
 * Handle a processor extension error fault
 * Returns non zero for error.
 */

/*ARGSUSED*/
int
fpexterrflt(struct regs *rp)
{
	uint32_t fpcw, fpsw;
	fpu_ctx_t *fp = &ttolwp(curthread)->lwp_pcb.pcb_fpu;

	ASSERT(fp_kind != FP_NO);

	/*
	 * Now we can enable the interrupts.
	 * (NOTE: x87 fp exceptions come thru interrupt gate)
	 */
	sti();

	if (!fpu_exists)
		return (FPE_FLTINV);

	/*
	 * Do an unconditional save of the FP state.  If it's dirty (TS=0),
	 * it'll be saved into the fpu context area passed in (that of the
	 * current thread).  If it's not dirty (it may not be, due to
	 * an intervening save due to a context switch between the sti(),
	 * above and here, then it's safe to just use the stored values in
	 * the context save area to determine the cause of the fault.
	 */
	fp_save(fp);

	/* clear exception flags in saved state, as if by fnclex */
	switch (fp_save_mech) {
#if defined(__i386)
	case FP_FNSAVE:
		fpsw = fp->fpu_regs.kfpu_u.kfpu_fn.f_fsw;
		fpcw = fp->fpu_regs.kfpu_u.kfpu_fn.f_fcw;
		fp->fpu_regs.kfpu_u.kfpu_fn.f_fsw &= ~FPS_SW_EFLAGS;
		break;
#endif

	case FP_FXSAVE:
		fpsw = fp->fpu_regs.kfpu_u.kfpu_fx.fx_fsw;
		fpcw = fp->fpu_regs.kfpu_u.kfpu_fx.fx_fcw;
		fp->fpu_regs.kfpu_u.kfpu_fx.fx_fsw &= ~FPS_SW_EFLAGS;
		break;

	case FP_XSAVE:
		fpsw = fp->fpu_regs.kfpu_u.kfpu_xs.xs_fxsave.fx_fsw;
		fpcw = fp->fpu_regs.kfpu_u.kfpu_xs.xs_fxsave.fx_fcw;
		fp->fpu_regs.kfpu_u.kfpu_xs.xs_fxsave.fx_fsw &= ~FPS_SW_EFLAGS;
		/*
		 * Always set LEGACY_FP as it may have been cleared by XSAVE
		 * instruction
		 */
		fp->fpu_regs.kfpu_u.kfpu_xs.xs_xstate_bv |= XFEATURE_LEGACY_FP;
		break;
	default:
		panic("Invalid fp_save_mech");
		/*NOTREACHED*/
	}

	fp->fpu_regs.kfpu_status = fpsw;

	if ((fpsw & FPS_ES) == 0)
		return (0);		/* No exception */

	/*
	 * "and" the exception flags with the complement of the mask
	 * bits to determine which exception occurred
	 */
	return (fpe_sicode(fpsw & ~fpcw & 0x3f));
}

/*
 * Handle an SSE/SSE2 precise exception.
 * Returns a non-zero sicode for error.
 */
/*ARGSUSED*/
int
fpsimderrflt(struct regs *rp)
{
	uint32_t mxcsr, xmask;
	fpu_ctx_t *fp = &ttolwp(curthread)->lwp_pcb.pcb_fpu;

	ASSERT(fp_kind & __FP_SSE);

	/*
	 * NOTE: Interrupts are disabled during execution of this
	 * function.  They are enabled by the caller in trap.c.
	 */

	/*
	 * The only way we could have gotten here if there is no FP unit
	 * is via a user executing an INT $19 instruction, so there is
	 * no fault in that case.
	 */
	if (!fpu_exists)
		return (0);

	/*
	 * Do an unconditional save of the FP state.  If it's dirty (TS=0),
	 * it'll be saved into the fpu context area passed in (that of the
	 * current thread).  If it's not dirty, then it's safe to just use
	 * the stored values in the context save area to determine the
	 * cause of the fault.
	 */
	fp_save(fp); 		/* save the FPU state */

	mxcsr = fp->fpu_regs.kfpu_u.kfpu_fx.fx_mxcsr;

	fp->fpu_regs.kfpu_status = fp->fpu_regs.kfpu_u.kfpu_fx.fx_fsw;

	fp->fpu_regs.kfpu_xstatus = mxcsr;

	/*
	 * compute the mask that determines which conditions can cause
	 * a #xm exception, and use this to clean the status bits so that
	 * we can identify the true cause of this one.
	 */
	xmask = (mxcsr >> 7) & SSE_MXCSR_EFLAGS;
	return (fpe_simd_sicode((mxcsr & SSE_MXCSR_EFLAGS) & ~xmask));
}

/*
 * In the unlikely event that someone is relying on this subcode being
 * FPE_FLTILL for denormalize exceptions, it can always be patched back
 * again to restore old behaviour.
 */
int fpe_fltden = FPE_FLTDEN;

/*
 * Map from the FPU status word to the FP exception si_code.
 */
static int
fpe_sicode(uint_t sw)
{
	if (sw & FPS_IE)
		return (FPE_FLTINV);
	if (sw & FPS_ZE)
		return (FPE_FLTDIV);
	if (sw & FPS_DE)
		return (fpe_fltden);
	if (sw & FPS_OE)
		return (FPE_FLTOVF);
	if (sw & FPS_UE)
		return (FPE_FLTUND);
	if (sw & FPS_PE)
		return (FPE_FLTRES);
	return (FPE_FLTINV);	/* default si_code for other exceptions */
}

/*
 * Map from the SSE status word to the FP exception si_code.
 */
static int
fpe_simd_sicode(uint_t sw)
{
	if (sw & SSE_IE)
		return (FPE_FLTINV);
	if (sw & SSE_ZE)
		return (FPE_FLTDIV);
	if (sw & SSE_DE)
		return (FPE_FLTDEN);
	if (sw & SSE_OE)
		return (FPE_FLTOVF);
	if (sw & SSE_UE)
		return (FPE_FLTUND);
	if (sw & SSE_PE)
		return (FPE_FLTRES);
	return (FPE_FLTINV);	/* default si_code for other exceptions */
}

/*
 * This routine is invoked as part of libc's __fpstart implementation
 * via sysi86(2).
 *
 * It may be called -before- any context has been assigned in which case
 * we try and avoid touching the hardware.  Or it may be invoked well
 * after the context has been assigned and fiddled with, in which case
 * just tweak it directly.
 */
void
fpsetcw(uint16_t fcw, uint32_t mxcsr)
{
	struct fpu_ctx *fp = &curthread->t_lwp->lwp_pcb.pcb_fpu;
	struct fxsave_state *fx;

	if (!fpu_exists || fp_kind == FP_NO)
		return;

	if ((fp->fpu_flags & FPU_EN) == 0) {
		if (fcw == FPU_CW_INIT && mxcsr == SSE_MXCSR_INIT) {
			/*
			 * Common case.  Floating point unit not yet
			 * enabled, and kernel already intends to initialize
			 * the hardware the way the caller wants.
			 */
			return;
		}
		/*
		 * Hmm.  Userland wants a different default.
		 * Do a fake "first trap" to establish the context, then
		 * handle as if we already had a context before we came in.
		 */
		kpreempt_disable();
		fp_seed();
		kpreempt_enable();
	}

	/*
	 * Ensure that the current hardware state is flushed back to the
	 * pcb, then modify that copy.  Next use of the fp will
	 * restore the context.
	 */
	fp_save(fp);

	switch (fp_save_mech) {
#if defined(__i386)
	case FP_FNSAVE:
		fp->fpu_regs.kfpu_u.kfpu_fn.f_fcw = fcw;
		break;
#endif
	case FP_FXSAVE:
		fx = &fp->fpu_regs.kfpu_u.kfpu_fx;
		fx->fx_fcw = fcw;
		fx->fx_mxcsr = sse_mxcsr_mask & mxcsr;
		break;

	case FP_XSAVE:
		fx = &fp->fpu_regs.kfpu_u.kfpu_xs.xs_fxsave;
		fx->fx_fcw = fcw;
		fx->fx_mxcsr = sse_mxcsr_mask & mxcsr;
		/*
		 * Always set LEGACY_FP as it may have been cleared by XSAVE
		 * instruction
		 */
		fp->fpu_regs.kfpu_u.kfpu_xs.xs_xstate_bv |= XFEATURE_LEGACY_FP;
		break;
	default:
		panic("Invalid fp_save_mech");
		/*NOTREACHED*/
	}
}
