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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/vmparam.h>
#include <sys/systm.h>
#include <sys/stack.h>
#include <sys/frame.h>
#include <sys/proc.h>
#include <sys/ucontext.h>
#include <sys/cpuvar.h>
#include <sys/asm_linkage.h>
#include <sys/kmem.h>
#include <sys/errno.h>
#include <sys/bootconf.h>
#include <sys/archsystm.h>
#include <sys/fpu/fpusystm.h>
#include <sys/debug.h>
#include <sys/privregs.h>
#include <sys/machpcb.h>
#include <sys/psr_compat.h>
#include <sys/cmn_err.h>
#include <sys/asi.h>
#include <sys/copyops.h>
#include <sys/model.h>
#include <sys/panic.h>
#include <sys/exec.h>

/*
 * By default, set the weakest model to TSO (Total Store Order)
 * which is the default memory model on SPARC.
 * If a platform does support a weaker model than TSO, this will be
 * updated at runtime to reflect that.
 */
uint_t weakest_mem_model = TSTATE_MM_TSO;

/*
 * modify the lower 32bits of a uint64_t
 */
#define	SET_LOWER_32(all, lower)	\
	(((uint64_t)(all) & 0xffffffff00000000) | (uint32_t)(lower))

#define	MEMCPY_FPU_EN		2	/* fprs on and fpu_en == 0 */

static uint_t mkpsr(uint64_t tstate, uint32_t fprs);

#ifdef _SYSCALL32_IMPL
static void fpuregset_32ton(const fpregset32_t *src, fpregset_t *dest,
    const struct fq32 *sfq, struct _fq *dfq);
#endif /* _SYSCALL32_IMPL */

/*
 * Set floating-point registers.
 * NOTE:  'lwp' might not correspond to 'curthread' since this is
 * called from code in /proc to set the registers of another lwp.
 */
void
setfpregs(klwp_t *lwp, fpregset_t *fp)
{
	struct machpcb *mpcb;
	kfpu_t *pfp;
	uint32_t fprs = (FPRS_FEF|FPRS_DU|FPRS_DL);
	model_t model = lwp_getdatamodel(lwp);

	mpcb = lwptompcb(lwp);
	pfp = lwptofpu(lwp);

	/*
	 * This is always true for both "real" fp programs and memcpy fp
	 * programs, because we force fpu_en to MEMCPY_FPU_EN in getfpregs,
	 * for the memcpy and threads cases where (fpu_en == 0) &&
	 * (fpu_fprs & FPRS_FEF), if setfpregs is called after getfpregs.
	 */
	if (fp->fpu_en) {
		kpreempt_disable();

		if (!(pfp->fpu_en) && (!(pfp->fpu_fprs & FPRS_FEF)) &&
		    fpu_exists) {
			/*
			 * He's not currently using the FPU but wants to in his
			 * new context - arrange for this on return to userland.
			 */
			pfp->fpu_fprs = (uint32_t)fprs;
		}
		/*
		 * Get setfpregs to restore fpu_en to zero
		 * for the memcpy/threads case (where pfp->fpu_en == 0 &&
		 * (pfp->fp_fprs & FPRS_FEF) == FPRS_FEF).
		 */
		if (fp->fpu_en == MEMCPY_FPU_EN)
			fp->fpu_en = 0;

		/*
		 * Load up a user's floating point context.
		 */
		if (fp->fpu_qcnt > MAXFPQ) 	/* plug security holes */
			fp->fpu_qcnt = MAXFPQ;
		fp->fpu_q_entrysize = sizeof (struct _fq);

		/*
		 * For v9 kernel, copy all of the fp regs.
		 * For v8 kernel, copy v8 fp regs (lower half of v9 fp regs).
		 * Restore entire fsr for v9, only lower half for v8.
		 */
		(void) kcopy(fp, pfp, sizeof (fp->fpu_fr));
		if (model == DATAMODEL_LP64)
			pfp->fpu_fsr = fp->fpu_fsr;
		else
			pfp->fpu_fsr = SET_LOWER_32(pfp->fpu_fsr, fp->fpu_fsr);
		pfp->fpu_qcnt = fp->fpu_qcnt;
		pfp->fpu_q_entrysize = fp->fpu_q_entrysize;
		pfp->fpu_en = fp->fpu_en;
		pfp->fpu_q = mpcb->mpcb_fpu_q;
		if (fp->fpu_qcnt)
			(void) kcopy(fp->fpu_q, pfp->fpu_q,
			    fp->fpu_qcnt * fp->fpu_q_entrysize);
		/* FSR ignores these bits on load, so they can not be set */
		pfp->fpu_fsr &= ~(FSR_QNE|FSR_FTT);

		/*
		 * If not the current process then resume() will handle it.
		 */
		if (lwp != ttolwp(curthread)) {
			/* force resume to reload fp regs */
			pfp->fpu_fprs |= FPRS_FEF;
			kpreempt_enable();
			return;
		}

		/*
		 * Load up FPU with new floating point context.
		 */
		if (fpu_exists) {
			pfp->fpu_fprs = _fp_read_fprs();
			if ((pfp->fpu_fprs & FPRS_FEF) != FPRS_FEF) {
				_fp_write_fprs(fprs);
				pfp->fpu_fprs = (uint32_t)fprs;
#ifdef DEBUG
				if (fpdispr)
					cmn_err(CE_NOTE,
					    "setfpregs with fp disabled!\n");
#endif
			}
			/*
			 * Load all fp regs for v9 user programs, but only
			 * load the lower half for v8[plus] programs.
			 */
			if (model == DATAMODEL_LP64)
				fp_restore(pfp);
			else
				fp_v8_load(pfp);
		}

		kpreempt_enable();
	} else {
		if ((pfp->fpu_en) ||	/* normal fp case */
		    (pfp->fpu_fprs & FPRS_FEF)) { /* memcpy/threads case */
			/*
			 * Currently the lwp has floating point enabled.
			 * Turn off FPRS_FEF in user's fprs, saved and
			 * real copies thereof.
			 */
			pfp->fpu_en = 0;
			if (fpu_exists) {
				fprs = 0;
				if (lwp == ttolwp(curthread))
					_fp_write_fprs(fprs);
				pfp->fpu_fprs = (uint32_t)fprs;
			}
		}
	}
}

#ifdef	_SYSCALL32_IMPL
void
setfpregs32(klwp_t *lwp, fpregset32_t *fp)
{
	fpregset_t fpregs;

	fpuregset_32ton(fp, &fpregs, NULL, NULL);
	setfpregs(lwp, &fpregs);
}
#endif	/* _SYSCALL32_IMPL */

/*
 * NOTE:  'lwp' might not correspond to 'curthread' since this is
 * called from code in /proc to set the registers of another lwp.
 */
void
run_fpq(klwp_t *lwp, fpregset_t *fp)
{
	/*
	 * If the context being loaded up includes a floating queue,
	 * we need to simulate those instructions (since we can't reload
	 * the fpu) and pass the process any appropriate signals
	 */

	if (lwp == ttolwp(curthread)) {
		if (fpu_exists) {
			if (fp->fpu_qcnt)
				fp_runq(lwp->lwp_regs);
		}
	}
}

/*
 * Get floating-point registers.
 * NOTE:  'lwp' might not correspond to 'curthread' since this is
 * called from code in /proc to set the registers of another lwp.
 */
void
getfpregs(klwp_t *lwp, fpregset_t *fp)
{
	kfpu_t *pfp;
	model_t model = lwp_getdatamodel(lwp);

	pfp = lwptofpu(lwp);
	kpreempt_disable();
	if (fpu_exists && ttolwp(curthread) == lwp)
		pfp->fpu_fprs = _fp_read_fprs();

	/*
	 * First check the fpu_en case, for normal fp programs.
	 * Next check the fprs case, for fp use by memcpy/threads.
	 */
	if (((fp->fpu_en = pfp->fpu_en) != 0) ||
	    (pfp->fpu_fprs & FPRS_FEF)) {
		/*
		 * Force setfpregs to restore the fp context in
		 * setfpregs for the memcpy and threads cases (where
		 * pfp->fpu_en == 0 && (pfp->fp_fprs & FPRS_FEF) == FPRS_FEF).
		 */
		if (pfp->fpu_en == 0)
			fp->fpu_en = MEMCPY_FPU_EN;
		/*
		 * If we have an fpu and the current thread owns the fp
		 * context, flush fp * registers into the pcb. Save all
		 * the fp regs for v9, xregs_getfpregs saves the upper half
		 * for v8plus. Save entire fsr for v9, only lower half for v8.
		 */
		if (fpu_exists && ttolwp(curthread) == lwp) {
			if ((pfp->fpu_fprs & FPRS_FEF) != FPRS_FEF) {
				uint32_t fprs = (FPRS_FEF|FPRS_DU|FPRS_DL);

				_fp_write_fprs(fprs);
				pfp->fpu_fprs = fprs;
#ifdef DEBUG
				if (fpdispr)
					cmn_err(CE_NOTE,
					    "getfpregs with fp disabled!\n");
#endif
			}
			if (model == DATAMODEL_LP64)
				fp_fksave(pfp);
			else
				fp_v8_fksave(pfp);
		}
		(void) kcopy(pfp, fp, sizeof (fp->fpu_fr));
		fp->fpu_q = pfp->fpu_q;
		if (model == DATAMODEL_LP64)
			fp->fpu_fsr = pfp->fpu_fsr;
		else
			fp->fpu_fsr = (uint32_t)pfp->fpu_fsr;
		fp->fpu_qcnt = pfp->fpu_qcnt;
		fp->fpu_q_entrysize = pfp->fpu_q_entrysize;
	} else {
		int i;
		for (i = 0; i < 32; i++)		/* NaN */
			((uint32_t *)fp->fpu_fr.fpu_regs)[i] = (uint32_t)-1;
		if (model == DATAMODEL_LP64) {
			for (i = 16; i < 32; i++)	/* NaN */
				((uint64_t *)fp->fpu_fr.fpu_dregs)[i] =
				    (uint64_t)-1;
		}
		fp->fpu_fsr = 0;
		fp->fpu_qcnt = 0;
	}
	kpreempt_enable();
}

#ifdef	_SYSCALL32_IMPL
void
getfpregs32(klwp_t *lwp, fpregset32_t *fp)
{
	fpregset_t fpregs;

	getfpregs(lwp, &fpregs);
	fpuregset_nto32(&fpregs, fp, NULL);
}
#endif	/* _SYSCALL32_IMPL */

/*
 * Set general registers.
 * NOTE:  'lwp' might not correspond to 'curthread' since this is
 * called from code in /proc to set the registers of another lwp.
 */

/* 64-bit gregset_t */
void
setgregs(klwp_t *lwp, gregset_t grp)
{
	struct regs *rp = lwptoregs(lwp);
	kfpu_t *fp = lwptofpu(lwp);
	uint64_t tbits;

	int current = (lwp == curthread->t_lwp);

	if (current)
		(void) save_syscall_args();	/* copy the args first */

	tbits = (((grp[REG_CCR] & TSTATE_CCR_MASK) << TSTATE_CCR_SHIFT) |
	    ((grp[REG_ASI] & TSTATE_ASI_MASK) << TSTATE_ASI_SHIFT));
	rp->r_tstate &= ~(((uint64_t)TSTATE_CCR_MASK << TSTATE_CCR_SHIFT) |
	    ((uint64_t)TSTATE_ASI_MASK << TSTATE_ASI_SHIFT));
	rp->r_tstate |= tbits;
	kpreempt_disable();
	fp->fpu_fprs = (uint32_t)grp[REG_FPRS];
	if (fpu_exists && (current) && (fp->fpu_fprs & FPRS_FEF))
		_fp_write_fprs(fp->fpu_fprs);
	kpreempt_enable();

	/*
	 * pc and npc must be 4-byte aligned on sparc.
	 * We silently make it so to avoid a watchdog reset.
	 */
	rp->r_pc = grp[REG_PC] & ~03L;
	rp->r_npc = grp[REG_nPC] & ~03L;
	rp->r_y = grp[REG_Y];

	rp->r_g1 = grp[REG_G1];
	rp->r_g2 = grp[REG_G2];
	rp->r_g3 = grp[REG_G3];
	rp->r_g4 = grp[REG_G4];
	rp->r_g5 = grp[REG_G5];
	rp->r_g6 = grp[REG_G6];
	rp->r_g7 = grp[REG_G7];

	rp->r_o0 = grp[REG_O0];
	rp->r_o1 = grp[REG_O1];
	rp->r_o2 = grp[REG_O2];
	rp->r_o3 = grp[REG_O3];
	rp->r_o4 = grp[REG_O4];
	rp->r_o5 = grp[REG_O5];
	rp->r_o6 = grp[REG_O6];
	rp->r_o7 = grp[REG_O7];

	if (current) {
		/*
		 * This was called from a system call, but we
		 * do not want to return via the shared window;
		 * restoring the CPU context changes everything.
		 */
		lwp->lwp_eosys = JUSTRETURN;
		curthread->t_post_sys = 1;
	}
}

/*
 * Return the general registers.
 * NOTE:  'lwp' might not correspond to 'curthread' since this is
 * called from code in /proc to get the registers of another lwp.
 */
void
getgregs(klwp_t *lwp, gregset_t grp)
{
	struct regs *rp = lwptoregs(lwp);
	uint32_t fprs;

	kpreempt_disable();
	if (fpu_exists && ttolwp(curthread) == lwp) {
		fprs = _fp_read_fprs();
	} else {
		kfpu_t *fp = lwptofpu(lwp);
		fprs = fp->fpu_fprs;
	}
	kpreempt_enable();
	grp[REG_CCR] = (rp->r_tstate >> TSTATE_CCR_SHIFT) & TSTATE_CCR_MASK;
	grp[REG_PC] = rp->r_pc;
	grp[REG_nPC] = rp->r_npc;
	grp[REG_Y] = (uint32_t)rp->r_y;
	grp[REG_G1] = rp->r_g1;
	grp[REG_G2] = rp->r_g2;
	grp[REG_G3] = rp->r_g3;
	grp[REG_G4] = rp->r_g4;
	grp[REG_G5] = rp->r_g5;
	grp[REG_G6] = rp->r_g6;
	grp[REG_G7] = rp->r_g7;
	grp[REG_O0] = rp->r_o0;
	grp[REG_O1] = rp->r_o1;
	grp[REG_O2] = rp->r_o2;
	grp[REG_O3] = rp->r_o3;
	grp[REG_O4] = rp->r_o4;
	grp[REG_O5] = rp->r_o5;
	grp[REG_O6] = rp->r_o6;
	grp[REG_O7] = rp->r_o7;
	grp[REG_ASI] = (rp->r_tstate >> TSTATE_ASI_SHIFT) & TSTATE_ASI_MASK;
	grp[REG_FPRS] = fprs;
}

void
getgregs32(klwp_t *lwp, gregset32_t grp)
{
	struct regs *rp = lwptoregs(lwp);
	uint32_t fprs;

	kpreempt_disable();
	if (fpu_exists && ttolwp(curthread) == lwp) {
		fprs = _fp_read_fprs();
	} else {
		kfpu_t *fp = lwptofpu(lwp);
		fprs = fp->fpu_fprs;
	}
	kpreempt_enable();
	grp[REG_PSR] = mkpsr(rp->r_tstate, fprs);
	grp[REG_PC] = rp->r_pc;
	grp[REG_nPC] = rp->r_npc;
	grp[REG_Y] = rp->r_y;
	grp[REG_G1] = rp->r_g1;
	grp[REG_G2] = rp->r_g2;
	grp[REG_G3] = rp->r_g3;
	grp[REG_G4] = rp->r_g4;
	grp[REG_G5] = rp->r_g5;
	grp[REG_G6] = rp->r_g6;
	grp[REG_G7] = rp->r_g7;
	grp[REG_O0] = rp->r_o0;
	grp[REG_O1] = rp->r_o1;
	grp[REG_O2] = rp->r_o2;
	grp[REG_O3] = rp->r_o3;
	grp[REG_O4] = rp->r_o4;
	grp[REG_O5] = rp->r_o5;
	grp[REG_O6] = rp->r_o6;
	grp[REG_O7] = rp->r_o7;
}

/*
 * Return the user-level PC.
 * If in a system call, return the address of the syscall trap.
 */
greg_t
getuserpc()
{
	return (lwptoregs(ttolwp(curthread))->r_pc);
}

/*
 * Set register windows.
 */
void
setgwins(klwp_t *lwp, gwindows_t *gwins)
{
	struct machpcb *mpcb = lwptompcb(lwp);
	int wbcnt = gwins->wbcnt;
	caddr_t sp;
	int i;
	struct rwindow32 *rwp;
	int wbuf_rwindow_size;
	int is64;

	if (mpcb->mpcb_wstate == WSTATE_USER32) {
		wbuf_rwindow_size = WINDOWSIZE32;
		is64 = 0;
	} else {
		wbuf_rwindow_size = WINDOWSIZE64;
		is64 = 1;
	}
	ASSERT(wbcnt >= 0 && wbcnt <= SPARC_MAXREGWINDOW);
	mpcb->mpcb_wbcnt = 0;
	for (i = 0; i < wbcnt; i++) {
		sp = (caddr_t)gwins->spbuf[i];
		mpcb->mpcb_spbuf[i] = sp;
		rwp = (struct rwindow32 *)
		    (mpcb->mpcb_wbuf + (i * wbuf_rwindow_size));
		if (is64 && IS_V9STACK(sp))
			bcopy(&gwins->wbuf[i], rwp, sizeof (struct rwindow));
		else
			rwindow_nto32(&gwins->wbuf[i], rwp);
		mpcb->mpcb_wbcnt++;
	}
}

void
setgwins32(klwp_t *lwp, gwindows32_t *gwins)
{
	struct machpcb *mpcb = lwptompcb(lwp);
	int wbcnt = gwins->wbcnt;
	caddr_t sp;
	int i;

	struct rwindow *rwp;
	int wbuf_rwindow_size;
	int is64;

	if (mpcb->mpcb_wstate == WSTATE_USER32) {
		wbuf_rwindow_size = WINDOWSIZE32;
		is64 = 0;
	} else {
		wbuf_rwindow_size = WINDOWSIZE64;
		is64 = 1;
	}

	ASSERT(wbcnt >= 0 && wbcnt <= SPARC_MAXREGWINDOW);
	mpcb->mpcb_wbcnt = 0;
	for (i = 0; i < wbcnt; i++) {
		sp = (caddr_t)(uintptr_t)gwins->spbuf[i];
		mpcb->mpcb_spbuf[i] = sp;
		rwp = (struct rwindow *)
		    (mpcb->mpcb_wbuf + (i * wbuf_rwindow_size));
		if (is64 && IS_V9STACK(sp))
			rwindow_32ton(&gwins->wbuf[i], rwp);
		else
			bcopy(&gwins->wbuf[i], rwp, sizeof (struct rwindow32));
		mpcb->mpcb_wbcnt++;
	}
}

/*
 * Get register windows.
 * NOTE:  'lwp' might not correspond to 'curthread' since this is
 * called from code in /proc to set the registers of another lwp.
 */
void
getgwins(klwp_t *lwp, gwindows_t *gwp)
{
	struct machpcb *mpcb = lwptompcb(lwp);
	int wbcnt = mpcb->mpcb_wbcnt;
	caddr_t sp;
	int i;
	struct rwindow32 *rwp;
	int wbuf_rwindow_size;
	int is64;

	if (mpcb->mpcb_wstate == WSTATE_USER32) {
		wbuf_rwindow_size = WINDOWSIZE32;
		is64 = 0;
	} else {
		wbuf_rwindow_size = WINDOWSIZE64;
		is64 = 1;
	}
	ASSERT(wbcnt >= 0 && wbcnt <= SPARC_MAXREGWINDOW);
	gwp->wbcnt = wbcnt;
	for (i = 0; i < wbcnt; i++) {
		sp = mpcb->mpcb_spbuf[i];
		gwp->spbuf[i] = (greg_t *)sp;
		rwp = (struct rwindow32 *)
		    (mpcb->mpcb_wbuf + (i * wbuf_rwindow_size));
		if (is64 && IS_V9STACK(sp))
			bcopy(rwp, &gwp->wbuf[i], sizeof (struct rwindow));
		else
			rwindow_32ton(rwp, &gwp->wbuf[i]);
	}
}

void
getgwins32(klwp_t *lwp, gwindows32_t *gwp)
{
	struct machpcb *mpcb = lwptompcb(lwp);
	int wbcnt = mpcb->mpcb_wbcnt;
	int i;
	struct rwindow *rwp;
	int wbuf_rwindow_size;
	caddr_t sp;
	int is64;

	if (mpcb->mpcb_wstate == WSTATE_USER32) {
		wbuf_rwindow_size = WINDOWSIZE32;
		is64 = 0;
	} else {
		wbuf_rwindow_size = WINDOWSIZE64;
		is64 = 1;
	}

	ASSERT(wbcnt >= 0 && wbcnt <= SPARC_MAXREGWINDOW);
	gwp->wbcnt = wbcnt;
	for (i = 0; i < wbcnt; i++) {
		sp = mpcb->mpcb_spbuf[i];
		rwp = (struct rwindow *)
		    (mpcb->mpcb_wbuf + (i * wbuf_rwindow_size));
		gwp->spbuf[i] = (caddr32_t)(uintptr_t)sp;
		if (is64 && IS_V9STACK(sp))
			rwindow_nto32(rwp, &gwp->wbuf[i]);
		else
			bcopy(rwp, &gwp->wbuf[i], sizeof (struct rwindow32));
	}
}

/*
 * For things that depend on register state being on the stack,
 * copy any register windows that get saved into the window buffer
 * (in the pcb) onto the stack.  This normally gets fixed up
 * before returning to a user program.  Callers of this routine
 * require this to happen immediately because a later kernel
 * operation depends on window state (like instruction simulation).
 */
int
flush_user_windows_to_stack(caddr_t *psp)
{
	int j, k;
	caddr_t sp;
	struct machpcb *mpcb = lwptompcb(ttolwp(curthread));
	int err;
	int error = 0;
	int wbuf_rwindow_size;
	int rwindow_size;
	int stack_align;
	int watched;

	flush_user_windows();

	if (mpcb->mpcb_wstate != WSTATE_USER32)
		wbuf_rwindow_size = WINDOWSIZE64;
	else
		wbuf_rwindow_size = WINDOWSIZE32;

	j = mpcb->mpcb_wbcnt;
	while (j > 0) {
		sp = mpcb->mpcb_spbuf[--j];

		if ((mpcb->mpcb_wstate != WSTATE_USER32) &&
		    IS_V9STACK(sp)) {
			sp += V9BIAS64;
			stack_align = STACK_ALIGN64;
			rwindow_size = WINDOWSIZE64;
		} else {
			/*
			 * Reduce sp to a 32 bit value.  This was originally
			 * done by casting down to uint32_t and back up to
			 * caddr_t, but one compiler didn't like that, so the
			 * uintptr_t casts were added.  The temporary 32 bit
			 * variable was introduced to avoid depending on all
			 * compilers to generate the desired assembly code for a
			 * quadruple cast in a single expression.
			 */
			caddr32_t sp32 = (uint32_t)(uintptr_t)sp;
			sp = (caddr_t)(uintptr_t)sp32;

			stack_align = STACK_ALIGN32;
			rwindow_size = WINDOWSIZE32;
		}
		if (((uintptr_t)sp & (stack_align - 1)) != 0)
			continue;

		watched = watch_disable_addr(sp, rwindow_size, S_WRITE);
		err = xcopyout(mpcb->mpcb_wbuf +
		    (j * wbuf_rwindow_size), sp, rwindow_size);
		if (err != 0) {
			if (psp != NULL) {
				/*
				 * Determine the offending address.
				 * It may not be the stack pointer itself.
				 */
				uint_t *kaddr = (uint_t *)(mpcb->mpcb_wbuf +
				    (j * wbuf_rwindow_size));
				uint_t *uaddr = (uint_t *)sp;

				for (k = 0;
				    k < rwindow_size / sizeof (int);
				    k++, kaddr++, uaddr++) {
					if (suword32(uaddr, *kaddr))
						break;
				}

				/* can't happen? */
				if (k == rwindow_size / sizeof (int))
					uaddr = (uint_t *)sp;

				*psp = (caddr_t)uaddr;
			}
			error = err;
		} else {
			/*
			 * stack was aligned and copyout succeeded;
			 * move other windows down.
			 */
			mpcb->mpcb_wbcnt--;
			for (k = j; k < mpcb->mpcb_wbcnt; k++) {
				mpcb->mpcb_spbuf[k] = mpcb->mpcb_spbuf[k+1];
				bcopy(
				    mpcb->mpcb_wbuf +
				    ((k+1) * wbuf_rwindow_size),
				    mpcb->mpcb_wbuf +
				    (k * wbuf_rwindow_size),
				    wbuf_rwindow_size);
			}
		}
		if (watched)
			watch_enable_addr(sp, rwindow_size, S_WRITE);
	} /* while there are windows in the wbuf */
	return (error);
}

static int
copy_return_window32(int dotwo)
{
	klwp_t *lwp = ttolwp(curthread);
	struct machpcb *mpcb = lwptompcb(lwp);
	struct rwindow32 rwindow32;
	caddr_t sp1;
	caddr_t sp2;

	(void) flush_user_windows_to_stack(NULL);
	if (mpcb->mpcb_rsp[0] == NULL) {
		/*
		 * Reduce r_sp to a 32 bit value before storing it in sp1.  This
		 * was originally done by casting down to uint32_t and back up
		 * to caddr_t, but that generated complaints under one compiler.
		 * The uintptr_t cast was added to address that, and the
		 * temporary 32 bit variable was introduced to avoid depending
		 * on all compilers to generate the desired assembly code for a
		 * triple cast in a single expression.
		 */
		caddr32_t sp1_32 = (uint32_t)lwptoregs(lwp)->r_sp;
		sp1 = (caddr_t)(uintptr_t)sp1_32;

		if ((copyin_nowatch(sp1, &rwindow32,
		    sizeof (struct rwindow32))) == 0)
			mpcb->mpcb_rsp[0] = sp1;
		rwindow_32ton(&rwindow32, &mpcb->mpcb_rwin[0]);
	}
	mpcb->mpcb_rsp[1] = NULL;
	if (dotwo && mpcb->mpcb_rsp[0] != NULL &&
	    (sp2 = (caddr_t)mpcb->mpcb_rwin[0].rw_fp) != NULL) {
		if ((copyin_nowatch(sp2, &rwindow32,
		    sizeof (struct rwindow32)) == 0))
			mpcb->mpcb_rsp[1] = sp2;
		rwindow_32ton(&rwindow32, &mpcb->mpcb_rwin[1]);
	}
	return (mpcb->mpcb_rsp[0] != NULL);
}

int
copy_return_window(int dotwo)
{
	proc_t *p = ttoproc(curthread);
	klwp_t *lwp;
	struct machpcb *mpcb;
	caddr_t sp1;
	caddr_t sp2;

	if (p->p_model == DATAMODEL_ILP32)
		return (copy_return_window32(dotwo));

	lwp = ttolwp(curthread);
	mpcb = lwptompcb(lwp);
	(void) flush_user_windows_to_stack(NULL);
	if (mpcb->mpcb_rsp[0] == NULL) {
		sp1 = (caddr_t)lwptoregs(lwp)->r_sp + STACK_BIAS;
		if ((copyin_nowatch(sp1, &mpcb->mpcb_rwin[0],
		    sizeof (struct rwindow)) == 0))
			mpcb->mpcb_rsp[0] = sp1 - STACK_BIAS;
	}
	mpcb->mpcb_rsp[1] = NULL;
	if (dotwo && mpcb->mpcb_rsp[0] != NULL &&
	    (sp2 = (caddr_t)mpcb->mpcb_rwin[0].rw_fp) != NULL) {
		sp2 += STACK_BIAS;
		if ((copyin_nowatch(sp2, &mpcb->mpcb_rwin[1],
		    sizeof (struct rwindow)) == 0))
			mpcb->mpcb_rsp[1] = sp2 - STACK_BIAS;
	}
	return (mpcb->mpcb_rsp[0] != NULL);
}

/*
 * Clear registers on exec(2).
 */
void
setregs(uarg_t *args)
{
	struct regs *rp;
	klwp_t *lwp = ttolwp(curthread);
	kfpu_t *fpp = lwptofpu(lwp);
	struct machpcb *mpcb = lwptompcb(lwp);
	proc_t *p = ttoproc(curthread);

	/*
	 * Initialize user registers.
	 */
	(void) save_syscall_args();	/* copy args from registers first */
	rp = lwptoregs(lwp);
	rp->r_g1 = rp->r_g2 = rp->r_g3 = rp->r_g4 = rp->r_g5 =
	    rp->r_g6 = rp->r_o0 = rp->r_o1 = rp->r_o2 =
	    rp->r_o3 = rp->r_o4 = rp->r_o5 = rp->r_o7 = 0;
	if (p->p_model == DATAMODEL_ILP32)
		rp->r_tstate = TSTATE_USER32 | weakest_mem_model;
	else
		rp->r_tstate = TSTATE_USER64 | weakest_mem_model;
	if (!fpu_exists)
		rp->r_tstate &= ~TSTATE_PEF;
	rp->r_g7 = args->thrptr;
	rp->r_pc = args->entry;
	rp->r_npc = args->entry + 4;
	rp->r_y = 0;
	curthread->t_post_sys = 1;
	lwp->lwp_eosys = JUSTRETURN;
	lwp->lwp_pcb.pcb_trap0addr = NULL;	/* no trap 0 handler */
	/*
	 * Clear the fixalignment flag
	 */
	p->p_fixalignment = 0;

	/*
	 * Throw out old user windows, init window buf.
	 */
	trash_user_windows();

	if (p->p_model == DATAMODEL_LP64 &&
	    mpcb->mpcb_wstate != WSTATE_USER64) {
		ASSERT(mpcb->mpcb_wbcnt == 0);
		kmem_cache_free(wbuf32_cache, mpcb->mpcb_wbuf);
		mpcb->mpcb_wbuf = kmem_cache_alloc(wbuf64_cache, KM_SLEEP);
		ASSERT(((uintptr_t)mpcb->mpcb_wbuf & 7) == 0);
		mpcb->mpcb_wstate = WSTATE_USER64;
	} else if (p->p_model == DATAMODEL_ILP32 &&
	    mpcb->mpcb_wstate != WSTATE_USER32) {
		ASSERT(mpcb->mpcb_wbcnt == 0);
		kmem_cache_free(wbuf64_cache, mpcb->mpcb_wbuf);
		mpcb->mpcb_wbuf = kmem_cache_alloc(wbuf32_cache, KM_SLEEP);
		mpcb->mpcb_wstate = WSTATE_USER32;
	}
	mpcb->mpcb_pa = va_to_pa(mpcb);
	mpcb->mpcb_wbuf_pa = va_to_pa(mpcb->mpcb_wbuf);

	/*
	 * Here we initialize minimal fpu state.
	 * The rest is done at the first floating
	 * point instruction that a process executes
	 * or by the lib_psr memcpy routines.
	 */
	if (fpu_exists) {
		extern void _fp_write_fprs(unsigned);
		_fp_write_fprs(0);
	}
	fpp->fpu_en = 0;
	fpp->fpu_fprs = 0;
}

void
lwp_swapin(kthread_t *tp)
{
	struct machpcb *mpcb = lwptompcb(ttolwp(tp));

	mpcb->mpcb_pa = va_to_pa(mpcb);
	mpcb->mpcb_wbuf_pa = va_to_pa(mpcb->mpcb_wbuf);
}

/*
 * Construct the execution environment for the user's signal
 * handler and arrange for control to be given to it on return
 * to userland.  The library code now calls setcontext() to
 * clean up after the signal handler, so sigret() is no longer
 * needed.
 */
int
sendsig(int sig, k_siginfo_t *sip, void (*hdlr)())
{
	/*
	 * 'volatile' is needed to ensure that values are
	 * correct on the error return from on_fault().
	 */
	volatile int minstacksz; /* min stack required to catch signal */
	int newstack = 0;	/* if true, switching to altstack */
	label_t ljb;
	caddr_t sp;
	struct regs *volatile rp;
	klwp_t *lwp = ttolwp(curthread);
	proc_t *volatile p = ttoproc(curthread);
	int fpq_size = 0;
	struct sigframe {
		struct frame frwin;
		ucontext_t uc;
	};
	siginfo_t *sip_addr;
	struct sigframe *volatile fp;
	ucontext_t *volatile tuc = NULL;
	char *volatile xregs = NULL;
	volatile size_t xregs_size = 0;
	gwindows_t *volatile gwp = NULL;
	volatile int gwin_size = 0;
	kfpu_t *fpp;
	struct machpcb *mpcb;
	volatile int watched = 0;
	volatile int watched2 = 0;
	caddr_t tos;

	/*
	 * Make sure the current last user window has been flushed to
	 * the stack save area before we change the sp.
	 * Restore register window if a debugger modified it.
	 */
	(void) flush_user_windows_to_stack(NULL);
	if (lwp->lwp_pcb.pcb_xregstat != XREGNONE)
		xregrestore(lwp, 0);

	mpcb = lwptompcb(lwp);
	rp = lwptoregs(lwp);

	/*
	 * Clear the watchpoint return stack pointers.
	 */
	mpcb->mpcb_rsp[0] = NULL;
	mpcb->mpcb_rsp[1] = NULL;

	minstacksz = sizeof (struct sigframe);

	/*
	 * We know that sizeof (siginfo_t) is stack-aligned:
	 * 128 bytes for ILP32, 256 bytes for LP64.
	 */
	if (sip != NULL)
		minstacksz += sizeof (siginfo_t);

	/*
	 * These two fields are pointed to by ABI structures and may
	 * be of arbitrary length. Size them now so we know how big
	 * the signal frame has to be.
	 */
	fpp = lwptofpu(lwp);
	fpp->fpu_fprs = _fp_read_fprs();
	if ((fpp->fpu_en) || (fpp->fpu_fprs & FPRS_FEF)) {
		fpq_size = fpp->fpu_q_entrysize * fpp->fpu_qcnt;
		minstacksz += SA(fpq_size);
	}

	mpcb = lwptompcb(lwp);
	if (mpcb->mpcb_wbcnt != 0) {
		gwin_size = (mpcb->mpcb_wbcnt * sizeof (struct rwindow)) +
		    (SPARC_MAXREGWINDOW * sizeof (caddr_t)) + sizeof (long);
		minstacksz += SA(gwin_size);
	}

	/*
	 * Extra registers, if support by this platform, may be of arbitrary
	 * length. Size them now so we know how big the signal frame has to be.
	 * For sparcv9 _LP64 user programs, use asrs instead of the xregs.
	 */
	minstacksz += SA(xregs_size);

	/*
	 * Figure out whether we will be handling this signal on
	 * an alternate stack specified by the user. Then allocate
	 * and validate the stack requirements for the signal handler
	 * context. on_fault will catch any faults.
	 */
	newstack = (sigismember(&PTOU(curproc)->u_sigonstack, sig) &&
	    !(lwp->lwp_sigaltstack.ss_flags & (SS_ONSTACK|SS_DISABLE)));

	tos = (caddr_t)rp->r_sp + STACK_BIAS;
	/*
	 * Force proper stack pointer alignment, even in the face of a
	 * misaligned stack pointer from user-level before the signal.
	 * Don't use the SA() macro because that rounds up, not down.
	 */
	tos = (caddr_t)((uintptr_t)tos & ~(STACK_ALIGN - 1ul));

	if (newstack != 0) {
		fp = (struct sigframe *)
		    (SA((uintptr_t)lwp->lwp_sigaltstack.ss_sp) +
		    SA((int)lwp->lwp_sigaltstack.ss_size) - STACK_ALIGN -
		    SA(minstacksz));
	} else {
		/*
		 * If we were unable to flush all register windows to
		 * the stack and we are not now on an alternate stack,
		 * just dump core with a SIGSEGV back in psig().
		 */
		if (sig == SIGSEGV &&
		    mpcb->mpcb_wbcnt != 0 &&
		    !(lwp->lwp_sigaltstack.ss_flags & SS_ONSTACK))
			return (0);
		fp = (struct sigframe *)(tos - SA(minstacksz));
		/*
		 * Could call grow here, but stack growth now handled below
		 * in code protected by on_fault().
		 */
	}
	sp = (caddr_t)fp + sizeof (struct sigframe);

	/*
	 * Make sure process hasn't trashed its stack.
	 */
	if ((caddr_t)fp >= p->p_usrstack ||
	    (caddr_t)fp + SA(minstacksz) >= p->p_usrstack) {
#ifdef DEBUG
		printf("sendsig: bad signal stack cmd=%s, pid=%d, sig=%d\n",
		    PTOU(p)->u_comm, p->p_pid, sig);
		printf("sigsp = 0x%p, action = 0x%p, upc = 0x%lx\n",
		    (void *)fp, (void *)hdlr, rp->r_pc);
		printf("fp above USRSTACK\n");
#endif
		return (0);
	}

	watched = watch_disable_addr((caddr_t)fp, SA(minstacksz), S_WRITE);
	if (on_fault(&ljb))
		goto badstack;

	tuc = kmem_alloc(sizeof (ucontext_t), KM_SLEEP);
	savecontext(tuc, &lwp->lwp_sigoldmask);

	/*
	 * save extra register state if it exists
	 */
	if (xregs_size != 0) {
		xregs_setptr(lwp, tuc, sp);
		xregs = kmem_alloc(xregs_size, KM_SLEEP);
		xregs_get(lwp, xregs);
		copyout_noerr(xregs, sp, xregs_size);
		kmem_free(xregs, xregs_size);
		xregs = NULL;
		sp += SA(xregs_size);
	}

	copyout_noerr(tuc, &fp->uc, sizeof (*tuc));
	kmem_free(tuc, sizeof (*tuc));
	tuc = NULL;

	if (sip != NULL) {
		zoneid_t zoneid;

		uzero(sp, sizeof (siginfo_t));
		if (SI_FROMUSER(sip) &&
		    (zoneid = p->p_zone->zone_id) != GLOBAL_ZONEID &&
		    zoneid != sip->si_zoneid) {
			k_siginfo_t sani_sip = *sip;
			sani_sip.si_pid = p->p_zone->zone_zsched->p_pid;
			sani_sip.si_uid = 0;
			sani_sip.si_ctid = -1;
			sani_sip.si_zoneid = zoneid;
			copyout_noerr(&sani_sip, sp, sizeof (sani_sip));
		} else {
			copyout_noerr(sip, sp, sizeof (*sip));
		}
		sip_addr = (siginfo_t *)sp;
		sp += sizeof (siginfo_t);

		if (sig == SIGPROF &&
		    curthread->t_rprof != NULL &&
		    curthread->t_rprof->rp_anystate) {
			/*
			 * We stand on our head to deal with
			 * the real time profiling signal.
			 * Fill in the stuff that doesn't fit
			 * in a normal k_siginfo structure.
			 */
			int i = sip->si_nsysarg;
			while (--i >= 0) {
				sulword_noerr(
				    (ulong_t *)&sip_addr->si_sysarg[i],
				    (ulong_t)lwp->lwp_arg[i]);
			}
			copyout_noerr(curthread->t_rprof->rp_state,
			    sip_addr->si_mstate,
			    sizeof (curthread->t_rprof->rp_state));
		}
	} else {
		sip_addr = (siginfo_t *)NULL;
	}

	/*
	 * When flush_user_windows_to_stack() can't save all the
	 * windows to the stack, it puts them in the lwp's pcb.
	 */
	if (gwin_size != 0) {
		gwp = kmem_alloc(gwin_size, KM_SLEEP);
		getgwins(lwp, gwp);
		sulword_noerr(&fp->uc.uc_mcontext.gwins, (ulong_t)sp);
		copyout_noerr(gwp, sp, gwin_size);
		kmem_free(gwp, gwin_size);
		gwp = NULL;
		sp += SA(gwin_size);
	} else
		sulword_noerr(&fp->uc.uc_mcontext.gwins, (ulong_t)NULL);

	if (fpq_size != 0) {
		struct _fq *fqp = (struct _fq *)sp;
		sulword_noerr(&fp->uc.uc_mcontext.fpregs.fpu_q, (ulong_t)fqp);
		copyout_noerr(mpcb->mpcb_fpu_q, fqp, fpq_size);

		/*
		 * forget the fp queue so that the signal handler can run
		 * without being harrassed--it will do a setcontext that will
		 * re-establish the queue if there still is one
		 *
		 * NOTE: fp_runq() relies on the qcnt field being zeroed here
		 *	to terminate its processing of the queue after signal
		 *	delivery.
		 */
		mpcb->mpcb_fpu->fpu_qcnt = 0;
		sp += SA(fpq_size);

		/* Also, syscall needs to know about this */
		mpcb->mpcb_flags |= FP_TRAPPED;

	} else {
		sulword_noerr(&fp->uc.uc_mcontext.fpregs.fpu_q, (ulong_t)NULL);
		suword8_noerr(&fp->uc.uc_mcontext.fpregs.fpu_qcnt, 0);
	}


	/*
	 * Since we flushed the user's windows and we are changing his
	 * stack pointer, the window that the user will return to will
	 * be restored from the save area in the frame we are setting up.
	 * We copy in save area for old stack pointer so that debuggers
	 * can do a proper stack backtrace from the signal handler.
	 */
	if (mpcb->mpcb_wbcnt == 0) {
		watched2 = watch_disable_addr(tos, sizeof (struct rwindow),
		    S_READ);
		ucopy(tos, &fp->frwin, sizeof (struct rwindow));
	}

	lwp->lwp_oldcontext = (uintptr_t)&fp->uc;

	if (newstack != 0) {
		lwp->lwp_sigaltstack.ss_flags |= SS_ONSTACK;

		if (lwp->lwp_ustack) {
			copyout_noerr(&lwp->lwp_sigaltstack,
			    (stack_t *)lwp->lwp_ustack, sizeof (stack_t));
		}
	}

	no_fault();
	mpcb->mpcb_wbcnt = 0;		/* let user go on */

	if (watched2)
		watch_enable_addr(tos, sizeof (struct rwindow), S_READ);
	if (watched)
		watch_enable_addr((caddr_t)fp, SA(minstacksz), S_WRITE);

	/*
	 * Set up user registers for execution of signal handler.
	 */
	rp->r_sp = (uintptr_t)fp - STACK_BIAS;
	rp->r_pc = (uintptr_t)hdlr;
	rp->r_npc = (uintptr_t)hdlr + 4;
	/* make sure %asi is ASI_PNF */
	rp->r_tstate &= ~((uint64_t)TSTATE_ASI_MASK << TSTATE_ASI_SHIFT);
	rp->r_tstate |= ((uint64_t)ASI_PNF << TSTATE_ASI_SHIFT);
	rp->r_o0 = sig;
	rp->r_o1 = (uintptr_t)sip_addr;
	rp->r_o2 = (uintptr_t)&fp->uc;
	/*
	 * Don't set lwp_eosys here.  sendsig() is called via psig() after
	 * lwp_eosys is handled, so setting it here would affect the next
	 * system call.
	 */
	return (1);

badstack:
	no_fault();
	if (watched2)
		watch_enable_addr(tos, sizeof (struct rwindow), S_READ);
	if (watched)
		watch_enable_addr((caddr_t)fp, SA(minstacksz), S_WRITE);
	if (tuc)
		kmem_free(tuc, sizeof (ucontext_t));
	if (xregs)
		kmem_free(xregs, xregs_size);
	if (gwp)
		kmem_free(gwp, gwin_size);
#ifdef DEBUG
	printf("sendsig: bad signal stack cmd=%s, pid=%d, sig=%d\n",
	    PTOU(p)->u_comm, p->p_pid, sig);
	printf("on fault, sigsp = %p, action = %p, upc = 0x%lx\n",
	    (void *)fp, (void *)hdlr, rp->r_pc);
#endif
	return (0);
}


#ifdef _SYSCALL32_IMPL

/*
 * Construct the execution environment for the user's signal
 * handler and arrange for control to be given to it on return
 * to userland.  The library code now calls setcontext() to
 * clean up after the signal handler, so sigret() is no longer
 * needed.
 */
int
sendsig32(int sig, k_siginfo_t *sip, void (*hdlr)())
{
	/*
	 * 'volatile' is needed to ensure that values are
	 * correct on the error return from on_fault().
	 */
	volatile int minstacksz; /* min stack required to catch signal */
	int newstack = 0;	/* if true, switching to altstack */
	label_t ljb;
	caddr_t sp;
	struct regs *volatile rp;
	klwp_t *lwp = ttolwp(curthread);
	proc_t *volatile p = ttoproc(curthread);
	struct fq32 fpu_q[MAXFPQ]; /* to hold floating queue */
	struct fq32 *dfq = NULL;
	size_t fpq_size = 0;
	struct sigframe32 {
		struct frame32 frwin;
		ucontext32_t uc;
	};
	struct sigframe32 *volatile fp;
	siginfo32_t *sip_addr;
	ucontext32_t *volatile tuc = NULL;
	char *volatile xregs = NULL;
	volatile int xregs_size = 0;
	gwindows32_t *volatile gwp = NULL;
	volatile size_t gwin_size = 0;
	kfpu_t *fpp;
	struct machpcb *mpcb;
	volatile int watched = 0;
	volatile int watched2 = 0;
	caddr_t tos;

	/*
	 * Make sure the current last user window has been flushed to
	 * the stack save area before we change the sp.
	 * Restore register window if a debugger modified it.
	 */
	(void) flush_user_windows_to_stack(NULL);
	if (lwp->lwp_pcb.pcb_xregstat != XREGNONE)
		xregrestore(lwp, 0);

	mpcb = lwptompcb(lwp);
	rp = lwptoregs(lwp);

	/*
	 * Clear the watchpoint return stack pointers.
	 */
	mpcb->mpcb_rsp[0] = NULL;
	mpcb->mpcb_rsp[1] = NULL;

	minstacksz = sizeof (struct sigframe32);

	if (sip != NULL)
		minstacksz += sizeof (siginfo32_t);

	/*
	 * These two fields are pointed to by ABI structures and may
	 * be of arbitrary length. Size them now so we know how big
	 * the signal frame has to be.
	 */
	fpp = lwptofpu(lwp);
	fpp->fpu_fprs = _fp_read_fprs();
	if ((fpp->fpu_en) || (fpp->fpu_fprs & FPRS_FEF)) {
		fpq_size = sizeof (struct fpq32) * fpp->fpu_qcnt;
		minstacksz += fpq_size;
		dfq = fpu_q;
	}

	mpcb = lwptompcb(lwp);
	if (mpcb->mpcb_wbcnt != 0) {
		gwin_size = (mpcb->mpcb_wbcnt * sizeof (struct rwindow32)) +
		    (SPARC_MAXREGWINDOW * sizeof (caddr32_t)) +
		    sizeof (int32_t);
		minstacksz += gwin_size;
	}

	/*
	 * Extra registers, if supported by this platform, may be of arbitrary
	 * length. Size them now so we know how big the signal frame has to be.
	 */
	xregs_size = xregs_getsize(p);
	minstacksz += SA32(xregs_size);

	/*
	 * Figure out whether we will be handling this signal on
	 * an alternate stack specified by the user. Then allocate
	 * and validate the stack requirements for the signal handler
	 * context. on_fault will catch any faults.
	 */
	newstack = (sigismember(&PTOU(curproc)->u_sigonstack, sig) &&
	    !(lwp->lwp_sigaltstack.ss_flags & (SS_ONSTACK|SS_DISABLE)));

	tos = (void *)(uintptr_t)(uint32_t)rp->r_sp;
	/*
	 * Force proper stack pointer alignment, even in the face of a
	 * misaligned stack pointer from user-level before the signal.
	 * Don't use the SA32() macro because that rounds up, not down.
	 */
	tos = (caddr_t)((uintptr_t)tos & ~(STACK_ALIGN32 - 1ul));

	if (newstack != 0) {
		fp = (struct sigframe32 *)
		    (SA32((uintptr_t)lwp->lwp_sigaltstack.ss_sp) +
		    SA32((int)lwp->lwp_sigaltstack.ss_size) -
		    STACK_ALIGN32 -
		    SA32(minstacksz));
	} else {
		/*
		 * If we were unable to flush all register windows to
		 * the stack and we are not now on an alternate stack,
		 * just dump core with a SIGSEGV back in psig().
		 */
		if (sig == SIGSEGV &&
		    mpcb->mpcb_wbcnt != 0 &&
		    !(lwp->lwp_sigaltstack.ss_flags & SS_ONSTACK))
			return (0);
		fp = (struct sigframe32 *)(tos - SA32(minstacksz));
		/*
		 * Could call grow here, but stack growth now handled below
		 * in code protected by on_fault().
		 */
	}
	sp = (caddr_t)fp + sizeof (struct sigframe32);

	/*
	 * Make sure process hasn't trashed its stack.
	 */
	if ((caddr_t)fp >= p->p_usrstack ||
	    (caddr_t)fp + SA32(minstacksz) >= p->p_usrstack) {
#ifdef DEBUG
		printf("sendsig32: bad signal stack cmd=%s, pid=%d, sig=%d\n",
		    PTOU(p)->u_comm, p->p_pid, sig);
		printf("sigsp = 0x%p, action = 0x%p, upc = 0x%lx\n",
		    (void *)fp, (void *)hdlr, rp->r_pc);
		printf("fp above USRSTACK32\n");
#endif
		return (0);
	}

	watched = watch_disable_addr((caddr_t)fp, SA32(minstacksz), S_WRITE);
	if (on_fault(&ljb))
		goto badstack;

	tuc = kmem_alloc(sizeof (ucontext32_t), KM_SLEEP);
	savecontext32(tuc, &lwp->lwp_sigoldmask, dfq);

	/*
	 * save extra register state if it exists
	 */
	if (xregs_size != 0) {
		xregs_setptr32(lwp, tuc, (caddr32_t)(uintptr_t)sp);
		xregs = kmem_alloc(xregs_size, KM_SLEEP);
		xregs_get(lwp, xregs);
		copyout_noerr(xregs, sp, xregs_size);
		kmem_free(xregs, xregs_size);
		xregs = NULL;
		sp += SA32(xregs_size);
	}

	copyout_noerr(tuc, &fp->uc, sizeof (*tuc));
	kmem_free(tuc, sizeof (*tuc));
	tuc = NULL;

	if (sip != NULL) {
		siginfo32_t si32;
		zoneid_t zoneid;

		siginfo_kto32(sip, &si32);
		if (SI_FROMUSER(sip) &&
		    (zoneid = p->p_zone->zone_id) != GLOBAL_ZONEID &&
		    zoneid != sip->si_zoneid) {
			si32.si_pid = p->p_zone->zone_zsched->p_pid;
			si32.si_uid = 0;
			si32.si_ctid = -1;
			si32.si_zoneid = zoneid;
		}
		uzero(sp, sizeof (siginfo32_t));
		copyout_noerr(&si32, sp, sizeof (siginfo32_t));
		sip_addr = (siginfo32_t *)sp;
		sp += sizeof (siginfo32_t);

		if (sig == SIGPROF &&
		    curthread->t_rprof != NULL &&
		    curthread->t_rprof->rp_anystate) {
			/*
			 * We stand on our head to deal with
			 * the real time profiling signal.
			 * Fill in the stuff that doesn't fit
			 * in a normal k_siginfo structure.
			 */
			int i = sip->si_nsysarg;
			while (--i >= 0) {
				suword32_noerr(&sip_addr->si_sysarg[i],
				    (uint32_t)lwp->lwp_arg[i]);
			}
			copyout_noerr(curthread->t_rprof->rp_state,
			    sip_addr->si_mstate,
			    sizeof (curthread->t_rprof->rp_state));
		}
	} else {
		sip_addr = NULL;
	}

	/*
	 * When flush_user_windows_to_stack() can't save all the
	 * windows to the stack, it puts them in the lwp's pcb.
	 */
	if (gwin_size != 0) {
		gwp = kmem_alloc(gwin_size, KM_SLEEP);
		getgwins32(lwp, gwp);
		suword32_noerr(&fp->uc.uc_mcontext.gwins,
		    (uint32_t)(uintptr_t)sp);
		copyout_noerr(gwp, sp, gwin_size);
		kmem_free(gwp, gwin_size);
		gwp = NULL;
		sp += gwin_size;
	} else {
		suword32_noerr(&fp->uc.uc_mcontext.gwins, (uint32_t)NULL);
	}

	if (fpq_size != 0) {
		/*
		 * Update the (already copied out) fpu32.fpu_q pointer
		 * from NULL to the 32-bit address on the user's stack
		 * where we then copyout the fq32 to.
		 */
		struct fq32 *fqp = (struct fq32 *)sp;
		suword32_noerr(&fp->uc.uc_mcontext.fpregs.fpu_q,
		    (uint32_t)(uintptr_t)fqp);
		copyout_noerr(dfq, fqp, fpq_size);

		/*
		 * forget the fp queue so that the signal handler can run
		 * without being harrassed--it will do a setcontext that will
		 * re-establish the queue if there still is one
		 *
		 * NOTE: fp_runq() relies on the qcnt field being zeroed here
		 *	to terminate its processing of the queue after signal
		 *	delivery.
		 */
		mpcb->mpcb_fpu->fpu_qcnt = 0;
		sp += fpq_size;

		/* Also, syscall needs to know about this */
		mpcb->mpcb_flags |= FP_TRAPPED;

	} else {
		suword32_noerr(&fp->uc.uc_mcontext.fpregs.fpu_q,
		    (uint32_t)NULL);
		suword8_noerr(&fp->uc.uc_mcontext.fpregs.fpu_qcnt, 0);
	}


	/*
	 * Since we flushed the user's windows and we are changing his
	 * stack pointer, the window that the user will return to will
	 * be restored from the save area in the frame we are setting up.
	 * We copy in save area for old stack pointer so that debuggers
	 * can do a proper stack backtrace from the signal handler.
	 */
	if (mpcb->mpcb_wbcnt == 0) {
		watched2 = watch_disable_addr(tos, sizeof (struct rwindow32),
		    S_READ);
		ucopy(tos, &fp->frwin, sizeof (struct rwindow32));
	}

	lwp->lwp_oldcontext = (uintptr_t)&fp->uc;

	if (newstack != 0) {
		lwp->lwp_sigaltstack.ss_flags |= SS_ONSTACK;
		if (lwp->lwp_ustack) {
			stack32_t stk32;

			stk32.ss_sp =
			    (caddr32_t)(uintptr_t)lwp->lwp_sigaltstack.ss_sp;
			stk32.ss_size = (size32_t)lwp->lwp_sigaltstack.ss_size;
			stk32.ss_flags = (int32_t)lwp->lwp_sigaltstack.ss_flags;

			copyout_noerr(&stk32, (stack32_t *)lwp->lwp_ustack,
			    sizeof (stack32_t));
		}
	}

	no_fault();
	mpcb->mpcb_wbcnt = 0;		/* let user go on */

	if (watched2)
		watch_enable_addr(tos, sizeof (struct rwindow32), S_READ);
	if (watched)
		watch_enable_addr((caddr_t)fp, SA32(minstacksz), S_WRITE);

	/*
	 * Set up user registers for execution of signal handler.
	 */
	rp->r_sp = (uintptr_t)fp;
	rp->r_pc = (uintptr_t)hdlr;
	rp->r_npc = (uintptr_t)hdlr + 4;
	/* make sure %asi is ASI_PNF */
	rp->r_tstate &= ~((uint64_t)TSTATE_ASI_MASK << TSTATE_ASI_SHIFT);
	rp->r_tstate |= ((uint64_t)ASI_PNF << TSTATE_ASI_SHIFT);
	rp->r_o0 = sig;
	rp->r_o1 = (uintptr_t)sip_addr;
	rp->r_o2 = (uintptr_t)&fp->uc;
	/*
	 * Don't set lwp_eosys here.  sendsig() is called via psig() after
	 * lwp_eosys is handled, so setting it here would affect the next
	 * system call.
	 */
	return (1);

badstack:
	no_fault();
	if (watched2)
		watch_enable_addr(tos, sizeof (struct rwindow32), S_READ);
	if (watched)
		watch_enable_addr((caddr_t)fp, SA32(minstacksz), S_WRITE);
	if (tuc)
		kmem_free(tuc, sizeof (*tuc));
	if (xregs)
		kmem_free(xregs, xregs_size);
	if (gwp)
		kmem_free(gwp, gwin_size);
#ifdef DEBUG
	printf("sendsig32: bad signal stack cmd=%s, pid=%d, sig=%d\n",
	    PTOU(p)->u_comm, p->p_pid, sig);
	printf("on fault, sigsp = 0x%p, action = 0x%p, upc = 0x%lx\n",
	    (void *)fp, (void *)hdlr, rp->r_pc);
#endif
	return (0);
}

#endif /* _SYSCALL32_IMPL */


/*
 * Load user registers into lwp.  Called only from syslwp_create().
 * thrptr ignored for sparc.
 */
/* ARGSUSED2 */
void
lwp_load(klwp_t *lwp, gregset_t grp, uintptr_t thrptr)
{
	setgregs(lwp, grp);
	if (lwptoproc(lwp)->p_model == DATAMODEL_ILP32)
		lwptoregs(lwp)->r_tstate = TSTATE_USER32 | TSTATE_MM_TSO;
	else
		lwptoregs(lwp)->r_tstate = TSTATE_USER64 | TSTATE_MM_TSO;

	if (!fpu_exists)
		lwptoregs(lwp)->r_tstate &= ~TSTATE_PEF;
	lwp->lwp_eosys = JUSTRETURN;
	lwptot(lwp)->t_post_sys = 1;
}

/*
 * set syscall()'s return values for a lwp.
 */
void
lwp_setrval(klwp_t *lwp, int v1, int v2)
{
	struct regs *rp = lwptoregs(lwp);

	rp->r_tstate &= ~TSTATE_IC;
	rp->r_o0 = v1;
	rp->r_o1 = v2;
}

/*
 * set stack pointer for a lwp
 */
void
lwp_setsp(klwp_t *lwp, caddr_t sp)
{
	struct regs *rp = lwptoregs(lwp);
	rp->r_sp = (uintptr_t)sp;
}

/*
 * Take any PCB specific actions that are required or flagged in the PCB.
 */
extern void trap_async_hwerr(void);
#pragma	weak trap_async_hwerr

void
lwp_pcb_exit(void)
{
	klwp_t *lwp = ttolwp(curthread);

	if (lwp->lwp_pcb.pcb_flags & ASYNC_HWERR) {
		lwp->lwp_pcb.pcb_flags &= ~ASYNC_HWERR;
		trap_async_hwerr();
	}
}

/*
 * Invalidate the saved user register windows in the pcb struct
 * for the current thread. They will no longer be preserved.
 */
void
lwp_clear_uwin(void)
{
	struct machpcb *m = lwptompcb(ttolwp(curthread));

	/*
	 * This has the effect of invalidating all (any) of the
	 * user level windows that are currently sitting in the
	 * kernel buffer.
	 */
	m->mpcb_wbcnt = 0;
}

/*
 *  Set memory model to Total Store Order (TSO).
 */
static void
mmodel_set_tso(void)
{
	struct regs *rp = lwptoregs(ttolwp(curthread));

	/*
	 * The thread is doing something which requires TSO semantics
	 * (creating a 2nd thread, or mapping writable shared memory).
	 * It's no longer safe to run in WC mode.
	 */
	rp->r_tstate &= ~TSTATE_MM;
	/* LINTED E_EXPR_NULL_EFFECT */
	rp->r_tstate |= TSTATE_MM_TSO;
}

/*
 * When this routine is invoked, the process is just about to add a new lwp;
 * making it multi threaded.
 *
 * If the program requires default stronger/legacy memory model semantics,
 * this is an indication that the processor memory model
 * should be altered to provide those semantics.
 */
void
lwp_mmodel_newlwp(void)
{
	/*
	 * New thread has been created and it's no longer safe
	 * to run in WC mode, so revert back to TSO.
	 */
	mmodel_set_tso();
}

/*
 * This routine is invoked immediately after the lwp has added a mapping
 * to shared memory to its address space. The mapping starts at address
 * 'addr' and extends for 'size' bytes.
 *
 * Unless we can (somehow) guarantee that all the processes we're sharing
 * the underlying mapped object with, are using the same memory model that
 * this process is using, this call should change the memory model
 * configuration of the processor to be the most pessimistic available.
 */
/* ARGSUSED */
void
lwp_mmodel_shared_as(caddr_t addr, size_t sz)
{
	/*
	 * lwp has mapped shared memory and is no longer safe
	 * to run in WC mode, so revert back to TSO.
	 * For now, any shared memory access is enough to get back to TSO
	 * and hence not checking on 'addr' & 'sz'.
	 */
	mmodel_set_tso();
}

static uint_t
mkpsr(uint64_t tstate, uint_t fprs)
{
	uint_t psr, icc;

	psr = tstate & TSTATE_CWP_MASK;
	if (tstate & TSTATE_PRIV)
		psr |= PSR_PS;
	if (fprs & FPRS_FEF)
		psr |= PSR_EF;
	icc = (uint_t)(tstate >> PSR_TSTATE_CC_SHIFT) & PSR_ICC;
	psr |= icc;
	psr |= V9_PSR_IMPLVER;
	return (psr);
}

void
sync_icache(caddr_t va, uint_t len)
{
	caddr_t end;

	end = va + len;
	va = (caddr_t)((uintptr_t)va & -8l);	/* sparc needs 8-byte align */
	while (va < end) {
		doflush(va);
		va += 8;
	}
}

#ifdef _SYSCALL32_IMPL

/*
 * Copy the floating point queue if and only if there is a queue and a place
 * to copy it to. Let xregs take care of the other fp regs, for v8plus.
 * The issue is that while we are handling the fq32 in sendsig, we
 * still need a 64-bit pointer to it, and the caddr32_t in fpregset32_t
 * will not suffice, so we have the third parameter to this function.
 */
void
fpuregset_nto32(const fpregset_t *src, fpregset32_t *dest, struct fq32 *dfq)
{
	int i;

	bzero(dest, sizeof (*dest));
	for (i = 0; i < 32; i++)
		dest->fpu_fr.fpu_regs[i] = src->fpu_fr.fpu_regs[i];
	dest->fpu_q = NULL;
	dest->fpu_fsr = (uint32_t)src->fpu_fsr;
	dest->fpu_qcnt = src->fpu_qcnt;
	dest->fpu_q_entrysize = sizeof (struct fpq32);
	dest->fpu_en = src->fpu_en;

	if ((src->fpu_qcnt) && (dfq != NULL)) {
		struct _fq *sfq = src->fpu_q;
		for (i = 0; i < src->fpu_qcnt; i++, dfq++, sfq++) {
			dfq->FQu.fpq.fpq_addr =
			    (caddr32_t)(uintptr_t)sfq->FQu.fpq.fpq_addr;
			dfq->FQu.fpq.fpq_instr = sfq->FQu.fpq.fpq_instr;
		}
	}
}

/*
 * Copy the floating point queue if and only if there is a queue and a place
 * to copy it to. Let xregs take care of the other fp regs, for v8plus.
 * The *dfq is required to escape the bzero in both this function and in
 * ucontext_32ton. The *sfq is required because once the fq32 is copied
 * into the kernel, in setcontext, then we need a 64-bit pointer to it.
 */
static void
fpuregset_32ton(const fpregset32_t *src, fpregset_t *dest,
    const struct fq32 *sfq, struct _fq *dfq)
{
	int i;

	bzero(dest, sizeof (*dest));
	for (i = 0; i < 32; i++)
		dest->fpu_fr.fpu_regs[i] = src->fpu_fr.fpu_regs[i];
	dest->fpu_q = dfq;
	dest->fpu_fsr = (uint64_t)src->fpu_fsr;
	if ((dest->fpu_qcnt = src->fpu_qcnt) > 0)
		dest->fpu_q_entrysize = sizeof (struct _fpq);
	else
		dest->fpu_q_entrysize = 0;
	dest->fpu_en = src->fpu_en;

	if ((src->fpu_qcnt) && (sfq) && (dfq)) {
		for (i = 0; i < src->fpu_qcnt; i++, dfq++, sfq++) {
			dfq->FQu.fpq.fpq_addr =
			    (unsigned int *)(uintptr_t)sfq->FQu.fpq.fpq_addr;
			dfq->FQu.fpq.fpq_instr = sfq->FQu.fpq.fpq_instr;
		}
	}
}

void
ucontext_32ton(const ucontext32_t *src, ucontext_t *dest,
    const struct fq32 *sfq, struct _fq *dfq)
{
	int i;

	bzero(dest, sizeof (*dest));

	dest->uc_flags = src->uc_flags;
	dest->uc_link = (ucontext_t *)(uintptr_t)src->uc_link;

	for (i = 0; i < 4; i++) {
		dest->uc_sigmask.__sigbits[i] = src->uc_sigmask.__sigbits[i];
	}

	dest->uc_stack.ss_sp = (void *)(uintptr_t)src->uc_stack.ss_sp;
	dest->uc_stack.ss_size = (size_t)src->uc_stack.ss_size;
	dest->uc_stack.ss_flags = src->uc_stack.ss_flags;

	/* REG_CCR is 0, skip over it and handle it after this loop */
	for (i = 1; i < _NGREG32; i++)
		dest->uc_mcontext.gregs[i] =
		    (greg_t)(uint32_t)src->uc_mcontext.gregs[i];
	dest->uc_mcontext.gregs[REG_CCR] =
	    (src->uc_mcontext.gregs[REG_PSR] & PSR_ICC) >> PSR_ICC_SHIFT;
	dest->uc_mcontext.gregs[REG_ASI] = ASI_PNF;
	/*
	 * A valid fpregs is only copied in if (uc.uc_flags & UC_FPU),
	 * otherwise there is no guarantee that anything in fpregs is valid.
	 */
	if (src->uc_flags & UC_FPU) {
		dest->uc_mcontext.gregs[REG_FPRS] =
		    ((src->uc_mcontext.fpregs.fpu_en) ?
		    (FPRS_DU|FPRS_DL|FPRS_FEF) : 0);
	} else {
		dest->uc_mcontext.gregs[REG_FPRS] = 0;
	}
	dest->uc_mcontext.gwins =
	    (gwindows_t *)(uintptr_t)src->uc_mcontext.gwins;
	if (src->uc_flags & UC_FPU) {
		fpuregset_32ton(&src->uc_mcontext.fpregs,
		    &dest->uc_mcontext.fpregs, sfq, dfq);
	}
}

void
rwindow_nto32(struct rwindow *src, struct rwindow32 *dest)
{
	greg_t *s = (greg_t *)src;
	greg32_t *d = (greg32_t *)dest;
	int i;

	for (i = 0; i < 16; i++)
		*d++ = (greg32_t)*s++;
}

void
rwindow_32ton(struct rwindow32 *src, struct rwindow *dest)
{
	greg32_t *s = (greg32_t *)src;
	greg_t *d = (greg_t *)dest;
	int i;

	for (i = 0; i < 16; i++)
		*d++ = (uint32_t)*s++;
}

#endif /* _SYSCALL32_IMPL */

/*
 * The panic code invokes panic_saveregs() to record the contents of a
 * regs structure into the specified panic_data structure for debuggers.
 */
void
panic_saveregs(panic_data_t *pdp, struct regs *rp)
{
	panic_nv_t *pnv = PANICNVGET(pdp);

	PANICNVADD(pnv, "tstate", rp->r_tstate);
	PANICNVADD(pnv, "g1", rp->r_g1);
	PANICNVADD(pnv, "g2", rp->r_g2);
	PANICNVADD(pnv, "g3", rp->r_g3);
	PANICNVADD(pnv, "g4", rp->r_g4);
	PANICNVADD(pnv, "g5", rp->r_g5);
	PANICNVADD(pnv, "g6", rp->r_g6);
	PANICNVADD(pnv, "g7", rp->r_g7);
	PANICNVADD(pnv, "o0", rp->r_o0);
	PANICNVADD(pnv, "o1", rp->r_o1);
	PANICNVADD(pnv, "o2", rp->r_o2);
	PANICNVADD(pnv, "o3", rp->r_o3);
	PANICNVADD(pnv, "o4", rp->r_o4);
	PANICNVADD(pnv, "o5", rp->r_o5);
	PANICNVADD(pnv, "o6", rp->r_o6);
	PANICNVADD(pnv, "o7", rp->r_o7);
	PANICNVADD(pnv, "pc", (ulong_t)rp->r_pc);
	PANICNVADD(pnv, "npc", (ulong_t)rp->r_npc);
	PANICNVADD(pnv, "y", (uint32_t)rp->r_y);

	PANICNVSET(pdp, pnv);
}
