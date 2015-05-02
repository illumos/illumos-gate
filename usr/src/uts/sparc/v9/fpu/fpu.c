/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/signal.h>
#include <sys/trap.h>
#include <sys/machtrap.h>
#include <sys/fault.h>
#include <sys/systm.h>
#include <sys/user.h>
#include <sys/file.h>
#include <sys/proc.h>
#include <sys/core.h>
#include <sys/pcb.h>
#include <sys/cpuvar.h>
#include <sys/thread.h>
#include <sys/disp.h>
#include <sys/stack.h>
#include <sys/cmn_err.h>
#include <sys/privregs.h>
#include <sys/debug.h>

#include <sys/fpu/fpu_simulator.h>
#include <sys/fpu/globals.h>
#include <sys/fpu/fpusystm.h>

int fpdispr = 0;

/*
 * For use by procfs to save the floating point context of the thread.
 * Note the if (ttolwp(lwp) == curthread) in prstop, which calls
 * this function, ensures that it is safe to read the fprs here.
 */
void
fp_prsave(kfpu_t *fp)
{
	if ((fp->fpu_en) || (fp->fpu_fprs & FPRS_FEF))  {
		kpreempt_disable();
		if (fpu_exists) {
			fp->fpu_fprs = _fp_read_fprs();
			if ((fp->fpu_fprs & FPRS_FEF) != FPRS_FEF) {
				uint32_t fprs = (FPRS_FEF|FPRS_DU|FPRS_DL);

				_fp_write_fprs(fprs);
				fp->fpu_fprs = fprs;
#ifdef DEBUG
				if (fpdispr)
					cmn_err(CE_NOTE,
					    "fp_prsave with fp disabled!");
#endif
			}
			fp_fksave(fp);
		}
		kpreempt_enable();
	}
}

/*
 * Copy the floating point context of the forked thread.
 */
void
fp_fork(klwp_t *lwp, klwp_t *clwp)
{
	kfpu_t *cfp, *pfp;
	int i;

	cfp = lwptofpu(clwp);
	pfp = lwptofpu(lwp);

	/*
	 * copy the parents fpq
	 */
	cfp->fpu_qcnt = pfp->fpu_qcnt;
	for (i = 0; i < pfp->fpu_qcnt; i++)
		cfp->fpu_q[i] = pfp->fpu_q[i];

	/*
	 * save the context of the parent into the childs fpu structure
	 */
	cfp->fpu_fprs = pfp->fpu_fprs;
	if (ttolwp(curthread) == lwp && fpu_exists) {
		fp_fksave(cfp);
	} else {
		for (i = 0; i < 32; i++)
			cfp->fpu_fr.fpu_regs[i] = pfp->fpu_fr.fpu_regs[i];
		for (i = 16; i < 32; i++)
			cfp->fpu_fr.fpu_dregs[i] = pfp->fpu_fr.fpu_dregs[i];
	}
	cfp->fpu_en = 1;
}

/*
 * Free any state associated with floating point context.
 * Fp_free can be called in two cases:
 * 1) from reaper -> thread_free -> lwp_freeregs -> fp_free
 *	fp context belongs to a thread on deathrow
 *	nothing to do,  thread will never be resumed
 *	thread calling ctxfree is reaper
 *
 * 2) from exec -> lwp_freeregs -> fp_free
 *	fp context belongs to the current thread
 *	must disable fpu, thread calling ctxfree is curthread
 */
/*ARGSUSED1*/
void
fp_free(kfpu_t *fp, int isexec)
{
	int s;
	uint32_t fprs = 0;

	if (curthread->t_lwp != NULL && lwptofpu(curthread->t_lwp) == fp) {
		fp->fpu_en = 0;
		fp->fpu_fprs = fprs;
		s = splhigh();
		_fp_write_fprs(fprs);
		splx(s);
	}
}


#ifdef SF_ERRATA_30 /* call causes fp-disabled */
extern int spitfire_call_bug;
int ill_fpcalls;
#endif

void
fp_enable(void)
{
	klwp_id_t lwp;
	kfpu_t *fp;

	lwp = ttolwp(curthread);
	ASSERT(lwp != NULL);
	fp = lwptofpu(lwp);

	if (fpu_exists) {
		if (fp->fpu_en) {
#ifdef DEBUG
			if (fpdispr)
				cmn_err(CE_NOTE,
				    "fpu disabled, but already enabled\n");
#endif
			if ((fp->fpu_fprs & FPRS_FEF) != FPRS_FEF) {
				fp->fpu_fprs = FPRS_FEF;
#ifdef DEBUG
				if (fpdispr)
					cmn_err(CE_NOTE,
					"fpu disabled, saved fprs disabled\n");
#endif
			}
			_fp_write_fprs(FPRS_FEF);
			fp_restore(fp);
		} else {
			fp->fpu_en = 1;
			fp->fpu_fsr = 0;
			fp->fpu_fprs = FPRS_FEF;
			_fp_write_fprs(FPRS_FEF);
			fp_clearregs(fp);
		}
	} else {
		int i;

		if (!fp->fpu_en) {
			fp->fpu_en = 1;
			fp->fpu_fsr = 0;
			for (i = 0; i < 32; i++)
				fp->fpu_fr.fpu_regs[i] = (uint_t)-1; /* NaN */
			for (i = 16; i < 32; i++)		/* NaN */
				fp->fpu_fr.fpu_dregs[i] = (uint64_t)-1;
		}
	}
}

/*
 * fp_disabled normally occurs when the first floating point in a non-threaded
 * program causes an fp_disabled trap. For threaded programs, the ILP32 threads
 * library calls the .setpsr fasttrap, which has been modified to also set the
 * appropriate bits in fpu_en and fpu_fprs, as well as to enable the %fprs,
 * as before. The LP64 threads library will write to the %fprs directly,
 * so fpu_en will never get updated for LP64 threaded programs,
 * although fpu_fprs will, via resume.
 */
void
fp_disabled(struct regs *rp)
{
	klwp_id_t lwp;
	kfpu_t *fp;
	int ftt;

#ifdef SF_ERRATA_30 /* call causes fp-disabled */
	/*
	 * This code is here because sometimes the call instruction
	 * generates an fp_disabled trap when the call offset is large.
	 */
	if (spitfire_call_bug) {
		uint_t instr = 0;
		extern void trap(struct regs *rp, caddr_t addr, uint32_t type,
		    uint32_t mmu_fsr);

		if (USERMODE(rp->r_tstate)) {
			(void) fuword32((void *)rp->r_pc, &instr);
		} else {
			instr = *(uint_t *)(rp->r_pc);
		}
		if ((instr & 0xc0000000) == 0x40000000) {
			ill_fpcalls++;
			trap(rp, NULL, T_UNIMP_INSTR, 0);
			return;
		}
	}
#endif /* SF_ERRATA_30 - call causes fp-disabled */

#ifdef CHEETAH_ERRATUM_109 /* interrupts not taken during fpops */
	/*
	 * UltraSPARC III will report spurious fp-disabled exceptions when
	 * the pipe is full of fpops and an interrupt is triggered.  By the
	 * time we get here the interrupt has been taken and we just need
	 * to return to where we came from and try again.
	 */
	if (fpu_exists && _fp_read_fprs() & FPRS_FEF)
		return;
#endif /* CHEETAH_ERRATUM_109 */

	lwp = ttolwp(curthread);
	ASSERT(lwp != NULL);
	fp = lwptofpu(lwp);
	if (fpu_exists) {
		kpreempt_disable();
		if (fp->fpu_en) {
#ifdef DEBUG
			if (fpdispr)
				cmn_err(CE_NOTE,
				    "fpu disabled, but already enabled\n");
#endif
			if ((fp->fpu_fprs & FPRS_FEF) != FPRS_FEF) {
				fp->fpu_fprs = FPRS_FEF;
#ifdef DEBUG
				if (fpdispr)
					cmn_err(CE_NOTE,
					"fpu disabled, saved fprs disabled\n");
#endif
			}
			_fp_write_fprs(FPRS_FEF);
			fp_restore(fp);
		} else {
			fp->fpu_en = 1;
			fp->fpu_fsr = 0;
			fp->fpu_fprs = FPRS_FEF;
			_fp_write_fprs(FPRS_FEF);
			fp_clearregs(fp);
		}
		kpreempt_enable();
	} else {
		fp_simd_type fpsd;
		int i;

		(void) flush_user_windows_to_stack(NULL);
		if (!fp->fpu_en) {
			fp->fpu_en = 1;
			fp->fpu_fsr = 0;
			for (i = 0; i < 32; i++)
				fp->fpu_fr.fpu_regs[i] = (uint_t)-1; /* NaN */
			for (i = 16; i < 32; i++)		/* NaN */
				fp->fpu_fr.fpu_dregs[i] = (uint64_t)-1;
		}
		if (ftt = fp_emulator(&fpsd, (fp_inst_type *)rp->r_pc,
		    rp, (ulong_t *)rp->r_sp, fp)) {
			fp->fpu_q_entrysize = sizeof (struct _fpq);
			fp_traps(&fpsd, ftt, rp);
		}
	}
}

/*
 * Process the floating point queue in lwp->lwp_pcb.
 *
 * Each entry in the floating point queue is processed in turn.
 * If processing an entry results in an exception fp_traps() is called to
 * handle the exception - this usually results in the generation of a signal
 * to be delivered to the user. There are 2 possible outcomes to this (note
 * that hardware generated signals cannot be held!):
 *
 *   1. If the signal is being ignored we continue to process the rest
 *	of the entries in the queue.
 *
 *   2. If arrangements have been made for return to a user signal handler,
 *	sendsig() will have copied the floating point queue onto the user's
 *	signal stack and zero'ed the queue count in the u_pcb. Note that
 *	this has the side effect of terminating fp_runq's processing loop.
 *	We will re-run the floating point queue on return from the user
 *	signal handler if necessary as part of normal setcontext processing.
 */
void
fp_runq(struct regs *rp)
{
	kfpu_t *fp = lwptofpu(curthread->t_lwp);
	struct _fq *fqp = fp->fpu_q;
	fp_simd_type fpsd;
	uint64_t gsr = get_gsr(fp);

	/*
	 * don't preempt while manipulating the queue
	 */
	kpreempt_disable();

	while (fp->fpu_qcnt) {
		int fptrap;

		fptrap = fpu_simulator((fp_simd_type *)&fpsd,
		    (fp_inst_type *)fqp->FQu.fpq.fpq_addr,
		    (fsr_type *)&fp->fpu_fsr, gsr,
		    fqp->FQu.fpq.fpq_instr);
		if (fptrap) {
			/*
			 * Instruction could not be simulated so we will
			 * attempt to deliver a signal.
			 * We may be called again upon signal exit (setcontext)
			 * and can continue to process the queue then.
			 */
			if (fqp != fp->fpu_q) {
				int i;
				struct _fq *fqdp;

				/*
				 * We need to normalize the floating queue so
				 * the excepting instruction is at the head,
				 * so that the queue may be copied onto the
				 * user signal stack by sendsig().
				 */
				fqdp = fp->fpu_q;
				for (i = fp->fpu_qcnt; i; i--) {
					*fqdp++ = *fqp++;
				}
				fqp = fp->fpu_q;
			}
			fp->fpu_q_entrysize = sizeof (struct _fpq);

			/*
			 * fpu_simulator uses the fp registers directly but it
			 * uses the software copy of the fsr. We need to write
			 * that back to fpu so that fpu's state is current for
			 * ucontext.
			 */
			if (fpu_exists)
				_fp_write_pfsr(&fp->fpu_fsr);

			/* post signal */
			fp_traps(&fpsd, fptrap, rp);

			/*
			 * Break from loop to allow signal to be sent.
			 * If there are other instructions in the fp queue
			 * they will be processed when/if the user retuns
			 * from the signal handler with a non-empty queue.
			 */
			break;
		}
		fp->fpu_qcnt--;
		fqp++;
	}

	/*
	 * fpu_simulator uses the fp registers directly, so we have
	 * to update the pcb copies to keep current, but it uses the
	 * software copy of the fsr, so we write that back to fpu
	 */
	if (fpu_exists) {
		int i;

		for (i = 0; i < 32; i++)
			_fp_read_pfreg(&fp->fpu_fr.fpu_regs[i], i);
		for (i = 16; i < 32; i++)
			_fp_read_pdreg(&fp->fpu_fr.fpu_dregs[i], i);
		_fp_write_pfsr(&fp->fpu_fsr);
	}

	kpreempt_enable();
}

/*
 * Get the precise trapped V9 floating point instruction.
 * Fake up a queue to process. If getting the instruction results
 * in an exception fp_traps() is called to handle the exception - this
 * usually results in the generation of a signal to be delivered to the user.
 */

void
fp_precise(struct regs *rp)
{
	fp_simd_type	fpsd;
	int		inst_ftt;

	union {
		uint_t		i;
		fp_inst_type	inst;
	} kluge;

	klwp_t *lwp = ttolwp(curthread);
	kfpu_t *fp = lwptofpu(lwp);
	uint64_t gsr;
	int mstate;
	if (fpu_exists)
		save_gsr(fp);
	gsr = get_gsr(fp);

	/*
	 * Get the instruction to be emulated from the pc saved by the trap.
	 * Note that the kernel is NOT prepared to handle a kernel fp
	 * exception if it can't pass successfully through the fp simulator.
	 *
	 * If the trap occurred in user mode, set lwp_state to LWP_SYS for the
	 * purposes of clock accounting and switch to the LMS_TRAP microstate.
	 */
	if (USERMODE(rp->r_tstate)) {
		inst_ftt = _fp_read_inst((uint32_t *)rp->r_pc, &kluge.i, &fpsd);
		mstate = new_mstate(curthread, LMS_TRAP);
		lwp->lwp_state = LWP_SYS;
	} else {
		kluge.i = *(uint_t *)rp->r_pc;
		inst_ftt = ftt_none;
	}

	if (inst_ftt != ftt_none) {
		/*
		 * Save the bad address and post the signal.
		 * It can only be an ftt_alignment or ftt_fault trap.
		 * XXX - How can this work w/mainsail and do_unaligned?
		 */
		fpsd.fp_trapaddr = (caddr_t)rp->r_pc;
		fp_traps(&fpsd, inst_ftt, rp);
	} else {
		/*
		 * Conjure up a floating point queue and advance the pc/npc
		 * to fake a deferred fp trap. We now run the fp simulator
		 * in fp_precise, while allowing setfpregs to call fp_runq,
		 * because this allows us to do the ugly machinations to
		 * inc/dec the pc depending on the trap type, as per
		 * bugid 1210159. fp_runq is still going to have the
		 * generic "how do I connect the "fp queue to the pc/npc"
		 * problem alluded to in bugid 1192883, which is only a
		 * problem for a restorecontext of a v8 fp queue on a
		 * v9 system, which seems like the .000000001% case (on v9)!
		 */
		struct _fpq *pfpq = &fp->fpu_q->FQu.fpq;
		fp_simd_type	fpsd;
		int fptrap;

		pfpq->fpq_addr = (uint_t *)rp->r_pc;
		pfpq->fpq_instr = kluge.i;
		fp->fpu_qcnt = 1;
		fp->fpu_q_entrysize = sizeof (struct _fpq);

		kpreempt_disable();
		(void) flush_user_windows_to_stack(NULL);
		fptrap = fpu_vis_sim((fp_simd_type *)&fpsd,
		    (fp_inst_type *)pfpq->fpq_addr, rp,
		    (fsr_type *)&fp->fpu_fsr, gsr, kluge.i);

		/* update the hardware fp fsr state for sake of ucontext */
		if (fpu_exists)
			_fp_write_pfsr(&fp->fpu_fsr);

		if (fptrap) {
			/* back up the pc if the signal needs to be precise */
			if (fptrap != ftt_ieee) {
				fp->fpu_qcnt = 0;
			}
			/* post signal */
			fp_traps(&fpsd, fptrap, rp);

			/* decrement queue count for ieee exceptions */
			if (fptrap == ftt_ieee) {
				fp->fpu_qcnt = 0;
			}
		} else {
			fp->fpu_qcnt = 0;
		}
		/* update the software pcb copies of hardware fp registers */
		if (fpu_exists) {
			fp_save(fp);
		}
		kpreempt_enable();
	}

	/*
	 * Reset lwp_state to LWP_USER for the purposes of clock accounting,
	 * and restore the previously saved microstate.
	 */
	if (USERMODE(rp->r_tstate)) {
		(void) new_mstate(curthread, mstate);
		lwp->lwp_state = LWP_USER;
	}
}

/*
 * Handle floating point traps generated by simulation/emulation.
 */
void
fp_traps(
	fp_simd_type *pfpsd,	/* Pointer to simulator data */
	enum ftt_type ftt,	/* trap type */
	struct regs *rp)	/* ptr to regs fro trap */
{
	/*
	 * If we take a user's exception in kernel mode, we want to trap
	 * with the user's registers.
	 */
	switch (ftt) {
	case ftt_ieee:
		fpu_trap(rp, pfpsd->fp_trapaddr, T_FP_EXCEPTION_IEEE,
		    pfpsd->fp_trapcode);
		break;
	case ftt_fault:
		fpu_trap(rp, pfpsd->fp_trapaddr, T_DATA_EXCEPTION, 0);
		break;
	case ftt_alignment:
		fpu_trap(rp, pfpsd->fp_trapaddr, T_ALIGNMENT, 0);
		break;
	case ftt_unimplemented:
		fpu_trap(rp, pfpsd->fp_trapaddr, T_UNIMP_INSTR, 0);
		break;
	default:
		/*
		 * We don't expect any of the other types here.
		 */
		cmn_err(CE_PANIC, "fp_traps: bad ftt");
	}
}
