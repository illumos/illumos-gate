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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2017 Joyent, Inc.
 */

#include <sys/dtrace_impl.h>
#include <sys/atomic.h>
#include <sys/model.h>
#include <sys/frame.h>
#include <sys/stack.h>
#include <sys/machpcb.h>
#include <sys/procfs_isa.h>
#include <sys/cmn_err.h>
#include <sys/sysmacros.h>

#define	DTRACE_FMT3OP3_MASK	0x81000000
#define	DTRACE_FMT3OP3		0x80000000
#define	DTRACE_FMT3RS1_SHIFT	14
#define	DTRACE_FMT3RD_SHIFT	25
#define	DTRACE_DISP22_SHIFT	10
#define	DTRACE_RMASK		0x1f
#define	DTRACE_REG_L0		16
#define	DTRACE_REG_O7		15
#define	DTRACE_REG_I0		24
#define	DTRACE_REG_I6		30
#define	DTRACE_RET		0x81c7e008
#define	DTRACE_RETL		0x81c3e008
#define	DTRACE_SAVE_MASK	0xc1f80000
#define	DTRACE_SAVE		0x81e00000
#define	DTRACE_RESTORE		0x81e80000
#define	DTRACE_CALL_MASK	0xc0000000
#define	DTRACE_CALL		0x40000000
#define	DTRACE_JMPL_MASK	0x81f80000
#define	DTRACE_JMPL		0x81c00000
#define	DTRACE_BA_MASK		0xdfc00000
#define	DTRACE_BA		0x10800000
#define	DTRACE_BA_MAX		10

extern int dtrace_getupcstack_top(uint64_t *, int, uintptr_t *);
extern int dtrace_getustackdepth_top(uintptr_t *);
extern ulong_t dtrace_getreg_win(uint_t, uint_t);
extern void dtrace_putreg_win(uint_t, ulong_t);
extern int dtrace_fish(int, int, uintptr_t *);

int	dtrace_ustackdepth_max = 2048;

/*
 * This is similar in principle to getpcstack(), but there are several marked
 * differences in implementation:
 *
 * (a)	dtrace_getpcstack() is called from probe context.  Thus, the call
 *	to flush_windows() from getpcstack() is a call to the probe-safe
 *	equivalent here.
 *
 * (b)  dtrace_getpcstack() is willing to sacrifice some performance to get
 *	a correct stack.  While consumers of getpcstack() are largely
 *	subsystem-specific in-kernel debugging facilities, DTrace consumers
 *	are arbitrary user-level analysis tools; dtrace_getpcstack() must
 *	deliver as correct a stack as possible.  Details on the issues
 *	surrounding stack correctness are found below.
 *
 * (c)	dtrace_getpcstack() _always_ fills in pcstack_limit pc_t's -- filling
 *	in the difference between the stack depth and pcstack_limit with NULLs.
 *	Due to this behavior dtrace_getpcstack() returns void.
 *
 * (d)	dtrace_getpcstack() takes a third parameter, aframes, that
 *	denotes the number of _artificial frames_ on the bottom of the
 *	stack.  An artificial frame is one induced by the provider; all
 *	artificial frames are stripped off before frames are stored to
 *	pcstack.
 *
 * (e)	dtrace_getpcstack() takes a fourth parameter, pc, that indicates
 *	an interrupted program counter (if any).  This should be a non-NULL
 *	value if and only if the hit probe is unanchored.  (Anchored probes
 *	don't fire through an interrupt source.)  This parameter is used to
 *	assure (b), above.
 */
void
dtrace_getpcstack(pc_t *pcstack, int pcstack_limit, int aframes, uint32_t *pc)
{
	struct frame *fp, *nextfp, *minfp, *stacktop;
	int depth = 0;
	int on_intr, j = 0;
	uint32_t i, r;

	fp = (struct frame *)((caddr_t)dtrace_getfp() + STACK_BIAS);
	dtrace_flush_windows();

	if (pc != NULL) {
		/*
		 * If we've been passed a non-NULL pc, we need to determine
		 * whether or not the specified program counter falls in a leaf
		 * function.  If it falls within a leaf function, we know that
		 * %o7 is valid in its frame (and we can just drive on).  If
		 * it's a non-leaf, however, we know that %o7 is garbage in the
		 * bottom frame.  To trim this frame, we simply increment
		 * aframes and drop into the stack-walking loop.
		 *
		 * To quickly determine if the specified program counter is in
		 * a leaf function, we exploit the fact that leaf functions
		 * tend to be short and non-leaf functions tend to frequently
		 * perform operations that are only permitted in a non-leaf
		 * function (e.g., using the %i's or %l's; calling a function;
		 * performing a restore).  We exploit these tendencies by
		 * simply scanning forward from the specified %pc -- if we see
		 * an operation only permitted in a non-leaf, we know we're in
		 * a non-leaf; if we see a retl, we know we're in a leaf.
		 * Fortunately, one need not perform anywhere near full
		 * disassembly to effectively determine the former: determining
		 * that an instruction is a format-3 instruction and decoding
		 * its rd and rs1 fields, for example, requires very little
		 * manipulation.  Overall, this method of leaf determination
		 * performs quite well:  on average, we only examine between
		 * 1.5 and 2.5 instructions before making the determination.
		 * (Outliers do exist, however; of note is the non-leaf
		 * function ip_sioctl_not_ours() which -- as of this writing --
		 * has a whopping 455 straight instructions that manipulate
		 * only %g's and %o's.)
		 */
		int delay = 0, branches = 0, taken = 0;

		if (depth < pcstack_limit)
			pcstack[depth++] = (pc_t)(uintptr_t)pc;

		/*
		 * Our heuristic is exactly that -- a heuristic -- and there
		 * exists a possibility that we could be either be vectored
		 * off into the weeds (by following a bogus branch) or could
		 * wander off the end of the function and off the end of a
		 * text mapping (by not following a conditional branch at the
		 * end of the function that is effectively always taken).  So
		 * as a precautionary measure, we set the NOFAULT flag.
		 */
		DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);

		for (;;) {
			i = pc[j++];

			if ((i & DTRACE_FMT3OP3_MASK) == DTRACE_FMT3OP3) {
				/*
				 * This is a format-3 instruction.  We can
				 * look at rd and rs1.
				 */
				r = (i >> DTRACE_FMT3RS1_SHIFT) & DTRACE_RMASK;

				if (r >= DTRACE_REG_L0)
					goto nonleaf;

				r = (i >> DTRACE_FMT3RD_SHIFT) & DTRACE_RMASK;

				if (r >= DTRACE_REG_L0)
					goto nonleaf;

				if ((i & DTRACE_JMPL_MASK) == DTRACE_JMPL) {
					delay = 1;
					continue;
				}

				/*
				 * If we see explicit manipulation with %o7
				 * as a destination register, we know that
				 * %o7 is likely bogus -- and we treat this
				 * function as a non-leaf.
				 */
				if (r == DTRACE_REG_O7) {
					if (delay)
						goto leaf;

					i &= DTRACE_JMPL_MASK;

					if (i == DTRACE_JMPL) {
						delay = 1;
						continue;
					}

					goto nonleaf;
				}
			} else {
				/*
				 * If this is a call, it may or may not be
				 * a leaf; we need to check the delay slot.
				 */
				if ((i & DTRACE_CALL_MASK) == DTRACE_CALL) {
					delay = 1;
					continue;
				}

				/*
				 * If we see a ret it's not a leaf; if we
				 * see a retl, it is a leaf.
				 */
				if (i == DTRACE_RET)
					goto nonleaf;

				if (i == DTRACE_RETL)
					goto leaf;

				/*
				 * If this is a ba (annulled or not), then we
				 * need to actually follow the branch.  No, we
				 * don't look at the delay slot -- hopefully
				 * anything that can be gleaned from the delay
				 * slot can also be gleaned from the branch
				 * target.  To prevent ourselves from iterating
				 * infinitely, we clamp the number of branches
				 * that we'll follow, and we refuse to follow
				 * the same branch twice consecutively.  In
				 * both cases, we abort by deciding that we're
				 * looking at a leaf.  While in theory this
				 * could be wrong (we could be in the middle of
				 * a loop in a non-leaf that ends with a ba and
				 * only manipulates outputs and globals in the
				 * body of the loop -- therefore leading us to
				 * the wrong conclusion), this doesn't seem to
				 * crop up in practice.  (Or rather, this
				 * condition could not be deliberately induced,
				 * despite concerted effort.)
				 */
				if ((i & DTRACE_BA_MASK) == DTRACE_BA) {
					if (++branches == DTRACE_BA_MAX ||
					    taken == j)
						goto nonleaf;

					taken = j;
					j += ((int)(i << DTRACE_DISP22_SHIFT) >>
					    DTRACE_DISP22_SHIFT) - 1;
					continue;
				}

				/*
				 * Finally, if it's a save, it should be
				 * treated as a leaf; if it's a restore it
				 * should not be treated as a leaf.
				 */
				if ((i & DTRACE_SAVE_MASK) == DTRACE_SAVE)
					goto leaf;

				if ((i & DTRACE_SAVE_MASK) == DTRACE_RESTORE)
					goto nonleaf;
			}

			if (delay) {
				/*
				 * If this was a delay slot instruction and
				 * we didn't pick it up elsewhere, this is a
				 * non-leaf.
				 */
				goto nonleaf;
			}
		}
nonleaf:
		aframes++;
leaf:
		DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);
	}

	if ((on_intr = CPU_ON_INTR(CPU)) != 0)
		stacktop = (struct frame *)(CPU->cpu_intr_stack + SA(MINFRAME));
	else
		stacktop = (struct frame *)curthread->t_stk;
	minfp = fp;

	while (depth < pcstack_limit) {
		nextfp = (struct frame *)((caddr_t)fp->fr_savfp + STACK_BIAS);
		if (nextfp <= minfp || nextfp >= stacktop) {
			if (!on_intr && nextfp == stacktop && aframes != 0) {
				/*
				 * If we are exactly at the top of the stack
				 * with a non-zero number of artificial frames,
				 * it must be that the stack is filled with
				 * nothing _but_ artificial frames.  In this
				 * case, we assert that this is so, zero
				 * pcstack, and return.
				 */
				ASSERT(aframes == 1);
				ASSERT(depth == 0);

				while (depth < pcstack_limit)
					pcstack[depth++] = NULL;
				return;
			}

			if (on_intr) {
				/*
				 * Hop from interrupt stack to thread stack.
				 */
				stacktop = (struct frame *)curthread->t_stk;
				minfp = (struct frame *)curthread->t_stkbase;

				on_intr = 0;

				if (nextfp > minfp && nextfp < stacktop)
					continue;
			} else {
				/*
				 * High-level interrupts may occur when %sp is
				 * not necessarily contained in the stack
				 * bounds implied by %g7 -- interrupt thread
				 * management runs with %pil at DISP_LEVEL,
				 * and high-level interrupts may thus occur
				 * in windows when %sp and %g7 are not self-
				 * consistent.  If we call dtrace_getpcstack()
				 * from a high-level interrupt that has occurred
				 * in such a window, we will fail the above test
				 * of nextfp against minfp/stacktop.  If the
				 * high-level interrupt has in turn interrupted
				 * a non-passivated interrupt thread, we
				 * will execute the below code with non-zero
				 * aframes.  We therefore want to assert that
				 * aframes is zero _or_ we are in a high-level
				 * interrupt -- but because cpu_intr_actv is
				 * updated with high-level interrupts enabled,
				 * we must reduce this to only asserting that
				 * %pil is greater than DISP_LEVEL.
				 */
				ASSERT(aframes == 0 ||
				    dtrace_getipl() > DISP_LEVEL);
				pcstack[depth++] = (pc_t)fp->fr_savpc;
			}

			while (depth < pcstack_limit)
				pcstack[depth++] = NULL;
			return;
		}

		if (aframes > 0) {
			aframes--;
		} else {
			pcstack[depth++] = (pc_t)fp->fr_savpc;
		}

		fp = nextfp;
		minfp = fp;
	}
}

static int
dtrace_getustack_common(uint64_t *pcstack, int pcstack_limit, uintptr_t sp)
{
	proc_t *p = curproc;
	int ret = 0;
	uintptr_t oldsp;
	volatile uint16_t *flags =
	    (volatile uint16_t *)&cpu_core[CPU->cpu_id].cpuc_dtrace_flags;

	ASSERT(pcstack == NULL || pcstack_limit > 0);
	ASSERT(dtrace_ustackdepth_max > 0);

	if (p->p_model == DATAMODEL_NATIVE) {
		for (;;) {
			struct frame *fr = (struct frame *)(sp + STACK_BIAS);
			uintptr_t pc;

			if (sp == 0 || fr == NULL ||
			    !IS_P2ALIGNED((uintptr_t)fr, STACK_ALIGN))
				break;

			oldsp = sp;

			pc = dtrace_fulword(&fr->fr_savpc);
			sp = dtrace_fulword(&fr->fr_savfp);

			if (pc == 0)
				break;

			/*
			 * We limit the number of times we can go around this
			 * loop to account for a circular stack.
			 */
			if (sp == oldsp || ret++ >= dtrace_ustackdepth_max) {
				*flags |= CPU_DTRACE_BADSTACK;
				cpu_core[CPU->cpu_id].cpuc_dtrace_illval = sp;
				break;
			}

			if (pcstack != NULL) {
				*pcstack++ = pc;
				pcstack_limit--;
				if (pcstack_limit == 0)
					break;
			}
		}
	} else {
		/*
		 * Truncate the stack pointer to 32-bits as there may be
		 * garbage in the upper bits which would normally be ignored
		 * by the processor in 32-bit mode.
		 */
		sp = (uint32_t)sp;

		for (;;) {
			struct frame32 *fr = (struct frame32 *)sp;
			uint32_t pc;

			if (sp == 0 ||
			    !IS_P2ALIGNED((uintptr_t)fr, STACK_ALIGN32))
				break;

			oldsp = sp;

			pc = dtrace_fuword32(&fr->fr_savpc);
			sp = dtrace_fuword32(&fr->fr_savfp);

			if (pc == 0)
				break;

			if (sp == oldsp || ret++ >= dtrace_ustackdepth_max) {
				*flags |= CPU_DTRACE_BADSTACK;
				cpu_core[CPU->cpu_id].cpuc_dtrace_illval = sp;
				break;
			}

			if (pcstack != NULL) {
				*pcstack++ = pc;
				pcstack_limit--;
				if (pcstack_limit == 0)
					break;
			}
		}
	}

	return (ret);
}

void
dtrace_getupcstack(uint64_t *pcstack, int pcstack_limit)
{
	klwp_t *lwp = ttolwp(curthread);
	proc_t *p = curproc;
	struct regs *rp;
	uintptr_t sp;
	int n;

	ASSERT(DTRACE_CPUFLAG_ISSET(CPU_DTRACE_NOFAULT));

	if (pcstack_limit <= 0)
		return;

	/*
	 * If there's no user context we still need to zero the stack.
	 */
	if (lwp == NULL || p == NULL || (rp = lwp->lwp_regs) == NULL)
		goto zero;

	*pcstack++ = (uint64_t)p->p_pid;
	pcstack_limit--;

	if (pcstack_limit <= 0)
		return;

	*pcstack++ = (uint64_t)rp->r_pc;
	pcstack_limit--;

	if (pcstack_limit <= 0)
		return;

	if (DTRACE_CPUFLAG_ISSET(CPU_DTRACE_ENTRY)) {
		*pcstack++ = (uint64_t)rp->r_o7;
		pcstack_limit--;
		if (pcstack_limit <= 0)
			return;
	}

	sp = rp->r_sp;

	n = dtrace_getupcstack_top(pcstack, pcstack_limit, &sp);
	ASSERT(n >= 0);
	ASSERT(n <= pcstack_limit);

	pcstack += n;
	pcstack_limit -= n;
	if (pcstack_limit <= 0)
		return;

	n = dtrace_getustack_common(pcstack, pcstack_limit, sp);
	ASSERT(n >= 0);
	ASSERT(n <= pcstack_limit);

	pcstack += n;
	pcstack_limit -= n;

zero:
	while (pcstack_limit-- > 0)
		*pcstack++ = NULL;
}

int
dtrace_getustackdepth(void)
{
	klwp_t *lwp = ttolwp(curthread);
	proc_t *p = curproc;
	struct regs *rp;
	uintptr_t sp;
	int n = 1;

	if (lwp == NULL || p == NULL || (rp = lwp->lwp_regs) == NULL)
		return (0);

	if (DTRACE_CPUFLAG_ISSET(CPU_DTRACE_FAULT))
		return (-1);

	sp = rp->r_sp;

	n += dtrace_getustackdepth_top(&sp);
	n += dtrace_getustack_common(NULL, 0, sp);

	/*
	 * Add one more to the stack depth if we're in an entry probe as long
	 * as the return address is non-NULL or there are additional frames
	 * beyond that NULL return address.
	 */
	if (DTRACE_CPUFLAG_ISSET(CPU_DTRACE_ENTRY) &&
	    (rp->r_o7 != NULL || n != 1))
		n++;

	return (n);
}

void
dtrace_getufpstack(uint64_t *pcstack, uint64_t *fpstack, int pcstack_limit)
{
	klwp_t *lwp = ttolwp(curthread);
	proc_t *p = ttoproc(curthread);
	struct regs *rp;
	uintptr_t sp;

	if (pcstack_limit <= 0)
		return;

	/*
	 * If there's no user context we still need to zero the stack.
	 */
	if (lwp == NULL || p == NULL || (rp = lwp->lwp_regs) == NULL)
		goto zero;

	*pcstack++ = (uint64_t)p->p_pid;
	pcstack_limit--;

	if (pcstack_limit <= 0)
		return;

	if (DTRACE_CPUFLAG_ISSET(CPU_DTRACE_ENTRY)) {
		*fpstack++ = 0;
		*pcstack++ = (uint64_t)rp->r_pc;
		pcstack_limit--;
		if (pcstack_limit <= 0)
			return;

		*fpstack++ = (uint64_t)rp->r_sp;
		*pcstack++ = (uint64_t)rp->r_o7;
		pcstack_limit--;
	} else {
		*fpstack++ = (uint64_t)rp->r_sp;
		*pcstack++ = (uint64_t)rp->r_pc;
		pcstack_limit--;
	}

	if (pcstack_limit <= 0)
		return;

	sp = rp->r_sp;

	dtrace_flush_user_windows();

	if (p->p_model == DATAMODEL_NATIVE) {
		while (pcstack_limit > 0) {
			struct frame *fr = (struct frame *)(sp + STACK_BIAS);
			uintptr_t pc;

			if (sp == 0 || fr == NULL ||
			    ((uintptr_t)&fr->fr_savpc & 3) != 0 ||
			    ((uintptr_t)&fr->fr_savfp & 3) != 0)
				break;

			pc = dtrace_fulword(&fr->fr_savpc);
			sp = dtrace_fulword(&fr->fr_savfp);

			if (pc == 0)
				break;

			*fpstack++ = sp;
			*pcstack++ = pc;
			pcstack_limit--;
		}
	} else {
		/*
		 * Truncate the stack pointer to 32-bits as there may be
		 * garbage in the upper bits which would normally be ignored
		 * by the processor in 32-bit mode.
		 */
		sp = (uint32_t)sp;

		while (pcstack_limit > 0) {
			struct frame32 *fr = (struct frame32 *)sp;
			uint32_t pc;

			if (sp == 0 ||
			    ((uintptr_t)&fr->fr_savpc & 3) != 0 ||
			    ((uintptr_t)&fr->fr_savfp & 3) != 0)
				break;

			pc = dtrace_fuword32(&fr->fr_savpc);
			sp = dtrace_fuword32(&fr->fr_savfp);

			if (pc == 0)
				break;

			*fpstack++ = sp;
			*pcstack++ = pc;
			pcstack_limit--;
		}
	}

zero:
	while (pcstack_limit-- > 0)
		*pcstack++ = NULL;
}

uint64_t
dtrace_getarg(int arg, int aframes)
{
	uintptr_t val;
	struct frame *fp;
	uint64_t rval;

	/*
	 * Account for the fact that dtrace_getarg() consumes an additional
	 * stack frame.
	 */
	aframes++;

	if (arg < 6) {
		if (dtrace_fish(aframes, DTRACE_REG_I0 + arg, &val) == 0)
			return (val);
	} else {
		if (dtrace_fish(aframes, DTRACE_REG_I6, &val) == 0) {
			/*
			 * We have a stack pointer; grab the argument.
			 */
			fp = (struct frame *)(val + STACK_BIAS);

			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
			rval = fp->fr_argx[arg - 6];
			DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);

			return (rval);
		}
	}

	/*
	 * There are other ways to do this.  But the slow, painful way works
	 * just fine.  Because this requires some loads, we need to set
	 * CPU_DTRACE_NOFAULT to protect against looking for an argument that
	 * isn't there.
	 */
	fp = (struct frame *)((caddr_t)dtrace_getfp() + STACK_BIAS);
	dtrace_flush_windows();

	DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);

	for (aframes -= 1; aframes; aframes--)
		fp = (struct frame *)((caddr_t)fp->fr_savfp + STACK_BIAS);

	if (arg < 6) {
		rval = fp->fr_arg[arg];
	} else {
		fp = (struct frame *)((caddr_t)fp->fr_savfp + STACK_BIAS);
		rval = fp->fr_argx[arg - 6];
	}

	DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);

	return (rval);
}

int
dtrace_getstackdepth(int aframes)
{
	struct frame *fp, *nextfp, *minfp, *stacktop;
	int depth = 0;
	int on_intr;

	fp = (struct frame *)((caddr_t)dtrace_getfp() + STACK_BIAS);
	dtrace_flush_windows();

	if ((on_intr = CPU_ON_INTR(CPU)) != 0)
		stacktop = (struct frame *)CPU->cpu_intr_stack + SA(MINFRAME);
	else
		stacktop = (struct frame *)curthread->t_stk;
	minfp = fp;

	for (;;) {
		nextfp = (struct frame *)((caddr_t)fp->fr_savfp + STACK_BIAS);
		if (nextfp <= minfp || nextfp >= stacktop) {
			if (on_intr) {
				/*
				 * Hop from interrupt stack to thread stack.
				 */
				stacktop = (struct frame *)curthread->t_stk;
				minfp = (struct frame *)curthread->t_stkbase;
				on_intr = 0;
				continue;
			}

			return (++depth);
		}

		if (aframes > 0) {
			aframes--;
		} else {
			depth++;
		}

		fp = nextfp;
		minfp = fp;
	}
}

/*
 * This uses the same register numbering scheme as in sys/procfs_isa.h.
 */
ulong_t
dtrace_getreg(struct regs *rp, uint_t reg)
{
	ulong_t value;
	uintptr_t fp;
	struct machpcb *mpcb;

	if (reg == R_G0)
		return (0);

	if (reg <= R_G7)
		return ((&rp->r_g1)[reg - 1]);

	if (reg > R_I7) {
		switch (reg) {
		case R_CCR:
			return ((rp->r_tstate >> TSTATE_CCR_SHIFT) &
			    TSTATE_CCR_MASK);
		case R_PC:
			return (rp->r_pc);
		case R_nPC:
			return (rp->r_npc);
		case R_Y:
			return (rp->r_y);
		case R_ASI:
			return ((rp->r_tstate >> TSTATE_ASI_SHIFT) &
			    TSTATE_ASI_MASK);
		case R_FPRS:
			return (dtrace_getfprs());
		default:
			DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);
			return (0);
		}
	}

	/*
	 * We reach go to the fake restore case if the probe we hit was a pid
	 * return probe on a restore instruction. We partially emulate the
	 * restore in the kernel and then execute a simple restore
	 * instruction that we've secreted away to do the actual register
	 * window manipulation. We need to go one register window further
	 * down to get at the %ls, and %is and we need to treat %os like %is
	 * to pull them out of the topmost user frame.
	 */
	if (DTRACE_CPUFLAG_ISSET(CPU_DTRACE_FAKERESTORE)) {
		if (reg > R_O7)
			goto fake_restore;
		else
			reg += R_I0 - R_O0;

	} else if (reg <= R_O7) {
		return ((&rp->r_g1)[reg - 1]);
	}

	if (dtrace_getotherwin() > 0)
		return (dtrace_getreg_win(reg, 1));

	mpcb = (struct machpcb *)((caddr_t)rp - REGOFF);

	if (curproc->p_model == DATAMODEL_NATIVE) {
		struct frame *fr = (void *)(rp->r_sp + STACK_BIAS);

		if (mpcb->mpcb_wbcnt > 0) {
			struct rwindow *rwin = (void *)mpcb->mpcb_wbuf;
			int i = mpcb->mpcb_wbcnt;
			do {
				i--;
				if ((long)mpcb->mpcb_spbuf[i] == rp->r_sp)
					return (rwin[i].rw_local[reg - 16]);
			} while (i > 0);
		}

		DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
		value = dtrace_fulword(&fr->fr_local[reg - 16]);
		DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);
	} else {
		struct frame32 *fr = (void *)(uintptr_t)(caddr32_t)rp->r_sp;

		if (mpcb->mpcb_wbcnt > 0) {
			struct rwindow32 *rwin = (void *)mpcb->mpcb_wbuf;
			int i = mpcb->mpcb_wbcnt;
			do {
				i--;
				if ((long)mpcb->mpcb_spbuf[i] == rp->r_sp)
					return (rwin[i].rw_local[reg - 16]);
			} while (i > 0);
		}

		DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
		value = dtrace_fuword32(&fr->fr_local[reg - 16]);
		DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);
	}

	return (value);

fake_restore:
	ASSERT(R_L0 <= reg && reg <= R_I7);

	/*
	 * We first look two user windows down to see if we can dig out
	 * the register we're looking for.
	 */
	if (dtrace_getotherwin() > 1)
		return (dtrace_getreg_win(reg, 2));

	/*
	 * First we need to get the frame pointer and then we perform
	 * the same computation as in the non-fake-o-restore case.
	 */

	mpcb = (struct machpcb *)((caddr_t)rp - REGOFF);

	if (dtrace_getotherwin() > 0) {
		fp = dtrace_getreg_win(R_FP, 1);
		goto got_fp;
	}

	if (curproc->p_model == DATAMODEL_NATIVE) {
		struct frame *fr = (void *)(rp->r_sp + STACK_BIAS);

		if (mpcb->mpcb_wbcnt > 0) {
			struct rwindow *rwin = (void *)mpcb->mpcb_wbuf;
			int i = mpcb->mpcb_wbcnt;
			do {
				i--;
				if ((long)mpcb->mpcb_spbuf[i] == rp->r_sp) {
					fp = rwin[i].rw_fp;
					goto got_fp;
				}
			} while (i > 0);
		}

		DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
		fp = dtrace_fulword(&fr->fr_savfp);
		DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);
		if (cpu_core[CPU->cpu_id].cpuc_dtrace_flags & CPU_DTRACE_FAULT)
			return (0);
	} else {
		struct frame32 *fr = (void *)(uintptr_t)(caddr32_t)rp->r_sp;

		if (mpcb->mpcb_wbcnt > 0) {
			struct rwindow32 *rwin = (void *)mpcb->mpcb_wbuf;
			int i = mpcb->mpcb_wbcnt;
			do {
				i--;
				if ((long)mpcb->mpcb_spbuf[i] == rp->r_sp) {
					fp = rwin[i].rw_fp;
					goto got_fp;
				}
			} while (i > 0);
		}

		DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
		fp = dtrace_fuword32(&fr->fr_savfp);
		DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);
		if (cpu_core[CPU->cpu_id].cpuc_dtrace_flags & CPU_DTRACE_FAULT)
			return (0);
	}
got_fp:

	if (curproc->p_model == DATAMODEL_NATIVE) {
		struct frame *fr = (void *)(fp + STACK_BIAS);

		if (mpcb->mpcb_wbcnt > 0) {
			struct rwindow *rwin = (void *)mpcb->mpcb_wbuf;
			int i = mpcb->mpcb_wbcnt;
			do {
				i--;
				if ((long)mpcb->mpcb_spbuf[i] == fp)
					return (rwin[i].rw_local[reg - 16]);
			} while (i > 0);
		}

		DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
		value = dtrace_fulword(&fr->fr_local[reg - 16]);
		DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);
	} else {
		struct frame32 *fr = (void *)(uintptr_t)(caddr32_t)fp;

		if (mpcb->mpcb_wbcnt > 0) {
			struct rwindow32 *rwin = (void *)mpcb->mpcb_wbuf;
			int i = mpcb->mpcb_wbcnt;
			do {
				i--;
				if ((long)mpcb->mpcb_spbuf[i] == fp)
					return (rwin[i].rw_local[reg - 16]);
			} while (i > 0);
		}

		DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
		value = dtrace_fuword32(&fr->fr_local[reg - 16]);
		DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);
	}

	return (value);
}

/* ARGSUSED */
int
dtrace_setreg(struct regs *rp, uint_t reg, ulong_t val)
{
	/* Not supported at this time */
	DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);
	return (0);
}

/*ARGSUSED*/
uint64_t
dtrace_getvmreg(uint_t ndx, volatile uint16_t *flags)
{
	*flags |= CPU_DTRACE_ILLOP;

	return (0);
}
