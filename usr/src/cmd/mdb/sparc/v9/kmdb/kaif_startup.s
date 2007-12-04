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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#if !defined(__lint)
#include <sys/asm_linkage.h>
#include <sys/trap.h>
#include <sys/mmu.h>
#include <sys/machasi.h>
#include <sys/intreg.h>
#define	_KERNEL
#include <sys/privregs.h>
#undef _KERNEL
#include <sys/machthread.h>
#include <sys/machtrap.h>
#include <sys/machparam.h>
#endif

#include <mdb/mdb_kreg_impl.h>
#include <kmdb/kaif_regs.h>
#include <kmdb/kaif_off.h>
#include <kmdb/kaif.h>
#include <kmdb/kaif_asmutil.h>

#define	KAIF_CPU_INDEX				\
	set	mdb, %g1;			\
	ldx	[%g1 + MDB_KDI], %g1;		\
	ldx	[%g1 + MKDI_CPU_INDEX], %g1;	\
	set	1f, %g7;			\
	jmp	%g1;				\
	nop;					\
1:

#define	KAIF_CPU_GETADDR_TL1			\
	set	kaif_cpusave_getaddr, %g6;	\
	sethi	%hi(1f), %g7;			\
	jmp	%g6;				\
	or	%g7, %lo(1f), %g7;		\
1:

#define	KAIF_COPY_KREG(src, tgt, idx, tmp)	\
	ldx	[src + KREG_OFF(idx)], tmp;	\
	stx	tmp, [tgt + KREG_OFF(idx)]

#ifndef sun4v
/*
 * Creates a new primary context register value by copying the nucleus page
 * size bits to the primary context page size bits and setting the primary
 * context to zero.  The updated value is stored in the ctx parameter.
 */
#define	KAIF_MAKE_NEW_CTXREG(ctx, tmp)		\
	srlx	ctx, CTXREG_NEXT_SHIFT, ctx ;	\
	sllx 	ctx, CTXREG_NEXT_SHIFT, ctx;	\
	sllx	ctx, 3, tmp;			\
	srlx	tmp, CTXREG_NEXT_SHIFT, tmp;	\
	sllx	tmp, CTXREG_EXT_SHIFT, tmp;	\
	or	ctx, tmp, ctx;			\
	srlx	ctx, CTXREG_NEXT_SHIFT + 3, tmp; \
	sllx	tmp, CTXREG_EXT_SHIFT, tmp;	\
	or	ctx, tmp, ctx
#endif /* sun4v */
	
#if !defined(__lint)

	/*
	 * Calculate the address of the save area for the current CPU.  This
	 * would be a macro, but for need to call platform-specific CPU ID
	 * routines.  The kernel provides, via the KDI, a TL=1-safe "function"
	 * for CPU ID retrieval, which we call here.  The retrieval code returns
	 * the ID in %g1, and is allowed to clobber %g2.  It also assumes that
	 * the return address is in %g7.
	 *
	 * Arguments:
	 *   %g7 - return address
	 * Returns:
	 *   %g6 - address of save area
	 *
	 * %g4 will be preserved.
	 */
	ENTRY_NP(kaif_cpusave_getaddr)

	mov	%g7, %g5	! we'll need %g7 for the ID retriever
	KAIF_CPU_INDEX		! index returned in %g1, clobbers %g2, %g7

	set	KRS_SIZE, %g2
	mulx	%g1, %g2, %g2
	set	kaif_cpusave, %g6
	ldx	[%g6], %g6

	jmp	%g5		! return to caller-provided address
	add	%g6, %g2, %g6

	SET_SIZE(kaif_cpusave_getaddr)

	/*
	 * Save volatile state - state that won't be available when we switch
	 * back to TL=0.  We're currently at TL=1, and are on either the
	 * alternate or interrupt globals, so we'll need to do a bit of a
	 * dance in order to save the normal globals.
	 *
	 * NOTE: This routine and kaif_trap_obp must be equivalent.
	 *
	 * Parameters:
	 *  %g7 - return address
	 *  %g6 - cpusave area
	 *  %g4 - the %pstate value to get us back to our current globals set
	 *  %g4 not applicable on sun4v as it uses %gl
	 */

	ENTRY_NP(kaif_save_tl1_state)

	add	%g6, KRS_GREGS + GREG_KREGS, %g5

	rdpr	%tstate, %g2
	stx	%g2, [%g6 + KRS_TSTATE]
	rdpr	%tpc, %g2
	stx	%g2, [%g5 + KREG_OFF(KREG_PC)]
	rdpr	%tnpc, %g2
	stx	%g2, [%g5 + KREG_OFF(KREG_NPC)]
	rdpr	%tt, %g2
	stx	%g2, [%g5 + KREG_OFF(KREG_TT)]

	/*
	 * Switch over to the normal globals, so we can save them.  We'll need
	 * our gregs pointer and the return %pstate value, so stash them in
	 * registers that will be available to us on both sides.
	 *
	 * NOTE: Global register sets is selected by %gl register in sun4v.
	 *	 There is no PSTATE.AG bit in sun4v to select global set.
	 *       - Normal globals is the set when %gl = 0.
	 *	 - TL1 globals is the set when %gl = 1.
	 */
	SWITCH_TO_NORMAL_GLOBALS();	/* saves %o5 and %o4 */
	stx	%g1, [%o5 + KREG_OFF(KREG_G1)]
	stx	%g2, [%o5 + KREG_OFF(KREG_G2)]
	stx	%g3, [%o5 + KREG_OFF(KREG_G3)]
	stx	%g4, [%o5 + KREG_OFF(KREG_G4)]
	stx	%g5, [%o5 + KREG_OFF(KREG_G5)]
	stx	%g6, [%o5 + KREG_OFF(KREG_G6)]
	stx	%g7, [%o5 + KREG_OFF(KREG_G7)]

	/*
	 * Restore saved %o registers and return.
	 */
	SWITCH_TO_TL1_GLOBALS_AND_RET();	/* restores %o5 and %o4 */
	SET_SIZE(kaif_save_tl1_state)

	/*
	 * Save the remaining state, and prepare to enter the debugger.
	 */

	ENTRY_NP(kaif_trap_common)

	/* Make sure the world is as it should be */
	wrpr	%g0, PTSTATE_KERN_COMMON, %pstate
	wrpr	%g0, %tl

	SET_GL(0);
	set	1f, %g7
	set	kaif_cpusave_getaddr, %g6
	jmp	%g6
	nop
1:	/* CPU save area address is now in %g6 */
	add	%g6, KRS_GREGS + GREG_KREGS, %g5

	ldx	[%g5 + KREG_OFF(KREG_PC)], %g4
	ADD_CRUMB(%g6, KRM_PC, %g4, %g1)
	ldx	[%g5 + KREG_OFF(KREG_TT)], %g4
	ADD_CRUMB(%g6, KRM_TT, %g4, %g1)

	/*
	 * The %tba is special.  With normal entry, we're on the same trap table
	 * the kernel is using (this could be OBP's table if we're early enough
	 * in the boot process).  We want to save it, but we don't want to
	 * switch to OBP's table just yet, as we need to ensure that only one
	 * CPU uses OBP's table at a time.  We do this by waiting until we've
	 * selected the master before switching.
	 *
	 * Single-step is a bit different.  Everything about the CPU's state is
	 * as it should be, with the exception of %tba.  We need to step on
	 * OBP's trap table, so we didn't restore %tba during resume.  The save
	 * state area still contains the real %tba value - the one we had when
	 * we first entered the debugger.  We don't want to clobber that, so
	 * we'll only save %tba if we're not stepping.
	 */

	set	kaif_master_cpuid, %g1
	ld	[%g1], %g1
	ld	[%g6 + KRS_CPU_ID], %g2
	cmp	%g1, %g2
	be	1f
	nop

	rdpr	%tba, %g2
	stx	%g2, [%g5 + KREG_OFF(KREG_TBA)]

1:
	rdpr	%pil, %g4
	stx	%g4, [%g5 + KREG_OFF(KREG_PIL)]
	wrpr	%g0, 14, %pil

	rd	%y, %g4
	stx	%g4, [%g5 + KREG_OFF(KREG_Y)]

	/*
	 * Save window state and windows
	 */
	rdpr	%cwp, %g4
	stx	%g4, [%g5 + KREG_OFF(KREG_CWP)]
	rdpr	%otherwin, %g4
	stx	%g4, [%g5 + KREG_OFF(KREG_OTHERWIN)]
	rdpr	%cleanwin, %g4
	stx	%g4, [%g5 + KREG_OFF(KREG_CLEANWIN)]
	rdpr	%cansave, %g4
	stx	%g4, [%g5 + KREG_OFF(KREG_CANSAVE)]
	rdpr	%canrestore, %g4
	stx	%g4, [%g5 + KREG_OFF(KREG_CANRESTORE)]
	rdpr	%wstate, %g4
	stx	%g4, [%g5 + KREG_OFF(KREG_WSTATE)]

	GET_NWIN(%g1, %g4);	! %g1 is scratch, %g4 set to nwin-1

	wrpr	%g4, %cleanwin

	sub	%g4, 1, %g1
	wrpr	%g1, %cansave
	wrpr	%g0, %otherwin
	wrpr	%g0, %canrestore
	wrpr	%g0, %cwp

	clr	%g2
	ldx	[%g6 + KRS_RWINS], %g3
1:	SAVE_V9WINDOW(%g3)
	inc	%g2
	add	%g3, RWIN_SIZE, %g3
	cmp	%g2, %g4
	ble	1b
	wrpr	%g2, %cwp

	/*
	 * Save FP state
	 */
	add	%g6, KRS_FPREGS, %g4
	rd	%fprs, %g1
	stx	%g1, [%g4 + FPU_FPRS]
	btst	FPRS_FEF, %g1		! is FP enabled?
	bz	%icc, 1f		! if not, don't save FP regs
	wr	%g0, FPRS_FEF, %fprs	! enable FP

	STORE_FPREGS(%g4)
	stx	%fsr, [%g4 + FPU_FSR]

1:	/*
	 * We're almost done saving state.  Go back to the starting window, and
	 * switch to the CPU-specific stack.  We'll use this stack to finish
	 * saving state, and for the next stage of debugger startup/resumption,
	 * when we designate the master.  The slaves will continue to run on
	 * this stack until released or turned into masters.
	 */
	ldx	[%g5 + KREG_OFF(KREG_CWP)], %g4
	wrpr	%g4, %cwp

	set	KRS_CPUSTACK + KAIF_CPU_STKSZ - 1, %g1
	add	%g1, %g6, %g1
	and	%g1, -STACK_ALIGN64, %g1
	sub	%g1, SA64(MINFRAME) + V9BIAS64, %sp
	clr	%fp
	save	%sp, -SA64(MINFRAME64), %sp

	/*
	 * We'll need to access cpusave and gregs for our final state-saving,
	 * so stash them where they won't be clobbered by function calls.
	 */
	mov	%g6, %l6
	mov	%g5, %l5

	/*
	 * Now that we have a stack, we can save %stick.  %stick isn't present
	 * on all of our target machines, so we have to use the KDI to fetch the
	 * current value (if any).  We save %tick here too, because they get
	 * lonely if separated.
	 */
	rd	%tick, %g4
	stx	%g4, [%l5 + KREG_OFF(KREG_TICK)]

	call	kmdb_kdi_get_stick
	add	%l5, KREG_OFF(KREG_STICK), %o0
	brnz	%o0, 1f
	nop

	/*
	 * We found %stick.  Set the %stick-found flag.
	 */
	ld	[%l5 + GREG_FLAGS], %g1
	or	%g1, MDB_V9GREG_F_STICK_VALID, %g1
	st	%g1, [%l5 + GREG_FLAGS]

1:	/*
	 * Enter the next phase of debugger startup
	 */
	call	kaif_debugger_entry
	mov	%l6, %o0

	ba,a	kaif_resume	! expects valid %l5, %l6

	/*NOTREACHED*/

	SET_SIZE(kaif_trap_common)

#endif	/* !__lint */

	/*
	 * The primary debugger-entry routine.  This routine is the trap handler
	 * for programmed entry, watchpoints, and breakpoints, and is entered at
	 * TL=1, on the kernel's trap table, with PSTATE.AG set.  It is used in
	 * the following cases:
	 *
	 * 1. (common case) - intentional entry by a CPU intending to be the
	 *    master.  The CPU may have encountered a watchpoint, a breakpoint,
	 *    or a programmed entry trap, and is *NOT* coming from OBP.  The CPU
	 *    is allowed direct entry into the debugger.
	 *
	 * 2. A CPU was cross-called into kaif_slave_entry while executing in 
	 *    OBP.  The CPU was released, but a programmed entry trap was 
	 *    activated, designed to be encountered when the cross-called CPU
	 *    returned from OBP.  The CPU is allowed to enter the debugger.  We
	 *    don't know how many other CPUs need the PROM-return trap, so we'll
	 *    leave it active until everyone arrives.
	 *
	 * The remaining cases deal with instances where OBP got in the way.
	 * We can't allow a CPU into the debugger if it is currently executing
	 * in OBP, as chaos would ensue (OBP isn't re-entrant).  As such, we
	 * have to ask the CPU to come back when it has finished with OBP (or
	 * vice versa).  Depending on the circumstances, we'll need to dance
	 * around it.
	 *
	 * 3. A bystander CPU runs into the PROM-return trap described above
	 *    before being cross-called.  We'll let it into the debugger now, as
	 *    it would have ended up here anyway.
	 *
	 * 4. An innocent CPU encounters a watchpoint while executing in OBP.
	 *    We can't let the CPU into the debugger for the reasons given
	 *    above, so we'll need to ignore the watchpoint.  We disable
	 *    watchpoints, place a programmed-entry trap at %npc, and release
	 *    the CPU.
	 *
	 * 5. The stepping CPU described in case 4 encounters the programmed-
	 *    entry trap.  We'll remove the trap, re-enable watchpoints, and
	 *    send the CPU on its way.
	 *
	 * 6. Someone encounters a breakpoint or a programmed-entry trap in OBP.
	 *    We can step through watchpoints, as the text hasn't been touched.
	 *    With breakpoints and programmed-entry traps, however, chances are
	 *    high that someone replaced an instruction in the text with the
	 *    trap instruction.  We don't know where they stashed the
	 *    (presumably) saved instruction, so we can't step through it.  This
	 *    is a very unlikely scenario, so we're going to throw up our hands,
	 *    and will attempt to trigger a panic.
	 */

#if defined(__lint)
void
kaif_ktrap(void)
{
}
#else	/* __lint */

	ENTRY_NP(kaif_ktrap)

	set	1f, %g7
	set	kaif_cpusave_getaddr, %g6
	jmp	%g6
	nop
1:	/* CPU save area address is now in %g6 */

	ADVANCE_CRUMB_POINTER(%g6, %g1, %g2)
	ADD_CRUMB_CONST(%g6, KRM_SRC, KAIF_CRUMB_SRC_MAIN, %g1, %g2)

	rdpr	%tpc, %g2
	set	OFW_START_ADDR, %g1
	cmp	%g2, %g1
	bl	main_not_in_obp
	nop

	set	OFW_END_ADDR, %g1
	cmp	%g2, %g1
	bg	main_not_in_obp
	nop

	/*
	 * The CPU was in OBP when it encountered the trap that sent it here.
	 * See cases 3-6 above.
	 */
	rdpr	%tt, %g4
	cmp	%g4, T_PA_WATCHPOINT
	be	main_obp_wapt

	cmp	%g4, T_VA_WATCHPOINT
	be	main_obp_wapt

	cmp	%g4, T_SOFTWARE_TRAP|ST_KMDB_TRAP
	be	main_obp_progent

	cmp	%g4, T_SOFTWARE_TRAP|ST_BREAKPOINT
	be	main_obp_breakpoint
	nop

	/* This shouldn't happen - all valid traps should be checked above */
1:	ldx	[%g0], %g0
	ba,a	1b

	/* Cases 1 and 2 - head into the debugger, via the state-saver */
main_not_in_obp:
	ADD_CRUMB_FLAG(%g6, KAIF_CRUMB_F_MAIN_NORMAL, %g1, %g2, %g3)

	/* A formality - we know we came from kernel context */
	mov	MMU_PCONTEXT, %g3
	ldxa	[%g3]ASI_MMU_CTX, %g2	! ASI_MMU_CTX == ASI_DMMU for sun4u
	stx	%g2, [%g6 + KRS_MMU_PCONTEXT]

#ifndef sun4v
	/*
	 * If OBP supports preserving the Solaris kernel context register,
	 * then shift the nucleus bits into the primary and set context to 0,
	 * Otherwise, flush TLBs and clear the entire context register since
	 * OBP will clear it without flushing on entry to OBP.
	 */
	sethi	%hi(kmdb_prom_preserve_kctx), %g4
	ld	[%g4 + %lo(kmdb_prom_preserve_kctx)], %g4
	brz	%g4, 1f
	  nop
	/*
	 * Move nucleus context page size bits into primary context page size
	 * and set context to 0.  Use %g4 as a temporary.
	 */
	KAIF_MAKE_NEW_CTXREG(%g2, %g4)		! new context reg in %g2

	stxa	%g2, [%g3]ASI_MMU_CTX
	membar	#Sync
	ba	2f
	  nop
1:
#endif /* sun4v */
	/*
	 * Flush TLBs and clear primary context register.
	 */
	KAIF_DEMAP_TLB_ALL(%g4)
	stxa	%g0, [%g3]ASI_MMU_CTX	! ASI_MMU_CTX == ASI_DMMU for sun4u
	membar	#Sync
2:

	set	kaif_trap_common, %g7

	KAIF_SAVE_TL1_STATE();
	/*NOTREACHED*/

	/* Case 4 - watchpoint in OBP - step over it */
main_obp_wapt:
	ADD_CRUMB_FLAG(%g6, KAIF_CRUMB_F_MAIN_OBPWAPT, %g1, %g2, %g3)

#ifndef sun4v
	/* Turn off watchpoints */
	ldxa	[%g0]ASI_LSU, %g4
	stx	%g4, [%g6 + KRS_LSUCR_SAVE]
	setx	KAIF_LSUCTL_WAPT_MASK, %g1, %g3
	andn	%g4, %g3, %g4
	stxa	%g4, [%g0]ASI_LSU
#endif /* sun4v */

	/*
	 * SPARC only supports data watchpoints, and we know that only certain
	 * types of instructions, none of which include branches, can trigger
	 * memory reads.  As such, we can simply place a breakpoint at %npc.
	 */
	rdpr	%tnpc, %g4
	ld	[%g4], %g3
	st	%g3, [%g6 + KRS_INSTR_SAVE]
	set	0x91d0207d, %g3	! ta ST_KMDB_TRAP
	st	%g3, [%g4]
	flush	%g4
	membar	#Sync

	/* Back into the pool */
	retry

	/* Case 5 - programmed entry from wapt step - restore and resume */
main_obp_progent:
	ADD_CRUMB_FLAG(%g6, KAIF_CRUMB_F_MAIN_OBPPENT, %g1, %g2, %g3)

	rdpr	%tpc, %g4
	ld	[%g6 + KRS_INSTR_SAVE], %g3
	brz	%g3, main_obp_fail ! we don't have any open wapt steps
	nop

	st	%g3, [%g4]
	membar	#Sync
	st	%g0, [%g6 + KRS_INSTR_SAVE]

	/* XXX I$ invalidate? */

#ifndef sun4v
	ldx	[%g6 + KRS_LSUCR_SAVE], %g4
	stxa	%g4, [%g0]ASI_LSU
#endif /* sun4v */

	/* Restored - throw it back */
	retry

	/* Case 6 - breakpoint or unclaimed programmed entry */
main_obp_breakpoint:
main_obp_fail:
	ldx	[%g0], %g0
	ba,a	main_obp_fail

	SET_SIZE(kaif_ktrap)

#endif	/* __lint */

	/*
	 * The target for slave-stopping cross calls.  This routine is entered at
	 * TL=1, on the kernel's trap table, with PSTATE.IG set.  CPUs entering
	 * this handler will fall into one of the following categories:
	 *
	 * 1. (common case) - the CPU was not executing in OBP when it entered
	 *    this routine.  It will be allowed direct entry into the debugger.
	 *
	 * 2. The CPU had already entered the debugger, and was spinning in the
	 *    slave loop (at TL=0) when it was cross-called by the debugger's
	 *    world-stopper.  This could happen if two CPUs encountered
	 *    breakpoints simultaneously, triggering a race to become master.
	 *    One would lose, and would already be in the slave loop when the
	 *    master started trying to stop the world.  The CPU is already where
	 *    it is supposed to be, so we ignore the trap.
	 *
	 * 3. The CPU was executing in OBP.  We can't allow it to go directly
	 *    into OBP (see the kaif_ktrap comment), but we want to grab it when
	 *    it leaves OBP.  Arm the PROM-return programmed entry trap and
	 *    release the CPU.
	 */

#if defined(__lint)
void
kaif_slave_entry(void)
{
}
#else	/* __lint */

	ENTRY_NP(kaif_slave_entry)

	/*
	 * We may have arrived from userland.  We need to be in kernel context
	 * before we can save state, so we'll stash the current value in %g4
	 * until we've calculated the save address and have decided that we're
	 * heading into the debugger.
	 *
	 * %g4 is used to hold the entry MMU context until we decide whether to
	 * return or re-enter the debugger.
	 */
	mov	MMU_PCONTEXT, %g3
	ldxa	[%g3]ASI_MMU_CTX, %g4

#ifndef sun4v
	/*
	 * If OBP supports preserving the Solaris kernel context register,
	 * then shift the nucleus bits into the primary and set context to 0,
	 * Otherwise, flush TLBs and clear the entire context register since
	 * OBP will clear it without flushing on entry to OBP.
	 */
	sethi	%hi(kmdb_prom_preserve_kctx), %g1
	ld	[%g1 + %lo(kmdb_prom_preserve_kctx)], %g1
	brz	%g1, 1f
	  nop
	/*
	 * Move nucleus context page size bits into primary context page size
	 * and set context to 0.  Use %g2 as a temporary.
	 */
	mov	%g4, %g2
	KAIF_MAKE_NEW_CTXREG(%g2, %g1)		! new context reg in %g2

	stxa	%g2, [%g3]ASI_MMU_CTX
	membar	#Sync
	ba	2f
	  nop
1:
#endif /* sun4v */
	/*
	 * Flush TLBs and clear primary context register.
	 */
	KAIF_DEMAP_TLB_ALL(%g1)
	stxa	%g0, [%g3]ASI_MMU_CTX
	membar	#Sync
2:

	set	1f, %g7
	set	kaif_cpusave_getaddr, %g6
	jmp	%g6		! is not to alter %g4
	nop
1:	/* CPU save area address is now in %g6 */

	ADVANCE_CRUMB_POINTER(%g6, %g1, %g2)
	ADD_CRUMB_CONST(%g6, KRM_SRC, KAIF_CRUMB_SRC_IVEC, %g1, %g2)

	ld	[%g6 + KRS_CPU_STATE], %g5
	cmp	%g5, KAIF_CPU_STATE_NONE
	be,a	ivec_not_already_in_debugger

	/* Case 2 - CPU was already stopped, so ignore this cross call */
	ADD_CRUMB_FLAG(%g6, KAIF_CRUMB_F_IVEC_REENTER, %g1, %g2, %g3)

	/* Restore MMU_PCONTEXT, which we set on the way in */
	mov	MMU_PCONTEXT, %g3
	KAIF_DEMAP_TLB_ALL(%g2)
	stxa	%g4, [%g3]ASI_MMU_CTX
	membar	#Sync

	retry

ivec_not_already_in_debugger:
	brnz	%g4, ivec_not_in_obp	/* OBP runs in kernel context */
	nop

	/* Were we in OBP's memory range? */
	rdpr	%tpc, %g2
	set	OFW_START_ADDR, %g1
	cmp	%g2, %g1
	bl	ivec_not_in_obp
	nop

	set	OFW_END_ADDR, %g1
	cmp	%g2, %g1
	bg	ivec_not_in_obp
	nop

	/* Case 3 - CPU in OBP - arm return trap, release the CPU */
	ADD_CRUMB_FLAG(%g6, KAIF_CRUMB_F_IVEC_INOBP, %g1, %g2, %g3)

	set	kaif_promexitarmp, %g1
	ldx	[%g1], %g1
	mov	1, %g2
	st	%g2, [%g1]

	/* We were already in kernel context, so no need to restore it */

	retry

	/* Case 1 - head into debugger, via the state-saver */
ivec_not_in_obp:
	ADD_CRUMB_FLAG(%g6, KAIF_CRUMB_F_IVEC_NORMAL, %g1, %g2, %g3)

	stx	%g4, [%g6 + KRS_MMU_PCONTEXT]

	set	kaif_trap_common, %g7

	KAIF_SAVE_TL1_STATE_SLAVE();

	/*NOTREACHED*/

	SET_SIZE(kaif_slave_entry)

#endif

	/*
	 * The trap handler used when we're on OBP's trap table, which is used
	 * during initial system startup, while the debugger itself is
	 * executing, and when we're single-stepping.  When a trap occurs that
	 * it can't handle, OBP will execute our Forth word (kmdb_callback).
	 * Our word saves TL1 state, much as kaif_save_tl1_state does for the
	 * other handlers.  kmdb_callback will then cause control to be
	 * transferred to this routine.
	 *
	 * CPUs entering this routine will fall into the following categories:
	 *
	 * 1. The system is booting, and we encountered a trap that OBP couldn't
	 *    handle.  We save the CPU's state, and let it into the debugger.
	 *
	 * 2. We were single-stepping this CPU, causing it to encounter one of
	 *    the breakpoint traps we installed for stepping.  We save the CPU's
	 *    state, and let it back into the debugger.
	 *
	 * 3. We took a trap while executing in the debugger.  Before saving
	 *    this CPU's state in the CPU-specific save area, we will let the
	 *    debugger handle the trap.  If the trap resulted from a debugger
	 *    problem, and if the user decides to use the debugger to debug
	 *    itself, we'll overwrite the existing state with the state saved
	 *    by the Forth word, after which we'll let the CPU enter the
	 *    debugger.
	 *
	 * NOTE: The Forth word and the copying code here *must* be kept
	 * in sync with kaif_save_tl1_state.
	 */

#if defined(__lint)
void
kaif_trap_obp(void)
{
}
#else	/* __lint */

	ENTRY_NP(kaif_trap_obp)

	set	1f, %g7
	set	kaif_cpusave_getaddr, %g6
	jmp	%g6
	nop
1:	/* CPU save area address is now in %g6 */
	add	%g6, KRS_GREGS + GREG_KREGS, %g5

	ADVANCE_CRUMB_POINTER(%g6, %g1, %g2)
	ADD_CRUMB_CONST(%g6, KRM_SRC, KAIF_CRUMB_SRC_OBP, %g1, %g2)
	ADD_CRUMB_FLAG(%g6, KAIF_CRUMB_F_OBP_NORMAL, %g1, %g2, %g3)

	set	kaif_cb_save, %g4
	add	%g4, KRS_GREGS + GREG_KREGS, %g4
	ldx	[%g4 + KREG_OFF(KREG_PC)], %g1
	ADD_CRUMB(%g6, KRM_PC, %g1, %g2)
	ldx	[%g4 + KREG_OFF(KREG_TT)], %g1
	ADD_CRUMB(%g6, KRM_TT, %g1, %g2)

	ALTENTRY(kaif_trap_obp_saved)

	/*
	 * Are we here because of a trap we took while running the debugger, or
	 * because of one we took while executing kernel code?
	 */
	set	kaif_dseg, %g1
	ldx	[%g1], %g1
	cmp	%sp, %g1
	bl	obp_normal_entry
	nop

	set	kaif_dseg_lim, %g1
	ldx	[%g1], %g1
	cmp	%sp, %g1
	bg	obp_normal_entry
	nop

	/*
	 * The debugger fault code will need access to saved copies of the outs
	 * and %y if the user elects to panic.  We'll also need the saved outs if
	 * they decide to debug the fault with the debugger, as we'll have 
	 * trashed the outs while asking the user how to handle the fault.
	 */
	set	kaif_cb_save, %g4
	add	%g4, KRS_GREGS + GREG_KREGS, %g4
	rd	%y, %g2
	stx	%g2, [%g4 + KREG_OFF(KREG_Y)]
	stx	%o0, [%g4 + KREG_OFF(KREG_O0)]
	stx	%o1, [%g4 + KREG_OFF(KREG_O1)]
	stx	%o2, [%g4 + KREG_OFF(KREG_O2)]
	stx	%o3, [%g4 + KREG_OFF(KREG_O3)]
	stx	%o4, [%g4 + KREG_OFF(KREG_O4)]
	stx	%o5, [%g4 + KREG_OFF(KREG_O5)]
	stx	%o6, [%g4 + KREG_OFF(KREG_O6)]
	stx	%o7, [%g4 + KREG_OFF(KREG_O7)]

	/*
	 * Receipt of an XIR while on the debugger's stack is likely to mean
	 * that something has gone very wrong in the debugger.  Our safest
	 * course of action is to bail out to OBP, thus preserving as much state
	 * as we can.
	 */
	ldx	[%g4 + KREG_OFF(KREG_TT)], %g1
	cmp	%g1, T_XIR
	bne	1f
	nop

	call	prom_enter_mon
	nop

1:
	/*
	 * We're still on the debugger's stack, as we were when we took the
	 * fault.  Re-arm the Forth word and transfer control to the debugger.
	 */
	call	kaif_prom_rearm
	nop

	KAIF_CPU_INDEX		! index returned in %g1, clobbers %g2, %g7
	mov	%g1, %o4

	set	kaif_cb_save, %g5
	ldx	[%g5 + KREG_OFF(KREG_TT)], %o0
	ldx	[%g5 + KREG_OFF(KREG_PC)], %o1
	ldx	[%g5 + KREG_OFF(KREG_NPC)], %o2
	call	kmdb_dpi_handle_fault
	mov	%sp, %o3

	/*
	 * If we return from kmdb_dpi_handle_fault, the trap was due to a
	 * problem in the debugger, and the user has elected to diagnose it
	 * using the debugger.  When we pass back into the normal kaif_trap_obp
	 * flow, we'll save the debugger fault state over the state saved when
	 * we initially entered the debugger.  Debugger fault handling trashed
	 * the out registers, so we'll need to restore them before returning
	 * to the normal flow.
	 */

	set	kaif_cb_save, %g4
	ldx	[%g4 + KREG_OFF(KREG_O0)], %o0
	ldx	[%g4 + KREG_OFF(KREG_O1)], %o1
	ldx	[%g4 + KREG_OFF(KREG_O2)], %o2
	ldx	[%g4 + KREG_OFF(KREG_O3)], %o3
	ldx	[%g4 + KREG_OFF(KREG_O4)], %o4
	ldx	[%g4 + KREG_OFF(KREG_O5)], %o5
	ldx	[%g4 + KREG_OFF(KREG_O6)], %o6
	ldx	[%g4 + KREG_OFF(KREG_O7)], %o7

obp_normal_entry:

	set	1f, %g7
	set	kaif_cpusave_getaddr, %g6
	jmp	%g6
	nop
1:	/* CPU save area address is now in %g6 */
	add	%g6, KRS_GREGS + GREG_KREGS, %g5

	/*
	 * Register state has been saved in kaif_cb_save.  Now that we're sure
	 * we're going into the debugger using this state, copy it to the CPU-
	 * specific save area.
	 */

	set	kaif_cb_save, %g4
	add	%g4, KRS_GREGS + GREG_KREGS, %g3

	KAIF_COPY_KREG(%g3, %g5, KREG_PC, %g1)
	KAIF_COPY_KREG(%g3, %g5, KREG_NPC, %g1)
	KAIF_COPY_KREG(%g3, %g5, KREG_G1, %g1)
	KAIF_COPY_KREG(%g3, %g5, KREG_G2, %g1)
	KAIF_COPY_KREG(%g3, %g5, KREG_G3, %g1)
	KAIF_COPY_KREG(%g3, %g5, KREG_G4, %g1)
	KAIF_COPY_KREG(%g3, %g5, KREG_G5, %g1)
	KAIF_COPY_KREG(%g3, %g5, KREG_G6, %g1)
	KAIF_COPY_KREG(%g3, %g5, KREG_G7, %g1)
	KAIF_COPY_KREG(%g3, %g5, KREG_TT, %g1)

	ldx	[%g4 + KRS_TSTATE], %g1
	stx	%g1, [%g6 + KRS_TSTATE]

	/* A formality */
	mov	MMU_PCONTEXT, %g3
	ldxa	[%g3]ASI_MMU_CTX, %g2
	stx	%g2, [%g6 + KRS_MMU_PCONTEXT]

#ifndef sun4v
	/*
	 * If OBP supports preserving the Solaris kernel context register,
	 * then shift the nucleus bits into the primary and set context to 0,
	 * Otherwise, flush TLBs and clear the entire context register since
	 * OBP will clear it without flushing on entry to OBP.
	 */
	sethi	%hi(kmdb_prom_preserve_kctx), %g4
	ld	[%g4 + %lo(kmdb_prom_preserve_kctx)], %g4
	brz	%g4, 1f
	  nop
	/*
	 * Move nucleus context page size bits into primary context page size
	 * and set context to 0.  Use %g4 as a temporary.
	 */
	KAIF_MAKE_NEW_CTXREG(%g2, %g4)		! new context reg in %g2

	stxa	%g2, [%g3]ASI_MMU_CTX
	membar	#Sync
	ba	2f
	  nop
1:
#endif /* sun4v */
	/*
	 * Flush TLBs and clear primary context register.
	 */
	KAIF_DEMAP_TLB_ALL(%g4)
	stxa	%g0, [%g3]ASI_MMU_CTX	! ASI_MMU_CTX == ASI_DMMU for sun4u
	membar	#Sync
2:

	ba,a	kaif_trap_common

	SET_SIZE(kaif_trap_obp_saved)
	SET_SIZE(kaif_trap_obp)

#endif	/* __lint */

#if defined(lint)
void
kaif_dtrap_dprot(void)
{
}
#else   /* lint */

	/*
	 * This routine is used to handle all "failed" traps.  A trap is
	 * considered to have failed if it was not able to return to the code
	 * that caused the trap.  A DTLB miss handler, for example, fails if
	 * it can't find a translation for a given address.  Some traps always
	 * fail, because the thing that caused the trap is an actual problem
	 * that can't be resolved by the handler.  Examples of these include
	 * alignment and DTLB protection faults.
	 */

	ENTRY_NP(kaif_dtrap)

	SET_PSTATE_COMMON_AG(%g1);
	SET_GL(1);		/* set %gl = 1 */

	KAIF_CPU_GETADDR_TL1	/* uses label 1, %g1, %g2, %g7, ret in %g6 */

	ADVANCE_CRUMB_POINTER(%g6, %g1, %g2)
	ADD_CRUMB_CONST(%g6, KRM_SRC, KAIF_CRUMB_SRC_OBP, %g1, %g2)
	ADD_CRUMB_FLAG(%g6, KAIF_CRUMB_F_OBP_REVECT, %g1, %g2, %g3)

	rdpr	%tt, %g1
	ADD_CRUMB(%g6, KRM_TT, %g1, %g2)
	rdpr	%tpc, %g1
	ADD_CRUMB(%g6, KRM_PC, %g1, %g2)

	set	kaif_cb_save, %g6

	set	1f, %g7
	ba	kaif_save_tl1_state
	rdpr	%pstate, %g4

1:	wrpr	%g0, PTSTATE_KERN_COMMON, %pstate
	wrpr	%g0, %tl
	SET_GL(0);

	ba	kaif_trap_obp_saved
	nop

	SET_SIZE(kaif_dtrap)

#endif	/* lint */
