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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Assembly code support for the Cheetah module
 */

#include "assym.h"

#include <sys/asm_linkage.h>
#include <sys/mmu.h>
#include <vm/hat_sfmmu.h>
#include <sys/machparam.h>
#include <sys/machcpuvar.h>
#include <sys/machthread.h>
#include <sys/machtrap.h>
#include <sys/privregs.h>
#include <sys/asm_linkage.h>
#include <sys/trap.h>
#include <sys/cheetahregs.h>
#include <sys/us3_module.h>
#include <sys/xc_impl.h>
#include <sys/intreg.h>
#include <sys/async.h>
#include <sys/clock.h>
#include <sys/cheetahasm.h>

#ifdef TRAPTRACE
#include <sys/traptrace.h>
#endif /* TRAPTRACE */

/* BEGIN CSTYLED */

/*
 * Cheetah version to flush an Ecache line by index (aliased address)
 */
#define	ECACHE_REFLUSH_LINE(ecache_size, alias_address, scr2)		\
	ldxa	[alias_address]ASI_MEM, %g0

#define	ECACHE_FLUSH_LINE(physaddr, ecache_size, scr1, scr2)		\
	xor	physaddr, ecache_size, scr1;				\
	add	ecache_size, ecache_size, scr2;				\
	sub	scr2, 1, scr2;						\
	and	scr1, scr2, scr1;					\
	ASM_LDX(scr2, ecache_flushaddr);				\
	add	scr1, scr2, scr1;					\
	ECACHE_REFLUSH_LINE(ecache_size, scr1, scr2)

/* END CSTYLED */


/*
 * Fast ECC error at TL>0 handler
 * We get here via trap 70 at TL>0->Software trap 0 at TL>0.  We enter
 * this routine with %g1 and %g2 already saved in %tpc, %tnpc and %tstate.
 * For a complete description of the Fast ECC at TL>0 handling see the
 * comment block "Cheetah/Cheetah+ Fast ECC at TL>0 trap strategy" in
 * us3_common_asm.s
 */

	.section ".text"
	.align	64
	ENTRY_NP(fast_ecc_tl1_err)

	/*
	 * This macro turns off the D$/I$ if they are on and saves their
	 * original state in ch_err_tl1_tmp, saves all the %g registers in the
	 * ch_err_tl1_data structure, updates the ch_err_tl1_flags and saves
	 * the %tpc in ch_err_tl1_tpc.  At the end of this macro, %g1 will
	 * point to the ch_err_tl1_data structure and the original D$/I$ state
	 * will be saved in ch_err_tl1_tmp.  All %g registers except for %g1
	 * will be available.
	 */
	CH_ERR_TL1_FECC_ENTER;

	/*
	 * Get the diagnostic logout data.  %g4 must be initialized to
	 * current CEEN state, %g5 must point to logout structure in
	 * ch_err_tl1_data_t.  %g3 will contain the nesting count upon
	 * return.
	 */
	ldxa	[%g0]ASI_ESTATE_ERR, %g4
	and	%g4, EN_REG_CEEN, %g4
	add	%g1, CH_ERR_TL1_LOGOUT, %g5
	DO_TL1_CPU_LOGOUT(%g3, %g2, %g4, %g5, %g6, %g3, %g4)

	/*
	 * If the logout nesting count is exceeded, we're probably
	 * not making any progress, try to panic instead.
	 */
	cmp	%g3, CLO_NESTING_MAX
	bge	fecc_tl1_err
	  nop

	/*
	 * Save the current CEEN and NCEEN state in %g7 and turn them off
	 * before flushing the Ecache.
	 */
	ldxa	[%g0]ASI_ESTATE_ERR, %g7
	andn	%g7, EN_REG_CEEN | EN_REG_NCEEN, %g5
	stxa	%g5, [%g0]ASI_ESTATE_ERR
	membar	#Sync

	/*
	 * Flush the Ecache, using the largest possible cache size with the
	 * smallest possible line size since we can't get the actual sizes
	 * from the cpu_node due to DTLB misses.
	 */
	set	CH_ECACHE_8M_SIZE, %g4
	set	CH_ECACHE_MIN_LSIZE, %g5

	/*
	 * Use a different flush address to avoid recursion if the error
	 * exists in ecache_flushaddr.
	 */
	ASM_LDX(%g6, ecache_tl1_flushaddr)
	cmp	%g6, -1		! check if address is valid
	be	%xcc, fecc_tl1_err
	  nop
	CH_ECACHE_FLUSHALL(%g4, %g5, %g6)

	/*
	 * Restore CEEN and NCEEN to the previous state.
	 */
	stxa	%g7, [%g0]ASI_ESTATE_ERR
	membar	#Sync

	/*
	 * If we turned off the D$, then flush it and turn it back on.
	 */
	ldxa	[%g1 + CH_ERR_TL1_TMP]%asi, %g3
	andcc	%g3, CH_ERR_TSTATE_DC_ON, %g0
	bz	%xcc, 3f
	  nop

	/*
	 * Flush the D$.
	 */
	ASM_LD(%g4, dcache_size)
	ASM_LD(%g5, dcache_linesize)
	CH_DCACHE_FLUSHALL(%g4, %g5, %g6)

	/*
	 * Turn the D$ back on.
	 */
	ldxa	[%g0]ASI_DCU, %g3
	or	%g3, DCU_DC, %g3
	stxa	%g3, [%g0]ASI_DCU
	membar	#Sync
3:
	/*
	 * If we turned off the I$, then flush it and turn it back on.
	 */
	ldxa	[%g1 + CH_ERR_TL1_TMP]%asi, %g3
	andcc	%g3, CH_ERR_TSTATE_IC_ON, %g0
	bz	%xcc, 4f
	  nop

	/*
	 * Flush the I$.
	 */
	ASM_LD(%g4, icache_size)
	ASM_LD(%g5, icache_linesize)
	CH_ICACHE_FLUSHALL(%g4, %g5, %g6, %g3)

	/*
	 * Turn the I$ back on.  Changing DCU_IC requires flush.
	 */
	ldxa	[%g0]ASI_DCU, %g3
	or	%g3, DCU_IC, %g3
	stxa	%g3, [%g0]ASI_DCU
	flush	%g0	
4:

#ifdef TRAPTRACE
	/*
	 * Get current trap trace entry physical pointer.
	 */
	CPU_INDEX(%g6, %g5)
	sll	%g6, TRAPTR_SIZE_SHIFT, %g6
	set	trap_trace_ctl, %g5
	add	%g6, %g5, %g6
	ld	[%g6 + TRAPTR_LIMIT], %g5
	tst	%g5
	be	%icc, skip_traptrace
	  nop
	ldx	[%g6 + TRAPTR_PBASE], %g5
	ld	[%g6 + TRAPTR_OFFSET], %g4
	add	%g5, %g4, %g5

	/*
	 * Create trap trace entry.
	 */
	rd	%asi, %g7
	wr	%g0, TRAPTR_ASI, %asi
	rd	STICK, %g4
	stxa	%g4, [%g5 + TRAP_ENT_TICK]%asi
	rdpr	%tl, %g4
	stha	%g4, [%g5 + TRAP_ENT_TL]%asi
	rdpr	%tt, %g4
	stha	%g4, [%g5 + TRAP_ENT_TT]%asi
	rdpr	%tpc, %g4
	stna	%g4, [%g5 + TRAP_ENT_TPC]%asi
	rdpr	%tstate, %g4
	stxa	%g4, [%g5 + TRAP_ENT_TSTATE]%asi
	stna	%sp, [%g5 + TRAP_ENT_SP]%asi
	stna	%g0, [%g5 + TRAP_ENT_TR]%asi
	wr	%g0, %g7, %asi
	ldxa	[%g1 + CH_ERR_TL1_SDW_AFAR]%asi, %g3
	ldxa	[%g1 + CH_ERR_TL1_SDW_AFSR]%asi, %g4
	wr	%g0, TRAPTR_ASI, %asi
	stna	%g3, [%g5 + TRAP_ENT_F1]%asi
	stna	%g4, [%g5 + TRAP_ENT_F2]%asi
	wr	%g0, %g7, %asi
	ldxa	[%g1 + CH_ERR_TL1_AFAR]%asi, %g3
	ldxa	[%g1 + CH_ERR_TL1_AFSR]%asi, %g4
	wr	%g0, TRAPTR_ASI, %asi
	stna	%g3, [%g5 + TRAP_ENT_F3]%asi
	stna	%g4, [%g5 + TRAP_ENT_F4]%asi
	wr	%g0, %g7, %asi

	/*
	 * Advance trap trace pointer.
	 */
	ld	[%g6 + TRAPTR_OFFSET], %g5
	ld	[%g6 + TRAPTR_LIMIT], %g4
	st	%g5, [%g6 + TRAPTR_LAST_OFFSET]
	add	%g5, TRAP_ENT_SIZE, %g5
	sub	%g4, TRAP_ENT_SIZE, %g4
	cmp	%g5, %g4
	movge	%icc, 0, %g5
	st	%g5, [%g6 + TRAPTR_OFFSET]
skip_traptrace:
#endif	/* TRAPTRACE */

	/*
	 * If nesting count is not zero, skip all the AFSR/AFAR
	 * handling and just do the necessary cache-flushing.
	 */
	ldxa	[%g1 + CH_ERR_TL1_NEST_CNT]%asi, %g2
	brnz	%g2, 6f
	  nop

	/*
	 * If a UCU followed by a WDU has occurred go ahead and panic
	 * since a UE will occur (on the retry) before the UCU and WDU
	 * messages are enqueued.
	 */
	ldxa	[%g1 + CH_ERR_TL1_AFSR]%asi, %g3
	set	1, %g4
	sllx	%g4, C_AFSR_UCU_SHIFT, %g4
	btst	%g4, %g3		! UCU in original AFSR?
	bz	%xcc, 6f
	  nop
	ldxa	[%g0]ASI_AFSR, %g4	! current AFSR
	or	%g3, %g4, %g3		! %g3 = original + current AFSR
	set	1, %g4
	sllx	%g4, C_AFSR_WDU_SHIFT, %g4
	btst	%g4, %g3		! WDU in original or current AFSR?
	bnz	%xcc, fecc_tl1_err
	  nop

6:
	/*
	 * We fall into this macro if we've successfully logged the error in
	 * the ch_err_tl1_data structure and want the PIL15 softint to pick
	 * it up and log it.  %g1 must point to the ch_err_tl1_data structure.
	 * Restores the %g registers and issues retry.
	 */
	CH_ERR_TL1_EXIT;

	/*
	 * Establish panic exit label.
	 */
	CH_ERR_TL1_PANIC_EXIT(fecc_tl1_err);

	SET_SIZE(fast_ecc_tl1_err)


/*
 * scrubphys - Pass in the aligned physical memory address
 * that you want to scrub, along with the ecache set size.
 *
 *	1) Displacement flush the E$ line corresponding to %addr.
 *	   The first ldxa guarantees that the %addr is no longer in
 *	   M, O, or E (goes to I or S (if instruction fetch also happens).
 *	2) "Write" the data using a CAS %addr,%g0,%g0.
 *	   The casxa guarantees a transition from I to M or S to M.
 *	3) Displacement flush the E$ line corresponding to %addr.
 *	   The second ldxa pushes the M line out of the ecache, into the
 *	   writeback buffers, on the way to memory.
 *	4) The "membar #Sync" pushes the cache line out of the writeback
 *	   buffers onto the bus, on the way to dram finally.
 *
 * This is a modified version of the algorithm suggested by Gary Lauterbach.
 * In theory the CAS %addr,%g0,%g0 is supposed to mark the addr's cache line
 * as modified, but then we found out that for spitfire, if it misses in the
 * E$ it will probably install as an M, but if it hits in the E$, then it
 * will stay E, if the store doesn't happen. So the first displacement flush
 * should ensure that the CAS will miss in the E$.  Arrgh.
 */
	ENTRY(scrubphys)
	rdpr	%pstate, %o4
	andn	%o4, PSTATE_IE | PSTATE_AM, %o5
	wrpr	%o5, %g0, %pstate	! clear IE, AM bits

	ECACHE_FLUSH_LINE(%o0, %o1, %o2, %o3)
	casxa	[%o0]ASI_MEM, %g0, %g0
	ECACHE_REFLUSH_LINE(%o1, %o2, %o3)

	wrpr	%g0, %o4, %pstate	! restore earlier pstate register value

	retl
	membar	#Sync			! move the data out of the load buffer
	SET_SIZE(scrubphys)


/*
 * clearphys - Pass in the physical memory address of the checkblock
 * that you want to push out, cleared with a recognizable pattern,
 * from the ecache.
 *
 * To ensure that the ecc gets recalculated after the bad data is cleared,
 * we must write out enough data to fill the w$ line (64 bytes). So we read
 * in an entire ecache subblock's worth of data, and write it back out.
 * Then we overwrite the 16 bytes of bad data with the pattern.
 */
	ENTRY(clearphys)
	/* turn off IE, AM bits */
	rdpr	%pstate, %o4
	andn	%o4, PSTATE_IE | PSTATE_AM, %o5
	wrpr	%o5, %g0, %pstate

	/* turn off NCEEN */
	ldxa	[%g0]ASI_ESTATE_ERR, %o5
	andn	%o5, EN_REG_NCEEN, %o3
	stxa	%o3, [%g0]ASI_ESTATE_ERR
	membar	#Sync

	/* align address passed with 64 bytes subblock size */
	mov	CH_ECACHE_SUBBLK_SIZE, %o2
	andn	%o0, (CH_ECACHE_SUBBLK_SIZE - 1), %g1

	/* move the good data into the W$ */
1:
	subcc	%o2, 8, %o2
	ldxa	[%g1 + %o2]ASI_MEM, %g2
	bge	1b
	  stxa	%g2, [%g1 + %o2]ASI_MEM

	/* now overwrite the bad data */
	setx	0xbadecc00badecc01, %g1, %g2
	stxa	%g2, [%o0]ASI_MEM
	mov	8, %g1
	stxa	%g2, [%o0 + %g1]ASI_MEM
	
	ECACHE_FLUSH_LINE(%o0, %o1, %o2, %o3)
	casxa	[%o0]ASI_MEM, %g0, %g0
	ECACHE_REFLUSH_LINE(%o1, %o2, %o3)

	/* clear the AFSR */
	ldxa	[%g0]ASI_AFSR, %o1
	stxa	%o1, [%g0]ASI_AFSR
	membar	#Sync

	/* turn NCEEN back on */
	stxa	%o5, [%g0]ASI_ESTATE_ERR
	membar	#Sync

	/* return and re-enable IE and AM */
	retl
	  wrpr	%g0, %o4, %pstate
	SET_SIZE(clearphys)


/*
 * Cheetah Ecache displacement flush the specified line from the E$
 *
 * Register usage:
 *	%o0 - 64 bit physical address for flushing
 *	%o1 - Ecache set size
 */
	ENTRY(ecache_flush_line)

	ECACHE_FLUSH_LINE(%o0, %o1, %o2, %o3)

	retl
	  nop
	SET_SIZE(ecache_flush_line)

/*
 * This routine will not be called in Cheetah systems.
 */
	ENTRY(flush_ipb)
	retl
	nop
	SET_SIZE(flush_ipb)

