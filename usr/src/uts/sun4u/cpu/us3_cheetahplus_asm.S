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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Assembly code support for the Cheetah+ module
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
#include <sys/cmpregs.h>

#ifdef TRAPTRACE
#include <sys/traptrace.h>
#endif /* TRAPTRACE */


/* BEGIN CSTYLED */

/*
 * Cheetah+ version to reflush an Ecache line by index.
 *
 * By default we assume the Ecache is 2-way so we flush both
 * ways. Even if the cache is direct-mapped no harm will come
 * from performing the flush twice, apart from perhaps a performance
 * penalty.
 *
 * XXX - scr2 not used.
 */
#define	ECACHE_REFLUSH_LINE(ec_set_size, index, scr2)			\
	ldxa	[index]ASI_EC_DIAG, %g0;				\
	ldxa	[index + ec_set_size]ASI_EC_DIAG, %g0;

/*
 * Cheetah+ version of ecache_flush_line.  Uses Cheetah+ Ecache Displacement
 * Flush feature.
 */
#define	ECACHE_FLUSH_LINE(physaddr, ec_set_size, scr1, scr2)		\
	sub	ec_set_size, 1, scr1;					\
	and	physaddr, scr1, scr1;					\
	set	CHP_ECACHE_IDX_DISP_FLUSH, scr2;			\
	or	scr2, scr1, scr1;					\
	ECACHE_REFLUSH_LINE(ec_set_size, scr1, scr2)

/* END CSTYLED */

/*
 * Panther version to reflush a line from both the L2 cache and L3
 * cache by the respective indexes. Flushes all ways of the line from
 * each cache.
 *
 * l2_index	Index into the L2$ of the line to be flushed. This
 *		register will not be modified by this routine.
 * l3_index	Index into the L3$ of the line to be flushed. This
 *		register will not be modified by this routine.
 * scr2		scratch register.
 * scr3		scratch register.
 *
 */
#define	PN_ECACHE_REFLUSH_LINE(l2_index, l3_index, scr2, scr3)		\
	set	PN_L2_MAX_SET, scr2;					\
	set	PN_L2_SET_SIZE, scr3;					\
1:									\
	ldxa	[l2_index + scr2]ASI_L2_TAG, %g0;			\
	cmp	scr2, %g0;						\
	bg,a	1b;							\
	  sub	scr2, scr3, scr2;					\
	mov	6, scr2;						\
7:									\
	cmp	scr2, %g0;						\
	bg,a	7b;							\
	  sub	scr2, 1, scr2;						\
	set	PN_L3_MAX_SET, scr2;					\
	set	PN_L3_SET_SIZE, scr3;					\
2:									\
	ldxa	[l3_index + scr2]ASI_EC_DIAG, %g0;			\
	cmp	scr2, %g0;						\
	bg,a	2b;							\
	  sub	scr2, scr3, scr2;

/*
 * Panther version of ecache_flush_line. Flushes the line corresponding
 * to physaddr from both the L2 cache and the L3 cache.
 *
 * physaddr	Input: Physical address to flush.
 *              Output: Physical address to flush (preserved).
 * l2_idx_out	Input: scratch register.
 *              Output: Index into the L2$ of the line to be flushed.
 * l3_idx_out	Input: scratch register.
 *              Output: Index into the L3$ of the line to be flushed.
 * scr3		scratch register.
 * scr4		scratch register.
 *
 */
#define	PN_ECACHE_FLUSH_LINE(physaddr, l2_idx_out, l3_idx_out, scr3, scr4)	\
	set	PN_L3_SET_SIZE, l2_idx_out;					\
	sub	l2_idx_out, 1, l2_idx_out;					\
	and	physaddr, l2_idx_out, l3_idx_out;				\
	set	PN_L3_IDX_DISP_FLUSH, l2_idx_out;				\
	or	l2_idx_out, l3_idx_out, l3_idx_out;				\
	set	PN_L2_SET_SIZE, l2_idx_out;					\
	sub	l2_idx_out, 1, l2_idx_out;					\
	and	physaddr, l2_idx_out, l2_idx_out;				\
	set	PN_L2_IDX_DISP_FLUSH, scr3;					\
	or	l2_idx_out, scr3, l2_idx_out;					\
	PN_ECACHE_REFLUSH_LINE(l2_idx_out, l3_idx_out, scr3, scr4)

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
	PN_L2_FLUSHALL(%g3, %g4, %g5)

	set	CH_ECACHE_MAX_SIZE, %g4
	set	CH_ECACHE_MIN_LSIZE, %g5

	GET_CPU_IMPL(%g6)
	cmp	%g6, PANTHER_IMPL
	bne	%xcc, 2f
	  nop
	set	PN_L3_SIZE, %g4
2:
	mov	%g6, %g3
	CHP_ECACHE_FLUSHALL(%g4, %g5, %g3)

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
	 * Flush the I$.  Panther has different I$ parameters, and we
	 * can't access the logout I$ params without possibly generating
	 * a MMU miss.
	 */
	GET_CPU_IMPL(%g6)
	set	PN_ICACHE_SIZE, %g3
	set	CH_ICACHE_SIZE, %g4
	mov	CH_ICACHE_LSIZE, %g5
	cmp	%g6, PANTHER_IMPL
	movz	%xcc, %g3, %g4
	movz	%xcc, PN_ICACHE_LSIZE, %g5
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
	 * If a UCU or L3_UCU followed by a WDU has occurred go ahead
	 * and panic since a UE will occur (on the retry) before the
	 * UCU and WDU messages are enqueued.  On a Panther processor,
	 * we need to also see an L3_WDU before panicking.  Note that
	 * we avoid accessing the _EXT ASIs if not on a Panther.
	 */
	ldxa	[%g1 + CH_ERR_TL1_SDW_AFSR]%asi, %g3
	set	1, %g4
	sllx	%g4, C_AFSR_UCU_SHIFT, %g4
	btst	%g4, %g3		! UCU in original shadow AFSR?
	bnz	%xcc, 5f
	  nop
	GET_CPU_IMPL(%g6)
	cmp	%g6, PANTHER_IMPL
	bne	%xcc, 6f		! not Panther, no UCU, skip the rest
	  nop
	ldxa	[%g1 + CH_ERR_TL1_SDW_AFSR_EXT]%asi, %g3
	btst	C_AFSR_L3_UCU, %g3	! L3_UCU in original shadow AFSR_EXT?
	bz	%xcc, 6f		! neither UCU nor L3_UCU was seen
	  nop
5:
	ldxa	[%g1 + CH_ERR_TL1_AFSR]%asi, %g4	! original AFSR
	ldxa	[%g0]ASI_AFSR, %g3	! current AFSR
	or	%g3, %g4, %g3		! %g3 = original + current AFSR
	set	1, %g4
	sllx	%g4, C_AFSR_WDU_SHIFT, %g4
	btst	%g4, %g3		! WDU in original or current AFSR?
	bz	%xcc, 6f                ! no WDU, skip remaining tests
	  nop
	GET_CPU_IMPL(%g6)
	cmp	%g6, PANTHER_IMPL
	bne	%xcc, fecc_tl1_err	! if not Panther, panic (saw UCU, WDU)
	  nop
	ldxa	[%g1 + CH_ERR_TL1_SDW_AFSR_EXT]%asi, %g4 ! original AFSR_EXT
	set	ASI_AFSR_EXT_VA, %g6	! ASI of current AFSR_EXT
	ldxa	[%g6]ASI_AFSR, %g3	! value of current AFSR_EXT
	or	%g3, %g4, %g3		! %g3 = original + current AFSR_EXT
	btst	C_AFSR_L3_WDU, %g3	! L3_WDU in original or current AFSR?
	bnz	%xcc, fecc_tl1_err	! panic (saw L3_WDU and UCU or L3_UCU)
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

	GET_CPU_IMPL(%o5)		! Panther Ecache is flushed differently
	cmp	%o5, PANTHER_IMPL
	bne	scrubphys_1
	  nop
	PN_ECACHE_FLUSH_LINE(%o0, %o1, %o2, %o3, %o5)
	casxa	[%o0]ASI_MEM, %g0, %g0
	PN_ECACHE_REFLUSH_LINE(%o1, %o2, %o3, %o0)
	b	scrubphys_2
	  nop
scrubphys_1:
	ECACHE_FLUSH_LINE(%o0, %o1, %o2, %o3)
	casxa	[%o0]ASI_MEM, %g0, %g0
	ECACHE_REFLUSH_LINE(%o1, %o2, %o3)
scrubphys_2:
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
clearphys_1:
	subcc	%o2, 8, %o2
	ldxa	[%g1 + %o2]ASI_MEM, %g2
	bge	clearphys_1
	  stxa	%g2, [%g1 + %o2]ASI_MEM

	/* now overwrite the bad data */
	setx	0xbadecc00badecc01, %g1, %g2
	stxa	%g2, [%o0]ASI_MEM
	mov	8, %g1
	stxa	%g2, [%o0 + %g1]ASI_MEM

	GET_CPU_IMPL(%o3)		! Panther Ecache is flushed differently
	cmp	%o3, PANTHER_IMPL
	bne	clearphys_2
	  nop
	PN_ECACHE_FLUSH_LINE(%o0, %o1, %o2, %o3, %g1)
	casxa	[%o0]ASI_MEM, %g0, %g0
	PN_ECACHE_REFLUSH_LINE(%o1, %o2, %o3, %o0)
	b	clearphys_3
	  nop
clearphys_2:
	ECACHE_FLUSH_LINE(%o0, %o1, %o2, %o3)
	casxa	[%o0]ASI_MEM, %g0, %g0
	ECACHE_REFLUSH_LINE(%o1, %o2, %o3)
clearphys_3:
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
 * Cheetah+ Ecache displacement flush the specified line from the E$
 *
 * For Panther, this means flushing the specified line from both the
 * L2 cache and L3 cache.
 *
 * Register usage:
 *	%o0 - 64 bit physical address for flushing
 *	%o1 - Ecache set size
 */
	ENTRY(ecache_flush_line)

	GET_CPU_IMPL(%o3)		! Panther Ecache is flushed differently
	cmp	%o3, PANTHER_IMPL
	bne	ecache_flush_line_1
	  nop

	PN_ECACHE_FLUSH_LINE(%o0, %o1, %o2, %o3, %o4)
	b	ecache_flush_line_2
	  nop
ecache_flush_line_1:
	ECACHE_FLUSH_LINE(%o0, %o1, %o2, %o3)
ecache_flush_line_2:
	retl
	  nop
	SET_SIZE(ecache_flush_line)

	ENTRY(set_afsr_ext)
	set	ASI_AFSR_EXT_VA, %o1
	stxa	%o0, [%o1]ASI_AFSR		! afsr_ext reg
	membar	#Sync
	retl
	nop
	SET_SIZE(set_afsr_ext)


/*
 * The CPU jumps here from the MMU exception handler if an ITLB parity
 * error is detected and we are running on Panther.
 *
 * In this routine we collect diagnostic information and write it to our
 * logout structure (if possible) and clear all ITLB entries that may have
 * caused our parity trap.
 * Then we call cpu_tlb_parity_error via systrap in order to drop down to TL0
 * and log any error messages. As for parameters to cpu_tlb_parity_error, we
 * send two:
 *
 * %g2	- Contains the VA whose lookup in the ITLB caused the parity error
 * %g3	- Contains the tlo_info field of the pn_tlb_logout logout struct,
 *	  regardless of whether or not we actually used the logout struct.
 *
 * In the TL0 handler (cpu_tlb_parity_error) we will compare those two
 * parameters to the data contained in the logout structure in order to
 * determine whether the logout information is valid for this particular
 * error or not.
 */
	ENTRY_NP(itlb_parity_trap)
	/*
	 * Collect important information about the trap which will be
	 * used as a parameter to the TL0 handler.
	 */
	wr	%g0, ASI_IMMU, %asi
	rdpr	%tpc, %g2			! VA that caused the IMMU trap
	ldxa	[MMU_TAG_ACCESS_EXT]%asi, %g3	! read the trap VA page size
	set	PN_ITLB_PGSZ_MASK, %g4
	and	%g3, %g4, %g3
	ldxa	[MMU_TAG_ACCESS]%asi, %g4
	set	TAGREAD_CTX_MASK, %g5
	and	%g4, %g5, %g4
	or	%g4, %g3, %g3			! 'or' in the trap context and
	mov	1, %g4				! add the IMMU flag to complete
	sllx	%g4, PN_TLO_INFO_IMMU_SHIFT, %g4
	or	%g4, %g3, %g3			! the tlo_info field for logout
	stxa	%g0,[MMU_SFSR]%asi		! clear the SFSR
	membar	#Sync

	/*
	 * at this point:
	 *    %g2 - contains the VA whose lookup caused the trap
	 *    %g3 - contains the tlo_info field
	 *
	 * Next, we calculate the TLB index value for the failing VA.
	 */
	mov	%g2, %g4			! We need the ITLB index
	set	PN_ITLB_PGSZ_MASK, %g5
	and	%g3, %g5, %g5
	srlx	%g5, PN_ITLB_PGSZ_SHIFT, %g5
	PN_GET_TLB_INDEX(%g4, %g5)		! %g4 has the index
	sllx	%g4, PN_TLB_ACC_IDX_SHIFT, %g4	! shift the index into place
	set	PN_ITLB_T512, %g5
	or	%g4, %g5, %g4			! and add in the TLB ID

	/*
	 * at this point:
	 *    %g2 - contains the VA whose lookup caused the trap
	 *    %g3 - contains the tlo_info field
	 *    %g4 - contains the TLB access index value for the
	 *          VA/PgSz in question
	 *
	 * Check to see if the logout structure is available.
	 */
	set	CHPR_TLB_LOGOUT, %g6
	GET_CPU_PRIVATE_PTR(%g6, %g1, %g5, itlb_parity_trap_1)
	set	LOGOUT_INVALID_U32, %g6
	sllx	%g6, 32, %g6			! if our logout structure is
	set	LOGOUT_INVALID_L32, %g5		! unavailable or if it is
	or	%g5, %g6, %g5			! already being used, then we
	ldx	[%g1 + PN_TLO_ADDR], %g6	! don't collect any diagnostic
	cmp	%g6, %g5			! information before clearing
	bne	itlb_parity_trap_1		! and logging the error.
	  nop

	/*
	 * Record the logout information. %g4 contains our index + TLB ID
	 * for use in ASI_ITLB_ACCESS and ASI_ITLB_TAGREAD. %g1 contains
	 * the pointer to our logout struct.
	 */
	stx	%g3, [%g1 + PN_TLO_INFO]
	stx	%g2, [%g1 + PN_TLO_ADDR]
	stx	%g2, [%g1 + PN_TLO_PC]		! %tpc == fault addr for IMMU

	add	%g1, PN_TLO_ITLB_TTE, %g1	! move up the pointer

	ldxa	[%g4]ASI_ITLB_ACCESS, %g5	! read the data
	stx	%g5, [%g1 + CH_TLO_TTE_DATA]	! store it away
	ldxa	[%g4]ASI_ITLB_TAGREAD, %g5	! read the tag
	stx	%g5, [%g1 + CH_TLO_TTE_TAG]	! store it away

	set	PN_TLB_ACC_WAY_BIT, %g6		! same thing again for way 1
	or	%g4, %g6, %g4
	add	%g1, CH_TLO_TTE_SIZE, %g1	! move up the pointer

	ldxa	[%g4]ASI_ITLB_ACCESS, %g5	! read the data
	stx	%g5, [%g1 + CH_TLO_TTE_DATA]	! store it away
	ldxa	[%g4]ASI_ITLB_TAGREAD, %g5	! read the tag
	stx	%g5, [%g1 + CH_TLO_TTE_TAG]	! store it away

	andn	%g4, %g6, %g4			! back to way 0

itlb_parity_trap_1:
	/*
	 * at this point:
	 *    %g2 - contains the VA whose lookup caused the trap
	 *    %g3 - contains the tlo_info field
	 *    %g4 - contains the TLB access index value for the
	 *          VA/PgSz in question
	 *
	 * Here we will clear the errors from the TLB.
	 */
	set	MMU_TAG_ACCESS, %g5		! We write a TTE tag value of
	stxa	%g0, [%g5]ASI_IMMU		! 0 as it will be invalid.
	stxa	%g0, [%g4]ASI_ITLB_ACCESS	! Write the data and tag
	membar	#Sync

	set	PN_TLB_ACC_WAY_BIT, %g6		! same thing again for way 1
	or	%g4, %g6, %g4

	stxa	%g0, [%g4]ASI_ITLB_ACCESS	! Write same data and tag
	membar	#Sync

	sethi	%hi(FLUSH_ADDR), %g6		! PRM says we need to issue a
	flush   %g6				! flush after writing MMU regs

	/*
	 * at this point:
	 *    %g2 - contains the VA whose lookup caused the trap
	 *    %g3 - contains the tlo_info field
	 *
	 * Call cpu_tlb_parity_error via systrap at PIL 14 unless we're
	 * already at PIL 15.	 */
	set	cpu_tlb_parity_error, %g1
	rdpr	%pil, %g4
	cmp	%g4, PIL_14
	movl	%icc, PIL_14, %g4
	ba	sys_trap
	  nop
	SET_SIZE(itlb_parity_trap)

/*
 * The CPU jumps here from the MMU exception handler if a DTLB parity
 * error is detected and we are running on Panther.
 *
 * In this routine we collect diagnostic information and write it to our
 * logout structure (if possible) and clear all DTLB entries that may have
 * caused our parity trap.
 * Then we call cpu_tlb_parity_error via systrap in order to drop down to TL0
 * and log any error messages. As for parameters to cpu_tlb_parity_error, we
 * send two:
 *
 * %g2	- Contains the VA whose lookup in the DTLB caused the parity error
 * %g3	- Contains the tlo_info field of the pn_tlb_logout logout struct,
 *	  regardless of whether or not we actually used the logout struct.
 *
 * In the TL0 handler (cpu_tlb_parity_error) we will compare those two
 * parameters to the data contained in the logout structure in order to
 * determine whether the logout information is valid for this particular
 * error or not.
 */
	ENTRY_NP(dtlb_parity_trap)
	/*
	 * Collect important information about the trap which will be
	 * used as a parameter to the TL0 handler.
	 */
	wr	%g0, ASI_DMMU, %asi
	ldxa	[MMU_SFAR]%asi, %g2		! VA that caused the IMMU trap
	ldxa	[MMU_TAG_ACCESS_EXT]%asi, %g3	! read the trap VA page sizes
	set	PN_DTLB_PGSZ_MASK, %g4
	and	%g3, %g4, %g3
	ldxa	[MMU_TAG_ACCESS]%asi, %g4
	set	TAGREAD_CTX_MASK, %g5		! 'or' in the trap context
	and	%g4, %g5, %g4			! to complete the tlo_info
	or	%g4, %g3, %g3			! field for logout
	stxa	%g0,[MMU_SFSR]%asi		! clear the SFSR
	membar	#Sync

	/*
	 * at this point:
	 *    %g2 - contains the VA whose lookup caused the trap
	 *    %g3 - contains the tlo_info field
	 *
	 * Calculate the TLB index values for the failing VA. Since the T512
	 * TLBs can be configured for different page sizes, we need to find
	 * the index into each one separately.
	 */
	mov	%g2, %g4			! First we get the DTLB_0 index
	set	PN_DTLB_PGSZ0_MASK, %g5
	and	%g3, %g5, %g5
	srlx	%g5, PN_DTLB_PGSZ0_SHIFT, %g5
	PN_GET_TLB_INDEX(%g4, %g5)		! %g4 has the DTLB_0 index
	sllx	%g4, PN_TLB_ACC_IDX_SHIFT, %g4	! shift the index into place
	set	PN_DTLB_T512_0, %g5
	or	%g4, %g5, %g4			! and add in the TLB ID

	mov	%g2, %g7			! Next we get the DTLB_1 index
	set	PN_DTLB_PGSZ1_MASK, %g5
	and	%g3, %g5, %g5
	srlx	%g5, PN_DTLB_PGSZ1_SHIFT, %g5
	PN_GET_TLB_INDEX(%g7, %g5)		! %g7 has the DTLB_1 index
	sllx	%g7, PN_TLB_ACC_IDX_SHIFT, %g7	! shift the index into place
	set	PN_DTLB_T512_1, %g5
	or	%g7, %g5, %g7			! and add in the TLB ID

	/*
	 * at this point:
	 *    %g2 - contains the VA whose lookup caused the trap
	 *    %g3 - contains the tlo_info field
	 *    %g4 - contains the T512_0 access index value for the
	 *          VA/PgSz in question
	 *    %g7 - contains the T512_1 access index value for the
	 *          VA/PgSz in question
	 *
	 * If this trap happened at TL>0, then we don't want to mess
	 * with the normal logout struct since that could caused a TLB
	 * miss.
	 */
	rdpr	%tl, %g6			! read current trap level
	cmp	%g6, 1				! skip over the tl>1 code
	ble	dtlb_parity_trap_1		! if TL <= 1.
	  nop

	/*
	 * If we are here, then the trap happened at TL>1. Simply
	 * update our tlo_info field and then skip to the TLB flush
	 * code.
	 */
	mov	1, %g6
	sllx	%g6, PN_TLO_INFO_TL1_SHIFT, %g6
	or	%g6, %g3, %g3
	ba	dtlb_parity_trap_2
	  nop

dtlb_parity_trap_1:
	/*
	 * at this point:
	 *    %g2 - contains the VA whose lookup caused the trap
	 *    %g3 - contains the tlo_info field
	 *    %g4 - contains the T512_0 access index value for the
	 *          VA/PgSz in question
	 *    %g7 - contains the T512_1 access index value for the
	 *          VA/PgSz in question
	 *
	 * Check to see if the logout structure is available.
	 */
	set	CHPR_TLB_LOGOUT, %g6
	GET_CPU_PRIVATE_PTR(%g6, %g1, %g5, dtlb_parity_trap_2)
	set	LOGOUT_INVALID_U32, %g6
	sllx	%g6, 32, %g6			! if our logout structure is
	set	LOGOUT_INVALID_L32, %g5		! unavailable or if it is
	or	%g5, %g6, %g5			! already being used, then we
	ldx	[%g1 + PN_TLO_ADDR], %g6	! don't collect any diagnostic
	cmp	%g6, %g5			! information before clearing
	bne	dtlb_parity_trap_2		! and logging the error.
	  nop

	/*
	 * Record the logout information. %g4 contains our DTLB_0
	 * index + TLB ID and %g7 contains our DTLB_1 index + TLB ID
	 * both of which will be used for ASI_DTLB_ACCESS and
	 * ASI_DTLB_TAGREAD. %g1 contains the pointer to our logout
	 * struct.
	 */
	stx	%g3, [%g1 + PN_TLO_INFO]
	stx	%g2, [%g1 + PN_TLO_ADDR]
	rdpr	%tpc, %g5
	stx	%g5, [%g1 + PN_TLO_PC]

	add	%g1, PN_TLO_DTLB_TTE, %g1	! move up the pointer

	ldxa	[%g4]ASI_DTLB_ACCESS, %g5	! read the data from DTLB_0
	stx	%g5, [%g1 + CH_TLO_TTE_DATA]	! way 0 and store it away
	ldxa	[%g4]ASI_DTLB_TAGREAD, %g5	! read the tag from DTLB_0
	stx	%g5, [%g1 + CH_TLO_TTE_TAG]	! way 0 and store it away

	ldxa	[%g7]ASI_DTLB_ACCESS, %g5	! now repeat for DTLB_1 way 0
	stx	%g5, [%g1 + (CH_TLO_TTE_DATA + (CH_TLO_TTE_SIZE * 2))]
	ldxa	[%g7]ASI_DTLB_TAGREAD, %g5
	stx	%g5, [%g1 + (CH_TLO_TTE_TAG + (CH_TLO_TTE_SIZE * 2))]

	set	PN_TLB_ACC_WAY_BIT, %g6		! same thing again for way 1
	or	%g4, %g6, %g4			! of each TLB.
	or	%g7, %g6, %g7
	add	%g1, CH_TLO_TTE_SIZE, %g1	! move up the pointer

	ldxa	[%g4]ASI_DTLB_ACCESS, %g5	! read the data from DTLB_0
	stx	%g5, [%g1 + CH_TLO_TTE_DATA]	! way 1 and store it away
	ldxa	[%g4]ASI_DTLB_TAGREAD, %g5	! read the tag from DTLB_0
	stx	%g5, [%g1 + CH_TLO_TTE_TAG]	! way 1 and store it away

	ldxa	[%g7]ASI_DTLB_ACCESS, %g5	! now repeat for DTLB_1 way 1
	stx	%g5, [%g1 + (CH_TLO_TTE_DATA + (CH_TLO_TTE_SIZE * 2))]
	ldxa	[%g7]ASI_DTLB_TAGREAD, %g5
	stx	%g5, [%g1 + (CH_TLO_TTE_TAG + (CH_TLO_TTE_SIZE * 2))]

	andn	%g4, %g6, %g4			! back to way 0
	andn	%g7, %g6, %g7			! back to way 0

dtlb_parity_trap_2:
	/*
	 * at this point:
	 *    %g2 - contains the VA whose lookup caused the trap
	 *    %g3 - contains the tlo_info field
	 *    %g4 - contains the T512_0 access index value for the
	 *          VA/PgSz in question
	 *    %g7 - contains the T512_1 access index value for the
	 *          VA/PgSz in question
	 *
	 * Here we will clear the errors from the DTLB.
	 */
	set	MMU_TAG_ACCESS, %g5		! We write a TTE tag value of
	stxa	%g0, [%g5]ASI_DMMU		! 0 as it will be invalid.
	stxa	%g0, [%g4]ASI_DTLB_ACCESS	! Write the data and tag.
	stxa	%g0, [%g7]ASI_DTLB_ACCESS	! Now repeat for DTLB_1 way 0
	membar	#Sync

	set	PN_TLB_ACC_WAY_BIT, %g6		! same thing again for way 1
	or	%g4, %g6, %g4
	or	%g7, %g6, %g7

	stxa	%g0, [%g4]ASI_DTLB_ACCESS	! Write same data and tag.
	stxa	%g0, [%g7]ASI_DTLB_ACCESS	! Now repeat for DTLB_1 way 0
	membar	#Sync

	sethi	%hi(FLUSH_ADDR), %g6		! PRM says we need to issue a
	flush   %g6				! flush after writing MMU regs

	/*
	 * at this point:
	 *    %g2 - contains the VA whose lookup caused the trap
	 *    %g3 - contains the tlo_info field
	 *
	 * Call cpu_tlb_parity_error via systrap at PIL 14 unless we're
	 * already at PIL 15. We do this even for TL>1 traps since
	 * those will lead to a system panic.
	 */
	set	cpu_tlb_parity_error, %g1
	rdpr	%pil, %g4
	cmp	%g4, PIL_14
	movl	%icc, PIL_14, %g4
	ba	sys_trap
	  nop
	SET_SIZE(dtlb_parity_trap)


/*
 * Calculates the Panther TLB index based on a virtual address and page size
 *
 * Register usage:
 *	%o0 - virtual address whose index we want
 *	%o1 - Page Size of the TLB in question as encoded in the
 *	      ASI_[D|I]MMU_TAG_ACCESS_EXT register.
 */
	ENTRY(pn_get_tlb_index)

	PN_GET_TLB_INDEX(%o0, %o1)

	retl
	  nop
	SET_SIZE(pn_get_tlb_index)


/*
 * For Panther CPUs we need to flush the IPB after any I$ or D$
 * parity errors are detected.
 */
	ENTRY(flush_ipb)
	clr	%o0

flush_ipb_1:
	stxa	%g0, [%o0]ASI_IPB_TAG
	membar	#Sync
	cmp	%o0, PN_IPB_TAG_ADDR_MAX
	blt	flush_ipb_1
	  add	%o0, PN_IPB_TAG_ADDR_LINESIZE, 	%o0

	sethi	%hi(FLUSH_ADDR), %o0
	flush   %o0
	retl
	nop
	SET_SIZE(flush_ipb)


