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
#include <sys/xc_impl.h>
#include <sys/intreg.h>
#include <sys/async.h>
#include <sys/clock.h>
#include <sys/cheetahasm.h>
#include <sys/cmpregs.h>

#ifdef TRAPTRACE
#include <sys/traptrace.h>
#endif /* TRAPTRACE */


	.global retire_l2_start
	.global retire_l2_end
	.global unretire_l2_start
	.global unretire_l2_end
	.global retire_l3_start
	.global retire_l3_end
	.global unretire_l3_start
	.global unretire_l3_end

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
6:									\
	cmp	scr2, %g0;						\
	bg,a	6b;							\
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


	.align 4096
	ENTRY(retire_l2)
retire_l2_start:

	! since we disable interrupts, we don't need to do kpreempt_disable()
	rdpr	%pstate, %o2
	andn	%o2, PSTATE_IE, %g1
	wrpr	%g0, %g1, %pstate		! disable interrupts
	/*
	 * Save current DCU state.  Turn off IPS
	 */
	setx	DCU_IPS_MASK, %g2, %o3
	ldxa	[%g0]ASI_DCU, %g1	! save DCU in %g1
	andn	%g1, %o3, %g4
	stxa	%g4, [%g0]ASI_DCU
	flush	%g0
	PARK_SIBLING_CORE(%g1, %o3, %o4)	! %g1 has DCU value
	clr	%o5	! assume success
8:
	PN_ECACHE_FLUSH_LINE(%o0, %o3, %o4, %g2, %g3)
1:
	! Check if line is invalid; if so, NA it.
	ldxa	[%o0]ASI_L2_TAG, %o3
	btst	0x7, %o3
	bnz	%xcc, 2f
	 nop
	stxa	%o1, [%o0]ASI_L2_TAG
	membar #Sync	! still on same cache line 
	! now delay 15 cycles so we don't have hazard when we return
	mov	16, %o1
1:
	brnz,pt	%o1, 1b
	 dec	%o1
9:
	! UNPARK-SIBLING_CORE is 7 instructions, so we cross a cache boundary
	UNPARK_SIBLING_CORE(%g1, %o3, %o4)	! 7 instructions
	/*
	 * Restore the DCU
	 */
	stxa	%g1, [%g0]ASI_DCU
	flush	%g0
	wrpr	%g0, %o2, %pstate		!restore pstate
	retl
	 mov	%o5, %o0
2:
	! It is OK to have STATE as NA (if so, nothing to do!)
	and	%o3, 0x7, %o3
	cmp	%o3, 0x5
	be,a,pt	%xcc, 9b
	 mov	1, %o5	! indicate was already NA
	! Hmm.	Not INV, not NA.
	cmp	%o5, 0
	be,a,pt	%xcc, 8b	! Flush the cacheline again
	 mov	2, %o5	! indicate retry was done
	! We already Flushed cacheline second time. Return -1
	clr	%o5
	ba	9b
	 dec	%o5
retire_l2_end:
	SET_SIZE(retire_l2)

	ENTRY(unretire_l2)
unretire_l2_start:

	! since we disable interrupts, we don't need to do kpreempt_disable()
	rdpr	%pstate, %o2
	andn	%o2, PSTATE_IE, %g1
	wrpr	%g0, %g1, %pstate		! disable interrupts
	/*
	 * Save current DCU state.  Turn off IPS
	 */
	setx	DCU_IPS_MASK, %g2, %o3
	ldxa	[%g0]ASI_DCU, %g1	! save DCU in %g1
	andn	%g1, %o3, %g4
	stxa	%g4, [%g0]ASI_DCU
	flush	%g0	/* flush required after changing the IC bit */
	PARK_SIBLING_CORE(%g1, %o3, %o4)	! %g1 has DCU value

	PN_ECACHE_FLUSH_LINE(%o0, %o3, %o4, %o5, %g2)
1:
	clr	%o5	! assume success
	! Check that line is in NA state; if so, INV it.
	ldxa	[%o0]ASI_L2_TAG, %o3
	and	%o3, 0x7, %o3
	cmp	%o3, 0x5
	bne,a,pt %xcc, 9f	! Wasn't NA, so something is wrong
	 dec	%o5	! indicate not NA
	stxa	%g0, [%o0]ASI_L2_TAG
	membar #Sync
	! now delay 15 cycles so we don't have hazard when we return
	mov	16, %o1
1:
	brnz,pt	%o1, 1b
	 dec	%o1
9:
	! UNPARK-SIBLING_CORE is 7 instructions
	UNPARK_SIBLING_CORE(%g1, %o3, %o4)	! 7 instructions
	/*
	 * Restore the DCU
	 */
	stxa	%g1, [%g0]ASI_DCU
	flush	%g0
	wrpr	%g0, %o2, %pstate		!restore pstate
	retl
	 mov	%o5, %o0
unretire_l2_end:
	SET_SIZE(unretire_l2)

	ENTRY(retire_l3)
retire_l3_start:

	! since we disable interrupts, we don't need to do kpreempt_disable()
	rdpr	%pstate, %o2
	andn	%o2, PSTATE_IE, %g1
	wrpr	%g0, %g1, %pstate		! disable interrupts
	/*
	 * Save current DCU state.  Turn off IPS
	 */
	setx	DCU_IPS_MASK, %g2, %o3
	ldxa	[%g0]ASI_DCU, %g1	! save DCU in %g1
	andn	%g1, %o3, %g4
	stxa	%g4, [%g0]ASI_DCU
	flush	%g0	/* flush required after changing the IC bit */
	PARK_SIBLING_CORE(%g1, %o3, %o4)	! %g1 has DCU value

	! PN-ECACHE-FLUSH_LINE is 30 instructions
	PN_ECACHE_FLUSH_LINE(%o0, %o3, %o4, %o5, %g2)
1:
	clr	%o5	! assume success
	! Check if line is invalid; if so, NA it.
	ldxa	[%o0]ASI_EC_DIAG, %o3
	btst	0x7, %o3
	bnz	%xcc, 2f
	 nop
	stxa	%o1, [%o0]ASI_EC_DIAG
	membar #Sync	! still on same cache line 
	! now delay 15 cycles so we don't have hazard when we return
	mov	16, %o1
1:
	brnz,pt	%o1, 1b
	 dec	%o1
9:
	! UNPARK-SIBLING_CORE is 7 instructions, so we cross a cache boundary
	UNPARK_SIBLING_CORE(%g1, %o3, %o4)	! 7 instructions
	/*
	 * Restore the DCU
	 */
	stxa	%g1, [%g0]ASI_DCU
	flush	%g0
	wrpr	%g0, %o2, %pstate		!restore pstate
	retl
	 mov	%o5, %o0
2:
	! It is OK to have STATE as NA (if so, nothing to do!)
	and	%o3, 0x7, %o3
	cmp	%o3, 0x5
	be,a,pt	%xcc, 9b
	 inc	%o5	! indicate was already NA
	! Hmm.	Not INV, not NA
	ba	9b
	 dec	%o5
retire_l3_end:
	SET_SIZE(retire_l3)

	ENTRY(unretire_l3)
unretire_l3_start:

	! since we disable interrupts, we don't need to do kpreempt_disable()
	rdpr	%pstate, %o2
	andn	%o2, PSTATE_IE, %g1
	wrpr	%g0, %g1, %pstate		! disable interrupts
	/*
	 * Save current DCU state.  Turn off IPS
	 */
	setx	DCU_IPS_MASK, %g2, %o3
	ldxa	[%g0]ASI_DCU, %g1	! save DCU in %g1
	andn	%g1, %o3, %g4
	stxa	%g4, [%g0]ASI_DCU
	flush	%g0	/* flush required after changing the IC bit */
	PARK_SIBLING_CORE(%g1, %o3, %o4)	! %g1 has DCU value

	PN_ECACHE_FLUSH_LINE(%o0, %o3, %o4, %o5, %g2)
1:
	clr	%o5	! assume success
	! Check that line is in NA state; if so, INV it.
	ldxa	[%o0]ASI_EC_DIAG, %o3
	and	%o3, 0x7, %o3
	cmp	%o3, 0x5
	bne,a,pt %xcc, 9f	! Wasn't NA, so something is wrong
	 dec	%o5	! indicate not NA
	stxa	%g0, [%o0]ASI_EC_DIAG
	membar #Sync
	! now delay 15 cycles so we don't have hazard when we return
	mov	16, %o1
1:
	brnz,pt	%o1, 1b
	 dec	%o1
9:
	! UNPARK-SIBLING_CORE is 7 instructions
	UNPARK_SIBLING_CORE(%g1, %o3, %o4)	! 7 instructions
	/*
	 * Restore the DCU
	 */
	stxa	%g1, [%g0]ASI_DCU
	flush	%g0
	wrpr	%g0, %o2, %pstate		!restore pstate
	retl
	 mov	%o5, %o0
unretire_l3_end:
	SET_SIZE(unretire_l3)

	.align 2048

	ENTRY(retire_l2_alternate)

	! since we disable interrupts, we don't need to do kpreempt_disable()
	rdpr	%pstate, %o2
	andn	%o2, PSTATE_IE, %g1
	wrpr	%g0, %g1, %pstate		! disable interrupts
	/*
	 * Save current DCU state.  Turn off IPS
	 */
	setx	DCU_IPS_MASK, %g2, %o3
	ldxa	[%g0]ASI_DCU, %g1	! save DCU in %g1
	andn	%g1, %o3, %g4
	stxa	%g4, [%g0]ASI_DCU
	flush	%g0
	PARK_SIBLING_CORE(%g1, %o3, %o4)	! %g1 has DCU value
	clr	%o5	! assume success
8:
	PN_ECACHE_FLUSH_LINE(%o0, %o3, %o4, %g2, %g3)
1:
	! Check if line is invalid; if so, NA it.
	ldxa	[%o0]ASI_L2_TAG, %o3
	btst	0x7, %o3
	bnz	%xcc, 2f
	 nop
	stxa	%o1, [%o0]ASI_L2_TAG
	membar #Sync	! still on same cache line 
	! now delay 15 cycles so we don't have hazard when we return
	mov	16, %o1
1:
	brnz,pt	%o1, 1b
	 dec	%o1
9:
	! UNPARK-SIBLING_CORE is 7 instructions, so we cross a cache boundary
	UNPARK_SIBLING_CORE(%g1, %o3, %o4)	! 7 instructions
	/*
	 * Restore the DCU
	 */
	stxa	%g1, [%g0]ASI_DCU
	flush	%g0
	wrpr	%g0, %o2, %pstate		!restore pstate
	retl
	 mov	%o5, %o0
2:
	! It is OK to have STATE as NA (if so, nothing to do!)
	and	%o3, 0x7, %o3
	cmp	%o3, 0x5
	be,a,pt	%xcc, 9b
	 mov	1, %o5	! indicate was already NA
	! Hmm.	Not INV, not NA.
	cmp	%o5, 0
	be,a,pt	%xcc, 8b	! Flush the cacheline again
	 mov	2, %o5	! indicate retry was done
	! We already Flushed cacheline second time. Return -1
	clr	%o5
	ba	9b
	 dec	%o5
	SET_SIZE(retire_l2_alternate)

	ENTRY(unretire_l2_alternate)

	! since we disable interrupts, we don't need to do kpreempt_disable()
	rdpr	%pstate, %o2
	andn	%o2, PSTATE_IE, %g1
	wrpr	%g0, %g1, %pstate		! disable interrupts
	/*
	 * Save current DCU state.  Turn off IPS
	 */
	setx	DCU_IPS_MASK, %g2, %o3
	ldxa	[%g0]ASI_DCU, %g1	! save DCU in %g1
	andn	%g1, %o3, %g4
	stxa	%g4, [%g0]ASI_DCU
	flush	%g0	/* flush required after changing the IC bit */
	PARK_SIBLING_CORE(%g1, %o3, %o4)	! %g1 has DCU value

	PN_ECACHE_FLUSH_LINE(%o0, %o3, %o4, %o5, %g2)
1:
	clr	%o5	! assume success
	! Check that line is in NA state; if so, INV it.
	ldxa	[%o0]ASI_L2_TAG, %o3
	and	%o3, 0x7, %o3
	cmp	%o3, 0x5
	bne,a,pt %xcc, 9f	! Wasn't NA, so something is wrong
	 dec	%o5	! indicate not NA
	stxa	%g0, [%o0]ASI_L2_TAG
	membar #Sync
	! now delay 15 cycles so we don't have hazard when we return
	mov	16, %o1
1:
	brnz,pt	%o1, 1b
	 dec	%o1
9:
	! UNPARK-SIBLING_CORE is 7 instructions
	UNPARK_SIBLING_CORE(%g1, %o3, %o4)	! 7 instructions
	/*
	 * Restore the DCU
	 */
	stxa	%g1, [%g0]ASI_DCU
	flush	%g0
	wrpr	%g0, %o2, %pstate		!restore pstate
	retl
	 mov	%o5, %o0
	SET_SIZE(unretire_l2_alternate)

	ENTRY(retire_l3_alternate)

	! since we disable interrupts, we don't need to do kpreempt_disable()
	rdpr	%pstate, %o2
	andn	%o2, PSTATE_IE, %g1
	wrpr	%g0, %g1, %pstate		! disable interrupts
	/*
	 * Save current DCU state.  Turn off IPS
	 */
	setx	DCU_IPS_MASK, %g2, %o3
	ldxa	[%g0]ASI_DCU, %g1	! save DCU in %g1
	andn	%g1, %o3, %g4
	stxa	%g4, [%g0]ASI_DCU
	flush	%g0	/* flush required after changing the IC bit */
	PARK_SIBLING_CORE(%g1, %o3, %o4)	! %g1 has DCU value

	! PN-ECACHE-FLUSH_LINE is 30 instructions
	PN_ECACHE_FLUSH_LINE(%o0, %o3, %o4, %o5, %g2)
1:
	clr	%o5	! assume success
	! Check if line is invalid; if so, NA it.
	ldxa	[%o0]ASI_EC_DIAG, %o3
	btst	0x7, %o3
	bnz	%xcc, 2f
	 nop
	stxa	%o1, [%o0]ASI_EC_DIAG
	membar #Sync	! still on same cache line 
	! now delay 15 cycles so we don't have hazard when we return
	mov	16, %o1
1:
	brnz,pt	%o1, 1b
	 dec	%o1
9:
	! UNPARK-SIBLING_CORE is 7 instructions, so we cross a cache boundary
	UNPARK_SIBLING_CORE(%g1, %o3, %o4)	! 7 instructions
	/*
	 * Restore the DCU
	 */
	stxa	%g1, [%g0]ASI_DCU
	flush	%g0
	wrpr	%g0, %o2, %pstate		!restore pstate
	retl
	 mov	%o5, %o0
2:
	! It is OK to have STATE as NA (if so, nothing to do!)
	and	%o3, 0x7, %o3
	cmp	%o3, 0x5
	be,a,pt	%xcc, 9b
	 inc	%o5	! indicate was already NA
	! Hmm.	Not INV, not NA
	ba	9b
	 dec	%o5
	SET_SIZE(retire_l3_alternate)

	ENTRY(unretire_l3_alternate)

	! since we disable interrupts, we don't need to do kpreempt_disable()
	rdpr	%pstate, %o2
	andn	%o2, PSTATE_IE, %g1
	wrpr	%g0, %g1, %pstate		! disable interrupts
	/*
	 * Save current DCU state.  Turn off IPS
	 */
	setx	DCU_IPS_MASK, %g2, %o3
	ldxa	[%g0]ASI_DCU, %g1	! save DCU in %g1
	andn	%g1, %o3, %g4
	stxa	%g4, [%g0]ASI_DCU
	flush	%g0	/* flush required after changing the IC bit */
	PARK_SIBLING_CORE(%g1, %o3, %o4)	! %g1 has DCU value

	PN_ECACHE_FLUSH_LINE(%o0, %o3, %o4, %o5, %g2)
1:
	clr	%o5	! assume success
	! Check that line is in NA state; if so, INV it.
	ldxa	[%o0]ASI_EC_DIAG, %o3
	and	%o3, 0x7, %o3
	cmp	%o3, 0x5
	bne,a,pt %xcc, 9f	! Wasn't NA, so something is wrong
	 dec	%o5	! indicate not NA
	stxa	%g0, [%o0]ASI_EC_DIAG
	membar #Sync
	! now delay 15 cycles so we don't have hazard when we return
	mov	16, %o1
1:
	brnz,pt	%o1, 1b
	 dec	%o1
9:
	! UNPARK-SIBLING_CORE is 7 instructions
	UNPARK_SIBLING_CORE(%g1, %o3, %o4)	! 7 instructions
	/*
	 * Restore the DCU
	 */
	stxa	%g1, [%g0]ASI_DCU
	flush	%g0
	wrpr	%g0, %o2, %pstate		!restore pstate
	retl
	 mov	%o5, %o0
	SET_SIZE(unretire_l3_alternate)

	ENTRY(get_ecache_dtags_tl1)


	PARK_SIBLING_CORE(%g3, %g4, %g5)	
	add	%g2, CH_CLO_DATA + CH_CHD_EC_DATA, %g2
	rd	%asi, %g4
	wr	%g0, ASI_N, %asi
	GET_ECACHE_DTAGS(%g1, %g2, %g5, %g6, %g7)
	wr	%g4, %asi
	UNPARK_SIBLING_CORE(%g3, %g4, %g5)	! can use %g3 again

	retry
	SET_SIZE(get_ecache_dtags_tl1)

	ENTRY(get_l2_tag_tl1)

	/*
	 * Now read the tag data
	 */
	ldxa	[%g1]ASI_L2_TAG, %g4		! save tag_data
	stx	%g4, [%g2]

	retry
	SET_SIZE(get_l2_tag_tl1)

	ENTRY(get_l3_tag_tl1)

	/*
	 * Now read the tag data
	 */
	ldxa	[%g1]ASI_EC_DIAG, %g4		! save tag_data
	stx	%g4, [%g2]

	retry
	SET_SIZE(get_l3_tag_tl1)

