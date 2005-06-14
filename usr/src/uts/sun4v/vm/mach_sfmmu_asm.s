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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * SFMMU primitives.  These primitives should only be used by sfmmu
 * routines.
 */

#if defined(lint)
#include <sys/types.h>
#else	/* lint */
#include "assym.h"
#endif	/* lint */

#include <sys/asm_linkage.h>
#include <sys/machtrap.h>
#include <sys/machasi.h>
#include <sys/sun4asi.h>
#include <sys/pte.h>
#include <sys/mmu.h>
#include <vm/hat_sfmmu.h>
#include <vm/seg_spt.h>
#include <sys/machparam.h>
#include <sys/privregs.h>
#include <sys/scb.h>
#include <sys/intreg.h>
#include <sys/machthread.h>
#include <sys/clock.h>
#include <sys/trapstat.h>

/*
 * sfmmu related subroutines
 */

#if defined (lint)

/* ARGSUSED */
void
sfmmu_ctx_steal_tl1(uint64_t sctx, uint64_t rctx)
{}

/* ARGSUSED */
void
sfmmu_raise_tsb_exception(uint64_t sctx, uint64_t rctx)
{}

int
sfmmu_getctx_pri()
{ return(0); }

int
sfmmu_getctx_sec()
{ return(0); }

/* ARGSUSED */
void
sfmmu_setctx_sec(int ctx)
{}

/* ARGSUSED */
void
sfmmu_load_mmustate(sfmmu_t *sfmmup)
{
}

#else	/* lint */

/*
 * 1. If stealing ctx, flush all TLB entries whose ctx is ctx-being-stolen.
 * 2. If processor is running in the ctx-being-stolen, set the
 *    context to the resv context. That is 
 *    If processor in User-mode - pri/sec-ctx both set to ctx-being-stolen,
 *		change both pri/sec-ctx registers to resv ctx.
 *    If processor in Kernel-mode - pri-ctx is 0, sec-ctx is ctx-being-stolen,
 *		just change sec-ctx register to resv ctx. When it returns to
 *		kernel-mode, user_rtt will change pri-ctx.
 *
 * Note: For multiple page size TLB, no need to set page sizes for
 *       DEMAP context.
 *
 * %g1 = ctx being stolen (victim)
 * %g2 = invalid ctx to replace victim with
 */
	ENTRY(sfmmu_ctx_steal_tl1)
	/*
	 * Flush TLBs.
	 */

	/* flush context from the tlb via HV call */
	mov	%o0, %g3
	mov	%o1, %g4
	mov	%o2, %g5
	mov	%o3, %g6
	mov	%o5, %g7

	mov	%g1, %o2	! ctx#
	mov	%g0, %o0	! Current CPU only (use NULL)
	mov	%g0, %o1	! Current CPU only (use NULL)
	mov	MAP_ITLB | MAP_DTLB, %o3
	mov	MMU_DEMAP_CTX, %o5
	ta	FAST_TRAP
	brnz,a,pn %o0, ptl1_panic
	  mov	PTL1_BAD_HCALL, %g1

	mov	%g3, %o0
	mov	%g4, %o1
	mov	%g5, %o2
	mov	%g6, %o3
	mov	%g7, %o5

	/* fall through to the code below */

	/*
	 * We enter here if we're just raising a TSB miss
	 * exception, without switching MMU contexts.  In
	 * this case, there is no need to flush the TLB.
	 */
	ALTENTRY(sfmmu_raise_tsb_exception)
	!
	! %g1 = ctx being stolen (victim)
	! %g2 = invalid ctx to replace victim with
	!
	! if (sec-ctx != victim) {
	!	return
	! } else {
	!	if (pri-ctx == victim) {
	!		write INVALID_CONTEXT to sec-ctx
	!		write INVALID_CONTEXT to pri-ctx
	!	} else {
	!		write INVALID_CONTEXT to sec-ctx
	!	}
	! }
	!
	cmp	%g1, NUM_LOCKED_CTXS
	blt,a,pn %icc, ptl1_panic		/* can't steal locked ctx */
	  mov	PTL1_BAD_CTX_STEAL, %g1
	set	CTXREG_CTX_MASK, %g6
	set	MMU_SCONTEXT, %g3
	ldxa	[%g3]ASI_MMU_CTX, %g5		/* get sec-ctx */
	and	%g5, %g6, %g5
	cmp	%g5, %g1			/* is it the victim? */
	bne,pn	%icc, 2f			/* was our sec-ctx a victim? */
	  mov	MMU_PCONTEXT, %g7
	ldxa	[%g7]ASI_MMU_CTX, %g4		/* get pri-ctx */
	and	%g4, %g6, %g4
	stxa	%g2, [%g3]ASI_MMU_CTX		/* set sec-ctx to invalid ctx */
	membar	#Sync
	cmp	%g1, %g4			/* is it the victim? */
	bne 	%icc, 3f			/* nope, no need to change it */
	  nop
	stxa	%g2, [%g7]ASI_MMU_CTX		/* set pri-ctx to invalid ctx */
	/* next instruction is retry so no membar sync */
3:
	membar	#Sync
	/* TSB program must be cleared - walkers do not check a context. */
	mov	%o0, %g3
	mov	%o1, %g4
	mov	%o5, %g7
	clr	%o0
	clr	%o1
	mov	MMU_TSB_CTXNON0, %o5
	ta	FAST_TRAP
	brnz,a,pn %o0, ptl1_panic
	  mov	PTL1_BAD_HCALL, %g1
	mov	%g3, %o0
	mov	%g4, %o1
	mov	%g7, %o5
2:
	retry
	SET_SIZE(sfmmu_ctx_steal_tl1)

	ENTRY_NP(sfmmu_getctx_pri)
	set	MMU_PCONTEXT, %o0
	set	CTXREG_CTX_MASK, %o1
	ldxa	[%o0]ASI_MMU_CTX, %o0
	retl
	and	%o0, %o1, %o0
	SET_SIZE(sfmmu_getctx_pri)

	ENTRY_NP(sfmmu_getctx_sec)
	set	MMU_SCONTEXT, %o0
	set	CTXREG_CTX_MASK, %o1
	ldxa	[%o0]ASI_MMU_CTX, %o0
	retl
	and	%o0, %o1, %o0
	SET_SIZE(sfmmu_getctx_sec)

	/*
	 * Set the secondary context register for this process.
	 * %o0 = context number for this process.
	 */
	ENTRY_NP(sfmmu_setctx_sec)
	/*
	 * From resume we call sfmmu_setctx_sec with interrupts disabled.
	 * But we can also get called from C with interrupts enabled. So,
	 * we need to check first. Also, resume saves state in %o3 and %o5
	 * so we can't use those registers here.
	 */

	/* If interrupts are not disabled, then disable them */
	rdpr	%pstate, %g1
	btst	PSTATE_IE, %g1
	bnz,a,pt %icc, 1f
	wrpr	%g1, PSTATE_IE, %pstate		/* disable interrupts */
1:
	mov	MMU_SCONTEXT, %o1
	sethi	%hi(FLUSH_ADDR), %o4
	stxa	%o0, [%o1]ASI_MMU_CTX		/* set 2nd context reg. */
	flush	%o4

	btst	PSTATE_IE, %g1
	bnz,a,pt %icc, 1f
	wrpr	%g0, %g1, %pstate		/* enable interrupts */
1:	retl
	nop
	SET_SIZE(sfmmu_setctx_sec)

	/*
	 * set ktsb_phys to 1 if the processor supports ASI_QUAD_LDD_PHYS.
	 * returns the detection value in %o0.
	 */
	ENTRY_NP(sfmmu_setup_4lp)
	set	ktsb_phys, %o2
	mov	1, %o1
	st	%o1, [%o2]
	retl
	mov	%o1, %o0
	SET_SIZE(sfmmu_setup_4lp)

	/*
	 * Called to load MMU registers and tsbmiss area
	 * for the active process.  This function should
	 * only be called from TL=0.
	 *
	 * %o0 - hat pointer
	 */
	ENTRY_NP(sfmmu_load_mmustate)
	/*
	 * From resume we call sfmmu_load_mmustate with interrupts disabled.
	 * But we can also get called from C with interrupts enabled. So,
	 * we need to check first. Also, resume saves state in %o5 and we
	 * can't use this register here.
	 */

	sethi	%hi(ksfmmup), %o3
	ldx	[%o3 + %lo(ksfmmup)], %o3
	cmp	%o3, %o0
	be,pn	%xcc, 3f			! if kernel as, do nothing
	  nop

	/* If interrupts are not disabled, then disable them */
	rdpr	%pstate, %g1
	btst	PSTATE_IE, %g1
	bnz,a,pt %icc, 1f
	wrpr	%g1, PSTATE_IE, %pstate		! disable interrupts
1:
	/*
	 * We need to set up the TSB base register, tsbmiss
	 * area, and pass the TSB information into the hypervisor
	 */
	ldx	[%o0 + SFMMU_TSB], %o1		! %o1 = first tsbinfo
	ldx	[%o1 + TSBINFO_NEXTPTR], %g2	! %g2 = second tsbinfo

	/* create/set first UTSBREG */
	MAKE_UTSBREG(%o1, %o2, %o3)		! %o2 = user tsbreg
	SET_UTSBREG(SCRATCHPAD_UTSBREG1, %o2, %o3)

	brz,pt	%g2, 2f
	  mov	-1, %o2				! use -1 if no second TSB

	/* make 2nd UTSBREG */
	MAKE_UTSBREG(%g2, %o2, %o3)		! %o2 = user tsbreg
2:
	SET_UTSBREG(SCRATCHPAD_UTSBREG2, %o2, %o3)

#ifdef DEBUG
	/* check if hypervisor/hardware should handle user TSB */
	sethi	%hi(hv_use_non0_tsb), %o2
	ld	[%o2 + %lo(hv_use_non0_tsb)], %o2
	brz,pn	%o2, 5f
	nop
#endif /* DEBUG */
	CPU_ADDR(%o2, %o4)	! load CPU struct addr to %o2 using %o4
	ldub    [%o2 + CPU_TSTAT_FLAGS], %o1	! load cpu_tstat_flag to %o1
	lduh	[%o0 + SFMMU_CNUM], %o2
	mov	%o5, %o4			! preserve %o5 for resume
	mov	%o0, %o3			! preserve %o0
	btst	TSTAT_TLB_STATS, %o1
	bnz,a,pn %icc, 4f			! ntsb = 0 if TLB stats enabled
	  clr	%o0
	cmp	%o2, INVALID_CONTEXT
	be,a,pn	%icc, 4f
	  clr	%o0				! ntsb = 0 for invalid ctx
	ldx	[%o3 + SFMMU_HVBLOCK + HV_TSB_INFO_CNT], %o0
4:
	ldx	[%o3 + SFMMU_HVBLOCK + HV_TSB_INFO_PA], %o1
	mov	MMU_TSB_CTXNON0, %o5
	ta	FAST_TRAP			! set TSB info for user process
	brnz,a,pn %o0, panic_bad_hcall
	mov	MMU_TSB_CTXNON0, %o1
	mov	%o3, %o0			! restore %o0
	mov	%o4, %o5			! restore %o5
5:
	ldx	[%o0 + SFMMU_ISMBLKPA], %o1	! copy members of sfmmu
	CPU_TSBMISS_AREA(%o2, %o3)		! we need to access from
	stx	%o1, [%o2 + TSBMISS_ISMBLKPA]	! sfmmu_tsb_miss into the
	lduh	[%o0 + SFMMU_FLAGS], %o3	! per-CPU tsbmiss area.
	stx	%o0, [%o2 + TSBMISS_UHATID]
	stuh	%o3, [%o2 + TSBMISS_HATFLAGS]

	btst	PSTATE_IE, %g1
	bnz,a,pt %icc, 3f
	wrpr	%g0, %g1, %pstate		! enable interrupts
3:	retl
	nop
	SET_SIZE(sfmmu_load_mmustate)

#endif /* lint */

#if defined(lint)

/* Prefetch "struct tsbe" while walking TSBs */
/*ARGSUSED*/
void
prefetch_tsbe_read(struct tsbe *tsbep)
{}

/* Prefetch the tsbe that we are about to write */
/*ARGSUSED*/
void
prefetch_tsbe_write(struct tsbe *tsbep)
{}

#else /* lint */

	ENTRY(prefetch_tsbe_read)
	retl
	nop
	SET_SIZE(prefetch_tsbe_read)

	ENTRY(prefetch_tsbe_write)
	retl
	nop
	SET_SIZE(prefetch_tsbe_write)
#endif /* lint */
