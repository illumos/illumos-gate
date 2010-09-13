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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/asm_linkage.h>
#include <sys/machasi.h>
#include <sys/machtrap.h>
#include <sys/privregs.h>
#include <sys/mmu.h>
#include <vm/mach_sfmmu.h>

#if defined(sun4v) && !defined(lint)
#include <sys/machparam.h>
#endif

#if defined(sun4v) && defined(KMDB_TRAPCOUNT)
/*
 * The sun4v implemenations of the fast miss handlers are larger than those
 * of their sun4u kin. This is unfortunate because there is not enough space
 * remaining in the respective trap table entries for this debug feature.
 */
#error "KMDB_TRAPCOUNT not supported on sun4v"
#endif

/*
 * This file contains the trap handlers that will be copied to kmdb's trap
 * table.  See kaif_activate.c for the code that does the actual copying.
 *
 * The handlers have a debugging feature, enabled when KMDB_TRAPCOUNT is
 * defined, which allows them to keep a running count of the number of times
 * a given trap has occurred.  The counter is stored in the padding at the end
 * of the handler.  Write access is of course required to allow the values to
 * be updated, so KMDB_TRAPCOUNT also enables the installation of DTLB entries
 * for each trap table page.  Finally, the code in this file is copied into
 * the actual location used by the handler, so we can't perform compile-time
 * counter location calculations.  The calculations are instead performed at
 * run-time, as A) we generally already derive the table location as part of
 * the trap processing and B) simplicity is more of a concern than is speed.
 */

#if defined(lint)
#include <kmdb/kaif.h>

void
kaif_hdlr_dmiss(void)
{
}

void
kaif_itlb_handler(void)
{
}

#else /* lint */

#ifdef sun4v

#define	GET_MMU_D_ADDR_CTX(daddr, ctx)			\
	MMU_FAULT_STATUS_AREA(ctx);			\
	ldx	[ctx + MMFSA_D_ADDR], daddr;		\
	ldx	[ctx + MMFSA_D_CTX], ctx

#define	GET_MMU_I_ADDR_CTX(iaddr, ctx)			\
	MMU_FAULT_STATUS_AREA(ctx);			\
	ldx	[ctx + MMFSA_I_ADDR], iaddr;		\
	ldx	[ctx + MMFSA_I_CTX], ctx

/*
 * KAIF_ITLB_STUFF
 * derived from ITLB_STUFF in uts/sun4v/vm/mach_sfmmu.h
 *
 * Load ITLB entry
 *
 * In:
 *   tte = reg containing tte
 *   ouch = branch target label used if hcall fails (sun4v only)
 *   scr1, scr2, scr3, scr4 = scratch registers (must not be %o0-%o3)
 */
#define	KAIF_ITLB_STUFF(tte, ouch, scr1, scr2, scr3, scr4)	\
	mov	%o0, scr1;				\
	mov	%o1, scr2;				\
	mov	%o2, scr3;				\
	mov	%o3, scr4;				\
	MMU_FAULT_STATUS_AREA(%o2);			\
	ldx	[%o2 + MMFSA_I_ADDR], %o0;		\
	ldx	[%o2 + MMFSA_I_CTX], %o1;		\
	srlx	%o0, PAGESHIFT, %o0;			\
	sllx	%o0, PAGESHIFT, %o0;			\
	mov	tte, %o2;				\
	mov	MAP_ITLB, %o3;				\
	ta	MMU_MAP_ADDR;				\
	/* BEGIN CSTYLED */				\
	brnz,a,pn %o0, ouch;				\
	  nop;						\
	/* END CSTYLED */				\
	mov	scr1, %o0;				\
	mov	scr2, %o1;				\
	mov	scr3, %o2;				\
	mov	scr4, %o3

/*
 * KAIF_DTLB_STUFF
 * derived from DTLB_STUFF in uts/sun4v/vm/mach_sfmmu.h
 *
 * Load DTLB entry
 *
 * In:
 *   tte = reg containing tte
 *   ouch = branch target label used if hcall fails (sun4v only)
 *   scr1, scr2, scr3, scr4 = scratch registers (must not be %o0-%o3)
 */
#define	KAIF_DTLB_STUFF(tte, ouch, scr1, scr2, scr3, scr4)	\
	mov	%o0, scr1;				\
	mov	%o1, scr2;				\
	mov	%o2, scr3;				\
	mov	%o3, scr4;				\
	MMU_FAULT_STATUS_AREA(%o2);			\
	ldx	[%o2 + MMFSA_D_ADDR], %o0;		\
	ldx	[%o2 + MMFSA_D_CTX], %o1;		\
	srlx	%o0, PAGESHIFT, %o0;			\
	sllx	%o0, PAGESHIFT, %o0;			\
	mov	tte, %o2;				\
	mov	MAP_DTLB, %o3;				\
	ta	MMU_MAP_ADDR;				\
	/* BEGIN CSTYLED */				\
	brnz,a,pn %o0, ouch;				\
	  nop;						\
	/* END CSTYLED */				\
	mov	scr1, %o0;				\
	mov	scr2, %o1;				\
	mov	scr3, %o2;				\
	mov	scr4, %o3

#else /* sun4v */

#define	GET_MMU_D_ADDR_CTX(daddr, ctx)			\
	mov	MMU_TAG_ACCESS, ctx;			\
	ldxa	[ctx]ASI_DMMU, daddr;			\
	sllx	daddr, TAGACC_CTX_LSHIFT, ctx;		\
	srlx	ctx, TAGACC_CTX_LSHIFT, ctx

#define	GET_MMU_I_ADDR_CTX(iaddr, ctx)			\
	rdpr	%tpc, iaddr;				\
	ldxa	[%g0]ASI_IMMU, ctx;			\
	srlx	ctx, TTARGET_CTX_SHIFT, ctx

#define	KAIF_DTLB_STUFF(tte, ouch, scr1, scr2, scr3, scr4)	\
	DTLB_STUFF(tte, scr1, scr2, scr3, scr4)

#define	KAIF_ITLB_STUFF(tte, ouch, scr1, scr2, scr3, scr4)	\
	ITLB_STUFF(tte, scr1, scr2, scr3, scr4)

#endif /* sun4v */
	
/*
 * KAIF_CALL_KDI_VATOTTE
 *
 * Use kdi_vatotte to look up the tte.  We don't bother stripping the
 * context, as it won't change the tte we get.
 *
 * The two instruction at patch_lbl are modified during runtime
 * by kaif to point to kdi_vatotte
 *
 * Clobbers all globals.
 * Returns tte in %g1 if successful, otherwise 0 in %g1
 * Leaves address of next instruction following this macro in scr1
 */
#define	KAIF_CALL_KDI_VATOTTE(addr, ctx, patch_lbl, scr0, scr1)	\
	.global	patch_lbl;					\
patch_lbl:							\
	sethi	%hi(0), scr0;					\
	or	scr0, %lo(0), scr0;				\
	jmpl	scr0, scr1;					\
	add	scr1, 8, scr1


	ENTRY_NP(kaif_hdlr_dmiss)
	GET_MMU_D_ADDR_CTX(%g1, %g2)

	KAIF_CALL_KDI_VATOTTE(%g1, %g2, kaif_hdlr_dmiss_patch, %g3, %g7)
0:	brz	%g1, 1f
	nop

	/* 
	 * kdi_vatotte gave us a TTE to use.  Load it up and head back 
	 * into the world, but first bump a counter.
	 */

#ifdef	KMDB_TRAPCOUNT			/* Trap counter.  See top comment */
	ldx	[%g7 + .count-0b], %g2
	add	%g2, 1, %g2
	stx	%g2, [%g7 + .count-0b]
#endif

	KAIF_DTLB_STUFF(%g1, 1f, %g2, %g3, %g4, %g5)
	retry

1:	/* 
	 * kdi_vatotte didn't give us a tte, which is unfortunate.  We're
	 * going to need to jump into the debugger so as to allow it to
	 * handle the trap.  The debugger itself isn't locked into the TLB,
	 * so we may well incur a TLB miss while trying to get into it.  As
	 * such, we're going to switch off the MMU globals before setting foot
	 * into the debugger, thus allowing a TL>1 miss to be handled without
	 * clobbering our state.  We'll also save off the tag just in case the
	 * world ends and someone wants to find out what happened.
	 *
	 * We will only reach this point at TL=1, as kdi_vatotte will always
	 * find the TTE for the debugger without missing.
	 */

#ifdef	KMDB_TRAPCOUNT			/* Trap address "counter". */
	GET_MMU_D_ADDR(%g2, %g3)
	stx	%g2, [%g7 + .daddr-0b]
	stx	%g1, [%g7 + .ecode-0b]
#endif

	sethi	%hi(kaif_dtrap), %g1
	jmp	%g1 + %lo(kaif_dtrap)
	nop
	/* NOTREACHED */

#ifdef KMDB_TRAPCOUNT
	.align 8
.count:	.xword 0			/* counter goes here */
.daddr:	.xword 0			/* miss address goes here */
.ecode:	.xword 0			/* sun4v: g1 contains err code */
#endif

	.align 32*4			/* force length to 32 instr. */
	SET_SIZE(kaif_hdlr_dmiss)



	ENTRY_NP(kaif_hdlr_imiss)
	GET_MMU_I_ADDR_CTX(%g1, %g2)

	KAIF_CALL_KDI_VATOTTE(%g1, %g2, kaif_hdlr_imiss_patch, %g3, %g7)
0:	brz	%g1, 1f
	nop

	/* 
	 * kdi_vatotte gave us a TTE to use.  Load it up and head back 
	 * into the world, but first bump a counter.
	 */
#ifdef	KMDB_TRAPCOUNT			/* Trap counter.  See top comment */
	ldx	[%g7 + .count-0b], %g2
	add	%g2, 1, %g2
	stx	%g2, [%g7 + .count-0b]
#endif

	KAIF_ITLB_STUFF(%g1, 1f, %g2, %g3, %g4, %g5)
	retry

1:	/* 
	 * kdi_vatotte didn't give us a tte, which is unfortunate.  We're
	 * going to need to jump into the debugger so as to allow it to
	 * handle the trap.  The debugger itself isn't locked into the TLB,
	 * so we may well incur a TLB miss while trying to get into it.  As
	 * such, we're going to switch off the MMU globals before setting foot
	 * into the debugger, thus allowing a TL>1 miss to be handled without
	 * clobbering our state.
	 *
	 * We will only reach this point at TL=1, as kdi_vatotte will always
	 * find the TTE for the debugger without missing.
	 */

	sethi	%hi(kaif_dtrap), %g1
	jmp	%g1 + %lo(kaif_dtrap)
	nop
	/* NOTREACHED */

#ifdef KMDB_TRAPCOUNT
	.align	8
.count:	.xword	0
#endif

	.align	32*4			/* force length to 32 instr. */
	SET_SIZE(kaif_hdlr_imiss)



	ENTRY_NP(kaif_hdlr_generic)
#ifdef	KMDB_TRAPCOUNT			/* Trap counter.  See top comment */
0:	rd	%pc, %g3
	ldx	[%g3 + .count-0b], %g4
	add	%g4, 1, %g4
	stx	%g4, [%g3 + .count-0b]
#endif

	sethi	%hi(kaif_dtrap), %g1
	jmp	%g1 + %lo(kaif_dtrap)
	nop
	/* NOTREACHED */

#ifdef	KMDB_TRAPCOUNT
	.align	8
.count:	.xword	0			/* counter goes here */
#endif

	.align	32*4			/* force length to 32 instr. */
	SET_SIZE(kaif_hdlr_generic)

#endif /* lint */
