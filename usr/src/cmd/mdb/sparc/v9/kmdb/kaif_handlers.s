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

#include <sys/asm_linkage.h>
#include <sys/machasi.h>
#include <sys/machtrap.h>
#include <sys/privregs.h>
#include <sys/mmu.h>

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
#endif /* lint */

#if defined(lint)

#ifdef sun4v
#else /* sun4v */
void
kaif_hdlr_dmiss(void)
{
}

void
kaif_itlb_handler(void)
{
}
#endif /* sun4v */
#else	/* lint */

#ifdef sun4v
#else /* sun4v */

	.global	kaif_hdlr_dmiss_patch
	.global	kaif_hdlr_imiss_patch

	/*
	 * This routine must be exactly 32 instructions long.
	 */
	ENTRY_NP(kaif_hdlr_dmiss)
	mov	MMU_TAG_ACCESS, %g1
	ldxa	[%g1]ASI_DMMU, %g1		/* %g1 = addr|ctx */
	sllx	%g1, TAGACC_CTX_LSHIFT, %g2	/* strip addr */
	srlx	%g2, TAGACC_CTX_LSHIFT, %g2	/* %g2 = ctx */

	/*
	 * Use kdi_vatotte to look up the tte.  We don't bother stripping the
	 * context, as it won't change the tte we get.
	 */
kaif_hdlr_dmiss_patch:
	sethi	%hi(0), %g3	/* set by kaif to kdi_vatotte */
	or	%g3, %lo(0), %g3
	jmpl	%g3, %g7	/* uses all regs, ret to %g7, tte or 0 in %g1 */
	add	%g7, 8, %g7	/* adjust return */

	brz	%g1, 1f
	nop

	/* 
	 * kdi_vatotte gave us a TTE to use.  Load it up and head back 
	 * into the world, but first bump a counter.
	 */
#ifdef	KMDB_TRAPCOUNT
	ldx	[%g7 + 0x40], %g2	/* Trap counter.  See top comment */
	add	%g2, 1, %g2
	stx	%g2, [%g7 + 0x40]
#else
	nop
	nop
	nop
#endif
	stxa	%g1, [%g0]ASI_DTLB_IN
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

#ifdef	KMDB_TRAPCOUNT
	mov	MMU_TAG_ACCESS, %g1	/* Trap address "counter". */
	ldxa	[%g1]ASI_DMMU, %g1
	stx	%g1, [%g7 + 0x48]
#else
	nop
	nop
	nop
#endif

	mov	PTSTATE_KERN_COMMON | PSTATE_AG, %g3
	wrpr	%g3, %pstate
	sethi	%hi(kaif_dtrap), %g4
	jmp	%g4 + %lo(kaif_dtrap)
	nop
	unimp	0
	unimp	0	/* counter goes here (base + 0x60) */
	unimp	0
	unimp	0	/* miss address goes here (base + 0x68) */
	unimp	0
	unimp	0
	unimp	0
	unimp	0
	unimp	0
	SET_SIZE(kaif_hdlr_dmiss)

	/*
	 * This routine must be exactly 32 instructions long.
	 */
	ENTRY_NP(kaif_hdlr_imiss)
	rdpr	%tpc, %g1
	ldxa	[%g0]ASI_IMMU, %g2
	srlx	%g2, TTARGET_CTX_SHIFT, %g2

kaif_hdlr_imiss_patch:
	sethi	%hi(0), %g3	/* set by kaif to kdi_vatotte */
	or	%g3, %lo(0), %g3
	jmpl	%g3, %g7	/* uses all regs, ret to %g7, tte or 0 in %g1 */
	add	%g7, 8, %g7	/* adjust return */

	brz	%g1, 1f
	nop

	/* 
	 * kdi_vatotte gave us a TTE to use.  Load it up and head back 
	 * into the world, but first bump a counter.
	 */
#ifdef	KMDB_TRAPCOUNT
	ldx	[%g7 + 0x3c], %g2	/* Trap counter.  See top comment */
	add	%g2, 1, %g2
	stx	%g2, [%g7 + 0x3c]
#else
	nop
	nop
	nop
#endif
	stxa	%g1, [%g0]ASI_ITLB_IN
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
	rdpr	%pstate, %g1
	or	%g0, PTSTATE_KERN_COMMON | PSTATE_AG, %g2
	set	kaif_dtrap, %g3
	jmp	%g3
	wrpr	%g2, %pstate
	unimp	0
	unimp	0
	unimp	0	/* counter goes here */
	unimp	0
	unimp	0
	unimp	0
	unimp	0
	unimp	0
	unimp	0
	unimp	0
	unimp	0
	unimp	0
	SET_SIZE(kaif_hdlr_imiss)
#endif /* sun4v */

	ENTRY_NP(kaif_hdlr_generic)
#ifdef	KMDB_TRAPCOUNT
	rd	%pc, %g3		/* Trap counter.  See top comment */
	ld	[%g3 + 0x1c], %g4
	add	%g4, 1, %g4
	st	%g4, [%g3 + 0x1c]
#else
	nop
	nop
	nop
	nop
#endif
	sethi	%hi(kaif_dtrap), %g3
	jmp	%g3 + %lo(kaif_dtrap)
	rdpr	%pstate, %g1
	unimp	0	/* counter goes here */
	SET_SIZE(kaif_hdlr_generic)

#endif
