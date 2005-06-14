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
 * System-resumption code.  kaif_resume is called whenever the world, as a whole
 * or merely a single CPU, is to be resumed.
 */

#if !defined(__lint)
#include <sys/asm_linkage.h>
#include <sys/trap.h>
#include <sys/machtrap.h>
#include <sys/mmu.h>
#include <sys/machasi.h>
#define _KERNEL
#include <sys/privregs.h>
#undef _KERNEL
#include <sys/machthread.h>
#include <sys/machparam.h>
#endif

#if defined(__lint)
#include <sys/ddi.h>
#include <sys/sunddi.h>
#endif

#include <mdb/mdb_kreg.h>
#include <kmdb/kaif_asmutil.h>
#include <kmdb/kaif_off.h>
#include <kmdb/kaif.h>

#if defined(__lint)
/*ARGSUSED*/
void
kaif_resume(int work_required)
{
}
#else /* __lint */

	/*
	 * Used to start the world back up, as a whole or in part (single-step).
	 * Arguments:
	 *    %l5 - the CPU-specific gregs save area
	 *    %l6 - the CPU-specific save area
	 */
	ENTRY_NP(kaif_resume)

	/* globals only from here on out */
	mov	%l5, %g5
	mov	%l6, %g6

	/*
	 * To resume the world, we reverse what we did in startup
	 */

	/* FP state */
	add	%g6, KRS_FPREGS, %g4	! %g4 = &cpusave[this_cpuid].krs_fpregs

	ldx	[%g4 + FPU_FPRS], %g2
	btst	FPRS_FEF, %g2		! was fp enabled?
	bz,pt	%icc, 1f		! nope drive on...
	wr	%g2, %fprs		! restore %fprs regardless

	LOAD_FPREGS(%g4)
	ldx	[%g4 + FPU_FSR], %fsr

1:
	/* Register windows */
	GET_NWIN(%g1, %g4);		! %g1 is scratch, %g4 set to nwin-1
	wrpr	%g4, %cleanwin

	sub	%g4, 1, %g1
	wrpr	%g1, %cansave

	wrpr	%g0, %otherwin
	wrpr	%g0, %canrestore
	wrpr	%g0, %cwp
	clr	%g2

	ldx	[%g6 + KRS_RWINS], %g3	! %g3 = &cpusave[this_cpuid].krs_wins

1:
	RESTORE_V9WINDOW(%g3)
	add	%g2, 1, %g2
	add	%g3, RWIN_SIZE, %g3
	cmp	%g2, %g4
	ble	1b
	wrpr	%g2, %cwp

	/* Restore various privileged registers */
	ldx	[%g5 + KREG_OFF(KREG_CWP)], %g4
	wrpr	%g4, %cwp
	ldx	[%g5 + KREG_OFF(KREG_OTHERWIN)], %g4
	wrpr	%g4, %otherwin
	ldx	[%g5 + KREG_OFF(KREG_CLEANWIN)], %g4
	wrpr	%g4, %cleanwin
	ldx	[%g5 + KREG_OFF(KREG_CANSAVE)], %g4
	wrpr	%g4, %cansave
	ldx	[%g5 + KREG_OFF(KREG_CANRESTORE)], %g4
	wrpr	%g4, %canrestore
	ldx	[%g5 + KREG_OFF(KREG_WSTATE)], %g4
	wrpr	%g4, %wstate

	ldx	[%g5 + KREG_OFF(KREG_Y)], %g4
	wr	%g4, %y

	ldx	[%g5 + KREG_OFF(KREG_PIL)], %g4
	wrpr	%g4, %pil

	/* Set up the return from the trap */
	wrpr	%g0, 1, %tl

	/*
	 * Restore the MMU primary context.  
	 */
	mov	MMU_PCONTEXT, %g3
	ldx	[%g6 + KRS_MMU_PCONTEXT], %g4
	KAIF_DEMAP_TLB_ALL(%g2)
	stxa	%g4, [%g3]ASI_MMU_CTX
	membar	#Sync

	ldx	[%g6 + KRS_TSTATE], %g4
	wrpr	%g4, %tstate

	ldx	[%g5 + KREG_OFF(KREG_PC)], %g4
	wrpr	%g4, %tpc
	
	ldx	[%g5 + KREG_OFF(KREG_NPC)], %g4
	wrpr	%g4, %tnpc

	/*
	 * If we're here because of the debugger trap (most likely from 
	 * kaif_entry), we don't want to jump back to %tpc, since it
	 * is likely to be the ta that brought us here in the first place.
	 * We'll test for it here, and we'll leave %xcc untouched until
	 * the end when we're about to return.
	 */
	ldx	[%g5 + KREG_OFF(KREG_TT)], %g4
	wrpr	%g4, %tt
	cmp	%g4, ST_KMDB_TRAP|T_SOFTWARE_TRAP

	/* Restore saved globals */
	ldx	[%g5 + KREG_OFF(KREG_G1)], %g1
	ldx	[%g5 + KREG_OFF(KREG_G2)], %g2
	ldx	[%g5 + KREG_OFF(KREG_G3)], %g3
	ldx	[%g5 + KREG_OFF(KREG_G4)], %g4
	ldx	[%g5 + KREG_OFF(KREG_G6)], %g6
	ldx	[%g5 + KREG_OFF(KREG_G7)], %g7
	be	%xcc, 1f			! the trap type check, above
	ldx	[%g5 + KREG_OFF(KREG_G5)], %g5

	retry
1:
	done

	SET_SIZE(kaif_resume)

#endif	/* __lint */
