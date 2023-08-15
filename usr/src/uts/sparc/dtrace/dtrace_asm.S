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

#include <sys/asm_linkage.h>
#include <sys/privregs.h>
#include <sys/fsr.h>
#include <sys/asi.h>
#include "assym.h"

	ENTRY_NP(dtrace_getipl)
	retl
	rdpr	%pil, %o0
	SET_SIZE(dtrace_getipl)

	ENTRY_NP(dtrace_getotherwin)
	retl
	rdpr	%otherwin, %o0
	SET_SIZE(dtrace_getotherwin)

	ENTRY_NP(dtrace_getfprs)
	retl
	rd	%fprs, %o0
	SET_SIZE(dtrace_getfprs)

	ENTRY_NP(dtrace_getfsr)
	rdpr	%pstate, %o1
	andcc	%o1, PSTATE_PEF, %g0
	bz,pn	%xcc, 1f
	nop
	rd	%fprs, %o1
	andcc	%o1, FPRS_FEF, %g0
	bz,pn	%xcc, 1f
	nop
	retl
	stx	%fsr, [%o0]
1:
	retl
	stx	%g0, [%o0]
	SET_SIZE(dtrace_getfsr)

	ENTRY_NP(dtrace_getfp)
	retl
	mov	%fp, %o0
	SET_SIZE(dtrace_getfp)

	ENTRY_NP(dtrace_flush_user_windows)
	rdpr	%otherwin, %g1
	brz	%g1, 3f
	clr	%g2
1:
	save	%sp, -WINDOWSIZE, %sp
	rdpr	%otherwin, %g1
	brnz	%g1, 1b
	add	%g2, 1, %g2
2:
	sub	%g2, 1, %g2		! restore back to orig window
	brnz	%g2, 2b
	restore
3:
	retl
	nop
	SET_SIZE(dtrace_flush_user_windows)

	ENTRY(dtrace_cas32)
	cas	[%o0], %o1, %o2
	retl
	mov	%o2, %o0
	SET_SIZE(dtrace_cas32)

	ENTRY(dtrace_casptr)
	casn	[%o0], %o1, %o2
	retl
	mov	%o2, %o0
	SET_SIZE(dtrace_casptr)

	ENTRY(dtrace_caller)
	sethi	%hi(nwin_minus_one), %g4
	ld	[%g4 + %lo(nwin_minus_one)], %g4
	rdpr	%canrestore, %g2
	cmp	%g2, %o0
	bl	%icc, 1f
	rdpr	%cwp, %g1
	sub	%g1, %o0, %g3
	brgez,a,pt %g3, 0f
	wrpr	%g3, %cwp

	!
	! CWP minus the number of frames is negative; we must perform the
	! arithmetic modulo MAXWIN.
	!
	add	%g4, %g3, %g3
	inc	%g3
	wrpr	%g3, %cwp
0:
	mov	%i7, %g4
	wrpr	%g1, %cwp
	retl
	mov	%g4, %o0
1:
	!
	! The caller has been flushed to the stack.  This is unlikely
	! (interrupts are disabled in dtrace_probe()), but possible (the
	! interrupt inducing the spill may have been taken before the
	! call to dtrace_probe()).
	!
	retl
	mov	-1, %o0
	SET_SIZE(dtrace_caller)

	ENTRY(dtrace_fish)

	rd	%pc, %g5
	ba	0f
	add	%g5, 12, %g5
	mov	%l0, %g4
	mov	%l1, %g4
	mov	%l2, %g4
	mov	%l3, %g4
	mov	%l4, %g4
	mov	%l5, %g4
	mov	%l6, %g4
	mov	%l7, %g4
	mov	%i0, %g4
	mov	%i1, %g4
	mov	%i2, %g4
	mov	%i3, %g4
	mov	%i4, %g4
	mov	%i5, %g4
	mov	%i6, %g4
	mov	%i7, %g4
0:
	sub	%o1, 16, %o1		! Can only retrieve %l's and %i's
	sll	%o1, 2, %o1		! Multiply by instruction size
	add	%g5, %o1, %g5		! %g5 now contains the instr. to pick

	sethi	%hi(nwin_minus_one), %g4
	ld	[%g4 + %lo(nwin_minus_one)], %g4

	!
	! First we need to see if the frame that we're fishing in is still
	! contained in the register windows.
	!
	rdpr	%canrestore, %g2
	cmp	%g2, %o0
	bl	%icc, 2f
	rdpr	%cwp, %g1
	sub	%g1, %o0, %g3
	brgez,a,pt %g3, 0f
	wrpr	%g3, %cwp

	!
	! CWP minus the number of frames is negative; we must perform the
	! arithmetic modulo MAXWIN.
	!
	add	%g4, %g3, %g3
	inc	%g3
	wrpr	%g3, %cwp
0:
	jmp	%g5
	ba	1f
1:
	wrpr	%g1, %cwp
	stn	%g4, [%o2]
	retl
	clr	%o0			! Success; return 0.
2:
	!
	! The frame that we're looking for has been flushed to the stack; the
	! caller will be forced to
	!
	retl
	add	%g2, 1, %o0		! Failure; return deepest frame + 1
	SET_SIZE(dtrace_fish)

	ENTRY(dtrace_copyin)
	tst	%o2
	bz	2f
	clr	%g1
	lduba	[%o0 + %g1]ASI_USER, %g2
0:
	! check for an error if the count is 4k-aligned
	andcc	%g1, 0xfff, %g0
	bnz,pt	%icc, 1f
	stub	%g2, [%o1 + %g1]
	lduh	[%o3], %g3
	andcc	%g3, CPU_DTRACE_BADADDR, %g0
	bnz,pn	%icc, 2f
	nop
1:
	inc	%g1
	cmp	%g1, %o2
	bl,a	0b
	lduba	[%o0 + %g1]ASI_USER, %g2
2:
	retl
	nop

	SET_SIZE(dtrace_copyin)

	ENTRY(dtrace_copyinstr)
	tst	%o2
	bz	2f
	clr	%g1
	lduba	[%o0 + %g1]ASI_USER, %g2
0:
	stub	%g2, [%o1 + %g1]		! Store byte

	! check for an error if the count is 4k-aligned
	andcc	%g1, 0xfff, %g0
	bnz,pt	%icc, 1f
	inc	%g1
	lduh	[%o3], %g3
	andcc	%g3, CPU_DTRACE_BADADDR, %g0
	bnz,pn	%icc, 2f
	nop
1:
	cmp	%g2, 0				! Was that '\0'?
	be	2f				! If so, we're done
	cmp	%g1, %o2			! Compare to limit
	bl,a	0b				! If less, take another lap
	lduba	[%o0 + %g1]ASI_USER, %g2	!   delay: load user byte
2:
	retl
	nop

	SET_SIZE(dtrace_copyinstr)

	ENTRY(dtrace_copyout)
	tst	%o2
	bz	2f
	clr	%g1
	ldub	[%o0 + %g1], %g2
0:
	! check for an error if the count is 4k-aligned
	andcc	%g1, 0xfff, %g0
	bnz,pt	%icc, 1f
	stba	%g2, [%o1 + %g1]ASI_USER
	lduh	[%o3], %g3
	andcc	%g3, CPU_DTRACE_BADADDR, %g0
	bnz,pn	%icc, 2f
	nop
1:
	inc	%g1
	cmp	%g1, %o2
	bl,a	0b
	ldub	[%o0 + %g1], %g2
2:
	retl
	nop
	SET_SIZE(dtrace_copyout)

	ENTRY(dtrace_copyoutstr)
	tst	%o2
	bz	2f
	clr	%g1
	ldub	[%o0 + %g1], %g2
0:
	stba	%g2, [%o1 + %g1]ASI_USER

	! check for an error if the count is 4k-aligned
	andcc	%g1, 0xfff, %g0
	bnz,pt  %icc, 1f
	inc	%g1
	lduh	[%o3], %g3
	andcc	%g3, CPU_DTRACE_BADADDR, %g0
	bnz,pn	%icc, 2f
	nop
1:
	cmp	%g2, 0
	be	2f
	cmp	%g1, %o2
	bl,a	0b
	ldub	[%o0 + %g1], %g2
2:
	retl
	nop
	SET_SIZE(dtrace_copyoutstr)

	ENTRY(dtrace_fulword)
	clr	%o1
	ldna	[%o0]ASI_USER, %o1
	retl
	mov	%o1, %o0
	SET_SIZE(dtrace_fulword)

	ENTRY(dtrace_fuword8)
	clr	%o1
	lduba	[%o0]ASI_USER, %o1
	retl
	mov	%o1, %o0
	SET_SIZE(dtrace_fuword8)

	ENTRY(dtrace_fuword16)
	clr	%o1
	lduha	[%o0]ASI_USER, %o1
	retl
	mov	%o1, %o0
	SET_SIZE(dtrace_fuword16)

	ENTRY(dtrace_fuword32)
	clr	%o1
	lda	[%o0]ASI_USER, %o1
	retl
	mov	%o1, %o0
	SET_SIZE(dtrace_fuword32)

	ENTRY(dtrace_fuword64)
	clr	%o1
	ldxa	[%o0]ASI_USER, %o1
	retl
	mov	%o1, %o0
	SET_SIZE(dtrace_fuword64)

	/*
	 * %g1	pcstack
	 * %g2	current window
	 * %g3	maxwin (nwindows - 1)
	 * %g4	saved %cwp (so we can get back to the original window)
	 * %g5	iteration count
	 * %g6	saved %fp
	 *
	 * %o0	pcstack / return value (iteration count)
	 * %o1	pcstack_limit
	 * %o2	last_fp
	 */

	ENTRY(dtrace_getupcstack_top)
	mov	%o0, %g1		! we need the pcstack pointer while
					! we're visiting other windows

	rdpr	%otherwin, %g5		! compute the number of iterations
	cmp	%g5, %o1		! (windows to observe) by taking the
	movg	%icc, %o1, %g5		! min of %otherwin and pcstack_limit

	brlez,a,pn %g5, 2f		! return 0 if count <= 0
	clr	%o0

	sethi	%hi(nwin_minus_one), %g3 ! hang onto maxwin since we'll need
	ld	[%g3 + %lo(nwin_minus_one)], %g3 ! it for our modular arithmetic

	rdpr	%cwp, %g4		! remember our window so we can return
	rdpr	%canrestore, %g2	! compute the first non-user window
	subcc	%g4, %g2, %g2		! current = %cwp - %canrestore

	bge,pt	%xcc, 1f		! good to go if current is >= 0
	mov	%g5, %o0		! we need to return the count

	add	%g2, %g3, %g2		! normalize our current window if it's
	add	%g2, 1, %g2		! less than zero

	! note that while it's tempting, we can't execute restore to decrement
	! the %cwp by one (mod nwindows) because we're in the user's windows
1:
	deccc	%g2			! decrement the current window
	movl	%xcc, %g3, %g2		! normalize if it's negative (-1)

	wrpr	%g2, %cwp		! change windows

	stx	%i7, [%g1]		! stash the return address in pcstack

	deccc	%g5			! decrement the count
	bnz,pt	%icc, 1b		! we iterate until the count reaches 0
	add	%g1, 8, %g1		! increment the pcstack pointer

	mov	%i6, %g6		! stash the last frame pointer we
					! encounter so the caller can
					! continue the stack walk in memory

	wrpr	%g4, %cwp		! change back to the original window

	stn	%g6, [%o2]		! return the last frame pointer

2:
	retl
	nop
	SET_SIZE(dtrace_getupcstack_top)

	ENTRY(dtrace_getustackdepth_top)
	mov	%o0, %o2
	rdpr	%otherwin, %o0

	brlez,a,pn %o0, 2f		! return 0 if there are no user wins
	clr	%o0

	rdpr	%cwp, %g4		! remember our window so we can return
	rdpr	%canrestore, %g2	! compute the first user window
	sub	%g4, %g2, %g2		! current = %cwp - %canrestore -
	subcc	%g2, %o0, %g2		!     %otherwin

	bge,pt	%xcc, 1f		! normalize the window if necessary
	sethi	%hi(nwin_minus_one), %g3
	ld	[%g3 + %lo(nwin_minus_one)], %g3
	add	%g2, %g3, %g2
	add	%g2, 1, %g2

1:
	wrpr	%g2, %cwp		! change to the first user window
	mov	%i6, %g6		! stash the frame pointer
	wrpr	%g4, %cwp		! change back to the original window

	stn	%g6, [%o2]		! return the frame pointer

2:
	retl
	nop
	SET_SIZE(dtrace_getustackdepth_top)

	ENTRY(dtrace_getreg_win)
	sub	%o0, 16, %o0
	cmp	%o0, 16			! %o0 must begin in the range [16..32)
	blu,pt	%xcc, 1f
	nop
	retl
	clr	%o0

1:
	set	dtrace_getreg_win_table, %g3
	sll	%o0, 2, %o0
	add	%g3, %o0, %g3

	rdpr	%canrestore, %o3
	rdpr	%cwp, %g2

	! Set %cwp to be (%cwp - %canrestore - %o1) mod NWINDOWS

	sub	%g2, %o3, %o2		! %o2 is %cwp - %canrestore
	subcc	%o2, %o1, %o4
	bge,a,pn %xcc, 2f
	wrpr	%o4, %cwp

	sethi	%hi(nwin_minus_one), %o3
	ld	[%o3 + %lo(nwin_minus_one)], %o3

	add	%o2, %o3, %o4
	wrpr	%o4, %cwp
2:
	jmp	%g3
	ba	3f
3:
	wrpr	%g2, %cwp
	retl
	mov	%g1, %o0

dtrace_getreg_win_table:
	mov	%l0, %g1
	mov	%l1, %g1
	mov	%l2, %g1
	mov	%l3, %g1
	mov	%l4, %g1
	mov	%l5, %g1
	mov	%l6, %g1
	mov	%l7, %g1
	mov	%i0, %g1
	mov	%i1, %g1
	mov	%i2, %g1
	mov	%i3, %g1
	mov	%i4, %g1
	mov	%i5, %g1
	mov	%i6, %g1
	mov	%i7, %g1
	SET_SIZE(dtrace_getreg_win)

	ENTRY(dtrace_putreg_win)
	sub	%o0, 16, %o0
	cmp	%o0, 16			! %o0 must be in the range [16..32)
	blu,pt	%xcc, 1f
	nop
	retl
	nop

1:
	mov	%o1, %g1		! move the value into a global register

	set	dtrace_putreg_table, %g3
	sll	%o0, 2, %o0
	add	%g3, %o0, %g3

	rdpr	%canrestore, %o3
	rdpr	%cwp, %g2

	! Set %cwp to be (%cwp - %canrestore - 1) mod NWINDOWS

	sub	%g2, %o3, %o2		! %o2 is %cwp - %canrestore
	subcc	%o2, 1, %o4
	bge,a,pn %xcc, 2f
	wrpr	%o4, %cwp

	sethi	%hi(nwin_minus_one), %o3
	ld	[%o3 + %lo(nwin_minus_one)], %o3
	add	%o2, %o3, %o4
	wrpr	%o4, %cwp
2:
	jmp	%g3
	ba	3f
3:
	wrpr	%g2, %cwp
	retl
	nop

dtrace_putreg_table:
	mov	%g1, %l0
	mov	%g1, %l1
	mov	%g1, %l2
	mov	%g1, %l3
	mov	%g1, %l4
	mov	%g1, %l5
	mov	%g1, %l6
	mov	%g1, %l7
	mov	%g1, %i0
	mov	%g1, %i1
	mov	%g1, %i2
	mov	%g1, %i3
	mov	%g1, %i4
	mov	%g1, %i5
	mov	%g1, %i6
	mov	%g1, %i7
	SET_SIZE(dtrace_putreg_win)

	ENTRY(dtrace_probe_error)
	save	%sp, -SA(MINFRAME), %sp
	sethi	%hi(dtrace_probeid_error), %l0
	ld	[%l0 + %lo(dtrace_probeid_error)], %o0
	mov	%i0, %o1
	mov	%i1, %o2
	mov	%i2, %o3
	mov	%i3, %o4
	call	dtrace_probe
	mov	%i4, %o5
	ret
	restore
	SET_SIZE(dtrace_probe_error)

