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
 * Copyright (c) 2000, 2010, Oracle and/or its affiliates. All rights reserved.
 */

	.file	"memcmp.s"

/*
 * memcmp(s1, s2, len)
 *
 * Compare n bytes:  s1>s2: >0  s1==s2: 0  s1<s2: <0
 *
 * Fast assembler language version of the following C-program for memcmp
 * which represents the `standard' for the C-library.
 *
 *	int
 *	memcmp(const void *s1, const void *s2, size_t n)
 *	{
 *		if (s1 != s2 && n != 0) {
 *			const char *ps1 = s1;
 *			const char *ps2 = s2;
 *			do {
 *				if (*ps1++ != *ps2++)
 *					return(ps1[-1] - ps2[-1]);
 *			} while (--n != 0);
 *		}
 *		return (0);
 *	}
 */

#include <sys/asm_linkage.h>
#include <sys/machasi.h>

#define	BLOCK_SIZE	64

	ANSI_PRAGMA_WEAK(memcmp,function)

	ENTRY(memcmp)
	cmp	%o0, %o1		! s1 == s2?
	be	%ncc, .cmpeq
	prefetch [%o0], #one_read
	prefetch [%o1], #one_read

	! for small counts byte compare immediately
	cmp	%o2, 48
	bleu,a 	%ncc, .bytcmp
	mov	%o2, %o3		! o3 <= 48

	! Count > 48. We will byte compare (8 + num of bytes to dbl align)
	! bytes. We assume that most miscompares will occur in the 1st 8 bytes

	prefetch [%o0 + (1 * BLOCK_SIZE)], #one_read
	prefetch [%o1 + (1 * BLOCK_SIZE)], #one_read

.chkdbl:
	and     %o0, 7, %o4             ! is s1 aligned on a 8 byte bound
	mov	8, %o3			! o2 > 48;  o3 = 8
        sub     %o4, 8, %o4		! o4 = -(num of bytes to dbl align)
	ba	%ncc, .bytcmp
        sub     %o3, %o4, %o3           ! o3 = 8 + (num of bytes to dbl align)

1:	ldub	[%o1], %o5        	! byte compare loop
        inc     %o1
        inc     %o0
	dec	%o2
        cmp     %o4, %o5
	bne	%ncc, .noteq
.bytcmp:
	deccc   %o3
	bgeu,a	%ncc, 1b
        ldub    [%o0], %o4

	! Check to see if there are more bytes to compare
	cmp	%o2, 0			! is o2 > 0
	bgu	%ncc, .dwcmp		! we should already be dbl aligned
	nop
.cmpeq:
        retl                             ! strings compare equal
	sub	%g0, %g0, %o0

.noteq:
	retl				! strings aren't equal
	sub	%o4, %o5, %o0		! return(*s1 - *s2)


        ! double word compare - using ldd and faligndata. Compares upto
        ! 8 byte multiple count and does byte compare for the residual.

.dwcmp:
	prefetch [%o0 + (2 * BLOCK_SIZE)], #one_read
	prefetch [%o1 + (2 * BLOCK_SIZE)], #one_read

        ! if fprs.fef == 0, set it. Checking it, reqires 2 instructions.
        ! So set it anyway, without checking.
        rd      %fprs, %o3              ! o3 = fprs
        wr      %g0, 0x4, %fprs         ! fprs.fef = 1

        andn    %o2, 7, %o4             ! o4 has 8 byte aligned cnt
	sub     %o4, 8, %o4
        alignaddr %o1, %g0, %g1
        ldd     [%g1], %d0
4:
        add     %g1, 8, %g1
        ldd     [%g1], %d2
	ldd	[%o0], %d6
	prefetch [%g1 + (3 * BLOCK_SIZE)], #one_read
	prefetch [%o0 + (3 * BLOCK_SIZE)], #one_read
        faligndata %d0, %d2, %d8
	fcmpne32 %d6, %d8, %o5
	fsrc1	%d6, %d6		! 2 fsrc1's added since o5 cannot
	fsrc1	%d8, %d8		! be used for 3 cycles else we
	fmovd	%d2, %d0		! create 9 bubbles in the pipeline
	brnz,a,pn %o5, 6f
	sub     %o1, %o0, %o1           ! o1 gets the difference
        subcc   %o4, 8, %o4
        add     %o0, 8, %o0
        add     %o1, 8, %o1
        bgu,pt	%ncc, 4b
        sub     %o2, 8, %o2

.residcmp:
        ba      6f
	sub     %o1, %o0, %o1           ! o1 gets the difference

5:      ldub    [%o0 + %o1], %o5        ! byte compare loop
        inc     %o0
        cmp     %o4, %o5
        bne     %ncc, .dnoteq
6:
        deccc   %o2
        bgeu,a	%ncc, 5b
        ldub    [%o0], %o4

	and     %o3, 0x4, %o3           ! fprs.du = fprs.dl = 0
	wr      %o3, %g0, %fprs         ! fprs = o3 - restore fprs
	retl
	sub	%g0, %g0, %o0		! strings compare equal

.dnoteq:
	and     %o3, 0x4, %o3           ! fprs.du = fprs.dl = 0
	wr      %o3, %g0, %fprs         ! fprs = o3 - restore fprs
	retl
	sub	%o4, %o5, %o0		! return(*s1 - *s2)

	SET_SIZE(memcmp)
