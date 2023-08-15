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
 */

	.file	"strcmp.s"

/* strcmp(s1, s2)
 *
 * Compare strings:  s1>s2: >0  s1==s2: 0  s1<s2: <0
 *
 * Fast assembler language version of the following C-program for strcmp
 * which represents the `standard' for the C-library.
 *
 *	int
 *	strcmp(s1, s2)
 *	register const char *s1;
 *	register const char *s2;
 *	{
 *
 *		if(s1 == s2)
 *			return(0);
 *		while(*s1 == *s2++)
 *			if(*s1++ == '\0')
 *				return(0);
 *		return(*s1 - s2[-1]);
 *	}
 */

#include <sys/asm_linkage.h>

	! This strcmp implementation first determines whether s1 is aligned.
	! If it is not, it attempts to align it and then checks the
	! alignment of the destination string.  If it is possible to
	! align s2, this also happens and then the compare begins.  Otherwise,
	! a different compare for non-aligned strings is used.

	ENTRY(strcmp)

	.align 32

	subcc	%o0, %o1, %o2		! s1 == s2 ?
	bz,pn	%xcc, .stringsequal	! yup, same string, done
 	sethi	%hi(0x01010101), %o5	! magic2<31:13>
	andcc	%o0, 7, %o3		! s1 sword-aligned ?
	or	%o5, %lo(0x01010101),%o5! magic2<31:0>
	bz,pn	%xcc, .s1aligned	! yup
	sllx	%o5, 32, %o4		! magic2<63:32>
	sub 	%o3, 8, %o3		! number of bytes till s1 aligned

.aligns1:
	ldub	[%o1 + %o2], %o0	! s1[]
	ldub	[%o1], %g1		! s2[]
	subcc	%o0, %g1, %o0		! s1[] != s2[] ?
	bne,pn	%xcc, .done		! yup, done
	addcc	%o0, %g1, %g0		! s1[] == 0 ?
	bz,pn	%xcc, .done		! yup, done
	inccc	%o3			! s1 aligned yet?
	bnz,pt	%xcc, .aligns1		! nope, compare another pair of bytes
	inc	%o1			! s1++, s2++

.s1aligned:
	andcc	%o1, 7, %o3		! s2 dword aligned ?
	or	%o5, %o4, %o5		! magic2<63:0>
	bz,pn	%xcc, .s2aligned	! yup
	sllx	%o5, 7, %o4		! magic1
	sllx	%o3, 3, %g5		! leftshift = 8*ofs
	orn	%g0, %g0, %g1		! all ones
	and	%o1, -8, %o1		! round s1 down to next aligned dword
	srlx	%g1, %g5, %g1		! mask for fixing up bytes
	ldx	[%o1], %o0		! new lower dword in s2
	orn	%o0, %g1, %o0 		! force start bytes to non-zero
	sub	%g0, %g5, %g4		! rightshift = -(8*ofs) mod 64
	sllx	%o0, %g5, %g1		! partial unaligned word from s2
	add	%o2, %o3, %o2		! adjust pointers
	nop				! align loop to 16-byte boundary
	nop				! align loop to 16-byte boundary

.cmp:
	andn	%o4, %o0, %o3		! ~word & 0x80808080
	sub	%o0, %o5, %o0		! word - 0x01010101
	andcc	%o0, %o3, %g0		! (word - 0x01010101) & ~word & 0x80808080
	bz,a,pt	%xcc, .doload		! no null byte in previous word from s2
 	ldx	[%o1+8], %o0		! next aligned word in s2
.doload:
	srlx	%o0, %g4, %o3		! bytes from aligned word from s2
	or	%g1, %o3, %g1		! merge to get unaligned word from s2
	ldx	[%o1 + %o2], %o3	! word from s1
	cmp	%o3, %g1		! *s1 != *s2 ?
	bne,pn	%xcc, .wordsdiffer	! yup, find the byte that is different
	add	%o1, 8, %o1		! s1+=8, s2+=8
	andn	%o4, %o3, %g1		! ~word & 0x80808080
	sub	%o3, %o5, %o3		! word - 0x01010101
	andcc	%o3, %g1, %g0		! (word - 0x01010101) & ~word & 0x80808080
	bz,pt	%xcc, .cmp		! no null-byte in s1 yet
	sllx	%o0, %g5, %g1		! partial unaligned word from s2

	! words are equal but the end of s1 has been reached
	! this means the strings must be equal
.strequal:
	retl				! return from leaf function
	mov	%g0, %o0		! return 0, i.e. strings are equal
	nop

.s2aligned:
	ldx	[%o1 + %o2], %o3	! load word from s1

.cmpaligned:
	ldx	[%o1], %g1		! load word from s2
	cmp	%o3, %g1		! *scr1 == *src2 ?
	bne,pn	%xcc, .wordsdiffer	! nope, find mismatching character
	add	%o1, 8, %o1		! src1 += 8, src2 += 8
	andn	%o4, %o3, %o0		! ~word & 0x80808080
	sub	%o3, %o5, %o3		! word - 0x01010101
	andcc	%o3, %o0, %g0		! (word - 0x01010101) & ~word & 0x80808080
	bz,a,pt	%xcc, .cmpaligned	! no null-byte in s1 yet
	ldx	[%o1 + %o2], %o3	! load word from s1

	! words are equal but the end of s1 has been reached
	! this means the strings must be equal

.stringsequal:
	retl				! return from leaf function
	mov	%g0, %o0		! return 0, i.e. strings are equal
	nop				! align loop on 16-byte boundary
	nop				! align loop on 16-byte boundary
	nop				! align loop on 16-byte boundary

.wordsdiffer:
	mov	56, %o4			! initial shift count
	srlx	%g1, %o4, %o2		! first byte of mismatching word in s2
.cmpbytes:
	srlx	%o3, %o4, %o1		! first byte of mismatching word in s1
	subcc	%o1, %o2, %o0		! *s1-*s2
	bnz,pn	%xcc, .done		! bytes differ, return difference
	nop
	andcc	%o1, 0xff, %o0		! *s1 == 0 ?
	bz,pn	%xcc, .done		! yup, strings match
	subcc	%o4, 8, %o4		! shift_count -= 8
	bpos,pt	%xcc, .cmpbytes		! until all bytes processed
	srlx	%g1, %o4, %o2		! first byte of mismatching word in s2

.done:
	retl				! return from leaf routine
	nop				! padding

	SET_SIZE(strcmp)
