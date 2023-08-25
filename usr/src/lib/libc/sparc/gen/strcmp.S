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
	! In this case, we have multiple routines depending upon the
	! degree to which a string is mis-aligned.

	ENTRY(strcmp)

	.align 32

	subcc	%o0, %o1, %o2		! s1 == s2 ?
	bz	.stringsequal1		! yup, same string, done
	sethi	%hi(0x01010101), %o5	! start loading Mycroft's magic2
	andcc	%o0, 3, %o3		! s1 word-aligned ?
	or	%o5, %lo(0x01010101),%o5! finish loading Mycroft's magic2
	bz	.s1aligned		! yup
	sll	%o5, 7, %o4		! load Mycroft's magic1
	sub	%o3, 4, %o3		! number of bytes till aligned

.aligns1:
	ldub	[%o1 + %o2], %o0	! s1[]
	ldub	[%o1], %g1		! s2[]
	subcc	%o0, %g1, %o0		! s1[] != s2[] ?
	bne	.done			! yup, done
	addcc	%o0, %g1, %g0		! s1[] == 0 ?
	bz	.done			! yup, done
	inccc	%o3			! s1 aligned yet?
	bnz	.aligns1		! nope, compare another pair of bytes
	inc	%o1			! s1++, s2++

.s1aligned:
	andcc	%o1, 3, %o3		! s2 word aligned ?
	bz	.word4			! yup
	cmp	%o3, 2			! s2 half-word aligned ?
	be	.word2			! yup
	cmp	%o3, 3			! s2 offset to dword == 3 ?
	be,a	.word3			! yup
	ldub	[%o1], %o0		! new lower word in s2

.word1:
	lduw	[%o1 - 1], %o0		! new lower word in s2
	sethi	%hi(0xff000000), %o3	! mask for forcing byte 1 non-zero
	sll	%o0, 8, %g1		! partial unaligned word from s2
	or	%o0, %o3, %o0		! force byte 1 non-zero

.cmp1:
	andn	%o4, %o0, %o3		! ~word & 0x80808080
	sub	%o0, %o5, %o0		! word - 0x01010101
	andcc	%o0, %o3, %g0		! (word - 0x01010101) & ~word & 0x80808080
	bz,a	.doload1		! no null byte in previous word from s2
	lduw	[%o1 + 3], %o0		! load next aligned word from s2
.doload1:
	srl	%o0, 24, %o3		! byte 1 of new aligned word from s2
	or	%g1, %o3, %g1		! merge to get unaligned word from s2
	lduw	[%o1 + %o2], %o3	! word from s1
	cmp	%o3, %g1		! *s1 != *s2 ?
	bne	.wordsdiffer		! yup, find the byte that is different
	add	%o1, 4, %o1		! s1+=4, s2+=4
	andn	%o4, %o3, %g1		! ~word & 0x80808080
	sub	%o3, %o5, %o3		! word - 0x01010101
	andcc	%o3, %g1, %g0		! (word - 0x01010101) & ~word & 0x80808080
	bz	.cmp1			! no null-byte in s1 yet
	sll	%o0, 8, %g1		! partial unaligned word from s2

	! words are equal but the end of s1 has been reached
	! this means the strings must be equal
.stringsequal1:
	retl				! return from leaf function
	mov	%g0, %o0		! return 0, i.e. strings are equal
	nop				! pad for optimal alignment of .cmp2
	nop				! pad for optimal alignment of .cmp2

.word2:
	lduh	[%o1], %o0		! new lower word in s2
	sethi	%hi(0xffff0000), %o3	! mask for forcing bytes 1,2 non-zero
	sll	%o0, 16, %g1		! partial unaligned word from s2
	or	%o0, %o3, %o0		! force bytes 1,2 non-zero

.cmp2:
	andn	%o4, %o0, %o3		! ~word & 0x80808080
	sub	%o0, %o5, %o0		! word - 0x01010101
	andcc	%o0, %o3, %g0		! (word - 0x01010101) & ~word & 0x80808080
	bz,a	.doload2		! no null byte in previous word from s2
	lduw	[%o1 + 2], %o0		! load next aligned word from s2
.doload2:
	srl	%o0, 16, %o3		! bytes 1,2 of new aligned word from s2
	or	%g1, %o3, %g1		! merge to get unaligned word from s2
	lduw	[%o1 + %o2], %o3	! word from s1
	cmp	%o3, %g1		! *s1 != *s2 ?
	bne	.wordsdiffer		! yup, find the byte that is different
	add	%o1, 4, %o1		! s1+=4, s2+=4
	andn	%o4, %o3, %g1		! ~word & 0x80808080
	sub	%o3, %o5, %o3		! word - 0x01010101
	andcc	%o3, %g1, %g0		! (word - 0x01010101) & ~word & 0x80808080
	bz	.cmp2			! no null-byte in s1 yet
	sll	%o0, 16, %g1		! partial unaligned word from s2

	! words are equal but the end of s1 has been reached
	! this means the strings must be equal
.stringsequal2:
	retl				! return from leaf function
	mov	%g0, %o0		! return 0, i.e. strings are equal

.word3:
	sll	%o0, 24, %g1		! partial unaligned word from s2
	nop				! pad for optimal alignment of .cmp3
.cmp3:
	andcc	%o0, 0xff, %g0		! did previous word contain null-byte ?
	bnz,a	.doload3		! nope, load next word from s2
	lduw	[%o1 + 1], %o0		! load next aligned word from s2
.doload3:
	srl	%o0, 8, %o3		! bytes 1,2,3 from new aligned s2 word
	or	%g1, %o3, %g1		! merge to get unaligned word from s2
	lduw	[%o1 + %o2], %o3	! word from s1
	cmp	%o3, %g1		! *s1 != *s2 ?
	bne	.wordsdiffer		! yup, find the byte that is different
	add	%o1, 4, %o1		! s1+=4, s2+=4
	andn	%o4, %o3, %g1		! ~word & 0x80808080
	sub	%o3, %o5, %o3		! word - 0x01010101
	andcc	%o3, %g1, %g0		! (word - 0x01010101) & ~word & 0x80808080
	bz	.cmp3			! no null-byte in s1 yet
	sll	%o0, 24, %g1		! partial unaligned word from s2

	! words are equal but the end of s1 has been reached
	! this means the strings must be equal
.stringsequal3:
	retl				! return from leaf function
	mov	%g0, %o0		! return 0, i.e. strings are equal

.word4:
	lduw	[%o1 + %o2], %o3	! load word from s1
	nop				! pad for optimal alignment of .cmp4
	nop				! pad for optimal alignment of .cmp4
	nop				! pad for optimal alignment of .cmp4

.cmp4:
	lduw	[%o1], %g1		! load word from s2
	cmp	%o3, %g1		! *scr1 == *src2 ?
	bne	.wordsdiffer		! nope, find mismatching character
	add	%o1, 4, %o1		! src1 += 4, src2 += 4
	andn	%o4, %o3, %o0		! ~word & 0x80808080
	sub	%o3, %o5, %o3		! word - 0x01010101
	andcc	%o3, %o0, %g0		! (word - 0x01010101) & ~word & 0x80808080
	bz,a	.cmp4			! no null-byte in s1 yet
	lduw	[%o1 + %o2], %o3	! load word from s1

	! words are equal but the end of s1 has been reached
	! this means the strings must be equal
.stringsequal4:
	retl				! return from leaf function
	mov	%g0, %o0		! return 0, i.e. strings are equal

.wordsdiffer:
	srl	%g1, 24, %o2		! first byte of mismatching word in s2
	srl	%o3, 24, %o1		! first byte of mismatching word in s1
	subcc	%o1, %o2, %o0		! *s1-*s2
	bnz	.done			! bytes differ, return difference
	srl	%g1, 16, %o2		! second byte of mismatching word in s2
	andcc	%o1, 0xff, %o0		! *s1 == 0 ?
	bz	.done			! yup

	! we know byte 1 is equal, so can compare bytes 1,2 as a group

	srl	%o3, 16, %o1		! second byte of mismatching word in s1
	subcc	%o1, %o2, %o0		! *s1-*s2
	bnz	.done			! bytes differ, return difference
	srl	%g1, 8, %o2		! third byte of mismatching word in s2
	andcc	%o1, 0xff, %o0		! *s1 == 0 ?
	bz	.done			! yup

	! we know bytes 1, 2 are equal, so can compare bytes 1,2,3 as a group

	srl	%o3, 8, %o1		! third byte of mismatching word in s1
	subcc	%o1, %o2, %o0		! *s1-*s2
	bnz	.done			! bytes differ, return difference
	andcc	%o1, 0xff, %g0		! *s1 == 0 ?
	bz	.stringsequal1		! yup

	! we know bytes 1,2,3 are equal, so can compare bytes 1,2,3,4 as group

	subcc	%o3, %g1, %o0		! *s1-*s2
	bz,a	.done			! bytes differ, return difference
	andcc	%o3, 0xff, %o0		! *s1 == 0 ?

.done:
	retl				! return from leaf routine
	nop				! padding


	SET_SIZE(strcmp)
