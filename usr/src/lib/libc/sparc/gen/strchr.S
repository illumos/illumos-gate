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

	.file	"strchr.s"

/*
 * The strchr() function returns a pointer to the first occurrence of c
 * (converted to a char) in string s, or a null pointer if c does not occur
 * in the string.
 */

#include <sys/asm_linkage.h>

	! Here, we start by checking to see if we're searching the dest
	! string for a null byte.  We have fast code for this, so it's
	! an important special case.  Otherwise, if the string is not
	! word aligned, we check a for the search char a byte at a time
	! until we've reached a word boundary.  Once this has happened
	! some zero-byte finding values are initialized and the string
	! is checked a word at a time

	ENTRY(strchr)

	.align 32

	andcc	%o1, 0xff, %o1		! search only for this one byte
	bz	.searchnullbyte		! faster code for searching null
	andcc	%o0, 3, %o4		! str word aligned ?
	bz,a	.prepword2		! yup, prepare for word-wise search
	sll	%o1, 8, %g1		! start spreading findchar across word

	ldub	[%o0], %o2		! str[0]
	cmp	%o2, %o1		! str[0] == findchar ?
	be	.done			! yup, done
	tst	%o2			! str[0] == 0 ?
	bz	.notfound		! yup, return null pointer
	cmp	%o4, 3			! only one byte needed to align?
	bz	.prepword		! yup, prepare for word-wise search
	inc	%o0			! str++
	ldub	[%o0], %o2		! str[1]
	cmp	%o2, %o1		! str[1] == findchar ?
	be	.done			! yup, done
	tst	%o2			! str[1] == 0 ?
	bz	.notfound		! yup, return null pointer
	cmp	%o4, 2			! only two bytes needed to align?
	bz	.prepword		! yup, prepare for word-wise search
	inc	%o0			! str++
	ldub	[%o0], %o2		! str[2]
	cmp	%o2, %o1		! str[2] == findchar ?
	be	.done			! yup, done
	tst	%o2			! str[2] == 0 ?
	bz	.notfound		! yup, return null pointer
	inc	%o0			! str++

.prepword:
	sll	%o1, 8, %g1		! spread findchar ------+
.prepword2:							!
	sethi	%hi(0x01010101), %o4	! Alan Mycroft's magic1 !
	or	%o1, %g1, %o1		!  across all <---------+
	sethi	%hi(0x80808080), %o5	! Alan Mycroft's magic2	!
	sll	%o1, 16, %g1		!   four bytes <--------+
	or	%o4, %lo(0x01010101), %o4			!
	or	%o1, %g1, %o1		!    of a word <--------+
	or	%o5, %lo(0x80808080), %o5

.searchchar:
	lduw	[%o0], %o2		! src word
	andn	%o5, %o2, %o3		! ~word & 0x80808080
	sub	%o2, %o4, %g1		! word = (word - 0x01010101)
	andcc	%o3, %g1, %g0		! ((word - 0x01010101) & ~word & 0x80808080)
	bnz	.haszerobyte		! zero byte if magic expression != 0
	xor	%o2, %o1, %g1		! tword = word ^ findchar
	andn	%o5, %g1, %o3		! ~tword & 0x80808080
	sub	%g1, %o4, %o2		! (tword - 0x01010101)
	andcc	%o3, %o2, %g0		! ((tword - 0x01010101) & ~tword & 0x80808080)
	bz,a	.searchchar		! no findchar if magic expression == 0
	add	%o0, 4, %o0		! str += 4

	! here we know "word" contains the searched character, but no null
	! byte. if there was a null byte, we would have gone to .haszerobyte
	! "tword" has null bytes where "word" had findchar. Examine "tword"

.foundchar:
	set	0xff000000, %o4		! mask for 1st byte
	andcc	%g1, %o4, %g0		! first byte zero (= found search char) ?
	bz	.done			! yup, done
	set	0x00ff0000, %o5		! mask for 2nd byte
	inc	%o0			! str++
	andcc	%g1, %o5, %g0		! second byte zero (= found search char) ?
	bz	.done			! yup, done
	srl	%o4, 16, %o4		! 0x0000ff00 = mask for 3rd byte
	inc	%o0			! str++
	andcc	%g1, %o4, %g0		! third byte zero (= found search char) ?
	bnz,a	.done			! nope, increment in delay slot
	inc	%o0			! str++

.done:
	retl				! done with leaf function
	nop				! padding

	! Here we know that "word" contains a null byte indicating the
	! end of the string. However, "word" might also contain findchar
	! "tword" (in %g1) has null bytes where "word" had findchar. So
	! check both "tword" and "word"

.haszerobyte:
	set	0xff000000, %o4		! mask for 1st byte
	andcc	%g1, %o4, %g0		! first byte == findchar ?
	bz	.done			! yup, done
	andcc	%o2, %o4, %g0		! first byte == 0 ?
	bz	.notfound		! yup, return null pointer
	set	0x00ff0000, %o4		! mask for 2nd byte
	inc	%o0			! str++
	andcc	%g1, %o4, %g0		! second byte == findchar ?
	bz	.done			! yup, done
	andcc	%o2, %o4, %g0		! second byte == 0 ?
	bz	.notfound		! yup, return null pointer
	srl	%o4, 8, %o4		! mask for 3rd byte = 0x0000ff00
	inc	%o0			! str++
	andcc	%g1, %o4, %g0		! third byte == findchar ?
	bz	.done			! yup, done
	andcc	%o2, %o4, %g0		! third byte == 0 ?
	bz	.notfound		! yup, return null pointer
	andcc	%g1, 0xff, %g0		! fourth byte == findchar ?
	bz	.done			! yup, done
	inc	%o0			! str++

.notfound:
	retl				! done with leaf function
	xor	%o0, %o0, %o0		! return null pointer

	! since findchar == 0, we only have to do one test per item
	! instead of two. This makes the search much faster.

.searchnullbyte:
	bz	.straligned		! str is word aligned
	nop				! padding

	cmp	%o4, 2			! str halfword aligned ?
	be	.s2aligned		! yup
	ldub	[%o0], %o1		! str[0]
	tst	%o1			! byte zero?
	bz	.done2			! yup, done
	cmp	%o4, 3			! only one byte needed to align?
	bz	.straligned		! yup
	inc	%o0			! str++

	! check to see if we're half word aligned, which it better than
	! not being aligned at all.  Search the first half of the word
	! if we are, and then search by whole word.

.s2aligned:
	lduh	[%o0], %o1		! str[]
	srl	%o1, 8, %o4		! %o4<7:0> = first byte
	tst	%o4			! first byte zero ?
	bz	.done2			! yup, done
	andcc	%o1, 0xff, %g0		! second byte zero ?
	bz,a	.done2			! yup, done
	inc	%o0			! str++
	add	%o0, 2, %o0		! str+=2

.straligned:
	sethi	%hi(0x01010101), %o4	! Alan Mycroft's magic1
	sethi	%hi(0x80808080), %o5	! Alan Mycroft's magic2
	or	%o4, %lo(0x01010101), %o4
	or	%o5, %lo(0x80808080), %o5

.searchword:
	lduw	[%o0], %o1		! src word
	andn	%o5, %o1, %o3		! ~word & 0x80808080
	sub	%o1, %o4, %g1		! word = (word - 0x01010101)
	andcc	%o3, %g1, %g0		! ((word - 0x01010101) & ~word & 0x80808080)
	bz,a	.searchword		! no zero byte if magic expression == 0
	add	%o0, 4, %o0		! str += 4

.zerobyte:
	set	0xff000000, %o4		! mask for 1st byte
	andcc	%o1, %o4, %g0		! first byte zero?
	bz	.done2			! yup, done
	set	0x00ff0000, %o5		! mask for 2nd byte
	inc	%o0			! str++
	andcc	%o1, %o5, %g0		! second byte zero?
	bz	.done2			! yup, done
	srl	%o4, 16, %o4		! 0x0000ff00 = mask for 3rd byte
	inc	%o0			! str++
	andcc	%o1, %o4, %g0		! third byte zero?
	bnz,a	.done2			! nope, increment in delay slot
	inc	%o0			! str++
.done2:
    	retl				! return from leaf function
	nop				! padding

	SET_SIZE(strchr)
