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

	.file	"memchr.s"

/*
 * Return the ptr in sptr at which the character c1 appears;
 * or NULL if not found in n chars; don't stop at \0.
 * void *
 * memchr(const void *sptr, int c1, size_t n)
 *  {
 *       if (n != 0) {
 *               unsigned char c = (unsigned char)c1;
 *               const unsigned char *sp = sptr;
 *
 *               do {
 *                       if (*sp++ == c)
 *                               return ((void *)--sp);
 *               } while (--n != 0);
 *       }
 *       return (NULL);
 *  }
 */

#include <sys/asm_linkage.h>

	! The first part of this algorithm focuses on determining
	! whether or not the desired character is in the first few bytes
	! of memory, aligning the memory for word-wise copies, and
	! initializing registers to detect zero bytes

	ENTRY(memchr)

	.align 32

	tst	%o2			! n == 0 ?
	bz	.notfound		! yup, c not found, return null ptr
	andcc	%o0, 3, %o4		! s word aligned ?
	add	%o0, %o2, %o0		! s + n
	sub	%g0, %o2, %o2		! n = -n
	bz	.prepword		! yup, prepare for word-wise search
	and	%o1, 0xff, %o1		! search only for this one byte

	ldub	[%o0 + %o2], %o3	! s[0]
	cmp	%o3, %o1		! s[0] == c ?
	be	.done			! yup, done
	nop				!
	addcc	%o2, 1, %o2		! n++, s++
	bz	.notfound		! c not found in first n bytes
	cmp	%o4, 3			! only one byte needed to align?
	bz	.prepword2		! yup, prepare for word-wise search
	sll	%o1, 8, %g1		! start spreading c across word
	ldub	[%o0 + %o2], %o3	! s[1]
	cmp	%o3, %o1		! s[1] == c ?
	be	.done			! yup, done
	nop				!
	addcc	%o2, 1, %o2		! n++, s++
	bz	.notfound		! c not found in first n bytes
	cmp	%o4, 2			! only two bytes needed to align?
	bz	.prepword3		! yup, prepare for word-wise search
	sethi	%hi(0x01010101), %o4	! start loading Alan Mycroft's magic1
	ldub	[%o0 + %o2], %o3	! s[1]
	cmp	%o3, %o1		! s[1] == c ?
	be	.done			! yup, done
	nop
	addcc	%o2, 1, %o2		! n++, s++
	bz	.notfound		! c not found in first n bytes
	nop

.prepword:
	sll	%o1, 8, %g1		! spread c -------------+
.prepword2:				!			!
	sethi	%hi(0x01010101), %o4	! Alan Mycroft's magic1 !
.prepword3:				!			!
	or	%o1, %g1, %o1		!  across all <---------+
	or	%o4, %lo(0x01010101),%o4! finish loading magic1	!
	sll	%o1, 16, %g1		!   four bytes <--------+
	sll	%o4, 7, %o5		! Alan Mycroft's magic2	!
	or	%o1, %g1, %o1		!    of a word <--------+

.searchchar:
	lduw	[%o0 + %o2], %o3	! src word
.searchchar2:
	addcc	%o2, 4, %o2		! s+=4, n+=4
	bcs	.lastword		! if counter wraps, last word
	xor	%o3, %o1, %g1		! tword = word ^ c
	andn	%o5, %g1, %o3		! ~tword & 0x80808080
	sub	%g1, %o4, %g1		! (tword - 0x01010101)
	andcc	%o3, %g1, %g0		! ((tword - 0x01010101) & ~tword & 0x80808080)
	bz,a	.searchchar2		! c not found if magic expression == 0
	lduw	[%o0 + %o2], %o3	! src word

	! here we know "word" contains the searched character, and no byte in
	! "word" exceeds n. If we had exceeded n, we would have gone to label
	! .lastword. "tword" has null bytes where "word" had c. After
	! restoring "tword" from "(tword - 0x01010101)" in %g1, examine "tword"

.foundchar:
	add	%g1, %o4, %g1		! restore tword
	set	0xff000000, %o4		! mask for 1st byte
	andcc	%g1, %o4, %g0		! first byte zero (= found c) ?
	bz,a	.done			! yup, done
	sub	%o2, 4, %o2		! n -= 4 (undo counter bumping)
	set	0x00ff0000, %o5		! mask for 2nd byte
	andcc	%g1, %o5, %g0		! second byte zero (= found c) ?
	bz,a	.done			! yup, done
	sub	%o2, 3, %o2		! n -= 3 (undo counter bumping)
	srl	%o4, 16, %o4		! 0x0000ff00 = mask for 3rd byte
	andcc	%g1, %o4, %g0		! third byte zero (= found c) ?
	bz,a	.done			! nope, must be fourth byte
	sub	%o2, 2, %o2		! n -= 2 (undo counter bumping)
	sub	%o2, 1, %o2		! n -= 1, if fourth byte
	retl				! done with leaf function
	add	%o0, %o2, %o0		! return pointer to c in s
.done:
	retl				! done with leaf function
	add	%o0, %o2, %o0		! return pointer to c in s
	nop
	nop

	! Here we know that "word" is the last word in the search, and that
	! some bytes possibly exceed n. However, "word" might also contain c.
	! "tword" (in %g1) has null bytes where "word" had c. Examine "tword"
	! while keeping track of number of remaining bytes

.lastword:
	set	0xff000000, %o4		! mask for 1st byte
	sub	%o2, 4, %o2		! n -= 4 (undo counter bumping)
	andcc	%g1, %o4, %g0		! first byte zero (= found c) ?
	bz	.done			! yup, done
	set	0x00ff0000, %o5		! mask for 2nd byte
	addcc	%o2, 1, %o2		! n += 1
	bz	.notfound		! c not found in first n bytes
	andcc	%g1, %o5, %g0		! second byte zero (= found c) ?
	bz	.done			! yup, done
	srl	%o4, 16, %o4		! 0x0000ff00 = mask for 3rd byte
	addcc	%o2, 1, %o2		! n += 1
	bz	.notfound		! c not found in first n bytes
	andcc	%g1, %o4, %g0		! third byte zero (= found c) ?
	bz	.done			! yup, done
	nop				!
	addcc	%o2, 1, %o2		! n += 1
	bz	.notfound		! c not found in first n bytes
	andcc	%g1, 0xff, %g0		! fourth byte zero (= found c) ?
	bz	.done			! yup, done
	nop

.notfound:
	retl				! done with leaf function
	mov	%g0, %o0		! return null pointer

	SET_SIZE(memchr)
