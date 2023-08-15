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

	.file	"strcpy.s"

/*
 * strcpy(s1, s2)
 *
 * Copy string s2 to s1.  s1 must be large enough. Return s1.
 *
 * Fast assembler language version of the following C-program strcpy
 * which represents the `standard' for the C-library.
 *
 *	char *
 *	strcpy(s1, s2)
 *	register char *s1;
 *	register const char *s2;
 *	{
 *		char *os1 = s1;
 *
 *		while(*s1++ = *s2++)
 *			;
 *		return(os1);
 *	}
 *
 */

#include <sys/asm_linkage.h>

	! This is a 32-bit implementation of strcpy.  It works by
	! first checking the alignment of its source pointer. And,
	! if it is not aligned, attempts to copy bytes until it is.
	! once this has occurred, the copy takes place, while checking
	! for zero bytes, based upon destination alignment.
	! Methods exist to handle per-byte, half-word, and word sized
	! copies.

	ENTRY(strcpy)

	.align 32

	sub	%o1, %o0, %o3		! src - dst
	andcc	%o1, 3, %o4		! src word aligned ?
	bz	.srcaligned		! yup
	mov	%o0, %o2		! save dst

	cmp	%o4, 2			! src halfword aligned
	be	.s2aligned		! yup
	ldub	[%o2 + %o3], %o1	! src[0]
	tst	%o1			! byte zero?
	stb	%o1, [%o2]		! store first byte
	bz	.done			! yup, done
	cmp	%o4, 3			! only one byte needed to align?
	bz	.srcaligned		! yup
	inc	%o2			! src++, dst++

.s2aligned:
	lduh	[%o2 + %o3], %o1	! src[]
	srl	%o1, 8, %o4		! %o4<7:0> = first byte
	tst	%o4			! first byte zero ?
	bz	.done			! yup, done
	stb	%o4, [%o2]		! store first byte
	andcc	%o1, 0xff, %g0		! second byte zero ?
	bz	.done			! yup, done
	stb	%o1, [%o2 + 1]		! store second byte
	add	%o2, 2, %o2		! src += 2, dst += 2

.srcaligned:
	sethi	%hi(0x01010101), %o4	! Alan Mycroft's magic1
	sethi	%hi(0x80808080), %o5	! Alan Mycroft's magic2
	or	%o4, %lo(0x01010101), %o4
	andcc	%o2, 3, %o1		! destination word aligned?
	bnz	.dstnotaligned		! nope
	or	%o5, %lo(0x80808080), %o5

.copyword:
	lduw	[%o2 + %o3], %o1	! src word
	add	%o2, 4, %o2		! src += 4, dst += 4
	andn	%o5, %o1, %g1		! ~word & 0x80808080
	sub	%o1, %o4, %o1		! word - 0x01010101
	andcc	%o1, %g1, %g0		! ((word - 0x01010101) & ~word & 0x80808080)
	add	%o1, %o4, %o1		! restore word
	bz,a	.copyword		! no zero byte if magic expression == 0
	st	%o1, [%o2 - 4]		! store word to dst (address pre-incremented)

.zerobyte:
	set	0xff000000, %o4		! mask for 1st byte
	srl	%o1, 24, %o3		! %o3<7:0> = first byte
	andcc	%o1, %o4, %g0		! first byte zero?
	bz	.done			! yup, done
	stb	%o3, [%o2 - 4]		! store first byte
	set	0x00ff0000, %o5		! mask for 2nd byte
	srl	%o1, 16, %o3		! %o3<7:0> = second byte
	andcc	%o1, %o5, %g0		! second byte zero?
	bz	.done			! yup, done
	stb	%o3, [%o2 - 3]		! store second byte
	srl	%o4, 16, %o4		! 0x0000ff00 = mask for 3rd byte
	andcc	%o1, %o4, %g0		! third byte zero?
	srl	%o1, 8, %o3		! %o3<7:0> = third byte
	bz	.done			! yup, done
	stb	%o3, [%o2 - 2]		! store third byte
	stb	%o1, [%o2 - 1]		! store fourth byte

.done:
	retl				! done with leaf function
	.empty

.dstnotaligned:
	cmp	%o1, 2			! dst half word aligned?
	be,a	.storehalfword2		! yup, store half word at a time
	lduw	[%o2 + %o3], %o1	! src word

.storebyte:
	lduw	[%o2 + %o3], %o1	! src word
	add	%o2, 4, %o2		! src += 4, dst += 4
	sub	%o1, %o4, %g1		! x - 0x01010101
	andn	%g1, %o1, %g1		! (x - 0x01010101) & ~x
	andcc	%g1, %o5, %g0		! ((x - 0x01010101) & ~x & 0x80808080)
	bnz	.zerobyte		! word has zero byte, handle end cases
	srl	%o1, 24, %g1		! %g1<7:0> = first byte
	stb	%g1, [%o2 - 4]		! store first byte; half-word aligned now
	srl	%o1, 8, %g1		! %g1<15:0> = byte 2, 3
	sth	%g1, [%o2 - 3]		! store bytes 2, 3
	ba	.storebyte		! next word
	stb	%o1, [%o2 - 1]		! store fourth byte

.storehalfword:
	lduw	[%o2 + %o3], %o1	! src word
.storehalfword2:
	add	%o2, 4, %o2		! src += 4, dst += 4
	sub	%o1, %o4, %g1		! x - 0x01010101
	andn	%g1, %o1, %g1		! (x - 0x01010101) & ~x
	andcc	%g1, %o5, %g0		! ((x - 0x01010101) & ~x & 0x80808080)
	bnz	.zerobyte		! word has zero byte, handle end cases
	srl	%o1, 16, %g1		! get first and second byte
	sth	%g1, [%o2 - 4]		! store first and second byte
	ba	.storehalfword		! next word
	sth	%o1, [%o2 - 2]		! store third and fourth byte

	! DO NOT remove these NOPs. It will slow down the halfword loop by 15%

	nop				! padding
	nop				! padding

	SET_SIZE(strcpy)

