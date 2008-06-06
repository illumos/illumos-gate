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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

	.file	"%M%"

/*
 * strncmp(s1, s2, n)
 *
 * Compare strings (at most n bytes):  s1>s2: >0  s1==s2: 0  s1<s2: <0
 *
 * Fast assembler language version of the following C-program for strncmp
 * which represents the `standard' for the C-library.
 *
 *	int
 *	strncmp(const char *s1, const char *s2, size_t n)
 *	{
 *		n++;
 *		if (s1 == s2)
 *			return (0);
 *		while (--n != 0 && *s1 == *s2++)
 *			if(*s1++ == '\0')
 *				return(0);
 *		return ((n == 0) ? 0 : (*s1 - s2[-1]));
 *	}
 */

#include <sys/asm_linkage.h>

	ENTRY(strncmp)
	save	%sp, -SA(WINDOWSIZE), %sp
	cmp	%i2, 8
	blu,a,pn %xcc, .cmp_bytes	! for small counts go do bytes
	sub	%i0, %i1, %i0		! delay slot, get diff from s1 - s2
	andcc	%i0, 3, %g0		! is s1 aligned
1:	bz,pn	%icc, .iss2		! if so go check s2
	andcc	%i1, 3, %i3		! is s2 aligned

	deccc	%i2			! --n >= 0 ?
	bcs,pn	%xcc, .doneq
	nop				! delay slot

	ldub	[%i0], %i4		! else cmp one byte
	ldub	[%i1], %i5
	inc	%i0
	cmp	%i4, %i5
	bne,pn	%icc, .noteqb
	inc	%i1
	tst	%i4			! terminating zero
	bnz,pt	%icc, 1b
	andcc	%i0, 3, %g0
	b,a	.doneq

.iss2:
	set     0x7efefeff, %l6
	set     0x81010100, %l7
	sethi	%hi(0xff000000), %l0	! masks to test for terminating null
	sethi	%hi(0x00ff0000), %l1
	srl	%l1, 8, %l2		! generate 0x0000ff00 mask

	bz,pn	%icc, .w4cmp		! if s2 word aligned, compare words
	cmp	%i3, 2			! check if s2 half aligned
	be,pn	%icc, .w2cmp
	cmp	%i3, 1			! check if aligned to 1 or 3 bytes
.w3cmp:	ldub	[%i1], %i5
	inc	1, %i1
	be,pt	%icc, .w1cmp
	sll	%i5, 24, %i5
	sub	%i0, %i1, %i0
2:
	deccc	4, %i2			! n >= 4 ?
	bgeu,a,pt %xcc, 3f
	lduw	[%i1], %i3		! delay slot
	dec	%i1			! reset s2
	inc	%i0			! reset s1 diff
	b	.cmp_bytes		! do a byte at a time if n < 4
	inc	4, %i2
3:
	lduw	[%i0 + %i1], %i4
	inc	4, %i1
	srl	%i3, 8, %l4		! merge with the other half
	or	%l4, %i5, %i5
	cmp	%i4, %i5
	be,pn	%icc, 1f

	add	%i4, %l6, %l3
	b,a	.noteq
1:	xor	%l3, %i4, %l3
	and	%l3, %l7, %l3
	cmp	%l3, %l7
	be,a,pt	%icc, 2b
	sll	%i3, 24, %i5

	!
	! For 7-bit characters, we know one of the bytes is zero, but for
	! 8-bit characters, the zero detection algorithm gives some false
	! triggers ... check every byte individually.
	!
	andcc	%i4, %l0, %g0		! check if first byte was zero
	bnz,pt	%icc, 1f
	andcc	%i4, %l1, %g0		! check if second byte was zero
	b,a	.doneq
1:	bnz,pt	%icc, 1f
	andcc 	%i4, %l2, %g0		! check if third byte was zero
	b,a	.doneq
1:	bnz,pt	%icc, 1f
	andcc	%i4, 0xff, %g0		! check if last byte is zero
	b,a	.doneq
1:	bnz,pn	%icc, 2b
	sll	%i3, 24, %i5
	b,a	.doneq

.w1cmp:	clr	%l4
	lduh	[%i1], %l4
	inc	2, %i1
	sll	%l4, 8, %l4
	or	%i5, %l4, %i5

	sub	%i0, %i1, %i0
3:
	deccc	4, %i2			! n >= 4 ?
	bgeu,a,pt %xcc, 4f
	lduw	[%i1], %i3		! delay slot
	dec	3, %i1			! reset s2
	inc	3, %i0			! reset s1 diff
	b	.cmp_bytes		! do a byte at a time if n < 4
	inc	4, %i2
4:
	lduw	[%i0 + %i1], %i4
	inc	4, %i1
	srl	%i3, 24, %l4		! merge with the other half
	or	%l4, %i5, %i5
	cmp	%i4, %i5
	be,pt	%icc, 1f

	add	%i4, %l6, %l3
	b,a	.noteq
1:	xor	%l3, %i4, %l3
	and	%l3, %l7, %l3
	cmp	%l3, %l7
	be,a,pt	%icc, 3b
	sll	%i3, 8, %i5

	andcc	%i4, %l0, %g0		! check if first byte was zero
	bnz,pt	%icc, 1f
	andcc	%i4, %l1, %g0		! check if second byte was zero
	b,a	.doneq
1:	bnz,pt	%icc, 1f
	andcc 	%i4, %l2, %g0		! check if third byte was zero
	b,a	.doneq
1:	bnz,pt	%icc, 1f
	andcc	%i4, 0xff, %g0		! check if last byte is zero
	b,a	.doneq
1:	bnz,pn	%icc, 3b
	sll	%i3, 8, %i5
	b,a	.doneq

.w2cmp:
	lduh	[%i1], %i5		! read a halfword to align s2
	inc	2, %i1
	sll	%i5, 16, %i5

	sub	%i0, %i1, %i0
4:
	deccc	4, %i2			! n >= 4 ?
	bgeu,a,pt %xcc, 5f
	lduw	[%i1], %i3		! delay slot
	dec	2, %i1			! reset s2
	inc	2, %i0			! reset s1 diff
	b	.cmp_bytes		! do a byte at a time if n < 4
	inc	4, %i2			! delay slot
5:
	lduw	[%i1 + %i0], %i4	! read a word from s2
	inc	4, %i1
	srl	%i3, 16, %l4		! merge with the other half
	or	%l4, %i5, %i5
	cmp	%i4, %i5
	be,pt	%icc, 1f

	add	%i4, %l6, %l3
	b,a	.noteq
1:	xor	%l3, %i4, %l3		! are any bytes 0?
	and	%l3, %l7, %l3
	cmp	%l3, %l7
	be,a,pt	%icc, 4b
	sll	%i3, 16, %i5

	andcc	%i4, %l0, %g0		! check if first byte was zero
	bnz,pt	%icc, 1f
	andcc	%i4, %l1, %g0		! check if second byte was zero
	b,a	.doneq
1:	bnz,pt	%icc, 1f
	andcc 	%i4, %l2, %g0		! check if third byte was zero
	b,a	.doneq
1:	bnz,pt	%icc, 1f
	andcc	%i4, 0xff, %g0		! check if last byte is zero
	b,a	.doneq
1:	bnz,pn	%icc, 4b
	sll	%i3, 16, %i5
	b,a	.doneq

.w4cmp:	sub	%i0, %i1, %i0
	lduw	[%i1], %i5		! read a word from s1
5:	cmp	%i2, 0
	be,a,pn	%xcc, .doneq
	nop
	lduw	[%i1], %i5		! read a word from s1
	deccc	4, %i2			! n >= 4 ?
	bcs,a,pn %xcc, .cmp_bytes	! do a byte at a time if n < 4
	inc	4, %i2

	lduw	[%i1 + %i0], %i4	! read a word from s2
	cmp	%i4, %i5
	inc	4, %i1
	be,pt	%icc, 1f

	add	%i4, %l6, %l3
	b,a	.noteq
1:	xor	%l3, %i4, %l3
	and	%l3, %l7, %l3
	cmp	%l3, %l7
	be,pt	%icc, 5b
	nop

	andcc	%i4, %l0, %g0		! check if first byte was zero
	bnz,pt	%icc, 1f
	andcc	%i4, %l1, %g0		! check if second byte was zero
	b,a	.doneq
1:	bnz,pt	%icc, 1f
	andcc 	%i4, %l2, %g0		! check if third byte was zero
	b,a	.doneq
1:	bnz,pt	%icc, 1f
	andcc	%i4, 0xff, %g0		! check if last byte is zero
	b,a	.doneq
1:	bnz,a,pn %icc, 5b
	lduw	[%i1], %i5
.doneq:	ret
	restore	%g0, %g0, %o0		! equal return zero

.noteq:	srl	%i4, 24, %l4
	srl	%i5, 24, %l5
	subcc	%l4, %l5, %i0
	bne,pt	%icc, 6f
	andcc	%l4, 0xff, %g0
	bz	.doneq
	sll	%i4, 8, %l4
	sll	%i5, 8, %l5
	srl	%l4, 24, %l4
	srl	%l5, 24, %l5
	subcc	%l4, %l5, %i0
	bne,pt	%icc, 6f
	andcc	%l4, 0xff, %g0
	bz,pt	%icc, .doneq
	sll	%i4, 16, %l4
	sll	%i5, 16, %l5
	srl	%l4, 24, %l4
	srl	%l5, 24, %l5
	subcc	%l4, %l5, %i0
	bne,pt	%icc, 6f
	andcc	%l4, 0xff, %g0
	bz,pt	%icc, .doneq
	nop
.noteqb:
	and	%i4, 0xff, %l4
	and	%i5, 0xff, %l5
	subcc	%l4, %l5, %i0
6:	ret
	restore	%i0, %g0, %o0

	! Do a byte by byte comparison, disregarding alignments
.cmp_bytes:
	deccc	%i2			! --n >= 0 ?
1:
	bcs,pn	%xcc, .doneq
	nop				! delay slot
	ldub	[%i1 + %i0], %i4	! read a byte from s1
	ldub	[%i1], %i5		! read a byte from s2

	inc	%i1
	cmp	%i4, %i5
	bne,pt	%icc, .noteqb
	tst	%i4			! terminating zero
	bnz,pt	%icc, 1b
	deccc	%i2			! --n >= 0
	b,a	.doneq

	SET_SIZE(strncmp)
