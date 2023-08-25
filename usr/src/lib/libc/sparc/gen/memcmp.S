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
 *					return (ps1[-1] - ps2[-1]);
 *			} while (--n != 0);
 *		}
 *		return (NULL);
 *	}
 */

#include <sys/asm_linkage.h>

	ANSI_PRAGMA_WEAK(memcmp,function)

	ENTRY(memcmp)
	st	%g2, [%sp + 68]		! g2 must be restored before retl
	cmp	%o0, %o1		! s1 == s2?
	be	.cmpeq
	cmp	%o2, 17
	bleu,a	.cmpbyt			! for small counts go do bytes
	sub	%o1, %o0, %o1

	andcc	%o0, 3, %o3		! is s1 aligned?
	bz,a	.iss2			! if so go check s2
	andcc	%o1, 3, %o4		! is s2 aligned?
	cmp	%o3, 2
	be	.algn2
	cmp	%o3, 3

.algn1:	ldub	[%o0], %o4		! cmp one byte
	inc	%o0
	ldub	[%o1], %o5
	inc	%o1
	dec	%o2
	be	.algn3
	cmp	%o4, %o5
	be	.algn2
	nop
	b,a	.noteq

.algn2:	lduh	[%o0], %o4
	inc	2, %o0
	ldub	[%o1], %o5
	inc	1, %o1
	srl	%o4, 8, %o3
	cmp	%o3, %o5
	be,a	1f
	ldub	[%o1], %o5		! delay slot, get next byte from s2
	b	.noteq
	mov	%o3, %o4		! delay slot, move *s1 to %o4
1:	inc	%o1
	dec	2, %o2
	and	%o4, 0xff, %o4
	cmp	%o4, %o5
.algn3:	be,a	.iss2
	andcc	%o1, 3, %o4		! delay slot, is s2 aligned?
	b,a	.noteq

.cmpbyt:b	.bytcmp
	deccc	%o2
1:	ldub	[%o0 + %o1], %o5	! byte compare loop
	inc	%o0
	cmp	%o4, %o5
	be,a	.bytcmp
	deccc	%o2			! delay slot, compare count (len)
	b,a	.noteq
.bytcmp:bgeu,a	1b
	ldub	[%o0], %o4
.cmpeq:	ld	[%sp + 68], %g2
	retl				! strings compare equal
	clr	%o0

.noteq_word:				! words aren't equal. find unequal byte
	srl	%o4, 24, %o1		! first byte
	srl	%o5, 24, %o2
	cmp	%o1, %o2
	bne	1f
	sll	%o4, 8, %o4
	sll	%o5, 8, %o5
	srl	%o4, 24, %o1
	srl	%o5, 24, %o2
	cmp	%o1, %o2
	bne	1f
	sll	%o4, 8, %o4
	sll	%o5, 8, %o5
	srl	%o4, 24, %o1
	srl	%o5, 24, %o2
	cmp	%o1, %o2
	bne	1f
	sll	%o4, 8, %o4
	sll	%o5, 8, %o5
	srl	%o4, 24, %o1
	srl	%o5, 24, %o2
1:
	ld	[%sp + 68], %g2
	retl
	sub	%o1, %o2, %o0		! delay slot

.noteq:
	ld	[%sp + 68], %g2
	retl				! strings aren't equal
	sub	%o4, %o5, %o0		! delay slot, return(*s1 - *s2)

.iss2:	andn	%o2, 3, %o3		! count of aligned bytes
	and	%o2, 3, %o2		! remaining bytes
	bz	.w4cmp			! if s2 word aligned, compare words
	cmp	%o4, 2
	be	.w2cmp			! s2 half aligned
	cmp	%o4, 1

.w3cmp:
	dec	4, %o3			! avoid reading beyond the last byte
	inc	4, %o2
	ldub	[%o1], %g1		! read a byte to align for word reads
	inc	1, %o1
	be	.w1cmp			! aligned to 1 or 3 bytes
	sll	%g1, 24, %o5

	sub	%o1, %o0, %o1
2:	ld	[%o0 + %o1], %g1
	ld	[%o0], %o4
	inc	4, %o0
	srl	%g1, 8, %g2		! merge with the other half
	or	%g2, %o5, %o5
	cmp	%o4, %o5
	bne	.noteq_word
	deccc	4, %o3
	bnz	2b
	sll	%g1, 24, %o5
	sub	%o1, 1, %o1		! used 3 bytes of the last word read
	b	.bytcmp
	deccc	%o2

.w1cmp:
	dec	4, %o3			! avoid reading beyond the last byte
	inc	4, %o2
	lduh	[%o1], %g1		! read 3 bytes to word align
	inc	2, %o1
	sll	%g1, 8, %g2
	or	%o5, %g2, %o5

	sub	%o1, %o0, %o1
3:	ld	[%o0 + %o1], %g1
	ld	[%o0], %o4
	inc	4, %o0
	srl	%g1, 24, %g2		! merge with the other half
	or	%g2, %o5, %o5
	cmp	%o4, %o5
	bne	.noteq_word
	deccc	4, %o3
	bnz	3b
	sll	%g1, 8, %o5
	sub	%o1, 3, %o1		! used 1 byte of the last word read
	b	.bytcmp
	deccc	%o2

.w2cmp:
	dec	4, %o3			! avoid reading beyond the last byte
	inc	4, %o2
	lduh	[%o1], %g1		! read a halfword to align s2
	inc	2, %o1
	sll	%g1, 16, %o5

	sub	%o1, %o0, %o1
4:	ld	[%o0 + %o1], %g1	! read a word from s2
	ld	[%o0], %o4		! read a word from s1
	inc	4, %o0
	srl	%g1, 16, %g2		! merge with the other half
	or	%g2, %o5, %o5
	cmp	%o4, %o5
	bne	.noteq_word
	deccc	4, %o3
	bnz	4b
	sll	%g1, 16, %o5
	sub	%o1, 2, %o1		! only used half of the last read word
	b	.bytcmp
	deccc	%o2

.w4cmp:
	sub	%o1, %o0, %o1
	ld	[%o0 + %o1], %o5
5:	ld	[%o0], %o4
	inc	4, %o0
	cmp	%o4, %o5
	bne	.noteq_word
	deccc	4, %o3
	bnz,a	5b
	ld	[%o0 + %o1], %o5
	b	.bytcmp			! compare remaining bytes, if any
	deccc	%o2

	SET_SIZE(memcmp)
