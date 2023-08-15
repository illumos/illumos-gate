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
 * Copyright (c) 1988, 2010, Oracle and/or its affiliates. All rights reserved.
 */

	.file	"memcpy.s"

/*
 * memcpy(s1, s2, len)
 *
 * Copy s2 to s1, always copy n bytes.
 * Note: this does not work for overlapped copies, bcopy() does
 *
 * Fast assembler language version of the following C-program for memcpy
 * which represents the `standard' for the C-library.
 *
 *	void *
 *	memcpy(void *s, const void *s0, size_t n)
 *	{
 *		if (n != 0) {
 *	   	    char *s1 = s;
 *		    const char *s2 = s0;
 *		    do {
 *			*s1++ = *s2++;
 *		    } while (--n != 0);
 *		}
 *		return (s);
 *	}
 */

#include "SYS.h"

	ANSI_PRAGMA_WEAK(memcpy,function)

	ENTRY(memcpy)
        ENTRY(__align_cpy_1)
	st	%o0, [%sp + 68]		! save des address for return val
	cmp	%o2, 17			! for small counts copy bytes
	bleu	.dbytecp
	andcc	%o1, 3, %o5		! is src word aligned
	bz	.aldst
	cmp	%o5, 2			! is src half-word aligned
	be	.s2algn
	cmp	%o5, 3			! src is byte aligned
.s1algn:ldub	[%o1], %o3		! move 1 or 3 bytes to align it
	inc	1, %o1
	stb	%o3, [%o0]		! move a byte to align src
	inc	1, %o0
	bne	.s2algn
	dec	%o2
	b	.ald			! now go align dest
	andcc	%o0, 3, %o5

.s2algn:lduh	[%o1], %o3		! know src is 2 byte alinged
	inc	2, %o1
	srl	%o3, 8, %o4
	stb	%o4, [%o0]		! have to do bytes,
	stb	%o3, [%o0 + 1]		! don't know dst alingment
	inc	2, %o0
	dec	2, %o2

.aldst:	andcc	%o0, 3, %o5		! align the destination address
.ald:	bz	.w4cp
	cmp	%o5, 2
	bz	.w2cp
	cmp	%o5, 3
.w3cp:	ld	[%o1], %o4
	inc	4, %o1
	srl	%o4, 24, %o5
	stb	%o5, [%o0]
	bne	.w1cp
	inc	%o0
	dec	1, %o2
	andn	%o2, 3, %o3		! o3 is aligned word count
	dec	4, %o3			! avoid reading beyond tail of src
	sub	%o1, %o0, %o1		! o1 gets the difference

1:	sll	%o4, 8, %g1		! save residual bytes
	ld	[%o1+%o0], %o4
	deccc	4, %o3
	srl	%o4, 24, %o5		! merge with residual
	or	%o5, %g1, %g1
	st	%g1, [%o0]
	bnz	1b
	inc	4, %o0
	sub	%o1, 3, %o1		! used one byte of last word read
	and	%o2, 3, %o2
	b	7f
	inc	4, %o2

.w1cp:	srl	%o4, 8, %o5
	sth	%o5, [%o0]
	inc	2, %o0
	dec	3, %o2
	andn	%o2, 3, %o3		! o3 is aligned word count
	dec	4, %o3			! avoid reading beyond tail of src
	sub	%o1, %o0, %o1		! o1 gets the difference

2:	sll	%o4, 24, %g1		! save residual bytes
	ld	[%o1+%o0], %o4
	deccc	4, %o3
	srl	%o4, 8, %o5		! merge with residual
	or	%o5, %g1, %g1
	st	%g1, [%o0]
	bnz	2b
	inc	4, %o0
	sub	%o1, 1, %o1		! used three bytes of last word read
	and	%o2, 3, %o2
	b	7f
	inc	4, %o2

.w2cp:	ld	[%o1], %o4
	inc	4, %o1
	srl	%o4, 16, %o5
	sth	%o5, [%o0]
	inc	2, %o0
	dec	2, %o2
	andn	%o2, 3, %o3		! o3 is aligned word count
	dec	4, %o3			! avoid reading beyond tail of src
	sub	%o1, %o0, %o1		! o1 gets the difference

3:	sll	%o4, 16, %g1		! save residual bytes
	ld	[%o1+%o0], %o4
	deccc	4, %o3
	srl	%o4, 16, %o5		! merge with residual
	or	%o5, %g1, %g1
	st	%g1, [%o0]
	bnz	3b
	inc	4, %o0
	sub	%o1, 2, %o1		! used two bytes of last word read
	and	%o2, 3, %o2
	b	7f
	inc	4, %o2

.w4cp:	andn	%o2, 3, %o3		! o3 is aligned word count
	sub	%o1, %o0, %o1		! o1 gets the difference

1:	ld	[%o1+%o0], %o4		! read from address
	deccc	4, %o3			! decrement count
	st	%o4, [%o0]		! write at destination address
	bgu	1b
	inc	4, %o0			! increment to address
	b	7f
	and	%o2, 3, %o2		! number of leftover bytes, if any

	!
	! differenced byte copy, works with any alignment
	!
.dbytecp:
	b	7f
	sub	%o1, %o0, %o1		! o1 gets the difference

4:	stb	%o4, [%o0]		! write to address
	inc	%o0			! inc to address
7:	deccc	%o2			! decrement count
	bgeu,a	4b			! loop till done
	ldub	[%o1+%o0], %o4		! read from address
	retl
	ld	[%sp + 68], %o0		! return s1, destination address

	SET_SIZE(memcpy)
