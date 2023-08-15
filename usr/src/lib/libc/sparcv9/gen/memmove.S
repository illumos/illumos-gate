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

	.file	"memmove.s"

#include <sys/asm_linkage.h>

	ANSI_PRAGMA_WEAK(memmove,function)

/*
 * memmove(s1, s2, len)
 * Copy s2 to s1, always copy n bytes.
 * For overlapped copies it does the right thing.
 */
	ENTRY(memmove)
	save	%sp, -SA(MINFRAME), %sp		! not a leaf routine any more
	mov	%i0, %l6	! Save pointer to destination
	cmp	%i1, %i0	! if from address is >= to use forward copy
	bgeu,a	%xcc, 2f	! else use backward if ...
	cmp	%i2, 17		! delay slot, for small counts copy bytes

	sub	%i0, %i1, %i4	! get difference of two addresses
	cmp	%i2, %i4	! compare size and difference of addresses
	bgu	%xcc, ovbc	! if size is bigger, have to do overlapped copy
	cmp	%i2, 17		! delay slot, for small counts copy bytes
	!
	! normal, copy forwards
	!
2:	ble	%xcc, dbytecp
	andcc	%i1, 3, %i5		! is src word aligned
	bz,pn	%icc, aldst
	cmp	%i5, 2			! is src half-word aligned
	be,pn	%icc, s2algn
	cmp	%i5, 3			! src is byte aligned
s1algn:	ldub	[%i1], %i3		! move 1 or 3 bytes to align it
	inc	1, %i1
	stb	%i3, [%i0]		! move a byte to align src
	inc	1, %i0
	bne,pn	%icc, s2algn
	dec	%i2
	b	ald			! now go align dest
	andcc	%i0, 3, %i5

s2algn:	lduh	[%i1], %i3		! know src is 2 byte alinged
	inc	2, %i1
	srl	%i3, 8, %i4
	stb	%i4, [%i0]		! have to do bytes,
	stb	%i3, [%i0 + 1]		! don't know dst alingment
	inc	2, %i0
	dec	2, %i2

aldst:	andcc	%i0, 3, %i5		! align the destination address
ald:	bz,pn	%icc, w4cp
	cmp	%i5, 2
	bz,pn	%icc, w2cp
	cmp	%i5, 3
w3cp:	lduw	[%i1], %i4
	inc	4, %i1
	srl	%i4, 24, %i5
	stb	%i5, [%i0]
	bne,pt	%icc, w1cp
	inc	%i0
	dec	1, %i2
	andn	%i2, 3, %i3		! i3 is aligned word count
	dec	4, %i3			! avoid reading beyond tail of src
	sub	%i1, %i0, %i1		! i1 gets the difference

1:	sll	%i4, 8, %g1		! save residual bytes
	lduw	[%i1+%i0], %i4
	deccc	4, %i3
	srl	%i4, 24, %i5		! merge with residual
	or	%i5, %g1, %g1
	st	%g1, [%i0]
	bnz,pt	%xcc, 1b
	inc	4, %i0
	sub	%i1, 3, %i1		! used one byte of last word read
	and	%i2, 3, %i2
	b	7f
	inc	4, %i2

w1cp:	srl	%i4, 8, %i5
	sth	%i5, [%i0]
	inc	2, %i0
	dec	3, %i2
	andn	%i2, 3, %i3
	dec	4, %i3			! avoid reading beyond tail of src
	sub	%i1, %i0, %i1		! i1 gets the difference

2:	sll	%i4, 24, %g1		! save residual bytes
	lduw	[%i1+%i0], %i4
	deccc	4, %i3
	srl	%i4, 8, %i5		! merge with residual
	or	%i5, %g1, %g1
	st	%g1, [%i0]
	bnz,pt	%xcc, 2b
	inc	4, %i0
	sub	%i1, 1, %i1		! used three bytes of last word read
	and	%i2, 3, %i2
	b	7f
	inc	4, %i2

w2cp:	lduw	[%i1], %i4
	inc	4, %i1
	srl	%i4, 16, %i5
	sth	%i5, [%i0]
	inc	2, %i0
	dec	2, %i2
	andn	%i2, 3, %i3		! i3 is aligned word count
	dec	4, %i3			! avoid reading beyond tail of src
	sub	%i1, %i0, %i1		! i1 gets the difference

3:	sll	%i4, 16, %g1		! save residual bytes
	lduw	[%i1+%i0], %i4
	deccc	4, %i3
	srl	%i4, 16, %i5		! merge with residual
	or	%i5, %g1, %g1
	st	%g1, [%i0]
	bnz,pt	%xcc, 3b
	inc	4, %i0
	sub	%i1, 2, %i1		! used two bytes of last word read
	and	%i2, 3, %i2
	b	7f
	inc	4, %i2

w4cp:	andn	%i2, 3, %i3		! i3 is aligned word count
	sub	%i1, %i0, %i1		! i1 gets the difference

1:	lduw	[%i1+%i0], %i4		! read from address
	deccc	4, %i3			! decrement count
	st	%i4, [%i0]		! write at destination address
	bg,pt	%xcc, 1b
	inc	4, %i0			! increment to address
	b	7f
	and	%i2, 3, %i2		! number of leftover bytes, if any

	!
	! differenced byte copy, works with any alignment
	!
dbytecp:
	b	7f
	sub	%i1, %i0, %i1		! i1 gets the difference

4:	stb	%i4, [%i0]		! write to address
	inc	%i0			! inc to address
7:	deccc	%i2			! decrement count
	bge,a	%xcc, 4b		! loop till done
	ldub	[%i1+%i0], %i4		! read from address
	ret
	restore %l6, %g0, %o0		! return pointer to destination

	!
	! an overlapped copy that must be done "backwards"
	!
ovbc:	add	%i1, %i2, %i1		! get to end of source space
	add	%i0, %i2, %i0		! get to end of destination space
	sub	%i1, %i0, %i1		! i1 gets the difference

5:	dec	%i0			! decrement to address
	ldub	[%i1+%i0], %i3		! read a byte
	deccc	%i2			! decrement count
	bg,pt	%xcc, 5b		! loop until done
	stb	%i3, [%i0]		! write byte
	ret
	restore %l6, %g0, %o0		! return pointer to destination

	SET_SIZE(memmove)
