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

	.file	"strlcpy.s"
/*
 * The strlcpy() function copies at most dstsize-1 characters
 * (dstsize being the size of the string buffer dst) from src
 * to dst, truncating src if necessary. The result is always
 * null-terminated.  The function returns strlen(src). Buffer
 * overflow can be checked as follows:
 *
 *   if (strlcpy(dst, src, dstsize) >= dstsize)
 *           return -1;
 */

#include <sys/asm_linkage.h>

	! strlcpy implementation is similar to that of strcpy, except
	! in this case, the maximum size of the detination must be
	! tracked since it bounds our maximum copy size.  However,
	! we must still continue to check for zero since the routine
	! is expected to null-terminate any string that is within
	! the dest size bound.
	!
	! this method starts by checking for and arranging source alignment.
	! Once this has occurred, we copy based upon destination alignment.
	! This is either by word, halfword, or byte.  As this occurs, we
	! check for a zero-byte.  If one is found, we branch to a method
	! which checks for the exact location of a zero-byte within a
	! larger word/half-word quantity.

	ENTRY(strlcpy)

	.align 32
	save	%sp, -SA(WINDOWSIZE), %sp
	subcc	%g0, %i2, %g4		! n = -n or n == 0 ?
	bz,pn	%icc, .getstrlen	! if 0 do nothing but strlen(src)
	add	%i1, %i2, %i3		! i3 = src + n
	andcc	%i1, 3, %i4		! word aligned?
	bz,pn	%icc, .wordaligned
	add	%i0, %i2, %i2		! n = dst + n
	sub	%i4, 4, %i4		! bytes until src aligned

.alignsrc:
	ldub	[%i3 + %g4], %l1	! l1 = src[]
	andcc	%l1, 0xff, %g0		! null byte reached?
	stub	%l1, [%i2 + %g4]	! dst[] = src[]
	bz,a	%icc, .done
	add	%i2, %g4, %i2		! get single dest ptr for strlen
	addcc	%g4, 1, %g4		! src++ dest++ n--
	bz,pn	%icc, .forcenullunalign	! n == 0, append null byte
	addcc	%i4, 1, %i4		! incr, check align
	bnz,a 	%icc, .alignsrc
	nop

.wordaligned:
	sethi	%hi(0x01010101), %i4
	add	%i2, %g4, %l0		! l0 = dest
	or	%i4, %lo(0x01010101), %i4
	sub	%i2, 4, %i2		! pre-incr for in cpy loop
	andcc	%l0, 3, %g1		! word aligned?
	bnz	%icc, .dstnotaligned
	sll	%i4, 7, %i5		! Mycroft part deux

.storeword:
	ld	[%i3 + %g4], %l1	! l1 = src[]
	addcc	%g4, 4, %g4		! n += 4, src += 4, dst +=4
	bcs,pn	%icc, .lastword
	andn	%i5, %l1, %g1		! ~word & 0x80808080
	sub	%l1, %i4, %l0		! word - 0x01010101
	andcc	%l0, %g1, %g0		! doit
	bz,a,pt	%icc, .storeword	! if expr == 0, no zero byte
	st	%l1, [%i2 + %g4]	! dst[] = src[]

.zerobyte:
	add	%i2, %g4, %i2		! ptr to dest
	srl	%l1, 24, %g1		! 1st byte
	andcc	%g1, 0xff, %g0		! test for end
	bz,pn	%icc, .done
	stb	%g1, [%i2]		! store byte
	add	%i2, 1, %i2		! dst ++
	srl	%l1, 16, %g1		! 2nd byte
	andcc	%g1, 0xff, %g0		! zero byte ?
	bz,pn	%icc, .done
	stb	%g1, [%i2]		! store byte
	add	%i2, 1, %i2		! dst ++
	srl	%l1, 8, %g1		! 3rd byte
	andcc	%g1, 0xff, %g0		! zero byte ?
	bz,pn	%icc, .done
	stb	%g1, [%i2]		! store byte
	stb	%l1, [%i2 + 1]		! store last byte
	add	%i2, 1, %i2		! dst ++

.done:
	sub	%i2, %i0, %i0		! len = dst - orig dst
	ret
	restore	%i0, %g0, %o0

.lastword:
	add	%i2, %g4, %i2
	sub	%g4, 4, %g4		! undo pre-incr
	add	%i3, %g4, %i3

	srl	%l1, 24, %g1		! 1st byte
	andcc	%g1, 0xff, %g0		! zero byte?
	bz,pn	%icc, .done
	stb	%g1, [%i2]		! store byte
	inccc	%g4			! n--
	bz	.forcenull
	srl	%l1, 16, %g1		! 2nd byte
	add	%i2, 1, %i2		! dst++
	andcc	%g1, 0xff, %g0		! zero?
	bz,pn	%icc, .done
	stb	%g1, [%i2]		! store
	inccc	%g4
	bz	.forcenull
	srl	%l1, 8, %g1		! 3rd byte
	add	%i2, 1, %i2		! dst++
	andcc	%g1, 0xff, %g0		! zero?
	bz,pn	%icc, .done
	stb	%g1, [%i2]		! store
	inccc	%g4			! n--
	bz	.forcenull
	andcc	%l1, 0xff, %g0		! zero?
	add	%i2, 1, %i2		! dst++
	bz,pn	%ncc, .done
	stb	%l1, [%i2]

.forcenull:
	stb	%g0, [%i2]

.searchword:
	ld	[%i3], %l1
.searchword2:
	andn	%i5, %l1, %g1		! word & 0x80808080
	sub	%l1, %i4, %l0		! word - 0x01010101
	andcc	%l0, %g1, %g0		! do it
	bz,a,pt	%icc, .searchword
	add	%i3, 4, %i3		! src += 4

	mov	0xff, %i5
	sll	%i5, 24, %i5		! mask 1st byte = 0xff000000
.searchbyte:
	andcc	%l1, %i5, %g0		! cur byte 0?
	srl	%i5, 8, %i5		! mask next byte
	bnz,a	%icc, .searchbyte	! cur !=0 continue
	add	%i3, 1, %i3

.endfound:
	sub	%i3, %i1, %i0		! len = src - orig src
	ret
	restore	%i0, %g0, %o0
	nop

.dstnotaligned:
	cmp	%g1, 2			! halfword aligned?
	be	.storehalfword2
	.empty
.storebyte:
	ld	[%i3 + %g4], %l1	! load src word
	addcc	%g4, 4, %g4		! src +=4 dst +=4
	bcs,pn	%icc, .lastword
	andn	%i5, %l1, %g1		! ~x & 0x80808080
	sub	%l1, %i4, %l0		! x - 0x01010101
	andcc	%l0, %g1, %g0		! get your Mycroft on
	bnz,pn	%icc, .zerobyte		! non-zero, we have zero byte
	add	%i2, %g4, %l0		! dst in ptr form
	srl	%l1, 24, %g1		! get 1st byte, then be hw aligned
	stb	%g1, [%l0]
	srl	%l1, 8, %g1		! 2nd & 3rd bytes
	sth	%g1, [%l0 + 1]
	ba	.storebyte
	stb	%l1, [%l0 + 3]		! store 4th byte

.storehalfword:
	ld	[%i3 + %g4], %l1	! src word
.storehalfword2:
	addcc	%g4, 4, %g4		! src += 4 dst += 4
	bcs,pn	%icc, .lastword
	andn	%i5, %l1, %g1		! ~x & 0x80808080
	sub	%l1, %i4, %l0		! x - 0x01010101
	andcc	%l0, %g1, %g0		! Mycroft again...
	bnz,pn	%icc, .zerobyte		! non-zer, we have zero byte
	add	%i2, %g4, %l0		! dst in ptr form
	srl	%l1, 16, %g1		! first two bytes
	sth	%g1, [%l0]
	ba	.storehalfword
	sth	%l1, [%l0 + 2]

.forcenullunalign:
	add	%i2, %g4, %i2		! single dst ptr
	stb	%g0, [%i2 - 1]		! store terminating null byte

.getstrlen:
	sethi	%hi(0x01010101), %i4	! Mycroft...
	or	%i4, %lo(0x01010101), %i4
	sll	%i4, 7, %i5

.getstrlenloop:
	andcc	%i3, 3, %g0		! word aligned?
	bz,a,pn	%icc, .searchword2	! search word at a time
	ld	[%i3], %l1		! src word
	ldub	[%i3], %l1		! src byte
	andcc	%l1, 0xff, %g0		! end of src?
	bnz,a	%icc, .getstrlenloop
	add	%i3, 1, %i3		! src ++
	sub	%i3, %i1, %i0		! len = src - orig src
	ret
	restore	%i0, %g0, %o0
	SET_SIZE(strlcpy)
