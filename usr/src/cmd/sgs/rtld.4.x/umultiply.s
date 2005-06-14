/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 *	.seg	"data"
 *	.asciz	"Copyr 1987 Sun Micro"
 *	.align	4
 */
	.seg	"text"

#ident	"%Z%%M%	%I%	%E% SMI"

!	Copyright (c) 1987 by Sun Microsystems, Inc.


#include <sys/asm_linkage.h>

/*
 * procedure to perform a 32 by 32 unsigned integer multiply.
 * pass the multiplier into %o0, and the multiplicand into %o1
 * the least significant 32 bits of the result will be returned in %o0,
 * and the most significant in %o1
 *
 * Most unsigned integer multiplies involve small numbers, so it is
 * worthwhile to optimize for short multiplies at the expense of long 
 * multiplies.  This code checks the size of the multiplier, and has
 * special cases for the following:
 *
 *	4 or fewer bit multipliers:	19 or 21 instruction cycles
 *	8 or fewer bit multipliers:	26 or 28 instruction cycles
 *	12 or fewer bit multipliers:	34 or 36 instruction cycles
 *	16 or fewer bit multipliers:	42 or 44 instruction cycles
 *
 * Long multipliers require 58 or 60 instruction cycles:
 *
 * This code indicates that overflow has occured, by leaving the Z condition
 * code clear. The following call sequence would be used if you wish to
 * deal with overflow:
 *
 *	 	call	.umul
 *		nop		( or set up last parameter here )
 *		bnz	overflow_code	(or tnz to overflow handler)
 */

!	RTENTRY(.umul)
	.global	.umul
.umul:
	wr	%o0, %y			! multiplier to Y register

	andncc	%o0, 0xf, %o4		! mask out lower 4 bits; if branch
					! taken, %o4, N and V have been cleared 

	be	umul_4bit		! 4-bit multiplier
	sethi	%hi(0xffff0000), %o5	! mask for 16-bit case; have to
					! wait 3 instructions after wd
					! before %y has stabilized anyway

	andncc	%o0, 0xff, %o4
	be,a	umul_8bit		! 8-bit multiplier
	mulscc	%o4, %o1, %o4		! first iteration of 9

	andncc	%o0, 0xfff, %o4
	be,a	umul_12bit		! 12-bit multiplier
	mulscc	%o4, %o1, %o4		! first iteration of 13

	andcc	%o0, %o5, %o4
	be,a	umul_16bit		! 16-bit multiplier
	mulscc	%o4, %o1, %o4		! first iteration of 17

	andcc	%g0, %g0, %o4		! zero the partial product
					! and clear N and V conditions
	!
	! long multiply
	!
	mulscc	%o4, %o1, %o4		! first iteration of 33
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4		! 32nd iteration
	mulscc	%o4, %g0, %o4		! last iteration only shifts
	!
	! For unsigned multiplies, a pure shifty-add approach yields the
	! correct result.  Signed multiplies introduce complications.
	!
	! With 32-bit twos-complement numbers, -x can be represented as
	!
	!	((2 - (x/(2**32)) mod 2) * 2**32.
	!
	! To simplify the equations, the radix point can be moved to just
	! to the left of the sign bit.  So:
	!
	! 	 x *  y	= (xy) mod 2
	!	-x *  y	= (2 - x) mod 2 * y = (2y - xy) mod 2
	!	 x * -y	= x * (2 - y) mod 2 = (2x - xy) mod 2
	!	-x * -y = (2 - x) * (2 - y) = (4 - 2x - 2y + xy) mod 2
	!
	! Because of the way the shift into the partial product is calculated
	! (N xor V), the extra term is automagically removed for negative
	! multiplicands, so no adjustment is necessary.
	!
	! But for unsigned multiplies, the high-order bit of the multiplicand
	! is incorrectly treated as a sign bit.  For unsigned multiplies where
	! the high-order bit of the multiplicand is one, the result is
	!
	!	xy - y * (2**32)
	! 
	! we fix that here
	!
	tst	%o1
	bge	1f
	nop

	add	%o4, %o0, %o4		! add (2**32) * %o0; bits 63-32
					! of the product are in %o4
	!
	! The multiply hasn't overflowed if the high-order bits are 0
	!
	! if you are not interested in detecting overflow,
	! replace the following code with:
	!
	!	1:
	!		rd	%y, %o0
	!		retl
	!		mov	%o4, %o1
	!
1:
	rd	%y, %o0
	retl				! leaf routine return
	addcc	%o4, %g0, %o1		! return high-order bits and set Z if
					! high order bits are 0 
	!
	! 4-bit multiply
	!
umul_4bit:
	mulscc	%o4, %o1, %o4		! first iteration of 5
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4		! 4th iteration
	mulscc	%o4, %g0, %o4		! last iteration only shifts

	rd	%y, %o5
	!
	! The folowing code adds (2**32) * %o0 to the product if the
	! multiplicand had it's high bit set (see 32-bit case for explanation)
	!
	tst	%o1
	bge	2f
	sra	%o4, 28, %o1		! right shift high bits by 28 bits

	add	%o1, %o0, %o1
	!
	! The multiply hasn't overflowed if high-order bits are 0
	!
	! if you are not interested in detecting overflow,
	! replace the following code with:
	!
	!	2:
	!		sll	%o4, 4, %o0
	!		srl	%o5, 28, %o5
	!		retl
	!		or	%o5, %o0, %o0
	!
2:
	sll	%o4, 4, %o0		! left shift middle bits by 4 bits
	srl	%o5, 28, %o5		! right shift low bits by 28 bits
	or	%o5, %o0, %o0		! merge for true product
	retl				! leaf routine return
	tst	%o1			! set Z if high order bits are 0
	!
	! 8-bit multiply
	!
umul_8bit:
	mulscc	%o4, %o1, %o4		! second iteration of 9
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4		! 8th iteration
	mulscc	%o4, %g0, %o4		! last iteration only shifts

	rd	%y, %o5
	!
	! The folowing code adds (2**32) * %o0 to the product if the
	! multiplicand had it's high bit set (see 32-bit case for explanation)
	!
	tst	%o1
	bge	3f
	sra	%o4, 24, %o1		! right shift high bits by 24 bits

	add	%o1, %o0, %o1
	!
	! The multiply hasn't overflowed if high-order bits are 0
	!
	! if you are not interested in detecting overflow,
	! replace the following code with:
	!
	!	3:
	!		sll	%o4, 8, %o0
	!		srl	%o5, 24, %o5
	!		retl
	!		or	%o5, %o0, %o0
	!
3:
	sll	%o4, 8, %o0		! left shift middle bits by 8 bits
	srl	%o5, 24, %o5		! right shift low bits by 24 bits
	or	%o5, %o0, %o0		! merge for true product
	retl				! leaf routine return
	tst	%o1			! set Z if high order bits are 0
	!
	! 12-bit multiply
	!
umul_12bit:
	mulscc	%o4, %o1, %o4		! second iteration of 13
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4		! 12th iteration
	mulscc	%o4, %g0, %o4		! last iteration only shifts

	rd	%y, %o5
	!
	! The folowing code adds (2**32) * %o0 to the product if the
	! multiplicand had it's high bit set (see 32-bit case for explanation)
	!
	tst	%o1
	bge	4f
	sra	%o4, 20, %o1		! right shift high bits by 20 bits

	add	%o1, %o0, %o1
	!
	! The multiply hasn't overflowed if high-order bits are 0
	!
	! if you are not interested in detecting overflow,
	! replace the following code with:
	!
	!	4:
	!		sll	%o4, 12, %o0
	!		srl	%o5, 20, %o5
	!		retl
	!		or	%o5, %o0, %o0
	!
4:
	sll	%o4, 12, %o0		! left shift middle bits by 12 bits
	srl	%o5, 20, %o5		! right shift low bits by 20 bits
	or	%o5, %o0, %o0		! merge for true product
	retl				! leaf routine return
	tst	%o1			! set Z if high order bits are 0
	!
	! 16-bit multiply
	!
umul_16bit:
	mulscc	%o4, %o1, %o4		! second iteration of 17
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4
	mulscc	%o4, %o1, %o4		! 16th iteration
	mulscc	%o4, %g0, %o4		! last iteration only shifts

	rd	%y, %o5
	!
	! The folowing code adds (2**32) * %o0 to the product if the
	! multiplicand had it's high bit set (see 32-bit case for explanation)
	!
	tst	%o1
	bge	5f
	sra	%o4, 16, %o1		! right shift high bits by 16 bits

	add	%o1, %o0, %o1
	!
	! The multiply hasn't overflowed if high-order bits are 0
	!
	! if you are not interested in detecting overflow,
	! replace the following code with:
	!
	!	5:
	!		sll	%o4, 16, %o0
	!		srl	%o5, 16, %o5
	!		retl
	!		or	%o5, %o0, %o0
	!
5:
	sll	%o4, 16, %o0		! left shift middle bits by 16 bits
	srl	%o5, 16, %o5		! right shift low bits by 16 bits
	or	%o5, %o0, %o0		! merge for true product
	retl				! leaf routine return
	tst	%o1			! set Z if high order bits are 0
