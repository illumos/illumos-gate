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

!	.seg	"data"
!	.asciz	"Copyr 1986 Sun Micro"
	.seg	"text"

#ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright 1986 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * divison/remainder
 *
 * Input is:
 *	dividend -- the thing being divided
 * divisor  -- how many ways to divide
 * Important parameters:
 *	N -- how many bits per iteration we try to get
 *		as our current guess: 
 *	WORDSIZE -- how many bits altogether we're talking about:
 *		obviously: 
 * A derived constant:
 *	TOPBITS -- how many bits are in the top "decade" of a number:
 *		
 * Important variables are:
 *	Q -- the partial quotient under development -- initally 0
 *	R -- the remainder so far -- initially == the dividend
 *	ITER -- number of iterations of the main division loop will
 *		be required. Equal to CEIL( lg2(quotient)/4 )
 *		Note that this is log_base_(2^4) of the quotient.
 *	V -- the current comparand -- initially divisor*2^(ITER*4-1)
 * Cost:
 *	current estimate for non-large dividend is 
 *		CEIL( lg2(quotient) / 4 ) x ( 10 + 74/2 ) + C
 *	a large dividend is one greater than 2^(31-4 ) and takes a 
 *	different path, as the upper bits of the quotient must be developed 
 *	one bit at a time.
 */

#include <sys/trap.h>
#include <sys/asm_linkage.h>








	! working variable


/*
 * this is the recursive definition of how we develop quotient digits.
 * it takes three important parameters:
 *	$1 -- the current depth, 1<=$1<=4
 *	$2 -- the current accumulation of quotient bits
 *	4  -- max depth
 * We add a new bit to $2 and either recurse or 
 * insert the bits in the quotient.
 * Dynamic input:
 *	%o3 -- current remainder
 *	%o2 -- current quotient
 *	%o5 -- current comparand
 *	cc -- set on current value of %o3
 * Dynamic output:
 * %o3', %o2', %o5', cc'
 */




!	RTENTRY(.urem)		! UNSIGNED REMAINDER
	.global	.urem
.urem:
	b	divide
	mov	0,%g1		! result always positive

!	RTENTRY(.rem)		! SIGNED REMAINDER
	.global	.rem
.rem:
	orcc	%o1,%o0,%g0 ! are either %o0 or %o1 negative
	bge	divide		! if not, skip this junk
	mov	%o0,%g1	! record sign of result in sign of %g1
		tst	%o1
		bge	2f
		tst	%o0
	!	%o1 < 0
		bge	divide
		neg	%o1
	2:
	!	%o0 < 0
		neg	%o0
	!	FALL THROUGH


divide:
!	compute size of quotient, scale comparand
	orcc	%o1,%g0,%o5	! movcc	%o1,%o5
	bnz	0f		! if %o1 != 0
	mov	%o0,%o3
	ba	zero_divide
	nop
0:
	cmp     %o3,%o5
	blu     got_result ! if %o3<%o5 already, there's no point in continuing
	mov	0,%o2
	sethi	%hi(1<<(32-4 -1)),%g2
	cmp	%o3,%g2
	blu	not_really_big
	mov	0,%o4
	!
	! here, the %o0 is >= 2^(31-4) or so. We must be careful here, as
	! our usual 4-at-a-shot divide step will cause overflow and havoc. The
	! total number of bits in the result here is 4*%o4+%g3, where %g3 <= 4.
	! compute %o4, in an unorthodox manner: know we need to Shift %o5 into
	!	the top decade: so don't even bother to compare to %o3.
	1:
		cmp	%o5,%g2
		bgeu	3f
		mov	1,%g3
		sll	%o5,4,%o5
		b	1b
		inc	%o4
	! now compute %g3
	2:	addcc	%o5,%o5,%o5
		bcc	not_too_big ! bcc	not_too_big
		add	%g3,1,%g3
			!
			! here if the %o1 overflowed when Shifting
			! this means that %o3 has the high-order bit set
			! restore %o5 and subtract from %o3
			sll	%g2,4 ,%g2 ! high order bit
			srl	%o5,1,%o5 ! rest of %o5
			add	%o5,%g2,%o5
			b	do_single_div
			sub	%g3,1,%g3
	not_too_big:
	3:	cmp	%o5,%o3
		blu	2b
		nop
		be	do_single_div
		nop
	! %o5 > %o3: went too far: back up 1 step
	!	srl	%o5,1,%o5
	!	dec	%g3
	! do single-bit divide steps
	!
	! we have to be careful here. We know that %o3 >= %o5, so we can do the
	! first divide step without thinking. BUT, the others are conditional,
	! and are only done if %o3 >= 0. Because both %o3 and %o5 may have the high-
	! order bit set in the first step, just falling into the regular 
	! division loop will mess up the first time around. 
	! So we unroll slightly...
	do_single_div:
		deccc	%g3
		bl	end_regular_divide
		nop
		sub	%o3,%o5,%o3
		mov	1,%o2
		b,a	end_single_divloop
	single_divloop:
		sll	%o2,1,%o2
		bl	1f
		srl	%o5,1,%o5
		! %o3 >= 0
		sub	%o3,%o5,%o3
		b	2f
		inc	%o2
	1:	! %o3 < 0
		add	%o3,%o5,%o3
		dec	%o2
	2:	
	end_single_divloop:
		deccc	%g3
		bge	single_divloop
		tst	%o3
		b,a	end_regular_divide

not_really_big:
1:	
	sll	%o5,4,%o5
	cmp	%o5,%o3
	bleu	1b
	inccc	%o4
	be	got_result
	dec	%o4
do_regular_divide:

!	do the main division iteration
	tst	%o3
!	fall through into divide loop
divloop:
	sll	%o2,4,%o2
		!depth 1, accumulated bits 0 
	bl	L.1.16
	srl	%o5,1,%o5
	! remainder is positive
	subcc	%o3,%o5,%o3
			!depth 2, accumulated bits 1
	bl	L.2.17
	srl	%o5,1,%o5
	! remainder is positive
	subcc	%o3,%o5,%o3
			!depth 3, accumulated bits 3
	bl	L.3.19
	srl	%o5,1,%o5
	! remainder is positive
	subcc	%o3,%o5,%o3
			!depth 4, accumulated bits 7
	bl	L.4.23
	srl	%o5,1,%o5
	! remainder is positive
	subcc	%o3,%o5,%o3
		b	9f
		add	%o2, (7*2+1), %o2
	
L.4.23:	! remainder is negative
	addcc	%o3,%o5,%o3
		b	9f
		add	%o2, (7*2-1), %o2
	
	

	
L.3.19:	! remainder is negative
	addcc	%o3,%o5,%o3
			!depth 4, accumulated bits 5
	bl	L.4.21
	srl	%o5,1,%o5
	! remainder is positive
	subcc	%o3,%o5,%o3
		b	9f
		add	%o2, (5*2+1), %o2
	
L.4.21:	! remainder is negative
	addcc	%o3,%o5,%o3
		b	9f
		add	%o2, (5*2-1), %o2
	
	

	
	

	
L.2.17:	! remainder is negative
	addcc	%o3,%o5,%o3
			!depth 3, accumulated bits 1
	bl	L.3.17
	srl	%o5,1,%o5
	! remainder is positive
	subcc	%o3,%o5,%o3
			!depth 4, accumulated bits 3
	bl	L.4.19
	srl	%o5,1,%o5
	! remainder is positive
	subcc	%o3,%o5,%o3
		b	9f
		add	%o2, (3*2+1), %o2
	
L.4.19:	! remainder is negative
	addcc	%o3,%o5,%o3
		b	9f
		add	%o2, (3*2-1), %o2
	
	

	
L.3.17:	! remainder is negative
	addcc	%o3,%o5,%o3
			!depth 4, accumulated bits 1
	bl	L.4.17
	srl	%o5,1,%o5
	! remainder is positive
	subcc	%o3,%o5,%o3
		b	9f
		add	%o2, (1*2+1), %o2
	
L.4.17:	! remainder is negative
	addcc	%o3,%o5,%o3
		b	9f
		add	%o2, (1*2-1), %o2
	
	

	
	

	
	

	
L.1.16:	! remainder is negative
	addcc	%o3,%o5,%o3
			!depth 2, accumulated bits -1
	bl	L.2.15
	srl	%o5,1,%o5
	! remainder is positive
	subcc	%o3,%o5,%o3
			!depth 3, accumulated bits -1
	bl	L.3.15
	srl	%o5,1,%o5
	! remainder is positive
	subcc	%o3,%o5,%o3
			!depth 4, accumulated bits -1
	bl	L.4.15
	srl	%o5,1,%o5
	! remainder is positive
	subcc	%o3,%o5,%o3
		b	9f
		add	%o2, (-1*2+1), %o2
	
L.4.15:	! remainder is negative
	addcc	%o3,%o5,%o3
		b	9f
		add	%o2, (-1*2-1), %o2
	
	

	
L.3.15:	! remainder is negative
	addcc	%o3,%o5,%o3
			!depth 4, accumulated bits -3
	bl	L.4.13
	srl	%o5,1,%o5
	! remainder is positive
	subcc	%o3,%o5,%o3
		b	9f
		add	%o2, (-3*2+1), %o2
	
L.4.13:	! remainder is negative
	addcc	%o3,%o5,%o3
		b	9f
		add	%o2, (-3*2-1), %o2
	
	

	
	

	
L.2.15:	! remainder is negative
	addcc	%o3,%o5,%o3
			!depth 3, accumulated bits -3
	bl	L.3.13
	srl	%o5,1,%o5
	! remainder is positive
	subcc	%o3,%o5,%o3
			!depth 4, accumulated bits -5
	bl	L.4.11
	srl	%o5,1,%o5
	! remainder is positive
	subcc	%o3,%o5,%o3
		b	9f
		add	%o2, (-5*2+1), %o2
	
L.4.11:	! remainder is negative
	addcc	%o3,%o5,%o3
		b	9f
		add	%o2, (-5*2-1), %o2
	
	

	
L.3.13:	! remainder is negative
	addcc	%o3,%o5,%o3
			!depth 4, accumulated bits -7
	bl	L.4.9
	srl	%o5,1,%o5
	! remainder is positive
	subcc	%o3,%o5,%o3
		b	9f
		add	%o2, (-7*2+1), %o2
	
L.4.9:	! remainder is negative
	addcc	%o3,%o5,%o3
		b	9f
		add	%o2, (-7*2-1), %o2
	
	

	
	

	
	

	
	9:

end_regular_divide:
	deccc	%o4
	bge	divloop
	tst	%o3
	bl,a	got_result
	add	%o3,%o1,%o3


got_result:
	tst	%g1
	bl,a	1f
	neg	%o3	! remainder <- -%o3

1:
	retl
	mov	%o3,%o0	! remainder <-  %o3

	
zero_divide:
	ta	ST_DIV0		! divide by zero trap
	retl			! if handled, ignored, return
	mov	0, %o0
