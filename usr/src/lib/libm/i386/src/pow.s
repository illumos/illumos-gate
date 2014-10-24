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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */
/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

        .file "pow.s"

/ Note: 0^NaN should not signal "invalid" but this implementation
/ does because y is placed on the NPX stack.

/ Special cases:
/
/ x ** 0 is 1				_SVID_libm_err if x is 0 or NaN
/ 1 ** y is 1				(C99)
/ x ** NaN is NaN
/ NaN ** y (except 0) is NaN
/ x ** 1 is x
/ +-(|x| > 1) **  +inf is +inf
/ +-(|x| > 1) **  -inf is +0
/ +-(|x| < 1) **  +inf is +0
/ +-(|x| < 1) **  -inf is +inf
/ (-1) ** +-inf is +1			(C99)
/ +0 ** +y (except 0, NaN)		is +0
/ -0 ** +y (except 0, NaN, odd int)	is +0
/ -0 ** +y (odd int)			is -0
/ +-0 ** -y (except 0, NaN)		_SVID_libm_err
/ +inf ** +y (except 0, NaN)		is +inf
/ +inf ** -y (except 0, NaN)		is +0
/ -inf ** +-y (except 0, NaN)		is -0 ** -+y (NO z flag)
/ x ** -1 is 1/x
/ x ** 2 is x*x
/ -x ** y (an integer) is (-1)**(y) * (+x)**(y)
/ x ** y (x negative & y not integer)	_SVID_libm_err
/ if x and y are finite and x**y = 0	_SVID_libm_err (underflow)
/ if x and y are finite and x**y = inf	_SVID_libm_err (overflow)

#include "libm.h"
LIBM_ANSI_PRAGMA_WEAK(pow,function)
#include "libm_protos.h"
#include "xpg6.h"

	.data
	.align	4
negzero:
	.float	-0.0
one:
	.float	1.0
negone:
	.float	-1.0
two:
	.float	2.0
Snan:
	.long	0x7f800001
pinfinity:
	.long	0x7f800000
ninfinity:
	.long	0xff800000


	ENTRY(pow)
	pushl	%ebp
	movl	%esp,%ebp
	PIC_SETUP(1)

	fldl	8(%ebp)			/ x
	fxam				/ determine class of x
	fnstsw	%ax			/ store status in %ax
	movb	%ah,%dh			/ %dh <- condition code of x

	fldl	16(%ebp)		/ y , x
	fxam				/ determine class of y
	fnstsw	%ax			/ store status in %ax
	movb	%ah,%dl			/ %dl <- condition code of y

	call	.pow_main		/// LOCAL
	PIC_WRAPUP
	leave
	ret

.pow_main:
	/ x ** 0 is 1 unless x is 0 or a NaN
	movb	%dl,%cl
	andb	$0x45,%cl
	cmpb	$0x40,%cl		/ C3=1 C2=0 C1=? C0=0 when +-0
	jne	1f
	movb	%dh,%cl
	andb	$0x45,%cl
	cmpb	$0x40,%cl		/ C3=1 C2=0 C1=? C0=0 when +-0
	jne	2f
	/ 0^0
	pushl	$20
	jmp	.SVIDerr		/ SVID error handler
2:
	cmpb	$0x01,%cl		/// C3=0 C2=0 C1=? C0=1 when +-NaN
	jne	2f
	/ NaN^0
	pushl	$42
	jmp	.SVIDerr
2:
	/ (not 0 or NaN)^0
	fstp	%st(0)			/ x
	fstp	%st(0)			/ stack empty
	fld1				/ 1
	ret

1:	/ y is not zero
	PIC_G_LOAD(movzwl,__xpg6,eax)
	andl	$_C99SUSv3_pow_treats_Inf_as_an_even_int,%eax
	cmpl	$0,%eax
	je	1f

	/ C99: 1 ** anything is 1
	fld1				/ 1, y, x
	fucomp	%st(2)			/ y, x
	fnstsw	%ax			/ store status in %ax
	sahf				/ 80387 flags in %ax to 80386 flags
	jp	1f			/ so that pow(NaN1,NaN2) returns NaN2
	jne	1f
	fstp	%st(0)			/ x
	ret

1:
	/ x ** NaN is NaN
	movb	%dl,%cl
	andb	$0x45,%cl
	cmpb	$0x01,%cl		/ C3=0 C2=0 C1=? C0=1 when +-NaN
	jne	1f
	fstp	%st(1)			/ y
	ret

1:	/ y is not NaN
	/ NaN ** y (except 0) is NaN
	movb	%dh,%cl
	andb	$0x45,%cl
	cmpb	$0x01,%cl		/ C3=0 C2=0 C1=? C0=1 when +-NaN
	jne	1f
	fstp	%st(0)			/ x
	ret

1:	/ x is not NaN
	/ x ** 1 is x
	fcoms	PIC_L(one)		/ y , x
	fnstsw	%ax			/ store status in %ax
	sahf				/ 80387 flags in %ax to 80386 flags
	jne	1f
	fstp	%st(0)			/ x
	ret

1:	/ y is not 1
	/ +-(|x| > 1) **  +inf is +inf
	/ +-(|x| > 1) **  -inf is +0
	/ +-(|x| < 1) **  +inf is +0
	/ +-(|x| < 1) **  -inf is +inf
	/ +-(|x| = 1) ** +-inf is NaN
	movb	%dl,%cl
	andb	$0x47,%cl
	cmpb	$0x05,%cl		/ C3=0 C2=1 C1=0 C0=1 when +inf
	je	.yispinf
	cmpb	$0x07,%cl		/ C3=0 C2=1 C1=1 C0=1 when -inf
	je	.yisninf

	/ +0 ** +y (except 0, NaN)		is +0
	/ -0 ** +y (except 0, NaN, odd int)	is +0
	/ +0 ** -y (except 0, NaN)		is +inf (z flag)
	/ -0 ** -y (except 0, NaN, odd int)	is +inf (z flag)
	/ -0 ** y (odd int)			is - (+0 ** x)
	movb	%dh,%cl
	andb	$0x47,%cl
	cmpb	$0x40,%cl		/ C3=1 C2=0 C1=0 C0=0 when +0
	je	.xispzero
	cmpb	$0x42,%cl		/ C3=1 C2=0 C1=1 C0=0 when -0
	je	.xisnzero

	/ +inf ** +y (except 0, NaN)	is +inf
	/ +inf ** -y (except 0, NaN)	is +0
	/ -inf ** +-y (except 0, NaN)	is -0 ** -+y (NO z flag)
	movb	%dh,%cl
	andb	$0x47,%cl
	cmpb	$0x05,%cl		/ C3=0 C2=1 C1=0 C0=1 when +inf
	je	.xispinf
	cmpb	$0x07,%cl		/ C3=0 C2=1 C1=1 C0=1 when -inf
	je	.xisninf

	/ x ** -1 is 1/x
	fcoms	PIC_L(negone)		/ y , x
	fnstsw	%ax			/ store status in %ax
	sahf				/ 80387 flags in %ax to 80386 flags
	jne	1f
	fld	%st(1)			/ x , y , x
	fdivrs	PIC_L(one)		/ 1/x , y , x
	jmp	.signok			/ check for over/underflow

1:	/ y is not -1
	/ x ** 2 is x*x
	fcoms	PIC_L(two)		/ y , x
	fnstsw	%ax			/ store status in %ax
	sahf				/ 80387 flags in %ax to 80386 flags
	jne	1f
	fld	%st(1)			/ x , y , x
	fld	%st(0)			/ x , x , y , x
	fmulp				/ x^2 , y , x
	jmp	.signok			/ check for over/underflow

1:	/ y is not 2
	/ make copies of x & y
	fld	%st(1)			/ x , y , x
	fld	%st(1)			/ y , x , y , x

	/ -x ** y (an integer) is (-1)**(y) * (+x)**(y)
	/ x ** y (x negative & y not integer) is  NaN
	movl	$0,%ecx			/ track whether to flip sign of result
	fld	%st(1)			/ x , y , x , y , x
	ftst				/ compare %st(0) with 0
	fnstsw	%ax			/ store status in %ax
	sahf				/ 80387 flags in %ax to 80386 flags
	fstp	%st(0)			/ y , x , y , x
	ja	.merge			/ x > 0
	/ x < 0
	call	.y_is_int
	cmpl	$0,%ecx
	jne	1f
	/ x < 0, y is non-integral
	fstp	%st(0)			/ x , y , x
	fstp	%st(0)			/ y , x
	pushl	$24
	jmp	.SVIDerr		/ SVID error handler

1:	/ x < 0 & y = int
	fxch				/ x , y , y , x
	fchs				/ px = -x , y , y , x
	fxch				/ y , px , y , x
.merge:
	/ px > 0
	fxch				/ px , y , y , x

	/ x**y   =   exp(y*ln(x))
	fyl2x				/ t=y*log2(px) , y , x
	fld	%st(0)			/ t , t , y , x
	frndint				/ [t] , t , y , x
	fxch				/ t , [t] , y , x
	fucom
	fnstsw	%ax			/ store status in %ax
	sahf				/ 80387 flags in %ax to 80386 flags
	je	1f			/ t is integral
	fsub    %st(1),%st		/ t-[t] , [t] , y , x
	f2xm1				/ 2**(t-[t])-1 , [t] , y , x
	fadds	PIC_L(one)		/ 2**(t-[t]) , [t] , y , x
	fscale				/ 2**t = px**y , [t] , y , x
	jmp	2f
1:
	fstp    %st(0)                  / t=[t] , y , x
	fld1                            / 1 , t , y , x
	fscale                          / 1*2**t = x**y , t , y , x
2:
	fstp	%st(1)			/ x**y , y , x
	cmpl	$1,%ecx
	jne	.signok
	fchs				/ change sign since x<0 & y=-int
.signok:
	subl	$8,%esp
	fstpl	(%esp)			/ round to double precision
	fldl	(%esp)			/ place result on NPX stack
	addl	$8,%esp

	fxam				/ determine class of x**y
	fnstsw	%ax			/ store status in %ax
	andw	$0x4500,%ax
	/ check for overflow
	cmpw	$0x0500,%ax		/ C0=0 C1=1 C2=? C3=1 then +-inf
	jne	1f
	/ x^y overflows
	fstp	%st(0)			/ y , x
	pushl	$21
	jmp	.SVIDerr
1:
	/ check for underflow
	cmpw	$0x4000,%ax		/ C0=1 C1=0 C2=? C3=0 then +-0
	jne	1f
	/ x^y underflows
	fstp	%st(0)			/ y , x
	pushl	$22
	jmp	.SVIDerr
1:
	fstp	%st(2)			/ y , x**y
	fstp	%st(0)			/ x**y
	ret

/ ------------------------------------------------------------------------

.xispinf:
	ftst				/ compare %st(0) with 0
	fnstsw	%ax			/ store status in %ax
	sahf				/ 80387 flags in %ax to 80386 flags
	ja	.retpinf		/ y > 0
	jmp	.retpzero		/ y < 0

.xisninf:
	/ -inf ** +-y is -0 ** -+y
	fchs				/ -y , x
	flds	PIC_L(negzero)		/ -0 , -y , x
	fstp	%st(2)			/ -y , -0
	jmp	.xisnzero

.yispinf:
	fld	%st(1)			/ x , y , x
	fabs				/ |x| , y , x
	fcomps	PIC_L(one)		/ y , x
	fnstsw	%ax			/ store status in %ax
	sahf				/ 80387 flags in %ax to 80386 flags
	je	.retponeorinvalid	/ x == -1	C99
	ja	.retpinf		/ |x| > 1
	jmp	.retpzero		/ |x| < 1

.yisninf:
	fld	%st(1)			/ x , y , x
	fabs				/ |x| , y , x
	fcomps	PIC_L(one)		/ y , x
	fnstsw	%ax			/ store status in %ax
	sahf				/ 80387 flags in %ax to 80386 flags
	je	.retponeorinvalid	/ x == -1	C99
	ja	.retpzero		/ |x| > 1
	jmp	.retpinf		/ |x| < 1

.xispzero:
	/ y cannot be 0 or NaN ; stack has	y , x
	ftst				/ compare %st(0) with 0
	fnstsw	%ax			/ store status in %ax
	sahf				/ 80387 flags in %ax to 80386 flags
	ja	.retpzero		/ y > 0
	/ x = +0 & y < 0
	jmp	.SVIDzerotoneg

.xisnzero:
	/ y cannot be 0 or NaN ; stack has	y , x
	call	.y_is_int
	cmpl	$1,%ecx
	jne	1f			/ y is not an odd integer
	/ y is an odd integer
	ftst				/ compare %st(0) with 0
	fnstsw	%ax			/ store status in %ax
	sahf				/ 80387 flags in %ax to 80386 flags
	ja	.retnzero		/ y > 0
	/ x = -0 & y < 0 (odd int)	return -inf (z flag)
	/ x = -inf & y != 0 or NaN	return -inf (NO z flag)
	movb	%dh,%cl
	andb	$0x45,%cl
	cmpb	$0x05,%cl		/ C3=0 C2=1 C1=? C0=1 when +-inf
	jne	.SVIDzerotoneg
	fstp	%st(0)			/ x
	fstp	%st(0)			/ stack empty
	flds	PIC_L(ninfinity)	/ -inf
	ret

1:	/ y is not an odd integer
	ftst				/ compare %st(0) with 0
	fnstsw	%ax			/ store status in %ax
	sahf				/ 80387 flags in %ax to 80386 flags
	ja	.retpzero		/ y > 0
	/ x = -0 & y < 0 (not odd int)	return +inf (z flag)
	/ x = -inf & y not 0 or NaN 	return +inf (NO z flag)
	movb	%dh,%cl
	andb	$0x45,%cl
	cmpb	$0x05,%cl		/ C3=0 C2=1 C1=? C0=1 when +-inf
	jne	.SVIDzerotoneg
	jmp	.retpinf		/ return +inf (NO z flag)

.retpzero:
	fstp	%st(0)			/ x
	fstp	%st(0)			/ stack empty
	fldz				/ +0
	ret

.retnzero:
	fstp	%st(0)			/ x
	fstp	%st(0)			/ stack empty
	flds	PIC_L(negzero)		/ -0
	ret

.retponeorinvalid:
	PIC_G_LOAD(movzwl,__xpg6,eax)
	andl	$_C99SUSv3_pow_treats_Inf_as_an_even_int,%eax
	cmpl	$0,%eax
	je	1f
	fstp	%st(0)			/ x
	fstp	%st(0)			/ stack empty
	fld1				/ 1
	ret

1:
	fstp	%st(0)			/ x
	fstp	%st(0)			/ stack empty
	flds	PIC_L(Snan)		/ Q NaN (i flag)
	fwait
	ret

.retpinf:
	fstp	%st(0)			/ x
	fstp	%st(0)			/ stack empty
	flds	PIC_L(pinfinity)	/ +inf
	ret

.SVIDzerotoneg:
	pushl	$23
.SVIDerr:
	/ At this point the fp stack contains  y , x  and the number
	/ of the error case has been pushed on the memory stack.
	subl	$16,%esp
	fstpl	8(%esp)			/ push y
	fstpl	(%esp)			/ push x; NPX stack empty
	call	PIC_F(_SVID_libm_err)	/ report result/error according to SVID
	addl	$20,%esp
	ret

/ Set %ecx to 2 if y is an even integer, 1 if y is an odd integer,
/ 0 otherwise.  Assume y is not zero.  Do not raise inexact or modify
/ %edx.
.y_is_int:
	movl	20(%ebp),%eax
	andl	$0x7fffffff,%eax	/ |y|
	cmpl	$0x43400000,%eax
	jae	1f			/ |y| >= 2^53, an even int
	cmpl	$0x3ff00000,%eax
	jb	2f			/ |y| < 1, can't be an int
	movl	%eax,%ecx
	sarl	$20,%ecx
	subl	$0x433,%ecx
	negl	%ecx			/ 52 - unbiased exponent of y
	movl	16(%ebp),%eax
	bsfl	%eax,%eax		/ index of least sig. 1 bit
	jne	3f			/ jump if 1 bit found
	movl	20(%ebp),%eax
	bsfl	%eax,%eax
	addl	$32,%eax		/ 32 + index of least sig. 1 bit
3:
	cmpl	%ecx,%eax
	jb	2f
	ja	1f
	movl	$1,%ecx
	ret
1:
	movl	$2,%ecx
	ret
2:
	xorl	%ecx,%ecx
	ret
	.align	4
	SET_SIZE(pow)
