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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

	.file	"nextafterl.s"

#include "libm.h"
LIBM_ANSI_PRAGMA_WEAK(nextafterl,function)
#include "libm_synonyms.h"

	.section .rodata
	.align	4
.LFmaxl:	.long	0xffffffff,0xffffffff,0x00007ffe
.LFminl:	.long	0x1,0x0,0x0


	ENTRY(nextafterl)
	pushl	%ebp
	movl	%esp,%ebp
	fldt	20(%ebp)	/ y
	subl	$12,%esp
	fldt	8(%ebp)		/ load x
	fucom			/ x : y
	fstsw	%ax
	sahf
	jp	.LNaN
	je	.Lequal
	fstp	%st(1)		/ x
	ja	.Lbigger
	/ x < y
	ftst
	movl	$1,-12(%ebp)	/// -12(%ebp) contains Fminl
	movl	$0,-8(%ebp)
	movl	$0,%ecx			/// final needs this
	movl	%ecx,-4(%ebp)
	fnstsw	%ax
	sahf
	je	.Lfinal
	ja	.Laddulp
	jb	.Lsubulp
.Lbigger:
	/ x > y
	ftst
	movl	$1,-12(%ebp)	/// -12(%ebp) contains -Fminl
	movl	$0,-8(%ebp)
	movl	$0x00008000,%ecx	/// final needs this
	movl	%ecx,-4(%ebp)
	fnstsw	%ax
	sahf
	je	.Lfinal
	jb	.Laddulp
.Lsubulp:
	movl	12(%ebp),%edx	/ high word of significand of x
	movl	16(%ebp),%ecx	/ x's exponent
	andl	$0x0000ffff,%ecx
	movl	%edx,%eax
	not	%eax
	andl	$0x80000000,%eax	/ look at explicit leading bit
	orl	%ecx,%eax
	andl	$0x80007fff,%eax
	jnz	.Lnot_pseudonormal	/ zero value implies pseudonormal
	addl	$1,%ecx		/ if pseudonormal, turn into equivalent normal
.Lnot_pseudonormal:
	movl	8(%ebp),%eax	/ low x
	subl	$1,%eax		/ low x - ulp
	movl	%eax,-12(%ebp)
	cmpl	$0xffffffff,%eax	/ this means low x was 0
	jz	.Lborrow
	movl	%edx,-8(%ebp)
	movl	%ecx,-4(%ebp)
	jmp	.Lfinal
.Lborrow:
	cmpl	$0x80000000,%edx	/ look at high x
	je	.Lsecond_borrow
	subl	$1,%edx
	movl	%edx,-8(%ebp)
	movl	%ecx,-4(%ebp)
	jmp	.Lfinal
.Lsecond_borrow:
	movl	%ecx,%eax
	andl	$0x7fff,%eax	/ look at exp x without sign bit
	cmpl	$1,%eax
	jbe	.Lsubnormal_result	/ exp > 1 ==> result will be normal
	movl	$0xffffffff,-8(%ebp)
	subl	$1,%ecx
	movl	%ecx,-4(%ebp)
	jmp	.Lfinal
.Lsubnormal_result:
	movl	$0x7fffffff,-8(%ebp)
	movl	%ecx,%eax
	andl	$0x8000,%eax	/ look at sign bit
	jz	.Lpositive
	movl	$0x8000,%ecx
	movl	%ecx,-4(%ebp)
	jmp	.Lfinal
.Lpositive:
	movl	$0,%ecx
	movl	%ecx,-4(%ebp)
	jmp	.Lfinal
.Laddulp:
	movl	12(%ebp),%edx	/ high x
	movl	16(%ebp),%ecx	/ x's exponent
	andl	$0x0000ffff,%ecx
	movl	%edx,%eax
	not	%eax
	andl	$0x80000000,%eax	/ look at explicit leading bit
	orl	%ecx,%eax
	andl	$0x80007fff,%eax
	jnz	.Lnot_pseudonormal_2	/ zero value implies pseudonormal
	addl	$1,%ecx
.Lnot_pseudonormal_2:
	movl	8(%ebp),%eax	/ low x
	addl	$1,%eax		/ low x + ulp
	movl	%eax,-12(%ebp)
	jz	.Lcarry		/ jump if the content of %eax is 0
	movl	%edx,-8(%ebp)
	movl	%ecx,-4(%ebp)
	jmp .Lfinal
.Lcarry:
	movl	%edx,%eax
	andl	$0x7fffffff,%eax
	cmpl	$0x7fffffff,%eax	/ look at high x
	je	.Lsecond_carry
	addl	$1,%edx
	movl	%edx,-8(%ebp)
	movl	%ecx,-4(%ebp)
	jmp	.Lfinal
.Lsecond_carry:
	movl	$0x80000000,-8(%ebp)
	addl	$1,%ecx
	movl	%ecx,-4(%ebp)
.Lfinal:
	fstp	%st(0)
	fldt	-12(%ebp)
	andl	$0x00007fff,%ecx
	jz	.Lunderflow
	cmpw	$0x7fff,%cx
	je	.Loverflow
	jmp	.Lreturn
.Loverflow:
	PIC_SETUP(1)
	fldt	PIC_L(.LFmaxl)
	PIC_WRAPUP
	fmulp	%st,%st(0)	/ create overflow signal
	jmp	.Lreturn
.Lunderflow:
	PIC_SETUP(2)
	fldt	PIC_L(.LFminl)
	PIC_WRAPUP
	fmulp	%st,%st(0)	/ create underflow signal
	jmp	.Lreturn
.Lequal:
	fstp	%st(0)		/ C99 says to return y when x == y
	jmp	.Lreturn
.LNaN:
	faddp	%st,%st(1)	/ x+y,x
.Lreturn:
	fwait
	leave
	ret
	.align	4
	SET_SIZE(nextafterl)
