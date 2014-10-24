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

        .file "rndintl.s"

#include "libm.h"

	ENTRY(aintl)
	movq	%rsp,%rax
	subq	$16,%rsp
	fstcw	-8(%rax)
	fldt	8(%rax)
	movw	-8(%rax),%cx
	orw	$0x0c00,%cx
	movw	%cx,-4(%rax)
	fldcw	-4(%rax)		/ set RD = to_zero
	frndint
	fstcw	-4(%rax)
	movw	-4(%rax),%dx
	andw	$0xf3ff,%dx
	movw	-8(%rax),%cx
	andw	$0x0c00,%cx
	orw	%dx,%cx
	movw	%cx,-8(%rax)
	fldcw	-8(%rax)		/ restore RD
	addq	$16,%rsp
	ret
	.align	16
	SET_SIZE(aintl)

	ENTRY(irintl)
	movq	%rsp,%rcx
	subq	$16,%rsp
	fldt	8(%rcx)			/ load x
	fistpl	-8(%rcx)		/ [x]
	fwait
	movslq	-8(%rcx),%rax
	addq	$16,%rsp
	ret
	.align	16
	SET_SIZE(irintl)

	.data
	.align	16
half:	.float	0.5

	ENTRY(anintl)
.Lanintl:
	movq	%rsp,%rcx
	subq	$16,%rsp
	fstcw	-8(%rcx)
	fldt	8(%rcx)
	movw	-8(%rcx),%dx
	andw	$0xf3ff,%dx
	movw	%dx,-4(%rcx)
	fldcw	-4(%rcx)		/ set RD = to_nearest
	fld	%st(0)
	frndint				/ [x],x
	fstcw	-4(%rcx)
	movw	-4(%rcx),%dx
	andw	$0xf3ff,%dx
	movw	-8(%rcx),%ax
	andw	$0x0c00,%ax
	orw	%dx,%ax
	movw	%ax,-8(%rcx)
	fldcw	-8(%rcx)		/ restore RD
	fucomi	%st(1),%st		/ check if x is already an integer
	jp	.L0
	je	.L0
	fxch				/ x,[x]
	fsub	%st(1),%st		/ x-[x],[x]
	fabs				/ |x-[x]|,[x]
	PIC_SETUP(1)
	flds	PIC_L(half)
	fcomip	%st(1),%st		/ compare 0.5 with |x-[x]|
	PIC_WRAPUP
	je	.halfway		/ if 0.5 = |x-[x]| goto halfway, 
					/ most cases will not take branch.
.L0:
	addq	$16,%rsp
	fstp	%st(0)
	ret
.halfway:
	/ x = n+0.5, recompute anint(x) as x+sign(x)*0.5
	fldt	8(%rcx)			/ x, 0.5, [x]
	movw	16(%rcx),%ax		/ sign+exp part of x
	andw	$0x8000,%ax		/ look at sign bit
	jnz	.x_neg
	faddp
	addq	$16,%rsp
	fstp	%st(1)
	ret
.x_neg:
	/ here, x is negative, so return x-0.5
	fsubp	%st,%st(1)		/ x-0.5,[x]
	addq	$16,%rsp
	fstp	%st(1)
	ret
	.align	16
	SET_SIZE(anintl)

	ENTRY(nintl)
	pushq	%rbp
	movq	%rsp,%rbp
	subq	$16,%rsp
	pushq	24(%rbp)
	pushq	16(%rbp)
	call	.Lanintl		/// LOCAL
	fistpl	-8(%rbp)
	fwait
	movslq	-8(%rbp),%rax
	leave
	ret
	.align	16
	SET_SIZE(nintl)
