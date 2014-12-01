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

        .file "rndintl.s"

#include "libm.h"

	ENTRY(aintl)
	movl	%esp,%eax
	subl	$8,%esp
	fstcw	-8(%eax)
	fldt	4(%eax)
	movw	-8(%eax),%cx
	orw	$0x0c00,%cx
	movw	%cx,-4(%eax)
	fldcw	-4(%eax)		/ set RD = to_zero
	frndint
	fstcw	-4(%eax)
	movw	-4(%eax),%dx
	andw	$0xf3ff,%dx
	movw	-8(%eax),%cx
	andw	$0x0c00,%cx
	orw	%dx,%cx
	movw	%cx,-8(%eax)
	fldcw	-8(%eax)		/ restore RD
	addl	$8,%esp
	ret
	.align	4
	SET_SIZE(aintl)

	ENTRY(irintl)
	movl	%esp,%ecx
	subl	$8,%esp
	fldt	4(%ecx)			/ load x
	fistpl	-8(%ecx)		/ [x]
	fwait
	movl	-8(%ecx),%eax
	addl	$8,%esp
	ret
	.align	4
	SET_SIZE(irintl)

	.data
	.align	4
half:	.float	0.5

	ENTRY(anintl)
.Lanintl:
	movl	%esp,%ecx
	subl	$8,%esp
	fstcw	-8(%ecx)
	fldt	4(%ecx)
	movw	-8(%ecx),%dx
	andw	$0xf3ff,%dx
	movw	%dx,-4(%ecx)
	fldcw	-4(%ecx)		/ set RD = to_nearest
	fld	%st(0)
	frndint				/ [x],x
	fstcw	-4(%ecx)
	movw	-4(%ecx),%dx
	andw	$0xf3ff,%dx
	movw	-8(%ecx),%ax
	andw	$0x0c00,%ax
	orw	%dx,%ax
	movw	%ax,-8(%ecx)
	fldcw	-8(%ecx)		/ restore RD
	fucom				/ check if x is already an integer
	fstsw	%ax
	sahf
	jp	.L0
	je	.L0
	fxch				/ x,[x]
	fsub	%st(1),%st		/ x-[x],[x]
	fabs				/ |x-[x]|,[x]
	PIC_SETUP(1)
	fcoms	PIC_L(half)
	PIC_WRAPUP
	fnstsw	%ax
	sahf
	jae	.halfway		/ if |x-[x]| = 0.5 goto halfway, 
					/ most cases will not take branch.
.L0:
	addl	$8,%esp
	fstp	%st(0)
	ret
.halfway:
	/ x = n+0.5, recompute anint(x) as x+sign(x)*0.5
	fldt	4(%ecx)			/ x, 0.5, [x]
	movw	12(%ecx),%ax		/ sign+exp part of x
	andw	$0x8000,%ax		/ look at sign bit
	jnz	.x_neg
	faddp
	addl	$8,%esp
	fstp	%st(1)
	ret
.x_neg:
	/ here, x is negative, so return x-0.5
	fsubp	%st,%st(1)		/ x-0.5,[x]
	addl	$8,%esp
	fstp	%st(1)
	ret
	.align	4
	SET_SIZE(anintl)

	ENTRY(nintl)
	pushl	%ebp
	movl	%esp,%ebp
	subl	$8,%esp
	pushl	16(%ebp)
	pushl	12(%ebp)
	pushl	8(%ebp)
	call	.Lanintl		/// LOCAL
	fistpl	-8(%ebp)
	fwait
	movl	-8(%ebp),%eax
	leave
	ret
	.align	4
	SET_SIZE(nintl)
