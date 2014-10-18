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

	.file	"round.s"

#include "libm.h"
LIBM_ANSI_PRAGMA_WEAK(round,function)
#include "libm_synonyms.h"
#undef fabs

	.section .rodata
	.align	4
.Lhalf:	.float	0.5

	ENTRY(round)
	movl	%esp,%ecx
	subl	$8,%esp
	fstcw	-8(%ecx)
	fldl	4(%ecx)
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
	jp	0f
	je	0f
	fxch				/ x,[x]
	fsub	%st(1),%st		/ x-[x],[x]
	fabs				/ |x-[x]|,[x]
	PIC_SETUP(1)
	fcoms	PIC_L(.Lhalf)
	PIC_WRAPUP
	fnstsw	%ax
	sahf
	jae	2f			/ if |x-[x]| = 0.5 goto halfway, 
					/ most cases will not take branch.
0:
	addl	$8,%esp
	fstp	%st(0)
	ret
2:
    / x = n+0.5, recompute round(x) as x+sign(x)*0.5
	fldl	4(%ecx)			/ x, 0.5, [x]
	movl	8(%ecx),%eax		/ high part of x
	andl	$0x80000000,%eax
	jnz	3f
	faddp
	addl	$8,%esp
	fstp	%st(1)
	ret
3:
	/ here, x is negative, so return x-0.5
	fsubp	%st,%st(1)		/ x-0.5,[x]
	addl	$8,%esp
	fstp	%st(1)
	ret
	.align	4
	SET_SIZE(round)
