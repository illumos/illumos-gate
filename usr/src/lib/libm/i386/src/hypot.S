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

        .file "hypot.s"

#include "libm.h"
LIBM_ANSI_PRAGMA_WEAK(hypot,function)
#include "libm_protos.h"

	.data
	.align	4
inf:
	.long	0x7f800000

	ENTRY(hypot)
	movl	8(%esp),%eax		/ eax <-- hi_32(x)
	andl	$0x7fffffff,%eax	/ eax <-- hi_32(|x|)
	jz	.x_maybe_0		/ if x = +/-0, return |y|
	subl	$0x7ff00000,%eax	/ eax <-- hi_32(|x|) - hi_32(INF)
	jz	.x_maybe_inf
.check_y:
	movl	16(%esp),%eax		/ eax <-- hi_32(y)
	andl	$0x7fffffff,%eax	/ eax <-- hi_32(|y|)
	jz	.y_maybe_0		/ if y = +/-0, return |x|
	subl	$0x7ff00000,%eax	/ eax <-- hi_32(|y|) - hi_32(INF)
	jz	.y_maybe_inf
.do_hypot:
	fldl	12(%esp)		/ ,y
	fmul	%st(0),%st		/ ,y*y
	fldl	4(%esp)			/ x,y*y
	fmul	%st(0),%st		/ x*x,y*y
	faddp	%st,%st(1)		/ x*x+y*y
	fsqrt				/ sqrt(x*x+y*y)
	subl	$8,%esp
	fstpl	(%esp)			/ round to double
	fldl	(%esp)			/ sqrt(x*x+y*y) rounded to double
	PIC_SETUP(1)
	flds	PIC_L(inf)		/ inf , sqrt(x*x+y*y)
	PIC_WRAPUP
	addl	$8,%esp
	fucomp
	fstsw	%ax			/ store status in %ax
	sahf				/ 80387 flags in %ah to 80386 flags
	jz	.maybe_ovflw
	ret

.maybe_ovflw:
	jnp	.ovflw
	ret

.ovflw:
	/	overflow occurred
	fstp	%st(0)			/ stack empty
	pushl	%ebp
	movl	%esp,%ebp
	PIC_SETUP(2)
	pushl	$4
	pushl	20(%ebp)		/ high y
	pushl	16(%ebp)		/ low y
	pushl	12(%ebp)		/ high x
	pushl	8(%ebp)			/ low x
	call	PIC_F(_SVID_libm_err)
	addl	$20,%esp
	PIC_WRAPUP
	leave
	ret

.x_maybe_0:
	movl	4(%esp),%ecx		/ ecx <-- lo_32(x)
	orl	%ecx,%eax		/ is x = +/-0?
	jnz	.check_y		/ branch if x is denormal
	/  x = +/-0, so return |y|
	fldl	12(%esp)
	fabs
	ret

.x_maybe_inf:
	movl	4(%esp),%ecx		/ ecx <-- lo_32(x)
	orl	%ecx,%eax		/ is x = +/-INF?
	jnz	.check_y		/ branch if x is NaN
	/ push&pop y in case y is a SNaN
	fldl	12(%esp)
	fstp	%st(0)
	/ x = +/-INF, so return |x|
	fldl	4(%esp)
	fabs
	ret

.y_maybe_0:
	movl	12(%esp),%ecx		/ ecx <-- lo_32(y)
	orl	%ecx,%eax		/ is y = +/-0?
	jnz	.do_hypot		/ branch if y is denormal
	/  y = +/-0, so return |x|
	fldl	4(%esp)
	fabs
	ret

.y_maybe_inf:
	movl	12(%esp),%ecx		/ ecx <-- lo_32(y)
	orl	%ecx,%eax		/ is y = +/-INF?
	jnz	.do_hypot		/ branch if y is NaN
	/ push&pop x in case x is a SNaN
	fldl	4(%esp)
	fstp	%st(0)
	/  y = +/-INF, so return |y|
	fldl	12(%esp)
	fabs
	ret
	.align	4
	SET_SIZE(hypot)
