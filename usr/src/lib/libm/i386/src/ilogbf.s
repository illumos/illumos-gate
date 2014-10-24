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

        .file "ilogbf.s"

#include "libm.h"
LIBM_ANSI_PRAGMA_WEAK(ilogbf,function)
#include "xpg6.h"

	.data
	.align	8
two23:	.long	0x4b000000		/ 2**23

	ENTRY(ilogbf)
	movl	4(%esp),%eax		/ eax <-- x
	testl	$0x7f800000,%eax	/ is bexp(x) 0?
	jz	.bexp_0 		/ jump if x is 0 or subnormal
					/ here, biased exponent is non-zero
	andl	$0x7fffffff,%eax	/ eax <-- abs(x)
	cmpl	$0x7f800000,%eax	/ is bexp(x) 0xff?
	jae	.bexp_all_1		/ jump if x is NaN or Inf
	shrl	$23,%eax		/ eax <-- zero_xtnd(bexp(x))
	subl	$127,%eax 		/ unbias exponent by 127
	ret

.bexp_all_1:
	movl	$0x7fffffff,%eax	/ x is NaN or inf, so return 0x7fffffff
	jmp	0f

.bexp_0:
	andl	$0x7fffffff,%eax	/ eax <-- abs(x), and
					/ ZF = 1 iff x = 0.0
	jnz	.ilogb_subnorm
	movl	$0x80000001,%eax	/ x is +/-0, so return 0x80000001
0:
	PIC_SETUP(0)
	PIC_G_LOAD(movzwl,__xpg6,ecx)
	PIC_WRAPUP
	andl	$_C99SUSv3_ilogb_0InfNaN_raises_invalid,%ecx
	cmpl	$0,%ecx
	je	1f
	fldz
	fdivp	%st,%st(0)		/ raise invalid as per SUSv3
1:
	ret

.ilogb_subnorm:				/ subnormal input
	flds	4(%esp)			/ push x
	PIC_SETUP(1)
	fmuls	PIC_L(two23)		/ x*2**23; rebias x by 127+23,
					/	   instead of 127
	PIC_WRAPUP
	subl	$4,%esp			/ set up storage area
	fstps	(%esp)			/ store x*2**23 in storage area
	fwait				/ (shouldn't raise exception, but
					/ just in case)
	movl	$0x7f800000,%eax	/ eax <-- single_bexp_mask
	andl	(%esp),%eax		/ eax[23..30]  <-- bexp(x*2**23),
					/ rest_of(eax) <-- 0
	shrl	$23,%eax		/ eax <-- zero_xtnd(bexp(x*2**23))
	subl	$150,%eax		/ unbias rebiased x by 150 (= 127 + 23)
	addl	$4,%esp			/ restore stack for caller
	ret
	.align	4
	SET_SIZE(ilogbf)
