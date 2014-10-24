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

        .file "ilogb.s"

#include "libm.h"
LIBM_ANSI_PRAGMA_WEAK(ilogb,function)
#include "xpg6.h"

	.data
	.align	8
two52:	.long	0x0,0x43300000	/ 2**52

	ENTRY(ilogb)
	movl	8(%esp),%eax		/ eax <-- hi_32(x)
	andl	$0x7fffffff,%eax	/ eax <-- hi_32(abs(x))
	testl	$0x7ff00000,%eax	/ is bexp(x) 0?
	jz	.bexp_0 		/ jump if x is 0 or subnormal
					/ biased exponent is non-zero
	cmpl	$0x7ff00000,%eax	/ is bexp(x) 0x7ff?
	jae	.bexp_all_1		/ jump if x is NaN or Inf
	shrl	$20,%eax		/ eax <-- bexp(x)
	subl	$1023,%eax		/ unbias exponent by 1023
	ret

.bexp_all_1:
	movl	$0x7fffffff,%eax	/ x is NaN or inf, so return 0x7fffffff
	jmp	0f

.bexp_0:
	orl	4(%esp),%eax		/ test whether x is 0
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
	fldl	4(%esp)			/ push x
	PIC_SETUP(1)
	fmull	PIC_L(two52)		/ x*2**52
	PIC_WRAPUP
	subl	$8,%esp			/ set up storage area
	fstpl	(%esp)			/ store x*2**52 in storage are
	movl	$0x7ff00000,%eax
	andl	4(%esp),%eax
	shrl	$20,%eax		/ extract exponent of x*2**52
	subl	$1075,%eax		/ unbias it by 1075 (= 1023 + 52)
	addl	$8,%esp
	ret
	.align	4
	SET_SIZE(ilogb)
