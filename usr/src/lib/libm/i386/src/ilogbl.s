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

        .file "ilogbl.s"

#include "libm.h"
LIBM_ANSI_PRAGMA_WEAK(ilogbl,function)
#include "xpg6.h"

	.data
	.align	8
two63:	.long	0x0,0x43d00000		/ 2**63

	ENTRY(ilogbl)
	movl	12(%esp),%eax		/ eax <-- sign and bexp of x
	andl	$0x00007fff,%eax	/ eax <-- bexp(x)
	jz	.bexp_0			/ jump iff x is 0 or subnormal
					/ here, biased exponent is non-zero
	testl	$0x80000000,8(%esp)	/ test msb of hi_32(sgnfcnd(x))
	jz	.ilogbl_not_finite	/ jump if unsupported format
	cmpl	$0x00007fff,%eax
	je	.ilogbl_not_finite
	subl	$16383,%eax 		/ unbias exponent by 16383 = 0x3fff
	ret

.ilogbl_not_finite:
	movl	$0x7fffffff,%eax	/ x is NaN/inf/unsup
	jmp	0f

.bexp_0:
	movl	8(%esp),%eax		/ eax <-- hi_32(sgnfcnd(x))
	orl	4(%esp),%eax		/ test whether x is 0
	jnz	.ilogbl_subnorm		/ jump iff x is subnormal
	movl	$0x80000001,%eax 	/ x is +/-0, so return 0x80000001
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


.ilogbl_subnorm:			/ subnormal or pseudo-denormal input
	fldt	4(%esp)			/ push x, setting D-flag
	PIC_SETUP(1)
	fmull	PIC_L(two63)		/ x*2**63
	PIC_WRAPUP
	subl	$12,%esp
	fstpt	(%esp)
	movl	$0x00007fff,%eax
	andl    8(%esp),%eax            / eax <-- sign and bexp of x*2**63
	subl    $16445,%eax             / unbias it by (16,383 + 63)
	addl	$12,%esp
	ret
	.align	4
	SET_SIZE(ilogbl)
