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

        .file "ilogbl.s"

#include "libm.h"
LIBM_ANSI_PRAGMA_WEAK(ilogbl,function)
#include "xpg6.h"

	.data
	.align	16
two63:	.4byte	0x0,0x43d00000		/ 2**63

	ENTRY(ilogbl)
	movq	16(%rsp),%rax		/ eax <-- sign and bexp of x
	andq	$0x7fff,%rax		/ eax <-- bexp(x)
	jz	.bexp_0			/ jump iff x is 0 or subnormal
					/ here, biased exponent is non-zero
	testl	$0x80000000,12(%rsp)	/ test msb of hi_32(sgnfcnd(x))
	jz	.ilogbl_not_finite	/ jump if unsupported format
	cmpq	$0x7fff,%rax
	je	.ilogbl_not_finite
	subq	$16383,%rax 		/ unbias exponent by 16383 = 0x3fff
	ret

.ilogbl_not_finite:
	movq	$0x7fffffff,%rax	/ x is NaN/inf/unsup
	jmp	0f

.bexp_0:
	movq	8(%rsp),%rax		/ rax <-- sgnfcnd(x)
	orq	%rax,%rax
	jnz	.ilogbl_subnorm		/ jump iff x is subnormal
	movq	$-2147483647,%rax 	/ x is +/-0, so return 1-2^31
0:
	PIC_SETUP(0)
	PIC_G_LOAD(movzwq,__xpg6,rcx)
	PIC_WRAPUP
	andl	$_C99SUSv3_ilogb_0InfNaN_raises_invalid,%ecx
	cmpl	$0,%ecx
	je	1f
	fldz
	fdivp	%st,%st(0)		/ raise invalid as per SUSv3
1:
	ret


.ilogbl_subnorm:			/ subnormal or pseudo-denormal input
	fldt	8(%rsp)			/ push x, setting D-flag
	PIC_SETUP(1)
	fmull	PIC_L(two63)		/ x*2**63
	PIC_WRAPUP
	subq	$16,%rsp
	fstpt	(%rsp)
	movq	$0x7fff,%rax
	andq    8(%rsp),%rax            / eax <-- sign and bexp of x*2**63
	subq    $16445,%rax             / unbias it by (16,383 + 63)
	addq	$16,%rsp
	ret
	.align	16
	SET_SIZE(ilogbl)
