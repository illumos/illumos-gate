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

        .file "ieee_funcl.s"

#include "libm.h"
LIBM_ANSI_PRAGMA_WEAK(isinfl,function)
LIBM_ANSI_PRAGMA_WEAK(isnormall,function)
LIBM_ANSI_PRAGMA_WEAK(issubnormall,function)
LIBM_ANSI_PRAGMA_WEAK(iszerol,function)
LIBM_ANSI_PRAGMA_WEAK(signbitl,function)
#include "libm_synonyms.h"

	ENTRY(isinfl)
	movl	16(%rsp),%eax		/ ax <-- sign and bexp of x 
	notl	%eax
	andq	$0x7fff,%rax
	jz	.L6
	movq	$0,%rax
.not_inf:
	ret

.L6:					/ here, (eax) = 0.0
	movl	12(%rsp),%ecx
	xorl	$0x80000000,%ecx	/ handle unsupported implicitly
	orl	8(%rsp), %ecx
	jnz	.not_inf
	movq	$1,%rax
	ret
	.align	16
	SET_SIZE(isinfl)

	ENTRY(isnormall)
					/ TRUE iff (x is finite, but
					/	    neither subnormal nor zero)
					/      iff (msb(sgnfcnd(x) /= 0 
					/	    &  0 < bexp(x) < 0x7fff)
	movl	12(%rsp),%eax		/ eax <-- hi_32(sgnfcnd(x))
	andl	$-0x80000000,%eax	/ eax[31]  <-- msb(sgnfcnd(x)),
					/ rest_of(eax) <-- 0
	jz	.L8			/ jump iff msb(sgnfcnd(x)) = 0
	movl	16(%rsp),%eax		/ ax <-- sign and bexp of x
	notl	%eax			/ ax[0..14] <-- not(bexp(x))
	andq	$0x7fff,%rax		/ eax  <-- zero_xtnd(not(bexp(x)))
	jz	.L8			/ jump	iff bexp(x) = 0x7fff or 0
	xorq	$0x7fff,%rax		/ treat pseudo-denormal as subnormal
	jz	.L8
	movq	$1,%rax
.L8:
	ret
	.align	16
	SET_SIZE(isnormall)

	ENTRY(issubnormall)
					/ TRUE iff (bexp(x) = 0 &
					/ msb(sgnfcnd(x)) = 0 & frac(x) /= 0)
	movl	12(%rsp),%eax		/ eax <-- hi_32(sgnfcnd(x))
	testl	$0x80000000,%eax	/ eax[31] = msb(sgnfcnd(x));
					/ set ZF if it's 0.
	jz	.may_be_subnorm		/ jump iff msb(sgnfcnd(x)) = 0
.not_subnorm:
	movq	$0,%rax
	ret
.may_be_subnorm:
	testl	$0x7fff,16(%rsp)	/ set ZF iff bexp(x)  = 0
	jnz	.not_subnorm		/ jump   iff bexp(x) /= 0
	orl	8(%rsp),%eax		/ (eax) = 0 iff sgnfcnd(x) = 0
	jz	.not_subnorm
	movq	$1,%rax
	ret
	.align	16
	SET_SIZE(issubnormall)

	ENTRY(iszerol)
	movl	16(%rsp),%eax		/ ax <-- sign and bexp of x
	andl	$0x7fff,%eax		/ eax <-- zero_xtnd(bexp(x))
	jz	.may_be_zero		/ jump iff bexp(x) = 0
.not_zero:
	movq	$0,%rax
	ret
.may_be_zero:				/ here, (eax) = 0
	orl	12(%rsp),%eax		/ is hi_32(sgnfcnd(x)) = 0?
	jnz	.not_zero		/ jump iff hi_32(sgnfcnd(x)) /= 0
	orl	8(%rsp),%eax		/ is lo_32(sgnfcnd(x)) = 0?
	jnz	.not_zero		/ jump iff lo_32(sgnfcnd(x)) /= 0
	movq	$1,%rax
	ret
	.align	16
	SET_SIZE(iszerol)

	ENTRY(signbitl)
	movl	16(%rsp),%eax		/ eax[15] <-- sign_bit(x)
	shrl	$15,%eax		/ eax <-- zero_xtnd(sign_bit(x))
	andq	$1,%rax
	ret
	.align	16
	SET_SIZE(signbitl)
