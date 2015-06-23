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

        .file "expm1l.s"

#include "libm.h"
LIBM_ANSI_PRAGMA_WEAK(expm1l,function)

	.data
	.align	16
ln2_hi:	.4byte	0xd1d00000, 0xb17217f7, 0x3ffe, 0x0
ln2_lo:	.4byte	0x4c67fc0d, 0x8654361c, 0xbfce, 0x0

	ENTRY(expm1l)
	movl	16(%rsp),%ecx		/ cx <--sign&bexp(x)
	movl	%ecx,%eax		/ ax <--sign&bexp(x)
	andl	$0x7fff,%ecx		/ ecx <-- zero_xtnd(bexp(x))
	cmpl	$0x3ffe,%ecx		/ Is |x| < ln(2)?
	jb	.shortcut		/ If so, take a shortcut.
	je	.check_tail		/ |x| may be only slightly < ln(2)
.general_case:				/ Here, |x| > ln(2) or x is NaN
	cmpl	$0x7fff,%ecx		/ bexp(|x|) = bexp(INF)?
	je	.not_finite		/ if so, x is not finite
	andl	$0xffff,%eax		/ eax <-- sign&bexp(x)
	cmpl	$0xc006,%eax		/ x <= -128?
	jae	1f			/ if so, simply return -1
	cmpl	$0x400d,%ecx		/ |x| < 16384 = 2^14?
	jb	.finite_non_special	/ if so, proceed with argument reduction
	fldt	8(%rsp)			/ x >= 16384; x
	fld1				/ 1, x
	fscale				/ +Inf, x
	fstp	%st(1)			/ +Inf
	ret

.finite_non_special:			/ -128 < x < -ln(2) || ln(2) < x < 2^14
	fldt	8(%rsp)			/ x
	fld	%st(0)			/ x, x
	fldl2e				/ log2(e), x, x
	fmulp				/ z := x*log2(e), x
	frndint				/ [z], x
	fst	%st(2)			/ [z], x, [z]
	PIC_SETUP(1)
	fldt	PIC_L(ln2_hi)		/ ln2_hi, [z], x, [z]
	fmulp				/ [z]*ln2_hi, x, [z]
	fsubrp	%st,%st(1)		/ x-[z]*ln2_hi, [z]
	fldt	PIC_L(ln2_lo)		/ ln2_lo, x-[z]*ln2_hi, [z]
	PIC_WRAPUP
	fmul	%st(2),%st		/ [z]*ln2_lo, x-[z]*ln2_hi, [z]
	fsubrp	%st,%st(1)		/ r := x-[z]*ln(2), [z]
	fldl2e				/ log2(e), r, [z]
	fmulp				/ f := r*log2(e), [z]
	f2xm1				/ 2^f-1,[z]
	fld1				/ 1, 2^f-1, [z]
	faddp	%st,%st(1)		/ 2^f, [z]
	fscale				/ e^x, [z]
	fstp	%st(1)			/ e^x
	fld1				/ 1, e^x
	fsubrp	%st,%st(1)		/ e^x-1
	ret

.check_tail:
	movl	12(%rsp),%ecx		/ ecx <-- hi_32(sgnfcnd(x))
	cmpl	$0xb17217f7,%ecx	/ Is |x| < ln(2)?
	ja	.finite_non_special
	jb	.shortcut
	movl	8(%rsp),%edx		/ edx <-- lo_32(x)
	cmpl	$0xd1cf79ab,%edx	/ Is |x| slightly < ln(2)?
	ja	.finite_non_special	/ branch if |x| slightly > ln(2)
.shortcut:
	/ Here, |x| < ln(2), so |z| = |x/ln(2)| < 1,
	/ whence z is in f2xm1's domain.
	fldt	8(%rsp)			/ x
	fldl2e				/ log2(e), x
	fmulp				/ z := x*log2(e)
	f2xm1				/ 2^(x*log2(e))-1 = e^x-1
	ret

.not_finite:
	movl	12(%rsp),%ecx		/ ecx <-- hi_32(sgnfcnd(x))
	cmpl	$0x80000000,%ecx	/ hi_32(|x|) = hi_32(INF)?
	jne	.NaN_or_pinf		/ if not, x is NaN 
	movl	8(%rsp),%edx		/ edx <-- lo_32(x)
	cmpl	$0,%edx			/ lo_32(x) = 0?
	jne	.NaN_or_pinf		/ if not, x is NaN
	movl	16(%rsp),%eax		/ ax <-- sign&bexp((x))
	andl	$0x8000,%eax		/ here, x is infinite, but +/-?
	jz	.NaN_or_pinf		/ branch if x = +INF
1:
	fld1				/ Here, x = -inf, so return -1
	fchs
	ret

.NaN_or_pinf:
	/ Here, x = NaN or +inf, so load x and return immediately.
	fldt	8(%rsp)
	ret
	.align	16
	SET_SIZE(expm1l)
