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

        .file "expm1.s"

#include "libm.h"
LIBM_ANSI_PRAGMA_WEAK(expm1,function)

	.data
	.align	4
.mhundred:	.float	-100.0

	ENTRY(expm1)
	movl	8(%esp),%ecx		/ ecx <-- hi_32(x)
	andl	$0x7fffffff,%ecx	/ ecx <-- hi_32(|x|)
	cmpl	$0x3fe62e42,%ecx	/ Is |x| < ln(2)?
	jb	.shortcut		/ If so, take a shortcut.
	je	.check_tail		/ |x| may be only slightly < ln(2)
	cmpl	$0x7ff00000,%ecx	/ hi_32(|x|) >= hi_32(INF)?
	jae	.not_finite		/ if so, x is not finite
.finite_non_special:			/ Here, ln(2) < |x| < INF
	fldl	4(%esp)			/ push x

	subl	$8,%esp			/ save RP and set round-to-64-bits
	fstcw	(%esp)
	movw	(%esp),%ax
	movw	%ax,4(%esp)
	orw	$0x0300,%ax
	movw	%ax,(%esp)
	fldcw	(%esp)

	fldl2e				/ push log2e   }not for xtndd_dbl
	fmulp	%st,%st(1)		/ z = x*log2e  }not for xtndd_dbl
	fld	%st(0)			/ duplicate stack top
	frndint				/ [z],z
	/ [z] != 0, compute exp(x) and then subtract one to get expm1(x)
	fxch				/ z,[z]
	fsub    %st(1),%st		/ z-[z],[z]
	f2xm1				/ 2**(z-[z])-1,[z]
	/ avoid spurious underflow when scaling to compute exp(x) 
	PIC_SETUP(1)
	flds	PIC_L(.mhundred)
	PIC_WRAPUP
	fucom	%st(2)			/ if -100 !< [z], then use -100
	fstsw	%ax
	sahf
	jb	.got_int_part
	fxch	%st(2)
.got_int_part:
	fstp	%st(0)			/   2**(z-[z])-1,max([z],-100)
	fld1				/ 1,2**(z-[z])-1,max([z],-100)
	faddp	%st,%st(1)		/   2**(z-[z])  ,max([z],-100)
	fscale				/   exp(x)      ,max([z],-100)
	fld1				/ 1,exp(x)      ,max([z],-100)
 	fxch                            / exp(x),1      ,max([z],-100)
	fsubp	%st,%st(1)		/   exp(x)-1    ,max([z],-100)
	fstp	%st(1)

	fstcw	(%esp)			/ restore old RP
	movw	(%esp),%dx
	andw	$0xfcff,%dx
	movw	4(%esp),%cx
	andw	$0x0300,%cx
	orw	%dx,%cx
	movw	%cx,(%esp)
	fldcw	(%esp)
	add	$8,%esp

	ret

.check_tail:
	movl	4(%esp),%edx		/ edx <-- lo_32(x)
	cmpl	$0xfefa39ef,%edx	/ Is |x| slightly < ln(2)?
	ja	.finite_non_special	/ branch if |x| slightly > ln(2)
.shortcut:
	/ Here, |x| < ln(2), so |z| = |x*log2(e)| < 1,
	/ whence z is in f2xm1's domain.
	fldl	4(%esp)			/ push x
	fldl2e				/ push log2e  }not for xtndd_dbl
	fmulp	%st,%st(1)		/ z = x*log2e }not for xtndd_dbl
	f2xm1				/ 2**(x*log2(e))-1 = e**x - 1
	ret

.not_finite:
	/ Here, flags still have settings from execution of
	/	cmpl	$0x7ff00000,%ecx	/ hi_32(|x|) > hi_32(INF)?
	ja	.NaN_or_pinf		/ if not, x may be +/- INF 
	movl	4(%esp),%edx		/ edx <-- lo_32(x)
	cmpl	$0,%edx			/ lo_32(x) = 0?
	jne	.NaN_or_pinf		/ if not, x is NaN
	movl	8(%esp),%eax		/ eax <-- hi_32(x)
	andl	$0x80000000,%eax	/ here, x is infinite, but +/-?
	jz	.NaN_or_pinf		/ branch if x = +INF
	fld1				/ Here, x = -inf, so return -1
	fchs
	ret

.NaN_or_pinf:
	/ Here, x = NaN or +inf, so load x and return immediately.
	fldl	4(%esp)
	fwait
	ret
	.align	4
	SET_SIZE(expm1)
