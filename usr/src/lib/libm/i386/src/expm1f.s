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

        .file "expm1f.s"

#include "libm.h"
LIBM_ANSI_PRAGMA_WEAK(expm1f,function)

	.data
	.align	4
.mhundred:	.float	-100.0

	ENTRY(expm1f)
	movl	4(%esp),%ecx		/ ecx <-- x
	andl	$0x7fffffff,%ecx	/ ecx <-- |x|
	cmpl	$0x3f317217,%ecx	/ Is |x| < ln(2)?
	jbe	.shortcut		/ If so, take a shortcut.
	cmpl	$0x7f800000,%ecx	/ |x| >= INF?
	jae	.not_finite		/ if so, x is not finite
	flds	4(%esp)			/ push x

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
	fucom				/ This and the next 3 instructions
	fstsw	%ax			/ add 10 clocks to runtime of the
	sahf				/ main branch, but save about 265
	je      .z_integral		/ upon detection of integral z.
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
	fsubrp	%st,%st(1)		/   exp(x)-1    ,max([z],-100)
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

.z_integral:				/ here, z is integral
	fstp	%st(0)			/ ,z
	/ avoid spurious underflow when scaling to compute exp(x) 
	PIC_SETUP(2)
	flds	PIC_L(.mhundred)
	PIC_WRAPUP
	fucom	%st(1)			/ if -100 !< [z], then use -100
	fstsw	%ax
	sahf
	jb	.scale_wont_ovfl
	fxch	%st(1)
.scale_wont_ovfl:
	fstp	%st(0)			/   max([z],-100)
	fld1				/ 1,max([z],-100)
	fscale				/   exp(x)      ,max([z],-100)
	fld1				/ 1,exp(x)      ,max([z],-100)
	fsubrp	%st,%st(1)		/   exp(x)-1    ,max([z],-100)
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

.shortcut:
	/ Here, |x| < ln(2), so |z| = |x*log2(e)| < 1,
	/ whence z is in f2xm1's domain.
	flds	4(%esp)			/ push x
	fldl2e				/ push log2e  }not for xtndd_dbl
	fmulp	%st,%st(1)		/ z = x*log2e }not for xtndd_dbl
	f2xm1				/ 2**(x*log2(e))-1 = e**x - 1
	ret

.not_finite:
	ja	.NaN_or_pinf		/ branch if x is NaN 
	movl	4(%esp),%eax		/ eax <-- x
	andl	$0x80000000,%eax	/ here, x is infinite, but +/-?
	jz	.NaN_or_pinf		/ branch if x = +INF
	fld1				/ Here, x = -inf, so return -1
	fchs
	ret

.NaN_or_pinf:
	/ Here, x = NaN or +inf, so load x and return immediately.
	flds	4(%esp)
	fwait
	ret
	.align	4
	SET_SIZE(expm1f)
