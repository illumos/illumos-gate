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

        .file "exp10f.s"

#include "libm.h"
LIBM_ANSI_PRAGMA_WEAK(exp10f,function)
#include "libm_synonyms.h"

	ENTRY(exp10f)
	movl	4(%esp),%ecx		/ ecx <-- x
	andl	$0x7fffffff,%ecx	/ ecx <-- |x|
	cmpl	$0x3e9a209a,%ecx	/ Is |x| < log10(2)?
	jbe	.shortcut		/ If so, take a shortcut.
	cmpl	$0x7f800000,%ecx	/ |x| >= INF?
	jae	.not_finite		/ if so, x is not finite
	flds	4(%esp)			/ push x (=arg)

	subl	$8,%esp			/ save RP and set round-to-64-bits
	fstcw	(%esp)
	movw	(%esp),%ax
	movw	%ax,4(%esp)
	orw	$0x0300,%ax
	movw	%ax,(%esp)
	fldcw	(%esp)

	fldl2t				/ push log2(10)  }NOT for xtndd_dbl
	fmulp	%st,%st(1)		/ z = x*log2(10) }NOT for xtndd_dbl
	fld	%st(0)			/ duplicate stack top
	frndint				/ [z],z
	fucom				/ z integral?
	fstsw	%ax
	sahf
	je      .z_integral		/ branch if z integral
	fxch				/ z, [z]
	fsub	%st(1),%st		/ z-[z], [z]
	f2xm1				/ 2**(z-[z])-1, [z]
	fld1				/ 1,2**(z-[z])-1, [z]
	faddp	%st,%st(1)		/ 2**(z-[z]), [z]
	fscale				/ 2**z = 10**(arg), [z]
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
	fld1				/ 1 = 2**0, z
	fscale				/ 2**(0 + z) = 2**z = 10**(arg), z
	fstp	%st(1)			/ 10**(arg)

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
	/ Here, |x| < log10(2), so |z| = |x*log2(10)| < 1
	/ whence z is in f2xm1's domain.
	flds	4(%esp)			/ push x (=arg)
	fldl2t				/ push log2(10)  }NOT for xtndd_dbl
	fmulp	%st,%st(1)		/ z = x*log2(10) }NOT for xtndd_dbl
	f2xm1				/ 2**z - 1
	fld1				/ 1,2**z - 1
	faddp	%st,%st(1)		/ 2**z = 10**x
	ret

.not_finite:
	ja	.NaN_or_pinf		/ branch if x is NaN 
	movl	4(%esp),%eax		/ eax <-- x
	andl	$0x80000000,%eax	/ here, x is infinite, but +/-?
	jz	.NaN_or_pinf		/ branch if x = +INF
	fldz				/ Here, x = -inf, so return 0
	ret

.NaN_or_pinf:
	/ Here, x = NaN or +inf, so load x and return immediately.
	flds	4(%esp)
	fwait
	ret
	.align	4
	SET_SIZE(exp10f)
