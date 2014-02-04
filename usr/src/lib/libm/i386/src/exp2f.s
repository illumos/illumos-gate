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

        .file "exp2f.s"

#include "libm.h"
LIBM_ANSI_PRAGMA_WEAK(exp2f,function)
#include "libm_synonyms.h"

	ENTRY(exp2f)
	movl	4(%esp),%ecx		/ ecx <-- x
	andl	$0x7fffffff,%ecx	/ ecx <-- |x|
	cmpl	$0x3f800000,%ecx	/ Is |x| <= 1?
	jbe	.shortcut		/ If so, take a shortcut.
	cmpl	$0x7f800000,%ecx	/ |x| >= INF?
	jae	.not_finite		/ if so, x is not finite
	flds	4(%esp)			/ push arg
	fld	%st(0)			/ duplicate stack top
	frndint				/ [x],x
	fucom				/ x integral?
	fstsw	%ax
	sahf
	je      .x_integral		/ branch if x integral
	fxch				/ x, [x]
	fsub	%st(1),%st		/ x-[x], [x]
	f2xm1				/ 2**(x-[x])-1, [x]
	fld1				/ 1,2**(x-[x])-1, [x]
	faddp	%st,%st(1)		/ 2**(x-[x]), [x]
	fscale				/ 2**x = 2**(arg), [x]
	fstp	%st(1)
	ret

.x_integral:				/ here, x is integral
	fstp	%st(0)			/ ,x
	fld1				/ 1 = 2**0, x
	fscale				/ 2**(0 + x) = 2**x, x
	fstp	%st(1)			/ 2**x
	ret

.shortcut:
	/ Here, |x| <= 1,
	/ whence x is in f2xm1's domain.
	flds	4(%esp)			/ push x
	f2xm1				/ 2**x - 1
	fld1				/ 1,2**x - 1
	faddp	%st,%st(1)		/ 2**x
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
	SET_SIZE(exp2f)
