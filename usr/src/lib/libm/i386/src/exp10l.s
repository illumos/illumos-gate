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

        .file "exp10l.s"

#include "libm.h"
LIBM_ANSI_PRAGMA_WEAK(exp10l,function)
#include "libm_synonyms.h"

	.data
	.align	4
lt2_hi:	.long	0xfbd00000, 0x9a209a84, 0x00003ffd
lt2_lo:	.long	0x653f4837, 0x8677076a, 0x0000bfc9

	ENTRY(exp10l)
	movl	12(%esp),%ecx		/ cx <--sign&bexp(x)
	andl	$0x00007fff,%ecx	/ ecx <-- zero_xtnd(bexp(x))
	cmpl	$0x00003ffd,%ecx	/ Is |x| < log10(2)?
	jb	.shortcut		/ If so, take a shortcut.
	je	.check_tail		/ maybe |x| only slightly < log10(2)
	cmpl	$0x00007fff,%ecx	/ bexp(|x|) = bexp(INF)?
	je	.not_finite		/ if so, x is not finite
	cmpl	$0x0000400e,%ecx	/ |x| < 32768 = 2^15?
	jb	.finite_non_special	/ if so, proceed with argument reduction
	fldt	4(%esp)			/ x
	fld1				/ 1, x
	jmp	1f
.finite_non_special:			/ Here, log10(2) < |x| < 2^15
	fldt	4(%esp)			/ x
	fld	%st(0)			/ x, x
	fldl2t				/ log2(10), x, x
	fmulp				/ z := x*log2(10), x
	frndint				/ [z], x
	fst	%st(2)			/ [z], x, [z]
	PIC_SETUP(1)
	fldt	PIC_L(lt2_hi)		/ lt2_hi, [z], x, [z]
	fmulp				/ [z]*lt2_hi, x, [z]
	fsubrp	%st,%st(1)		/ x-[z]*lt2_hi, [z]
	fldt	PIC_L(lt2_lo)		/ lt2_lo, x-[z]*lt2_hi, [z]
	PIC_WRAPUP
	fmul	%st(2),%st		/ [z]*lt2_lo, x-[z]*lt2_hi, [z]
	fsubrp	%st,%st(1)		/ r := x-[z]*log10(2), [z]
	fldl2t				/ log2(10), r, [z]
	fmulp				/ f := r*log2(10), [z]
	f2xm1				/ 2^f-1,[z]
	fld1				/ 1, 2^f-1, [z]
	faddp	%st,%st(1)		/ 2^f, [z]
1:
	fscale				/ 10^x, [z]
	fstp	%st(1)
	ret

.check_tail:
	movl	8(%esp),%ecx		/ ecx <-- hi_32(sgnfcnd(x))
	cmpl	$0x9a209a84,%ecx	/ Is |x| < log10(2)?
	ja	.finite_non_special
	jb	.shortcut
	movl	4(%esp),%edx		/ edx <-- lo_32(sgnfcnd(x))
	cmpl	$0xfbcff798,%edx	/ Is |x| slightly > log10(2)?
	ja	.finite_non_special	/ branch if |x| slightly > log10(2)
.shortcut:
	/ Here, |x| < log10(2), so |z| = |x/log10(2)| < 1
	/ whence z is in f2xm1's domain.
	fldt	4(%esp)			/ x
	fldl2t				/ log2(10), x
	fmulp				/ z := x*log2(10)
	f2xm1				/ 2^z-1
	fld1				/ 1, 2^z-1
	faddp	%st,%st(1)		/ 10^x
	ret

.not_finite:
	movl	8(%esp),%ecx		/ ecx <-- hi_32(sgnfcnd(x))
	cmpl	$0x80000000,%ecx	/ hi_32(sgnfcnd(x)) = hi_32(sgnfcnd(INF))?
	jne	.NaN_or_pinf		/ if not, x is NaN or unsupp.
	movl	4(%esp),%edx		/ edx <-- lo_32(sgnfcnd(x))
	cmpl	$0,%edx			/ lo_32(sgnfcnd(x)) = 0?
	jne	.NaN_or_pinf		/ if not, x is NaN
	movl	12(%esp),%eax		/ ax <-- sign&bexp((x))
	andl	$0x00008000,%eax	/ here, x is infinite, but +/-?
	jz	.NaN_or_pinf		/ branch if x = +INF
	fldz				/ Here, x = -inf, so return 0
	ret

.NaN_or_pinf:
	/ Here, x = NaN or +inf, so load x and return immediately.
	fldt	4(%esp)
	ret
	.align	4
	SET_SIZE(exp10l)
