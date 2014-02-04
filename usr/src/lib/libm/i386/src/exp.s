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

        .file "exp.s"

#include "libm.h"
LIBM_ANSI_PRAGMA_WEAK(exp,function)
#include "libm_synonyms.h"
#include "libm_protos.h"

	ENTRY(exp)
	movl	8(%esp),%ecx		/ ecx <-- hi_32(x)
	andl	$0x7fffffff,%ecx	/ ecx <-- hi_32(|x|)
	cmpl	$0x3fe62e42,%ecx	/ Is |x| < ln(2)?
	jb	.shortcut		/ If so, take a shortcut.
	je	.check_tail		/ |x| may be only slightly < ln(2)
	cmpl	$0x7ff00000,%ecx	/ hi_32(|x|) >= hi_32(INF)?
	jae	.not_finite		/ if so, x is not finite
.finite_non_special:			/ Here, ln(2) < |x| < INF
	fldl	4(%esp)			/ push x
	subl	$8,%esp
					/// overhead of RP save/restore; 63/15
	fstcw	(%esp)			/// ; 15/3
	movw	(%esp),%ax		/// ; 4/1
	movw	%ax,4(%esp)		/// save old RP; 2/1
	orw	$0x0300,%ax		/// force 64-bit RP; 2/1
	movw	%ax,(%esp)		/// ; 2/1
	fldcw	(%esp)			/// ; 19/4
	fldl2e				/ push log2e   }not for xtndd_dbl
	fmulp	%st,%st(1)		/ z = x*log2e  }not for xtndd_dbl
	fld	%st(0)			/ duplicate stack top
	frndint				/ [z],z
	fucom				/ This and the next 3 instructions
	fstsw  %ax			/ add 10 clocks to runtime of the
	sahf				/ main branch, but save about 265
	je      .z_integral		/ upon detection of integral z.
	/ [z] != z, compute exp(x)
	fxch				/ z,[z]
	fsub    %st(1),%st		/ z-[z],[z]
	f2xm1				/ 2**(z-[z])-1,[z]
	fld1				/ 1,2**(z-[z])-1,[z]
	faddp	%st,%st(1)		/   2**(z-[z])  ,[z]
.merge:
	fscale				/   exp(x)      ,[z]
	fstp	%st(1)
	fstcw	(%esp)			/ restore RD
	movw	(%esp),%dx
	andw	$0xfcff,%dx
	movw	4(%esp),%cx
	andw	$0x0300,%cx
	orw	%dx,%cx
	movw	%cx,(%esp)
	fldcw	(%esp)			/// restore old RP; 19/4
	fstpl	(%esp)			/ round to double
	fldl	(%esp)			/ exp(x) rounded to double
	fxam				/ determine class of exp(x)
	add	$8,%esp
	fstsw	%ax			/ store status in ax
	andw	$0x4500,%ax
	cmpw	$0x0500,%ax
	je	.overflow
	cmpw	$0x4000,%ax
	je	.underflow
	ret

.overflow:
	fstp	%st(0)			/ stack empty
	push	%ebp
	mov	%esp,%ebp
	PIC_SETUP(1)
	pushl	$6
	jmp	.error

.underflow:
	fstp	%st(0)			/ stack empty
	push	%ebp
	mov	%esp,%ebp
	PIC_SETUP(2)
	pushl	$7

.error:
	pushl	12(%ebp)		/ high x
	pushl	8(%ebp)			/ low x
	pushl	12(%ebp)		/ high x
	pushl	8(%ebp)			/ low x
	call	PIC_F(_SVID_libm_err)
	addl	$20,%esp
	PIC_WRAPUP
	leave
	ret

.z_integral:				/ here, z is integral
	fstp	%st(0)			/ ,z
	fld1				/ 1,z
	jmp	.merge

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
	fld1				/ 1,2**(z)-1
	faddp	%st,%st(1)		/   2**(z) = e**x
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
	fldz				/ Here, x = -inf, so return 0
	ret

.NaN_or_pinf:
	/ Here, x = NaN or +inf, so load x and return immediately.
	fldl	4(%esp)
	fwait
	ret
	.align	4
	SET_SIZE(exp)
