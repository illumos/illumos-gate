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

	.file "log.s"

#include "libm.h"
LIBM_ANSI_PRAGMA_WEAK(log,function)
#include "libm_protos.h"

	ENTRY(log)
	fldln2				/ loge(2)
	movl	8(%esp),%eax		/ eax <-- hi_32(x)
	testl	$0x80000000,%eax
	jnz	.maybe_0_or_less
	testl	$0x7fffffff,%eax
	jz	.maybe_0
	fldl	4(%esp)			/ arg, loge(2)
	fyl2x				/ loge(2)*log2(arg); ln(arg)
	ret

.maybe_0:
	movl	4(%esp),%ecx		/ ecx <-- lo_32(x)
	cmpl	$0,%ecx
	je	.zero			/ no branch if x is +denormal
.neg_nan_reentry:
	fldl	4(%esp)			/ arg, loge(2)
	fyl2x				/ loge(2)*log2(arg); ln(arg)
	ret

.zero_or_less:
	/ x =< 0
	testl	$0x7fffffff,%eax
	jnz	.less_than_0
	movl	4(%esp),%ecx		/ ecx <-- lo_32(x)
	cmpl	$0,%ecx
	jne	.less_than_0		/ branch if x is -denormal
.zero:
	/ x = +/-0
	pushl	%ebp
	movl	%esp,%ebp
	PIC_SETUP(1)
	pushl	$16
	jmp	.merge
	
.maybe_0_or_less:
	cmpl	$0xfff00000,%eax	/ -INF below hi_32(x)?
	ja	.neg_nan_reentry
	jb	.zero_or_less
	movl	4(%esp),%ecx		/ ecx <-- lo_32(x)
	cmpl	$0,%ecx			/ is x NaN or -INF?
	jne	.neg_nan_reentry	/ branch if x is NaN with signbit = 1
	/ x = -INF
.less_than_0:
	pushl	%ebp
	movl	%esp,%ebp
	PIC_SETUP(2)
	pushl	$17
.merge:
	fstp	%st(0)			/ stack empty
	pushl	12(%ebp)
	pushl	8(%ebp)
	pushl	12(%ebp)
	pushl	8(%ebp)
	call	PIC_F(_SVID_libm_err)
	addl	$20,%esp
	PIC_WRAPUP
	leave
	ret
	.align	4
	SET_SIZE(log)
