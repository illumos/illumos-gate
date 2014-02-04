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

	.file "remainder.s"

#include "libm.h"
LIBM_ANSI_PRAGMA_WEAK(remainder,function)
#include "libm_synonyms.h"
#include "libm_protos.h"

	ENTRY(remainder)
	pushl	%ebp
	movl	%esp,%ebp
	fldl	16(%esp)		/ load arg y
	fldl	8(%esp)			/ load arg x
	fucom
	fnstsw	%ax
	sahf
	jp	.rem_loop		/ if x or y is NaN, use fprem1

	movl	20(%esp),%eax		/ eax <-- hi_32(y)
	andl	$0x7fffffff,%eax	/ eax <-- hi_32(|y|)
	orl	16(%esp),%eax		/ eax <-- lo_32(y)|hi_32(|y|)
	je	.yzero_or_xinf

	movl	12(%esp),%eax		/ eax <-- hi_32(x)
	andl	$0x7fffffff,%eax	/ eax <-- hi_32(|x|)
	cmpl	$0x7ff00000,%eax
	jne	.rem_loop
	cmpl	$0,8(%esp)
	je	.yzero_or_xinf

.rem_loop:
	fprem1				/ partial remainder
	fstsw	%ax			/ store status word
	andw	$0x400,%ax		/ check for incomplete reduction
	jne	.rem_loop		/ while incomplete, do fprem1 again
	fstp	%st(1)
	leave
	ret

.yzero_or_xinf:
	PIC_SETUP(1)
	fstp	%st(0)			/ x
	fstp	%st(0)			/ empty NPX stack
	pushl	$28			/ case 28 in _SVID_libm_err
	pushl	20(%ebp)		/ pass y
	pushl	16(%ebp)
	pushl	12(%ebp)		/ pass x
	pushl	8(%ebp)
	call	PIC_F(_SVID_libm_err)
	addl	$20,%esp
	PIC_WRAPUP
	leave
	ret
	.align	4
	SET_SIZE(remainder)
