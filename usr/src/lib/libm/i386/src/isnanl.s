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

        .file "isnanl.s"

#include "libm.h"
LIBM_ANSI_PRAGMA_WEAK(isnanl,function)

	ENTRY(isnanl)
	movl    12(%esp),%eax		/ ax <-- sign bit and exp
	andl    $0x00007fff,%eax
	jz	.not_nan		/ jump if exp is all 0
	xorl    $0x00007fff,%eax
	jz	.nan_or_inf		/ jump if exp is all 1
	testl   $0x80000000,8(%esp)
	jz	.got_nan		/ jump if leading bit is 0
	movl	$0,%eax
.not_nan:
	ret
.nan_or_inf:				/ note that %eax = 0 from before
	cmpl    $0x80000000,8(%esp)     / what is first half of significand?
	jnz	.got_nan		/ jump if not equal to 0x80000000
	testl	$0xffffffff,4(%esp)	/ is second half of significand 0?
	jnz	.got_nan		/ jump if not equal to 0
	ret
.got_nan:
	movl	$1,%eax
	ret
	.align	4
	SET_SIZE(isnanl)
