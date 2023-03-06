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

        .file "hypotf.s"

#include "libm.h"
LIBM_ANSI_PRAGMA_WEAK(hypotf,function)
#include "libm_protos.h"

	ENTRY(hypotf)
	movl	4(%esp),%eax		/ eax <-- x
	andl	$0x7fffffff,%eax	/ eax <-- |x|
	jz	.return_abs_y		/ if x = +/-0, return |y|
	subl	$0x7f800000,%eax	/ eax <-- |x| - INF
	jz	.return_abs_x		/ if x = +/-INF, return |x|
	movl	8(%esp),%eax		/ eax <-- y
	andl	$0x7fffffff,%eax	/ eax <-- |y|
	jz	.return_abs_x		/ if y = +/-0, return |x|
	subl	$0x7f800000,%eax	/ eax <-- |y| - INF
.return_abs_y:
	flds	8(%esp)			/ y
	jz	.take_abs		/ if y = +/-INF, return |y|
	fmul	%st(0),%st		/ y*y
	flds	4(%esp)			/ x,y*y
	fmul	%st(0),%st		/ x*x,y*y
	faddp	%st,%st(1)		/ x*x+y*y
	fsqrt				/ sqrt(x*x+y*y)
	subl	$4,%esp
	fstps	(%esp)			/ round to single
	flds	(%esp)
	fwait
	addl	$4,%esp
	ret

.return_abs_x:
	/ returns |x|
	flds	4(%esp)
.take_abs:
	fabs	
	ret
	.align	4
	SET_SIZE(hypotf)
