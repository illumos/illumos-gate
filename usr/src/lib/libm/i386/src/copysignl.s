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

	.file	"copysignl.s"

#include "libm.h"
LIBM_ANSI_PRAGMA_WEAK(copysignl,function)
#include "libm_synonyms.h"

	ENTRY(copysignl)
	movl    12(%esp),%eax		/ sign and bexp of x
	movl    24(%esp),%ecx		/ sign and bexp of y
	andl    $0x00007fff,%eax	/ eax <-- bexp(x)
	andl    $0x00008000,%ecx	/ ecx <-- sign(y)
	orl     %ecx,%eax		/ eax <-- bexp(x) with sign(y)
	movl    8(%esp),%ecx		/ ecx <-- hi_32(sgnfcnd(x))
	movl    4(%esp),%edx		/ edx <-- lo_32(sgnfcnd(x))
	subl	$12,%esp		/ set up loading dock for result
	movl	%edx,(%esp)		/ copy lo_32(result's sgnfcnd)
					/ to loading dock
	movl	%ecx,4(%esp)		/ copy hi_32(result's sgnfcnd)
					/ to loading dock
	movl    %eax,8(%esp)		/ copy sign&bexp(result)
					/ to loading dock
	fldt    (%esp)			/ load copysign(x,y)
	addl	$12,%esp		/ restore stack-pointer for return
	ret
	.align	4
	SET_SIZE(copysignl)
