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

	.file	"copysignf.s"

#include "libm.h"
LIBM_ANSI_PRAGMA_WEAK(copysignf,function)

	ENTRY(copysignf)
	movl    4(%esp),%eax		/ eax <-- x
	movl    8(%esp),%ecx		/ ecx <-- y
	andl    $0x7fffffff,%eax	/ eax <-- abs(x)
	andl    $0x80000000,%ecx	/ ecx[31] <-- sign_bit(y)
	orl     %ecx,%eax		/ eax <-- copysign(x,y)
	subl	$4,%esp			/ set up loading dock for result
	movl	%eax,(%esp)		/ copy result to loading dock
	flds    (%esp)			/ load copysign(x,y)
	fwait				/ in case fldl causes exception
	addl	$4,%esp			/ restore stack-pointer for return
	ret
	.align	4
	SET_SIZE(copysignf)
