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

	.file	"copysign.s"

#include "libm.h"
LIBM_ANSI_PRAGMA_WEAK(copysign,function)

	ENTRY(copysign)
	movl    8(%esp),%eax		/ eax <-- hi_32(x)
	movl    16(%esp),%ecx		/ ecx <-- hi_32(y)
	andl    $0x7fffffff,%eax	/ eax <-- hi_32(abs(x))
	andl    $0x80000000,%ecx	/ ecx[31] <-- sign_bit(y)
	orl     %ecx,%eax		/ eax <-- hi_32(copysign(x,y))
	movl	4(%esp),%ecx		/ ecx <-- lo_32(x)
					/	= lo_32(copysign(x,y))
	subl	$8,%esp			/ set up loading dock for result
	movl	%ecx,(%esp)		/ copy lo_32(result) to loading dock
	movl    %eax,4(%esp)		/ copy hi_32(result) to loading dock
	fldl    (%esp)			/ load copysign(x,y)
	fwait				/ in case fldl causes exception
	addl	$8,%esp			/ restore stack-pointer for return
	ret
	.align	4
	SET_SIZE(copysign)
