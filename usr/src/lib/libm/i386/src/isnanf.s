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

        .file "isnanf.s"

#include "libm.h"
LIBM_ANSI_PRAGMA_WEAK(isnanf,function)
	.weak _isnanf
	.type _isnanf,@function
_isnanf	= __isnanf

	ENTRY(isnanf)
	movl    4(%esp),%eax		/ eax <-- x
	andl	$0x7fffffff,%eax	/ eax <-- abs(x)
	subl    $0x7f800000,%eax	/ ZF <-- 1      iff x is infinite
	jae	.nan_or_inf		/ no jump iff arg. is finite
	movl	$0,%eax
	ret
.nan_or_inf:
	jnz	.got_nan		/ no jump if arg. infinite;
					/ let nan waste time
	ret				/ %eax = 0 here
.got_nan:
	movl	$1,%eax			/ %eax was 0, must be made 1 to
					/ indicate TRUE 
	ret
	.align	4
	SET_SIZE(isnanf)

