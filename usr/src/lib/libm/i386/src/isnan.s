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

        .file "isnan.s"

#include "libm.h"
LIBM_ANSI_PRAGMA_WEAK(isnan,function)
	.weak _isnan
	.type _isnan,@function
_isnan	= __isnan
	.weak _isnand
	.type _isnand,@function
_isnand	= __isnan
	.weak isnand
	.type isnand,@function
isnand	= __isnan
#include "libm_synonyms.h"

	ENTRY(isnan)
	movl    8(%esp),%eax		/ eax <-- hi_32(x)
	andl    $0x7fffffff,%eax	/ eax <-- hi_32(abs(x))
	subl    $0x7ff00000,%eax	/ weed out finite values
	jae	.nan_or_inf		/ no jump if arg. is finite
	movl	$0,%eax			/ ansi needs (eax) = 0
	ret
.nan_or_inf:
	ja	.got_nan		/ no jump if arg. may be infinite;
					/ let nan waste time
					/ (eax) = 0 here
	testl	$0xffffffff,4(%esp)	/ ZF <-- 1 iff lo_frac. = 0
					/	   iff arg. is infinite
	jnz	.got_nan		/ no jump if arg. is infinite;
	ret
.got_nan:
	movl	$1,%eax			/ %eax was 0, must be made 1 to
					/ indicate TRUE 
	ret
	.align	4
	SET_SIZE(isnan)
