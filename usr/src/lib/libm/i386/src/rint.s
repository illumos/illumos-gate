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

        .file "rint.s"

#include "libm.h"
LIBM_ANSI_PRAGMA_WEAK(rint,function)
#include "libm_synonyms.h"

	ENTRY(rint)
	fldl	4(%esp)			/ load x
	movl	8(%esp),%eax		/ eax <-- hi_32(x)
	andl	$0x7fffffff,%eax	/ eax <-- hi_32(|x|)
	cmpl	$0x43300000,%eax	/ is |x| >= 2**52?
	jae	.done			/ if so, branch (already integral)
	frndint				/ [x], per rounding mode
.done:
	fwait
	ret
	.align	4
	SET_SIZE(rint)
