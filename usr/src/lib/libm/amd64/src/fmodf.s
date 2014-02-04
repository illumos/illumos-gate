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

        .file "fmodf.s"

#include "libm.h"
LIBM_ANSI_PRAGMA_WEAK(fmodf,function)
#include "libm_synonyms.h"

	ENTRY(fmodf)
	push	%rbp
	movq	%rsp,%rbp
	subq	$16,%rsp
	movss	%xmm1,-8(%rbp)
	movss	%xmm0,-4(%rbp)
	flds	-8(%rbp)		/ load arg y
	flds	-4(%rbp)		/ load arg x
.loop:
	fprem				/ partial remainder
	fstsw	%ax			/ store status word
	andw	$0x400,%ax		/ check whether reduction complete
	jne	.loop			/ loop while reduction incomplete
	fstps	-4(%rbp)
	movss	-4(%rbp),%xmm0
	fstp	%st(0)
	leave
	ret
	.align	4
	SET_SIZE(fmodf)
