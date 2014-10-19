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

        .file "atan2.s"

#include "libm.h"
LIBM_ANSI_PRAGMA_WEAK(atan2,function)
#include "libm_synonyms.h"
#include "libm_protos.h"

	ENTRY(atan2)
	movl	4(%esp),%eax		/ low part of y
	movl	12(%esp),%ecx		/ low part of x
	orl	%eax,%ecx
	jz	.maybe_0s

	/ not both x and y are 0's
1:
	fldl	4(%esp)			/ push y
	fldl	12(%esp)		/ push x
	fpatan				/ return atan2(y,x)
	ret

.maybe_0s:
	movl	8(%esp),%eax		/ high part of y
	movl	16(%esp),%ecx		/ high part of x
	orl	%eax,%ecx
	andl	$0x7fffffff,%ecx	/ clear sign
	jnz	1b
	/ both x and y are 0's
	pushl	%ebp
	movl	%esp,%ebp
	PIC_SETUP(1)
	pushl	$3
	pushl	12(%ebp)		/ high y
	pushl	8(%ebp)			/ low y
	pushl	20(%ebp)		/ high x
	pushl	16(%ebp)		/ low x
	call	PIC_F(_SVID_libm_err)	/ report SVID result/error
	addl	$20,%esp
	PIC_WRAPUP
	leave
	ret
	.align	4
	SET_SIZE(atan2)
