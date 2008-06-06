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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

	.file	"%M%"

/
/ Wide character wcschr() implementation
/
/ Algorithm based on Solaris 2.6 gen/strchr.s implementation
/

#include "SYS.h"

	ANSI_PRAGMA_WEAK(wcschr,function)
	ANSI_PRAGMA_WEAK(wschr,function)

	.align	8		/ accounts for .loop alignment and prolog

	ENTRY(wcschr)
	movl	4(%esp),%eax	/ %eax = string address
	movl	8(%esp),%ecx	/ %ecx = wchar sought
.loop:
	movl	(%eax),%edx	/ %edx = wchar of string
	cmpl	%ecx,%edx	/ find it?
	je	.found		/ yes
	testl	%edx,%edx	/ is it null?
	je	.notfound

	movl	4(%eax),%edx	/ %edx = wchar of string
	cmpl	%ecx,%edx	/ find it?
	je	.found1		/ yes
	testl	%edx,%edx	/ is it null?
	je	.notfound

	movl	8(%eax),%edx	/ %edx = wchar of string
	cmpl	%ecx,%edx	/ find it?
	je	.found2		/ yes
	testl	%edx,%edx	/ is it null?
	je	.notfound

	movl	12(%eax),%edx	/ %edx = wchar of string
	cmpl	%ecx,%edx	/ find it?
	je	.found3		/ yes
	addl	$16,%eax
	testl	%edx,%edx	/ is it null?
	jne	.loop

.notfound:
	xorl	%eax,%eax	/ %eax = NULL
	ret

.found3:
	addl	$12,%eax
	ret
.found2:
	addl	$8,%eax
	ret
.found1:
	addl	$4,%eax
.found:
	ret
	SET_SIZE(wcschr)

	ENTRY(wschr)
	_prologue_
	movl	_esp_(8),%eax
	movl	_esp_(4),%edx
	pushl	%eax
	pushl	%edx
	call	_fref_(wcschr)
	addl	$8,%esp
	_epilogue_
	ret
	SET_SIZE(wschr)
