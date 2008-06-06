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

#include <sys/asm_linkage.h>

	ANSI_PRAGMA_WEAK(wcschr,function)
	ANSI_PRAGMA_WEAK(wschr,function)

	.align	8		/ accounts for .loop alignment and prolog

	ENTRY(wcschr)		/* (wchar_t *s, wchar_t wc) */
	movq	%rdi,%rax
.loop:
	movl	(%rax),%edx	/ %edx = wchar of string
	cmpl	%esi,%edx	/ find it?
	je	.found		/ yes
	testl	%edx,%edx	/ is it null?
	je	.notfound

	movl	4(%rax),%edx	/ %edx = wchar of string
	cmpl	%esi,%edx	/ find it?
	je	.found1		/ yes
	testl	%edx,%edx	/ is it null?
	je	.notfound

	movl	8(%rax),%edx	/ %edx = wchar of string
	cmpl	%esi,%edx	/ find it?
	je	.found2		/ yes
	testl	%edx,%edx	/ is it null?
	je	.notfound

	movl	12(%rax),%edx	/ %edx = wchar of string
	cmpl	%esi,%edx	/ find it?
	je	.found3		/ yes
	addq	$16,%rax
	testl	%edx,%edx	/ is it null?
	jne	.loop

.notfound:
	xorl	%eax,%eax	/ %rax = NULL
	ret

.found3:
	addq	$12,%rax
	ret
.found2:
	addq	$8,%rax
	ret
.found1:
	addq	$4,%rax
.found:
	ret
	SET_SIZE(wcschr)

	ENTRY(wschr)
	jmp	wcschr		/ tail call into wcschr
	SET_SIZE(wschr)
