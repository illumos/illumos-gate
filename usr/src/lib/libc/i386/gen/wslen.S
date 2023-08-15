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

	.file	"wslen.s"

/*
 * Wide character wcslen() implementation
 *
 * size_t
 * wcslen(const wchar_t *s)
 *{
 *	const wchar_t *s0 = s + 1;
 *	while (*s++)
 *		;
 *	return (s - s0);
 *}
 */

#include "SYS.h"

	ANSI_PRAGMA_WEAK(wcslen,function)
	ANSI_PRAGMA_WEAK(wslen,function)

	ENTRY(wcslen)
	movl	4(%esp),%edx
	xorl	%eax,%eax

	.align	8
.loop:
	cmpl	$0,(%edx)
	je	.out0
	cmpl	$0,4(%edx)
	je	.out1
	cmpl	$0,8(%edx)
	je	.out2
	cmpl	$0,12(%edx)
	je	.out3
	addl	$4,%eax
	addl	$16,%edx
	jmp	.loop

	.align	4
.out1:
	incl	%eax
.out0:
	ret

	.align	4
.out2:
	add	$2,%eax
	ret

	.align	4
.out3:
	add	$3, %eax
	ret
	SET_SIZE(wcslen)

	ENTRY(wslen)
	_prologue_
	movl	_esp_(8),%eax
	movl	_esp_(4),%edx
	pushl	%eax
	pushl	%edx
	call	_fref_(wcslen)
	addl	$8,%esp
	_epilogue_
	ret
	SET_SIZE(wslen)
