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

#include <sys/asm_linkage.h>

	ANSI_PRAGMA_WEAK(wcslen,function)
	ANSI_PRAGMA_WEAK(wslen,function)

	ENTRY(wcslen)		/* (wchar_t *) */
	xorl	%eax,%eax

	.align	8
.loop:
	cmpl	$0,(%rdi)
	je	.out0
	cmpl	$0,4(%rdi)
	je	.out1
	cmpl	$0,8(%rdi)
	je	.out2
	cmpl	$0,12(%rdi)
	je	.out3
	addq	$4,%rax
	addq	$16,%rdi
	jmp	.loop

	.align	4
.out1:
	incq	%rax
.out0:
	ret

	.align	4
.out2:
	addq	$2,%rax
	ret

	.align	4
.out3:
	addq	$3, %rax
	ret
	SET_SIZE(wcslen)

	ENTRY(wslen)
	jmp	wcslen		/ tail call into wcslen
	SET_SIZE(wslen)
