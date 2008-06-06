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
/ Wide character wcsncpy() implementation
/
/ Algorithm based on Solaris 2.6 gen/strncpy.s implementation
/

#include <sys/asm_linkage.h>

	ANSI_PRAGMA_WEAK(wcsncmp,function)
	ANSI_PRAGMA_WEAK(wsncmp,function)

	ENTRY(wcsncmp)		/* (wchar *ws1, wchar_t *ws2, size_t n) */
	cmpq	%rdi,%rsi	/ same string?
	je	.equal
	incq	%rdx		/ will later predecrement this uint
.loop:
	decq	%rdx
	je	.equal		/ Used all n chars?
	movl	(%rdi),%eax	/ slodb ; scab
	cmpl	(%rsi),%eax
	jne	.notequal_0	/ Are the bytes equal?
	testl	%eax,%eax
	je	.equal		/ End of string?

	decq	%rdx
	je	.equal		/ Used all n chars?
	movl	4(%rdi),%eax	/ slodb ; scab
	cmpl	4(%rsi),%eax
	jne	.notequal_1	/ Are the bytes equal?
	testl	%eax,%eax
	je	.equal		/ End of string?

	decq	%rdx
	je	.equal		/ Used all n chars?
	movl	8(%rdi),%eax	/ slodb ; scab
	cmpl	8(%rsi),%eax
	jne	.notequal_2	/ Are the bytes equal?
	testl	%eax,%eax
	je	.equal		/ End of string?

	decq	%rdx
	je	.equal		/ Used all n chars?
	movl	12(%rdi),%eax	/ slodb ; scab
	cmpl	12(%rsi),%eax
	jne	.notequal_3	/ Are the bytes equal?
	addq	$16,%rdi
	addq	$16,%rsi
	testl	%eax,%eax
	jne	.loop		/ End of string?

.equal:
	xorl	%eax,%eax	/ return 0
	ret

	.align	4
.notequal_3:
	addq	$4,%rsi
.notequal_2:
	addq	$4,%rsi
.notequal_1:
	addq	$4,%rsi
.notequal_0:
	subl	(%rsi),%eax	/ return value is (*s1 - *--s2)
	ret
	SET_SIZE(wcsncmp)

	ENTRY(wsncmp)
	jmp	wcsncmp		/ tail call into wcsncmp
	SET_SIZE(wsncmp)
