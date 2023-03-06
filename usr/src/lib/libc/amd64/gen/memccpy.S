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

	.file	"memccpy.s"

#include <sys/asm_linkage.h>

	ANSI_PRAGMA_WEAK(memccpy,function)

	ENTRY(memccpy)	/* (void *dst, void *src, uchar_t c, size_t) */
.loop:
	decq	%rcx		/ decrement bytes to go
	jl	.notfound
	movb	(%rsi),%dh
	movb	%dh,(%rdi)	/ move byte
	cmpb	%dh,%dl		/ is it the byte sought?
	je	.found		/ yes

	decq	%rcx		/ decrement bytes to go
	jl	.notfound
	movb	1(%rsi),%dh
	movb	%dh,1(%rdi)	/ move byte
	cmpb	%dh,%dl		/ is it the byte sought?
	je	.found1		/ yes

	decq	%rcx		/ decrement bytes to go
	jl	.notfound
	movb	2(%rsi),%dh
	movb	%dh,2(%rdi)	/ move byte
	cmpb	%dh,%dl		/ is it the byte sought?
	je	.found2		/ yes

	decq	%rcx		/ decrement bytes to go
	jl	.notfound
	movb	3(%rsi),%dh
	movb	%dh,3(%rdi)	/ move byte
	addq	$4,%rsi
	addq	$4,%rdi
	cmpb	%dh,%dl		/ is it the byte sought?
	jne	.loop		/ no
	decq	%rdi

.found:
	incq	%rdi		/ return pointer to next byte in dest
	movq	%rdi,%rax
	ret

	.align	4
.found2:
	incq	%rdi
.found1:
	addq	$2,%rdi		/ return pointer to next byte in dest
	movq	%rdi,%rax
	ret

	.align	4
.notfound:
	xorl	%eax,%eax	/ search fails
	ret
	SET_SIZE(memccpy)
