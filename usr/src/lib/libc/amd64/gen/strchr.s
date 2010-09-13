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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

	.file	"strchr.s"

#include "SYS.h"

	ENTRY(strchr)		/* (char *, char) */
.loop:
	movb	(%rdi),%dl	/ %dl = byte of string
	cmpb	%sil,%dl	/ find it?
	je	.found		/ yes
	testb	%dl,%dl		/ is it null?
	je	.notfound

	movb	1(%rdi),%dl	/ %dl = byte of string
	cmpb	%sil,%dl	/ find it?
	je	.found1		/ yes
	testb	%dl,%dl		/ is it null?
	je	.notfound

	movb	2(%rdi),%dl	/ %dl = byte of string
	cmpb	%sil,%dl	/ find it?
	je	.found2		/ yes
	testb	%dl,%dl		/ is it null?
	je	.notfound

	movb	3(%rdi),%dl	/ %dl = byte of string
	cmpb	%sil,%dl	/ find it?
	je	.found3		/ yes
	addq	$4,%rdi
	testb	%dl,%dl		/ is it null?
	jne	.loop

.notfound:
	xorl	%eax,%eax	/ %rax = NULL
	ret

.found3:
	incq	%rdi
.found2:
	incq	%rdi
.found1:
	incq	%rdi
.found:
	movq	%rdi,%rax
	ret
	SET_SIZE(strchr)
