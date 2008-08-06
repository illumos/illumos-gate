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

	.file	"memccpy.s"

#include <sys/asm_linkage.h>

	ANSI_PRAGMA_WEAK(memccpy,function)

#include "SYS.h"

	ENTRY(memccpy)
	pushl	%esi		/ save register variable
	movl	8(%esp),%eax	/ %eax = address of dest string
	movl	12(%esp),%esi	/ %esi = address of source string
	movb	16(%esp),%dh	/ %dh = character to search for
	movl	20(%esp),%ecx	/ %ecx = length to go still
.loop:
	decl	%ecx		/ decrement bytes to go
	jl	.notfound
	movb	(%esi),%dl
	movb	%dl,(%eax)	/ move byte
	cmpb	%dh,%dl		/ is it the byte sought?
	je	.found		/ yes

	decl	%ecx		/ decrement bytes to go
	jl	.notfound
	movb	1(%esi),%dl
	movb	%dl,1(%eax)	/ move byte
	cmpb	%dh,%dl		/ is it the byte sought?
	je	.found1		/ yes

	decl	%ecx		/ decrement bytes to go
	jl	.notfound
	movb	2(%esi),%dl
	movb	%dl,2(%eax)	/ move byte
	cmpb	%dh,%dl		/ is it the byte sought?
	je	.found2		/ yes

	decl	%ecx		/ decrement bytes to go
	jl	.notfound
	movb	3(%esi),%dl
	movb	%dl,3(%eax)	/ move byte
	addl	$4,%esi
	addl	$4,%eax
	cmpb	%dh,%dl		/ is it the byte sought?
	jne	.loop		/ no
	decl	%eax

.found:
	popl	%esi		/ restore register variable
	incl	%eax		/ return pointer to next byte in dest
	ret

	.align	4
.found2:
	incl	%eax
.found1:
	popl	%esi		/ restore register variable
	addl	$2,%eax		/ return pointer to next byte in dest
	ret

	.align	4
.notfound:
	popl	%esi		/ restore register variable
	xorl	%eax,%eax	/ search fails
	ret
	SET_SIZE(memccpy)
