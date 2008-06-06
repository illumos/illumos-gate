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

#include "SYS.h"

	ANSI_PRAGMA_WEAK(wcsncmp,function)
	ANSI_PRAGMA_WEAK(wsncmp,function)

	ENTRY(wcsncmp)
	pushl	%esi		/ save register variables
	movl	8(%esp),%esi	/ %esi = first string
	movl	%edi,%edx
	movl	12(%esp),%edi	/ %edi = second string
	cmpl	%esi,%edi	/ same string?
	je	.equal
	movl	16(%esp),%ecx	/ %ecx = length
	incl	%ecx		/ will later predecrement this uint
.loop:
	decl	%ecx
	je	.equal		/ Used all n chars?
	movl	(%esi),%eax	/ slodb ; scab
	cmpl	(%edi),%eax
	jne	.notequal_0	/ Are the bytes equal?
	testl	%eax,%eax
	je	.equal		/ End of string?

	decl	%ecx
	je	.equal		/ Used all n chars?
	movl	4(%esi),%eax	/ slodb ; scab
	cmpl	4(%edi),%eax
	jne	.notequal_1	/ Are the bytes equal?
	testl	%eax,%eax
	je	.equal		/ End of string?

	decl	%ecx
	je	.equal		/ Used all n chars?
	movl	8(%esi),%eax	/ slodb ; scab
	cmpl	8(%edi),%eax
	jne	.notequal_2	/ Are the bytes equal?
	testl	%eax,%eax
	je	.equal		/ End of string?

	decl	%ecx
	je	.equal		/ Used all n chars?
	movl	12(%esi),%eax	/ slodb ; scab
	cmpl	12(%edi),%eax
	jne	.notequal_3	/ Are the bytes equal?
	addl	$16,%esi
	addl	$16,%edi
	testl	%eax,%eax
	jne	.loop		/ End of string?

.equal:
	popl	%esi		/ restore registers
	xorl	%eax,%eax	/ return 0
	movl	%edx,%edi
	ret

	.align	4
.notequal_3:
	addl	$4,%edi
.notequal_2:
	addl	$4,%edi
.notequal_1:
	addl	$4,%edi
.notequal_0:
	popl	%esi		/ restore registers
	subl	(%edi),%eax	/ return value is (*s1 - *--s2)
	movl	%edx,%edi
	ret
	SET_SIZE(wcsncmp)

	ENTRY(wsncmp)
	_prologue_
	movl	_esp_(12),%ecx
	movl	_esp_(8),%eax
	movl	_esp_(4),%edx
	pushl	%ecx
	pushl	%eax
	pushl	%edx
	call	_fref_(wcsncmp)
	addl	$12,%esp
	_epilogue_
	ret
	SET_SIZE(wsncmp)
