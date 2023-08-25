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

	.file	"strncmp.s"

#include "SYS.h"

	ENTRY(strncmp)
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
	movb	(%esi),%al	/ slodb ; scab
	cmpb	(%edi),%al
	jne	.notequal_0	/ Are the bytes equal?
	testb	%al,%al
	je	.equal		/ End of string?

	decl	%ecx
	je	.equal		/ Used all n chars?
	movb	1(%esi),%al	/ slodb ; scab
	cmpb	1(%edi),%al
	jne	.notequal_1	/ Are the bytes equal?
	testb	%al,%al
	je	.equal		/ End of string?

	decl	%ecx
	je	.equal		/ Used all n chars?
	movb	2(%esi),%al	/ slodb ; scab
	cmpb	2(%edi),%al
	jne	.notequal_2	/ Are the bytes equal?
	testb	%al,%al
	je	.equal		/ End of string?

	decl	%ecx
	je	.equal		/ Used all n chars?
	movb	3(%esi),%al	/ slodb ; scab
	cmpb	3(%edi),%al
	jne	.notequal_3	/ Are the bytes equal?
	addl	$4,%esi
	addl	$4,%edi
	testb	%al,%al
	jne	.loop		/ End of string?

.equal:
	popl	%esi		/ restore registers
	xorl	%eax,%eax	/ return 0
	movl	%edx,%edi
	ret

	.align	4
.notequal_3:
	incl	%edi
.notequal_2:
	incl	%edi
.notequal_1:
	incl	%edi
.notequal_0:
	popl	%esi		/ restore registers
	clc			/ clear carry bit
	subb	(%edi),%al
	movl	%edx,%edi
	movl	$-1, %eax	/ possibly wasted instr
	jc	.neg		/ did we overflow in the sub
	movl	$1, %eax	/ if not a > b
.neg:
	ret
	SET_SIZE(strncmp)
