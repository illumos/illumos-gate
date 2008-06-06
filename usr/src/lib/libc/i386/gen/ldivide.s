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

/ Double long divide routine.

#include "SYS.h"

	.set	lop,16
	.set	rop,24
	.set	ans,0

	ENTRY(ldivide)
	popl	%eax
	xchgl	%eax,0(%esp)
	pushl	%eax

	pushl	%esi
	pushl	%edi

	movl	lop(%esp),%eax
	movl	lop+4(%esp),%edx

/ the following code is only for compatibility with original ldivide code
	orl	%edx,%edx	/ force numerator positive
	jns	.ldiv1
	notl	%edx
	negl	%eax
	sbbl	$0xffffffff,%edx
.ldiv1:
	testl	$0x80000000,rop+4(%esp)
	jz	.ldiv2
	notl	rop+4(%esp)	/ force denominator positive
	negl	rop(%esp)
	sbbl	$0xffffffff,rop+4(%esp)
.ldiv2:
/ end of compatibility code

	xorl	%esi,%esi	/ initialize remainder to 0
	movl	%esi,%edi
	movl	$64,%ecx	/ initialize counter for 64-bits
.div_mod_loop:
	shll	$1,%edi
	rcll	$1,%esi		/ remainder * 2
	shll	$1,%eax
	rcll	$1,%edx		/ numerator * 2 (also quotient)
	adcl	$0,%edi		/ add in any carry from the shift
	subl	rop(%esp),%edi	/ subtract denominator from remainder
	sbbl	rop+4(%esp),%esi
	incl	%eax		/ turn on quotient bit for now
	jnc	.inc_remainder	/ inc didn't affect carry flag
/ can't subtract the denominator from the remainder, add it back
	addl	rop(%esp),%edi
	adcl	rop+4(%esp),%esi
	decl	%eax		/ turn quotient bit off
.inc_remainder:
	loop	.div_mod_loop

/ at this point, %edx:%eax has the quotient and %edi:%esi has the remainder
	popl	%edi
	popl	%esi
	movl	%eax,%ecx
	popl	%eax
	movl	%ecx,ans(%eax)
	movl	%edx,ans+4(%eax)
	ret
	SET_SIZE(ldivide)
