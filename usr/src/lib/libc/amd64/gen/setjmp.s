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

/*
 *	longjmp(env, val)
 * will generate a "return(val)" from
 * the last call to
 *	setjmp(env)
 * by restoring registers rip rsp rbp rbx r12 r13 r14 r15 from 'env'
 * and doing a return.
 */

/*
 * entry    reg   offset
 * env[0] = %rbx  0	register variables
 * env[1] = %r12  8
 * env[2] = %r13  16
 * env[3] = %r14  24
 * env[4] = %r15  32
 * env[5] = %rbp  40	stack frame
 * env[6] = %rsp  48
 * env[7] = %rip  56
 */

#include <sys/asm_linkage.h>

	ANSI_PRAGMA_WEAK(setjmp,function)
	ANSI_PRAGMA_WEAK(longjmp,function)

	ENTRY(setjmp)
	movq	%rbx, 0(%rdi)
	movq	%r12, 8(%rdi)
	movq	%r13, 16(%rdi)
	movq	%r14, 24(%rdi)
	movq	%r15, 32(%rdi)
	movq	%rbp, 40(%rdi)
	popq	%rdx		/* return address */
	movq	%rsp, 48(%rdi)
	movq	%rdx, 56(%rdi)
	xorl	%eax, %eax	/* return 0 */
	jmp	*%rdx
	SET_SIZE(setjmp)

	ENTRY(longjmp)
	movq	0(%rdi), %rbx
	movq	8(%rdi), %r12
	movq	16(%rdi), %r13
	movq	24(%rdi), %r14
	movq	32(%rdi), %r15
	movq	40(%rdi), %rbp
	movq	48(%rdi), %rsp
	movl	%esi, %eax
	test	%eax, %eax	/* if val != 0		*/
	jnz	1f		/* 	return val	*/
	incl	%eax		/* else return 1	*/
1:
	movq	56(%rdi), %rdx	/* return to caller of setjmp */
	jmp	*%rdx
	SET_SIZE(longjmp)
