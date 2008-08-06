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

	.file	"syscall.s"

#include "SYS.h"

	ANSI_PRAGMA_WEAK(syscall,function)

	ENTRY(syscall)
	pushq	%rbp
	movq	%rsp, %rbp
	/* construct a new call stack frame */
	movl	%edi, %eax	/* sysnum */
	movq	%rsi, %rdi	/* arg0 */
	movq	%rdx, %rsi	/* arg1 */
	movq	%rcx, %rdx	/* arg2 */
	movq	%r8, %rcx	/* arg3 */
	movq	%r9, %r8	/* arg4 */
	movq	16(%rbp), %r9	/* arg5 */
	movq	32(%rbp), %r10
	pushq	%r10		/* arg7 */
	movq	24(%rbp), %r10
	pushq	%r10		/* arg6 */
	movq	8(%rbp), %r10
	pushq	%r10		/* return addr */
	/* issue the system call */
	movq	%rcx, %r10
	syscall
	/* restore the stack frame */
	leave
	SYSCERROR
	ret
	SET_SIZE(syscall)

/*
 * Same as _syscall(), but restricted to 6 syscall arguments
 * so it doesn't need to incur the overhead of a new call stack frame.
 * Implemented for use only within libc; symbol is not exported.
 */
	ENTRY(_syscall6)
	movl	%edi, %eax	/* sysnum */
	movq	%rsi, %rdi	/* arg0 */
	movq	%rdx, %rsi	/* arg1 */
	movq	%rcx, %rdx	/* arg2 */
	movq	%r8, %rcx	/* arg3 */
	movq	%r9, %r8	/* arg4 */
	movq	8(%rsp), %r9	/* arg5 */
	movq	%rcx, %r10
	syscall
	SYSCERROR
	ret
	SET_SIZE(_syscall6)

	ENTRY(__systemcall)
	pushq	%rbp
	movq	%rsp, %rbp
	/* construct a new call stack frame */
	pushq	%rdi		/* sysret_t pointer */
	movl	%esi, %eax	/* sysnum */
	movq	%rdx, %rdi	/* arg0 */
	movq	%rcx, %rsi	/* arg1 */
	movq	%r8, %rdx	/* arg2 */
	movq	%r9, %rcx	/* arg3 */
	movq	16(%rbp), %r8	/* arg4 */
	movq	24(%rbp), %r9	/* arg5 */
	movq	40(%rbp), %r10
	pushq	%r10		/* arg7 */
	movq	32(%rbp), %r10
	pushq	%r10		/* arg6 */
	movq	8(%rbp), %r10
	pushq	%r10		/* return addr */
	/* issue the system call */
	movq	%rcx, %r10
	syscall
	movq	-8(%rbp), %r10	/* sysret_t pointer */
	jb	1f
	movq	%rax, 0(%r10)	/* no error */
	movq	%rdx, 8(%r10)
	xorq	%rax, %rax
	/* restore the stack frame */
	leave
	ret
1:
	movq	$-1, 0(%r10)	/* error */
	movq	$-1, 8(%r10)
	/* restore the stack frame */
	leave
	ret
	SET_SIZE(__systemcall)

/*
 * Same as __systemcall(), but restricted to 6 syscall arguments
 * so it doesn't need to incur the overhead of a new call stack frame.
 * Implemented for use only within libc; symbol is not exported.
 */
	ENTRY(__systemcall6)
	pushq	%rdi		/* sysret_t pointer */
	movl	%esi, %eax	/* sysnum */
	movq	%rdx, %rdi	/* arg0 */
	movq	%rcx, %rsi	/* arg1 */
	movq	%r8, %rdx	/* arg2 */
	movq	%r9, %rcx	/* arg3 */
	movq	16(%rsp), %r8	/* arg4 */
	movq	24(%rsp), %r9	/* arg5 */
	/* issue the system call */
	movq	%rcx, %r10
	syscall
	popq	%r10		/* sysret_t pointer */
	jb	1f
	movq	%rax, 0(%r10)	/* no error */
	movq	%rdx, 8(%r10)
	xorq	%rax, %rax
	ret
1:
	movq	$-1, 0(%r10)	/* error */
	movq	$-1, 8(%r10)
	ret
	SET_SIZE(__systemcall6)
