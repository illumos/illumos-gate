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

/
/ Inline functions for the x64 kernel running on the hypervisor
/

	.inline	__hypercall0, 0
	movq	%rdi, %rax
	syscall
	.end

	.inline	__hypercall1, 0
	movq	%rdi, %rax
	movq	%rsi, %rdi		/ arg 1 
	syscall
	.end

	.inline	__hypercall2, 0
	movq	%rdi, %rax
	movq	%rsi, %rdi		/ arg 1
	movq	%rdx, %rsi		/ arg 2
	syscall
	.end

	.inline	__hypercall3, 0
	movq	%rdi, %rax
	movq	%rsi, %rdi		/ arg 1
	movq	%rdx, %rsi		/ arg 2
	movq	%rcx, %rdx		/ arg 3
	syscall
	.end

/*  XXPV studio bug  r10 is changed to eax by compiler */
	.inline	__hypercall4_broken, 0
	movq	%rdi, %rax
	movq	%rsi, %rdi		/ arg 1
	movq	%rdx, %rsi		/ arg 2
	movq	%rcx, %rdx		/ arg 3
	movq	%r8, %r10		/ r10 = 4th arg
	syscall
	.end

	.inline	__hypercall5_broken, 0
	movq	%rdi, %rax
	movq	%rsi, %rdi		/ arg 1
	movq	%rdx, %rsi		/ arg 2
	movq	%rcx, %rdx		/ arg 3
	movq	%r8, %r10		/ r10 = 4th arg
	movq	%r9, %r8		/ arg 5
	syscall
	.end

/*
 * Read the -real- TSC.
 * This is difficult to virtualize on the hypervisor given there is
 * no way to prevent preemption; thus this inline function
 * should only be used in the middle of the paravirtualized
 * implementation of tsc_read.
 */
	.inline	__rdtsc_insn, 0
	rdtsc
	shlq	$32, %rdx
	orq	%rdx, %rax
	.end

/
/ prefetch 64 bytes
/
	.inline	prefetch64,8
	prefetcht0 (%rdi)
	prefetcht0 32(%rdi)
	.end

