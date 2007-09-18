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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/
/ Inline functions for the x86 kernel running on the hypervisor
/

	.inline	__hypercall0, 4
	movl	(%esp), %eax
	int	$0x82
	.end

	.inline	__hypercall1, 8
	pushl	%ebx
	movl	4(%esp), %eax
	movl	8(%esp), %ebx
	int	$0x82
	popl	%ebx
	.end

	.inline	__hypercall2, 12
	pushl	%ebx
	movl	4(%esp), %eax
	movl	8(%esp), %ebx
	movl	12(%esp), %ecx
	int	$0x82
	popl	%ebx
	.end

	.inline	__hypercall3, 16
	pushl	%ebx
	movl	4(%esp), %eax
	movl	8(%esp), %ebx
	movl	12(%esp), %ecx
	movl	16(%esp), %edx
	int	$0x82
	popl	%ebx
	.end

	.inline	__hypercall4, 20
	pushl	%ebx
	pushl	%esi
	movl	8(%esp), %eax
	movl	12(%esp), %ebx
	movl	16(%esp), %ecx
	movl	20(%esp), %edx
	movl	24(%esp), %esi
	int	$0x82
	popl	%esi
	popl	%ebx
	.end

	.inline	__hypercall5, 24
	pushl	%ebx
	pushl	%esi
	pushl	%edi
	movl	12(%esp), %eax
	movl	16(%esp), %ebx
	movl	20(%esp), %ecx
	movl	24(%esp), %edx
	movl	28(%esp), %esi
	movl	32(%esp), %edi
	int	$0x82
	popl	%edi
	popl	%esi
	popl	%ebx
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
	.end
