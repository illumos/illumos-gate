/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1992,2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/
/ In-line functions for i86 calls.
/


/
/ in and out
/
	.inline	inb,4
	movl	(%esp), %edx
	xorl    %eax, %eax
	inb	(%dx)
	.end

	.inline	inw,4
	movl	(%esp), %edx
	xorl    %eax, %eax
	inw	(%dx)
	.end

	.inline	inl,4
	movl	(%esp), %edx
	xorl    %eax, %eax
	inl	(%dx)
	.end

	.inline	outb,8
	movl	(%esp), %edx
	movl    4(%esp), %eax
	outb	(%dx)
	.end

	.inline	outw,8
	movl	(%esp), %edx
	movl    4(%esp), %eax
	outw	(%dx)
	.end

	.inline	outl,8
	movl	(%esp), %edx
	movl    4(%esp), %eax
	outl	(%dx)
	.end

/
/ Networking byte order functions (too bad, Intel has the wrong byte order)
/

	.inline	htonl,4
	movl	(%esp), %eax
	bswap	%eax
	.end

	.inline	ntohl,4
	movl	(%esp), %eax
	bswap	%eax
	.end

	.inline	htons,4
	movl	(%esp), %eax
	bswap	%eax
	shrl	$16, %eax
	.end

	.inline	ntohs,4
	movl	(%esp), %eax
	bswap	%eax
	shrl	$16, %eax
	.end

/
/ disable interrupts and return value describing if interrupts were enabled
/
	.inline	clear_int_flag,0
	pushfl
	cli
	popl	%eax
	.end

/
/ restore interrupt enable flag to value returned from 'clear_int_flag' above
/
	.inline restore_int_flag,4
	pushl	(%esp)
	popfl
	.end

/
/ stub function. 
/ i386 arch currently has a unified cache
/
	.inline sync_instruction_memory,8
	nop
	.end
