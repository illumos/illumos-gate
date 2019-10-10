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

#include <sys/asm_linkage.h>
#include <sys/asm_misc.h>
#include "dboot_xboot.h"

#if defined(__amd64)

	ENTRY_NP(_start)
	/*
	 * At entry we are passed a (start_info_t *) in %rsi.
	 */
	movq	%rsi, xen_info(%rip)

	/*
	 * make sure we have sane processor state
	 */
	xorw	%ax, %ax
	movw	%ax, %fs
	movw	%ax, %gs
	pushq	$0
	popfq
	pushq	$0

	/*
	 * go off and unpack the kernel bits, adjust page tables, etc.
	 */
	call	startup_kernel

	/*
	 * we can only setup a stack after startup_kernel().
	 * Its in the lower part of memroy.
	 */
	leaq	stack_space(%rip), %rsp
	addq	$STACK_SIZE, %rsp
	andl	$0xfffffff0, %esp

	pushq	$0x0			/* push a dead-end frame */
	pushq	$0x0
	movq	%rsp, %rbp

	/*
	 * when we get back, load the kernel entry point and jump to it
	 * The address of the xboot_info is the kernel's only argument.
	 */
	movl	entry_addr_low, %esi
	movq	$0xffffffff00000000,%rdx
	orq	%rdx, %rsi		/* set upper bits of entry addr */

        movl    bi, %edi
	call	*%rsi
	SET_SIZE(_start)

#elif defined(__i386)

	ENTRY_NP(_start)
	/*
	 * At entry we are passed a (start_info_t *) in %esi.
	 */
	movl	%esi, xen_info

	/*
	 * make sure we have sane processor state
	 */
	cld
	xorw	%ax, %ax
	movw	%ax, %fs
	movw	%ax, %gs


	/*
	 * go off and unpack the kernel bits, adjust page tables, etc.
	 */
	call	startup_kernel

	/*
	 * we can only setup a stack after startup_kernel().
	 */
	movl	$stack_space, %esp	/* load my stack pointer */
	addl	$STACK_SIZE, %esp

	pushl	$0x0			/* push a dead-end frame */
	pushl	$0x0
	movl	%esp, %ebp

	/*
	 * when we get back, load the kernel entry point and jump to it
	 * The address of the xboot_info is the kernel's only argument.
	 */
	movl	entry_addr_low, %esi
	movl	bi, %eax
	pushl	%eax
	call	*%esi
	SET_SIZE(_start)

#endif	/* __i386 */

