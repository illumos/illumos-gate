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

	.file	"_stack_grow.s"

/*
 * void *
 * _stack_grow(void *addr)
 * {
 *	uintptr_t base = (uintptr_t)curthread->ul_ustack.ss_sp;
 *	size_t size = curthread->ul_ustack.ss_size;
 *
 *	if (size > (uintptr_t)addr - base)
 *		return (addr);
 *
 *	if (size == 0)
 *		return (addr);
 *
 *	if (size > %sp - base)
 *		%sp = base - STACK_ALIGN;
 *
 *	*((char *)(base - 1));
 *
 *	_lwp_kill(_lwp_self(), SIGSEGV);
 * }
 */

#include "SYS.h"
#include <assym.h>

	ENTRY(_stack_grow)
	movl	4(%esp), %eax
	movl	%gs:UL_USTACK+SS_SP, %ecx
	movl	%gs:UL_USTACK+SS_SIZE, %edx
	movl	%eax, %ebx
	subl	%ecx, %ebx
	cmpl	%edx, %ebx
	jae	1f
	ret
1:
	/
	/ If the stack size is 0, stack checking is disabled.
	/
	cmpl	$0, %edx
	jne	2f
	ret
2:
	/
	/ Move the stack pointer outside the stack bounds if it isn't already.
	/
	movl	%esp, %ebx
	subl	%ecx, %ebx
	cmpl	%edx, %ebx
	jae	3f
	pushl	%ebp
	movl	%esp, %ebp
	movl	%ecx, %esp
	subl	$STACK_ALIGN, %esp
3:
	/
	/ Dereference an address in the guard page.
	/
	movb	-1(%ecx), %bl

	/
	/ If the above load doesn't raise a SIGSEGV then do it ourselves.
	/
	SYSTRAP_RVAL1(lwp_self)
	pushl	$SIGSEGV
	pushl	%eax
	pushl	$0
	SYSTRAP_RVAL1(lwp_kill)
	addl	$12, %esp

	/
	/ Try one last time to take out the process.
	/
	movl	0x0, %eax
	SET_SIZE(_stack_grow)
