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
#include <../assym.h>

	ENTRY(_stack_grow)
	movq	%rdi, %rax
	movq	%fs:UL_USTACK+SS_SP, %rcx
	movq	%fs:UL_USTACK+SS_SIZE, %rdx
	movq	%rax, %rbx
	subq	%rcx, %rbx
	cmpq	%rdx, %rbx
	jae	1f
	ret
1:
	/
	/ If the stack size is 0, stack checking is disabled.
	/
	cmpq	$0, %rdx
	jne	2f
	ret
2:
	/
	/ Move the stack pointer outside the stack bounds if it isn't already.
	/
	movq	%rsp, %rbx
	subq	%rcx, %rbx
	cmpq	%rdx, %rbx
	jae	3f
	pushq	%rbp
	movq	%rsp, %rbp
	movq	%rcx, %rsp
	subq	$STACK_ALIGN, %rsp
3:
	/
	/ Dereference an address in the guard page.
	/
	movb	-1(%rcx), %bl

	/
	/ If the above load doesn't raise a SIGSEGV then do it ourselves.
	/
	SYSTRAP_RVAL1(lwp_self)
	movl	$SIGSEGV, %esi
	movl	%eax, %edi
	SYSTRAP_RVAL1(lwp_kill)

	/
	/ Try one last time to take out the process.
	/
	movq	0x0, %rax
	SET_SIZE(_stack_grow)
