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

	.file	"_stack_grow.s"

#include "SYS.h"
#include <../assym.h>

/*
 * void *
 * _stack_grow(void *addr)
 * {
 *	uintptr_t base = (uintptr_t)curthread->ul_ustack.ss_sp;
 *	size_t size = curthread->ul_ustack.ss_size;
 *
 *	if (size > (uintptr_t)addr - (base - STACK_BIAS))
 *		return (addr);
 *
 *	if (size == 0)
 *		return (addr);
 *
 *	if (size > %sp - (base - STACK_BIAS))
 *		%sp = base - STACK_BIAS - STACK_ALIGN;
 *
 *	*((char *)(base - 1));
 *
 *	_lwp_kill(_lwp_self(), SIGSEGV);
 * }
 */

#if defined(__sparcv9)
#define	PN	,pn %xcc,
#else
#define	PN
#endif

	/*
	 * o0: address to which the stack will be grown (biased)
	 */
	ENTRY(_stack_grow)
	ldn	[%g7 + UL_USTACK + SS_SP], %o1
	ldn	[%g7 + UL_USTACK + SS_SIZE], %o2
	sub	%o1, STACK_BIAS, %o3

	sub	%o0, %o3, %o4
	cmp	%o2, %o4
	bleu PN	1f
	tst	%o2

	retl
	nop
1:
	/*
	 * If the stack size is 0, stack checking is disabled.
	 */
	bnz PN	2f
	nop
	retl
	nop
2:
	/*
	 * Move the stack pointer outside the stack bounds if it isn't already.
	 */
	sub	%sp, %o3, %o4
	cmp	%o2, %o4
	bleu PN	3f
	nop
	sub	%o3, STACK_ALIGN, %sp
3:
	/*
	 * Dereference an address in the guard page.
	 */
	ldub	[%o1 - 1], %g0

	/*
	 * If the above load doesn't raise a SIGSEGV then do it ourselves.
	 */
	SYSTRAP_RVAL1(lwp_self)
	mov	SIGSEGV, %o1
	SYSTRAP_RVAL1(lwp_kill)

	/*
	 * We should never get here; explode if we do.
	 */
	illtrap
	SET_SIZE(_stack_grow)
