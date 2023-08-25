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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

	.file	"unwind_frame.s"

#ifdef _LIBCRUN_
#define ENTRY(x) \
        .text; \
        .align  8; \
        .globl  x; \
        .type   x, @function; \
	x:
#define SET_SIZE(x) \
        .size   x, .-x
#else
#include "SYS.h"
#endif

/*
 * ====================
 * _Unw_capture_regs()
 * --------------------
 *
 *	Given  foo()->ex_throw()->_Unwind_RaiseException()->_Unw_capture_regs()
 *	fills in a register array with FP and the preserved registers
 */
	ENTRY(_Unw_capture_regs)
	movq	%rbx,24(%rdi)		/* save preserved registers */
	movq	%rbp,48(%rdi)
	movq	%r12,96(%rdi)
	movq	%r13,104(%rdi)
	movq	%r14,112(%rdi)
	movq	%r15,120(%rdi)
	ret
	SET_SIZE(_Unw_capture_regs)

/*
 * ====================
 * _Unw_jmp
 * --------------------
 *
 * _Unw_jmp is passed a pc and an array of register values.
 */

	ENTRY(_Unw_jmp)
	movq	%rdi,%r8		/* save arguments to this func */
	movq	%rsi,%rax
	movq	40(%rax),%rdi		/* set handler parameters */
	movq	32(%rax),%rsi
	movq	8(%rax),%rdx
	movq	16(%rax),%rcx
	movq	24(%rax),%rbx		/* restore preserved registers */
	movq	96(%rax),%r12
	movq	104(%rax),%r13
	movq	112(%rax),%r14
	movq	120(%rax),%r15
	movq	48(%rax),%rbp
	movq	56(%rax),%rsp
	movq	(%rax),%rax
	jmp	*%r8			/* branch to handler */
	SET_SIZE(_Unw_jmp)
