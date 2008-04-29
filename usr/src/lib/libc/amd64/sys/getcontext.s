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

#include <sys/asm_linkage.h>

	ANSI_PRAGMA_WEAK(getcontext,function)
	ANSI_PRAGMA_WEAK(swapcontext,function)

#include "SYS.h"
#include <../assym.h>

/*
 * getcontext() is written in assembler since it has to capture the correct
 * machine state of the calle.
 *
 * As swapcontext() is actually equivalent to getcontext() + setcontext(),
 * swapcontext() shares the most code with getcontext().
 */

#define	GETCONTEXT_IMPL(offset)						\
	pushq	%rdi;		/* preserve the ucontext_t pointer */	\
	call	__getcontext;						\
				/* call getcontext: syscall */		\
	popq	%rdx;							\
	andl	%eax, %eax;	/* if (error_return_from_syscall) */	\
	je	1f;							\
	addq	$offset, %rsp;						\
	ret;			/*	then just return */		\
1:									\
	/*								\
	 * fix up %rsp and %rip						\
	 */								\
	addq	$UC_MCONTEXT_GREGS, %rdx;				\
				/* &ucp->uc_mcontext.gregs */		\
	movq	offset+0(%rsp), %rax;					\
				/* read return PC from stack */		\
	movq	%rax, RIP_OFF (%rdx);					\
				/* store ret PC in EIP of env var */	\
	leaq	offset+8(%rsp), %rax;					\
				/* get caller's sp at time of call */	\
	movq	%rax, RSP_OFF (%rdx);					\
				/* store the sp into UESP of env var */	\
	xorq	%rax, %rax;	/* return 0 */				\
	movq	%rax, RAX_OFF (%rdx);					\
				/* getcontext returns 0 after setcontext */

/*	
 * getcontext(ucontext_t *ucp)
 */

	ENTRY(getcontext)
	GETCONTEXT_IMPL(0)
	ret
	SET_SIZE(getcontext)

/*
 * swapcontext(ucontext_t *oucp, const ucontext_t *ucp)
 */

	ENTRY(swapcontext)
	pushq	%rsi			/* preserve the 2nd argument */
	
	GETCONTEXT_IMPL(8)

	/* call setcontext */
	popq	%rdi
	call	setcontext
	ret
	SET_SIZE(swapcontext)
