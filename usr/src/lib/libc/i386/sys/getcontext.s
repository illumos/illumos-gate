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

	.file	"getcontext.s"

#include <sys/asm_linkage.h>

	ANSI_PRAGMA_WEAK(getcontext,function)
	ANSI_PRAGMA_WEAK(swapcontext,function)

#include "SYS.h"
#include <assym.h>

/*
 * getcontext() and swapcontext() are written in assembler since it has to
 * capture the correct machine state of the caller, including
 * the registers: %edi, %esi and %ebx.
 *
 * As swapcontext() is actually equivalent to getcontext() + setcontext(),
 * swapcontext() shares the most code with getcontext().
 */


#define	GETCONTEXT_IMPL							\
	movl	4(%esp), %eax;		/* %eax <-- first arg: ucp */	\
	pushl	%eax;			/* push ucp for system call */	\
	call	__getcontext;		/* call getcontext: syscall */	\
	addl	$4, %esp;		/* pop arg */			\
	andl	%eax, %eax;		/* if (err_ret_from_syscall) */	\
	je	1f;							\
	ret;				/*	then return */		\
1:									\
	movl	4(%esp), %eax;		/* recompute first arg */	\
	/*								\
	 * fix up %esp and %eip						\
	 */								\
	leal	UC_MCONTEXT_GREGS (%eax), %edx;				\
				/* %edx <-- &ucp->uc_mcontext.gregs */	\
	movl	0(%esp), %eax;	/* read return PC from stack */		\
	movl	%eax, EIP_OFF (%edx);					\
				/* store ret PC in EIP of env var */	\
	leal	4(%esp), %eax;	/* get caller's sp at time of call */	\
	movl	%eax, UESP_OFF (%edx);					\
				/* store the sp into UESP of env var */	\
	xorl	%eax, %eax;	/* return 0 */				\
	movl	%eax, EAX_OFF (%edx);					\
				/* getcontext returns 0 after a setcontext */

/*
 * getcontext(ucontext_t *ucp)
 */
	ENTRY(getcontext)
	GETCONTEXT_IMPL
	ret
	SET_SIZE(getcontext)


/*
 * swapcontext(ucontext_t *oucp, const ucontext_t *ucp)
 */
	ENTRY(swapcontext)
	GETCONTEXT_IMPL
	/ call setcontext
	movl	8(%esp), %eax		/* %eax <-- second arg: ucp */
	pushl	%eax			/* push ucp for setcontext */
	call	setcontext
	addl	$4, %esp		/* pop arg: just in case */
	ret
	SET_SIZE(swapcontext)
