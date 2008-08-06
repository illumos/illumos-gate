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

	.file	"asm_subr.s"

#include <SYS.h>

	/ This is where execution resumes when a thread created with
	/ thr_create() or pthread_create() returns (see setup_context()).
	/ We pass the (void *) return value to _thrp_terminate().
	ENTRY(_lwp_start)
	addl	$4, %esp
	pushl	%eax
	call	_thrp_terminate
	addl	$4, %esp	/ actually, never returns
	SET_SIZE(_lwp_start)

	/ All we need to do now is (carefully) call lwp_exit().
	ENTRY(_lwp_terminate)
	SYSTRAP_RVAL1(lwp_exit)
	RET		/ if we return, it is very bad
	SET_SIZE(_lwp_terminate)

	ENTRY(set_curthread)
	movl	4(%esp), %eax
	movl	%eax, %gs:0
	ret
	SET_SIZE(set_curthread)

	ENTRY(__lwp_park)
	popl	%edx		/ add subcode; save return address
	pushl	$0
	pushl	%edx
	SYSTRAP_RVAL1(lwp_park)
	SYSLWPERR
	popl	%edx		/ restore return address
	movl	%edx, 0(%esp)
	RET
	SET_SIZE(__lwp_park)

	ENTRY(__lwp_unpark)
	popl	%edx		/ add subcode; save return address
	pushl	$1
	pushl	%edx
	SYSTRAP_RVAL1(lwp_park)
	SYSLWPERR
	popl	%edx		/ restore return address
	movl	%edx, 0(%esp)
	RET
	SET_SIZE(__lwp_unpark)

	ENTRY(__lwp_unpark_all)
	popl	%edx		/ add subcode; save return address
	pushl	$2
	pushl	%edx
	SYSTRAP_RVAL1(lwp_park)
	SYSLWPERR
	popl	%edx		/ restore return address
	movl	%edx, 0(%esp)
	RET
	SET_SIZE(__lwp_unpark_all)

/*
 * __sighndlr(int sig, siginfo_t *si, ucontext_t *uc, void (*hndlr)())
 *
 * This is called from sigacthandler() for the entire purpose of
 * communicating the ucontext to java's stack tracing functions.
 */
	ENTRY(__sighndlr)
	.globl	__sighndlrend
	pushl	%ebp
	movl	%esp, %ebp
	pushl	16(%ebp)
	pushl	12(%ebp)
	pushl	8(%ebp)
	call	*20(%ebp)
	addl	$12, %esp
	leave
	ret
__sighndlrend:
	SET_SIZE(__sighndlr)

/*
 * int _sigsetjmp(sigjmp_buf env, int savemask)
 *
 * This version is faster than the old non-threaded version because we
 * don't normally have to call __getcontext() to get the signal mask.
 * (We have a copy of it in the ulwp_t structure.)
 */

#undef	sigsetjmp

	ENTRY2(sigsetjmp,_sigsetjmp)	/ EIP already pushed
	pusha				/ EAX .. EDI
	push	%ds			/ segment registers
	push	%es
	push	%fs
	push	%gs
	push	%ss
	push	%cs
	/ args:  cs, ss, gs, ..., eip, env, savemask
	call	__csigsetjmp
	addl	$56, %esp		/ pop 14 words
	ret
	SET_SIZE(sigsetjmp)
	SET_SIZE(_sigsetjmp)
