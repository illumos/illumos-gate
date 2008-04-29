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

#include <SYS.h>
#include <sys/regset.h>
#include <../assym.h>

	/*
	 * This is where execution resumes when a thread created with
	 * thr_create() or pthread_create() returns (see setup_context()).
	 * We pass the (void *) return value to _thr_terminate().
	 */
	ENTRY(_lwp_start)
	movq	%rax, %rdi
	call	_thr_terminate
	RET		/* actually, never returns */
	SET_SIZE(_lwp_start)

	/* All we need to do now is (carefully) call lwp_exit(). */
	ENTRY(_lwp_terminate)
	SYSTRAP_RVAL1(lwp_exit)
	RET		/* if we return, it is very bad */
	SET_SIZE(_lwp_terminate)

	ENTRY(set_curthread)
	movq	%rdi, %fs:0
	ret
	SET_SIZE(set_curthread)

	ENTRY(__lwp_park)
	movq	%rsi, %rdx
	movq	%rdi, %rsi
	movq	$0, %rdi
	SYSTRAP_RVAL1(lwp_park)
	SYSLWPERR
	RET
	SET_SIZE(__lwp_park)

	ENTRY(__lwp_unpark)
	movq	%rdi, %rsi
	movq	$1, %rdi
	SYSTRAP_RVAL1(lwp_park)
	SYSLWPERR
	RET
	SET_SIZE(__lwp_unpark)

	ENTRY(__lwp_unpark_all)
	movq	%rsi, %rdx
	movq	%rdi, %rsi
	movq	$2, %rdi
	SYSTRAP_RVAL1(lwp_park)
	SYSLWPERR
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
	pushq	%rbp
	movq	%rsp, %rbp
	call	*%rcx
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

#if SIZEOF_SIGJMP_BUF < SIZEOF_UCONTEXT_T

#error "sigjmp_buf is too small to contain a ucontext_t"

#else

#if defined(__GNUC_AS__)
#define	REGOFF(reg)	( reg * CLONGSIZE )
#else
#define	REGOFF(reg)	[ reg \* CLONGSIZE ]
#endif

	ENTRY2(sigsetjmp,_sigsetjmp)
	pushq	%rbp
	movq	%rsp, %rbp

	/* construct a complete gregset_t for __csigsetjmp */
	subq	$REGOFF(_NGREG), %rsp
	movq	%r15,	REGOFF(REG_R15) (%rsp)
	movq	%r14,	REGOFF(REG_R14) (%rsp)
	movq	%r13,	REGOFF(REG_R13) (%rsp)
	movq	%r12,	REGOFF(REG_R12) (%rsp)
	movq	%r11,	REGOFF(REG_R11) (%rsp)
	movq	%r10,	REGOFF(REG_R10) (%rsp)
	movq	%r9,	REGOFF(REG_R9) (%rsp)
	movq	%r8,	REGOFF(REG_R8) (%rsp)
	movq	%rdi,	REGOFF(REG_RDI) (%rsp)
	movq	%rsi,	REGOFF(REG_RSI) (%rsp)
	movq	%rbx,	REGOFF(REG_RBX) (%rsp)
	movq	%rdx,	REGOFF(REG_RDX) (%rsp)
	movq	%rcx,	REGOFF(REG_RCX) (%rsp)
	movq	$0,	REGOFF(REG_RAX) (%rsp)
	movq	$0,	REGOFF(REG_TRAPNO) (%rsp)
	movq	$0,	REGOFF(REG_ERR) (%rsp)
	xorq	%rax, %rax
	movw	%cs, %ax
	movq	%rax,	REGOFF(REG_CS) (%rsp)
	movq	$0,	REGOFF(REG_RFL) (%rsp)
	movw	%ss, %ax
	movq	%rax,	REGOFF(REG_SS) (%rsp)
	movw	%fs, %ax
	movq	%rax,	REGOFF(REG_FS) (%rsp)
	movw	%gs, %ax
	movq	%rax,	REGOFF(REG_GS) (%rsp)
	movw	%es, %ax
	movq	%rax,	REGOFF(REG_ES) (%rsp)
	movw	%ds, %ax
	movq	%rax,	REGOFF(REG_DS) (%rsp)
	movq	%fs:0, %rax
	movq	%rax,	REGOFF(REG_FSBASE) (%rsp)
	movq	$0,	REGOFF(REG_GSBASE) (%rsp)

	movq	(%rbp), %rax		/* previous %rbp */
	movq	%rax,	REGOFF(REG_RBP) (%rsp)
	movq	8(%rbp), %rax		/* previous %rip */
	movq	%rax,	REGOFF(REG_RIP) (%rsp)
	leaq	16(%rbp), %rax		/* previous %rsp */
	movq	%rax,	REGOFF(REG_RSP) (%rsp)

	movq	%rsp, %rdx	/* pointer to gregset_t */
	call	__csigsetjmp
	xorq	%rax, %rax
	leave
	ret
	SET_SIZE(sigsetjmp)
	SET_SIZE(_sigsetjmp)

#endif	/* SIZEOF_SIGJMP_BUF < SIZEOF_UCONTEXT_T */
