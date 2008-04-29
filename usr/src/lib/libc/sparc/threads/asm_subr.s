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

	.file	"asm_subr.s"

#include <sys/asm_linkage.h>
#include <sys/trap.h>
#include <../assym.h>
#include "SYS.h"

	! This is where execution resumes when a thread created with
	! thr_create() or pthread_create() returns (see setup_context()).
	! We pass the (void *) return value to _thr_terminate().
	ENTRY(_lwp_start)
	nop	! this is the location from which the func() was "called"
	nop
	call	_thr_terminate	! %o0 contains the return value
	nop
	SET_SIZE(_lwp_start)

	ENTRY(_lwp_terminate)
	! Flush the register windows so the stack can be reused.
	ta	ST_FLUSH_WINDOWS
	! All we need to do now is (carefully) call lwp_exit().
	mov	SYS_lwp_exit, %g1
	ta	SYSCALL_TRAPNUM
	RET		! if we return, it is very bad
	SET_SIZE(_lwp_terminate)

	ENTRY(set_curthread)
	retl
	mov	%o0, %g7
	SET_SIZE(set_curthread)

#ifdef __sparcv9
#define	GREGSIZE	8
#else
#define	GREGSIZE	4
#endif
	! void _fetch_globals(greg_t *);
	! (called from siglongjmp())
	ENTRY(_fetch_globals)
	stn	%g1, [%o0 + 0*GREGSIZE]
	stn	%g2, [%o0 + 1*GREGSIZE]
	stn	%g3, [%o0 + 2*GREGSIZE]
	stn	%g4, [%o0 + 3*GREGSIZE]
	stn	%g5, [%o0 + 4*GREGSIZE]
	stn	%g6, [%o0 + 5*GREGSIZE]
	retl
	stn	%g7, [%o0 + 6*GREGSIZE]
	SET_SIZE(_fetch_globals)

#ifdef __sparcv9
	ENTRY(_getfprs)
	retl
	mov	%fprs, %o0
	SET_SIZE(_getfprs)
#else
	ENTRY(_getpsr)
	retl
	ta	ST_GETPSR
	SET_SIZE(_getpsr)
#endif

	ENTRY(_getfsr)
	retl
	stn	%fsr, [%o0]
	SET_SIZE(_getfsr)

	ENTRY(_setfsr)
	retl
	ldn	[%o0], %fsr
	SET_SIZE(_setfsr)

	ENTRY(_flush_windows)
	retl
	ta	ST_FLUSH_WINDOWS
	SET_SIZE(_flush_windows)

	ENTRY(__lwp_park)
	mov	%o1, %o2
	mov	%o0, %o1
	mov	0, %o0
	SYSTRAP_RVAL1(lwp_park)
	SYSLWPERR
	RET
	SET_SIZE(__lwp_park)

	ENTRY(__lwp_unpark)
	mov	%o0, %o1
	mov	1, %o0
	SYSTRAP_RVAL1(lwp_park)
	SYSLWPERR
	RET
	SET_SIZE(__lwp_unpark)

	ENTRY(__lwp_unpark_all)
	mov	%o1, %o2
	mov	%o0, %o1
	mov	2, %o0
	SYSTRAP_RVAL1(lwp_park)
	SYSLWPERR
	RET
	SET_SIZE(__lwp_unpark_all)

/*
 * __sighndlr(int sig, siginfo_t *si, ucontex_t *uc, void (*hndlr)())
 *
 * This is called from sigacthandler() for the entire purpose of
 * communicating the ucontext to java's stack tracing functions.
 */
	ENTRY(__sighndlr)
	.globl	__sighndlrend
	save	%sp, -SA(MINFRAME), %sp
	mov	%i0, %o0
	mov	%i1, %o1
	jmpl	%i3, %o7
	mov	%i2, %o2
	ret
	restore
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

	ENTRY2(sigsetjmp,_sigsetjmp)
	stn	%sp, [%o0 + SJS_SP]	! save caller's sp into env->sjs_sp
	add	%o7, 8, %o2		! calculate caller's return pc
	stn	%o2, [%o0 + SJS_PC]	! save caller's pc into env->sjs_pc
	stn	%fp, [%o0 + SJS_FP]	! save caller's return linkage
	stn	%i7, [%o0 + SJS_I7]
	call	__csigsetjmp
	sub	%o2, 8, %o7		! __csigsetjmp returns to caller
	SET_SIZE(sigsetjmp)
	SET_SIZE(_sigsetjmp)
