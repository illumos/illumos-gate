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

#include "SYS.h"
#include <sys/door.h>

	/*
	 * weak aliases for public interfaces
	 */
	ANSI_PRAGMA_WEAK2(door_bind,__door_bind,function)
	ANSI_PRAGMA_WEAK2(door_getparam,__door_getparam,function)
	ANSI_PRAGMA_WEAK2(door_info,__door_info,function)
	ANSI_PRAGMA_WEAK2(door_revoke,__door_revoke,function)
	ANSI_PRAGMA_WEAK2(door_setparam,__door_setparam,function)
	ANSI_PRAGMA_WEAK2(door_unbind,__door_unbind,function)

/*
 * Offsets within struct door_results
 */
#define	DOOR_COOKIE	(SA(MINFRAME) + STACK_BIAS + 0*CLONGSIZE)
#define	DOOR_DATA_PTR	(SA(MINFRAME) + STACK_BIAS + 1*CLONGSIZE)
#define	DOOR_DATA_SIZE	(SA(MINFRAME) + STACK_BIAS + 2*CLONGSIZE)
#define	DOOR_DESC_PTR	(SA(MINFRAME) + STACK_BIAS + 3*CLONGSIZE)
#define	DOOR_DESC_SIZE	(SA(MINFRAME) + STACK_BIAS + 4*CLONGSIZE)
#define	DOOR_PC		(SA(MINFRAME) + STACK_BIAS + 5*CLONGSIZE)
#define	DOOR_SERVERS	(SA(MINFRAME) + STACK_BIAS + 6*CLONGSIZE)
#define	DOOR_INFO_PTR	(SA(MINFRAME) + STACK_BIAS + 7*CLONGSIZE)

/*
 * All of the syscalls except door_return() follow the same pattern.  The
 * subcode goes in %o5, after all of the other arguments.
 */
#define	DOOR_SYSCALL(name, code)					\
	ENTRY(name);							\
	mov	code, %o5;		/* subcode */			\
	SYSTRAP_RVAL1(door);						\
	SYSCERROR;							\
	RET;								\
	SET_SIZE(name)

	DOOR_SYSCALL(__door_bind,	DOOR_BIND)
	DOOR_SYSCALL(__door_call,	DOOR_CALL)
	DOOR_SYSCALL(__door_create,	DOOR_CREATE)
	DOOR_SYSCALL(__door_getparam,	DOOR_GETPARAM)
	DOOR_SYSCALL(__door_info,	DOOR_INFO)
	DOOR_SYSCALL(__door_revoke,	DOOR_REVOKE)
	DOOR_SYSCALL(__door_setparam,	DOOR_SETPARAM)
	DOOR_SYSCALL(__door_ucred,	DOOR_UCRED)
	DOOR_SYSCALL(__door_unbind,	DOOR_UNBIND)
	DOOR_SYSCALL(__door_unref,	DOOR_UNREFSYS)

/*
 * int
 * __door_return(
 *	void 			*data_ptr,
 *	size_t			data_size,	(in bytes)
 *	door_return_desc_t	*door_ptr,	(holds returned desc info)
 *	caddr_t			stack_base,
 *	size_t			stack_size)
 */
	ENTRY(__door_return)
door_restart:
	mov	DOOR_RETURN, %o5	/* subcode */
	SYSTRAP_RVAL1(door)
	bcs,pn	%icc, 2f			/* errno is set */
	ld	[%sp + DOOR_SERVERS], %g1	/* (delay) load nservers */
	/*
	 * On return, we're serving a door_call.  Our stack looks like this:
	 *
	 *		descriptors (if any)
	 *		data (if any)
	 *		struct door_results
	 *		MINFRAME
	 *	sp ->
	 */
	tst	%g1				/* test nservers */
	bg	1f				/* everything looks o.k. */
	ldn	[%sp + DOOR_COOKIE], %o0	/* (delay) load cookie */
	/*
	 * this is the last server thread - call creation func for more
	 */
	save	%sp, -SA(MINFRAME), %sp
	PIC_SETUP(g1)
#ifdef __sparcv9
	sethi	%hi(door_server_func), %g5
	or	%g5, %lo(door_server_func), %g5
	ldn	[%g5 + %g1], %g1
#else
	ldn	[%g1 + door_server_func], %g1
#endif
	ldn	[%g1], %g1
	jmpl	%g1, %o7			/* call create function */
	ldn	[%fp + DOOR_INFO_PTR], %o0	/* (delay) load door_info ptr */
	restore
1:
	/* Call the door server function now */
	ldn	[%sp + DOOR_DATA_PTR], %o1
	ldn	[%sp + DOOR_DATA_SIZE], %o2
	ldn	[%sp + DOOR_DESC_PTR], %o3
	ldn	[%sp + DOOR_PC], %g1
	jmpl	%g1, %o7
	ldn	[%sp + DOOR_DESC_SIZE], %o4

	/* Exit the thread if we return here */
	call	_thrp_terminate
	mov	%g0, %o0
	/* NOTREACHED */
2:
	/*
	 * Error during door_return call.  Repark the thread in the kernel if
	 * the error code is EINTR (or ERESTART) and this lwp is still part
	 * of the same process.
	 */
	cmp	%o0, ERESTART		/* ERESTART is same as EINTR */
	be,a	3f
	mov	EINTR, %o0
3:
	cmp	%o0, EINTR		/* interrupted while waiting? */
	bne	__cerror		/* if not, return the error */
	nop

	save	%sp, -SA(MINFRAME), %sp
	call	getpid
	nop
	PIC_SETUP(g1)
#ifdef __sparcv9
	sethi	%hi(door_create_pid), %g5
	or	%g5, %lo(door_create_pid), %g5
	ldn	[%g1 + %g5], %g1
#else
	ldn	[%g1 + door_create_pid], %g1
#endif
	ld	[%g1], %g1
	cmp	%o0, %g1		/* same process? */
	mov	EINTR, %o0	/* if no, return EINTR (child of forkall) */
	bne	__cerror
	restore

	clr	%o0			/* clear arguments and restart */
	clr	%o1
	ba	door_restart
	clr	%o2
	SET_SIZE(__door_return)
