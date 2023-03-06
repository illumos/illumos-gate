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

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * C library -- long syscall(int sysnum, ...);
 * C library -- long __systemcall(sysret_t *, int sysnum, ...);
 *
 * Interpret a given system call
 *
 * This version handles up to 8 'long' arguments to a system call.
 *
 * Even though indirect system call support exists in the SPARC
 * 32-bit kernel, we want to eliminate it in a future release,
 * so the real trap for the desired system call is issued right here.
 *
 * Even though %g5 can be used as a scratch register for sparcv9, we don't
 * use it here because this code is shared between sparcv8 and sparcv9.
 */

	.file	"syscall.s"

#include "SYS.h"

	ANSI_PRAGMA_WEAK(syscall,function)

	ENTRY(syscall)
	save	%sp, -SA(MINFRAME + 2*CLONGSIZE), %sp
	ldn	[%fp + STACK_BIAS + MINFRAME], %o5	! arg 5
	mov	%i3, %o2				! arg 2
	ldn	[%fp + STACK_BIAS + MINFRAME + CLONGSIZE], %g1
	mov	%i4, %o3				! arg 3
	stn	%g1, [%sp + STACK_BIAS + MINFRAME]	! arg 6
	mov	%i5, %o4				! arg 4
	ldn	[%fp + STACK_BIAS + MINFRAME + 2*CLONGSIZE], %g1
	mov	%i1, %o0				! arg 0
	stn	%g1, [%sp + STACK_BIAS + MINFRAME + CLONGSIZE] ! arg 7
	mov	%i2, %o1				! arg 1
	mov	%i0, %g1				! sysnum
	ta	SYSCALL_TRAPNUM
	bcc,a,pt %icc, 1f
	  sra	%o0, 0, %i0				! (int) cast
	restore	%o0, 0, %o0
	ba	__cerror
	  nop
1:
	ret
	  restore
	SET_SIZE(syscall)

/*
 * Same as _syscall(), but restricted to 6 syscall arguments
 * so it doesn't need to incur the overhead of a register window.
 * Implemented for use only within libc; symbol is not exported.
 */
	ENTRY(_syscall6)
	mov	%o0, %g1			/* sysnum */
	mov	%o1, %o0			/* syscall args */
	mov	%o2, %o1
	mov	%o3, %o2
	mov	%o4, %o3
	mov	%o5, %o4
	ldn	[%sp + STACK_BIAS + MINFRAME], %o5
	ta	SYSCALL_TRAPNUM
	SYSCERROR
	retl
	  sra	%o0, 0, %o0			/* (int) cast */
	SET_SIZE(_syscall6)

	ENTRY(__systemcall)
	save	%sp, -SA(MINFRAME + 2*CLONGSIZE), %sp
	ldn	[%fp + STACK_BIAS + MINFRAME], %o4	! arg 4
	mov	%i3, %o1				! arg 1
	ldn	[%fp + STACK_BIAS + MINFRAME + CLONGSIZE], %o5 ! arg5
	mov	%i4, %o2				! arg 2
	ldn	[%fp + STACK_BIAS + MINFRAME + 2*CLONGSIZE], %g1
	mov	%i5, %o3				! arg 3
	stn	%g1, [%sp + STACK_BIAS + MINFRAME]	! arg 6
	mov	%i2, %o0				! arg 0
	ldn	[%fp + STACK_BIAS + MINFRAME + 3*CLONGSIZE], %g1
	stn	%g1, [%sp + STACK_BIAS + MINFRAME + CLONGSIZE] ! arg7
	mov	%i1, %g1				! sysnum
	ta	SYSCALL_TRAPNUM
	bcc,pt	%icc, 1f
	  mov	-1, %g1
	stn	%g1, [%i0]	/* error */
	ba	2f
	  stn	%g1, [%i0 + CLONGSIZE]
1:
	stn	%o0, [%i0]	/* no error */
	clr	%o0
	stn	%o1, [%i0 + CLONGSIZE]
2:
	ret
	  restore %o0, 0, %o0
	SET_SIZE(__systemcall)

/*
 * Same as __systemcall(), but restricted to 6 syscall arguments
 * so it doesn't need to incur the overhead of a register window.
 * Implemented for use only within libc; symbol is not exported.
 */
	ENTRY(__systemcall6)
	stn	%o0, [%sp + SAVE_OFFSET]	/* sysret address */
	mov	%o1, %g1			/* sysnum */
	mov	%o2, %o0			/* syscall args */
	mov	%o3, %o1
	mov	%o4, %o2
	mov	%o5, %o3
	ldn	[%sp + STACK_BIAS + MINFRAME], %o4
	ldn	[%sp + STACK_BIAS + MINFRAME + CLONGSIZE], %o5
	ta	SYSCALL_TRAPNUM
	bcs,pn	%icc, 1f
	  ldn	[%sp + SAVE_OFFSET], %g1
	stn	%o0, [%g1]	/* no error */
	stn	%o1, [%g1 + CLONGSIZE]
	retl
	  clr	%o0
1:
	mov	-1, %o1		/* error */
	stn	%o1, [%g1]
	retl
	  stn	%o1, [%g1 + CLONGSIZE]
	SET_SIZE(__systemcall6)
