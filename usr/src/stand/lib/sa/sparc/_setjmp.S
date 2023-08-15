/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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

#ident	"%Z%%M%	%I%	%E% SMI"

#if defined(lint)

typedef long *jmp_buf_ptr;

#else	/* lint */

#include <sys/asm_linkage.h>

#endif	/* lint */

/*
 * _setjmp(buf_ptr)
 * buf_ptr points to a five word array (jmp_buf). In the first is our
 * return address, the second, is the callers SP.
 * The rest is cleared by _setjmp
 *
 *		+----------------+
 *   %i0->	|      pc        |
 *		+----------------+
 *		|      sp        |
 *		+----------------+
 *		|    sigmask     |
 *		+----------------+
 *		|   stagstack    |
 *		|   structure    |
 *		+----------------+
 */

#if defined(lint)

/* ARGSUSED */
int
_setjmp(jmp_buf_ptr buf_ptr)
{ return (0); }

#else	/* lint */

	PCVAL	=	0	! offsets in buf structure
	SPVAL	=	4
	SIGMASK	=	8
	SIGSTACK =	12

	SS_SP	   =	0	! offset in sigstack structure
	SS_ONSTACK =	4

	ENTRY(_setjmp)
	st	%o7, [%o0 + PCVAL] 	! return pc
	st	%sp, [%o0 + SPVAL] 	! save caller's sp
	clr	[%o0 + SIGMASK]		! clear the remainder of the jmp_buf
	clr	[%o0 + SIGSTACK + SS_SP]
	clr	[%o0 + SIGSTACK + SS_ONSTACK]
	retl
	clr	%o0
	SET_SIZE(_setjmp)

#endif	/* lint */

/*
 * _longjmp(buf_ptr, val)
 * buf_ptr points to an array which has been initialized by _setjmp.
 * val is the value we wish to return to _setjmp's caller
 *
 * We will flush our registers by doing (nwindows-1) save instructions.
 * This could be better done as a kernel call. This is necessary to
 * ensure that the registers we want to pick up are stored in the stack.
 * Then, we set fp from the saved fp and make ourselves a stack frame.
 */

#if defined(lint)

/* ARGSUSED */
void
_longjmp(jmp_buf_ptr buf_ptr, int val)
{
	return;
}

#else	/* lint */

	ENTRY(_longjmp)
	save	%sp, -WINDOWSIZE, %sp
	!
	! flush all register windows to the stack.
	!
	set	nwindows, %g7
	ld	[%g7], %g7
	sub	%g7, 2, %g6
1:
	deccc	%g6			! all windows done?
	bnz	1b
	save	%sp, -WINDOWSIZE, %sp
	sub	%g7, 2, %g6
2:
	deccc	%g6			! all windows done?
	bnz	2b
	restore				! delay slot, increment CWP

	ld	[%i0 + SPVAL], %fp	! build new stack frame
	sub	%fp, -SA(MINFRAME), %sp	! establish new save area
	ld	[%i0 + PCVAL], %i7	! get new return pc
	ret
	restore	%i1, 0, %o0		! return (val)
	SET_SIZE(_longjmp)

#endif	/* lint */
