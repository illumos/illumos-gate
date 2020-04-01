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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/asm_linkage.h>
#include <sys/privregs.h>
#include <sys/scb.h>
#include <sys/machparam.h>
#include <sys/machthread.h>

#include "assym.h"

/*
 * void
 * reestablish_curthread(void)
 *    - reestablishes the invariant that THREAD_REG contains
 *      the same value as the cpu struct for this cpu (implicit from
 *      where we're running). This is needed for OBP callback routines.
 *	The CPU_ADDR macro figures out the cpuid by reading hardware registers.
 */

	ENTRY_NP(reestablish_curthread)

	CPU_ADDR(%o0, %o1)
	retl
	ldn	[%o0 + CPU_THREAD], THREAD_REG
	SET_SIZE(reestablish_curthread)


/*
 * Return the current THREAD pointer.
 * This is also available as an inline function.
 */

	ENTRY_NP(threadp)
	retl
	mov	THREAD_REG, %o0
	SET_SIZE(threadp)


/*
 * The IEEE 1275-1994 callback handler for a 64-bit SPARC V9 PROM calling
 * a 32 bit client program. The PROM calls us with a 64 bit stack and a
 * pointer to a client interface argument array in %o0.  The called code
 * returns 0 if the call succeeded (i.e. the service name exists) or -1
 * if the call failed. NOTE: All addresses are in the range 0..2^^32-1
 *
 * This code is called as trusted subroutine of the firmware, and is
 * called with %tba pointing to the boot firmware's trap table.  All of
 * the prom's window handlers are mixed mode handlers.
 */

	ENTRY_NP(callback_handler)
	!
	! We assume we are called with a 64 bit stack with PSTATE_AM clear
	!
	save	%sp, -SA64(MINFRAME64), %sp	! 64 bit save
	rdpr	%wstate, %l5			! save %wstate
	andn	%l5, WSTATE_MASK, %l6
	wrpr	%l6, WSTATE_KMIX, %wstate
	rdpr	%pstate, %l0			! save %pstate

	!
	! If anybody tries to trace the call stack of this callback
	! then the traceback should stop here.  This matters
	! particularly for sync callbacks on Serengeti, but it's a
	! good idea generally.
	!
	flushw
	mov	%fp, %l1
	clr	%fp				! terminate stack traces

	call	vx_handler			! vx_handler(void **arg_array)
	  mov	%i0, %o0			! delay; argument array
	sra	%o0, 0, %i0			! sign extend result

	mov	%l1, %fp			! restore %fp for return

1:	wrpr	%g0, %l0, %pstate		! restore %pstate
	wrpr	%g0, %l5, %wstate		! restore %wstate

	ret					! return result in %o0
	restore					! back to a 64 bit stack
	SET_SIZE(callback_handler)

