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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma weak _siglongjmp = siglongjmp

#include "lint.h"
#include <sys/types.h>
#include <sys/stack.h>
#include <sys/frame.h>
#include <memory.h>
#include <ucontext.h>
#include <setjmp.h>
#include "sigjmp_struct.h"
#include "libc.h"

void
siglongjmp(sigjmp_buf env, int val)
{
	extern void _fetch_globals(greg_t *);
	ucontext_t uc;
	greg_t *reg = uc.uc_mcontext.gregs;
	volatile sigjmp_struct_t *bp = (sigjmp_struct_t *)env;
	greg_t fp = bp->sjs_fp;
	greg_t i7 = bp->sjs_i7;

	/*
	 * Create a ucontext_t structure from scratch.
	 * We only need to fetch the globals.
	 * The outs are assumed to be trashed on return from sigsetjmp().
	 * The ins and locals are restored from the resumed register window.
	 * The floating point state is unmodified.
	 * Everything else is in the sigjmp_struct_t buffer.
	 */
	(void) memset(&uc, 0, sizeof (uc));
	uc.uc_flags = UC_STACK | UC_CPU;
	_fetch_globals(&reg[REG_G1]);
	uc.uc_stack = bp->sjs_stack;
	uc.uc_link = bp->sjs_uclink;
	reg[REG_PC] = bp->sjs_pc;
	reg[REG_nPC] = reg[REG_PC] + 0x4;
	reg[REG_SP] = bp->sjs_sp;
	reg[REG_ASI] = bp->sjs_asi;
	reg[REG_FPRS] = bp->sjs_fprs;

	if (bp->sjs_flags & JB_SAVEMASK) {
		uc.uc_flags |= UC_SIGMASK;
		uc.uc_sigmask = bp->sjs_sigmask;
	}

	if (val)
		reg[REG_O0] = (greg_t)val;
	else
		reg[REG_O0] = (greg_t)1;

	/*
	 * Copy the fp and i7 values into the register window save area.
	 * These may have been clobbered between calls to sigsetjmp
	 * and siglongjmp.  For example, the save area could have been
	 * relocated to lower addresses and the original save area
	 * given to an alloca() call.  Notice that all reads from
	 * the sigjmp_struct_t buffer should take place before the
	 * following two writes.  It is possible that user code may
	 * move/copy the sigjmpbuf around, and overlap the original
	 * register window save area.
	 */
	if (bp->sjs_sp != 0 && (bp->sjs_flags & JB_FRAMEPTR)) {
		struct frame *sp = (struct frame *)(bp->sjs_sp + STACK_BIAS);
		sp->fr_savfp = (struct frame *)fp;
		sp->fr_savpc = i7;
	}

	(void) setcontext(&uc);
}
