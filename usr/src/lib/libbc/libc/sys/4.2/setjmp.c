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
/*	Copyright (c) 1988 AT&T */
/*	All Rights Reserved   */


/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <sys/setjmp.h>
#include "../common/ucontext.h"

int _getsp();

int
setjmp(env)
	jmp_buf env;
{
	register o_setjmp_struct_t *bp = (o_setjmp_struct_t *)env;
	register int sp = _getsp();
	ucontext_t uc;

	/*
	 * Get the current machine context.
	 */
	uc.uc_flags = UC_STACK | UC_SIGMASK;
	__getcontext(&uc);

	/*
	 * Note that the pc and former sp (fp) from the stack are valid
	 * because the call to __getcontext must flush the user windows
	 * to the stack.
	 */
	bp->sjs_flags = 0;
	bp->sjs_sp    = *((int *)sp+14);
	bp->sjs_pc    = *((int *)sp+15) + 0x8;
	bp->sjs_stack = uc.uc_stack;

	/* save the mask */
	bp->sjs_flags |= JB_SAVEMASK;
	memcpy(bp->sjs_sigmask, &(uc.uc_sigmask), 3 * sizeof (int));

	return (0);
}



void
longjmp(env, val)
	jmp_buf env;
	int val;
{
	o_setjmp_struct_t *bp = (o_setjmp_struct_t *)env;
	setjmp_struct_t sjmp, *sp;

	sp = &sjmp;
	sp->sjs_flags = bp->sjs_flags;
	sp->sjs_sp = bp->sjs_sp;
	sp->sjs_pc = bp->sjs_pc;
	sp->sjs_fp = 0;
	sp->sjs_i7 = 0;
	sp->sjs_uclink = 0;
	sp->sjs_sigmask[0] = bp->sjs_sigmask[0];
	sp->sjs_sigmask[1] = bp->sjs_sigmask[1];
	sp->sjs_sigmask[2] = bp->sjs_sigmask[2];
	sp->sjs_sigmask[3] = 0;
	sp->sjs_stack = bp->sjs_stack;
	_siglongjmp(sjmp, val);
}
