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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Context-saving routine used for pipelines.  Designed for use only
 * with kmdb_setcontext, and with the assumption that func() will never
 * return.
 */

#include <strings.h>
#include <ucontext.h>
#include <sys/types.h>
#include <sys/stack.h>

#include <kmdb/kmdb_context_impl.h>
#include <mdb/mdb_kreg.h>

void
kmdb_makecontext(ucontext_t *ucp, void (*func)(void *), void *arg, caddr_t stk,
    size_t stksize)
{
	/*
	 * Top-of-stack must be rounded down to STACK_ALIGN and
	 * there must be a minimum frame for the register window.
	 */
	uintptr_t stack = (((uintptr_t)stk + stksize - 1) &
	    ~(STACK_ALIGN - 1)) - SA(MINFRAME);

	/* clear the top stack frame */
	bzero((void *)stack, SA(MINFRAME));

	/* fill in registers of interest */
	ucp->uc_mcontext.gregs[REG_PC] = (greg_t)func;
	ucp->uc_mcontext.gregs[REG_nPC] = (greg_t)func + 4;
	ucp->uc_mcontext.gregs[REG_O0] = (greg_t)arg;
	ucp->uc_mcontext.gregs[REG_SP] = (greg_t)(stack - STACK_BIAS);
	ucp->uc_mcontext.gregs[REG_O7] = NULL;
	ucp->uc_mcontext.gregs[REG_G7] = NULL;
}
