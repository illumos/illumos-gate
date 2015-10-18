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
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#pragma weak _makecontext = makecontext

#include "lint.h"
#include <stdarg.h>
#include <ucontext.h>
#include <sys/stack.h>

/*
 * The ucontext_t that the user passes in must have been primed with a
 * call to getcontext(2), have the uc_stack member set to reflect the
 * stack which this context will use, and have the uc_link member set
 * to the context which should be resumed when this context returns.
 * When makecontext() returns, the ucontext_t will be set to run the
 * given function with the given parameters on the stack specified by
 * uc_stack, and which will return to the ucontext_t specified by uc_link.
 */

static void resumecontext(void);

void
makecontext(ucontext_t *ucp, void (*func)(), int argc, ...)
{
	long *sp;
	long *tsp;
	va_list ap;
	size_t size;

	ucp->uc_mcontext.gregs[EIP] = (greg_t)func;

	size = sizeof (long) * (argc + 1);

	sp = (long *)(((uintptr_t)ucp->uc_stack.ss_sp +
	    ucp->uc_stack.ss_size - size) & ~(STACK_ALIGN - 1));

	tsp = sp + 1;

	va_start(ap, argc);

	while (argc-- > 0) {
		*tsp++ = va_arg(ap, long);
	}

	va_end(ap);

	*sp = (long)resumecontext;		/* return address */

	ucp->uc_mcontext.gregs[UESP] = (greg_t)sp;
}


static void
resumecontext(void)
{
	ucontext_t uc;

	(void) getcontext(&uc);
	(void) setcontext(uc.uc_link);
}
