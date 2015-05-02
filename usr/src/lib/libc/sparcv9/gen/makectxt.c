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

#pragma weak _makecontext = makecontext
#pragma weak ___makecontext_v2 = __makecontext_v2

#include "lint.h"
#include <stdarg.h>
#include <strings.h>
#include <sys/ucontext.h>
#include <sys/stack.h>
#include <sys/frame.h>
#include <sys/regset.h>

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
	greg_t *reg;
	long *tsp;
	char *sp;
	int argno;
	va_list ap;
	size_t size;

	reg = ucp->uc_mcontext.gregs;
	reg[REG_PC] = (greg_t)func;
	reg[REG_nPC] = reg[REG_PC] + 0x4;

	/*
	 * Reserve enough space for a frame and the arguments beyond the
	 * sixth; round to stack alignment.
	 */
	size = sizeof (struct frame);
	size += (argc > 6 ? argc - 6 : 0) * sizeof (long);

	/*
	 * The legacy implemenation of makecontext() on sparc has been to
	 * interpret the uc_stack.ss_sp member incorrectly as the top of the
	 * stack rather than the base. We preserve this behavior here, but
	 * provide the correct semantics in __makecontext_v2().
	 */
	sp = (char *)(((uintptr_t)ucp->uc_stack.ss_sp - size) &
	    ~(STACK_ALIGN - 1));

	/*
	 * Copy all args to the stack, and put the first 6 args into the
	 * ucontext_t. Zero the other fields of the frame.
	 */
	/* LINTED pointer cast may result in improper alignment */
	tsp = &((struct frame *)sp)->fr_argd[0];
	bzero(sp, sizeof (struct frame));

	va_start(ap, argc);

	for (argno = 0; argno < argc; argno++) {
		if (argno < 6)
			*tsp++ = reg[REG_O0 + argno] = va_arg(ap, long);
		else
			*tsp++ = va_arg(ap, long);
	}

	va_end(ap);

	reg[REG_SP] = (greg_t)sp - STACK_BIAS;		/* sp (when done) */
	reg[REG_O7] = (greg_t)resumecontext - 8;	/* return pc */
}

void
__makecontext_v2(ucontext_t *ucp, void (*func)(), int argc, ...)
{
	greg_t *reg;
	long *tsp;
	char *sp;
	int argno;
	va_list ap;
	size_t size;

	reg = ucp->uc_mcontext.gregs;
	reg[REG_PC] = (greg_t)func;
	reg[REG_nPC] = reg[REG_PC] + 0x4;

	/*
	 * Reserve enough space for a frame and the arguments beyond the
	 * sixth; round to stack alignment.
	 */
	size = sizeof (struct frame);
	size += (argc > 6 ? argc - 6 : 0) * sizeof (long);

	sp = (char *)(((uintptr_t)ucp->uc_stack.ss_sp +
	    ucp->uc_stack.ss_size - size) & ~(STACK_ALIGN - 1));

	/*
	 * Copy all args to the stack, and put the first 6 args into the
	 * ucontext_t. Zero the other fields of the frame.
	 */
	/* LINTED pointer cast may result in improper alignment */
	tsp = &((struct frame *)sp)->fr_argd[0];
	bzero(sp, sizeof (struct frame));

	va_start(ap, argc);

	for (argno = 0; argno < argc; argno++) {
		if (argno < 6)
			*tsp++ = reg[REG_O0 + argno] = va_arg(ap, long);
		else
			*tsp++ = va_arg(ap, long);
	}

	va_end(ap);

	reg[REG_SP] = (greg_t)sp - STACK_BIAS;		/* sp (when done) */
	reg[REG_O7] = (greg_t)resumecontext - 8;	/* return pc */
}

static void
resumecontext(void)
{
	/*
	 * We can't include ucontext.h (where these functions are defined)
	 * because it remaps the symbol makecontext.
	 */
	extern int getcontext(ucontext_t *);
	extern int setcontext(const ucontext_t *);
	ucontext_t uc;

	(void) getcontext(&uc);
	(void) setcontext(uc.uc_link);
}
