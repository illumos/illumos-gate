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
 * Copyright 2023 Oxide Computer Company
 */

#pragma weak _makecontext = makecontext

#include "lint.h"
#include <stdarg.h>
#include <ucontext.h>
#include <sys/stack.h>
#include <sys/auxv.h>
#include <errno.h>
#include "libc.h"

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
	int pusharg = (argc > 6 ? argc - 6 : 0);
	greg_t tmp;
	int i;

	ucp->uc_mcontext.gregs[REG_PC] = (greg_t)func;

	size = sizeof (long) * (pusharg + 1);

	/*
	 * Calculate new value for %rsp. On entry to a function,
	 * %rsp must be STACK_ENTRY_ALIGNed but not STACK_ALIGNed.
	 * This is because the pushq %rbp will correct the alignment.
	 */

	sp = (long *)(((uintptr_t)ucp->uc_stack.ss_sp +
	    ucp->uc_stack.ss_size - size) & ~(STACK_ENTRY_ALIGN - 1));

	if (((uintptr_t)sp & (STACK_ALIGN - 1ul)) == 0)
		sp -= STACK_ENTRY_ALIGN / sizeof (*sp);

	tsp = sp + 1;

	va_start(ap, argc);

	for (i = 0; i < argc; i++) {
		tmp = va_arg(ap, long);
		switch (i) {
		case 0:
			ucp->uc_mcontext.gregs[REG_RDI] = tmp;
			break;
		case 1:
			ucp->uc_mcontext.gregs[REG_RSI] = tmp;
			break;
		case 2:
			ucp->uc_mcontext.gregs[REG_RDX] = tmp;
			break;
		case 3:
			ucp->uc_mcontext.gregs[REG_RCX] = tmp;
			break;
		case 4:
			ucp->uc_mcontext.gregs[REG_R8] = tmp;
			break;
		case 5:
			ucp->uc_mcontext.gregs[REG_R9] = tmp;
			break;
		default:
			*tsp++ = tmp;
			break;
		}
	}

	va_end(ap);

	*sp = (long)resumecontext;		/* return address */

	ucp->uc_mcontext.gregs[REG_SP] = (greg_t)sp;
}


static void
resumecontext(void)
{
	ucontext_t uc;

	(void) getcontext(&uc);
	(void) setcontext(uc.uc_link);
}

/*
 * This is the ISA-specific allocation logic for allocating and setting up an
 * extended ucontext_t. In particular, we need to allocate and add space for the
 * UC_XSAVE member if we have the appropriate hardware support.  The i386 /
 * amd64 versions could be consolidated in a single x86 impl, but we don't have
 * that yet.
 */
ucontext_t *
ucontext_alloc(uint32_t flags)
{
	boolean_t do_xsave = B_FALSE;
	size_t to_alloc = sizeof (ucontext_t);
	ucontext_t *ucp;

	if (flags != 0) {
		errno = EINVAL;
		return (NULL);
	}

	/*
	 * The AT_SUN_FPTYPE value is used as an approximation for the size of
	 * the uc_xsave structure that we need additional space for. Ideally we
	 * should ask the kernel how much space we actually need and only
	 * allocate that much. Because the uc_xsave member does not need to
	 * include the 512-byte XMM structure or the full xsave header, this
	 * will work in the interim.
	 *
	 * Currently the system doesn't support dynamically enabling FPU
	 * features with the Intel xfd (extended feature disable) MSR. When we
	 * have support for that we'll need to redo this and ask the kernel for
	 * the right size. We will probably want to cache the size for rtld as
	 * well. For more information see uts/intel/os/fpu.c's big theory
	 * statement.
	 */
	switch (___getauxval(AT_SUN_FPTYPE)) {
	case AT_386_FPINFO_XSAVE:
	case AT_386_FPINFO_XSAVE_AMD:
		do_xsave = B_TRUE;
		to_alloc += ___getauxval(AT_SUN_FPSIZE);
		break;
	default:
		break;
	}

	ucp = calloc(1, to_alloc);
	if (ucp == NULL) {
		return (NULL);
	}

	if (do_xsave) {
		/*
		 * Right now we're not really concerned with alignment of the
		 * uc_xsave member. This structure it points to is no defined
		 * for application access and the kernel doesn't care. This will
		 * give us something that is fairly reasonable though.
		 */
		uintptr_t addr = (uintptr_t)ucp;
		ucp->uc_xsave = addr + sizeof (ucontext_t);
	}

	return (ucp);
}

void
ucontext_free(ucontext_t *ucp)
{
	free(ucp);
}
