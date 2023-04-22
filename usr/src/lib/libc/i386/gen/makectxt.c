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

/*
 * The original i386 ABI said that the stack pointer need be only 4-byte
 * aligned before a function call (STACK_ALIGN == 4).  The ABI supplement
 * version 1.0 changed the required alignment to 16-byte for the benefit of
 * floating point code compiled using sse2.  The compiler assumes this
 * alignment and maintains it for calls it generates.  If the stack is
 * initially properly aligned, it will continue to be so aligned.  If it is
 * not initially so aligned, it will never become so aligned.
 *
 * One slightly confusing detail to keep in mind is that the 16-byte
 * alignment (%esp & 0xf == 0) is true just *before* the call instruction.
 * The call instruction will then push a return value, decrementing %esp by
 * 4.  Therefore, if one dumps %esp at the at the very first instruction in
 * a function, it will end with a 0xc.  The compiler expects this and
 * compensates for it properly.
 *
 * Note: If you change this value, you need to change it in the following
 * files as well:
 *
 *  - lib/libc/i386/threads/machdep.c
 *  - lib/crt/i386/crti.s
 *  - lib/crt/i386/crt1.s
 */
#undef	STACK_ALIGN
#define	STACK_ALIGN	16

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

	tsp = (long *)(((uintptr_t)ucp->uc_stack.ss_sp +
	    ucp->uc_stack.ss_size - size) & ~(STACK_ALIGN - 1));

	/*
	 * Since we're emulating the call instruction, we must push the
	 * return address (which involves adjusting the stack pointer to
	 * have the proper 4-byte bias).
	 */
	sp = tsp - 1;

	*sp = (long)resumecontext;		/* return address */

	ucp->uc_mcontext.gregs[UESP] = (greg_t)sp;

	/*
	 * "push" all the arguments
	 */
	va_start(ap, argc);
	while (argc-- > 0)
		*tsp++ = va_arg(ap, long);
	va_end(ap);
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
