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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "thr_uberdata.h"
#include <sys/stack.h>

/*
 * Initialization of the main stack is performed in libc_init().
 * Initialization of thread stacks is performed in _thrp_setup().
 */

#pragma weak _stack_getbounds = stack_getbounds
int
stack_getbounds(stack_t *sp)
{
	*sp = curthread->ul_ustack;
	return (0);
}

#pragma weak _stack_setbounds = stack_setbounds
int
stack_setbounds(const stack_t *sp)
{
	ulwp_t *self = curthread;

	if (sp == NULL || sp->ss_sp == NULL ||
	    (uintptr_t)sp->ss_sp != SA((uintptr_t)sp->ss_sp) ||
	    sp->ss_flags != 0 || sp->ss_size < MINSIGSTKSZ ||
	    (uintptr_t)sp->ss_size != SA((uintptr_t)sp->ss_size)) {
		errno = EINVAL;
		return (-1);
	}

	sigoff(self);
	self->ul_ustack = *sp;
	sigon(self);

	return (0);
}

/*
 * Returns a boolean value:
 *	1 addr is within the bounds of the current stack
 *	0 addr is outside of the bounds of the current stack
 * Note that addr is an unbiased value.
 */
#pragma weak _stack_inbounds = stack_inbounds
int
stack_inbounds(void *addr)
{
	stack_t *ustackp = &curthread->ul_ustack;
	uintptr_t base = (uintptr_t)ustackp->ss_sp;
	size_t size = ustackp->ss_size;

	return ((uintptr_t)addr >= base && (uintptr_t)addr < base + size);
}

#pragma weak _stack_violation = stack_violation
int
stack_violation(int sig, const siginfo_t *sip, const ucontext_t *ucp)
{
	uintptr_t addr;
	uintptr_t base;
	size_t size;

	if ((sig != SIGSEGV && sig != SIGBUS) ||
	    sip == NULL || ucp == NULL || SI_FROMUSER(sip))
		return (0);

	/*
	 * ucp has the correct view of the stack when the signal was raised.
	 */
	base = (uintptr_t)ucp->uc_stack.ss_sp;
	size = ucp->uc_stack.ss_size;
#if defined(__sparc)
	addr = ucp->uc_mcontext.gregs[REG_SP] + STACK_BIAS;
#elif defined(__amd64) || defined(__i386)
	addr = ucp->uc_mcontext.gregs[REG_SP];
	/*
	 * If the faulted address is just below the stack pointer we
	 * might be looking at a push instruction that caused the fault
	 * (the largest amount a push instruction can decrement the
	 * stack pointer by is 32).  In that case, use the faulted
	 * address in our computation rather than the stack pointer.
	 */
	if (addr - (uintptr_t)sip->si_addr < 32)
		addr = (uintptr_t)sip->si_addr;
#else
#error "none of __sparc, __amd64, __i386 is defined"
#endif
	return (!(addr >= base && addr < base + size));
}
