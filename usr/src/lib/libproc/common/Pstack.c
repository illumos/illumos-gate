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

/*
 * Pstack.c
 *
 * Common helper functions for stack walking.  The ISA-specific code is found in
 * Pstack_iter() in Pisadep.c.
 */

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "libproc.h"
#include "Pcontrol.h"
#include "P32ton.h"
#include "Pstack.h"

/*
 * Utility function to prevent stack loops from running on forever by
 * detecting when there is a stack loop (the %fp has been seen before).
 */
int
stack_loop(prgreg_t fp, prgreg_t **prevfpp, int *nfpp, uint_t *pfpsizep)
{
	prgreg_t *prevfp = *prevfpp;
	uint_t pfpsize = *pfpsizep;
	int nfp = *nfpp;
	int i;

	for (i = 0; i < nfp; i++) {
		if (fp == prevfp[i])
			return (1); /* stack loop detected */
	}

	if (nfp == pfpsize) {
		pfpsize = pfpsize ? pfpsize * 2 : 16;
		prevfp = realloc(prevfp, pfpsize * sizeof (prgreg_t));
		/*
		 * Just assume there is no loop in the face of allocation
		 * failure; the caller still has the original prevfp pointer.
		 */
		if (prevfp == NULL)
			return (0);
	}

	prevfp[nfp++] = fp;
	*prevfpp = prevfp;
	*pfpsizep = pfpsize;
	*nfpp = nfp;

	return (0);
}

/*
 * Signal Frame Detection
 *
 * In order to facilitate detection and processing of signal handler frames
 * during a stack backtrace, we define a set of utility routines to operate on
 * a uclist (ucontext address list), and then use these routines in the various
 * implementations of Pstack_iter below.  Certain source-level debuggers and
 * virtual machines that shall remain nameless believe that in order to detect
 * signal handler frames, one must hard-code checks for symbol names defined
 * in libc and libthread and knowledge of their implementation.  We make no
 * such assumptions, allowing us to operate on programs that manipulate their
 * underlying kernel signal handlers (i.e. use __sigaction) and to not require
 * changes in the face of future library modifications.
 *
 * A signal handler frame is essentially a set of data pushed on to the user
 * stack by the kernel prior to returning to the user program in one of the
 * pre-defined signal handlers.  The signal handler itself receives the signal
 * number, an optional pointer to a siginfo_t, and a pointer to the interrupted
 * ucontext as arguments.  When performing a stack backtrace, we would like to
 * detect these frames so that we can correctly return the interrupted program
 * counter and frame pointer as a separate frame.  When a signal handler frame
 * is constructed on the stack by the kernel, the signalled LWP has its
 * lwp_oldcontext member (exported through /proc as lwpstatus.pr_oldcontext)
 * set to the user address at which the ucontext_t was placed on the LWP's
 * stack.  The ucontext_t's uc_link member is set to the previous value of
 * lwp_oldcontext.  Thus when signal handlers are active, pr_oldcontext will
 * point to the first element of a linked list of ucontext_t addresses.
 *
 * The stack layout for a signal handler frame is as follows:
 *
 * SPARC v7/v9:                           Intel ia32:
 * +--------------+ -        high         +--------------+ -
 * |  struct fq   | ^        addrs        |  siginfo_t   | optional
 * +--------------+ |          ^          +--------------+ -
 * |  gwindows_t  |            |          |  ucontext_t  | ^
 * +--------------+ optional              +--------------+ |
 * |  siginfo_t   |                       | ucontext_t * | |
 * +--------------+ |          |          +--------------+
 * |  xregs data  | v          v          |  siginfo_t * | mandatory
 * +--------------+ -         low         +--------------+
 * |  ucontext_t  | ^        addrs        |  int (signo) | |
 * +--------------+ mandatory             +--------------+ |
 * | struct frame | v                     | struct frame | v
 * +--------------+ - <- %sp on resume    +--------------+ - <- %esp on resume
 *
 * amd64 (64-bit):
 * +--------------+ -
 * |  siginfo_t   | optional
 * +--------------+ -
 * |  ucontext_t  | ^
 * +--------------+ |
 * |  siginfo_t * |
 * +--------------+ mandatory
 * |  int (signo) |
 * +--------------+ |
 * | struct frame | v
 * +--------------+ - <- %rsp on resume
 *
 * The bottom-most struct frame is actually constructed by the kernel by
 * copying the previous stack frame, allowing naive backtrace code to simply
 * skip over the interrupted frame.  The copied frame is never really used,
 * since it is presumed the libc or libthread signal handler wrapper function
 * will explicitly setcontext(2) to the interrupted context if the user
 * program's handler returns.  If we detect a signal handler frame, we simply
 * read the interrupted context structure from the stack, use its embedded
 * gregs to construct the register set for the interrupted frame, and then
 * continue our backtrace.  Detecting the frame itself is easy according to
 * the diagram ("oldcontext" represents any element in the uc_link chain):
 *
 * On SPARC v7 or v9:
 * %fp + sizeof (struct frame) == oldcontext
 *
 * On Intel ia32:
 * %ebp + sizeof (struct frame) + (3 * regsize) == oldcontext
 *
 * On amd64:
 * %rbp + sizeof (struct frame) + (2 * regsize) == oldcontext
 *
 * A final complication is that we want libproc to support backtraces from
 * arbitrary addresses without the caller passing in an LWP id.  To do this,
 * we must first determine all the known oldcontexts by iterating over all
 * LWPs and following their pr_oldcontext pointers.  We optimize our search
 * by discarding NULL pointers and pointers whose value is less than that
 * of the initial stack pointer (since stacks grow down from high memory),
 * and then sort the resulting list by virtual address so we can binary search.
 */

int
load_uclist(uclist_t *ucl, const lwpstatus_t *psp)
{
	struct ps_prochandle *P = ucl->uc_proc;
	uintptr_t addr = psp->pr_oldcontext;

	uintptr_t *new_addrs;
	uint_t new_size, i;
	ucontext_t uc;

	if (addr == (uintptr_t)NULL)
		return (0);

	for (;;) {
		if (ucl->uc_nelems == ucl->uc_size) {
			new_size = ucl->uc_size ? ucl->uc_size * 2 : 16;
			new_addrs = realloc(ucl->uc_addrs,
			    new_size * sizeof (uintptr_t));

			if (new_addrs != NULL) {
				ucl->uc_addrs = new_addrs;
				ucl->uc_size = new_size;
			} else
				break; /* abort if allocation failure */
		}
#ifdef _LP64
		if (P->status.pr_dmodel == PR_MODEL_ILP32) {
			ucontext32_t u32;

			if (Pread(P, &u32, sizeof (u32), addr) != sizeof (u32))
				break; /* abort if we fail to read ucontext */
			uc.uc_link = (ucontext_t *)(uintptr_t)u32.uc_link;
		} else
#endif
		if (Pread(P, &uc, sizeof (uc), addr) != sizeof (uc))
			break; /* abort if we fail to read ucontext */

		dprintf("detected lwp %d signal context at %p\n",
		    (int)psp->pr_lwpid, (void *)addr);
		ucl->uc_addrs[ucl->uc_nelems++] = addr;

		addr = (uintptr_t)uc.uc_link;

		/*
		 * Abort if we find a NULL uc_link pointer or a duplicate
		 * entry which could indicate a cycle or a very peculiar
		 * interference pattern between threads.
		 */
		if (addr == (uintptr_t)NULL)
			break;

		for (i = 0; i < ucl->uc_nelems - 1; i++) {
			if (ucl->uc_addrs[i] == addr)
				return (0);
		}
	}

	return (0);
}

int
sort_uclist(const void *lhp, const void *rhp)
{
	uintptr_t lhs = *((const uintptr_t *)lhp);
	uintptr_t rhs = *((const uintptr_t *)rhp);

	if (lhs < rhs)
		return (-1);
	if (lhs > rhs)
		return (+1);
	return (0);
}

void
init_uclist(uclist_t *ucl, struct ps_prochandle *P)
{
	if ((P->state == PS_STOP || P->state == PS_DEAD) &&
	    P->ucaddrs != NULL) {
		ucl->uc_proc = P;
		ucl->uc_addrs = P->ucaddrs;
		ucl->uc_nelems = P->ucnelems;
		ucl->uc_size = P->ucnelems;
		ucl->uc_cached = 1;
		return;
	}

	ucl->uc_proc = P;
	ucl->uc_addrs = NULL;
	ucl->uc_nelems = 0;
	ucl->uc_size = 0;

	(void) Plwp_iter(P, (proc_lwp_f *)load_uclist, ucl);
	qsort(ucl->uc_addrs, ucl->uc_nelems, sizeof (uintptr_t), sort_uclist);

	if (P->state == PS_STOP || P->state == PS_DEAD) {
		P->ucaddrs = ucl->uc_addrs;
		P->ucnelems = ucl->uc_nelems;
		ucl->uc_cached = 1;
	} else {
		ucl->uc_cached = 0;
	}
}

void
free_uclist(uclist_t *ucl)
{
	if (!ucl->uc_cached && ucl->uc_addrs != NULL)
		free(ucl->uc_addrs);
}

int
find_uclink(uclist_t *ucl, uintptr_t addr)
{
	if (ucl->uc_nelems != 0) {
		return (bsearch(&addr, ucl->uc_addrs, ucl->uc_nelems,
		    sizeof (uintptr_t), sort_uclist) != NULL);
	}

	return (0);
}
