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
 * Debugger co-routine context support:  In order to implement the context-
 * switching necessary for MDB pipes, we need the ability to establish a
 * co-routine context that has a separate stack.  We use this stack to execute
 * the MDB parser, and then switch back and forth between this code and the
 * dcmd which is producing output to be consumed.  We implement a context by
 * mapping a few pages of anonymous memory, and then using setcontext(2) to
 * switch to this stack and begin execution of a new function.
 */

#include <mdb/mdb_context_impl.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_err.h>

#include <sys/types.h>
#include <sys/mman.h>

#include <ucontext.h>
#include <unistd.h>
#include <setjmp.h>
#include <fcntl.h>
#include <errno.h>

static void
context_init(mdb_context_t *volatile c)
{
	c->ctx_status = c->ctx_func();
	ASSERT(c->ctx_resumes > 0);
	longjmp(c->ctx_pcb, 1);
}

mdb_context_t *
mdb_context_create(int (*func)(void))
{
	mdb_context_t *c = mdb_zalloc(sizeof (mdb_context_t), UM_NOSLEEP);
	size_t pagesize = sysconf(_SC_PAGESIZE);
	int prot = sysconf(_SC_STACK_PROT);
	static int zfd = -1;

	if (c == NULL)
		return (NULL);

	if (prot == -1)
		prot = PROT_READ | PROT_WRITE | PROT_EXEC;

	c->ctx_func = func;
	c->ctx_stacksize = pagesize * 4;
	c->ctx_stack = mmap(NULL, c->ctx_stacksize, prot,
	    MAP_PRIVATE | MAP_ANON, -1, 0);

	/*
	 * If the mmap failed with EBADFD, this kernel doesn't have MAP_ANON
	 * support; fall back to opening /dev/zero, caching the fd, and using
	 * that to mmap chunks of anonymous memory.
	 */
	if (c->ctx_stack == MAP_FAILED && errno == EBADF) {
		if (zfd == -1 && (zfd = open("/dev/zero", O_RDWR)) >= 0)
			(void) fcntl(zfd, F_SETFD, FD_CLOEXEC);

		if (zfd >= 0) {
			c->ctx_stack = mmap(NULL, c->ctx_stacksize, prot,
			    MAP_PRIVATE, zfd, 0);
		}
	}

	c->ctx_uc.uc_flags = UC_ALL;
	if (c->ctx_stack == MAP_FAILED || getcontext(&c->ctx_uc) != 0) {
		mdb_free(c, sizeof (mdb_context_t));
		return (NULL);
	}

	c->ctx_uc.uc_stack.ss_sp = c->ctx_stack;
	c->ctx_uc.uc_stack.ss_size = c->ctx_stacksize;
	c->ctx_uc.uc_stack.ss_flags = 0;
	c->ctx_uc.uc_link = NULL;
	makecontext(&c->ctx_uc, context_init, 1, c);

	return (c);
}

void
mdb_context_destroy(mdb_context_t *c)
{
	if (munmap(c->ctx_stack, c->ctx_stacksize) == -1)
		fail("failed to unmap stack %p", c->ctx_stack);

	mdb_free(c, sizeof (mdb_context_t));
}

void
mdb_context_switch(mdb_context_t *c)
{
	if (setjmp(c->ctx_pcb) == 0 && setcontext(&c->ctx_uc) == -1)
		fail("failed to change context to %p", (void *)c);
	else
		fail("unexpectedly returned from context %p", (void *)c);
}

jmp_buf *
mdb_context_getpcb(mdb_context_t *c)
{
	c->ctx_resumes++;
	return (&c->ctx_pcb);
}
