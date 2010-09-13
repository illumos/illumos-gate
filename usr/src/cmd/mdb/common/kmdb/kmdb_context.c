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
 * Debugger co-routine context support.  kmdb co-routines are essentially the
 * same as the ones used by mdb, with the exception that we allocate the stack
 * for the co-routine from our heap.
 */

#include <kmdb/kmdb_context_impl.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_umem.h>
#include <mdb/mdb.h>

#include <sys/types.h>

#include <ucontext.h>
#include <setjmp.h>

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
	size_t pagesize = mdb.m_pagesize;

	if (c == NULL)
		return (NULL);

	c->ctx_func = func;
	c->ctx_stacksize = pagesize * 4;
	c->ctx_stack = mdb_alloc_align(c->ctx_stacksize, pagesize, UM_NOSLEEP);

	if (c->ctx_stack == NULL) {
		mdb_free(c, sizeof (mdb_context_t));
		return (NULL);
	}

	kmdb_makecontext(&c->ctx_uc, (void (*)(void *))context_init, c,
	    c->ctx_stack, c->ctx_stacksize);

	return (c);
}

void
mdb_context_destroy(mdb_context_t *c)
{
	mdb_free_align(c->ctx_stack, c->ctx_stacksize);
	mdb_free(c, sizeof (mdb_context_t));
}

void
mdb_context_switch(mdb_context_t *c)
{
	if (setjmp(c->ctx_pcb) == 0 && kmdb_setcontext(&c->ctx_uc) == -1)
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
