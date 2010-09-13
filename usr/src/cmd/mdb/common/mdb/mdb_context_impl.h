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

#ifndef _MDB_CONTEXT_IMPL_H
#define	_MDB_CONTEXT_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <mdb/mdb_context.h>

#include <sys/types.h>

#include <ucontext.h>
#include <setjmp.h>

#ifdef __cplusplus
extern "C" {
#endif

struct mdb_context {
	int (*ctx_func)(void);		/* pointer to start function */
	int ctx_status;			/* return status of ctx_func */
	int ctx_resumes;		/* count of context resume calls */
	size_t ctx_stacksize;		/* size of stack in bytes */
	void *ctx_stack;		/* stack base address */
	ucontext_t ctx_uc;		/* user context structure */
	jmp_buf ctx_pcb;		/* control block for resume */
};

#ifdef __cplusplus
}
#endif

#endif /* _MDB_CONTEXT_IMPL_H */
