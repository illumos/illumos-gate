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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include <sys/mdb_modapi.h>
#include <sys/thread.h>
#include "ctxop.h"

int
ctxop_walk_init(mdb_walk_state_t *wsp)
{
	kthread_t thread, *tp = &thread;

	if (wsp->walk_addr == 0) {
		mdb_warn("must specify thread for ctxop walk\n");
		return (WALK_ERR);
	}
	if (mdb_vread(tp, sizeof (*tp), wsp->walk_addr) == -1) {
		mdb_warn("failed to read thread at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	wsp->walk_data = mdb_alloc(sizeof (ctxop_t), UM_SLEEP);
	wsp->walk_addr = (uintptr_t)tp->t_ctx;

	return (WALK_NEXT);
}

int
ctxop_walk_step(mdb_walk_state_t *wsp)
{
	int status;

	if (wsp->walk_addr == 0)
		return (WALK_DONE);

	if (mdb_vread(wsp->walk_data,
	    sizeof (ctxop_t), wsp->walk_addr) == -1) {
		mdb_warn("failed to read ctxop at %p", wsp->walk_addr);
		return (WALK_DONE);
	}

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	wsp->walk_addr = (uintptr_t)(((ctxop_t *)wsp->walk_data)->next);
	return (status);
}

void
ctxop_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (ctxop_t));
}
