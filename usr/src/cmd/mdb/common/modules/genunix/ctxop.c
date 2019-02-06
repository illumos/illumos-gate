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
/*
 * Copyright 2018 Joyent, Inc.
 */

#include <sys/mdb_modapi.h>
#include <sys/thread.h>
#include "ctxop.h"

struct ctxop_walk_state {
	uintptr_t	cws_head;
	uint_t		cws_next_offset;
};

int
ctxop_walk_init(mdb_walk_state_t *wsp)
{
	struct ctxop_walk_state *priv;
	int offset;
	uintptr_t addr;

	if (wsp->walk_addr == 0) {
		mdb_warn("must specify thread for ctxop walk\n");
		return (WALK_ERR);
	}

	offset = mdb_ctf_offsetof_by_name("kthread_t", "t_ctx");
	if (offset == -1)
		return (WALK_ERR);

	if (mdb_vread(&addr, sizeof (addr),
	    wsp->walk_addr + offset) != sizeof (addr)) {
		mdb_warn("failed to read thread %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	/* No further work for threads with a NULL t_ctx */
	if (addr == 0) {
		wsp->walk_data = NULL;
		return (WALK_DONE);
	}

	/* rely on CTF for the offset of the 'next' pointer */
	offset = mdb_ctf_offsetof_by_name("struct ctxop", "next");
	if (offset == -1)
		return (WALK_ERR);

	priv = mdb_alloc(sizeof (*priv), UM_SLEEP);
	priv->cws_head = addr;
	priv->cws_next_offset = (uint_t)offset;

	wsp->walk_data = priv;
	wsp->walk_addr = addr;
	return (WALK_NEXT);
}

int
ctxop_walk_step(mdb_walk_state_t *wsp)
{
	struct ctxop_walk_state *priv = wsp->walk_data;
	uintptr_t next;
	int status;

	if (wsp->walk_addr == 0)
		return (WALK_DONE);

	if (mdb_vread(wsp->walk_data,
	    sizeof (ctxop_t), wsp->walk_addr) == -1) {
		mdb_warn("failed to read ctxop at %p", wsp->walk_addr);
		return (WALK_DONE);
	}

	status = wsp->walk_callback(wsp->walk_addr, NULL, wsp->walk_cbdata);

	if (status == WALK_NEXT) {
		/*
		 * If a NULL terminator or a loop back to the head element is
		 * encountered, the walk is done.
		 */
		if (next == 0 || next == priv->cws_head) {
			status = WALK_DONE;
		}
	}

	wsp->walk_addr = next;
	return (status);
}

void
ctxop_walk_fini(mdb_walk_state_t *wsp)
{
	struct ctxop_walk_state *priv = wsp->walk_data;

	if (priv != NULL) {
		mdb_free(priv, sizeof (*priv));
	}
}
