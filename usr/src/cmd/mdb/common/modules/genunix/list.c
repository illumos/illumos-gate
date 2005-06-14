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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <mdb/mdb_modapi.h>
#include <sys/list.h>

typedef struct list_walk_data {
	uintptr_t lw_start;
	size_t	lw_size;
	size_t	lw_offset;
	void	*lw_obj;
} list_walk_data_t;

int
list_walk_init(mdb_walk_state_t *wsp)
{
	list_walk_data_t *lwd;
	list_t list;

	lwd = mdb_alloc(sizeof (list_walk_data_t), UM_SLEEP);
	if (mdb_vread(&list, sizeof (list_t), wsp->walk_addr) == -1) {
		mdb_warn("failed to read list_t at %#lx", wsp->walk_addr);
		mdb_free(lwd, sizeof (list_walk_data_t));
		return (WALK_ERR);
	}

	lwd->lw_size = list.list_size;
	lwd->lw_offset = list.list_offset;
	lwd->lw_obj = mdb_alloc(list.list_size, UM_SLEEP);
	lwd->lw_start = (uintptr_t)&((list_t *)wsp->walk_addr)->list_head;

	wsp->walk_addr = (uintptr_t)list.list_head.list_next;
	wsp->walk_data = lwd;

	return (WALK_NEXT);
}

int
list_walk_step(mdb_walk_state_t *wsp)
{
	list_walk_data_t *lwd = wsp->walk_data;
	uintptr_t addr = wsp->walk_addr - lwd->lw_offset;
	list_node_t *node;
	int status;

	if (wsp->walk_addr == lwd->lw_start)
		return (WALK_DONE);

	if (mdb_vread(lwd->lw_obj, lwd->lw_size, addr) == -1) {
		mdb_warn("failed to read list element at %#lx", addr);
		return (WALK_ERR);
	}

	status = wsp->walk_callback(addr, lwd->lw_obj, wsp->walk_cbdata);
	node = (list_node_t *)((uintptr_t)lwd->lw_obj + lwd->lw_offset);
	wsp->walk_addr = (uintptr_t)node->list_next;

	return (status);
}

void
list_walk_fini(mdb_walk_state_t *wsp)
{
	list_walk_data_t *lwd = wsp->walk_data;

	mdb_free(lwd->lw_obj, lwd->lw_size);
	mdb_free(lwd, sizeof (list_walk_data_t));
}
