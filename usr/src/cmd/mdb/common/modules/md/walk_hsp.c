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

#include "mdinclude.h"

/*
 * walk the hotspare pools
 */
/* ARGSUSED */
int
hotsparepool_walk_init(mdb_walk_state_t *wsp)
{
	uintptr_t	addr;

	snarf_sets();
	addr = (uintptr_t)mdset[0].s_hsp;
	wsp->walk_data = mdb_alloc(sizeof (int), UM_SLEEP);
	/* walk_data hold the number of the set we're walking */
	*((int *)wsp->walk_data) = 0;
	mdb_printf("Hotspare Pools for set number 0\n");
	wsp->walk_addr = addr;
	return (WALK_NEXT);
}

int
hotsparepool_walk_step(mdb_walk_state_t *wsp)
{
	int	status;
	hot_spare_pool_t	hsp;

	if (wsp->walk_addr == NULL) {
		*((int *)wsp->walk_data) += 1;
		if (*((int *)wsp->walk_data) < md_nsets) {
			wsp->walk_addr =
			    (uintptr_t)mdset[*((int *)wsp->walk_data)].s_hsp;
			if (wsp->walk_addr == NULL)
				return (WALK_NEXT);
			mdb_printf("Hotspare Pools for set number %d\n",
			    *((int *)wsp->walk_data));
		} else {
			return (WALK_DONE);
		}
	}

	if (mdb_vread(&hsp, sizeof (hot_spare_pool_t), wsp->walk_addr) !=
	    sizeof (hot_spare_pool_t)) {
		mdb_warn("failed to read hot_spare_pool_t at %p",
		    wsp->walk_addr);
		return (WALK_DONE);
	}



	status = wsp->walk_callback(wsp->walk_addr, (&hsp)->hsp_next,
	    wsp->walk_cbdata);

	wsp->walk_addr = (uintptr_t)(&hsp)->hsp_next;

	return (status);
}

void
hotsparepool_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (int));
}
