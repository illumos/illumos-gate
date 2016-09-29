/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2016 Joyent, Inc.
 */

#include "dnlc.h"

#include <mdb/mdb_modapi.h>
#include <sys/dnlc.h>

typedef struct dnlc_walk {
	int dw_hashsz;
	int dw_index;
	uintptr_t dw_hash;
	uintptr_t dw_head;
} dnlc_walk_t;


int
dnlc_walk_init(mdb_walk_state_t *wsp)
{
	dnlc_walk_t *dwp;

	if (wsp->walk_addr != NULL) {
		mdb_warn("dnlc walk doesn't support global walks\n");
		return (WALK_ERR);
	}

	dwp = mdb_zalloc(sizeof (dnlc_walk_t), UM_SLEEP);
	if (mdb_readvar(&dwp->dw_hashsz, "nc_hashsz") == -1 ||
	    dwp->dw_hashsz <= 0) {
		mdb_warn("failed to read 'nc_hashsz'\n");
		mdb_free(dwp, sizeof (dnlc_walk_t));
		return (WALK_ERR);
	}
	if (dwp->dw_hashsz <= 0) {
		mdb_warn("invalid 'nc_hashsz' value\n");
		mdb_free(dwp, sizeof (dnlc_walk_t));
		return (WALK_ERR);
	}
	if (mdb_readvar(&dwp->dw_hash, "nc_hash") == -1) {
		mdb_warn("failed to read 'nc_hash'\n");
		mdb_free(dwp, sizeof (dnlc_walk_t));
		return (WALK_ERR);
	}

	wsp->walk_data = dwp;
	return (WALK_NEXT);
}

int
dnlc_walk_step(mdb_walk_state_t *wsp)
{
	dnlc_walk_t *dwp = wsp->walk_data;
	nc_hash_t hash;
	uintptr_t result, addr = wsp->walk_addr;

next:
	while (addr == dwp->dw_head || addr == NULL) {
		if (dwp->dw_index >= dwp->dw_hashsz) {
			return (WALK_DONE);
		}
		dwp->dw_head = dwp->dw_hash +
		    (sizeof (nc_hash_t) * dwp->dw_index);
		if (mdb_vread(&hash, sizeof (hash), dwp->dw_head) == -1) {
			mdb_warn("failed to read nc_hash_t at %#lx",
			    dwp->dw_hash);
			return (WALK_ERR);
		}
		dwp->dw_index++;
		addr = (uintptr_t)hash.hash_next;
	}

	result = addr;
	if (mdb_vread(&addr, sizeof (uintptr_t), addr) == -1) {
		/*
		 * This entry may have become bogus since acquiring the address
		 * from its neighbor.  Continue on if that is the case.
		 */
		addr = NULL;
		goto next;
	}
	wsp->walk_addr = addr;

	return (wsp->walk_callback(result, &result, wsp->walk_cbdata));
}

void
dnlc_walk_fini(mdb_walk_state_t *wsp)
{
	dnlc_walk_t *dwp = wsp->walk_data;

	mdb_free(dwp, sizeof (dnlc_walk_t));
}
