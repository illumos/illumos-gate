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
 * Copyright (c) 2013 Joyent, Inc.  All rights reserved.
 */

/*
 * Routines for debugging ctf containers
 */

#include <mdb/mdb_modapi.h>
#include <ctf_impl.h>

static int
mdb_ctf_idhash_walk_init(mdb_walk_state_t *wsp)
{
	ctf_idhash_t *ihp;

	if (wsp->walk_addr == NULL) {
		mdb_warn("ctf_idhash walker does not support global walks\n");
		return (WALK_ERR);
	}

	ihp = mdb_alloc(sizeof (ctf_idhash_t), UM_NOSLEEP | UM_GC);
	if (ihp == NULL) {
		mdb_warn("failed to allocate memory for a ctf_idhash_t");
		return (WALK_ERR);
	}

	if (mdb_vread(ihp, sizeof (ctf_idhash_t), wsp->walk_addr) !=
	    sizeof (ctf_idhash_t)) {
		mdb_warn("failed to read ctf_idhash_t at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	if (ihp->ih_free == 0)
		return (WALK_DONE);
	wsp->walk_data = ihp;
	wsp->walk_arg = (void *)(uintptr_t)1;

	return (WALK_NEXT);
}

static int
mdb_ctf_idhash_walk_step(mdb_walk_state_t *wsp)
{
	ctf_ihelem_t ihe;
	ctf_idhash_t *ihp = wsp->walk_data;
	int index = (uintptr_t)wsp->walk_arg;

	if (index == ihp->ih_free)
		return (WALK_DONE);

	if (mdb_vread(&ihe, sizeof (ihe),
	    (uintptr_t)(ihp->ih_chains + index)) != sizeof (ihe)) {
		mdb_warn("failed to read index %d at %p", index,
		    ihp->ih_chains + index);
		return (WALK_ERR);
	}
	wsp->walk_arg = (void *)(uintptr_t)(index + 1);
	return (wsp->walk_callback((uintptr_t)(ihp->ih_chains + index), &ihe,
	    wsp->walk_cbdata));
}

static const mdb_walker_t walkers[] = {
	{ "ctf_idhash", "walk entries in a ctf idhash",
		mdb_ctf_idhash_walk_init, mdb_ctf_idhash_walk_step }
};

static const mdb_modinfo_t modinfo = { MDB_API_VERSION, NULL, walkers };

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
