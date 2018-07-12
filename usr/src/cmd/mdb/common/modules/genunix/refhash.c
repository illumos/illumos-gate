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
 * Copyright 2018, Joyent, Inc.
 */

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ctf.h>

#include <inttypes.h>
#include <sys/refhash.h>

typedef struct refhash_walk_data {
	size_t	rwd_offset;
} refhash_walk_data_t;

int
refhash_walk_init(mdb_walk_state_t *wsp)
{
	refhash_t refh = { 0 };
	refhash_walk_data_t *rwd;
	int offset;

	/*  mdb_ctf_offsetof_by_name() will print any errors */
	if ((offset = mdb_ctf_offsetof_by_name("refhash_t", "rh_objs")) == -1)
		return (WALK_ERR);

	if (mdb_vread(&refh, sizeof (refhash_t), wsp->walk_addr) == -1) {
		mdb_warn("failed to read refhash_t at %#lx", wsp->walk_addr);
		return (WALK_ERR);
	}

	rwd = wsp->walk_data = mdb_zalloc(sizeof (*rwd), UM_SLEEP | UM_GC);
	rwd->rwd_offset = refh.rh_link_off;

	wsp->walk_addr += offset;
	if (mdb_layered_walk("list", wsp) == -1) {
		mdb_warn("can't walk refhash_t");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

int
refhash_walk_step(mdb_walk_state_t *wsp)
{
	refhash_walk_data_t *rwd = wsp->walk_data;
	uintptr_t addr = wsp->walk_addr - rwd->rwd_offset;

	return (wsp->walk_callback(addr, wsp->walk_layer, wsp->walk_cbdata));
}
