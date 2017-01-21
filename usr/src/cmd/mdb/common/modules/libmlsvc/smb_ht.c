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
 * Copyright 2018 Nexenta Systems, Inc. All rights reserved.
 */

/*
 * walker for libsmb : smb_ht.c (hash tables)
 */

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ks.h>
#include <mdb/mdb_ctf.h>

#include <smbsrv/hash_table.h>

/* smb_ht_walk info */
struct hw_info {
	HT_HANDLE hw_handle;	/* struct ht_handle being walked */
	HT_TABLE_ENTRY hw_tblent;
	HT_ITEM hw_item;
	int hw_idx;
};

/*
 * Walker for libsmb/smb_ht.c code.  Calls the call-back function with
 * each HT_ITEM object.  Top-level is HT_HANDLE, passed to _walk_init.
 */
int
smb_ht_walk_init(mdb_walk_state_t *wsp)
{
	struct hw_info *hw;
	uintptr_t addr = wsp->walk_addr;
	HT_HANDLE *ht;

	if (addr == 0) {
		mdb_printf("require address of an HT_HANDLE\n");
		return (WALK_ERR);
	}

	/*
	 * allocate the AVL walk data
	 */
	wsp->walk_data = hw = mdb_zalloc(sizeof (*hw), UM_GC|UM_SLEEP);

	/*
	 * get an mdb copy of the HT_HANDLE being walked
	 */
	ht = &hw->hw_handle;
	if (mdb_vread(ht, sizeof (*ht), wsp->walk_addr) == -1) {
		mdb_warn("failed to read %s at %#lx",
		    "HT_HANDLE", wsp->walk_addr);
		return (WALK_ERR);
	}

	hw->hw_idx = -1;
	wsp->walk_addr = 0;
	wsp->walk_data = hw;

	return (WALK_NEXT);
}

int
smb_ht_walk_step(mdb_walk_state_t *wsp)
{
	struct hw_info *hw = wsp->walk_data;
	HT_TABLE_ENTRY *he = &hw->hw_tblent;
	HT_ITEM *hi = &hw->hw_item;
	uintptr_t he_addr;
	int rv;

	while (wsp->walk_addr == 0) {
		if (++hw->hw_idx >= hw->hw_handle.ht_table_size)
			return (WALK_DONE);
		he_addr = (uintptr_t)hw->hw_handle.ht_table +
		    (hw->hw_idx * sizeof (HT_TABLE_ENTRY));
		if (mdb_vread(he, sizeof (*he), he_addr) == -1) {
			mdb_warn("failed to read %s at %p",
			    "HT_TABLE_ENTRY", wsp->walk_addr);
			return (WALK_ERR);
		}
		wsp->walk_addr = (uintptr_t)he->he_head;
	}

	if (mdb_vread(hi, sizeof (*hi), wsp->walk_addr) == -1) {
		mdb_warn("failed to read %s at %p",
		    "HT_ITEM", wsp->walk_addr);
		return (WALK_ERR);
	}

	rv = wsp->walk_callback(wsp->walk_addr, hi,
	    wsp->walk_cbdata);

	wsp->walk_addr = (uintptr_t)hi->hi_next;

	return (rv);
}
