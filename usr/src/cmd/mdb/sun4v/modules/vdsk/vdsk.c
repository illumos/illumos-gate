/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This module provides debugging tools for the LDoms vDisk drivers
 * (vds and vdc).
 */

#include <sys/mdb_modapi.h>

#include <sys/vdsk_common.h>

/*
 */
int
vd_dring_entry_walk_init(mdb_walk_state_t *wsp)
{
	/* Must have a start addr.  */
	if (wsp->walk_addr == (uintptr_t)NULL) {
		mdb_warn("Descriptor Ring base address required\n");

		return (WALK_ERR);
	}

	return (WALK_NEXT);
}


/*
 * Generic entry walker step routine.
 */
int
vd_dring_entry_walk_step(mdb_walk_state_t *wsp)
{
	static int		entry_count = 0;
	int			status;
	vd_dring_entry_t	dring_entry;

	if (mdb_vread(&dring_entry, VD_DRING_ENTRY_SZ,
	    (uintptr_t)wsp->walk_addr) == -1) {
		mdb_warn("failed to read vd_dring_entry_t at %p",
		    wsp->walk_addr);

		return (WALK_ERR);
	}

	status = wsp->walk_callback(wsp->walk_addr, &dring_entry,
	    wsp->walk_cbdata);
	wsp->walk_addr = (uintptr_t)(wsp->walk_addr + VD_DRING_ENTRY_SZ);

	/* Check if we're at the last element */
	if (++entry_count >= VD_DRING_LEN) {
		/* reset counter for next call to this walker */
		entry_count = 0;

		return (WALK_DONE);
	}

	return (status);
}

/*
 * MDB module linkage information:
 */

static const mdb_walker_t walkers[] = {
	{ "vd_dring_entry", "walk vDisk public Descriptor Ring entries",
	    vd_dring_entry_walk_init, vd_dring_entry_walk_step, NULL, NULL },
	{ NULL }
};

static const mdb_modinfo_t modinfo = {
	MDB_API_VERSION, NULL, walkers
};

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
