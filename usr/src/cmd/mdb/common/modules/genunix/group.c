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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Display group information and walk all elements of a group
 */

#include "group.h"

#include <mdb/mdb_modapi.h>
#include <sys/group.h>

/*
 * Display group information
 */

/* ARGSUSED */
int
group(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	group_t	group;
	int	opt_q = 0; /* display only address. */

	/* Should provide an address */
	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_getopts(argc, argv,
	    'q', MDB_OPT_SETBITS, TRUE, &opt_q,
		NULL) != argc)
		return (DCMD_USAGE);

	if (flags & DCMD_PIPE_OUT)
		opt_q = B_TRUE;

	if (DCMD_HDRSPEC(flags) && !opt_q) {
		mdb_printf("%?s %6s %9s %?s\n",
		    "ADDR",
		    "SIZE",
		    "CAPACITY",
		    "SET");
	}

	if (mdb_vread(&group, sizeof (struct group), addr) == -1) {
		mdb_warn("unable to read 'group' at %p", addr);
		return (DCMD_ERR);
	}

	if (opt_q) {
		mdb_printf("%0?p\n", addr);
		return (DCMD_OK);
	}

	mdb_printf("%?p %6d %9d %?p\n",
	    addr, group.grp_size, group.grp_capacity, group.grp_set);

	return (DCMD_OK);
}

/*
 * Walk all elements in the group set.
 */

typedef struct group_walk {
	uintptr_t *gw_set;
	int gw_size;
	int gw_pos;
	int gw_initialized;
} group_walk_t;


/*
 * Initialize the walk structure with the copy of a group set, its size and the
 * initial pointer position.
 */
int
group_walk_init(mdb_walk_state_t *wsp)
{
	group_walk_t	*gw;
	group_t		group;

	gw = mdb_alloc(sizeof (group_walk_t), UM_SLEEP | UM_GC);

	if (mdb_vread(&group, sizeof (struct group), wsp->walk_addr) == -1) {
		mdb_warn("couldn't read 'group' at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	gw->gw_size = group.grp_size;
	gw->gw_initialized = 0;
	gw->gw_pos = 0;

	if (gw->gw_size < 0) {
		mdb_warn("invalid group at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	if (gw->gw_size == 0)
		return (WALK_DONE);

	/*
	 * Allocate space for the set and copy all set entries.
	 */
	gw->gw_set = mdb_alloc(group.grp_size * sizeof (uintptr_t),
	    UM_SLEEP | UM_GC);

	if (mdb_vread(gw->gw_set, group.grp_size * sizeof (uintptr_t),
	    (uintptr_t)group.grp_set) == -1) {
		mdb_warn("couldn't read 'group set' at %p", group.grp_set);
		return (WALK_ERR);
	}

	wsp->walk_data = gw;
	wsp->walk_addr = gw->gw_set[0];
	gw->gw_pos = 0;

	return (WALK_NEXT);
}

/*
 * Print element of the set and advance the pointer.
 */
int
group_walk_step(mdb_walk_state_t *wsp)
{
	group_walk_t *gw = (group_walk_t *)wsp->walk_data;
	int status;

	/*
	 * Already visited all valid elements, nothing else to do.
	 */
	if (gw->gw_size < 0)
		return (WALK_DONE);

	/*
	 * Print non-NULL elements
	 */
	status = wsp->walk_addr == 0 ?
	    WALK_NEXT :
	    wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
		wsp->walk_cbdata);

	/*
	 * Adjust walk_addr to point to the next element
	 */
	gw->gw_size--;

	if (gw->gw_size > 0)
		wsp->walk_addr = gw->gw_set[++gw->gw_pos];
	else
		status = WALK_DONE;

	return (status);
}
