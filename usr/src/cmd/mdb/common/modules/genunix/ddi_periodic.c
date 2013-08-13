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
 * Copyright (c) 2013, Joyent, Inc. All rights reserved.
 */

#include "ddi_periodic.h"

#include <mdb/mdb_modapi.h>
#include <sys/ddi_periodic.h>
#include <sys/sysmacros.h>
#include <stdio.h>

/*ARGSUSED*/
int
dprinfo(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	char prflags[4];
	ddi_periodic_impl_t dpr;
	boolean_t verbose = B_FALSE;

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("ddi_periodic", "ddi_periodic", argc, argv)
		    == -1) {
			mdb_warn("cannot walk 'ddi_periodic'");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, B_TRUE, &verbose, NULL) != argc)
		return (DCMD_USAGE);

	if (mdb_vread(&dpr, sizeof (dpr), addr) == -1) {
		mdb_warn("could not read ddi_periodic_impl_t at %p", addr);
		return (DCMD_ERR);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%16s %4s %3s %5s %5s %12s %s\n", "ADDR", "ID",
		    "LVL", "FLAGS", "MS", "FIRE_COUNT", "HANDLER");
		if (verbose) {
			mdb_printf("%16s %16s %16s %s\n", "", "THREAD",
			    "CYCLIC_ID", "ARGUMENT");
		}
	}

	prflags[0] = dpr.dpr_flags & DPF_DISPATCHED ? 'D' : '-';
	prflags[1] = dpr.dpr_flags & DPF_EXECUTING ? 'X' : '-';
	prflags[2] = dpr.dpr_flags & DPF_CANCELLED ? 'C' : '-';
	prflags[3] = '\0';

	mdb_printf("%16p %4x %3d %5s %5d %12x %a\n", addr, dpr.dpr_id,
	    dpr.dpr_level, prflags, (int)(dpr.dpr_interval / 1000000),
	    dpr.dpr_fire_count, dpr.dpr_handler);
	if (verbose) {
		mdb_printf("%16s %16p %16p %a\n", "", dpr.dpr_thread,
		    dpr.dpr_cyclic_id, dpr.dpr_arg);
	}

	return (DCMD_OK);
}
