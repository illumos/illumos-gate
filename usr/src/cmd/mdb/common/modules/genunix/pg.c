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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Display processor group information
 */

#include "pg.h"

#include <mdb/mdb_modapi.h>
#include <sys/pghw.h>

/*
 * PG hardware types indexed by hardware ID
 */
char *pg_hw_names[] = {
	"hw",
	"ipipe",
	"cache",
	"fpu",
	"mpipe",
	"chip",
	"memory",
};

#define	A_CNT(arr)	(sizeof (arr) / sizeof (arr[0]))

#define	NHW	 A_CNT(pg_hw_names)

/*
 * Convert HW id to symbolic name
 */
static char *
pg_hw_name(int hw)
{
	return ((hw < 0 || hw > NHW) ? "UNKNOWN" : pg_hw_names[hw]);
}

/*
 * Display processor group.
 */
/* ARGSUSED */
int
pg(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	pg_t		pg;
	pghw_t		pghw;
	pg_class_t	pg_class;
	int		opt_q = 0; /* display only address. */

	/* Should provide an address */
	if (! (flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_getopts(argc, argv,
	    'q', MDB_OPT_SETBITS, TRUE, &opt_q,
	    NULL) != argc)
		return (DCMD_USAGE);

	if (flags & DCMD_PIPE_OUT)
		opt_q = B_TRUE;

	if (DCMD_HDRSPEC(flags) && !opt_q) {
		mdb_printf("%6s %?s %6s %7s %9s %5s\n",
		    "PGID",
		    "ADDR",
		    "PHYSID",
		    "CLASS",
		    "HARDWARE",
		    "#CPUs");
	}

	/*
	 * Read pg at specified address
	 */
	if (mdb_vread(&pg, sizeof (struct pg), addr) == -1) {
		mdb_warn("unable to read 'pg' at %p", addr);
		return (DCMD_ERR);
	}

	/*
	 * In quiet mode just print pg address
	 */
	if (opt_q) {
		mdb_printf("%0?p\n", addr);
		return (DCMD_OK);
	}

	if (mdb_vread(&pg_class, sizeof (struct pg_class),
	    (uintptr_t)pg.pg_class) == -1) {
		mdb_warn("unable to read 'pg_class' at %p", pg.pg_class);
		return (DCMD_ERR);
	}

	if (pg.pg_relation == PGR_PHYSICAL) {
		if (mdb_vread(&pghw, sizeof (struct pghw), addr) == -1) {
			mdb_warn("unable to read 'pghw' at %p", addr);
			return (DCMD_ERR);
		}
		/*
		 * Display the physical PG info.
		 */
		mdb_printf("%6d %?p %6d %7s %9s %5d\n",
		    pg.pg_id, addr, pghw.pghw_instance,
		    pg_class.pgc_name, pg_hw_name(pghw.pghw_hw),
		    pg.pg_cpus.grp_size);
	} else {
		/*
		 * Display the basic PG info.
		 */
		mdb_printf("%6d %?p %7s %5d\n",
		    pg.pg_id, addr, pg_class.pgc_name,
		    pg.pg_cpus.grp_size);
	}

	return (DCMD_OK);
}
