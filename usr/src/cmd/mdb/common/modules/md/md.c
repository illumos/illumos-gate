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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/mdb_modapi.h>


int	md_verbose = 0;		/* be verbose about the addresses */

extern int metaset(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int metastat(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int set_io(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int dumpnamespace(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int dumpsetaddr(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int dumphotspare(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int printmmbm(uintptr_t, uint_t, int, const mdb_arg_t *);
extern void set_io_help();

/* from mdbgen */
extern int mddb_db_walk_init(mdb_walk_state_t *);
extern int mddb_db_walk_step(mdb_walk_state_t *);
extern int mddb_de_ic_walk_init(mdb_walk_state_t *);
extern int mddb_de_ic_walk_step(mdb_walk_state_t *);
extern int hotsparepool_walk_init(mdb_walk_state_t *);
extern int hotsparepool_walk_step(mdb_walk_state_t *);
extern void hotsparepool_walk_fini(mdb_walk_state_t *);
extern int didnamespace_walk_init(mdb_walk_state_t *);
extern int didnamespace_walk_step(mdb_walk_state_t *);
extern void didnamespace_walk_fini(mdb_walk_state_t *);
extern int namespace_walk_init(mdb_walk_state_t *);
extern int namespace_walk_step(mdb_walk_state_t *);
extern void namespace_walk_fini(mdb_walk_state_t *);
extern int sets_walk_init(mdb_walk_state_t *);
extern int sets_walk_step(mdb_walk_state_t *);
extern void sets_walk_fini(mdb_walk_state_t *);
extern int units_walk_init(mdb_walk_state_t *);
extern int units_walk_step(mdb_walk_state_t *);
extern void units_walk_fini(mdb_walk_state_t *);
extern int simple_de_ic(uintptr_t, uint_t, int, const mdb_arg_t *);
int md_set_verbose(uintptr_t, uint_t, int, const mdb_arg_t *);


const mdb_dcmd_t dcmds[] = {
	{ "md_verbose", NULL, "toggle verbose mode for SVM dcmds",
	    md_set_verbose },
	{ "metaset", NULL, "list SVM metasets", metaset },
	{ "metastat", "[-v]", "list SVM metadevices",
	    metastat },
	{ "set_io", NULL, "show the pending IO counts", set_io,
	    set_io_help },
	{ "dumpnamespace", "[-s setname]", "dump the SVM name space",
	    dumpnamespace },
	{ "dumphotspare", NULL, "dump the hot spare pools",
	    dumphotspare },
	{ "dumpsetaddr", "[-s setname]", "dump the SVM set addresses",
	    dumpsetaddr },
	{ "simple_de_ic", NULL, "simple mddb_de_ic_t",
	    simple_de_ic },
	{ "printmmbm", NULL, "print bitmaps for given mm_unit_t",
	    printmmbm },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "mddb_db", "walk list of mddb_db_t structures",
	    mddb_db_walk_init, mddb_db_walk_step, NULL, NULL },
	{ "mddb_de_ic", "walk list of mddb_de_t structures",
	    mddb_de_ic_walk_init, mddb_de_ic_walk_step, NULL, NULL },
	{ "hotsparepool", "walk list of hotspare pools",
	    hotsparepool_walk_init, hotsparepool_walk_step,
	    hotsparepool_walk_fini, NULL },
	{ "didnamespace", "walk the did namespace",
	    didnamespace_walk_init, didnamespace_walk_step,
	    didnamespace_walk_fini, NULL },
	{ "namespace", "walk the namespace",
	    namespace_walk_init, namespace_walk_step, namespace_walk_fini,
	    NULL },
	{ "md_sets", "walk list of sets",
	    sets_walk_init, sets_walk_step, sets_walk_fini, NULL },
	{ "md_units", "walk list of unit structures",
	    units_walk_init, units_walk_step, units_walk_fini, NULL },
	{ NULL }
};

static const mdb_modinfo_t modinfo = {
	MDB_API_VERSION, dcmds, walkers
};

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}


/* ARGSUSED */
int
md_set_verbose(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	md_verbose = !md_verbose;

	if ((flags & DCMD_ADDRSPEC) != 0 || argc != 0)
		return (DCMD_USAGE);

	mdb_printf("Verbose mode is now %d\n", md_verbose);
	return (DCMD_OK);
}
