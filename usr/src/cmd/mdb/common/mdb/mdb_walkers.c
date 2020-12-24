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
 * Copyright 2021 Joyent, Inc.
 */

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_linkerset.h>

const mdb_walker_t mdb_walker_builtins[] = {
	{ "linkerset", "walk a linkerset", ldset_walk_init, ldset_walk_step },
	{ "linkersets", "walk all linkersets", ldsets_walk_init,
	    ldsets_walk_step },
	NULL
};
