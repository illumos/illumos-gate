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
 * Copyright 2019 Joyent, Inc.
 */

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ks.h>
#include <sys/refstr.h>

#define	REFSTR_LEN (1024)

int
cmd_refstr(uintptr_t addr, uint_t flags __unused,
    int argc, const mdb_arg_t *argv)
{
	if (!(flags & DCMD_ADDRSPEC)) {
		mdb_warn("address is required\n");
		return (DCMD_ERR);
	}

	if (mdb_getopts(argc, argv, NULL) != argc)
		return (DCMD_USAGE);

	char *buf = mdb_alloc(REFSTR_LEN, UM_SLEEP | UM_GC);

	if (mdb_read_refstr(addr, buf, REFSTR_LEN) < 0) {
		mdb_warn("couldn't read refstr from %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("%s\n", buf);
	return (DCMD_OK);
}
