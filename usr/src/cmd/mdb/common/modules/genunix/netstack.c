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
 * Copyright (c) 2012, Joyent, Inc.  All rights reserved.
 */

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ks.h>
#include <mdb/mdb_ctf.h>
#include <sys/types.h>
#include <sys/netstack.h>

int
netstack_walk_init(mdb_walk_state_t *wsp)
{
	GElf_Sym sym;
	uintptr_t addr;

	if (mdb_lookup_by_name("netstack_head", &sym) == -1) {
		mdb_warn("couldn't find netstack_head");
		return (WALK_ERR);
	}
	addr = (uintptr_t)sym.st_value;

	if (mdb_vread(&wsp->walk_addr, sizeof (wsp->walk_addr),	addr) == -1) {
		mdb_warn("failed to read address of initial netstack "
		    "at %p", addr);
		return (WALK_ERR);
	}
	return (WALK_NEXT);
}

int
netstack_walk_step(mdb_walk_state_t *wsp)
{
	int status;
	netstack_t nss;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(&nss, sizeof (netstack_t), wsp->walk_addr) == -1) {
		mdb_warn("failed to read netstack at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	status = wsp->walk_callback(wsp->walk_addr, &nss,
	    wsp->walk_cbdata);

	if (status != WALK_NEXT)
		return (status);

	wsp->walk_addr = (uintptr_t)nss.netstack_next;
	return (status);
}

/*ARGSUSED*/
int
netstack(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	netstack_t nss;
	uint_t quiet = FALSE;
	uint_t verbose = FALSE;

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("genunix`netstack", "genunix`netstack",
		    argc, argv) == -1) {
			mdb_warn("failed to walk netstack");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}
	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose,
	    'q', MDB_OPT_SETBITS, TRUE, &quiet,
	    NULL) != argc)
		return (DCMD_USAGE);

	if (DCMD_HDRSPEC(flags) && !quiet) {
		mdb_printf("%?s %-7s %6s\n",
		    "ADDR", "STACKID", "FLAGS");
	}

	if (mdb_vread(&nss, sizeof (nss), addr) == -1) {
		mdb_warn("couldn't read netstack at %p", addr);
		return (DCMD_ERR);
	}

	/*
	 * Options are specified for filtering, so If any option is specified on
	 * the command line, just print address and exit.
	 */
	if (quiet) {
		mdb_printf("%0?p\n", addr);
		return (DCMD_OK);
	}

	mdb_printf("%0?p %6d    %06x\n",
	    addr, nss.netstack_stackid, nss.netstack_flags);

	return (DCMD_OK);
}

static int
netstackid_lookup_cb(uintptr_t addr, const netstack_t *ns, void *arg)
{
	netstackid_t nid = *(uintptr_t *)arg;
	if (ns->netstack_stackid == nid)
		mdb_printf("%p\n", addr);

	return (WALK_NEXT);
}

/*ARGSUSED*/
int
netstackid2netstack(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	if (!(flags & DCMD_ADDRSPEC) || argc != 0)
		return (DCMD_USAGE);

	if (mdb_walk("netstack", (mdb_walk_cb_t)netstackid_lookup_cb, &addr) ==
	    -1) {
		mdb_warn("failed to walk zone");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}
