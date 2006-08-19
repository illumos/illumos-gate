/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "main.h"

static uintptr_t firstaddr = 0;
char mdipathinfo_cb_str[] = "::print struct mdi_pathinfo";
char mdiphci_cb_str[] = "::print struct mdi_phci";

/* mdi_pathinfo client walker */

/* ARGUSED */
int
mdi_pi_client_link_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL) {
		mdb_warn("Address is required");
		return (WALK_ERR);
	}
	wsp->walk_data = mdb_alloc(sizeof (struct mdi_pathinfo), UM_SLEEP);
	firstaddr = wsp->walk_addr;
	return (WALK_NEXT);
}

/* ARGUSED */
int
mdi_pi_client_link_walk_step(mdb_walk_state_t *wsp)
{
	int 		status = 0;
	static int	counts = 0;

	if (firstaddr == wsp->walk_addr && counts != 0) {
		counts = 0;
		return (WALK_DONE);
	}
	if (wsp->walk_addr == NULL) {
		counts = 0;
		return (WALK_DONE);
	}
	if (mdb_vread(wsp->walk_data, sizeof (struct mdi_pathinfo),
	    wsp->walk_addr) == -1) {
		mdb_warn("failed to read mdi_pathinfo at %p", wsp->walk_addr);
		return (WALK_DONE);
	}
	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);
	wsp->walk_addr = (uintptr_t)
	    (((struct mdi_pathinfo *)wsp->walk_data)->pi_client_link);
	counts++;
	return (status);
}

/* ARGUSED */
void
mdi_pi_client_link_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (struct mdi_pathinfo));
}

/*
 * mdiclient_paths()
 *
 * Given a path, walk through mdi_pathinfo client links.
 */
/* ARGUSED */
int
mdiclient_paths(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int status;
	if (argc != 0)
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC)) {
		mdb_warn("Address needs to be specified");
		return (DCMD_ERR);
	}
	status =
	    mdb_pwalk_dcmd("mdipi_client_list", "mdipi", argc, argv, addr);
	return (status);
}

/* mdi_pathinfo phci walker */
int
mdi_pi_phci_link_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL) {
		mdb_warn("Address is required");
		return (WALK_ERR);
	}
	wsp->walk_data = mdb_alloc(sizeof (struct mdi_pathinfo), UM_SLEEP);
	firstaddr = wsp->walk_addr;
	return (WALK_NEXT);
}

int
mdi_pi_phci_link_walk_step(mdb_walk_state_t *wsp)
{
	int status;
	static int	counts = 0;

	if (firstaddr == wsp->walk_addr && counts != 0) {
		counts = 0;
		return (WALK_DONE);
	}
	if (wsp->walk_addr == NULL) {
		counts = 0;
		return (WALK_DONE);
	}
	if (mdb_vread(wsp->walk_data, sizeof (struct mdi_pathinfo),
	    wsp->walk_addr) == -1) {
		mdb_warn("failed to read mdi_pathinfo at %p", wsp->walk_addr);
		return (WALK_DONE);
	}
	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);
	wsp->walk_addr = (uintptr_t)
	    (((struct mdi_pathinfo *)wsp->walk_data)->pi_phci_link);
	counts++;
	return (status);
}

void
mdi_pi_phci_link_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (struct mdi_pathinfo));
}

/*
 * mdiphci_paths()
 *
 * Given a path, walk through mdi_pathinfo phci links.
 */
int
mdiphci_paths(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int status;
	if (argc != 0)
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC)) {
		mdb_warn("Address needs to be specified");
		return (DCMD_ERR);
	}
	status =
	    mdb_pwalk_dcmd("mdipi_phci_list", "mdipi", argc, argv, addr);
	return (status);
}

/* mdi_phci walker */
int
mdi_phci_ph_next_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL) {
		mdb_warn("Address is required");
		return (WALK_ERR);
	}
	wsp->walk_data = mdb_alloc(sizeof (struct mdi_phci), UM_SLEEP);
	firstaddr = wsp->walk_addr;
	return (WALK_NEXT);
}

int
mdi_phci_ph_next_walk_step(mdb_walk_state_t *wsp)
{
	int status;
	static int counts = 0;

	if (firstaddr == wsp->walk_addr && counts != 0) {
		counts = 0;
		return (WALK_DONE);
	}
	if (wsp->walk_addr == NULL) {
		counts = 0;
		return (WALK_DONE);
	}
	if (mdb_vread(wsp->walk_data, sizeof (struct mdi_phci), wsp->walk_addr)
	    == -1) {
		mdb_warn("failed to read mdi_phci at %p", wsp->walk_addr);
		return (WALK_DONE);
	}
	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);
	wsp->walk_addr = (uintptr_t)
	    (((struct mdi_phci *)wsp->walk_data)->ph_next);
	counts++;
	return (status);
}

void
mdi_phci_ph_next_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (struct mdi_phci));
}

/*
 * mdiphcis()
 *
 * Given a phci, walk through mdi_phci ph_next links.
 */
int
mdiphcis(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int status;
	if (argc != 0)
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC)) {
		mdb_warn("Address needs to be specified");
		return (DCMD_ERR);
	}
	status =
	    mdb_pwalk_dcmd("mdiphci_list", "mdiphci", argc, argv, addr);
	return (status);
}
