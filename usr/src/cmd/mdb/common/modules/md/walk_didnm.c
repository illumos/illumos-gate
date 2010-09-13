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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mdinclude.h"

/*
 * walk the device id namespace
 */
int
didnamespace_walk_init(mdb_walk_state_t *wsp)
{
	uintptr_t	addr;

	snarf_sets();
	wsp->walk_data = mdb_alloc(sizeof (int), UM_SLEEP);
	/* walk_data will hold the set number of the set being printed */
	*((int *)wsp->walk_data) = 0;
	addr = (uintptr_t)mdset[0].s_did_nm;

	wsp->walk_addr = addr;
	return (WALK_NEXT);
}

int
didnamespace_walk_step(mdb_walk_state_t *wsp)
{
	int	status;
	struct nm_header_hdr	 hdr;

	if (wsp->walk_addr == NULL) {
		if (*((int *)wsp->walk_data) < md_nsets) {
			*((int *)wsp->walk_data) += 1;
			wsp->walk_addr =
			    (uintptr_t)mdset[*((int *)wsp->walk_data)].s_did_nm;
			if (wsp->walk_addr == NULL)
				return (WALK_NEXT);
		} else {
			return (WALK_DONE);
		}
	}

	mdb_printf("DID Namespace for set number %d\n",
	    *((int *)wsp->walk_data));
	if (mdb_vread(&hdr, sizeof (struct nm_header_hdr), wsp->walk_addr) !=
	    sizeof (struct nm_header_hdr)) {
		mdb_warn("failed to read nm_header_hdr at %p",
		    wsp->walk_addr);
		return (WALK_DONE);
	}



	status = wsp->walk_callback(wsp->walk_addr, (&hdr)->hh_header,
	    wsp->walk_cbdata);

	*((int *)wsp->walk_data) += 1;
	wsp->walk_addr = (uintptr_t)mdset[*((int *)wsp->walk_data)].s_did_nm;
	return (status);
}

void
didnamespace_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (int));
}
