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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mdinclude.h"


typedef struct unit_data {
	int	nunits;
	int	do_all;
	int	setno;
} unit_data_t;

/*
 * walk the units
 */
/* ARGSUSED */
int
units_walk_init(mdb_walk_state_t *wsp)
{
	uintptr_t	addr;
	int		i;

	snarf_sets();
	wsp->walk_data = mdb_alloc(sizeof (unit_data_t), UM_SLEEP);
	/*
	 * walk_data contains the following information:
	 *	 nunits : the number of units of the set we've printed out.
	 *	 setno: set number we're printing out the information from.
	 *	 do_all: print all the sets on the system or not.
	 */
	((unit_data_t *)wsp->walk_data)->nunits = 0;
	if (wsp->walk_addr == NULL) {
		/* if no address is specified, walk all units of all sets */
		mdb_printf("Units for set number 0\n");
		addr = (uintptr_t)mdset[0].s_un;
		wsp->walk_addr = addr;
		((unit_data_t *)wsp->walk_data)->setno = 0;
		((unit_data_t *)wsp->walk_data)->do_all = 1;
	} else {
		/* walk the specified set */
		((unit_data_t *)wsp->walk_data)->do_all = 0;
		for (i = 0; i < md_nsets; i++) {
			if (mdset[i].s_db == (void **)wsp->walk_addr) {
				wsp->walk_addr = (uintptr_t)mdset[i].s_un;
				((unit_data_t *)wsp->walk_data)->setno = i;
				return (WALK_NEXT);
			}
		}
	}
	return (WALK_NEXT);
}

int
units_walk_step(mdb_walk_state_t *wsp)
{
	int		status;
	unit_data_t	*un = (unit_data_t *)wsp->walk_data;
	void		**ptr;

	if (un->nunits >= md_nunits) {
		un->setno += 1;
		if ((un->setno < md_nsets) && (un->do_all == 1)) {
			un->nunits = 0;
			wsp->walk_addr = (uintptr_t)mdset[un->setno].s_un;
			if (wsp->walk_addr != NULL)
				mdb_printf("Units for set number %d\n",
				    un->setno);
		} else {
			return (WALK_DONE);
		}
	}

	if (wsp->walk_addr == NULL) {
		un->nunits = md_nunits;
		return (WALK_NEXT);
	}

	status = wsp->walk_callback(wsp->walk_addr, NULL, wsp->walk_cbdata);

	if (status != WALK_DONE) {
		ptr = (void **)wsp->walk_addr;
		ptr++;
		wsp->walk_addr = (uintptr_t)ptr;
		un->nunits += 1;
	}
	return (status);
}

void
units_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (unit_data_t));
}
