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
 * Generic walker svm mddb directory block walker.
 */
int
mddb_db_walk_init(mdb_walk_state_t *wsp)
{

	/* Must have a start addr.  */
	if (wsp->walk_addr == NULL) {
		mdb_warn("start address required\n");
		return (WALK_ERR);
	}
	return (WALK_NEXT);
}


/*
 * svm mddb directory block walker step routine.
 */
int
mddb_db_walk_step(mdb_walk_state_t *wsp)
{
	mddb_db_t	db_entry;
	int		status;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(&db_entry, sizeof (mddb_db_t), wsp->walk_addr) == -1) {
		mdb_warn("failed to read mddb_db_t at %p",
		wsp->walk_addr);
		return (WALK_ERR);
	}

	status = wsp->walk_callback(wsp->walk_addr, (&db_entry)->db_next,
	    wsp->walk_cbdata);

	wsp->walk_addr = (uintptr_t)db_entry.db_next;

	return (status);
}
