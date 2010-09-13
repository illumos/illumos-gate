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
 * Copyright 2000-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <mdb/mdb_modapi.h>
#include <sys/machelf.h>

#include <libproc.h>
#include <stdio.h>

#include "proc_kludges.h"

typedef struct prockuldge_mappings {
	struct ps_prochandle *pkm_Pr;

	uint_t pkm_idx;

	uint_t pkm_count;
	uint_t pkm_max;

	prmap_t *pkm_mappings;

	uint_t pkm_old_max;
	prmap_t *pkm_old_mappings;
} prockludge_mappings_t;

/* ARGSUSED */
static int
prockludge_mappings_iter(prockludge_mappings_t *pkm, const prmap_t *pmp,
    const char *object_name)
{
	if (pkm->pkm_count >= pkm->pkm_max) {
		int s = pkm->pkm_max ? pkm->pkm_max * 2 : 16;

		pkm->pkm_old_max = pkm->pkm_max;
		pkm->pkm_old_mappings = pkm->pkm_mappings;
		pkm->pkm_max = s;
		pkm->pkm_mappings = mdb_alloc(sizeof (prmap_t) * s, UM_SLEEP);

		bcopy(pkm->pkm_old_mappings, pkm->pkm_mappings,
		    sizeof (prmap_t) * pkm->pkm_old_max);

		mdb_free(pkm->pkm_old_mappings,
		    sizeof (prmap_t) * pkm->pkm_old_max);

		pkm->pkm_old_mappings = NULL;
		pkm->pkm_old_max = 0;
	}
	bcopy(pmp, &pkm->pkm_mappings[pkm->pkm_count++], sizeof (prmap_t));

	return (0);
}

int
prockludge_mappings_walk_init(mdb_walk_state_t *mws)
{
	struct ps_prochandle *Pr;
	int rc;

	prockludge_mappings_t *pkm;

	if (mdb_get_xdata("pshandle", &Pr, sizeof (Pr)) == -1) {
		mdb_warn("couldn't read pshandle xdata");
		return (WALK_ERR);
	}

	pkm = mdb_zalloc(sizeof (prockludge_mappings_t), UM_SLEEP);
	pkm->pkm_Pr = Pr;
	mws->walk_data = pkm;

	rc = Pmapping_iter(Pr, (proc_map_f *)prockludge_mappings_iter, pkm);
	if (rc != 0) {
		mdb_warn("Pmapping_iter failed");
		/* clean up */
		prockludge_mappings_walk_fini(mws);
		return (WALK_ERR);
	}
	return (WALK_NEXT);
}

int
prockludge_mappings_walk_step(mdb_walk_state_t *wsp)
{
	prockludge_mappings_t *pkm = wsp->walk_data;
	int status;

	if (pkm->pkm_idx >= pkm->pkm_count)
		return (WALK_DONE);

	status = wsp->walk_callback(0, &pkm->pkm_mappings[pkm->pkm_idx++],
	    wsp->walk_cbdata);

	return (status);
}

void
prockludge_mappings_walk_fini(mdb_walk_state_t *wsp)
{
	prockludge_mappings_t *pkm = wsp->walk_data;
	if (pkm != NULL) {
		if (pkm->pkm_old_mappings != NULL) {
			mdb_free(pkm->pkm_old_mappings,
			    sizeof (prmap_t) * pkm->pkm_old_max);
		}
		if (pkm->pkm_mappings &&
		    pkm->pkm_mappings != pkm->pkm_old_mappings) {
			mdb_free(pkm->pkm_mappings,
			    sizeof (prmap_t) * pkm->pkm_max);
		}
		mdb_free(pkm, sizeof (prockludge_mappings_t));
	}
}

static int add_count = 0;

void
prockludge_add_walkers(void)
{
	mdb_walker_t w;

	if (add_count++ == 0) {
		w.walk_name = KLUDGE_MAPWALK_NAME;
		w.walk_descr = "kludge: walk the process' prmap_ts";
		w.walk_init = prockludge_mappings_walk_init;
		w.walk_step = prockludge_mappings_walk_step;
		w.walk_fini = prockludge_mappings_walk_fini;
		w.walk_init_arg = NULL;

		if (mdb_add_walker(&w) == -1) {
			mdb_warn("unable to add walker "KLUDGE_MAPWALK_NAME);
		}
	}
}

void
prockludge_remove_walkers(void)
{
	if (--add_count == 0) {
		mdb_remove_walker(KLUDGE_MAPWALK_NAME);
	}
}
