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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/tsol/tndb.h>
#include <sys/modhash_impl.h>

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ks.h>

#include "tsol.h"
#include "modhash.h"

/* ****************** tnrh ****************** */

typedef struct tnrh_walk_s {
	tnrhc_hash_t **hptr;
	int idx;
	tnrhc_hash_t *tnrhc_table[TSOL_MASK_TABLE_SIZE];
	tnrhc_hash_t *tnrhc_table_v6[TSOL_MASK_TABLE_SIZE_V6];
} tnrh_walk_t;

/*
 * Free the mdb storage pointed to by the given per-prefix table.
 */
static void
free_table(tnrhc_hash_t **table, int ntable)
{
	while (--ntable >= 0) {
		if (*table != NULL)
			mdb_free(*table, TNRHC_SIZE * sizeof (**table));
		table++;
	}
}

/*
 * Read in a list of per-prefix-length hash tables.  Allocate storage for the
 * hashes that are present.  On successful return, the table will contain
 * pointers to mdb-resident storage, not kernel addresses.  On failure, the
 * contents will not point to any mdb storage.
 */
static int
read_table(const char *symname, tnrhc_hash_t **table, int ntable)
{
	GElf_Sym tnrhc_hash;
	tnrhc_hash_t **hp;
	uintptr_t addr;

	if (mdb_lookup_by_name(symname, &tnrhc_hash) == -1) {
		mdb_warn("failed to read %s", symname);
		return (-1);
	}
	if (mdb_vread(table, ntable * sizeof (*table),
	    tnrhc_hash.st_value) == -1) {
		mdb_warn("can't read %s at %p", symname, tnrhc_hash.st_value);
		return (-1);
	}
	for (hp = table; hp < table + ntable; hp++) {
		if ((addr = (uintptr_t)*hp) != 0) {
			*hp = mdb_alloc(TNRHC_SIZE * sizeof (**hp), UM_SLEEP);
			if (mdb_vread(*hp, TNRHC_SIZE * sizeof (**hp),
			    addr) == -1) {
				mdb_warn("can't read %s[%d] at %p", symname,
				    hp - table, addr);
				free_table(table, (hp - table) + 1);
				return (-1);
			}
		}
	}
	return (0);
}

int
tnrh_walk_init(mdb_walk_state_t *wsp)
{
	tnrh_walk_t *twp;

	twp = mdb_alloc(sizeof (*twp), UM_SLEEP);

	if (read_table("tnrhc_table", twp->tnrhc_table,
	    TSOL_MASK_TABLE_SIZE) == -1) {
		mdb_free(twp, sizeof (*twp));
		return (WALK_ERR);
	}
	if (read_table("tnrhc_table_v6", twp->tnrhc_table_v6,
	    TSOL_MASK_TABLE_SIZE_V6) == -1) {
		free_table(twp->tnrhc_table, TSOL_MASK_TABLE_SIZE);
		mdb_free(twp, sizeof (*twp));
		return (WALK_ERR);
	}

	twp->hptr = twp->tnrhc_table;
	twp->idx = 0;
	wsp->walk_addr = 0;
	wsp->walk_data = twp;

	return (WALK_NEXT);
}

int
tnrh_walk_step(mdb_walk_state_t *wsp)
{
	tnrh_walk_t *twp = wsp->walk_data;
	tsol_tnrhc_t tnrhc;
	int status;

	while (wsp->walk_addr == 0) {
		if (*twp->hptr == NULL || twp->idx >= TNRHC_SIZE) {
			twp->hptr++;
			if (twp->hptr == twp->tnrhc_table +
			    TSOL_MASK_TABLE_SIZE)
				twp->hptr = twp->tnrhc_table_v6;
			else if (twp->hptr == twp->tnrhc_table_v6 +
			    TSOL_MASK_TABLE_SIZE_V6)
				return (WALK_DONE);
			twp->idx = 0;
		} else {
			wsp->walk_addr = (uintptr_t)(*twp->hptr)[twp->idx++].
			    tnrh_list;
		}
	}

	if (mdb_vread(&tnrhc, sizeof (tnrhc), wsp->walk_addr) == -1) {
		mdb_warn("can't read tsol_tnrhc_t at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	status = wsp->walk_callback(wsp->walk_addr, &tnrhc,
	    wsp->walk_cbdata);

	wsp->walk_addr = (uintptr_t)tnrhc.rhc_next;
	return (status);
}

void
tnrh_walk_fini(mdb_walk_state_t *wsp)
{
	tnrh_walk_t *twp = wsp->walk_data;

	free_table(twp->tnrhc_table, TSOL_MASK_TABLE_SIZE);
	free_table(twp->tnrhc_table_v6, TSOL_MASK_TABLE_SIZE_V6);
	mdb_free(twp, sizeof (*twp));
}

/* ****************** tnrhtp ****************** */

typedef struct tnrhtp_walk_data_s {
	int (*old_callback)(uintptr_t, const void *, void *);
	void *old_cbdata;
} tnrhtp_walk_data_t;

/* ARGSUSED */
static int
tnrhtp_walk_callback(uintptr_t addr, const void *data, void *private)
{
	const struct mod_hash_entry *mhe = data;
	tnrhtp_walk_data_t *twd = private;
	tsol_tpc_t tpc;

	if (mdb_vread(&tpc, sizeof (tpc), (uintptr_t)mhe->mhe_val) == -1) {
		mdb_warn("failed to read tsol_tpc_t at %p", mhe->mhe_val);
		return (WALK_ERR);
	} else {
		return (twd->old_callback((uintptr_t)mhe->mhe_val, &tpc,
		    twd->old_cbdata));
	}
}

int
tnrhtp_walk_init(mdb_walk_state_t *wsp)
{
	mod_hash_t *tpc_name_hash;

	if (mdb_readvar(&tpc_name_hash, "tpc_name_hash") == -1) {
		mdb_warn("failed to read tpc_name_hash");
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)tpc_name_hash;

	return (modent_walk_init(wsp));
}

int
tnrhtp_walk_step(mdb_walk_state_t *wsp)
{
	tnrhtp_walk_data_t twd;
	int retv;

	twd.old_callback = wsp->walk_callback;
	twd.old_cbdata = wsp->walk_cbdata;
	wsp->walk_callback = tnrhtp_walk_callback;
	wsp->walk_cbdata = &twd;

	retv = modent_walk_step(wsp);

	wsp->walk_callback = twd.old_callback;
	wsp->walk_cbdata = twd.old_cbdata;

	return (retv);
}

void
tnrhtp_walk_fini(mdb_walk_state_t *wsp)
{
	modent_walk_fini(wsp);
}
