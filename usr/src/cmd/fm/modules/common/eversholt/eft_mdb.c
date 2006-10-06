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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/mdb_modapi.h>

#include <lut.h>
#include <itree.h>

#define	LUT_SIZE_INIT	300
#define	LUT_SIZE_INCR	100

struct lut {
	struct lut *lut_left;
	struct lut *lut_right;
	uintptr_t lut_lhs;		/* search key */
	uintptr_t lut_rhs;		/* the datum */
};

struct lut_cp {
	uintptr_t lutcp_addr;
	struct lut lutcp_lut;
};

#define	LCPSZ	sizeof (struct lut_cp)

struct lut_dump_desc {
	struct lut_cp *ld_array;
	int ld_arraysz;
	int ld_nents;
};

static void
lut_dump_array_alloc(struct lut_dump_desc *lddp)
{
	struct lut_cp *new;

	if (lddp->ld_array == NULL) {
		lddp->ld_arraysz = LUT_SIZE_INIT;
		lddp->ld_array = mdb_zalloc(LUT_SIZE_INIT * LCPSZ, UM_SLEEP);
		return;
	}

	new = mdb_zalloc((lddp->ld_arraysz + LUT_SIZE_INCR) * LCPSZ, UM_SLEEP);
	bcopy(lddp->ld_array, new, lddp->ld_arraysz * LCPSZ);
	mdb_free(lddp->ld_array, lddp->ld_arraysz * LCPSZ);
	lddp->ld_array = new;
	lddp->ld_arraysz += LUT_SIZE_INCR;
}

static void
lut_dump_array_free(struct lut_dump_desc *lddp)
{
	if (lddp->ld_array != NULL) {
		mdb_free(lddp->ld_array, lddp->ld_arraysz * LCPSZ);
		lddp->ld_array = NULL;
	}
}

static void
lut_collect_addent(uintptr_t addr, struct lut *ent, struct lut_dump_desc *lddp)
{
	struct lut_cp *lcp;

	if (lddp->ld_nents == lddp->ld_arraysz)
		lut_dump_array_alloc(lddp);

	lcp = &lddp->ld_array[lddp->ld_nents++];

	lcp->lutcp_addr = addr;
	bcopy(ent, &lcp->lutcp_lut, sizeof (struct lut));
}

static int
eft_lut_walk(uintptr_t root, struct lut_dump_desc *lddp)
{
	struct lut lutent;

	if (root) {
		if (mdb_vread(&lutent, sizeof (struct lut), root) !=
		    sizeof (struct lut)) {
			mdb_warn("failed to read struct lut at %p", root);
			return (WALK_ERR);
		}

		if (eft_lut_walk((uintptr_t)lutent.lut_left, lddp) != WALK_NEXT)
			return (WALK_ERR);

		lut_collect_addent(root, &lutent, lddp);

		if (eft_lut_walk((uintptr_t)lutent.lut_right, lddp) !=
		    WALK_NEXT)
			return (WALK_ERR);
	}
	return (WALK_NEXT);
}

static int
lut_collect(uintptr_t addr, struct lut_dump_desc *lddp)
{
	lut_dump_array_alloc(lddp);

	if (eft_lut_walk(addr, lddp) != WALK_NEXT) {
		lut_dump_array_free(lddp);
		return (WALK_ERR);
	} else {
		return (WALK_NEXT);	/* caller must free dump array */
	}
}

static int
lut_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL) {
		mdb_warn("lut walker requires a lut table address\n");
		return (WALK_ERR);
	}

	wsp->walk_data = mdb_zalloc(sizeof (struct lut_dump_desc), UM_SLEEP);
	wsp->walk_arg = 0;

	if (lut_collect(wsp->walk_addr, wsp->walk_data) == WALK_NEXT) {
		return (WALK_NEXT);
	} else {
		mdb_warn("failed to suck in full lut\n");
		mdb_free(wsp->walk_data, sizeof (struct lut_dump_desc));
		return (WALK_ERR);
	}
}

static int
lut_walk_step(mdb_walk_state_t *wsp)
{
	struct lut_dump_desc *lddp = wsp->walk_data;
	int *ip = (int *)&wsp->walk_arg;
	struct lut_cp *lcp = &lddp->ld_array[*ip];

	if (*ip == lddp->ld_nents)
		return (WALK_DONE);

	++*ip;

	return (wsp->walk_callback(lcp->lutcp_addr, &lcp->lutcp_lut,
	    wsp->walk_cbdata));
}

static void
lut_walk_fini(mdb_walk_state_t *wsp)
{
	struct lut_dump_desc *lddp = wsp->walk_data;

	lut_dump_array_free(lddp);
	mdb_free(lddp, sizeof (struct lut_dump_desc));
}

static const mdb_walker_t walkers[] = {
	{ "lut", "walk a lookup table", lut_walk_init, lut_walk_step,
	    lut_walk_fini, NULL },
	{ NULL, NULL, NULL, NULL, NULL, NULL }
};

static const mdb_modinfo_t modinfo = { MDB_API_VERSION, NULL, walkers };

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
