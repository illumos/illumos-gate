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

#include <mdb/mdb_modapi.h>

#include <sys/types.h>
#include <sys/uio.h>
#include <sys/vnode.h>
#include <sys/fs/ufs_log.h>
#include "ufs_cmds.h"


typedef struct ufslogmap_walk_data {
	mapentry_t me;
	mapentry_t *start_addr;
	mapentry_t *prev_addr;
} ufslogmap_walk_data_t;

/*
 * Ensure we are started with a user specified address.
 * We also allocate a ufslogmap_walk_data_t for storage,
 * and save this using the walk_data pointer.
 */
int
ufslogmap_walk_init(mdb_walk_state_t *wsp)
{
	ufslogmap_walk_data_t *uw;

	if (wsp->walk_addr == 0) {
		mdb_warn("must specify an address\n");
		return (WALK_ERR);
	}

	uw = mdb_zalloc(sizeof (ufslogmap_walk_data_t), UM_SLEEP | UM_GC);

	uw->start_addr = (mapentry_t *)wsp->walk_addr;
	wsp->walk_data = uw;
	return (WALK_NEXT);
}

/*
 * Routine to step through one element of the list.
 */
int
ufslogmap_walk_step(mdb_walk_state_t *wsp)
{
	ufslogmap_walk_data_t *uw = wsp->walk_data;
	uintptr_t walk_addr = wsp->walk_addr;

	/*
	 * Read the mapentry at the current walk address
	 */
	if (mdb_vread(&uw->me, sizeof (mapentry_t), walk_addr) == -1) {
		mdb_warn("failed to read mapentry_t at %p", walk_addr);
		return (WALK_DONE);
	}

	/*
	 * Check for empty list.
	 */
	if (uw->me.me_next == uw->me.me_prev) {
		return (WALK_DONE);
	}

	/*
	 * Check for end of list.
	 */
	if (uw->me.me_next == uw->start_addr) {
		return (WALK_DONE);
	}

	/*
	 * Check for proper linkage
	 */
	if (uw->prev_addr && (uw->me.me_prev != uw->prev_addr)) {
		mdb_warn("invalid linkage mapentry_t at %p", walk_addr);
		return (WALK_DONE);
	}
	uw->prev_addr = (mapentry_t *)walk_addr;

	/*
	 * Save next address and call callback with current address
	 */
	wsp->walk_addr = (uintptr_t)uw->me.me_next;
	return (wsp->walk_callback(walk_addr, wsp->walk_data,
	    wsp->walk_cbdata));
}

static const char *
delta2str(delta_t delta_type)
{
	switch (delta_type) {
		case DT_NONE: return ("none");
		case DT_SB: return ("sb");
		case DT_CG: return ("cg");
		case DT_SI: return ("si");
		case DT_AB: return ("ab");
		case DT_ABZERO: return ("abzero");
		case DT_DIR: return ("dir");
		case DT_INODE: return ("inode");
		case DT_FBI: return ("fbi");
		case DT_QR: return ("quota");
		case DT_COMMIT: return ("commit");
		case DT_CANCEL: return ("cancel");
		case DT_BOT: return ("trans");
		case DT_EOT: return ("etrans");
		case DT_UD: return ("udata");
		case DT_SUD: return ("sudata");
		case DT_SHAD: return ("shadow");
		default: return ("???");
	}
}

/* ARGSUSED */
int
mapentry_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mapentry_t me;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<u>%?s %6s %8s %8s %s%</u>\n",
		    "ADDR", "TYPE", "SIZE", "TRANS", "HANDLER");
	}

	if (mdb_vread(&me, sizeof (me), addr) == -1) {
		mdb_warn("couldn't read ufslog mapentry at %p", addr);
		return (DCMD_ABORT);
	}

	/*
	 * Validate mapentry
	 */
	if (me.me_delta.d_typ >= DT_MAX) {
		mdb_warn("Invalid delta type for mapentry at %p", addr);
		return (DCMD_ABORT);
	}

	mdb_printf("%0?p %6s %8x %8x %a\n",
	    addr,
	    delta2str(me.me_delta.d_typ),
	    me.me_delta.d_nb,
	    me.me_tid,
	    me.me_func);

	return (DCMD_OK);
}

typedef struct {
	uint64_t nentries;	/* number of mapentries */
	uint64_t totalsize;	/* total number of bytes */
	uint32_t transid;	/* first transaction id */
	int transdiff;		/* transaction different */
	uint32_t delta_cnt[DT_MAX]; /* count of each delta */
	uint64_t delta_sum[DT_MAX]; /* total number of bytes for delta */
} mapstats_t;

/* ARGSUSED */
int
mapadd(uintptr_t *addr, ufslogmap_walk_data_t *uw, mapstats_t *msp)
{
	if (msp->nentries == 0) {
		msp->transid = uw->me.me_tid;
	} else {
		if (msp->transid != uw->me.me_tid) {
			msp->transdiff = TRUE;
		}
	}
	msp->nentries++;
	msp->totalsize += uw->me.me_nb;
	if (uw->me.me_dt >= DT_MAX) {
		mdb_warn("Invalid delta type for mapentry at %p", addr);
	} else {
		msp->delta_cnt[uw->me.me_dt]++;
		msp->delta_sum[uw->me.me_dt] += uw->me.me_nb;
	}
	return (WALK_NEXT);
}

/*ARGSUSED*/
int
mapstats_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mapstats_t *msp;
	int i;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	msp = mdb_zalloc(sizeof (mapstats_t), UM_SLEEP | UM_GC);
	msp->transdiff = FALSE;

	if (mdb_pwalk("ufslogmap", (mdb_walk_cb_t)(uintptr_t)mapadd,
	    msp, addr) == -1) {
		mdb_warn("can't walk ufslogmap for stats");
		return (DCMD_ERR);
	}

	mdb_printf("Number of entries 0x%llx\n", msp->nentries);
	mdb_printf("Total map size 0x%llx\n", msp->totalsize);
	if (msp->transdiff) {
		mdb_printf("Multiple transactions\n");
	} else {
		mdb_printf("All the same transaction id = %d\n", msp->transid);
	}
	if (msp->nentries) {
		mdb_printf("%<u>delta  count(hex)  avsize(hex)%</u>\n");
		for (i = 0; i < DT_MAX; i++) {
			if (msp->delta_cnt[i]) {
				mdb_printf("%6s %10X %10X\n",
				    delta2str(i), msp->delta_cnt[i],
				    msp->delta_sum[i] / msp->delta_cnt[i]);
			}
		}
	}
	return (DCMD_OK);
}
