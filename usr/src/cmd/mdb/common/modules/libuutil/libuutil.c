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

#include <mdb/mdb_modapi.h>

#include <pthread.h>
#include <stddef.h>

#include <libuutil.h>
#include <libuutil_impl.h>

/*ARGSUSED*/
static int
uutil_status(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	pthread_t uu_panic_thread = 0;

	if ((flags & DCMD_ADDRSPEC) || argc != 0)
		return (DCMD_USAGE);

	if (mdb_readvar(&uu_panic_thread, "uu_panic_thread") == -1) {
		mdb_warn("unable to read uu_panic_thread");
	}

	if (uu_panic_thread != 0) {
		mdb_printf("thread %d uu_panicked\n", uu_panic_thread);
	}

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
uutil_listpool(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uu_list_pool_t ulp;

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("uu_list_pool", "uu_list_pool", argc,
		    argv) == -1) {
			mdb_warn("can't walk uu_list_pool");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (argc != 0)
		return (DCMD_USAGE);

	if (DCMD_HDRSPEC(flags))
		mdb_printf("%-?s %-30s %?s %5s\n",
		    "ADDR", "NAME", "COMPARE", "FLAGS");

	if (mdb_vread(&ulp, sizeof (uu_list_pool_t), addr) == -1) {
		mdb_warn("failed to read uu_list_pool\n");
		return (DCMD_ERR);
	}

	mdb_printf("%0?p %-30s %08x     %c\n", addr, ulp.ulp_name, ulp.ulp_cmp,
	    ulp.ulp_debug ? 'D' : ' ');

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
uutil_list(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uu_list_t ul;

	if (!(flags & DCMD_ADDRSPEC) || argc != 0)
		return (DCMD_USAGE);

	if (mdb_vread(&ul, sizeof (uu_list_t), addr) == -1) {
		mdb_warn("failed to read uu_list\n");
		return (DCMD_ERR);
	}

	if (DCMD_HDRSPEC(flags))
		mdb_printf("%-?s %-?s %-?s %6s %5s\n",
		    "ADDR", "POOL", "PARENT", "NODES", "FLAGS");

	mdb_printf("%0?p %0?p %0?p %6u    %c%c\n",
	    addr, ul.ul_pool, UU_PTR_DECODE(ul.ul_parent_enc),
	    ul.ul_numnodes, ul.ul_sorted ? 'S' : ' ', ul.ul_debug? 'D' : ' ');

	return (DCMD_OK);
}

typedef struct uutil_listpool_walk {
	uintptr_t ulpw_final;
	uintptr_t ulpw_current;
} uutil_listpool_walk_t;

int
uutil_listpool_walk_init(mdb_walk_state_t *wsp)
{
	uu_list_pool_t null_lpool;
	uutil_listpool_walk_t *ulpw;
	GElf_Sym sym;

	bzero(&null_lpool, sizeof (uu_list_pool_t));

	if (mdb_lookup_by_obj("libuutil.so.1", "uu_null_lpool", &sym) ==
	    -1) {
		mdb_warn("failed to find 'uu_null_lpool'\n");
		return (WALK_ERR);
	}

	if (mdb_vread(&null_lpool, sym.st_size, (uintptr_t)sym.st_value) ==
	    -1) {
		mdb_warn("failed to read data from 'uu_null_lpool' address\n");
		return (WALK_ERR);
	}

	ulpw = mdb_alloc(sizeof (uutil_listpool_walk_t), UM_SLEEP);

	ulpw->ulpw_final = (uintptr_t)null_lpool.ulp_prev;
	ulpw->ulpw_current = (uintptr_t)null_lpool.ulp_next;
	wsp->walk_data = ulpw;

	return (WALK_NEXT);
}

int
uutil_listpool_walk_step(mdb_walk_state_t *wsp)
{
	uu_list_pool_t ulp;
	uutil_listpool_walk_t *ulpw = wsp->walk_data;
	int status;

	if (mdb_vread(&ulp, sizeof (uu_list_pool_t),
	    ulpw->ulpw_current) == -1) {
		mdb_warn("failed to read uu_list_pool %x", ulpw->ulpw_current);
		return (WALK_ERR);
	}

	status = wsp->walk_callback(ulpw->ulpw_current, &ulp, wsp->walk_cbdata);

	if (ulpw->ulpw_current == ulpw->ulpw_final)
		return (WALK_DONE);

	ulpw->ulpw_current = (uintptr_t)ulp.ulp_next;

	return (status);
}

void
uutil_listpool_walk_fini(mdb_walk_state_t *wsp)
{
	uutil_listpool_walk_t *ulpw = wsp->walk_data;
	mdb_free(ulpw, sizeof (uutil_listpool_walk_t));
}

typedef struct uutil_list_walk {
	uintptr_t ulw_final;
	uintptr_t ulw_current;
} uutil_list_walk_t;

int
uutil_list_walk_init(mdb_walk_state_t *wsp)
{
	uutil_list_walk_t *ulw;
	uu_list_pool_t ulp;

	if (mdb_vread(&ulp, sizeof (uu_list_pool_t), wsp->walk_addr) == -1) {
		mdb_warn("failed to read uu_list_pool_t at given address\n");
		return (WALK_ERR);
	}

	if (UU_LIST_PTR(ulp.ulp_null_list.ul_next_enc) ==
	    &((uu_list_pool_t *)wsp->walk_addr)->ulp_null_list)
		return (WALK_DONE);

	ulw = mdb_alloc(sizeof (uutil_list_walk_t), UM_SLEEP);

	ulw->ulw_final = (uintptr_t)UU_LIST_PTR(ulp.ulp_null_list.ul_prev_enc);
	ulw->ulw_current =
	    (uintptr_t)UU_LIST_PTR(ulp.ulp_null_list.ul_next_enc);
	wsp->walk_data = ulw;

	return (WALK_NEXT);
}

int
uutil_list_walk_step(mdb_walk_state_t *wsp)
{
	uu_list_t ul;
	uutil_list_walk_t *ulw = wsp->walk_data;
	int status;

	if (mdb_vread(&ul, sizeof (uu_list_t), ulw->ulw_current) == -1) {
		mdb_warn("failed to read uu_list %x", ulw->ulw_current);
		return (WALK_ERR);
	}

	status = wsp->walk_callback(ulw->ulw_current, &ul, wsp->walk_cbdata);

	if (ulw->ulw_current == ulw->ulw_final)
		return (WALK_DONE);

	ulw->ulw_current = (uintptr_t)UU_LIST_PTR(ul.ul_next_enc);

	return (status);
}

void
uutil_list_walk_fini(mdb_walk_state_t *wsp)
{
	uutil_list_walk_t *ulw = wsp->walk_data;
	mdb_free(ulw, sizeof (uutil_list_walk_t));
}

typedef struct uutil_list_node_walk {
	size_t ulnw_offset;
	uintptr_t ulnw_final;
	uintptr_t ulnw_current;
	void *ulnw_buf;
	size_t ulnw_bufsz;
} uutil_list_node_walk_t;

int
uutil_list_node_walk_init(mdb_walk_state_t *wsp)
{
	uutil_list_node_walk_t *ulnw;
	uu_list_t ul;
	uu_list_pool_t ulp;

	if (mdb_vread(&ul, sizeof (uu_list_t), wsp->walk_addr) == -1) {
		mdb_warn("failed to read uu_list_t at given address\n");
		return (WALK_ERR);
	}

	if (mdb_vread(&ulp, sizeof (uu_list_pool_t), (uintptr_t)ul.ul_pool) ==
	    -1) {
		mdb_warn("failed to read supporting uu_list_pool_t\n");
		return (WALK_ERR);
	}

	ulnw = mdb_alloc(sizeof (uutil_list_node_walk_t), UM_SLEEP);

	ulnw->ulnw_offset = ul.ul_offset;
	ulnw->ulnw_final = wsp->walk_addr + offsetof(uu_list_t, ul_null_node);
	ulnw->ulnw_current = (uintptr_t)ul.ul_null_node.uln_next;
	ulnw->ulnw_buf = mdb_alloc(ulp.ulp_objsize, UM_SLEEP);
	ulnw->ulnw_bufsz = ulp.ulp_objsize;

	wsp->walk_data = ulnw;

	return (WALK_NEXT);
}

int
uutil_list_node_walk_step(mdb_walk_state_t *wsp)
{
	uu_list_node_impl_t uln;
	uutil_list_node_walk_t *ulnw = wsp->walk_data;
	int status;
	uintptr_t diff;

	if (ulnw->ulnw_current == ulnw->ulnw_final)
		return (WALK_DONE);

	if (mdb_vread(&uln, sizeof (uu_list_node_impl_t), ulnw->ulnw_current) ==
	    -1) {
		mdb_warn("failed to read uu_list_node %x", ulnw->ulnw_current);
		return (WALK_ERR);
	}

	diff = ulnw->ulnw_current - ulnw->ulnw_offset;

	if (mdb_vread(ulnw->ulnw_buf, ulnw->ulnw_bufsz, diff) == -1) {
		mdb_warn("failed to read enclosing structure %x", diff);
		return (WALK_ERR);
	}
	/*
	 * Correct for offset; we return the address of the included structure.
	 */
	status = wsp->walk_callback(diff, ulnw->ulnw_buf, wsp->walk_cbdata);

	ulnw->ulnw_current = (uintptr_t)uln.uln_next;

	return (status);
}

void
uutil_list_node_walk_fini(mdb_walk_state_t *wsp)
{
	uutil_list_node_walk_t *ulnw = wsp->walk_data;

	mdb_free(ulnw->ulnw_buf, ulnw->ulnw_bufsz);
	mdb_free(ulnw, sizeof (uutil_list_node_walk_t));
}

static const mdb_dcmd_t dcmds[] = {
	{ "uutil_status", NULL, "libuutil status summary", uutil_status },
	{ "uu_list_pool", NULL, "display uu_list_pool information",
		uutil_listpool },
	{ "uu_list", NULL, "display uu_list information",
		uutil_list },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "uu_list_pool", "walk uu_list_pools",
		uutil_listpool_walk_init, uutil_listpool_walk_step,
		uutil_listpool_walk_fini },
	{ "uu_list", "given a uu_list_pool, walk its uu_lists",
		uutil_list_walk_init, uutil_list_walk_step,
		uutil_list_walk_fini },
	{ "uu_list_node",
		"given a uu_list, walk its nodes, returning container addr",
		uutil_list_node_walk_init, uutil_list_node_walk_step,
		uutil_list_node_walk_fini },
	{ NULL }
};

static const mdb_modinfo_t modinfo = {
	MDB_API_VERSION, dcmds, walkers
};

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
