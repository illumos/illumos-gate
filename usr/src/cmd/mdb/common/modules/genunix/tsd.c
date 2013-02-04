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
 * Copyright (c) 2000-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */
/*
 * Copyright (c) 2012 by Delphix. All rights reserved.
 */

#include <sys/thread.h>
#include "tsd.h"

/*
 * Initialize the tsd walker by either using the given starting address,
 * or reading the value of the kernel's tsd_list pointer.
 */
int
tsd_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL &&
	    mdb_readvar(&wsp->walk_addr, "tsd_list") == -1) {
		mdb_warn("failed to read 'tsd_list'");
		return (WALK_ERR);
	}

	wsp->walk_data = mdb_alloc(sizeof (struct tsd_thread), UM_SLEEP);
	return (WALK_NEXT);
}

int
tsd_walk_step(mdb_walk_state_t *wsp)
{
	int status;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(wsp->walk_data,
	    sizeof (struct tsd_thread), wsp->walk_addr) == -1) {
		mdb_warn("failed to read tsd at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	wsp->walk_addr =
	    (uintptr_t)(((struct tsd_thread *)wsp->walk_data)->ts_next);
	return (status);
}

void
tsd_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (struct tsd_thread));
}

/*
 * Map from thread pointer to tsd pointer for given key
 */
int
ttotsd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	kthread_t thread, *t = &thread;
	struct tsd_thread tsdata, *ts = &tsdata;
	uintptr_t key = NULL;
	uintptr_t eladdr;
	void *element = NULL;

	if (mdb_getopts(argc, argv, 'k', MDB_OPT_UINTPTR, &key, NULL) != argc)
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC) || key == NULL)
		return (DCMD_USAGE);

	if (mdb_vread(t, sizeof (*t), addr) == -1) {
		mdb_warn("failed to read thread at %p", addr);
		return (DCMD_ERR);
	}

	if (t->t_tsd == NULL)
		goto out;

	if (mdb_vread(ts, sizeof (*ts), (uintptr_t)t->t_tsd) == -1) {
		mdb_warn("failed to read tsd at %p", t->t_tsd);
		return (DCMD_ERR);
	}

	if (key > ts->ts_nkeys)
		goto out;

	eladdr = (uintptr_t)(ts->ts_value + key - 1);
	if (mdb_vread(&element, sizeof (element), eladdr) == -1) {
		mdb_warn("failed to read t->t_tsd[%d] at %p", key - 1, eladdr);
		return (DCMD_ERR);
	}

out:
	if (element == NULL && (flags & DCMD_PIPE))
		return (DCMD_OK);

	mdb_printf("%p\n", element);
	return (DCMD_OK);
}

static int
tsdthr_match(uintptr_t addr, const kthread_t *t, uintptr_t tsdaddr)
{
	/*
	 * Allow for multiple matches, even though that "can't happen."
	 */
	if (tsdaddr == (uintptr_t)t->t_tsd)
		mdb_printf("%p\n", addr);
	return (WALK_NEXT);
}

/*
 * Given a tsd pointer, find the owning thread
 */
/*ARGSUSED*/
int
tsdtot(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (addr == 0 || argc != 0)
		return (DCMD_USAGE);
	if (mdb_walk("thread", (mdb_walk_cb_t)tsdthr_match, (void *)addr) == -1)
		return (DCMD_ERR);
	return (DCMD_OK);
}
