/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */
/*
 * Copyright 2021 Tintri by DDN, Inc. All rights reserved.
 */

#include <sys/mdb_modapi.h>
#include <mdb/mdb_ctf.h>
#include <sys/types.h>
#include <sys/zone.h>
#include <rpc/svc.h>

#include "common.h"
#include "svc.h"

/*
 * svc_pool dcmd implementation
 */

static const char *
svc_idname(uint_t id)
{
	switch (id) {
	case NFS_SVCPOOL_ID:
		return ("NFS");
	case NLM_SVCPOOL_ID:
		return ("NLM");
	case NFS_CB_SVCPOOL_ID:
		return ("NFS_CB");
	default:
		return ("");
	}
}

static void
svc_print_pool(SVCPOOL *pool, uintptr_t addr)
{
	mdb_printf("SVCPOOL = %p -> POOL ID = %s(%d)\n", addr,
	    svc_idname(pool->p_id), pool->p_id);
	mdb_printf("Non detached threads    = %d\n", pool->p_threads);
	mdb_printf("Detached threads        = %d\n", pool->p_detached_threads);
	mdb_printf("Max threads             = %d\n", pool->p_maxthreads);
	mdb_printf("`redline'               = %d\n", pool->p_redline);
	mdb_printf("Reserved threads        = %d\n", pool->p_reserved_threads);
	mdb_printf("Thread lock             = %s\n",
	    common_mutex(&pool->p_thread_lock));

	mdb_printf("Asleep threads          = %d\n", pool->p_asleep);
	mdb_printf("Request lock            = %s\n",
	    common_mutex(&pool->p_req_lock));

	mdb_printf("Pending requests        = %d\n", pool->p_reqs);
	mdb_printf("Walking threads         = %d\n", pool->p_walkers);
	mdb_printf("Max requests from xprt  = %d\n", pool->p_max_same_xprt);
	mdb_printf("Stack size for svc_run  = %d\n", pool->p_stksize);
	mdb_printf("Creator lock            = %s\n",
	    common_mutex(&pool->p_creator_lock));

	mdb_printf("No of Master xprt's     = %d\n", pool->p_lcount);
	mdb_printf("rwlock for mxprtlist    = %s\n",
	    common_rwlock(&pool->p_lrwlock));
	mdb_printf("master xprt list ptr    = %p\n\n", pool->p_lhead);
}

int
svc_pool_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	SVCPOOL svcpool;
	uint_t opt_v = FALSE;
	int *pools;
	int count, i;

	if ((flags & DCMD_ADDRSPEC) == 0) {
		/* Walk through all svcpools in the global zone */
		if (mdb_walk_dcmd("svc_pool", "svc_pool", argc, argv) == -1) {
			mdb_warn("failed to walk svcpools");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	count = mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &opt_v, NULL);
	argc -= count;
	argv += count;

	pools = mdb_alloc(argc * sizeof (*pools), UM_SLEEP | UM_GC);
	for (i = 0; i < argc; i++) {
		const char *s;

		switch (argv[i].a_type) {
		case MDB_TYPE_STRING:
			s = argv[i].a_un.a_str;

			if (strcmp(s, "nfs") == 0)
				pools[i] = NFS_SVCPOOL_ID;
			else if (strcmp(s, "nlm") == 0)
				pools[i] = NLM_SVCPOOL_ID;
			else if (strcmp(s, "nfs_cb") == 0)
				pools[i] = NFS_CB_SVCPOOL_ID;
			else
				return (DCMD_USAGE);

			break;

		case MDB_TYPE_IMMEDIATE:
			pools[i] = (int)argv[i].a_un.a_val;
			break;

		default:
			return (DCMD_USAGE);
		}
	}

	if (mdb_vread(&svcpool, sizeof (svcpool), addr) == -1) {
		mdb_warn("failed to read svcpool");
		return (DCMD_ERR);
	}

	/*
	 * Make sure the svcpool is on the list (or the list is empty).
	 * If not, just return with DCMD_OK.
	 */
	for (i = 0; i < argc; i++) {
		if (svcpool.p_id == pools[i]) {
			argc = 0;
			break;
		}
	}
	if (argc != 0)
		return (DCMD_OK);

	/* Print the svcpool */
	svc_print_pool(&svcpool, addr);
	if (opt_v && svcpool.p_lhead && (mdb_pwalk_dcmd("svc_mxprt",
	    "svc_mxprt", 0, NULL, (uintptr_t)svcpool.p_lhead) == -1))
		return (DCMD_ERR);

	return (DCMD_OK);
}

void
svc_pool_help(void)
{
	mdb_printf(
	    "-v       display also the master xprts for the svcpools\n"
	    "poolid   either $[numeric] or verbose: nfs or nlm or nfs_cb\n"
	    "\n"
	    "If the poolid list is specified, only those svcpools are dumped\n"
	    "whose poolid is in the list.\n");
}

/*
 * svc_mxprt dcmd implementation
 */

static void
svc_print_masterxprt(SVCMASTERXPRT *xprt)
{
	mdb_printf("svcxprt_common structure:\n");
	mdb_printf("queue ptr               = %p\n", xprt->xp_wq);
	mdb_printf("cached cred for server  = %d\n", xprt->xp_cred);
	mdb_printf("transport type          = %d\n", xprt->xp_type);
	mdb_printf("TSDU or TIDU size       = %d\n", xprt->xp_msg_size);

	mdb_printf("address                 = %s\n",
	    common_netbuf_str(&xprt->xp_rtaddr));
	mdb_printf("Request queue head      = %p\n", xprt->xp_req_head);
	mdb_printf("Request queue tail      = %p\n", xprt->xp_req_tail);
	mdb_printf("Request lock address    = %s\n",
	    common_mutex(&xprt->xp_req_lock));

	mdb_printf("Current no of attached threads  = %d\n",
	    xprt->xp_threads);
	mdb_printf("Current no of detached threads  = %d\n",
	    xprt->xp_detached_threads);
	mdb_printf("Thread count lock address       = %s\n\n",
	    common_mutex(&xprt->xp_thread_lock));
}

int
svc_mxprt_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	SVCMASTERXPRT xprt;
	uint_t opt_w = FALSE;

	if (mdb_getopts(argc, argv,
	    'w', MDB_OPT_SETBITS, TRUE, &opt_w, NULL) != argc)
		return (DCMD_USAGE);

	if ((flags & DCMD_ADDRSPEC) == 0) {
		mdb_printf("requires address of SVCMASTERXPRT\n");
		return (DCMD_USAGE);
	}

	if (opt_w) {
		/* Walk through all xprts */
		if (mdb_pwalk_dcmd("svc_mxprt", "svc_mxprt", 0, NULL,
		    addr) == -1) {
			mdb_warn("failed to walk svc_mxprt");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (mdb_vread(&xprt, sizeof (xprt), addr) == -1) {
		mdb_warn("failed to read xprt");
		return (DCMD_ERR);
	}

	svc_print_masterxprt(&xprt);

	return (DCMD_OK);
}

void
svc_mxprt_help(void)
{
	mdb_printf(
	    "-w       walks along all master xprts in the list\n"
	    "\n"
	    "The following two commands are equivalent:\n"
	    "  ::svc_mxprt -w\n"
	    "  ::walk svc_mxprt|::svc_mxprt\n");
}

/*
 * svc_pool walker implementation
 */

static int
svc_get_pool(uintptr_t zone_addr, uintptr_t *svc_addr)
{
	mdb_ctf_id_t id;
	ulong_t offset;
	uintptr_t glob_addr;

	if (zoned_get_zsd(zone_addr, "svc_zone_key", &glob_addr) != DCMD_OK) {
		mdb_warn("failed to get zoned svc");
		return (WALK_ERR);
	}

	if (mdb_ctf_lookup_by_name("struct svc_globals", &id)) {
		mdb_warn("failed to look up type %s", "struct svc_globals");
		return (WALK_ERR);
	}

	if (mdb_ctf_offsetof(id, "svc_pools", &offset)) {
		mdb_warn("failed to get %s offset", "svc_pools");
		return (WALK_ERR);
	}

	offset /= NBBY;
	if (mdb_vread(svc_addr, sizeof (*svc_addr), glob_addr + offset) == -1) {
		mdb_warn("failed to read svc_pools address");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

int
svc_pool_walk_init(mdb_walk_state_t *wsp)
{
	/* Use global zone by default */
	if (wsp->walk_addr == 0) {
		/* wsp->walk_addr = global_zone */
		if (mdb_readvar(&wsp->walk_addr, "global_zone") == -1) {
			mdb_warn("failed to locate global_zone");
			return (WALK_ERR);
		}
	}

	/* put svcpool address of the zone into wsp->walk_addr */
	return (svc_get_pool(wsp->walk_addr, &wsp->walk_addr));
}

int
svc_pool_walk_step(mdb_walk_state_t *wsp)
{
	SVCPOOL pool;
	uintptr_t addr = wsp->walk_addr;

	if (addr == 0)
		return (WALK_DONE);

	if (mdb_vread(&pool, sizeof (pool), addr) == -1) {
		mdb_warn("failed to read SVCPOOL");
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)pool.p_next;
	return (wsp->walk_callback(addr, &pool, wsp->walk_cbdata));
}

/*
 * svc_mxprt walker implementation
 */

int
svc_mxprt_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == 0) {
		mdb_warn("global walk not supported");
		return (WALK_ERR);
	}

	wsp->walk_data = (void *)wsp->walk_addr;

	return (WALK_NEXT);
}

int
svc_mxprt_walk_step(mdb_walk_state_t *wsp)
{
	SVCMASTERXPRT xprt;
	uintptr_t addr = wsp->walk_addr;
	int status;

	if (mdb_vread(&xprt, sizeof (xprt), addr) == -1) {
		mdb_warn("can't read SVCMASTERXPRT");
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)xprt.xp_next;

	status = wsp->walk_callback(addr, &xprt, wsp->walk_cbdata);
	if (status != WALK_NEXT)
		return (status);

	return (((void *)wsp->walk_addr == wsp->walk_data) ? WALK_DONE
	    : WALK_NEXT);
}
