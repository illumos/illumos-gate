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
 *
 * Copyright 2019 Joyent, Inc.
 */

#include <sys/mdb_modapi.h>
#include <sys/kcpc.h>
#include <sys/cpc_impl.h>

#define	 KCPC_HASH_BUCKETS	(1l << KCPC_LOG2_HASH_BUCKETS)

/*
 * Assume 64-bit kernel address max is 100000000000 - 1.
 */
#ifdef _LP64
#define	ADDR_WIDTH 11
#else
#define	ADDR_WIDTH 8
#endif

struct cpc_ctx_aux {
	uintptr_t  cca_hash[KCPC_HASH_BUCKETS];
	int	   cca_bucket;
};

/*ARGSUSED*/
static int
cpc(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	kcpc_ctx_t	ctx;
	kcpc_set_t	set;
	kcpc_request_t	*reqs;
	uint64_t	*data;
	kcpc_attr_t	*attr;
	int		i;
	int		j;
	uint_t		opt_v = FALSE;

	if (mdb_getopts(argc, argv, 'v', MDB_OPT_SETBITS, TRUE, &opt_v, NULL) !=
	    argc)
		return (DCMD_USAGE);

	if ((flags & DCMD_ADDRSPEC) == 0) {
		/*
		 * We weren't given the address of any specific cpc ctx, so
		 * invoke the walker to find them all.
		 */
		mdb_walk_dcmd("cpc_ctx", "cpc", argc, argv);
		return (DCMD_OK);
	}

	if (mdb_vread(&ctx, sizeof (ctx), addr) == -1) {
		mdb_warn("failed to read kcpc_ctx_t at %p", addr);
		return (DCMD_ABORT);
	}

	if (mdb_vread(&set, sizeof (set), (uintptr_t)ctx.kc_set) == -1) {
		mdb_warn("failed to read kcpc_set_t at %p", ctx.kc_set);
		return (DCMD_ABORT);
	}

	reqs = mdb_alloc(set.ks_nreqs * sizeof (*reqs), UM_GC);
	data = mdb_alloc(set.ks_nreqs * sizeof (*data), UM_GC);

	if (mdb_vread(reqs, set.ks_nreqs * sizeof (*reqs),
	    (uintptr_t)set.ks_req) == -1) {
		mdb_warn("failed to read requests at %p", set.ks_req);
		return (DCMD_ABORT);
	}

	if (mdb_vread(data, set.ks_nreqs * sizeof (*data),
	    (uintptr_t)set.ks_data) == -1) {
		mdb_warn("failed to read set data at %p", set.ks_data);
		return (DCMD_ABORT);
	}

	if (DCMD_HDRSPEC(flags))
		mdb_printf("N PIC NDX %16s FLG %16s %*s EVENT\n", "VAL",
		    "PRESET", ADDR_WIDTH, "CFG");
	mdb_printf("-----------------------------------------------------------"
	    "---------------------\n");
	if (opt_v)
		mdb_printf("Set: %p\t%d requests. Flags = %x\n", ctx.kc_set,
		    set.ks_nreqs, set.ks_flags);

	for (i = 0; i < set.ks_nreqs; i++) {
		mdb_printf("%d %3d %3d %16llx %1s%1s%1s %16llx %8p %s\n", i,
		    reqs[i].kr_picnum, reqs[i].kr_index,
		    data[reqs[i].kr_index],
		    (reqs[i].kr_flags & CPC_OVF_NOTIFY_EMT)	? "O" : "",
		    (reqs[i].kr_flags & CPC_COUNT_USER)		? "U" : "",
		    (reqs[i].kr_flags & CPC_COUNT_SYSTEM)	? "S" : "",
		    reqs[i].kr_preset, reqs[i].kr_config,
		    reqs[i].kr_event);
		if (opt_v == 0)
			continue;
		if (reqs[i].kr_nattrs > 0) {
			attr = mdb_alloc(reqs[i].kr_nattrs * sizeof (*attr),
			    UM_GC);
			if (mdb_vread(attr, reqs[i].kr_nattrs * sizeof (*attr),
			    (uintptr_t)reqs[i].kr_attr) == -1) {
				mdb_warn("failed to read attributes at %p",
				    reqs[i].kr_attr);
				return (DCMD_ABORT);
			}
			for (j = 0; j < reqs[i].kr_nattrs; j++)
				mdb_printf("\t%s = %llx", attr[j].ka_name,
				    attr[j].ka_val);
			mdb_printf("\n");
		}
	}

	return (DCMD_OK);
}

static void
cpc_help(void)
{
	mdb_printf("Displays the contents of the CPC context at the supplied "
	    "address.  If no address is given, displays contents of all active "
	    "CPC contexts.\n");
	mdb_printf("Flag codes: \n"
	    "O = overflow notify     U = count user events     "
	    "S = count system events\n");
}


/*
 * Initialize the global walk by grabbing the hash table in the
 * cpc module.
 */
static int
cpc_ctx_walk_init(mdb_walk_state_t *wsp)
{
	struct cpc_ctx_aux *cca;

	if (wsp->walk_addr != 0) {
		mdb_warn("only global cpc_ctx walk supported\n");
		return (WALK_ERR);
	}

	cca = mdb_zalloc(sizeof (*cca), UM_SLEEP);

	if (mdb_readsym(&cca->cca_hash, sizeof (cca->cca_hash),
	    "kcpc_ctx_list") == -1) {
		mdb_warn("cannot read cpc_ctx hash table");
		mdb_free(cca, sizeof (*cca));
		return (WALK_ERR);
	}

	wsp->walk_data = cca;
	wsp->walk_addr = 0;
	return (WALK_NEXT);
}

static int
cpc_ctx_walk_step(mdb_walk_state_t *wsp)
{
	int status;
	kcpc_ctx_t ctx;
	struct cpc_ctx_aux *cca = wsp->walk_data;

	while (wsp->walk_addr == 0) {
		if (cca->cca_bucket == KCPC_HASH_BUCKETS)
			return (WALK_DONE);
		wsp->walk_addr = cca->cca_hash[cca->cca_bucket++];
	}

	if (mdb_vread(&ctx, sizeof (ctx), wsp->walk_addr) == -1) {
		mdb_warn("failed to read cpc_ctx at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	status = wsp->walk_callback(wsp->walk_addr, &ctx,
	    wsp->walk_cbdata);

	wsp->walk_addr = (uintptr_t)ctx.kc_next;
	return (status);
}

static void
cpc_ctx_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (struct cpc_ctx_aux));
}

static const mdb_walker_t walkers[] = {
	{ "cpc_ctx", "walk global list of cpc contexts",
		cpc_ctx_walk_init, cpc_ctx_walk_step, cpc_ctx_walk_fini },
	{ NULL }
};

static const mdb_dcmd_t dcmds[] = {
	{ "cpc", "?[-v]", "Display contents of CPC context", cpc, cpc_help },
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
