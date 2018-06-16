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
 * Copyright 2018 Nexenta Systems, Inc. All rights reserved.
 */

/*
 * mdb module for libmlsvc, which contains interesting data structures
 * including: the share cache
 */

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ks.h>
#include <mdb/mdb_ctf.h>

#include <synch.h>
#include <smbsrv/hash_table.h>
#include <smbsrv/libsmb.h>
#include <smbsrv/smb_share.h>

#define	MLSVC_OBJNAME	"libmlsvc.so.1"
#define	MLSVC_SCOPE	MLSVC_OBJNAME "`"

#define	AFLAG		1
#define	VFLAG		2

typedef struct dump_shr_args {
	uint_t dsa_opts;
	uintptr_t dsa_hdl;
	smb_share_t dsa_shr;
} dump_shr_args_t;

/*ARGSUSED*/
static int
dump_shr_cb(uintptr_t addr, const void *data, void *varg)
{
	dump_shr_args_t *args = varg;
	const HT_ITEM *hi = data;
	smb_share_t *shr = &args->dsa_shr;

	if (hi->hi_data == NULL)
		return (WALK_NEXT);

	if ((hi->hi_flags & HT_DELETE) != 0 &&
	    (args->dsa_opts & AFLAG) == 0)
		return (WALK_NEXT);

	if (args->dsa_opts & VFLAG) {
		mdb_arg_t argv;
		int flags = DCMD_ADDRSPEC;

		argv.a_type = MDB_TYPE_STRING;
		argv.a_un.a_str = MLSVC_SCOPE "smb_share_t";
		/* Don't fail the walk if this fails. */
		mdb_printf("%-?p ", hi->hi_data);
		mdb_call_dcmd("print", (uintptr_t)hi->hi_data,
		    flags, 1, &argv);
	} else {
		if (mdb_vread(shr, sizeof (*shr),
		    (uintptr_t)hi->hi_data) == -1) {
			mdb_warn("failed to read %s at %p",
			    "smb_share_t", hi->hi_data);
			return (WALK_NEXT);
		}

		mdb_printf("%-?p ", hi->hi_data);
		mdb_printf("name=%s path=%s desc=\"%s\"\n",
		    shr->shr_name, shr->shr_path, shr->shr_cmnt);
	}

	return (WALK_NEXT);
}


/*
 * *************************** Top level dcmds ****************************
 */

typedef struct mdb_smb_shr_cache {
	HT_HANDLE	*sc_cache;
	rwlock_t	sc_cache_lck;
	mutex_t		sc_mtx;
	cond_t		sc_cv;
	uint32_t	sc_state;
	uint32_t	sc_nops;
} mdb_smb_shr_cache_t;


static void
smb_shr_cache_help(void)
{
	mdb_printf(
	    "Displays the list of shares in the smbd smb_shr_cache.\n"
	    "With -a, also show deleted entries.\n"
	    "With -v, print full smb_share_t objects.\n\n");
}

/*
 * ::smb_shr_cache
 */
/*ARGSUSED*/
static int
smb_shr_cache_dcmd(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	dump_shr_args_t *args;
	mdb_smb_shr_cache_t *ssc;

	args = mdb_zalloc(sizeof (*args), UM_SLEEP | UM_GC);

	if (mdb_getopts(argc, argv,
	    'a', MDB_OPT_SETBITS, AFLAG, &args->dsa_opts,
	    'v', MDB_OPT_SETBITS, VFLAG, &args->dsa_opts,
	    NULL) != argc)
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC)) {
		GElf_Sym	sym;

		/* Locate the shr hash head. */
		if (mdb_lookup_by_obj(MLSVC_OBJNAME, "smb_shr_cache", &sym)) {
			mdb_warn("failed to lookup `smb_shr_cache'\n");
			return (DCMD_ERR);
		}
		addr = sym.st_value;
	}

	ssc = mdb_zalloc(sizeof (*ssc), UM_SLEEP | UM_GC);
	if (mdb_ctf_vread(ssc, MLSVC_SCOPE "smb_shr_cache_t",
	    "mdb_smb_shr_cache_t", addr, 0) < 0) {
		mdb_warn("failed to read smb_shr_cache at %p", addr);
		return (DCMD_ERR);
	}

	/* Now walk HT_HANDLE *sc_cache */
	args->dsa_hdl = (uintptr_t)ssc->sc_cache;

	if (mdb_pwalk(MLSVC_SCOPE "smb_ht_walker",
	    dump_shr_cb, args, args->dsa_hdl) == -1) {
		mdb_warn("cannot walk smb_shr_cache list");
		return (DCMD_ERR);
	}
	return (DCMD_OK);
}



/*
 * MDB module linkage information:
 *
 * We declare a list of structures describing our dcmds, a list of structures
 * describing our walkers and a function named _mdb_init to return a pointer
 * to our module information.
 */
static const mdb_dcmd_t dcmds[] = {

	/* Avoiding name conflict with smbsrv`smb_shr_cache */
	{   "smbd_shr_cache",
	    "[-av]",
	    "print SMB share cache",
	    smb_shr_cache_dcmd,
	    smb_shr_cache_help },

	{ NULL }
};

int smb_ht_walk_init(mdb_walk_state_t *wsp);
int smb_ht_walk_step(mdb_walk_state_t *wsp);

static const mdb_walker_t walkers[] = {
	{   "smb_ht_walker",
	    "walk an smb_hash_t structure",
	    smb_ht_walk_init,
	    smb_ht_walk_step,
	    NULL,
	    NULL },
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
