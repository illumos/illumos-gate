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
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <string.h>
#include <sys/modhash_impl.h>

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ks.h>

#include "modhash.h"

/* This is passed to the modent callback; allows caller to get context */
typedef struct modent_step_data_s {
	struct mod_hash_entry	msd_mhe;	/* must be first */
	int			msd_hash_index;
	int			msd_position;	/* entry position in chain */
	uintptr_t		msd_first_addr;	/* first address in chain */
} modent_step_data_t;

/* Context for a walk over a modhash (variable length) */
typedef struct hash_walk_s {
	modent_step_data_t	hwalk_msd;	/* current entry data */
	mod_hash_t		hwalk_hash;	/* always last (var. len) */
} hash_walk_t;

/* Computes number of bytes to allocate for hash_walk_t structure. */
#define	HW_SIZE(n)	(sizeof (modent_step_data_t) + MH_SIZE(n))

/* Used for decoding hash keys for display */
typedef struct hash_type_entry_s {
	const char *hte_type;		/* name of hash type for ::modent -t */
	const char *hte_comparator;	/* name of comparator function */
	void (*hte_format)(const mod_hash_key_t, char *, size_t);
} hash_type_entry_t;

static void format_strhash(const mod_hash_key_t, char *, size_t);
static void format_ptrhash(const mod_hash_key_t, char *, size_t);
static void format_idhash(const mod_hash_key_t, char *, size_t);
static void format_default(const mod_hash_key_t, char *, size_t);

static const hash_type_entry_t hte_table[] = {
	{ "str", "mod_hash_strkey_cmp", format_strhash },
	{ "ptr", "mod_hash_ptrkey_cmp", format_ptrhash },
	{ "id", "mod_hash_idkey_cmp", format_idhash },
	{ NULL, NULL, format_default }
};

static int modent_print(uintptr_t, int, uint_t, const hash_type_entry_t *,
    boolean_t, uint_t, uint_t);

/* The information used during a walk */
typedef struct mod_walk_data_s {
	const hash_type_entry_t	*mwd_hte;	/* pointer to entry type */
	int			mwd_main_flags;	/* ::modhash flags */
	int			mwd_flags;	/* DCMD_* flags for looping */
	uint_t			mwd_opt_e;	/* call-modent mode */
	uint_t			mwd_opt_c;	/* chain head only mode */
	uint_t			mwd_opt_h;	/* hash index output */
	boolean_t		mwd_opt_k_set;	/* key supplied */
	boolean_t		mwd_opt_v_set;	/* value supplied */
	uintptr_t		mwd_opt_k;	/* key */
	uintptr_t		mwd_opt_v;	/* value */
	int			mwd_maxposn;	/* len of longest chain - 1 */
	int			mwd_maxidx;	/* hash idx of longest chain */
	uintptr_t		mwd_maxaddr;	/* addr of 1st elem @ maxidx */
	uintptr_t		mwd_idxtoprint;	/* desired hash pos to print */
	uintptr_t		mwd_addr;	/* 1st elem addr @idxtoprint */
} mod_walk_data_t;

/*
 * Initialize a walk over all the modhashes in the system.
 */
int
modhash_walk_init(mdb_walk_state_t *wsp)
{
	mod_hash_t *mh_head;

	if (mdb_readvar(&mh_head, "mh_head") == -1) {
		mdb_warn("failed to read mh_head");
		return (WALK_ERR);
	}
	wsp->walk_addr = (uintptr_t)mh_head;

	return (WALK_NEXT);
}

/*
 * Step to the next modhash in the system.
 */
int
modhash_walk_step(mdb_walk_state_t *wsp)
{
	mod_hash_t mh;
	int status;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(&mh, sizeof (mh), wsp->walk_addr) == -1) {
		mdb_warn("failed to read mod_hash_t at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	status = wsp->walk_callback(wsp->walk_addr, &mh, wsp->walk_cbdata);

	wsp->walk_addr = (uintptr_t)mh.mh_next;

	return (status);
}

/*
 * Initialize a walk over the entries in a given modhash.
 */
int
modent_walk_init(mdb_walk_state_t *wsp)
{
	mod_hash_t mh;
	hash_walk_t *hwp;
	int retv;

	if (wsp->walk_addr == NULL) {
		mdb_warn("mod_hash_t address required\n");
		return (WALK_ERR);
	}

	if (mdb_vread(&mh, sizeof (mh), wsp->walk_addr) == -1) {
		mdb_warn("failed to read mod_hash_t at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	if (mh.mh_nchains <= 1) {
		mdb_warn("impossible number of chains in mod_hash_t at %p",
		    wsp->walk_addr);
		return (WALK_ERR);
	}

	/*
	 * If the user presents us with a garbage pointer, and thus the number
	 * of chains is just absurd, we don't want to bail out of mdb.  Fail to
	 * walk instead.
	 */
	hwp = mdb_alloc(HW_SIZE(mh.mh_nchains), UM_NOSLEEP);
	if (hwp == NULL) {
		mdb_warn("unable to allocate %#x bytes for mod_hash_t at %p",
		    HW_SIZE(mh.mh_nchains), wsp->walk_addr);
		return (WALK_ERR);
	}

	(void) memcpy(&hwp->hwalk_hash, &mh, sizeof (hwp->hwalk_hash));

	retv = mdb_vread(hwp->hwalk_hash.mh_entries + 1,
	    (mh.mh_nchains - 1) * sizeof (struct mod_hash_entry *),
	    wsp->walk_addr + sizeof (mh));

	if (retv == -1) {
		mdb_free(hwp, HW_SIZE(mh.mh_nchains));
		mdb_warn("failed to read %#x mod_hash_entry pointers at %p",
		    mh.mh_nchains - 1, wsp->walk_addr + sizeof (mh));
		return (WALK_ERR);
	}

	hwp->hwalk_msd.msd_hash_index = -1;
	hwp->hwalk_msd.msd_position = 0;
	hwp->hwalk_msd.msd_first_addr = NULL;

	wsp->walk_addr = NULL;
	wsp->walk_data = hwp;

	return (WALK_NEXT);
}

/*
 * Step to the next entry in the modhash.
 */
int
modent_walk_step(mdb_walk_state_t *wsp)
{
	hash_walk_t *hwp = wsp->walk_data;
	int status;

	while (wsp->walk_addr == NULL) {
		hwp->hwalk_msd.msd_position = 0;
		if (++hwp->hwalk_msd.msd_hash_index >=
		    hwp->hwalk_hash.mh_nchains)
			return (WALK_DONE);
		wsp->walk_addr = hwp->hwalk_msd.msd_first_addr =
		    (uintptr_t)hwp->hwalk_hash.mh_entries[
		    hwp->hwalk_msd.msd_hash_index];
	}

	if (mdb_vread(&hwp->hwalk_msd.msd_mhe, sizeof (hwp->hwalk_msd.msd_mhe),
	    wsp->walk_addr) == -1) {
		mdb_warn("failed to read mod_hash_entry at %p",
		    wsp->walk_addr);
		return (WALK_ERR);
	}

	status = wsp->walk_callback(wsp->walk_addr, &hwp->hwalk_msd,
	    wsp->walk_cbdata);

	hwp->hwalk_msd.msd_position++;
	wsp->walk_addr = (uintptr_t)hwp->hwalk_msd.msd_mhe.mhe_next;

	return (status);
}

/*
 * Clean up after walking the entries in a modhash.
 */
void
modent_walk_fini(mdb_walk_state_t *wsp)
{
	hash_walk_t *hwp = wsp->walk_data;

	mdb_free(hwp, HW_SIZE(hwp->hwalk_hash.mh_nchains));
	wsp->walk_data = NULL;
}

/*
 * Step to next entry on a hash chain.
 */
int
modchain_walk_step(mdb_walk_state_t *wsp)
{
	struct mod_hash_entry mhe;
	int status;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(&mhe, sizeof (mhe), wsp->walk_addr) == -1) {
		mdb_warn("failed to read mod_hash_entry at %p",
		    wsp->walk_addr);
		return (WALK_ERR);
	}

	status = wsp->walk_callback(wsp->walk_addr, &mhe, wsp->walk_cbdata);

	wsp->walk_addr = (uintptr_t)mhe.mhe_next;

	return (status);
}

/*
 * This is called by ::modhash (via a callback) when gathering data about the
 * entries in a given modhash.  It keeps track of the longest chain, finds a
 * specific entry (if the user requested one) and prints out a summary of the
 * entry or entries.
 */
static int
modent_format(uintptr_t addr, const void *data, void *private)
{
	const modent_step_data_t *msd = data;
	mod_walk_data_t *mwd = private;
	int retv = DCMD_OK;

	/* If this chain is longest seen, then save start of chain */
	if (msd->msd_position > mwd->mwd_maxposn) {
		mwd->mwd_maxposn = msd->msd_position;
		mwd->mwd_maxidx = msd->msd_hash_index;
		mwd->mwd_maxaddr = msd->msd_first_addr;
	}

	/* If the user specified a particular chain, then ignore others */
	if (mwd->mwd_idxtoprint != (uintptr_t)-1) {
		/* Save address of *first* entry */
		if (mwd->mwd_idxtoprint == msd->msd_hash_index)
			mwd->mwd_addr = msd->msd_first_addr;
		else
			return (retv);
	}

	/* If the user specified a particular key, ignore others. */
	if (mwd->mwd_opt_k_set &&
	    (uintptr_t)msd->msd_mhe.mhe_key != mwd->mwd_opt_k)
		return (retv);

	/* If the user specified a particular value, ignore others. */
	if (mwd->mwd_opt_v_set &&
	    (uintptr_t)msd->msd_mhe.mhe_val != mwd->mwd_opt_v)
		return (retv);

	/* If the user just wants the chain heads, skip intermediate nodes. */
	if (mwd->mwd_opt_c && msd->msd_position != 0)
		return (retv);

	/* If the user asked to have the entries printed, then do that. */
	if (mwd->mwd_opt_e) {
		/* If the output is to a pipeline, just print addresses */
		if (mwd->mwd_main_flags & DCMD_PIPE_OUT)
			mdb_printf("%p\n", addr);
		else
			retv = modent_print(addr, msd->msd_hash_index,
			    mwd->mwd_flags, mwd->mwd_hte, mwd->mwd_opt_h, 0, 0);
		mwd->mwd_flags &= ~DCMD_LOOPFIRST;
	}
	return (retv);
}

void
modhash_help(void)
{
	mdb_printf("Prints information about one or all mod_hash_t databases "
	    "in the system.\n"
	    "This command has three basic forms, summarized below.\n\n"
	    "  ::modhash [-t]\n  <addr>::modhash\n"
	    "  <addr>::modhash -e [-ch] [-k key] [-v val] [-i index]\n\n"
	    "In the first form, no address is provided, and a summary of all "
	    "registered\n"
	    "hashes in the system is printed; adding the '-t' option shows"
	    " the hash\n"
	    "type instead of the limits.  In the second form, the address of a"
	    " mod_hash_t\n"
	    "is provided, and the output is in a verbose format.  The final "
	    "form prints\n"
	    "the elements of the hash, optionally selecting just those with a "
	    "particular\n"
	    "key, value, and/or hash index, or just the chain heads (-c).  "
	    "The -h option\n"
	    "shows hash indices instead of addresses.\n");
}

int
modhash(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mod_hash_t mh;
	char name[256];
	int len;
	mod_walk_data_t mwd;
	uint_t opt_s = FALSE;
	uint_t opt_t = FALSE;
	char kfunc[MDB_SYM_NAMLEN];
	const hash_type_entry_t *htep;
	boolean_t elem_flags;

	(void) memset(&mwd, 0, sizeof (mwd));
	mwd.mwd_main_flags = flags;
	mwd.mwd_flags = DCMD_ADDRSPEC | DCMD_LOOP | DCMD_LOOPFIRST;
	mwd.mwd_maxposn = -1;
	mwd.mwd_idxtoprint = (uintptr_t)-1;

	len = mdb_getopts(argc, argv,
	    's', MDB_OPT_SETBITS, TRUE, &opt_s,
	    't', MDB_OPT_SETBITS, TRUE, &opt_t,
	    'c', MDB_OPT_SETBITS, TRUE, &mwd.mwd_opt_c,
	    'e', MDB_OPT_SETBITS, TRUE, &mwd.mwd_opt_e,
	    'h', MDB_OPT_SETBITS, TRUE, &mwd.mwd_opt_h,
	    'i', MDB_OPT_UINTPTR, &mwd.mwd_idxtoprint,
	    'k', MDB_OPT_UINTPTR_SET, &mwd.mwd_opt_k_set, &mwd.mwd_opt_k,
	    'v', MDB_OPT_UINTPTR_SET, &mwd.mwd_opt_v_set, &mwd.mwd_opt_v,
	    NULL);

	if (len < argc) {
		argv += len;
		if (argv->a_type == MDB_TYPE_STRING)
			mdb_warn("unexpected argument: %s\n",
			    argv->a_un.a_str);
		else
			mdb_warn("unexpected argument(s)\n");
		return (DCMD_USAGE);
	}

	/* true if any element-related flags are set */
	elem_flags = mwd.mwd_opt_c || mwd.mwd_opt_e || mwd.mwd_opt_h ||
	    mwd.mwd_opt_k_set || mwd.mwd_opt_v_set ||
	    mwd.mwd_idxtoprint != (uintptr_t)-1;

	if (!(flags & DCMD_ADDRSPEC)) {
		mdb_arg_t new_argv[1];

		if (elem_flags) {
			/*
			 * This isn't allowed so that the output doesn't become
			 * a confusing mix of hash table descriptions and
			 * element entries.
			 */
			mdb_warn("printing elements from all hashes is not "
			    "permitted\n");
			return (DCMD_USAGE);
		}
		/* we force short mode here, no matter what it says */
		new_argv[0].a_type = MDB_TYPE_STRING;
		new_argv[0].a_un.a_str = opt_t ? "-st" : "-s";
		if (mdb_walk_dcmd("modhash", "modhash", 1, new_argv) == -1) {
			mdb_warn("can't walk mod_hash structures");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (mwd.mwd_opt_e) {
		if (opt_s | opt_t) {
			mdb_warn("hash summary options not permitted when "
			    "displaying elements\n");
			return (DCMD_USAGE);
		}
	} else {
		if (elem_flags) {
			/*
			 * This isn't allowed so that the output doesn't become
			 * a confusing mix of hash table description and
			 * element entries.
			 */
			mdb_warn("printing elements requires -e\n");
			return (DCMD_USAGE);
		}
	}

	if (mdb_vread(&mh, sizeof (mh), addr) == -1) {
		mdb_warn("failed to read mod_hash_t at %p", addr);
		return (DCMD_ERR);
	}

	if (mwd.mwd_idxtoprint != (uintptr_t)-1 &&
	    mwd.mwd_idxtoprint >= mh.mh_nchains) {
		mdb_warn("mod_hash chain index %x out of range 0..%x\n",
		    mwd.mwd_idxtoprint, mh.mh_nchains - 1);
		return (DCMD_ERR);
	}

	if (DCMD_HDRSPEC(flags) && opt_s) {
		if (opt_t != 0) {
			mdb_printf("%<u>%?s %6s %5s %?s %s%</u>\n",
			    "ADDR", "CHAINS", "ELEMS", "TYPE", "NAME");
		} else {
			mdb_printf("%<u>%?s %6s %5s %6s %6s %s%</u>\n",
			    "ADDR", "CHAINS", "ELEMS", "MAXLEN", "MAXIDX",
			    "NAME");
		}
	}

	len = mdb_readstr(name, sizeof (name), (uintptr_t)mh.mh_name);
	if (len < 0)
		(void) strcpy(name, "??");

	if (mdb_lookup_by_addr((uintptr_t)mh.mh_keycmp, MDB_SYM_EXACT, kfunc,
	    sizeof (kfunc), NULL) == -1)
		kfunc[0] = '\0';
	for (htep = hte_table; htep->hte_type != NULL; htep++)
		if (strcmp(kfunc, htep->hte_comparator) == 0)
			break;
	mwd.mwd_hte = htep;

	if (!mwd.mwd_opt_e && !opt_s) {
		mdb_printf("mod_hash_t %?p %s%s:\n", addr, name,
		    len == sizeof (name) ? "..." : "");
		mdb_printf("\tKey comparator: %?p %s\n",
		    mh.mh_keycmp, kfunc);
		mdb_printf("\tType: %s\n",
		    htep->hte_type == NULL ? "unknown" : htep->hte_type);
		mdb_printf("\tSleep flag = %s, alloc failed = %#x\n",
		    mh.mh_sleep ? "true" : "false",
		    mh.mh_stat.mhs_nomem);
		mdb_printf("\tNumber of chains = %#x, elements = %#x\n",
		    mh.mh_nchains, mh.mh_stat.mhs_nelems);
		mdb_printf("\tHits = %#x, misses = %#x, dups = %#x\n",
		    mh.mh_stat.mhs_hit, mh.mh_stat.mhs_miss,
		    mh.mh_stat.mhs_coll);
	}
	if (mdb_pwalk("modent", modent_format, &mwd, addr) == -1) {
		mdb_warn("can't walk mod_hash entries");
		return (DCMD_ERR);
	}
	if (opt_s) {
		const char *tname;
		char tbuf[64];

		if (htep->hte_type == NULL) {
			(void) mdb_snprintf(tbuf, sizeof (tbuf), "%p",
			    mh.mh_keycmp);
			tname = tbuf;
		} else {
			tname = htep->hte_type;
		}
		mdb_printf("%?p %6x %5x ", addr, mh.mh_nchains,
		    mh.mh_stat.mhs_nelems);
		if (opt_t != 0) {
			mdb_printf("%?s", tname);
		} else {
			mdb_printf("%6x %6x", mwd.mwd_maxposn + 1,
			    mwd.mwd_maxidx);
		}
		mdb_printf(" %s%s\n", name, len == sizeof (name) ? "..." : "");
	} else if (!mwd.mwd_opt_e) {
		mdb_printf("\tMaximum chain length = %x (at index %x, first "
		    "entry %p)\n", mwd.mwd_maxposn + 1, mwd.mwd_maxidx,
		    mwd.mwd_maxaddr);
	}
	return (DCMD_OK);
}

static void
format_strhash(const mod_hash_key_t key, char *keystr, size_t keystrlen)
{
	int len;

	(void) mdb_snprintf(keystr, keystrlen, "%?p ", key);
	len = strlen(keystr);
	(void) mdb_readstr(keystr + len, keystrlen - len, (uintptr_t)key);
}

static void
format_ptrhash(const mod_hash_key_t key, char *keystr, size_t keystrlen)
{
	int len;

	(void) mdb_snprintf(keystr, keystrlen, "%?p ", key);
	len = strlen(keystr);
	(void) mdb_lookup_by_addr((uintptr_t)key, MDB_SYM_EXACT, keystr + len,
	    keystrlen - len, NULL);
}

static void
format_idhash(const mod_hash_key_t key, char *keystr, size_t keystrlen)
{
	(void) mdb_snprintf(keystr, keystrlen, "%?x", (uint_t)(uintptr_t)key);
}

static void
format_default(const mod_hash_key_t key, char *keystr, size_t keystrlen)
{
	(void) mdb_snprintf(keystr, keystrlen, "%?p", key);
}

void
modent_help(void)
{
	mdb_printf("Options are mutually exclusive:\n"
	    "  -t <type>  print key in symbolic form; <type> is one of str, "
	    "ptr, or id\n"
	    "  -v         print value pointer alone\n"
	    "  -k         print key pointer alone\n");
}

static int
modent_print(uintptr_t addr, int hidx, uint_t flags,
    const hash_type_entry_t *htep, boolean_t prtidx, uint_t opt_k,
    uint_t opt_v)
{
	char keystr[256];
	struct mod_hash_entry mhe;

	if (DCMD_HDRSPEC(flags) && opt_k == 0 && opt_v == 0) {
		mdb_printf("%<u>%?s %?s %?s%</u>\n",
		    prtidx ? "HASH_IDX" : "ADDR", "VAL", "KEY");
	}

	if (mdb_vread(&mhe, sizeof (mhe), addr) == -1) {
		mdb_warn("failed to read mod_hash_entry at %p", addr);
		return (DCMD_ERR);
	}

	if (opt_k) {
		mdb_printf("%p\n", mhe.mhe_key);
	} else if (opt_v) {
		mdb_printf("%p\n", mhe.mhe_val);
	} else {
		htep->hte_format(mhe.mhe_key, keystr, sizeof (keystr));
		if (prtidx)
			mdb_printf("%?x", hidx);
		else
			mdb_printf("%?p", addr);
		mdb_printf(" %?p %s\n", mhe.mhe_val, keystr);
	}

	return (DCMD_OK);
}

/*
 * This prints out a single mod_hash element, showing its value and its key.
 * The key is decoded based on the type of hash keys in use.
 */
int
modent(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	const char *opt_t = NULL;
	const hash_type_entry_t *htep;
	int len;
	uint_t opt_k = 0;
	uint_t opt_v = 0;

	if (!(flags & DCMD_ADDRSPEC)) {
		mdb_warn("address of mod_hash_entry must be specified\n");
		return (DCMD_ERR);
	}

	len = mdb_getopts(argc, argv,
	    't', MDB_OPT_STR, &opt_t,
	    'k', MDB_OPT_SETBITS, 1, &opt_k,
	    'v', MDB_OPT_SETBITS, 1, &opt_v,
	    NULL);

	/* options are mutually exclusive */
	if ((opt_k && opt_v) || (opt_t != NULL && (opt_k || opt_v)) ||
	    len < argc) {
		return (DCMD_USAGE);
	}

	for (htep = hte_table; htep->hte_type != NULL; htep++)
		if (opt_t != NULL && strcmp(opt_t, htep->hte_type) == 0)
			break;

	if (opt_t != NULL && htep->hte_type == NULL) {
		mdb_warn("unknown hash type %s\n", opt_t);
		return (DCMD_ERR);
	}

	return (modent_print(addr, 0, flags, htep, FALSE, opt_k, opt_v));
}
