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
#include <sys/zone.h>
#include <nfs/nfs4_kprot.h>
#include <nfs/nfs4_idmap_impl.h>

#include "idmap.h"
#include "common.h"

/*
 * nfs4_idmap dcmd implementation
 */

int
nfs4_idmap_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	nfsidmap_t idmap;
	char *s;

	if (argc > 0)
		return (DCMD_USAGE);

	if ((flags & DCMD_ADDRSPEC) == 0) {
		mdb_printf("requires address of nfsidmap_t\n");
		return (DCMD_USAGE);
	}

	if (mdb_vread(&idmap, sizeof (idmap), addr) == -1) {
		mdb_warn("unable to read nfsidmap_t");
		return (DCMD_ERR);
	}

	if (DCMD_HDRSPEC(flags))
		mdb_printf("%<b>%<u>%-20s %10s %-20s%</u>%</b>\n", "TimeStamp",
		    "Number", "String");

	s = mdb_alloc(idmap.id_str.utf8string_len + 1, UM_NOSLEEP | UM_GC);
	if (s == NULL || mdb_readstr(s, idmap.id_str.utf8string_len + 1,
	    (uintptr_t)idmap.id_str.utf8string_val) == -1)
		s = "??";

	mdb_printf("%-20Y %10i %s\n", idmap.id_time, idmap.id_no, s);

	return (DCMD_OK);
}

/*
 * nfs4_idmap_info dcmd implementation
 */

int
nfs4_idmap_info_dcmd(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	uint_t u2s, g2s, s2u, s2g;
	int i;

	if ((flags & DCMD_ADDRSPEC) == 0)
		addr = 0;

	u2s = g2s = s2u = s2g = argc == 0;

	for (i = 0; i < argc; i++) {
		const char *s;

		if (argv[i].a_type != MDB_TYPE_STRING)
			return (DCMD_USAGE);

		s = argv[i].a_un.a_str;

		if (strcmp(s, "u2s") == 0)
			u2s = TRUE;
		else if (strcmp(s, "g2s") == 0)
			g2s = TRUE;
		else if (strcmp(s, "s2u") == 0)
			s2u = TRUE;
		else if (strcmp(s, "s2g") == 0)
			s2g = TRUE;
		else
			return (DCMD_USAGE);
	}

	if (u2s) {
		mdb_printf("%<b>NFSv4 uid-to-string idmap cache:%</b>\n");
		mdb_pwalk_dcmd("nfs4_u2s", "nfs4_idmap", 0, NULL, addr);
	}

	if (g2s) {
		mdb_printf("%<b>NFSv4 gid-to-string idmap cache:%</b>\n");
		mdb_pwalk_dcmd("nfs4_g2s", "nfs4_idmap", 0, NULL, addr);
	}

	if (s2u) {
		mdb_printf("%<b>NFSv4 string-to-uid idmap cache:%</b>\n");
		mdb_pwalk_dcmd("nfs4_s2u", "nfs4_idmap", 0, NULL, addr);
	}

	if (s2g) {
		mdb_printf("%<b>NFSv4 string-to-gid idmap cache:%</b>\n");
		mdb_pwalk_dcmd("nfs4_s2g", "nfs4_idmap", 0, NULL, addr);
	}

	return (DCMD_OK);
}

void
nfs4_idmap_info_help(void)
{
	mdb_printf(
	    "u2s      display entries from NFSv4 uid-to-string idmap cache\n"
	    "g2s      display entries from NFSv4 gid-to-string idmap cache\n"
	    "s2u      display entries from NFSv4 string-to-uid idmap cache\n"
	    "s2g      display entries from NFSv4 string-to-gid idmap cache\n"
	    "\nWithout arguments display entries from all caches.\n");
}

/*
 * nfs4_u2s/nfs4_s2u/nfs4_g2s/nfs4_s2g walker implementation
 */

int
nfs4_idmap_walk_init(mdb_walk_state_t *wsp)
{
	uintptr_t table;
	hash_table_walk_arg_t *arg;
	int status;

	/* Use global zone by default */
	if (wsp->walk_addr == 0) {
		/* wsp->walk_addr = global_zone */
		if (mdb_readvar(&wsp->walk_addr, "global_zone") == -1) {
			mdb_warn("failed to locate global_zone");
			return (WALK_ERR);
		}
	}

	if (zoned_get_zsd(wsp->walk_addr, "nfsidmap_zone_key",
	    &wsp->walk_addr) != DCMD_OK) {
		mdb_warn("failed to get zoned idmap");
		return (WALK_ERR);
	}

	if (mdb_vread(&table, sizeof (table), wsp->walk_addr
	    + (uintptr_t)wsp->walk_arg + OFFSETOF(idmap_cache_info_t, table))
	    == -1) {
		mdb_warn("unable to read table pointer");
		return (WALK_ERR);
	}

	arg = mdb_alloc(sizeof (hash_table_walk_arg_t), UM_SLEEP);
	arg->array_addr = table;
	arg->array_len = NFSID_CACHE_ANCHORS;
	arg->head_size = sizeof (nfsidhq_t);
	arg->first_name = "hq_lru_forw";
	arg->first_offset = OFFSETOF(nfsidhq_t, hq_lru_forw);
	arg->member_type_name = "nfsidmap_t";
	arg->member_size = sizeof (nfsidmap_t);
	arg->next_offset = OFFSETOF(nfsidmap_t, id_forw);

	wsp->walk_arg = arg;

	status = hash_table_walk_init(wsp);
	if (status != WALK_NEXT)
		mdb_free(wsp->walk_arg, sizeof (hash_table_walk_arg_t));
	return (status);
}

void
nfs4_idmap_walk_fini(mdb_walk_state_t *wsp)
{
	hash_table_walk_fini(wsp);
	mdb_free(wsp->walk_arg, sizeof (hash_table_walk_arg_t));
}
