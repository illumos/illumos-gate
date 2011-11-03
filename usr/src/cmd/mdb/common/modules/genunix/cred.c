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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */

#include <mdb/mdb_modapi.h>
#include <sys/types.h>
#include <sys/cred_impl.h>
#include <sys/sid.h>

#include "cred.h"

#define	OPT_VERBOSE	1

static void print_ksid(const ksid_t *);

/*
 * dcmd ::cred - display a credential (cred_t)
 */
int
cmd_cred(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	credgrp_t cr_grps;
	cred_t	*cr;
	mdb_arg_t cmdarg;
	uint_t opts = FALSE;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, OPT_VERBOSE, &opts, NULL) != argc)
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC)) {
		return (DCMD_USAGE);
	}

	cr = mdb_alloc(sizeof (*cr), UM_SLEEP | UM_GC);
	if (mdb_vread(cr, sizeof (*cr), addr) == -1) {
		mdb_warn("error reading cred_t at %p", addr);
		return (DCMD_ERR);
	}

	if (cr->cr_grps == NULL) {
		bzero(&cr_grps, sizeof (cr_grps));
	} else {
		if (mdb_vread(&cr_grps, sizeof (cr_grps),
		    (uintptr_t)cr->cr_grps) == -1) {
			mdb_warn("error reading credgrp_t at %p",
			    cr->cr_grps);
			return (DCMD_ERR);
		}
	}

	if (opts & OPT_VERBOSE) {
		cmdarg.a_type = MDB_TYPE_STRING;
		cmdarg.a_un.a_str = "cred_t";
		(void) mdb_call_dcmd("print", addr, flags, 1, &cmdarg);
		cmdarg.a_un.a_str = "-v";

		mdb_printf("%<u>cr_grps:%</u>\n");
		mdb_inc_indent(4);
		if (cr->cr_grps == NULL) {
			mdb_printf("(null)\n");
		} else {
			(void) mdb_call_dcmd("credgrp",
			    (uintptr_t)cr->cr_grps, flags, 1, &cmdarg);
		}
		mdb_dec_indent(4);

		mdb_printf("%<u>cr_ksid:%</u>\n");
		mdb_inc_indent(4);
		if (cr->cr_ksid == NULL) {
			mdb_printf("(null)\n");
		} else {
			(void) mdb_call_dcmd("credsid",
			    (uintptr_t)cr->cr_ksid, flags, 1, &cmdarg);
		}
		mdb_dec_indent(4);

		return (DCMD_OK);
	}

	if (DCMD_HDRSPEC(flags))
		mdb_printf("%<u>%?s %8s %8s %8s %8s% %8s%</u>\n",
		    "ADDR", "UID", "GID", "RUID", "RGID", "#GRP(+SIDS)");

	mdb_printf("%0?p %8u %8u %8u %8u %4u%s\n", addr,
	    cr->cr_uid,  cr->cr_gid,
	    cr->cr_ruid, cr->cr_rgid,
	    cr_grps.crg_ngroups,
	    (cr->cr_ksid == NULL) ? "" : "+");

	return (DCMD_OK);
}

/*
 * dcmd ::credgrp - display cred_t groups
 */
int
cmd_credgrp(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	credgrp_t grps;
	gid_t gid;
	uint_t i, opts = FALSE;
	int rv = DCMD_OK;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, OPT_VERBOSE, &opts, NULL) != argc)
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC)) {
		return (DCMD_USAGE);
	}

	if (mdb_vread(&grps, sizeof (grps), addr) == -1) {
		mdb_warn("error reading credgrp_t at %p", addr);
		return (DCMD_ERR);
	}

	if (opts & OPT_VERBOSE) {
		mdb_printf("crg_ref = 0x%x\n", grps.crg_ref);
		mdb_printf("crg_ngroups = 0x%x\n", grps.crg_ngroups);
	}
	mdb_printf("crg_groups = [\n");

	addr += OFFSETOF(credgrp_t, crg_groups);
	mdb_inc_indent(4);
	for (i = 0; i < grps.crg_ngroups; i++, addr += sizeof (gid_t)) {
		if (mdb_vread(&gid, sizeof (gid), addr) == -1) {
			mdb_warn("error reading gid_t at %p", addr);
			rv = DCMD_ERR;
			break;
		}
		mdb_printf("\t%u,", gid);
	}
	mdb_dec_indent(4);
	mdb_printf("\n]\n");

	return (rv);
}

/*
 * dcmd ::credsid - display a credsid_t
 */
int
cmd_credsid(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	credsid_t kr;
	uint_t opts = FALSE;
	int rv = DCMD_OK;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, OPT_VERBOSE, &opts, NULL) != argc)
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC)) {
		return (DCMD_USAGE);
	}

	if (mdb_vread(&kr, sizeof (kr), addr) == -1) {
		mdb_warn("error reading credsid_t at %p", addr);
		return (DCMD_ERR);
	}

	if (opts & OPT_VERBOSE)
		mdb_printf("kr_ref = 0x%x\n", kr.kr_ref);

	mdb_printf("kr_sidx[USER]  = ");
	print_ksid(&kr.kr_sidx[KSID_USER]);

	mdb_printf("kr_sidx[GROUP] = ");
	print_ksid(&kr.kr_sidx[KSID_GROUP]);

	mdb_printf("kr_sidx[OWNER] = ");
	print_ksid(&kr.kr_sidx[KSID_OWNER]);

	mdb_printf("kr_sidlist = %p\n", kr.kr_sidlist);
	if (kr.kr_sidlist != NULL && (opts & OPT_VERBOSE) != 0) {
		mdb_printf("*kr_sidlist = {\n");
		mdb_inc_indent(4);
		rv = mdb_call_dcmd("ksidlist",
		    (uintptr_t)kr.kr_sidlist, flags, argc, argv);
		mdb_dec_indent(4);
		mdb_printf("}\n");
	}

	return (rv);
}

/*
 * dcmd ::ksidlist - display a ksidlist_t
 */
int
cmd_ksidlist(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	ksidlist_t ksl;
	ksid_t ks;
	uint_t i, opts = FALSE;
	int rv = DCMD_OK;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, OPT_VERBOSE, &opts, NULL) != argc)
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC)) {
		return (DCMD_USAGE);
	}

	if (mdb_vread(&ksl, sizeof (ksl), addr) == -1) {
		mdb_warn("error reading ksidlist_t at %p", addr);
		return (DCMD_ERR);
	}

	if (opts & OPT_VERBOSE) {
		mdb_printf("ksl_ref = 0x%x\n", ksl.ksl_ref);
		mdb_printf("ksl_nsid = 0x%x\n", ksl.ksl_nsid);
		mdb_printf("ksl_neid = 0x%x\n", ksl.ksl_neid);
	}

	mdb_printf("ksl_sids = [\n");
	addr += OFFSETOF(ksidlist_t, ksl_sids);
	mdb_inc_indent(4);
	for (i = 0; i < ksl.ksl_nsid; i++, addr += sizeof (ksid_t)) {
		if (mdb_vread(&ks, sizeof (ks), addr) == -1) {
			mdb_warn("error reading ksid_t at %p", addr);
			rv = DCMD_ERR;
			break;
		}
		print_ksid(&ks);
	}
	mdb_dec_indent(4);
	mdb_printf("]\n");

	return (rv);
}

static void
print_ksid(const ksid_t *ks)
{
	char str[80];
	ksiddomain_t kd;
	uintptr_t da, sa;

	/* in case of errors */
	strcpy(str, "(domain?)");

	da = (uintptr_t)ks->ks_domain;
	if (da == 0 || mdb_vread(&kd, sizeof (kd), da) < 0)
		bzero(&kd, sizeof (kd));
	sa = (uintptr_t)kd.kd_name;
	if (sa != 0)
		(void) mdb_readstr(str, sizeof (str), sa);

	mdb_printf("%s-%u,\n", str, ks->ks_rid);
}
