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
#include <nfs/nfs4.h>
#include <nfs/nfs4_db_impl.h>
#include <limits.h>

#include "rfs4.h"
#include "common.h"

/*
 * rfs4_db dcmd implementation
 */

int
rfs4_db_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uintptr_t	glbls;
	uintptr_t	zonep;
	rfs4_database_t	rfs4_db;
	nfs_globals_t	nfsglbls;
	struct nfs4_srv	nfs4srv;

	if (argc > 0)
		return (DCMD_USAGE);


	if ((flags & DCMD_ADDRSPEC) != 0) {
		zonep = addr;
	} else {
		if (mdb_readsym(&zonep, sizeof (uintptr_t),
		    "global_zone") == -1) {
			mdb_warn("Failed to find global_zone");
			return (DCMD_ERR);
		}
	}

	if (zoned_get_nfs_globals(zonep, &glbls) != DCMD_OK) {
		mdb_warn("failed to get zoned specific NFS globals");
		return (DCMD_ERR);
	}

	if (mdb_vread(&nfsglbls, sizeof (nfs_globals_t), glbls) == -1) {
		mdb_warn("can't read zone globals");
		return (DCMD_ERR);
	}

	if (mdb_vread(&nfs4srv, sizeof (struct nfs4_srv),
	    (uintptr_t)nfsglbls.nfs4_srv) == -1) {
		mdb_warn("can't read NFS4 server structure");
		return (DCMD_ERR);
	}

	if (mdb_vread(&rfs4_db, sizeof (rfs4_database_t),
	    (uintptr_t)nfs4srv.nfs4_server_state) == -1) {
		mdb_warn("can't read NFS4 server state");
		return (DCMD_ERR);
	}

	if (mdb_pwalk_dcmd("rfs4_db_tbl", "rfs4_tbl", 0, NULL,
	    (uintptr_t)rfs4_db.db_tables) == -1) {
		mdb_warn("failed to walk tables");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

/*
 * rfs4_tbl dcmd implementation
 */

int
rfs4_tbl_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	rfs4_table_t tbl;
	char name[14];
	uint_t opt_v = FALSE;
	uint_t opt_w = FALSE;

	if ((flags & DCMD_ADDRSPEC) == 0) {
		mdb_printf("requires address of rfs4_table_t\n");
		return (DCMD_USAGE);
	}

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &opt_v,
	    'w', MDB_OPT_SETBITS, TRUE, &opt_w, NULL) != argc)
		return (DCMD_USAGE);

	if (opt_w) {
		mdb_arg_t arg;
		mdb_arg_t *argp = NULL;
		int n = 0;

		if (opt_v) {
			arg.a_type = MDB_TYPE_STRING;
			arg.a_un.a_str = "-v";
			argp = &arg;
			n = 1;
		}

		/* Walk through all tables */
		if (mdb_pwalk_dcmd("rfs4_db_tbl", "rfs4_tbl", n, argp, addr)
		    == -1) {
			mdb_warn("failed to walk tables\n");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (mdb_vread(&tbl, sizeof (tbl), addr) == -1) {
		mdb_warn("can't read rfs4_table_t");
		return (DCMD_ERR);
	}

	if (!opt_v && DCMD_HDRSPEC(flags)) {
		const size_t ptrsize = mdb_snprintf(NULL, 0, "%?p");
		size_t sz = ptrsize + 1 + sizeof (name) + 8 + 5 - 7;
		size_t i;

		mdb_printf("%<b>");
		for (i = 0; i < (sz + 1) / 2; i++)
			mdb_printf("-");
		mdb_printf(" Table ");
		for (i = 0; i < sz - (sz + 1) / 2; i++)
			mdb_printf("-");

		mdb_printf(" Bkt  ");

		sz = ptrsize + 5 + 5 - 9;

		for (i = 0; i < (sz + 1) / 2; i++)
			mdb_printf("-");
		mdb_printf(" Indices ");
		for (i = 0; i < sz - (sz + 1) / 2; i++)
			mdb_printf("-");
		mdb_printf("%</b>\n");

		mdb_printf("%<b>%<u>%-?s %-*s%-8s Cnt %</u> %<u>Cnt %</u> "
		    "%<u>%-?s Cnt  Max %</u>%</b>\n", "Address", sizeof (name),
		    "Name", "Flags", "Pointer");
	}

	if (mdb_readstr(name, sizeof (name), (uintptr_t)tbl.dbt_name) == -1) {
		mdb_warn("can't read dbt_name");
		return (DCMD_ERR);
	}
	mdb_printf("%?p %-*s%08x %04u %04u %?p %04u %04u\n", addr,
	    sizeof (name), name, tbl.dbt_debug, tbl.dbt_count, tbl.dbt_len,
	    tbl.dbt_indices, tbl.dbt_idxcnt, tbl.dbt_maxcnt);

	if (opt_v) {
		mdb_inc_indent(8);
		mdb_printf("db              = %p\n", tbl.dbt_db);
		mdb_printf("t_lock          = %s\n",
		    common_rwlock(tbl.dbt_t_lock));
		mdb_printf("lock            = %s\n",
		    common_mutex(tbl.dbt_lock));
		mdb_printf("id_space        = %p\n", tbl.dbt_id_space);
		mdb_printf("min_cache_time  = %lu\n", tbl.dbt_min_cache_time);
		mdb_printf("max_cache_time  = %lu\n", tbl.dbt_max_cache_time);
		mdb_printf("usize           = %u\n", tbl.dbt_usize);
		mdb_printf("maxentries      = %u\n", tbl.dbt_maxentries);
		mdb_printf("len             = %u\n", tbl.dbt_len);
		mdb_printf("count           = %u\n", tbl.dbt_count);
		mdb_printf("idxcnt          = %u\n", tbl.dbt_idxcnt);
		mdb_printf("maxcnt          = %u\n", tbl.dbt_maxcnt);
		mdb_printf("ccnt            = %u\n", tbl.dbt_ccnt);
		mdb_printf("indices         = %p\n", tbl.dbt_indices);
		mdb_printf("create          = %a\n", tbl.dbt_create);
		mdb_printf("destroy         = %a\n", tbl.dbt_destroy);
		mdb_printf("expiry          = %a\n", tbl.dbt_expiry);
		mdb_printf("mem_cache       = %p\n", tbl.dbt_mem_cache);
		mdb_printf("debug           = %08x\n", tbl.dbt_debug);
		mdb_printf("reaper_shutdown = %s\n\n",
		    tbl.dbt_reaper_shutdown ? "TRUE" : "FALSE");
		mdb_dec_indent(8);
	}

	return (DCMD_OK);
}

void
rfs4_tbl_help(void)
{
	mdb_printf(
	    "-v       display more details about the table\n"
	    "-w       walks along all tables in the list\n"
	    "\n"
	    "The following two commands are equivalent:\n"
	    "  ::rfs4_tbl -w\n"
	    "  ::walk rfs4_db_tbl|::rfs4_tbl\n");
}

/*
 * rfs4_tbl dcmd implementation
 */

int
rfs4_idx_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	rfs4_index_t idx;
	char name[19];
	uint_t opt_w = FALSE;

	if ((flags & DCMD_ADDRSPEC) == 0) {
		mdb_printf("requires address of rfs4_index_t\n");
		return (DCMD_USAGE);
	}

	if (mdb_getopts(argc, argv,
	    'w', MDB_OPT_SETBITS, TRUE, &opt_w, NULL) != argc)
		return (DCMD_USAGE);

	if (opt_w) {
		/* Walk through all tables */
		if (mdb_pwalk_dcmd("rfs4_db_idx", "rfs4_idx", 0, NULL, addr)
		    == -1) {
			mdb_warn("failed to walk indices");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (mdb_vread(&idx, sizeof (idx), addr) == -1) {
		mdb_warn("can't read rfs4_index_t");
		return (DCMD_ERR);
	}

	if (DCMD_HDRSPEC(flags))
		mdb_printf("%<b>%<u>%-?s %-*sCreat Tndx %-?s%</u>%</b>\n",
		    "Address", sizeof (name), "Name", "Buckets");

	if (mdb_readstr(name, sizeof (name), (uintptr_t)idx.dbi_keyname)
	    == -1) {
		mdb_warn("can't read dbi_keyname");
		return (DCMD_ERR);
	}

	mdb_printf("%?p %-*s%-5s %04u %?p\n", addr, sizeof (name), name,
	    idx.dbi_createable ? "TRUE" : "FALSE", idx.dbi_tblidx,
	    idx.dbi_buckets);

	return (DCMD_OK);
}

void
rfs4_idx_help(void)
{
	mdb_printf(
	    "-w       walks along all indices in the list\n"
	    "\n"
	    "The following two commands are equivalent:\n"
	    "  ::rfs4_idx -w\n"
	    "  ::walk rfs4_db_idx|::rfs4_idx\n");
}

/*
 * rfs4_bkt dcmd implementation
 */

static int
rfs4_print_bkt_cb(uintptr_t addr, const void *data, void *cb_data)
{
	const rfs4_bucket_t *bkt = data;
	rfs4_link_t *lp;
	rfs4_link_t rl;

	for (lp = bkt->dbk_head; lp; lp = rl.next) {
		rfs4_dbe_t dbe;

		if (mdb_vread(&rl, sizeof (rl), (uintptr_t)lp) == -1) {
			mdb_warn("can't read rfs4_link_t");
			return (WALK_ERR);
		}

		if (mdb_vread(&dbe, sizeof (dbe), (uintptr_t)rl.entry) == -1) {
			mdb_warn("can't read rfs4_dbe_t");
			return (WALK_ERR);
		}

		mdb_inc_indent(4);
		mdb_printf(
		    "DBE {  Address=%p data->%p refcnt=%u skipsearch=%u\n"
		    "    invalid=%u time_rele=%Y\n}\n", rl.entry, dbe.dbe_data,
		    dbe.dbe_refcnt, dbe.dbe_skipsearch, dbe.dbe_invalid,
		    dbe.dbe_time_rele);
		mdb_dec_indent(4);
	}

	return (WALK_NEXT);
}

int
rfs4_bkt_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (argc > 0)
		return (DCMD_USAGE);

	if ((flags & DCMD_ADDRSPEC) == 0) {
		mdb_printf("requires address of rfs4_index_t\n");
		return (DCMD_USAGE);
	}

	if (mdb_pwalk("rfs4_db_bkt", rfs4_print_bkt_cb, NULL, addr) == -1) {
		mdb_warn("bucket walking failed");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

/*
 * rfs4_oo dcmd implementation
 */

static int
rfs4_print_oo(uintptr_t addr, uintptr_t client)
{
	rfs4_openowner_t oo;
	uint8_t *owner_val;
	uint_t i;

	if (mdb_vread(&oo, sizeof (oo), addr) == -1) {
		mdb_warn("can't read rfs4_openowner_t");
		return (DCMD_ERR);
	}

	if (client && (client != (uintptr_t)oo.ro_client))
		return (DCMD_OK);

	owner_val = mdb_alloc(oo.ro_owner.owner_len, UM_SLEEP | UM_GC);
	if (mdb_vread(owner_val, oo.ro_owner.owner_len,
	    (uintptr_t)oo.ro_owner.owner_val) == -1) {
		mdb_warn("can't read owner_val");
		return (DCMD_ERR);
	}

	mdb_printf("%?p %?p %?p %10u %16llx ", addr, oo.ro_dbe, oo.ro_client,
	    oo.ro_open_seqid, oo.ro_owner.clientid);
	for (i = 0; i < oo.ro_owner.owner_len; i++)
		mdb_printf("%02x", owner_val[i]);
	mdb_printf("\n");

	return (DCMD_OK);
}

static int
rfs4_print_oo_cb(uintptr_t addr, const void *data, void *cb_data)
{
	if (mdb_vread(&addr, sizeof (addr), addr + OFFSETOF(rfs4_dbe_t,
	    dbe_data)) == -1) {
		mdb_warn("failed to read dbe_data");
		return (WALK_ERR);
	}

	return (rfs4_print_oo(addr, (uintptr_t)cb_data) == DCMD_OK
	    ? WALK_NEXT : WALK_ERR);
}

static void
print_oo_hdr(void)
{
	mdb_printf("%<b>%<u>%-?s %-?s %-?s %10s %16s %-16s%</u>%</b>\n",
	    "Address", "Dbe", "Client", "OpenSeqID", "clientid",
	    "owner");
}

int
rfs4_oo_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (argc > 0)
		return (DCMD_USAGE);

	if (DCMD_HDRSPEC(flags))
		print_oo_hdr();

	if (flags & DCMD_ADDRSPEC)
		return (rfs4_print_oo(addr, 0));

	if (mdb_walk("OpenOwner_entry_cache", rfs4_print_oo_cb, NULL) == -1) {
		mdb_warn("walking of %s failed", "OpenOwner_entry_cache");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

/*
 * rfs4_osid dcmd implementation
 */

static void
print_stateid(const stateid_t *st)
{
	const char *s;

	mdb_printf("chgseq=%u boottime=%x pid=%i\n", st->bits.chgseq,
	    st->bits.boottime, st->bits.pid);

	switch ((stateid_type_t)st->bits.type) {
	case OPENID:
		s = "OpenID";
		break;
	case LOCKID:
		s = "LockID";
		break;
	case DELEGID:
		s = "DelegID";
		break;
	default:
		s = "<undefined>";
		break;
	}
	mdb_printf("type=%s ident=%x\n", s, st->bits.ident);
}

static int
rfs4_print_osid(uintptr_t addr, uint_t opt_v)
{
	rfs4_state_t osid;
	size_t i;
	const char *s;

	if (mdb_vread(&osid, sizeof (osid), addr) == -1) {
		mdb_warn("can't read rfs4_state_t");
		return (DCMD_ERR);
	}

	mdb_printf("%?p %?p %?p %?p ", addr, osid.rs_dbe, osid.rs_owner,
	    osid.rs_finfo);
	for (i = 0; i < sizeof (stateid4); i++)
		mdb_printf("%02x", ((uint8_t *)&osid.rs_stateid)[i]);
	mdb_printf("\n");

	if (!opt_v)
		return (DCMD_OK);

	mdb_inc_indent(8);

	print_stateid(&osid.rs_stateid);

	switch (osid.rs_share_access) {
	case 0:
		s = "none";
		break;
	case OPEN4_SHARE_ACCESS_READ:
		s = "read";
		break;
	case OPEN4_SHARE_ACCESS_WRITE:
		s = "write";
		break;
	case OPEN4_SHARE_ACCESS_BOTH:
		s = "read-write";
		break;
	default:
		s = "<invalid>";
		break;
	}
	mdb_printf("share_access: %s", s);

	switch (osid.rs_share_deny) {
	case OPEN4_SHARE_DENY_NONE:
		s = "none";
		break;
	case OPEN4_SHARE_DENY_READ:
		s = "read";
		break;
	case OPEN4_SHARE_DENY_WRITE:
		s = "write";
		break;
	case OPEN4_SHARE_DENY_BOTH:
		s = "read-write";
		break;
	default:
		s = "<invalid>";
		break;
	}
	mdb_printf(" share_deny: %s file is: %s\n", s,
	    osid.rs_closed ? "CLOSED" : "OPEN");

	mdb_dec_indent(8);

	return (DCMD_OK);
}

static int
rfs4_print_osid_cb(uintptr_t addr, const void *data, void *cb_data)
{
	/* addr = ((rfs4_dbe_t *)addr)->dbe_data */
	if (mdb_vread(&addr, sizeof (addr), addr + OFFSETOF(rfs4_dbe_t,
	    dbe_data)) == -1) {
		mdb_warn("failed to read dbe_data");
		return (WALK_ERR);
	}

	return (rfs4_print_osid(addr, *(uint_t *)cb_data) == DCMD_OK
	    ? WALK_NEXT : WALK_ERR);
}

int
rfs4_osid_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t opt_v = FALSE;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &opt_v, NULL) != argc)
		return (DCMD_USAGE);

	if (DCMD_HDRSPEC(flags))
		mdb_printf("%<b>%<u>%-?s %-?s %-?s %-?s %-*s%</u>%</b>\n",
		    "Address", "Dbe", "Owner", "finfo", 2 * sizeof (stateid4),
		    "StateID");

	if (flags & DCMD_ADDRSPEC)
		return (rfs4_print_osid(addr, opt_v));

	if (mdb_walk("OpenStateID_entry_cache", rfs4_print_osid_cb, &opt_v)
	    == -1) {
		mdb_warn("walking of %s failed", "OpenStateID_entry_cache");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

/*
 * rfs4_file dcmd implementation
 */

static void
print_time(time_t t)
{
	if (t == 0)
		mdb_printf("0");
	else
		mdb_printf("%Y", t);
}

static int
rfs4_print_file(uintptr_t addr, uint_t opt_v)
{
	rfs4_file_t f;
	uint8_t *nfs_fh4_val;
	uint_t i;
	uintptr_t vp;
	char *s;
	const rfs4_dinfo_t *di;

	if (mdb_vread(&f, sizeof (f), addr) == -1) {
		mdb_warn("can't read rfs4_file_t");
		return (DCMD_ERR);
	}

	nfs_fh4_val = mdb_alloc(f.rf_filehandle.nfs_fh4_len, UM_SLEEP | UM_GC);
	if (mdb_vread(nfs_fh4_val, f.rf_filehandle.nfs_fh4_len,
	    (uintptr_t)f.rf_filehandle.nfs_fh4_val) == -1) {
		mdb_warn("can't read nfs_fh4_val");
		return (DCMD_ERR);
	}

	mdb_printf("%?p %?p %?p ", addr, f.rf_dbe, f.rf_vp);
	for (i = 0; i < f.rf_filehandle.nfs_fh4_len; i++)
		mdb_printf("%02x", nfs_fh4_val[i]);
	mdb_printf("\n");

	if (!opt_v)
		return (DCMD_OK);

	/* vp = f.rf_vp->v_path */
	if (mdb_vread(&vp, sizeof (vp), (uintptr_t)f.rf_vp
	    + OFFSETOF(vnode_t, v_path)) == -1) {
		mdb_warn("can't read vnode_t");
		return (DCMD_ERR);
	}

	s = mdb_alloc(PATH_MAX, UM_SLEEP | UM_GC);
	if (mdb_readstr(s, PATH_MAX, vp) == -1) {
		mdb_warn("can't read v_path");
		return (DCMD_ERR);
	}

	mdb_inc_indent(8);

	mdb_printf("path=%s\n", s);

	di = &f.rf_dinfo;
	switch (di->rd_dtype) {
	case OPEN_DELEGATE_NONE:
		s = "None";
		break;
	case OPEN_DELEGATE_READ:
		s = "Read";
		break;
	case OPEN_DELEGATE_WRITE:
		s = "Write";
		break;
	default:
		s = "?????";
		break;
	}
	mdb_printf("dtype=%-5s rdgrants=%u wrgrants=%u recall_cnt=%i "
	    "ever_recalled=%s\n", s, di->rd_rdgrants, di->rd_wrgrants,
	    di->rd_recall_count, (di->rd_ever_recalled == TRUE) ? "True"
	    : "False");

	mdb_printf("Time: ");
	mdb_inc_indent(6);

	mdb_printf("returned=");
	print_time(di->rd_time_returned);
	mdb_printf(" recalled=");
	print_time(di->rd_time_recalled);
	mdb_printf("\nlastgrant=");
	print_time(di->rd_time_lastgrant);
	mdb_printf(" lastwrite=");
	print_time(di->rd_time_lastwrite);
	mdb_printf("\nrm_delayed=");
	print_time(di->rd_time_rm_delayed);
	mdb_printf("\n");

	mdb_dec_indent(14);

	return (DCMD_OK);
}

static int
rfs4_print_file_cb(uintptr_t addr, const void *data, void *cb_data)
{
	/* addr = ((rfs4_dbe_t *)addr)->dbe_data */
	if (mdb_vread(&addr, sizeof (addr), addr + OFFSETOF(rfs4_dbe_t,
	    dbe_data)) == -1) {
		mdb_warn("failed to read dbe_data");
		return (WALK_ERR);
	}

	return (rfs4_print_file(addr, *(uint_t *)cb_data) == DCMD_OK
	    ? WALK_NEXT : WALK_ERR);
}

int
rfs4_file_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t opt_v = FALSE;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &opt_v, NULL) != argc)
		return (DCMD_USAGE);

	if (DCMD_HDRSPEC(flags))
		mdb_printf("%<b>%<u>%-?s %-?s %-?s %-32s%</u>%</b>\n",
		    "Address", "Dbe", "Vnode", "Filehandle");

	if (flags & DCMD_ADDRSPEC)
		return (rfs4_print_file(addr, opt_v));

	if (mdb_walk("File_entry_cache", rfs4_print_file_cb, &opt_v) == -1) {
		mdb_warn("walking of %s failed", "File_entry_cache");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

/*
 * rfs4_deleg dcmd implementation
 */

static int
rfs4_print_deleg(uintptr_t addr, uint_t opt_v, uintptr_t client)
{
	rfs4_deleg_state_t ds;
	size_t i;
	uintptr_t pa;
	char *s;

	if (mdb_vread(&ds, sizeof (ds), addr) == -1) {
		mdb_warn("can't read rfs4_deleg_state_t");
		return (DCMD_ERR);
	}

	if (client && (client != (uintptr_t)ds.rds_client))
		return (DCMD_OK);

	mdb_printf("%?p %?p ", addr, ds.rds_dbe);
	for (i = 0; i < sizeof (stateid4); i++)
		mdb_printf("%02x", ((uint8_t *)&ds.rds_delegid)[i]);
	mdb_printf(" %?p %?p\n", ds.rds_finfo, ds.rds_client);

	if (!opt_v)
		return (DCMD_OK);

	/* pa = ds.rds_finfo->rf_vp */
	if (mdb_vread(&pa, sizeof (pa), (uintptr_t)ds.rds_finfo
	    + OFFSETOF(rfs4_file_t, rf_vp)) == -1) {
		mdb_warn("can't read rf_vp");
		return (DCMD_ERR);
	}
	/* pa = ((vnode_t *)pa)->v_path */
	if (mdb_vread(&pa, sizeof (pa), pa + OFFSETOF(vnode_t, v_path)) == -1) {
		mdb_warn("can't read rf_vp");
		return (DCMD_ERR);
	}

	s = mdb_alloc(PATH_MAX, UM_SLEEP | UM_GC);
	if (mdb_readstr(s, PATH_MAX, pa) == -1) {
		mdb_warn("can't read v_path");
		return (DCMD_ERR);
	}

	mdb_inc_indent(8);
	mdb_printf("Time: ");
	mdb_inc_indent(6);

	mdb_printf("granted=");
	print_time(ds.rds_time_granted);
	mdb_printf(" recalled=");
	print_time(ds.rds_time_recalled);
	mdb_printf(" revoked=");
	print_time(ds.rds_time_revoked);

	mdb_dec_indent(6);
	mdb_printf("\npath=%s\n", s);
	mdb_dec_indent(8);

	return (DCMD_OK);
}

static int
rfs4_print_deleg_cb(uintptr_t addr, const void *data, void *cb_data)
{
	/* addr = ((rfs4_dbe_t *)addr)->dbe_data */
	if (mdb_vread(&addr, sizeof (addr), addr + OFFSETOF(rfs4_dbe_t,
	    dbe_data)) == -1) {
		mdb_warn("failed to read dbe_data");
		return (WALK_ERR);
	}

	return (rfs4_print_deleg(addr, *(uint_t *)cb_data,
	    0) == DCMD_OK ? WALK_NEXT : WALK_ERR);
}

static void
print_deleg_hdr(void)
{
	mdb_printf("%<b>%<u>%-?s %-?s %-*s %-?s %-?s%</u>%</b>\n",
	    "Address", "Dbe", 2 * sizeof (stateid4), "StateID",
	    "File Info", "Client");
}

int
rfs4_deleg_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t opt_v = FALSE;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &opt_v, NULL) != argc)
		return (DCMD_USAGE);

	if (DCMD_HDRSPEC(flags))
		print_deleg_hdr();

	if (flags & DCMD_ADDRSPEC)
		return (rfs4_print_deleg(addr, opt_v, 0));

	if (mdb_walk("DelegStateID_entry_cache", rfs4_print_deleg_cb, &opt_v)
	    == -1) {
		mdb_warn("walking of %s failed", "DelegStateID_entry_cache");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

/*
 * rfs4_lo dcmd implementation
 */

static int
rfs4_print_lo(uintptr_t addr, uintptr_t client)
{
	rfs4_lockowner_t lo;
	uint8_t *owner_val;
	uint_t i;

	if (mdb_vread(&lo, sizeof (lo), addr) == -1) {
		mdb_warn("can't read rfs4_lockowner_t");
		return (DCMD_ERR);
	}

	if (client && (client != (uintptr_t)lo.rl_client))
		return (DCMD_OK);

	owner_val = mdb_alloc(lo.rl_owner.owner_len, UM_SLEEP | UM_GC);
	if (mdb_vread(owner_val, lo.rl_owner.owner_len,
	    (uintptr_t)lo.rl_owner.owner_val) == -1) {
		mdb_warn("can't read owner_val");
		return (DCMD_ERR);
	}

	mdb_printf("%?p %?p %?p %10i %16llx ", addr, lo.rl_dbe, lo.rl_client,
	    lo.rl_pid, lo.rl_owner.clientid);
	for (i = 0; i < lo.rl_owner.owner_len; i++)
		mdb_printf("%02x", owner_val[i]);
	mdb_printf("\n");

	return (DCMD_OK);
}

static int
rfs4_print_lo_cb(uintptr_t addr, const void *data, void *cb_data)
{
	if (mdb_vread(&addr, sizeof (addr), addr + OFFSETOF(rfs4_dbe_t,
	    dbe_data)) == -1) {
		mdb_warn("failed to read dbe_data");
		return (WALK_ERR);
	}

	return (rfs4_print_lo(addr, (uintptr_t)cb_data) == DCMD_OK
	    ? WALK_NEXT : WALK_ERR);
}

static void
print_lo_hdr(void)
{
	mdb_printf("%<b>%<u>%-?s %-?s %-?s %10s %16s %-16s%</u>%</b>\n",
	    "Address", "Dbe", "Client", "Pid", "clientid", "owner");
}

int
rfs4_lo_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (argc > 0)
		return (DCMD_USAGE);

	if (DCMD_HDRSPEC(flags))
		print_lo_hdr();

	if (flags & DCMD_ADDRSPEC)
		return (rfs4_print_lo(addr, 0));

	if (mdb_walk("Lockowner_entry_cache", rfs4_print_lo_cb, NULL) == -1) {
		mdb_warn("walking of %s failed", "Lockowner_entry_cache");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

/*
 * rfs4_lsid dcmd implementation
 */

static int
rfs4_print_lsid(uintptr_t addr, uint_t opt_v)
{
	rfs4_lo_state_t lsid;
	size_t i;

	if (mdb_vread(&lsid, sizeof (lsid), addr) == -1) {
		mdb_warn("can't read rfs4_lo_state_t");
		return (DCMD_ERR);
	}

	mdb_printf("%?p %?p %?p %10u ", addr, lsid.rls_dbe, lsid.rls_locker,
	    lsid.rls_seqid);
	for (i = 0; i < sizeof (stateid4); i++)
		mdb_printf("%02x", ((uint8_t *)&lsid.rls_lockid)[i]);
	mdb_printf("\n");

	if (!opt_v)
		return (DCMD_OK);

	mdb_inc_indent(8);
	print_stateid(&lsid.rls_lockid);
	mdb_dec_indent(8);

	return (DCMD_OK);
}

static int
rfs4_print_lsid_cb(uintptr_t addr, const void *data, void *cb_data)
{
	if (mdb_vread(&addr, sizeof (addr), addr + OFFSETOF(rfs4_dbe_t,
	    dbe_data)) == -1) {
		mdb_warn("failed to read dbe_data");
		return (WALK_ERR);
	}

	return (rfs4_print_lsid(addr, *(uint_t *)cb_data) == DCMD_OK
	    ? WALK_NEXT : WALK_ERR);
}

int
rfs4_lsid_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t opt_v = FALSE;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &opt_v, NULL) != argc)
		return (DCMD_USAGE);

	if (DCMD_HDRSPEC(flags))
		mdb_printf("%<b>%<u>%-?s %-?s %-?s %10s %-*s%</u>%</b>\n",
		    "Address", "Dbe", "Locker", "SeqID", 2 * sizeof (stateid4),
		    "Lockid");

	if (flags & DCMD_ADDRSPEC)
		return (rfs4_print_lsid(addr, opt_v));

	if (mdb_walk("LockStateID_entry_cache", rfs4_print_lsid_cb, &opt_v)
	    == -1) {
		mdb_warn("walking of %s failed", "LockStateID_entry_cache");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

/*
 * rfs4_client dcmd implementation
 */

static int
rfs4_print_client(uintptr_t addr)
{
	rfs4_client_t cl;

	if (mdb_vread(&cl, sizeof (cl), addr) == -1) {
		mdb_warn("can't read rfs4_client_t");
		return (DCMD_ERR);
	}

	mdb_printf("%?p %?p %-16llx %-16llx %-5s %-5s %?p %-20Y\n", addr,
	    cl.rc_dbe, cl.rc_clientid, cl.rc_confirm_verf,
	    cl.rc_need_confirm ? "True" : "False",
	    cl.rc_unlksys_completed ? "True" : "False", cl.rc_cp_confirmed,
	    cl.rc_last_access);

	return (DCMD_OK);
}

static int
rfs4_client_deleg_cb(uintptr_t addr, const void *data, void *cb_data)
{
	/* addr = ((rfs4_dbe_t *)addr)->dbe_data */
	if (mdb_vread(&addr, sizeof (addr), addr + OFFSETOF(rfs4_dbe_t,
	    dbe_data)) == -1) {
		mdb_warn("failed to read dbe_data");
		return (WALK_ERR);
	}

	return (rfs4_print_deleg(addr, FALSE, (uintptr_t)cb_data) == DCMD_OK
	    ? WALK_NEXT : WALK_ERR);
}

static int
rfs4_print_client_cb(uintptr_t addr, const void *data, void *cb_data)
{
	clientid4 clid;

	/* addr = ((rfs4_dbe_t *)addr)->dbe_data */
	if (mdb_vread(&addr, sizeof (addr), addr + OFFSETOF(rfs4_dbe_t,
	    dbe_data)) == -1) {
		mdb_warn("failed to read dbe_data");
		return (WALK_ERR);
	}

	/* if no clid specified then print all clients */
	if (!cb_data)
		return (rfs4_print_client(addr) == DCMD_OK ? WALK_NEXT
		    : WALK_ERR);

	/* clid = ((rfs4_client_t *)addr)->rc_clientid */
	if (mdb_vread(&clid, sizeof (clid), addr + OFFSETOF(rfs4_client_t,
	    rc_clientid)) == -1) {
		mdb_warn("can't read rc_clientid");
		return (WALK_ERR);
	}

	/* clid does not match, do not print the client */
	if (clid != *(clientid4 *)cb_data)
		return (WALK_NEXT);

	if (rfs4_print_client(addr) != DCMD_OK)
		return (WALK_ERR);

	mdb_printf("\n");
	print_oo_hdr();
	if (mdb_walk("OpenOwner_entry_cache", rfs4_print_oo_cb, (void *)addr)
	    == -1) {
		mdb_warn("walking of %s failed", "OpenOwner_entry_cache");
		return (WALK_ERR);
	}

	mdb_printf("\n");
	print_lo_hdr();
	if (mdb_walk("Lockowner_entry_cache", rfs4_print_lo_cb, (void *)addr)
	    == -1) {
		mdb_warn("walking of %s failed", "Lockowner_entry_cache");
		return (WALK_ERR);
	}

	mdb_printf("\n");
	print_deleg_hdr();
	if (mdb_walk("DelegStateID_entry_cache", rfs4_client_deleg_cb,
	    (void *)addr) == -1) {
		mdb_warn("walking of %s failed", "DelegStateID_entry_cache");
		return (WALK_ERR);
	}

	return (WALK_DONE);
}

int
rfs4_client_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	clientid4 clid;

	if (mdb_getopts(argc, argv,
	    'c', MDB_OPT_UINT64, &clid, NULL) != argc)
		return (DCMD_USAGE);

	if (DCMD_HDRSPEC(flags))
		mdb_printf("%<b>%<u>%-?s %-?s %-16s %-16s NCnfm unlnk %-?s "
		    "%-20s%</u>%</b>\n", "Address", "dbe", "clientid",
		    "confirm_verf", "cp_confirmed", "Last Access");

	if ((argc == 0) && (flags & DCMD_ADDRSPEC))
		return (rfs4_print_client(addr));

	if (mdb_walk("Client_entry_cache", rfs4_print_client_cb, (argc > 0)
	    ? &clid : NULL) == -1) {
		mdb_warn("walking of %s failed", "Client_entry_cache");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

void
rfs4_client_help(void)
{
	mdb_printf(
	    "-c       print all NFSv4 server state entries referencing\n"
	    "         the <clientid> client. In this case the supplied\n"
	    "         address is ignored\n");
}

/*
 * rfs4_db_tbl walker implementation
 */

int
rfs4_db_tbl_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == 0) {
		mdb_warn("db tbl global walk not supported");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

int
rfs4_db_tbl_walk_step(mdb_walk_state_t *wsp)
{
	rfs4_table_t tbl;
	uintptr_t addr = wsp->walk_addr;

	if (addr == 0)
		return (WALK_DONE);

	if (mdb_vread(&tbl, sizeof (tbl), addr) == -1) {
		mdb_warn("can't read rfs4_table_t");
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)tbl.dbt_tnext;
	return (wsp->walk_callback(addr, &tbl, wsp->walk_cbdata));
}

/*
 * rfs4_db_idx walker implementation
 */

int
rfs4_db_idx_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == 0) {
		mdb_warn("db idx global walk not supported");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

int
rfs4_db_idx_walk_step(mdb_walk_state_t *wsp)
{
	rfs4_index_t idx;
	uintptr_t addr = wsp->walk_addr;

	if (addr == 0)
		return (WALK_DONE);

	if (mdb_vread(&idx, sizeof (idx), addr) == -1) {
		mdb_warn("can't read rfs4_index_t");
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)idx.dbi_inext;
	return (wsp->walk_callback(addr, &idx, wsp->walk_cbdata));
}
/*
 * rfs4_db_bkt walker implementation
 */

int
rfs4_db_bkt_walk_init(mdb_walk_state_t *wsp)
{
	rfs4_index_t idx;
	uint32_t dbt_len;

	if (wsp->walk_addr == 0) {
		mdb_warn("db bkt global walk not supported");
		return (WALK_ERR);
	}

	if (mdb_vread(&idx, sizeof (idx), wsp->walk_addr) == -1) {
		mdb_warn("can't read rfs4_index_t");
		return (WALK_ERR);
	}

	/* dbt_len = idx.dbi_table->dbt_len */
	if (mdb_vread(&dbt_len, sizeof (dbt_len), (uintptr_t)idx.dbi_table
	    + OFFSETOF(rfs4_table_t, dbt_len)) == -1) {
		mdb_warn("can't read dbt_len");
		return (WALK_ERR);
	}

	wsp->walk_data = mdb_alloc(sizeof (dbt_len), UM_SLEEP);
	*(uint32_t *)wsp->walk_data = dbt_len;
	wsp->walk_addr = (uintptr_t)idx.dbi_buckets;

	return (WALK_NEXT);
}

int
rfs4_db_bkt_walk_step(mdb_walk_state_t *wsp)
{
	rfs4_bucket_t bkt;
	uintptr_t addr = wsp->walk_addr;

	if (*(uint32_t *)wsp->walk_data == 0)
		return (WALK_DONE);

	if (mdb_vread(&bkt, sizeof (bkt), addr) == -1) {
		mdb_warn("can't read rfs4_bucket_t");
		return (WALK_ERR);
	}

	(*(uint32_t *)wsp->walk_data)--;
	wsp->walk_addr = (uintptr_t)((rfs4_bucket_t *)addr + 1);

	return (wsp->walk_callback(addr, &bkt, wsp->walk_cbdata));
}

void
rfs4_db_bkt_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (uint32_t));
}
