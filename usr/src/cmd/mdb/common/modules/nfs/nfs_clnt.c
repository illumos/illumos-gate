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
#include <sys/list.h>
#include <nfs/rnode.h>
#include <nfs/rnode4.h>
#include <nfs/nfs_clnt.h>
#include <nfs/nfs4_clnt.h>
#include <mdb/mdb_ks.h>
#include <mdb/mdb_ctf.h>

#include "nfs_clnt.h"
#include "common.h"

/*
 * Common functions
 */

static void
nfs_print_io_stat(uintptr_t kstat_addr)
{
	kstat_t kstat;
	kstat_io_t kstat_io;

	mdb_printf("IO statistics for this mount:\n");
	mdb_inc_indent(2);

	if (mdb_vread(&kstat, sizeof (kstat), kstat_addr) == -1 ||
	    mdb_vread(&kstat_io, sizeof (kstat_io),
	    (uintptr_t)KSTAT_IO_PTR(&kstat)) == -1) {
		mdb_printf("No. of bytes read:       %9s\n", "??");
		mdb_printf("No. of read operations:  %9s\n", "??");
		mdb_printf("No. of bytes written:    %9s\n", "??");
		mdb_printf("No. of write operations: %9s\n", "??");
	} else {
		mdb_printf("No. of bytes read:       %9llu\n", kstat_io.nread);
		mdb_printf("No. of read operations:  %9lu\n", kstat_io.reads);
		mdb_printf("No. of bytes written:    %9llu\n",
		    kstat_io.nwritten);
		mdb_printf("No. of write operations: %9lu\n", kstat_io.writes);
	}

	mdb_dec_indent(2);
}

static int
walk_count_cb(uintptr_t addr, const void *data, void *cb_data)
{
	(*(size_t *)cb_data)++;
	return (WALK_NEXT);
}

#define	TBL_ENTRY(e)	{#e, e}

static const struct {
	const char *str;
	nfs_opnum4 op;
} nfs4_op_tbl[] = {
	TBL_ENTRY(OP_ACCESS),
	TBL_ENTRY(OP_CLOSE),
	TBL_ENTRY(OP_COMMIT),
	TBL_ENTRY(OP_CREATE),
	TBL_ENTRY(OP_DELEGPURGE),
	TBL_ENTRY(OP_DELEGRETURN),
	TBL_ENTRY(OP_GETATTR),
	TBL_ENTRY(OP_GETFH),
	TBL_ENTRY(OP_LINK),
	TBL_ENTRY(OP_LOCK),
	TBL_ENTRY(OP_LOCKT),
	TBL_ENTRY(OP_LOCKU),
	TBL_ENTRY(OP_LOOKUP),
	TBL_ENTRY(OP_LOOKUPP),
	TBL_ENTRY(OP_NVERIFY),
	TBL_ENTRY(OP_OPEN),
	TBL_ENTRY(OP_OPENATTR),
	TBL_ENTRY(OP_OPEN_CONFIRM),
	TBL_ENTRY(OP_OPEN_DOWNGRADE),
	TBL_ENTRY(OP_PUTFH),
	TBL_ENTRY(OP_PUTPUBFH),
	TBL_ENTRY(OP_PUTROOTFH),
	TBL_ENTRY(OP_READ),
	TBL_ENTRY(OP_READDIR),
	TBL_ENTRY(OP_READLINK),
	TBL_ENTRY(OP_REMOVE),
	TBL_ENTRY(OP_RENAME),
	TBL_ENTRY(OP_RENEW),
	TBL_ENTRY(OP_RESTOREFH),
	TBL_ENTRY(OP_SAVEFH),
	TBL_ENTRY(OP_SECINFO),
	TBL_ENTRY(OP_SETATTR),
	TBL_ENTRY(OP_SETCLIENTID),
	TBL_ENTRY(OP_SETCLIENTID_CONFIRM),
	TBL_ENTRY(OP_VERIFY),
	TBL_ENTRY(OP_WRITE),
	TBL_ENTRY(OP_RELEASE_LOCKOWNER),
	TBL_ENTRY(OP_ILLEGAL),
	TBL_ENTRY(OP_CCREATE),
	TBL_ENTRY(OP_CLINK),
	TBL_ENTRY(OP_CLOOKUP),
	TBL_ENTRY(OP_COPEN),
	TBL_ENTRY(OP_CPUTFH),
	TBL_ENTRY(OP_CREMOVE),
	TBL_ENTRY(OP_CRENAME),
	TBL_ENTRY(OP_CSECINFO),
	{NULL}
};

static const char *
nfs4_op_str(nfs_opnum4 op)
{
	int i;

	for (i = 0; nfs4_op_tbl[i].str != NULL; i++)
		if (nfs4_op_tbl[i].op == op)
			return (nfs4_op_tbl[i].str);

	return ("??");
}

static const struct {
	const char *str;
	nfs4_recov_t action;
} nfs4_recov_tbl[] = {
	TBL_ENTRY(NR_UNUSED),
	TBL_ENTRY(NR_CLIENTID),
	TBL_ENTRY(NR_OPENFILES),
	TBL_ENTRY(NR_FHEXPIRED),
	TBL_ENTRY(NR_FAILOVER),
	TBL_ENTRY(NR_WRONGSEC),
	TBL_ENTRY(NR_EXPIRED),
	TBL_ENTRY(NR_BAD_STATEID),
	TBL_ENTRY(NR_BADHANDLE),
	TBL_ENTRY(NR_BAD_SEQID),
	TBL_ENTRY(NR_OLDSTATEID),
	TBL_ENTRY(NR_GRACE),
	TBL_ENTRY(NR_DELAY),
	TBL_ENTRY(NR_LOST_LOCK),
	TBL_ENTRY(NR_LOST_STATE_RQST),
	TBL_ENTRY(NR_STALE),
	TBL_ENTRY(NR_MOVED),
	{NULL}
};

static const char *
nfs4_recov_str(nfs4_recov_t action)
{
	int i;

	for (i = 0; nfs4_recov_tbl[i].str != NULL; i++)
		if (nfs4_recov_tbl[i].action == action)
			return (nfs4_recov_tbl[i].str);

	return ("??");
}

static const struct {
	const char *str;
	nfsstat4 stat;
} nfs4_stat_tbl[] = {
	TBL_ENTRY(NFS4_OK),
	TBL_ENTRY(NFS4ERR_PERM),
	TBL_ENTRY(NFS4ERR_NOENT),
	TBL_ENTRY(NFS4ERR_IO),
	TBL_ENTRY(NFS4ERR_NXIO),
	TBL_ENTRY(NFS4ERR_ACCESS),
	TBL_ENTRY(NFS4ERR_EXIST),
	TBL_ENTRY(NFS4ERR_XDEV),
	TBL_ENTRY(NFS4ERR_NOTDIR),
	TBL_ENTRY(NFS4ERR_ISDIR),
	TBL_ENTRY(NFS4ERR_INVAL),
	TBL_ENTRY(NFS4ERR_FBIG),
	TBL_ENTRY(NFS4ERR_NOSPC),
	TBL_ENTRY(NFS4ERR_ROFS),
	TBL_ENTRY(NFS4ERR_MLINK),
	TBL_ENTRY(NFS4ERR_NAMETOOLONG),
	TBL_ENTRY(NFS4ERR_NOTEMPTY),
	TBL_ENTRY(NFS4ERR_DQUOT),
	TBL_ENTRY(NFS4ERR_STALE),
	TBL_ENTRY(NFS4ERR_BADHANDLE),
	TBL_ENTRY(NFS4ERR_BAD_COOKIE),
	TBL_ENTRY(NFS4ERR_NOTSUPP),
	TBL_ENTRY(NFS4ERR_TOOSMALL),
	TBL_ENTRY(NFS4ERR_SERVERFAULT),
	TBL_ENTRY(NFS4ERR_BADTYPE),
	TBL_ENTRY(NFS4ERR_DELAY),
	TBL_ENTRY(NFS4ERR_SAME),
	TBL_ENTRY(NFS4ERR_DENIED),
	TBL_ENTRY(NFS4ERR_EXPIRED),
	TBL_ENTRY(NFS4ERR_LOCKED),
	TBL_ENTRY(NFS4ERR_GRACE),
	TBL_ENTRY(NFS4ERR_FHEXPIRED),
	TBL_ENTRY(NFS4ERR_SHARE_DENIED),
	TBL_ENTRY(NFS4ERR_WRONGSEC),
	TBL_ENTRY(NFS4ERR_CLID_INUSE),
	TBL_ENTRY(NFS4ERR_RESOURCE),
	TBL_ENTRY(NFS4ERR_MOVED),
	TBL_ENTRY(NFS4ERR_NOFILEHANDLE),
	TBL_ENTRY(NFS4ERR_MINOR_VERS_MISMATCH),
	TBL_ENTRY(NFS4ERR_STALE_CLIENTID),
	TBL_ENTRY(NFS4ERR_STALE_STATEID),
	TBL_ENTRY(NFS4ERR_OLD_STATEID),
	TBL_ENTRY(NFS4ERR_BAD_STATEID),
	TBL_ENTRY(NFS4ERR_BAD_SEQID),
	TBL_ENTRY(NFS4ERR_NOT_SAME),
	TBL_ENTRY(NFS4ERR_LOCK_RANGE),
	TBL_ENTRY(NFS4ERR_SYMLINK),
	TBL_ENTRY(NFS4ERR_RESTOREFH),
	TBL_ENTRY(NFS4ERR_LEASE_MOVED),
	TBL_ENTRY(NFS4ERR_ATTRNOTSUPP),
	TBL_ENTRY(NFS4ERR_NO_GRACE),
	TBL_ENTRY(NFS4ERR_RECLAIM_BAD),
	TBL_ENTRY(NFS4ERR_RECLAIM_CONFLICT),
	TBL_ENTRY(NFS4ERR_BADXDR),
	TBL_ENTRY(NFS4ERR_LOCKS_HELD),
	TBL_ENTRY(NFS4ERR_OPENMODE),
	TBL_ENTRY(NFS4ERR_BADOWNER),
	TBL_ENTRY(NFS4ERR_BADCHAR),
	TBL_ENTRY(NFS4ERR_BADNAME),
	TBL_ENTRY(NFS4ERR_BAD_RANGE),
	TBL_ENTRY(NFS4ERR_LOCK_NOTSUPP),
	TBL_ENTRY(NFS4ERR_OP_ILLEGAL),
	TBL_ENTRY(NFS4ERR_DEADLOCK),
	TBL_ENTRY(NFS4ERR_FILE_OPEN),
	TBL_ENTRY(NFS4ERR_ADMIN_REVOKED),
	TBL_ENTRY(NFS4ERR_CB_PATH_DOWN),
	{NULL}
};

static const char *
nfs4_stat_str(nfsstat4 stat)
{
	int i;

	for (i = 0; nfs4_stat_tbl[i].str != NULL; i++)
		if (nfs4_stat_tbl[i].stat == stat)
			return (nfs4_stat_tbl[i].str);

	return ("??");
}

static const struct {
	const char *str;
	nfs4_tag_type_t tt;
} nfs4_tag_tbl[] = {
	{"", TAG_NONE},
	{"access", TAG_ACCESS},
	{"close", TAG_CLOSE},
	{"lost close", TAG_CLOSE_LOST},
	{"undo close", TAG_CLOSE_UNDO},
	{"commit", TAG_COMMIT},
	{"delegreturn", TAG_DELEGRETURN},
	{"fsinfo", TAG_FSINFO},
	{"get symlink text", TAG_GET_SYMLINK},
	{"getattr", TAG_GETATTR},
	{"getattr fslocation", TAG_GETATTR_FSLOCATION},
	{"inactive", TAG_INACTIVE},
	{"link", TAG_LINK},
	{"lock", TAG_LOCK},
	{"reclaim lock", TAG_LOCK_RECLAIM},
	{"resend lock", TAG_LOCK_RESEND},
	{"reinstate lock", TAG_LOCK_REINSTATE},
	{"unknown lock", TAG_LOCK_UNKNOWN},
	{"lock test", TAG_LOCKT},
	{"unlock", TAG_LOCKU},
	{"resend locku", TAG_LOCKU_RESEND},
	{"reinstate unlock", TAG_LOCKU_REINSTATE},
	{"lookup", TAG_LOOKUP},
	{"lookup parent", TAG_LOOKUP_PARENT},
	{"lookup valid", TAG_LOOKUP_VALID},
	{"lookup valid parent", TAG_LOOKUP_VPARENT},
	{"mkdir", TAG_MKDIR},
	{"mknod", TAG_MKNOD},
	{"mount", TAG_MOUNT},
	{"open", TAG_OPEN},
	{"open confirm", TAG_OPEN_CONFIRM},
	{"lost open confirm", TAG_OPEN_CONFIRM_LOST},
	{"open downgrade", TAG_OPEN_DG},
	{"lost open downgrade", TAG_OPEN_DG_LOST},
	{"lost open", TAG_OPEN_LOST},
	{"openattr", TAG_OPENATTR},
	{"pathconf", TAG_PATHCONF},
	{"putrootfh", TAG_PUTROOTFH},
	{"read", TAG_READ},
	{"readahead", TAG_READAHEAD},
	{"readdir", TAG_READDIR},
	{"readlink", TAG_READLINK},
	{"relock", TAG_RELOCK},
	{"remap lookup", TAG_REMAP_LOOKUP},
	{"remap lookup attr dir", TAG_REMAP_LOOKUP_AD},
	{"remap lookup named attrs", TAG_REMAP_LOOKUP_NA},
	{"remap mount", TAG_REMAP_MOUNT},
	{"rmdir", TAG_RMDIR},
	{"remove", TAG_REMOVE},
	{"rename", TAG_RENAME},
	{"rename volatile fh", TAG_RENAME_VFH},
	{"renew", TAG_RENEW},
	{"reopen", TAG_REOPEN},
	{"lost reopen", TAG_REOPEN_LOST},
	{"secinfo", TAG_SECINFO},
	{"setattr", TAG_SETATTR},
	{"setclientid", TAG_SETCLIENTID},
	{"setclientid_confirm", TAG_SETCLIENTID_CF},
	{"symlink", TAG_SYMLINK},
	{"write", TAG_WRITE},
	{NULL, 0}
};

static const char *
nfs4_tag_str(nfs4_tag_type_t tt)
{
	int i;

	for (i = 0; nfs4_tag_tbl[i].str != NULL; i++)
		if (nfs4_tag_tbl[i].tt == tt)
			return (nfs4_tag_tbl[i].str);

	return ("??");
}

/*
 * nfs_mntinfo dcmd implementation
 */

static const mdb_bitmask_t nfs_mi_flags[] = {
	{"MI_HARD", MI_HARD, MI_HARD},
	{"MI_PRINTED", MI_PRINTED, MI_PRINTED},
	{"MI_INT", MI_INT, MI_INT},
	{"MI_DOWN", MI_DOWN, MI_DOWN},
	{"MI_NOAC", MI_NOAC, MI_NOAC},
	{"MI_NOCTO", MI_NOCTO, MI_NOCTO},
	{"MI_DYNAMIC", MI_DYNAMIC, MI_DYNAMIC},
	{"MI_LLOCK", MI_LLOCK, MI_LLOCK},
	{"MI_GRPID", MI_GRPID, MI_GRPID},
	{"MI_RPCTIMESYNC", MI_RPCTIMESYNC, MI_RPCTIMESYNC},
	{"MI_LINK", MI_LINK, MI_LINK},
	{"MI_SYMLINK", MI_SYMLINK, MI_SYMLINK},
	{"MI_READDIRONLY", MI_READDIRONLY, MI_READDIRONLY},
	{"MI_ACL", MI_ACL, MI_ACL},
	{"MI_BINDINPROG", MI_BINDINPROG, MI_BINDINPROG},
	{"MI_LOOPBACK", MI_LOOPBACK, MI_LOOPBACK},
	{"MI_SEMISOFT", MI_SEMISOFT, MI_SEMISOFT},
	{"MI_NOPRINT", MI_NOPRINT, MI_NOPRINT},
	{"MI_DIRECTIO", MI_DIRECTIO, MI_DIRECTIO},
	{"MI_EXTATTR", MI_EXTATTR, MI_EXTATTR},
	{"MI_ASYNC_MGR_STOP", MI_ASYNC_MGR_STOP, MI_ASYNC_MGR_STOP},
	{"MI_DEAD", MI_DEAD, MI_DEAD},
	{NULL, 0, 0}
};

static int
nfs_print_mntinfo_cb(uintptr_t addr, const void *data, void *cb_data)
{
	const mntinfo_t *mi = data;
	uintptr_t nfs3_ops;
	vfs_t vfs;
	char buf[MAXPATHLEN];
	uint_t opt_v = *(uint_t *)cb_data;
	int i;

	if (mdb_readvar(&nfs3_ops, "nfs3_vfsops") == -1) {
		mdb_warn("failed to read %s", "nfs3_vfsops");
		return (WALK_ERR);
	}

	if (mdb_vread(&vfs, sizeof (vfs), (uintptr_t)mi->mi_vfsp) == -1) {
		mdb_warn("failed to read vfs_t at %p", mi->mi_vfsp);
		return (WALK_ERR);
	}

	mdb_printf("NFS Version: %d\n",
	    nfs3_ops == (uintptr_t)vfs.vfs_op ? 3 : 2);
	mdb_inc_indent(2);

	mdb_printf("mi_flags:    %b\n", mi->mi_flags, nfs_mi_flags);
	if (mdb_read_refstr((uintptr_t)vfs.vfs_mntpt, buf,
	    sizeof (buf)) == -1)
		strcpy(buf, "??");
	mdb_printf("mount point: %s\n", buf);
	if (mdb_read_refstr((uintptr_t)vfs.vfs_resource, buf,
	    sizeof (buf)) == -1)
		strcpy(buf, "??");
	mdb_printf("mount from:  %s\n", buf);

	mdb_dec_indent(2);
	mdb_printf("\n");

	if (!opt_v)
		return (WALK_NEXT);

	mdb_inc_indent(2);

	mdb_printf("mi_zone = %p\n", mi->mi_zone);
	mdb_printf("mi_curread = %i, mi_curwrite = %i, mi_retrans = %i, "
	    "mi_timeo = %i\n", mi->mi_curread, mi->mi_curwrite, mi->mi_retrans,
	    mi->mi_timeo);
	mdb_printf("mi_acregmin = %lu, mi_acregmax = %lu, mi_acdirmin = %lu, "
	    "mi_acdirmax = %lu\n", mi->mi_acregmin, mi->mi_acregmax,
	    mi->mi_acdirmin, mi->mi_acdirmax);

	mdb_printf("\nServer list: %p\n", mi->mi_servers);
	mdb_inc_indent(2);
	if (mdb_pwalk_dcmd("nfs_serv", "nfs_servinfo", 0, NULL,
	    (uintptr_t)mi->mi_servers) == -1)
		mdb_printf("??\n");
	mdb_dec_indent(2);

	mdb_printf("Current Server: %p ", mi->mi_curr_serv);
	if (mdb_call_dcmd("nfs_servinfo", (uintptr_t)mi->mi_curr_serv,
	    DCMD_ADDRSPEC, 0, NULL) == -1)
		mdb_printf("??\n");

	mdb_printf(
	    "\nTotal: Server Non-responses = %u, Server Failovers = %u\n",
	    mi->mi_noresponse, mi->mi_failover);

	if (mi->mi_io_kstats != NULL)
		nfs_print_io_stat((uintptr_t)mi->mi_io_kstats);

	mdb_printf("\nAsync Request queue:\n");
	mdb_inc_indent(2);
	mdb_printf("max threads = %u, active threads = %u\n",
	    mi->mi_max_threads, mi->mi_threads[NFS_ASYNC_QUEUE]);
	mdb_printf("Async reserved page operation only active threads = %u\n",
	    mi->mi_threads[NFS_ASYNC_PGOPS_QUEUE]);
	mdb_printf("number requests queued:\n");
	for (i = 0; i < NFS_ASYNC_TYPES; i++) {
		const char *opname;
		size_t count = 0;

		switch (i) {
		case NFS_PUTAPAGE:
			opname = "PUTAPAGE";
			break;
		case NFS_PAGEIO:
			opname = "PAGEIO";
			break;
		case NFS_COMMIT:
			opname = "COMMIT";
			break;
		case NFS_READ_AHEAD:
			opname = "READ_AHEAD";
			break;
		case NFS_READDIR:
			opname = "READDIR";
			break;
		case NFS_INACTIVE:
			opname = "INACTIVE";
			break;
		default:
			opname = "??";
			break;
		}

		if (mi->mi_async_reqs[i] == NULL || mdb_pwalk("nfs_async",
		    walk_count_cb, &count, (uintptr_t)mi->mi_async_reqs[i])
		    == -1)
			mdb_printf("\t%s = ??", opname);
		else
			mdb_printf("\t%s = %llu", opname, count);
	}
	mdb_printf("\n");
	mdb_dec_indent(2);

	if (mi->mi_printftime)
		mdb_printf("\nLast error report time = %Y\n",
		    mi->mi_printftime);

	mdb_dec_indent(2);
	mdb_printf("\n");

	return (WALK_NEXT);
}

int
nfs_mntinfo_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mntinfo_t mi;
	uint_t opt_v = FALSE;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &opt_v, NULL) != argc)
		return (DCMD_USAGE);

	if ((flags & DCMD_ADDRSPEC) == 0) {
		if (mdb_walk("nfs_mnt", nfs_print_mntinfo_cb, &opt_v) == -1) {
			mdb_warn("failed to walk nfs_mnt");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (mdb_vread(&mi, sizeof (mi), addr) == -1) {
		mdb_warn("failed to read mntinfo_t");
		return (DCMD_ERR);
	}

	return (nfs_print_mntinfo_cb(addr, &mi, &opt_v) == WALK_ERR ? DCMD_ERR
	    : DCMD_OK);
}

void
nfs_mntinfo_help(void)
{
	mdb_printf("-v       verbose information\n");
}

/*
 * nfs_servinfo dcmd implementation
 */

int
nfs_servinfo_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	servinfo_t si;
	uint_t opt_v = FALSE;
	const char *addr_str;
	struct knetconfig knconf;
	char *hostname;
	int i;

	if ((flags & DCMD_ADDRSPEC) == 0) {
		mdb_printf("requires address of servinfo_t\n");
		return (DCMD_USAGE);
	}

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &opt_v, NULL) != argc)
		return (DCMD_USAGE);

	if (mdb_vread(&si, sizeof (si), addr) == -1) {
		mdb_warn("can't read servinfo_t");
		return (DCMD_ERR);
	}

	addr_str = common_netbuf_str(&si.sv_addr);

	if (!opt_v) {
		mdb_printf("%s\n", addr_str);
		return (DCMD_OK);
	}

	mdb_printf("secdata ptr = %p\n", si.sv_secdata);

	mdb_printf("address = ");
	if (mdb_vread(&knconf, sizeof (knconf),
	    (uintptr_t)si.sv_knconf) == -1) {
		mdb_printf("?\?/?\?/??");
	} else {
		char knc_str[KNC_STRSIZE];

		mdb_printf("%u", knconf.knc_semantics);

		if (mdb_readstr(knc_str, sizeof (knc_str),
		    (uintptr_t)knconf.knc_protofmly) == -1)
			mdb_printf("/??");
		else
			mdb_printf("/%s", knc_str);

		if (mdb_readstr(knc_str, sizeof (knc_str),
		    (uintptr_t)knconf.knc_proto) == -1)
			mdb_printf("/??");
		else
			mdb_printf("/%s", knc_str);
	}
	mdb_printf("/%s\n", addr_str);

	if (si.sv_hostnamelen <= 0 || (hostname = mdb_alloc(si.sv_hostnamelen,
	    UM_NOSLEEP | UM_GC)) == NULL || mdb_readstr(hostname,
	    si.sv_hostnamelen, (uintptr_t)si.sv_hostname) == -1)
		mdb_printf("hostname = ??\n");
	else
		mdb_printf("hostname = %s\n", hostname);

	mdb_printf("filehandle = ");
	if (si.sv_fhandle.fh_len >= 0 &&
	    si.sv_fhandle.fh_len <= NFS_FHANDLE_LEN)
		for (i = 0; i < si.sv_fhandle.fh_len; i++)
			mdb_printf("%02x",
			    (unsigned char)si.sv_fhandle.fh_buf[i]);
	else
		mdb_printf("??");
	mdb_printf("\n\n");

	return (DCMD_OK);
}

void
nfs_servinfo_help(void)
{
	mdb_printf("-v       verbose information\n");
}

/*
 * nfs4_mntinfo dcmd implementation
 */

static const mdb_bitmask_t nfs_mi4_flags[] = {
	{"MI4_HARD", MI4_HARD, MI4_HARD},
	{"MI4_PRINTED", MI4_PRINTED, MI4_PRINTED},
	{"MI4_INT", MI4_INT, MI4_INT},
	{"MI4_DOWN", MI4_DOWN, MI4_DOWN},
	{"MI4_NOAC", MI4_NOAC, MI4_NOAC},
	{"MI4_NOCTO", MI4_NOCTO, MI4_NOCTO},
	{"MI4_LLOCK", MI4_LLOCK, MI4_LLOCK},
	{"MI4_GRPID", MI4_GRPID, MI4_GRPID},
	{"MI4_SHUTDOWN", MI4_SHUTDOWN, MI4_SHUTDOWN},
	{"MI4_LINK", MI4_LINK, MI4_LINK},
	{"MI4_SYMLINK", MI4_SYMLINK, MI4_SYMLINK},
	{"MI4_EPHEMERAL_RECURSED", MI4_EPHEMERAL_RECURSED,
		MI4_EPHEMERAL_RECURSED},
	{"MI4_ACL", MI4_ACL, MI4_ACL},
	{"MI4_MIRRORMOUNT", MI4_MIRRORMOUNT, MI4_MIRRORMOUNT},
	{"MI4_REFERRAL", MI4_REFERRAL, MI4_REFERRAL},
	{"MI4_EPHEMERAL", MI4_EPHEMERAL, MI4_EPHEMERAL},
	{"MI4_NOPRINT", MI4_NOPRINT, MI4_NOPRINT},
	{"MI4_DIRECTIO", MI4_DIRECTIO, MI4_DIRECTIO},
	{"MI4_RECOV_ACTIV", MI4_RECOV_ACTIV, MI4_RECOV_ACTIV},
	{"MI4_REMOVE_ON_LAST_CLOSE", MI4_REMOVE_ON_LAST_CLOSE,
		MI4_REMOVE_ON_LAST_CLOSE},
	{"MI4_RECOV_FAIL", MI4_RECOV_FAIL, MI4_RECOV_FAIL},
	{"MI4_PUBLIC", MI4_PUBLIC, MI4_PUBLIC},
	{"MI4_MOUNTING", MI4_MOUNTING, MI4_MOUNTING},
	{"MI4_POSIX_LOCK", MI4_POSIX_LOCK, MI4_POSIX_LOCK},
	{"MI4_LOCK_DEBUG", MI4_LOCK_DEBUG, MI4_LOCK_DEBUG},
	{"MI4_DEAD", MI4_DEAD, MI4_DEAD},
	{"MI4_INACTIVE_IDLE", MI4_INACTIVE_IDLE, MI4_INACTIVE_IDLE},
	{"MI4_BADOWNER_DEBUG", MI4_BADOWNER_DEBUG, MI4_BADOWNER_DEBUG},
	{"MI4_ASYNC_MGR_STOP", MI4_ASYNC_MGR_STOP, MI4_ASYNC_MGR_STOP},
	{"MI4_TIMEDOUT", MI4_TIMEDOUT, MI4_TIMEDOUT},
	{NULL, 0, 0}
};

static const mdb_bitmask_t nfs_mi4_recovflags[] = {
	{"MI4R_NEED_CLIENTID", MI4R_NEED_CLIENTID, MI4R_NEED_CLIENTID},
	{"MI4R_REOPEN_FILES", MI4R_REOPEN_FILES, MI4R_REOPEN_FILES},
	{"MI4R_NEED_SECINFO", MI4R_NEED_SECINFO, MI4R_NEED_SECINFO},
	{"MI4R_NEED_NEW_SERVER", MI4R_NEED_NEW_SERVER, MI4R_NEED_NEW_SERVER},
	{"MI4R_REMAP_FILES", MI4R_REMAP_FILES, MI4R_REMAP_FILES},
	{"MI4R_SRV_REBOOT", MI4R_SRV_REBOOT, MI4R_SRV_REBOOT},
	{"MI4R_LOST_STATE", MI4R_LOST_STATE, MI4R_LOST_STATE},
	{"MI4R_BAD_SEQID", MI4R_BAD_SEQID, MI4R_BAD_SEQID},
	{"MI4R_MOVED", MI4R_MOVED, MI4R_MOVED},
	{NULL, 0, 0}
};

int
nfs4_mntinfo_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mntinfo4_t mi;
	vfs_t vfs;
	char buf[MAXPATHLEN];
	uint_t opt_m = FALSE;
	uint_t opt_v = FALSE;

	if ((flags & DCMD_ADDRSPEC) == 0) {
		if (mdb_walk_dcmd("nfs4_mnt", "nfs4_mntinfo", argc,
		    argv) == -1) {
			mdb_warn("failed to walk nfs4_mnt");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (mdb_getopts(argc, argv,
	    'm', MDB_OPT_SETBITS, TRUE, &opt_m,
	    'v', MDB_OPT_SETBITS, TRUE, &opt_v, NULL) != argc)
		return (DCMD_USAGE);

	if (mdb_vread(&mi, sizeof (mi), addr) == -1) {
		mdb_warn("failed to read mntinfo4_t at %p", addr);
		return (DCMD_ERR);
	}

	if (mdb_vread(&vfs, sizeof (vfs), (uintptr_t)mi.mi_vfsp) == -1) {
		mdb_warn("failed to read vfs_t at %p", mi.mi_vfsp);
		return (DCMD_ERR);
	}

	mdb_printf("+--------------------------------------+\n");
	mdb_printf("    mntinfo4_t: 0x%p\n", addr);
	mdb_printf("   NFS Version: 4\n");
	mdb_printf("      mi_flags: %b\n", mi.mi_flags, nfs_mi4_flags);
	mdb_printf("      mi_error: %u\n", mi.mi_error);
	mdb_printf(" mi_open_files: %i\n", mi.mi_open_files);
	mdb_printf("  mi_msg_count: %i\n", mi.mi_msg_count);
	mdb_printf(" mi_recovflags: %b\n", mi.mi_recovflags,
	    nfs_mi4_recovflags);
	mdb_printf("mi_recovthread: 0x%p\n", mi.mi_recovthread);
	mdb_printf("mi_in_recovery: %i\n", mi.mi_in_recovery);

	if (mdb_read_refstr((uintptr_t)vfs.vfs_mntpt, buf,
	    sizeof (buf)) == -1)
		strcpy(buf, "??");
	mdb_printf("   mount point: %s\n", buf);
	if (mdb_read_refstr((uintptr_t)vfs.vfs_resource, buf,
	    sizeof (buf)) == -1)
		strcpy(buf, "??");
	mdb_printf("    mount from: %s\n", buf);

	if (opt_v) {
		int i;

		mdb_printf("\n");
		mdb_inc_indent(2);

		mdb_printf("mi_zone = %p\n", mi.mi_zone);
		mdb_printf("mi_curread = %i, mi_curwrite = %i, "
		    "mi_retrans = %i, mi_timeo = %i\n", mi.mi_curread,
		    mi.mi_curwrite, mi.mi_retrans, mi.mi_timeo);
		mdb_printf("mi_acregmin = %lu, mi_acregmax = %lu, "
		    "mi_acdirmin = %lu, mi_acdirmax = %lu\n", mi.mi_acregmin,
		    mi.mi_acregmax, mi.mi_acdirmin, mi.mi_acdirmax);

		mdb_printf("\nServer list: %p\n", mi.mi_servers);
		mdb_inc_indent(2);
		if (mdb_pwalk_dcmd("nfs4_serv", "nfs4_servinfo", 0, NULL,
		    (uintptr_t)mi.mi_servers) == -1)
			mdb_printf("??\n");
		mdb_dec_indent(2);

		mdb_printf("Current Server: %p ", mi.mi_curr_serv);
		if (mdb_call_dcmd("nfs4_servinfo", (uintptr_t)mi.mi_curr_serv,
		    DCMD_ADDRSPEC, 0, NULL) == -1)
			mdb_printf("??\n");

		mdb_printf("\nTotal: Server Non-responses = %u, "
		    "Server Failovers = %u\n", mi.mi_noresponse,
		    mi.mi_failover);

		if (mi.mi_io_kstats != NULL)
			nfs_print_io_stat((uintptr_t)mi.mi_io_kstats);

		mdb_printf("\nAsync Request queue:\n");
		mdb_inc_indent(2);
		mdb_printf("max threads = %u, active threads = %u\n",
		    mi.mi_max_threads, mi.mi_threads[NFS4_ASYNC_QUEUE]);
		mdb_printf("Async reserved page operation only active "
		    "threads = %u\n", mi.mi_threads[NFS4_ASYNC_PGOPS_QUEUE]);
		mdb_printf("number requests queued:\n");
		for (i = 0; i < NFS4_ASYNC_TYPES; i++) {
			const char *opname;
			size_t count = 0;

			switch (i) {
			case NFS4_PUTAPAGE:
				opname = "PUTAPAGE";
				break;
			case NFS4_PAGEIO:
				opname = "PAGEIO";
				break;
			case NFS4_COMMIT:
				opname = "COMMIT";
				break;
			case NFS4_READ_AHEAD:
				opname = "READ_AHEAD";
				break;
			case NFS4_READDIR:
				opname = "READDIR";
				break;
			case NFS4_INACTIVE:
				opname = "INACTIVE";
				break;
			default:
				opname = "??";
				break;
			}

			if (mi.mi_async_reqs[i] != NULL &&
			    mdb_pwalk("nfs4_async", walk_count_cb, &count,
			    (uintptr_t)mi.mi_async_reqs[i]) == -1)
				mdb_printf("\t%s = ??", opname);
			else
				mdb_printf("\t%s = %llu", opname, count);
		}
		mdb_printf("\n");
		mdb_dec_indent(2);

		mdb_dec_indent(2);
	}

	return (DCMD_OK);
}

void
nfs4_mntinfo_help(void)
{
	mdb_printf("<mntinfo4>::nfs4_mntinfo  -> gives mntinfo4_t information\n"
	    "          ::nfs4_mntinfo  -> walks thru all NFSv4 mntinfo4_t\n"
	    "Each of these formats also takes the following argument\n"
	    "        -v      -> Verbose output\n");
}

/*
 * nfs4_servinfo dcmd implementation
 */

int
nfs4_servinfo_dcmd(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	servinfo4_t si;
	uint_t opt_v = FALSE;
	const char *addr_str;
	struct knetconfig knconf;
	char *hostname;
	int i;

	if ((flags & DCMD_ADDRSPEC) == 0) {
		mdb_printf("requires address of servinfo4_t\n");
		return (DCMD_USAGE);
	}

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &opt_v, NULL) != argc)
		return (DCMD_USAGE);

	if (mdb_vread(&si, sizeof (si), addr) == -1) {
		mdb_warn("can't read servinfo_t");
		return (DCMD_ERR);
	}

	addr_str = common_netbuf_str(&si.sv_addr);

	if (!opt_v) {
		mdb_printf("%s\n", addr_str);
		return (DCMD_OK);
	}

	mdb_printf("secdata ptr = %p\n", si.sv_secdata);

	mdb_printf("address = ");
	if (mdb_vread(&knconf, sizeof (knconf),
	    (uintptr_t)si.sv_knconf) == -1) {
		mdb_printf("?\?/?\?/??");
	} else {
		char knc_str[KNC_STRSIZE];

		mdb_printf("%u", knconf.knc_semantics);

		if (mdb_readstr(knc_str, sizeof (knc_str),
		    (uintptr_t)knconf.knc_protofmly) == -1)
			mdb_printf("/??");
		else
			mdb_printf("/%s", knc_str);

		if (mdb_readstr(knc_str, sizeof (knc_str),
		    (uintptr_t)knconf.knc_proto) == -1)
			mdb_printf("/??");
		else
			mdb_printf("/%s", knc_str);
	}
	mdb_printf("/%s\n", addr_str);

	if (si.sv_hostnamelen <= 0 || (hostname = mdb_alloc(si.sv_hostnamelen,
	    UM_NOSLEEP | UM_GC)) == NULL || mdb_readstr(hostname,
	    si.sv_hostnamelen, (uintptr_t)si.sv_hostname) == -1)
		mdb_printf("hostname = ??\n");
	else
		mdb_printf("hostname = %s\n", hostname);

	mdb_printf("server filehandle = ");
	if (si.sv_fhandle.fh_len >= 0 && si.sv_fhandle.fh_len <= NFS4_FHSIZE)
		for (i = 0; i < si.sv_fhandle.fh_len; i++)
			mdb_printf("%02x",
			    (unsigned char)si.sv_fhandle.fh_buf[i]);
	else
		mdb_printf("??");

	mdb_printf("\nparent dir filehandle = ");
	if (si.sv_pfhandle.fh_len >= 0 && si.sv_pfhandle.fh_len <= NFS4_FHSIZE)
		for (i = 0; i < si.sv_pfhandle.fh_len; i++)
			mdb_printf("%02x",
			    (unsigned char)si.sv_pfhandle.fh_buf[i]);
	else
		mdb_printf("??");
	mdb_printf("\n\n");

	return (DCMD_OK);
}

void
nfs4_servinfo_help(void)
{
	mdb_printf("-v       verbose information\n");
}

/*
 * nfs4_server_info dcmd implementation
 */

static const mdb_bitmask_t nfs4_si_flags[] = {
	{"N4S_CLIENTID_SET", N4S_CLIENTID_SET, N4S_CLIENTID_SET},
	{"N4S_CLIENTID_PEND", N4S_CLIENTID_PEND, N4S_CLIENTID_PEND},
	{"N4S_CB_PINGED", N4S_CB_PINGED, N4S_CB_PINGED},
	{"N4S_CB_WAITER", N4S_CB_WAITER, N4S_CB_WAITER},
	{"N4S_INSERTED", N4S_INSERTED, N4S_INSERTED},
	{"N4S_BADOWNER_DEBUG", N4S_BADOWNER_DEBUG, N4S_BADOWNER_DEBUG},
	{NULL, 0, 0}
};

int
nfs4_server_info_dcmd(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	nfs4_server_t srv;
	char *id_val;
	uint_t opt_c = FALSE;
	uint_t opt_s = FALSE;

	if ((flags & DCMD_ADDRSPEC) == 0) {
		if (mdb_walk_dcmd("nfs4_server", "nfs4_server_info", argc, argv)
		    == -1) {
			mdb_warn("nfs4_server walker failed");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (mdb_getopts(argc, argv,
	    'c', MDB_OPT_SETBITS, TRUE, &opt_c,
	    's', MDB_OPT_SETBITS, TRUE, &opt_s, NULL) != argc)
		return (DCMD_USAGE);

	if (mdb_vread(&srv, sizeof (srv), addr) == -1) {
		mdb_warn("failed to read nfs4_server_t at %p", addr);
		return (DCMD_ERR);
	}

	if (srv.saddr.len == 0)
		return (DCMD_OK);

	mdb_printf("Address: %p Zone: %i Server: %s\n", addr, srv.zoneid,
	    common_netbuf_str(&srv.saddr));
	mdb_printf("Program: %x Flags: %b\n", srv.s_program, srv.s_flags,
	    nfs4_si_flags);
	mdb_printf("Client ID: %#llx", srv.clientid);
	if (opt_s) {
		struct {
			uint32_t start_time;
			uint32_t c_id;
		} *impl_id = (void *)&srv.clientid;
		mdb_printf(" (srvrboot: %Y, c_id: %u)", impl_id->start_time,
		    impl_id->c_id);
	}

	mdb_printf("\nCLIDtoSend: [verifier: %llx", srv.clidtosend.verifier);
	if (opt_c) {
		struct {
			uint32_t sec;
			uint32_t subsec;
		} *curtime = (void *)&srv.clidtosend.verifier;
		mdb_printf(" (%Y + %u nsec)", curtime->sec, curtime->subsec);
	}

	mdb_printf(", client identifier: ");
	id_val = mdb_alloc(srv.clidtosend.id_len, UM_NOSLEEP | UM_GC);
	if (id_val != NULL && mdb_vread(id_val, srv.clidtosend.id_len,
	    (uintptr_t)srv.clidtosend.id_val) == srv.clidtosend.id_len) {
		uint_t i;

		if (opt_c) {
			size_t l;
			struct netbuf nb;

			l = strlen(id_val) + 1;
			nb.len = nb.maxlen = srv.clidtosend.id_len - l;
			nb.buf = srv.clidtosend.id_val + l;
			mdb_printf("(%s/%s) ", id_val, common_netbuf_str(&nb));
		}

		for (i = 0; i < srv.clidtosend.id_len; i++)
			mdb_printf("%02x", (unsigned char)id_val[i]);
	} else {
		mdb_printf("??");
	}
	mdb_printf(" ]\n");

	mdb_printf("mntinfo4 list: %p\n", srv.mntinfo4_list);
	mdb_printf("Deleg list: %p ::walk list\n", addr +
	    OFFSETOF(nfs4_server_t, s_deleg_list));
	mdb_printf("Lease Valid: ");
	switch (srv.lease_valid) {
	case NFS4_LEASE_INVALID:
		mdb_printf("INVALID\n");
		break;
	case NFS4_LEASE_VALID:
		mdb_printf("VALID\n");
		break;
	case NFS4_LEASE_UNINITIALIZED:
		mdb_printf("UNINIT\n");
		break;
	case NFS4_LEASE_NOT_STARTED:
		mdb_printf("NOT_STARTED\n");
		break;
	default:
		mdb_printf("??\n");
		break;
	}

	mdb_printf("Lease Time: %i sec\n", srv.s_lease_time);
	mdb_printf("Last renewal: %Y\n", srv.last_renewal_time);
	mdb_printf("Propgn Delay: %li sec : %li nsec\n",
	    srv.propagation_delay.tv_sec, srv.propagation_delay.tv_nsec);
	mdb_printf("Credential: %p\n\n", srv.s_cred);

	return (DCMD_OK);
}

void
nfs4_server_info_help(void)
{
	mdb_printf(
	    "-c       assumes client is an illumos NFSv4 Client\n"
	    "-s       assumes server is an illumos NFSv4 Server\n"
	    "\n"
	    "The -c option enables the dcmd to decode the client generated\n"
	    "structure CLIDtoSend that is normally opaque to the server.\n"
	    "The -s option enables the dcmd to decode the server generated\n"
	    "structure Client ID that is normally opaque to the client.\n");
}

/*
 * nfs4_mimsg dcmd implementation
 */

static const struct {
	const char *str;
	nfs4_event_type_t et;
} nfs4_event_type_tbl[] = {
	TBL_ENTRY(RE_BAD_SEQID),
	TBL_ENTRY(RE_BADHANDLE),
	TBL_ENTRY(RE_CLIENTID),
	TBL_ENTRY(RE_DEAD_FILE),
	TBL_ENTRY(RE_END),
	TBL_ENTRY(RE_FAIL_RELOCK),
	TBL_ENTRY(RE_FAIL_REMAP_LEN),
	TBL_ENTRY(RE_FAIL_REMAP_OP),
	TBL_ENTRY(RE_FAILOVER),
	TBL_ENTRY(RE_FILE_DIFF),
	TBL_ENTRY(RE_LOST_STATE),
	TBL_ENTRY(RE_OPENS_CHANGED),
	TBL_ENTRY(RE_SIGLOST),
	TBL_ENTRY(RE_SIGLOST_NO_DUMP),
	TBL_ENTRY(RE_START),
	TBL_ENTRY(RE_UNEXPECTED_ACTION),
	TBL_ENTRY(RE_UNEXPECTED_ERRNO),
	TBL_ENTRY(RE_UNEXPECTED_STATUS),
	TBL_ENTRY(RE_WRONGSEC),
	TBL_ENTRY(RE_LOST_STATE_BAD_OP),
	TBL_ENTRY(RE_REFERRAL),
	{NULL}
};

static const struct {
	const char *str;
	nfs4_fact_type_t ft;
} nfs4_fact_type_tbl[] = {
	TBL_ENTRY(RF_BADOWNER),
	TBL_ENTRY(RF_ERR),
	TBL_ENTRY(RF_RENEW_EXPIRED),
	TBL_ENTRY(RF_SRV_NOT_RESPOND),
	TBL_ENTRY(RF_SRV_OK),
	TBL_ENTRY(RF_SRVS_NOT_RESPOND),
	TBL_ENTRY(RF_SRVS_OK),
	TBL_ENTRY(RF_DELMAP_CB_ERR),
	TBL_ENTRY(RF_SENDQ_FULL),
	{NULL}
};

static void
mimsg_print_event(const nfs4_debug_msg_t *msg)
{
	const nfs4_revent_t *ep = &msg->rmsg_u.msg_event;
	char msg_srv[MAXPATHLEN];
	char msg_mntpt[MAXPATHLEN];
	char char1[MAXPATHLEN];
	char *char1p = char1;
	char char2[MAXPATHLEN];
	char *char2p = char2;

	if (mdb_readstr(msg_srv, sizeof (msg_srv),
	    (uintptr_t)msg->msg_srv) == -1)
		strcpy(msg_srv, "??");

	if (mdb_readstr(msg_mntpt, sizeof (msg_mntpt),
	    (uintptr_t)msg->msg_mntpt) == -1)
		strcpy(msg_mntpt, "??");

	if (ep->re_char1 != NULL) {
		if (mdb_readstr(char1, sizeof (char1),
		    (uintptr_t)ep->re_char1) == -1)
			strcpy(char1, "??");
	} else {
		char1[0] = '\0';
		char1p = NULL;
	}

	if (ep->re_char2 != NULL) {
		if (mdb_readstr(char2, sizeof (char2),
		    (uintptr_t)ep->re_char2) == -1)
			strcpy(char2, "??");
	} else {
		char2[0] = '\0';
		char2p = NULL;
	}

	switch (ep->re_type) {
	case RE_BAD_SEQID:
		mdb_printf("Operation %s for file %s (rnode_pt 0x%p), pid %d "
		    "using seqid %u got %s on server %s.  Last good seqid was "
		    "%u for operation %s.", nfs4_tag_str(ep->re_tag1), char1p,
		    ep->re_rp1, ep->re_pid, ep->re_seqid1,
		    nfs4_stat_str(ep->re_stat4), msg_srv, ep->re_seqid2,
		    nfs4_tag_str(ep->re_tag2));
		break;
	case RE_BADHANDLE:
		if (ep->re_char1 != NULL) {
			mdb_printf("server %s said filehandle was invalid for "
			    "file: %s (rnode_pt %p) on mount %s", msg_srv,
			    char1, ep->re_rp1, msg_mntpt);
		} else {
			mdb_printf("server %s said filehandle was invalid for "
			    "file: (rnode_pt %p) on mount %s", msg_srv,
			    ep->re_rp1, msg_mntpt);
		}
		break;
	case RE_CLIENTID:
		mdb_printf("Can't recover clientid on mi 0x%p due to error %u "
		    "(%s), for server %s.  Marking file system as unusable.",
		    ep->re_mi, ep->re_uint, nfs4_stat_str(ep->re_stat4),
		    msg_srv);
		break;
	case RE_DEAD_FILE:
		mdb_printf("File %s (rnode_pt %p) on server %s could not be "
		    "recovered and was closed.  %s %s.", char1p, ep->re_rp1,
		    msg_srv, char2,
		    ep->re_stat4 ? nfs4_stat_str(ep->re_stat4) : "");
		break;
	case RE_END:
		mdb_printf("Recovery done for mount %s (0x%p) on server %s, "
		    "rnode_pt1 %s (0x%p), rnode_pt2 %s (0x%p)", msg_mntpt,
		    ep->re_mi, msg_srv, char1p, ep->re_rp1, char2p, ep->re_rp2);
		break;
	case RE_FAIL_RELOCK:
		mdb_printf("Couldn't reclaim lock for pid %d for file %s "
		    "(rnode_pt %p) on (server %s): error %u", ep->re_pid,
		    char1p, ep->re_rp1, msg_srv,
		    ep->re_uint ? ep->re_uint : ep->re_stat4);
		break;
	case RE_FAIL_REMAP_LEN:
		mdb_printf("remap_lookup: server %s returned bad fhandle "
		    "length (%u)", msg_srv, ep->re_uint);
		break;
	case RE_FAIL_REMAP_OP:
		mdb_printf("remap_lookup: didn't get expected OP_GETFH for "
		    "server %s", msg_srv);
		break;
	case RE_FAILOVER:
		if (ep->re_char1)
			mdb_printf("Failing over from %s to %s", msg_srv,
			    char1p);
		else
			mdb_printf("Failing over: selecting original server %s",
			    msg_srv);
		break;
	case RE_FILE_DIFF:
		mdb_printf("Replicas %s and %s: file %s(%p) not same",
		    msg_srv, msg_mntpt, ep->re_char1, (void *)ep->re_rp1);
		break;
	case RE_LOST_STATE:
		/*
		 * if char1 is null you should use ::nfs4_fname for re_rp1
		 */
		mdb_printf("client has a lost %s request for rnode_pt1 %s "
		    "(0x%p), rnode_pt2 %s (0x%p) on fs %s, server %s.",
		    nfs4_op_str(ep->re_uint), char1p, ep->re_rp1, char2p,
		    ep->re_rp2, msg_mntpt, msg_srv);
		break;
	case RE_OPENS_CHANGED:
		mdb_printf("Recovery: number of open files changed "
		    "for mount %s (0x%p) (old %d, new %d) on server %s\n",
		    msg_mntpt, (void *)ep->re_mi, ep->re_uint, ep->re_pid,
		    msg_srv);
		break;
	case RE_SIGLOST:
	case RE_SIGLOST_NO_DUMP:
		mdb_printf("Process %d lost its locks on file %s (rnode_pt %p) "
		    "due to a NFS error (%u) on server %s", ep->re_pid, char1p,
		    ep->re_rp1, ep->re_uint ? ep->re_uint : ep->re_stat4,
		    msg_srv);
		break;
	case RE_START:
		mdb_printf("Starting recovery for mount %s (0x%p, flags %#x) "
		    "on server %s, rnode_pt1 %s (0x%p), rnode_pt2 %s (0x%p)",
		    msg_mntpt, ep->re_mi, ep->re_uint, msg_srv, char1p,
		    ep->re_rp1, char2p, ep->re_rp2);
		break;
	case RE_UNEXPECTED_ACTION:
		mdb_printf("Recovery, unexpected action (%d) on server %s\n",
		    ep->re_uint, msg_srv);
		break;
	case RE_UNEXPECTED_ERRNO:
		mdb_printf("Recovery, unexpected errno (%d) on server %s\n",
		    ep->re_uint, msg_srv);
		break;
	case RE_UNEXPECTED_STATUS:
		mdb_printf("Recovery, unexpected NFS status code (%s) "
		    "on server %s\n",
		    nfs4_stat_str(ep->re_stat4), msg_srv);
		break;
	case RE_WRONGSEC:
		mdb_printf("Recovery, can't recover from NFS4ERR_WRONGSEC."
		    " error %d for mount %s server %s: rnode_pt1 %s (0x%p)"
		    " rnode_pt2 %s (0x%p)", ep->re_uint, msg_mntpt, msg_srv,
		    ep->re_char1, (void *)ep->re_rp1, ep->re_char2,
		    (void *)ep->re_rp2);
		break;
	case RE_LOST_STATE_BAD_OP:
		mdb_printf("NFS lost state with unrecognized op (%d)."
		    " fs %s, server %s, pid %d, file %s (rnode_pt: 0x%p), "
		    "dir %s (0x%p)", ep->re_uint, msg_mntpt, msg_srv,
		    ep->re_pid, ep->re_char1, (void *)ep->re_rp1,
		    ep->re_char2, (void *)ep->re_rp2);
		break;
	case RE_REFERRAL:
		if (ep->re_char1)
			mdb_printf("Referal, Server: %s on Mntpt: %s"
			    "being referred from %s to %s", msg_srv,
			    msg_mntpt, msg_srv, ep->re_char1);
		else
			mdb_printf("Referal, Server: %s on Mntpt: %s"
			    "NFS4: being referred from %s to unknown server",
			    msg_srv, msg_mntpt, msg->msg_srv);
		break;
	default:
		mdb_printf("illegal event %d", ep->re_type);
		break;
	}
}

static void
mimsg_print_fact(const nfs4_debug_msg_t *msg)
{
	const nfs4_rfact_t *fp = &msg->rmsg_u.msg_fact;
	char msg_srv[MAXPATHLEN];
	char file[MAXPATHLEN];

	if (mdb_readstr(msg_srv, sizeof (msg_srv),
	    (uintptr_t)msg->msg_srv) == -1)
		strcpy(msg_srv, "??");

	switch (fp->rf_type) {
	case RF_BADOWNER:
		mdb_printf("NFSMAPID_DOMAIN does not match server: %s's "
		    "domain.", msg_srv);
		break;
	case RF_ERR:
		mdb_printf("Op %s got error ", nfs4_op_str(fp->rf_op));
		if (fp->rf_error)
			mdb_printf("%d", fp->rf_error);
		else
			mdb_printf("%s", nfs4_stat_str(fp->rf_stat4));
		mdb_printf(" causing recovery action %s.",
		    nfs4_recov_str(fp->rf_action));
		if (fp->rf_reboot)
			mdb_printf("  Client also suspects server rebooted");
		break;
	case RF_RENEW_EXPIRED:
		mdb_printf("Client's lease expired on server %s.", msg_srv);
		break;
	case RF_SRV_NOT_RESPOND:
		mdb_printf("Server %s not responding, still trying", msg_srv);
		break;
	case RF_SRV_OK:
		mdb_printf("Server %s ok", msg_srv);
		break;
	case RF_SRVS_NOT_RESPOND:
		mdb_printf("Servers %s not responding, still trying", msg_srv);
		break;
	case RF_SRVS_OK:
		mdb_printf("Servers %s ok", msg_srv);
		break;
	case RF_DELMAP_CB_ERR:
		if (mdb_readstr(file, sizeof (file),
		    (uintptr_t)fp->rf_char1) == -1)
			strcpy(file, "??");
		mdb_printf("Op %s got error %s when executing delmap on file "
		    "%s (rnode_pt 0x%p).", nfs4_op_str(fp->rf_op),
		    nfs4_stat_str(fp->rf_stat4), file, fp->rf_rp1);
		break;
	case RF_SENDQ_FULL:
		mdb_printf("Send queue to NFS server %s is full; still trying",
		    msg_srv);
		break;
	default:
		mdb_printf("??");
		break;
	}
}

static int
print_mimsg_cb(uintptr_t addr, const void *data, void *cb_data)
{
	nfs4_debug_msg_t msg;
	uint_t opt_s = *(uint_t *)cb_data;

	if (mdb_vread(&msg, sizeof (msg), addr) == -1) {
		mdb_warn("failed to read nfs4_debug_msg_t at %p", addr);
		return (WALK_ERR);
	}

	if (opt_s) {
		const char *msg_type = "??";
		const char *ef_type = "??";
		int i;

		switch (msg.msg_type) {
		case RM_EVENT:
			msg_type = "event";
			for (i = 0; nfs4_event_type_tbl[i].str != NULL; i++)
				if (nfs4_event_type_tbl[i].et ==
				    msg.rmsg_u.msg_event.re_type) {
					ef_type = nfs4_event_type_tbl[i].str;
					break;
				}
			break;
		case RM_FACT:
			msg_type = "fact";
			for (i = 0; nfs4_fact_type_tbl[i].str != NULL; i++)
				if (nfs4_fact_type_tbl[i].ft ==
				    msg.rmsg_u.msg_fact.rf_type) {
					ef_type = nfs4_fact_type_tbl[i].str;
					break;
				}
			break;
		}

		mdb_printf("%Y: %s %s\n", msg.msg_time.tv_sec, msg_type,
		    ef_type);

		return (WALK_NEXT);
	}

	mdb_printf("[NFS4]%Y: ", msg.msg_time.tv_sec);
	switch (msg.msg_type) {
	case RM_EVENT:
		mimsg_print_event(&msg);
		break;
	case RM_FACT:
		mimsg_print_fact(&msg);
		break;
	default:
		mdb_printf("??");
		break;
	}
	mdb_printf("\n");

	return (WALK_NEXT);
}

int
nfs4_mimsg_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t opt_s = FALSE;

	if ((flags & DCMD_ADDRSPEC) == 0) {
		mdb_printf("requires address of mi_msg_list\n");
		return (DCMD_USAGE);
	}

	if (mdb_getopts(argc, argv,
	    's', MDB_OPT_SETBITS, TRUE, &opt_s, NULL) != argc)
		return (DCMD_USAGE);

	if (mdb_pwalk("list", print_mimsg_cb, &opt_s, addr) == -1) {
		mdb_warn("failed to walk mi_msg_list list");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

void
nfs4_mimsg_help(void)
{
	mdb_printf(
	    "-c       assumes client is an illumos NFSv4 Client\n"
	    "-s       assumes server is an illumos NFSv4 Server\n"
	    "\n"
	    "The -c option enables the dcmd to decode the client generated\n"
	    "structure CLIDtoSend that is normally opaque to the server.\n"
	    "The -s option enables the dcmd to decode the server generated\n"
	    "structure Client ID that is normally opaque to the client.\n");
}

/*
 * nfs4_fname dcmd implementation
 */

static void
print_nfs4_fname(uintptr_t addr)
{
	char path[MAXPATHLEN];
	char *p = path + sizeof (path) - 1;

	*p = '\0';
	while (addr != 0) {
		nfs4_fname_t fn;
		char name[MAXNAMELEN];

		if (mdb_vread(&fn, sizeof (fn), addr) == -1 ||
		    fn.fn_len >= sizeof (name) || fn.fn_len < 0 ||
		    p - fn.fn_len - 1 < path || mdb_readstr(name, sizeof (name),
		    (uintptr_t)fn.fn_name) != fn.fn_len) {
			mdb_printf("??");
			break;
		}

		bcopy(name, p -= fn.fn_len, fn.fn_len);

		if ((addr = (uintptr_t)fn.fn_parent) != 0)
			*--p = '/';
	}
	mdb_printf("%s", p);
}

int
nfs4_fname_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if ((flags & DCMD_ADDRSPEC) == 0) {
		mdb_printf("requires address of nfs4_fname_t \n");
		return (DCMD_USAGE);
	}

	if (argc != 0)
		return (DCMD_USAGE);

	print_nfs4_fname(addr);
	mdb_printf("\n");

	return (DCMD_OK);
}

/*
 * Open Owner commands and walkers
 */
int
nfs4_oo_cb(uintptr_t addr, const void *data, void *varg)
{
	nfs4_open_owner_t	oop;

	if (mdb_vread(&oop, sizeof (nfs4_open_owner_t), addr) == -1) {
		mdb_warn("failed to read nfs4_open_onwer at %p", addr);
		return (WALK_ERR);
	}
	mdb_printf("%p %p %d %d %s %s\n", addr, oop.oo_cred,
	    oop.oo_ref_count, oop.oo_seqid,
	    oop.oo_just_created ? "True" : "False",
	    oop.oo_seqid_inuse  ? "True" : "False");

	return (WALK_NEXT);
}

/*
 * nfs4_foo dcmd implementation
 */
int
nfs4_foo_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int			foo_off;
	uintptr_t		list_addr;

	mntinfo4_t		mi;
	foo_off = offsetof(mntinfo4_t, mi_foo_list);

	if ((flags & DCMD_ADDRSPEC) == 0) {
		mdb_printf("requires address of mntinfo4_t\n");
		return (DCMD_USAGE);
	}

	if (argc != 0)
		return (DCMD_USAGE);

	if (mdb_vread(&mi, sizeof (mntinfo4_t), addr) == -1) {
		mdb_warn("Failed to read mntinfo at %p", addr);
		return (DCMD_ERR);
	}

	list_addr =  addr + foo_off;

	mdb_printf("mntinfo4: %p, mi_foo_num=%d, mi_foo_max=%d \n",
	    addr, mi.mi_foo_num, mi.mi_foo_max);
	mdb_printf("Address       Cred             RefCnt   SeqID    ");
	mdb_printf("JustCre SeqInUse BadSeqid\n");

	if (mdb_pwalk("list", nfs4_oo_cb, NULL, list_addr) == -1) {
		mdb_warn("failed to walk 'nfs4_foo'");
		return (DCMD_ERR);
	}
	return (DCMD_OK);
}

/*
 * nfs4_oob_dcmd dcmd
 */
int
nfs4_oob_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int			oo_off;
	uintptr_t		list_addr;
	uintptr_t		list_inst;
	int			i;


	if ((flags & DCMD_ADDRSPEC) == 0) {
		mdb_printf("requires address of mntinfo4_t\n");
		return (DCMD_USAGE);
	}

	if (argc != 0)
		return (DCMD_USAGE);

	oo_off = offsetof(mntinfo4_t, mi_oo_list);
	list_addr =  addr + oo_off;

	mdb_printf("Address       Cred             RefCnt   SeqID    ");
	mdb_printf("JustCre SeqInUse BadSeqid\n");

	for (i = 0; i < NFS4_NUM_OO_BUCKETS; i++) {
		list_inst = list_addr + (sizeof (nfs4_oo_hash_bucket_t) * i);

		if (mdb_pwalk("list", nfs4_oo_cb, NULL, list_inst) == -1) {
			mdb_warn("failed to walk 'nfs4_oob'");
			return (DCMD_ERR);
		}
	}

	return (DCMD_OK);
}

/*
 * print out open stream entry
 */
int
nfs4_openstream_print(uintptr_t addr, void *buf, int *opts)
{
	nfs4_open_stream_t	os;

	if (mdb_vread(&os, sizeof (nfs4_open_stream_t), addr) == -1) {
		mdb_warn("Failed to read open stream at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("%p\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t"
	    "%d\t%d\t%d\n", addr, os.os_ref_count, os.os_share_acc_read,
	    os.os_share_acc_write, os.os_mmap_read, os.os_mmap_write,
	    os.os_share_deny_none, os.os_share_deny_read,
	    os.os_share_deny_write, os.os_open_ref_count, os.os_dc_openacc,
	    os.os_mapcnt);

	if (opts && *opts & TRUE) {
		mdb_printf("  ");
		if (os.os_valid)
			mdb_printf("os_valid ");
		if (os.os_delegation)
			mdb_printf("os_delegation ");
		if (os.os_final_close)
			mdb_printf("os_final_close ");
		if (os.os_pending_close)
			mdb_printf("os_pending_close ");
		if (os.os_failed_reopen)
			mdb_printf("os_failed_reopen ");
		if (os.os_force_close)
			mdb_printf("os_force_close ");
		mdb_printf("os_orig_oo_name: %s\n",
		    (uchar_t *)&os.os_orig_oo_name);
	}
	return (DCMD_OK);
}

/*
 * nfs4_svnode dcmd implementation
 */
int
nfs4_openstreams_cb(uintptr_t addr, void *private, int *opts)
{
	mdb_ctf_id_t ctfid;
	ulong_t offset;
	uintptr_t os_list_ptr;

	/*
	 * Walk the rnode4 ptr's r_open_streams list.
	 */
	if ((mdb_ctf_lookup_by_name("rnode4_t", &ctfid) == 0) &&
	    (mdb_ctf_offsetof(ctfid, "r_open_streams", &offset) == 0) &&
	    (offset % (sizeof (uintptr_t) * NBBY) == 0)) {
		offset /= NBBY;
	} else {
		offset = offsetof(rnode4_t, r_open_streams);
	}

	os_list_ptr = addr + offset;

	if (mdb_pwalk("list", (mdb_walk_cb_t)nfs4_openstream_print, opts,
	    os_list_ptr) == -1) {
		mdb_warn("Failed to walk r_open_streams");
		return (DCMD_ERR);
	}
	return (DCMD_OK);
}

/*
 * nfs4_os_dcmd list open streams
 */
int
nfs4_os_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int opts = 0;

	if (mdb_getopts(argc, argv, 'v', MDB_OPT_SETBITS, TRUE, &opts,
	    NULL) != argc) {
		return (DCMD_USAGE);
	}

	mdb_printf("    ref\t|    os_share   |    os_mmap   |       "
	    "os_share_deny       |    open    |    deleg    |\t|\n");

	mdb_printf("%<u>%-?s %-s|%s %s|%s  %s|%s %s %s|"
	    "%s |%s |%s |%</u>\n", "Address", "count", "acc_read",
	    "acc_write", "read", "write", "none", "read", "write", "count",
	    "access", "mapcnt");

	/*
	 * Walk the rnode4 cache if no address is specified
	 */
	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk("nfs_rtable4", (mdb_walk_cb_t)nfs4_openstreams_cb,
		    &opts) == -1) {
			mdb_warn("unable to walk nfs_rtable4");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}
	return (nfs4_openstreams_cb(addr, NULL, &opts));
}


int
nfs4_svnode_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	svnode_t sn;

	if ((flags & DCMD_ADDRSPEC) == 0) {
		mdb_printf("requires address of svnode_t\n");
		return (DCMD_USAGE);
	}

	if (argc != 0)
		return (DCMD_USAGE);

	if (mdb_vread(&sn, sizeof (sn), addr) == -1) {
		mdb_warn("can't read svnode_t at %p", addr);
		return (DCMD_ERR);
	}

	if (DCMD_HDRSPEC(flags))
		mdb_printf("%<b>%<u>%-?s %-?s %-20s%</u>%</b>\n", "SVNODE",
		    "VNODE", "PATH");

	mdb_printf("%-?p %-?p ", addr, sn.sv_r_vnode);
	print_nfs4_fname((uintptr_t)sn.sv_name);
	mdb_printf("\n");

	return (DCMD_OK);
}

/*
 * nfs_rtable walker implementation
 */

hash_table_walk_arg_t nfs_rtable_arg = {
	0,		/* will be set in the init */
	0,		/* will be set in the init */
	sizeof (rhashq_t),
	"r_hashf",
	OFFSETOF(rhashq_t, r_hashf),
	"rnode_t",
	sizeof (rnode_t),
	OFFSETOF(struct rnode, r_hashf)
};

static int
nfs_rtable_common_init(mdb_walk_state_t *wsp, const char *tabname,
    const char *sizename)
{
	hash_table_walk_arg_t *arg = wsp->walk_arg;
	int rtsize;
	uintptr_t rtaddr;

	if (mdb_readsym(&rtsize, sizeof (rtsize), sizename) == -1) {
		mdb_warn("failed to get %s", sizename);
		return (WALK_ERR);
	}

	if (rtsize < 0) {
		mdb_warn("%s is negative: %d", sizename, rtsize);
		return (WALK_ERR);
	}

	if (mdb_readsym(&rtaddr, sizeof (rtaddr), tabname) == -1) {
		mdb_warn("failed to get %s", tabname);
		return (WALK_ERR);
	}

	arg->array_addr = rtaddr;
	arg->array_len = rtsize;

	return (hash_table_walk_init(wsp));
}

int
nfs_rtable_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr != 0) {
		mdb_warn("nfs_rtable supports only global walks");
		return (WALK_ERR);
	}

	return (nfs_rtable_common_init(wsp, "rtable", "rtablesize"));
}

/*
 * nfs_rtable4 walker implementation
 */

hash_table_walk_arg_t nfs_rtable4_arg = {
	0,		/* will be set in the init */
	0,		/* will be set in the init */
	sizeof (r4hashq_t),
	"r_hashf",
	OFFSETOF(r4hashq_t, r_hashf),
	"rnode4_t",
	sizeof (rnode4_t),
	OFFSETOF(struct rnode4, r_hashf)
};

int
nfs_rtable4_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr != 0) {
		mdb_warn("nfs_rtable4 supports only global walks");
		return (WALK_ERR);
	}

	return (nfs_rtable_common_init(wsp, "rtable4", "rtable4size"));
}

/*
 * nfs_vfs walker implementation
 */

typedef struct nfs_vfs_walk {
	uintptr_t nfs2_ops;
	uintptr_t nfs3_ops;
	uintptr_t nfs4_ops;
	void *data;		/* walker specific data */
} nfs_vfs_walk_t;

int
nfs_vfs_walk_init(mdb_walk_state_t *wsp)
{
	nfs_vfs_walk_t data;
	nfs_vfs_walk_t *datap;

	if (mdb_readvar(&data.nfs2_ops, "nfs_vfsops") == -1) {
		mdb_warn("failed to read %s", "nfs_vfsops");
		return (WALK_ERR);
	}

	if (mdb_readvar(&data.nfs3_ops, "nfs3_vfsops") == -1) {
		mdb_warn("failed to read %s", "nfs3_vfsops");
		return (WALK_ERR);
	}

	if (mdb_readvar(&data.nfs4_ops, "nfs4_vfsops") == -1) {
		mdb_warn("failed to read %s", "nfs4_vfsops");
		return (WALK_ERR);
	}

	if (mdb_layered_walk("genunix`vfs", wsp) == -1) {
		mdb_warn("failed to walk vfs");
		return (WALK_ERR);
	}

	datap = mdb_alloc(sizeof (data), UM_SLEEP);
	*datap = data;
	wsp->walk_data = datap;

	return (WALK_NEXT);
}

int
nfs_vfs_walk_step(mdb_walk_state_t *wsp)
{
	nfs_vfs_walk_t *data = (nfs_vfs_walk_t *)wsp->walk_data;
	vfs_t *vfs = (vfs_t *)wsp->walk_layer;

	if (data->nfs2_ops != (uintptr_t)vfs->vfs_op &&
	    data->nfs3_ops != (uintptr_t)vfs->vfs_op &&
	    data->nfs4_ops != (uintptr_t)vfs->vfs_op)
		return (WALK_NEXT);

	return (wsp->walk_callback(wsp->walk_addr, wsp->walk_layer,
	    wsp->walk_cbdata));
}

void
nfs_vfs_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (nfs_vfs_walk_t));
}

/*
 * nfs_mnt walker implementation
 */

int
nfs_mnt_walk_init(mdb_walk_state_t *wsp)
{
	int status;
	nfs_vfs_walk_t *data;

	status = nfs_vfs_walk_init(wsp);
	if (status != WALK_NEXT)
		return (status);

	data = wsp->walk_data;
	data->data = mdb_alloc(sizeof (mntinfo_t), UM_SLEEP);

	return (WALK_NEXT);
}

int
nfs_mnt_walk_step(mdb_walk_state_t *wsp)
{
	nfs_vfs_walk_t *data = (nfs_vfs_walk_t *)wsp->walk_data;
	vfs_t *vfs = (vfs_t *)wsp->walk_layer;

	if (data->nfs2_ops != (uintptr_t)vfs->vfs_op &&
	    data->nfs3_ops != (uintptr_t)vfs->vfs_op)
		return (WALK_NEXT);

	if (mdb_vread(data->data, sizeof (mntinfo_t), (uintptr_t)VFTOMI(vfs))
	    == -1) {
		mdb_warn("can't read mntinfo");
		return (WALK_ERR);
	}

	return (wsp->walk_callback((uintptr_t)VFTOMI(vfs), data->data,
	    wsp->walk_cbdata));
}

void
nfs_mnt_walk_fini(mdb_walk_state_t *wsp)
{
	nfs_vfs_walk_t *data = (nfs_vfs_walk_t *)wsp->walk_data;

	mdb_free(data->data, sizeof (mntinfo_t));
	nfs_vfs_walk_fini(wsp);
}

/*
 * nfs4_mnt walker implementation
 */

int
nfs4_mnt_walk_init(mdb_walk_state_t *wsp)
{
	int status;
	nfs_vfs_walk_t *data;

	status = nfs_vfs_walk_init(wsp);
	if (status != WALK_NEXT)
		return (status);

	data = wsp->walk_data;
	data->data = mdb_alloc(sizeof (mntinfo4_t), UM_SLEEP);

	return (WALK_NEXT);
}

int
nfs4_mnt_walk_step(mdb_walk_state_t *wsp)
{
	nfs_vfs_walk_t *data = (nfs_vfs_walk_t *)wsp->walk_data;
	vfs_t *vfs = (vfs_t *)wsp->walk_layer;

	if (data->nfs4_ops != (uintptr_t)vfs->vfs_op)
		return (WALK_NEXT);

	if (mdb_vread(data->data, sizeof (mntinfo4_t), (uintptr_t)VFTOMI4(vfs))
	    == -1) {
		mdb_warn("can't read mntinfo4");
		return (WALK_ERR);
	}

	return (wsp->walk_callback((uintptr_t)VFTOMI4(vfs), data->data,
	    wsp->walk_cbdata));
}

void
nfs4_mnt_walk_fini(mdb_walk_state_t *wsp)
{
	nfs_vfs_walk_t *data = (nfs_vfs_walk_t *)wsp->walk_data;

	mdb_free(data->data, sizeof (mntinfo4_t));
	nfs_vfs_walk_fini(wsp);
}

/*
 * nfs_serv walker implementation
 */

int
nfs_serv_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == 0) {
		mdb_warn("global walk not supported");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

int
nfs_serv_walk_step(mdb_walk_state_t *wsp)
{
	servinfo_t si;
	uintptr_t addr = wsp->walk_addr;

	if (addr == 0)
		return (WALK_DONE);

	if (mdb_vread(&si, sizeof (si), addr) == -1) {
		mdb_warn("can't read servinfo_t");
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)si.sv_next;
	return (wsp->walk_callback(addr, &si, wsp->walk_cbdata));
}

/*
 * nfs4_serv walker implementation
 */

int
nfs4_serv_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == 0) {
		mdb_warn("global walk not supported");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

int
nfs4_serv_walk_step(mdb_walk_state_t *wsp)
{
	servinfo4_t si;
	uintptr_t addr = wsp->walk_addr;

	if (addr == 0)
		return (WALK_DONE);

	if (mdb_vread(&si, sizeof (si), addr) == -1) {
		mdb_warn("can't read servinfo4_t");
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)si.sv_next;
	return (wsp->walk_callback(addr, &si, wsp->walk_cbdata));
}

/*
 * nfs4_svnode walker implementation
 */

int
nfs4_svnode_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == 0) {
		mdb_warn("global walk not supported");
		return (WALK_ERR);
	}

	wsp->walk_data = (void *)wsp->walk_addr;

	return (WALK_NEXT);
}

int
nfs4_svnode_walk_step(mdb_walk_state_t *wsp)
{
	svnode_t sn;
	uintptr_t addr = wsp->walk_addr;
	int status;

	if (mdb_vread(&sn, sizeof (sn), addr) == -1) {
		mdb_warn("can't read svnode_t");
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)sn.sv_forw;

	status = wsp->walk_callback(addr, &sn, wsp->walk_cbdata);
	if (status != WALK_NEXT)
		return (status);

	return (((void *)wsp->walk_addr == wsp->walk_data) ? WALK_DONE
	    : WALK_NEXT);
}

/*
 * nfs4_server walker implementation
 */

int
nfs4_server_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == 0) {
		GElf_Sym sym;

		if (mdb_lookup_by_name("nfs4_server_lst", &sym) == -1) {
			mdb_warn("failed to find 'nfs4_server_lst'");
			return (WALK_ERR);
		}

		wsp->walk_addr = sym.st_value;
	}

	wsp->walk_data = (void *)wsp->walk_addr;

	return (WALK_NEXT);
}

int
nfs4_server_walk_step(mdb_walk_state_t *wsp)
{
	nfs4_server_t srv;
	uintptr_t addr = wsp->walk_addr;
	int status;

	if (mdb_vread(&srv, sizeof (srv), addr) == -1) {
		mdb_warn("can't read nfs4_server_t");
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)srv.forw;

	status = wsp->walk_callback(addr, &srv, wsp->walk_cbdata);
	if (status != WALK_NEXT)
		return (status);

	return (((void *)wsp->walk_addr == wsp->walk_data) ? WALK_DONE
	    : WALK_NEXT);
}

/*
 * nfs_async walker implementation
 */

int
nfs_async_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == 0) {
		mdb_warn("global walk not supported");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

int
nfs_async_walk_step(mdb_walk_state_t *wsp)
{
	struct nfs_async_reqs areq;
	uintptr_t addr = wsp->walk_addr;

	if (addr == 0)
		return (WALK_DONE);

	if (mdb_vread(&areq, sizeof (areq), addr) == -1) {
		mdb_warn("can't read struct nfs_async_reqs");
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)areq.a_next;

	return (wsp->walk_callback(addr, &areq, wsp->walk_cbdata));
}

/*
 * nfs4_async walker implementation
 */

int
nfs4_async_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == 0) {
		mdb_warn("global walk not supported");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

int
nfs4_async_walk_step(mdb_walk_state_t *wsp)
{
	struct nfs4_async_reqs areq;
	uintptr_t addr = wsp->walk_addr;

	if (addr == 0)
		return (WALK_DONE);

	if (mdb_vread(&areq, sizeof (areq), addr) == -1) {
		mdb_warn("can't read struct nfs4_async_reqs");
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)areq.a_next;

	return (wsp->walk_callback(addr, &areq, wsp->walk_cbdata));
}

/*
 * nfs_acache_rnode walker implementation
 */

int
nfs_acache_rnode_walk_init(mdb_walk_state_t *wsp)
{
	rnode_t rn;

	if (wsp->walk_addr == 0) {
		mdb_warn("global walk not supported");
		return (WALK_ERR);
	}

	if (mdb_vread(&rn, sizeof (rn), wsp->walk_addr) == -1) {
		mdb_warn("can't read rnode_t at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)rn.r_acache;

	return (WALK_NEXT);
}

int
nfs_acache_rnode_walk_step(mdb_walk_state_t *wsp)
{
	acache_t ac;
	uintptr_t addr = wsp->walk_addr;

	if (addr == 0)
		return (WALK_DONE);

	if (mdb_vread(&ac, sizeof (ac), addr) == -1) {
		mdb_warn("can't read acache_t at %p", addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)ac.list;

	return (wsp->walk_callback(addr, &ac, wsp->walk_cbdata));
}

/*
 * nfs_acache walker implementation
 */

static const hash_table_walk_arg_t nfs_acache_arg = {
	0,		/* placeholder */
	0,		/* placeholder */
	sizeof (acache_hash_t),
	"next",
	OFFSETOF(acache_hash_t, next),
	"acache_t",
	sizeof (acache_t),
	OFFSETOF(acache_t, next)
};

int
nfs_acache_walk_init(mdb_walk_state_t *wsp)
{
	hash_table_walk_arg_t *arg;
	int size;
	uintptr_t addr;
	int status;

	if (wsp->walk_addr != 0) {
		mdb_warn("local walk not supported");
		return (WALK_ERR);
	}

	if (mdb_readsym(&size, sizeof (size), "acachesize") == -1) {
		mdb_warn("failed to get %s", "acachesize");
		return (WALK_ERR);
	}

	if (size < 0) {
		mdb_warn("%s is negative: %d", "acachesize", size);
		return (WALK_ERR);
	}

	if (mdb_readsym(&addr, sizeof (addr), "acache") == -1) {
		mdb_warn("failed to get %s", "acache");
		return (WALK_ERR);
	}

	arg = mdb_alloc(sizeof (*arg), UM_SLEEP);
	bcopy(&nfs_acache_arg, arg, sizeof (*arg));

	arg->array_addr = addr;
	arg->array_len = size;

	wsp->walk_arg = arg;

	status = hash_table_walk_init(wsp);
	if (status != WALK_NEXT)
		mdb_free(wsp->walk_arg, sizeof (hash_table_walk_arg_t));
	return (status);
}

void
nfs_acache_walk_fini(mdb_walk_state_t *wsp)
{
	hash_table_walk_fini(wsp);
	mdb_free(wsp->walk_arg, sizeof (hash_table_walk_arg_t));
}

/*
 * nfs_acache4_rnode walker implementation
 */

int
nfs_acache4_rnode_walk_init(mdb_walk_state_t *wsp)
{
	rnode4_t rn;

	if (wsp->walk_addr == 0) {
		mdb_warn("global walk not supported");
		return (WALK_ERR);
	}

	if (mdb_vread(&rn, sizeof (rn), wsp->walk_addr) == -1) {
		mdb_warn("can't read rnode4_t at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)rn.r_acache;

	return (WALK_NEXT);
}

int
nfs_acache4_rnode_walk_step(mdb_walk_state_t *wsp)
{
	acache4_t ac;
	uintptr_t addr = wsp->walk_addr;

	if (addr == 0)
		return (WALK_DONE);

	if (mdb_vread(&ac, sizeof (ac), addr) == -1) {
		mdb_warn("can't read acache4_t at %p", addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)ac.list;

	return (wsp->walk_callback(addr, &ac, wsp->walk_cbdata));
}

/*
 * nfs_acache4 walker implementation
 */

static const hash_table_walk_arg_t nfs_acache4_arg = {
	0,		/* placeholder */
	0,		/* placeholder */
	sizeof (acache4_hash_t),
	"next",
	OFFSETOF(acache4_hash_t, next),
	"acache4_t",
	sizeof (acache4_t),
	OFFSETOF(acache4_t, next)
};

int
nfs_acache4_walk_init(mdb_walk_state_t *wsp)
{
	hash_table_walk_arg_t *arg;
	int size;
	uintptr_t addr;
	int status;

	if (wsp->walk_addr != 0) {
		mdb_warn("local walk not supported");
		return (WALK_ERR);
	}

	if (mdb_readsym(&size, sizeof (size), "acache4size") == -1) {
		mdb_warn("failed to get %s", "acache4size");
		return (WALK_ERR);
	}

	if (size < 0) {
		mdb_warn("%s is negative: %d\n", "acache4size", size);
		return (WALK_ERR);
	}

	if (mdb_readsym(&addr, sizeof (addr), "acache4") == -1) {
		mdb_warn("failed to get %s", "acache4");
		return (WALK_ERR);
	}

	arg = mdb_alloc(sizeof (*arg), UM_SLEEP);
	bcopy(&nfs_acache4_arg, arg, sizeof (*arg));

	arg->array_addr = addr;
	arg->array_len = size;

	wsp->walk_arg = arg;

	status = hash_table_walk_init(wsp);
	if (status != WALK_NEXT)
		mdb_free(wsp->walk_arg, sizeof (hash_table_walk_arg_t));
	return (status);
}

void
nfs_acache4_walk_fini(mdb_walk_state_t *wsp)
{
	hash_table_walk_fini(wsp);
	mdb_free(wsp->walk_arg, sizeof (hash_table_walk_arg_t));
}
