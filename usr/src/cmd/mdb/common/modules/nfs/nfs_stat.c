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

#include <sys/types.h>
#include <sys/kstat.h>
#include <sys/mdb_modapi.h>
#include <rpc/clnt.h>
#include <nfs/nfs_clnt.h>
#include <nfs/nfs4_clnt.h>

#include "svc.h"
#include "rfs4.h"
#include "nfssrv.h"
#include "common.h"

#define	NFS4_MINOR_VERS_COUNT 0
#define	NFS_STAT_NUM_STATS 79

/*
 * Structure used to group kstats we want to print.
 */
typedef struct nfs_mdb_stats {
	struct nfs_stats nfsstats;
	struct rpcstat rpcstats;
	struct nfs_globals nfsglbls;
	uintptr_t clntstat;
	uintptr_t clntstat4; /* extend this for NFS4.X */
	uintptr_t callback_stats;
} nfs_mdb_stats_t;

static int nfs_stat_clnt(nfs_mdb_stats_t *, int, int);
static int nfs_stat_srv(nfs_mdb_stats_t *, int, int);
static int nfs_srvstat(nfs_mdb_stats_t *, int);
static int nfs_srvstat_rpc(nfs_mdb_stats_t *);
static int nfs_srvstat_acl(nfs_mdb_stats_t *, int);
static int nfs_clntstat(nfs_mdb_stats_t *, int);
static int nfs_clntstat_rpc(nfs_mdb_stats_t *);
static int nfs_clntstat_acl(nfs_mdb_stats_t *, int);
static int nfs_srvstat_cb(nfs_mdb_stats_t *);

#define	NFS_SRV_STAT	0x1
#define	NFS_CLNT_STAT	0x2
#define	NFS_CB_STAT	0x4
#define	NFS_NFS_STAT	0x1
#define	NFS_ACL_STAT	0x2
#define	NFS_RPC_STAT	0x4
#define	NFS_V2_STAT	0x1
#define	NFS_V3_STAT	0x2
#define	NFS_V4_STAT	0x4

static int prt_nfs_stats(uintptr_t, char *);
static void kstat_prtout(char *, uint64_t *, int);

void
nfs_stat_help(void)
{
	mdb_printf("Switches similar to those of nfsstat command.\n",
	    "            ::nfs_stat -a	-> ACL    Statistics.\n"
	    "            ::nfs_stat -b  -> Callback Stats. (V4 only)\n"
	    "            ::nfs_stat -c  -> Client Statistics.\n"
	    "            ::nfs_stat -n	-> NFS    Statistics.\n"
	    "            ::nfs_stat -r	-> RPC    Statistics.\n"
	    "            ::nfs_stat -s	-> Server Statistics.\n"
	    "            ::nfs_stat -2	-> Version 2.\n"
	    "            ::nfs_stat -3	-> Version 3.\n"
	    "            ::nfs_stat -4	-> Version 4.\n");
}

int
nfs_stat_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int host_flag = 0; /* host or client flag */
	int type_flag = 0; /* type acl, rpc of nfs */
	int vers_flag = 0; /* NFS version flag */
	nfs_mdb_stats_t mdb_stats;
	uintptr_t glbls;
	uintptr_t cb_glbls;
	uintptr_t zonep;

	if (argc == 1 && argv->a_type == MDB_TYPE_IMMEDIATE) {
		kstat_named_t ksts;
		int i;
		for (i = argv->a_un.a_val; i; i--) {
			if (mdb_vread(&ksts, sizeof (ksts), addr) < 0) {
				mdb_warn("failed to read kstat_name_t");
				return (DCMD_ERR);
			}
			mdb_printf(" %8s %30d\n", ksts.name, ksts.value.ui64);
			addr += sizeof (ksts);
		}
		return (DCMD_OK);
	}

	if (mdb_getopts(argc, argv,
	    'a', MDB_OPT_SETBITS, NFS_ACL_STAT, &type_flag,
	    'b', MDB_OPT_SETBITS, NFS_CB_STAT, &host_flag,
	    'c', MDB_OPT_SETBITS, NFS_CLNT_STAT, &host_flag,
	    'n', MDB_OPT_SETBITS, NFS_NFS_STAT, &type_flag,
	    'r', MDB_OPT_SETBITS, NFS_RPC_STAT, &type_flag,
	    's', MDB_OPT_SETBITS, NFS_SRV_STAT, &host_flag,
	    '2', MDB_OPT_SETBITS, NFS_V2_STAT, &vers_flag,
	    '3', MDB_OPT_SETBITS, NFS_V3_STAT, &vers_flag,
	    '4', MDB_OPT_SETBITS, NFS_V4_STAT, &vers_flag,
	    NULL) != argc) {
		return (DCMD_USAGE);
	}


	if (flags & DCMD_ADDRSPEC) {
		zonep = addr;
	} else {
		if (mdb_readsym(&zonep, sizeof (uintptr_t),
		    "global_zone") == -1) {
			mdb_warn("Failed to find global_zone");
			return (DCMD_ERR);
		}
	}

	if (zoned_get_zsd(zonep, "nfssrv_zone_key", &glbls)) {
		mdb_warn("Failed to find nfssrv_zone_key");
		return (DCMD_ERR);
	}

	if (mdb_vread(&mdb_stats.nfsglbls, sizeof (struct nfs_globals),
	    glbls) == -1) {
		mdb_warn("Failed to read nfs_stats at %p", glbls);
		return (DCMD_ERR);
	}

	if (zoned_get_zsd(zonep, "nfsstat_zone_key", &glbls)) {
		mdb_warn("Failed to find %s", "nfsstat_zone_key");
		return (DCMD_ERR);
	}

	if (mdb_vread(&mdb_stats.nfsstats, sizeof (struct nfs_stats),
	    glbls) == -1) {
		mdb_warn("Failed to read nfs_stats at %p", glbls);
		return (DCMD_ERR);
	}

	if (zoned_get_zsd(zonep, "rpcstat_zone_key", &glbls)) {
		mdb_warn("Failed to find %s", "rpcstat_zone_key");
		return (DCMD_ERR);
	}

	if (mdb_vread(&mdb_stats.rpcstats, sizeof (struct rpcstat),
	    glbls) == -1) {
		mdb_warn("Failed to read nfs_stats at %p", glbls);
		return (DCMD_ERR);
	}

	if (zoned_get_zsd(zonep, "nfsclnt_zone_key", &glbls)) {
		mdb_warn("Failed to find %s", "nfsclnt_zone_key");
		return (DCMD_ERR);
	}
	mdb_stats.clntstat = glbls + offsetof(struct nfs_clnt, nfscl_stat);

	if (zoned_get_zsd(zonep, "nfs4clnt_zone_key", &glbls)) {
		mdb_warn("Failed to find %s", "nfs4clnt_zone_key");
		return (DCMD_ERR);
	}
	/*
	 * currently only have NFSv4.0 is availble. When NFSv4.1 and above are
	 * available stats support will need to be added.
	 */
	mdb_stats.clntstat4 = glbls + offsetof(struct nfs4_clnt, nfscl_stat);

	if (zoned_get_zsd(zonep, "nfs4_callback_zone_key",
	    (uintptr_t *)&cb_glbls)) {
		mdb_warn("Failed to find %s", "nfs4_callback_zone_key");
		return (DCMD_ERR);
	}

	mdb_stats.callback_stats =
	    (cb_glbls + offsetof(struct nfs4_callback_globals,
	    nfs4_callback_stats));

	if (host_flag == 0)
		host_flag = NFS_SRV_STAT | NFS_CLNT_STAT | NFS_CB_STAT;
	if (vers_flag == 0)
		vers_flag = NFS_V2_STAT | NFS_V3_STAT | NFS_V4_STAT;
	if (type_flag == 0)
		type_flag = NFS_NFS_STAT | NFS_ACL_STAT | NFS_RPC_STAT;

	if (host_flag & NFS_CB_STAT)
		if (nfs_srvstat_cb(&mdb_stats))
			return (DCMD_ERR);
	if (host_flag & NFS_SRV_STAT)
		if (nfs_stat_srv(&mdb_stats, type_flag, vers_flag))
			return (DCMD_ERR);
	if (host_flag & NFS_CLNT_STAT)
		if (nfs_stat_clnt(&mdb_stats, type_flag, vers_flag))
			return (DCMD_ERR);
	return (DCMD_OK);
}

static int
nfs_srvstat_cb(nfs_mdb_stats_t *stptr)
{
	int ret = 0;
	mdb_printf("CALLBACK STATISTICS:\n");

	ret = prt_nfs_stats(stptr->callback_stats, "nfs4_callback_stats_tmpl");

	return (ret);
}

static int
nfs_stat_srv(nfs_mdb_stats_t *stptr, int type_flag, int vers_flag)
{
	mdb_printf("NFS SERVER STATS:\n");
	if (type_flag & NFS_SRV_STAT) {
		if (nfs_srvstat(stptr, vers_flag) != 0)
			return (1);
	}
	if (type_flag & NFS_RPC_STAT) {
		if (nfs_srvstat_rpc(stptr) != 0)
			return (1);
	}
	if (type_flag & NFS_ACL_STAT) {
		if (nfs_srvstat_acl(stptr, vers_flag) != 0)
			return (1);
	}
	return (0);
}

static int
nfs_stat_clnt(nfs_mdb_stats_t *stptr, int type_flag, int vers_flag)
{
	mdb_printf("CLIENT STATISTICS:\n");
	if (type_flag & NFS_CLNT_STAT) {
		if (nfs_clntstat(stptr, vers_flag))
			return (1);
	}
	if (type_flag & NFS_ACL_STAT) {
		if (nfs_clntstat_acl(stptr, vers_flag))
			return (1);
	}
	if (type_flag & NFS_RPC_STAT) {
		if (nfs_clntstat_rpc(stptr))
			return (1);
	}
	return (0);
}


static int
nfs_srvstat(nfs_mdb_stats_t *stptr, int flag)
{
	mdb_printf("NFS Statistics\n");
	if (flag & NFS_V2_STAT) {
		mdb_printf("NFSv2\n");
		if (prt_nfs_stats((uintptr_t)stptr->nfsglbls.svstat[2],
		    "svstat_tmpl") ||
		    prt_nfs_stats((uintptr_t)stptr->nfsglbls.rfsproccnt[2],
		    "rfsproccnt_v2_tmpl"))
			return (-1);
	}
	if (flag & NFS_V3_STAT) {
		mdb_printf("NFSv3\n");
		if (prt_nfs_stats((uintptr_t)stptr->nfsglbls.svstat[3],
		    "svstat_tmpl") ||
		    prt_nfs_stats((uintptr_t)stptr->nfsglbls.rfsproccnt[3],
		    "rfsproccnt_v3_tmpl"))
			return (-1);
	}
	if (flag & NFS_V4_STAT) {
		mdb_printf("NFSv4\n");
		if (prt_nfs_stats((uintptr_t)stptr->nfsglbls.svstat[4],
		    "svstat_tmpl") ||
		    prt_nfs_stats((uintptr_t)stptr->nfsglbls.rfsproccnt[4],
		    "rfsproccnt_v4_tmpl"))
			return (-1);
	}
	return (0);
}


static int
nfs_srvstat_rpc(nfs_mdb_stats_t *stptr)
{
	mdb_printf("NFS RPC Statistics\n");
	mdb_printf("ConnectionLess\n");
	if (prt_nfs_stats((uintptr_t)stptr->rpcstats.rpc_clts_server,
	    "clts_rsstat_tmpl"))
		return (-1);
	mdb_printf("ConnectionOriented\n");
	if (prt_nfs_stats((uintptr_t)stptr->rpcstats.rpc_cots_server,
	    "cots_rsstat_tmpl"))
		return (-1);
	return (0);
}


static int
nfs_srvstat_acl(nfs_mdb_stats_t *stptr, int flags)
{
	mdb_printf("NFS ACL Statistics\n");
	if (flags & NFS_V2_STAT) {
		mdb_printf("NFSv2\n");
		if (prt_nfs_stats((uintptr_t)stptr->nfsglbls.aclproccnt[2],
		    "aclproccnt_v2_tmpl"))
			return (-1);
	}
	if (flags & NFS_V3_STAT) {
		mdb_printf("NFSv3\n");
		if (prt_nfs_stats((uintptr_t)stptr->nfsglbls.aclproccnt[3],
		    "aclproccnt_v3_tmpl"))
			return (-1);
	}
	if (flags & NFS_V4_STAT) {
		mdb_printf("NFSv4\n");
		if (prt_nfs_stats((uintptr_t)stptr->nfsglbls.aclproccnt[4],
		    "aclreqcnt_v4_tmpl"))
			return (-1);
	}
	return (0);
}

static int
nfs_clntstat(nfs_mdb_stats_t *stptr, int flags)
{
	mdb_printf("NFS Statistics\n");
	if (prt_nfs_stats((uintptr_t)stptr->clntstat, "clstat_tmpl"))
		return (-1);
	if (flags & NFS_V2_STAT) {
		mdb_printf("Version 2\n");
		if (prt_nfs_stats(
		    (uintptr_t)stptr->nfsstats.nfs_stats_v2.rfsreqcnt_ptr,
		    "rfsreqcnt_v2_tmpl"))
			return (-1);
	}
	if (flags & NFS_V3_STAT) {
		mdb_printf("Version 3\n");
		if (prt_nfs_stats(
		    (uintptr_t)stptr->nfsstats.nfs_stats_v3.rfsreqcnt_ptr,
		    "rfsreqcnt_v3_tmpl"))
			return (-1);
	}
	if (flags & NFS_V4_STAT) {
		mdb_printf("NFSv4 client\n");
		if (prt_nfs_stats((uintptr_t)stptr->clntstat, "clstat4_tmpl"))
			return (-1);
		mdb_printf("Version 4\n");
		if (prt_nfs_stats(
		    (uintptr_t)stptr->nfsstats.nfs_stats_v4.rfsreqcnt_ptr,
		    "rfsreqcnt_v4_tmpl"))
			return (-1);
	}
	return (0);
}

static int
nfs_clntstat_rpc(nfs_mdb_stats_t *stptr)
{
	mdb_printf("NFS RPC Statistics\n");
	mdb_printf("ConnectionLess\n");
	if (prt_nfs_stats((uintptr_t)stptr->rpcstats.rpc_clts_client,
	    "clts_rcstat_tmpl"))
		return (-1);
	mdb_printf("ConnectionOriented\n");
	if (prt_nfs_stats((uintptr_t)stptr->rpcstats.rpc_cots_client,
	    "cots_rcstat_tmpl"))
		return (-1);
	return (0);
}

static int
nfs_clntstat_acl(nfs_mdb_stats_t *stptr, int flags)
{
	mdb_printf("ACL Statistics\n");
	if (flags & NFS_V2_STAT) {
		mdb_printf("Version 2\n");
		if (prt_nfs_stats(
		    (uintptr_t)stptr->nfsstats.nfs_stats_v2.aclreqcnt_ptr,
		    "aclreqcnt_v2_tmpl"))
			return (-1);
	}
	if (flags & NFS_V3_STAT) {
		mdb_printf("Version 3\n");
		if (prt_nfs_stats(
		    (uintptr_t)stptr->nfsstats.nfs_stats_v3.aclreqcnt_ptr,
		    "aclreqcnt_v3_tmpl"))
			return (-1);
	}
	if (flags & NFS_V4_STAT) {
		mdb_printf("Version 4\n");
		if (prt_nfs_stats(
		    (uintptr_t)stptr->nfsstats.nfs_stats_v4.aclreqcnt_ptr,
		    "aclreqcnt_v4_tmpl"))
			return (-1);
	}
	return (0);
}


/*
 * helper functions for printing out the kstat data
 */

#define	NFS_STAT_NUM_CLMNS 16

static int
prt_nfs_stats(uintptr_t addr, char *name)
{

	GElf_Sym sym;
	kstat_named_t kstats;
	char *kstat_line;
	uint64_t *value;
	uint_t count;
	int i = 0, status = 0;


	if (mdb_lookup_by_name(name, &sym) != 0) {
		mdb_warn("failed to find %s", name);
		return (1);
	}

	count = sym.st_size / sizeof (kstat_named_t);

	kstat_line = mdb_alloc(count * NFS_STAT_NUM_CLMNS, UM_SLEEP);
	value = mdb_alloc(count * sizeof (uint64_t), UM_SLEEP);
	for (i = 0; i < count; i++) {
		if (mdb_vread(&kstats, sizeof (kstat_named_t),
		    addr + (i * sizeof (kstat_named_t))) < 0) {
			status = 1;
			goto done;
		}
		mdb_snprintf(&kstat_line[NFS_STAT_NUM_CLMNS * i],
		    NFS_STAT_NUM_CLMNS, "%s", kstats.name);
		value[i] = kstats.value.ui64;
	}
	kstat_prtout(kstat_line, value, count);
done:
	mdb_free(kstat_line, count * NFS_STAT_NUM_CLMNS);
	mdb_free(value, count * sizeof (uint64_t));
	return (status);
}

static void
kstat_prtout(char *ks_line, uint64_t *values, int count)
{
	char val_str[32];
	int i = 0, num = 0;

	while (i < count) {
		mdb_printf("%-*s", NFS_STAT_NUM_CLMNS,
		    &ks_line[NFS_STAT_NUM_CLMNS * i]);

		num++;
		if (num == NFS_STAT_NUM_STATS / NFS_STAT_NUM_CLMNS) {
			mdb_printf("\n");
			while (num > 0) {
				mdb_snprintf(val_str, 24, "%ld  ",
				    values[i+1-num]);
				mdb_printf("%-*s", NFS_STAT_NUM_CLMNS, val_str);
				--num;
			}
			mdb_printf("\n");
		}
		i++;
	}
	mdb_printf("\n");
}
