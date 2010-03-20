/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Net DFS server side RPC service for managing DFS namespaces.
 *
 * For more details refer to following Microsoft specification:
 * [MS-DFSNM]
 *    Distributed File System (DFS): Namespace Management Protocol Specification
 */

#include <unistd.h>
#include <libgen.h>
#include <strings.h>
#include <sys/sysmacros.h>

#include <smbsrv/ndl/netdfs.ndl>
#include <smbsrv/nmpipes.h>
#include <smbsrv/nterror.h>
#include <smbsrv/libmlsvc.h>
#include <dfs.h>

/*
 * Depends on the information level requested around 4000 or more links
 * can be provided with this buffer size. The limitation here is due
 * to some problem in NDR and/or opipe layer so:
 *
 * - Do NOT increase the buffer size until that problem is fixed
 * - The buffer size should be increased when the problem is fixed
 *   so the 4000 link limitation is removed.
 */
#define	NETDFS_MAXBUFLEN	(800 * 1024)
#define	NETDFS_MAXPREFLEN	((uint32_t)(-1))

typedef struct netdfs_enumhandle_t {
	uint32_t	de_level;	/* level of detail being requested */
	uint32_t	de_prefmaxlen;	/* client MAX size buffer preference */
	uint32_t	de_resume;	/* client resume handle */
	uint32_t	de_bavail;	/* remaining buffer space in bytes */
	uint32_t	de_ntotal;	/* total number of objects */
	uint32_t	de_nmax;	/* MAX number of objects to return */
	uint32_t	de_nitems;	/* number of objects in buf */
	uint32_t	de_nskip;	/* number of objects to skip */
	void		*de_entries;	/* ndr buffer */
} netdfs_enumhandle_t;

static int netdfs_s_getver(void *, ndr_xa_t *);
static int netdfs_s_add(void *, ndr_xa_t *);
static int netdfs_s_remove(void *, ndr_xa_t *);
static int netdfs_s_setinfo(void *, ndr_xa_t *);
static int netdfs_s_getinfo(void *, ndr_xa_t *);
static int netdfs_s_enum(void *, ndr_xa_t *);
static int netdfs_s_move(void *, ndr_xa_t *);
static int netdfs_s_rename(void *, ndr_xa_t *);
static int netdfs_s_addstdroot(void *, ndr_xa_t *);
static int netdfs_s_remstdroot(void *, ndr_xa_t *);
static int netdfs_s_enumex(void *, ndr_xa_t *);

static uint32_t netdfs_setinfo_100(dfs_path_t *, netdfs_info100_t *);
static uint32_t netdfs_setinfo_101(dfs_path_t *, netdfs_info101_t *,
    const char *, const char *);
static uint32_t netdfs_setinfo_102(dfs_path_t *, netdfs_info102_t *);
static uint32_t netdfs_setinfo_103(dfs_path_t *, netdfs_info103_t *);
static uint32_t netdfs_setinfo_104(dfs_path_t *, netdfs_info104_t *,
    const char *, const char *);
static uint32_t netdfs_setinfo_105(dfs_path_t *, netdfs_info105_t *);

static uint32_t netdfs_info_1(netdfs_info1_t *, dfs_info_t *, ndr_xa_t *,
    uint32_t *);
static uint32_t netdfs_info_2(netdfs_info2_t *, dfs_info_t *, ndr_xa_t *,
    uint32_t *);
static uint32_t netdfs_info_3(netdfs_info3_t *, dfs_info_t *, ndr_xa_t *,
    uint32_t *);
static uint32_t netdfs_info_4(netdfs_info4_t *, dfs_info_t *, ndr_xa_t *,
    uint32_t *);
static uint32_t netdfs_info_5(netdfs_info5_t *, dfs_info_t *, ndr_xa_t *,
    uint32_t *);
static uint32_t netdfs_info_6(netdfs_info6_t *, dfs_info_t *, ndr_xa_t *,
    uint32_t *);
static uint32_t netdfs_info_100(netdfs_info100_t *, dfs_info_t *, ndr_xa_t *,
    uint32_t *);
static uint32_t netdfs_info_300(netdfs_info300_t *, dfs_info_t *, ndr_xa_t *,
    uint32_t *);

static uint32_t netdfs_enum_common(netdfs_enumhandle_t *, ndr_xa_t *);

static void netdfs_path_create(const char *);
static void netdfs_path_remove(smb_unc_t *);
static boolean_t netdfs_guid_fromstr(char *, netdfs_uuid_t *);

static ndr_stub_table_t netdfs_stub_table[] = {
	{ netdfs_s_getver,	NETDFS_OPNUM_GETVER },
	{ netdfs_s_add,		NETDFS_OPNUM_ADD },
	{ netdfs_s_remove,	NETDFS_OPNUM_REMOVE },
	{ netdfs_s_setinfo,	NETDFS_OPNUM_SETINFO },
	{ netdfs_s_getinfo,	NETDFS_OPNUM_GETINFO },
	{ netdfs_s_enum,	NETDFS_OPNUM_ENUM },
	{ netdfs_s_rename,	NETDFS_OPNUM_RENAME },
	{ netdfs_s_move,	NETDFS_OPNUM_MOVE },
	{ netdfs_s_addstdroot,	NETDFS_OPNUM_ADDSTDROOT },
	{ netdfs_s_remstdroot,	NETDFS_OPNUM_REMSTDROOT },
	{ netdfs_s_enumex,	NETDFS_OPNUM_ENUMEX },
	{0}
};

static ndr_service_t netdfs_service = {
	"NETDFS",			/* name */
	"DFS",				/* desc */
	"\\netdfs",			/* endpoint */
	PIPE_NETDFS,			/* sec_addr_port */
	NETDFS_ABSTRACT_UUID,	NETDFS_ABSTRACT_VERS,
	NETDFS_TRANSFER_UUID,	NETDFS_TRANSFER_VERS,

	0,				/* no bind_instance_size */
	0,				/* no bind_req() */
	0,				/* no unbind_and_close() */
	0,				/* use generic_call_stub() */

	&TYPEINFO(netdfs_interface),	/* interface ti */
	netdfs_stub_table		/* stub_table */
};

/*
 * Register the NETDFS RPC interface with the RPC runtime library.
 * The service must be registered in order to use either the client
 * side or the server side functions.
 */
void
netdfs_initialize(void)
{
	(void) ndr_svc_register(&netdfs_service);
	dfs_init();
}

void
netdfs_finalize(void)
{
	dfs_fini();
}

/*
 * Returns the version number of the DFS server in use on the server.
 *
 * [MS-DFSNM]: NetrDfsManagerGetVersion (Opnum 0)
 */
/*ARGSUSED*/
static int
netdfs_s_getver(void *arg, ndr_xa_t *mxa)
{
	struct netdfs_getver *param = arg;

	param->version = DFS_MANAGER_VERSION_NT4;
	return (NDR_DRC_OK);
}

/*
 * Creates a new DFS link or adds a new target to an existing link of a
 * DFS namespace.
 *
 * [MS-DFSNM]: NetrDfsAdd (Opnum 1)
 */
static int
netdfs_s_add(void *arg, ndr_xa_t *mxa)
{
	netdfs_add_t *param = arg;
	dfs_path_t path;
	uint32_t status;
	const char *uncpath = (const char *)param->dfs_path;
	const char *fspath = (const char *)path.p_fspath;
	boolean_t newlink;

	if (!ndr_is_admin(mxa)) {
		param->status = ERROR_ACCESS_DENIED;
		return (NDR_DRC_OK);
	}

	if (param->server == NULL || param->share == NULL) {
		param->status = ERROR_INVALID_PARAMETER;
		return (NDR_DRC_OK);
	}

	switch (param->flags) {
	case DFS_CREATE_VOLUME:
	case DFS_ADD_VOLUME:
	case DFS_RESTORE_VOLUME:
	case (DFS_ADD_VOLUME | DFS_RESTORE_VOLUME):
		break;
	default:
		param->status = ERROR_INVALID_PARAMETER;
		return (NDR_DRC_OK);
	}

	status = dfs_path_parse(&path, uncpath, DFS_OBJECT_LINK);
	if (status != ERROR_SUCCESS) {
		param->status = status;
		return (NDR_DRC_OK);
	}

	status = smb_name_validate_rpath(path.p_unc.unc_path);
	if (status != ERROR_SUCCESS) {
		dfs_path_free(&path);
		param->status = status;
		return (NDR_DRC_OK);
	}

	dfs_setpriv(PRIV_ON);

	netdfs_path_create(fspath);

	status = dfs_link_add(fspath, (const char *)param->server,
	    (const char *)param->share, (const char *)param->comment,
	    param->flags, &newlink);

	if (newlink)
		(void) dfs_cache_add_byname(path.p_unc.unc_share,
		    path.p_unc.unc_path, DFS_OBJECT_LINK);

	if (status != ERROR_SUCCESS)
		netdfs_path_remove(&path.p_unc);

	dfs_setpriv(PRIV_OFF);

	dfs_path_free(&path);
	param->status = status;
	return (NDR_DRC_OK);
}

/*
 * Removes a link or a link target from a DFS namespace. A link can be
 * removed regardless of the number of targets associated with it.
 *
 * [MS-DFSNM]: NetrDfsRemove (Opnum 2)
 */
static int
netdfs_s_remove(void *arg, ndr_xa_t *mxa)
{
	struct netdfs_remove *param = arg;
	dfs_path_t path;
	uint32_t status, stat;
	const char *uncpath = (const char *)param->dfs_path;
	const char *fspath = (const char *)path.p_fspath;

	if (!ndr_is_admin(mxa)) {
		param->status = ERROR_ACCESS_DENIED;
		return (NDR_DRC_OK);
	}

	/* both server and share must be NULL or non-NULL */
	if ((param->server == NULL && param->share != NULL) ||
	    (param->server != NULL && param->share == NULL)) {
		param->status = ERROR_INVALID_PARAMETER;
		return (NDR_DRC_OK);
	}

	status = dfs_path_parse(&path, uncpath, DFS_OBJECT_LINK);
	if (status != ERROR_SUCCESS) {
		param->status = status;
		return (NDR_DRC_OK);
	}

	dfs_setpriv(PRIV_ON);

	status = dfs_link_remove(fspath, (const char *)param->server,
	    (const char *)param->share);

	if (status == ERROR_SUCCESS) {
		if (dfs_link_stat(fspath, &stat) == ERROR_SUCCESS) {
			if (stat != DFS_STAT_ISDFS)
				dfs_cache_remove(path.p_unc.unc_share,
				    path.p_unc.unc_path);
			/*
			 * if link is removed then try to remove its
			 * empty parent directories if any
			 */
			if (stat == DFS_STAT_NOTFOUND)
				netdfs_path_remove(&path.p_unc);
		}
	}

	dfs_setpriv(PRIV_OFF);

	dfs_path_free(&path);
	param->status = status;
	return (NDR_DRC_OK);
}

/*
 * Sets or modifies information relevant to a specific DFS root, DFS root
 * target, DFS link, or DFS link target
 *
 * [MS-DFSNM]: NetrDfsSetInfo (Opnum 3)
 */
/*ARGSUSED*/
static int
netdfs_s_setinfo(void *arg, ndr_xa_t *mxa)
{
	netdfs_setinfo_t *param = arg;
	dfs_path_t path;
	uint32_t status, stat;

	/* both server and share must be NULL or non-NULL */
	if ((param->server == NULL && param->share != NULL) ||
	    (param->server != NULL && param->share == NULL)) {
		param->status = ERROR_INVALID_PARAMETER;
		return (NDR_DRC_OK);
	}

	status = dfs_path_parse(&path, (const char *)param->dfs_path,
	    DFS_OBJECT_ANY);

	if (status != ERROR_SUCCESS) {
		param->status = status;
		return (NDR_DRC_OK);
	}

	dfs_setpriv(PRIV_ON);
	status = dfs_link_stat((const char *)path.p_fspath, &stat);

	if ((path.p_type == DFS_OBJECT_LINK) && (stat != DFS_STAT_ISDFS)) {
		dfs_setpriv(PRIV_OFF);
		dfs_path_free(&path);
		param->status = ERROR_NOT_FOUND;
		return (NDR_DRC_OK);
	}

	switch (param->info.level) {
	case 100:
		status = netdfs_setinfo_100(&path, param->info.iu.info100);
		break;
	case 101:
		status = netdfs_setinfo_101(&path, param->info.iu.info101,
		    (const char *)param->server, (const char *)param->share);
		break;
	case 102:
		status = netdfs_setinfo_102(&path, param->info.iu.info102);
		break;
	case 103:
		status = netdfs_setinfo_103(&path, param->info.iu.info103);
		break;
	case 104:
		status = netdfs_setinfo_104(&path, param->info.iu.info104,
		    (const char *)param->server, (const char *)param->share);
		break;
	case 105:
		status = netdfs_setinfo_105(&path, param->info.iu.info105);
		break;
	default:
		status = ERROR_INVALID_LEVEL;
		break;
	}

	dfs_setpriv(PRIV_OFF);
	dfs_path_free(&path);
	param->status = status;
	return (NDR_DRC_OK);
}

/*
 * Returns information about a DFS root or a DFS link of the specified
 * DFS namespace.
 *
 * [MS-DFSNM]: NetrDfsGetInfo (Opnum 4)
 */
static int
netdfs_s_getinfo(void *arg, ndr_xa_t *mxa)
{
	netdfs_getinfo_t *param = arg;
	netdfs_info1_t *info1;
	netdfs_info2_t *info2;
	netdfs_info3_t *info3;
	netdfs_info4_t *info4;
	netdfs_info5_t *info5;
	netdfs_info6_t *info6;
	netdfs_info100_t *info100;
	dfs_info_t info;
	dfs_path_t path;
	uint32_t status, stat;
	const char *fspath;
	uint32_t level = param->level;

	status = dfs_path_parse(&path, (const char *)param->dfs_path,
	    DFS_OBJECT_ANY);

	if (status != ERROR_SUCCESS)
		goto getinfo_error;

	dfs_setpriv(PRIV_ON);

	fspath = path.p_fspath;
	if (path.p_type == DFS_OBJECT_LINK) {
		status = dfs_link_stat(fspath, &stat);
		if ((status != ERROR_SUCCESS) || (stat != DFS_STAT_ISDFS)) {
			status = ERROR_NOT_FOUND;
			goto getinfo_error;
		}

		status = dfs_link_getinfo(fspath, &info, param->level);
	} else {
		status = dfs_root_getinfo(fspath, &info, param->level);
	}

	if (status != ERROR_SUCCESS)
		goto getinfo_error;

	(void) strlcpy(info.i_uncpath, (char *)param->dfs_path,
	    sizeof (info.i_uncpath));

	dfs_info_trace("netdfs_s_getinfo", &info);

	status = ERROR_NOT_ENOUGH_MEMORY;

	switch (level) {
	case 1:
		if ((info1 = NDR_NEW(mxa, netdfs_info1_t)) != NULL) {
			param->info.iu.info1 = info1;
			status = netdfs_info_1(info1, &info, mxa, NULL);
		}
		break;
	case 2:
		if ((info2 = NDR_NEW(mxa, netdfs_info2_t)) != NULL) {
			param->info.iu.info2 = info2;
			status = netdfs_info_2(info2, &info, mxa, NULL);
		}
		break;
	case 3:
		if ((info3 = NDR_NEW(mxa, netdfs_info3_t)) != NULL) {
			param->info.iu.info3 = info3;
			status = netdfs_info_3(info3, &info, mxa, NULL);
		}
		break;
	case 4:
		if ((info4 = NDR_NEW(mxa, netdfs_info4_t)) != NULL) {
			param->info.iu.info4 = info4;
			status = netdfs_info_4(info4, &info, mxa, NULL);
		}
		break;
	case 5:
		if ((info5 = NDR_NEW(mxa, netdfs_info5_t)) != NULL) {
			param->info.iu.info5 = info5;
			status = netdfs_info_5(info5, &info, mxa, NULL);
		}
		break;
	case 6:
		if ((info6 = NDR_NEW(mxa, netdfs_info6_t)) != NULL) {
			param->info.iu.info6 = info6;
			status = netdfs_info_6(info6, &info, mxa, NULL);
		}
		break;
	case 100:
		if ((info100 = NDR_NEW(mxa, netdfs_info100_t)) != NULL) {
			param->info.iu.info100 = info100;
			status = netdfs_info_100(info100, &info, mxa, NULL);
		}
		break;

	default:
		status = ERROR_INVALID_LEVEL;
		break;
	}

	dfs_info_free(&info);

getinfo_error:
	dfs_setpriv(PRIV_OFF);
	dfs_path_free(&path);
	if (status != ERROR_SUCCESS)
		bzero(param, sizeof (netdfs_getinfo_t));

	param->info.level = level;
	param->status = status;
	return (NDR_DRC_OK);
}

/*
 * Enumerates the DFS root hosted on a server or the DFS links of the
 * namespace hosted by a server. Depending on the information level,
 * the targets of the root and links are also displayed.
 *
 * For unsupported levels, it should return ERROR_INVALID_LEVEL as
 * Microsoft does for DFS server on Win2000 and NT.
 *
 * [MS-DFSNM]: NetrDfsEnum (Opnum 5)
 */
/*ARGSUSED*/
static int
netdfs_s_enum(void *arg, ndr_xa_t *mxa)
{
	netdfs_enum_t *param = arg;
	netdfs_enumhandle_t de;
	uint32_t level = param->level;
	uint32_t status = ERROR_SUCCESS;
	uint32_t nroot;
	size_t entsize;

	if (param->info == NULL) {
		status = ERROR_INVALID_PARAMETER;
		goto enum_error;
	}

	if ((nroot = dfs_namespace_count()) == 0)
		status = ERROR_NOT_FOUND;
	else if (nroot > 1)
		status = ERROR_DEVICE_NOT_AVAILABLE;

	if (status != ERROR_SUCCESS)
		goto enum_error;

	bzero(&de, sizeof (netdfs_enumhandle_t));
	de.de_level = level;
	de.de_ntotal = dfs_cache_num();

	if (param->pref_max_len == NETDFS_MAXPREFLEN ||
	    param->pref_max_len > NETDFS_MAXBUFLEN)
		de.de_prefmaxlen = NETDFS_MAXBUFLEN;
	else
		de.de_prefmaxlen = param->pref_max_len;

	de.de_bavail = de.de_prefmaxlen;

	if (param->resume_handle != NULL) {
		if (*param->resume_handle >= de.de_ntotal) {
			status = ERROR_NO_MORE_ITEMS;
			goto enum_error;
		}
		de.de_resume = *param->resume_handle;
		de.de_nskip = de.de_resume;
		*param->resume_handle = 0;
	}

	dfs_setpriv(PRIV_ON);

	status = ERROR_NOT_ENOUGH_MEMORY;

	switch (level) {
	case 1:
		entsize = sizeof (netdfs_info1_t);
		de.de_nmax = MAX((de.de_prefmaxlen / entsize), 1);
		de.de_entries = NDR_NEWN(mxa, netdfs_info1_t, de.de_nmax);
		if (de.de_entries == NULL)
			goto enum_error;

		if ((status = netdfs_enum_common(&de, mxa)) == ERROR_SUCCESS) {
			param->info->iu.info1->info1 = de.de_entries;
			param->info->iu.info1->count = de.de_nitems;
		}
		break;
	case 2:
		entsize = sizeof (netdfs_info2_t);
		de.de_nmax = MAX((de.de_prefmaxlen / entsize), 1);
		de.de_entries = NDR_NEWN(mxa, netdfs_info2_t, de.de_nmax);
		if (de.de_entries == NULL)
			goto enum_error;

		if ((status = netdfs_enum_common(&de, mxa)) == ERROR_SUCCESS) {
			param->info->iu.info2->info2 = de.de_entries;
			param->info->iu.info2->count = de.de_nitems;
		}
		break;
	case 3:
		entsize = sizeof (netdfs_info3_t) +
		    sizeof (netdfs_storage_info_t);
		de.de_nmax = MAX((de.de_prefmaxlen / entsize), 1);
		de.de_entries = NDR_NEWN(mxa, netdfs_info3_t, de.de_nmax);
		if (de.de_entries == NULL)
			goto enum_error;

		if ((status = netdfs_enum_common(&de, mxa)) == ERROR_SUCCESS) {
			param->info->iu.info3->info3 = de.de_entries;
			param->info->iu.info3->count = de.de_nitems;
		}
		break;
	case 4:
		entsize = sizeof (netdfs_info4_t) +
		    sizeof (netdfs_storage_info_t);
		de.de_nmax = MAX((de.de_prefmaxlen / entsize), 1);
		de.de_entries = NDR_NEWN(mxa, netdfs_info4_t, de.de_nmax);
		if (de.de_entries == NULL)
			goto enum_error;

		if ((status = netdfs_enum_common(&de, mxa)) == ERROR_SUCCESS) {
			param->info->iu.info4->info4 = de.de_entries;
			param->info->iu.info4->count = de.de_nitems;
		}
		break;

	case 5:
		entsize = sizeof (netdfs_info5_t);
		de.de_nmax = MAX((de.de_prefmaxlen / entsize), 1);
		de.de_entries = NDR_NEWN(mxa, netdfs_info5_t, de.de_nmax);
		if (de.de_entries == NULL)
			goto enum_error;

		if ((status = netdfs_enum_common(&de, mxa)) == ERROR_SUCCESS) {
			param->info->iu.info5->info5 = de.de_entries;
			param->info->iu.info5->count = de.de_nitems;
		}
		break;

	case 6:
		entsize = sizeof (netdfs_info6_t) +
		    sizeof (netdfs_storage_info1_t);
		de.de_nmax = MAX((de.de_prefmaxlen / entsize), 1);
		de.de_entries = NDR_NEWN(mxa, netdfs_info6_t, de.de_nmax);
		if (de.de_entries == NULL)
			goto enum_error;

		if ((status = netdfs_enum_common(&de, mxa)) == ERROR_SUCCESS) {
			param->info->iu.info6->info6 = de.de_entries;
			param->info->iu.info6->count = de.de_nitems;
		}
		break;

	case 300:
		entsize = sizeof (netdfs_info300_t);
		de.de_nmax = MAX((de.de_prefmaxlen / entsize), 1);
		de.de_entries = NDR_NEWN(mxa, netdfs_info300_t, de.de_nmax);
		if (de.de_entries == NULL)
			goto enum_error;

		if ((status = netdfs_enum_common(&de, mxa)) == ERROR_SUCCESS) {
			param->info->iu.info300->info300 = de.de_entries;
			param->info->iu.info300->count = de.de_nitems;
		}
		break;

	default:
		status = ERROR_INVALID_PARAMETER;
		break;
	}

	if ((status == ERROR_SUCCESS) && (param->resume_handle != NULL))
		*param->resume_handle = de.de_resume;

enum_error:
	dfs_setpriv(PRIV_OFF);
	param->status = status;
	return (NDR_DRC_OK);
}

/*
 * Renames or moves a DFS link
 *
 * Does not need to be supported for DFS version 1
 *
 * [MS-DFSNM]: NetrDfsMove (Opnum 6)
 */
/*ARGSUSED*/
static int
netdfs_s_move(void *arg, ndr_xa_t *mxa)
{
	struct netdfs_move *param = arg;

	param->status = ERROR_NOT_SUPPORTED;
	return (NDR_DRC_OK);
}

/*
 * According to [MS-DFSNM] spec this operation (opnum 7) is not
 * used over the wire.
 */
/*ARGSUSED*/
static int
netdfs_s_rename(void *arg, ndr_xa_t *mxa)
{
	struct netdfs_rename *param = arg;

	param->status = ERROR_NOT_SUPPORTED;
	return (NDR_DRC_OK);
}

/*
 * Creates a new standalone DFS namespace
 *
 * [MS-DFSNM]: NetrDfsAddStdRoot (Opnum 12)
 */
/*ARGSUSED*/
static int
netdfs_s_addstdroot(void *arg, ndr_xa_t *mxa)
{
	struct netdfs_addstdroot *param = arg;
	const char *share = (const char *)param->share;
	const char *comment = (const char *)param->comment;

	if (!ndr_is_admin(mxa)) {
		param->status = ERROR_ACCESS_DENIED;
		return (NDR_DRC_OK);
	}

	dfs_setpriv(PRIV_ON);

	/* For now only allow a single standalone namespace */
	if (dfs_namespace_count() == 0)
		param->status = dfs_namespace_add(share, comment);
	else
		param->status = ERROR_NOT_SUPPORTED;

	dfs_setpriv(PRIV_OFF);
	return (NDR_DRC_OK);
}

/*
 * Deletes the specified stand-alone DFS namespace. The DFS namespace can be
 * removed without first removing all of the links in it.
 *
 * [MS-DFSNM]: NetrDfsRemoveStdRoot (Opnum 13)
 */
/*ARGSUSED*/
static int
netdfs_s_remstdroot(void *arg, ndr_xa_t *mxa)
{
	struct netdfs_remstdroot *param = arg;
	const char *share = (const char *)param->share;

	dfs_setpriv(PRIV_ON);

	if (ndr_is_admin(mxa))
		param->status = dfs_namespace_remove(share);
	else
		param->status = ERROR_ACCESS_DENIED;

	dfs_setpriv(PRIV_OFF);
	return (NDR_DRC_OK);
}

/*
 * Enumerates the DFS roots hosted on a server, or DFS links of a namespace
 * hosted by the server. Depending on the information level, the targets
 * associated with the roots and links are also displayed
 *
 * Does not need to be supported for DFS version 1
 *
 * [MS-DFSNM] NetrDfsEnumEx (Opnum 21)
 */
/*ARGSUSED*/
static int
netdfs_s_enumex(void *arg, ndr_xa_t *mxa)
{
	struct netdfs_enumex *param = arg;

	bzero(param->info, sizeof (struct netdfs_enumex));
	param->status = ERROR_NOT_SUPPORTED;
	return (NDR_DRC_OK);
}

/*
 * Sets the comment for the DFS link/root.
 */
static uint32_t
netdfs_setinfo_100(dfs_path_t *path, netdfs_info100_t *netinfo)
{
	dfs_info_t info;
	uint32_t status;
	char *cmnt = (char *)netinfo->comment;

	bzero(&info, sizeof (dfs_info_t));
	if (cmnt != NULL)
		(void) strlcpy(info.i_comment, cmnt, sizeof (info.i_comment));

	if (path->p_type == DFS_OBJECT_LINK)
		status = dfs_link_setinfo(path->p_fspath, &info, 100);
	else
		status = dfs_root_setinfo(path->p_fspath, &info, 100);

	return (status);
}

/*
 * Sets the state for the DFS root/link or its target.
 */
static uint32_t
netdfs_setinfo_101(dfs_path_t *path, netdfs_info101_t *netinfo,
    const char *t_server, const char *t_share)
{
	dfs_info_t info;
	dfs_target_t target;
	uint32_t status;

	bzero(&info, sizeof (dfs_info_t));
	bzero(&target, sizeof (dfs_target_t));

	if (t_server == NULL && t_share == NULL) {
		info.i_state = netinfo->state;
	} else {
		target.t_state = netinfo->state;
		(void) strlcpy(target.t_server, t_server,
		    sizeof (target.t_server));
		(void) strlcpy(target.t_share, t_share,
		    sizeof (target.t_share));
		info.i_targets = &target;
	}

	if (path->p_type == DFS_OBJECT_LINK)
		status = dfs_link_setinfo(path->p_fspath, &info, 101);
	else
		status = dfs_root_setinfo(path->p_fspath, &info, 101);

	return (status);
}

/*
 * Sets the timeout value of the DFS link/root.
 */
static uint32_t
netdfs_setinfo_102(dfs_path_t *path, netdfs_info102_t *netinfo)
{
	dfs_info_t info;
	uint32_t status;

	bzero(&info, sizeof (dfs_info_t));
	info.i_timeout = netinfo->timeout;

	if (path->p_type == DFS_OBJECT_LINK)
		status = dfs_link_setinfo(path->p_fspath, &info, 102);
	else
		status = dfs_root_setinfo(path->p_fspath, &info, 102);

	return (status);
}

/*
 * Sets the property flags for the root or link.
 */
static uint32_t
netdfs_setinfo_103(dfs_path_t *path, netdfs_info103_t *netinfo)
{
	dfs_info_t info;
	uint32_t status;

	bzero(&info, sizeof (dfs_info_t));
	info.i_propflags =
	    netinfo->property_flags & netinfo->property_flag_mask;

	if (path->p_type == DFS_OBJECT_LINK)
		status = dfs_link_setinfo(path->p_fspath, &info, 103);
	else
		status = dfs_root_setinfo(path->p_fspath, &info, 103);

	return (status);
}

/*
 * Sets the target priority rank and class for the root target or link target
 */
static uint32_t
netdfs_setinfo_104(dfs_path_t *path, netdfs_info104_t *netinfo,
    const char *t_server, const char *t_share)
{
	dfs_info_t info;
	dfs_target_t target;
	uint32_t status;

	if ((t_server == NULL) || (t_share == NULL))
		return (ERROR_INVALID_PARAMETER);

	bzero(&info, sizeof (dfs_info_t));
	bzero(&target, sizeof (dfs_target_t));

	target.t_priority.p_class = netinfo->priority_class;
	target.t_priority.p_rank = netinfo->priority_rank;
	(void) strlcpy(target.t_server, t_server, sizeof (target.t_server));
	(void) strlcpy(target.t_share, t_share, sizeof (target.t_share));
	info.i_targets = &target;

	if (path->p_type == DFS_OBJECT_LINK)
		status = dfs_link_setinfo(path->p_fspath, &info, 104);
	else
		status = dfs_root_setinfo(path->p_fspath, &info, 104);

	return (status);
}

/*
 * Sets the comment, state, time-out information, and property flags for the
 * namespace root or link specified in DfsInfo. Does not apply to a root target
 * or link target.
 */
static uint32_t
netdfs_setinfo_105(dfs_path_t *path, netdfs_info105_t *netinfo)
{
	dfs_info_t info;
	uint32_t status;
	char *cmnt = (char *)netinfo->comment;

	bzero(&info, sizeof (dfs_info_t));

	if (cmnt != NULL)
		(void) strlcpy(info.i_comment, cmnt, sizeof (info.i_comment));
	info.i_state = netinfo->state;
	info.i_timeout = netinfo->timeout;
	info.i_propflags =
	    netinfo->property_flags & netinfo->property_flag_mask;

	if (path->p_type == DFS_OBJECT_LINK)
		status = dfs_link_setinfo(path->p_fspath, &info, 105);
	else
		status = dfs_root_setinfo(path->p_fspath, &info, 105);

	return (status);
}

/*
 * DFS_STORAGE_INFO: target information
 */
static uint32_t
netdfs_info_storage(netdfs_storage_info_t **sinfo, dfs_info_t *info,
    ndr_xa_t *mxa, uint32_t *size)
{
	netdfs_storage_info_t *storage;
	dfs_target_t *target;
	int i;

	*sinfo = NULL;
	if (info->i_ntargets == 0)
		return (ERROR_SUCCESS);

	*sinfo = NDR_NEWN(mxa, netdfs_storage_info_t, info->i_ntargets);
	if (*sinfo == NULL)
		return (ERROR_NOT_ENOUGH_MEMORY);

	if (size != NULL)
		*size += info->i_ntargets * sizeof (netdfs_storage_info_t);

	target = info->i_targets;
	storage = *sinfo;
	for (i = 0; i < info->i_ntargets; i++, target++, storage++) {
		storage->state = target->t_state;
		storage->server = NDR_STRDUP(mxa, target->t_server);
		storage->share = NDR_STRDUP(mxa, target->t_share);

		if (storage->server == NULL || storage->share == NULL)
			return (ERROR_NOT_ENOUGH_MEMORY);

		if (size != NULL)
			*size += smb_wcequiv_strlen(target->t_server) +
			    smb_wcequiv_strlen(target->t_share);
	}

	return (ERROR_SUCCESS);
}

/*
 * DFS_STORAGE_INFO_1: target information
 */
static uint32_t
netdfs_info_storage1(netdfs_storage_info1_t **sinfo, dfs_info_t *info,
    ndr_xa_t *mxa, uint32_t *size)
{
	netdfs_storage_info1_t *storage;
	dfs_target_t *target;
	int i;

	*sinfo = NULL;
	if (info->i_ntargets == 0)
		return (ERROR_SUCCESS);

	*sinfo = NDR_NEWN(mxa, netdfs_storage_info1_t, info->i_ntargets);
	if (*sinfo == NULL)
		return (ERROR_NOT_ENOUGH_MEMORY);

	if (size != NULL)
		*size += info->i_ntargets * sizeof (netdfs_storage_info1_t);

	target = info->i_targets;
	storage = *sinfo;
	for (i = 0; i < info->i_ntargets; i++, target++, storage++) {
		storage->state = target->t_state;
		storage->server = NDR_STRDUP(mxa, target->t_server);
		storage->share = NDR_STRDUP(mxa, target->t_share);
		storage->p_class = target->t_priority.p_class;
		storage->p_rank = target->t_priority.p_rank;
		storage->p_reserved = 0;

		if (storage->server == NULL || storage->share == NULL)
			return (ERROR_NOT_ENOUGH_MEMORY);

		if (size != NULL)
			*size += smb_wcequiv_strlen(target->t_server) +
			    smb_wcequiv_strlen(target->t_share);
	}

	return (ERROR_SUCCESS);
}

/*
 * Sets a DFS_INFO_1 for get/enum response
 */
static uint32_t
netdfs_info_1(netdfs_info1_t *info1, dfs_info_t *info, ndr_xa_t *mxa,
    uint32_t *size)
{
	info1->entry_path = NDR_STRDUP(mxa, info->i_uncpath);
	if (info1->entry_path == NULL)
		return (ERROR_NOT_ENOUGH_MEMORY);

	if (size != NULL)
		*size = sizeof (netdfs_info1_t) +
		    smb_wcequiv_strlen(info->i_uncpath);

	return (ERROR_SUCCESS);
}

/*
 * Sets a DFS_INFO_2 for get/enum response
 */
static uint32_t
netdfs_info_2(netdfs_info2_t *info2, dfs_info_t *info, ndr_xa_t *mxa,
    uint32_t *size)
{
	void *entry_path;
	void *comment;

	entry_path = NDR_STRDUP(mxa, info->i_uncpath);
	comment = NDR_STRDUP(mxa, info->i_comment);

	if (entry_path == NULL || comment == NULL)
		return (ERROR_NOT_ENOUGH_MEMORY);

	info2->entry_path = entry_path;
	info2->comment = comment;
	info2->state = info->i_state;
	info2->n_store = info->i_ntargets;

	if (size != NULL)
		*size = sizeof (netdfs_info2_t) +
		    smb_wcequiv_strlen(info->i_uncpath) +
		    smb_wcequiv_strlen(info->i_comment);

	return (ERROR_SUCCESS);
}

/*
 * Sets a DFS_INFO_3 for get/enum response
 */
static uint32_t
netdfs_info_3(netdfs_info3_t *info3, dfs_info_t *info, ndr_xa_t *mxa,
    uint32_t *size)
{
	void *entry_path;
	void *comment;

	entry_path = NDR_STRDUP(mxa, info->i_uncpath);
	comment = NDR_STRDUP(mxa, info->i_comment);

	if (entry_path == NULL || comment == NULL)
		return (ERROR_NOT_ENOUGH_MEMORY);

	info3->entry_path = entry_path;
	info3->comment = comment;
	info3->state = info->i_state;
	info3->n_store = info->i_ntargets;

	if (size != NULL)
		*size = sizeof (netdfs_info3_t) +
		    smb_wcequiv_strlen(info->i_uncpath) +
		    smb_wcequiv_strlen(info->i_comment);

	return (netdfs_info_storage(&info3->si, info, mxa, size));
}

/*
 * Sets a DFS_INFO_4 for get/enum response
 */
static uint32_t
netdfs_info_4(netdfs_info4_t *info4, dfs_info_t *info, ndr_xa_t *mxa,
    uint32_t *size)
{
	void *entry_path;
	void *comment;

	entry_path = NDR_STRDUP(mxa, info->i_uncpath);
	comment = NDR_STRDUP(mxa, info->i_comment);

	if (entry_path == NULL || comment == NULL)
		return (ERROR_NOT_ENOUGH_MEMORY);

	if (!netdfs_guid_fromstr(info->i_guid, &info4->guid))
		return (ERROR_INVALID_DATA);

	info4->entry_path = entry_path;
	info4->comment = comment;
	info4->state = info->i_state;
	info4->timeout = info->i_timeout;
	info4->n_store = info->i_ntargets;

	if (size != NULL)
		*size = sizeof (netdfs_info4_t) +
		    smb_wcequiv_strlen(info->i_uncpath) +
		    smb_wcequiv_strlen(info->i_comment);

	return (netdfs_info_storage(&info4->si, info, mxa, size));
}

/*
 * Sets a DFS_INFO_5 for get/enum response
 */
static uint32_t
netdfs_info_5(netdfs_info5_t *info5, dfs_info_t *info, ndr_xa_t *mxa,
    uint32_t *size)
{
	void *entry_path;
	void *comment;

	entry_path = NDR_STRDUP(mxa, info->i_uncpath);
	comment = NDR_STRDUP(mxa, info->i_comment);

	if (entry_path == NULL || comment == NULL)
		return (ERROR_NOT_ENOUGH_MEMORY);

	if (!netdfs_guid_fromstr(info->i_guid, &info5->guid))
		return (ERROR_INVALID_DATA);

	info5->entry_path = entry_path;
	info5->comment = comment;
	info5->state = info->i_state;
	info5->timeout = info->i_timeout;
	info5->flags = info->i_propflags;
	info5->metadata_sz = 0;
	info5->n_store = info->i_ntargets;

	if (size != NULL)
		*size = sizeof (netdfs_info5_t) +
		    smb_wcequiv_strlen(info->i_uncpath) +
		    smb_wcequiv_strlen(info->i_comment);

	return (ERROR_SUCCESS);
}

/*
 * Sets a DFS_INFO_6 for get/enum response
 */
static uint32_t
netdfs_info_6(netdfs_info6_t *info6, dfs_info_t *info, ndr_xa_t *mxa,
    uint32_t *size)
{
	void *entry_path;
	void *comment;

	entry_path = NDR_STRDUP(mxa, info->i_uncpath);
	comment = NDR_STRDUP(mxa, info->i_comment);

	if (entry_path == NULL || comment == NULL)
		return (ERROR_NOT_ENOUGH_MEMORY);

	if (!netdfs_guid_fromstr(info->i_guid, &info6->guid))
		return (ERROR_INVALID_DATA);

	info6->entry_path = entry_path;
	info6->comment = comment;
	info6->state = info->i_state;
	info6->timeout = info->i_timeout;
	info6->flags = info->i_propflags;
	info6->metadata_sz = 0;
	info6->n_store = info->i_ntargets;

	if (size != NULL)
		*size = sizeof (netdfs_info6_t) +
		    smb_wcequiv_strlen(info->i_uncpath) +
		    smb_wcequiv_strlen(info->i_comment);

	return (netdfs_info_storage1(&info6->si, info, mxa, size));
}

/*
 * Sets a DFS_INFO_100 for Get response
 */
static uint32_t
netdfs_info_100(netdfs_info100_t *info100, dfs_info_t *info, ndr_xa_t *mxa,
    uint32_t *size)
{
	info100->comment = NDR_STRDUP(mxa, info->i_comment);
	if (info100->comment == NULL)
		return (ERROR_NOT_ENOUGH_MEMORY);

	if (size != NULL)
		*size = sizeof (netdfs_info100_t) +
		    smb_wcequiv_strlen(info->i_comment);

	return (ERROR_SUCCESS);
}

/*
 * Sets a DFS_INFO_300 for Enum response
 */
static uint32_t
netdfs_info_300(netdfs_info300_t *info300, dfs_info_t *info, ndr_xa_t *mxa,
    uint32_t *size)
{
	info300->dfsname = NDR_STRDUP(mxa, info->i_uncpath);
	if (info300->dfsname == NULL)
		return (ERROR_NOT_ENOUGH_MEMORY);

	info300->flavor = DFS_VOLUME_FLAVOR_STANDALONE;
	if (size != NULL)
		*size = sizeof (netdfs_info300_t) +
		    smb_wcequiv_strlen(info->i_uncpath);

	return (ERROR_SUCCESS);
}

/*
 * Common enumeration function
 */
static uint32_t
netdfs_enum_common(netdfs_enumhandle_t *de, ndr_xa_t *mxa)
{
	netdfs_info1_t *info1 = de->de_entries;
	netdfs_info2_t *info2 = de->de_entries;
	netdfs_info3_t *info3 = de->de_entries;
	netdfs_info4_t *info4 = de->de_entries;
	netdfs_info5_t *info5 = de->de_entries;
	netdfs_info6_t *info6 = de->de_entries;
	netdfs_info300_t *info300 = de->de_entries;
	dfs_info_t dfsinfo;
	smb_cache_cursor_t cursor;
	dfs_nscnode_t nscnode;
	uint32_t status;
	uint32_t itemsz;

	dfs_cache_iterinit(&cursor);

	de->de_nitems = 0;
	while (dfs_cache_iterate(&cursor, &nscnode)) {
		if (de->de_nskip > 0) {
			de->de_nskip--;
			continue;
		}

		if (de->de_nitems == de->de_nmax)
			break;

		status = dfs_cache_getinfo(&nscnode, &dfsinfo, de->de_level);
		if (status != ERROR_SUCCESS)
			continue;

		switch (de->de_level) {
		case 1:
			status = netdfs_info_1(info1, &dfsinfo, mxa, &itemsz);
			info1++;
			break;
		case 2:
			status = netdfs_info_2(info2, &dfsinfo, mxa, &itemsz);
			info2++;
			break;
		case 3:
			status = netdfs_info_3(info3, &dfsinfo, mxa, &itemsz);
			info3++;
			break;
		case 4:
			status = netdfs_info_4(info4, &dfsinfo, mxa, &itemsz);
			info4++;
			break;
		case 5:
			status = netdfs_info_5(info5, &dfsinfo, mxa, &itemsz);
			info5++;
			break;
		case 6:
			status = netdfs_info_6(info6, &dfsinfo, mxa, &itemsz);
			info6++;
			break;
		case 300:
			status = netdfs_info_300(info300, &dfsinfo, mxa,
			    &itemsz);
			info300++;
			break;
		default:
			status = ERROR_INVALID_LEVEL;
		}

		dfs_info_free(&dfsinfo);

		if (status != ERROR_SUCCESS)
			return (status);

		if (de->de_nmax == 1) {
			de->de_nitems = 1;
			break;
		}

		if (itemsz > de->de_bavail)
			break;

		de->de_bavail -= itemsz;
		de->de_nitems++;
	}

	de->de_resume += de->de_nitems;
	return (ERROR_SUCCESS);
}

/*
 * Creates intermediate directories of a link from the root share path.
 *
 * TODO: directories should be created by smbsrv to get Windows compatible
 * ACL inheritance.
 */
static void
netdfs_path_create(const char *path)
{
	char dirpath[DFS_PATH_MAX];
	mode_t mode;
	char *p;

	(void) strlcpy(dirpath, path, DFS_PATH_MAX);

	/* drop the link itself from the path */
	if ((p = strrchr(dirpath, '/')) != NULL) {
		*p = '\0';
		mode = umask(0);
		(void) mkdirp(dirpath, 0777);
		(void) umask(mode);
	}
}

/*
 * Removes empty directories
 */
static void
netdfs_path_remove(smb_unc_t *unc)
{
	char rootdir[DFS_PATH_MAX];
	char relpath[DFS_PATH_MAX];
	char dir[DFS_PATH_MAX];
	uint32_t status;
	char *p;

	status = dfs_namespace_path(unc->unc_share, rootdir, DFS_PATH_MAX);
	if ((status == ERROR_SUCCESS) && (chdir(rootdir) == 0)) {
		(void) strlcpy(relpath, unc->unc_path, DFS_PATH_MAX);
		/* drop the link itself from the path */
		if ((p = strrchr(relpath, '/')) != NULL) {
			*p = '\0';
			(void) rmdirp(relpath, dir);
		}
	}
}

/*
 * Converts the guid string into binary format in network byte order.
 */
static boolean_t
netdfs_guid_fromstr(char *guid_str, netdfs_uuid_t *guid)
{
	uuid_t uuid;

	if (uuid_parse(guid_str, uuid) != 0)
		return (B_FALSE);

	bcopy(&uuid, guid, sizeof (uuid_t));

	guid->data1 = htonl(guid->data1);
	guid->data2 = htons(guid->data2);
	guid->data3 = htons(guid->data3);

	return (B_TRUE);
}
