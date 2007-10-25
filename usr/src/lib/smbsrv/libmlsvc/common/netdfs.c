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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Net DFS server side RPC service.
 */

#include <sys/types.h>
#include <strings.h>
#include <string.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/lmerr.h>
#include <smbsrv/lmdfs.h>
#include <smbsrv/nmpipes.h>
#include <smbsrv/nterror.h>
#include <smbsrv/mlrpc.h>
#include <smbsrv/ndl/netdfs.ndl>

typedef struct {
	char *server;
	char *share;
	char *path;
	char *buf;
} netdfs_unc_t;

static int netdfs_unc_parse(struct mlrpc_xaction *, const char *,
    netdfs_unc_t *);

static int netdfs_s_getver(void *, struct mlrpc_xaction *);
static int netdfs_s_add(void *, struct mlrpc_xaction *);
static int netdfs_s_remove(void *, struct mlrpc_xaction *);
static int netdfs_s_setinfo(void *, struct mlrpc_xaction *);
static int netdfs_s_getinfo(void *, struct mlrpc_xaction *);
static int netdfs_s_enum(void *, struct mlrpc_xaction *);
static int netdfs_s_move(void *, struct mlrpc_xaction *);
static int netdfs_s_rename(void *, struct mlrpc_xaction *);
static int netdfs_s_addstdroot(void *, struct mlrpc_xaction *);
static int netdfs_s_remstdroot(void *, struct mlrpc_xaction *);
static int netdfs_s_enumex(void *, struct mlrpc_xaction *);

static mlrpc_stub_table_t netdfs_stub_table[] = {
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

static mlrpc_service_t netdfs_service = {
	"NETDFS",			/* name */
	"DFS",				/* desc */
	"\\dfs",			/* endpoint */
	PIPE_NTSVCS,			/* sec_addr_port */
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
	(void) mlrpc_register_service(&netdfs_service);
}

/*
 * Return the version.
 *
 * We have to indicate that we emulate a Windows 2003 Server or the
 * client will not use the EnumEx RPC and this would limit support
 * to a single DFS root.
 */
/*ARGSUSED*/
static int
netdfs_s_getver(void *arg, struct mlrpc_xaction *mxa)
{
	struct netdfs_getver *param = arg;

	param->version = DFS_MANAGER_VERSION_W2K3;
	return (MLRPC_DRC_OK);
}

/*
 * Add a new volume or additional storage for an existing volume at
 * dfs_path.
 */
static int
netdfs_s_add(void *arg, struct mlrpc_xaction *mxa)
{
	struct netdfs_add *param = arg;
	netdfs_unc_t unc;
	DWORD status = ERROR_SUCCESS;

	if (param->dfs_path == NULL || param->server == NULL ||
	    param->share == NULL) {
		bzero(param, sizeof (struct netdfs_add));
		param->status = ERROR_INVALID_PARAMETER;
		return (MLRPC_DRC_OK);
	}

	if (netdfs_unc_parse(mxa, (char *)param->dfs_path, &unc) != 0) {
		status = ERROR_INVALID_PARAMETER;
	} else {
		if (unc.path == NULL)
			status = ERROR_BAD_PATHNAME;

		if (unc.share == NULL)
			status = ERROR_INVALID_SHARENAME;
	}

	if (param->status != ERROR_SUCCESS) {
		bzero(param, sizeof (struct netdfs_add));
		param->status = status;
		return (MLRPC_DRC_OK);
	}

	bzero(param, sizeof (struct netdfs_add));
	param->status = ERROR_ACCESS_DENIED;
	return (MLRPC_DRC_OK);
}

/*
 * netdfs_s_remove
 *
 * Remove a volume or additional storage for volume from the DFS at
 * dfs_path. When applied to the last storage in a volume, removes
 * the volume from the DFS.
 */
static int
netdfs_s_remove(void *arg, struct mlrpc_xaction *mxa)
{
	struct netdfs_remove *param = arg;
	netdfs_unc_t unc;
	DWORD status = ERROR_SUCCESS;

	if (param->dfs_path == NULL || param->server == NULL ||
	    param->share == NULL) {
		bzero(param, sizeof (struct netdfs_remove));
		param->status = ERROR_INVALID_PARAMETER;
		return (MLRPC_DRC_OK);
	}

	if (netdfs_unc_parse(mxa, (char *)param->dfs_path, &unc) != 0) {
		status = ERROR_INVALID_PARAMETER;
	} else {
		if (unc.path == NULL)
			status = ERROR_BAD_PATHNAME;

		if (unc.share == NULL)
			status = ERROR_INVALID_SHARENAME;
	}

	if (param->status != ERROR_SUCCESS) {
		bzero(param, sizeof (struct netdfs_remove));
		param->status = status;
		return (MLRPC_DRC_OK);
	}

	bzero(param, sizeof (struct netdfs_remove));
	param->status = ERROR_ACCESS_DENIED;
	return (MLRPC_DRC_OK);
}

/*
 * Set information about the volume or storage. If the server and share
 * are specified, the information set is specific to that server and
 * share. Otherwise the information is specific to the volume as a whole.
 *
 * Valid levels are 100-102.
 */
/*ARGSUSED*/
static int
netdfs_s_setinfo(void *arg, struct mlrpc_xaction *mxa)
{
	struct netdfs_setinfo *param = arg;
	netdfs_unc_t unc;
	DWORD status = ERROR_SUCCESS;

	if (param->dfs_path == NULL) {
		bzero(param, sizeof (struct netdfs_setinfo));
		param->status = ERROR_INVALID_PARAMETER;
		return (MLRPC_DRC_OK);
	}

	if (netdfs_unc_parse(mxa, (char *)param->dfs_path, &unc) != 0) {
		status = ERROR_INVALID_PARAMETER;
	} else {
		if (unc.share == NULL)
			status = ERROR_INVALID_SHARENAME;
	}

	if (param->status != ERROR_SUCCESS) {
		bzero(param, sizeof (struct netdfs_setinfo));
		param->status = status;
		return (MLRPC_DRC_OK);
	}

	switch (param->info.level) {
	case 100:
	case 101:
	case 102:
		break;

	default:
		bzero(param, sizeof (struct netdfs_setinfo));
		param->status = ERROR_INVALID_LEVEL;
		return (MLRPC_DRC_OK);
	}

	bzero(param, sizeof (struct netdfs_setinfo));
	param->status = ERROR_ACCESS_DENIED;
	return (MLRPC_DRC_OK);
}

/*
 * Get information about the volume or storage. If the server and share
 * are specified, the information returned is specific to that server
 * and share. Otherwise the information is specific to the volume as a
 * whole.
 *
 * Valid levels are 1-4, 100-104.
 */
/*ARGSUSED*/
static int
netdfs_s_getinfo(void *arg, struct mlrpc_xaction *mxa)
{
	struct netdfs_getinfo *param = arg;
	netdfs_unc_t unc;
	DWORD status = ERROR_SUCCESS;

	if (param->dfs_path == NULL) {
		bzero(param, sizeof (struct netdfs_getinfo));
		param->status = ERROR_INVALID_PARAMETER;
		return (MLRPC_DRC_OK);
	}

	if (netdfs_unc_parse(mxa, (char *)param->dfs_path, &unc) != 0) {
		status = ERROR_INVALID_PARAMETER;
	} else {
		if (unc.share == NULL)
			status = ERROR_INVALID_SHARENAME;
	}

	if (param->status != ERROR_SUCCESS) {
		bzero(param, sizeof (struct netdfs_getinfo));
		param->status = status;
		return (MLRPC_DRC_OK);
	}

	switch (param->level) {
	case 1:
	case 2:
	case 3:
	case 4:
	case 100:
	case 101:
	case 102:
	case 103:
	case 104:
		break;

	default:
		bzero(param, sizeof (struct netdfs_getinfo));
		param->status = ERROR_INVALID_LEVEL;
		return (MLRPC_DRC_OK);
	}

	bzero(param, sizeof (struct netdfs_getinfo));
	param->status = ERROR_ACCESS_DENIED;
	return (MLRPC_DRC_OK);
}

/*
 * Get information about all of the volumes in the DFS. dfs_name is
 * the "server" part of the UNC name used to refer to this particular
 * DFS.
 *
 * Valid levels are 1-3.
 */
/*ARGSUSED*/
static int
netdfs_s_enum(void *arg, struct mlrpc_xaction *mxa)
{
	struct netdfs_enum *param = arg;

	switch (param->level) {
	case 1:
	case 2:
	case 3:
		break;

	default:
		(void) bzero(param, sizeof (struct netdfs_enum));
		param->status = ERROR_INVALID_LEVEL;
		return (MLRPC_DRC_OK);
	}

	(void) bzero(param, sizeof (struct netdfs_enum));
	param->status = ERROR_ACCESS_DENIED;
	return (MLRPC_DRC_OK);
}

/*
 * Move a DFS volume and all subordinate volumes from one place in the
 * DFS to another place in the DFS.
 */
/*ARGSUSED*/
static int
netdfs_s_move(void *arg, struct mlrpc_xaction *mxa)
{
	struct netdfs_move *param = arg;

	if (param->dfs_path == NULL || param->new_path == NULL) {
		bzero(param, sizeof (struct netdfs_move));
		param->status = ERROR_INVALID_PARAMETER;
		return (MLRPC_DRC_OK);
	}

	bzero(param, sizeof (struct netdfs_move));
	param->status = ERROR_ACCESS_DENIED;
	return (MLRPC_DRC_OK);
}

/*
 * Rename the current path in a DFS to a new path in the same DFS.
 */
/*ARGSUSED*/
static int
netdfs_s_rename(void *arg, struct mlrpc_xaction *mxa)
{
	struct netdfs_rename *param = arg;

	if (param->dfs_path == NULL || param->new_path == NULL) {
		bzero(param, sizeof (struct netdfs_rename));
		param->status = ERROR_INVALID_PARAMETER;
		return (MLRPC_DRC_OK);
	}

	bzero(param, sizeof (struct netdfs_rename));
	param->status = ERROR_ACCESS_DENIED;
	return (MLRPC_DRC_OK);
}

/*
 * Add a DFS root share.
 */
/*ARGSUSED*/
static int
netdfs_s_addstdroot(void *arg, struct mlrpc_xaction *mxa)
{
	struct netdfs_addstdroot *param = arg;

	bzero(param, sizeof (struct netdfs_addstdroot));
	param->status = ERROR_INVALID_PARAMETER;
	return (MLRPC_DRC_OK);
}

/*
 * Remove a DFS root share.
 */
/*ARGSUSED*/
static int
netdfs_s_remstdroot(void *arg, struct mlrpc_xaction *mxa)
{
	struct netdfs_remstdroot *param = arg;

	bzero(param, sizeof (struct netdfs_remstdroot));
	param->status = ERROR_INVALID_PARAMETER;
	return (MLRPC_DRC_OK);
}

/*
 * Get information about all of the volumes in the DFS. dfs_path is
 * the "server" part of the UNC name used to refer to this particular
 * DFS.
 *
 * Valid levels are 1-3, 300.
 */
static int
netdfs_s_enumex(void *arg, struct mlrpc_xaction *mxa)
{
	struct netdfs_enumex *param = arg;
	netdfs_unc_t unc;
	DWORD status = ERROR_SUCCESS;

	if (param->dfs_path == NULL) {
		bzero(param, sizeof (struct netdfs_enumex));
		param->status = ERROR_INVALID_PARAMETER;
		return (MLRPC_DRC_OK);
	}

	if (param->resume_handle == NULL)
		param->resume_handle = MLRPC_HEAP_NEW(mxa, DWORD);

	if (param->resume_handle)
		*(param->resume_handle) = 0;

	if (netdfs_unc_parse(mxa, (char *)param->dfs_path, &unc) != 0) {
		status = ERROR_INVALID_PARAMETER;
	} else {
		if (unc.path == NULL)
			status = ERROR_BAD_PATHNAME;

		if (unc.share == NULL)
			status = ERROR_INVALID_SHARENAME;
	}

	if (param->status != ERROR_SUCCESS) {
		bzero(param, sizeof (struct netdfs_enumex));
		param->status = status;
		return (MLRPC_DRC_OK);
	}

	param->info = MLRPC_HEAP_NEW(mxa, struct netdfs_enum_info);
	if (param->info == NULL) {
		bzero(param, sizeof (struct netdfs_enumex));
		param->status = ERROR_NOT_ENOUGH_MEMORY;
		return (MLRPC_DRC_OK);
	}

	bzero(param->info, sizeof (struct netdfs_enumex));
	param->status = ERROR_SUCCESS;
	return (MLRPC_DRC_OK);
}

/*
 * Parse a UNC path (\\server\share\path) into components.
 * Path separators are converted to forward slashes.
 *
 * Returns 0 on success, otherwise -1 to indicate an error.
 */
static int
netdfs_unc_parse(struct mlrpc_xaction *mxa, const char *path, netdfs_unc_t *unc)
{
	char *p;

	if (path == NULL || unc == NULL)
		return (-1);

	if ((unc->buf = MLRPC_HEAP_STRSAVE(mxa, (char *)path)) == NULL)
		return (-1);

	if ((p = strchr(unc->buf, '\n')) != NULL)
		*p = '\0';

	(void) strsubst(unc->buf, '\\', '/');
	(void) strcanon(unc->buf, "/");

	unc->server = unc->buf;
	unc->server += strspn(unc->buf, "/");

	if (unc->server) {
		unc->share = strchr(unc->server, '/');
		if ((p = unc->share) != NULL) {
			unc->share += strspn(unc->share, "/");
			*p = '\0';
		}
	}

	if (unc->share) {
		unc->path = strchr(unc->share, '/');
		if ((p = unc->path) != NULL) {
			unc->path += strspn(unc->path, "/");
			*p = '\0';
		}
	}

	if (unc->path) {
		if ((p = strchr(unc->path, '\0')) != NULL) {
			if (*(--p) == '/')
				*p = '\0';
		}
	}

	return (0);
}
