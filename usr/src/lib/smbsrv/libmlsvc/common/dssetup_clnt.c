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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Client side for the DSSETUP RPC service.
 */

#include <string.h>
#include <strings.h>
#include <smbsrv/libsmb.h>
#include <smbsrv/libsmbrdr.h>
#include <smbsrv/ndl/rpcpdu.ndl>
#include <smbsrv/ndl/dssetup.ndl>
#include <smbsrv/mlsvc_util.h>

/*
 * Open the lsarpc pipe and bind to the dssetup service.
 */
static int
dssetup_open(mlsvc_handle_t *handle, mlrpc_heapref_t *heapref)
{
	smb_ntdomain_t *di;
	int fid;
	int rc;

	if ((di = smb_getdomaininfo(0)) == NULL)
		return (-1);

	if (mlsvc_logon(di->server, di->domain, MLSVC_ANON_USER) != 0)
		return (-1);

	fid = mlsvc_open_pipe(di->server, di->domain, MLSVC_ANON_USER,
	    "\\lsarpc");
	if (fid < 0)
		return (-1);

	if ((rc = mlsvc_rpc_bind(handle, fid, "DSSETUP")) < 0) {
		(void) mlsvc_close_pipe(fid);
		return (rc);
	}

	rc = mlsvc_rpc_init(heapref);
	return (rc);
}

/*
 * Close the dssetup pipe and free the associated context.
 * This function should only be called if the open was successful.
 */
static void
dssetup_close(mlsvc_handle_t *handle, mlrpc_heapref_t *heapref)
{
	mlsvc_rpc_free(handle->context, heapref);
	(void) mlsvc_close_pipe(handle->context->fid);
	free(handle->context);
}

int
dssetup_get_domain_info(ds_primary_domain_info_t *ds_info)
{
	dssetup_DsRoleGetPrimaryDomainInfo_t arg;
	struct dssetup_DsRolePrimaryDomInfo1 *info;
	mlsvc_handle_t handle;
	mlrpc_heapref_t heap;
	int opnum;
	int rc;

	if (dssetup_open(&handle, &heap) != 0)
		return (-1);

	opnum = DSSETUP_OPNUM_DsRoleGetPrimaryDomainInfo;
	bzero(&arg, sizeof (dssetup_DsRoleGetPrimaryDomainInfo_t));
	arg.level = DS_ROLE_BASIC_INFORMATION;

	rc = mlsvc_rpc_call(handle.context, opnum, &arg, &heap);
	if ((rc != 0) || (arg.status != 0) || arg.info == NULL) {
		dssetup_close(&handle, &heap);
		return (-1);
	}

	info = &arg.info->ru.info1;

	if (info->nt_domain == NULL ||
	    info->dns_domain == NULL ||
	    info->forest == NULL) {
		dssetup_close(&handle, &heap);
		return (-1);
	}

	bcopy(info, ds_info, sizeof (ds_primary_domain_info_t));
	ds_info->nt_domain = (uint8_t *)strdup((char *)info->nt_domain);
	ds_info->dns_domain = (uint8_t *)strdup((char *)info->dns_domain);
	ds_info->forest = (uint8_t *)strdup((char *)info->forest);

	dssetup_close(&handle, &heap);
	return (0);
}
