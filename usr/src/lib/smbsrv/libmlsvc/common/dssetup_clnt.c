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
#include <smbsrv/wintypes.h>
#include <smbsrv/libsmb.h>
#include <smbsrv/libsmbrdr.h>
#include <smbsrv/ndl/dssetup.ndl>
#include <smbsrv/libmlsvc.h>

int
dssetup_get_domain_info(ds_primary_domain_info_t *ds_info)
{
	dssetup_DsRoleGetPrimaryDomainInfo_t arg;
	struct dssetup_DsRolePrimaryDomInfo1 *info;
	smb_domain_t di;
	mlsvc_handle_t handle;
	int opnum;
	int rc;

	if (!smb_domain_getinfo(&di))
		return (-1);

	if (ndr_rpc_bind(&handle, di.d_dc, di.d_nbdomain,
	    MLSVC_ANON_USER, "DSSETUP") != 0)
		return (-1);

	opnum = DSSETUP_OPNUM_DsRoleGetPrimaryDomainInfo;
	bzero(&arg, sizeof (dssetup_DsRoleGetPrimaryDomainInfo_t));
	arg.level = DS_ROLE_BASIC_INFORMATION;

	rc = ndr_rpc_call(&handle, opnum, &arg);
	if ((rc != 0) || (arg.status != 0) || arg.info == NULL) {
		ndr_rpc_unbind(&handle);
		return (-1);
	}

	info = &arg.info->ru.info1;

	if (info->nt_domain == NULL ||
	    info->dns_domain == NULL ||
	    info->forest == NULL) {
		ndr_rpc_unbind(&handle);
		return (-1);
	}

	bcopy(info, ds_info, sizeof (ds_primary_domain_info_t));
	ds_info->nt_domain = (uint8_t *)strdup((char *)info->nt_domain);
	ds_info->dns_domain = (uint8_t *)strdup((char *)info->dns_domain);
	ds_info->forest = (uint8_t *)strdup((char *)info->forest);

	ndr_rpc_unbind(&handle);
	return (0);
}
