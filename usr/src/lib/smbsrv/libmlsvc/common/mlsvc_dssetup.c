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
 * Active Directory Setup RPC interface used by Windows2000.
 */

#include <strings.h>
#include <stdlib.h>
#include <netdb.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/libmlrpc.h>
#include <smbsrv/libmlsvc.h>
#include <smbsrv/mlsvc_util.h>
#include <smbsrv/ndl/dssetup.ndl>
#include <smbsrv/ntstatus.h>
#include <smbsrv/smbinfo.h>
#include <smbsrv/nmpipes.h>

static int dssetup_DsRoleGetPrimaryDomainInfo(void *, struct mlrpc_xaction *);

static mlrpc_stub_table_t dssetup_stub_table[] = {
	{ dssetup_DsRoleGetPrimaryDomainInfo,
	    DSSETUP_OPNUM_DsRoleGetPrimaryDomainInfo },
	{0}
};

static mlrpc_service_t dssetup_service = {
	"DSSETUP",			/* name */
	"Active Directory Setup",	/* desc */
	"\\lsarpc",			/* endpoint */
	PIPE_LSASS,			/* sec_addr_port */
	"3919286a-b10c-11d0-9ba800c04fd92ef5", 0,	/* abstract */
	"8a885d04-1ceb-11c9-9fe808002b104860", 2,	/* transfer */
	0,				/* no bind_instance_size */
	0,				/* no bind_req() */
	0,				/* no unbind_and_close() */
	0,				/* use generic_call_stub() */
	&TYPEINFO(dssetup_interface),	/* interface ti */
	dssetup_stub_table		/* stub_table */
};

/*
 * dssetup_initialize
 *
 * This function registers the DSSETUP interface with the RPC runtime
 * library. It must be called in order to use either the client side
 * or the server side functions.
 */
void
dssetup_initialize(void)
{
	(void) mlrpc_register_service(&dssetup_service);
}

/*
 * Request for primary domain information and status.
 */
static int
dssetup_DsRoleGetPrimaryDomainInfo(void *arg, struct mlrpc_xaction *mxa)
{
	struct dssetup_DsRoleGetPrimaryDomainInfo *param = arg;
	char dns_domain[MAXHOSTNAMELEN];
	smb_ntdomain_t *di;
	DWORD status;

	switch (param->level) {
	case DS_ROLE_BASIC_INFORMATION:
		break;

	case DS_ROLE_UPGRADE_STATUS:
	case DS_ROLE_OP_STATUS:
	default:
		bzero(param,
		    sizeof (struct dssetup_DsRoleGetPrimaryDomainInfo));
		param->status = NT_SC_ERROR(NT_STATUS_INVALID_LEVEL);
		return (MLRPC_DRC_OK);
	}

	di = smb_getdomaininfo(0);
	(void) smb_getdomainname(dns_domain, MAXHOSTNAMELEN);

	if (di == NULL) {
		bzero(param,
		    sizeof (struct dssetup_DsRoleGetPrimaryDomainInfo));
		param->status = NT_SC_ERROR(NT_STATUS_CANT_ACCESS_DOMAIN_INFO);
		return (MLRPC_DRC_OK);
	}

	(void) utf8_strlwr(dns_domain);

	param->ru.info1.role = DS_ROLE_MEMBER_SERVER;
	param->ru.info1.flags = 0;
	param->ru.info1.nt_domain =
	    (uint8_t *)MLRPC_HEAP_STRSAVE(mxa, di->domain);
	param->ru.info1.dns_domain =
	    (uint8_t *)MLRPC_HEAP_STRSAVE(mxa, dns_domain);
	param->ru.info1.forest =
	    (uint8_t *)MLRPC_HEAP_STRSAVE(mxa, dns_domain);
	bzero(&param->ru.info1.domain_guid, sizeof (mlrpc_uuid_t));

	if (param->ru.info1.nt_domain == NULL ||
	    param->ru.info1.dns_domain == NULL ||
	    param->ru.info1.forest == NULL) {
		bzero(param,
		    sizeof (struct dssetup_DsRoleGetPrimaryDomainInfo));
		status = NT_SC_ERROR(NT_STATUS_NO_MEMORY);
	} else {
		status = NT_STATUS_SUCCESS;
	}

	param->status = status;
	return (MLRPC_DRC_OK);
}

DECL_FIXUP_STRUCT(dssetup_GetPrimaryDomainInfo_ru);
DECL_FIXUP_STRUCT(dssetup_GetPrimaryDomainInfoRes);
DECL_FIXUP_STRUCT(dssetup_DsRoleGetPrimaryDomainInfo);

void
fixup_dssetup_DsRoleGetPrimaryDomainInfo(
    struct dssetup_DsRoleGetPrimaryDomainInfo *val)
{
	unsigned short size1 = 0;
	unsigned short size2 = 0;
	unsigned short size3 = 0;

	switch (val->switch_value) {
	CASE_INFO_ENT(dssetup_DsRolePrimaryDomInfo, 1);
	CASE_INFO_ENT(dssetup_DsRolePrimaryDomInfo, 2);
	CASE_INFO_ENT(dssetup_DsRolePrimaryDomInfo, 3);

	default:
		return;
	};

	size2 = size1 + (2 * sizeof (DWORD));
	size3 = size2 + sizeof (mlrpcconn_request_hdr_t) + sizeof (DWORD);

	FIXUP_PDU_SIZE(dssetup_GetPrimaryDomainInfo_ru, size1);
	FIXUP_PDU_SIZE(dssetup_GetPrimaryDomainInfoRes, size2);
	FIXUP_PDU_SIZE(dssetup_DsRoleGetPrimaryDomainInfo, size3);
}
