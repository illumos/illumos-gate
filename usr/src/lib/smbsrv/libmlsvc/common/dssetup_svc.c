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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Active Directory Setup RPC interface used by Windows 2000.
 */

#include <synch.h>
#include <strings.h>
#include <stdlib.h>
#include <netdb.h>

#include <libmlrpc/libmlrpc.h>
#include <smbsrv/libsmb.h>
#include <smbsrv/libmlsvc.h>
#include <smbsrv/ndl/dssetup.ndl>
#include <smbsrv/smbinfo.h>
#include <smbsrv/nmpipes.h>

int dssetup_get_domain_info(ds_primary_domain_info_t *);

static int dssetup_DsRoleGetPrimaryDomainInfo(void *, ndr_xa_t *);
static uint32_t dssetup_member_server(ds_primary_domain_info_t *, ndr_xa_t *);
static uint32_t dssetup_standalone_server(ds_primary_domain_info_t *,
    ndr_xa_t *);

static ndr_stub_table_t dssetup_stub_table[] = {
	{ dssetup_DsRoleGetPrimaryDomainInfo,
	    DSSETUP_OPNUM_DsRoleGetPrimaryDomainInfo },
	{0}
};

static ndr_service_t dssetup_service = {
	"DSSETUP",			/* name */
	"Active Directory Setup",	/* desc */
	"\\lsarpc",			/* endpoint */
	PIPE_LSASS,			/* sec_addr_port */
	"3919286a-b10c-11d0-9ba8-00c04fd92ef5",	0,	/* abstract */
	NDR_TRANSFER_SYNTAX_UUID,		2,	/* transfer */
	0,				/* no bind_instance_size */
	0,				/* no bind_req() */
	0,				/* no unbind_and_close() */
	0,				/* use generic_call_stub() */
	&TYPEINFO(dssetup_interface),	/* interface ti */
	dssetup_stub_table		/* stub_table */
};

static ds_primary_domain_info_t ds_info;
static mutex_t ds_info_mtx;

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
	dssetup_clear_domain_info();
	(void) ndr_svc_register(&dssetup_service);
}

void
dssetup_clear_domain_info(void)
{
	(void) mutex_lock(&ds_info_mtx);

	free(ds_info.nt_domain);
	free(ds_info.dns_domain);
	free(ds_info.forest);
	bzero(&ds_info, sizeof (ds_primary_domain_info_t));

	(void) mutex_unlock(&ds_info_mtx);
}

/*
 * Request for machine role and primary domain information.
 */
static int
dssetup_DsRoleGetPrimaryDomainInfo(void *arg, ndr_xa_t *mxa)
{
	dssetup_DsRoleGetPrimaryDomainInfo_t *param = arg;
	dssetup_GetPrimaryDomainInfo_t *info;
	ds_primary_domain_info_t *info1;
	uint32_t status;
	int security_mode;

	info = NDR_MALLOC(mxa, sizeof (dssetup_GetPrimaryDomainInfo_t));
	if (info == NULL) {
		status = NT_STATUS_NO_MEMORY;
	} else if (param->level != DS_ROLE_BASIC_INFORMATION) {
		status = NT_STATUS_INVALID_LEVEL;
	} else {
		info->switch_value = param->level;
		info1 = &info->ru.info1;

		security_mode = smb_config_get_secmode();

		if (security_mode == SMB_SECMODE_DOMAIN)
			status = dssetup_member_server(info1, mxa);
		else
			status = dssetup_standalone_server(info1, mxa);
	}

	if (status != NT_STATUS_SUCCESS) {
		bzero(param, sizeof (dssetup_DsRoleGetPrimaryDomainInfo_t));
		param->status = NT_SC_ERROR(status);
	} else {
		param->info = info;
		param->status = NT_STATUS_SUCCESS;
	}

	return (NDR_DRC_OK);
}

/*
 * When the machine role is domain member:
 * 	nt_domain must contain the NetBIOS domain name
 * 	dns_domain must contain the DNS domain name (cannot be NULL)
 * 	forest must contain the forest name (cannot be NULL)
 *
 * If DS_ROLE_PRIMARY_DOMAIN_GUID_PRESENT is set in flags, the domain_guid
 * must contain the domain UUID.  Otherwise domain_guid is ignored.
 */
static uint32_t
dssetup_member_server(ds_primary_domain_info_t *info, ndr_xa_t *mxa)
{
	char dns_domain[MAXHOSTNAMELEN];
	char nt_domain[MAXHOSTNAMELEN];

	(void) mutex_lock(&ds_info_mtx);

	if ((ds_info.flags & DS_ROLE_PRIMARY_DOMAIN_GUID_PRESENT) == 0) {
		/*
		 * If we don't have the domain GUID, try to get it from a
		 * domain controller. Otherwise, use local configuration.
		 */
		free(ds_info.nt_domain);
		free(ds_info.dns_domain);
		free(ds_info.forest);
		(void) dssetup_get_domain_info(&ds_info);
	}

	if (ds_info.flags & DS_ROLE_PRIMARY_DOMAIN_GUID_PRESENT) {
		info->flags = DS_ROLE_PRIMARY_DOMAIN_GUID_PRESENT;
		info->nt_domain = NDR_STRDUP(mxa, (char *)ds_info.nt_domain);
		info->dns_domain = NDR_STRDUP(mxa, (char *)ds_info.dns_domain);
		info->forest = NDR_STRDUP(mxa, (char *)ds_info.forest);
		bcopy(&ds_info.domain_guid, &info->domain_guid,
		    sizeof (ndr_uuid_t));
	} else {
		if (smb_getdomainname(nt_domain, MAXHOSTNAMELEN) != 0) {
			(void) mutex_unlock(&ds_info_mtx);
			return (NT_STATUS_CANT_ACCESS_DOMAIN_INFO);
		}

		if (smb_getfqdomainname(dns_domain, MAXHOSTNAMELEN) != 0) {
			(void) mutex_unlock(&ds_info_mtx);
			return (NT_STATUS_CANT_ACCESS_DOMAIN_INFO);
		}

		(void) smb_strlwr(dns_domain);

		info->flags = 0;
		info->nt_domain = NDR_STRDUP(mxa, nt_domain);
		info->dns_domain = NDR_STRDUP(mxa, dns_domain);
		info->forest = NDR_STRDUP(mxa, dns_domain);
		bzero(&info->domain_guid, sizeof (ndr_uuid_t));
	}

	(void) mutex_unlock(&ds_info_mtx);

	if (info->nt_domain == NULL ||
	    info->dns_domain == NULL ||
	    info->forest == NULL)
		return (NT_STATUS_NO_MEMORY);

	info->role = DS_ROLE_MEMBER_SERVER;
	return (NT_STATUS_SUCCESS);
}

/*
 * When the machine role is standalone:
 * 	nt_domain must contain the NetBIOS workgroup name
 * 	dns_domain must be NULL
 * 	forest must be NULL
 *
 * We don't maintain a domain GUID.  When DS_ROLE_PRIMARY_DOMAIN_GUID_PRESENT
 * is not set in flags, domain_guid is ignored.
 */
static uint32_t
dssetup_standalone_server(ds_primary_domain_info_t *info, ndr_xa_t *mxa)
{
	char nt_domain[MAXHOSTNAMELEN];

	if (smb_getdomainname(nt_domain, MAXHOSTNAMELEN) != 0)
		return (NT_STATUS_CANT_ACCESS_DOMAIN_INFO);

	info->nt_domain = NDR_STRDUP(mxa, nt_domain);
	if (info->nt_domain == NULL)
		return (NT_STATUS_NO_MEMORY);

	info->role = DS_ROLE_STANDALONE_SERVER;
	info->flags = 0;
	info->dns_domain = NULL;
	info->forest = NULL;
	bzero(&info->domain_guid, sizeof (ndr_uuid_t));
	return (NT_STATUS_SUCCESS);
}
