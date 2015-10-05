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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Local Security Authority RPC (LSAR) server-side interface.
 */

#include <unistd.h>
#include <strings.h>
#include <pwd.h>
#include <grp.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/libmlrpc.h>
#include <smbsrv/libmlsvc.h>
#include <smbsrv/ndl/lsarpc.ndl>
#include <lsalib.h>
#include <smbsrv/smbinfo.h>
#include <smbsrv/nmpipes.h>
#include <smbsrv/ntlocale.h>

struct local_group_table {
	WORD sid_name_use;
	WORD domain_ix;
	char *sid;
	char *name;
};

static int lsarpc_key_domain;
static int lsarpc_key_account;

static int lsarpc_call_stub(ndr_xa_t *mxa);

static int lsarpc_s_CloseHandle(void *, ndr_xa_t *);
static int lsarpc_s_QuerySecurityObject(void *, ndr_xa_t *);
static int lsarpc_s_EnumAccounts(void *, ndr_xa_t *);
static int lsarpc_s_EnumTrustedDomain(void *, ndr_xa_t *);
static int lsarpc_s_EnumTrustedDomainsEx(void *, ndr_xa_t *);
static int lsarpc_s_OpenAccount(void *, ndr_xa_t *);
static int lsarpc_s_EnumPrivsAccount(void *, ndr_xa_t *);
static int lsarpc_s_LookupPrivValue(void *, ndr_xa_t *);
static int lsarpc_s_LookupPrivName(void *, ndr_xa_t *);
static int lsarpc_s_LookupPrivDisplayName(void *, ndr_xa_t *);
static int lsarpc_s_CreateSecret(void *, ndr_xa_t *);
static int lsarpc_s_OpenSecret(void *, ndr_xa_t *);
static int lsarpc_s_QueryInfoPolicy(void *, ndr_xa_t *);
static int lsarpc_s_OpenDomainHandle(void *, ndr_xa_t *);
static int lsarpc_s_OpenDomainHandle(void *, ndr_xa_t *);
static int lsarpc_s_LookupSids(void *, ndr_xa_t *);
static int lsarpc_s_LookupNames(void *, ndr_xa_t *);
static int lsarpc_s_GetConnectedUser(void *, ndr_xa_t *);
static int lsarpc_s_LookupSids2(void *, ndr_xa_t *);
static int lsarpc_s_LookupSids3(void *, ndr_xa_t *);
static int lsarpc_s_LookupNames2(void *, ndr_xa_t *);
static int lsarpc_s_LookupNames3(void *, ndr_xa_t *);
static int lsarpc_s_LookupNames4(void *, ndr_xa_t *);

static DWORD lsarpc_s_PrimaryDomainInfo(struct mslsa_PrimaryDomainInfo *,
    ndr_xa_t *);
static DWORD lsarpc_s_AccountDomainInfo(struct mslsa_AccountDomainInfo *,
    ndr_xa_t *);
static int lsarpc_s_UpdateDomainTable(ndr_xa_t *,
    smb_account_t *, struct mslsa_domain_table *, DWORD *);

static ndr_stub_table_t lsarpc_stub_table[] = {
	{ lsarpc_s_CloseHandle,		  LSARPC_OPNUM_CloseHandle },
	{ lsarpc_s_QuerySecurityObject,	  LSARPC_OPNUM_QuerySecurityObject },
	{ lsarpc_s_EnumAccounts,	  LSARPC_OPNUM_EnumerateAccounts },
	{ lsarpc_s_EnumTrustedDomain,	  LSARPC_OPNUM_EnumTrustedDomain },
	{ lsarpc_s_EnumTrustedDomainsEx,  LSARPC_OPNUM_EnumTrustedDomainsEx },
	{ lsarpc_s_OpenAccount,		  LSARPC_OPNUM_OpenAccount },
	{ lsarpc_s_EnumPrivsAccount,	  LSARPC_OPNUM_EnumPrivsAccount },
	{ lsarpc_s_LookupPrivValue,	  LSARPC_OPNUM_LookupPrivValue },
	{ lsarpc_s_LookupPrivName,	  LSARPC_OPNUM_LookupPrivName },
	{ lsarpc_s_LookupPrivDisplayName, LSARPC_OPNUM_LookupPrivDisplayName },
	{ lsarpc_s_CreateSecret,	  LSARPC_OPNUM_CreateSecret },
	{ lsarpc_s_OpenSecret,		  LSARPC_OPNUM_OpenSecret },
	{ lsarpc_s_QueryInfoPolicy,	  LSARPC_OPNUM_QueryInfoPolicy },
	{ lsarpc_s_OpenDomainHandle,	  LSARPC_OPNUM_OpenPolicy },
	{ lsarpc_s_OpenDomainHandle,	  LSARPC_OPNUM_OpenPolicy2 },
	{ lsarpc_s_LookupSids,		  LSARPC_OPNUM_LookupSids },
	{ lsarpc_s_LookupNames,		  LSARPC_OPNUM_LookupNames },
	{ lsarpc_s_GetConnectedUser,	  LSARPC_OPNUM_GetConnectedUser },
	{ lsarpc_s_LookupSids2,		  LSARPC_OPNUM_LookupSids2 },
	{ lsarpc_s_LookupSids3,		  LSARPC_OPNUM_LookupSids3 },
	{ lsarpc_s_LookupNames2,	  LSARPC_OPNUM_LookupNames2 },
	{ lsarpc_s_LookupNames3,	  LSARPC_OPNUM_LookupNames3 },
	{ lsarpc_s_LookupNames4,	  LSARPC_OPNUM_LookupNames4 },
	{0}
};

static ndr_service_t lsarpc_service = {
	"LSARPC",			/* name */
	"Local Security Authority",	/* desc */
	"\\lsarpc",			/* endpoint */
	PIPE_LSASS,			/* sec_addr_port */
	"12345778-1234-abcd-ef00-0123456789ab", 0,	/* abstract */
	NDR_TRANSFER_SYNTAX_UUID,		2,	/* transfer */
	0,				/* no bind_instance_size */
	NULL,				/* no bind_req() */
	NULL,				/* no unbind_and_close() */
	lsarpc_call_stub,		/* call_stub() */
	&TYPEINFO(lsarpc_interface),	/* interface ti */
	lsarpc_stub_table		/* stub_table */
};

/*
 * lsarpc_initialize
 *
 * This function registers the LSA RPC interface with the RPC runtime
 * library. It must be called in order to use either the client side
 * or the server side functions.
 */
void
lsarpc_initialize(void)
{
	(void) ndr_svc_register(&lsarpc_service);
}

/*
 * Custom call_stub to set the stream string policy.
 */
static int
lsarpc_call_stub(ndr_xa_t *mxa)
{
	NDS_SETF(&mxa->send_nds, NDS_F_NOTERM);
	NDS_SETF(&mxa->recv_nds, NDS_F_NOTERM);

	return (ndr_generic_call_stub(mxa));
}

/*
 * lsarpc_s_OpenDomainHandle opnum=0x06
 *
 * This is a request to open the LSA (OpenPolicy and OpenPolicy2).
 * The client is looking for an LSA domain handle.
 */
static int
lsarpc_s_OpenDomainHandle(void *arg, ndr_xa_t *mxa)
{
	struct mslsa_OpenPolicy2 *param = arg;
	ndr_hdid_t *id;

	if ((id = ndr_hdalloc(mxa, &lsarpc_key_domain)) != NULL) {
		bcopy(id, &param->domain_handle, sizeof (mslsa_handle_t));
		param->status = NT_STATUS_SUCCESS;
	} else {
		bzero(&param->domain_handle, sizeof (mslsa_handle_t));
		param->status = NT_SC_ERROR(NT_STATUS_NO_MEMORY);
	}

	return (NDR_DRC_OK);
}

/*
 * lsarpc_s_CloseHandle opnum=0x00
 *
 * This is a request to close the LSA interface specified by the handle.
 * We don't track handles (yet), so just zero out the handle and return
 * NDR_DRC_OK. Setting the handle to zero appears to be standard
 * behaviour and someone may rely on it, i.e. we do on the client side.
 */
static int
lsarpc_s_CloseHandle(void *arg, ndr_xa_t *mxa)
{
	struct mslsa_CloseHandle *param = arg;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->handle;

	ndr_hdfree(mxa, id);

	bzero(&param->result_handle, sizeof (param->result_handle));
	param->status = NT_STATUS_SUCCESS;
	return (NDR_DRC_OK);
}

/*
 * lsarpc_s_QuerySecurityObject
 */
/*ARGSUSED*/
static int
lsarpc_s_QuerySecurityObject(void *arg, ndr_xa_t *mxa)
{
	struct mslsa_QuerySecurityObject *param = arg;

	bzero(param, sizeof (struct mslsa_QuerySecurityObject));
	param->status = NT_SC_ERROR(NT_STATUS_ACCESS_DENIED);

	return (NDR_DRC_OK);
}

/*
 * lsarpc_s_EnumAccounts
 *
 * Enumerate the list of local accounts SIDs. The client should supply
 * a valid OpenPolicy2 handle. The enum_context is used to support
 * multiple enumeration calls to obtain the complete list of SIDs.
 * It should be set to 0 on the first call and passed unchanged on
 * subsequent calls until there are no more accounts - the server will
 * return STATUS_NO_MORE_ENTRIES.
 *
 * For now just set the status to access-denied. Note that we still have
 * to provide a valid address for enum_buf because it's a reference and
 * the marshalling rules require that references must not be null.
 * The enum_context is used to support multiple
 */
static int
lsarpc_s_EnumAccounts(void *arg, ndr_xa_t *mxa)
{
	struct mslsa_EnumerateAccounts *param = arg;
	struct mslsa_EnumAccountBuf *enum_buf;

	bzero(param, sizeof (struct mslsa_EnumerateAccounts));

	enum_buf = NDR_NEW(mxa, struct mslsa_EnumAccountBuf);
	if (enum_buf == NULL) {
		param->status = NT_SC_ERROR(NT_STATUS_NO_MEMORY);
		return (NDR_DRC_OK);
	}

	bzero(enum_buf, sizeof (struct mslsa_EnumAccountBuf));
	param->enum_buf = enum_buf;
	param->status = NT_SC_ERROR(NT_STATUS_ACCESS_DENIED);
	return (NDR_DRC_OK);
}


/*
 * lsarpc_s_EnumTrustedDomain
 *
 * This is the server side function for handling requests to enumerate
 * the list of trusted domains: currently held in the NT domain database.
 * This call requires an OpenPolicy2 handle. The enum_context is used to
 * support multiple enumeration calls to obtain the complete list.
 * It should be set to 0 on the first call and passed unchanged on
 * subsequent calls until there are no more accounts - the server will
 * return STATUS_NO_MORE_ENTRIES.
 *
 * For now just set the status to access-denied. Note that we still have
 * to provide a valid address for enum_buf because it's a reference and
 * the marshalling rules require that references must not be null.
 */
static int
lsarpc_s_EnumTrustedDomain(void *arg, ndr_xa_t *mxa)
{
	struct mslsa_EnumTrustedDomain *param = arg;
	struct mslsa_EnumTrustedDomainBuf *enum_buf;

	bzero(param, sizeof (struct mslsa_EnumTrustedDomain));

	enum_buf = NDR_NEW(mxa, struct mslsa_EnumTrustedDomainBuf);
	if (enum_buf == NULL) {
		param->status = NT_SC_ERROR(NT_STATUS_NO_MEMORY);
		return (NDR_DRC_OK);
	}

	bzero(enum_buf, sizeof (struct mslsa_EnumTrustedDomainBuf));
	param->enum_buf = enum_buf;
	param->status = NT_SC_ERROR(NT_STATUS_ACCESS_DENIED);
	return (NDR_DRC_OK);
}

/*
 * lsarpc_s_EnumTrustedDomainsEx
 *
 * This is the server side function for handling requests to enumerate
 * the list of trusted domains: currently held in the NT domain database.
 * This call requires an OpenPolicy2 handle. The enum_context is used to
 * support multiple enumeration calls to obtain the complete list.
 * It should be set to 0 on the first call and passed unchanged on
 * subsequent calls until there are no more accounts - the server will
 * return STATUS_NO_MORE_ENTRIES.
 *
 * For now just set the status to access-denied. Note that we still have
 * to provide a valid address for enum_buf because it's a reference and
 * the marshalling rules require that references must not be null.
 */
static int
lsarpc_s_EnumTrustedDomainsEx(void *arg, ndr_xa_t *mxa)
{
	struct mslsa_EnumTrustedDomainEx *param = arg;
	struct mslsa_EnumTrustedDomainBufEx *enum_buf;

	bzero(param, sizeof (struct mslsa_EnumTrustedDomainEx));

	enum_buf = NDR_NEW(mxa, struct mslsa_EnumTrustedDomainBufEx);
	if (enum_buf == NULL) {
		param->status = NT_SC_ERROR(NT_STATUS_NO_MEMORY);
		return (NDR_DRC_OK);
	}

	bzero(enum_buf, sizeof (struct mslsa_EnumTrustedDomainBufEx));
	param->enum_buf = enum_buf;
	param->status = NT_SC_ERROR(NT_STATUS_ACCESS_DENIED);
	return (NDR_DRC_OK);
}

/*
 * lsarpc_s_OpenAccount
 *
 * This is a request to open an account handle.
 */
static int
lsarpc_s_OpenAccount(void *arg, ndr_xa_t *mxa)
{
	struct mslsa_OpenAccount *param = arg;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->handle;
	ndr_handle_t *hd;

	hd = ndr_hdlookup(mxa, id);
	if ((hd == NULL) || (hd->nh_data != &lsarpc_key_domain)) {
		bzero(param, sizeof (struct mslsa_OpenAccount));
		param->status = NT_SC_ERROR(NT_STATUS_INVALID_HANDLE);
		return (NDR_DRC_OK);
	}

	if ((id = ndr_hdalloc(mxa, &lsarpc_key_account)) != NULL) {
		bcopy(id, &param->account_handle, sizeof (mslsa_handle_t));
		param->status = NT_STATUS_SUCCESS;
	} else {
		bzero(&param->account_handle, sizeof (mslsa_handle_t));
		param->status = NT_SC_ERROR(NT_STATUS_NO_MEMORY);
	}

	return (NDR_DRC_OK);
}


/*
 * lsarpc_s_EnumPrivsAccount
 *
 * This is the server side function for handling requests for account
 * privileges. For now just set the status to not-supported status and
 * return NDR_DRC_OK. Note that we still have to provide a valid
 * address for enum_buf because it's a reference and the marshalling
 * rules require that references must not be null.
 */
/*ARGSUSED*/
static int
lsarpc_s_EnumPrivsAccount(void *arg, ndr_xa_t *mxa)
{
	struct mslsa_EnumPrivsAccount *param = arg;

	bzero(param, sizeof (struct mslsa_EnumPrivsAccount));
	param->status = NT_SC_ERROR(NT_STATUS_NOT_SUPPORTED);
	return (NDR_DRC_OK);
}

/*
 * lsarpc_s_LookupPrivValue
 *
 * Server side function used to map a privilege name to a locally unique
 * identifier (LUID).
 */
/*ARGSUSED*/
static int
lsarpc_s_LookupPrivValue(void *arg, ndr_xa_t *mxa)
{
	struct mslsa_LookupPrivValue *param = arg;
	smb_privinfo_t *pi;

	if ((pi = smb_priv_getbyname((char *)param->name.str)) == NULL) {
		bzero(param, sizeof (struct mslsa_LookupPrivValue));
		param->status = NT_SC_ERROR(NT_STATUS_NO_SUCH_PRIVILEGE);
		return (NDR_DRC_OK);
	}

	param->luid.low_part = pi->id;
	param->luid.high_part = 0;
	param->status = NT_STATUS_SUCCESS;
	return (NDR_DRC_OK);
}

/*
 * lsarpc_s_LookupPrivName
 *
 * Server side function used to map a locally unique identifier (LUID)
 * to the appropriate privilege name string.
 */
static int
lsarpc_s_LookupPrivName(void *arg, ndr_xa_t *mxa)
{
	struct mslsa_LookupPrivName *param = arg;
	smb_privinfo_t *pi;
	int rc;

	if ((pi = smb_priv_getbyvalue(param->luid.low_part)) == NULL) {
		bzero(param, sizeof (struct mslsa_LookupPrivName));
		param->status = NT_SC_ERROR(NT_STATUS_NO_SUCH_PRIVILEGE);
		return (NDR_DRC_OK);
	}

	param->name = NDR_NEW(mxa, mslsa_string_t);
	if (param->name == NULL) {
		bzero(param, sizeof (struct mslsa_LookupPrivName));
		param->status = NT_SC_ERROR(NT_STATUS_NO_MEMORY);
		return (NDR_DRC_OK);
	}

	rc = NDR_MSTRING(mxa, pi->name, (ndr_mstring_t *)param->name);
	if (rc == -1) {
		bzero(param, sizeof (struct mslsa_LookupPrivName));
		param->status = NT_SC_ERROR(NT_STATUS_NO_MEMORY);
		return (NDR_DRC_OK);
	}

	param->status = NT_STATUS_SUCCESS;
	return (NDR_DRC_OK);
}

/*
 * lsarpc_s_LookupPrivDisplayName
 *
 * This is the server side function for handling requests for account
 * privileges. For now just set the status to not-supported status and
 * return NDR_DRC_OK.
 */
static int
lsarpc_s_LookupPrivDisplayName(void *arg, ndr_xa_t *mxa)
{
	struct mslsa_LookupPrivDisplayName *param = arg;
	smb_privinfo_t *pi;
	int rc;

	if ((pi = smb_priv_getbyname((char *)param->name.str)) == NULL) {
		bzero(param, sizeof (struct mslsa_LookupPrivDisplayName));
		param->status = NT_SC_ERROR(NT_STATUS_NO_SUCH_PRIVILEGE);
		return (NDR_DRC_OK);
	}

	param->display_name = NDR_NEW(mxa, mslsa_string_t);
	if (param->display_name == NULL) {
		bzero(param, sizeof (struct mslsa_LookupPrivDisplayName));
		param->status = NT_SC_ERROR(NT_STATUS_NO_MEMORY);
		return (NDR_DRC_OK);
	}

	rc = NDR_MSTRING(mxa, pi->display_name,
	    (ndr_mstring_t *)param->display_name);
	if (rc == -1) {
		bzero(param, sizeof (struct mslsa_LookupPrivDisplayName));
		param->status = NT_SC_ERROR(NT_STATUS_NO_MEMORY);
		return (NDR_DRC_OK);
	}

	param->language_ret = MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL);
	param->status = NT_STATUS_SUCCESS;
	return (NDR_DRC_OK);
}

static int
lsarpc_s_CreateSecret(void *arg, ndr_xa_t *mxa)
{
	struct mslsa_CreateSecret *param = arg;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->handle;
	ndr_handle_t *hd;

	hd = ndr_hdlookup(mxa, id);
	if ((hd == NULL) || (hd->nh_data != &lsarpc_key_domain)) {
		bzero(param, sizeof (struct mslsa_OpenAccount));
		param->status = NT_SC_ERROR(NT_STATUS_INVALID_HANDLE);
		return (NDR_DRC_OK);
	}

	bzero(&param->secret_handle, sizeof (mslsa_handle_t));
	param->status = NT_SC_ERROR(NT_STATUS_ACCESS_DENIED);
	return (NDR_DRC_OK);
}

static int
lsarpc_s_OpenSecret(void *arg, ndr_xa_t *mxa)
{
	struct mslsa_OpenSecret *param = arg;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->handle;
	ndr_handle_t *hd;

	hd = ndr_hdlookup(mxa, id);
	if ((hd == NULL) || (hd->nh_data != &lsarpc_key_domain)) {
		bzero(param, sizeof (struct mslsa_OpenAccount));
		param->status = NT_SC_ERROR(NT_STATUS_INVALID_HANDLE);
		return (NDR_DRC_OK);
	}

	bzero(&param->secret_handle, sizeof (mslsa_handle_t));
	param->status = NT_SC_ERROR(NT_STATUS_ACCESS_DENIED);
	return (NDR_DRC_OK);
}

/*
 * lsarpc_s_GetConnectedUser
 *
 * Return the account name and NetBIOS domain name for the user making
 * the request.  The hostname field should be ignored by the server.
 *
 * Note: MacOS uses this, whether we're a domain member or not.
 */
static int
lsarpc_s_GetConnectedUser(void *arg, ndr_xa_t *mxa)
{
	struct mslsa_GetConnectedUser *param = arg;
	smb_netuserinfo_t *user = mxa->pipe->np_user;
	DWORD status = NT_STATUS_SUCCESS;
	int rc1;
	int rc2;

	param->owner = NDR_NEW(mxa, struct mslsa_string_desc);
	param->domain = NDR_NEW(mxa, struct mslsa_DomainName);
	if (param->owner == NULL || param->domain == NULL) {
		status = NT_SC_ERROR(NT_STATUS_NO_MEMORY);
		param->status = status;
		return (NDR_DRC_OK);
	}

	param->domain->name = NDR_NEW(mxa, struct mslsa_string_desc);
	if (param->domain->name == NULL) {
		status = NT_SC_ERROR(NT_STATUS_NO_MEMORY);
		param->status = status;
		return (NDR_DRC_OK);
	}

	rc1 = NDR_MSTRING(mxa, user->ui_account,
	    (ndr_mstring_t *)param->owner);
	rc2 = NDR_MSTRING(mxa, user->ui_domain,
	    (ndr_mstring_t *)param->domain->name);

	if (rc1 == -1 || rc2 == -1)
		status = NT_SC_ERROR(NT_STATUS_NO_MEMORY);

	param->status = status;
	return (NDR_DRC_OK);
}


/*
 * lsarpc_s_QueryInfoPolicy
 *
 * This is the server side function for handling LSA information policy
 * queries. Currently, we only support primary domain and account
 * domain queries. This is just a front end to switch on the request
 * and hand it off to the appropriate function to actually deal with
 * obtaining and building the response.
 */
static int
lsarpc_s_QueryInfoPolicy(void *arg, ndr_xa_t *mxa)
{
	struct mslsa_QueryInfoPolicy *param = arg;
	union mslsa_PolicyInfoResUnion *ru = &param->ru;
	int security_mode;
	DWORD status;

	param->switch_value = param->info_class;

	switch (param->info_class) {
	case MSLSA_POLICY_AUDIT_EVENTS_INFO:
		ru->audit_events.enabled = 0;
		ru->audit_events.count = 1;
		ru->audit_events.settings
		    = NDR_MALLOC(mxa, sizeof (DWORD));
		bzero(ru->audit_events.settings, sizeof (DWORD));
		status = NT_STATUS_SUCCESS;
		break;

	case MSLSA_POLICY_PRIMARY_DOMAIN_INFO:
		status = lsarpc_s_PrimaryDomainInfo(&ru->pd_info, mxa);
		break;

	case MSLSA_POLICY_ACCOUNT_DOMAIN_INFO:
		status = lsarpc_s_AccountDomainInfo(&ru->ad_info, mxa);
		break;

	case MSLSA_POLICY_SERVER_ROLE_INFO:
		security_mode = smb_config_get_secmode();

		if (security_mode == SMB_SECMODE_DOMAIN)
			ru->server_role.role = LSA_ROLE_MEMBER_SERVER;
		else
			ru->server_role.role = LSA_ROLE_STANDALONE_SERVER;

		ru->server_role.pad = 0;
		status = NT_STATUS_SUCCESS;
		break;

	default:
		bzero(param, sizeof (struct mslsa_QueryInfoPolicy));
		param->status = NT_SC_ERROR(NT_STATUS_INVALID_INFO_CLASS);
		return (NDR_DRC_OK);
	}

	if (status != NT_STATUS_SUCCESS)
		param->status = NT_SC_ERROR(status);
	else
		param->status = NT_STATUS_SUCCESS;
	param->address = (DWORD)(uintptr_t)ru;

	return (NDR_DRC_OK);
}


/*
 * lsarpc_s_PrimaryDomainInfo
 *
 * Service primary domain policy queries.  In domain mode, return the
 * primary domain name and SID.   In workgroup mode, return the local
 * hostname and local domain SID.
 *
 * Note: info is zeroed on entry to ensure the SID and name do not
 * contain spurious values if an error is returned.
 */
static DWORD
lsarpc_s_PrimaryDomainInfo(struct mslsa_PrimaryDomainInfo *info,
    ndr_xa_t *mxa)
{
	smb_domain_t di;
	boolean_t found;
	int rc;

	bzero(info, sizeof (struct mslsa_PrimaryDomainInfo));

	if (smb_config_get_secmode() != SMB_SECMODE_DOMAIN)
		found = smb_domain_lookup_type(SMB_DOMAIN_LOCAL, &di);
	else
		found = smb_domain_lookup_type(SMB_DOMAIN_PRIMARY, &di);

	if (!found)
		return (NT_STATUS_CANT_ACCESS_DOMAIN_INFO);

	rc = NDR_MSTRING(mxa, di.di_nbname, (ndr_mstring_t *)&info->name);
	info->sid = (struct mslsa_sid *)NDR_SIDDUP(mxa, di.di_binsid);

	if ((rc == -1) || (info->sid == NULL))
		return (NT_STATUS_NO_MEMORY);

	return (NT_STATUS_SUCCESS);
}


/*
 * lsarpc_s_AccountDomainInfo
 *
 * Service account domain policy queries.  We return our local domain
 * information so that the client knows who to query for information
 * on local names and SIDs.  The domain name is the local hostname.
 *
 * Note: info is zeroed on entry to ensure the SID and name do not
 * contain spurious values if an error is returned.
 */
static DWORD
lsarpc_s_AccountDomainInfo(struct mslsa_AccountDomainInfo *info,
    ndr_xa_t *mxa)
{
	smb_domain_t di;
	int rc;

	bzero(info, sizeof (struct mslsa_AccountDomainInfo));

	if (!smb_domain_lookup_type(SMB_DOMAIN_LOCAL, &di))
		return (NT_STATUS_CANT_ACCESS_DOMAIN_INFO);

	rc = NDR_MSTRING(mxa, di.di_nbname, (ndr_mstring_t *)&info->name);
	info->sid = (struct mslsa_sid *)NDR_SIDDUP(mxa, di.di_binsid);

	if ((rc == -1) || (info->sid == NULL))
		return (NT_STATUS_NO_MEMORY);

	return (NT_STATUS_SUCCESS);
}

/*
 * lsarpc_s_LookupNames
 *
 * This is the service side function for handling name lookup requests.
 * Currently, we only support lookups of a single name. This is also a
 * pass through interface so all we do is act as a proxy between the
 * client and the DC.
 */
static int
lsarpc_s_LookupNames(void *arg, ndr_xa_t *mxa)
{
	struct mslsa_LookupNames *param = arg;
	struct mslsa_rid_entry *rids;
	struct mslsa_domain_table *domain_table;
	struct mslsa_domain_entry *domain_entry;
	smb_account_t account;
	uint32_t status;
	char *accname;
	int rc = 0;

	if (param->name_table->n_entry != 1)
		return (NDR_DRC_FAULT_PARAM_0_UNIMPLEMENTED);

	rids = NDR_NEW(mxa, struct mslsa_rid_entry);
	domain_table = NDR_NEW(mxa, struct mslsa_domain_table);
	domain_entry = NDR_NEW(mxa, struct mslsa_domain_entry);

	if (rids == NULL || domain_table == NULL || domain_entry == NULL) {
		bzero(param, sizeof (struct mslsa_LookupNames));
		param->status = NT_SC_ERROR(NT_STATUS_NO_MEMORY);
		return (NDR_DRC_OK);
	}

	accname = (char *)param->name_table->names->str;
	status = lsa_lookup_name(accname, SidTypeUnknown, &account);
	if (status != NT_STATUS_SUCCESS) {
		bzero(param, sizeof (struct mslsa_LookupNames));
		param->status = NT_SC_ERROR(status);
		return (NDR_DRC_OK);
	}

	/*
	 * Set up the rid table.
	 */
	rids[0].sid_name_use = account.a_type;
	rids[0].rid = account.a_rid;
	rids[0].domain_index = 0;
	param->translated_sids.n_entry = 1;
	param->translated_sids.rids = rids;

	/*
	 * Set up the domain table.
	 */
	domain_table->entries = domain_entry;
	domain_table->n_entry = 1;
	domain_table->max_n_entry = MLSVC_DOMAIN_MAX;

	rc = NDR_MSTRING(mxa, account.a_domain,
	    (ndr_mstring_t *)&domain_entry->domain_name);
	domain_entry->domain_sid =
	    (struct mslsa_sid *)NDR_SIDDUP(mxa, account.a_domsid);

	if (rc == -1 || domain_entry->domain_sid == NULL) {
		smb_account_free(&account);
		bzero(param, sizeof (struct mslsa_LookupNames));
		param->status = NT_SC_ERROR(NT_STATUS_NO_MEMORY);
		return (NDR_DRC_OK);
	}

	param->domain_table = domain_table;
	param->mapped_count = 1;
	param->status = NT_STATUS_SUCCESS;

	smb_account_free(&account);
	return (NDR_DRC_OK);
}

/*
 * lsarpc_s_LookupSids
 *
 * This is the service side function for handling sid lookup requests.
 * We have to set up both the name table and the domain table in the
 * response. For each SID, we check for UNIX domain (local lookup) or
 * NT domain (DC lookup) and call the appropriate lookup function. This
 * should resolve the SID to a name. Then we need to update the domain
 * table and make the name entry point at the appropriate domain table
 * entry.
 *
 *
 * This RPC should behave as if LookupOptions is LSA_LOOKUP_OPT_ALL and
 * ClientRevision is LSA_CLIENT_REVISION_NT.
 *
 * On success return 0. Otherwise return an RPC specific error code.
 */

static int
lsarpc_s_LookupSids(void *arg, ndr_xa_t *mxa)
{
	struct mslsa_LookupSids *param = arg;
	struct mslsa_domain_table *domain_table;
	struct mslsa_domain_entry *domain_entry;
	struct mslsa_name_entry *names;
	struct mslsa_name_entry *name;
	smb_account_t account;
	smb_sid_t *sid;
	DWORD n_entry;
	DWORD n_mapped;
	char sidstr[SMB_SID_STRSZ];
	int result;
	int i;

	bzero(&account, sizeof (smb_account_t));
	n_mapped = 0;
	n_entry = param->lup_sid_table.n_entry;

	names = NDR_NEWN(mxa, struct mslsa_name_entry, n_entry);
	domain_table = NDR_NEW(mxa, struct mslsa_domain_table);
	domain_entry = NDR_NEWN(mxa, struct mslsa_domain_entry,
	    MLSVC_DOMAIN_MAX);

	if (names == NULL || domain_table == NULL || domain_entry == NULL)
		goto lookup_sid_failed;

	domain_table->entries = domain_entry;
	domain_table->n_entry = 0;
	domain_table->max_n_entry = MLSVC_DOMAIN_MAX;

	name = names;
	for (i = 0; i < n_entry; ++i, name++) {
		bzero(name, sizeof (struct mslsa_name_entry));
		sid = (smb_sid_t *)param->lup_sid_table.entries[i].psid;

		result = lsa_lookup_sid(sid, &account);
		if ((result != NT_STATUS_SUCCESS) ||
		    (account.a_name == NULL) || (*account.a_name == '\0')) {
			account.a_type = SidTypeUnknown;
			smb_sid_tostr(sid, sidstr);

			if (NDR_MSTRING(mxa, sidstr,
			    (ndr_mstring_t *)&name->name) == -1)
				goto lookup_sid_failed;

		} else {
			if (NDR_MSTRING(mxa, account.a_name,
			    (ndr_mstring_t *)&name->name) == -1)
				goto lookup_sid_failed;

			++n_mapped;
		}

		name->sid_name_use = account.a_type;

		result = lsarpc_s_UpdateDomainTable(mxa, &account,
		    domain_table, &name->domain_ix);
		if (result == -1)
			goto lookup_sid_failed;

		smb_account_free(&account);
	}

	param->domain_table = domain_table;
	param->name_table.n_entry = n_entry;
	param->name_table.entries = names;
	param->mapped_count = n_mapped;

	if (n_mapped == n_entry)
		param->status = NT_STATUS_SUCCESS;
	else if (n_mapped == 0)
		param->status = NT_STATUS_NONE_MAPPED;
	else
		param->status = NT_STATUS_SOME_NOT_MAPPED;

	return (NDR_DRC_OK);

lookup_sid_failed:
	smb_account_free(&account);
	bzero(param, sizeof (struct mslsa_LookupSids));
	return (NDR_DRC_FAULT_OUT_OF_MEMORY);
}

/*
 * lsarpc_s_UpdateDomainTable
 *
 * This routine is responsible for maintaining the domain table which
 * will be returned from a SID lookup. Whenever a name is added to the
 * name table, this function should be called with the corresponding
 * domain name. If the domain information is not already in the table,
 * it is added. On success return 0; Otherwise -1 is returned.
 */
static int
lsarpc_s_UpdateDomainTable(ndr_xa_t *mxa,
    smb_account_t *account, struct mslsa_domain_table *domain_table,
    DWORD *domain_idx)
{
	struct mslsa_domain_entry *dentry;
	DWORD n_entry;
	DWORD i;
	int rc;

	if (account->a_type == SidTypeUnknown ||
	    account->a_type == SidTypeInvalid) {
		/*
		 * These types don't need to reference an entry in the
		 * domain table. So return -1.
		 */
		*domain_idx = (DWORD)-1;
		return (0);
	}

	if ((dentry = domain_table->entries) == NULL)
		return (-1);

	if ((n_entry = domain_table->n_entry) >= MLSVC_DOMAIN_MAX)
		return (-1);

	for (i = 0; i < n_entry; ++i) {
		if (smb_sid_cmp((smb_sid_t *)dentry[i].domain_sid,
		    account->a_domsid)) {
			*domain_idx = i;
			return (0);
		}
	}

	if (i == MLSVC_DOMAIN_MAX)
		return (-1);

	rc = NDR_MSTRING(mxa, account->a_domain,
	    (ndr_mstring_t *)&dentry[i].domain_name);
	dentry[i].domain_sid =
	    (struct mslsa_sid *)NDR_SIDDUP(mxa, account->a_domsid);

	if (rc == -1 || dentry[i].domain_sid == NULL)
		return (-1);

	++domain_table->n_entry;
	*domain_idx = i;
	return (0);
}

/*
 * lsarpc_s_LookupSids2
 *
 * Other than the use of lsar_lookup_sids2 and lsar_name_entry2, this
 * is identical to lsarpc_s_LookupSids.
 *
 * Ignore lookup_level, it is reserved and should be zero.
 */
static int
lsarpc_s_LookupSids2(void *arg, ndr_xa_t *mxa)
{
	struct lsar_lookup_sids2 *param = arg;
	struct lsar_name_entry2 *names;
	struct lsar_name_entry2 *name;
	struct mslsa_domain_table *domain_table;
	struct mslsa_domain_entry *domain_entry;
	smb_account_t account;
	smb_sid_t *sid;
	DWORD n_entry;
	DWORD n_mapped;
	char sidstr[SMB_SID_STRSZ];
	int result;
	int i;

	bzero(&account, sizeof (smb_account_t));
	n_mapped = 0;
	n_entry = param->lup_sid_table.n_entry;

	names = NDR_NEWN(mxa, struct lsar_name_entry2, n_entry);
	domain_table = NDR_NEW(mxa, struct mslsa_domain_table);
	domain_entry = NDR_NEWN(mxa, struct mslsa_domain_entry,
	    MLSVC_DOMAIN_MAX);

	if (names == NULL || domain_table == NULL || domain_entry == NULL)
		goto lookup_sid_failed;

	domain_table->entries = domain_entry;
	domain_table->n_entry = 0;
	domain_table->max_n_entry = MLSVC_DOMAIN_MAX;

	name = names;
	for (i = 0; i < n_entry; ++i, name++) {
		bzero(name, sizeof (struct lsar_name_entry2));
		sid = (smb_sid_t *)param->lup_sid_table.entries[i].psid;

		result = lsa_lookup_sid(sid, &account);
		if ((result != NT_STATUS_SUCCESS) ||
		    (account.a_name == NULL) || (*account.a_name == '\0')) {
			account.a_type = SidTypeUnknown;
			smb_sid_tostr(sid, sidstr);

			if (NDR_MSTRING(mxa, sidstr,
			    (ndr_mstring_t *)&name->name) == -1)
				goto lookup_sid_failed;

		} else {
			if (NDR_MSTRING(mxa, account.a_name,
			    (ndr_mstring_t *)&name->name) == -1)
				goto lookup_sid_failed;

			++n_mapped;
		}

		name->sid_name_use = account.a_type;

		result = lsarpc_s_UpdateDomainTable(mxa, &account,
		    domain_table, &name->domain_ix);
		if (result == -1)
			goto lookup_sid_failed;

		smb_account_free(&account);
	}

	param->domain_table = domain_table;
	param->name_table.n_entry = n_entry;
	param->name_table.entries = names;
	param->mapped_count = n_mapped;

	if (n_mapped == n_entry)
		param->status = NT_STATUS_SUCCESS;
	else if (n_mapped == 0)
		param->status = NT_STATUS_NONE_MAPPED;
	else
		param->status = NT_STATUS_SOME_NOT_MAPPED;

	return (NDR_DRC_OK);

lookup_sid_failed:
	smb_account_free(&account);
	bzero(param, sizeof (struct lsar_lookup_sids2));
	return (NDR_DRC_FAULT_OUT_OF_MEMORY);
}

/*
 * LookupSids3 is only valid on domain controllers.
 * Other servers must return NT_STATUS_INVALID_SERVER_STATE.
 */
/*ARGSUSED*/
static int
lsarpc_s_LookupSids3(void *arg, ndr_xa_t *mxa)
{
	struct lsar_lookup_sids3 *param = arg;

	bzero(param, sizeof (struct lsar_lookup_sids3));
	param->status = NT_SC_ERROR(NT_STATUS_INVALID_SERVER_STATE);
	return (NDR_DRC_OK);
}

/*
 * lsarpc_s_LookupNames2
 *
 * Other than the use of lsar_LookupNames2 and lsar_rid_entry2, this
 * is identical to lsarpc_s_LookupNames.
 *
 * If LookupOptions contains LSA_LOOKUP_OPT_LOCAL and LookupLevel is not
 * LSA_LOOKUP_WKSTA, return STATUS_INVALID_PARAMETER.
 */
static int
lsarpc_s_LookupNames2(void *arg, ndr_xa_t *mxa)
{
	struct lsar_LookupNames2 *param = arg;
	struct lsar_rid_entry2 *rids;
	struct mslsa_domain_table *domain_table;
	struct mslsa_domain_entry *domain_entry;
	smb_account_t account;
	uint32_t status;
	char *accname;
	int rc = 0;

	if (param->name_table->n_entry != 1)
		return (NDR_DRC_FAULT_PARAM_0_UNIMPLEMENTED);

	if ((param->lookup_options & LSA_LOOKUP_OPT_LOCAL) &&
	    param->lookup_level != LSA_LOOKUP_WKSTA) {
		bzero(param, sizeof (struct lsar_LookupNames2));
		param->status = NT_SC_ERROR(NT_STATUS_INVALID_PARAMETER);
		return (NDR_DRC_OK);
	}

	rids = NDR_NEW(mxa, struct lsar_rid_entry2);
	domain_table = NDR_NEW(mxa, struct mslsa_domain_table);
	domain_entry = NDR_NEW(mxa, struct mslsa_domain_entry);

	if (rids == NULL || domain_table == NULL || domain_entry == NULL) {
		bzero(param, sizeof (struct lsar_LookupNames2));
		param->status = NT_SC_ERROR(NT_STATUS_NO_MEMORY);
		return (NDR_DRC_OK);
	}

	accname = (char *)param->name_table->names->str;
	status = lsa_lookup_name(accname, SidTypeUnknown, &account);
	if (status != NT_STATUS_SUCCESS) {
		bzero(param, sizeof (struct lsar_LookupNames2));
		param->status = NT_SC_ERROR(status);
		return (NDR_DRC_OK);
	}

	/*
	 * Set up the rid table.
	 */
	bzero(rids, sizeof (struct lsar_rid_entry2));
	rids[0].sid_name_use = account.a_type;
	rids[0].rid = account.a_rid;
	rids[0].domain_index = 0;
	param->translated_sids.n_entry = 1;
	param->translated_sids.rids = rids;

	/*
	 * Set up the domain table.
	 */
	domain_table->entries = domain_entry;
	domain_table->n_entry = 1;
	domain_table->max_n_entry = MLSVC_DOMAIN_MAX;

	rc = NDR_MSTRING(mxa, account.a_domain,
	    (ndr_mstring_t *)&domain_entry->domain_name);

	domain_entry->domain_sid =
	    (struct mslsa_sid *)NDR_SIDDUP(mxa, account.a_domsid);

	if (rc == -1 || domain_entry->domain_sid == NULL) {
		smb_account_free(&account);
		bzero(param, sizeof (struct lsar_LookupNames2));
		param->status = NT_SC_ERROR(NT_STATUS_NO_MEMORY);
		return (NDR_DRC_OK);
	}

	param->domain_table = domain_table;
	param->mapped_count = 1;
	param->status = NT_STATUS_SUCCESS;

	smb_account_free(&account);
	return (NDR_DRC_OK);
}

/*
 * Other than the use of lsar_LookupNames2 and lsar_rid_entry2, this
 * is identical to lsarpc_s_LookupNames.
 *
 * If LookupOptions contains LSA_LOOKUP_OPT_LOCAL and LookupLevel is not
 * LSA_LOOKUP_WKSTA, return STATUS_INVALID_PARAMETER.
 */
static int
lsarpc_s_LookupNames3(void *arg, ndr_xa_t *mxa)
{
	struct lsar_LookupNames3	*param = arg;
	struct lsar_translated_sid_ex2	*sids;
	struct mslsa_domain_table	*domain_table;
	struct mslsa_domain_entry	*domain_entry;
	smb_account_t			account;
	uint32_t			status;
	char				*accname;
	int				rc = 0;

	if (param->name_table->n_entry != 1)
		return (NDR_DRC_FAULT_PARAM_0_UNIMPLEMENTED);

	if ((param->lookup_options & LSA_LOOKUP_OPT_LOCAL) &&
	    param->lookup_level != LSA_LOOKUP_WKSTA) {
		bzero(param, sizeof (struct lsar_LookupNames3));
		param->status = NT_SC_ERROR(NT_STATUS_INVALID_PARAMETER);
		return (NDR_DRC_OK);
	}

	sids = NDR_NEW(mxa, struct lsar_translated_sid_ex2);
	domain_table = NDR_NEW(mxa, struct mslsa_domain_table);
	domain_entry = NDR_NEW(mxa, struct mslsa_domain_entry);

	if (sids == NULL || domain_table == NULL || domain_entry == NULL) {
		bzero(param, sizeof (struct lsar_LookupNames3));
		param->status = NT_SC_ERROR(NT_STATUS_NO_MEMORY);
		return (NDR_DRC_OK);
	}

	accname = (char *)param->name_table->names->str;
	status = lsa_lookup_name(accname, SidTypeUnknown, &account);
	if (status != NT_STATUS_SUCCESS) {
		bzero(param, sizeof (struct lsar_LookupNames3));
		param->status = NT_SC_ERROR(status);
		return (NDR_DRC_OK);
	}

	/*
	 * Set up the SID table.
	 */
	bzero(sids, sizeof (struct lsar_translated_sid_ex2));
	sids[0].sid_name_use = account.a_type;
	sids[0].sid = (struct mslsa_sid *)NDR_SIDDUP(mxa, account.a_sid);
	sids[0].domain_index = 0;
	param->translated_sids.n_entry = 1;
	param->translated_sids.sids = sids;

	/*
	 * Set up the domain table.
	 */
	domain_table->entries = domain_entry;
	domain_table->n_entry = 1;
	domain_table->max_n_entry = MLSVC_DOMAIN_MAX;

	rc = NDR_MSTRING(mxa, account.a_domain,
	    (ndr_mstring_t *)&domain_entry->domain_name);

	domain_entry->domain_sid =
	    (struct mslsa_sid *)NDR_SIDDUP(mxa, account.a_domsid);

	if (rc == -1 || domain_entry->domain_sid == NULL) {
		smb_account_free(&account);
		bzero(param, sizeof (struct lsar_LookupNames3));
		param->status = NT_SC_ERROR(NT_STATUS_NO_MEMORY);
		return (NDR_DRC_OK);
	}

	param->domain_table = domain_table;
	param->mapped_count = 1;
	param->status = NT_STATUS_SUCCESS;

	smb_account_free(&account);
	return (NDR_DRC_OK);
}

/*
 * LookupNames4 is only valid on domain controllers.
 * Other servers must return NT_STATUS_INVALID_SERVER_STATE.
 */
/*ARGSUSED*/
static int
lsarpc_s_LookupNames4(void *arg, ndr_xa_t *mxa)
{
	struct lsar_LookupNames4 *param = arg;

	bzero(param, sizeof (struct lsar_LookupNames4));
	param->status = NT_SC_ERROR(NT_STATUS_INVALID_SERVER_STATE);
	return (NDR_DRC_OK);
}

/*
 * There is a bug in the way that ndrgen and the marshalling code handles
 * unions so we need to fix some of the data offsets at runtime. The
 * following macros and the fixup functions handle the corrections.
 */

DECL_FIXUP_STRUCT(mslsa_PolicyInfoResUnion);
DECL_FIXUP_STRUCT(mslsa_PolicyInfoRes);
DECL_FIXUP_STRUCT(mslsa_QueryInfoPolicy);
void
fixup_mslsa_QueryInfoPolicy(struct mslsa_QueryInfoPolicy *val)
{
	unsigned short size1 = 0;
	unsigned short size2 = 0;
	unsigned short size3 = 0;

	switch (val->info_class) {
		case MSLSA_POLICY_AUDIT_EVENTS_INFO:
			size1 = sizeof (struct mslsa_AuditEventsInfo);
			break;

		case MSLSA_POLICY_PRIMARY_DOMAIN_INFO:
			size1 = sizeof (struct mslsa_PrimaryDomainInfo);
			break;

		case MSLSA_POLICY_ACCOUNT_DOMAIN_INFO:
			size1 = sizeof (struct mslsa_AccountDomainInfo);
			break;

		case MSLSA_POLICY_SERVER_ROLE_INFO:
			size1 = sizeof (struct mslsa_ServerRoleInfo);
			break;

		case MSLSA_POLICY_DNS_DOMAIN_INFO:
			size1 = sizeof (struct mslsa_DnsDomainInfo);
			break;

		default:
			return;
	};

	size2 = size1 + (2 * sizeof (DWORD));
	size3 = size2 + sizeof (ndr_request_hdr_t) + sizeof (DWORD);

	FIXUP_PDU_SIZE(mslsa_PolicyInfoResUnion, size1);
	FIXUP_PDU_SIZE(mslsa_PolicyInfoRes, size2);
	FIXUP_PDU_SIZE(mslsa_QueryInfoPolicy, size3);
}
