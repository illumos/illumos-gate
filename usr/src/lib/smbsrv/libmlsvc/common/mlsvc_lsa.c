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

#pragma ident	"%Z%%M%	%I%	%E% SMI"


/*
 * Local Security Authority RPC (LSARPC) server-side interface definition.
 */

#include <unistd.h>
#include <strings.h>
#include <pwd.h>
#include <grp.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/libmlrpc.h>
#include <smbsrv/libmlsvc.h>
#include <smbsrv/mlsvc_util.h>
#include <smbsrv/ndl/lsarpc.ndl>
#include <smbsrv/lsalib.h>
#include <smbsrv/ntstatus.h>
#include <smbsrv/nterror.h>
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

static int lsarpc_call_stub(struct mlrpc_xaction *mxa);

static int lsarpc_s_CloseHandle(void *arg, struct mlrpc_xaction *);
static int lsarpc_s_QuerySecurityObject(void *arg, struct mlrpc_xaction *);
static int lsarpc_s_EnumAccounts(void *arg, struct mlrpc_xaction *);
static int lsarpc_s_EnumTrustedDomain(void *arg, struct mlrpc_xaction *);
static int lsarpc_s_OpenAccount(void *arg, struct mlrpc_xaction *);
static int lsarpc_s_EnumPrivsAccount(void *arg, struct mlrpc_xaction *);
static int lsarpc_s_LookupPrivValue(void *arg, struct mlrpc_xaction *);
static int lsarpc_s_LookupPrivName(void *arg, struct mlrpc_xaction *);
static int lsarpc_s_LookupPrivDisplayName(void *arg, struct mlrpc_xaction *);
static int lsarpc_s_CreateSecret(void *, struct mlrpc_xaction *);
static int lsarpc_s_OpenSecret(void *, struct mlrpc_xaction *);
static int lsarpc_s_QueryInfoPolicy(void *arg, struct mlrpc_xaction *);
static int lsarpc_s_OpenDomainHandle(void *arg, struct mlrpc_xaction *);
static int lsarpc_s_OpenDomainHandle(void *arg, struct mlrpc_xaction *);
static int lsarpc_s_LookupSids(void *arg, struct mlrpc_xaction *);
static int lsarpc_s_LookupNames(void *arg, struct mlrpc_xaction *);
static int lsarpc_s_GetConnectedUser(void *arg, struct mlrpc_xaction *);
static int lsarpc_s_LookupSids2(void *arg, struct mlrpc_xaction *);
static int lsarpc_s_LookupNames2(void *arg, struct mlrpc_xaction *);

static DWORD lsarpc_s_PrimaryDomainInfo(struct mslsa_PrimaryDomainInfo *,
    struct mlrpc_xaction *);
static DWORD lsarpc_s_AccountDomainInfo(struct mslsa_AccountDomainInfo *,
    struct mlrpc_xaction *);
static int lsarpc_s_UpdateDomainTable(struct mlrpc_xaction *,
    smb_userinfo_t *, struct mslsa_domain_table *, DWORD *);

static int lsarpc_w2k_enable;

static mlrpc_stub_table_t lsarpc_stub_table[] = {
	{ lsarpc_s_CloseHandle,		  LSARPC_OPNUM_CloseHandle },
	{ lsarpc_s_QuerySecurityObject,	  LSARPC_OPNUM_QuerySecurityObject },
	{ lsarpc_s_EnumAccounts,	  LSARPC_OPNUM_EnumerateAccounts },
	{ lsarpc_s_EnumTrustedDomain,	  LSARPC_OPNUM_EnumTrustedDomain },
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
	{ lsarpc_s_LookupNames2,	  LSARPC_OPNUM_LookupNames2 },
	{0}
};

static mlrpc_service_t lsarpc_service = {
	"LSARPC",			/* name */
	"Local Security Authority",	/* desc */
	"\\lsarpc",			/* endpoint */
	PIPE_LSASS,			/* sec_addr_port */
	"12345778-1234-abcd-ef000123456789ab", 0,	/* abstract */
	"8a885d04-1ceb-11c9-9fe808002b104860", 2,	/* transfer */
	0,				/* no bind_instance_size */
	NULL,				/* no bind_req() */
	NULL,				/* no unbind_and_close() */
	lsarpc_call_stub,		/* call_stub() */
	&TYPEINFO(lsarpc_interface),	/* interface ti */
	lsarpc_stub_table		/* stub_table */
};

/*
 * Windows 2000 interface.
 */
static mlrpc_service_t lsarpc_w2k_service = {
	"LSARPC_W2K",			/* name */
	"Local Security Authority",	/* desc */
	"\\lsarpc",			/* endpoint */
	PIPE_LSASS,			/* sec_addr_port */
	"3919286a-b10c-11d0-9ba800c04fd92ef5", 0,	/* abstract */
	"8a885d04-1ceb-11c9-9fe808002b104860", 2,	/* transfer */
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
	(void) mlrpc_register_service(&lsarpc_service);

	if (lsarpc_w2k_enable)
		(void) mlrpc_register_service(&lsarpc_w2k_service);
}

/*
 * Custom call_stub to set the stream string policy.
 */
static int
lsarpc_call_stub(struct mlrpc_xaction *mxa)
{
	MLNDS_SETF(&mxa->send_mlnds, MLNDS_F_NOTERM);
	MLNDS_SETF(&mxa->recv_mlnds, MLNDS_F_NOTERM);

	return (mlrpc_generic_call_stub(mxa));
}

/*
 * lsarpc_s_OpenDomainHandle opnum=0x06
 *
 * This is a request to open the LSA (OpenPolicy and OpenPolicy2).
 * The client is looking for an LSA domain handle.
 */
static int
lsarpc_s_OpenDomainHandle(void *arg, struct mlrpc_xaction *mxa)
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

	return (MLRPC_DRC_OK);
}

/*
 * lsarpc_s_CloseHandle opnum=0x00
 *
 * This is a request to close the LSA interface specified by the handle.
 * We don't track handles (yet), so just zero out the handle and return
 * MLRPC_DRC_OK. Setting the handle to zero appears to be standard
 * behaviour and someone may rely on it, i.e. we do on the client side.
 */
static int
lsarpc_s_CloseHandle(void *arg, struct mlrpc_xaction *mxa)
{
	struct mslsa_CloseHandle *param = arg;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->handle;

	ndr_hdfree(mxa, id);

	bzero(&param->result_handle, sizeof (param->result_handle));
	param->status = NT_STATUS_SUCCESS;
	return (MLRPC_DRC_OK);
}

/*
 * lsarpc_s_QuerySecurityObject
 */
/*ARGSUSED*/
static int
lsarpc_s_QuerySecurityObject(void *arg, struct mlrpc_xaction *mxa)
{
	struct mslsa_QuerySecurityObject *param = arg;

	bzero(param, sizeof (struct mslsa_QuerySecurityObject));
	param->status = NT_SC_ERROR(NT_STATUS_ACCESS_DENIED);

	return (MLRPC_DRC_OK);
}

/*
 * lsarpc_s_EnumAccounts
 *
 * Enumerate the list of local accounts SIDs. The client should supply
 * a valid OpenPolicy2 handle. The enum_context is used to support
 * multiple enumeration calls to obtain the complete list of SIDs.
 * It should be set to 0 on the first call and passed unchanged on
 * subsequent calls until there are no more accounts - the server will
 * return NT_SC_WARNING(MLSVC_NO_MORE_DATA).
 *
 * For now just set the status to access-denied. Note that we still have
 * to provide a valid address for enum_buf because it's a reference and
 * the marshalling rules require that references must not be null.
 * The enum_context is used to support multiple
 */
static int
lsarpc_s_EnumAccounts(void *arg, struct mlrpc_xaction *mxa)
{
	struct mslsa_EnumerateAccounts *param = arg;
	struct mslsa_EnumAccountBuf *enum_buf;

	bzero(param, sizeof (struct mslsa_EnumerateAccounts));

	enum_buf = MLRPC_HEAP_NEW(mxa, struct mslsa_EnumAccountBuf);
	if (enum_buf == NULL) {
		param->status = NT_SC_ERROR(NT_STATUS_NO_MEMORY);
		return (MLRPC_DRC_OK);
	}

	bzero(enum_buf, sizeof (struct mslsa_EnumAccountBuf));
	param->enum_buf = enum_buf;
	param->status = NT_SC_ERROR(NT_STATUS_ACCESS_DENIED);
	return (MLRPC_DRC_OK);
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
 * return NT_SC_WARNING(MLSVC_NO_MORE_DATA).
 *
 * For now just set the status to access-denied. Note that we still have
 * to provide a valid address for enum_buf because it's a reference and
 * the marshalling rules require that references must not be null.
 */
static int
lsarpc_s_EnumTrustedDomain(void *arg, struct mlrpc_xaction *mxa)
{
	struct mslsa_EnumTrustedDomain *param = arg;
	struct mslsa_EnumTrustedDomainBuf *enum_buf;

	bzero(param, sizeof (struct mslsa_EnumTrustedDomain));

	enum_buf = MLRPC_HEAP_NEW(mxa, struct mslsa_EnumTrustedDomainBuf);
	if (enum_buf == NULL) {
		param->status = NT_SC_ERROR(NT_STATUS_NO_MEMORY);
		return (MLRPC_DRC_OK);
	}

	bzero(enum_buf, sizeof (struct mslsa_EnumTrustedDomainBuf));
	param->enum_buf = enum_buf;
	param->status = NT_SC_ERROR(NT_STATUS_ACCESS_DENIED);
	return (MLRPC_DRC_OK);
}


/*
 * lsarpc_s_OpenAccount
 *
 * This is a request to open an account handle.
 */
static int
lsarpc_s_OpenAccount(void *arg, struct mlrpc_xaction *mxa)
{
	struct mslsa_OpenAccount *param = arg;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->handle;
	ndr_handle_t *hd;

	hd = ndr_hdlookup(mxa, id);
	if ((hd == NULL) || (hd->nh_data != &lsarpc_key_domain)) {
		bzero(param, sizeof (struct mslsa_OpenAccount));
		param->status = NT_SC_ERROR(NT_STATUS_INVALID_HANDLE);
		return (MLRPC_DRC_OK);
	}

	if ((id = ndr_hdalloc(mxa, &lsarpc_key_account)) != NULL) {
		bcopy(id, &param->account_handle, sizeof (mslsa_handle_t));
		param->status = NT_STATUS_SUCCESS;
	} else {
		bzero(&param->account_handle, sizeof (mslsa_handle_t));
		param->status = NT_SC_ERROR(NT_STATUS_NO_MEMORY);
	}

	return (MLRPC_DRC_OK);
}


/*
 * lsarpc_s_EnumPrivsAccount
 *
 * This is the server side function for handling requests for account
 * privileges. For now just set the status to not-supported status and
 * return MLRPC_DRC_OK. Note that we still have to provide a valid
 * address for enum_buf because it's a reference and the marshalling
 * rules require that references must not be null.
 */
/*ARGSUSED*/
static int
lsarpc_s_EnumPrivsAccount(void *arg, struct mlrpc_xaction *mxa)
{
	struct mslsa_EnumPrivsAccount *param = arg;

	bzero(param, sizeof (struct mslsa_EnumPrivsAccount));
	param->status = NT_SC_ERROR(NT_STATUS_NOT_SUPPORTED);
	return (MLRPC_DRC_OK);
}

/*
 * lsarpc_s_LookupPrivValue
 *
 * Server side function used to map a privilege name to a locally unique
 * identifier (LUID).
 */
/*ARGSUSED*/
static int
lsarpc_s_LookupPrivValue(void *arg, struct mlrpc_xaction *mxa)
{
	struct mslsa_LookupPrivValue *param = arg;
	smb_privinfo_t *pi;

	if ((pi = smb_priv_getbyname((char *)param->name.str)) == NULL) {
		bzero(param, sizeof (struct mslsa_LookupPrivValue));
		param->status = NT_SC_ERROR(NT_STATUS_NO_SUCH_PRIVILEGE);
		return (MLRPC_DRC_OK);
	}

	param->luid.low_part = pi->id;
	param->luid.high_part = 0;
	param->status = NT_STATUS_SUCCESS;
	return (MLRPC_DRC_OK);
}

/*
 * lsarpc_s_LookupPrivName
 *
 * Server side function used to map a locally unique identifier (LUID)
 * to the appropriate privilege name string.
 */
static int
lsarpc_s_LookupPrivName(void *arg, struct mlrpc_xaction *mxa)
{
	struct mslsa_LookupPrivName *param = arg;
	smb_privinfo_t *pi;
	int rc;

	if ((pi = smb_priv_getbyvalue(param->luid.low_part)) == NULL) {
		bzero(param, sizeof (struct mslsa_LookupPrivName));
		param->status = NT_SC_ERROR(NT_STATUS_NO_SUCH_PRIVILEGE);
		return (MLRPC_DRC_OK);
	}

	param->name = MLRPC_HEAP_NEW(mxa, mslsa_string_t);
	if (param->name == NULL) {
		bzero(param, sizeof (struct mslsa_LookupPrivName));
		param->status = NT_SC_ERROR(NT_STATUS_NO_MEMORY);
		return (MLRPC_DRC_OK);
	}

	rc = mlsvc_string_save((ms_string_t *)param->name, pi->name, mxa);
	if (rc == 0) {
		bzero(param, sizeof (struct mslsa_LookupPrivName));
		param->status = NT_SC_ERROR(NT_STATUS_NO_MEMORY);
		return (MLRPC_DRC_OK);
	}

	param->status = NT_STATUS_SUCCESS;
	return (MLRPC_DRC_OK);
}

/*
 * lsarpc_s_LookupPrivDisplayName
 *
 * This is the server side function for handling requests for account
 * privileges. For now just set the status to not-supported status and
 * return MLRPC_DRC_OK.
 */
static int
lsarpc_s_LookupPrivDisplayName(void *arg, struct mlrpc_xaction *mxa)
{
	struct mslsa_LookupPrivDisplayName *param = arg;
	smb_privinfo_t *pi;
	int rc;

	if ((pi = smb_priv_getbyname((char *)param->name.str)) == NULL) {
		bzero(param, sizeof (struct mslsa_LookupPrivDisplayName));
		param->status = NT_SC_ERROR(NT_STATUS_NO_SUCH_PRIVILEGE);
		return (MLRPC_DRC_OK);
	}

	param->display_name = MLRPC_HEAP_NEW(mxa, mslsa_string_t);
	if (param->display_name == NULL) {
		bzero(param, sizeof (struct mslsa_LookupPrivDisplayName));
		param->status = NT_SC_ERROR(NT_STATUS_NO_MEMORY);
		return (MLRPC_DRC_OK);
	}

	rc = mlsvc_string_save((ms_string_t *)param->display_name,
	    pi->display_name, mxa);

	if (rc == 0) {
		bzero(param, sizeof (struct mslsa_LookupPrivDisplayName));
		param->status = NT_SC_ERROR(NT_STATUS_NO_MEMORY);
		return (MLRPC_DRC_OK);
	}

	param->language_ret = MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL);
	param->status = NT_STATUS_SUCCESS;
	return (MLRPC_DRC_OK);
}

static int
lsarpc_s_CreateSecret(void *arg, struct mlrpc_xaction *mxa)
{
	struct mslsa_CreateSecret *param = arg;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->handle;
	ndr_handle_t *hd;

	hd = ndr_hdlookup(mxa, id);
	if ((hd == NULL) || (hd->nh_data != &lsarpc_key_domain)) {
		bzero(param, sizeof (struct mslsa_OpenAccount));
		param->status = NT_SC_ERROR(NT_STATUS_INVALID_HANDLE);
		return (MLRPC_DRC_OK);
	}

	bzero(&param->secret_handle, sizeof (mslsa_handle_t));
	param->status = NT_SC_ERROR(NT_STATUS_ACCESS_DENIED);
	return (MLRPC_DRC_OK);
}

static int
lsarpc_s_OpenSecret(void *arg, struct mlrpc_xaction *mxa)
{
	struct mslsa_OpenSecret *param = arg;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->handle;
	ndr_handle_t *hd;

	hd = ndr_hdlookup(mxa, id);
	if ((hd == NULL) || (hd->nh_data != &lsarpc_key_domain)) {
		bzero(param, sizeof (struct mslsa_OpenAccount));
		param->status = NT_SC_ERROR(NT_STATUS_INVALID_HANDLE);
		return (MLRPC_DRC_OK);
	}

	bzero(&param->secret_handle, sizeof (mslsa_handle_t));
	param->status = NT_SC_ERROR(NT_STATUS_ACCESS_DENIED);
	return (MLRPC_DRC_OK);
}

/*
 * lsarpc_s_GetConnectedUser
 *
 * This is still guesswork. Netmon doesn't know about this
 * call and I'm not really sure what it is intended to achieve.
 * Another packet capture application, Ethereal, calls this RPC as
 * GetConnectedUser.
 * We will receive our own hostname in the request and it appears
 * we should respond with an account name and the domain name of connected
 * user from the client that makes this call.
 */
static int
lsarpc_s_GetConnectedUser(void *arg, struct mlrpc_xaction *mxa)
{
	struct mslsa_GetConnectedUser *param = arg;
	smb_dr_user_ctx_t *user_ctx = mxa->context->user_ctx;
	DWORD status = NT_STATUS_SUCCESS;
	int rc1;
	int rc2;

	if (user_ctx == NULL) {
		bzero(param, sizeof (struct mslsa_GetConnectedUser));
		status = NT_SC_ERROR(NT_STATUS_NO_TOKEN);
		param->status = status;
		return (MLRPC_DRC_OK);
	}

	if (smb_getdomaininfo(0) == NULL) {
		bzero(param, sizeof (struct mslsa_GetConnectedUser));
		status = NT_SC_ERROR(NT_STATUS_CANT_ACCESS_DOMAIN_INFO);
		param->status = status;
		return (MLRPC_DRC_OK);
	}

	param->owner = MLRPC_HEAP_NEW(mxa, struct mslsa_string_desc);
	param->domain = MLRPC_HEAP_NEW(mxa, struct mslsa_DomainName);
	if (param->owner == NULL || param->domain == NULL) {
		status = NT_SC_ERROR(NT_STATUS_NO_MEMORY);
		param->status = status;
		return (MLRPC_DRC_OK);
	}

	param->domain->name = MLRPC_HEAP_NEW(mxa, struct mslsa_string_desc);
	if (param->domain->name == NULL) {
		status = NT_SC_ERROR(NT_STATUS_NO_MEMORY);
		param->status = status;
		return (MLRPC_DRC_OK);
	}

	rc1 = mlsvc_string_save((ms_string_t *)param->owner,
	    user_ctx->du_account, mxa);

	rc2 = mlsvc_string_save((ms_string_t *)param->domain->name,
	    user_ctx->du_domain, mxa);

	if (rc1 == 0 || rc2 == 0)
		status = NT_SC_ERROR(NT_STATUS_NO_MEMORY);

	param->status = status;
	return (MLRPC_DRC_OK);
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
lsarpc_s_QueryInfoPolicy(void *arg, struct mlrpc_xaction *mxa)
{
	struct mslsa_QueryInfoPolicy *param = arg;
	struct mslsa_PolicyInfo *info;
	int security_mode;
	DWORD status;

	info = (struct mslsa_PolicyInfo *)MLRPC_HEAP_MALLOC(
	    mxa, sizeof (struct mslsa_PolicyInfo));
	if (info == NULL) {
		bzero(param, sizeof (struct mslsa_QueryInfoPolicy));
		param->status = NT_SC_ERROR(NT_STATUS_NO_MEMORY);
		return (MLRPC_DRC_OK);
	}

	info->switch_value = param->info_class;

	switch (param->info_class) {
	case MSLSA_POLICY_AUDIT_EVENTS_INFO:
		info->ru.audit_events.enabled = 0;
		info->ru.audit_events.count = 1;
		info->ru.audit_events.settings
		    = MLRPC_HEAP_MALLOC(mxa, sizeof (DWORD));
		bzero(info->ru.audit_events.settings, sizeof (DWORD));
		status = NT_STATUS_SUCCESS;
		break;

	case MSLSA_POLICY_PRIMARY_DOMAIN_INFO:
		status = lsarpc_s_PrimaryDomainInfo(&info->ru.pd_info, mxa);
		break;

	case MSLSA_POLICY_ACCOUNT_DOMAIN_INFO:
		status = lsarpc_s_AccountDomainInfo(&info->ru.ad_info, mxa);
		break;

	case MSLSA_POLICY_SERVER_ROLE_INFO:
		security_mode = smb_config_get_secmode();

		if (security_mode == SMB_SECMODE_DOMAIN)
			info->ru.server_role.role = LSA_ROLE_MEMBER_SERVER;
		else
			info->ru.server_role.role = LSA_ROLE_STANDALONE_SERVER;

		info->ru.server_role.pad = 0;
		status = NT_STATUS_SUCCESS;
		break;

	default:
		bzero(param, sizeof (struct mslsa_QueryInfoPolicy));
		param->status = NT_SC_ERROR(NT_STATUS_INVALID_INFO_CLASS);
		return (MLRPC_DRC_OK);
	}

	if (status != NT_STATUS_SUCCESS)
		param->status = NT_SC_ERROR(status);
	else
		param->status = NT_STATUS_SUCCESS;
	param->info = info;
	return (MLRPC_DRC_OK);
}


/*
 * lsarpc_s_PrimaryDomainInfo
 *
 * This is the service side function for handling primary domain policy
 * queries. This will return the primary domain name and sid. This is
 * currently a pass through interface so all we do is act as a proxy
 * between the client and the DC. If there is no session, fake up the
 * response with default values - useful for share mode.
 *
 * If the server name matches the local hostname, we should return
 * the local domain SID.
 */
static DWORD
lsarpc_s_PrimaryDomainInfo(struct mslsa_PrimaryDomainInfo *info,
    struct mlrpc_xaction *mxa)
{
	char domain_name[MLSVC_DOMAIN_NAME_MAX];
	nt_sid_t *sid = NULL;
	int security_mode;
	int rc;

	security_mode = smb_config_get_secmode();

	if (security_mode != SMB_SECMODE_DOMAIN) {
		rc = smb_gethostname(domain_name, MLSVC_DOMAIN_NAME_MAX, 1);
		sid = nt_sid_dup(nt_domain_local_sid());
	} else {
		rc = smb_getdomainname(domain_name, MLSVC_DOMAIN_NAME_MAX);
		sid = smb_getdomainsid();
	}

	if ((sid == NULL) || (rc != 0))
		return (NT_STATUS_CANT_ACCESS_DOMAIN_INFO);

	rc = mlsvc_string_save((ms_string_t *)&info->name, domain_name, mxa);
	info->sid = (struct mslsa_sid *)mlsvc_sid_save(sid, mxa);
	free(sid);

	if ((rc == 0) || (info->sid == NULL))
		return (NT_STATUS_NO_MEMORY);

	return (NT_STATUS_SUCCESS);
}


/*
 * lsarpc_s_AccountDomainInfo
 *
 * This is the service side function for handling account domain policy
 * queries. This is where we return our local domain information so that
 * NT knows who to query for information on local names and SIDs. The
 * domain name is the local hostname.
 */
static DWORD
lsarpc_s_AccountDomainInfo(struct mslsa_AccountDomainInfo *info,
    struct mlrpc_xaction *mxa)
{
	char domain_name[MLSVC_DOMAIN_NAME_MAX];
	nt_sid_t *domain_sid;
	int rc;

	if (smb_gethostname(domain_name, MLSVC_DOMAIN_NAME_MAX, 1) != 0)
		return (NT_STATUS_NO_MEMORY);

	if ((domain_sid = nt_domain_local_sid()) == NULL)
		return (NT_STATUS_NO_MEMORY);

	rc = mlsvc_string_save((ms_string_t *)&info->name, domain_name, mxa);
	info->sid = (struct mslsa_sid *)mlsvc_sid_save(domain_sid, mxa);

	if ((rc == 0) || (info->sid == NULL))
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
lsarpc_s_LookupNames(void *arg, struct mlrpc_xaction *mxa)
{
	struct mslsa_LookupNames *param = arg;
	struct mslsa_rid_entry *rids;
	smb_userinfo_t *user_info = 0;
	struct mslsa_domain_table *domain_table;
	struct mslsa_domain_entry *domain_entry;
	DWORD status = NT_STATUS_SUCCESS;
	char *account;
	int rc = 0;

	if (param->name_table->n_entry != 1)
		return (MLRPC_DRC_FAULT_PARAM_0_UNIMPLEMENTED);

	rids = MLRPC_HEAP_NEW(mxa, struct mslsa_rid_entry);
	domain_table = MLRPC_HEAP_NEW(mxa, struct mslsa_domain_table);
	domain_entry = MLRPC_HEAP_NEW(mxa, struct mslsa_domain_entry);
	user_info = mlsvc_alloc_user_info();

	if (rids == NULL || domain_table == NULL ||
	    domain_entry == NULL || user_info == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto name_lookup_failed;
	}

	account = (char *)param->name_table->names->str;
	status = lsa_lookup_name(NULL, account, SidTypeUnknown, user_info);
	if (status != NT_STATUS_SUCCESS)
		goto name_lookup_failed;

	/*
	 * Set up the rid table.
	 */
	rids[0].sid_name_use = user_info->sid_name_use;
	rids[0].rid = user_info->rid;
	rids[0].domain_index = 0;
	param->translated_sids.n_entry = 1;
	param->translated_sids.rids = rids;

	/*
	 * Set up the domain table.
	 */
	domain_table->entries = domain_entry;
	domain_table->n_entry = 1;
	domain_table->max_n_entry = MLSVC_DOMAIN_MAX;

	rc = mlsvc_string_save((ms_string_t *)&domain_entry->domain_name,
	    user_info->domain_name, mxa);

	domain_entry->domain_sid =
	    (struct mslsa_sid *)mlsvc_sid_save(user_info->domain_sid, mxa);

	if (rc == 0 || domain_entry->domain_sid == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto name_lookup_failed;
	}

	param->domain_table = domain_table;
	param->mapped_count = 1;
	param->status = 0;

	mlsvc_free_user_info(user_info);
	return (MLRPC_DRC_OK);

name_lookup_failed:
	mlsvc_free_user_info(user_info);
	bzero(param, sizeof (struct mslsa_LookupNames));
	param->status = NT_SC_ERROR(status);
	return (MLRPC_DRC_OK);
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
 * On success return 0. Otherwise return an RPC specific error code.
 */
static int
lsarpc_s_LookupSids(void *arg, struct mlrpc_xaction *mxa)
{
	struct mslsa_LookupSids *param = arg;
	struct mslsa_domain_table *domain_table;
	struct mslsa_domain_entry *domain_entry;
	struct mslsa_name_entry *names;
	struct mslsa_name_entry *name;
	smb_userinfo_t *user_info;
	nt_sid_t *sid;
	DWORD n_entry;
	int result;
	int i;

	user_info = mlsvc_alloc_user_info();

	n_entry = param->lup_sid_table.n_entry;
	names = MLRPC_HEAP_NEWN(mxa, struct mslsa_name_entry, n_entry);
	domain_table = MLRPC_HEAP_NEW(mxa, struct mslsa_domain_table);
	domain_entry = MLRPC_HEAP_NEWN(mxa, struct mslsa_domain_entry,
	    MLSVC_DOMAIN_MAX);

	if (names == NULL || domain_table == NULL ||
	    domain_entry == NULL || user_info == NULL) {
		bzero(param, sizeof (struct mslsa_LookupSids));
		param->status = NT_SC_ERROR(NT_STATUS_NO_MEMORY);
		return (MLRPC_DRC_OK);
	}

	domain_table->entries = domain_entry;
	domain_table->n_entry = 0;
	domain_table->max_n_entry = MLSVC_DOMAIN_MAX;

	name = names;
	for (i = 0; i < n_entry; ++i, name++) {
		bzero(&names[i], sizeof (struct mslsa_name_entry));
		sid = (nt_sid_t *)param->lup_sid_table.entries[i].psid;

		result = lsa_lookup_sid(sid, user_info);
		if (result != NT_STATUS_SUCCESS)
			goto lookup_sid_failed;

		if (!mlsvc_string_save((ms_string_t *)&name->name,
		    user_info->name, mxa)) {
			result = NT_STATUS_NO_MEMORY;
			goto lookup_sid_failed;
		}
		name->sid_name_use = user_info->sid_name_use;

		result = lsarpc_s_UpdateDomainTable(mxa, user_info,
		    domain_table, &name->domain_ix);

		if (result == -1) {
			result = NT_STATUS_INTERNAL_ERROR;
			goto lookup_sid_failed;
		}

		mlsvc_release_user_info(user_info);
	}

	param->domain_table = domain_table;
	param->name_table.n_entry = n_entry;
	param->name_table.entries = names;
	param->mapped_count = n_entry;
	param->status = 0;

	mlsvc_free_user_info(user_info);
	return (MLRPC_DRC_OK);

lookup_sid_failed:
	param->domain_table = 0;
	param->name_table.n_entry = 0;
	param->name_table.entries = 0;
	param->mapped_count = 0;
	param->status = NT_SC_ERROR(result);

	mlsvc_free_user_info(user_info);
	return (MLRPC_DRC_OK);
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
lsarpc_s_UpdateDomainTable(struct mlrpc_xaction *mxa,
    smb_userinfo_t *user_info, struct mslsa_domain_table *domain_table,
    DWORD *domain_idx)
{
	struct mslsa_domain_entry *dentry;
	DWORD n_entry;
	DWORD i;

	if (user_info->sid_name_use == SidTypeUnknown ||
	    user_info->sid_name_use == SidTypeInvalid) {
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
		if (nt_sid_is_equal((nt_sid_t *)dentry[i].domain_sid,
		    user_info->domain_sid)) {
			*domain_idx = i;
			return (0);
		}
	}

	if (i == MLSVC_DOMAIN_MAX)
		return (-1);

	if (!mlsvc_string_save((ms_string_t *)&dentry[i].domain_name,
	    user_info->domain_name, mxa))
		return (-1);

	dentry[i].domain_sid =
	    (struct mslsa_sid *)mlsvc_sid_save(user_info->domain_sid, mxa);

	if (dentry[i].domain_sid == NULL)
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
 */
static int
lsarpc_s_LookupSids2(void *arg, struct mlrpc_xaction *mxa)
{
	struct lsar_lookup_sids2 *param = arg;
	struct lsar_name_entry2 *names;
	struct lsar_name_entry2 *name;
	struct mslsa_domain_table *domain_table;
	struct mslsa_domain_entry *domain_entry;
	smb_userinfo_t *user_info;
	nt_sid_t *sid;
	DWORD n_entry;
	int result;
	int i;

	user_info = mlsvc_alloc_user_info();

	n_entry = param->lup_sid_table.n_entry;
	names = MLRPC_HEAP_NEWN(mxa, struct lsar_name_entry2, n_entry);
	domain_table = MLRPC_HEAP_NEW(mxa, struct mslsa_domain_table);
	domain_entry = MLRPC_HEAP_NEWN(mxa, struct mslsa_domain_entry,
	    MLSVC_DOMAIN_MAX);

	if (names == NULL || domain_table == NULL ||
	    domain_entry == NULL || user_info == NULL) {
		bzero(param, sizeof (struct lsar_lookup_sids2));
		param->status = NT_SC_ERROR(NT_STATUS_NO_MEMORY);
		return (MLRPC_DRC_OK);
	}

	domain_table->entries = domain_entry;
	domain_table->n_entry = 0;
	domain_table->max_n_entry = MLSVC_DOMAIN_MAX;

	name = names;
	for (i = 0; i < n_entry; ++i, name++) {
		bzero(name, sizeof (struct lsar_name_entry2));
		sid = (nt_sid_t *)param->lup_sid_table.entries[i].psid;

		result = lsa_lookup_sid(sid, user_info);
		if (result != NT_STATUS_SUCCESS)
			goto lookup_sid_failed;

		if (!mlsvc_string_save((ms_string_t *)&name->name,
		    user_info->name, mxa)) {
			result = NT_STATUS_NO_MEMORY;
			goto lookup_sid_failed;
		}
		name->sid_name_use = user_info->sid_name_use;

		result = lsarpc_s_UpdateDomainTable(mxa, user_info,
		    domain_table, &name->domain_ix);

		if (result == -1) {
			result = NT_STATUS_INTERNAL_ERROR;
			goto lookup_sid_failed;
		}

		mlsvc_release_user_info(user_info);
	}

	param->domain_table = domain_table;
	param->name_table.n_entry = n_entry;
	param->name_table.entries = names;
	param->mapped_count = n_entry;
	param->status = 0;

	mlsvc_free_user_info(user_info);
	return (MLRPC_DRC_OK);

lookup_sid_failed:
	param->domain_table = 0;
	param->name_table.n_entry = 0;
	param->name_table.entries = 0;
	param->mapped_count = 0;
	param->status = NT_SC_ERROR(result);

	mlsvc_free_user_info(user_info);
	return (MLRPC_DRC_OK);
}

/*
 * lsarpc_s_LookupNames2
 *
 * Other than the use of lsar_LookupNames2 and lsar_rid_entry2, this
 * is identical to lsarpc_s_LookupNames.
 */
static int
lsarpc_s_LookupNames2(void *arg, struct mlrpc_xaction *mxa)
{
	struct lsar_LookupNames2 *param = arg;
	struct lsar_rid_entry2 *rids;
	smb_userinfo_t *user_info = 0;
	struct mslsa_domain_table *domain_table;
	struct mslsa_domain_entry *domain_entry;
	char *account;
	DWORD status = NT_STATUS_SUCCESS;
	int rc = 0;

	if (param->name_table->n_entry != 1)
		return (MLRPC_DRC_FAULT_PARAM_0_UNIMPLEMENTED);

	rids = MLRPC_HEAP_NEW(mxa, struct lsar_rid_entry2);
	domain_table = MLRPC_HEAP_NEW(mxa, struct mslsa_domain_table);
	domain_entry = MLRPC_HEAP_NEW(mxa, struct mslsa_domain_entry);
	user_info = mlsvc_alloc_user_info();

	if (rids == 0 || domain_table == 0 ||
	    domain_entry == 0 || user_info == 0) {
		status = NT_STATUS_NO_MEMORY;
		goto name_lookup2_failed;
	}

	account = (char *)param->name_table->names->str;
	status = lsa_lookup_name(NULL, account, SidTypeUnknown, user_info);
	if (status != NT_STATUS_SUCCESS)
		goto name_lookup2_failed;

	/*
	 * Set up the rid table.
	 */
	bzero(rids, sizeof (struct lsar_rid_entry2));
	rids[0].sid_name_use = user_info->sid_name_use;
	rids[0].rid = user_info->rid;
	rids[0].domain_index = 0;
	param->translated_sids.n_entry = 1;
	param->translated_sids.rids = rids;

	/*
	 * Set up the domain table.
	 */
	domain_table->entries = domain_entry;
	domain_table->n_entry = 1;
	domain_table->max_n_entry = MLSVC_DOMAIN_MAX;

	rc = mlsvc_string_save((ms_string_t *)&domain_entry->domain_name,
	    user_info->domain_name, mxa);

	domain_entry->domain_sid =
	    (struct mslsa_sid *)mlsvc_sid_save(user_info->domain_sid, mxa);

	if (rc == 0 || domain_entry->domain_sid == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto name_lookup2_failed;
	}

	param->domain_table = domain_table;
	param->mapped_count = 1;
	param->status = 0;

	mlsvc_free_user_info(user_info);
	return (MLRPC_DRC_OK);

name_lookup2_failed:
	mlsvc_free_user_info(user_info);
	bzero(param, sizeof (struct lsar_LookupNames2));
	param->status = NT_SC_ERROR(status);
	return (MLRPC_DRC_OK);
}
