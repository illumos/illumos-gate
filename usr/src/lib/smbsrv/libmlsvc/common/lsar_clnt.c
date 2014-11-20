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
 * Copyright 2012 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Local Security Authority RPC (LSAR) client-side interface.
 */

#include <sys/errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/libmlsvc.h>
#include <smbsrv/smbinfo.h>
#include <smbsrv/ntaccess.h>
#include <smbsrv/ntlocale.h>
#include <smbsrv/string.h>
#include <lsalib.h>

/*
 * The maximum number of bytes we are prepared to deal with in a
 * response.
 */
#define	MLSVC_MAX_RESPONSE_LEN		1024

/*
 * This structure is used when looking up names. We only lookup one
 * name at a time but the structure will allow for more.
 */
typedef struct lsa_names {
	uint32_t	n_entry;
	mslsa_string_t	name[8];
} lsa_names_t;

typedef DWORD (*lsar_nameop_t)(mlsvc_handle_t *, lsa_names_t *,
    smb_account_t *);

static uint32_t lsar_lookup_names1(mlsvc_handle_t *, lsa_names_t *,
    smb_account_t *);
static uint32_t lsar_lookup_names2(mlsvc_handle_t *, lsa_names_t *,
    smb_account_t *);
static uint32_t lsar_lookup_names3(mlsvc_handle_t *, lsa_names_t *,
    smb_account_t *);
static uint32_t lsar_lookup_sids1(mlsvc_handle_t *, lsa_sid_t *,
    smb_account_t *);
static uint32_t lsar_lookup_sids2(mlsvc_handle_t *, lsa_sid_t *,
    smb_account_t *account);

static char *lsar_get_username(const char *);
static void smb_account_trace(const smb_account_t *);

static void lsar_set_trusted_domains_ex(struct mslsa_EnumTrustedDomainBufEx *,
    smb_trusted_domains_t *);
static void lsar_set_trusted_domains(struct mslsa_EnumTrustedDomainBuf *,
    smb_trusted_domains_t *);

/*
 * lsar_open
 *
 * This is a wrapper round lsar_open_policy2 to ensure that we connect
 * using the appropriate domain information.
 *
 * If username argument is NULL, an anonymous connection will be established.
 * Otherwise, an authenticated connection will be established.
 *
 * On success 0 is returned. Otherwise a -ve error code.
 */
int
lsar_open(char *server, char *domain, char *username,
    mlsvc_handle_t *domain_handle)
{
	if (server == NULL || domain == NULL)
		return (-1);

	if (username == NULL)
		username = MLSVC_ANON_USER;

	return (lsar_open_policy2(server, domain, username, domain_handle));
}

/*
 * lsar_open_policy2
 *
 * Obtain an LSA policy handle. A policy handle is required to access
 * LSA resources on a remote server. The server name supplied here does
 * not need the double backslash prefix; it is added here. Call this
 * function via lsar_open to ensure that the appropriate connection is
 * in place.
 *
 * Returns 0 on success. Otherwise non-zero to indicate a failure.
 */
int
lsar_open_policy2(char *server, char *domain, char *username,
    mlsvc_handle_t *lsa_handle)
{
	struct mslsa_OpenPolicy2 arg;
	int opnum;
	int len;
	int rc;

	rc = ndr_rpc_bind(lsa_handle, server, domain, username, "LSARPC");
	if (rc != 0)
		return (-1);

	opnum = LSARPC_OPNUM_OpenPolicy2;
	bzero(&arg, sizeof (struct mslsa_OpenPolicy2));

	len = strlen(server) + 4;
	arg.servername = ndr_rpc_malloc(lsa_handle, len);
	if (arg.servername == NULL) {
		ndr_rpc_unbind(lsa_handle);
		return (-1);
	}

	(void) snprintf((char *)arg.servername, len, "\\\\%s", server);
	arg.attributes.length = sizeof (struct mslsa_object_attributes);
	arg.desiredAccess = MAXIMUM_ALLOWED;

	if ((rc = ndr_rpc_call(lsa_handle, opnum, &arg)) != 0) {
		ndr_rpc_unbind(lsa_handle);
		return (-1);
	}

	if (arg.status != 0) {
		rc = -1;
	} else {
		(void) memcpy(&lsa_handle->handle, &arg.domain_handle,
		    sizeof (ndr_hdid_t));

		if (ndr_is_null_handle(lsa_handle))
			rc = -1;
	}

	ndr_rpc_release(lsa_handle);

	if (rc != 0)
		ndr_rpc_unbind(lsa_handle);
	return (rc);
}

/*
 * lsar_open_account
 *
 * Obtain an LSA account handle. The lsa_handle must be a valid handle
 * obtained via lsar_open_policy2. The main thing to remember here is
 * to set up the context in the lsa_account_handle. I'm not sure what
 * the requirements are for desired access. Some values require admin
 * access.
 *
 * Returns 0 on success. Otherwise non-zero to indicate a failure.
 */
int
lsar_open_account(mlsvc_handle_t *lsa_handle, struct mslsa_sid *sid,
    mlsvc_handle_t *lsa_account_handle)
{
	struct mslsa_OpenAccount arg;
	int opnum;
	int rc;

	if (ndr_is_null_handle(lsa_handle) || sid == NULL)
		return (-1);

	opnum = LSARPC_OPNUM_OpenAccount;
	bzero(&arg, sizeof (struct mslsa_OpenAccount));

	(void) memcpy(&arg.handle, lsa_handle, sizeof (mslsa_handle_t));
	arg.sid = sid;
	arg.access_mask = STANDARD_RIGHTS_REQUIRED
#if 0
	    | POLICY_VIEW_AUDIT_INFORMATION
	    | POLICY_GET_PRIVATE_INFORMATION
	    | POLICY_TRUST_ADMIN
#endif
	    | POLICY_VIEW_LOCAL_INFORMATION;

	if ((rc = ndr_rpc_call(lsa_handle, opnum, &arg)) != 0)
		return (-1);

	if (arg.status != 0) {
		rc = -1;
	} else {
		ndr_inherit_handle(lsa_account_handle, lsa_handle);

		(void) memcpy(&lsa_account_handle->handle,
		    &arg.account_handle, sizeof (ndr_hdid_t));

		if (ndr_is_null_handle(lsa_account_handle))
			rc = -1;
	}

	ndr_rpc_release(lsa_handle);
	return (rc);
}

/*
 * lsar_close
 *
 * Close the LSA connection associated with the handle. The lsa_handle
 * must be a valid handle obtained via a call to lsar_open_policy2 or
 * lsar_open_account. On success the handle will be zeroed out to
 * ensure that it is not used again. If this is the top level handle
 * (i.e. the one obtained via lsar_open_policy2) the pipe is closed.
 *
 * Returns 0 on success. Otherwise non-zero to indicate a failure.
 */
int
lsar_close(mlsvc_handle_t *lsa_handle)
{
	struct mslsa_CloseHandle arg;
	int opnum;

	if (ndr_is_null_handle(lsa_handle))
		return (-1);

	opnum = LSARPC_OPNUM_CloseHandle;
	bzero(&arg, sizeof (struct mslsa_CloseHandle));
	(void) memcpy(&arg.handle, lsa_handle, sizeof (mslsa_handle_t));

	(void) ndr_rpc_call(lsa_handle, opnum, &arg);
	ndr_rpc_release(lsa_handle);

	if (ndr_is_bind_handle(lsa_handle))
		ndr_rpc_unbind(lsa_handle);

	bzero(lsa_handle, sizeof (mlsvc_handle_t));
	return (0);
}

/*
 * lsar_query_security_desc
 *
 * Don't use this call yet. It is just a place holder for now.
 */
int
lsar_query_security_desc(mlsvc_handle_t *lsa_handle)
{
	struct mslsa_QuerySecurityObject	arg;
	int	rc;
	int	opnum;

	opnum = LSARPC_OPNUM_QuerySecurityObject;

	bzero(&arg, sizeof (struct mslsa_QuerySecurityObject));
	(void) memcpy(&arg.handle, lsa_handle, sizeof (mslsa_handle_t));

	rc = ndr_rpc_call(lsa_handle, opnum, &arg);
	ndr_rpc_release(lsa_handle);
	return (rc);
}

/*
 * lsar_query_info_policy
 *
 * The general purpose of this function is to allow various pieces of
 * information to be queried on the domain controller. The only
 * information queries supported are MSLSA_POLICY_PRIMARY_DOMAIN_INFO
 * and MSLSA_POLICY_ACCOUNT_DOMAIN_INFO.
 *
 * On success, the return code will be 0 and the user_info structure
 * will be set up. The sid_name_use field will be set to SidTypeDomain
 * indicating that the domain name and domain sid fields are vaild. If
 * the infoClass returned from the server is not one of the supported
 * values, the sid_name_use willbe set to SidTypeUnknown. If the RPC
 * fails, a negative error code will be returned, in which case the
 * user_info will not have been updated.
 */
DWORD
lsar_query_info_policy(mlsvc_handle_t *lsa_handle, WORD infoClass,
    smb_domain_t *info)
{
	struct mslsa_QueryInfoPolicy	arg;
	struct mslsa_PrimaryDomainInfo	*pd_info;
	struct mslsa_AccountDomainInfo	*ad_info;
	struct mslsa_DnsDomainInfo	*dns_info;
	char	guid_str[UUID_PRINTABLE_STRING_LENGTH];
	char	sidstr[SMB_SID_STRSZ];
	int	opnum;
	DWORD	status;

	if (lsa_handle == NULL || info == NULL)
		return (NT_STATUS_INVALID_PARAMETER);

	opnum = LSARPC_OPNUM_QueryInfoPolicy;

	bzero(info, sizeof (smb_domain_t));
	bzero(&arg, sizeof (struct mslsa_QueryInfoPolicy));
	(void) memcpy(&arg.handle, lsa_handle, sizeof (mslsa_handle_t));

	arg.info_class = infoClass;

	if (ndr_rpc_call(lsa_handle, opnum, &arg) != 0) {
		status = NT_STATUS_INVALID_PARAMETER;
	} else if (arg.status != 0) {
		ndr_rpc_status(lsa_handle, opnum, arg.status);
		status = NT_SC_VALUE(arg.status);
	} else {

		switch (infoClass) {
		case MSLSA_POLICY_PRIMARY_DOMAIN_INFO:
			pd_info = &arg.ru.pd_info;

			smb_sid_tostr((smb_sid_t *)pd_info->sid, sidstr);
			info->di_type = SMB_DOMAIN_PRIMARY;
			smb_domain_set_basic_info(sidstr,
			    (char *)pd_info->name.str, "", info);

			status = NT_STATUS_SUCCESS;
			break;

		case MSLSA_POLICY_ACCOUNT_DOMAIN_INFO:
			ad_info = &arg.ru.ad_info;

			smb_sid_tostr((smb_sid_t *)ad_info->sid, sidstr);
			info->di_type = SMB_DOMAIN_ACCOUNT;
			smb_domain_set_basic_info(sidstr,
			    (char *)ad_info->name.str, "", info);

			status = NT_STATUS_SUCCESS;
			break;

		case MSLSA_POLICY_DNS_DOMAIN_INFO:
			dns_info = &arg.ru.dns_info;
			ndr_uuid_unparse((ndr_uuid_t *)&dns_info->guid,
			    guid_str);
			smb_sid_tostr((smb_sid_t *)dns_info->sid, sidstr);

			info->di_type = SMB_DOMAIN_PRIMARY;
			smb_domain_set_dns_info(sidstr,
			    (char *)dns_info->nb_domain.str,
			    (char *)dns_info->dns_domain.str,
			    (char *)dns_info->forest.str,
			    guid_str, info);
			status = NT_STATUS_SUCCESS;
			break;

		default:
			status = NT_STATUS_INVALID_INFO_CLASS;
			break;
		}
	}

	ndr_rpc_release(lsa_handle);
	return (status);
}

/*
 * Lookup a name and obtain the sid/rid.
 * This is a wrapper for the various lookup sid RPCs.
 */
uint32_t
lsar_lookup_names(mlsvc_handle_t *lsa_handle, char *name, smb_account_t *info)
{
	static lsar_nameop_t ops[] = {
		lsar_lookup_names3,
		lsar_lookup_names2,
		lsar_lookup_names1
	};

	const srvsvc_server_info_t	*svinfo;
	lsa_names_t	names;
	char		*p;
	uint32_t	length;
	uint32_t	status = NT_STATUS_INVALID_PARAMETER;
	int		n_op = (sizeof (ops) / sizeof (ops[0]));
	int		i;

	if (lsa_handle == NULL || name == NULL || info == NULL)
		return (NT_STATUS_INVALID_PARAMETER);

	bzero(info, sizeof (smb_account_t));

	svinfo = ndr_rpc_server_info(lsa_handle);
	if (svinfo->sv_os == NATIVE_OS_WIN2000 &&
	    svinfo->sv_version_major == 5 && svinfo->sv_version_minor == 0) {
		/*
		 * Windows 2000 doesn't like an LSA lookup for
		 * DOMAIN\Administrator.
		 */
		if ((p = strchr(name, '\\')) != 0) {
			++p;

			if (strcasecmp(p, "administrator") == 0)
				name = p;
		}

	}

	length = smb_wcequiv_strlen(name);
	names.name[0].length = length;
	names.name[0].allosize = length;
	names.name[0].str = (unsigned char *)name;
	names.n_entry = 1;

	if (ndr_rpc_server_os(lsa_handle) == NATIVE_OS_WIN2000) {
		for (i = 0; i < n_op; ++i) {
			ndr_rpc_set_nonull(lsa_handle);
			status = (*ops[i])(lsa_handle, &names, info);

			if (status != NT_STATUS_INVALID_PARAMETER)
				break;
		}
	} else {
		ndr_rpc_set_nonull(lsa_handle);
		status = lsar_lookup_names1(lsa_handle, &names, info);
	}

	if (status == NT_STATUS_SUCCESS) {
		info->a_name = lsar_get_username(name);

		if (!smb_account_validate(info)) {
			smb_account_free(info);
			status = NT_STATUS_NO_MEMORY;
		} else {
			smb_account_trace(info);
		}
	}

	return (status);
}

/*
 * The name may be in one of the following forms:
 *
 *	domain\username
 *	domain/username
 *	username
 *	username@domain
 *
 * Return a strdup'd copy of the username.  The caller is responsible
 * for freeing the allocated memory.
 */
static char *
lsar_get_username(const char *name)
{
	char	tmp[MAXNAMELEN];
	char	*dp = NULL;
	char	*np = NULL;

	(void) strlcpy(tmp, name, MAXNAMELEN);
	smb_name_parse(tmp, &np, &dp);

	if (dp != NULL && np != NULL)
		return (strdup(np));
	else
		return (strdup(name));
}

/*
 * lsar_lookup_names1
 *
 * Lookup a name and obtain the domain and user rid.
 *
 * Note: NT returns an error if the mapped_count is non-zero when the RPC
 * is called.
 *
 * If the lookup fails, the status will typically be NT_STATUS_NONE_MAPPED.
 */
static uint32_t
lsar_lookup_names1(mlsvc_handle_t *lsa_handle, lsa_names_t *names,
    smb_account_t *info)
{
	struct mslsa_LookupNames	arg;
	struct mslsa_rid_entry		*rid_entry;
	struct mslsa_domain_entry	*domain_entry;
	uint32_t			status = NT_STATUS_SUCCESS;
	char				*domname;
	int				opnum = LSARPC_OPNUM_LookupNames;

	bzero(&arg, sizeof (struct mslsa_LookupNames));
	(void) memcpy(&arg.handle, lsa_handle, sizeof (mslsa_handle_t));
	arg.lookup_level = LSA_LOOKUP_WKSTA;
	arg.name_table = (struct mslsa_lup_name_table *)names;

	if (ndr_rpc_call(lsa_handle, opnum, &arg) != 0) {
		ndr_rpc_release(lsa_handle);
		return (NT_STATUS_INVALID_PARAMETER);
	}

	if (arg.status != NT_STATUS_SUCCESS) {
		ndr_rpc_status(lsa_handle, opnum, arg.status);
		ndr_rpc_release(lsa_handle);
		return (NT_SC_VALUE(arg.status));
	}

	if (arg.mapped_count == 0) {
		ndr_rpc_release(lsa_handle);
		return (NT_STATUS_NONE_MAPPED);
	}

	rid_entry = &arg.translated_sids.rids[0];
	if (rid_entry->domain_index != 0) {
		ndr_rpc_release(lsa_handle);
		return (NT_STATUS_NONE_MAPPED);
	}

	domain_entry = &arg.domain_table->entries[0];

	info->a_type = rid_entry->sid_name_use;
	info->a_domsid = smb_sid_dup((smb_sid_t *)domain_entry->domain_sid);
	if ((domname = (char *)domain_entry->domain_name.str) != NULL)
		info->a_domain = strdup(domname);
	info->a_rid = rid_entry->rid;
	info->a_sid = smb_sid_splice(info->a_domsid, info->a_rid);

	ndr_rpc_release(lsa_handle);
	return (status);
}

/*
 * lsar_lookup_names2
 */
static uint32_t
lsar_lookup_names2(mlsvc_handle_t *lsa_handle, lsa_names_t *names,
    smb_account_t *info)
{
	struct lsar_LookupNames2	arg;
	struct lsar_rid_entry2		*rid_entry;
	struct mslsa_domain_entry	*domain_entry;
	uint32_t			status = NT_STATUS_SUCCESS;
	char				*domname;
	int				opnum = LSARPC_OPNUM_LookupNames2;

	bzero(&arg, sizeof (struct lsar_LookupNames2));
	(void) memcpy(&arg.policy_handle, lsa_handle, sizeof (mslsa_handle_t));
	arg.lookup_level = LSA_LOOKUP_WKSTA;
	arg.client_revision = LSA_CLIENT_REVISION_AD;
	arg.name_table = (struct mslsa_lup_name_table *)names;

	if (ndr_rpc_call(lsa_handle, opnum, &arg) != 0) {
		ndr_rpc_release(lsa_handle);
		return (NT_STATUS_INVALID_PARAMETER);
	}

	if (arg.status != NT_STATUS_SUCCESS) {
		ndr_rpc_status(lsa_handle, opnum, arg.status);
		ndr_rpc_release(lsa_handle);
		return (NT_SC_VALUE(arg.status));
	}

	if (arg.mapped_count == 0) {
		ndr_rpc_release(lsa_handle);
		return (NT_STATUS_NONE_MAPPED);
	}

	rid_entry = &arg.translated_sids.rids[0];
	if (rid_entry->domain_index != 0) {
		ndr_rpc_release(lsa_handle);
		return (NT_STATUS_NONE_MAPPED);
	}

	domain_entry = &arg.domain_table->entries[0];

	info->a_type = rid_entry->sid_name_use;
	info->a_domsid = smb_sid_dup((smb_sid_t *)domain_entry->domain_sid);
	if ((domname = (char *)domain_entry->domain_name.str) != NULL)
		info->a_domain = strdup(domname);
	info->a_rid = rid_entry->rid;
	info->a_sid = smb_sid_splice(info->a_domsid, info->a_rid);

	ndr_rpc_release(lsa_handle);
	return (status);
}

/*
 * lsar_lookup_names3
 */
static uint32_t
lsar_lookup_names3(mlsvc_handle_t *lsa_handle, lsa_names_t *names,
    smb_account_t *info)
{
	struct lsar_LookupNames3	arg;
	lsar_translated_sid_ex2_t	*sid_entry;
	struct mslsa_domain_entry	*domain_entry;
	uint32_t			status = NT_STATUS_SUCCESS;
	char				*domname;
	int				opnum = LSARPC_OPNUM_LookupNames3;

	bzero(&arg, sizeof (struct lsar_LookupNames3));
	(void) memcpy(&arg.policy_handle, lsa_handle, sizeof (mslsa_handle_t));
	arg.lookup_level = LSA_LOOKUP_WKSTA;
	arg.client_revision = LSA_CLIENT_REVISION_AD;
	arg.name_table = (struct mslsa_lup_name_table *)names;

	if (ndr_rpc_call(lsa_handle, opnum, &arg) != 0) {
		ndr_rpc_release(lsa_handle);
		return (NT_STATUS_INVALID_PARAMETER);
	}

	if (arg.status != NT_STATUS_SUCCESS) {
		ndr_rpc_status(lsa_handle, opnum, arg.status);
		ndr_rpc_release(lsa_handle);
		return (NT_SC_VALUE(arg.status));
	}

	if (arg.mapped_count == 0) {
		ndr_rpc_release(lsa_handle);
		return (NT_STATUS_NONE_MAPPED);
	}

	sid_entry = &arg.translated_sids.sids[0];
	if (sid_entry->domain_index != 0) {
		ndr_rpc_release(lsa_handle);
		return (NT_STATUS_NONE_MAPPED);
	}

	domain_entry = &arg.domain_table->entries[0];

	info->a_type = sid_entry->sid_name_use;
	info->a_domsid = smb_sid_dup((smb_sid_t *)domain_entry->domain_sid);
	if ((domname = (char *)domain_entry->domain_name.str) != NULL)
		info->a_domain = strdup(domname);
	info->a_sid = smb_sid_dup((smb_sid_t *)sid_entry->sid);
	(void) smb_sid_getrid(info->a_sid, &info->a_rid);

	ndr_rpc_release(lsa_handle);
	return (status);
}

/*
 * lsar_lookup_names4
 *
 * This function is only valid if the remote RPC server is a domain
 * controller and requires the security extensions defined in MS-RPCE.
 *
 * Domain controllers will return RPC_NT_PROTSEQ_NOT_SUPPORTED here
 * because we don't support the RPC_C_AUTHN_NETLOGON security provider.
 * Non-domain controllers will return NT_STATUS_INVALID_SERVER_STATE.
 */
static uint32_t /*LINTED E_STATIC_UNUSED*/
lsar_lookup_names4(mlsvc_handle_t *lsa_handle, lsa_names_t *names,
    smb_account_t *info)
{
	struct lsar_LookupNames4	arg;
	lsar_translated_sid_ex2_t	*sid_entry;
	struct mslsa_domain_entry	*domain_entry;
	uint32_t			status = NT_STATUS_SUCCESS;
	char				*domname;
	int				opnum = LSARPC_OPNUM_LookupNames4;

	bzero(&arg, sizeof (struct lsar_LookupNames4));
	arg.lookup_level = LSA_LOOKUP_WKSTA;
	arg.client_revision = LSA_CLIENT_REVISION_AD;
	arg.name_table = (struct mslsa_lup_name_table *)names;

	if (ndr_rpc_call(lsa_handle, opnum, &arg) != 0) {
		ndr_rpc_release(lsa_handle);
		return (NT_STATUS_INVALID_PARAMETER);
	}

	if (arg.status != NT_STATUS_SUCCESS) {
		ndr_rpc_status(lsa_handle, opnum, arg.status);
		ndr_rpc_release(lsa_handle);
		if (arg.status == RPC_NT_PROTSEQ_NOT_SUPPORTED ||
		    arg.status == NT_STATUS_INVALID_SERVER_STATE)
			return (NT_STATUS_INVALID_PARAMETER);
		return (NT_SC_VALUE(arg.status));
	}

	if (arg.mapped_count == 0) {
		ndr_rpc_release(lsa_handle);
		return (NT_STATUS_NONE_MAPPED);
	}

	sid_entry = &arg.translated_sids.sids[0];
	if (sid_entry->domain_index != 0) {
		ndr_rpc_release(lsa_handle);
		return (NT_STATUS_NONE_MAPPED);
	}

	domain_entry = &arg.domain_table->entries[0];

	info->a_type = sid_entry->sid_name_use;
	info->a_domsid = smb_sid_dup((smb_sid_t *)domain_entry->domain_sid);
	if ((domname = (char *)domain_entry->domain_name.str) != NULL)
		info->a_domain = strdup(domname);
	info->a_sid = smb_sid_dup((smb_sid_t *)sid_entry->sid);
	(void) smb_sid_getrid(info->a_sid, &info->a_rid);

	ndr_rpc_release(lsa_handle);
	return (status);
}

/*
 * Lookup a sid and obtain the domain sid and account name.
 * This is a wrapper for the various lookup sid RPCs.
 */
uint32_t
lsar_lookup_sids(mlsvc_handle_t *lsa_handle, smb_sid_t *sid,
    smb_account_t *account)
{
	char		sidbuf[SMB_SID_STRSZ];
	uint32_t	status;

	if (lsa_handle == NULL || sid == NULL || account == NULL)
		return (NT_STATUS_INVALID_PARAMETER);

	bzero(account, sizeof (smb_account_t));
	bzero(sidbuf, SMB_SID_STRSZ);
	smb_sid_tostr(sid, sidbuf);
	smb_tracef("%s", sidbuf);

	if (ndr_rpc_server_os(lsa_handle) == NATIVE_OS_WIN2000)
		status = lsar_lookup_sids2(lsa_handle, (lsa_sid_t *)sid,
		    account);
	else
		status = lsar_lookup_sids1(lsa_handle, (lsa_sid_t *)sid,
		    account);

	if (status == NT_STATUS_SUCCESS) {
		if (!smb_account_validate(account)) {
			smb_account_free(account);
			status = NT_STATUS_NO_MEMORY;
		} else {
			smb_account_trace(account);
		}
	}

	return (status);
}

/*
 * lsar_lookup_sids1
 */
static uint32_t
lsar_lookup_sids1(mlsvc_handle_t *lsa_handle, lsa_sid_t *sid,
    smb_account_t *account)
{
	struct mslsa_LookupSids		arg;
	struct mslsa_lup_sid_entry	sid_entry;
	struct mslsa_name_entry		*name_entry;
	struct mslsa_domain_entry	*domain_entry;
	uint32_t			status = NT_STATUS_SUCCESS;
	char				*name;
	int				opnum = LSARPC_OPNUM_LookupSids;

	bzero(&arg, sizeof (struct mslsa_LookupSids));
	(void) memcpy(&arg.handle, lsa_handle, sizeof (mslsa_handle_t));
	arg.lookup_level = LSA_LOOKUP_WKSTA;

	sid_entry.psid = sid;
	arg.lup_sid_table.n_entry = 1;
	arg.lup_sid_table.entries = &sid_entry;

	if (ndr_rpc_call(lsa_handle, opnum, &arg) != 0) {
		ndr_rpc_release(lsa_handle);
		return (NT_STATUS_INVALID_PARAMETER);
	}

	if (arg.status != NT_STATUS_SUCCESS) {
		ndr_rpc_status(lsa_handle, opnum, arg.status);
		ndr_rpc_release(lsa_handle);
		return (NT_SC_VALUE(arg.status));
	}

	if (arg.mapped_count == 0) {
		ndr_rpc_release(lsa_handle);
		return (NT_STATUS_NONE_MAPPED);
	}

	name_entry = &arg.name_table.entries[0];
	if (name_entry->domain_ix != 0) {
		ndr_rpc_release(lsa_handle);
		return (NT_STATUS_NONE_MAPPED);
	}

	name = (char *)name_entry->name.str;
	account->a_name = (name) ? strdup(name) : strdup("");
	account->a_type = name_entry->sid_name_use;
	account->a_sid = smb_sid_dup((smb_sid_t *)sid);
	(void) smb_sid_getrid(account->a_sid, &account->a_rid);

	domain_entry = &arg.domain_table->entries[0];
	if ((name = (char *)domain_entry->domain_name.str) != NULL)
		account->a_domain = strdup(name);
	account->a_domsid = smb_sid_dup((smb_sid_t *)domain_entry->domain_sid);

	ndr_rpc_release(lsa_handle);
	return (status);
}

/*
 * lsar_lookup_sids2
 */
static uint32_t
lsar_lookup_sids2(mlsvc_handle_t *lsa_handle, lsa_sid_t *sid,
    smb_account_t *account)
{
	struct lsar_lookup_sids2	arg;
	struct lsar_name_entry2		*name_entry;
	struct mslsa_lup_sid_entry	sid_entry;
	struct mslsa_domain_entry	*domain_entry;
	uint32_t			status = NT_STATUS_SUCCESS;
	char				*name;
	int				opnum = LSARPC_OPNUM_LookupSids2;

	bzero(&arg, sizeof (struct lsar_lookup_sids2));
	(void) memcpy(&arg.policy_handle, lsa_handle, sizeof (mslsa_handle_t));

	sid_entry.psid = sid;
	arg.lup_sid_table.n_entry = 1;
	arg.lup_sid_table.entries = &sid_entry;
	arg.lookup_level = LSA_LOOKUP_WKSTA;
	arg.client_revision = LSA_CLIENT_REVISION_AD;

	if (ndr_rpc_call(lsa_handle, opnum, &arg) != 0) {
		ndr_rpc_release(lsa_handle);
		return (NT_STATUS_INVALID_PARAMETER);
	}

	if (arg.status != NT_STATUS_SUCCESS) {
		ndr_rpc_status(lsa_handle, opnum, arg.status);
		ndr_rpc_release(lsa_handle);
		return (NT_SC_VALUE(arg.status));
	}

	if (arg.mapped_count == 0) {
		ndr_rpc_release(lsa_handle);
		return (NT_STATUS_NONE_MAPPED);
	}

	name_entry = &arg.name_table.entries[0];
	if (name_entry->domain_ix != 0) {
		ndr_rpc_release(lsa_handle);
		return (NT_STATUS_NONE_MAPPED);
	}

	name = (char *)name_entry->name.str;
	account->a_name = (name) ? strdup(name) : strdup("");
	account->a_type = name_entry->sid_name_use;
	account->a_sid = smb_sid_dup((smb_sid_t *)sid);
	(void) smb_sid_getrid(account->a_sid, &account->a_rid);

	domain_entry = &arg.domain_table->entries[0];
	if ((name = (char *)domain_entry->domain_name.str) != NULL)
		account->a_domain = strdup(name);
	account->a_domsid = smb_sid_dup((smb_sid_t *)domain_entry->domain_sid);

	ndr_rpc_release(lsa_handle);
	return (status);
}

/*
 * lsar_lookup_sids3
 *
 * This function is only valid if the remote RPC server is a domain
 * controller and requires the security extensions defined in MS-RPCE.
 *
 * Domain controllers will return RPC_NT_PROTSEQ_NOT_SUPPORTED here
 * because we don't support the RPC_C_AUTHN_NETLOGON security provider.
 * Non-domain controllers will return NT_STATUS_INVALID_SERVER_STATE.
 */
static uint32_t /*LINTED E_STATIC_UNUSED*/
lsar_lookup_sids3(mlsvc_handle_t *lsa_handle, lsa_sid_t *sid,
    smb_account_t *account)
{
	struct lsar_lookup_sids3	arg;
	lsar_translated_name_ex_t	*name_entry;
	struct mslsa_lup_sid_entry	sid_entry;
	struct mslsa_domain_entry	*domain_entry;
	uint32_t			status = NT_STATUS_SUCCESS;
	char				*name;
	int				opnum = LSARPC_OPNUM_LookupSids3;

	bzero(&arg, sizeof (struct lsar_lookup_sids3));

	sid_entry.psid = sid;
	arg.lup_sid_table.n_entry = 1;
	arg.lup_sid_table.entries = &sid_entry;
	arg.lookup_level = LSA_LOOKUP_WKSTA;
	arg.client_revision = LSA_CLIENT_REVISION_AD;

	if (ndr_rpc_call(lsa_handle, opnum, &arg) != 0) {
		ndr_rpc_release(lsa_handle);
		return (NT_STATUS_INVALID_PARAMETER);
	}

	if (arg.status != NT_STATUS_SUCCESS) {
		ndr_rpc_status(lsa_handle, opnum, arg.status);
		ndr_rpc_release(lsa_handle);
		if (arg.status == RPC_NT_PROTSEQ_NOT_SUPPORTED ||
		    arg.status == NT_STATUS_INVALID_SERVER_STATE)
			return (NT_STATUS_INVALID_PARAMETER);
		return (NT_SC_VALUE(arg.status));
	}

	if (arg.mapped_count == 0) {
		ndr_rpc_release(lsa_handle);
		return (NT_STATUS_NONE_MAPPED);
	}

	name_entry = &arg.name_table.entries[0];
	if (name_entry->domain_ix != 0) {
		ndr_rpc_release(lsa_handle);
		return (NT_STATUS_NONE_MAPPED);
	}

	name = (char *)name_entry->name.str;
	account->a_name = (name) ? strdup(name) : strdup("");
	account->a_type = name_entry->sid_name_use;
	account->a_sid = smb_sid_dup((smb_sid_t *)sid);
	(void) smb_sid_getrid(account->a_sid, &account->a_rid);

	domain_entry = &arg.domain_table->entries[0];
	if ((name = (char *)domain_entry->domain_name.str) != NULL)
		account->a_domain = strdup(name);
	account->a_domsid = smb_sid_dup((smb_sid_t *)domain_entry->domain_sid);

	ndr_rpc_release(lsa_handle);
	return (status);
}

/*
 * lsar_enum_accounts
 *
 * Enumerate the list of accounts (i.e. SIDs). Use the handle returned
 * from lsa_open_policy2. The enum_context is used to support multiple
 * calls to this enumeration function. It should be set to 0 on the
 * first call. It will be updated by the domain controller and should
 * simply be passed unchanged to subsequent calls until there are no
 * more accounts. A warning status of 0x1A indicates that no more data
 * is available. The list of accounts will be returned in accounts.
 * This list is dynamically allocated using malloc, it should be freed
 * by the caller when it is no longer required.
 */
int
lsar_enum_accounts(mlsvc_handle_t *lsa_handle, DWORD *enum_context,
    struct mslsa_EnumAccountBuf *accounts)
{
	struct mslsa_EnumerateAccounts	arg;
	struct mslsa_AccountInfo	*info;
	int	opnum;
	int	rc;
	DWORD	n_entries;
	DWORD	i;
	int	nbytes;

	if (lsa_handle == NULL || enum_context == NULL || accounts == NULL)
		return (-1);

	accounts->entries_read = 0;
	accounts->info = 0;

	opnum = LSARPC_OPNUM_EnumerateAccounts;

	bzero(&arg, sizeof (struct mslsa_EnumerateAccounts));
	(void) memcpy(&arg.handle, lsa_handle, sizeof (mslsa_handle_t));
	arg.enum_context = *enum_context;
	arg.max_length = MLSVC_MAX_RESPONSE_LEN;

	rc = ndr_rpc_call(lsa_handle, opnum, &arg);
	if (rc == 0) {
		if (arg.status != 0) {
			if (arg.status == NT_STATUS_NO_MORE_ENTRIES) {
				*enum_context = arg.enum_context;
			} else {
				ndr_rpc_status(lsa_handle, opnum, arg.status);
				rc = -1;
			}
		} else if (arg.enum_buf->entries_read != 0) {
			n_entries = arg.enum_buf->entries_read;
			nbytes = n_entries * sizeof (struct mslsa_AccountInfo);

			if ((info = malloc(nbytes)) == NULL) {
				ndr_rpc_release(lsa_handle);
				return (-1);
			}

			for (i = 0; i < n_entries; ++i)
				info[i].sid = (lsa_sid_t *)smb_sid_dup(
				    (smb_sid_t *)arg.enum_buf->info[i].sid);

			accounts->entries_read = n_entries;
			accounts->info = info;
			*enum_context = arg.enum_context;
		}
	}

	ndr_rpc_release(lsa_handle);
	return (rc);
}

/*
 * lsar_enum_trusted_domains
 *
 * Enumerate the list of trusted domains. Use the handle returned from
 * lsa_open_policy2. The enum_context is used to support multiple calls
 * to this enumeration function. It should be set to 0 on the first
 * call. It will be updated by the domain controller and should simply
 * be passed unchanged to subsequent calls until there are no more
 * domains.
 *
 * The trusted domains aren't actually returned here. They are added
 * to the NT domain database. After all of the trusted domains have
 * been discovered, the database can be interrogated to find all of
 * the trusted domains.
 */
DWORD
lsar_enum_trusted_domains(mlsvc_handle_t *lsa_handle, DWORD *enum_context,
    smb_trusted_domains_t *list)
{
	struct mslsa_EnumTrustedDomain	arg;
	int	opnum;
	DWORD	status;

	if (list == NULL)
		return (NT_STATUS_INVALID_PARAMETER);

	opnum = LSARPC_OPNUM_EnumTrustedDomain;

	bzero(list, sizeof (smb_trusted_domains_t));
	bzero(&arg, sizeof (struct mslsa_EnumTrustedDomain));
	(void) memcpy(&arg.handle, lsa_handle, sizeof (mslsa_handle_t));
	arg.enum_context = *enum_context;
	arg.max_length = MLSVC_MAX_RESPONSE_LEN;

	if (ndr_rpc_call(lsa_handle, opnum, &arg) != 0) {
		status = NT_STATUS_INVALID_PARAMETER;
	} else if (arg.status != 0) {
		*enum_context = arg.enum_context;
		status = NT_SC_VALUE(arg.status);

		/*
		 * STATUS_NO_MORE_ENTRIES provides call
		 * status but does not indicate an error.
		 */
		if (status != NT_STATUS_NO_MORE_ENTRIES)
			ndr_rpc_status(lsa_handle, opnum, arg.status);
	} else if (arg.enum_buf->entries_read == 0) {
		*enum_context = arg.enum_context;
		status = 0;
	} else {
		lsar_set_trusted_domains(arg.enum_buf, list);
		*enum_context = arg.enum_context;
		status = 0;
	}

	ndr_rpc_release(lsa_handle);
	return (status);
}

DWORD
lsar_enum_trusted_domains_ex(mlsvc_handle_t *lsa_handle, DWORD *enum_context,
    smb_trusted_domains_t *list)
{
	struct mslsa_EnumTrustedDomainEx	arg;
	int	opnum;
	DWORD	status;

	if (list == NULL)
		return (NT_STATUS_INVALID_PARAMETER);

	opnum = LSARPC_OPNUM_EnumTrustedDomainsEx;

	bzero(list, sizeof (smb_trusted_domains_t));
	bzero(&arg, sizeof (struct mslsa_EnumTrustedDomainEx));
	(void) memcpy(&arg.handle, lsa_handle, sizeof (mslsa_handle_t));
	arg.enum_context = *enum_context;
	arg.max_length = MLSVC_MAX_RESPONSE_LEN;

	if (ndr_rpc_call(lsa_handle, opnum, &arg) != 0) {
		status = NT_STATUS_INVALID_PARAMETER;
	} else if (arg.status != 0) {
		*enum_context = arg.enum_context;
		status = NT_SC_VALUE(arg.status);

		/*
		 * STATUS_NO_MORE_ENTRIES provides call
		 * status but does not indicate an error.
		 */
		if (status != NT_STATUS_NO_MORE_ENTRIES)
			ndr_rpc_status(lsa_handle, opnum, arg.status);
	} else if (arg.enum_buf->entries_read == 0) {
		*enum_context = arg.enum_context;
		status = 0;
	} else {
		lsar_set_trusted_domains_ex(arg.enum_buf, list);
		*enum_context = arg.enum_context;
		status = 0;
	}

	ndr_rpc_release(lsa_handle);
	return (status);
}

/*
 * lsar_enum_privs_account
 *
 * Privileges enum? Need an account handle.
 */
/*ARGSUSED*/
int
lsar_enum_privs_account(mlsvc_handle_t *account_handle, smb_account_t *account)
{
	struct mslsa_EnumPrivsAccount	arg;
	int	opnum;
	int	rc;

	opnum = LSARPC_OPNUM_EnumPrivsAccount;

	bzero(&arg, sizeof (struct mslsa_EnumPrivsAccount));
	(void) memcpy(&arg.account_handle, &account_handle->handle,
	    sizeof (mslsa_handle_t));

	rc = ndr_rpc_call(account_handle, opnum, &arg);
	if ((rc == 0) && (arg.status != 0)) {
		ndr_rpc_status(account_handle, opnum, arg.status);
		rc = -1;
	}
	ndr_rpc_release(account_handle);
	return (rc);
}

/*
 * lsar_lookup_priv_value
 *
 * Map a privilege name to a local unique id (LUID). Privilege names
 * are consistent across the network. LUIDs are machine specific.
 * This function provides the means to map a privilege name to the
 * LUID used by a remote server to represent it. The handle here is
 * a policy handle.
 */
int
lsar_lookup_priv_value(mlsvc_handle_t *lsa_handle, char *name,
    struct ms_luid *luid)
{
	struct mslsa_LookupPrivValue	arg;
	int	opnum;
	int	rc;
	size_t	length;

	if (lsa_handle == NULL || name == NULL || luid == NULL)
		return (-1);

	opnum = LSARPC_OPNUM_LookupPrivValue;

	bzero(&arg, sizeof (struct mslsa_LookupPrivValue));
	(void) memcpy(&arg.handle, lsa_handle, sizeof (mslsa_handle_t));

	length = smb_wcequiv_strlen(name);
	if (ndr_rpc_server_os(lsa_handle) == NATIVE_OS_WIN2000)
		length += sizeof (smb_wchar_t);

	arg.name.length = length;
	arg.name.allosize = length;
	arg.name.str = (unsigned char *)name;

	rc = ndr_rpc_call(lsa_handle, opnum, &arg);
	if (rc == 0) {
		if (arg.status != 0)
			rc = -1;
		else
			(void) memcpy(luid, &arg.luid, sizeof (struct ms_luid));
	}

	ndr_rpc_release(lsa_handle);
	return (rc);
}

/*
 * lsar_lookup_priv_name
 *
 * Map a local unique id (LUID) to a privilege name. Privilege names
 * are consistent across the network. LUIDs are machine specific.
 * This function the means to map the LUID used by a remote server to
 * the appropriate privilege name. The handle here is a policy handle.
 */
int
lsar_lookup_priv_name(mlsvc_handle_t *lsa_handle, struct ms_luid *luid,
    char *name, int namelen)
{
	struct mslsa_LookupPrivName	arg;
	int	opnum;
	int	rc;

	if (lsa_handle == NULL || luid == NULL || name == NULL)
		return (-1);

	opnum = LSARPC_OPNUM_LookupPrivName;

	bzero(&arg, sizeof (struct mslsa_LookupPrivName));
	(void) memcpy(&arg.handle, lsa_handle, sizeof (mslsa_handle_t));
	(void) memcpy(&arg.luid, luid, sizeof (struct ms_luid));

	rc = ndr_rpc_call(lsa_handle, opnum, &arg);
	if (rc == 0) {
		if (arg.status != 0)
			rc = -1;
		else
			(void) strlcpy(name, (char const *)arg.name->str,
			    namelen);
	}

	ndr_rpc_release(lsa_handle);
	return (rc);
}

/*
 * lsar_lookup_priv_display_name
 *
 * Map a privilege name to a privilege display name. The input handle
 * should be an LSA policy handle and the name would normally be one
 * of the privileges defined in smb_privilege.h
 *
 * There's something peculiar about the return status from NT servers,
 * it's not always present. So for now, I'm ignoring the status in the
 * RPC response.
 *
 * Returns NT status codes.
 */
DWORD
lsar_lookup_priv_display_name(mlsvc_handle_t *lsa_handle, char *name,
    char *display_name, int display_len)
{
	struct mslsa_LookupPrivDisplayName	arg;
	int	opnum;
	size_t	length;
	DWORD	status;

	if (lsa_handle == NULL || name == NULL || display_name == NULL)
		return (NT_STATUS_INVALID_PARAMETER);

	opnum = LSARPC_OPNUM_LookupPrivDisplayName;

	bzero(&arg, sizeof (struct mslsa_LookupPrivDisplayName));
	(void) memcpy(&arg.handle, lsa_handle, sizeof (mslsa_handle_t));

	length = smb_wcequiv_strlen(name);
	arg.name.length = length;
	arg.name.allosize = length;
	arg.name.str = (unsigned char *)name;

	arg.client_language = MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US);
	arg.default_language = MAKELANGID(LANG_ENGLISH, SUBLANG_NEUTRAL);

	if (ndr_rpc_call(lsa_handle, opnum, &arg) != 0)
		status = NT_STATUS_INVALID_PARAMETER;
#if 0
	else if (arg.status != 0)
		status = NT_SC_VALUE(arg.status);
#endif
	else {
		(void) strlcpy(display_name,
		    (char const *)arg.display_name->str, display_len);
		status = NT_STATUS_SUCCESS;
	}

	ndr_rpc_release(lsa_handle);
	return (status);
}

static void
lsar_set_trusted_domains_ex(struct mslsa_EnumTrustedDomainBufEx *enum_buf,
    smb_trusted_domains_t *list)
{
	char	sidstr[SMB_SID_STRSZ];
	int	i;

	if (list == NULL || enum_buf == NULL || enum_buf->entries_read == 0)
		return;

	list->td_num = 0;
	list->td_domains = calloc(enum_buf->entries_read,
	    sizeof (smb_domain_t));

	if (list->td_domains == NULL)
		return;

	list->td_num = enum_buf->entries_read;
	for (i = 0; i < list->td_num; i++) {
		smb_sid_tostr((smb_sid_t *)enum_buf->info[i].sid, sidstr);
		smb_domain_set_trust_info(
		    sidstr,
		    (char *)enum_buf->info[i].nb_name.str,
		    (char *)enum_buf->info[i].dns_name.str,
		    enum_buf->info[i].trust_direction,
		    enum_buf->info[i].trust_type,
		    enum_buf->info[i].trust_attrs,
		    &list->td_domains[i]);
	}
}

static void
lsar_set_trusted_domains(struct mslsa_EnumTrustedDomainBuf *enum_buf,
    smb_trusted_domains_t *list)
{
	char	sidstr[SMB_SID_STRSZ];
	int	i;

	if (list == NULL || enum_buf == NULL || enum_buf->entries_read == 0)
		return;

	list->td_num = 0;
	list->td_domains = calloc(enum_buf->entries_read,
	    sizeof (smb_domain_t));

	if (list->td_domains == NULL)
		return;

	list->td_num = enum_buf->entries_read;
	for (i = 0; i < list->td_num; i++) {
		smb_sid_tostr((smb_sid_t *)enum_buf->info[i].sid, sidstr);
		smb_domain_set_trust_info(
		    sidstr, (char *)enum_buf->info[i].name.str,
		    "", 0, 0, 0, &list->td_domains[i]);
	}
}

static void
smb_account_trace(const smb_account_t *info)
{
	char	sidbuf[SMB_SID_STRSZ];

	bzero(sidbuf, SMB_SID_STRSZ);
	smb_sid_tostr(info->a_sid, sidbuf);

	smb_tracef("%s %s %s %lu %s", info->a_domain, info->a_name,
	    sidbuf, info->a_rid, smb_sid_type2str(info->a_type));
}
