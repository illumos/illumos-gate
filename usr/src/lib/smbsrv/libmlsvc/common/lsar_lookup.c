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
 * Local Security Authority RPC (LSARPC) library interface functions for
 * query, lookup and enumeration calls.
 */


#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/errno.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/ntaccess.h>
#include <smbsrv/ntstatus.h>
#include <smbsrv/ntlocale.h>
#include <smbsrv/lsalib.h>
#include <smbsrv/string.h>
#include <smbsrv/mlsvc.h>

/*
 * The maximum number of bytes we are prepared to deal with in a
 * response.
 */
#define	MLSVC_MAX_RESPONSE_LEN		1024

/*
 * This structure is used when lookuping up names. We only lookup one
 * name at a time but the structure will allow for more.
 */
typedef struct lookup_name_table {
	DWORD n_entry;
	mslsa_string_t name[8];
} lookup_name_table_t;

/*
 * lsar_query_security_desc
 *
 * Don't use this call yet. It is just a place holder for now.
 */
int
lsar_query_security_desc(mlsvc_handle_t *lsa_handle)
{
	struct mslsa_QuerySecurityObject arg;
	struct mlsvc_rpc_context *context;
	mlrpc_heapref_t heap;
	int rc;
	int opnum;

	context = lsa_handle->context;
	opnum = LSARPC_OPNUM_QuerySecurityObject;

	bzero(&arg, sizeof (struct mslsa_QuerySecurityObject));
	(void) memcpy(&arg.handle, lsa_handle, sizeof (mslsa_handle_t));

	(void) mlsvc_rpc_init(&heap);
	rc = mlsvc_rpc_call(context, opnum, &arg, &heap);
	mlsvc_rpc_free(context, &heap);
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
lsar_query_info_policy(mlsvc_handle_t *lsa_handle, WORD infoClass)
{
	struct mslsa_QueryInfoPolicy arg;
	struct mlsvc_rpc_context *context;
	struct mslsa_PrimaryDomainInfo *pd_info;
	struct mslsa_AccountDomainInfo *ad_info;
	mlrpc_heapref_t heap;
	nt_domain_t *nt_new_dp;
	int opnum;
	DWORD status;

	if (lsa_handle == 0)
		return (NT_STATUS_INVALID_PARAMETER);

	context = lsa_handle->context;
	opnum = LSARPC_OPNUM_QueryInfoPolicy;

	bzero(&arg, sizeof (struct mslsa_QueryInfoPolicy));
	(void) memcpy(&arg.handle, lsa_handle, sizeof (mslsa_handle_t));
	arg.info_class = infoClass;

	(void) mlsvc_rpc_init(&heap);
	if (mlsvc_rpc_call(context, opnum, &arg, &heap) != 0) {
		status = NT_STATUS_INVALID_PARAMETER;
	} else if (arg.status != 0) {
		mlsvc_rpc_report_status(opnum, arg.status);
		status = NT_SC_VALUE(arg.status);
	} else {
		switch (infoClass) {
		case MSLSA_POLICY_PRIMARY_DOMAIN_INFO:
			pd_info = &arg.info->ru.pd_info;

			nt_domain_flush(NT_DOMAIN_PRIMARY);
			nt_new_dp = nt_domain_new(NT_DOMAIN_PRIMARY,
			    (char *)pd_info->name.str,
			    (nt_sid_t *)pd_info->sid);
			(void) nt_domain_add(nt_new_dp);
			status = NT_STATUS_SUCCESS;
			break;

		case MSLSA_POLICY_ACCOUNT_DOMAIN_INFO:
			ad_info = &arg.info->ru.ad_info;

			nt_domain_flush(NT_DOMAIN_ACCOUNT);
			nt_new_dp = nt_domain_new(NT_DOMAIN_ACCOUNT,
			    (char *)ad_info->name.str,
			    (nt_sid_t *)ad_info->sid);
			(void) nt_domain_add(nt_new_dp);
			status = NT_STATUS_SUCCESS;
			break;

		default:
			status = NT_STATUS_INVALID_INFO_CLASS;
			break;
		}
	}

	mlsvc_rpc_free(context, &heap);
	return (status);
}

/*
 * lsar_lookup_names
 *
 * Lookup a name and obtain the domain and user rid. The RPC call will
 * actually support lookup of multiple names but we probably don't
 * need to do that. On the final system the lookup level should be
 * level 2 but for now we want to restrict it to level 1 so that we
 * don't crash the PDC when we get things wrong.
 *
 * If the lookup fails, the status will typically be
 * NT_STATUS_NONE_MAPPED.
 */
uint32_t
lsar_lookup_names(mlsvc_handle_t *lsa_handle, char *name,
    smb_userinfo_t *user_info)
{
	struct mlsvc_rpc_context *context;
	mlrpc_heapref_t heap;
	int opnum;
	int index;
	uint32_t status;
	struct mslsa_LookupNames arg;
	size_t length;
	lookup_name_table_t name_table;
	struct mslsa_rid_entry *rid_entry;
	struct mslsa_domain_entry *domain_entry;
	char *p;

	if (lsa_handle == NULL || name == NULL || user_info == NULL)
		return (NT_STATUS_INVALID_PARAMETER);

	bzero(user_info, sizeof (smb_userinfo_t));
	user_info->sid_name_use = SidTypeUnknown;

	context = lsa_handle->context;
	opnum = LSARPC_OPNUM_LookupNames;

	bzero(&arg, sizeof (struct mslsa_LookupNames));
	(void) memcpy(&arg.handle, lsa_handle, sizeof (mslsa_handle_t));

	arg.name_table = (struct mslsa_lup_name_table *)&name_table;
	name_table.n_entry = 1;

	/*
	 * Windows NT expects the name length to exclude the terminating
	 * wchar null but doesn't care whether the allosize includes or
	 * excludes the null char. Windows 2000 insists that both the
	 * length and the allosize include the wchar null.
	 *
	 * Note: NT returns an error if the mapped_count is non-zero
	 * when the RPC is called.
	 */
	if (context->server_os == NATIVE_OS_WIN2000) {
		/*
		 * Windows 2000 doesn't like an LSA lookup for
		 * DOMAIN\Administrator.
		 */
		if ((p = strchr(name, '\\')) != 0) {
			++p;

			if (strcasecmp(p, "administrator") == 0)
				name = p;
		}

		length = mts_wcequiv_strlen(name) + sizeof (mts_wchar_t);
		arg.lookup_level = MSLSA_LOOKUP_LEVEL_1;
	} else {
		length = mts_wcequiv_strlen(name);
		arg.lookup_level = MSLSA_LOOKUP_LEVEL_1;
	}

	name_table.name[0].length = length;
	name_table.name[0].allosize = length;
	name_table.name[0].str = (unsigned char *)name;

	(void) mlsvc_rpc_init(&heap);
	if (mlsvc_rpc_call(context, opnum, &arg, &heap) != 0) {
		status = NT_STATUS_INVALID_PARAMETER;
	} else if (arg.status != 0) {
		mlsvc_rpc_report_status(opnum, arg.status);
		status = NT_SC_VALUE(arg.status);
	} else if (arg.mapped_count == 0) {
		user_info->sid_name_use = SidTypeInvalid;
		status = NT_STATUS_NONE_MAPPED;
	} else {
		rid_entry = &arg.translated_sids.rids[0];
		user_info->sid_name_use = rid_entry->sid_name_use;
		user_info->rid = rid_entry->rid;
		user_info->name = MEM_STRDUP("mlrpc", name);

		if ((index = rid_entry->domain_index) == -1) {
			user_info->domain_sid = 0;
			user_info->domain_name = 0;
		} else {
			domain_entry =
			    &arg.domain_table->entries[index];
			user_info->domain_sid = nt_sid_dup(
			    (nt_sid_t *)domain_entry->domain_sid);
			user_info->domain_name = MEM_STRDUP("mlrpc",
			    (const char *)
			    domain_entry->domain_name.str);
			user_info->user_sid = nt_sid_splice(
			    user_info->domain_sid, user_info->rid);
		}
		status = NT_STATUS_SUCCESS;
	}

	mlsvc_rpc_free(context, &heap);
	return (status);
}

/*
 * lsar_lookup_sids
 *
 * Lookup a sid and obtain the domain sid and user name. The RPC call
 * will actually support lookup of multiple sids but we probably don't
 * need to do that. On the final system the lookup level should be
 * level 2 but for now we want to restrict it to level 1 so that we
 * don't crash the PDC when we get things wrong.
 */
uint32_t
lsar_lookup_sids(mlsvc_handle_t *lsa_handle, struct mslsa_sid *sid,
    smb_userinfo_t *user_info)
{
	struct mslsa_LookupSids arg;
	struct mslsa_lup_sid_entry sid_entry;
	struct mslsa_name_entry *name_entry;
	struct mslsa_domain_entry *domain_entry;
	struct mlsvc_rpc_context *context;
	mlrpc_heapref_t heap;
	int opnum;
	int index;
	uint32_t status;

	if (lsa_handle == NULL || sid == NULL || user_info == NULL)
		return (NT_STATUS_INVALID_PARAMETER);

	context = lsa_handle->context;
	opnum = LSARPC_OPNUM_LookupSids;

	bzero(&arg, sizeof (struct mslsa_LookupSids));
	(void) memcpy(&arg.handle, lsa_handle, sizeof (mslsa_handle_t));
	arg.lookup_level = MSLSA_LOOKUP_LEVEL_2;

	sid_entry.psid = sid;
	arg.lup_sid_table.n_entry = 1;
	arg.lup_sid_table.entries = &sid_entry;

	(void) mlsvc_rpc_init(&heap);
	if (mlsvc_rpc_call(context, opnum, &arg, &heap) != 0) {
		status = NT_STATUS_INVALID_PARAMETER;
	} else if (arg.mapped_count == 0) {
		user_info->sid_name_use = SidTypeInvalid;
		status = NT_STATUS_NONE_MAPPED;
	} else if (arg.status != 0) {
		mlsvc_rpc_report_status(opnum, arg.status);
		status = NT_SC_VALUE(arg.status);
	} else {
		name_entry = &arg.name_table.entries[0];
		user_info->sid_name_use = name_entry->sid_name_use;

		if (user_info->sid_name_use == SidTypeUser ||
		    user_info->sid_name_use == SidTypeGroup ||
		    user_info->sid_name_use == SidTypeAlias) {

			user_info->rid =
			    sid->SubAuthority[sid->SubAuthCount - 1];

			user_info->name = MEM_STRDUP("mlrpc",
			    (const char *)name_entry->name.str);
		}

		if ((index = name_entry->domain_ix) == -1) {
			user_info->domain_sid = 0;
			user_info->domain_name = 0;
		} else {
			domain_entry =
			    &arg.domain_table->entries[index];

			user_info->domain_sid = nt_sid_dup(
			    (nt_sid_t *)domain_entry->domain_sid);

			user_info->domain_name = MEM_STRDUP("mlrpc",
			    (const char *)
			    domain_entry->domain_name.str);
		}
		status = NT_STATUS_SUCCESS;
	}

	mlsvc_rpc_free(context, &heap);
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
	struct mslsa_EnumerateAccounts arg;
	struct mslsa_AccountInfo *info;
	struct mlsvc_rpc_context *context;
	mlrpc_heapref_t heap;
	int opnum;
	int rc;
	DWORD n_entries;
	DWORD i;
	int nbytes;

	if (lsa_handle == NULL || enum_context == NULL || accounts == NULL)
		return (-1);

	accounts->entries_read = 0;
	accounts->info = 0;

	context = lsa_handle->context;
	opnum = LSARPC_OPNUM_EnumerateAccounts;

	bzero(&arg, sizeof (struct mslsa_EnumerateAccounts));
	(void) memcpy(&arg.handle, lsa_handle, sizeof (mslsa_handle_t));
	arg.enum_context = *enum_context;
	arg.max_length = MLSVC_MAX_RESPONSE_LEN;

	(void) mlsvc_rpc_init(&heap);
	rc = mlsvc_rpc_call(context, opnum, &arg, &heap);
	if (rc == 0) {
		if (arg.status != 0) {
			if ((arg.status & 0x00FFFFFF) == MLSVC_NO_MORE_DATA) {
				*enum_context = arg.enum_context;
			} else {
				mlsvc_rpc_report_status(opnum,
				    (DWORD)arg.status);
				rc = -1;
			}
		} else if (arg.enum_buf->entries_read != 0) {
			n_entries = arg.enum_buf->entries_read;
			nbytes = n_entries * sizeof (struct mslsa_AccountInfo);

			info = (struct mslsa_AccountInfo *)MEM_MALLOC("mlrpc",
			    nbytes);
			if (info == NULL) {
				mlsvc_rpc_free(context, &heap);
				return (-1);
			}

			for (i = 0; i < n_entries; ++i)
				info[i].sid = (struct mslsa_sid *)nt_sid_dup(
				    (nt_sid_t *)arg.enum_buf->info[i].sid);

			accounts->entries_read = n_entries;
			accounts->info = info;
			*enum_context = arg.enum_context;
		}
	}

	mlsvc_rpc_free(context, &heap);
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
lsar_enum_trusted_domains(mlsvc_handle_t *lsa_handle, DWORD *enum_context)
{
	struct mslsa_EnumTrustedDomain arg;
	struct mlsvc_rpc_context *context;
	mlrpc_heapref_t heap;
	nt_domain_t *nt_new_dp;
	int opnum;
	DWORD status;
	DWORD n_entries;
	DWORD i;

	context = lsa_handle->context;
	opnum = LSARPC_OPNUM_EnumTrustedDomain;

	bzero(&arg, sizeof (struct mslsa_EnumTrustedDomain));
	(void) memcpy(&arg.handle, lsa_handle, sizeof (mslsa_handle_t));
	arg.enum_context = *enum_context;
	arg.max_length = MLSVC_MAX_RESPONSE_LEN;

	(void) mlsvc_rpc_init(&heap);
	if (mlsvc_rpc_call(context, opnum, &arg, &heap) != 0) {
		status = NT_STATUS_INVALID_PARAMETER;
	} else if (arg.status != 0) {
		*enum_context = arg.enum_context;
		status = NT_SC_VALUE(arg.status);

		/*
		 * status 0x8000001A means NO_MORE_DATA,
		 * which is not an error.
		 */
		if (status != MLSVC_NO_MORE_DATA)
			mlsvc_rpc_report_status(opnum, arg.status);
	} else if (arg.enum_buf->entries_read == 0) {
		*enum_context = arg.enum_context;
		status = 0;
	} else {
		nt_domain_flush(NT_DOMAIN_TRUSTED);
		n_entries = arg.enum_buf->entries_read;

		for (i = 0; i < n_entries; ++i) {
			nt_new_dp = nt_domain_new(
			    NT_DOMAIN_TRUSTED,
			    (char *)arg.enum_buf->info[i].name.str,
			    (nt_sid_t *)arg.enum_buf->info[i].sid);

			(void) nt_domain_add(nt_new_dp);
		}

		*enum_context = arg.enum_context;
		status = 0;
	}

	mlsvc_rpc_free(context, &heap);
	return (status);
}

/*
 * lsar_enum_privs_account
 *
 * Privileges enum? Need an account handle.
 */
/*ARGSUSED*/
int
lsar_enum_privs_account(mlsvc_handle_t *account_handle,
    smb_userinfo_t *user_info)
{
	struct mslsa_EnumPrivsAccount arg;
	struct mlsvc_rpc_context *context;
	mlrpc_heapref_t heap;
	int opnum;
	int rc;

	context = account_handle->context;
	opnum = LSARPC_OPNUM_EnumPrivsAccount;

	bzero(&arg, sizeof (struct mslsa_EnumPrivsAccount));
	(void) memcpy(&arg.account_handle, &account_handle->handle,
	    sizeof (mslsa_handle_t));

	(void) mlsvc_rpc_init(&heap);
	rc = mlsvc_rpc_call(context, opnum, &arg, &heap);
	if ((rc == 0) && (arg.status != 0)) {
		mlsvc_rpc_report_status(opnum, (DWORD)arg.status);
		rc = -1;
	}
	mlsvc_rpc_free(context, &heap);
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
	struct mslsa_LookupPrivValue arg;
	struct mlsvc_rpc_context *context;
	mlrpc_heapref_t heap;
	int opnum;
	int rc;
	size_t length;

	if (lsa_handle == NULL || name == NULL || luid == NULL)
		return (-1);

	context = lsa_handle->context;
	opnum = LSARPC_OPNUM_LookupPrivValue;

	bzero(&arg, sizeof (struct mslsa_LookupPrivValue));
	(void) memcpy(&arg.handle, lsa_handle, sizeof (mslsa_handle_t));

	length = mts_wcequiv_strlen(name);
	if (context->server_os == NATIVE_OS_WIN2000)
		length += sizeof (mts_wchar_t);

	arg.name.length = length;
	arg.name.allosize = length;
	arg.name.str = (unsigned char *)name;

	(void) mlsvc_rpc_init(&heap);
	rc = mlsvc_rpc_call(context, opnum, &arg, &heap);
	if (rc == 0) {
		if (arg.status != 0)
			rc = -1;
		else
			(void) memcpy(luid, &arg.luid, sizeof (struct ms_luid));
	}

	mlsvc_rpc_free(context, &heap);
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
	struct mslsa_LookupPrivName arg;
	struct mlsvc_rpc_context *context;
	mlrpc_heapref_t heap;
	int opnum;
	int rc;

	if (lsa_handle == NULL || luid == NULL || name == NULL)
		return (-1);

	context = lsa_handle->context;
	opnum = LSARPC_OPNUM_LookupPrivName;

	bzero(&arg, sizeof (struct mslsa_LookupPrivName));
	(void) memcpy(&arg.handle, lsa_handle, sizeof (mslsa_handle_t));
	(void) memcpy(&arg.luid, luid, sizeof (struct ms_luid));

	(void) mlsvc_rpc_init(&heap);
	rc = mlsvc_rpc_call(context, opnum, &arg, &heap);
	if (rc == 0) {
		if (arg.status != 0)
			rc = -1;
		else
			(void) strlcpy(name, (char const *)arg.name->str,
			    namelen);
	}

	mlsvc_rpc_free(context, &heap);
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
	struct mslsa_LookupPrivDisplayName arg;
	struct mlsvc_rpc_context *context;
	mlrpc_heapref_t heap;
	int opnum;
	size_t length;
	DWORD status;

	if (lsa_handle == NULL || name == NULL || display_name == NULL)
		return (NT_STATUS_INVALID_PARAMETER);

	context = lsa_handle->context;
	opnum = LSARPC_OPNUM_LookupPrivDisplayName;

	bzero(&arg, sizeof (struct mslsa_LookupPrivDisplayName));
	(void) memcpy(&arg.handle, lsa_handle, sizeof (mslsa_handle_t));

	length = mts_wcequiv_strlen(name);
	arg.name.length = length;
	arg.name.allosize = length;
	arg.name.str = (unsigned char *)name;

	arg.client_language = MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US);
	arg.default_language = MAKELANGID(LANG_ENGLISH, SUBLANG_NEUTRAL);

	(void) mlsvc_rpc_init(&heap);

	if (mlsvc_rpc_call(context, opnum, &arg, &heap) != 0)
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

	mlsvc_rpc_free(context, &heap);
	return (status);
}

/*
 * lsar_lookup_sids2
 */
DWORD
lsar_lookup_sids2(mlsvc_handle_t *lsa_handle, struct mslsa_sid *sid,
    smb_userinfo_t *user_info)
{
	struct lsar_lookup_sids2 arg;
	struct lsar_name_entry2 *name_entry;
	struct mslsa_lup_sid_entry sid_entry;
	struct mslsa_domain_entry *domain_entry;
	struct mlsvc_rpc_context *context;
	mlrpc_heapref_t heap;
	int opnum;
	int index;
	DWORD status;

	if (lsa_handle == NULL || sid == NULL || user_info == NULL)
		return (NT_STATUS_INVALID_PARAMETER);

	context = lsa_handle->context;
	opnum = LSARPC_OPNUM_LookupSids2;

	if (context->server_os != NATIVE_OS_WIN2000)
		return (NT_STATUS_REVISION_MISMATCH);

	bzero(&arg, sizeof (struct lsar_lookup_sids2));
	(void) memcpy(&arg.policy_handle, lsa_handle, sizeof (mslsa_handle_t));

	sid_entry.psid = sid;
	arg.lup_sid_table.n_entry = 1;
	arg.lup_sid_table.entries = &sid_entry;
	arg.lookup_level = MSLSA_LOOKUP_LEVEL_1;
	arg.requested_count = arg.lup_sid_table.n_entry;

	(void) mlsvc_rpc_init(&heap);

	if (mlsvc_rpc_call(context, opnum, &arg, &heap) != 0) {
		status = NT_STATUS_INVALID_PARAMETER;
	} else if (arg.mapped_count == 0) {
		user_info->sid_name_use = SidTypeInvalid;
		status = NT_STATUS_NONE_MAPPED;
	} else if (arg.status != 0) {
		mlsvc_rpc_report_status(opnum, arg.status);
		status = NT_SC_VALUE(arg.status);
	} else {
		name_entry = &arg.name_table.entries[0];
		user_info->sid_name_use = name_entry->sid_name_use;

		if (user_info->sid_name_use == SidTypeUser ||
		    user_info->sid_name_use == SidTypeGroup ||
		    user_info->sid_name_use == SidTypeAlias) {

			user_info->rid =
			    sid->SubAuthority[sid->SubAuthCount - 1];

			user_info->name = MEM_STRDUP("mlrpc",
			    (char const *)name_entry->name.str);

		}

		if ((index = name_entry->domain_ix) == -1) {
			user_info->domain_sid = 0;
			user_info->domain_name = 0;
		} else {
			domain_entry = &arg.domain_table->entries[index];

			user_info->domain_sid = nt_sid_dup(
			    (nt_sid_t *)domain_entry->domain_sid);

			user_info->domain_name = MEM_STRDUP("mlrpc",
			    (char const *)domain_entry->domain_name.str);
		}
		status = NT_STATUS_SUCCESS;
	}

	mlsvc_rpc_free(context, &heap);
	return (status);
}


/*
 * lsar_lookup_names2
 *
 * Windows NT expects the name length to exclude the terminating
 * wchar null but Windows 2000 insists that both the length and
 * the allosize include the wchar null. Windows NT doesn't care
 * whether or not the allosize includes or excludes the null char.
 *
 * As a precaution, I set the lookup level to 1 on Windows 2000
 * until I can do some more testing.
 *
 * Note that NT returns an error if the mapped_count is non-zero
 * when the RPC is called.
 *
 * It should be okay to lookup DOMAIN\Administrator in this function.
 */
uint32_t
lsar_lookup_names2(mlsvc_handle_t *lsa_handle, char *name,
    smb_userinfo_t *user_info)
{
	struct mlsvc_rpc_context *context;
	mlrpc_heapref_t heap;
	int opnum;
	int index;
	struct lsar_LookupNames2 arg;
	size_t length;
	lookup_name_table_t name_table;
	struct lsar_rid_entry2 *rid_entry;
	struct mslsa_domain_entry *domain_entry;
	uint32_t status;

	if (lsa_handle == NULL || name == NULL || user_info == NULL)
		return (NT_STATUS_INVALID_PARAMETER);

	bzero(user_info, sizeof (smb_userinfo_t));
	user_info->sid_name_use = SidTypeUnknown;

	context = lsa_handle->context;
	opnum = LSARPC_OPNUM_LookupNames2;

	if (context->server_os != NATIVE_OS_WIN2000)
		return (NT_STATUS_REVISION_MISMATCH);

	bzero(&arg, sizeof (struct lsar_LookupNames2));
	(void) memcpy(&arg.policy_handle, lsa_handle, sizeof (mslsa_handle_t));
	arg.unknown_sb2 = 0x00000002;
	arg.lookup_level = MSLSA_LOOKUP_LEVEL_1;

	arg.name_table = (struct mslsa_lup_name_table *)&name_table;
	name_table.n_entry = 1;

	length = mts_wcequiv_strlen(name) + sizeof (mts_wchar_t);
	name_table.name[0].length = length;
	name_table.name[0].allosize = length;
	name_table.name[0].str = (unsigned char *)name;

	(void) mlsvc_rpc_init(&heap);

	if (mlsvc_rpc_call(context, opnum, &arg, &heap) != 0) {
		status = NT_STATUS_INVALID_PARAMETER;
	} else if (arg.status != 0) {
		mlsvc_rpc_report_status(opnum, arg.status);
		status = NT_SC_VALUE(arg.status);
	} else if (arg.mapped_count == 0) {
		user_info->sid_name_use = SidTypeInvalid;
		status = NT_STATUS_NONE_MAPPED;
	} else {
		rid_entry = &arg.translated_sids.rids[0];
		user_info->sid_name_use = rid_entry->sid_name_use;
		user_info->rid = rid_entry->rid;
		user_info->name = MEM_STRDUP("mlrpc", name);

		if ((index = rid_entry->domain_index) == -1) {
			user_info->domain_sid = 0;
			user_info->domain_name = 0;
		} else {
			domain_entry = &arg.domain_table->entries[index];

			user_info->domain_sid = nt_sid_dup(
			    (nt_sid_t *)domain_entry->domain_sid);

			user_info->domain_name = MEM_STRDUP("mlrpc",
			    (char const *)domain_entry->domain_name.str);
			user_info->user_sid = nt_sid_splice(
			    user_info->domain_sid, user_info->rid);
		}
		status = NT_STATUS_SUCCESS;
	}

	mlsvc_rpc_free(context, &heap);
	return (status);
}

void
mlsvc_rpc_report_status(int opnum, DWORD status)
{
	char *s = "unknown";

	if (status == 0)
		s = "success";
	else if (NT_SC_IS_ERROR(status))
		s = "error";
	else if (NT_SC_IS_WARNING(status))
		s = "warning";
	else if (NT_SC_IS_INFO(status))
		s = "info";

	smb_tracef("mlrpc[0x%02x]: %s: %s (0x%08x)",
	    opnum, s, xlate_nt_status(status), status);
}
