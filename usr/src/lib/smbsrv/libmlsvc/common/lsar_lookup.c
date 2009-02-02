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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

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
#include <smbsrv/string.h>
#include <smbsrv/libmlsvc.h>
#include <lsalib.h>

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

static void lsar_set_nt_domaininfo(smb_sid_t *, char *, lsa_nt_domaininfo_t *);
static void lsar_set_primary_domaininfo(smb_sid_t *, char *, lsa_info_t *);
static void lsar_set_account_domaininfo(smb_sid_t *, char *, lsa_info_t *);
static void lsar_set_dns_domaininfo(smb_sid_t *, char *, char *, char *,
	mslsa_guid_t *, lsa_info_t *);
static void lsar_set_trusted_domainlist(struct mslsa_EnumTrustedDomainBuf *,
    lsa_info_t *);

/*
 * lsar_query_security_desc
 *
 * Don't use this call yet. It is just a place holder for now.
 */
int
lsar_query_security_desc(mlsvc_handle_t *lsa_handle)
{
	struct mslsa_QuerySecurityObject arg;
	int rc;
	int opnum;

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
    lsa_info_t *info)
{
	struct mslsa_QueryInfoPolicy arg;
	struct mslsa_PrimaryDomainInfo *pd_info;
	struct mslsa_AccountDomainInfo *ad_info;
	struct mslsa_DnsDomainInfo *dns_info;
	int opnum;
	DWORD status;


	if (lsa_handle == NULL || info == NULL)
		return (NT_STATUS_INVALID_PARAMETER);

	opnum = LSARPC_OPNUM_QueryInfoPolicy;

	bzero(info, sizeof (lsa_info_t));
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

			lsar_set_primary_domaininfo((smb_sid_t *)pd_info->sid,
			    (char *)pd_info->name.str, info);

			status = NT_STATUS_SUCCESS;
			break;

		case MSLSA_POLICY_ACCOUNT_DOMAIN_INFO:
			ad_info = &arg.ru.ad_info;

			lsar_set_account_domaininfo((smb_sid_t *)ad_info->sid,
			    (char *)ad_info->name.str, info);

			status = NT_STATUS_SUCCESS;
			break;

		case MSLSA_POLICY_DNS_DOMAIN_INFO:
			dns_info = &arg.ru.dns_info;

			lsar_set_dns_domaininfo((smb_sid_t *)dns_info->sid,
			    (char *)dns_info->nb_domain.str,
			    (char *)dns_info->dns_domain.str,
			    (char *)dns_info->forest.str,
			    &dns_info->guid,
			    info);
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
lsar_lookup_names(mlsvc_handle_t *lsa_handle, char *name, smb_account_t *info)
{
	struct mslsa_LookupNames arg;
	struct mslsa_rid_entry *rid_entry;
	struct mslsa_domain_entry *domain_entry;
	lookup_name_table_t name_table;
	uint32_t status = NT_STATUS_SUCCESS;
	int opnum;
	size_t length;
	char *p;

	if (lsa_handle == NULL || name == NULL || info == NULL)
		return (NT_STATUS_INVALID_PARAMETER);

	bzero(info, sizeof (smb_account_t));

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
	if (ndr_rpc_server_os(lsa_handle) == NATIVE_OS_WIN2000) {
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
	info->a_name = strdup(name);
	info->a_domsid = smb_sid_dup((smb_sid_t *)domain_entry->domain_sid);
	info->a_domain = strdup((const char *)domain_entry->domain_name.str);
	info->a_rid = rid_entry->rid;
	info->a_sid = smb_sid_splice(info->a_domsid, info->a_rid);

	if (!smb_account_validate(info)) {
		smb_account_free(info);
		status = NT_STATUS_NO_MEMORY;
	}

	ndr_rpc_release(lsa_handle);
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
    smb_account_t *account)
{
	struct mslsa_LookupSids arg;
	struct mslsa_lup_sid_entry sid_entry;
	struct mslsa_name_entry *name_entry;
	struct mslsa_domain_entry *domain_entry;
	uint32_t status = NT_STATUS_SUCCESS;
	int opnum;

	if (lsa_handle == NULL || sid == NULL || account == NULL)
		return (NT_STATUS_INVALID_PARAMETER);

	bzero(account, sizeof (smb_account_t));
	opnum = LSARPC_OPNUM_LookupSids;

	bzero(&arg, sizeof (struct mslsa_LookupSids));
	(void) memcpy(&arg.handle, lsa_handle, sizeof (mslsa_handle_t));
	arg.lookup_level = MSLSA_LOOKUP_LEVEL_2;

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

	domain_entry = &arg.domain_table->entries[0];

	account->a_type = name_entry->sid_name_use;
	account->a_name = strdup((char const *)name_entry->name.str);
	account->a_sid = smb_sid_dup((smb_sid_t *)sid);
	account->a_domain = strdup((char const *)domain_entry->domain_name.str);
	account->a_domsid = smb_sid_dup((smb_sid_t *)domain_entry->domain_sid);

	if (!smb_account_validate(account)) {
		smb_account_free(account);
		status = NT_STATUS_NO_MEMORY;
	}

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
	struct mslsa_EnumerateAccounts arg;
	struct mslsa_AccountInfo *info;
	int opnum;
	int rc;
	DWORD n_entries;
	DWORD i;
	int nbytes;

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
			if ((arg.status & 0x00FFFFFF) == MLSVC_NO_MORE_DATA) {
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
				info[i].sid = (struct mslsa_sid *)smb_sid_dup(
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
    lsa_info_t *info)
{
	struct mslsa_EnumTrustedDomain arg;
	int opnum;
	DWORD status;

	if (info == NULL)
		return (NT_STATUS_INVALID_PARAMETER);

	opnum = LSARPC_OPNUM_EnumTrustedDomain;

	bzero(info, sizeof (lsa_info_t));
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
		 * status 0x8000001A means NO_MORE_DATA,
		 * which is not an error.
		 */
		if (status != MLSVC_NO_MORE_DATA)
			ndr_rpc_status(lsa_handle, opnum, arg.status);
	} else if (arg.enum_buf->entries_read == 0) {
		*enum_context = arg.enum_context;
		status = 0;
	} else {
		lsar_set_trusted_domainlist(arg.enum_buf, info);
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
	struct mslsa_EnumPrivsAccount arg;
	int opnum;
	int rc;

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
	struct mslsa_LookupPrivValue arg;
	int opnum;
	int rc;
	size_t length;

	if (lsa_handle == NULL || name == NULL || luid == NULL)
		return (-1);

	opnum = LSARPC_OPNUM_LookupPrivValue;

	bzero(&arg, sizeof (struct mslsa_LookupPrivValue));
	(void) memcpy(&arg.handle, lsa_handle, sizeof (mslsa_handle_t));

	length = mts_wcequiv_strlen(name);
	if (ndr_rpc_server_os(lsa_handle) == NATIVE_OS_WIN2000)
		length += sizeof (mts_wchar_t);

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
	struct mslsa_LookupPrivName arg;
	int opnum;
	int rc;

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
	struct mslsa_LookupPrivDisplayName arg;
	int opnum;
	size_t length;
	DWORD status;

	if (lsa_handle == NULL || name == NULL || display_name == NULL)
		return (NT_STATUS_INVALID_PARAMETER);

	opnum = LSARPC_OPNUM_LookupPrivDisplayName;

	bzero(&arg, sizeof (struct mslsa_LookupPrivDisplayName));
	(void) memcpy(&arg.handle, lsa_handle, sizeof (mslsa_handle_t));

	length = mts_wcequiv_strlen(name);
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

/*
 * lsar_lookup_sids2
 */
uint32_t
lsar_lookup_sids2(mlsvc_handle_t *lsa_handle, struct mslsa_sid *sid,
    smb_account_t *account)
{
	struct lsar_lookup_sids2 arg;
	struct lsar_name_entry2 *name_entry;
	struct mslsa_lup_sid_entry sid_entry;
	struct mslsa_domain_entry *domain_entry;
	uint32_t status = NT_STATUS_SUCCESS;
	int opnum;

	if (lsa_handle == NULL || sid == NULL || account == NULL)
		return (NT_STATUS_INVALID_PARAMETER);

	bzero(account, sizeof (smb_account_t));
	opnum = LSARPC_OPNUM_LookupSids2;

	if (ndr_rpc_server_os(lsa_handle) != NATIVE_OS_WIN2000)
		return (NT_STATUS_REVISION_MISMATCH);

	bzero(&arg, sizeof (struct lsar_lookup_sids2));
	(void) memcpy(&arg.policy_handle, lsa_handle, sizeof (mslsa_handle_t));

	sid_entry.psid = sid;
	arg.lup_sid_table.n_entry = 1;
	arg.lup_sid_table.entries = &sid_entry;
	arg.lookup_level = MSLSA_LOOKUP_LEVEL_1;
	arg.requested_count = arg.lup_sid_table.n_entry;

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

	domain_entry = &arg.domain_table->entries[0];

	account->a_type = name_entry->sid_name_use;
	account->a_name = strdup((char const *)name_entry->name.str);
	account->a_sid = smb_sid_dup((smb_sid_t *)sid);
	account->a_domain = strdup((char const *)domain_entry->domain_name.str);
	account->a_domsid = smb_sid_dup((smb_sid_t *)domain_entry->domain_sid);

	if (!smb_account_validate(account)) {
		smb_account_free(account);
		status = NT_STATUS_NO_MEMORY;
	}

	ndr_rpc_release(lsa_handle);
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
lsar_lookup_names2(mlsvc_handle_t *lsa_handle, char *name, smb_account_t *info)
{
	struct lsar_LookupNames2 arg;
	struct lsar_rid_entry2 *rid_entry;
	struct mslsa_domain_entry *domain_entry;
	lookup_name_table_t name_table;
	uint32_t status = NT_STATUS_SUCCESS;
	size_t length;
	int opnum;

	if (lsa_handle == NULL || name == NULL || info == NULL)
		return (NT_STATUS_INVALID_PARAMETER);

	bzero(info, sizeof (smb_account_t));

	opnum = LSARPC_OPNUM_LookupNames2;

	if (ndr_rpc_server_os(lsa_handle) != NATIVE_OS_WIN2000)
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
	info->a_name = strdup(name);
	info->a_domsid = smb_sid_dup((smb_sid_t *)domain_entry->domain_sid);
	info->a_domain = strdup((char const *)domain_entry->domain_name.str);
	info->a_rid = rid_entry->rid;
	info->a_sid = smb_sid_splice(info->a_domsid, info->a_rid);

	if (!smb_account_validate(info)) {
		smb_account_free(info);
		status = NT_STATUS_NO_MEMORY;
	}

	ndr_rpc_release(lsa_handle);
	return (status);
}

static void
lsar_set_nt_domaininfo(smb_sid_t *sid, char *nb_domain,
    lsa_nt_domaininfo_t *info)
{
	if (sid == NULL || nb_domain == NULL || info == NULL)
		return;

	info->n_sid = smb_sid_dup(sid);
	(void) strlcpy(info->n_domain, nb_domain, NETBIOS_NAME_SZ);
}

static void
lsar_set_primary_domaininfo(smb_sid_t *sid, char *nb_domain,
    lsa_info_t *info)
{
	lsa_nt_domaininfo_t *di;

	if (sid == NULL || nb_domain == NULL || info == NULL)
		return;

	info->i_type = LSA_INFO_PRIMARY_DOMAIN;
	di = &info->i_domain.di_primary;
	lsar_set_nt_domaininfo(sid, nb_domain, di);
}

static void
lsar_set_account_domaininfo(smb_sid_t *sid, char *nb_domain,
    lsa_info_t *info)
{
	lsa_nt_domaininfo_t *di;

	if (sid == NULL || nb_domain == NULL || info == NULL)
		return;

	info->i_type = LSA_INFO_ACCOUNT_DOMAIN;
	di = &info->i_domain.di_account;
	lsar_set_nt_domaininfo(sid, nb_domain, di);
}

static void
lsar_set_dns_domaininfo(smb_sid_t *sid, char *nb_domain, char *fq_domain,
    char *forest, mslsa_guid_t *guid, lsa_info_t *info)
{
	lsa_dns_domaininfo_t *di;

	if (sid == NULL || nb_domain == NULL || fq_domain == NULL ||
	    forest == NULL)
		return;

	if (guid == NULL || info == NULL)
		return;

	info->i_type = LSA_INFO_DNS_DOMAIN;
	di = &info->i_domain.di_dns;
	di->d_sid = smb_sid_dup(sid);
	(void) strlcpy(di->d_nbdomain, nb_domain, NETBIOS_NAME_SZ);
	(void) strlcpy(di->d_fqdomain, fq_domain, MAXHOSTNAMELEN);
	(void) strlcpy(di->d_forest, forest, MAXHOSTNAMELEN);
	(void) bcopy(guid, &di->d_guid, sizeof (mslsa_guid_t));
}

static void
lsar_set_trusted_domainlist(struct mslsa_EnumTrustedDomainBuf *enum_buf,
    lsa_info_t *info)
{
	int i;
	lsa_trusted_domainlist_t *list;

	if (info == NULL)
		return;

	if (enum_buf == NULL || enum_buf->entries_read == 0)
		return;

	info->i_type = LSA_INFO_TRUSTED_DOMAINS;
	list = &info->i_domain.di_trust;
	list->t_domains = malloc(enum_buf->entries_read *
	    sizeof (lsa_nt_domaininfo_t));
	if (list->t_domains == NULL) {
		list->t_num = 0;
	} else {
		list->t_num = enum_buf->entries_read;
		for (i = 0; i < list->t_num; i++)
			lsar_set_nt_domaininfo(
			    (smb_sid_t *)enum_buf->info[i].sid,
			    (char *)enum_buf->info[i].name.str,
			    &list->t_domains[i]);
	}
}
