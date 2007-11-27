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
 * This module provides the high level interface to the LSA RPC functions.
 */

#include <strings.h>
#include <unistd.h>
#include <netdb.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/libsmbns.h>
#include <smbsrv/libmlsvc.h>
#include <smbsrv/libsmbrdr.h>
#include <smbsrv/lsalib.h>
#include <smbsrv/ntstatus.h>
#include <smbsrv/smbinfo.h>
#include <smbsrv/ntsid.h>
#include <smbsrv/smb_token.h>

static int lsa_list_accounts(mlsvc_handle_t *);

/*
 * lsa_query_primary_domain_info
 *
 * Obtains the primary domain SID and name from the specified server
 * (domain controller). The information is stored in the NT domain
 * database by the lower level lsar_query_info_policy call. The caller
 * should query the database to obtain a reference to the primary
 * domain information.
 *
 * Returns NT status codes.
 */
DWORD
lsa_query_primary_domain_info(void)
{
	mlsvc_handle_t domain_handle;
	DWORD status;
	char *user = smbrdr_ipc_get_user();

	if ((lsar_open(NULL, NULL, user, &domain_handle)) != 0)
		return (NT_STATUS_CANT_ACCESS_DOMAIN_INFO);

	status = lsar_query_info_policy(&domain_handle,
	    MSLSA_POLICY_PRIMARY_DOMAIN_INFO);

	(void) lsar_close(&domain_handle);
	return (status);
}

/*
 * lsa_query_account_domain_info
 *
 * Obtains the account domain SID and name from the current server
 * (domain controller). The information is stored in the NT domain
 * database by the lower level lsar_query_info_policy call. The caller
 * should query the database to obtain a reference to the account
 * domain information.
 *
 * Returns NT status codes.
 */
DWORD
lsa_query_account_domain_info(void)
{
	mlsvc_handle_t domain_handle;
	DWORD status;
	char *user = smbrdr_ipc_get_user();

	if ((lsar_open(NULL, NULL, user, &domain_handle)) != 0)
		return (NT_STATUS_CANT_ACCESS_DOMAIN_INFO);

	status = lsar_query_info_policy(&domain_handle,
	    MSLSA_POLICY_ACCOUNT_DOMAIN_INFO);

	(void) lsar_close(&domain_handle);
	return (status);
}

/*
 * lsa_enum_trusted_domains
 *
 * Enumerate the trusted domains in our primary domain. The information
 * is stored in the NT domain database by the lower level
 * lsar_enum_trusted_domains call. The caller should query the database
 * to obtain a reference to the trusted domain information.
 *
 * Returns NT status codes.
 */
DWORD
lsa_enum_trusted_domains(void)
{
	mlsvc_handle_t domain_handle;
	DWORD enum_context;
	DWORD status;
	char *user = smbrdr_ipc_get_user();

	if ((lsar_open(NULL, NULL, user, &domain_handle)) != 0)
		return (NT_STATUS_CANT_ACCESS_DOMAIN_INFO);

	enum_context = 0;

	status = lsar_enum_trusted_domains(&domain_handle, &enum_context);
	if (status == MLSVC_NO_MORE_DATA) {
		/*
		 * MLSVC_NO_MORE_DATA indicates that we
		 * have all of the available information.
		 */
		status = NT_STATUS_SUCCESS;
	}

	(void) lsar_close(&domain_handle);
	return (status);
}

/*
 * lsa_test_lookup
 *
 * Test routine for lsa_lookup_name and lsa_lookup_sid.
 */
void
lsa_test_lookup(char *name)
{
	smb_userinfo_t *user_info;
	nt_sid_t *sid;
	DWORD status;
	smb_ntdomain_t *di;

	if ((di = smb_getdomaininfo(0)) == 0)
		return;

	user_info = mlsvc_alloc_user_info();

	if (lsa_lookup_builtin_name(name, user_info) != 0) {
		status = lsa_lookup_name(di->server, di->domain, name,
		    user_info);

		if (status == 0) {
			sid = nt_sid_splice(user_info->domain_sid,
			    user_info->rid);

			(void) lsa_lookup_sid(sid, user_info);
			free(sid);
		}
	}

	mlsvc_free_user_info(user_info);
}

/*
 * lsa_lookup_builtin_name
 *
 * lookup builtin account table to see if account_name is
 * there. If it is there, set sid_name_use, domain_sid,
 * domain_name, and rid fields of the passed user_info
 * structure and return 0. If lookup fails return 1.
 */
int
lsa_lookup_builtin_name(char *account_name, smb_userinfo_t *user_info)
{
	char *domain;
	int res;

	user_info->domain_sid = nt_builtin_lookup_name(account_name,
	    &user_info->sid_name_use);

	if (user_info->domain_sid == 0)
		return (1);

	res = nt_sid_split(user_info->domain_sid, &user_info->rid);
	if (res < 0)
		return (1);

	domain = nt_builtin_lookup_domain(account_name);
	if (domain) {
		user_info->domain_name = strdup(domain);
		return (0);
	}

	return (1);
}

/*
 * lsa_lookup_local_sam
 *
 * lookup for the given account name in the local SAM database.
 * Returns 0 on success. If lookup fails return 1.
 */
int
lsa_lookup_local_sam(char *domain, char *account_name,
    smb_userinfo_t *user_info)
{
	nt_group_t *grp;

	if (*domain == '\0' || *account_name == '\0')
		return (1);

	grp = nt_group_getinfo(account_name, RWLOCK_READER);
	if (grp == 0)
		return (1);

	user_info->sid_name_use = *grp->sid_name_use;
	user_info->domain_sid = nt_sid_dup(grp->sid);
	nt_group_putinfo(grp);

	if (user_info->domain_sid == 0)
		return (1);

	(void) nt_sid_split(user_info->domain_sid, &user_info->rid);
	user_info->domain_name = strdup(domain);

	if (user_info->domain_name == 0) {
		free(user_info->domain_sid);
		user_info->domain_sid = 0;
		return (1);
	}

	return (0);
}

/*
 * lsa_lookup_local
 *
 * if given account name has domain part, check to see if
 * it matches with host name or any of host's primary addresses.
 * if any match found first lookup in builtin accounts table and
 * then in local SAM table.
 *
 * if account name doesn't have domain part, first do local lookups
 * if nothing is found return 1. This means that caller function should
 * do domain lookup.
 * if any error happened return -1, if name is found return 0.
 */
int
lsa_lookup_local(char *name, smb_userinfo_t *user_info)
{
	char hostname[MAXHOSTNAMELEN];
	int res = 0;
	int local_lookup = 0;
	char *tmp;
	net_cfg_t cfg;
	uint32_t addr;

	if (smb_gethostname(hostname, MAXHOSTNAMELEN, 1) != 0)
		return (-1);

	tmp = strchr(name, '\\');
	if (tmp != 0) {
		*tmp = 0;
		if (strcasecmp(name, hostname) == 0)
			local_lookup = 1;

		if (!local_lookup) {
			addr = inet_addr(name);
			if (smb_nic_get_byip(addr, &cfg) != NULL) {
				local_lookup = 1;
			}
		}

		if (!local_lookup) {
			/* do domain lookup */
			*tmp = '\\';
			return (1);
		}

		name = tmp + 1;
		local_lookup = 1;
	}

	res = lsa_lookup_builtin_name(name, user_info);
	if (res != 0)
		res = lsa_lookup_local_sam(hostname, name, user_info);

	if (res == 0)
		return (0);

	if (local_lookup)
		return (-1);

	return (1);
}

/*
 * lsa_lookup_name
 *
 * Lookup a name on the specified server (domain controller) and obtain
 * the appropriate SID. The information is returned in the user_info
 * structure. The caller is responsible for allocating and releasing
 * this structure. On success sid_name_use will be set to indicate the
 * type of SID. If the name is the domain name, this function will be
 * identical to lsa_domain_info. Otherwise the rid and name fields will
 * also be valid. On failure sid_name_use will be set to SidTypeUnknown.
 *
 * On success 0 is returned. Otherwise a -ve error code.
 */
int lsa_lookup_name(char *server, char *domain, char *account_name,
    smb_userinfo_t *user_info)
{
	mlsvc_handle_t domain_handle;
	int rc;
	char *user = smbrdr_ipc_get_user();

	rc = lsar_open(server, domain, user, &domain_handle);
	if (rc != 0)
		return (-1);

	rc = lsar_lookup_names(&domain_handle, account_name, user_info);

	(void) lsar_close(&domain_handle);
	return (rc);
}

/*
 * lsa_lookup_name2
 *
 * Returns NT status codes.
 */
DWORD lsa_lookup_name2(char *server, char *domain, char *account_name,
    smb_userinfo_t *user_info)
{
	mlsvc_handle_t domain_handle;
	DWORD status;
	int rc;
	char *user = smbrdr_ipc_get_user();

	rc = lsar_open(server, domain, user, &domain_handle);
	if (rc != 0)
		return (NT_STATUS_INVALID_PARAMETER);

	status = lsar_lookup_names2(&domain_handle, account_name, user_info);
	if (status == NT_STATUS_REVISION_MISMATCH) {
		/*
		 * Not a Windows 2000 domain controller:
		 * use the NT compatible call.
		 */
		if (lsar_lookup_names(&domain_handle, account_name,
		    user_info) != 0)
			status = NT_STATUS_NONE_MAPPED;
		else
			status = 0;
	}

	(void) lsar_close(&domain_handle);
	return (status);
}

/*
 * lsa_lookup_sid
 *
 * Lookup a SID on the specified server (domain controller) and obtain
 * the appropriate name. The information is returned in the user_info
 * structure. The caller is responsible for allocating and releasing
 * this structure. On success sid_name_use will be set to indicate the
 * type of SID. On failure sid_name_use will be set to SidTypeUnknown.
 *
 * On success 0 is returned. Otherwise a -ve error code.
 */
int
lsa_lookup_sid(nt_sid_t *sid, smb_userinfo_t *user_info)
{
	mlsvc_handle_t domain_handle;
	int rc;
	char *user = smbrdr_ipc_get_user();

	rc = lsar_open(NULL, NULL, user, &domain_handle);
	if (rc != 0)
		return (-1);

	rc = lsar_lookup_sids(&domain_handle,
	    (struct mslsa_sid *)sid, user_info);

	(void) lsar_close(&domain_handle);
	return (rc);
}

/*
 * lsa_lookup_sid2
 *
 * Returns NT status codes.
 */
DWORD
lsa_lookup_sid2(nt_sid_t *sid, smb_userinfo_t *user_info)
{
	mlsvc_handle_t domain_handle;
	DWORD status;
	int rc;
	char *user = smbrdr_ipc_get_user();

	rc = lsar_open(NULL, NULL, user, &domain_handle);
	if (rc != 0)
		return (NT_STATUS_INVALID_PARAMETER);

	status = lsar_lookup_sids2(&domain_handle,
	    (struct mslsa_sid *)sid, user_info);

	if (status == NT_STATUS_REVISION_MISMATCH) {
		/*
		 * Not a Windows 2000 domain controller:
		 * use the NT compatible call.
		 */
		if (lsar_lookup_sids(&domain_handle, (struct mslsa_sid *)sid,
		    user_info) != 0)
			status = NT_STATUS_NONE_MAPPED;
		else
			status = 0;
	}

	(void) lsar_close(&domain_handle);
	return (status);
}

/*
 * lsa_test_lookup2
 *
 * Test routine for lsa_lookup_name2 and lsa_lookup_sid2.
 */
void
lsa_test_lookup2(char *name)
{
	smb_userinfo_t *user_info;
	nt_sid_t *sid;
	DWORD status;
	smb_ntdomain_t *di;

	if ((di = smb_getdomaininfo(0)) == 0)
		return;

	user_info = mlsvc_alloc_user_info();

	if (lsa_lookup_builtin_name(name, user_info) != 0) {
		status = lsa_lookup_name2(di->server, di->domain, name,
		    user_info);

		if (status == 0) {
			sid = nt_sid_splice(user_info->domain_sid,
			    user_info->rid);

			(void) lsa_lookup_sid2(sid, user_info);
			free(sid);
		}
	}

	mlsvc_free_user_info(user_info);
}

/*
 * lsa_lookup_privs
 *
 * Request the privileges associated with the specified account. In
 * order to get the privileges, we first have to lookup the name on
 * the specified domain controller and obtain the appropriate SID.
 * The SID can then be used to open the account and obtain the
 * account privileges. The results from both the name lookup and the
 * privileges are returned in the user_info structure. The caller is
 * responsible for allocating and releasing this structure.
 *
 * On success 0 is returned. Otherwise a -ve error code.
 */
/*ARGSUSED*/
int
lsa_lookup_privs(char *server, char *account_name, char *target_name,
    smb_userinfo_t *user_info)
{
	mlsvc_handle_t domain_handle;
	int rc;
	char *user = smbrdr_ipc_get_user();

	if ((lsar_open(NULL, NULL, user, &domain_handle)) != 0)
		return (-1);

	rc = lsa_list_accounts(&domain_handle);
	(void) lsar_close(&domain_handle);
	return (rc);
}

/*
 * lsa_list_privs
 *
 * List the privileges supported by the specified server.
 * This function is only intended for diagnostics.
 *
 * Returns NT status codes.
 */
DWORD
lsa_list_privs(char *server, char *domain)
{
	static char name[128];
	static struct ms_luid luid;
	mlsvc_handle_t domain_handle;
	int rc;
	int i;
	char *user = smbrdr_ipc_get_user();

	rc = lsar_open(server, domain, user, &domain_handle);
	if (rc != 0)
		return (NT_STATUS_INVALID_PARAMETER);

	for (i = 0; i < 30; ++i) {
		luid.low_part = i;
		rc = lsar_lookup_priv_name(&domain_handle, &luid, name, 128);
		if (rc != 0)
			continue;

		(void) lsar_lookup_priv_value(&domain_handle, name, &luid);
		(void) lsar_lookup_priv_display_name(&domain_handle, name,
		    name, 128);
	}

	(void) lsar_close(&domain_handle);
	return (NT_STATUS_SUCCESS);
}

/*
 * lsa_test
 *
 * LSA test routine: open and close the LSA interface.
 * TBD: the parameters should be server and domain.
 *
 * On success 0 is returned. Otherwise a -ve error code.
 */
/*ARGSUSED*/
int
lsa_test(char *server, char *account_name)
{
	mlsvc_handle_t domain_handle;
	int rc;
	char *user = smbrdr_ipc_get_user();

	rc = lsar_open(NULL, NULL, user, &domain_handle);
	if (rc != 0)
		return (-1);

	if (lsar_close(&domain_handle) != 0)
		return (-1);

	return (0);
}

/*
 * lsa_list_accounts
 *
 * This function can be used to list the accounts in the specified
 * domain. For now the SIDs are just listed in the system log.
 *
 * On success 0 is returned. Otherwise a -ve error code.
 */
static int
lsa_list_accounts(mlsvc_handle_t *domain_handle)
{
	mlsvc_handle_t account_handle;
	struct mslsa_EnumAccountBuf accounts;
	struct mslsa_sid *sid;
	char *name;
	WORD sid_name_use;
	smb_userinfo_t *user_info;
	DWORD enum_context = 0;
	int rc;
	int i;

	user_info = mlsvc_alloc_user_info();
	bzero(&accounts, sizeof (struct mslsa_EnumAccountBuf));

	do {
		rc = lsar_enum_accounts(domain_handle, &enum_context,
		    &accounts);
		if (rc != 0)
			return (rc);

		for (i = 0; i < accounts.entries_read; ++i) {
			sid = accounts.info[i].sid;

			name = nt_builtin_lookup_sid((nt_sid_t *)sid,
			    &sid_name_use);

			if (name == 0) {
				if (lsar_lookup_sids(domain_handle, sid,
				    user_info) == 0) {
					name = user_info->name;
					sid_name_use = user_info->sid_name_use;
				} else {
					name = "unknown";
					sid_name_use = SidTypeUnknown;
				}
			}

			nt_sid_logf((nt_sid_t *)sid);

			if (lsar_open_account(domain_handle, sid,
			    &account_handle) == 0) {
				(void) lsar_enum_privs_account(&account_handle,
				    user_info);
				(void) lsar_close(&account_handle);
			}

			free(accounts.info[i].sid);
			mlsvc_release_user_info(user_info);
		}

		if (accounts.info)
			free(accounts.info);
	} while (rc == 0 && accounts.entries_read != 0);

	mlsvc_free_user_info(user_info);
	return (0);
}
