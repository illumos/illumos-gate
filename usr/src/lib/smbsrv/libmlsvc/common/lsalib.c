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
 * This module provides the high level interface to the LSA RPC functions.
 */

#include <strings.h>
#include <unistd.h>
#include <netdb.h>
#include <pwd.h>
#include <grp.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/libsmbns.h>
#include <smbsrv/libmlsvc.h>
#include <smbsrv/libsmbrdr.h>
#include <smbsrv/lsalib.h>
#include <smbsrv/ntstatus.h>
#include <smbsrv/smbinfo.h>
#include <smbsrv/ntsid.h>
#include <smbsrv/smb_token.h>

/*
 * Name Lookup modes
 */
#define	MLSVC_LOOKUP_BUILTIN	1
#define	MLSVC_LOOKUP_LOCAL	2
#define	MLSVC_LOOKUP_DOMAIN	3
#define	MLSVC_LOOKUP_DOMLOC	4

static int lsa_lookup_mode(const char *, const char *);
static uint32_t lsa_lookup_name_builtin(char *, smb_userinfo_t *);
static uint32_t lsa_lookup_name_local(char *, char *, uint16_t,
    smb_userinfo_t *);
static uint32_t lsa_lookup_name_lusr(char *, nt_sid_t **);
static uint32_t lsa_lookup_name_lgrp(char *, nt_sid_t **);
static uint32_t lsa_lookup_name_domain(char *, char *, char *,
    smb_userinfo_t *);

static uint32_t lsa_lookup_sid_builtin(nt_sid_t *, smb_userinfo_t *);
static uint32_t lsa_lookup_sid_local(nt_sid_t *, smb_userinfo_t *);
static uint32_t lsa_lookup_sid_domain(nt_sid_t *, smb_userinfo_t *);

static int lsa_list_accounts(mlsvc_handle_t *);

/*
 * lsa_lookup_name
 *
 * Lookup the given account and returns the account information
 * in 'ainfo'
 *
 * If the name is a domain account, it may refer to a user, group or
 * alias. If it is a local account, its type should be specified
 * in the sid_type parameter. In case the account type is unknown
 * sid_type should be set to SidTypeUnknown.
 *
 * account argument could be either [domain\\]name or [domain/]name.
 * If domain is not specified and service is in domain mode then it
 * first does a domain lookup and then a local lookup.
 */
uint32_t
lsa_lookup_name(char *server, char *account, uint16_t sid_type,
    smb_userinfo_t *ainfo)
{
	nt_domain_t *dominfo;
	int lookup_mode;
	char *name;
	char *domain;
	uint32_t status = NT_STATUS_NONE_MAPPED;

	(void) strsubst(account, '\\', '/');
	name = strchr(account, '/');
	if (name) {
		/* domain is specified */
		*name++ = '\0';
		domain = account;
	} else {
		name = account;
		domain = NULL;
	}

	lookup_mode = lsa_lookup_mode(domain, name);

	switch (lookup_mode) {
	case MLSVC_LOOKUP_BUILTIN:
		return (lsa_lookup_name_builtin(name, ainfo));

	case MLSVC_LOOKUP_LOCAL:
		return (lsa_lookup_name_local(domain, name, sid_type, ainfo));

	case MLSVC_LOOKUP_DOMAIN:
		return (lsa_lookup_name_domain(server, domain, name, ainfo));

	default:
		/* lookup the name in domain */
		dominfo = nt_domain_lookupbytype(NT_DOMAIN_PRIMARY);
		if (dominfo == NULL)
			return (NT_STATUS_INTERNAL_ERROR);
		status = lsa_lookup_name_domain(server, dominfo->name, name,
		    ainfo);
		if (status != NT_STATUS_NONE_MAPPED)
			return (status);

		mlsvc_release_user_info(ainfo);
		/* lookup the name locally */
		status = lsa_lookup_name_local(domain, name, sid_type, ainfo);
	}

	return (status);
}

uint32_t
lsa_lookup_sid(nt_sid_t *sid, smb_userinfo_t *ainfo)
{
	if (!nt_sid_is_valid(sid))
		return (NT_STATUS_INVALID_SID);

	if (nt_sid_is_local(sid))
		return (lsa_lookup_sid_local(sid, ainfo));

	if (nt_builtin_lookup_sid(sid, NULL))
		return (lsa_lookup_sid_builtin(sid, ainfo));

	return (lsa_lookup_sid_domain(sid, ainfo));
}

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
 * lsa_lookup_name_builtin
 *
 * lookup builtin account table to see if account_name is
 * there. If it is there, set sid_name_use, domain_sid,
 * domain_name, and rid fields of the passed user_info
 * structure.
 */
static uint32_t
lsa_lookup_name_builtin(char *account_name, smb_userinfo_t *user_info)
{
	char *domain;
	int res;

	user_info->user_sid = nt_builtin_lookup_name(account_name,
	    &user_info->sid_name_use);

	if (user_info->user_sid == NULL)
		return (NT_STATUS_NONE_MAPPED);

	user_info->domain_sid = nt_sid_dup(user_info->user_sid);
	res = nt_sid_split(user_info->domain_sid, &user_info->rid);
	if (res < 0)
		return (NT_STATUS_INTERNAL_ERROR);

	domain = nt_builtin_lookup_domain(account_name);
	if (domain) {
		user_info->domain_name = strdup(domain);
		return (NT_STATUS_SUCCESS);
	}

	return (NT_STATUS_INTERNAL_ERROR);
}

/*
 * lsa_lookup_name_local
 *
 * Obtains the infomation for the given local account name if it
 * can be found. The type of account is specified by sid_type,
 * which can be of user, group or unknown type. If the caller
 * doesn't know whether the name is a user or group name then
 * SidTypeUnknown should be passed, in which case this
 * function first tries to find a user and then a group match.
 *
 * CAVEAT: if there are both a user and a group account with
 * the same name, user SID will always be returned.
 */
static uint32_t
lsa_lookup_name_local(char *domain, char *name, uint16_t sid_type,
    smb_userinfo_t *ainfo)
{
	char hostname[MAXHOSTNAMELEN];
	nt_sid_t *sid;
	uint32_t status;

	switch (sid_type) {
	case SidTypeUser:
		status = lsa_lookup_name_lusr(name, &sid);
		if (status != NT_STATUS_SUCCESS)
			return (status);
		break;

	case SidTypeGroup:
	case SidTypeAlias:
		status = lsa_lookup_name_lgrp(name, &sid);
		if (status != NT_STATUS_SUCCESS)
			return (status);
		break;

	case SidTypeUnknown:
		sid_type = SidTypeUser;
		status = lsa_lookup_name_lusr(name, &sid);
		if (status == NT_STATUS_SUCCESS)
			break;

		if (status == NT_STATUS_NONE_MAPPED)
			return (status);

		sid_type = SidTypeAlias;
		status = lsa_lookup_name_lgrp(name, &sid);
		if (status != NT_STATUS_SUCCESS)
			return (status);
		break;

	default:
			return (NT_STATUS_INVALID_PARAMETER);
	}

	ainfo->sid_name_use = sid_type;
	ainfo->user_sid = sid;
	ainfo->domain_sid = nt_sid_dup(sid);
	if (ainfo->domain_sid == NULL)
		return (NT_STATUS_NO_MEMORY);

	(void) nt_sid_split(ainfo->domain_sid, &ainfo->rid);
	if ((domain == NULL) || (*domain == '\0')) {
		(void) smb_getnetbiosname(hostname, sizeof (hostname));
		ainfo->domain_name = strdup(hostname);
	} else {
		ainfo->domain_name = strdup(domain);
	}

	if (ainfo->domain_name == NULL)
		return (NT_STATUS_NO_MEMORY);

	return (NT_STATUS_SUCCESS);
}

/*
 * lsa_lookup_name_domain
 *
 * Lookup a name on the specified server (domain controller) and obtain
 * the appropriate SID. The information is returned in the user_info
 * structure. The caller is responsible for allocating and releasing
 * this structure. On success sid_name_use will be set to indicate the
 * type of SID. If the name is the domain name, this function will be
 * identical to lsa_domain_info. Otherwise the rid and name fields will
 * also be valid. On failure sid_name_use will be set to SidTypeUnknown.
 */
static uint32_t
lsa_lookup_name_domain(char *server, char *domain, char *account_name,
    smb_userinfo_t *user_info)
{
	mlsvc_handle_t domain_handle;
	char *user = smbrdr_ipc_get_user();
	uint32_t status;

	if (lsar_open(server, domain, user, &domain_handle) != 0)
		return (NT_STATUS_INVALID_PARAMETER);

	status = lsar_lookup_names2(&domain_handle, account_name, user_info);
	if (status == NT_STATUS_REVISION_MISMATCH) {
		/*
		 * Not a Windows 2000 domain controller:
		 * use the NT compatible call.
		 */
		status = lsar_lookup_names(&domain_handle, account_name,
		    user_info);
	}

	(void) lsar_close(&domain_handle);
	return (status);
}

/*
 * lsa_test_lookup
 *
 * Test routine for lsa_lookup_name_domain and lsa_lookup_sid2.
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

	if (lsa_lookup_name_builtin(name, user_info) != 0) {
		status = lsa_lookup_name_domain(di->server, di->domain, name,
		    user_info);

		if (status == 0) {
			sid = nt_sid_splice(user_info->domain_sid,
			    user_info->rid);

			(void) lsa_lookup_sid_domain(sid, user_info);
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

/*
 * lsa_lookup_name_lusr
 *
 * Obtains the SID for the given local user name if it
 * can be found. Upon successful return the allocated memory
 * for the returned SID must be freed by the caller.
 *
 * Note that in domain mode this function might actually return
 * a domain SID if local users are mapped to domain users.
 */
static uint32_t
lsa_lookup_name_lusr(char *name, nt_sid_t **sid)
{
	struct passwd *pw;

	if ((pw = getpwnam(name)) == NULL)
		return (NT_STATUS_NO_SUCH_USER);

	if (smb_idmap_getsid(pw->pw_uid, SMB_IDMAP_USER, sid) != IDMAP_SUCCESS)
		return (NT_STATUS_NONE_MAPPED);

	return (NT_STATUS_SUCCESS);
}

/*
 * lsa_lookup_name_lgrp
 *
 * Obtains the SID for the given local group name if it
 * can be found. Upon successful return the allocated memory
 * for the returned SID must be freed by the caller.
 *
 * Note that in domain mode this function might actually return
 * a domain SID if local groups are mapped to domain groups.
 */
static uint32_t
lsa_lookup_name_lgrp(char *name, nt_sid_t **sid)
{
	struct group *gr;

	if ((gr = getgrnam(name)) == NULL)
		return (NT_STATUS_NO_SUCH_ALIAS);

	if (smb_idmap_getsid(gr->gr_gid, SMB_IDMAP_GROUP, sid) != IDMAP_SUCCESS)
		return (NT_STATUS_NONE_MAPPED);

	return (NT_STATUS_SUCCESS);
}

static int
lsa_lookup_mode(const char *domain, const char *name)
{
	int lookup_mode;

	if (nt_builtin_lookup((char *)name))
		return (MLSVC_LOOKUP_BUILTIN);

	if (smb_config_get_secmode() == SMB_SECMODE_WORKGRP)
		return (MLSVC_LOOKUP_LOCAL);

	if ((domain == NULL) || (*domain == '\0'))
		return (MLSVC_LOOKUP_DOMLOC);

	if (mlsvc_is_local_domain(domain) == 1)
		lookup_mode = MLSVC_LOOKUP_LOCAL;
	else
		lookup_mode = MLSVC_LOOKUP_DOMAIN;

	return (lookup_mode);
}

static uint32_t
lsa_lookup_sid_local(nt_sid_t *sid, smb_userinfo_t *ainfo)
{
	char hostname[MAXHOSTNAMELEN];
	struct passwd *pw;
	struct group *gr;
	uid_t id;
	int id_type;

	id_type = SMB_IDMAP_UNKNOWN;
	if (smb_idmap_getid(sid, &id, &id_type) != IDMAP_SUCCESS)
		return (NT_STATUS_NONE_MAPPED);

	switch (id_type) {
	case SMB_IDMAP_USER:
		ainfo->sid_name_use = SidTypeUser;
		if ((pw = getpwuid(id)) == NULL)
			return (NT_STATUS_NO_SUCH_USER);

		ainfo->name = strdup(pw->pw_name);
		break;

	case SMB_IDMAP_GROUP:
		ainfo->sid_name_use = SidTypeAlias;
		if ((gr = getgrgid(id)) == NULL)
			return (NT_STATUS_NO_SUCH_ALIAS);

		ainfo->name = strdup(gr->gr_name);
		break;

	default:
		return (NT_STATUS_NONE_MAPPED);
	}

	if (ainfo->name == NULL)
		return (NT_STATUS_NO_MEMORY);

	ainfo->domain_sid = nt_sid_dup(sid);
	if (nt_sid_split(ainfo->domain_sid, &ainfo->rid) < 0)
		return (NT_STATUS_INTERNAL_ERROR);
	*hostname = '\0';
	(void) smb_getnetbiosname(hostname, MAXHOSTNAMELEN);
	if ((ainfo->domain_name = strdup(hostname)) == NULL)
		return (NT_STATUS_NO_MEMORY);

	return (NT_STATUS_SUCCESS);
}

static uint32_t
lsa_lookup_sid_builtin(nt_sid_t *sid, smb_userinfo_t *ainfo)
{
	char *name;
	WORD sid_name_use;

	if ((name = nt_builtin_lookup_sid(sid, &sid_name_use)) == NULL)
		return (NT_STATUS_NONE_MAPPED);

	ainfo->sid_name_use = sid_name_use;
	ainfo->name = strdup(name);
	ainfo->domain_sid = nt_sid_dup(sid);

	if (ainfo->name == NULL || ainfo->domain_sid == NULL)
		return (NT_STATUS_NO_MEMORY);

	if (sid_name_use != SidTypeDomain)
		(void) nt_sid_split(ainfo->domain_sid, &ainfo->rid);

	if ((name = nt_builtin_lookup_domain(ainfo->name)) != NULL)
		ainfo->domain_name = strdup(name);
	else
		ainfo->domain_name = strdup("UNKNOWN");

	if (ainfo->domain_name == NULL)
		return (NT_STATUS_NO_MEMORY);

	return (NT_STATUS_SUCCESS);
}

static uint32_t
lsa_lookup_sid_domain(nt_sid_t *sid, smb_userinfo_t *ainfo)
{
	mlsvc_handle_t domain_handle;
	char *user = smbrdr_ipc_get_user();
	uint32_t status;

	if (lsar_open(NULL, NULL, user, &domain_handle) != 0)
		return (NT_STATUS_INVALID_PARAMETER);

	status = lsar_lookup_sids2(&domain_handle,
	    (struct mslsa_sid *)sid, ainfo);

	if (status == NT_STATUS_REVISION_MISMATCH) {
		/*
		 * Not a Windows 2000 domain controller:
		 * use the NT compatible call.
		 */
		status = lsar_lookup_sids(&domain_handle,
		    (struct mslsa_sid *)sid, ainfo);
	}

	(void) lsar_close(&domain_handle);
	return (status);
}
