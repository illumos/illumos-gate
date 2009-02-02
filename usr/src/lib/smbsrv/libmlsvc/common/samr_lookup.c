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
 * Security Access Manager RPC (SAMR) library interface functions for
 * query and lookup calls.
 */


#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/libmlsvc.h>
#include <smbsrv/ntstatus.h>
#include <smbsrv/smb_sid.h>
#include <samlib.h>
#include <smbsrv/libmlrpc.h>

static int samr_setup_user_info(WORD, struct samr_QueryUserInfo *,
    union samr_user_info *);
static void samr_set_user_unknowns(struct samr_SetUserInfo23 *);
static void samr_set_user_logon_hours(struct samr_SetUserInfo *);
static int samr_set_user_password(smb_auth_info_t *, BYTE *);

/*
 * samr_lookup_domain
 *
 * Lookup up the domain SID for the specified domain name. The handle
 * should be one returned from samr_connect. The allocated memory for
 * the returned SID must be freed by caller.
 */
smb_sid_t *
samr_lookup_domain(mlsvc_handle_t *samr_handle, char *domain_name)
{
	struct samr_LookupDomain arg;
	smb_sid_t *domsid = NULL;
	int opnum;
	size_t length;

	if (ndr_is_null_handle(samr_handle) || domain_name == NULL)
		return (NULL);

	opnum = SAMR_OPNUM_LookupDomain;
	bzero(&arg, sizeof (struct samr_LookupDomain));

	(void) memcpy(&arg.handle, &samr_handle->handle,
	    sizeof (samr_handle_t));

	length = mts_wcequiv_strlen(domain_name);
	if (ndr_rpc_server_os(samr_handle) == NATIVE_OS_WIN2000)
		length += sizeof (mts_wchar_t);

	arg.domain_name.length = length;
	arg.domain_name.allosize = length;
	arg.domain_name.str = (unsigned char *)domain_name;

	if (ndr_rpc_call(samr_handle, opnum, &arg) == 0)
		domsid = smb_sid_dup((smb_sid_t *)arg.sid);

	ndr_rpc_release(samr_handle);
	return (domsid);
}

/*
 * samr_enum_local_domains
 *
 * Get the list of local domains supported by a server.
 *
 * Returns NT status codes.
 */
DWORD
samr_enum_local_domains(mlsvc_handle_t *samr_handle)
{
	struct samr_EnumLocalDomain arg;
	int opnum;
	DWORD status;

	if (ndr_is_null_handle(samr_handle))
		return (NT_STATUS_INVALID_PARAMETER);

	opnum = SAMR_OPNUM_EnumLocalDomains;
	bzero(&arg, sizeof (struct samr_EnumLocalDomain));

	(void) memcpy(&arg.handle, &samr_handle->handle,
	    sizeof (samr_handle_t));
	arg.enum_context = 0;
	arg.max_length = 0x00002000;	/* Value used by NT */

	if (ndr_rpc_call(samr_handle, opnum, &arg) != 0) {
		status = NT_STATUS_INVALID_PARAMETER;
	} else {
		status = NT_SC_VALUE(arg.status);

		/*
		 * Handle none-mapped status quietly.
		 */
		if (status != NT_STATUS_NONE_MAPPED)
			ndr_rpc_status(samr_handle, opnum, arg.status);
	}

	ndr_rpc_release(samr_handle);
	return (status);
}

/*
 * samr_lookup_domain_names
 *
 * Lookup up the given name in the domain specified by domain_handle.
 * Upon a successful lookup the information is returned in the account
 * arg and caller must free allocated memories by calling smb_account_free().
 *
 * Returns NT status codes.
 */
uint32_t
samr_lookup_domain_names(mlsvc_handle_t *domain_handle, char *name,
    smb_account_t *account)
{
	struct samr_LookupNames arg;
	int opnum;
	uint32_t status;
	size_t length;

	if (ndr_is_null_handle(domain_handle) ||
	    name == NULL || account == NULL) {
		return (NT_STATUS_INVALID_PARAMETER);
	}

	bzero(account, sizeof (smb_account_t));
	opnum = SAMR_OPNUM_LookupNames;
	bzero(&arg, sizeof (struct samr_LookupNames));

	(void) memcpy(&arg.handle, &domain_handle->handle,
	    sizeof (samr_handle_t));
	arg.n_entry = 1;
	arg.max_n_entry = 1000;
	arg.index = 0;
	arg.total = 1;

	length = mts_wcequiv_strlen(name);
	if (ndr_rpc_server_os(domain_handle) == NATIVE_OS_WIN2000)
		length += sizeof (mts_wchar_t);

	arg.name.length = length;
	arg.name.allosize = length;
	arg.name.str = (unsigned char *)name;

	if (ndr_rpc_call(domain_handle, opnum, &arg) != 0) {
		status = NT_STATUS_INVALID_PARAMETER;
	} else if (arg.status != NT_STATUS_SUCCESS) {
		status = NT_SC_VALUE(arg.status);

		/*
		 * Handle none-mapped status quietly.
		 */
		if (status != NT_STATUS_NONE_MAPPED)
			ndr_rpc_status(domain_handle, opnum, arg.status);
	} else {
		account->a_type = arg.rid_types.rid_type[0];
		account->a_rid = arg.rids.rid[0];
		status = NT_STATUS_SUCCESS;
	}

	ndr_rpc_release(domain_handle);
	return (status);
}

/*
 * samr_query_user_info
 *
 * Query information on a specific user. The handle must be a valid
 * user handle obtained via samr_open_user.
 *
 * Returns 0 on success, otherwise returns -ve error code.
 */
int
samr_query_user_info(mlsvc_handle_t *user_handle, WORD switch_value,
    union samr_user_info *user_info)
{
	struct samr_QueryUserInfo arg;
	int opnum;
	int rc;

	if (ndr_is_null_handle(user_handle) || user_info == 0)
		return (-1);

	opnum = SAMR_OPNUM_QueryUserInfo;
	bzero(&arg, sizeof (struct samr_QueryUserInfo));

	(void) memcpy(&arg.user_handle, &user_handle->handle,
	    sizeof (samr_handle_t));
	arg.switch_value = switch_value;

	if (ndr_rpc_call(user_handle, opnum, &arg) != 0) {
		ndr_rpc_release(user_handle);
		return (-1);
	}

	if (arg.status != 0)
		rc = -1;
	else
		rc = samr_setup_user_info(switch_value, &arg, user_info);

	ndr_rpc_release(user_handle);
	return (rc);
}

/*
 * samr_setup_user_info
 *
 * Private function to set up the samr_user_info data. Dependent on
 * the switch value this function may use strdup which will malloc
 * memory. The caller is responsible for deallocating this memory.
 *
 * Returns 0 on success, otherwise returns -1.
 */
static int
samr_setup_user_info(WORD switch_value,
    struct samr_QueryUserInfo *arg, union samr_user_info *user_info)
{
	struct samr_QueryUserInfo1 *info1;
	struct samr_QueryUserInfo6 *info6;

	switch (switch_value) {
	case 1:
		info1 = &arg->ru.info1;
		user_info->info1.username = strdup(
		    (char const *)info1->username.str);
		user_info->info1.fullname = strdup(
		    (char const *)info1->fullname.str);
		user_info->info1.description = strdup(
		    (char const *)info1->description.str);
		user_info->info1.unknown = 0;
		user_info->info1.group_rid = info1->group_rid;
		return (0);

	case 6:
		info6 = &arg->ru.info6;
		user_info->info6.username = strdup(
		    (char const *)info6->username.str);
		user_info->info6.fullname = strdup(
		    (char const *)info6->fullname.str);
		return (0);

	case 7:
		user_info->info7.username = strdup(
		    (char const *)arg->ru.info7.username.str);
		return (0);

	case 8:
		user_info->info8.fullname = strdup(
		    (char const *)arg->ru.info8.fullname.str);
		return (0);

	case 9:
		user_info->info9.group_rid = arg->ru.info9.group_rid;
		return (0);

	case 16:
		return (0);

	default:
		break;
	};

	return (-1);
}

/*
 * samr_query_user_groups
 *
 * Query the groups for a specific user. The handle must be a valid
 * user handle obtained via samr_open_user. The list of groups is
 * returned in group_info. Note that group_info->groups is allocated
 * using malloc. The caller is responsible for deallocating this
 * memory when it is no longer required. If group_info->n_entry is 0
 * then no memory was allocated.
 *
 * Returns 0 on success, otherwise returns -1.
 */
int
samr_query_user_groups(mlsvc_handle_t *user_handle, int *n_groups,
    struct samr_UserGroups **groups)
{
	struct samr_QueryUserGroups arg;
	int opnum;
	int rc;
	int nbytes;

	if (ndr_is_null_handle(user_handle))
		return (-1);

	opnum = SAMR_OPNUM_QueryUserGroups;
	bzero(&arg, sizeof (struct samr_QueryUserGroups));

	(void) memcpy(&arg.user_handle, &user_handle->handle,
	    sizeof (samr_handle_t));

	rc = ndr_rpc_call(user_handle, opnum, &arg);
	if (rc == 0) {
		if (arg.info == 0) {
			rc = -1;
		} else {
			nbytes = arg.info->n_entry *
			    sizeof (struct samr_UserGroups);

			if ((*groups = malloc(nbytes)) == NULL) {
				*n_groups = 0;
				rc = -1;
			} else {
				*n_groups = arg.info->n_entry;
				bcopy(arg.info->groups, *groups, nbytes);
			}
		}
	}

	ndr_rpc_release(user_handle);
	return (rc);
}

/*
 * samr_get_user_pwinfo
 *
 * Get some user password info. I'm not sure what this is yet but it is
 * part of the create user sequence. The handle must be a valid user
 * handle. Since I don't know what this is returning, I haven't provided
 * any return data yet.
 *
 * Returns 0 on success. Otherwise returns an NT status code.
 */
DWORD
samr_get_user_pwinfo(mlsvc_handle_t *user_handle)
{
	struct samr_GetUserPwInfo arg;
	int opnum;
	DWORD status;

	if (ndr_is_null_handle(user_handle))
		return (NT_STATUS_INVALID_PARAMETER);

	opnum = SAMR_OPNUM_GetUserPwInfo;
	bzero(&arg, sizeof (struct samr_GetUserPwInfo));
	(void) memcpy(&arg.user_handle, &user_handle->handle,
	    sizeof (samr_handle_t));

	if (ndr_rpc_call(user_handle, opnum, &arg) != 0) {
		status = NT_STATUS_INVALID_PARAMETER;
	} else if (arg.status != 0) {
		ndr_rpc_status(user_handle, opnum, arg.status);
		status = NT_SC_VALUE(arg.status);
	} else {
		status = 0;
	}

	ndr_rpc_release(user_handle);
	return (status);
}

/*
 * samr_set_user_info
 *
 * Returns 0 on success. Otherwise returns an NT status code.
 * NT status codes observed so far:
 *	NT_STATUS_WRONG_PASSWORD
 */
/*ARGSUSED*/
DWORD
samr_set_user_info(mlsvc_handle_t *user_handle, smb_auth_info_t *auth)
{
	struct samr_SetUserInfo arg;
	int opnum;
	DWORD status = 0;

	if (ndr_is_null_handle(user_handle))
		return (NT_STATUS_INVALID_PARAMETER);

	opnum = SAMR_OPNUM_SetUserInfo;
	bzero(&arg, sizeof (struct samr_SetUserInfo));
	(void) memcpy(&arg.user_handle, &user_handle->handle,
	    sizeof (samr_handle_t));

	arg.info.index = SAMR_SET_USER_INFO_23;
	arg.info.switch_value = SAMR_SET_USER_INFO_23;

	samr_set_user_unknowns(&arg.info.ru.info23);
	samr_set_user_logon_hours(&arg);

	if (samr_set_user_password(auth, arg.info.ru.info23.password) < 0)
		status = NT_STATUS_INTERNAL_ERROR;

	if (ndr_rpc_call(user_handle, opnum, &arg) != 0) {
		status = NT_STATUS_INVALID_PARAMETER;
	} else if (arg.status != 0) {
		ndr_rpc_status(user_handle, opnum, arg.status);
		status = NT_SC_VALUE(arg.status);
	}

	ndr_rpc_release(user_handle);
	return (status);
}

static void
samr_set_user_unknowns(struct samr_SetUserInfo23 *info)
{
	bzero(info, sizeof (struct samr_SetUserInfo23));

	info->sd.length = 0;
	info->sd.data = 0;
	info->user_rid = 0;
	info->group_rid = DOMAIN_GROUP_RID_USERS;

	/*
	 * The trust account value used here should probably
	 * match the one used to create the trust account.
	 */
	info->acct_info = SAMR_AF_WORKSTATION_TRUST_ACCOUNT;
	info->flags = 0x09F827FA;
}

/*
 * samr_set_user_logon_hours
 *
 * SamrSetUserInfo appears to contain some logon hours information, which
 * looks like a varying, conformant array. The top level contains a value
 * (units), which probably indicates the how to interpret the array. The
 * array definition looks like it contains a maximum size, an initial
 * offset and a bit length (units/8), followed by the bitmap.
 *
 *  (info)
 * +-------+
 * | units |
 * +-------+    (hours)
 * | hours |-->+-----------+
 * +-------+   | max_is    |
 *             +-----------+
 *             | first_is  |
 *             +-----------+
 *             | length_is |
 *             +------------------------+
 *             | bitmap[length_is]      |
 *             +---------+--------------+
 *
 * 10080 minutes/week => 10080/8 = 1260 (0x04EC) bytes.
 * 168 hours/week => 168/8 = 21 (0xA8) bytes.
 * In the netmon examples seen so far, all bits are set to 1, i.e.
 * an array containing 0xff. This is probably the default setting.
 *
 * ndrgen has a problem with complex [size_is] statements (length/8).
 * So, for now, we fake it using two separate components.
 */
static void
samr_set_user_logon_hours(struct samr_SetUserInfo *sui)
{
	sui->logon_hours.size = SAMR_HOURS_MAX_SIZE;
	sui->logon_hours.first = 0;
	sui->logon_hours.length = SAMR_SET_USER_HOURS_SZ;
	(void) memset(sui->logon_hours.bitmap, 0xFF, SAMR_SET_USER_HOURS_SZ);

	sui->info.ru.info23.logon_info.units = SAMR_HOURS_PER_WEEK;
	sui->info.ru.info23.logon_info.hours =
	    (DWORD)(uintptr_t)sui->logon_hours.bitmap;
}

/*
 * samr_set_user_password
 *
 * Set the initial password for the user.
 *
 * Returns 0 if everything goes well, -1 if there is trouble generating a
 * key.
 */
static int
samr_set_user_password(smb_auth_info_t *auth, BYTE *oem_password)
{
	unsigned char nt_key[SMBAUTH_SESSION_KEY_SZ];
	char hostname[NETBIOS_NAME_SZ];

	randomize((char *)oem_password, SAMR_SET_USER_DATA_SZ);

	/*
	 * The new password is going to be the NetBIOS name of the system
	 * in lower case.
	 */
	if (smb_getnetbiosname(hostname, sizeof (hostname)) != 0)
		return (-1);

	(void) utf8_strlwr(hostname);

	if (smb_auth_gen_session_key(auth, nt_key) != SMBAUTH_SUCCESS)
		return (-1);

	/*
	 * Generate the OEM password from the hostname and the user session
	 * key(nt_key).
	 */
	/*LINTED E_BAD_PTR_CAST_ALIGN*/
	(void) sam_oem_password((oem_password_t *)oem_password,
	    (unsigned char *)hostname, nt_key);
	return (0);
}
