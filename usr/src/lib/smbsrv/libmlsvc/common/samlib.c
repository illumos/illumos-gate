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

/*
 * This module provides the high level interface to the SAM RPC
 * functions.
 */

#include <unistd.h>
#include <netdb.h>
#include <alloca.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/libsmbrdr.h>
#include <smbsrv/libmlsvc.h>

#include <smbsrv/ntstatus.h>
#include <smbsrv/ntaccess.h>
#include <lsalib.h>
#include <samlib.h>

/*
 * Valid values for the OEM OWF password encryption.
 */
#define	SAM_PASSWORD_516	516
#define	SAM_KEYLEN		16

extern DWORD samr_set_user_info(mlsvc_handle_t *, smb_auth_info_t *);

static struct samr_sid *sam_get_domain_sid(mlsvc_handle_t *, char *, char *,
    smb_userinfo_t *);

/*
 * sam_create_trust_account
 *
 * Create a trust account for this system.
 *
 *	SAMR_AF_WORKSTATION_TRUST_ACCOUNT: servers and workstations.
 *	SAMR_AF_SERVER_TRUST_ACCOUNT: domain controllers.
 *
 * Returns NT status codes.
 */
DWORD
sam_create_trust_account(char *server, char *domain, smb_auth_info_t *auth)
{
	char account_name[SMB_SAMACCT_MAXLEN];
	DWORD status;

	if (smb_getsamaccount(account_name, SMB_SAMACCT_MAXLEN) != 0)
		return (NT_STATUS_INTERNAL_ERROR);

	/*
	 * The trust account value here should match
	 * the value that will be used when the user
	 * information is set on this account.
	 */
	status = sam_create_account(server, domain, account_name,
	    auth, SAMR_AF_WORKSTATION_TRUST_ACCOUNT);

	/*
	 * Based on network traces, a Windows 2000 client will
	 * always try to create the computer account first.
	 * If it existed, then check the user permission to join
	 * the domain.
	 */

	if (status == NT_STATUS_USER_EXISTS)
		status = sam_check_user(server, domain, account_name);

	return (status);
}


/*
 * sam_create_account
 *
 * Create the specified domain account in the SAM database on the
 * domain controller.
 *
 * Account flags:
 *		SAMR_AF_NORMAL_ACCOUNT
 *		SAMR_AF_WORKSTATION_TRUST_ACCOUNT
 *		SAMR_AF_SERVER_TRUST_ACCOUNT
 *
 * Returns NT status codes.
 */
DWORD
sam_create_account(char *server, char *domain_name, char *account_name,
    smb_auth_info_t *auth, DWORD account_flags)
{
	mlsvc_handle_t samr_handle;
	mlsvc_handle_t domain_handle;
	mlsvc_handle_t user_handle;
	smb_userinfo_t *user_info;
	union samr_user_info sui;
	struct samr_sid *sid;
	DWORD rid;
	DWORD status;
	int rc;
	char *user = smbrdr_ipc_get_user();

	if ((user_info = mlsvc_alloc_user_info()) == 0)
		return (NT_STATUS_NO_MEMORY);

	rc = samr_open(server, domain_name, user, SAM_CONNECT_CREATE_ACCOUNT,
	    &samr_handle);

	if (rc != 0) {
		status = NT_STATUS_OPEN_FAILED;
		smb_tracef("SamCreateAccount[%s\\%s]: %s",
		    domain_name, account_name, xlate_nt_status(status));
		mlsvc_free_user_info(user_info);
		return (status);
	}

	sid = sam_get_domain_sid(&samr_handle, server, domain_name, user_info);

	status = samr_open_domain(&samr_handle,
	    SAM_DOMAIN_CREATE_ACCOUNT, sid, &domain_handle);

	if (status == NT_STATUS_SUCCESS) {
		status = samr_create_user(&domain_handle, account_name,
		    account_flags, &rid, &user_handle);

		if (status == NT_STATUS_SUCCESS) {
			(void) samr_query_user_info(&user_handle,
			    SAMR_QUERY_USER_UNKNOWN16, &sui);

			(void) samr_get_user_pwinfo(&user_handle);
			(void) samr_set_user_info(&user_handle, auth);
			(void) samr_close_handle(&user_handle);
		} else if (status != NT_STATUS_USER_EXISTS) {
			smb_tracef("SamCreateAccount[%s]: %s",
			    account_name, xlate_nt_status(status));
		}

		(void) samr_close_handle(&domain_handle);
	} else {
		smb_tracef("SamCreateAccount[%s]: open domain failed",
		    account_name);
		status = (NT_STATUS_CANT_ACCESS_DOMAIN_INFO);
	}

	(void) samr_close_handle(&samr_handle);
	mlsvc_free_user_info(user_info);
	free(sid);
	return (status);
}


/*
 * sam_remove_trust_account
 *
 * Attempt to remove the workstation trust account for this system.
 * Administrator access is required to perform this operation.
 *
 * Returns NT status codes.
 */
DWORD
sam_remove_trust_account(char *server, char *domain)
{
	char account_name[SMB_SAMACCT_MAXLEN];

	if (smb_getsamaccount(account_name, SMB_SAMACCT_MAXLEN) != 0)
		return (NT_STATUS_INTERNAL_ERROR);

	return (sam_delete_account(server, domain, account_name));
}


/*
 * sam_delete_account
 *
 * Attempt to remove an account from the SAM database on the specified
 * server.
 *
 * Returns NT status codes.
 */
DWORD
sam_delete_account(char *server, char *domain_name, char *account_name)
{
	mlsvc_handle_t samr_handle;
	mlsvc_handle_t domain_handle;
	mlsvc_handle_t user_handle;
	smb_userinfo_t *user_info;
	struct samr_sid *sid;
	DWORD rid;
	DWORD access_mask;
	DWORD status;
	int rc;
	char *user = smbrdr_ipc_get_user();

	if ((user_info = mlsvc_alloc_user_info()) == 0)
		return (NT_STATUS_NO_MEMORY);

	rc = samr_open(server, domain_name, user, SAM_LOOKUP_INFORMATION,
	    &samr_handle);

	if (rc != 0) {
		mlsvc_free_user_info(user_info);
		return (NT_STATUS_OPEN_FAILED);
	}

	sid = sam_get_domain_sid(&samr_handle, server, domain_name, user_info);

	status = samr_open_domain(&samr_handle, SAM_LOOKUP_INFORMATION,
	    sid, &domain_handle);
	if (status == 0) {
		mlsvc_release_user_info(user_info);
		status = samr_lookup_domain_names(&domain_handle,
		    account_name, user_info);

		if (status == 0) {
			rid = user_info->rid;
			access_mask = STANDARD_RIGHTS_EXECUTE | DELETE;

			status = samr_open_user(&domain_handle, access_mask,
			    rid, &user_handle);
			if (status == NT_STATUS_SUCCESS) {
				if (samr_delete_user(&user_handle) != 0)
					(void) samr_close_handle(&user_handle);
			}
		}

		(void) samr_close_handle(&domain_handle);
	}

	(void) samr_close_handle(&samr_handle);
	mlsvc_free_user_info(user_info);
	free(sid);
	return (status);
}

/*
 * sam_check_user
 *
 * Check to see if user have permission to access computer account.
 * The user being checked is the specified user for joining the Solaris
 * host to the domain.
 */
DWORD
sam_check_user(char *server, char *domain_name, char *account_name)
{
	mlsvc_handle_t samr_handle;
	mlsvc_handle_t domain_handle;
	mlsvc_handle_t user_handle;
	smb_userinfo_t *user_info;
	struct samr_sid *sid;
	DWORD rid;
	DWORD access_mask;
	DWORD status;
	int rc;
	char *user = smbrdr_ipc_get_user();

	if ((user_info = mlsvc_alloc_user_info()) == 0)
		return (NT_STATUS_NO_MEMORY);

	rc = samr_open(server, domain_name, user, SAM_LOOKUP_INFORMATION,
	    &samr_handle);

	if (rc != 0) {
		mlsvc_free_user_info(user_info);
		return (NT_STATUS_OPEN_FAILED);
	}

	sid = sam_get_domain_sid(&samr_handle, server, domain_name, user_info);

	status = samr_open_domain(&samr_handle, SAM_LOOKUP_INFORMATION, sid,
	    &domain_handle);
	if (status == 0) {
		mlsvc_release_user_info(user_info);
		status = samr_lookup_domain_names(&domain_handle, account_name,
		    user_info);

		if (status == 0) {
			rid = user_info->rid;

			/*
			 * Win2000 client uses this access mask.  The
			 * following SAMR user specific rights bits are
			 * set: set password, set attributes, and get
			 * attributes.
			 */

			access_mask = 0xb0;

			status = samr_open_user(&domain_handle,
			    access_mask, rid, &user_handle);
			if (status == NT_STATUS_SUCCESS)
				(void) samr_close_handle(&user_handle);
		}

		(void) samr_close_handle(&domain_handle);
	}

	(void) samr_close_handle(&samr_handle);
	mlsvc_free_user_info(user_info);
	free(sid);
	return (status);
}

/*
 * sam_lookup_name
 *
 * Lookup an account name in the SAM database on the specified domain
 * controller. Provides the account RID on success.
 *
 * Returns NT status codes.
 */
DWORD
sam_lookup_name(char *server, char *domain_name, char *account_name,
    DWORD *rid_ret)
{
	mlsvc_handle_t samr_handle;
	mlsvc_handle_t domain_handle;
	smb_userinfo_t *user_info;
	struct samr_sid *domain_sid;
	int rc;
	DWORD status;
	char *user = smbrdr_ipc_get_user();

	*rid_ret = 0;

	if ((user_info = mlsvc_alloc_user_info()) == 0)
		return (NT_STATUS_NO_MEMORY);

	rc = samr_open(server, domain_name, user, SAM_LOOKUP_INFORMATION,
	    &samr_handle);

	if (rc != 0) {
		mlsvc_free_user_info(user_info);
		return (NT_STATUS_OPEN_FAILED);
	}

	rc = samr_lookup_domain(&samr_handle, domain_name, user_info);
	if (rc != 0) {
		(void) samr_close_handle(&samr_handle);
		mlsvc_free_user_info(user_info);
		return (NT_STATUS_NO_SUCH_DOMAIN);
	}

	domain_sid = (struct samr_sid *)user_info->domain_sid;

	status = samr_open_domain(&samr_handle, SAM_LOOKUP_INFORMATION,
	    domain_sid, &domain_handle);
	if (status == 0) {
		mlsvc_release_user_info(user_info);

		status = samr_lookup_domain_names(&domain_handle,
		    account_name, user_info);
		if (status == 0)
			*rid_ret = user_info->rid;

		(void) samr_close_handle(&domain_handle);
	}

	(void) samr_close_handle(&samr_handle);
	mlsvc_free_user_info(user_info);
	return (status);
}


/*
 * sam_get_local_domains
 *
 * Query a remote server to get the list of local domains that it
 * supports.
 *
 * Returns NT status codes.
 */
DWORD
sam_get_local_domains(char *server, char *domain_name)
{
	mlsvc_handle_t samr_handle;
	DWORD status;
	int rc;
	char *user = smbrdr_ipc_get_user();

	rc = samr_open(server, domain_name, user, SAM_ENUM_LOCAL_DOMAIN,
	    &samr_handle);
	if (rc != 0)
		return (NT_STATUS_OPEN_FAILED);

	status = samr_enum_local_domains(&samr_handle);
	(void) samr_close_handle(&samr_handle);
	return (status);
}

/*
 * sam_oem_password
 *
 * Generate an OEM password.
 */
int
sam_oem_password(oem_password_t *oem_password, unsigned char *new_password,
    unsigned char *old_password)
{
	mts_wchar_t *unicode_password;
	int length;

#ifdef PBSHORTCUT
	assert(sizeof (oem_password_t) == SAM_PASSWORD_516);
#endif /* PBSHORTCUT */

	length = strlen((char const *)new_password);
	unicode_password = alloca((length + 1) * sizeof (mts_wchar_t));

	length = smb_auth_qnd_unicode((unsigned short *)unicode_password,
	    (char *)new_password, length);
	oem_password->length = length;

	(void) memcpy(&oem_password->data[512 - length],
	    unicode_password, length);

	rand_hash((unsigned char *)oem_password, sizeof (oem_password_t),
	    old_password, SAM_KEYLEN);

	return (0);
}

static struct samr_sid *
sam_get_domain_sid(mlsvc_handle_t *samr_handle, char *server, char *domain_name,
    smb_userinfo_t *user_info)
{
	struct samr_sid *sid;

	if (ndr_rpc_server_os(samr_handle) == NATIVE_OS_WIN2000) {
		nt_domain_t *ntdp;
		lsa_info_t account_domain;

		if ((ntdp = nt_domain_lookup_name(domain_name)) == 0) {
			if (lsa_query_account_domain_info(server,
			    domain_name, &account_domain) != NT_STATUS_SUCCESS)
				return (NULL);

			sid = (struct samr_sid *)
			    account_domain.i_domain.di_account.n_sid;
		} else {
			sid = (struct samr_sid *)smb_sid_dup(ntdp->sid);
		}
	} else {
		if (samr_lookup_domain(samr_handle, domain_name, user_info)
		    != 0)
			return (NULL);

		sid = (struct samr_sid *)smb_sid_dup(user_info->domain_sid);
	}

	return (sid);
}
