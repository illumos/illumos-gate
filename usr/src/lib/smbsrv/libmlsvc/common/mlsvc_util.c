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
 * Utility functions to support the RPC interface library.
 */

#include <stdio.h>
#include <stdarg.h>
#include <strings.h>
#include <unistd.h>
#include <netdb.h>
#include <stdlib.h>

#include <sys/time.h>
#include <sys/systm.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/libsmbrdr.h>
#include <smbsrv/libsmbns.h>
#include <smbsrv/libmlsvc.h>

#include <smbsrv/smbinfo.h>
#include <smbsrv/ntsid.h>
#include <smbsrv/lsalib.h>
#include <smbsrv/samlib.h>
#include <smbsrv/mlsvc_util.h>
#include <smbsrv/mlsvc.h>

/* Domain join support (using MS-RPC) */
static boolean_t mlsvc_ntjoin_support = B_FALSE;

extern int netr_open(char *, char *, mlsvc_handle_t *);
extern int netr_close(mlsvc_handle_t *);
extern DWORD netlogon_auth(char *, mlsvc_handle_t *, DWORD);
extern int mlsvc_user_getauth(char *, char *, smb_auth_info_t *);

/*
 * Compare the supplied domain name with the local hostname.
 * We need to deal with both server names and fully-qualified
 * domain names.
 *
 * Returns:
 *	0	The specified domain is not the local domain,
 *	1	The Specified domain is the local domain.
 *	-1	Invalid parameter or unable to get the local
 *		system information.
 */
int
mlsvc_is_local_domain(const char *domain)
{
	char hostname[MAXHOSTNAMELEN];
	int rc;

	if (smb_config_get_secmode() == SMB_SECMODE_WORKGRP)
		return (1);

	if (strchr(domain, '.') != NULL)
		rc = smb_getfqhostname(hostname, MAXHOSTNAMELEN);
	else
		rc = smb_gethostname(hostname, MAXHOSTNAMELEN, 1);

	if (rc != 0)
		return (-1);

	if (strcasecmp(domain, hostname) == 0)
		return (1);

	return (0);
}

/*
 * mlsvc_lookup_name
 *
 * This is just a wrapper for lsa_lookup_name.
 *
 * The memory for the sid is allocated using malloc so the caller should
 * call free when it is no longer required.
 */
uint32_t
mlsvc_lookup_name(char *account, nt_sid_t **sid, uint16_t *sid_type)
{
	smb_userinfo_t *ainfo;
	uint32_t status;

	if ((ainfo = mlsvc_alloc_user_info()) == NULL)
		return (NT_STATUS_NO_MEMORY);

	status = lsa_lookup_name(NULL, account, *sid_type, ainfo);
	if (status == NT_STATUS_SUCCESS) {
		*sid = ainfo->user_sid;
		ainfo->user_sid = NULL;
		*sid_type = ainfo->sid_name_use;
	}

	mlsvc_free_user_info(ainfo);
	return (status);
}

/*
 * mlsvc_lookup_sid
 *
 * This is just a wrapper for lsa_lookup_sid.
 *
 * The allocated memory for the returned name must be freed by caller upon
 * successful return.
 */
uint32_t
mlsvc_lookup_sid(nt_sid_t *sid, char **name)
{
	smb_userinfo_t *ainfo;
	uint32_t status;
	int namelen;

	if ((ainfo = mlsvc_alloc_user_info()) == NULL)
		return (NT_STATUS_NO_MEMORY);

	status = lsa_lookup_sid(sid, ainfo);
	if (status == NT_STATUS_SUCCESS) {
		namelen = strlen(ainfo->domain_name) + strlen(ainfo->name) + 2;
		if ((*name = malloc(namelen)) == NULL) {
			mlsvc_free_user_info(ainfo);
			return (NT_STATUS_NO_MEMORY);
		}
		(void) snprintf(*name, namelen, "%s\\%s",
		    ainfo->domain_name, ainfo->name);
	}

	mlsvc_free_user_info(ainfo);
	return (status);
}

/*
 * mlsvc_alloc_user_info
 *
 * Allocate a user_info structure and set the contents to zero. A
 * pointer to the user_info structure is returned.
 */
smb_userinfo_t *
mlsvc_alloc_user_info(void)
{
	smb_userinfo_t *user_info;

	user_info = (smb_userinfo_t *)malloc(sizeof (smb_userinfo_t));
	if (user_info == NULL)
		return (NULL);

	bzero(user_info, sizeof (smb_userinfo_t));
	return (user_info);
}

/*
 * mlsvc_free_user_info
 *
 * Free a user_info structure. This function ensures that the contents
 * of the user_info are freed as well as the user_info itself.
 */
void
mlsvc_free_user_info(smb_userinfo_t *user_info)
{
	if (user_info) {
		mlsvc_release_user_info(user_info);
		free(user_info);
	}
}

/*
 * mlsvc_release_user_info
 *
 * Release the contents of a user_info structure and zero out the
 * elements but do not free the user_info structure itself. This
 * function cleans out the structure so that it can be reused without
 * worrying about stale contents.
 */
void
mlsvc_release_user_info(smb_userinfo_t *user_info)
{
	int i;

	if (user_info == NULL)
		return;

	free(user_info->name);
	free(user_info->domain_sid);
	free(user_info->domain_name);
	free(user_info->groups);

	if (user_info->n_other_grps) {
		for (i = 0; i < user_info->n_other_grps; i++)
			free(user_info->other_grps[i].sid);

		free(user_info->other_grps);
	}

	free(user_info->user_sid);
	free(user_info->pgrp_sid);
	bzero(user_info, sizeof (smb_userinfo_t));
}

/*
 * mlsvc_setadmin_user_info
 *
 * Determines if the given user is the domain Administrator or a
 * member of Domain Admins or Administrators group and set the
 * user_info->flags accordingly.
 */
void
mlsvc_setadmin_user_info(smb_userinfo_t *user_info)
{
	nt_domain_t *domain;
	smb_group_t grp;
	int rc, i;

	if ((domain = nt_domain_lookupbytype(NT_DOMAIN_PRIMARY)) == NULL)
		return;

	if (!nt_sid_is_equal((nt_sid_t *)user_info->domain_sid, domain->sid))
		return;

	if (user_info->rid == DOMAIN_USER_RID_ADMIN)
		user_info->flags |= SMB_UINFO_FLAG_DADMIN;
	else if (user_info->primary_group_rid == DOMAIN_GROUP_RID_ADMINS)
		user_info->flags |= SMB_UINFO_FLAG_DADMIN;
	else {
		for (i = 0; i < user_info->n_groups; i++)
			if (user_info->groups[i].rid == DOMAIN_GROUP_RID_ADMINS)
				user_info->flags |= SMB_UINFO_FLAG_DADMIN;
	}

	rc = smb_lgrp_getbyname("Administrators", &grp);
	if (rc == SMB_LGRP_SUCCESS) {
		if (smb_lgrp_is_member(&grp, user_info->user_sid))
			user_info->flags |= SMB_UINFO_FLAG_LADMIN;
		smb_lgrp_free(&grp);
	}
}

/*
 * mlsvc_string_save
 *
 * This is a convenience function to prepare strings for an RPC call.
 * An ms_string_t is set up with the appropriate lengths and str is
 * set up to point to a copy of the original string on the heap. The
 * macro MLRPC_HEAP_STRSAVE is an alias for mlrpc_heap_strsave, which
 * extends the heap and copies the string into the new area.
 */
int
mlsvc_string_save(ms_string_t *ms, char *str, struct mlrpc_xaction *mxa)
{
	if (str == NULL)
		return (0);

	ms->length = mts_wcequiv_strlen(str);
	ms->allosize = ms->length + sizeof (mts_wchar_t);

	if ((ms->str = MLRPC_HEAP_STRSAVE(mxa, str)) == NULL)
		return (0);

	return (1);
}

/*
 * mlsvc_sid_save
 *
 * Expand the heap and copy the sid into the new area.
 * Returns a pointer to the copy of the sid on the heap.
 */
nt_sid_t *
mlsvc_sid_save(nt_sid_t *sid, struct mlrpc_xaction *mxa)
{
	nt_sid_t *heap_sid;
	unsigned size;

	if (sid == NULL)
		return (NULL);

	size = nt_sid_length(sid);

	if ((heap_sid = (nt_sid_t *)MLRPC_HEAP_MALLOC(mxa, size)) == NULL)
		return (0);

	bcopy(sid, heap_sid, size);
	return (heap_sid);
}

/*
 * mlsvc_is_null_handle
 *
 * Check a handle against a null handle. Returns 1 if the handle is
 * null. Otherwise returns 0.
 */
int
mlsvc_is_null_handle(mlsvc_handle_t *handle)
{
	static ms_handle_t zero_handle;

	if (handle == NULL || handle->context == NULL)
		return (1);

	if (!memcmp(&handle->handle, &zero_handle, sizeof (ms_handle_t)))
		return (1);

	return (0);
}

/*
 * mlsvc_join
 *
 * Returns NT status codes.
 */
DWORD
mlsvc_join(char *server, char *domain, char *plain_user, char *plain_text)
{
	smb_auth_info_t auth;
	smb_ntdomain_t *di;
	int erc;
	DWORD status;
	mlsvc_handle_t netr_handle;
	char machine_passwd[MLSVC_MACHINE_ACCT_PASSWD_MAX];
	char fqdn[MAXHOSTNAMELEN];

	machine_passwd[0] = '\0';

	/*
	 * Ensure that the domain name is uppercase.
	 */
	(void) utf8_strupr(domain);

	/*
	 * There is no point continuing if the domain information is
	 * not available. Wait for up to 10 seconds and then give up.
	 */
	if ((di = smb_getdomaininfo(10)) == 0) {
		status = NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
		return (status);
	}

	if (strcasecmp(domain, di->domain) != 0) {
		status = NT_STATUS_INVALID_PARAMETER;
		return (status);
	}

	erc = mlsvc_logon(server, domain, plain_user);

	if (erc == AUTH_USER_GRANT) {
		if (mlsvc_ntjoin_support == B_FALSE) {
			if (smb_resolve_fqdn(domain, fqdn, MAXHOSTNAMELEN) != 1)
				return (NT_STATUS_INVALID_PARAMETER);

			if (ads_join(fqdn, plain_user, plain_text,
			    machine_passwd, sizeof (machine_passwd))
			    == ADJOIN_SUCCESS)
				status = NT_STATUS_SUCCESS;
			else
				status = NT_STATUS_UNSUCCESSFUL;
		} else {
			if (mlsvc_user_getauth(server, plain_user, &auth)
			    != 0) {
				status = NT_STATUS_INVALID_PARAMETER;
				return (status);
			}

			status = sam_create_trust_account(server, domain,
			    &auth);
			if (status == NT_STATUS_SUCCESS) {
				(void) smb_gethostname(machine_passwd,
				    sizeof (machine_passwd), 0);
				(void) utf8_strlwr(machine_passwd);
			}
		}

		if (status == NT_STATUS_SUCCESS) {
			erc = smb_config_setstr(SMB_CI_MACHINE_PASSWD,
			    machine_passwd);
			if (erc != SMBD_SMF_OK)
				return (NT_STATUS_UNSUCCESSFUL);

			/*
			 * If we successfully create a trust account, we mark
			 * ourselves as a domain member in the environment so
			 * that we use the SAMLOGON version of the NETLOGON
			 * PDC location protocol.
			 */
			(void) smb_config_setbool(SMB_CI_DOMAIN_MEMB, B_TRUE);

			if (netr_open(server, domain, &netr_handle) == 0) {
				status = netlogon_auth(server, &netr_handle,
				    NETR_FLG_INIT);
				(void) netr_close(&netr_handle);
			} else {
				status = NT_STATUS_OPEN_FAILED;
			}
		}
	} else {
		status = NT_STATUS_LOGON_FAILURE;
	}

	return (status);
}
