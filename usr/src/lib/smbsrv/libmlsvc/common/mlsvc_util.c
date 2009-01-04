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
#include <lsalib.h>
#include <samlib.h>
#include <smbsrv/netrauth.h>

/* Domain join support (using MS-RPC) */
static boolean_t mlsvc_ntjoin_support = B_FALSE;

extern int netr_open(char *, char *, mlsvc_handle_t *);
extern int netr_close(mlsvc_handle_t *);
extern DWORD netlogon_auth(char *, mlsvc_handle_t *, DWORD);
extern int mlsvc_user_getauth(char *, char *, smb_auth_info_t *);

/*
 * mlsvc_lookup_name
 *
 * This is just a wrapper for lsa_lookup_name.
 *
 * The memory for the sid is allocated using malloc so the caller should
 * call free when it is no longer required.
 */
uint32_t
mlsvc_lookup_name(char *account, smb_sid_t **sid, uint16_t *sid_type)
{
	smb_userinfo_t *ainfo;
	uint32_t status;

	if ((ainfo = mlsvc_alloc_user_info()) == NULL)
		return (NT_STATUS_NO_MEMORY);

	status = lsa_lookup_name(account, *sid_type, ainfo);
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
mlsvc_lookup_sid(smb_sid_t *sid, char **name)
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

	free(user_info->session_key);
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

	if (!smb_sid_cmp((smb_sid_t *)user_info->domain_sid, domain->sid))
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

DWORD
mlsvc_netlogon(char *server, char *domain)
{
	mlsvc_handle_t netr_handle;
	DWORD status;

	if (netr_open(server, domain, &netr_handle) == 0) {
		status = netlogon_auth(server, &netr_handle,
		    NETR_FLG_INIT);
		(void) netr_close(&netr_handle);
	} else {
		status = NT_STATUS_OPEN_FAILED;
	}

	return (status);
}

/*
 * mlsvc_join
 *
 * Returns NT status codes.
 */
DWORD
mlsvc_join(smb_domain_t *dinfo, char *user, char *plain_text)
{
	smb_auth_info_t auth;
	int erc;
	DWORD status;
	char machine_passwd[NETR_MACHINE_ACCT_PASSWD_MAX];

	machine_passwd[0] = '\0';

	/*
	 * Ensure that the domain name is uppercase.
	 */
	(void) utf8_strupr(dinfo->d_nbdomain);

	erc = mlsvc_logon(dinfo->d_dc, dinfo->d_nbdomain, user);

	if (erc == AUTH_USER_GRANT) {
		if (mlsvc_ntjoin_support == B_FALSE) {

			if (smb_ads_join(dinfo->d_fqdomain, user, plain_text,
			    machine_passwd, sizeof (machine_passwd))
			    == SMB_ADJOIN_SUCCESS)
				status = NT_STATUS_SUCCESS;
			else
				status = NT_STATUS_UNSUCCESSFUL;
		} else {
			if (mlsvc_user_getauth(dinfo->d_dc, user, &auth)
			    != 0) {
				status = NT_STATUS_INVALID_PARAMETER;
				return (status);
			}

			status = sam_create_trust_account(dinfo->d_dc,
			    dinfo->d_nbdomain, &auth);
			if (status == NT_STATUS_SUCCESS) {
				(void) smb_getnetbiosname(machine_passwd,
				    sizeof (machine_passwd));
				(void) utf8_strlwr(machine_passwd);
			}
		}

		if (status == NT_STATUS_SUCCESS) {
			erc = smb_setdomainprops(NULL, dinfo->d_dc,
			    machine_passwd);
			if (erc != 0)
				return (NT_STATUS_UNSUCCESSFUL);

			status = mlsvc_netlogon(dinfo->d_dc, dinfo->d_nbdomain);
		}
	} else {
		status = NT_STATUS_LOGON_FAILURE;
	}

	return (status);
}
