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
mlsvc_lookup_name(char *name, smb_sid_t **sid, uint16_t *sid_type)
{
	smb_account_t account;
	uint32_t status;

	status = lsa_lookup_name(name, *sid_type, &account);
	if (status == NT_STATUS_SUCCESS) {
		*sid = account.a_sid;
		account.a_sid = NULL;
		*sid_type = account.a_type;
		smb_account_free(&account);
	}

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
	smb_account_t ainfo;
	uint32_t status;
	int namelen;

	if ((status = lsa_lookup_sid(sid, &ainfo)) == NT_STATUS_SUCCESS) {
		namelen = strlen(ainfo.a_domain) + strlen(ainfo.a_name) + 2;
		if ((*name = malloc(namelen)) != NULL)
			(void) snprintf(*name, namelen, "%s\\%s",
			    ainfo.a_domain, ainfo.a_name);
		else
			status = NT_STATUS_NO_MEMORY;

		smb_account_free(&ainfo);
	}

	return (status);
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
