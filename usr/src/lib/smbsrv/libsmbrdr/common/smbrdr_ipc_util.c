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
 * The IPC connection information is encapsulated within SMB Redirector.
 * Utility functions are defined here to allow other modules to get and
 * set the ipc configuration, as well as, to rollback or commit the
 * changes to the original authentication information.
 */

#include <string.h>
#include <strings.h>
#include <synch.h>

#include <smbsrv/libsmbrdr.h>
#include <smbsrv/mlsvc.h>
#include <smbsrv/smbinfo.h>
#include <smbrdr.h>
#include <smbrdr_ipc_util.h>

#define	SMBRDR_IPC_GETDOMAIN_TIMEOUT	10000

static rwlock_t		smbrdr_ipc_lock;
static smbrdr_ipc_t	ipc_info;
static smbrdr_ipc_t	orig_ipc_info;

static int
smbrdr_get_machine_pwd_hash(unsigned char *hash)
{
	char pwd[SMB_PI_MAX_PASSWD];
	int rc = 0;

	rc = smb_config_getstr(SMB_CI_MACHINE_PASSWD, pwd, sizeof (pwd));
	if ((rc != SMBD_SMF_OK) || *pwd == '\0') {
		return (-1);
	}

	if (smb_auth_ntlm_hash(pwd, hash) != 0)
		rc = -1;

	return (rc);
}

/*
 * smbrdr_ipc_init
 *
 * Get system configuration regarding IPC connection
 * credentials and initialize related variables.
 * This function will normally be called at startup
 * (i.e. at the time smbrdr gets loaded).
 */
void
smbrdr_ipc_init(void)
{
	int rc;

	(void) rw_wrlock(&smbrdr_ipc_lock);
	bzero(&ipc_info, sizeof (smbrdr_ipc_t));
	bzero(&orig_ipc_info, sizeof (smbrdr_ipc_t));

	(void) smb_gethostname(ipc_info.user, MLSVC_ACCOUNT_NAME_MAX - 1, 0);
	(void) strlcat(ipc_info.user, "$", MLSVC_ACCOUNT_NAME_MAX);
	rc = smbrdr_get_machine_pwd_hash(ipc_info.passwd);
	if (rc != 0)
		*ipc_info.passwd = 0;
	(void) rw_unlock(&smbrdr_ipc_lock);

}

/*
 * smbrdr_ipc_set
 *
 * The given username and password hash will be applied to the
 * ipc_info, which will be used for setting up the authenticated IPC
 * channel during join domain.
 *
 * If domain join operation succeeds, smbrdr_ipc_commit() should be
 * invoked to set the ipc_info with host credentials. Otherwise,
 * smbrdr_ipc_rollback() should be called to restore the previous
 * credentials.
 */
void
smbrdr_ipc_set(char *plain_user, unsigned char *passwd_hash)
{
	(void) rw_wrlock(&smbrdr_ipc_lock);
	(void) strlcpy(ipc_info.user, plain_user, sizeof (ipc_info.user));
	(void) memcpy(ipc_info.passwd, passwd_hash, SMBAUTH_HASH_SZ);
	(void) rw_unlock(&smbrdr_ipc_lock);

}

/*
 * smbrdr_ipc_commit
 *
 * Save the host credentials, which will be used for any authenticated
 * IPC channel establishment after domain join.
 *
 * The host credentials is also saved to the original IPC info as
 * rollback data in case the join domain process fails in the future.
 */
void
smbrdr_ipc_commit()
{
	(void) rw_wrlock(&smbrdr_ipc_lock);
	(void) smb_gethostname(ipc_info.user, MLSVC_ACCOUNT_NAME_MAX - 1, 0);
	(void) strlcat(ipc_info.user, "$", MLSVC_ACCOUNT_NAME_MAX);
	(void) smbrdr_get_machine_pwd_hash(ipc_info.passwd);
	(void) memcpy(&orig_ipc_info, &ipc_info, sizeof (smbrdr_ipc_t));
	(void) rw_unlock(&smbrdr_ipc_lock);
}

/*
 * smbrdr_ipc_rollback
 *
 * Restore the original credentials
 */
void
smbrdr_ipc_rollback()
{
	(void) rw_wrlock(&smbrdr_ipc_lock);
	(void) strlcpy(ipc_info.user, orig_ipc_info.user,
	    sizeof (ipc_info.user));
	(void) memcpy(ipc_info.passwd, orig_ipc_info.passwd,
	    sizeof (ipc_info.passwd));
	(void) rw_unlock(&smbrdr_ipc_lock);
}

/*
 * Get & Set functions
 */
char *
smbrdr_ipc_get_user()
{
	char	*user;

	(void) rw_rdlock(&smbrdr_ipc_lock);
	user = ipc_info.user;
	(void) rw_unlock(&smbrdr_ipc_lock);
	return (user);
}

unsigned char *
smbrdr_ipc_get_passwd()
{
	unsigned char	*passwd;

	(void) rw_rdlock(&smbrdr_ipc_lock);
	passwd = ipc_info.passwd;
	(void) rw_unlock(&smbrdr_ipc_lock);
	return (passwd);
}

/*
 * smbrdr_ipc_skip_lsa_query
 *
 * Determine whether LSA monitor should skip the LSA query due to the
 * incomplete authentication information if IPC is configured to be
 * authenticated.
 */
int
smbrdr_ipc_skip_lsa_query()
{
	char *user;
	unsigned char *pwd;


	(void) rw_rdlock(&smbrdr_ipc_lock);
	user = ipc_info.user;
	pwd = ipc_info.passwd;
	(void) rw_unlock(&smbrdr_ipc_lock);

	return (!(*user && *pwd));
}
