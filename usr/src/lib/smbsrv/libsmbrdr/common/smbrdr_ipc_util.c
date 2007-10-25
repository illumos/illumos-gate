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
 * The IPC connection information is encapsulated within SMB Redirector.
 * Utility functions are defined here to allow other modules to get and
 * set the ipc configuration, as well as, to rollback or commit the
 * changes to the original authentication information.
 */

#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <synch.h>

#include <smbsrv/libsmbrdr.h>

#include <smbsrv/mlsvc.h>
#include <smbsrv/smbinfo.h>
#include <smbrdr.h>
#include <smbrdr_ipc_util.h>

/*
 * The binary NTLM hash is 16 bytes. When it is converted to hexidecimal,
 * it will be at most twice as long.
 */
#define	SMBRDR_IPC_HEX_PASSWD_MAXLEN	(SMBAUTH_HASH_SZ * 2) + 1
#define	SMBRDR_IPC_GETDOMAIN_TIMEOUT	10000

static rwlock_t		smbrdr_ipc_lock;
static smbrdr_ipc_t	ipc_info;
static smbrdr_ipc_t	orig_ipc_info;

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
	char *p;

	bzero(&ipc_info, sizeof (smbrdr_ipc_t));
	bzero(&orig_ipc_info, sizeof (smbrdr_ipc_t));

	smb_config_rdlock();
	p = smb_config_getstr(SMB_CI_RDR_IPCMODE);

	if (!strncasecmp(p, IPC_MODE_AUTH, IPC_MODE_STRLEN)) {
		ipc_info.mode = MLSVC_IPC_ADMIN;

		p = smb_config_getstr(SMB_CI_RDR_IPCUSER);
		if (p)
			(void) strlcpy(ipc_info.user, p,
			    MLSVC_ACCOUNT_NAME_MAX);
		else
			syslog(LOG_WARNING, "smbrdr: (ipc) no admin user name");

		p = smb_config_get(SMB_CI_RDR_IPCPWD);
		if (p) {
			if (strlen(p) != SMBRDR_IPC_HEX_PASSWD_MAXLEN - 1) {
				*ipc_info.passwd = 0;
				syslog(LOG_WARNING,
				    "smbrdr: (ipc) invalid admin password");
			} else {
				(void) hextobin(p,
				    SMBRDR_IPC_HEX_PASSWD_MAXLEN - 1,
				    ipc_info.passwd, SMBAUTH_HASH_SZ);
			}
		} else {
			*ipc_info.passwd = 0;
			syslog(LOG_WARNING, "smbrdr: (ipc) no admin password");
		}

	} else {
		if (!strcasecmp(p, IPC_MODE_FALLBACK_ANON))
			ipc_info.flags |= IPC_FLG_FALLBACK_ANON;

		ipc_info.mode = MLSVC_IPC_ANON;
		(void) strlcpy(ipc_info.user, MLSVC_ANON_USER,
		    MLSVC_ACCOUNT_NAME_MAX);
		*ipc_info.passwd = 0;
	}
	smb_config_unlock();
}

/*
 * smbrdr_ipc_set
 *
 * The given username and password hash will be applied to the
 * ipc_info which will be used by mlsvc_validate_user().
 *
 * If mlsvc_validate_user() succeeds, the calling function is responsible
 * for invoking smbrdr_ipc_commit() for updating the environment
 * variables. Otherwise, it should invoke smbrdr_ipc_rollback() to restore
 * the previous credentials.
 */
void
smbrdr_ipc_set(char *plain_user, unsigned char *passwd_hash)
{
	(void) rw_wrlock(&smbrdr_ipc_lock);
	if (ipc_info.flags & IPC_FLG_FALLBACK_ANON)
		ipc_info.mode = MLSVC_IPC_ADMIN;

	(void) strlcpy(ipc_info.user, plain_user, sizeof (ipc_info.user));
	(void) memcpy(ipc_info.passwd, passwd_hash, SMBAUTH_HASH_SZ);
	ipc_info.flags |= IPC_FLG_NEED_VERIFY;
	(void) rw_unlock(&smbrdr_ipc_lock);

}

/*
 * smbrdr_ipc_commit
 *
 * Save the new admin credentials as environment variables.
 * The binary NTLM password hash is first converted to a
 * hex string before storing in the environment variable.
 *
 * The credentials also saved to the original IPC info as
 * rollback data in case the join domain process
 * fails in the future.
 */
void
smbrdr_ipc_commit()
{
	unsigned char hexpass[SMBRDR_IPC_HEX_PASSWD_MAXLEN];

	(void) rw_wrlock(&smbrdr_ipc_lock);
	smb_config_wrlock();
	(void) smb_config_set(SMB_CI_RDR_IPCUSER, ipc_info.user);
	(void) bintohex(ipc_info.passwd, sizeof (ipc_info.passwd),
	    (char *)hexpass, sizeof (hexpass));
	hexpass[SMBRDR_IPC_HEX_PASSWD_MAXLEN - 1] = 0;
	(void) smb_config_set(SMB_CI_RDR_IPCPWD, (char *)hexpass);

	ipc_info.flags &= ~IPC_FLG_NEED_VERIFY;

	if (ipc_info.flags & IPC_FLG_FALLBACK_ANON) {
		ipc_info.flags &= ~IPC_FLG_FALLBACK_ANON;
		ipc_info.mode = MLSVC_IPC_ADMIN;
		(void) smb_config_set(SMB_CI_RDR_IPCMODE, IPC_MODE_AUTH);
		syslog(LOG_DEBUG, "smbrdr: (ipc) Authenticated IPC "
		    "connection has been restored");
	}

	(void) memcpy(&orig_ipc_info, &ipc_info, sizeof (smbrdr_ipc_t));
	smb_config_unlock();
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

	ipc_info.flags &= ~IPC_FLG_NEED_VERIFY;

	if (ipc_info.flags & IPC_FLG_FALLBACK_ANON)
		ipc_info.mode = MLSVC_IPC_ANON;
	(void) rw_unlock(&smbrdr_ipc_lock);
}

/*
 * Get & Set functions
 */
int
smbrdr_ipc_get_mode()
{
	int	mode;

	(void) rw_rdlock(&smbrdr_ipc_lock);
	mode = ipc_info.mode;
	(void) rw_unlock(&smbrdr_ipc_lock);

	return (mode);
}

char *
smbrdr_ipc_get_user()
{
	char	*user;

	(void) rw_rdlock(&smbrdr_ipc_lock);
	user = ipc_info.user;
	(void) rw_unlock(&smbrdr_ipc_lock);
	return (user);
}

char *
smbrdr_ipc_get_passwd()
{
	char	*passwd;

	(void) rw_rdlock(&smbrdr_ipc_lock);
	passwd = ipc_info.passwd;
	(void) rw_unlock(&smbrdr_ipc_lock);
	return (passwd);
}

unsigned
smbrdr_ipc_get_flags()
{
	unsigned	flags;

	(void) rw_rdlock(&smbrdr_ipc_lock);
	flags = ipc_info.flags;
	(void) rw_unlock(&smbrdr_ipc_lock);
	return (flags);
}

void
smbrdr_ipc_set_fallback()
{
	(void) rw_wrlock(&smbrdr_ipc_lock);
	ipc_info.flags |= IPC_FLG_FALLBACK_ANON;
	(void) rw_unlock(&smbrdr_ipc_lock);
}

void
smbrdr_ipc_unset_fallback()
{
	(void) rw_wrlock(&smbrdr_ipc_lock);
	ipc_info.flags &= ~IPC_FLG_FALLBACK_ANON;
	(void) rw_unlock(&smbrdr_ipc_lock);
}

/*
 * Whether the smbrdr.ipc.mode is set to fallback,anon or not
 */
int
smbrdr_ipc_is_fallback()
{
	int is_fallback;

	smb_config_rdlock();
	is_fallback = (!strcasecmp(smb_config_getstr(SMB_CI_RDR_IPCMODE),
	    IPC_MODE_FALLBACK_ANON) ? 1 : 0);
	smb_config_unlock();

	return (is_fallback);
}

/*
 * smbrdr_ipc_save_mode
 *
 * Set the SMBRDR_IPC_MODE_ENV variable and update the
 * IPC mode of the cache.
 */
void
smbrdr_ipc_save_mode(char *val)
{
	(void) rw_wrlock(&smbrdr_ipc_lock);
	smb_config_wrlock();
	(void) smb_config_set(SMB_CI_RDR_IPCMODE, val);
	ipc_info.mode = !strncasecmp(val, IPC_MODE_AUTH, IPC_MODE_STRLEN)
	    ? MLSVC_IPC_ADMIN : MLSVC_IPC_ANON;
	smb_config_unlock();
	(void) rw_unlock(&smbrdr_ipc_lock);
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
	char *user, *pwd;

	if (ipc_info.mode != MLSVC_IPC_ADMIN)
		return (0);

	smb_config_rdlock();
	user = smb_config_get(SMB_CI_RDR_IPCUSER);
	pwd = smb_config_get(SMB_CI_RDR_IPCPWD);
	smb_config_unlock();
	if ((user == NULL) && pwd)
		return (1);

	(void) rw_rdlock(&smbrdr_ipc_lock);
	user = ipc_info.user;
	pwd = ipc_info.passwd;
	(void) rw_unlock(&smbrdr_ipc_lock);

	return (!(*user && *pwd));
}

static char *
smbrdr_ipc_modestr(int mode)
{
	switch (mode) {
	case MLSVC_IPC_ANON:
		return ("Anonymous");

	case MLSVC_IPC_ADMIN:
		return ("Authenticated");

	default:
		return ("Unknown");
	}
}

/*
 * For debugging purposes only.
 */
void
smbrdr_ipc_loginfo()
{
	smbrdr_ipc_t	tmp;
	smbrdr_ipc_t	tmporg;

	(void) rw_rdlock(&smbrdr_ipc_lock);
	(void) memcpy(&tmp, &ipc_info, sizeof (smbrdr_ipc_t));
	(void) memcpy(&tmporg, &orig_ipc_info, sizeof (smbrdr_ipc_t));
	(void) rw_unlock(&smbrdr_ipc_lock);

	syslog(LOG_DEBUG, "smbrdr: current IPC info:");
	syslog(LOG_DEBUG, "\t%s (user=%s, flags:0x%X)",
	    smbrdr_ipc_modestr(tmp.mode), tmp.user, tmp.flags);

	syslog(LOG_DEBUG, "smbrdr: original IPC info:");
	syslog(LOG_DEBUG, "\t%s (user=%s, flags:0x%X)",
	    smbrdr_ipc_modestr(tmporg.mode), tmporg.user, tmporg.flags);
}

/*
 * smbrdr_ipc_is_valid
 *
 * Determine whether the ipc_info has been validated or not.
 *
 */
int
smbrdr_ipc_is_valid()
{
	int isvalid;

	(void) rw_rdlock(&smbrdr_ipc_lock);
	isvalid = (ipc_info.flags & IPC_FLG_NEED_VERIFY) ? 0 : 1;
	(void) rw_unlock(&smbrdr_ipc_lock);

	return (isvalid);
}
