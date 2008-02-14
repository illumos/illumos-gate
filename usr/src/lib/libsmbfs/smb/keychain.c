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
 * External interface to the libsmbfs/netsmb keychain
 * storage mechanism.  This interface is consumed by
 * the "smbutil" commands: login, logout, ...
 * and by the SMBFS PAM module.
 */

#include <sys/types.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <libintl.h>

#include <netsmb/smb_dev.h>
#include <netsmb/smb_lib.h>
#include <netsmb/smb_keychain.h>

#include <cflib.h>

/* common func. for add/del/chk */
static int
smbfs_keychain_cmn(
	int cmd,
	uid_t uid,
	const char *dom,
	const char *usr,
	const char *pass)
{
	smbioc_pk_t pk;
	int err, fd;

	memset(&pk, 0, sizeof (pk));

	pk.pk_uid = uid;

	switch (cmd) {

	case SMBIOC_PK_ADD:
		if (pass == NULL)
			return (SMB_KEYCHAIN_BADPASSWD);
		if (strlcpy(pk.pk_pass, pass, sizeof (pk.pk_pass)) >=
		    sizeof (pk.pk_pass))
			return (SMB_KEYCHAIN_BADPASSWD);
		/* FALLTHROUGH */

	case SMBIOC_PK_CHK:
	case SMBIOC_PK_DEL:
		if (dom == NULL)
			return (SMB_KEYCHAIN_BADDOMAIN);
		if (strlcpy(pk.pk_dom, dom, sizeof (pk.pk_dom)) >=
		    sizeof (pk.pk_dom))
			return (SMB_KEYCHAIN_BADDOMAIN);
		if (usr == NULL)
			return (SMB_KEYCHAIN_BADUSER);
		if (strlcpy(pk.pk_usr, usr, sizeof (pk.pk_usr)) >=
		    sizeof (pk.pk_usr))
			return (SMB_KEYCHAIN_BADUSER);
		break;

	case SMBIOC_PK_DEL_OWNER:	/* all owned by the caller */
	case SMBIOC_PK_DEL_EVERYONE:	/* all owned by everyone */
		/*
		 * These two do not copyin any args, but we'll
		 * pass &pk here anyway just so we can use the
		 * common code path below.
		 */
		break;

	default:
		return (SMB_KEYCHAIN_UNKNOWN);
	}

	fd = smb_open_driver();
	if (fd < 0) {
		err = SMB_KEYCHAIN_NODRIVER;
		goto out;
	}

	err = 0;
	if (ioctl(fd, cmd, &pk) < 0)
		err = errno;

	close(fd);
out:
	memset(&pk, 0, sizeof (pk));
	return (err);
}

/* Add a password to the keychain. */
int
smbfs_keychain_add(uid_t uid, const char *dom, const char *usr,
	const char *pass)
{
	return (smbfs_keychain_cmn(SMBIOC_PK_ADD, uid, dom, usr, pass));
}

/* Delete a password from the keychain. */
int
smbfs_keychain_del(uid_t uid, const char *dom, const char *usr)
{
	return (smbfs_keychain_cmn(SMBIOC_PK_DEL, uid, dom, usr, NULL));
}

/*
 * Check for existence of a keychain entry.
 * Returns 0 if it exists, else ENOENT.
 */
int
smbfs_keychain_chk(const char *dom, const char *usr)
{
	return (smbfs_keychain_cmn(SMBIOC_PK_CHK, (uid_t)-1, dom, usr, NULL));
}

/*
 * Delete all keychain entries owned by the caller.
 */
int
smbfs_keychain_del_owner()
{
	return (smbfs_keychain_cmn(SMBIOC_PK_DEL_OWNER, getuid(), 0, 0, 0));
}

/*
 * Delete all keychain entries (regardless of onwer).
 * Requires super-user privliege.
 */
int
smbfs_keychain_del_everyone()
{
	return (smbfs_keychain_cmn(SMBIOC_PK_DEL_EVERYONE, getuid(), 0, 0, 0));
}


/*
 * This is not really part of the keychain library,
 * but is typically needed in code that wants to
 * provide (editable) defaults for domain/user
 *
 * Get default domain and user names
 * Server name is optional.
 */
int
smbfs_default_dom_usr(const char *home, const char *server,
	char *dom, int maxdom, char *usr, int maxusr)
{
	struct smb_ctx sctx, *ctx = &sctx;
	int err;

	err = smb_ctx_init(ctx, 0, NULL, SMBL_VC, SMBL_VC, SMB_ST_ANY);
	if (err)
		return (err);
	if (server)
		smb_ctx_setserver(ctx, server);
	if (home && *home)
		ctx->ct_home = (char *)home;
	err = smb_ctx_readrc(ctx);
	if (err)
		return (err);
	if (smb_rc)
		rc_close(smb_rc);

	if (dom)
		strlcpy(dom, ctx->ct_ssn.ioc_workgroup, maxdom);

	if (usr)
		strlcpy(usr, ctx->ct_ssn.ioc_user, maxusr);

	return (0);
}
