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

#ifndef _SMB_KEYCHAIN_H
#define	_SMB_KEYCHAIN_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * External interface to the libsmbfs/netsmb keychain
 * storage mechanism.  This interface is consumed by
 * the "smbutil" commands: login, logout, ...
 * and by the SMBFS PAM module.
 */

#define	SMB_KEYCHAIN_SUCCESS	0
#define	SMB_KEYCHAIN_BADPASSWD	300
#define	SMB_KEYCHAIN_BADDOMAIN	301
#define	SMB_KEYCHAIN_BADUSER	302
#define	SMB_KEYCHAIN_NODRIVER	303
#define	SMB_KEYCHAIN_UNKNOWN	304

/* Add a password to the keychain. */
int smbfs_keychain_add(uid_t uid, const char *domain, const char *user,
	const char *password);

/* Delete a password from the keychain. */
int smbfs_keychain_del(uid_t uid, const char *domain, const char *user);

/*
 * Check for existence of a keychain entry.
 * Returns 0 if it exists, else ENOENT.
 */
int smbfs_keychain_chk(const char *domain, const char *user);

/*
 * Delete all keychain entries owned by the caller.
 */
int smbfs_keychain_del_owner(void);

/*
 * Delete all keychain entries (regardless of owner).
 * Requires super-user privliege.
 */
int smbfs_keychain_del_everyone(void);

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
	char *dom, int maxdom, char *usr, int maxusr);

#endif /* _SMB_KEYCHAIN_H */
