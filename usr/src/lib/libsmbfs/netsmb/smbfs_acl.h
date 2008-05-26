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

#ifndef _NETSMB_SMBFS_ACL_H
#define	_NETSMB_SMBFS_ACL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Get/set ACL via contracted interface in libsmbfs.
 * The ACL is in the form used by libsec (type=ACE_T)
 * but we need to carry the uid/gid info here too.
 */

#include <sys/acl.h>

/*
 * Get a ZFS-style acl from an FD opened in smbfs.
 * Intentionally similar to: facl_get(3SEC)
 *
 * Allocates an acl_t via libsec.  Free with: acl_free(3SEC)
 * Get owner/group IDs too if ID pointers != NULL
 */
int smbfs_acl_get(int fd, acl_t **, uid_t *, gid_t *);

/*
 * Set a ZFS-style acl onto an FD opened in smbfs.
 * Intentionally similar to: facl_set(3SEC)
 *
 * The acl_t must be of type ACE_T (from libsec).
 * Set owner/group IDs too if ID values != -1
 */
int smbfs_acl_set(int fd, acl_t *, uid_t, gid_t);


/*
 * Slightly lower-level functions, allowing access to
 * the raw Windows Security Descriptor (SD)
 */
typedef struct i_ntsd i_ntsd_t;

/*
 * Get an "internal form" SD from the FD (opened in smbfs).
 * Allocates a hierarchy in isdp.  Caller must free it via
 * smbfs_acl_free_isd()
 */
int smbfs_acl_getsd(int fd, uint32_t, i_ntsd_t **);

/*
 * Set an "internal form" SD onto the FD (opened in smbfs).
 */
int smbfs_acl_setsd(int fd, uint32_t, i_ntsd_t *);

/*
 * Convert an internal SD to a ZFS-style ACL.
 * Get uid/gid too if pointers != NULL.
 */
int smbfs_acl_sd2zfs(i_ntsd_t *, acl_t *, uid_t *, gid_t *);

/*
 * Convert an internal SD to a ZFS-style ACL.
 * Include owner/group too if uid/gid != -1.
 */
int smbfs_acl_zfs2sd(acl_t *, uid_t, gid_t, i_ntsd_t **);

void smbfs_acl_free_sd(i_ntsd_t *);
void smbfs_acl_print_sd(FILE *, i_ntsd_t *);

#endif	/* _NETSMB_SMBFS_ACL_H */
