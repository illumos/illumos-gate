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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _NETSMB_SMBFS_ACL_H
#define	_NETSMB_SMBFS_ACL_H

/*
 * Get/set ACL via contracted interface in libsmbfs.
 * The ACL is in the form used by libsec (type=ACE_T)
 * but we need to carry the uid/gid info here too.
 */

#include <sys/acl.h>

#ifdef	__cplusplus
extern "C" {
#endif

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
 *
 * The struct i_ntsid is opaque in this I/F.
 * Real decl. in: common/smbclnt/smbfs_ntacl.h
 */
struct i_ntsd;

/*
 * Get an "internal form" SD from the FD (opened in smbfs).
 * Allocates a hierarchy in isdp.  Caller must free it via
 * smbfs_acl_free_isd()
 */
int smbfs_acl_getsd(int fd, uint32_t, struct i_ntsd **);

/*
 * Set an "internal form" SD onto the FD (opened in smbfs).
 */
int smbfs_acl_setsd(int fd, uint32_t, struct i_ntsd *);

/*
 * Selector bits (2nd arg above) copied from smb.h so we
 * don't need that whole thing exposed to our consumers.
 * Any mismatch would be detected in smb/acl_api.c
 */
#define	OWNER_SECURITY_INFORMATION		0x00000001
#define	GROUP_SECURITY_INFORMATION		0x00000002
#define	DACL_SECURITY_INFORMATION		0x00000004
#define	SACL_SECURITY_INFORMATION		0x00000008

struct __FILE;
void smbfs_acl_print_sd(struct __FILE *, struct i_ntsd *);

/*
 * These are duplicated from common/smbclnt/smbfs_ntacl.h
 * rather than exporting that header for this library.
 * Any mismatch would be detected in smb/acl_api.c
 */
int smbfs_acl_sd2zfs(struct i_ntsd *, acl_t *, uid_t *, gid_t *);
int smbfs_acl_zfs2sd(acl_t *, uid_t, gid_t, uint32_t, struct i_ntsd **);
void smbfs_acl_free_sd(struct i_ntsd *);

#ifdef	__cplusplus
}
#endif

#endif	/* _NETSMB_SMBFS_ACL_H */
