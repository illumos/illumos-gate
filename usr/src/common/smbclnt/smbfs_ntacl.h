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
 *
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _SMBFS_NTACL_H
#define	_SMBFS_NTACL_H

/*
 * Internal functions for dealing with
 * NT Security data structures.
 */

#include <netsmb/mchain.h>

/*
 * Internal form of an NT SID
 * Same as on the wire, but possibly byte-swapped.
 */
typedef struct i_ntsid {
	uint8_t	sid_revision;
	uint8_t	sid_subauthcount;
	uint8_t	sid_authority[6];
	uint32_t sid_subauthvec[1]; /* actually len=subauthcount */
} i_ntsid_t;
#define	I_SID_SIZE(sacnt)	(8 + 4 * (sacnt))

/*
 * Internal form of an NT ACE - first the header.
 * See MS SDK: ACE_HEADER  (For MS, it's the OtW form)
 * Note: ace_size here is the in-memoy size, not OtW.
 */
typedef struct i_ntace_hdr {
	uint8_t		ace_type;
	uint8_t		ace_flags;
	uint16_t	ace_size;
} i_ntace_hdr_t;

/*
 * Simple ACE for types: ACCESS_ALLOWED through SYSTEM_ALARM
 * See MS SDK: ACCESS_ALLOWED_ACE, ACCESS_DENIED_ACE,
 * SYSTEM_AUDIT_ACE, SYSTEM_ALARM_ACE.
 *
 * The above are the only types that appear in a V2 ACL.
 * Note that in the Windows SDK, the SID is stored as
 * "flat" data after the ACE header.  This implementation
 * stores the SID as a pointer instead.
 */
typedef struct i_ntace_v2 {
	i_ntace_hdr_t	ace_hdr;
	uint32_t	ace_rights; /* generic, standard, specific, etc */
	i_ntsid_t	*ace_sid;
} i_ntace_v2_t;

/*
 * A union for convenience of the conversion code.
 * There are lots more ACE types, ignored for now.
 */
typedef union i_ntace_u {
	i_ntace_hdr_t	ace_hdr;
	i_ntace_v2_t	ace_v2;
} i_ntace_t;

/*
 * Internal form of an NT ACL (see sacl/dacl below)
 */
typedef struct i_ntacl {
	uint8_t		acl_revision;	/* 0x02 observed with W2K */
	uint16_t	acl_acecount;
	i_ntace_t	*acl_acevec[1]; /* actually, len=acecount */
} i_ntacl_t;

/*
 * Internal form of an NT Security Descriptor (SD)
 */
typedef struct i_ntsd {
	uint8_t		sd_revision;	/* 0x01 observed between W2K */
	uint8_t		sd_rmctl;	/* resource mgr control (MBZ) */
	uint16_t	sd_flags;
	i_ntsid_t	*sd_owner;
	i_ntsid_t	*sd_group;
	i_ntacl_t	*sd_sacl;
	i_ntacl_t	*sd_dacl;
} i_ntsd_t;

/*
 * Import a raw SD (mb chain) into "internal" form.
 * (like "absolute" form per. NT docs)
 * Returns allocated data in sdp
 */
int md_get_ntsd(mdchain_t *mbp, i_ntsd_t **sdp);

/*
 * Export an "internal" SD into an raw SD (mb chain).
 * (a.k.a "self-relative" form per. NT docs)
 * Returns allocated mbchain in mbp.
 */
int mb_put_ntsd(mbchain_t *mbp, i_ntsd_t *sd);

/*
 * Convert an internal SD to a ZFS-style ACL.
 * Get uid/gid too if pointers != NULL.
 */
#if defined(_KERNEL) || defined(_FAKE_KERNEL)
int smbfs_acl_sd2zfs(i_ntsd_t *, vsecattr_t *, uid_t *, gid_t *);
#else /* _KERNEL */
/* See also: lib/libsmbfs/netsmb/smbfs_acl.h */
int smbfs_acl_sd2zfs(struct i_ntsd *, acl_t *, uid_t *, gid_t *);
#endif /* _KERNEL */

/*
 * Convert a ZFS-style ACL to an internal SD.
 * Set owner/group too if selector indicates.
 * Always need to pass uid+gid, either the new
 * (when setting them) or existing, so that any
 * owner@ or group@ ACEs can be translated.
 */
#if defined(_KERNEL) || defined(_FAKE_KERNEL)
int smbfs_acl_zfs2sd(vsecattr_t *, uid_t, gid_t, uint32_t, i_ntsd_t **);
#else /* _KERNEL */
/* See also: lib/libsmbfs/netsmb/smbfs_acl.h */
int smbfs_acl_zfs2sd(acl_t *, uid_t, gid_t, uint32_t, struct i_ntsd **);
#endif /* _KERNEL */

/*
 * Free an i_ntsd_t from md_get_ntsd() or smbfs_acl_zfs2sd().
 * See also: lib/libsmbfs/netsmb/smbfs_acl.h
 */
void smbfs_acl_free_sd(struct i_ntsd *);

/*
 * Convert an NT SID to string format.
 */
int smbfs_sid2str(i_ntsid_t *sid,
	char *obuf, size_t olen, uint32_t *ridp);

#endif	/* _SMBFS_NTACL_H */
