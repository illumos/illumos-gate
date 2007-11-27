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

#ifndef _SMB_SECDESC_H
#define	_SMB_SECDESC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/acl.h>
#include <smbsrv/ntsid.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Discretionary Access Control List (DACL)
 *
 * A Discretionary Access Control List (DACL), often abbreviated to
 * ACL, is a list of access controls which either allow or deny access
 * for users or groups to a resource. There is a list header followed
 * by a list of access control entries (ACE). Each ACE specifies the
 * access allowed or denied to a single user or group (identified by
 * a SID).
 *
 * There is another access control list object called a System Access
 * Control List (SACL), which is used to control auditing, but no
 * support is provideed for SACLs at this time.
 *
 * ACL header format:
 *
 *    3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
 *    1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 *   +-------------------------------+---------------+---------------+
 *   |            AclSize            |      Sbz1     |  AclRevision  |
 *   +-------------------------------+---------------+---------------+
 *   |              Sbz2             |           AceCount            |
 *   +-------------------------------+-------------------------------+
 *
 * AclRevision specifies the revision level of the ACL. This value should
 * be ACL_REVISION, unless the ACL contains an object-specific ACE, in which
 * case this value must be ACL_REVISION_DS. All ACEs in an ACL must be at the
 * same revision level.
 *
 * ACE header format:
 *
 *    3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
 *    1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 *   +---------------+-------+-------+---------------+---------------+
 *   |            AceSize            |    AceFlags   |     AceType   |
 *   +---------------+-------+-------+---------------+---------------+
 *
 * Access mask format:
 *
 *    3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
 *    1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 *   +---------------+---------------+-------------------------------+
 *   |G|G|G|G|Res'd|A| StandardRights|         SpecificRights        |
 *   |R|W|E|A|     |S|               |                               |
 *   +-+-------------+---------------+-------------------------------+
 *
 *   typedef struct ACCESS_MASK {
 *       WORD SpecificRights;
 *       BYTE StandardRights;
 *       BYTE AccessSystemAcl : 1;
 *       BYTE Reserved : 3;
 *       BYTE GenericAll : 1;
 *       BYTE GenericExecute : 1;
 *       BYTE GenericWrite : 1;
 *       BYTE GenericRead : 1;
 *   } ACCESS_MASK;
 *
 */

#define	ACL_REVISION1			1
#define	ACL_REVISION2			2
#define	MIN_ACL_REVISION2		ACL_REVISION2
#define	ACL_REVISION3			3
#define	ACL_REVISION4			4
#define	MAX_ACL_REVISION		ACL_REVISION4

/*
 * Current ACE and ACL revision Levels
 */
#define	ACE_REVISION			1
#define	ACL_REVISION			ACL_REVISION2
#define	ACL_REVISION_DS			ACL_REVISION4


#define	ACCESS_ALLOWED_ACE_TYPE		0
#define	ACCESS_DENIED_ACE_TYPE		1
#define	SYSTEM_AUDIT_ACE_TYPE		2
#define	SYSTEM_ALARM_ACE_TYPE		3

/*
 *  se_flags
 * ----------
 * Specifies a set of ACE type-specific control flags. This member can be a
 * combination of the following values.
 *
 * CONTAINER_INHERIT_ACE: Child objects that are containers, such as
 *		directories, inherit the ACE as an effective ACE. The inherited
 *		ACE is inheritable unless the NO_PROPAGATE_INHERIT_ACE bit flag
 *		is also set.
 *
 * INHERIT_ONLY_ACE: Indicates an inherit-only ACE which does not control
 *		access to the object to which it is attached.
 *		If this flag is not set,
 *		the ACE is an effective ACE which controls access to the object
 *		to which it is attached.
 * 		Both effective and inherit-only ACEs can be inherited
 *		depending on the state of the other inheritance flags.
 *
 * INHERITED_ACE: Windows 2000/XP: Indicates that the ACE was inherited.
 *		The system sets this bit when it propagates an
 *		inherited ACE to a child object.
 *
 * NO_PROPAGATE_INHERIT_ACE: If the ACE is inherited by a child object, the
 *		system clears the OBJECT_INHERIT_ACE and CONTAINER_INHERIT_ACE
 *		flags in the inherited ACE.
 *		This prevents the ACE from being inherited by
 *		subsequent generations of objects.
 *
 * OBJECT_INHERIT_ACE: Noncontainer child objects inherit the ACE as an
 *		effective ACE.  For child objects that are containers,
 *		the ACE is inherited as an inherit-only ACE unless the
 *		NO_PROPAGATE_INHERIT_ACE bit flag is also set.
 */
#define	OBJECT_INHERIT_ACE		0x01
#define	CONTAINER_INHERIT_ACE		0x02
#define	NO_PROPOGATE_INHERIT_ACE	0x04
#define	INHERIT_ONLY_ACE		0x08
#define	INHERITED_ACE			0x10
#define	INHERIT_MASK_ACE		0x1F


/*
 * These flags are only used in system audit or alarm ACEs to
 * indicate when an audit message should be generated, i.e.
 * on successful access or on unsuccessful access.
 */
#define	SUCCESSFUL_ACCESS_ACE_FLAG	0x40
#define	FAILED_ACCESS_ACE_FLAG		0x80


/*
 * AclSize is the size, in bytes, allocated for the ACL. This
 * includes the ACL header, ACEs and remaining free space in
 * the buffer. sl_acecnt is the number of ACES in the ACL.
 */
typedef struct smb_acl {
	uint8_t sl_revision;
	uint8_t sl_sbz1;
	uint16_t sl_size;
	uint16_t sl_acecnt;
	uint16_t sl_sbz2;
	/* immediately followed by ACE[]s */
} smb_acl_t;


/*
 * se_type denotes the type of the ace, there are some predefined
 * ACE types. se_size is the size, in bytes, of ACE. se_flags are
 * the ACE flags for auditing and inheritance.
 */
typedef struct smb_ace_hdr {
	uint8_t se_type;
	uint8_t se_flags;
	uint16_t se_size;
} smb_ace_hdr_t;


typedef struct smb_ace {
	smb_ace_hdr_t se_header;
	uint32_t se_mask;
	nt_sid_t se_sid;   /* variable length */
} smb_ace_t;


/*
 * Security Descriptor (SD)
 *
 * Security descriptors provide protection for objects, for example
 * files and directories. It identifies the owner and primary group
 * (SIDs) and contains an access control list. When a user tries to
 * access an object his SID is compared to the permissions in the
 * DACL to determine if access should be allowed or denied. Note that
 * this is a simplification because there are other factors, such as
 * default behavior and privileges to be taken into account (see also
 * access tokens).
 *
 * The boolean flags have the following meanings when set:
 *
 * SE_OWNER_DEFAULTED indicates that the SID pointed to by the Owner
 * field was provided by a defaulting mechanism rather than explicitly
 * provided by the original provider of the security descriptor. This
 * may affect the treatment of the SID with respect to inheritance of
 * an owner.
 *
 * SE_GROUP_DEFAULTED indicates that the SID in the Group field was
 * provided by a defaulting mechanism rather than explicitly provided
 * by the original provider of the security descriptor.  This may
 * affect the treatment of the SID with respect to inheritance of a
 * primary group.
 *
 * SE_DACL_PRESENT indicates that the security descriptor contains a
 * discretionary ACL. If this flag is set and the Dacl field of the
 * SECURITY_DESCRIPTOR is null, then a null ACL is explicitly being
 * specified.
 *
 * SE_DACL_DEFAULTED indicates that the ACL pointed to by the Dacl
 * field was provided by a defaulting mechanism rather than explicitly
 * provided by the original provider of the security descriptor. This
 * may affect the treatment of the ACL with respect to inheritance of
 * an ACL. This flag is ignored if the DaclPresent flag is not set.
 *
 * SE_SACL_PRESENT indicates that the security descriptor contains a
 * system ACL pointed to by the Sacl field. If this flag is set and
 * the Sacl field of the SECURITY_DESCRIPTOR is null, then an empty
 * (but present) ACL is being specified.
 *
 * SE_SACL_DEFAULTED indicates that the ACL pointed to by the Sacl
 * field was provided by a defaulting mechanism rather than explicitly
 * provided by the original provider of the security descriptor. This
 * may affect the treatment of the ACL with respect to inheritance of
 * an ACL. This flag is ignored if the SaclPresent flag is not set.
 *
 * SE_DACL_PROTECTED Prevents ACEs set on the DACL of the parent container
 * (and any objects above the parent container in the directory hierarchy)
 * from being applied to the object's DACL.
 *
 * SE_SACL_PROTECTED Prevents ACEs set on the SACL of the parent container
 * (and any objects above the parent container in the directory hierarchy)
 * from being applied to the object's SACL.
 *
 * Note that the SE_DACL_PRESENT flag needs to be present to set
 * SE_DACL_PROTECTED and SE_SACL_PRESENT needs to be present to set
 * SE_SACL_PROTECTED.
 *
 * SE_SELF_RELATIVE indicates that the security descriptor is in self-
 * relative form. In this form, all fields of the security descriptor
 * are contiguous in memory and all pointer fields are expressed as
 * offsets from the beginning of the security descriptor.
 *
 *    3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
 *    1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 *   +---------------------------------------------------------------+
 *   |            Control            |Reserved1 (SBZ)|   Revision    |
 *   +---------------------------------------------------------------+
 *   |                            Owner                              |
 *   +---------------------------------------------------------------+
 *   |                            Group                              |
 *   +---------------------------------------------------------------+
 *   |                            Sacl                               |
 *   +---------------------------------------------------------------+
 *   |                            Dacl                               |
 *   +---------------------------------------------------------------+
 *
 */

#define	SMB_OWNER_SECINFO	0x0001
#define	SMB_GROUP_SECINFO	0x0002
#define	SMB_DACL_SECINFO	0x0004
#define	SMB_SACL_SECINFO	0x0008
#define	SMB_ALL_SECINFO		0x000F
#define	SMB_ACL_SECINFO		(SMB_DACL_SECINFO | SMB_SACL_SECINFO)

#define	SECURITY_DESCRIPTOR_REVISION	1


#define	SE_OWNER_DEFAULTED		0x0001
#define	SE_GROUP_DEFAULTED		0x0002
#define	SE_DACL_PRESENT			0x0004
#define	SE_DACL_DEFAULTED		0x0008
#define	SE_SACL_PRESENT			0x0010
#define	SE_SACL_DEFAULTED		0x0020
#define	SE_DACL_AUTO_INHERIT_REQ	0x0100
#define	SE_SACL_AUTO_INHERIT_REQ	0x0200
#define	SE_DACL_AUTO_INHERITED		0x0400
#define	SE_SACL_AUTO_INHERITED		0x0800
#define	SE_DACL_PROTECTED		0x1000
#define	SE_SACL_PROTECTED		0x2000
#define	SE_SELF_RELATIVE		0x8000

#define	SE_DACL_INHERITANCE_MASK	0x1500
#define	SE_SACL_INHERITANCE_MASK	0x2A00

/*
 * Security descriptor structures:
 *
 * smb_sd_t     SD in SMB pointer form
 * smb_sdbuf_t  SD in SMB self-relative form
 * smb_fssd_t   SD in filesystem form
 *
 * We have to use two different structures to represent
 * pointer form and self-relative form of the security
 * descriptor because in SR form the offsets are 4-byte
 * but in pointer form, pointers will be 8-byte in 64-bit
 * kernel binary.
 *
 * Filesystems (e.g. ZFS/UFS) don't have something equivalent
 * to SD. The items comprising a SMB SD are kept separately in
 * filesystem. smb_fssd_t is introduced as a helper to provide
 * the required abstraction for CIFS code.
 */
typedef struct smb_sd_hdr {
	uint8_t sd_revision;
	uint8_t sd_sbz1;
	uint16_t sd_control;
} smb_sd_hdr_t;

typedef struct smb_sd {
	smb_sd_hdr_t	sd_hdr;
	nt_sid_t 	*sd_owner;	/* SID file owner */
	nt_sid_t 	*sd_group;	/* SID group (for POSIX) */
	smb_acl_t 	*sd_sacl;	/* ACL System (audits) */
	smb_acl_t 	*sd_dacl;	/* ACL Discretionary (perm) */
} smb_sd_t;

typedef struct smb_sdbuf {
	smb_sd_hdr_t	sd_hdr;
	uint32_t	sd_owner_offs;	/* SID file owner */
	uint32_t	sd_group_offs;	/* SID group (for POSIX) */
	uint32_t	sd_sacl_offs;	/* ACL System (audits) */
	uint32_t	sd_dacl_offs;	/* ACL Discretionary (perm) */
} smb_sdbuf_t;

/*
 * values for smb_fssd.sd_flags
 */
#define	SMB_FSSD_FLAGS_DIR	0x01

typedef struct smb_fssd {
	uint32_t	sd_secinfo;
	uint32_t	sd_flags;
	uid_t		sd_uid;
	gid_t		sd_gid;
	acl_t		*sd_zdacl;
	acl_t		*sd_zsacl;
} smb_fssd_t;

void smb_sd_init(smb_sd_t *sd, uint8_t revision);
void smb_sd_set_owner(smb_sd_t *sd, nt_sid_t *owner, int defaulted);
void smb_sd_set_group(smb_sd_t *sd, nt_sid_t *group, int defaulted);
void smb_sd_set_dacl(smb_sd_t *sd, int present, smb_acl_t *acl, int defaulted);
void smb_sd_set_sacl(smb_sd_t *sd, int present, smb_acl_t *acl, int defaulted);

nt_sid_t *smb_sd_get_owner(void *sd, int *defaulted);
nt_sid_t *smb_sd_get_group(void *sd, int *defaulted);
smb_acl_t *smb_sd_get_dacl(void *sd, int *present, int *defaulted);
smb_acl_t *smb_sd_get_sacl(void *sd, int *present, int *defaulted);
uint32_t smb_sd_get_secinfo(void *sd);
uint32_t smb_sd_len(void *sd, uint32_t secinfo);
void smb_sd_log(void *sd);
void smb_sd_term(smb_sd_t *sd);

smb_acl_t *smb_acl_from_zfs(acl_t *, uid_t, gid_t);
uint32_t smb_acl_to_zfs(smb_acl_t *, uint32_t, int, acl_t **);
int smb_acl_isvalid(smb_acl_t *, int);
uint16_t smb_acl_len(smb_acl_t *);
smb_acl_t *smb_acl_sort(smb_acl_t *);
int smb_acl_copy(uint16_t, smb_acl_t *, smb_acl_t *);
acl_t *smb_acl_inherit(acl_t *, int, int, uid_t);

smb_ace_t *smb_ace_get(smb_acl_t *acl, uint16_t idx);
int smb_ace_is_generic(int type);
int smb_ace_is_access(int type);
int smb_ace_is_audit(int type);


#ifdef __cplusplus
}
#endif

#endif /* _SMB_SECDESC_H */
