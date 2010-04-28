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
 * Copyright (c) 1993, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_SYS_FS_UFS_ACL_H
#define	_SYS_FS_UFS_ACL_H

#include <sys/types.h>
#include <sys/cred.h>
#include <sys/vfs.h>
#include <sys/acl.h>
#include <sys/fs/ufs_fs.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * On-disk UFS ACL structure
 */

typedef struct ufs_acl {
	union {
		uint32_t 	acl_next;	/* Pad for old structure */
		ushort_t	acl_tag;	/* Entry type */
	} acl_un;
	o_mode_t	acl_perm;		/* Permission bits */
	uid_t		acl_who;		/* User or group ID */
} ufs_acl_t;

#define	acl_tag acl_un.acl_tag
#define	acl_next acl_un.acl_next

/*
 * In-core UFS ACL structure
 */

typedef struct ufs_ic_acl {
	struct ufs_ic_acl	*acl_ic_next;	/* Next ACL for this inode */
	o_mode_t		acl_ic_perm;	/* Permission bits */
	uid_t			acl_ic_who;	/* User or group ID */
} ufs_ic_acl_t;

/*
 * In-core ACL mask
 */
typedef struct ufs_aclmask {
	short		acl_ismask;	/* Is mask defined? */
	o_mode_t	acl_maskbits;	/* Permission mask */
} ufs_aclmask_t;

/*
 * full acl
 */
typedef struct ic_acl {
	ufs_ic_acl_t	*owner;		/* owner object */
	ufs_ic_acl_t	*group;		/* group object */
	ufs_ic_acl_t	*other;		/* other object */
	ufs_ic_acl_t	*users;		/* list of users */
	ufs_ic_acl_t	*groups;	/* list of groups */
	ufs_aclmask_t	mask;		/* mask */
} ic_acl_t;

/*
 * In-core shadow inode
 */
typedef	struct si {
	struct si *s_next;		/* signature hash next */
	struct si *s_forw;		/* inode hash next */
	struct si *s_fore;		/* unref'd list next */

	int	s_flags;		/* see below */
	ino_t	s_shadow;		/* shadow inode number */
	dev_t	s_dev;			/* device (major,minor) */
	int	s_signature;		/* signature for all ACLs */
	int 	s_use;			/* on disk use count */
	int	s_ref;			/* in core reference count */
	krwlock_t s_lock;		/* lock for this structure */

	ic_acl_t  s_a;			/* acls */
	ic_acl_t  s_d;			/* def acls */
} si_t;

#define	aowner	s_a.owner
#define	agroup	s_a.group
#define	aother	s_a.other
#define	ausers	s_a.users
#define	agroups	s_a.groups
#define	aclass	s_a.mask

#define	downer	s_d.owner
#define	dgroup	s_d.group
#define	dother	s_d.other
#define	dusers	s_d.users
#define	dgroups	s_d.groups
#define	dclass	s_d.mask

#define	s_prev	s_forw

/*
 * s_flags
 */
#define	SI_CACHED 0x0001		/* Is in si_cache */

/*
 * Header to identify data on disk
 */
typedef struct ufs_fsd {
	int	fsd_type;		/* type of data */
	int	fsd_size;		/* size in bytes of ufs_fsd and data */
	char	fsd_data[1];		/* data */
} ufs_fsd_t;

/*
 * Data types  (fsd_type)
 */
#define	FSD_FREE	(0)		/* Free entry */
#define	FSD_ACL		(1)		/* Access Control Lists */
#define	FSD_DFACL	(2)		/* reserved for future use */
#define	FSD_RESERVED3	(3)		/* reserved for future use */
#define	FSD_RESERVED4	(4)		/* reserved for future use */
#define	FSD_RESERVED5	(5)		/* reserved for future use */
#define	FSD_RESERVED6	(6)		/* reserved for future use */
#define	FSD_RESERVED7	(7)		/* reserved for future use */

/*
 * FSD manipulation macros
 * The FSD macros are aligned on integer boundary even if the preceeding
 * record had a byte aligned length. So the record length is always
 * integer length. All increments of the data pointers must use the
 * FSD_RECSZ macro.
 */
#define	FSD_TPSZ(fsdp)		(sizeof (fsdp->fsd_type))
#define	FSD_TPMSK(fsdp)		(FSD_TPSZ(fsdp) - 1)
#define	FSD_RECSZ(fsdp, size)	((size + FSD_TPMSK(fsdp)) & ~FSD_TPMSK(fsdp))
/*
 * flags for acl_validate
 */
#define	ACL_CHECK	0x01
#define	DEF_ACL_CHECK	0x02

#define	MODE_CHECK(O, M, PERM, C, I) \
    secpolicy_vnode_access2(C, ITOV(I), O, (PERM), M)

/*
 * Check that the file type is one that accepts ACLs
 */
#define	CHECK_ACL_ALLOWED(MODE) (((MODE) == IFDIR) || ((MODE) == IFREG) || \
				((MODE) == IFIFO) || ((MODE) == IFCHR) || \
				((MODE) == IFBLK) || ((MODE) == IFATTRDIR))

/*
 * Get ACL group permissions if the mask is not present, and the ACL
 * group permission intersected with the mask if the mask is present
 */
#define	MASK2MODE(ACL)							\
	((ACL)->aclass.acl_ismask ?					\
		((((ACL)->aclass.acl_maskbits &				\
			(ACL)->agroup->acl_ic_perm) & 07) << 3) :	\
		(((ACL)->agroup->acl_ic_perm & 07) << 3))

#define	MODE2ACL(P, MODE, CRED)					\
	ASSERT((P));						\
	(P)->acl_ic_next = NULL;				\
	(P)->acl_ic_perm &= ((MODE) & 7);			\
	(P)->acl_ic_who = (CRED);

#define	ACL_MOVE(P, T, B)					\
{								\
	ufs_ic_acl_t *acl;					\
	for (acl = (P); acl; acl = acl->acl_ic_next) {		\
		(B)->acl_tag = (T);				\
		(B)->acl_perm = acl->acl_ic_perm;		\
		(B)->acl_who = acl->acl_ic_who;			\
		(B)++;						\
	}							\
}

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FS_UFS_ACL_H */
