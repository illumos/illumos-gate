/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_ACL_H
#define	_SYS_ACL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	MAX_ACL_ENTRIES		(1024)	/* max entries of each type */
typedef struct acl {
	int		a_type;		/* the type of ACL entry */
	uid_t		a_id;		/* the entry in -uid or gid */
	o_mode_t	a_perm;		/* the permission field */
} aclent_t;

typedef struct ace {
	uid_t		a_who;		/* uid or gid */
	uint32_t	a_access_mask;	/* "rwx" */
	uint16_t	a_flags;	/* see below */
	uint16_t	a_type;		/* allow or deny */
} ace_t;

/*
 * The following are Defined types for an aclent_t.
 */
#define	USER_OBJ	(0x01)		/* object owner */
#define	USER		(0x02)		/* additional users */
#define	GROUP_OBJ	(0x04)		/* owning group of the object */
#define	GROUP		(0x08)		/* additional groups */
#define	CLASS_OBJ	(0x10)		/* file group class and mask entry */
#define	OTHER_OBJ	(0x20)		/* other entry for the object */
#define	ACL_DEFAULT	(0x1000)	/* default flag */
/* default object owner */
#define	DEF_USER_OBJ	(ACL_DEFAULT | USER_OBJ)
/* defalut additional users */
#define	DEF_USER	(ACL_DEFAULT | USER)
/* default owning group */
#define	DEF_GROUP_OBJ	(ACL_DEFAULT | GROUP_OBJ)
/* default additional groups */
#define	DEF_GROUP	(ACL_DEFAULT | GROUP)
/* default mask entry */
#define	DEF_CLASS_OBJ	(ACL_DEFAULT | CLASS_OBJ)
/* default other entry */
#define	DEF_OTHER_OBJ	(ACL_DEFAULT | OTHER_OBJ)

/*
 * The following are defined for ace_t.
 */
#define	ACE_FILE_INHERIT_ACE		0x0001
#define	ACE_DIRECTORY_INHERIT_ACE	0x0002
#define	ACE_NO_PROPOGATE_INHERIT_ACE	0x0004
#define	ACE_INHERIT_ONLY_ACE		0x0008
#define	ACE_LOCALLY_DEFINED		0x0010
#define	ACE_OWNER			0x0100 /* file owner */
#define	ACE_GROUP			0x0200 /* file group */
#define	ACE_OTHER			0x0400 /* other field */
#define	ACE_USER			0x0800 /* additional users */
#define	ACE_GROUPS			0x1000 /* additional groups */
/*
 * The following flags are supported by both NFSv4 ACLs and ace_t.
 */
#define	ACE_NFSV4_SUP_FLAGS (ACE_FILE_INHERIT_ACE | \
    ACE_DIRECTORY_INHERIT_ACE | \
    ACE_NO_PROPOGATE_INHERIT_ACE | \
    ACE_INHERIT_ONLY_ACE)

#define	ALLOW	0
#define	DENY	1

#define	ACE_READ_DATA	04	/* 'r'	 */
#define	ACE_WRITE_DATA	02	/* 'w'	 */
#define	ACE_EXECUTE	01	/* 'x'	 */

/* cmd args to acl(2) for aclent_t  */
#define	GETACL			1
#define	SETACL			2
#define	GETACLCNT		3

/* cmd's to manipulate ace acl's. */
#define	ACE_GETACL		4
#define	ACE_SETACL		5
#define	ACE_GETACLCNT		6

/* minimal acl entries from GETACLCNT */
#define	MIN_ACL_ENTRIES		4

#if !defined(_KERNEL)

/* acl check errors */
#define	GRP_ERROR		1
#define	USER_ERROR		2
#define	OTHER_ERROR		3
#define	CLASS_ERROR		4
#define	DUPLICATE_ERROR		5
#define	MISS_ERROR		6
#define	MEM_ERROR		7
#define	ENTRY_ERROR		8

/*
 * similar to ufs_acl.h: changed to char type for user commands (tar, cpio)
 * Attribute types
 */
#define	UFSD_FREE	('0')	/* Free entry */
#define	UFSD_ACL	('1')	/* Access Control Lists */
#define	UFSD_DFACL	('2')	/* reserved for future use */

extern int aclcheck(aclent_t *, int, int *);
extern int acltomode(aclent_t *, int, mode_t *);
extern int aclfrommode(aclent_t *, int, mode_t *);
extern int aclsort(int, int, aclent_t *);
extern char *acltotext(aclent_t *, int);
extern aclent_t *aclfromtext(char *, int *);

#else	/* !defined(_KERNEL) */

extern void ksort(caddr_t, int, int, int (*)(void *, void *));
extern int cmp2acls(void *, void *);

#endif	/* !defined(_KERNEL) */

#if defined(__STDC__)
extern int acl(const char *path, int cmd, int cnt, void *buf);
extern int facl(int fd, int cmd, int cnt, void *buf);
#else	/* !__STDC__ */
extern int acl();
extern int facl();
#endif	/* defined(__STDC__) */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_ACL_H */
