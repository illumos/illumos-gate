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

#ifndef	_LIBMLSVC_H
#define	_LIBMLSVC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <smbsrv/ntsid.h>
#include <smbsrv/hash_table.h>
#include <smbsrv/smb_token.h>
#include <smbsrv/smb_privilege.h>
#include <smbsrv/lmshare.h>
#include <smbsrv/libsmb.h>

#ifdef	__cplusplus
extern "C" {
#endif

extern int mlsvc_init(void);
extern int mlsvc_is_local_domain(const char *);
extern DWORD lsa_query_primary_domain_info(void);
extern DWORD lsa_query_account_domain_info(void);
extern DWORD lsa_enum_trusted_domains(void);

extern boolean_t locate_resource_pdc(char *);

#define	SMB_AUTOHOME_FILE	"smbautohome"
#define	SMB_AUTOHOME_PATH	"/etc"

typedef struct smb_autohome {
	struct smb_autohome *ah_next;
	uint32_t ah_hits;
	time_t ah_timestamp;
	char *ah_name;		/* User account name */
	char *ah_path;		/* Home directory path */
	char *ah_container;	/* ADS container distinguished name */
} smb_autohome_t;

extern int smb_autohome_add(const char *);
extern int smb_autohome_remove(const char *);
extern int smb_is_autohome(const lmshare_info_t *);
extern void smb_autohome_setent(void);
extern void smb_autohome_endent(void);
extern smb_autohome_t *smb_autohome_getent(const char *name);
extern smb_autohome_t *smb_autohome_lookup(const char *name);

/*
 * Local groups
 */
#define	NT_GROUP_FMRI_PREFIX	"network/smb/group"

typedef enum {
	RWLOCK_NONE,
	RWLOCK_WRITER,
	RWLOCK_READER
} krwmode_t;

typedef struct nt_group_data {
	void *data;
	int size;
} nt_group_data_t;

/*
 * IMPORTANT NOTE:
 * If you change nt_group_member_t, nt_group_members_t, or nt_group_t
 * structures, you MIGHT have to change following functions accordingly:
 *	nt_group_setfields
 *	nt_group_init_size
 * 	nt_group_init
 */
typedef struct nt_group_member {
	uint16_t	info_size;	/* size of the whole structure */
	uint16_t	sid_name_use;	/* type of the specified SID */
	char		*account;	/* Pointer to account name of member */
	nt_sid_t 	sid;		/* Variable length */
} nt_group_member_t;

typedef struct nt_group_members {
	uint32_t		size;		/* in bytes */
	uint32_t		count;
	nt_group_member_t	list[ANY_SIZE_ARRAY];
} nt_group_members_t;

typedef struct nt_group {
	time_t			age;
	nt_group_data_t		info;
	/*
	 * following fields point to a contigous block
	 * of memory that is read and written from/to DB
	 */
	uint32_t		*attr;
	uint16_t		*sid_name_use;
	char			*name;
	char			*comment;
	nt_sid_t		*sid;
	smb_privset_t		*privileges;
	nt_group_members_t 	*members;
} nt_group_t;

typedef struct nt_group_iterator {
	HT_ITERATOR *iterator;
	int iteration;
} nt_group_iterator_t;

extern int 	nt_group_num_groups(void);
extern uint32_t	nt_group_add(char *, char *);
extern uint32_t	nt_group_modify(char *, char *, char *);
extern uint32_t	nt_group_delete(char *);
extern nt_group_t *nt_group_getinfo(char *, krwmode_t);
extern void 	nt_group_putinfo(nt_group_t *);

extern int	nt_group_getpriv(nt_group_t *, uint32_t);
extern uint32_t	nt_group_setpriv(nt_group_t *, uint32_t, uint32_t);

/* Member manipulation functions */
extern int 	nt_group_is_member(nt_group_t *, nt_sid_t *);
extern uint32_t	nt_group_del_member(nt_group_t *, void *, int);
extern uint32_t	nt_group_add_member(nt_group_t *, nt_sid_t *, uint16_t, char *);
extern int 	nt_group_num_members(nt_group_t *);

extern void nt_group_ht_lock(krwmode_t);
extern void nt_group_ht_unlock(void);

extern nt_group_iterator_t *nt_group_open_iterator(void);
extern void nt_group_close_iterator(nt_group_iterator_t *);
extern nt_group_t *nt_group_iterate(nt_group_iterator_t *);

extern int nt_group_cache_size(void);

extern int nt_group_member_list(int offset, nt_group_t *grp,
    ntgrp_member_list_t *rmembers);
extern void nt_group_list(int offset, char *pattern, ntgrp_list_t *list);

extern uint32_t sam_init(void);

extern uint32_t	nt_group_add_member_byname(char *, char *);
extern uint32_t	nt_group_del_member_byname(nt_group_t *, char *);
extern void 	nt_group_add_groupprivs(nt_group_t *, smb_privset_t *);

extern uint32_t	nt_groups_member_privs(nt_sid_t *, smb_privset_t *);
extern int 	nt_groups_member_ngroups(nt_sid_t *);
extern uint32_t nt_groups_member_groups(nt_sid_t *, smb_id_t *, int);
extern nt_group_t *nt_groups_lookup_rid(uint32_t);
extern int 	nt_groups_count(int);

/*
 * source for account name size is MSDN
 */
#define	NT_GROUP_NAME_CHAR_MAX		32
#define	NT_GROUP_NAME_MAX		(NT_GROUP_NAME_CHAR_MAX * 3 + 1)
#define	NT_GROUP_USER_NAME_MAX		(NT_GROUP_NAME_CHAR_MAX * 3 + 1)
#define	NT_GROUP_MEMBER_NAME_MAX	(NT_GROUP_NAME_CHAR_MAX * 3 + 1)
#define	NT_GROUP_COMMENT_MAX		256

/*
 * flags for count operation
 */
#define	NT_GROUP_CNT_BUILTIN		1
#define	NT_GROUP_CNT_LOCAL		2
#define	NT_GROUP_CNT_ALL		3

/*
 * flag to distinguish between add and modify
 * operations.
 */
#define	NT_GROUP_OP_CHANGE		1
#define	NT_GROUP_OP_SYNC		2

/*
 * specify key type for deleting a member i.e.
 * whether it's member's name or member's SID.
 */
#define	NT_GROUP_KEY_SID	1
#define	NT_GROUP_KEY_NAME	2

/* Macro for walking members */
#define	NEXT_MEMBER(m) (nt_group_member_t *)((char *)(m) + (m)->info_size)

/*
 * When NT requests the security descriptor for a local file that
 * doesn't already have a one, we generate one on-the-fly. The SD
 * contains both user and group SIDs. The problem is that we need a
 * way to distinguish a user SID from a group SID when NT performs a
 * subsequent SID lookup to obtain the appropriate name to display.
 * The following macros are used to map to and from an external
 * representation so that we can tell the difference between UIDs
 * and GIDs. The local UID/GID is shifted left and the LSB is used
 * to distinguish the id type before it is inserted into the SID.
 * We can then use this type identifier during lookup operations.
 */
#define	SAM_MIN_RID				1000
#define	SAM_RT_ERROR				-1
#define	SAM_RT_UNIX_UID				0
#define	SAM_RT_UNIX_GID				1
#define	SAM_RT_NT_UID				2
#define	SAM_RT_NT_GID				3
#define	SAM_RT_MASK				0x3
#define	SAM_RT_EVERYONE				4
#define	SAM_RT_UNKNOWN				5

#define	SAM_RID_TYPE(rid)		((rid) & SAM_RT_MASK)
#define	SAM_DECODE_RID(rid)		(((rid) - SAM_MIN_RID) >> 2)
#define	SAM_ENCODE_RID(type, id)	((((id) << 2) | type) + SAM_MIN_RID)
#define	SAM_ENCODE_UXUID(id)		SAM_ENCODE_RID(SAM_RT_UNIX_UID, id)
#define	SAM_ENCODE_UXGID(id)		SAM_ENCODE_RID(SAM_RT_UNIX_GID, id)
#define	SAM_ENCODE_NTUID(id)		SAM_ENCODE_RID(SAM_RT_NT_UID, id)
#define	SAM_ENCODE_NTGID(id)		SAM_ENCODE_RID(SAM_RT_NT_GID, id)

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBMLSVC_H */
