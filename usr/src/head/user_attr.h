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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_USER_ATTR_H
#define	_USER_ATTR_H

#ifdef	__cplusplus
extern "C" {
#endif


#include <sys/types.h>
#include <secdb.h>


struct __FILE;		/* structure tag for type FILE defined in stdio.h */

/*
 * Some macros used internally by the nsswitch code
 */
#define	USERATTR_FILENAME		"/etc/user_attr"
#define	USERATTR_DB_NAME		"user_attr.org_dir"
#define	USERATTR_DB_NCOL		5	/* total columns */
#define	USERATTR_DB_NKEYCOL		2	/* total searchable columns */
#define	USERATTR_DB_TBL			"user_attr_tbl"
#define	USERATTR_NAME_DEFAULT_KW	"nobody"

#define	USERATTR_COL0_KW		"name"
#define	USERATTR_COL1_KW		"qualifier"
#define	USERATTR_COL2_KW		"res1"
#define	USERATTR_COL3_KW		"res2"
#define	USERATTR_COL4_KW		"attr"

#define	DEF_LIMITPRIV			"PRIV_LIMIT="
#define	DEF_DFLTPRIV			"PRIV_DEFAULT="

/*
 * indices of searchable columns
 */
#define	USERATTR_KEYCOL0		0	/* name */
#define	USERATTR_KEYCOL1		1	/* qualifier */

/*
 * Key words used in the user_attr database
 */
#define	USERATTR_LOCK_KW		"lock"
#define	USERATTR_LOCK_LOCKED_KW		"locked"
#define	USERATTR_LOCK_OPEN_KW		"open"
#define	USERATTR_LOCK_FIXED_KW		"fixed"
#define	USERATTR_GEN_KW			"gen"
#define	USERATTR_GEN_AUTOMATIC_KW	"automatic"
#define	USERATTR_GEN_MANUAL_KW		"manual"
#define	USERATTR_GEN_SYSDEF_KW		"sysdef"
#define	USERATTR_PROFILES_KW		"profiles"
#define	USERATTR_PROFILES_NONE_KW	"none"
#define	USERATTR_ROLES_KW		"roles"
#define	USERATTR_ROLES_NONE_KW		"none"
#define	USERATTR_DEFAULTPROJ_KW		"project"
#define	USERATTR_TYPE_KW		"type"
#define	USERATTR_TYPE_NORMAL_KW		"normal"
#define	USERATTR_TYPE_ADMIN_KW		"admin"
#define	USERATTR_TYPE_NONADMIN_KW	"role"
#define	USERATTR_AUTHS_KW		"auths"
#define	USERATTR_LIMPRIV_KW		"limitpriv"
#define	USERATTR_DFLTPRIV_KW		"defaultpriv"
#define	USERATTR_LOCK_AFTER_RETRIES_KW	"lock_after_retries"
#define	USERATTR_CLEARANCE		"clearance"
#define	USERATTR_LABELVIEW		"labelview"
#define	USERATTR_LABELVIEW_EXTERNAL	"external"
#define	USERATTR_LABELVIEW_HIDESL	"hidesl"
#define	USERATTR_HIDESL			USERATTR_LABELVIEW_HIDESL
#define	USERATTR_LABELVIEW_INTERNAL	"internal"
#define	USERATTR_LABELVIEW_SHOWSL	"showsl"
#define	USERATTR_LABELTRANS		"labeltrans"
#define	USERATTR_LOCK_NO		"no"
#define	USERATTR_LOCK_YES		"yes"
#define	USERATTR_MINLABEL		"min_label"
#define	USERATTR_PASSWD			"password"
#define	USERATTR_PASSWD_AUTOMATIC	"automatic"
#define	USERATTR_PASSWD_MANUAL		"manual"
#define	USERATTR_TYPE_ROLE		USERATTR_TYPE_NONADMIN_KW
#define	USERATTR_AUDIT_FLAGS_KW		"audit_flags"


/*
 * Nsswitch representation of user attributes.
 */
typedef struct userstr_s {
	char   *name;		/* user name */
	char   *qualifier;	/* reserved for future use */
	char   *res1;		/* reserved for future use */
	char   *res2;		/* reserved for future use */
	char   *attr;		/* string of key-value pair attributes */
} userstr_t;

/*
 * API representation of user attributes.
 */
typedef struct userattr_s {
	char   *name;		/* user name */
	char   *qualifier;	/* reserved for future use */
	char   *res1;		/* reserved for future use */
	char   *res2;		/* reserved for future use */
	kva_t  *attr;		/* array of key-value pair attributes */
} userattr_t;

extern userattr_t *getusernam(const char *);
extern userattr_t *getuseruid(uid_t uid);
extern userattr_t *getuserattr(void);
extern userattr_t *fgetuserattr(struct __FILE *);
extern void setuserattr(void);
extern void enduserattr(void);
extern void free_userattr(userattr_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _USER_ATTR_H */
