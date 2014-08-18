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
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_EXEC_ATTR_H
#define	_EXEC_ATTR_H

#ifdef	__cplusplus
extern "C" {
#endif


#include <sys/types.h>
#include <secdb.h>


#define	EXECATTR_FILENAME		"/etc/security/exec_attr"
#define	EXECATTR_DB_NAME		"exec_attr.org_dir"
#define	EXECATTR_DB_NCOL		7	/* total columns */
#define	EXECATTR_DB_NKEYCOL		3	/* total searchable columns */
#define	EXECATTR_DB_TBLT		"exec_attr_tbl"
#define	EXECATTR_NAME_DEFAULT_KW	"nobody"

#define	EXECATTR_COL0_KW		"name"
#define	EXECATTR_COL1_KW		"policy"
#define	EXECATTR_COL2_KW		"type"
#define	EXECATTR_COL3_KW		"res1"
#define	EXECATTR_COL4_KW		"res2"
#define	EXECATTR_COL5_KW		"id"
#define	EXECATTR_COL6_KW		"attr"

/*
 * indices of searchable columns
 */
#define	EXECATTR_KEYCOL0		0	/* name */
#define	EXECATTR_KEYCOL1		1	/* policy */
#define	EXECATTR_KEYCOL2		5	/* id */


/*
 * Some macros used internally by the nsswitch code
 */

/*
 * These macros are bitmasks. GET_ONE and GET_ALL are bitfield 0
 * and thus mutually exclusive. __SEARCH_ALL_POLLS is bitfield
 * 1 and can be logically ORed with GET_ALL if one wants to get
 * all matching profiles from all policies, not just the ones from
 * the currently active policy
 *
 * Testing for these values should be done using the IS_* macros
 * defined below.
 */
#define	GET_ONE			0
#define	GET_ALL			1
#define	__SEARCH_ALL_POLS	2

/* get only one exec_attr from list */
#define	IS_GET_ONE(f) (((f) & GET_ALL) == 0)
/* get all matching exec_attrs in list */
#define	IS_GET_ALL(f) (((f) & GET_ALL) == 1)
/* search all existing policies */
#define	IS_SEARCH_ALL(f) (((f) & __SEARCH_ALL_POLS) == __SEARCH_ALL_POLS)

/*
 * Key words used in the exec_attr database
 */
#define	EXECATTR_EUID_KW	"euid"
#define	EXECATTR_EGID_KW	"egid"
#define	EXECATTR_UID_KW		"uid"
#define	EXECATTR_GID_KW		"gid"
#define	EXECATTR_LPRIV_KW	"limitprivs"
#define	EXECATTR_IPRIV_KW	"privs"

/*
 * Nsswitch representation of execution attributes.
 */
typedef struct execstr_s {
	char   *name;		/* profile name */
	char   *policy;		/* suser/rbac/tsol */
	char   *type;		/* cmd/act */
	char   *res1;		/* reserved for future use */
	char   *res2;		/* reserved for future use */
	char   *id;		/* unique ID */
	char   *attr;		/* string of key-value pair attributes */
	struct execstr_s *next;	/* pointer to next entry */
} execstr_t;

typedef struct execattr_s {
	char   *name;		/* profile name */
	char   *policy;		/* suser/rbac/tsol */
	char   *type;		/* cmd/act */
	char   *res1;		/* reserved for future use */
	char   *res2;		/* reserved for future use */
	char   *id;		/* unique ID */
	kva_t  *attr;		/* array of key-value pair attributes */
	struct execattr_s *next;	/* pointer to next entry */
} execattr_t;

typedef struct __private_execattr {
	const char *name;
	const char *type;
	const char *id;
	const char *policy;
	int search_flag;
	execstr_t *head_exec;
	execstr_t *prev_exec;
} _priv_execattr;		/* Un-supported. For Sun internal use only */


extern execattr_t *getexecattr(void);
extern execattr_t *getexecuser(const char *, const char *, const char *, int);
extern execattr_t *getexecprof(const char *, const char *, const char *, int);
extern execattr_t *match_execattr(execattr_t *, const char *, const char *, \
	const char *);
extern void free_execattr(execattr_t *);
extern void setexecattr(void);
extern void endexecattr(void);

#ifdef __cplusplus
}
#endif

#endif	/* _EXEC_ATTR_H */
