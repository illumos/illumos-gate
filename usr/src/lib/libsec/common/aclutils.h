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

#ifndef _ACLUTILS_H
#define	_ACLUTILS_H

#include <sys/types.h>
#include <sys/acl.h>
#include <strings.h>
#include <locale.h>
#include <ctype.h>
#include <grp.h>
#include <pwd.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	ACL_REMOVE_ALL		0x0
#define	ACL_REMOVE_FIRST	0x1

/*
 * Hint for whether acl_totext() should use
 * mnemonics:
 * read_data/list_directory
 * write_data/add_file or
 * append_data/add_subdirectory
 * when object of ACL is known.
 */

#define	PERM_TYPE_ACE		0x1	/* permissions are of ACE type */
#define	PERM_TYPE_UNKNOWN	0x2	/* permission type not yet known */
#define	PERM_TYPE_EMPTY		0x4	/* no permissions are specified */

struct acl_perm_type {
	int		perm_style;	/* type of perm style, see above */
	char		*perm_str;	/* string value being returned */
	uint32_t	perm_val;	/* numeric value being returned */
};

/*
 * Textual representation of ace_t's access mask
 */
#define	READ_DATA_TXT	"read_data/"
#define	WRITE_DATA_TXT	"write_data/"
#define	EXECUTE_TXT	"execute/"
#define	READ_XATTR_TXT	"read_xattr/"
#define	WRITE_XATTR_TXT	"write_xattr/"
#define	READ_ATTRIBUTES_TXT "read_attributes/"
#define	WRITE_ATTRIBUTES_TXT "write_attributes/"
#define	DELETE_TXT	"delete/"
#define	DELETE_CHILD_TXT "delete_child/"
#define	WRITE_OWNER_TXT "write_owner/"
#define	READ_ACL_TXT	"read_acl/"
#define	WRITE_ACL_TXT	"write_acl/"
#define	APPEND_DATA_TXT "append_data/"
#define	READ_DIR_TXT	"list_directory/read_data/"
#define	ADD_DIR_TXT	"add_subdirectory/append_data/"
#define	ADD_FILE_TXT	"add_file/write_data/"
#define	SYNCHRONIZE_TXT "synchronize/"

/*
 * ace_t's entry types
 */
#define	OWNERAT_TXT	"owner@:"
#define	GROUPAT_TXT	"group@:"
#define	EVERYONEAT_TXT	"everyone@:"
#define	GROUP_TXT	"group:"
#define	USER_TXT	"user:"
#define	USERSID_TXT	"usersid:"
#define	GROUPSID_TXT	"groupsid:"

/*
 * ace_t's access types
 */
#define	ALLOW_TXT	"allow"
#define	DENY_TXT	"deny"
#define	ALARM_TXT	"alarm"
#define	AUDIT_TXT	"audit"
#define	UNKNOWN_TXT	"unknown"

/*
 * ace_t's inheritance types
 */

#define	FILE_INHERIT_TXT	"file_inherit/"
#define	DIR_INHERIT_TXT		"dir_inherit/"
#define	NO_PROPAGATE_TXT	"no_propagate/"
#define	INHERIT_ONLY_TXT	"inherit_only/"
#define	INHERITED_ACE_TXT	"inherited/"
#define	SUCCESSFUL_ACCESS_TXT	"successful_access/"
#define	FAILED_ACCESS_TXT	"failed_access/"

extern char *yybuf;
extern acl_t *yyacl;

extern int yyerror(const char *);
extern int get_id(int entry_type, char *name, uid_t *id);
extern int get_id_nofail(int entry_type, char *name);
extern int ace_entry_type(int entry_type);
extern int aclent_entry_type(int type, int owning, int *ret);
extern int ace_perm_mask(struct acl_perm_type *, uint32_t *mask);
extern int compute_aclent_perms(char *str, o_mode_t *mask);
extern int compute_ace_inherit(char *str, uint32_t *imask);
extern int acl_addentries(acl_t *, acl_t *, int);
extern int acl_removeentries(acl_t *, acl_t *, int, int);
extern int acl_modifyentries(acl_t *, acl_t *, int);
extern void acl_printacl(acl_t *, int, int);
extern char *acl_strerror(int);
extern acl_t *acl_dup(acl_t *);
extern int acl_type(acl_t *);
extern int acl_cnt(acl_t *);
extern int acl_flags(acl_t *);
extern void *acl_data(acl_t *);
extern void acl_error(const char *, ...);
extern int acl_parse(const char *, acl_t **);
extern int yyparse(void);
extern void yyreset(void);
extern void yycleanup(void);
extern acl_t *acl_to_aclp(enum acl_type, void *, int);
extern int sid_to_id(char *, boolean_t, uid_t *);

#ifdef	__cplusplus
}
#endif

#endif /* _ACLUTILS_H */
