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

#ifndef _ACLUTILS_H
#define	_ACLUTILS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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

extern char *yybuf;
extern acl_t *yyacl;

extern int yyerror(const char *);
extern int get_id(int entry_type, char *name, int *id);
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
extern acl_t *acl_to_aclp(enum acl_type, void *, int);

#ifdef	__cplusplus
}
#endif

#endif /* _ACLUTILS_H */
