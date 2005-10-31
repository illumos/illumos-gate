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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _ACLUTILS_H
#define	_ACLUTILS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	ACL_REMOVE_ALL		0x0
#define	ACL_REMOVE_FIRST	0x1

/*
 * Hint for whether acl_totext() should use
 * mneumonics:
 * read_data/list_directory
 * write_data/add_file or
 * append_data/add_subdirectory
 * when object of ACL is known.
 */
#define	ACL_IS_DIR	0x2

typedef enum acl_type {
	ACLENT_T = 0,
	ACE_T = 1
} acl_type_t;

/*
 * acl flags
 */
#define	ACL_IS_TRIVIAL	0x1

struct acl_info {
	acl_type_t acl_type;		/* style of acl */
	int acl_cnt;			/* number of acl entries */
	int acl_entry_size;		/* sizeof acl entry */
	int acl_flags;			/* special flags about acl */
	void *acl_aclp;			/* the acl */
};


extern int acl_addentries(acl_t *, acl_t *, int);
extern int acl_removeentries(acl_t *, acl_t *, int, int);
extern int acl_modifyentries(acl_t *, acl_t *, int);
extern void acl_printacl(acl_t *, int);
extern char *acl_strerror(int);
extern acl_t *acl_dup(acl_t *);
extern int acl_type(acl_t *);
extern int acl_cnt(acl_t *);
extern int acl_flags(acl_t *);
extern void *acl_data(acl_t *);

#ifdef	__cplusplus
}
#endif

#endif /* _ACLUTILS_H */
