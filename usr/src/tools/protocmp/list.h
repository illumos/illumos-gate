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

#ifndef _LIST_H
#define	_LIST_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Constants
 */
#define	MAXNAME   256
#define	TYPESIZE  32


/*
 * find_elem flags
 */

#define	FOLLOW_LINK    1
#define	NO_FOLLOW_LINK 0

/*
 * elem_list types
 */
#define	PROTOLIST_LIST	1
#define	PROTODIR_LIST	2
#define	EXCEPTION_LIST	3


/*
 * file types
 */

#define	CHAR_DEV_T	'c'
#define	BLOCK_DEV_T	'b'
#define	DIR_T		'd'
#define	FILE_T		'f'
#define	EDIT_T		'e'
#define	VOLATILE_T	'v'
#define	SYM_LINK_T	's'
#define	LINK_T		'l'

/*
 * Arch Values
 */

/* sparc */
#define	P_SPARC		1
#define	P_SUN4		2
#define	P_SUN4c		3
#define	P_SUN4d		4
#define	P_SUN4e		5
#define	P_SUN4m		6
#define	P_SUN4u		7
#define	P_SUN4v		8

/* x86 values */
#define	P_I386		101
#define	P_I86PC		102

/* ppc values */
#define	P_PPC		201
#define	P_PREP		202

#if defined(sparc)
#define	P_ISA		P_SPARC
#elif defined(i386)
#define	P_ISA		P_I386
#elif defined(__ppc)
#define	P_ISA		P_PPC
#else
#error "Unknown instruction set"
#endif

#define	P_ALL		P_ISA

/*
 * typedefs
 */
typedef struct pkg_list {
	char		pkg_name[MAXNAME];
	struct pkg_list	*next;
} pkg_list;

typedef struct elem {
	int		inode;
	short		perm;
	int		ref_cnt;
	short		flag;
	short		major;
	short		minor;
	short		arch;
	struct elem	*next;
	struct elem	*link_parent;
	struct elem	*link_sib;
	pkg_list	*pkgs;
	char		*symsrc;
	char		name[MAXNAME];
	char		owner[TYPESIZE];
	char		group[TYPESIZE];
	char		file_type;
} elem;


typedef struct {
	int	num_of_buckets;
	elem	**list;
	short	type;
} elem_list;

#define	HASH_SIZE	4093

/*
 * Funcs
 */


extern void add_elem(elem_list*, elem *);
extern pkg_list *add_pkg(pkg_list *, const char *);
extern elem *find_elem(elem_list *, elem *, int);
extern elem *find_elem_mach(elem_list *, elem *, int);
extern elem *find_elem_isa(elem_list *, elem *, int);
extern void init_list(elem_list *, int);
extern unsigned int hash(const char *str);
extern int processed_package(const char *pkgname);
extern void mark_processed(const char *pkgname);
#ifdef DEBUG
extern void examine_list(elem_list *list);
extern void print_list(elem_list *);
extern void print_type_list(elem_list *list, char file_type);
#endif

/* Global statistics */
extern int max_list_depth;

#ifdef __cplusplus
}
#endif

#endif	/* _LIST_H */
