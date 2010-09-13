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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * ptree.h -- public definitions for tree print module
 *
 * these routines are used to print the "struct node" data
 * structures from tree.h.  they call out() to do the printing.
 */

#ifndef	_ESC_COMMON_PTREE_H
#define	_ESC_COMMON_PTREE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <tree.h>

/*
 * Use a pointer to one of these structs as the "arg" argument when
 * lut_walk()-ing with ptree_plut() as the callback.  "plut" is a
 * property lut, where the lhs is expected to be a const char * and
 * the rhs is a struct node.
 *
 *	flags is passed to out()
 *	first = 1 indicates the first in a list, first != 1 implies a later
 *	element and thus ptree_plut() adds a preceding comma
 *
 */
struct plut_wlk_data {
	int flags;
	int first;
};

void ptree(int flags, struct node *np, int no_iterators, int fileline);
void ptree_name(int flags, struct node *np);
void ptree_name_iter(int flags, struct node *np);
void ptree_all(int flags, const char *pat);
void ptree_fault(int flags, const char *pat);
void ptree_upset(int flags, const char *pat);
void ptree_defect(int flags, const char *pat);
void ptree_error(int flags, const char *pat);
void ptree_ereport(int flags, const char *pat);
void ptree_serd(int flags, const char *pat);
void ptree_stat(int flags, const char *pat);
void ptree_config(int flags, const char *pat);
void ptree_prop(int flags, const char *pat);
void ptree_mask(int flags, const char *pat);
void ptree_timeval(int flags, unsigned long long *ullp);
void ptree_plut(void *name, void *val, void *arg);
const char *ptree_nodetype2str(enum nodetype t);
const char *ptree_nametype2str(enum nametype t);

#ifdef	__cplusplus
}
#endif

#endif	/* _ESC_COMMON_PTREE_H */
