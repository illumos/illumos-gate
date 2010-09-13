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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_DIS_LIST_H
#define	_DIS_LIST_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <libuutil.h>

/* #include "dis_target.h" */

#ifdef	__cplusplus
extern "C" {
#endif

typedef uu_list_t dis_namelist_t;
typedef uu_list_t dis_scnlist_t;
typedef uu_list_t dis_funclist_t;

dis_namelist_t *dis_namelist_create(void);
void dis_namelist_add(dis_namelist_t *, const char *, int);
dis_funclist_t *dis_namelist_resolve_functions(dis_namelist_t *, dis_tgt_t *);
dis_scnlist_t *dis_namelist_resolve_sections(dis_namelist_t *, dis_tgt_t *);
void dis_scnlist_iter(dis_scnlist_t *, void (*)(dis_scn_t *, int, void *),
    void *);
void dis_funclist_iter(dis_funclist_t *, void (*)(dis_func_t *, int, void *),
    void *);
int dis_namelist_empty(dis_namelist_t *);
void dis_scnlist_destroy(dis_scnlist_t *);
void dis_funclist_destroy(dis_funclist_t *);
void dis_namelist_destroy(dis_namelist_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _DIS_LIST_H */
