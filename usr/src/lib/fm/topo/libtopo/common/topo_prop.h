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
 */

#ifndef _TOPO_PROP_H
#define	_TOPO_PROP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <fm/libtopo.h>

#include <topo_list.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct topo_pgroup {
	topo_list_t tpg_list;		/* next/prev pointers */
	char *tpg_name;			/* Group name */
	topo_stability_t tpg_stability;	/* SMI Stability level */
	topo_list_t tpg_pvals;		/* Property values */
} topo_pgroup_t;

typedef struct topo_propval {
	char *tp_name;			/* Prop name */
	topo_type_t tp_type;		/* Prop type */
	int tp_flag;			/* Dynamic property */
	int tp_refs;			/* ref count for this prop val */
	topo_hdl_t *tp_hdl;		/* handle pointer for allocations */
	void (*tp_free)(struct topo_propval *); /* Prop value destructor */
	union {
		int32_t tp_int32;
		int32_t tp_uint32;
		int64_t tp_int64;
		int64_t tp_uint64;
		char *tp_string;
		nvlist_t *tp_fmri;
	} tp_u;
} topo_propval_t;

typedef struct topo_proplist {
	topo_list_t tp_list;		/* next/prev pointers */
	topo_propval_t *tp_pval;	/* actual value */
} topo_proplist_t;

extern int topo_prop_inherit(tnode_t *, const char *, const char *, int *);
extern void topo_prop_hold(topo_propval_t *);
extern void topo_prop_rele(topo_propval_t *);
extern void topo_pgroup_destroy_all(tnode_t *);

#ifdef __cplusplus
}
#endif

#endif	/* _TOPO_PROP_H */
