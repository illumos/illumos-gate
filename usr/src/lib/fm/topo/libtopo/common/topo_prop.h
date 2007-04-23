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

#ifndef _TOPO_PROP_H
#define	_TOPO_PROP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <fm/libtopo.h>

#include <topo_list.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct topo_ipgroup_info {
	char *tpi_name;			/* property group name */
	topo_stability_t tpi_namestab;	/* stability of group name */
	topo_stability_t tpi_datastab;	/* stability of all property values */
	topo_version_t  tpi_version;	/* version of pgroup definition */
} topo_ipgroup_info_t;

typedef struct topo_pgroup {
	topo_list_t tpg_list;		/* next/prev pointers */
	topo_ipgroup_info_t *tpg_info;	/* name, version, stability */
	topo_list_t tpg_pvals;		/* property values */
} topo_pgroup_t;

typedef struct topo_propmethod {
	char *tpm_name;			/* property method name */
	topo_version_t tpm_version;	/* method version */
	nvlist_t *tpm_args;		/* in args for method */
} topo_propmethod_t;

typedef struct topo_propval {
	char *tp_name;			/* prop name */
	topo_type_t tp_type;		/* prop type */
	int tp_flag;			/* dynamic property */
	int tp_refs;			/* ref count for this prop val */
	topo_hdl_t *tp_hdl;		/* handle pointer for allocations */
	void (*tp_free)(struct topo_propval *); /* prop value destructor */
	nvlist_t *tp_val;
	topo_propmethod_t *tp_method;	/* Method for accessing dynamic prop */
} topo_propval_t;

typedef struct topo_proplist {
	topo_list_t tp_list;		/* next/prev pointers */
	topo_propval_t *tp_pval;	/* actual value */
} topo_proplist_t;

extern void topo_prop_hold(topo_propval_t *);
extern void topo_prop_rele(topo_propval_t *);
extern void topo_pgroup_destroy_all(tnode_t *);
extern nvlist_t *topo_prop_get(tnode_t *, const char *, const char *,
    topo_type_t, nvlist_t *, int *err);

#ifdef __cplusplus
}
#endif

#endif	/* _TOPO_PROP_H */
