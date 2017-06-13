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

#ifndef _UTIL_H
#define	_UTIL_H

#include <fm/topo_mod.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int child_range_add(topo_mod_t *, tnode_t *, const char *,
    topo_instance_t, topo_instance_t);
extern int labelmethod_inherit(topo_mod_t *, tnode_t *, nvlist_t *,
    nvlist_t **);
extern ulong_t fm_strtonum(topo_mod_t *, char *, int *);
extern tnode_t *tnode_create(topo_mod_t *, tnode_t *, const char *,
    topo_instance_t, void *);

#ifdef __cplusplus
}
#endif

#endif	/* _UTIL_H */
