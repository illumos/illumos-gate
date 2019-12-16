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
/*
 * Copyright 2019 Joyent, Inc.
 */

#ifndef	_TOPO_LIST_H
#define	_TOPO_LIST_H

#include <fm/libtopo.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	topo_list_prev(elem)	((void *)(((topo_list_t *)(elem))->l_prev))
#define	topo_list_next(elem)	((void *)(((topo_list_t *)(elem))->l_next))

extern void topo_list_append(topo_list_t *, void *);
extern void topo_list_prepend(topo_list_t *, void *);
extern void topo_list_insert_before(topo_list_t *, void *, void *);
extern void topo_list_insert_after(topo_list_t *, void *, void *);
extern void topo_list_delete(topo_list_t *, void *);
extern int topo_list_deepcopy(topo_hdl_t *, topo_list_t *, topo_list_t *,
    size_t);

/* Helpers for child/sibling lists */
extern tnode_t *topo_child_first(tnode_t *);
extern tnode_t *topo_child_next(tnode_t *, tnode_t *);
extern topo_list_t *topo_sibling_list(tnode_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _TOPO_LIST_H */
