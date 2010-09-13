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

#ifndef	_LIST_H
#define	_LIST_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <mdb/mdb_modapi.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	LIST_WALK_NAME	"list"
#define	LIST_WALK_DESC	"walk a linked list"

extern int list_walk_init(mdb_walk_state_t *wsp);
extern int list_walk_init_named(mdb_walk_state_t *wsp,
    const char *, const char *);
extern int list_walk_init_checked(mdb_walk_state_t *wsp,
    const char *, const char *,
    int (*)(void *, uintptr_t, void *), void *);
extern int list_walk_init_range(mdb_walk_state_t *wsp, uintptr_t, uintptr_t,
    const char *, const char *,
    int (*)(void *, uintptr_t, void *), void *);
extern int list_walk_step(mdb_walk_state_t *wsp);
extern void list_walk_fini(mdb_walk_state_t *wsp);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIST_H */
