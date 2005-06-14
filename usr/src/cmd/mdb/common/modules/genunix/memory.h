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
 * Copyright (c) 2000-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_MEMORY_H
#define	_MEMORY_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

int page_walk_init(mdb_walk_state_t *);
int page_walk_step(mdb_walk_state_t *);
void page_walk_fini(mdb_walk_state_t *);
int page(uintptr_t, uint_t, int, const mdb_arg_t *);
int memstat(uintptr_t, uint_t, int, const mdb_arg_t *);

int swap_walk_init(mdb_walk_state_t *);
int swap_walk_step(mdb_walk_state_t *);
int swapinfof(uintptr_t, uint_t, int, const mdb_arg_t *);

int memlist_walk_step(mdb_walk_state_t *);
int memlist(uintptr_t, uint_t, int, const mdb_arg_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _MEMORY_H */
