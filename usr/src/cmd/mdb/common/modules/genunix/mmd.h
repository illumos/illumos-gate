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
 * Copyright 1998-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_MMD_H
#define	_MMD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <mdb/mdb_modapi.h>

#ifdef	__cplusplus
extern "C" {
#endif

int multidata(uintptr_t, uint_t, int, const mdb_arg_t *);
int mmdq_walk_step(mdb_walk_state_t *);
void mmdq_walk_fini(mdb_walk_state_t *);
int pdesc_slab_walk_init(mdb_walk_state_t *);
int slab2multidata(uintptr_t, uint_t, int, const mdb_arg_t *);
int pdesc_walk_init(mdb_walk_state_t *);
int pattbl(uintptr_t, uint_t, int, const mdb_arg_t *);
int pattr_walk_init(mdb_walk_state_t *);
int pattr2multidata(uintptr_t, uint_t, int, const mdb_arg_t *);
int pdesc2slab(uintptr_t, uint_t, int, const mdb_arg_t *);
int pdesc_verify(uintptr_t, uint_t, int, const mdb_arg_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _MMD_H */
