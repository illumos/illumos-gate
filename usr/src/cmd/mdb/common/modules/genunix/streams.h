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
 * Copyright 1998-2001, 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_STREAMS_H
#define	_STREAMS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <mdb/mdb_modapi.h>

#ifdef	__cplusplus
extern "C" {
#endif

int queue_walk_init(mdb_walk_state_t *);
int queue_link_step(mdb_walk_state_t *);
int queue_next_step(mdb_walk_state_t *);
void queue_walk_fini(mdb_walk_state_t *);

int str_walk_init(mdb_walk_state_t *);
int strr_walk_step(mdb_walk_state_t *);
int strw_walk_step(mdb_walk_state_t *);
void str_walk_fini(mdb_walk_state_t *);

int mblk_walk_init(mdb_walk_state_t *);
int b_cont_step(mdb_walk_state_t *);
int b_next_step(mdb_walk_state_t *);
void mblk_walk_fini(mdb_walk_state_t *);

int strftblk_walk_init(mdb_walk_state_t *);
int strftblk_step(mdb_walk_state_t *);
void strftblk_walk_fini(mdb_walk_state_t *);

int stream(uintptr_t, uint_t, int, const mdb_arg_t *);
int queue(uintptr_t, uint_t, int, const mdb_arg_t *);
int q2syncq(uintptr_t, uint_t, int, const mdb_arg_t *);
int q2stream(uintptr_t, uint_t, int, const mdb_arg_t *);
int q2rdq(uintptr_t, uint_t, int, const mdb_arg_t *);
int q2wrq(uintptr_t, uint_t, int, const mdb_arg_t *);
int q2otherq(uintptr_t, uint_t, int, const mdb_arg_t *);
int stdata(uintptr_t, uint_t, int, const mdb_arg_t *);
int str2mate(uintptr_t, uint_t, int, const mdb_arg_t *);
int str2wrq(uintptr_t, uint_t, int, const mdb_arg_t *);
int syncq(uintptr_t, uint_t, int, const mdb_arg_t *);
int syncq2q(uintptr_t, uint_t, int, const mdb_arg_t *);
int strftevent(uintptr_t, uint_t, int, const mdb_arg_t *);
int mblk_prt(uintptr_t, uint_t, int, const mdb_arg_t *);
int mblk2dblk(uintptr_t, uint_t, int, const mdb_arg_t *);
int mblk_verify(uintptr_t, uint_t, int, const mdb_arg_t *);
void queue_help(void);
void syncq_help(void);
void stdata_help(void);
void mblk_help(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _STREAMS_H */
