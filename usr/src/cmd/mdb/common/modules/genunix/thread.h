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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2018, Joyent, Inc.
 */

#ifndef	_THREAD_H
#define	_THREAD_H


#include <mdb/mdb_modapi.h>

#ifdef	__cplusplus
extern "C" {
#endif

int thread_walk_init(mdb_walk_state_t *);
int thread_walk_step(mdb_walk_state_t *);
void thread_walk_fini(mdb_walk_state_t *);

int deathrow_walk_init(mdb_walk_state_t *);
int deathrow_walk_step(mdb_walk_state_t *);
int thread_deathrow_walk_init(mdb_walk_state_t *);
int lwp_deathrow_walk_init(mdb_walk_state_t *);

int cpu_dispq_walk_init(mdb_walk_state_t *);
int cpupart_dispq_walk_init(mdb_walk_state_t *);
int dispq_walk_step(mdb_walk_state_t *);
void dispq_walk_fini(mdb_walk_state_t *);

int thread(uintptr_t, uint_t, int, const mdb_arg_t *);
void thread_help(void);
int threadlist(uintptr_t, uint_t, int, const mdb_arg_t *);
void threadlist_help(void);
int stackinfo(uintptr_t, uint_t, int, const mdb_arg_t *);
void stackinfo_help(void);

void thread_state_to_text(uint_t, char *, size_t);
int thread_text_to_state(const char *, uint_t *);
void thread_walk_states(void (*)(uint_t, const char *, void *), void *);

int thread_getdesc(uintptr_t, boolean_t, char *, size_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _THREAD_H */
