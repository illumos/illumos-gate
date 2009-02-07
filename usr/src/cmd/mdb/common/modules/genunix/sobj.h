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
 */

#ifndef	_SOBJ_H
#define	_SOBJ_H

#ifdef	__cplusplus
extern "C" {
#endif

int wchan_walk_init(mdb_walk_state_t *);
int wchan_walk_step(mdb_walk_state_t *);
void wchan_walk_fini(mdb_walk_state_t *);

int wchaninfo(uintptr_t, uint_t, int, const mdb_arg_t *);

int blocked_walk_init(mdb_walk_state_t *);
int blocked_walk_step(mdb_walk_state_t *);

int rwlock(uintptr_t, uint_t, int, const mdb_arg_t *);
int mutex(uintptr_t, uint_t, int, const mdb_arg_t *);

int turnstile(uintptr_t, uint_t, int, const mdb_arg_t *);
int sobj2ts(uintptr_t, uint_t, int, const mdb_arg_t *);

void mutex_help(void);

void sobj_ops_to_text(uintptr_t, char *, size_t);
void sobj_type_to_text(int, char *, size_t);
int sobj_text_to_ops(const char *, uintptr_t *);
void sobj_type_walk(void (*)(int, const char *, const char *, void *), void *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SOBJ_H */
