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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _INJ_HASH_H
#define	_INJ_HASH_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct inj_var inj_var_t;

typedef struct inj_hash {
	inj_var_t **h_hash;
	size_t h_hashsz;
	size_t h_nelems;

	ulong_t (*h_hashfn)(void *);
	int (*h_cmpfn)(void *, void *);
	void (*h_freefn)(void *, uintmax_t);
} inj_hash_t;

extern void inj_hash_create(inj_hash_t *, ulong_t (*)(void *),
    int (*)(void *, void *));
extern void inj_hash_destroy(inj_hash_t *, void (*)(inj_var_t *, void *),
    void *);

extern int inj_hash_insert(inj_hash_t *, void *, uintmax_t);
extern inj_var_t *inj_hash_lookup(inj_hash_t *, void *);

extern void *inj_hash_get_key(inj_var_t *);
extern uintmax_t inj_hash_get_value(inj_var_t *);
extern void *inj_hash_get_cookie(inj_var_t *);

#ifdef __cplusplus
}
#endif

#endif /* _INJ_HASH_H */
