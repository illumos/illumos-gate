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
 * Copyright (c) 1999, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_HASHSET_H
#define	_HASHSET_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct HashSet *HASHSET;
typedef struct HashSetIterator *HASHSET_ITERATOR;

extern HASHSET h_create(uint_t (*hash) (const void *),
    int    (*equal) (const void *, const void *),
    uint_t initialCapacity,
    float loadFactor);
extern const void *h_get(const HASHSET h, void *key);
extern const void *h_put(HASHSET h, const void *key);
extern const void *h_delete(HASHSET h, const void *key);

extern HASHSET_ITERATOR h_iterator(HASHSET h);
extern const void *h_next(HASHSET_ITERATOR i);

#ifdef	__cplusplus
}
#endif

#endif	/* _HASHSET_H */
