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
 * Copyright 1998-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _MTMALLOC_IMPL_H
#define	_MTMALLOC_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Various data structures that define the guts of the mt malloc
 * library.
 */

#include <sys/types.h>
#include <synch.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cache {
	mutex_t mt_cache_lock;	/* lock for this data structure */
	caddr_t mt_freelist;	/* free block bit mask */
	caddr_t mt_arena;	/* addr of arena for actual dblks */
	size_t  mt_nfree;	/* how many freeblocks do we have */
	size_t mt_size;		/* size of this cache */
	size_t mt_span;		/* how long is this cache */
	struct cache *mt_next;	/* next cache in list */
	int mt_hunks;		/* at creation time what chunk size */
} cache_t;

typedef struct oversize {
	struct oversize *next_bysize;
	struct oversize *prev_bysize;
	struct oversize *next_byaddr;
	struct oversize *prev_byaddr;
	struct oversize *hash_next;
	caddr_t addr;
	size_t  size;
} oversize_t;

typedef struct cache_head {
	cache_t *mt_cache;
	cache_t *mt_hint;
} cache_head_t;

/* used to avoid false sharing, should be power-of-2 >= cache coherency size */
#define	CACHE_COHERENCY_UNIT	64

#define	PERCPU_SIZE	CACHE_COHERENCY_UNIT
#define	PERCPU_PAD	(PERCPU_SIZE - sizeof (mutex_t) - \
			sizeof (cache_head_t *))

typedef struct percpu {
	mutex_t mt_parent_lock;	/* used for hooking in new caches */
	cache_head_t *mt_caches;
	char mt_pad[PERCPU_PAD];
} percpu_t;

typedef uint_t (*curcpu_func)(void);

#define	DATA_SHIFT	1
#define	TAIL_SHIFT	2

/*
 * Oversize bit definitions: 3 bits to represent the oversize for
 * head fragment, data itself, and tail fragment.
 * If the head fragment is oversize, the first bit is on.
 * If the data itself is oversize, the second bit is on.
 * If the tail fragment is oversize, then the third bit is on.
 */
#define	NONE_OVERSIZE		0x0
#define	HEAD_OVERSIZE		0x1
#define	DATA_OVERSIZE		0x2
#define	HEAD_AND_DATA_OVERSIZE	0x3
#define	TAIL_OVERSIZE		0x4
#define	HEAD_AND_TAIL_OVERSIZE	0x5
#define	DATA_AND_TAIL_OVERSIZE	0x6
#define	ALL_OVERSIZE		0x7

#ifdef __cplusplus
}
#endif

#endif /* _MTMALLOC_IMPL_H */
