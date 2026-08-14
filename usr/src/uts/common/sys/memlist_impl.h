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
 * Copyright (c) 1997-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 * Copyright 2026 Oxide Computer Company
 */

#ifndef	_SYS_MEMLIST_IMPL_H
#define	_SYS_MEMLIST_IMPL_H

/*
 * Common memlist routines.
 */

#include <sys/memlist.h>
#include <sys/mutex.h>

#ifdef __cplusplus
extern "C" {
#endif

struct memlist_pool {
	memlist_t *mp_freelist;
	uint_t mp_freelist_count;
	kmutex_t mp_freelist_mutex;
	uint_t mp_flags;
};

#define	MEMLP_FL_EARLYBOOT	1
/*
 * A pool that is not really a pool: entries come from kmem on demand and go
 * back to it when freed, so allocation is unbounded and cannot fail rather
 * than being served from a freelist that has to be stocked in advance.  For
 * consumers that run late enough to call kmem and do not know ahead of time
 * how many entries they will need.
 *
 * Such a pool holds no state, so a single one serves everybody: see
 * memlist_kmem_pool below.  Its entries must never be mixed with a real
 * pool's, since freeing them is kmem_free() rather than a freelist push.
 * Use xmemlist_dup instead to copy entries to a memlist backed by a different
 * pool.
 */
#define	MEMLP_FL_KMEM		2

extern memlist_pool_t memlist_kmem_pool;

extern struct memlist *memlist_get_one(void);
extern void memlist_free_one(struct memlist *);
extern void memlist_free_list(struct memlist *);
extern void memlist_free_block(caddr_t, size_t);
extern void memlist_insert(struct memlist *, struct memlist **);
extern void memlist_del(struct memlist *, struct memlist **);
extern struct memlist *memlist_find(struct memlist *, uint64_t);

extern struct memlist *xmemlist_get_one(struct memlist_pool *);
extern void xmemlist_free_one(struct memlist_pool *, struct memlist *);
extern void xmemlist_free_list(struct memlist_pool *, struct memlist *);
extern void xmemlist_free_block(struct memlist_pool *, caddr_t, size_t);

#define	MEML_SPANOP_OK		0
#define	MEML_SPANOP_ESPAN	1
#define	MEML_SPANOP_EALLOC	2
#define	MEML_SPANOP_EOVERFLOW	3

/*
 * Optional for span operations: allow munging (relaxed coalescing).  When set,
 * the span to be added or deleted from the list may overlap multiple existing
 * entries and/or addresses not contained within the list.  See notes in
 * memlist_new.c.
 */
#define	MEML_FL_RELAXED	1

extern int memlist_add_span(uint64_t, uint64_t, struct memlist **);
extern int memlist_delete_span(uint64_t, uint64_t, struct memlist **);
extern int xmemlist_add_span(struct memlist_pool *, uint64_t, uint64_t,
    struct memlist **, uint64_t);
extern int xmemlist_delete_span(struct memlist_pool *, uint64_t, uint64_t,
    struct memlist **, uint64_t);

/*
 * Copy a list into the given pool, for handing it from one pool's ownership to
 * another's.  Returns NULL if that pool runs out.
 */
extern struct memlist *xmemlist_dup(memlist_pool_t *, const struct memlist *);

/*
 * Free a whole list back to its pool and clear the caller's pointer to it.
 */
extern void xmemlist_free_all(memlist_pool_t *, struct memlist **);

/*
 * Add every span of one list to another: their union, given MEML_FL_RELAXED.
 * merge() leaves the source alone while subsume() empties it into the pool.
 *
 * Both stop at the first span that cannot be added, so on failure the
 * destination holds what was transferred before it and, for subsume(), the
 * source holds the rest.
 */
extern int xmemlist_merge(memlist_pool_t *, const struct memlist *,
    struct memlist **, uint64_t);
extern int xmemlist_subsume(memlist_pool_t *, struct memlist **,
    struct memlist **, uint64_t);

/*
 * Delete every span of one list from another: their difference.  The list being
 * subtracted is untouched and need not belong to this pool.
 *
 * This will stop at the first failure to delete a span: no such span exists
 * (if MEML_FL_RELAXED wasn't passed) or failed to allocate an entry for a newly
 * split off span.  In either case, the list under mutation holds whatever it
 * started with less the spans successfully deleted.
 */
extern int xmemlist_delete_list(memlist_pool_t *, struct memlist **,
    const struct memlist *, uint64_t);

/*
 * Find the first span of the given size and alignment without modifying the
 * list, for asking whether an allocation would succeed.  Returns
 * MEML_SPANOP_ESPAN if there is no such span, otherwise MEML_SPANOP_OK with the
 * address a claim would hand back.  Any non-zero alignment value must be a
 * power-of-two.  The address out parameter may be NULL if the specific address
 * is not needed but just that such a span exists.
 */
extern int memlist_find_span(const struct memlist *, uint64_t, uint64_t,
    uint64_t *);

/*
 * These routines first try to find a span of the given size and alignment
 * (in the entry beginning exactly at the given address for the _at form) and
 * then call xmemlist_delete_span (with MEML_FL_RELAXED) to remove said span.
 * If no such span is not found, MEML_SPANOP_ESPAN is returned with the list
 * remaining untouched.  If a span is found and successfully deleted from the
 * list, the starting address is returned.  Any non-zero alignment value must be
 * a power-of-two.
 */
extern int xmemlist_claim_span(memlist_pool_t *, struct memlist **, uint64_t,
    uint64_t, uint64_t *);
extern int xmemlist_claim_span_at(memlist_pool_t *, struct memlist **,
    uint64_t, uint64_t, uint64_t, uint64_t *);

/*
 * Convenience methods for tracking available/in-use address space.  These are
 * wrappers around the above xmemlist_* operations making use of the kmem pool
 * and relaxed semantics.
 *
 * Fixing the pool and the flags is what makes most of these infallible, so they
 * return nothing: relaxed semantics rule out MEML_SPANOP_ESPAN, and a
 * kmem-backed pool sleeps for memory rather than returning MEML_SPANOP_EALLOC.
 */
extern void memlist_rsrc_add(struct memlist **, uint64_t, uint64_t);
extern void memlist_rsrc_delete(struct memlist **, uint64_t, uint64_t);
extern void memlist_rsrc_delete_list(struct memlist **, const struct memlist *);
extern void memlist_rsrc_merge(const struct memlist *, struct memlist **);
extern void memlist_rsrc_subsume(struct memlist **, struct memlist **);
extern int memlist_rsrc_claim(struct memlist **, uint64_t, uint64_t,
    uint64_t *);
extern int memlist_rsrc_claim_at(struct memlist **, uint64_t, uint64_t,
    uint64_t, uint64_t *);
extern struct memlist *memlist_rsrc_dup(const struct memlist *);
extern void memlist_rsrc_free(struct memlist **);

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_MEMLIST_IMPL_H */
