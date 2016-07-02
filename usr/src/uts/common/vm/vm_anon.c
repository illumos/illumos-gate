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
 * Copyright (c) 1986, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2015, Joyent, Inc. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*
 * VM - anonymous pages.
 *
 * This layer sits immediately above the vm_swap layer.  It manages
 * physical pages that have no permanent identity in the file system
 * name space, using the services of the vm_swap layer to allocate
 * backing storage for these pages.  Since these pages have no external
 * identity, they are discarded when the last reference is removed.
 *
 * An important function of this layer is to manage low-level sharing
 * of pages that are logically distinct but that happen to be
 * physically identical (e.g., the corresponding pages of the processes
 * resulting from a fork before one process or the other changes their
 * contents).  This pseudo-sharing is present only as an optimization
 * and is not to be confused with true sharing in which multiple
 * address spaces deliberately contain references to the same object;
 * such sharing is managed at a higher level.
 *
 * The key data structure here is the anon struct, which contains a
 * reference count for its associated physical page and a hint about
 * the identity of that page.  Anon structs typically live in arrays,
 * with an instance's position in its array determining where the
 * corresponding backing storage is allocated; however, the swap_xlate()
 * routine abstracts away this representation information so that the
 * rest of the anon layer need not know it.  (See the swap layer for
 * more details on anon struct layout.)
 *
 * In the future versions of the system, the association between an
 * anon struct and its position on backing store will change so that
 * we don't require backing store all anonymous pages in the system.
 * This is important for consideration for large memory systems.
 * We can also use this technique to delay binding physical locations
 * to anonymous pages until pageout/swapout time where we can make
 * smarter allocation decisions to improve anonymous klustering.
 *
 * Many of the routines defined here take a (struct anon **) argument,
 * which allows the code at this level to manage anon pages directly,
 * so that callers can regard anon structs as opaque objects and not be
 * concerned with assigning or inspecting their contents.
 *
 * Clients of this layer refer to anon pages indirectly.  That is, they
 * maintain arrays of pointers to anon structs rather than maintaining
 * anon structs themselves.  The (struct anon **) arguments mentioned
 * above are pointers to entries in these arrays.  It is these arrays
 * that capture the mapping between offsets within a given segment and
 * the corresponding anonymous backing storage address.
 */

#ifdef DEBUG
#define	ANON_DEBUG
#endif

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mman.h>
#include <sys/cred.h>
#include <sys/thread.h>
#include <sys/vnode.h>
#include <sys/cpuvar.h>
#include <sys/swap.h>
#include <sys/cmn_err.h>
#include <sys/vtrace.h>
#include <sys/kmem.h>
#include <sys/sysmacros.h>
#include <sys/bitmap.h>
#include <sys/vmsystm.h>
#include <sys/tuneable.h>
#include <sys/debug.h>
#include <sys/fs/swapnode.h>
#include <sys/tnf_probe.h>
#include <sys/lgrp.h>
#include <sys/policy.h>
#include <sys/condvar_impl.h>
#include <sys/mutex_impl.h>
#include <sys/rctl.h>

#include <vm/as.h>
#include <vm/hat.h>
#include <vm/anon.h>
#include <vm/page.h>
#include <vm/vpage.h>
#include <vm/seg.h>
#include <vm/rm.h>

#include <fs/fs_subr.h>

struct vnode *anon_vp;

int anon_debug;

kmutex_t	anoninfo_lock;
struct		k_anoninfo k_anoninfo;
ani_free_t	*ani_free_pool;
pad_mutex_t	anon_array_lock[ANON_LOCKSIZE];
kcondvar_t	anon_array_cv[ANON_LOCKSIZE];

/*
 * Global hash table for (vp, off) -> anon slot
 */
extern	int swap_maxcontig;
size_t	anon_hash_size;
unsigned int anon_hash_shift;
struct anon **anon_hash;

static struct kmem_cache *anon_cache;
static struct kmem_cache *anonmap_cache;

pad_mutex_t	*anonhash_lock;

/*
 * Used to make the increment of all refcnts of all anon slots of a large
 * page appear to be atomic.  The lock is grabbed for the first anon slot of
 * a large page.
 */
pad_mutex_t	*anonpages_hash_lock;

#define	APH_MUTEX(vp, off)				\
	(&anonpages_hash_lock[(ANON_HASH((vp), (off)) &	\
	    (AH_LOCK_SIZE - 1))].pad_mutex)

#ifdef VM_STATS
static struct anonvmstats_str {
	ulong_t getpages[30];
	ulong_t privatepages[10];
	ulong_t demotepages[9];
	ulong_t decrefpages[9];
	ulong_t	dupfillholes[4];
	ulong_t freepages[1];
} anonvmstats;
#endif /* VM_STATS */

/*ARGSUSED*/
static int
anonmap_cache_constructor(void *buf, void *cdrarg, int kmflags)
{
	struct anon_map *amp = buf;

	rw_init(&amp->a_rwlock, NULL, RW_DEFAULT, NULL);
	cv_init(&amp->a_purgecv, NULL, CV_DEFAULT, NULL);
	mutex_init(&amp->a_pmtx, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&amp->a_purgemtx, NULL, MUTEX_DEFAULT, NULL);
	return (0);
}

/*ARGSUSED1*/
static void
anonmap_cache_destructor(void *buf, void *cdrarg)
{
	struct anon_map *amp = buf;

	rw_destroy(&amp->a_rwlock);
	cv_destroy(&amp->a_purgecv);
	mutex_destroy(&amp->a_pmtx);
	mutex_destroy(&amp->a_purgemtx);
}

void
anon_init(void)
{
	int i;
	pad_mutex_t *tmp;

	/* These both need to be powers of 2 so round up to the next power */
	anon_hash_shift = highbit((physmem / ANON_HASHAVELEN) - 1);
	anon_hash_size = 1L << anon_hash_shift;

	/*
	 * We need to align the anonhash_lock and anonpages_hash_lock arrays
	 * to a 64B boundary to avoid false sharing.  We add 63B to our
	 * allocation so that we can get a 64B aligned address to use.
	 * We allocate both of these together to avoid wasting an additional
	 * 63B.
	 */
	tmp = kmem_zalloc((2 * AH_LOCK_SIZE * sizeof (pad_mutex_t)) + 63,
	    KM_SLEEP);
	anonhash_lock = (pad_mutex_t *)P2ROUNDUP((uintptr_t)tmp, 64);
	anonpages_hash_lock = anonhash_lock + AH_LOCK_SIZE;

	for (i = 0; i < AH_LOCK_SIZE; i++) {
		mutex_init(&anonhash_lock[i].pad_mutex, NULL, MUTEX_DEFAULT,
		    NULL);
		mutex_init(&anonpages_hash_lock[i].pad_mutex, NULL,
		    MUTEX_DEFAULT, NULL);
	}

	for (i = 0; i < ANON_LOCKSIZE; i++) {
		mutex_init(&anon_array_lock[i].pad_mutex, NULL,
		    MUTEX_DEFAULT, NULL);
		cv_init(&anon_array_cv[i], NULL, CV_DEFAULT, NULL);
	}

	anon_hash = (struct anon **)
	    kmem_zalloc(sizeof (struct anon *) * anon_hash_size, KM_SLEEP);
	anon_cache = kmem_cache_create("anon_cache", sizeof (struct anon),
	    AN_CACHE_ALIGN, NULL, NULL, NULL, NULL, NULL, KMC_PREFILL);
	anonmap_cache = kmem_cache_create("anonmap_cache",
	    sizeof (struct anon_map), 0,
	    anonmap_cache_constructor, anonmap_cache_destructor, NULL,
	    NULL, NULL, 0);
	swap_maxcontig = (1024 * 1024) >> PAGESHIFT;	/* 1MB of pages */

	tmp = kmem_zalloc((ANI_MAX_POOL * sizeof (ani_free_t)) + 63, KM_SLEEP);
	/* Round ani_free_pool to cacheline boundary to avoid false sharing. */
	ani_free_pool = (ani_free_t *)P2ROUNDUP((uintptr_t)tmp, 64);

	anon_vp = vn_alloc(KM_SLEEP);
	vn_setops(anon_vp, swap_vnodeops);
	anon_vp->v_type = VREG;
	anon_vp->v_flag |= (VISSWAP|VISSWAPFS);
}

/*
 * Global anon slot hash table manipulation.
 */

static void
anon_addhash(struct anon *ap)
{
	int index;

	ASSERT(MUTEX_HELD(AH_MUTEX(ap->an_vp, ap->an_off)));
	index = ANON_HASH(ap->an_vp, ap->an_off);
	ap->an_hash = anon_hash[index];
	anon_hash[index] = ap;
}

static void
anon_rmhash(struct anon *ap)
{
	struct anon **app;

	ASSERT(MUTEX_HELD(AH_MUTEX(ap->an_vp, ap->an_off)));

	for (app = &anon_hash[ANON_HASH(ap->an_vp, ap->an_off)];
	    *app; app = &((*app)->an_hash)) {
		if (*app == ap) {
			*app = ap->an_hash;
			break;
		}
	}
}

/*
 * The anon array interfaces. Functions allocating,
 * freeing array of pointers, and returning/setting
 * entries in the array of pointers for a given offset.
 *
 * Create the list of pointers
 */
struct anon_hdr *
anon_create(pgcnt_t npages, int flags)
{
	struct anon_hdr *ahp;
	ulong_t nchunks;
	int kmemflags = (flags & ANON_NOSLEEP) ? KM_NOSLEEP : KM_SLEEP;

	if ((ahp = kmem_zalloc(sizeof (struct anon_hdr), kmemflags)) == NULL) {
		return (NULL);
	}

	mutex_init(&ahp->serial_lock, NULL, MUTEX_DEFAULT, NULL);
	/*
	 * Single level case.
	 */
	ahp->size = npages;
	if (npages <= ANON_CHUNK_SIZE || (flags & ANON_ALLOC_FORCE)) {

		if (flags & ANON_ALLOC_FORCE)
			ahp->flags |= ANON_ALLOC_FORCE;

		ahp->array_chunk = kmem_zalloc(
		    ahp->size * sizeof (struct anon *), kmemflags);

		if (ahp->array_chunk == NULL) {
			kmem_free(ahp, sizeof (struct anon_hdr));
			return (NULL);
		}
	} else {
		/*
		 * 2 Level case.
		 * anon hdr size needs to be rounded off  to be a multiple
		 * of ANON_CHUNK_SIZE. This is important as various anon
		 * related functions depend on this.
		 * NOTE -
		 * anon_grow()  makes anon hdr size a multiple of
		 * ANON_CHUNK_SIZE.
		 * amp size is <= anon hdr size.
		 * anon_index + seg_pgs <= anon hdr size.
		 */
		ahp->size = P2ROUNDUP(npages, ANON_CHUNK_SIZE);
		nchunks = ahp->size >> ANON_CHUNK_SHIFT;

		ahp->array_chunk = kmem_zalloc(nchunks * sizeof (ulong_t *),
		    kmemflags);

		if (ahp->array_chunk == NULL) {
			kmem_free(ahp, sizeof (struct anon_hdr));
			return (NULL);
		}
	}
	return (ahp);
}

/*
 * Free the array of pointers
 */
void
anon_release(struct anon_hdr *ahp, pgcnt_t npages)
{
	ulong_t i;
	void **ppp;
	ulong_t nchunks;

	ASSERT(npages <= ahp->size);

	/*
	 * Single level case.
	 */
	if (npages <= ANON_CHUNK_SIZE || (ahp->flags & ANON_ALLOC_FORCE)) {
		kmem_free(ahp->array_chunk, ahp->size * sizeof (struct anon *));
	} else {
		/*
		 * 2 level case.
		 */
		nchunks = ahp->size >> ANON_CHUNK_SHIFT;
		for (i = 0; i < nchunks; i++) {
			ppp = &ahp->array_chunk[i];
			if (*ppp != NULL)
				kmem_free(*ppp, PAGESIZE);
		}
		kmem_free(ahp->array_chunk, nchunks * sizeof (ulong_t *));
	}
	mutex_destroy(&ahp->serial_lock);
	kmem_free(ahp, sizeof (struct anon_hdr));
}

/*
 * Return the pointer from the list for a
 * specified anon index.
 */
struct anon *
anon_get_ptr(struct anon_hdr *ahp, ulong_t an_idx)
{
	struct anon **app;

	ASSERT(an_idx < ahp->size);

	/*
	 * Single level case.
	 */
	if ((ahp->size <= ANON_CHUNK_SIZE) || (ahp->flags & ANON_ALLOC_FORCE)) {
		return ((struct anon *)
		    ((uintptr_t)ahp->array_chunk[an_idx] & ANON_PTRMASK));
	} else {

		/*
		 * 2 level case.
		 */
		app = ahp->array_chunk[an_idx >> ANON_CHUNK_SHIFT];
		if (app) {
			return ((struct anon *)
			    ((uintptr_t)app[an_idx & ANON_CHUNK_OFF] &
			    ANON_PTRMASK));
		} else {
			return (NULL);
		}
	}
}

/*
 * Return the anon pointer for the first valid entry in the anon list,
 * starting from the given index.
 */
struct anon *
anon_get_next_ptr(struct anon_hdr *ahp, ulong_t *index)
{
	struct anon *ap;
	struct anon **app;
	ulong_t chunkoff;
	ulong_t i;
	ulong_t j;
	pgcnt_t size;

	i = *index;
	size = ahp->size;

	ASSERT(i < size);

	if ((size <= ANON_CHUNK_SIZE) || (ahp->flags & ANON_ALLOC_FORCE)) {
		/*
		 * 1 level case
		 */
		while (i < size) {
			ap = (struct anon *)
			    ((uintptr_t)ahp->array_chunk[i] & ANON_PTRMASK);
			if (ap) {
				*index = i;
				return (ap);
			}
			i++;
		}
	} else {
		/*
		 * 2 level case
		 */
		chunkoff = i & ANON_CHUNK_OFF;
		while (i < size) {
			app = ahp->array_chunk[i >> ANON_CHUNK_SHIFT];
			if (app)
				for (j = chunkoff; j < ANON_CHUNK_SIZE; j++) {
					ap = (struct anon *)
					    ((uintptr_t)app[j] & ANON_PTRMASK);
					if (ap) {
						*index = i + (j - chunkoff);
						return (ap);
					}
				}
			chunkoff = 0;
			i = (i + ANON_CHUNK_SIZE) & ~ANON_CHUNK_OFF;
		}
	}
	*index = size;
	return (NULL);
}

/*
 * Set list entry with a given pointer for a specified offset
 */
int
anon_set_ptr(struct anon_hdr *ahp, ulong_t an_idx, struct anon *ap, int flags)
{
	void		**ppp;
	struct anon	**app;
	int kmemflags = (flags & ANON_NOSLEEP) ? KM_NOSLEEP : KM_SLEEP;
	uintptr_t	*ap_addr;

	ASSERT(an_idx < ahp->size);

	/*
	 * Single level case.
	 */
	if (ahp->size <= ANON_CHUNK_SIZE || (ahp->flags & ANON_ALLOC_FORCE)) {
		ap_addr = (uintptr_t *)&ahp->array_chunk[an_idx];
	} else {

		/*
		 * 2 level case.
		 */
		ppp = &ahp->array_chunk[an_idx >> ANON_CHUNK_SHIFT];

		ASSERT(ppp != NULL);
		if (*ppp == NULL) {
			mutex_enter(&ahp->serial_lock);
			ppp = &ahp->array_chunk[an_idx >> ANON_CHUNK_SHIFT];
			if (*ppp == NULL) {
				*ppp = kmem_zalloc(PAGESIZE, kmemflags);
				if (*ppp == NULL) {
					mutex_exit(&ahp->serial_lock);
					return (ENOMEM);
				}
			}
			mutex_exit(&ahp->serial_lock);
		}
		app = *ppp;
		ap_addr = (uintptr_t *)&app[an_idx & ANON_CHUNK_OFF];
	}
	*ap_addr = (*ap_addr & ~ANON_PTRMASK) | (uintptr_t)ap;
	return (0);
}

/*
 * Copy anon array into a given new anon array
 */
int
anon_copy_ptr(struct anon_hdr *sahp, ulong_t s_idx,
	struct anon_hdr *dahp, ulong_t d_idx,
	pgcnt_t npages, int flags)
{
	void **sapp, **dapp;
	void *ap;
	int kmemflags = (flags & ANON_NOSLEEP) ? KM_NOSLEEP : KM_SLEEP;

	ASSERT((s_idx < sahp->size) && (d_idx < dahp->size));
	ASSERT((npages <= sahp->size) && (npages <= dahp->size));

	/*
	 * Both arrays are 1 level.
	 */
	if (((sahp->size <= ANON_CHUNK_SIZE) &&
	    (dahp->size <= ANON_CHUNK_SIZE)) ||
	    ((sahp->flags & ANON_ALLOC_FORCE) &&
	    (dahp->flags & ANON_ALLOC_FORCE))) {

		bcopy(&sahp->array_chunk[s_idx], &dahp->array_chunk[d_idx],
		    npages * sizeof (struct anon *));
		return (0);
	}

	/*
	 * Both arrays are 2 levels.
	 */
	if (sahp->size > ANON_CHUNK_SIZE &&
	    dahp->size > ANON_CHUNK_SIZE &&
	    ((sahp->flags & ANON_ALLOC_FORCE) == 0) &&
	    ((dahp->flags & ANON_ALLOC_FORCE) == 0)) {

		ulong_t sapidx, dapidx;
		ulong_t *sap, *dap;
		ulong_t chknp;

		while (npages != 0) {

			sapidx = s_idx & ANON_CHUNK_OFF;
			dapidx = d_idx & ANON_CHUNK_OFF;
			chknp = ANON_CHUNK_SIZE - MAX(sapidx, dapidx);
			if (chknp > npages)
				chknp = npages;

			sapp = &sahp->array_chunk[s_idx >> ANON_CHUNK_SHIFT];
			if ((sap = *sapp) != NULL) {
				dapp = &dahp->array_chunk[d_idx
				    >> ANON_CHUNK_SHIFT];
				if ((dap = *dapp) == NULL) {
					*dapp = kmem_zalloc(PAGESIZE,
					    kmemflags);
					if ((dap = *dapp) == NULL)
						return (ENOMEM);
				}
				bcopy((sap + sapidx), (dap + dapidx),
				    chknp << ANON_PTRSHIFT);
			}
			s_idx += chknp;
			d_idx += chknp;
			npages -= chknp;
		}
		return (0);
	}

	/*
	 * At least one of the arrays is 2 level.
	 */
	while (npages--) {
		if ((ap = anon_get_ptr(sahp, s_idx)) != NULL) {
			ASSERT(!ANON_ISBUSY(anon_get_slot(sahp, s_idx)));
			if (anon_set_ptr(dahp, d_idx, ap, flags) == ENOMEM)
					return (ENOMEM);
		}
		s_idx++;
		d_idx++;
	}
	return (0);
}


/*
 * ANON_INITBUF is a convenience macro for anon_grow() below. It
 * takes a buffer dst, which is at least as large as buffer src. It
 * does a bcopy from src into dst, and then bzeros the extra bytes
 * of dst. If tail is set, the data in src is tail aligned within
 * dst instead of head aligned.
 */

#define	ANON_INITBUF(src, srclen, dst, dstsize, tail)			      \
	if (tail) {							      \
		bzero((dst), (dstsize) - (srclen));			      \
		bcopy((src), (char *)(dst) + (dstsize) - (srclen), (srclen)); \
	} else {							      \
		bcopy((src), (dst), (srclen));				      \
		bzero((char *)(dst) + (srclen), (dstsize) - (srclen));	      \
	}

#define	ANON_1_LEVEL_INC	(ANON_CHUNK_SIZE / 8)
#define	ANON_2_LEVEL_INC	(ANON_1_LEVEL_INC * ANON_CHUNK_SIZE)

/*
 * anon_grow() is used to efficiently extend an existing anon array.
 * startidx_p points to the index into the anon array of the first page
 * that is in use. oldseg_pgs is the number of pages in use, starting at
 * *startidx_p. newpages is the number of additional pages desired.
 *
 * If startidx_p == NULL, startidx is taken to be 0 and cannot be changed.
 *
 * The growth is done by creating a new top level of the anon array,
 * and (if the array is 2-level) reusing the existing second level arrays.
 *
 * flags can be used to specify ANON_NOSLEEP and ANON_GROWDOWN.
 *
 * Returns the new number of pages in the anon array.
 */
pgcnt_t
anon_grow(struct anon_hdr *ahp, ulong_t *startidx_p, pgcnt_t oldseg_pgs,
    pgcnt_t newseg_pgs, int flags)
{
	ulong_t startidx = startidx_p ? *startidx_p : 0;
	pgcnt_t oldamp_pgs = ahp->size, newamp_pgs;
	pgcnt_t oelems, nelems, totpages;
	void **level1;
	int kmemflags = (flags & ANON_NOSLEEP) ? KM_NOSLEEP : KM_SLEEP;
	int growdown = (flags & ANON_GROWDOWN);
	size_t newarrsz, oldarrsz;
	void *level2;

	ASSERT(!(startidx_p == NULL && growdown));
	ASSERT(startidx + oldseg_pgs <= ahp->size);

	/*
	 * Determine the total number of pages needed in the new
	 * anon array. If growing down, totpages is all pages from
	 * startidx through the end of the array, plus <newseg_pgs>
	 * pages. If growing up, keep all pages from page 0 through
	 * the last page currently in use, plus <newseg_pgs> pages.
	 */
	if (growdown)
		totpages = oldamp_pgs - startidx + newseg_pgs;
	else
		totpages = startidx + oldseg_pgs + newseg_pgs;

	/* If the array is already large enough, just return. */

	if (oldamp_pgs >= totpages) {
		if (growdown)
			*startidx_p = oldamp_pgs - totpages;
		return (oldamp_pgs);
	}

	/*
	 * oldamp_pgs/newamp_pgs are the total numbers of pages represented
	 * by the corresponding arrays.
	 * oelems/nelems are the number of pointers in the top level arrays
	 * which may be either level 1 or level 2.
	 * Will the new anon array be one level or two levels?
	 */
	if (totpages <= ANON_CHUNK_SIZE || (ahp->flags & ANON_ALLOC_FORCE)) {
		newamp_pgs = P2ROUNDUP(totpages, ANON_1_LEVEL_INC);
		oelems = oldamp_pgs;
		nelems = newamp_pgs;
	} else {
		newamp_pgs = P2ROUNDUP(totpages, ANON_2_LEVEL_INC);
		oelems = (oldamp_pgs + ANON_CHUNK_OFF) >> ANON_CHUNK_SHIFT;
		nelems = newamp_pgs >> ANON_CHUNK_SHIFT;
	}

	newarrsz = nelems * sizeof (void *);
	level1 = kmem_alloc(newarrsz, kmemflags);
	if (level1 == NULL)
		return (0);

	/* Are we converting from a one level to a two level anon array? */

	if (newamp_pgs > ANON_CHUNK_SIZE && oldamp_pgs <= ANON_CHUNK_SIZE &&
	    !(ahp->flags & ANON_ALLOC_FORCE)) {

		/*
		 * Yes, we're converting to a two level. Reuse old level 1
		 * as new level 2 if it is exactly PAGESIZE. Otherwise
		 * alloc a new level 2 and copy the old level 1 data into it.
		 */
		if (oldamp_pgs == ANON_CHUNK_SIZE) {
			level2 = (void *)ahp->array_chunk;
		} else {
			level2 = kmem_alloc(PAGESIZE, kmemflags);
			if (level2 == NULL) {
				kmem_free(level1, newarrsz);
				return (0);
			}
			oldarrsz = oldamp_pgs * sizeof (void *);

			ANON_INITBUF(ahp->array_chunk, oldarrsz,
			    level2, PAGESIZE, growdown);
			kmem_free(ahp->array_chunk, oldarrsz);
		}
		bzero(level1, newarrsz);
		if (growdown)
			level1[nelems - 1] = level2;
		else
			level1[0] = level2;
	} else {
		oldarrsz = oelems * sizeof (void *);

		ANON_INITBUF(ahp->array_chunk, oldarrsz,
		    level1, newarrsz, growdown);
		kmem_free(ahp->array_chunk, oldarrsz);
	}

	ahp->array_chunk = level1;
	ahp->size = newamp_pgs;
	if (growdown)
		*startidx_p = newamp_pgs - totpages;

	return (newamp_pgs);
}


/*
 * Called to sync ani_free value.
 */

void
set_anoninfo(void)
{
	processorid_t	ix, max_seqid;
	pgcnt_t		total = 0;
	static clock_t	last_time;
	clock_t		new_time;

	if (ani_free_pool == NULL)
		return;

	/*
	 * Recompute ani_free at most once per tick. Use max_cpu_seqid_ever to
	 * identify the maximum number of CPUs were ever online.
	 */
	new_time = ddi_get_lbolt();
	if (new_time > last_time) {

		max_seqid = max_cpu_seqid_ever;
		ASSERT(ANI_MAX_POOL > max_seqid);
		for (ix = 0; ix <= max_seqid; ix++)
			total += ani_free_pool[ix].ani_count;

		last_time = new_time;
		k_anoninfo.ani_free = total;
	}
}

/*
 * Reserve anon space.
 *
 * It's no longer simply a matter of incrementing ani_resv to
 * reserve swap space, we need to check memory-based as well
 * as disk-backed (physical) swap.  The following algorithm
 * is used:
 * 	Check the space on physical swap
 * 		i.e. amount needed < ani_max - ani_phys_resv
 * 	If we are swapping on swapfs check
 *		amount needed < (availrmem - swapfs_minfree)
 * Since the algorithm to check for the quantity of swap space is
 * almost the same as that for reserving it, we'll just use anon_resvmem
 * with a flag to decrement availrmem.
 *
 * Return non-zero on success.
 */
int
anon_resvmem(size_t size, boolean_t takemem, zone_t *zone, int tryhard)
{
	pgcnt_t npages = btopr(size);
	pgcnt_t mswap_pages = 0;
	pgcnt_t pswap_pages = 0;
	proc_t *p = curproc;

	if (zone != NULL) {
		/* test zone.max-swap resource control */
		mutex_enter(&p->p_lock);
		if (rctl_incr_swap(p, zone, ptob(npages)) != 0) {
			mutex_exit(&p->p_lock);

			if (takemem)
				atomic_add_64(&zone->zone_anon_alloc_fail, 1);

			return (0);
		}

		if (!takemem)
			rctl_decr_swap(zone, ptob(npages));

		mutex_exit(&p->p_lock);
	}
	mutex_enter(&anoninfo_lock);

	/*
	 * pswap_pages is the number of pages we can take from
	 * physical (i.e. disk-backed) swap.
	 */
	ASSERT(k_anoninfo.ani_max >= k_anoninfo.ani_phys_resv);
	pswap_pages = k_anoninfo.ani_max - k_anoninfo.ani_phys_resv;

	ANON_PRINT(A_RESV,
	    ("anon_resvmem: npages %lu takemem %u pswap %lu caller %p\n",
	    npages, takemem, pswap_pages, (void *)caller()));

	if (npages <= pswap_pages) {
		/*
		 * we have enough space on a physical swap
		 */
		if (takemem)
			k_anoninfo.ani_phys_resv += npages;
		mutex_exit(&anoninfo_lock);
		return (1);
	} else if (pswap_pages != 0) {
		/*
		 * we have some space on a physical swap
		 */
		if (takemem) {
			/*
			 * use up remainder of phys swap
			 */
			k_anoninfo.ani_phys_resv += pswap_pages;
			ASSERT(k_anoninfo.ani_phys_resv == k_anoninfo.ani_max);
		}
	}
	/*
	 * since (npages > pswap_pages) we need mem swap
	 * mswap_pages is the number of pages needed from availrmem
	 */
	ASSERT(npages > pswap_pages);
	mswap_pages = npages - pswap_pages;

	ANON_PRINT(A_RESV, ("anon_resvmem: need %ld pages from memory\n",
	    mswap_pages));

	/*
	 * priv processes can reserve memory as swap as long as availrmem
	 * remains greater than swapfs_minfree; in the case of non-priv
	 * processes, memory can be reserved as swap only if availrmem
	 * doesn't fall below (swapfs_minfree + swapfs_reserve). Thus,
	 * swapfs_reserve amount of memswap is not available to non-priv
	 * processes. This protects daemons such as automounter dying
	 * as a result of application processes eating away almost entire
	 * membased swap. This safeguard becomes useless if apps are run
	 * with root access.
	 *
	 * swapfs_reserve is minimum of 4Mb or 1/16 of physmem.
	 *
	 */
	if (tryhard) {
		pgcnt_t floor_pages;

		if (secpolicy_resource_anon_mem(CRED())) {
			floor_pages = swapfs_minfree;
		} else {
			floor_pages = swapfs_minfree + swapfs_reserve;
		}

		mutex_exit(&anoninfo_lock);
		(void) page_reclaim_mem(mswap_pages, floor_pages, 0);
		mutex_enter(&anoninfo_lock);
	}

	mutex_enter(&freemem_lock);
	if (availrmem > (swapfs_minfree + swapfs_reserve + mswap_pages) ||
	    (availrmem > (swapfs_minfree + mswap_pages) &&
	    secpolicy_resource(CRED()) == 0)) {

		if (takemem) {
			/*
			 * Take the memory from the rest of the system.
			 */
			availrmem -= mswap_pages;
			mutex_exit(&freemem_lock);
			k_anoninfo.ani_mem_resv += mswap_pages;
			ANI_ADD(mswap_pages);
			ANON_PRINT((A_RESV | A_MRESV),
			    ("anon_resvmem: took %ld pages of availrmem\n",
			    mswap_pages));
		} else {
			mutex_exit(&freemem_lock);
		}

		ASSERT(k_anoninfo.ani_max >= k_anoninfo.ani_phys_resv);
		mutex_exit(&anoninfo_lock);
		return (1);
	} else {
		/*
		 * Fail if not enough memory
		 */
		if (takemem) {
			k_anoninfo.ani_phys_resv -= pswap_pages;
		}

		mutex_exit(&freemem_lock);
		mutex_exit(&anoninfo_lock);
		ANON_PRINT(A_RESV,
		    ("anon_resvmem: not enough space from swapfs\n"));
		if (zone != NULL && takemem)
			rctl_decr_swap(zone, ptob(npages));
		return (0);
	}
}

/*
 * Give back an anon reservation.
 */
void
anon_unresvmem(size_t size, zone_t *zone)
{
	pgcnt_t npages = btopr(size);
	spgcnt_t mem_free_pages = 0;
	pgcnt_t phys_free_slots;
#ifdef	ANON_DEBUG
	pgcnt_t mem_resv;
#endif
	if (zone != NULL)
		rctl_decr_swap(zone, ptob(npages));

	mutex_enter(&anoninfo_lock);

	ASSERT(k_anoninfo.ani_mem_resv >= k_anoninfo.ani_locked_swap);

	/*
	 * If some of this reservation belonged to swapfs
	 * give it back to availrmem.
	 * ani_mem_resv is the amount of availrmem swapfs has reserved.
	 * but some of that memory could be locked by segspt so we can only
	 * return non locked ani_mem_resv back to availrmem
	 */
	if (k_anoninfo.ani_mem_resv > k_anoninfo.ani_locked_swap) {
		ANON_PRINT((A_RESV | A_MRESV),
		    ("anon_unresv: growing availrmem by %ld pages\n",
		    MIN(k_anoninfo.ani_mem_resv, npages)));

		mem_free_pages = MIN((spgcnt_t)(k_anoninfo.ani_mem_resv -
		    k_anoninfo.ani_locked_swap), npages);
		mutex_enter(&freemem_lock);
		availrmem += mem_free_pages;
		mutex_exit(&freemem_lock);
		k_anoninfo.ani_mem_resv -= mem_free_pages;

		ANI_ADD(-mem_free_pages);
	}
	/*
	 * The remainder of the pages is returned to phys swap
	 */
	ASSERT(npages >= mem_free_pages);
	phys_free_slots = npages - mem_free_pages;

	if (phys_free_slots) {
		k_anoninfo.ani_phys_resv -= phys_free_slots;
	}

#ifdef	ANON_DEBUG
	mem_resv = k_anoninfo.ani_mem_resv;
#endif

	ASSERT(k_anoninfo.ani_mem_resv >= k_anoninfo.ani_locked_swap);
	ASSERT(k_anoninfo.ani_max >= k_anoninfo.ani_phys_resv);

	mutex_exit(&anoninfo_lock);

	ANON_PRINT(A_RESV, ("anon_unresv: %lu, tot %lu, caller %p\n",
	    npages, mem_resv, (void *)caller()));
}

/*
 * Allocate an anon slot and return it with the lock held.
 */
struct anon *
anon_alloc(struct vnode *vp, anoff_t off)
{
	struct anon	*ap;
	kmutex_t	*ahm;

	ap = kmem_cache_alloc(anon_cache, KM_SLEEP);
	if (vp == NULL) {
		swap_alloc(ap);
	} else {
		ap->an_vp = vp;
		ap->an_off = off;
	}
	ap->an_refcnt = 1;
	ap->an_pvp = NULL;
	ap->an_poff = 0;
	ahm = AH_MUTEX(ap->an_vp, ap->an_off);
	mutex_enter(ahm);
	anon_addhash(ap);
	mutex_exit(ahm);
	ANI_ADD(-1);
	ANON_PRINT(A_ANON, ("anon_alloc: returning ap %p, vp %p\n",
	    (void *)ap, (ap ? (void *)ap->an_vp : NULL)));
	return (ap);
}

/*
 * Called for pages locked in memory via softlock/pagelock/mlock to make sure
 * such pages don't consume any physical swap resources needed for swapping
 * unlocked pages.
 */
void
anon_swap_free(struct anon *ap, page_t *pp)
{
	kmutex_t *ahm;

	ASSERT(ap != NULL);
	ASSERT(pp != NULL);
	ASSERT(PAGE_LOCKED(pp));
	ASSERT(pp->p_vnode != NULL);
	ASSERT(IS_SWAPFSVP(pp->p_vnode));
	ASSERT(ap->an_refcnt != 0);
	ASSERT(pp->p_vnode == ap->an_vp);
	ASSERT(pp->p_offset == ap->an_off);

	if (ap->an_pvp == NULL)
		return;

	page_io_lock(pp);
	ahm = AH_MUTEX(ap->an_vp, ap->an_off);
	mutex_enter(ahm);

	ASSERT(ap->an_refcnt != 0);
	ASSERT(pp->p_vnode == ap->an_vp);
	ASSERT(pp->p_offset == ap->an_off);

	if (ap->an_pvp != NULL) {
		swap_phys_free(ap->an_pvp, ap->an_poff, PAGESIZE);
		ap->an_pvp = NULL;
		ap->an_poff = 0;
		mutex_exit(ahm);
		hat_setmod(pp);
	} else {
		mutex_exit(ahm);
	}
	page_io_unlock(pp);
}

/*
 * Decrement the reference count of an anon page.
 * If reference count goes to zero, free it and
 * its associated page (if any).
 */
void
anon_decref(struct anon *ap)
{
	page_t *pp;
	struct vnode *vp;
	anoff_t off;
	kmutex_t *ahm;

	ahm = AH_MUTEX(ap->an_vp, ap->an_off);
	mutex_enter(ahm);
	ASSERT(ap->an_refcnt != 0);
	if (ap->an_refcnt == 0)
		panic("anon_decref: slot count 0");
	if (--ap->an_refcnt == 0) {
		swap_xlate(ap, &vp, &off);
		anon_rmhash(ap);
		if (ap->an_pvp != NULL)
			swap_phys_free(ap->an_pvp, ap->an_poff, PAGESIZE);
		mutex_exit(ahm);

		/*
		 * If there is a page for this anon slot we will need to
		 * call VN_DISPOSE to get rid of the vp association and
		 * put the page back on the free list as really free.
		 * Acquire the "exclusive" lock to ensure that any
		 * pending i/o always completes before the swap slot
		 * is freed.
		 */
		pp = page_lookup(vp, (u_offset_t)off, SE_EXCL);
		if (pp != NULL) {
			/*LINTED: constant in conditional context */
			VN_DISPOSE(pp, B_INVAL, 0, kcred);
		}
		ANON_PRINT(A_ANON, ("anon_decref: free ap %p, vp %p\n",
		    (void *)ap, (void *)ap->an_vp));

		kmem_cache_free(anon_cache, ap);

		ANI_ADD(1);
	} else {
		mutex_exit(ahm);
	}
}


/*
 * check an_refcnt of the root anon slot (anon_index argument is aligned at
 * seg->s_szc level) to determine whether COW processing is required.
 * anonpages_hash_lock[] held on the root ap ensures that if root's
 * refcnt is 1 all other refcnt's are 1 as well (and they can't increase
 * later since this process can't fork while its AS lock is held).
 *
 * returns 1 if the root anon slot has a refcnt > 1 otherwise returns 0.
 */
int
anon_szcshare(struct anon_hdr *ahp, ulong_t anon_index)
{
	struct anon	*ap;
	kmutex_t	*ahmpages = NULL;

	ap = anon_get_ptr(ahp, anon_index);
	if (ap == NULL)
		return (0);

	ahmpages = APH_MUTEX(ap->an_vp, ap->an_off);
	mutex_enter(ahmpages);
	ASSERT(ap->an_refcnt >= 1);
	if (ap->an_refcnt == 1) {
		mutex_exit(ahmpages);
		return (0);
	}
	mutex_exit(ahmpages);
	return (1);
}
/*
 * Check 'nslots' anon slots for refcnt > 1.
 *
 * returns 1 if any of the 'nslots' anon slots has a refcnt > 1 otherwise
 * returns 0.
 */
static int
anon_share(struct anon_hdr *ahp, ulong_t anon_index, pgcnt_t nslots)
{
	struct anon *ap;

	while (nslots-- > 0) {
		if ((ap = anon_get_ptr(ahp, anon_index)) != NULL &&
		    ap->an_refcnt > 1)
			return (1);
		anon_index++;
	}

	return (0);
}

static void
anon_decref_pages(
	struct anon_hdr *ahp,
	ulong_t an_idx,
	uint_t szc)
{
	struct anon *ap = anon_get_ptr(ahp, an_idx);
	kmutex_t *ahmpages = NULL;
	page_t *pp;
	pgcnt_t pgcnt = page_get_pagecnt(szc);
	pgcnt_t i;
	struct vnode *vp;
	anoff_t   off;
	kmutex_t *ahm;
#ifdef DEBUG
	int refcnt = 1;
#endif

	ASSERT(szc != 0);
	ASSERT(IS_P2ALIGNED(pgcnt, pgcnt));
	ASSERT(IS_P2ALIGNED(an_idx, pgcnt));
	ASSERT(an_idx < ahp->size);

	if (ahp->size - an_idx < pgcnt) {
		/*
		 * In case of shared mappings total anon map size may not be
		 * the largest page size aligned.
		 */
		pgcnt = ahp->size - an_idx;
	}

	VM_STAT_ADD(anonvmstats.decrefpages[0]);

	if (ap != NULL) {
		ahmpages = APH_MUTEX(ap->an_vp, ap->an_off);
		mutex_enter(ahmpages);
		ASSERT((refcnt = ap->an_refcnt) != 0);
		VM_STAT_ADD(anonvmstats.decrefpages[1]);
		if (ap->an_refcnt == 1) {
			VM_STAT_ADD(anonvmstats.decrefpages[2]);
			ASSERT(!anon_share(ahp, an_idx, pgcnt));
			mutex_exit(ahmpages);
			ahmpages = NULL;
		}
	}

	i = 0;
	while (i < pgcnt) {
		if ((ap = anon_get_ptr(ahp, an_idx + i)) == NULL) {
			ASSERT(refcnt == 1 && ahmpages == NULL);
			i++;
			continue;
		}
		ASSERT(ap->an_refcnt == refcnt);
		ASSERT(ahmpages != NULL || ap->an_refcnt == 1);
		ASSERT(ahmpages == NULL || ap->an_refcnt > 1);

		if (ahmpages == NULL) {
			swap_xlate(ap, &vp, &off);
			pp = page_lookup(vp, (u_offset_t)off, SE_EXCL);
			if (pp == NULL || pp->p_szc == 0) {
				VM_STAT_ADD(anonvmstats.decrefpages[3]);
				ahm = AH_MUTEX(ap->an_vp, ap->an_off);
				(void) anon_set_ptr(ahp, an_idx + i, NULL,
				    ANON_SLEEP);
				mutex_enter(ahm);
				ap->an_refcnt--;
				ASSERT(ap->an_refcnt == 0);
				anon_rmhash(ap);
				if (ap->an_pvp)
					swap_phys_free(ap->an_pvp, ap->an_poff,
					    PAGESIZE);
				mutex_exit(ahm);
				if (pp == NULL) {
					pp = page_lookup(vp, (u_offset_t)off,
					    SE_EXCL);
					ASSERT(pp == NULL || pp->p_szc == 0);
				}
				if (pp != NULL) {
					VM_STAT_ADD(anonvmstats.decrefpages[4]);
					/*LINTED*/
					VN_DISPOSE(pp, B_INVAL, 0, kcred);
				}
				kmem_cache_free(anon_cache, ap);
				ANI_ADD(1);
				i++;
			} else {
				pgcnt_t j;
				pgcnt_t curpgcnt =
				    page_get_pagecnt(pp->p_szc);
				size_t ppasize = curpgcnt * sizeof (page_t *);
				page_t **ppa = kmem_alloc(ppasize, KM_SLEEP);
				int dispose = 0;

				VM_STAT_ADD(anonvmstats.decrefpages[5]);

				ASSERT(pp->p_szc <= szc);
				ASSERT(IS_P2ALIGNED(curpgcnt, curpgcnt));
				ASSERT(IS_P2ALIGNED(i, curpgcnt));
				ASSERT(i + curpgcnt <= pgcnt);
				ASSERT(!(page_pptonum(pp) & (curpgcnt - 1)));
				ppa[0] = pp;
				for (j = i + 1; j < i + curpgcnt; j++) {
					ap = anon_get_ptr(ahp, an_idx + j);
					ASSERT(ap != NULL &&
					    ap->an_refcnt == 1);
					swap_xlate(ap, &vp, &off);
					pp = page_lookup(vp, (u_offset_t)off,
					    SE_EXCL);
					if (pp == NULL)
						panic("anon_decref_pages: "
						    "no page");

					(void) hat_pageunload(pp,
					    HAT_FORCE_PGUNLOAD);
					ASSERT(pp->p_szc == ppa[0]->p_szc);
					ASSERT(page_pptonum(pp) - 1 ==
					    page_pptonum(ppa[j - i - 1]));
					ppa[j - i] = pp;
					if (ap->an_pvp != NULL &&
					    !vn_matchopval(ap->an_pvp,
					    VOPNAME_DISPOSE,
					    (fs_generic_func_p)fs_dispose))
						dispose = 1;
				}
				for (j = i; j < i + curpgcnt; j++) {
					ap = anon_get_ptr(ahp, an_idx + j);
					ASSERT(ap != NULL &&
					    ap->an_refcnt == 1);
					ahm = AH_MUTEX(ap->an_vp, ap->an_off);
					(void) anon_set_ptr(ahp, an_idx + j,
					    NULL, ANON_SLEEP);
					mutex_enter(ahm);
					ap->an_refcnt--;
					ASSERT(ap->an_refcnt == 0);
					anon_rmhash(ap);
					if (ap->an_pvp)
						swap_phys_free(ap->an_pvp,
						    ap->an_poff, PAGESIZE);
					mutex_exit(ahm);
					kmem_cache_free(anon_cache, ap);
					ANI_ADD(1);
				}
				if (!dispose) {
					VM_STAT_ADD(anonvmstats.decrefpages[6]);
					page_destroy_pages(ppa[0]);
				} else {
					VM_STAT_ADD(anonvmstats.decrefpages[7]);
					for (j = 0; j < curpgcnt; j++) {
						ASSERT(PAGE_EXCL(ppa[j]));
						ppa[j]->p_szc = 0;
					}
					for (j = 0; j < curpgcnt; j++) {
						ASSERT(!hat_page_is_mapped(
						    ppa[j]));
						/*LINTED*/
						VN_DISPOSE(ppa[j], B_INVAL, 0,
						    kcred);
					}
				}
				kmem_free(ppa, ppasize);
				i += curpgcnt;
			}
		} else {
			VM_STAT_ADD(anonvmstats.decrefpages[8]);
			(void) anon_set_ptr(ahp, an_idx + i, NULL, ANON_SLEEP);
			ahm = AH_MUTEX(ap->an_vp, ap->an_off);
			mutex_enter(ahm);
			ap->an_refcnt--;
			mutex_exit(ahm);
			i++;
		}
	}

	if (ahmpages != NULL) {
		mutex_exit(ahmpages);
	}
}

/*
 * Duplicate references to size bytes worth of anon pages.
 * Used when duplicating a segment that contains private anon pages.
 * This code assumes that procedure calling this one has already used
 * hat_chgprot() to disable write access to the range of addresses that
 * that *old actually refers to.
 */
void
anon_dup(struct anon_hdr *old, ulong_t old_idx, struct anon_hdr *new,
			ulong_t new_idx, size_t size)
{
	spgcnt_t npages;
	kmutex_t *ahm;
	struct anon *ap;
	ulong_t off;
	ulong_t index;

	npages = btopr(size);
	while (npages > 0) {
		index = old_idx;
		if ((ap = anon_get_next_ptr(old, &index)) == NULL)
			break;

		ASSERT(!ANON_ISBUSY(anon_get_slot(old, index)));
		off = index - old_idx;
		npages -= off;
		if (npages <= 0)
			break;

		(void) anon_set_ptr(new, new_idx + off, ap, ANON_SLEEP);
		ahm = AH_MUTEX(ap->an_vp, ap->an_off);

		mutex_enter(ahm);
		ap->an_refcnt++;
		mutex_exit(ahm);

		off++;
		new_idx += off;
		old_idx += off;
		npages--;
	}
}

/*
 * Just like anon_dup but also guarantees there are no holes (unallocated anon
 * slots) within any large page region. That means if a large page region is
 * empty in the old array it will skip it. If there are 1 or more valid slots
 * in the large page region of the old array it will make sure to fill in any
 * unallocated ones and also copy them to the new array. If noalloc is 1 large
 * page region should either have no valid anon slots or all slots should be
 * valid.
 */
void
anon_dup_fill_holes(
	struct anon_hdr *old,
	ulong_t old_idx,
	struct anon_hdr *new,
	ulong_t new_idx,
	size_t size,
	uint_t szc,
	int noalloc)
{
	struct anon	*ap;
	spgcnt_t	npages;
	kmutex_t	*ahm, *ahmpages = NULL;
	pgcnt_t		pgcnt, i;
	ulong_t		index, off;
#ifdef DEBUG
	int		refcnt;
#endif

	ASSERT(szc != 0);
	pgcnt = page_get_pagecnt(szc);
	ASSERT(IS_P2ALIGNED(pgcnt, pgcnt));
	npages = btopr(size);
	ASSERT(IS_P2ALIGNED(npages, pgcnt));
	ASSERT(IS_P2ALIGNED(old_idx, pgcnt));

	VM_STAT_ADD(anonvmstats.dupfillholes[0]);

	while (npages > 0) {
		index = old_idx;

		/*
		 * Find the next valid slot.
		 */
		if (anon_get_next_ptr(old, &index) == NULL)
			break;

		ASSERT(!ANON_ISBUSY(anon_get_slot(old, index)));
		/*
		 * Now backup index to the beginning of the
		 * current large page region of the old array.
		 */
		index = P2ALIGN(index, pgcnt);
		off = index - old_idx;
		ASSERT(IS_P2ALIGNED(off, pgcnt));
		npages -= off;
		if (npages <= 0)
			break;

		/*
		 * Fill and copy a large page regions worth
		 * of anon slots.
		 */
		for (i = 0; i < pgcnt; i++) {
			if ((ap = anon_get_ptr(old, index + i)) == NULL) {
				if (noalloc) {
					panic("anon_dup_fill_holes: "
					    "empty anon slot\n");
				}
				VM_STAT_ADD(anonvmstats.dupfillholes[1]);
				ap = anon_alloc(NULL, 0);
				(void) anon_set_ptr(old, index + i, ap,
				    ANON_SLEEP);
			} else if (i == 0) {
				/*
				 * make the increment of all refcnts of all
				 * anon slots of a large page appear atomic by
				 * getting an anonpages_hash_lock for the
				 * first anon slot of a large page.
				 */
				VM_STAT_ADD(anonvmstats.dupfillholes[2]);

				ahmpages = APH_MUTEX(ap->an_vp, ap->an_off);
				mutex_enter(ahmpages);
				/*LINTED*/
				ASSERT(refcnt = ap->an_refcnt);

				VM_STAT_COND_ADD(ap->an_refcnt > 1,
				    anonvmstats.dupfillholes[3]);
			}
			(void) anon_set_ptr(new, new_idx + off + i, ap,
			    ANON_SLEEP);
			ahm = AH_MUTEX(ap->an_vp, ap->an_off);
			mutex_enter(ahm);
			ASSERT(ahmpages != NULL || ap->an_refcnt == 1);
			ASSERT(i == 0 || ahmpages == NULL ||
			    refcnt == ap->an_refcnt);
			ap->an_refcnt++;
			mutex_exit(ahm);
		}
		if (ahmpages != NULL) {
			mutex_exit(ahmpages);
			ahmpages = NULL;
		}
		off += pgcnt;
		new_idx += off;
		old_idx += off;
		npages -= pgcnt;
	}
}

/*
 * Used when a segment with a vnode changes szc. similarly to
 * anon_dup_fill_holes() makes sure each large page region either has no anon
 * slots or all of them. but new slots are created by COWing the file
 * pages. on entrance no anon slots should be shared.
 */
int
anon_fill_cow_holes(
	struct seg *seg,
	caddr_t addr,
	struct anon_hdr *ahp,
	ulong_t an_idx,
	struct vnode *vp,
	u_offset_t vp_off,
	size_t size,
	uint_t szc,
	uint_t prot,
	struct vpage vpage[],
	struct cred *cred)
{
	struct anon	*ap;
	spgcnt_t	npages;
	pgcnt_t		pgcnt, i;
	ulong_t		index, off;
	int		err = 0;
	int		pageflags = 0;

	ASSERT(szc != 0);
	pgcnt = page_get_pagecnt(szc);
	ASSERT(IS_P2ALIGNED(pgcnt, pgcnt));
	npages = btopr(size);
	ASSERT(IS_P2ALIGNED(npages, pgcnt));
	ASSERT(IS_P2ALIGNED(an_idx, pgcnt));

	while (npages > 0) {
		index = an_idx;

		/*
		 * Find the next valid slot.
		 */
		if (anon_get_next_ptr(ahp, &index) == NULL) {
			break;
		}

		ASSERT(!ANON_ISBUSY(anon_get_slot(ahp, index)));
		/*
		 * Now backup index to the beginning of the
		 * current large page region of the anon array.
		 */
		index = P2ALIGN(index, pgcnt);
		off = index - an_idx;
		ASSERT(IS_P2ALIGNED(off, pgcnt));
		npages -= off;
		if (npages <= 0)
			break;
		an_idx += off;
		vp_off += ptob(off);
		addr += ptob(off);
		if (vpage != NULL) {
			vpage += off;
		}

		for (i = 0; i < pgcnt; i++, an_idx++, vp_off += PAGESIZE) {
			if ((ap = anon_get_ptr(ahp, an_idx)) == NULL) {
				page_t *pl[1 + 1];
				page_t *pp;

				err = VOP_GETPAGE(vp, vp_off, PAGESIZE, NULL,
				    pl, PAGESIZE, seg, addr, S_READ, cred,
				    NULL);
				if (err) {
					break;
				}
				if (vpage != NULL) {
					prot = VPP_PROT(vpage);
					pageflags = VPP_ISPPLOCK(vpage) ?
					    LOCK_PAGE : 0;
				}
				pp = anon_private(&ap, seg, addr, prot, pl[0],
				    pageflags, cred);
				if (pp == NULL) {
					err = ENOMEM;
					break;
				}
				(void) anon_set_ptr(ahp, an_idx, ap,
				    ANON_SLEEP);
				page_unlock(pp);
			}
			ASSERT(ap->an_refcnt == 1);
			addr += PAGESIZE;
			if (vpage != NULL) {
				vpage++;
			}
		}
		npages -= pgcnt;
	}

	return (err);
}

/*
 * Free a group of "size" anon pages, size in bytes,
 * and clear out the pointers to the anon entries.
 */
void
anon_free(struct anon_hdr *ahp, ulong_t index, size_t size)
{
	spgcnt_t npages;
	struct anon *ap;
	ulong_t old;

	npages = btopr(size);

	while (npages > 0) {
		old = index;
		if ((ap = anon_get_next_ptr(ahp, &index)) == NULL)
			break;

		ASSERT(!ANON_ISBUSY(anon_get_slot(ahp, index)));
		npages -= index - old;
		if (npages <= 0)
			break;

		(void) anon_set_ptr(ahp, index, NULL, ANON_SLEEP);
		anon_decref(ap);
		/*
		 * Bump index and decrement page count
		 */
		index++;
		npages--;
	}
}

void
anon_free_pages(
	struct anon_hdr *ahp,
	ulong_t an_idx,
	size_t size,
	uint_t szc)
{
	spgcnt_t	npages;
	pgcnt_t		pgcnt;
	ulong_t		index, off;

	ASSERT(szc != 0);
	pgcnt = page_get_pagecnt(szc);
	ASSERT(IS_P2ALIGNED(pgcnt, pgcnt));
	npages = btopr(size);
	ASSERT(IS_P2ALIGNED(npages, pgcnt));
	ASSERT(IS_P2ALIGNED(an_idx, pgcnt));
	ASSERT(an_idx < ahp->size);

	VM_STAT_ADD(anonvmstats.freepages[0]);

	while (npages > 0) {
		index = an_idx;

		/*
		 * Find the next valid slot.
		 */
		if (anon_get_next_ptr(ahp, &index) == NULL)
			break;

		ASSERT(!ANON_ISBUSY(anon_get_slot(ahp, index)));
		/*
		 * Now backup index to the beginning of the
		 * current large page region of the old array.
		 */
		index = P2ALIGN(index, pgcnt);
		off = index - an_idx;
		ASSERT(IS_P2ALIGNED(off, pgcnt));
		npages -= off;
		if (npages <= 0)
			break;

		anon_decref_pages(ahp, index, szc);

		off += pgcnt;
		an_idx += off;
		npages -= pgcnt;
	}
}

/*
 * Make anonymous pages discardable
 */
int
anon_disclaim(struct anon_map *amp, ulong_t index, size_t size,
    uint_t behav, pgcnt_t *purged)
{
	spgcnt_t npages = btopr(size);
	struct anon *ap;
	struct vnode *vp;
	anoff_t off;
	page_t *pp, *root_pp;
	kmutex_t *ahm;
	pgcnt_t pgcnt, npurged = 0;
	ulong_t old_idx, idx, i;
	struct anon_hdr *ahp = amp->ahp;
	anon_sync_obj_t cookie;
	int err = 0;

	VERIFY(behav == MADV_FREE || behav == MADV_PURGE);
	ASSERT(RW_READ_HELD(&amp->a_rwlock));
	pgcnt = 1;
	for (; npages > 0; index = (pgcnt == 1) ? index + 1 :
	    P2ROUNDUP(index + 1, pgcnt), npages -= pgcnt) {

		/*
		 * get anon pointer and index for the first valid entry
		 * in the anon list, starting from "index"
		 */
		old_idx = index;
		if ((ap = anon_get_next_ptr(ahp, &index)) == NULL)
			break;

		/*
		 * decrement npages by number of NULL anon slots we skipped
		 */
		npages -= index - old_idx;
		if (npages <= 0)
			break;

		anon_array_enter(amp, index, &cookie);
		ap = anon_get_ptr(ahp, index);
		ASSERT(ap != NULL);

		/*
		 * Get anonymous page and try to lock it SE_EXCL;
		 * if we couldn't grab the lock we skip to next page.
		 */
		swap_xlate(ap, &vp, &off);
		pp = page_lookup_nowait(vp, (u_offset_t)off, SE_EXCL);
		if (pp == NULL) {
			segadvstat.MADV_FREE_miss.value.ul++;
			pgcnt = 1;
			anon_array_exit(&cookie);
			continue;
		}
		pgcnt = page_get_pagecnt(pp->p_szc);

		/*
		 * we cannot free a page which is permanently locked.
		 * The page_struct_lock need not be acquired to examine
		 * these fields since the page has an "exclusive" lock.
		 */
		if (pp->p_lckcnt != 0 || pp->p_cowcnt != 0) {
			page_unlock(pp);
			segadvstat.MADV_FREE_miss.value.ul++;
			anon_array_exit(&cookie);
			err = EBUSY;
			continue;
		}

		ahm = AH_MUTEX(vp, off);
		mutex_enter(ahm);
		ASSERT(ap->an_refcnt != 0);
		/*
		 * skip this one if copy-on-write is not yet broken.
		 */
		if (ap->an_refcnt > 1) {
			mutex_exit(ahm);
			page_unlock(pp);
			segadvstat.MADV_FREE_miss.value.ul++;
			anon_array_exit(&cookie);
			continue;
		}

		if (behav == MADV_PURGE && pp->p_szc != 0) {
			/*
			 * If we're purging and we have a large page, simplify
			 * things a bit by demoting ourselves into the base
			 * page case.
			 */
			(void) page_try_demote_pages(pp);
		}

		if (pp->p_szc == 0) {
			pgcnt = 1;

			/*
			 * free swap slot;
			 */
			if (ap->an_pvp) {
				swap_phys_free(ap->an_pvp, ap->an_poff,
				    PAGESIZE);
				ap->an_pvp = NULL;
				ap->an_poff = 0;
			}

			if (behav == MADV_PURGE) {
				/*
				 * If we're purging (instead of merely freeing),
				 * rip out this anon structure entirely to
				 * assure that any subsequent fault pulls from
				 * the backing vnode (if any).
				 */
				if (--ap->an_refcnt == 0)
					anon_rmhash(ap);

				mutex_exit(ahm);
				(void) anon_set_ptr(ahp, index,
				    NULL, ANON_SLEEP);
				npurged++;
				ANI_ADD(1);
				kmem_cache_free(anon_cache, ap);
			} else {
				mutex_exit(ahm);
			}

			segadvstat.MADV_FREE_hit.value.ul++;

			/*
			 * while we are at it, unload all the translations
			 * and attempt to free the page.
			 */
			(void) hat_pageunload(pp, HAT_FORCE_PGUNLOAD);
			/*LINTED: constant in conditional context */
			VN_DISPOSE(pp,
			    behav == MADV_FREE ? B_FREE : B_INVAL, 0, kcred);

			anon_array_exit(&cookie);
			continue;
		}

		pgcnt = page_get_pagecnt(pp->p_szc);
		if (!IS_P2ALIGNED(index, pgcnt) || npages < pgcnt) {
			if (!page_try_demote_pages(pp)) {
				mutex_exit(ahm);
				page_unlock(pp);
				segadvstat.MADV_FREE_miss.value.ul++;
				anon_array_exit(&cookie);
				err = EBUSY;
				continue;
			} else {
				pgcnt = 1;
				if (ap->an_pvp) {
					swap_phys_free(ap->an_pvp,
					    ap->an_poff, PAGESIZE);
					ap->an_pvp = NULL;
					ap->an_poff = 0;
				}
				mutex_exit(ahm);
				(void) hat_pageunload(pp, HAT_FORCE_PGUNLOAD);
				/*LINTED*/
				VN_DISPOSE(pp, B_FREE, 0, kcred);
				segadvstat.MADV_FREE_hit.value.ul++;
				anon_array_exit(&cookie);
				continue;
			}
		}
		mutex_exit(ahm);
		root_pp = pp;

		/*
		 * try to lock remaining pages
		 */
		for (idx = 1; idx < pgcnt; idx++) {
			pp++;
			if (!page_trylock(pp, SE_EXCL))
				break;
			if (pp->p_lckcnt != 0 || pp->p_cowcnt != 0) {
				page_unlock(pp);
				break;
			}
		}

		if (idx == pgcnt) {
			for (i = 0; i < pgcnt; i++) {
				ap = anon_get_ptr(ahp, index + i);
				if (ap == NULL)
					break;
				swap_xlate(ap, &vp, &off);
				ahm = AH_MUTEX(vp, off);
				mutex_enter(ahm);
				ASSERT(ap->an_refcnt != 0);

				/*
				 * skip this one if copy-on-write
				 * is not yet broken.
				 */
				if (ap->an_refcnt > 1) {
					mutex_exit(ahm);
					goto skiplp;
				}
				if (ap->an_pvp) {
					swap_phys_free(ap->an_pvp,
					    ap->an_poff, PAGESIZE);
					ap->an_pvp = NULL;
					ap->an_poff = 0;
				}
				mutex_exit(ahm);
			}
			page_destroy_pages(root_pp);
			segadvstat.MADV_FREE_hit.value.ul += pgcnt;
			anon_array_exit(&cookie);
			continue;
		}
skiplp:
		segadvstat.MADV_FREE_miss.value.ul += pgcnt;
		for (i = 0, pp = root_pp; i < idx; pp++, i++)
			page_unlock(pp);
		anon_array_exit(&cookie);
	}

	if (purged != NULL)
		*purged = npurged;

	return (err);
}

/*
 * Return the kept page(s) and protections back to the segment driver.
 */
int
anon_getpage(
	struct anon **app,
	uint_t *protp,
	page_t *pl[],
	size_t plsz,
	struct seg *seg,
	caddr_t addr,
	enum seg_rw rw,
	struct cred *cred)
{
	page_t *pp;
	struct anon *ap = *app;
	struct vnode *vp;
	anoff_t off;
	int err;
	kmutex_t *ahm;

	swap_xlate(ap, &vp, &off);

	/*
	 * Lookup the page. If page is being paged in,
	 * wait for it to finish as we must return a list of
	 * pages since this routine acts like the VOP_GETPAGE
	 * routine does.
	 */
	if (pl != NULL && (pp = page_lookup(vp, (u_offset_t)off, SE_SHARED))) {
		ahm = AH_MUTEX(ap->an_vp, ap->an_off);
		mutex_enter(ahm);
		if (ap->an_refcnt == 1)
			*protp = PROT_ALL;
		else
			*protp = PROT_ALL & ~PROT_WRITE;
		mutex_exit(ahm);
		pl[0] = pp;
		pl[1] = NULL;
		return (0);
	}

	/*
	 * Simply treat it as a vnode fault on the anon vp.
	 */

	TRACE_3(TR_FAC_VM, TR_ANON_GETPAGE,
	    "anon_getpage:seg %x addr %x vp %x",
	    seg, addr, vp);

	err = VOP_GETPAGE(vp, (u_offset_t)off, PAGESIZE, protp, pl, plsz,
	    seg, addr, rw, cred, NULL);

	if (err == 0 && pl != NULL) {
		ahm = AH_MUTEX(ap->an_vp, ap->an_off);
		mutex_enter(ahm);
		if (ap->an_refcnt != 1)
			*protp &= ~PROT_WRITE;	/* make read-only */
		mutex_exit(ahm);
	}
	return (err);
}

/*
 * Creates or returns kept pages to the segment driver.  returns -1 if a large
 * page cannot be allocated. returns -2 if some other process has allocated a
 * larger page.
 *
 * For cowfault it will allocate any size pages to fill the requested area to
 * avoid partially overwriting anon slots (i.e. sharing only some of the anon
 * slots within a large page with other processes). This policy greatly
 * simplifies large page freeing (which is only freed when all anon slot
 * refcnts are 0).
 */
int
anon_map_getpages(
	struct anon_map *amp,
	ulong_t	start_idx,
	uint_t	szc,
	struct seg *seg,
	caddr_t	addr,
	uint_t prot,
	uint_t *protp,
	page_t	*ppa[],
	uint_t	*ppa_szc,
	struct vpage vpage[],
	enum seg_rw rw,
	int brkcow,
	int anypgsz,
	int pgflags,
	struct cred *cred)
{
	pgcnt_t		pgcnt;
	struct anon	*ap;
	struct vnode	*vp;
	anoff_t		off;
	page_t		*pp, *pl[2], *conpp = NULL;
	caddr_t		vaddr;
	ulong_t		pg_idx, an_idx, i;
	spgcnt_t	nreloc = 0;
	int		prealloc = 1;
	int		err, slotcreate;
	uint_t		vpprot;
	int		upsize = (szc < seg->s_szc);

#if !defined(__i386) && !defined(__amd64)
	ASSERT(seg->s_szc != 0);
#endif
	ASSERT(szc <= seg->s_szc);
	ASSERT(ppa_szc != NULL);
	ASSERT(rw != S_CREATE);

	*protp = PROT_ALL;

	VM_STAT_ADD(anonvmstats.getpages[0]);

	if (szc == 0) {
		VM_STAT_ADD(anonvmstats.getpages[1]);
		if ((ap = anon_get_ptr(amp->ahp, start_idx)) != NULL) {
			err = anon_getpage(&ap, protp, pl, PAGESIZE, seg,
			    addr, rw, cred);
			if (err)
				return (err);
			ppa[0] = pl[0];
			if (brkcow == 0 || (*protp & PROT_WRITE)) {
				VM_STAT_ADD(anonvmstats.getpages[2]);
				if (ppa[0]->p_szc != 0 && upsize) {
					VM_STAT_ADD(anonvmstats.getpages[3]);
					*ppa_szc = MIN(ppa[0]->p_szc,
					    seg->s_szc);
					page_unlock(ppa[0]);
					return (-2);
				}
				return (0);
			}
			panic("anon_map_getpages: cowfault for szc 0");
		} else {
			VM_STAT_ADD(anonvmstats.getpages[4]);
			ppa[0] = anon_zero(seg, addr, &ap, cred);
			if (ppa[0] == NULL)
				return (ENOMEM);
			(void) anon_set_ptr(amp->ahp, start_idx, ap,
			    ANON_SLEEP);
			return (0);
		}
	}

	pgcnt = page_get_pagecnt(szc);
	ASSERT(IS_P2ALIGNED(pgcnt, pgcnt));
	ASSERT(IS_P2ALIGNED(start_idx, pgcnt));

	/*
	 * First we check for the case that the requtested large
	 * page or larger page already exists in the system.
	 * Actually we only check if the first constituent page
	 * exists and only preallocate if it's not found.
	 */
	ap = anon_get_ptr(amp->ahp, start_idx);
	if (ap) {
		uint_t pszc;
		swap_xlate(ap, &vp, &off);
		if (page_exists_forreal(vp, (u_offset_t)off, &pszc)) {
			if (pszc > szc && upsize) {
				*ppa_szc = MIN(pszc, seg->s_szc);
				return (-2);
			}
			if (pszc >= szc) {
				prealloc = 0;
			}
		}
	}

	VM_STAT_COND_ADD(prealloc == 0, anonvmstats.getpages[5]);
	VM_STAT_COND_ADD(prealloc != 0, anonvmstats.getpages[6]);

top:
	/*
	 * If a smaller page or no page at all was found,
	 * grab a large page off the freelist.
	 */
	if (prealloc) {
		ASSERT(conpp == NULL);
		if (page_alloc_pages(anon_vp, seg, addr, NULL, ppa,
		    szc, 0, pgflags) != 0) {
			VM_STAT_ADD(anonvmstats.getpages[7]);
			if (brkcow == 0 || szc < seg->s_szc ||
			    !anon_szcshare(amp->ahp, start_idx)) {
				/*
				 * If the refcnt's of all anon slots are <= 1
				 * they can't increase since we are holding
				 * the address space's lock. So segvn can
				 * safely decrease szc without risking to
				 * generate a cow fault for the region smaller
				 * than the segment's largest page size.
				 */
				VM_STAT_ADD(anonvmstats.getpages[8]);
				return (-1);
			}
		docow:
			/*
			 * This is a cow fault. Copy away the entire 1 large
			 * page region of this segment.
			 */
			if (szc != seg->s_szc)
				panic("anon_map_getpages: cowfault for szc %d",
				    szc);
			vaddr = addr;
			for (pg_idx = 0, an_idx = start_idx; pg_idx < pgcnt;
			    pg_idx++, an_idx++, vaddr += PAGESIZE) {
				if ((ap = anon_get_ptr(amp->ahp, an_idx)) !=
				    NULL) {
					err = anon_getpage(&ap, &vpprot, pl,
					    PAGESIZE, seg, vaddr, rw, cred);
					if (err) {
						for (i = 0; i < pg_idx; i++) {
							if ((pp = ppa[i]) !=
							    NULL)
								page_unlock(pp);
						}
						return (err);
					}
					ppa[pg_idx] = pl[0];
				} else {
					/*
					 * Since this is a cowfault we know
					 * that this address space has a
					 * parent or children which means
					 * anon_dup_fill_holes() has initialized
					 * all anon slots within a large page
					 * region that had at least one anon
					 * slot at the time of fork().
					 */
					panic("anon_map_getpages: "
					    "cowfault but anon slot is empty");
				}
			}
			VM_STAT_ADD(anonvmstats.getpages[9]);
			*protp = PROT_ALL;
			return (anon_map_privatepages(amp, start_idx, szc, seg,
			    addr, prot, ppa, vpage, anypgsz, pgflags, cred));
		}
	}

	VM_STAT_ADD(anonvmstats.getpages[10]);

	an_idx = start_idx;
	pg_idx = 0;
	vaddr = addr;
	while (pg_idx < pgcnt) {
		slotcreate = 0;
		if ((ap = anon_get_ptr(amp->ahp, an_idx)) == NULL) {
			VM_STAT_ADD(anonvmstats.getpages[11]);
			/*
			 * For us to have decided not to preallocate
			 * would have meant that a large page
			 * was found. Which also means that all of the
			 * anon slots for that page would have been
			 * already created for us.
			 */
			if (prealloc == 0)
				panic("anon_map_getpages: prealloc = 0");

			slotcreate = 1;
			ap = anon_alloc(NULL, 0);
		}
		swap_xlate(ap, &vp, &off);

		/*
		 * Now setup our preallocated page to pass down
		 * to swap_getpage().
		 */
		if (prealloc) {
			ASSERT(ppa[pg_idx]->p_szc == szc);
			conpp = ppa[pg_idx];
		}
		ASSERT(prealloc || conpp == NULL);

		/*
		 * If we just created this anon slot then call
		 * with S_CREATE to prevent doing IO on the page.
		 * Similar to the anon_zero case.
		 */
		err = swap_getconpage(vp, (u_offset_t)off, PAGESIZE,
		    NULL, pl, PAGESIZE, conpp, ppa_szc, &nreloc, seg, vaddr,
		    slotcreate == 1 ? S_CREATE : rw, cred);

		if (err) {
			ASSERT(err != -2 || upsize);
			VM_STAT_ADD(anonvmstats.getpages[12]);
			ASSERT(slotcreate == 0);
			goto io_err;
		}

		pp = pl[0];

		if (pp->p_szc < szc || (pp->p_szc > szc && upsize)) {
			VM_STAT_ADD(anonvmstats.getpages[13]);
			ASSERT(slotcreate == 0);
			ASSERT(prealloc == 0);
			ASSERT(pg_idx == 0);
			if (pp->p_szc > szc) {
				ASSERT(upsize);
				*ppa_szc = MIN(pp->p_szc, seg->s_szc);
				page_unlock(pp);
				VM_STAT_ADD(anonvmstats.getpages[14]);
				return (-2);
			}
			page_unlock(pp);
			prealloc = 1;
			goto top;
		}

		/*
		 * If we decided to preallocate but VOP_GETPAGE
		 * found a page in the system that satisfies our
		 * request then free up our preallocated large page
		 * and continue looping accross the existing large
		 * page via VOP_GETPAGE.
		 */
		if (prealloc && pp != ppa[pg_idx]) {
			VM_STAT_ADD(anonvmstats.getpages[15]);
			ASSERT(slotcreate == 0);
			ASSERT(pg_idx == 0);
			conpp = NULL;
			prealloc = 0;
			page_free_pages(ppa[0]);
		}

		if (prealloc && nreloc > 1) {
			/*
			 * we have relocated out of a smaller large page.
			 * skip npgs - 1 iterations and continue which will
			 * increment by one the loop indices.
			 */
			spgcnt_t npgs = nreloc;

			VM_STAT_ADD(anonvmstats.getpages[16]);

			ASSERT(pp == ppa[pg_idx]);
			ASSERT(slotcreate == 0);
			ASSERT(pg_idx + npgs <= pgcnt);
			if ((*protp & PROT_WRITE) &&
			    anon_share(amp->ahp, an_idx, npgs)) {
				*protp &= ~PROT_WRITE;
			}
			pg_idx += npgs;
			an_idx += npgs;
			vaddr += PAGESIZE * npgs;
			continue;
		}

		VM_STAT_ADD(anonvmstats.getpages[17]);

		/*
		 * Anon_zero case.
		 */
		if (slotcreate) {
			ASSERT(prealloc);
			pagezero(pp, 0, PAGESIZE);
			CPU_STATS_ADD_K(vm, zfod, 1);
			hat_setrefmod(pp);
		}

		ASSERT(prealloc == 0 || ppa[pg_idx] == pp);
		ASSERT(prealloc != 0 || PAGE_SHARED(pp));
		ASSERT(prealloc == 0 || PAGE_EXCL(pp));

		if (pg_idx > 0 &&
		    ((page_pptonum(pp) != page_pptonum(ppa[pg_idx - 1]) + 1) ||
		    (pp->p_szc != ppa[pg_idx - 1]->p_szc))) {
			panic("anon_map_getpages: unexpected page");
		} else if (pg_idx == 0 && (page_pptonum(pp) & (pgcnt - 1))) {
			panic("anon_map_getpages: unaligned page");
		}

		if (prealloc == 0) {
			ppa[pg_idx] = pp;
		}

		if (ap->an_refcnt > 1) {
			VM_STAT_ADD(anonvmstats.getpages[18]);
			*protp &= ~PROT_WRITE;
		}

		/*
		 * If this is a new anon slot then initialize
		 * the anon array entry.
		 */
		if (slotcreate) {
			(void) anon_set_ptr(amp->ahp, an_idx, ap, ANON_SLEEP);
		}
		pg_idx++;
		an_idx++;
		vaddr += PAGESIZE;
	}

	/*
	 * Since preallocated pages come off the freelist
	 * they are locked SE_EXCL. Simply downgrade and return.
	 */
	if (prealloc) {
		VM_STAT_ADD(anonvmstats.getpages[19]);
		conpp = NULL;
		for (pg_idx = 0; pg_idx < pgcnt; pg_idx++) {
			page_downgrade(ppa[pg_idx]);
		}
	}
	ASSERT(conpp == NULL);

	if (brkcow == 0 || (*protp & PROT_WRITE)) {
		VM_STAT_ADD(anonvmstats.getpages[20]);
		return (0);
	}

	if (szc < seg->s_szc)
		panic("anon_map_getpages: cowfault for szc %d", szc);

	VM_STAT_ADD(anonvmstats.getpages[21]);

	*protp = PROT_ALL;
	return (anon_map_privatepages(amp, start_idx, szc, seg, addr, prot,
	    ppa, vpage, anypgsz, pgflags, cred));
io_err:
	/*
	 * We got an IO error somewhere in our large page.
	 * If we were using a preallocated page then just demote
	 * all the constituent pages that we've succeeded with sofar
	 * to PAGESIZE pages and leave them in the system
	 * unlocked.
	 */

	ASSERT(err != -2 || ((pg_idx == 0) && upsize));

	VM_STAT_COND_ADD(err > 0, anonvmstats.getpages[22]);
	VM_STAT_COND_ADD(err == -1, anonvmstats.getpages[23]);
	VM_STAT_COND_ADD(err == -2, anonvmstats.getpages[24]);

	if (prealloc) {
		conpp = NULL;
		if (pg_idx > 0) {
			VM_STAT_ADD(anonvmstats.getpages[25]);
			for (i = 0; i < pgcnt; i++) {
				pp = ppa[i];
				ASSERT(PAGE_EXCL(pp));
				ASSERT(pp->p_szc == szc);
				pp->p_szc = 0;
			}
			for (i = 0; i < pg_idx; i++) {
				ASSERT(!hat_page_is_mapped(ppa[i]));
				page_unlock(ppa[i]);
			}
			/*
			 * Now free up the remaining unused constituent
			 * pages.
			 */
			while (pg_idx < pgcnt) {
				ASSERT(!hat_page_is_mapped(ppa[pg_idx]));
				page_free(ppa[pg_idx], 0);
				pg_idx++;
			}
		} else {
			VM_STAT_ADD(anonvmstats.getpages[26]);
			page_free_pages(ppa[0]);
		}
	} else {
		VM_STAT_ADD(anonvmstats.getpages[27]);
		ASSERT(err > 0);
		for (i = 0; i < pg_idx; i++)
			page_unlock(ppa[i]);
	}
	ASSERT(conpp == NULL);
	if (err != -1)
		return (err);
	/*
	 * we are here because we failed to relocate.
	 */
	ASSERT(prealloc);
	if (brkcow == 0 || szc < seg->s_szc ||
	    !anon_szcshare(amp->ahp, start_idx)) {
		VM_STAT_ADD(anonvmstats.getpages[28]);
		return (-1);
	}
	VM_STAT_ADD(anonvmstats.getpages[29]);
	goto docow;
}


/*
 * Turn a reference to an object or shared anon page
 * into a private page with a copy of the data from the
 * original page which is always locked by the caller.
 * This routine unloads the translation and unlocks the
 * original page, if it isn't being stolen, before returning
 * to the caller.
 *
 * NOTE:  The original anon slot is not freed by this routine
 *	  It must be freed by the caller while holding the
 *	  "anon_map" lock to prevent races which can occur if
 *	  a process has multiple lwps in its address space.
 */
page_t *
anon_private(
	struct anon **app,
	struct seg *seg,
	caddr_t addr,
	uint_t	prot,
	page_t *opp,
	int oppflags,
	struct cred *cred)
{
	struct anon *old = *app;
	struct anon *new;
	page_t *pp = NULL;
	struct vnode *vp;
	anoff_t off;
	page_t *anon_pl[1 + 1];
	int err;

	if (oppflags & STEAL_PAGE)
		ASSERT(PAGE_EXCL(opp));
	else
		ASSERT(PAGE_LOCKED(opp));

	CPU_STATS_ADD_K(vm, cow_fault, 1);

	/* Kernel probe */
	TNF_PROBE_1(anon_private, "vm pagefault", /* CSTYLED */,
		tnf_opaque,	address,	addr);

	*app = new = anon_alloc(NULL, 0);
	swap_xlate(new, &vp, &off);

	if (oppflags & STEAL_PAGE) {
		page_rename(opp, vp, (u_offset_t)off);
		pp = opp;
		TRACE_5(TR_FAC_VM, TR_ANON_PRIVATE,
		    "anon_private:seg %p addr %x pp %p vp %p off %lx",
		    seg, addr, pp, vp, off);
		hat_setmod(pp);

		/* bug 4026339 */
		page_downgrade(pp);
		return (pp);
	}

	/*
	 * Call the VOP_GETPAGE routine to create the page, thereby
	 * enabling the vnode driver to allocate any filesystem
	 * space (e.g., disk block allocation for UFS).  This also
	 * prevents more than one page from being added to the
	 * vnode at the same time.
	 */
	err = VOP_GETPAGE(vp, (u_offset_t)off, PAGESIZE, NULL,
	    anon_pl, PAGESIZE, seg, addr, S_CREATE, cred, NULL);
	if (err)
		goto out;

	pp = anon_pl[0];

	/*
	 * If the original page was locked, we need to move the lock
	 * to the new page by transfering 'cowcnt/lckcnt' of the original
	 * page to 'cowcnt/lckcnt' of the new page.
	 *
	 * See Statement at the beginning of segvn_lockop() and
	 * comments in page_pp_useclaim() regarding the way
	 * cowcnts/lckcnts are handled.
	 *
	 * Also availrmem must be decremented up front for read only mapping
	 * before calling page_pp_useclaim. page_pp_useclaim will bump it back
	 * if availrmem did not need to be decremented after all.
	 */
	if (oppflags & LOCK_PAGE) {
		if ((prot & PROT_WRITE) == 0) {
			mutex_enter(&freemem_lock);
			if (availrmem > pages_pp_maximum) {
				availrmem--;
				pages_useclaim++;
			} else {
				mutex_exit(&freemem_lock);
				goto out;
			}
			mutex_exit(&freemem_lock);
		}
		page_pp_useclaim(opp, pp, prot & PROT_WRITE);
	}

	/*
	 * Now copy the contents from the original page,
	 * which is locked and loaded in the MMU by
	 * the caller to prevent yet another page fault.
	 */
	/* XXX - should set mod bit in here */
	if (ppcopy(opp, pp) == 0) {
		/*
		 * Before ppcopy could hanlde UE or other faults, we
		 * would have panicked here, and still have no option
		 * but to do so now.
		 */
		panic("anon_private, ppcopy failed, opp = 0x%p, pp = 0x%p",
		    (void *)opp, (void *)pp);
	}

	hat_setrefmod(pp);		/* mark as modified */

	/*
	 * Unload the old translation.
	 */
	hat_unload(seg->s_as->a_hat, addr, PAGESIZE, HAT_UNLOAD);

	/*
	 * Free unmapped, unmodified original page.
	 * or release the lock on the original page,
	 * otherwise the process will sleep forever in
	 * anon_decref() waiting for the "exclusive" lock
	 * on the page.
	 */
	(void) page_release(opp, 1);

	/*
	 * we are done with page creation so downgrade the new
	 * page's selock to shared, this helps when multiple
	 * as_fault(...SOFTLOCK...) are done to the same
	 * page(aio)
	 */
	page_downgrade(pp);

	/*
	 * NOTE:  The original anon slot must be freed by the
	 * caller while holding the "anon_map" lock, if we
	 * copied away from an anonymous page.
	 */
	return (pp);

out:
	*app = old;
	if (pp)
		page_unlock(pp);
	anon_decref(new);
	page_unlock(opp);
	return ((page_t *)NULL);
}

int
anon_map_privatepages(
	struct anon_map *amp,
	ulong_t	start_idx,
	uint_t	szc,
	struct seg *seg,
	caddr_t addr,
	uint_t	prot,
	page_t	*ppa[],
	struct vpage vpage[],
	int anypgsz,
	int pgflags,
	struct cred *cred)
{
	pgcnt_t		pgcnt;
	struct vnode	*vp;
	anoff_t		off;
	page_t		*pl[2], *conpp = NULL;
	int		err;
	int		prealloc = 1;
	struct anon	*ap, *oldap;
	caddr_t		vaddr;
	page_t		*pplist, *pp;
	ulong_t		pg_idx, an_idx;
	spgcnt_t	nreloc = 0;
	int		pagelock = 0;
	kmutex_t	*ahmpages = NULL;
#ifdef DEBUG
	int		refcnt;
#endif

	ASSERT(szc != 0);
	ASSERT(szc == seg->s_szc);

	VM_STAT_ADD(anonvmstats.privatepages[0]);

	pgcnt = page_get_pagecnt(szc);
	ASSERT(IS_P2ALIGNED(pgcnt, pgcnt));
	ASSERT(IS_P2ALIGNED(start_idx, pgcnt));

	ASSERT(amp != NULL);
	ap = anon_get_ptr(amp->ahp, start_idx);
	ASSERT(ap == NULL || ap->an_refcnt >= 1);

	VM_STAT_COND_ADD(ap == NULL, anonvmstats.privatepages[1]);

	/*
	 * Now try and allocate the large page. If we fail then just
	 * let VOP_GETPAGE give us PAGESIZE pages. Normally we let
	 * the caller make this decision but to avoid added complexity
	 * it's simplier to handle that case here.
	 */
	if (anypgsz == -1) {
		VM_STAT_ADD(anonvmstats.privatepages[2]);
		prealloc = 0;
	} else if (page_alloc_pages(anon_vp, seg, addr, &pplist, NULL, szc,
	    anypgsz, pgflags) != 0) {
		VM_STAT_ADD(anonvmstats.privatepages[3]);
		prealloc = 0;
	}

	/*
	 * make the decrement of all refcnts of all
	 * anon slots of a large page appear atomic by
	 * getting an anonpages_hash_lock for the
	 * first anon slot of a large page.
	 */
	if (ap != NULL) {
		ahmpages = APH_MUTEX(ap->an_vp, ap->an_off);
		mutex_enter(ahmpages);
		if (ap->an_refcnt == 1) {
			VM_STAT_ADD(anonvmstats.privatepages[4]);
			ASSERT(!anon_share(amp->ahp, start_idx, pgcnt));
			mutex_exit(ahmpages);

			if (prealloc) {
				page_free_replacement_page(pplist);
				page_create_putback(pgcnt);
			}
			ASSERT(ppa[0]->p_szc <= szc);
			if (ppa[0]->p_szc == szc) {
				VM_STAT_ADD(anonvmstats.privatepages[5]);
				return (0);
			}
			for (pg_idx = 0; pg_idx < pgcnt; pg_idx++) {
				ASSERT(ppa[pg_idx] != NULL);
				page_unlock(ppa[pg_idx]);
			}
			return (-1);
		}
	}

	/*
	 * If we are passed in the vpage array and this is
	 * not PROT_WRITE then we need to decrement availrmem
	 * up front before we try anything. If we need to and
	 * can't decrement availrmem then its better to fail now
	 * than in the middle of processing the new large page.
	 * page_pp_usclaim() on behalf of each constituent page
	 * below will adjust availrmem back for the cases not needed.
	 */
	if (vpage != NULL && (prot & PROT_WRITE) == 0) {
		for (pg_idx = 0; pg_idx < pgcnt; pg_idx++) {
			if (VPP_ISPPLOCK(&vpage[pg_idx])) {
				pagelock = 1;
				break;
			}
		}
		if (pagelock) {
			VM_STAT_ADD(anonvmstats.privatepages[6]);
			mutex_enter(&freemem_lock);
			if (availrmem >= pages_pp_maximum + pgcnt) {
				availrmem -= pgcnt;
				pages_useclaim += pgcnt;
			} else {
				VM_STAT_ADD(anonvmstats.privatepages[7]);
				mutex_exit(&freemem_lock);
				if (ahmpages != NULL) {
					mutex_exit(ahmpages);
				}
				if (prealloc) {
					page_free_replacement_page(pplist);
					page_create_putback(pgcnt);
				}
				for (pg_idx = 0; pg_idx < pgcnt; pg_idx++)
					if (ppa[pg_idx] != NULL)
						page_unlock(ppa[pg_idx]);
				return (ENOMEM);
			}
			mutex_exit(&freemem_lock);
		}
	}

	CPU_STATS_ADD_K(vm, cow_fault, pgcnt);

	VM_STAT_ADD(anonvmstats.privatepages[8]);

	an_idx = start_idx;
	pg_idx = 0;
	vaddr = addr;
	for (; pg_idx < pgcnt; pg_idx++, an_idx++, vaddr += PAGESIZE) {
		ASSERT(ppa[pg_idx] != NULL);
		oldap = anon_get_ptr(amp->ahp, an_idx);
		ASSERT(ahmpages != NULL || oldap == NULL);
		ASSERT(ahmpages == NULL || oldap != NULL);
		ASSERT(ahmpages == NULL || oldap->an_refcnt > 1);
		ASSERT(ahmpages == NULL || pg_idx != 0 ||
		    (refcnt = oldap->an_refcnt));
		ASSERT(ahmpages == NULL || pg_idx == 0 ||
		    refcnt == oldap->an_refcnt);

		ap = anon_alloc(NULL, 0);

		swap_xlate(ap, &vp, &off);

		/*
		 * Now setup our preallocated page to pass down to
		 * swap_getpage().
		 */
		if (prealloc) {
			pp = pplist;
			page_sub(&pplist, pp);
			conpp = pp;
		}

		err = swap_getconpage(vp, (u_offset_t)off, PAGESIZE, NULL, pl,
		    PAGESIZE, conpp, NULL, &nreloc, seg, vaddr,
		    S_CREATE, cred);

		/*
		 * Impossible to fail this is S_CREATE.
		 */
		if (err)
			panic("anon_map_privatepages: VOP_GETPAGE failed");

		ASSERT(prealloc ? pp == pl[0] : pl[0]->p_szc == 0);
		ASSERT(prealloc == 0 || nreloc == 1);

		pp = pl[0];

		/*
		 * If the original page was locked, we need to move
		 * the lock to the new page by transfering
		 * 'cowcnt/lckcnt' of the original page to 'cowcnt/lckcnt'
		 * of the new page. pg_idx can be used to index
		 * into the vpage array since the caller will guarentee
		 * that vpage struct passed in corresponds to addr
		 * and forward.
		 */
		if (vpage != NULL && VPP_ISPPLOCK(&vpage[pg_idx])) {
			page_pp_useclaim(ppa[pg_idx], pp, prot & PROT_WRITE);
		} else if (pagelock) {
			mutex_enter(&freemem_lock);
			availrmem++;
			pages_useclaim--;
			mutex_exit(&freemem_lock);
		}

		/*
		 * Now copy the contents from the original page.
		 */
		if (ppcopy(ppa[pg_idx], pp) == 0) {
			/*
			 * Before ppcopy could hanlde UE or other faults, we
			 * would have panicked here, and still have no option
			 * but to do so now.
			 */
			panic("anon_map_privatepages, ppcopy failed");
		}

		hat_setrefmod(pp);		/* mark as modified */

		/*
		 * Release the lock on the original page,
		 * derement the old slot, and down grade the lock
		 * on the new copy.
		 */
		page_unlock(ppa[pg_idx]);

		if (!prealloc)
			page_downgrade(pp);

		ppa[pg_idx] = pp;

		/*
		 * Now reflect the copy in the new anon array.
		 */
		ASSERT(ahmpages == NULL || oldap->an_refcnt > 1);
		if (oldap != NULL)
			anon_decref(oldap);
		(void) anon_set_ptr(amp->ahp, an_idx, ap, ANON_SLEEP);
	}

	/*
	 * Unload the old large page translation.
	 */
	hat_unload(seg->s_as->a_hat, addr, pgcnt << PAGESHIFT, HAT_UNLOAD);

	if (ahmpages != NULL) {
		mutex_exit(ahmpages);
	}
	ASSERT(prealloc == 0 || pplist == NULL);
	if (prealloc) {
		VM_STAT_ADD(anonvmstats.privatepages[9]);
		for (pg_idx = 0; pg_idx < pgcnt; pg_idx++) {
			page_downgrade(ppa[pg_idx]);
		}
	}

	return (0);
}

/*
 * Allocate a private zero-filled anon page.
 */
page_t *
anon_zero(struct seg *seg, caddr_t addr, struct anon **app, struct cred *cred)
{
	struct anon *ap;
	page_t *pp;
	struct vnode *vp;
	anoff_t off;
	page_t *anon_pl[1 + 1];
	int err;

	/* Kernel probe */
	TNF_PROBE_1(anon_zero, "vm pagefault", /* CSTYLED */,
		tnf_opaque,	address,	addr);

	*app = ap = anon_alloc(NULL, 0);
	swap_xlate(ap, &vp, &off);

	/*
	 * Call the VOP_GETPAGE routine to create the page, thereby
	 * enabling the vnode driver to allocate any filesystem
	 * dependent structures (e.g., disk block allocation for UFS).
	 * This also prevents more than on page from being added to
	 * the vnode at the same time since it is locked.
	 */
	err = VOP_GETPAGE(vp, off, PAGESIZE, NULL,
	    anon_pl, PAGESIZE, seg, addr, S_CREATE, cred, NULL);
	if (err) {
		*app = NULL;
		anon_decref(ap);
		return (NULL);
	}
	pp = anon_pl[0];

	pagezero(pp, 0, PAGESIZE);	/* XXX - should set mod bit */
	page_downgrade(pp);
	CPU_STATS_ADD_K(vm, zfod, 1);
	hat_setrefmod(pp);	/* mark as modified so pageout writes back */
	return (pp);
}


/*
 * Allocate array of private zero-filled anon pages for empty slots
 * and kept pages for non empty slots within given range.
 *
 * NOTE: This rontine will try and use large pages
 *	if available and supported by underlying platform.
 */
int
anon_map_createpages(
	struct anon_map *amp,
	ulong_t start_index,
	size_t len,
	page_t *ppa[],
	struct seg *seg,
	caddr_t addr,
	enum seg_rw rw,
	struct cred *cred)
{

	struct anon	*ap;
	struct vnode	*ap_vp;
	page_t		*pp, *pplist, *anon_pl[1 + 1], *conpp = NULL;
	int		err = 0;
	ulong_t		p_index, index;
	pgcnt_t		npgs, pg_cnt;
	spgcnt_t	nreloc = 0;
	uint_t		l_szc, szc, prot;
	anoff_t		ap_off;
	size_t		pgsz;
	lgrp_t		*lgrp;
	kmutex_t	*ahm;

	/*
	 * XXX For now only handle S_CREATE.
	 */
	ASSERT(rw == S_CREATE);

	index	= start_index;
	p_index	= 0;
	npgs = btopr(len);

	/*
	 * If this platform supports multiple page sizes
	 * then try and allocate directly from the free
	 * list for pages larger than PAGESIZE.
	 *
	 * NOTE:When we have page_create_ru we can stop
	 *	directly allocating from the freelist.
	 */
	l_szc  = seg->s_szc;
	ANON_LOCK_ENTER(&amp->a_rwlock, RW_WRITER);
	while (npgs) {

		/*
		 * if anon slot already exists
		 *   (means page has been created)
		 * so 1) look up the page
		 *    2) if the page is still in memory, get it.
		 *    3) if not, create a page and
		 *	  page in from physical swap device.
		 * These are done in anon_getpage().
		 */
		ap = anon_get_ptr(amp->ahp, index);
		if (ap) {
			err = anon_getpage(&ap, &prot, anon_pl, PAGESIZE,
			    seg, addr, S_READ, cred);
			if (err) {
				ANON_LOCK_EXIT(&amp->a_rwlock);
				panic("anon_map_createpages: anon_getpage");
			}
			pp = anon_pl[0];
			ppa[p_index++] = pp;

			/*
			 * an_pvp can become non-NULL after SysV's page was
			 * paged out before ISM was attached to this SysV
			 * shared memory segment. So free swap slot if needed.
			 */
			if (ap->an_pvp != NULL) {
				page_io_lock(pp);
				ahm = AH_MUTEX(ap->an_vp, ap->an_off);
				mutex_enter(ahm);
				if (ap->an_pvp != NULL) {
					swap_phys_free(ap->an_pvp,
					    ap->an_poff, PAGESIZE);
					ap->an_pvp = NULL;
					ap->an_poff = 0;
					mutex_exit(ahm);
					hat_setmod(pp);
				} else {
					mutex_exit(ahm);
				}
				page_io_unlock(pp);
			}

			addr += PAGESIZE;
			index++;
			npgs--;
			continue;
		}
		/*
		 * Now try and allocate the largest page possible
		 * for the current address and range.
		 * Keep dropping down in page size until:
		 *
		 *	1) Properly aligned
		 *	2) Does not overlap existing anon pages
		 *	3) Fits in remaining range.
		 *	4) able to allocate one.
		 *
		 * NOTE: XXX When page_create_ru is completed this code
		 *	 will change.
		 */
		szc    = l_szc;
		pplist = NULL;
		pg_cnt = 0;
		while (szc) {
			pgsz	= page_get_pagesize(szc);
			pg_cnt	= pgsz >> PAGESHIFT;
			if (IS_P2ALIGNED(addr, pgsz) && pg_cnt <= npgs &&
			    anon_pages(amp->ahp, index, pg_cnt) == 0) {
				/*
				 * XXX
				 * Since we are faking page_create()
				 * we also need to do the freemem and
				 * pcf accounting.
				 */
				(void) page_create_wait(pg_cnt, PG_WAIT);

				/*
				 * Get lgroup to allocate next page of shared
				 * memory from and use it to specify where to
				 * allocate the physical memory
				 */
				lgrp = lgrp_mem_choose(seg, addr, pgsz);

				pplist = page_get_freelist(
				    anon_vp, (u_offset_t)0, seg,
				    addr, pgsz, 0, lgrp);

				if (pplist == NULL) {
					page_create_putback(pg_cnt);
				}

				/*
				 * If a request for a page of size
				 * larger than PAGESIZE failed
				 * then don't try that size anymore.
				 */
				if (pplist == NULL) {
					l_szc = szc - 1;
				} else {
					break;
				}
			}
			szc--;
		}

		/*
		 * If just using PAGESIZE pages then don't
		 * directly allocate from the free list.
		 */
		if (pplist == NULL) {
			ASSERT(szc == 0);
			pp = anon_zero(seg, addr, &ap, cred);
			if (pp == NULL) {
				ANON_LOCK_EXIT(&amp->a_rwlock);
				panic("anon_map_createpages: anon_zero");
			}
			ppa[p_index++] = pp;

			ASSERT(anon_get_ptr(amp->ahp, index) == NULL);
			(void) anon_set_ptr(amp->ahp, index, ap, ANON_SLEEP);

			addr += PAGESIZE;
			index++;
			npgs--;
			continue;
		}

		/*
		 * pplist is a list of pg_cnt PAGESIZE pages.
		 * These pages are locked SE_EXCL since they
		 * came directly off the free list.
		 */
		ASSERT(IS_P2ALIGNED(pg_cnt, pg_cnt));
		ASSERT(IS_P2ALIGNED(index, pg_cnt));
		ASSERT(conpp == NULL);
		while (pg_cnt--) {

			ap = anon_alloc(NULL, 0);
			swap_xlate(ap, &ap_vp, &ap_off);

			ASSERT(pplist != NULL);
			pp = pplist;
			page_sub(&pplist, pp);
			PP_CLRFREE(pp);
			PP_CLRAGED(pp);
			conpp = pp;

			err = swap_getconpage(ap_vp, ap_off, PAGESIZE,
			    (uint_t *)NULL, anon_pl, PAGESIZE, conpp, NULL,
			    &nreloc, seg, addr, S_CREATE, cred);

			if (err) {
				ANON_LOCK_EXIT(&amp->a_rwlock);
				panic("anon_map_createpages: S_CREATE");
			}

			ASSERT(anon_pl[0] == pp);
			ASSERT(nreloc == 1);
			pagezero(pp, 0, PAGESIZE);
			CPU_STATS_ADD_K(vm, zfod, 1);
			hat_setrefmod(pp);

			ASSERT(anon_get_ptr(amp->ahp, index) == NULL);
			(void) anon_set_ptr(amp->ahp, index, ap, ANON_SLEEP);

			ppa[p_index++] = pp;

			addr += PAGESIZE;
			index++;
			npgs--;
		}
		conpp = NULL;
		pg_cnt	= pgsz >> PAGESHIFT;
		p_index = p_index - pg_cnt;
		while (pg_cnt--) {
			page_downgrade(ppa[p_index++]);
		}
	}
	ANON_LOCK_EXIT(&amp->a_rwlock);
	return (0);
}

static int
anon_try_demote_pages(
	struct anon_hdr *ahp,
	ulong_t sidx,
	uint_t szc,
	page_t **ppa,
	int private)
{
	struct anon	*ap;
	pgcnt_t		pgcnt = page_get_pagecnt(szc);
	page_t		*pp;
	pgcnt_t		i;
	kmutex_t	*ahmpages = NULL;
	int		root = 0;
	pgcnt_t		npgs;
	pgcnt_t		curnpgs = 0;
	size_t		ppasize = 0;

	ASSERT(szc != 0);
	ASSERT(IS_P2ALIGNED(pgcnt, pgcnt));
	ASSERT(IS_P2ALIGNED(sidx, pgcnt));
	ASSERT(sidx < ahp->size);

	if (ppa == NULL) {
		ppasize = pgcnt * sizeof (page_t *);
		ppa = kmem_alloc(ppasize, KM_SLEEP);
	}

	ap = anon_get_ptr(ahp, sidx);
	if (ap != NULL && private) {
		VM_STAT_ADD(anonvmstats.demotepages[1]);
		ahmpages = APH_MUTEX(ap->an_vp, ap->an_off);
		mutex_enter(ahmpages);
	}

	if (ap != NULL && ap->an_refcnt > 1) {
		if (ahmpages != NULL) {
			VM_STAT_ADD(anonvmstats.demotepages[2]);
			mutex_exit(ahmpages);
		}
		if (ppasize != 0) {
			kmem_free(ppa, ppasize);
		}
		return (0);
	}
	if (ahmpages != NULL) {
		mutex_exit(ahmpages);
	}
	if (ahp->size - sidx < pgcnt) {
		ASSERT(private == 0);
		pgcnt = ahp->size - sidx;
	}
	for (i = 0; i < pgcnt; i++, sidx++) {
		ap = anon_get_ptr(ahp, sidx);
		if (ap != NULL) {
			if (ap->an_refcnt != 1) {
				panic("anon_try_demote_pages: an_refcnt != 1");
			}
			pp = ppa[i] = page_lookup(ap->an_vp, ap->an_off,
			    SE_EXCL);
			if (pp != NULL) {
				(void) hat_pageunload(pp,
				    HAT_FORCE_PGUNLOAD);
			}
		} else {
			ppa[i] = NULL;
		}
	}
	for (i = 0; i < pgcnt; i++) {
		if ((pp = ppa[i]) != NULL && pp->p_szc != 0) {
			ASSERT(pp->p_szc <= szc);
			if (!root) {
				VM_STAT_ADD(anonvmstats.demotepages[3]);
				if (curnpgs != 0)
					panic("anon_try_demote_pages: "
					    "bad large page");

				root = 1;
				curnpgs = npgs =
				    page_get_pagecnt(pp->p_szc);

				ASSERT(npgs <= pgcnt);
				ASSERT(IS_P2ALIGNED(npgs, npgs));
				ASSERT(!(page_pptonum(pp) & (npgs - 1)));
			} else {
				ASSERT(i > 0);
				ASSERT(page_pptonum(pp) - 1 ==
				    page_pptonum(ppa[i - 1]));
				if ((page_pptonum(pp) & (npgs - 1)) ==
				    npgs - 1)
					root = 0;
			}
			ASSERT(PAGE_EXCL(pp));
			pp->p_szc = 0;
			ASSERT(curnpgs > 0);
			curnpgs--;
		}
	}
	if (root != 0 || curnpgs != 0)
		panic("anon_try_demote_pages: bad large page");

	for (i = 0; i < pgcnt; i++) {
		if ((pp = ppa[i]) != NULL) {
			ASSERT(!hat_page_is_mapped(pp));
			ASSERT(pp->p_szc == 0);
			page_unlock(pp);
		}
	}
	if (ppasize != 0) {
		kmem_free(ppa, ppasize);
	}
	return (1);
}

/*
 * anon_map_demotepages() can only be called by MAP_PRIVATE segments.
 */
int
anon_map_demotepages(
	struct anon_map *amp,
	ulong_t	start_idx,
	struct seg *seg,
	caddr_t addr,
	uint_t prot,
	struct vpage vpage[],
	struct cred *cred)
{
	struct anon	*ap;
	uint_t		szc = seg->s_szc;
	pgcnt_t		pgcnt = page_get_pagecnt(szc);
	size_t		ppasize = pgcnt * sizeof (page_t *);
	page_t		**ppa = kmem_alloc(ppasize, KM_SLEEP);
	page_t		*pp;
	page_t		*pl[2];
	pgcnt_t		i, pg_idx;
	ulong_t		an_idx;
	caddr_t		vaddr;
	int 		err;
	int		retry = 0;
	uint_t		vpprot;

	ASSERT(RW_WRITE_HELD(&amp->a_rwlock));
	ASSERT(IS_P2ALIGNED(pgcnt, pgcnt));
	ASSERT(IS_P2ALIGNED(start_idx, pgcnt));
	ASSERT(ppa != NULL);
	ASSERT(szc != 0);
	ASSERT(szc == amp->a_szc);

	VM_STAT_ADD(anonvmstats.demotepages[0]);

top:
	if (anon_try_demote_pages(amp->ahp, start_idx, szc, ppa, 1)) {
		kmem_free(ppa, ppasize);
		return (0);
	}

	VM_STAT_ADD(anonvmstats.demotepages[4]);

	ASSERT(retry == 0); /* we can be here only once */

	vaddr = addr;
	for (pg_idx = 0, an_idx = start_idx; pg_idx < pgcnt;
	    pg_idx++, an_idx++, vaddr += PAGESIZE) {
		ap = anon_get_ptr(amp->ahp, an_idx);
		if (ap == NULL)
			panic("anon_map_demotepages: no anon slot");
		err = anon_getpage(&ap, &vpprot, pl, PAGESIZE, seg, vaddr,
		    S_READ, cred);
		if (err) {
			for (i = 0; i < pg_idx; i++) {
				if ((pp = ppa[i]) != NULL)
					page_unlock(pp);
			}
			kmem_free(ppa, ppasize);
			return (err);
		}
		ppa[pg_idx] = pl[0];
	}

	err = anon_map_privatepages(amp, start_idx, szc, seg, addr, prot, ppa,
	    vpage, -1, 0, cred);
	if (err > 0) {
		VM_STAT_ADD(anonvmstats.demotepages[5]);
		kmem_free(ppa, ppasize);
		return (err);
	}
	ASSERT(err == 0 || err == -1);
	if (err == -1) {
		VM_STAT_ADD(anonvmstats.demotepages[6]);
		retry = 1;
		goto top;
	}
	for (i = 0; i < pgcnt; i++) {
		ASSERT(ppa[i] != NULL);
		if (ppa[i]->p_szc != 0)
			retry = 1;
		page_unlock(ppa[i]);
	}
	if (retry) {
		VM_STAT_ADD(anonvmstats.demotepages[7]);
		goto top;
	}

	VM_STAT_ADD(anonvmstats.demotepages[8]);

	kmem_free(ppa, ppasize);

	return (0);
}

/*
 * Free pages of shared anon map. It's assumed that anon maps don't share anon
 * structures with private anon maps. Therefore all anon structures should
 * have at most one reference at this point. This means underlying pages can
 * be exclusively locked and demoted or freed.  If not freeing the entire
 * large pages demote the ends of the region we free to be able to free
 * subpages. Page roots correspond to aligned index positions in anon map.
 */
void
anon_shmap_free_pages(struct anon_map *amp, ulong_t sidx, size_t len)
{
	ulong_t eidx = sidx + btopr(len);
	pgcnt_t pages = page_get_pagecnt(amp->a_szc);
	struct anon_hdr *ahp = amp->ahp;
	ulong_t tidx;
	size_t size;
	ulong_t sidx_aligned;
	ulong_t eidx_aligned;

	ASSERT(ANON_WRITE_HELD(&amp->a_rwlock));
	ASSERT(amp->refcnt <= 1);
	ASSERT(amp->a_szc > 0);
	ASSERT(eidx <= ahp->size);
	ASSERT(!anon_share(ahp, sidx, btopr(len)));

	if (len == 0) {	/* XXX */
		return;
	}

	sidx_aligned = P2ALIGN(sidx, pages);
	if (sidx_aligned != sidx ||
	    (eidx < sidx_aligned + pages && eidx < ahp->size)) {
		if (!anon_try_demote_pages(ahp, sidx_aligned,
		    amp->a_szc, NULL, 0)) {
			panic("anon_shmap_free_pages: demote failed");
		}
		size = (eidx <= sidx_aligned + pages) ? (eidx - sidx) :
		    P2NPHASE(sidx, pages);
		size <<= PAGESHIFT;
		anon_free(ahp, sidx, size);
		sidx = sidx_aligned + pages;
		if (eidx <= sidx) {
			return;
		}
	}
	eidx_aligned = P2ALIGN(eidx, pages);
	if (sidx < eidx_aligned) {
		anon_free_pages(ahp, sidx,
		    (eidx_aligned - sidx) << PAGESHIFT,
		    amp->a_szc);
		sidx = eidx_aligned;
	}
	ASSERT(sidx == eidx_aligned);
	if (eidx == eidx_aligned) {
		return;
	}
	tidx = eidx;
	if (eidx != ahp->size && anon_get_next_ptr(ahp, &tidx) != NULL &&
	    tidx - sidx < pages) {
		if (!anon_try_demote_pages(ahp, sidx, amp->a_szc, NULL, 0)) {
			panic("anon_shmap_free_pages: demote failed");
		}
		size = (eidx - sidx) << PAGESHIFT;
		anon_free(ahp, sidx, size);
	} else {
		anon_free_pages(ahp, sidx, pages << PAGESHIFT, amp->a_szc);
	}
}

/*
 * This routine should be called with amp's writer lock when there're no other
 * users of amp.  All pcache entries of this amp must have been already
 * inactivated. We must not drop a_rwlock here to prevent new users from
 * attaching to this amp.
 */
void
anonmap_purge(struct anon_map *amp)
{
	ASSERT(ANON_WRITE_HELD(&amp->a_rwlock));
	ASSERT(amp->refcnt <= 1);

	if (amp->a_softlockcnt != 0) {
		seg_ppurge(NULL, amp, 0);
	}

	/*
	 * Since all pcache entries were already inactive before this routine
	 * was called seg_ppurge() couldn't return while there're still
	 * entries that can be found via the list anchored at a_phead. So we
	 * can assert this list is empty now. a_softlockcnt may be still non 0
	 * if asynchronous thread that manages pcache already removed pcache
	 * entries but hasn't unlocked the pages yet. If a_softlockcnt is non
	 * 0 we just wait on a_purgecv for shamp_reclaim() to finish. Even if
	 * a_softlockcnt is 0 we grab a_purgemtx to avoid freeing anon map
	 * before shamp_reclaim() is done with it. a_purgemtx also taken by
	 * shamp_reclaim() while a_softlockcnt was still not 0 acts as a
	 * barrier that prevents anonmap_purge() to complete while
	 * shamp_reclaim() may still be referencing this amp.
	 */
	ASSERT(amp->a_phead.p_lnext == &amp->a_phead);
	ASSERT(amp->a_phead.p_lprev == &amp->a_phead);

	mutex_enter(&amp->a_purgemtx);
	while (amp->a_softlockcnt != 0) {
		ASSERT(amp->a_phead.p_lnext == &amp->a_phead);
		ASSERT(amp->a_phead.p_lprev == &amp->a_phead);
		amp->a_purgewait = 1;
		cv_wait(&amp->a_purgecv, &amp->a_purgemtx);
	}
	mutex_exit(&amp->a_purgemtx);

	ASSERT(amp->a_phead.p_lnext == &amp->a_phead);
	ASSERT(amp->a_phead.p_lprev == &amp->a_phead);
	ASSERT(amp->a_softlockcnt == 0);
}

/*
 * Allocate and initialize an anon_map structure for seg
 * associating the given swap reservation with the new anon_map.
 */
struct anon_map *
anonmap_alloc(size_t size, size_t swresv, int flags)
{
	struct anon_map *amp;
	int kmflags = (flags & ANON_NOSLEEP) ? KM_NOSLEEP : KM_SLEEP;

	amp = kmem_cache_alloc(anonmap_cache, kmflags);
	if (amp == NULL) {
		ASSERT(kmflags == KM_NOSLEEP);
		return (NULL);
	}

	amp->ahp = anon_create(btopr(size), flags);
	if (amp->ahp == NULL) {
		ASSERT(flags == ANON_NOSLEEP);
		kmem_cache_free(anonmap_cache, amp);
		return (NULL);
	}
	amp->refcnt = 1;
	amp->size = size;
	amp->swresv = swresv;
	amp->locality = 0;
	amp->a_szc = 0;
	amp->a_sp = NULL;
	amp->a_softlockcnt = 0;
	amp->a_purgewait = 0;
	amp->a_phead.p_lnext = &amp->a_phead;
	amp->a_phead.p_lprev = &amp->a_phead;

	return (amp);
}

void
anonmap_free(struct anon_map *amp)
{
	ASSERT(amp->ahp != NULL);
	ASSERT(amp->refcnt == 0);
	ASSERT(amp->a_softlockcnt == 0);
	ASSERT(amp->a_phead.p_lnext == &amp->a_phead);
	ASSERT(amp->a_phead.p_lprev == &amp->a_phead);

	lgrp_shm_policy_fini(amp, NULL);
	anon_release(amp->ahp, btopr(amp->size));
	kmem_cache_free(anonmap_cache, amp);
}

/*
 * Returns true if the app array has some empty slots.
 * The offp and lenp parameters are in/out parameters.  On entry
 * these values represent the starting offset and length of the
 * mapping.  When true is returned, these values may be modified
 * to be the largest range which includes empty slots.
 */
int
non_anon(struct anon_hdr *ahp, ulong_t anon_idx, u_offset_t *offp,
				size_t *lenp)
{
	ulong_t i, el;
	ssize_t low, high;
	struct anon *ap;

	low = -1;
	for (i = 0, el = *lenp; i < el; i += PAGESIZE, anon_idx++) {
		ap = anon_get_ptr(ahp, anon_idx);
		if (ap == NULL) {
			if (low == -1)
				low = i;
			high = i;
		}
	}
	if (low != -1) {
		/*
		 * Found at least one non-anon page.
		 * Set up the off and len return values.
		 */
		if (low != 0)
			*offp += low;
		*lenp = high - low + PAGESIZE;
		return (1);
	}
	return (0);
}

/*
 * Return a count of the number of existing anon pages in the anon array
 * app in the range (off, off+len). The array and slots must be guaranteed
 * stable by the caller.
 */
pgcnt_t
anon_pages(struct anon_hdr *ahp, ulong_t anon_index, pgcnt_t nslots)
{
	pgcnt_t cnt = 0;

	while (nslots-- > 0) {
		if ((anon_get_ptr(ahp, anon_index)) != NULL)
			cnt++;
		anon_index++;
	}
	return (cnt);
}

/*
 * Move reserved phys swap into memory swap (unreserve phys swap
 * and reserve mem swap by the same amount).
 * Used by segspt when it needs to lock reserved swap npages in memory
 */
int
anon_swap_adjust(pgcnt_t npages)
{
	pgcnt_t unlocked_mem_swap;

	mutex_enter(&anoninfo_lock);

	ASSERT(k_anoninfo.ani_mem_resv >= k_anoninfo.ani_locked_swap);
	ASSERT(k_anoninfo.ani_max >= k_anoninfo.ani_phys_resv);

	unlocked_mem_swap = k_anoninfo.ani_mem_resv
	    - k_anoninfo.ani_locked_swap;
	if (npages > unlocked_mem_swap) {
		spgcnt_t adjusted_swap = npages - unlocked_mem_swap;

		/*
		 * if there is not enough unlocked mem swap we take missing
		 * amount from phys swap and give it to mem swap
		 */
		if (!page_reclaim_mem(adjusted_swap, segspt_minfree, 1)) {
			mutex_exit(&anoninfo_lock);
			return (ENOMEM);
		}

		k_anoninfo.ani_mem_resv += adjusted_swap;
		ASSERT(k_anoninfo.ani_phys_resv >= adjusted_swap);
		k_anoninfo.ani_phys_resv -= adjusted_swap;

		ANI_ADD(adjusted_swap);
	}
	k_anoninfo.ani_locked_swap += npages;

	ASSERT(k_anoninfo.ani_mem_resv >= k_anoninfo.ani_locked_swap);
	ASSERT(k_anoninfo.ani_max >= k_anoninfo.ani_phys_resv);

	mutex_exit(&anoninfo_lock);

	return (0);
}

/*
 * 'unlocked' reserved mem swap so when it is unreserved it
 * can be moved back phys (disk) swap
 */
void
anon_swap_restore(pgcnt_t npages)
{
	mutex_enter(&anoninfo_lock);

	ASSERT(k_anoninfo.ani_locked_swap <= k_anoninfo.ani_mem_resv);

	ASSERT(k_anoninfo.ani_locked_swap >= npages);
	k_anoninfo.ani_locked_swap -= npages;

	ASSERT(k_anoninfo.ani_locked_swap <= k_anoninfo.ani_mem_resv);

	mutex_exit(&anoninfo_lock);
}

/*
 * Return the pointer from the list for a
 * specified anon index.
 */
ulong_t *
anon_get_slot(struct anon_hdr *ahp, ulong_t an_idx)
{
	struct anon	**app;
	void 		**ppp;

	ASSERT(an_idx < ahp->size);

	/*
	 * Single level case.
	 */
	if ((ahp->size <= ANON_CHUNK_SIZE) || (ahp->flags & ANON_ALLOC_FORCE)) {
		return ((ulong_t *)&ahp->array_chunk[an_idx]);
	} else {

		/*
		 * 2 level case.
		 */
		ppp = &ahp->array_chunk[an_idx >> ANON_CHUNK_SHIFT];
		if (*ppp == NULL) {
			mutex_enter(&ahp->serial_lock);
			ppp = &ahp->array_chunk[an_idx >> ANON_CHUNK_SHIFT];
			if (*ppp == NULL)
				*ppp = kmem_zalloc(PAGESIZE, KM_SLEEP);
			mutex_exit(&ahp->serial_lock);
		}
		app = *ppp;
		return ((ulong_t *)&app[an_idx & ANON_CHUNK_OFF]);
	}
}

void
anon_array_enter(struct anon_map *amp, ulong_t an_idx, anon_sync_obj_t *sobj)
{
	ulong_t		*ap_slot;
	kmutex_t	*mtx;
	kcondvar_t	*cv;
	int		hash;

	/*
	 * Use szc to determine anon slot(s) to appear atomic.
	 * If szc = 0, then lock the anon slot and mark it busy.
	 * If szc > 0, then lock the range of slots by getting the
	 * anon_array_lock for the first anon slot, and mark only the
	 * first anon slot busy to represent whole range being busy.
	 */

	ASSERT(RW_READ_HELD(&amp->a_rwlock));
	an_idx = P2ALIGN(an_idx, page_get_pagecnt(amp->a_szc));
	hash = ANON_ARRAY_HASH(amp, an_idx);
	sobj->sync_mutex = mtx = &anon_array_lock[hash].pad_mutex;
	sobj->sync_cv = cv = &anon_array_cv[hash];
	mutex_enter(mtx);
	ap_slot = anon_get_slot(amp->ahp, an_idx);
	while (ANON_ISBUSY(ap_slot))
		cv_wait(cv, mtx);
	ANON_SETBUSY(ap_slot);
	sobj->sync_data = ap_slot;
	mutex_exit(mtx);
}

int
anon_array_try_enter(struct anon_map *amp, ulong_t an_idx,
			anon_sync_obj_t *sobj)
{
	ulong_t		*ap_slot;
	kmutex_t	*mtx;
	int		hash;

	/*
	 * Try to lock a range of anon slots.
	 * Use szc to determine anon slot(s) to appear atomic.
	 * If szc = 0, then lock the anon slot and mark it busy.
	 * If szc > 0, then lock the range of slots by getting the
	 * anon_array_lock for the first anon slot, and mark only the
	 * first anon slot busy to represent whole range being busy.
	 * Fail if the mutex or the anon_array are busy.
	 */

	ASSERT(RW_READ_HELD(&amp->a_rwlock));
	an_idx = P2ALIGN(an_idx, page_get_pagecnt(amp->a_szc));
	hash = ANON_ARRAY_HASH(amp, an_idx);
	sobj->sync_mutex = mtx = &anon_array_lock[hash].pad_mutex;
	sobj->sync_cv = &anon_array_cv[hash];
	if (!mutex_tryenter(mtx)) {
		return (EWOULDBLOCK);
	}
	ap_slot = anon_get_slot(amp->ahp, an_idx);
	if (ANON_ISBUSY(ap_slot)) {
		mutex_exit(mtx);
		return (EWOULDBLOCK);
	}
	ANON_SETBUSY(ap_slot);
	sobj->sync_data = ap_slot;
	mutex_exit(mtx);
	return (0);
}

void
anon_array_exit(anon_sync_obj_t *sobj)
{
	mutex_enter(sobj->sync_mutex);
	ASSERT(ANON_ISBUSY(sobj->sync_data));
	ANON_CLRBUSY(sobj->sync_data);
	if (CV_HAS_WAITERS(sobj->sync_cv))
		cv_broadcast(sobj->sync_cv);
	mutex_exit(sobj->sync_mutex);
}
