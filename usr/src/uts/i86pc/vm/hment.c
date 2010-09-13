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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/kmem.h>
#include <sys/atomic.h>
#include <sys/bitmap.h>
#include <sys/systm.h>
#include <vm/seg_kmem.h>
#include <vm/hat.h>
#include <vm/vm_dep.h>
#include <vm/hat_i86.h>
#include <sys/cmn_err.h>
#include <sys/avl.h>


/*
 * When pages are shared by more than one mapping, a list of these
 * structs hangs off of the page_t connected by the hm_next and hm_prev
 * fields.  Every hment is also indexed by a system-wide hash table, using
 * hm_hashlink to connect the hments within each hash bucket.
 */
struct hment {
	avl_node_t	hm_hashlink;	/* links for hash table */
	struct hment	*hm_next;	/* next mapping of same page */
	struct hment	*hm_prev;	/* previous mapping of same page */
	htable_t	*hm_htable;	/* corresponding htable_t */
	pfn_t		hm_pfn;		/* mapping page frame number */
	uint16_t	hm_entry;	/* index of pte in htable */
	uint16_t	hm_pad;		/* explicitly expose compiler padding */
#ifdef __amd64
	uint32_t	hm_pad2;	/* explicitly expose compiler padding */
#endif
};

/*
 * Value returned by hment_walk() when dealing with a single mapping
 * embedded in the page_t.
 */
#define	HMENT_EMBEDDED ((hment_t *)(uintptr_t)1)

kmem_cache_t *hment_cache;

/*
 * The hment reserve is similar to the htable reserve, with the following
 * exception. Hment's are never needed for HAT kmem allocs.
 *
 * The hment_reserve_amount variable is used, so that you can change it's
 * value to zero via a kernel debugger to force stealing to get tested.
 */
#define	HMENT_RESERVE_AMOUNT	(200)	/* currently a guess at right value. */
uint_t hment_reserve_amount = HMENT_RESERVE_AMOUNT;
kmutex_t hment_reserve_mutex;
uint_t	hment_reserve_count;
hment_t	*hment_reserve_pool;

/*
 * All hments are stored in a system wide hash of AVL trees.
 */
#define	HMENT_HASH_SIZE (64 * 1024)
static uint_t hment_hash_entries = HMENT_HASH_SIZE;
static avl_tree_t *hment_table;

/*
 * Lots of highly shared pages will have the same value for "entry" (consider
 * the starting address of "xterm" or "sh"). So we'll distinguish them by
 * adding the pfn of the page table into both the high bits.
 * The shift by 9 corresponds to the range of values for entry (0..511).
 */
#define	HMENT_HASH(pfn, entry) (uint32_t) 	\
	((((pfn) << 9) + entry + pfn) & (hment_hash_entries - 1))

/*
 * "mlist_lock" is a hashed mutex lock for protecting per-page mapping
 * lists and "hash_lock" is a similar lock protecting the hment hash
 * table.  The hashed approach is taken to avoid the spatial overhead of
 * maintaining a separate lock for each page, while still achieving better
 * scalability than a single lock would allow.
 */
#define	MLIST_NUM_LOCK	2048		/* must be power of two */
static kmutex_t *mlist_lock;

/*
 * the shift by 9 is so that all large pages don't use the same hash bucket
 */
#define	MLIST_MUTEX(pp) \
	&mlist_lock[((pp)->p_pagenum + ((pp)->p_pagenum >> 9)) & \
	(MLIST_NUM_LOCK - 1)]

#define	HASH_NUM_LOCK	2048		/* must be power of two */
static kmutex_t *hash_lock;

#define	HASH_MUTEX(idx) &hash_lock[(idx) & (HASH_NUM_LOCK-1)]

static avl_node_t null_avl_link;	/* always zero */
static hment_t *hment_steal(void);

/*
 * Utility to compare hment_t's for use in AVL tree. The ordering
 * is entirely arbitrary and is just so that the AVL algorithm works.
 */
static int
hment_compare(const void *hm1, const void *hm2)
{
	hment_t *h1 = (hment_t *)hm1;
	hment_t *h2 = (hment_t *)hm2;
	long diff;

	diff = (uintptr_t)h1->hm_htable - (uintptr_t)h2->hm_htable;
	if (diff == 0) {
		diff = h1->hm_entry - h2->hm_entry;
		if (diff == 0)
			diff = h1->hm_pfn - h2->hm_pfn;
	}
	if (diff < 0)
		diff = -1;
	else if (diff > 0)
		diff = 1;
	return (diff);
}

/*
 * put one hment onto the reserves list
 */
static void
hment_put_reserve(hment_t *hm)
{
	HATSTAT_INC(hs_hm_put_reserve);
	mutex_enter(&hment_reserve_mutex);
	hm->hm_next = hment_reserve_pool;
	hment_reserve_pool = hm;
	++hment_reserve_count;
	mutex_exit(&hment_reserve_mutex);
}

/*
 * Take one hment from the reserve.
 */
static hment_t *
hment_get_reserve(void)
{
	hment_t *hm = NULL;

	/*
	 * We rely on a "donation system" to refill the hment reserve
	 * list, which only takes place when we are allocating hments for
	 * user mappings.  It is theoretically possible that an incredibly
	 * long string of kernel hment_alloc()s with no intervening user
	 * hment_alloc()s could exhaust that pool.
	 */
	HATSTAT_INC(hs_hm_get_reserve);
	mutex_enter(&hment_reserve_mutex);
	if (hment_reserve_count != 0) {
		hm = hment_reserve_pool;
		hment_reserve_pool = hm->hm_next;
		--hment_reserve_count;
	}
	mutex_exit(&hment_reserve_mutex);
	return (hm);
}

/*
 * Allocate an hment
 */
static hment_t *
hment_alloc()
{
	int km_flag = can_steal_post_boot ? KM_NOSLEEP : KM_SLEEP;
	hment_t	*hm = NULL;

	/*
	 * If we aren't using the reserves, try using kmem to get an hment.
	 * Donate any successful allocations to reserves if low.
	 *
	 * If we're in panic, resort to using the reserves.
	 */
	HATSTAT_INC(hs_hm_alloc);
	if (!USE_HAT_RESERVES()) {
		for (;;) {
			hm = kmem_cache_alloc(hment_cache, km_flag);
			if (hm == NULL ||
			    USE_HAT_RESERVES() ||
			    hment_reserve_count >= hment_reserve_amount)
				break;
			hment_put_reserve(hm);
		}
	}

	/*
	 * If allocation failed, we need to tap the reserves or steal
	 */
	if (hm == NULL) {
		if (USE_HAT_RESERVES())
			hm = hment_get_reserve();

		/*
		 * If we still haven't gotten an hment, attempt to steal one by
		 * victimizing a mapping in a user htable.
		 */
		if (hm == NULL && can_steal_post_boot)
			hm = hment_steal();

		/*
		 * we're in dire straights, try the reserve
		 */
		if (hm == NULL)
			hm = hment_get_reserve();

		/*
		 * still no hment is a serious problem.
		 */
		if (hm == NULL)
			panic("hment_alloc(): no reserve, couldn't steal");
	}


	hm->hm_entry = 0;
	hm->hm_htable = NULL;
	hm->hm_hashlink = null_avl_link;
	hm->hm_next = NULL;
	hm->hm_prev = NULL;
	hm->hm_pfn = PFN_INVALID;
	return (hm);
}

/*
 * Free an hment, possibly to the reserves list when called from the
 * thread using the reserves. For example, when freeing an hment during an
 * htable_steal(), we can't recurse into the kmem allocator, so we just
 * push the hment onto the reserve list.
 */
void
hment_free(hment_t *hm)
{
#ifdef DEBUG
	/*
	 * zero out all fields to try and force any race conditions to segfault
	 */
	bzero(hm, sizeof (*hm));
#endif
	HATSTAT_INC(hs_hm_free);
	if (USE_HAT_RESERVES() ||
	    hment_reserve_count < hment_reserve_amount) {
		hment_put_reserve(hm);
	} else {
		kmem_cache_free(hment_cache, hm);
		hment_adjust_reserve();
	}
}

/*
 * These must test for mlist_lock not having been allocated yet.
 * We just ignore locking in that case, as it means were in early
 * single threaded startup.
 */
int
x86_hm_held(page_t *pp)
{
	ASSERT(pp != NULL);
	if (mlist_lock == NULL)
		return (1);
	return (MUTEX_HELD(MLIST_MUTEX(pp)));
}

void
x86_hm_enter(page_t *pp)
{
	ASSERT(pp != NULL);
	if (mlist_lock != NULL)
		mutex_enter(MLIST_MUTEX(pp));
}

void
x86_hm_exit(page_t *pp)
{
	ASSERT(pp != NULL);
	if (mlist_lock != NULL)
		mutex_exit(MLIST_MUTEX(pp));
}

/*
 * Internal routine to add a full hment to a page_t mapping list
 */
static void
hment_insert(hment_t *hm, page_t *pp)
{
	uint_t		idx;

	ASSERT(x86_hm_held(pp));
	ASSERT(!pp->p_embed);

	/*
	 * Add the hment to the page's mapping list.
	 */
	++pp->p_share;
	hm->hm_next = pp->p_mapping;
	if (pp->p_mapping != NULL)
		((hment_t *)pp->p_mapping)->hm_prev = hm;
	pp->p_mapping = hm;

	/*
	 * Add the hment to the system-wide hash table.
	 */
	idx = HMENT_HASH(hm->hm_htable->ht_pfn, hm->hm_entry);

	mutex_enter(HASH_MUTEX(idx));
	avl_add(&hment_table[idx], hm);
	mutex_exit(HASH_MUTEX(idx));
}

/*
 * Prepare a mapping list entry to the given page.
 *
 * There are 4 different situations to deal with:
 *
 * - Adding the first mapping to a page_t as an embedded hment
 * - Refaulting on an existing embedded mapping
 * - Upgrading an embedded mapping when adding a 2nd mapping
 * - Adding another mapping to a page_t that already has multiple mappings
 *	 note we don't optimized for the refaulting case here.
 *
 * Due to competition with other threads that may be mapping/unmapping the
 * same page and the need to drop all locks while allocating hments, any or
 * all of the 3 situations can occur (and in almost any order) in any given
 * call. Isn't this fun!
 */
hment_t *
hment_prepare(htable_t *htable, uint_t entry, page_t *pp)
{
	hment_t		*hm = NULL;

	ASSERT(x86_hm_held(pp));

	for (;;) {

		/*
		 * The most common case is establishing the first mapping to a
		 * page, so check that first. This doesn't need any allocated
		 * hment.
		 */
		if (pp->p_mapping == NULL) {
			ASSERT(!pp->p_embed);
			ASSERT(pp->p_share == 0);
			if (hm == NULL)
				break;

			/*
			 * we had an hment already, so free it and retry
			 */
			goto free_and_continue;
		}

		/*
		 * If there is an embedded mapping, we may need to
		 * convert it to an hment.
		 */
		if (pp->p_embed) {

			/* should point to htable */
			ASSERT(pp->p_mapping != NULL);

			/*
			 * If we are faulting on a pre-existing mapping
			 * there is no need to promote/allocate a new hment.
			 * This happens a lot due to segmap.
			 */
			if (pp->p_mapping == htable && pp->p_mlentry == entry) {
				if (hm == NULL)
					break;
				goto free_and_continue;
			}

			/*
			 * If we have an hment allocated, use it to promote the
			 * existing embedded mapping.
			 */
			if (hm != NULL) {
				hm->hm_htable = pp->p_mapping;
				hm->hm_entry = pp->p_mlentry;
				hm->hm_pfn = pp->p_pagenum;
				pp->p_mapping = NULL;
				pp->p_share = 0;
				pp->p_embed = 0;
				hment_insert(hm, pp);
			}

			/*
			 * We either didn't have an hment allocated or we just
			 * used it for the embedded mapping. In either case,
			 * allocate another hment and restart.
			 */
			goto allocate_and_continue;
		}

		/*
		 * Last possibility is that we're adding an hment to a list
		 * of hments.
		 */
		if (hm != NULL)
			break;
allocate_and_continue:
		x86_hm_exit(pp);
		hm = hment_alloc();
		x86_hm_enter(pp);
		continue;

free_and_continue:
		/*
		 * we allocated an hment already, free it and retry
		 */
		x86_hm_exit(pp);
		hment_free(hm);
		hm = NULL;
		x86_hm_enter(pp);
	}
	ASSERT(x86_hm_held(pp));
	return (hm);
}

/*
 * Record a mapping list entry for the htable/entry to the given page.
 *
 * hment_prepare() should have properly set up the situation.
 */
void
hment_assign(htable_t *htable, uint_t entry, page_t *pp, hment_t *hm)
{
	ASSERT(x86_hm_held(pp));

	/*
	 * The most common case is establishing the first mapping to a
	 * page, so check that first. This doesn't need any allocated
	 * hment.
	 */
	if (pp->p_mapping == NULL) {
		ASSERT(hm == NULL);
		ASSERT(!pp->p_embed);
		ASSERT(pp->p_share == 0);
		pp->p_embed = 1;
		pp->p_mapping = htable;
		pp->p_mlentry = entry;
		return;
	}

	/*
	 * We should never get here with a pre-existing embedded maping
	 */
	ASSERT(!pp->p_embed);

	/*
	 * add the new hment to the mapping list
	 */
	ASSERT(hm != NULL);
	hm->hm_htable = htable;
	hm->hm_entry = entry;
	hm->hm_pfn = pp->p_pagenum;
	hment_insert(hm, pp);
}

/*
 * Walk through the mappings for a page.
 *
 * must already have done an x86_hm_enter()
 */
hment_t *
hment_walk(page_t *pp, htable_t **ht, uint_t *entry, hment_t *prev)
{
	hment_t		*hm;

	ASSERT(x86_hm_held(pp));

	if (pp->p_embed) {
		if (prev == NULL) {
			*ht = (htable_t *)pp->p_mapping;
			*entry = pp->p_mlentry;
			hm = HMENT_EMBEDDED;
		} else {
			ASSERT(prev == HMENT_EMBEDDED);
			hm = NULL;
		}
	} else {
		if (prev == NULL) {
			ASSERT(prev != HMENT_EMBEDDED);
			hm = (hment_t *)pp->p_mapping;
		} else {
			hm = prev->hm_next;
		}

		if (hm != NULL) {
			*ht = hm->hm_htable;
			*entry = hm->hm_entry;
		}
	}
	return (hm);
}

/*
 * Remove a mapping to a page from its mapping list. Must have
 * the corresponding mapping list locked.
 * Finds the mapping list entry with the given pte_t and
 * unlinks it from the mapping list.
 */
hment_t *
hment_remove(page_t *pp, htable_t *ht, uint_t entry)
{
	hment_t		dummy;
	avl_index_t	where;
	hment_t		*hm;
	uint_t		idx;

	ASSERT(x86_hm_held(pp));

	/*
	 * Check if we have only one mapping embedded in the page_t.
	 */
	if (pp->p_embed) {
		ASSERT(ht == (htable_t *)pp->p_mapping);
		ASSERT(entry == pp->p_mlentry);
		ASSERT(pp->p_share == 0);
		pp->p_mapping = NULL;
		pp->p_mlentry = 0;
		pp->p_embed = 0;
		return (NULL);
	}

	/*
	 * Otherwise it must be in the list of hments.
	 * Find the hment in the system-wide hash table and remove it.
	 */
	ASSERT(pp->p_share != 0);
	dummy.hm_htable = ht;
	dummy.hm_entry = entry;
	dummy.hm_pfn = pp->p_pagenum;
	idx = HMENT_HASH(ht->ht_pfn, entry);
	mutex_enter(HASH_MUTEX(idx));
	hm = avl_find(&hment_table[idx], &dummy, &where);
	if (hm == NULL)
		panic("hment_remove() missing in hash table pp=%lx, ht=%lx,"
		    "entry=0x%x hash index=0x%x", (uintptr_t)pp, (uintptr_t)ht,
		    entry, idx);
	avl_remove(&hment_table[idx], hm);
	mutex_exit(HASH_MUTEX(idx));

	/*
	 * Remove the hment from the page's mapping list
	 */
	if (hm->hm_next)
		hm->hm_next->hm_prev = hm->hm_prev;
	if (hm->hm_prev)
		hm->hm_prev->hm_next = hm->hm_next;
	else
		pp->p_mapping = hm->hm_next;

	--pp->p_share;
	hm->hm_hashlink = null_avl_link;
	hm->hm_next = NULL;
	hm->hm_prev = NULL;

	return (hm);
}

/*
 * Put initial hment's in the reserve pool.
 */
void
hment_reserve(uint_t count)
{
	hment_t	*hm;

	count += hment_reserve_amount;

	while (hment_reserve_count < count) {
		hm = kmem_cache_alloc(hment_cache, KM_NOSLEEP);
		if (hm == NULL)
			return;
		hment_put_reserve(hm);
	}
}

/*
 * Readjust the hment reserves after they may have been used.
 */
void
hment_adjust_reserve()
{
	hment_t	*hm;

	/*
	 * Free up any excess reserves
	 */
	while (hment_reserve_count > hment_reserve_amount &&
	    !USE_HAT_RESERVES()) {
		hm = hment_get_reserve();
		if (hm == NULL)
			return;
		kmem_cache_free(hment_cache, hm);
	}
}

/*
 * initialize hment data structures
 */
void
hment_init(void)
{
	int i;
	int flags = KMC_NOHASH | KMC_NODEBUG;

	/*
	 * Initialize kmem caches. On 32 bit kernel's we shut off
	 * debug information to save on precious kernel VA usage.
	 */
	hment_cache = kmem_cache_create("hment_t",
	    sizeof (hment_t), 0, NULL, NULL, NULL,
	    NULL, hat_memload_arena, flags);

	hment_table = kmem_zalloc(hment_hash_entries * sizeof (*hment_table),
	    KM_SLEEP);

	mlist_lock = kmem_zalloc(MLIST_NUM_LOCK * sizeof (kmutex_t), KM_SLEEP);

	hash_lock = kmem_zalloc(HASH_NUM_LOCK * sizeof (kmutex_t), KM_SLEEP);

	for (i = 0; i < hment_hash_entries; ++i)
		avl_create(&hment_table[i], hment_compare, sizeof (hment_t),
		    offsetof(hment_t, hm_hashlink));

	for (i = 0; i < MLIST_NUM_LOCK; i++)
		mutex_init(&mlist_lock[i], NULL, MUTEX_DEFAULT, NULL);

	for (i = 0; i < HASH_NUM_LOCK; i++)
		mutex_init(&hash_lock[i], NULL, MUTEX_DEFAULT, NULL);


}

/*
 * return the number of mappings to a page
 *
 * Note there is no ASSERT() that the MUTEX is held for this.
 * Hence the return value might be inaccurate if this is called without
 * doing an x86_hm_enter().
 */
uint_t
hment_mapcnt(page_t *pp)
{
	uint_t cnt;
	uint_t szc;
	page_t *larger;
	hment_t	*hm;

	x86_hm_enter(pp);
	if (pp->p_mapping == NULL)
		cnt = 0;
	else if (pp->p_embed)
		cnt = 1;
	else
		cnt = pp->p_share;
	x86_hm_exit(pp);

	/*
	 * walk through all larger mapping sizes counting mappings
	 */
	for (szc = 1; szc <= pp->p_szc; ++szc) {
		larger = PP_GROUPLEADER(pp, szc);
		if (larger == pp)	/* don't double count large mappings */
			continue;

		x86_hm_enter(larger);
		if (larger->p_mapping != NULL) {
			if (larger->p_embed &&
			    ((htable_t *)larger->p_mapping)->ht_level == szc) {
				++cnt;
			} else if (!larger->p_embed) {
				for (hm = larger->p_mapping; hm;
				    hm = hm->hm_next) {
					if (hm->hm_htable->ht_level == szc)
						++cnt;
				}
			}
		}
		x86_hm_exit(larger);
	}
	return (cnt);
}

/*
 * We need to steal an hment. Walk through all the page_t's until we
 * find one that has multiple mappings. Unload one of the mappings
 * and reclaim that hment. Note that we'll save/restart the starting
 * page to try and spread the pain.
 */
static page_t *last_page = NULL;

static hment_t *
hment_steal(void)
{
	page_t *last = last_page;
	page_t *pp = last;
	hment_t *hm = NULL;
	hment_t *hm2;
	htable_t *ht;
	uint_t found_one = 0;

	HATSTAT_INC(hs_hm_steals);
	if (pp == NULL)
		last = pp = page_first();

	while (!found_one) {
		HATSTAT_INC(hs_hm_steal_exam);
		pp = page_next(pp);
		if (pp == NULL)
			pp = page_first();

		/*
		 * The loop and function exit here if nothing found to steal.
		 */
		if (pp == last)
			return (NULL);

		/*
		 * Only lock the page_t if it has hments.
		 */
		if (pp->p_mapping == NULL || pp->p_embed)
			continue;

		/*
		 * Search the mapping list for a usable mapping.
		 */
		x86_hm_enter(pp);
		if (!pp->p_embed) {
			for (hm = pp->p_mapping; hm; hm = hm->hm_next) {
				ht = hm->hm_htable;
				if (ht->ht_hat != kas.a_hat &&
				    ht->ht_busy == 0 &&
				    ht->ht_lock_cnt == 0) {
					found_one = 1;
					break;
				}
			}
		}
		if (!found_one)
			x86_hm_exit(pp);
	}

	/*
	 * Steal the mapping we found.  Note that hati_page_unmap() will
	 * do the x86_hm_exit().
	 */
	hm2 = hati_page_unmap(pp, ht, hm->hm_entry);
	ASSERT(hm2 == hm);
	last_page = pp;
	return (hm);
}
