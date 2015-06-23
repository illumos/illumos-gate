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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/mman.h>
#include <sys/sunddi.h>
#include <sys/tnf_probe.h>
#include <vm/hat_sfmmu.h>
#include <vm/as.h>
#include <vm/xhat.h>
#include <vm/xhat_sfmmu.h>
#include <sys/zulu_hat.h>
#include <sys/zulumod.h>

/*
 * This file contains the implementation of zulu_hat: an XHAT provider
 * to support the MMU for the XVR-4000 graphics accelerator (code name zulu).
 *
 * The zulu hat is linked into the kernel misc module zuluvm.
 * zuluvm provides services that the zulu device driver module requires
 * that are not part of the standard ddi. See PSARC 2002/231.
 *
 * The zulu driver is delivered by the graphics consolidation.
 * zuluvm is in ON workspace.
 *
 * There are two types of interfaces provided by zulu_hat
 *   1.	The set of functions and data structures used by zuluvm to obtain
 * 	tte entries for the zulu MMU and to manage the association between
 *	user process's address spaces and zulu graphics contexts.
 *
 *   2.	The entry points required for an XHAT provider: zulu_hat_ops
 */

/*
 * zulu_ctx_tab contains an array of pointers to the zulu_hats.
 *
 * During zulu graphics context switch, the zulu MMU's current context register
 * is set to the index of the process's zulu hat's location in the array
 * zulu_ctx_tab.
 *
 * This allows the TL=1 TLB miss handler to quickly find the zulu hat and
 * lookup a tte in the zulu hat's TSB.
 *
 * To synchronize with the trap handler we use bit zero of
 * the pointer as a lock bit. See the function zulu_ctx_tsb_lock_enter().
 *
 * If the trap handler finds the ctx locked it doesn't wait, it
 * posts a soft interrupt which is handled at TL=0.
 */

#define		ZULU_HAT_MAX_CTX 32
struct zulu_hat *zulu_ctx_tab[ZULU_HAT_MAX_CTX];

/*
 * To avoid searching through the whole zulu_ctx_tab for a free slot,
 * we maintain the value of zulu_ctx_search_start.
 *
 * This value is a guess as to where a free slot in the context table might be.
 * All slots < zulu_ctx_search_start are definitely occupied.
 */
static int zulu_ctx_search_start = 0;


/*
 * this mutex protects the zulu_ctx_tab and zulu_ctx_search_start
 */
static kmutex_t	zulu_ctx_lock;


uint64_t	zulu_tsb_hit = 0;	/* assembly code increments this */
static uint64_t	zulu_tsb_miss = 0;
static uint64_t	zulu_as_fault = 0;

/*
 * The zulu device has two zulu data mmus.
 * We use the base pagesize for one of them and the and 4M for the other.
 */
extern int zuluvm_base_pgsize;



/*
 * call zuluvm to remove translations for a page
 */
static void
zulu_hat_demap_page(struct zulu_hat *zhat, caddr_t vaddr, int size)
{
	if (zhat->zulu_ctx < 0) {
		/* context has been stolen, so page is already demapped */
		return;
	}
	zuluvm_demap_page(zhat->zdev, NULL, zhat->zulu_ctx, vaddr, size);
}

static void
zulu_hat_demap_ctx(void *zdev, int zulu_ctx)
{
	if (zulu_ctx < 0) {
		/* context has been stolen */
		return;
	}
	zuluvm_demap_ctx(zdev, zulu_ctx);
}


/*
 * steal the least recently used context slot.
 */
static int
zulu_hat_steal_ctx()
{
	int		ctx;
	hrtime_t	delta = INT64_MAX;
	struct zulu_hat *zhat_oldest = NULL;

	ASSERT(mutex_owned(&zulu_ctx_lock));

	for (ctx = 0; ctx < ZULU_HAT_MAX_CTX; ctx++) {
		struct zulu_hat *zhat = ZULU_CTX_GET_HAT(ctx);

		/*
		 * we shouldn't be here unless all slots are occupied
		 */
		ASSERT(zhat != NULL);

		TNF_PROBE_3(steal_ctx_loop, "zulu_hat", /* CSTYLED */,
		    tnf_int, ctx, ctx,
		    tnf_long, last_used, zhat->last_used,
		    tnf_long, oldest, delta);

		if (zhat->last_used <  delta) {
			zhat_oldest = zhat;
			delta  = zhat->last_used;
		}
	}

	ASSERT(zhat_oldest != NULL);

	mutex_enter(&zhat_oldest->lock);

	/* Nobody should have the tsb lock bit set here */
	ASSERT(((uint64_t)zulu_ctx_tab[zhat_oldest->zulu_ctx] & ZULU_CTX_LOCK)
	    == 0);

	ctx = zhat_oldest->zulu_ctx;
	zhat_oldest->zulu_ctx = -1;

	ZULU_CTX_SET_HAT(ctx, NULL);

	zulu_hat_demap_ctx(zhat_oldest->zdev, ctx);

	mutex_exit(&zhat_oldest->lock);

	TNF_PROBE_1(zulu_hat_steal_ctx, "zulu_hat", /* CSTYLED */,
		tnf_int, ctx, ctx);

	return (ctx);
}

/*
 * find a slot in the context table for a zulu_hat
 */
static void
zulu_hat_ctx_alloc(struct zulu_hat *zhat)
{
	int 		ctx;

	mutex_enter(&zulu_ctx_lock);

	for (ctx = zulu_ctx_search_start; ctx < ZULU_HAT_MAX_CTX; ctx++) {
		if (ZULU_CTX_IS_FREE(ctx)) {
			zulu_ctx_search_start = ctx + 1;
			break;
		}
	}

	if (ctx == ZULU_HAT_MAX_CTX) {
		/* table is full need to steal an entry */
		zulu_ctx_search_start = ZULU_HAT_MAX_CTX;
		ctx = zulu_hat_steal_ctx();
	}

	mutex_enter(&zhat->lock);

	ZULU_CTX_SET_HAT(ctx, zhat);
	zhat->zulu_ctx = ctx;

	mutex_exit(&zhat->lock);

	mutex_exit(&zulu_ctx_lock);

	TNF_PROBE_2(zulu_hat_ctx_alloc, "zulu_hat", /* CSTYLED */,
		tnf_opaque, zhat, zhat, tnf_int, ctx, ctx);
}

/*
 * zulu_hat_validate_ctx: Called before the graphics context associated
 * with a given zulu hat becomes the current zulu graphics context.
 * Make sure that the hat has a slot in zulu_ctx_tab.
 */
void
zulu_hat_validate_ctx(struct zulu_hat *zhat)
{
	if (zhat->zulu_ctx < 0)  {
		zulu_hat_ctx_alloc(zhat);
	}
	zhat->last_used = gethrtime();
}


static void
zulu_hat_ctx_free(struct zulu_hat *zhat)
{
	TNF_PROBE_1(zulu_hat_ctx_free, "zulu_hat", /* CSTYLED */,
		tnf_int, ctx, zhat->zulu_ctx);

	mutex_enter(&zulu_ctx_lock);

	mutex_enter(&zhat->lock);
	if (zhat->zulu_ctx >= 0) {
		ZULU_CTX_SET_HAT(zhat->zulu_ctx, NULL);

		if (zulu_ctx_search_start > zhat->zulu_ctx) {
			zulu_ctx_search_start = zhat->zulu_ctx;
		}
	}
	mutex_exit(&zhat->lock);
	mutex_exit(&zulu_ctx_lock);
}

/*
 * Lock the zulu tsb for a given zulu_hat.
 *
 * We're just protecting against the TLB trap handler here. Other operations
 * on the zulu_hat require entering the zhat's lock.
 */
static void
zulu_ctx_tsb_lock_enter(struct zulu_hat *zhat)
{
	uint64_t	lck;
	uint64_t    	*plck;

	ASSERT(mutex_owned(&zhat->lock));

	if (zhat->zulu_ctx < 0) {
		return;
	}
	plck = (uint64_t *)&zulu_ctx_tab[zhat->zulu_ctx];

	for (; ; ) {
		lck = *plck;
		if (!(lck & ZULU_CTX_LOCK)) {
			uint64_t old_lck, new_lck;

			new_lck = lck | ZULU_CTX_LOCK;

			old_lck = atomic_cas_64(plck, lck, new_lck);

			if (old_lck == lck) {
				/*
				 * success
				 */
				break;
			}
		}
	}
}

static void
zulu_ctx_tsb_lock_exit(struct zulu_hat *zhat)
{
	uint64_t	lck;
	int		zulu_ctx = zhat->zulu_ctx;

	if (zulu_ctx < 0) {
		return;
	}
	lck = (uint64_t)zulu_ctx_tab[zulu_ctx];
	ASSERT(lck & ZULU_CTX_LOCK);
	lck &= ~ZULU_CTX_LOCK;
	zulu_ctx_tab[zulu_ctx] = (struct zulu_hat *)lck;
}

/*
 * Each zulu hat has a "shadow tree" which is a table of 4MB address regions
 * for which the zhat has mappings.
 *
 * This table is maintained in an avl tree.
 * Nodes in the tree are called shadow blocks (or sblks)
 *
 * This data structure allows unload operations by (address, range) to be
 * much more efficent.
 *
 * We get called a lot for address ranges that have never been supplied
 * to zulu.
 */

/*
 * compare the base address of two nodes in the shadow tree
 */
static int
zulu_shadow_tree_compare(const void *a, const void *b)
{
	struct zulu_shadow_blk *zba = (struct zulu_shadow_blk *)a;
	struct zulu_shadow_blk *zbb = (struct zulu_shadow_blk *)b;
	uint64_t		addr_a = zba->ivaddr;
	uint64_t		addr_b = zbb->ivaddr;

	TNF_PROBE_2(zulu_shadow_tree_compare, "zulu_shadow_tree", /* CSTYLED */,
		tnf_opaque, addr_a, addr_a, tnf_opaque, addr_b, addr_b);

	if (addr_a < addr_b) {
		return (-1);
	} else if (addr_a > addr_b) {
		return (1);
	} else {
		return (0);
	}
}

/*
 * lookup the entry in the shadow tree for a given virtual address
 */
static struct zulu_shadow_blk *
zulu_shadow_tree_lookup(struct zulu_hat *zhat, uint64_t ivaddr,
	avl_index_t *where)
{
	struct zulu_shadow_blk proto;
	struct zulu_shadow_blk *sblk;

	proto.ivaddr = ivaddr & ZULU_SHADOW_BLK_MASK;

	/*
	 * pages typically fault in in order so we cache the last shadow
	 * block that was referenced so we usually get to reduce calls to
	 * avl_find.
	 */
	if ((zhat->sblk_last != NULL) &&
	    (proto.ivaddr == zhat->sblk_last->ivaddr)) {
		sblk = zhat->sblk_last;
	} else {
		sblk = (struct zulu_shadow_blk *)avl_find(&zhat->shadow_tree,
		    &proto, where);
		zhat->sblk_last = sblk;
	}

	TNF_PROBE_2(zulu_shadow_tree_lookup, "zulu_shadow_tree", /* CSTYLED */,
	    tnf_opaque, ivaddr, proto.ivaddr,
	    tnf_opaque, where, where ? *where : ~0);

	return (sblk);
}

/*
 * insert a sblk into the shadow tree for a given zblk.
 * If a sblk already exists, just increment it's refcount.
 */
static void
zulu_shadow_tree_insert(struct zulu_hat *zhat, struct zulu_hat_blk *zblk)
{
	avl_index_t		where;
	struct zulu_shadow_blk 	*sblk  = NULL;
	uint64_t		ivaddr;
	uint64_t		end;

	ivaddr = zblk->zulu_hat_blk_vaddr & ZULU_SHADOW_BLK_MASK;

	end = zblk->zulu_hat_blk_vaddr + ZULU_HAT_PGSZ(zblk->zulu_hat_blk_size);

	sblk = zulu_shadow_tree_lookup(zhat, ivaddr, &where);
	if (sblk != NULL) {
		sblk->ref_count++;

		end = zblk->zulu_hat_blk_vaddr +
		    ZULU_HAT_PGSZ(zblk->zulu_hat_blk_size);
		if (zblk->zulu_hat_blk_vaddr < sblk->min_addr) {
			sblk->min_addr = zblk->zulu_hat_blk_vaddr;
		}
		/*
		 * a blk can set both the minimum and maximum when it
		 * is the first zblk added to a previously emptied sblk
		 */
		if (end > sblk->max_addr) {
			sblk->max_addr = end;
		}
	} else {
		sblk = kmem_zalloc(sizeof (*sblk), KM_SLEEP);
		sblk->ref_count = 1;
		sblk->ivaddr = ivaddr;
		sblk->min_addr = zblk->zulu_hat_blk_vaddr;
		sblk->max_addr = end;
		zhat->sblk_last = sblk;

		avl_insert(&zhat->shadow_tree, sblk, where);
	}
	zblk->zulu_shadow_blk = sblk;
	TNF_PROBE_2(zulu_shadow_tree_insert, "zulu_shadow_tree", /* CSTYLED */,
	    tnf_opaque, vaddr, ivaddr,
	    tnf_opaque, ref_count, sblk->ref_count);
}

/*
 * decrement the ref_count for the sblk that corresponds to a given zblk.
 * When the ref_count goes to zero remove the sblk from the tree and free it.
 */

static void
zulu_shadow_tree_delete(struct zulu_hat *zhat, struct zulu_hat_blk *zblk)
{
	struct zulu_shadow_blk 	*sblk;

	ASSERT(zblk->zulu_shadow_blk != NULL);

	sblk = zblk->zulu_shadow_blk;

	TNF_PROBE_2(zulu_shadow_tree_delete, "zulu_shadow_tree", /* CSTYLED */,
	    tnf_opaque, vaddr, sblk->ivaddr,
	    tnf_opaque, ref_count, sblk->ref_count-1);

	if (--sblk->ref_count == 0) {
		if (zhat->sblk_last == sblk) {
			zhat->sblk_last = NULL;
		}
		sblk->min_addr = sblk->ivaddr + ZULU_SHADOW_BLK_RANGE;
		sblk->max_addr = sblk->ivaddr;
	} else {
		/*
		 * Update the high and low water marks for this sblk.
		 * These are estimates, because we don't know if the previous
		 * or next region are actually occupied, but we can tell
		 * whether the previous values have become invalid.
		 *
		 * In the most often applied case a segment is being
		 * unloaded, and the min_addr will be kept up to date as
		 * the zblks are deleted in order.
		 */
		uint64_t end = zblk->zulu_hat_blk_vaddr +
		    ZULU_HAT_PGSZ(zblk->zulu_hat_blk_size);

		if (zblk->zulu_hat_blk_vaddr == sblk->min_addr) {
			sblk->min_addr = end;
		}
		if (end == sblk->max_addr) {
			sblk->max_addr = zblk->zulu_hat_blk_vaddr;
		}
	}

	zblk->zulu_shadow_blk = NULL;
}

static void
zulu_shadow_tree_destroy(struct zulu_hat *zhat)
{
	struct zulu_shadow_blk *sblk;
	void	*cookie = NULL;

	while ((sblk = (struct zulu_shadow_blk *)avl_destroy_nodes(
	    &zhat->shadow_tree, &cookie)) != NULL) {
		TNF_PROBE_2(shadow_tree_destroy, "zulu_hat", /* CSTYLED */,
		    tnf_opaque, vaddr, sblk->ivaddr,
		    tnf_opaque, ref_count, sblk->ref_count);
		kmem_free(sblk, sizeof (*sblk));
	}
	avl_destroy(&zhat->shadow_tree);
}

/*
 * zulu_hat_insert_map:
 *
 * Add a zulu_hat_blk to the a zhat's mappings list.
 *
 * Several data stuctures are used
 *	tsb: for simple fast lookups by the trap handler
 *	hash table: for efficent lookups by address, range
 *	An shadow tree of 4MB ranges with mappings for unloading big regions.
 */
static void
zulu_hat_insert_map(struct zulu_hat *zhat, struct zulu_hat_blk *zblk)
{
	int tsb_hash;

	tsb_hash = ZULU_TSB_HASH(zblk->zulu_hat_blk_vaddr,
	    zblk->zulu_hat_blk_size, zhat->zulu_tsb_size);

	TNF_PROBE_3(zulu_hat_insert_map, "zulu_hat", /* CSTYLED */,
	    tnf_opaque, zblkp, zblk,
	    tnf_opaque, vaddr, zblk->zulu_hat_blk_vaddr,
	    tnf_opaque, hash, tsb_hash);

	ASSERT(tsb_hash < zhat->zulu_tsb_size);

	zulu_shadow_tree_insert(zhat, zblk);

	/*
	 * The hash table is an array of buckets. Each bucket is the
	 * head of a linked list of mappings who's address hashess to the bucket
	 * New entries go to the head of the list.
	 */
	zblk->zulu_hash_prev = NULL;
	zblk->zulu_hash_next = ZULU_MAP_HASH_HEAD(zhat,
	    zblk->zulu_hat_blk_vaddr, zblk->zulu_hat_blk_size);
	if (zblk->zulu_hash_next) {
		zblk->zulu_hash_next->zulu_hash_prev = zblk;
	}
	ZULU_MAP_HASH_HEAD(zhat, zblk->zulu_hat_blk_vaddr,
	    zblk->zulu_hat_blk_size) = zblk;

	zulu_ctx_tsb_lock_enter(zhat);
	zhat->zulu_tsb[tsb_hash] = zblk->zulu_hat_blk_tte;
	zulu_ctx_tsb_lock_exit(zhat);
}

/*
 * remove a block from a zhat
 */
static void
zulu_hat_remove_map(struct zulu_hat *zhat, struct zulu_hat_blk *zblk)
{
	int tsb_hash = ZULU_TSB_HASH(zblk->zulu_hat_blk_vaddr,
	    zblk->zulu_hat_blk_size, zhat->zulu_tsb_size);

	TNF_PROBE_2(zulu_hat_remove_map, "zulu_hat", /* CSTYLED */,
	    tnf_opaque, vaddr, zblk->zulu_hat_blk_vaddr,
	    tnf_opaque, hash, tsb_hash);

	ASSERT(tsb_hash < zhat->zulu_tsb_size);
	ASSERT(mutex_owned(&zhat->lock));

	zulu_shadow_tree_delete(zhat, zblk);

	/*
	 * first remove zblk from hash table
	 */
	if (zblk->zulu_hash_prev) {
		zblk->zulu_hash_prev->zulu_hash_next = zblk->zulu_hash_next;
	} else {
		ZULU_MAP_HASH_HEAD(zhat, zblk->zulu_hat_blk_vaddr,
		    zblk->zulu_hat_blk_size) = NULL;
	}
	if (zblk->zulu_hash_next) {
		zblk->zulu_hash_next->zulu_hash_prev = zblk->zulu_hash_prev;
	}
	zblk->zulu_hash_next = NULL;
	zblk->zulu_hash_prev = NULL;

	/*
	 * then remove the tsb entry
	 */
	zulu_ctx_tsb_lock_enter(zhat);
	if (zhat->zulu_tsb[tsb_hash].un.zulu_tte_addr ==
	    zblk->zulu_hat_blk_vaddr) {
		zhat->zulu_tsb[tsb_hash].zulu_tte_valid = 0;
	}
	zulu_ctx_tsb_lock_exit(zhat);
}

/*
 * look for a mapping to a given vaddr and page size
 */
static struct zulu_hat_blk *
zulu_lookup_map_bysize(struct zulu_hat *zhat, caddr_t vaddr, int page_sz)
{
	struct  	zulu_hat_blk *zblkp;
	uint64_t	ivaddr = (uint64_t)vaddr;
	int		blks_checked = 0;

	ASSERT(mutex_owned(&zhat->lock));

	for (zblkp = ZULU_MAP_HASH_HEAD(zhat, ivaddr, page_sz); zblkp != NULL;
	    zblkp = zblkp->zulu_hash_next) {
		uint64_t	size;
		uint64_t	iaddr;

		blks_checked++;

		size = ZULU_HAT_PGSZ(zblkp->zulu_hat_blk_size);
		iaddr = ZULU_VADDR((uint64_t)zblkp->zulu_hat_blk_vaddr);

		if (iaddr <= ivaddr && (iaddr + size) > ivaddr) {
			int tsb_hash;

			tsb_hash = ZULU_TSB_HASH(zblkp->zulu_hat_blk_vaddr,
			    zblkp->zulu_hat_blk_size,
			    zhat->zulu_tsb_size);
			ASSERT(tsb_hash < zhat->zulu_tsb_size);

			zulu_ctx_tsb_lock_enter(zhat);
			zhat->zulu_tsb[tsb_hash] = zblkp->zulu_hat_blk_tte;
			zulu_ctx_tsb_lock_exit(zhat);
			break;
		}

	}

	TNF_PROBE_3(zulu_hat_lookup_map_bysz, "zulu_hat", /* CSTYLED */,
	    tnf_opaque, zblkp, zblkp,
	    tnf_int, blks_checked, blks_checked,
	    tnf_int, page_sz, page_sz);

	return (zblkp);
}

/*
 * Lookup a zblk for a given virtual address.
 */
static struct zulu_hat_blk *
zulu_lookup_map(struct zulu_hat *zhat, caddr_t vaddr)
{
	struct  	zulu_hat_blk *zblkp = NULL;

	/*
	 * if the hat is using 4M pages, look first for a 4M page
	 */
	if (zhat->map4m) {
		zblkp = zulu_lookup_map_bysize(zhat, vaddr, ZULU_TTE4M);
		if (zblkp != NULL) {
			return (zblkp);
		}
	}
	/*
	 * Otherwise look for a 8k page
	 * Note: if base pagesize gets increased to 64K remove this test
	 */
	if (zhat->map8k) {
		zblkp = zulu_lookup_map_bysize(zhat, vaddr, ZULU_TTE8K);
		if (zblkp != NULL) {
			return (zblkp);
		}
	}
	/*
	 * only if the page isn't found in the sizes that match the zulu mmus
	 * look for the inefficient 64K or 512K page sizes
	 */
	if (zhat->map64k) {
		zblkp = zulu_lookup_map_bysize(zhat, vaddr, ZULU_TTE64K);
		if (zblkp != NULL) {
			return (zblkp);
		}
	}
	if (zhat->map512k) {
		zblkp = zulu_lookup_map_bysize(zhat, vaddr, ZULU_TTE512K);
	}

	return (zblkp);
}

/*
 * zulu_hat_load: Load translation for given vaddr
 */
int
zulu_hat_load(struct zulu_hat *zhat, caddr_t vaddr,
		enum seg_rw rw, int *ppg_size)
{
	faultcode_t 		as_err;
	struct zulu_hat_blk 	*zblkp;
	int			rval;
	uint64_t 		flags_pfn;
	struct zulu_tte		tte;

	TNF_PROBE_2(zulu_hat_load, "zulu_hat", /* CSTYLED */,
	    tnf_int, zulu_ctx, zhat->zulu_ctx,
	    tnf_opaque, vaddr, vaddr);

	mutex_enter(&zhat->lock);
	ASSERT(zhat->zulu_ctx >= 0);
	/*
	 * lookup in our tsb first
	 */
	zulu_ctx_tsb_lock_enter(zhat);
	flags_pfn = zulu_hat_tsb_lookup_tl0(zhat, vaddr);
	zulu_ctx_tsb_lock_exit(zhat);

	if (flags_pfn) {
		uint64_t *p = (uint64_t *)&tte;

		p++; 			/* ignore the tag */
		*p = flags_pfn;		/* load the flags */

		zuluvm_load_tte(zhat, vaddr, flags_pfn, tte.zulu_tte_perm,
		    tte.zulu_tte_size);
		if (ppg_size != NULL) {
			*ppg_size = tte.zulu_tte_size;
		}

		zulu_tsb_hit++;
		mutex_exit(&zhat->lock);
		return (0);
	}

	zulu_tsb_miss++;

	zblkp = zulu_lookup_map(zhat, vaddr);
	if (zblkp) {
		tte = zblkp->zulu_hat_blk_tte;
		tte.zulu_tte_pfn = ZULU_HAT_ADJ_PFN((&tte), vaddr);
		zuluvm_load_tte(zhat, vaddr,  tte.zulu_tte_pfn,
		    tte.zulu_tte_perm, tte.zulu_tte_size);
		if (ppg_size != NULL) {
			*ppg_size = tte.zulu_tte_size;
		}
		mutex_exit(&zhat->lock);
		return (0);
	}

	/*
	 * Set a flag indicating that we're processing a fault.
	 * See comments in zulu_hat_unload_region.
	 */
	zhat->in_fault = 1;
	mutex_exit(&zhat->lock);

	zulu_as_fault++;
	TNF_PROBE_0(calling_as_fault, "zulu_hat", /* CSTYLED */);

	as_err = as_fault((struct hat *)zhat, zhat->zulu_xhat.xhat_as,
	    (caddr_t)(ZULU_VADDR((uint64_t)vaddr) & PAGEMASK),
	    PAGESIZE, F_INVAL, rw);

	mutex_enter(&zhat->lock);
	zhat->in_fault = 0;
	if (ppg_size != NULL) {
		/*
		 * caller wants to know the page size (used by preload)
		 */
		zblkp = zulu_lookup_map(zhat, vaddr);
		if (zblkp != NULL) {
			*ppg_size = zblkp->zulu_hat_blk_size;
		} else {
			*ppg_size = -1;
		}
	}
	mutex_exit(&zhat->lock);

	TNF_PROBE_1(as_fault_returned, "zulu_hat", /* CSTYLED */,
		tnf_int, as_err, as_err);

	if (as_err != 0) {
		printf("as_fault returned %d\n", as_err);
		rval = as_err;
	} else if (zhat->freed) {
		rval = -1;
	} else {
		rval = 0;
	}

	return (rval);
}

static struct xhat *
zulu_hat_alloc(void *arg)
{
	struct zulu_hat *zhat = kmem_zalloc(sizeof (struct zulu_hat), KM_SLEEP);

	(void) arg;

	zulu_hat_ctx_alloc(zhat);

	mutex_init(&zhat->lock, NULL, MUTEX_DEFAULT, NULL);

	zhat->zulu_tsb = kmem_zalloc(ZULU_TSB_SZ, KM_SLEEP);
	zhat->zulu_tsb_size = ZULU_TSB_NUM;
	zhat->hash_tbl = kmem_zalloc(ZULU_HASH_TBL_SZ, KM_SLEEP);
	avl_create(&zhat->shadow_tree, zulu_shadow_tree_compare,
	    sizeof (zhat->shadow_tree), ZULU_SHADOW_BLK_LINK_OFFSET);
	/*
	 * The zulu hat has a few opaque data structs embedded in it.
	 * This tag makes finding the our data easier with a debugger.
	 */
	zhat->magic = 0x42;

	zhat->freed = 0;
	TNF_PROBE_1(zulu_hat_alloc, "zulu_hat", /* CSTYLED */,
		tnf_int, zulu_ctx, zhat->zulu_ctx);
	return ((struct xhat *)zhat);
}

static void
zulu_hat_free(struct xhat *xhat)
{
	struct zulu_hat *zhat = (struct zulu_hat *)xhat;

	TNF_PROBE_1(zulu_hat_free, "zulu_hat", /* CSTYLED */,
		tnf_int, zulu_ctx, zhat->zulu_ctx);

	zulu_shadow_tree_destroy(zhat);
	kmem_free(zhat->hash_tbl, ZULU_HASH_TBL_SZ);
	kmem_free(zhat->zulu_tsb, ZULU_TSB_SZ);
	mutex_destroy(&zhat->lock);
	kmem_free(xhat, sizeof (struct zulu_hat));
}

static void
zulu_hat_free_start(struct xhat *xhat)
{
	struct zulu_hat *zhat = (struct zulu_hat *)xhat;

	TNF_PROBE_1(zulu_hat_free_start, "zulu_hat", /* CSTYLED */,
		tnf_int, zulu_ctx, zhat->zulu_ctx);
	(void) xhat;
}

/*
 * zulu_hat_memload: This is the callback where the vm system gives us our
 * translations
 */
static void
zulu_do_hat_memload(struct xhat *xhat, caddr_t vaddr, struct page *page,
    uint_t attr, uint_t flags, int use_pszc)
{
	void *blk;
	struct zulu_hat *zhat = (struct zulu_hat *)xhat;
	struct zulu_hat_blk *zblk;
	pfn_t pfn;

	TNF_PROBE_4(zulu_hat_memload, "zulu_hat", /* CSTYLED */,
	    tnf_int, zulu_ctx, zhat->zulu_ctx,
	    tnf_opaque, vaddr, vaddr, tnf_opaque, attr, attr,
	    tnf_opaque, flags, flags);

	/*
	 * keep track of the highest address that this zhat has had
	 * a mapping for.
	 * We use this in unload to avoid searching for regions that
	 * we've never seen.
	 *
	 * This is particularly useful avoiding repeated searches for
	 * for the process's mappings to the zulu hardware. These mappings
	 * are explicitly unloaded at each graphics context switch..
	 *
	 * This takes advantage of the fact that the device addresses
	 * are always above than the heap where most DMA data is stored.
	 */
	if (vaddr > zhat->vaddr_max) {
		zhat->vaddr_max = vaddr;
	}

	pfn = xhat_insert_xhatblk(page, xhat, &blk);
	zblk = (struct zulu_hat_blk *)blk;
	zblk->zulu_hat_blk_vaddr = (uintptr_t)vaddr;
	zblk->zulu_hat_blk_pfn = (uint_t)pfn;
	/*
	 * The perm bit is actually in the tte which gets copied to the TSB
	 */
	zblk->zulu_hat_blk_perm = (attr & PROT_WRITE) ? 1 : 0;
	zblk->zulu_hat_blk_size = use_pszc ? page->p_szc : 0;
	zblk->zulu_hat_blk_valid = 1;

	switch (zblk->zulu_hat_blk_size) {
	case	ZULU_TTE8K:
		zhat->map8k = 1;
		break;
	case	ZULU_TTE64K:
		zhat->map64k = 1;
		break;
	case	ZULU_TTE512K:
		zhat->map512k = 1;
		break;
	case	ZULU_TTE4M:
		zhat->map4m = 1;
		break;
	default:
		panic("zulu_hat illegal page size\n");
	}

	mutex_enter(&zhat->lock);

	zulu_hat_insert_map(zhat, zblk);
	if (!zhat->freed) {
		zuluvm_load_tte(zhat, vaddr, zblk->zulu_hat_blk_pfn,
		    zblk->zulu_hat_blk_perm, zblk->zulu_hat_blk_size);
	}
	zhat->fault_ivaddr_last =
	    ZULU_VADDR((uint64_t)zblk->zulu_hat_blk_vaddr);

	mutex_exit(&zhat->lock);
}

static void
zulu_hat_memload(struct xhat *xhat, caddr_t vaddr, struct page *page,
    uint_t attr, uint_t flags)
{
	zulu_do_hat_memload(xhat, vaddr, page, attr, flags, 0);
}

static void
zulu_hat_devload(struct xhat *xhat, caddr_t vaddr, size_t size, pfn_t pfn,
	uint_t attr, int flags)
{
	struct page *pp = page_numtopp_nolock(pfn);
	(void) size;
	zulu_do_hat_memload(xhat, vaddr, pp, attr, (uint_t)flags, 1);
}

static void
zulu_hat_memload_array(struct xhat *xhat, caddr_t addr, size_t len,
    struct page **gen_pps, uint_t attr, uint_t flags)
{
	struct zulu_hat *zhat = (struct zulu_hat *)xhat;

	TNF_PROBE_3(zulu_hat_memload_array, "zulu_hat", /* CSTYLED */,
	    tnf_int, zulu_ctx, zhat->zulu_ctx,
	    tnf_opaque, addr, addr,
	    tnf_opaque, len, len);

	for (; len > 0; len -= ZULU_HAT_PGSZ((*gen_pps)->p_szc),
	    gen_pps += ZULU_HAT_NUM_PGS((*gen_pps)->p_szc)) {
		zulu_do_hat_memload(xhat, addr, *gen_pps, attr, flags, 1);

		addr += ZULU_HAT_PGSZ((*gen_pps)->p_szc);
	}
}

static void
free_zblks(struct zulu_hat_blk *free_list)
{
	struct zulu_hat_blk *zblkp;
	struct zulu_hat_blk *next;

	for (zblkp = free_list; zblkp != NULL; zblkp = next) {
		next = zblkp->zulu_hash_next;
		(void) xhat_delete_xhatblk((struct xhat_hme_blk *)zblkp, 0);
	}
}

static void
add_to_free_list(struct zulu_hat_blk **pfree_list, struct zulu_hat_blk *zblk)
{
	zblk->zulu_hash_next = *pfree_list;
	*pfree_list = zblk;
}

static void
zulu_hat_unload_region(struct zulu_hat *zhat, uint64_t ivaddr, size_t size,
		struct zulu_shadow_blk *sblk, struct zulu_hat_blk **pfree_list)
{
	uint64_t	end = ivaddr + size;
	int		found = 0;

	TNF_PROBE_2(zulu_hat_unload_region, "zulu_hat", /* CSTYLED */,
		tnf_opaque, vaddr, ivaddr, tnf_opaque, size, size);

	/*
	 * check address against the low and highwater marks for mappings
	 * in this sblk
	 */
	if (ivaddr < sblk->min_addr) {
		ivaddr = sblk->min_addr;
		TNF_PROBE_1(zulu_hat_unload_skip, "zulu_hat", /* CSTYLED */,
			tnf_opaque, ivaddr, ivaddr);
	}
	if (end > sblk->max_addr) {
		end = sblk->max_addr;
		TNF_PROBE_1(zulu_hat_unload_reg_skip, "zulu_hat", /* CSTYLED */,
			tnf_opaque, end, end);
	}
	/*
	 * REMIND: It's not safe to touch the sblk after we enter this loop
	 * because it may get deleted.
	 */

	while (ivaddr < end) {
		uint64_t iaddr;
		size_t  pg_sz;
		struct zulu_hat_blk *zblkp;

		zblkp = zulu_lookup_map(zhat, (caddr_t)ivaddr);
		if (zblkp == NULL) {
			ivaddr += PAGESIZE;
			continue;
		}

		iaddr = ZULU_VADDR((uint64_t)zblkp->zulu_hat_blk_vaddr);
		pg_sz = ZULU_HAT_PGSZ(zblkp->zulu_hat_blk_size);

		found++;

		zulu_hat_remove_map(zhat, zblkp);
		/*
		 * skip demap page if as_free has already been entered
		 * zuluvm demapped the context already
		 */
		if (!zhat->freed) {
			if ((zhat->in_fault) &&
			    (iaddr == zhat->fault_ivaddr_last)) {
				/*
				 * We're being called from within as_fault to
				 * unload the last translation we loaded.
				 *
				 * This is probably due to watchpoint handling.
				 * Delay the demap for a millisecond
				 * to allow zulu to make some progress.
				 */
				drv_usecwait(1000);
				zhat->fault_ivaddr_last = 0;
			}
			zulu_hat_demap_page(zhat, (caddr_t)iaddr,
			    zblkp->zulu_hat_blk_size);
		}

		add_to_free_list(pfree_list, zblkp);

		if ((iaddr + pg_sz) >= end) {
			break;
		}

		ivaddr += pg_sz;
	}
	TNF_PROBE_1(zulu_hat_unload_region_done, "zulu_hat", /* CSTYLED */,
		tnf_opaque, found, found);
}

static void
zulu_hat_unload(struct xhat *xhat, caddr_t vaddr, size_t size, uint_t flags)
{
	struct zulu_hat *zhat = (struct zulu_hat *)xhat;
	uint64_t	ivaddr;
	uint64_t	end;
	int		found = 0;
	struct zulu_hat_blk *free_list = NULL;

	(void) flags;

	TNF_PROBE_4(zulu_hat_unload, "zulu_hat", /* CSTYLED */,
	    tnf_int, zulu_ctx, zhat->zulu_ctx,
	    tnf_opaque, vaddr, vaddr,
	    tnf_opaque, vaddr_max, zhat->vaddr_max,
	    tnf_opaque, size, size);

	mutex_enter(&zhat->lock);

	/*
	 * The following test prevents us from searching for the user's
	 * mappings to the zulu device registers. Those mappings get unloaded
	 * every time a graphics context switch away from a given context
	 * occurs.
	 *
	 * Since the heap is located at smaller virtual addresses than the
	 * registers, this simple test avoids quite a bit of useless work.
	 */
	if (vaddr > zhat->vaddr_max) {
		/*
		 * all existing mappings have lower addresses than vaddr
		 * no need to search further.
		 */
		mutex_exit(&zhat->lock);
		return;
	}

	ivaddr = (uint64_t)vaddr;
	end = ivaddr + size;

	do {
		struct zulu_shadow_blk *sblk;

		sblk = zulu_shadow_tree_lookup(zhat, ivaddr, NULL);
		if (sblk != NULL) {
			uint64_t 	sblk_end;
			size_t		region_size;

			found++;

			sblk_end = (ivaddr + ZULU_SHADOW_BLK_RANGE) &
			    ZULU_SHADOW_BLK_MASK;

			if (sblk_end < end) {
				region_size = sblk_end - ivaddr;
			} else {
				region_size = end - ivaddr;
			}
			zulu_hat_unload_region(zhat, ivaddr, region_size, sblk,
			    &free_list);

		}
		ivaddr += ZULU_SHADOW_BLK_RANGE;
	} while (ivaddr < end);

	mutex_exit(&zhat->lock);

	free_zblks(free_list);

	TNF_PROBE_1(zulu_hat_unload_done, "zulu_hat", /* CSTYLED */,
		tnf_int, found, found);
}

static void
zulu_hat_unload_callback(struct xhat *xhat, caddr_t vaddr, size_t size,
	uint_t flags, hat_callback_t *pcb)
{
	(void) size;
	(void) pcb;
	zulu_hat_unload(xhat, vaddr, size, flags);
}


/*
 * unload one page
 */
static int
zulu_hat_pageunload(struct xhat *xhat, struct page *pp, uint_t flags,
    void *xblk)
{
	struct zulu_hat_blk *zblk = (struct zulu_hat_blk *)xblk;
	struct zulu_hat *zhat = (struct zulu_hat *)xhat;
	int	do_delete;

	(void) pp;
	(void) flags;

	TNF_PROBE_3(zulu_hat_pageunload, "zulu_hat", /* CSTYLED */,
	    tnf_int, zulu_ctx, zhat->zulu_ctx,
	    tnf_opaque, vaddr, zblk->zulu_hat_blk_vaddr,
	    tnf_int, pg_size, zblk->zulu_hat_blk_size);

	mutex_enter(&zhat->lock);
	if (zblk->zulu_shadow_blk != NULL) {

		do_delete = 1;

		zulu_hat_remove_map(zhat, zblk);

		/*
		 * now that the entry is removed from the TSB, remove the
		 * translation from the zulu hardware.
		 *
		 * Skip the demap if this as is in the process of being freed.
		 * The zuluvm as callback has demapped the whole context.
		 */
		if (!zhat->freed) {
			zulu_hat_demap_page(zhat,
			    (caddr_t)(uintptr_t)(zblk->zulu_hat_blk_page <<
			    ZULU_HAT_BP_SHIFT),
			    zblk->zulu_hat_blk_size);
		}
	} else {
		/*
		 * This block has already been removed from the zulu_hat,
		 * it's on a free list waiting for our thread to release
		 * a mutex so it can be freed
		 */
		do_delete = 0;

		TNF_PROBE_0(zulu_hat_pageunload_skip, "zulu_hat",
		    /* CSTYLED */);
	}
	mutex_exit(&zhat->lock);

	if (do_delete) {
		(void) xhat_delete_xhatblk(xblk, 1);
	}

	return (0);
}

static void
zulu_hat_swapout(struct xhat *xhat)
{
	struct zulu_hat *zhat = (struct zulu_hat *)xhat;
	struct zulu_hat_blk *zblk;
	struct zulu_hat_blk *free_list = NULL;
	int	i;
	int	nblks = 0;

	TNF_PROBE_1(zulu_hat_swapout, "zulu_hat", /* CSTYLED */,
		tnf_int, zulu_ctx, zhat->zulu_ctx);

	mutex_enter(&zhat->lock);

	/*
	 * real swapout calls are rare so we don't do anything in
	 * particular to optimize them.
	 *
	 * Just loop over all buckets in the hash table and free each
	 * zblk.
	 */
	for (i = 0; i < ZULU_HASH_TBL_NUM; i++) {
		struct zulu_hat_blk *next;
		for (zblk = zhat->hash_tbl[i]; zblk != NULL; zblk = next) {
			next = zblk->zulu_hash_next;
			zulu_hat_remove_map(zhat, zblk);
			add_to_free_list(&free_list, zblk);
			nblks++;
		}
	}

	/*
	 * remove all mappings for this context from zulu hardware.
	 */
	zulu_hat_demap_ctx(zhat->zdev, zhat->zulu_ctx);

	mutex_exit(&zhat->lock);

	free_zblks(free_list);

	TNF_PROBE_1(zulu_hat_swapout_done, "zulu_hat", /* CSTYLED */,
		tnf_int, nblks, nblks);
}


static void
zulu_hat_unshare(struct xhat *xhat, caddr_t vaddr, size_t size)
{
	TNF_PROBE_0(zulu_hat_unshare, "zulu_hat", /* CSTYLED */);

	zulu_hat_unload(xhat, vaddr, size, 0);
}

/*
 * Functions to manage changes in protections for mappings.
 *
 * These are rarely called in normal operation so for now just unload
 * the region.
 * If the mapping is still needed, it will fault in later with the new
 * attrributes.
 */
typedef enum {
	ZULU_HAT_CHGATTR,
	ZULU_HAT_SETATTR,
	ZULU_HAT_CLRATTR
} zulu_hat_prot_op;

static void
zulu_hat_update_attr(struct xhat *xhat, caddr_t vaddr, size_t size,
	uint_t flags, zulu_hat_prot_op op)
{
	struct zulu_hat *zhat = (struct zulu_hat *)xhat;

	TNF_PROBE_5(zulu_hat_changeprot, "zulu_hat", /* CSTYLED */,
	    tnf_int, ctx, zhat->zulu_ctx,
	    tnf_opaque, vaddr, vaddr, tnf_opaque, size, size,
	    tnf_uint, flags, flags, tnf_int, op, op);

	zulu_hat_unload(xhat, vaddr, size, 0);
}

static void
zulu_hat_chgprot(struct xhat *xhat, caddr_t vaddr, size_t size, uint_t flags)
{
	struct zulu_hat *zhat = (struct zulu_hat *)xhat;
#ifdef DEBUG
	printf("zulu_hat_chgprot: ctx: %d addr: %lx, size: %lx flags: %x\n",
	    zhat->zulu_ctx, (uint64_t)vaddr, size, flags);
#endif
	zulu_hat_update_attr(xhat, vaddr, size, flags, ZULU_HAT_CHGATTR);
}


static void
zulu_hat_setattr(struct xhat *xhat, caddr_t vaddr, size_t size, uint_t flags)
{
	struct zulu_hat *zhat = (struct zulu_hat *)xhat;
#ifdef DEBUG
	printf("zulu_hat_setattr: ctx: %d addr: %lx, size: %lx flags: %x\n",
	    zhat->zulu_ctx, (uint64_t)vaddr, size, flags);
#endif
	zulu_hat_update_attr(xhat, vaddr, size, flags, ZULU_HAT_SETATTR);
}

static void
zulu_hat_clrattr(struct xhat *xhat, caddr_t vaddr, size_t size, uint_t flags)
{
	struct zulu_hat *zhat = (struct zulu_hat *)xhat;
#ifdef DEBUG
	printf("zulu_hat_clrattr: ctx: %d addr: %lx, size: %lx flags: %x\n",
	    zhat->zulu_ctx, (uint64_t)vaddr, size, flags);
#endif
	zulu_hat_update_attr(xhat, vaddr, size, flags, ZULU_HAT_CLRATTR);
}

static void
zulu_hat_chgattr(struct xhat *xhat, caddr_t vaddr, size_t size, uint_t flags)
{
	struct zulu_hat *zhat = (struct zulu_hat *)xhat;
	TNF_PROBE_3(zulu_hat_chgattr, "zulu_hat", /* CSTYLED */,
	    tnf_int, ctx, zhat->zulu_ctx,
	    tnf_opaque, vaddr, vaddr,
	    tnf_opaque, flags, flags);
#ifdef DEBUG
	printf("zulu_hat_chgattr: ctx: %d addr: %lx, size: %lx flags: %x\n",
	    zhat->zulu_ctx, (uint64_t)vaddr, size, flags);
#endif
	zulu_hat_update_attr(xhat, vaddr, size, flags, ZULU_HAT_CHGATTR);
}


struct xhat_ops zulu_hat_ops = {
	zulu_hat_alloc,		/* xhat_alloc */
	zulu_hat_free,		/* xhat_free */
	zulu_hat_free_start,	/* xhat_free_start */
	NULL,			/* xhat_free_end */
	NULL,			/* xhat_dup */
	NULL,			/* xhat_swapin */
	zulu_hat_swapout,	/* xhat_swapout */
	zulu_hat_memload,	/* xhat_memload */
	zulu_hat_memload_array,	/* xhat_memload_array */
	zulu_hat_devload,	/* xhat_devload */
	zulu_hat_unload,	/* xhat_unload */
	zulu_hat_unload_callback, /* xhat_unload_callback */
	zulu_hat_setattr,	/* xhat_setattr */
	zulu_hat_clrattr,	/* xhat_clrattr */
	zulu_hat_chgattr,	/* xhat_chgattr */
	zulu_hat_unshare,	/* xhat_unshare */
	zulu_hat_chgprot,	/* xhat_chgprot */
	zulu_hat_pageunload,	/* xhat_pageunload */
};

xblk_cache_t zulu_xblk_cache = {
    NULL,
    NULL,
    NULL,
    xhat_xblkcache_reclaim
};

xhat_provider_t zulu_hat_provider = {
	XHAT_PROVIDER_VERSION,
	0,
	NULL,
	NULL,
	"zulu_hat_provider",
	&zulu_xblk_cache,
	&zulu_hat_ops,
	sizeof (struct zulu_hat_blk) + sizeof (struct xhat_hme_blk)
};

/*
 * The following functions are the entry points that zuluvm uses.
 */

/*
 * initialize this module. Called from zuluvm's _init function
 */
int
zulu_hat_init()
{
	int 	c;
	int	rval;
	mutex_init(&zulu_ctx_lock, NULL, MUTEX_DEFAULT, NULL);

	for (c = 0; c < ZULU_HAT_MAX_CTX; c++) {
		ZULU_CTX_LOCK_INIT(c);
	}
	zulu_ctx_search_start = 0;
	rval = xhat_provider_register(&zulu_hat_provider);
	if (rval != 0) {
		mutex_destroy(&zulu_ctx_lock);
	}
	return (rval);
}

/*
 * un-initialize this module. Called from zuluvm's _fini function
 */
int
zulu_hat_destroy()
{
	if (xhat_provider_unregister(&zulu_hat_provider) != 0) {
		return (-1);
	}
	mutex_destroy(&zulu_ctx_lock);
	return (0);
}

int
zulu_hat_attach(void *arg)
{
	(void) arg;
	return (0);
}

int
zulu_hat_detach(void *arg)
{
	(void) arg;
	return (0);
}

/*
 * create a zulu hat for this address space.
 */
struct zulu_hat *
zulu_hat_proc_attach(struct as *as, void *zdev)
{
	struct zulu_hat *zhat;
	int		xhat_rval;

	xhat_rval = xhat_attach_xhat(&zulu_hat_provider, as,
	    (struct xhat **)&zhat, NULL);
	if ((xhat_rval == 0) && (zhat != NULL)) {
		mutex_enter(&zhat->lock);
		ZULU_HAT2AS(zhat) = as;
		zhat->zdev = zdev;
		mutex_exit(&zhat->lock);
	}

	TNF_PROBE_3(zulu_hat_proc_attach, "zulu_hat", /* CSTYLED */,
	    tnf_int, xhat_rval, xhat_rval, tnf_opaque, as, as,
	    tnf_opaque, zhat, zhat);

	return (zhat);
}

void
zulu_hat_proc_detach(struct zulu_hat *zhat)
{
	struct  as *as = ZULU_HAT2AS(zhat);

	zulu_hat_ctx_free(zhat);

	(void) xhat_detach_xhat(&zulu_hat_provider, ZULU_HAT2AS(zhat));

	TNF_PROBE_1(zulu_hat_proc_detach, "zulu_hat", /* CSTYLED */,
			tnf_opaque, as, as);
}

/*
 * zulu_hat_terminate
 *
 * Disables any further TLB miss processing for this hat
 * Called by zuluvm's as_free callback. The primary purpose of this
 * function is to cause any pending zulu DMA to abort quickly.
 */
void
zulu_hat_terminate(struct zulu_hat *zhat)
{
	int	ctx = zhat->zulu_ctx;

	TNF_PROBE_1(zulu_hat_terminate, "zulu_hat", /* CSTYLED */,
		tnf_int, ctx, ctx);

	mutex_enter(&zhat->lock);

	zhat->freed = 1;

	zulu_ctx_tsb_lock_enter(zhat);
	/*
	 * zap the tsb
	 */
	bzero(zhat->zulu_tsb, ZULU_TSB_SZ);
	zulu_ctx_tsb_lock_exit(zhat);

	zulu_hat_demap_ctx(zhat->zdev, zhat->zulu_ctx);

	mutex_exit(&zhat->lock);

	TNF_PROBE_0(zulu_hat_terminate_done, "zulu_hat", /* CSTYLED */);
}
