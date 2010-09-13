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

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/mman.h>
#include <vm/hat_sfmmu.h>
#include <vm/xhat.h>
#include <vm/xhat_sfmmu.h>
#include <vm/page.h>
#include <vm/as.h>



/*
 * Allocates a block that includes both struct xhat and
 * provider-specific data.
 */
struct xhat_hme_blk *
xhat_alloc_xhatblk(struct xhat *xhat)
{
	struct xhat_hme_blk *xblk;
	xblk_cache_t	*xblkcache = xhat->xhat_provider->xblkcache;



	mutex_enter(&xblkcache->lock);
	if (xblkcache->free_blks) {
		xblk = (struct xhat_hme_blk *)
		    sfmmu_hmetohblk(xblkcache->free_blks);

		/*
		 * Since we are always walking the list in the
		 * forward direction, we don't update prev pointers
		 */
		xblkcache->free_blks = xblk->xblk_hme[0].hme_next;
		mutex_exit(&xblkcache->lock);
	} else {
		mutex_exit(&xblkcache->lock);
		xblk = kmem_cache_alloc(xblkcache->cache, KM_SLEEP);
	}

	return (xblk);
}


/*
 * Return the block to free_blks pool. The memory will
 * be freed in the reclaim routine.
 */
void
xhat_free_xhatblk(struct xhat_hme_blk *xblk)
{
	xblk_cache_t	*xblkcache = xblk->xhat_hme_blk_hat->
	    xhat_provider->xblkcache;


	mutex_enter(&xblkcache->lock);
	xblk->xblk_hme[0].hme_next = xblkcache->free_blks;
	xblkcache->free_blks = &xblk->xblk_hme[0];
	mutex_exit(&xblkcache->lock);
}


/*
 * Ran by kmem reaper thread. Also called when
 * provider unregisters
 */
void
xhat_xblkcache_reclaim(void *arg)
{
	xhat_provider_t *provider = (xhat_provider_t *)arg;
	struct sf_hment	*sfhme;
	struct xhat_hme_blk	*xblk;
	xblk_cache_t	*xblkcache;

	if (provider == NULL)
		cmn_err(CE_PANIC, "xhat_xblkcache_reclaim() is passed NULL");

	xblkcache = provider->xblkcache;


	while (xblkcache->free_blks != NULL) {

		/*
		 * Put free blocks on a separate list
		 * and free free_blks pointer.
		 */
		mutex_enter(&xblkcache->lock);
		sfhme = xblkcache->free_blks;
		xblkcache->free_blks = NULL;
		mutex_exit(&xblkcache->lock);

		while (sfhme != NULL) {
			xblk = (struct xhat_hme_blk *)sfmmu_hmetohblk(sfhme);
			ASSERT(xblk->xhat_hme_blk_misc.xhat_bit == 1);
			sfhme = sfhme->hme_next;
			kmem_cache_free(xblkcache->cache, xblk);
		}
	}
}




/*
 * Insert the xhat block (or, more precisely, the sf_hment)
 * into page's p_mapping list.
 */
pfn_t
xhat_insert_xhatblk(page_t *pp, struct xhat *xhat, void **blk)
{
	kmutex_t *pml;
	pfn_t pfn;
	struct xhat_hme_blk *xblk;



	xblk = xhat_alloc_xhatblk(xhat);
	if (xblk == NULL)
		return (0);

	/* Add a "user" to the XHAT */
	xhat_hat_hold(xhat);

	xblk->xhat_hme_blk_hat = xhat;
	xblk->xhat_hme_blk_misc.xhat_bit = 1;

	pml = sfmmu_mlist_enter(pp);


	/* Insert at the head of p_mapping list */
	xblk->xblk_hme[0].hme_prev = NULL;
	xblk->xblk_hme[0].hme_next = pp->p_mapping;
	xblk->xblk_hme[0].hme_page = pp;

	/* Only one tte per xhat_hme_blk, at least for now */
	xblk->xblk_hme[0].hme_tte.tte_hmenum = 0;

	if (pp->p_mapping) {
		((struct sf_hment *)(pp->p_mapping))->hme_prev =
		    &(xblk->xblk_hme[0]);
		ASSERT(pp->p_share > 0);
	} else	{
		/* EMPTY */
		ASSERT(pp->p_share == 0);
	}
	pp->p_mapping = &(xblk->xblk_hme[0]);

	/*
	 * Update number of mappings.
	 */
	pp->p_share++;
	pfn = pp->p_pagenum;

	sfmmu_mlist_exit(pml);

	*blk = XBLK2PROVBLK(xblk);

	return (pfn);
}


/*
 * mlist_locked indicates whether the mapping list
 * is locked. If provider did not lock it himself, the
 * only time it is locked in HAT layer is in
 * hat_pageunload().
 */
int
xhat_delete_xhatblk(void *blk, int mlist_locked)
{
	struct xhat_hme_blk *xblk = PROVBLK2XBLK(blk);
	page_t *pp = xblk->xblk_hme[0].hme_page;
	kmutex_t *pml;


	ASSERT(pp != NULL);
	ASSERT(pp->p_share > 0);

	if (!mlist_locked)
		pml = sfmmu_mlist_enter(pp);
	else
		ASSERT(sfmmu_mlist_held(pp));

	pp->p_share--;

	if (xblk->xblk_hme[0].hme_prev) {
		ASSERT(pp->p_mapping != &(xblk->xblk_hme[0]));
		ASSERT(xblk->xblk_hme[0].hme_prev->hme_page == pp);
		xblk->xblk_hme[0].hme_prev->hme_next =
		    xblk->xblk_hme[0].hme_next;
	} else {
		ASSERT(pp->p_mapping == &(xblk->xblk_hme[0]));
		pp->p_mapping = xblk->xblk_hme[0].hme_next;
		ASSERT((pp->p_mapping == NULL) ?
			(pp->p_share == 0) : 1);
	}

	if (xblk->xblk_hme->hme_next) {
		ASSERT(xblk->xblk_hme[0].hme_next->hme_page == pp);
		xblk->xblk_hme[0].hme_next->hme_prev =
		    xblk->xblk_hme[0].hme_prev;
	}

	if (!mlist_locked)
		sfmmu_mlist_exit(pml);

	xhat_hat_rele(xblk->xhat_hme_blk_hat);
	xhat_free_xhatblk(xblk);


	return (0);
}
