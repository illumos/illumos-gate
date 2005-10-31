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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/zfs_context.h>
#include <sys/spa_impl.h>
#include <sys/dmu.h>
#include <sys/dmu_tx.h>
#include <sys/space_map.h>
#include <sys/metaslab_impl.h>
#include <sys/vdev_impl.h>
#include <sys/zio.h>

/*
 * ==========================================================================
 * Metaslab classes
 * ==========================================================================
 */
metaslab_class_t *
metaslab_class_create(void)
{
	metaslab_class_t *mc;

	mc = kmem_zalloc(sizeof (metaslab_class_t), KM_SLEEP);

	mc->mc_rotor = NULL;

	return (mc);
}

void
metaslab_class_destroy(metaslab_class_t *mc)
{
	metaslab_group_t *mg;

	while ((mg = mc->mc_rotor) != NULL) {
		metaslab_class_remove(mc, mg);
		metaslab_group_destroy(mg);
	}

	kmem_free(mc, sizeof (metaslab_class_t));
}

void
metaslab_class_add(metaslab_class_t *mc, metaslab_group_t *mg)
{
	metaslab_group_t *mgprev, *mgnext;

	ASSERT(mg->mg_class == NULL);

	if ((mgprev = mc->mc_rotor) == NULL) {
		mg->mg_prev = mg;
		mg->mg_next = mg;
	} else {
		mgnext = mgprev->mg_next;
		mg->mg_prev = mgprev;
		mg->mg_next = mgnext;
		mgprev->mg_next = mg;
		mgnext->mg_prev = mg;
	}
	mc->mc_rotor = mg;
	mg->mg_class = mc;
}

void
metaslab_class_remove(metaslab_class_t *mc, metaslab_group_t *mg)
{
	metaslab_group_t *mgprev, *mgnext;

	ASSERT(mg->mg_class == mc);

	mgprev = mg->mg_prev;
	mgnext = mg->mg_next;

	if (mg == mgnext) {
		mc->mc_rotor = NULL;
	} else {
		mc->mc_rotor = mgnext;
		mgprev->mg_next = mgnext;
		mgnext->mg_prev = mgprev;
	}

	mg->mg_prev = NULL;
	mg->mg_next = NULL;
	mg->mg_class = NULL;
}

/*
 * ==========================================================================
 * Metaslab groups
 * ==========================================================================
 */
static int
metaslab_compare(const void *x1, const void *x2)
{
	const metaslab_t *m1 = x1;
	const metaslab_t *m2 = x2;

	if (m1->ms_weight < m2->ms_weight)
		return (1);
	if (m1->ms_weight > m2->ms_weight)
		return (-1);

	/*
	 * If the weights are identical, use the offset to force uniqueness.
	 */
	if (m1->ms_map.sm_start < m2->ms_map.sm_start)
		return (-1);
	if (m1->ms_map.sm_start > m2->ms_map.sm_start)
		return (1);

	ASSERT3P(m1, ==, m2);

	return (0);
}

metaslab_group_t *
metaslab_group_create(metaslab_class_t *mc, vdev_t *vd)
{
	metaslab_group_t *mg;

	mg = kmem_zalloc(sizeof (metaslab_group_t), KM_SLEEP);
	mutex_init(&mg->mg_lock, NULL, MUTEX_DEFAULT, NULL);
	avl_create(&mg->mg_metaslab_tree, metaslab_compare,
	    sizeof (metaslab_t), offsetof(struct metaslab, ms_group_node));
	mg->mg_aliquot = 2ULL << 20;		/* XXX -- tweak me */
	mg->mg_vd = vd;
	metaslab_class_add(mc, mg);

	return (mg);
}

void
metaslab_group_destroy(metaslab_group_t *mg)
{
	avl_destroy(&mg->mg_metaslab_tree);
	mutex_destroy(&mg->mg_lock);
	kmem_free(mg, sizeof (metaslab_group_t));
}

void
metaslab_group_add(metaslab_group_t *mg, metaslab_t *msp, uint64_t weight)
{
	mutex_enter(&mg->mg_lock);
	ASSERT(msp->ms_group == NULL);
	msp->ms_group = mg;
	msp->ms_weight = weight;
	avl_add(&mg->mg_metaslab_tree, msp);
	mutex_exit(&mg->mg_lock);
}

void
metaslab_group_remove(metaslab_group_t *mg, metaslab_t *msp)
{
	mutex_enter(&mg->mg_lock);
	ASSERT(msp->ms_group == mg);
	avl_remove(&mg->mg_metaslab_tree, msp);
	msp->ms_group = NULL;
	mutex_exit(&mg->mg_lock);
}

void
metaslab_group_sort(metaslab_group_t *mg, metaslab_t *msp, uint64_t weight)
{
	mutex_enter(&mg->mg_lock);
	ASSERT(msp->ms_group == mg);
	avl_remove(&mg->mg_metaslab_tree, msp);
	msp->ms_weight = weight;
	avl_add(&mg->mg_metaslab_tree, msp);
	mutex_exit(&mg->mg_lock);
}

/*
 * ==========================================================================
 * Metaslabs
 * ==========================================================================
 */
void
metaslab_init(metaslab_group_t *mg, space_map_obj_t *smo, metaslab_t **mspp,
	uint64_t start, uint64_t size, uint64_t txg)
{
	vdev_t *vd = mg->mg_vd;
	metaslab_t *msp;
	int fm;

	msp = kmem_zalloc(sizeof (metaslab_t), KM_SLEEP);

	msp->ms_smo = smo;

	space_map_create(&msp->ms_map, start, size, vd->vdev_ashift,
	    &msp->ms_lock);

	for (fm = 0; fm < TXG_SIZE; fm++) {
		space_map_create(&msp->ms_allocmap[fm], start, size,
		    vd->vdev_ashift, &msp->ms_lock);
		space_map_create(&msp->ms_freemap[fm], start, size,
		    vd->vdev_ashift, &msp->ms_lock);
	}

	/*
	 * If we're opening an existing pool (txg == 0) or creating
	 * a new one (txg == TXG_INITIAL), all space is available now.
	 * If we're adding space to an existing pool, the new space
	 * does not become available until after this txg has synced.
	 * We enforce this by assigning an initial weight of 0 to new space.
	 *
	 * (Transactional allocations for this txg would actually be OK;
	 * it's intent log allocations that cause trouble.  If we wrote
	 * a log block in this txg and lost power, the log replay would be
	 * based on the DVA translations that had been synced in txg - 1.
	 * Those translations would not include this metaslab's vdev.)
	 */
	metaslab_group_add(mg, msp, txg > TXG_INITIAL ? 0 : size);

	if (txg == 0) {
		/*
		 * We're opening the pool.  Make the metaslab's
		 * free space available immediately.
		 */
		vdev_space_update(vd, size, smo->smo_alloc);
		metaslab_sync_done(msp, 0);
	} else {
		/*
		 * We're adding a new metaslab to an already-open pool.
		 * Declare all of the metaslab's space to be free.
		 *
		 * Note that older transaction groups cannot allocate
		 * from this metaslab until its existence is committed,
		 * because we set ms_last_alloc to the current txg.
		 */
		smo->smo_alloc = 0;
		msp->ms_usable_space = size;
		mutex_enter(&msp->ms_lock);
		space_map_add(&msp->ms_map, start, size);
		msp->ms_map_incore = 1;
		mutex_exit(&msp->ms_lock);

		/* XXX -- we'll need a call to picker_init here */
		msp->ms_dirty[txg & TXG_MASK] |= MSD_ADD;
		msp->ms_last_alloc = txg;
		vdev_dirty(vd, VDD_ADD, txg);
		(void) txg_list_add(&vd->vdev_ms_list, msp, txg);
	}

	*mspp = msp;
}

void
metaslab_fini(metaslab_t *msp)
{
	int fm;
	metaslab_group_t *mg = msp->ms_group;

	vdev_space_update(mg->mg_vd, -msp->ms_map.sm_size,
	    -msp->ms_smo->smo_alloc);

	metaslab_group_remove(mg, msp);

	/* XXX -- we'll need a call to picker_fini here */

	mutex_enter(&msp->ms_lock);

	space_map_vacate(&msp->ms_map, NULL, NULL);
	msp->ms_map_incore = 0;
	space_map_destroy(&msp->ms_map);

	for (fm = 0; fm < TXG_SIZE; fm++) {
		space_map_destroy(&msp->ms_allocmap[fm]);
		space_map_destroy(&msp->ms_freemap[fm]);
	}

	mutex_exit(&msp->ms_lock);

	kmem_free(msp, sizeof (metaslab_t));
}

/*
 * Write a metaslab to disk in the context of the specified transaction group.
 */
void
metaslab_sync(metaslab_t *msp, uint64_t txg)
{
	vdev_t *vd = msp->ms_group->mg_vd;
	spa_t *spa = vd->vdev_spa;
	objset_t *os = spa->spa_meta_objset;
	space_map_t *allocmap = &msp->ms_allocmap[txg & TXG_MASK];
	space_map_t *freemap = &msp->ms_freemap[txg & TXG_MASK];
	space_map_t *freed_map = &msp->ms_freemap[TXG_CLEAN(txg) & TXG_MASK];
	space_map_obj_t *smo = msp->ms_smo;
	uint8_t *dirty = &msp->ms_dirty[txg & TXG_MASK];
	uint64_t alloc_delta;
	dmu_buf_t *db;
	dmu_tx_t *tx;

	dprintf("%s offset %llx\n", vdev_description(vd), msp->ms_map.sm_start);

	mutex_enter(&msp->ms_lock);

	if (*dirty & MSD_ADD)
		vdev_space_update(vd, msp->ms_map.sm_size, 0);

	if (*dirty & (MSD_ALLOC | MSD_FREE)) {
		tx = dmu_tx_create_assigned(spa_get_dsl(spa), txg);

		if (smo->smo_object == 0) {
			ASSERT(smo->smo_objsize == 0);
			ASSERT(smo->smo_alloc == 0);
			smo->smo_object = dmu_object_alloc(os,
			    DMU_OT_SPACE_MAP, 1 << SPACE_MAP_BLOCKSHIFT,
			    DMU_OT_SPACE_MAP_HEADER, sizeof (*smo), tx);
			ASSERT(smo->smo_object != 0);
			dmu_write(os, vd->vdev_ms_array, sizeof (uint64_t) *
			    (msp->ms_map.sm_start >> vd->vdev_ms_shift),
			    sizeof (uint64_t), &smo->smo_object, tx);
		}

		alloc_delta = allocmap->sm_space - freemap->sm_space;
		vdev_space_update(vd, 0, alloc_delta);
		smo->smo_alloc += alloc_delta;

		if (msp->ms_last_alloc == txg && msp->ms_map.sm_space == 0 &&
		    (*dirty & MSD_CONDENSE) == 0) {
			space_map_t *sm = &msp->ms_map;
			space_map_t *tsm;
			int i;

			ASSERT(msp->ms_map_incore);

			space_map_merge(freemap, freed_map);
			space_map_vacate(allocmap, NULL, NULL);

			/*
			 * Write out the current state of the allocation
			 * world.  The current metaslab is full, minus
			 * stuff that's been freed this txg (freed_map),
			 * minus allocations from txgs in the future.
			 */
			space_map_add(sm, sm->sm_start, sm->sm_size);
			for (i = 1; i < TXG_CONCURRENT_STATES; i++) {
				tsm = &msp->ms_allocmap[(txg + i) & TXG_MASK];
				space_map_iterate(tsm, space_map_remove, sm);
			}
			space_map_iterate(freed_map, space_map_remove, sm);

			space_map_write(sm, smo, os, tx);

			ASSERT(sm->sm_space == 0);
			ASSERT(freemap->sm_space == 0);
			ASSERT(allocmap->sm_space == 0);

			*dirty |= MSD_CONDENSE;
		} else {
			space_map_sync(allocmap, NULL, smo, SM_ALLOC, os, tx);
			space_map_sync(freemap, freed_map, smo, SM_FREE,
			    os, tx);
		}

		db = dmu_bonus_hold(os, smo->smo_object);
		dmu_buf_will_dirty(db, tx);
		ASSERT3U(db->db_size, ==, sizeof (*smo));
		bcopy(smo, db->db_data, db->db_size);
		dmu_buf_rele(db);

		dmu_tx_commit(tx);
	}

	*dirty &= ~(MSD_ALLOC | MSD_FREE | MSD_ADD);

	mutex_exit(&msp->ms_lock);

	(void) txg_list_add(&vd->vdev_ms_list, msp, TXG_CLEAN(txg));
}

/*
 * Called after a transaction group has completely synced to mark
 * all of the metaslab's free space as usable.
 */
void
metaslab_sync_done(metaslab_t *msp, uint64_t txg)
{
	uint64_t weight;
	uint8_t *dirty = &msp->ms_dirty[txg & TXG_MASK];
	space_map_obj_t *smo = msp->ms_smo;

	dprintf("%s offset %llx txg %llu\n",
	    vdev_description(msp->ms_group->mg_vd), msp->ms_map.sm_start, txg);

	mutex_enter(&msp->ms_lock);

	ASSERT3U((*dirty & (MSD_ALLOC | MSD_FREE | MSD_ADD)), ==, 0);

	msp->ms_usable_space = msp->ms_map.sm_size - smo->smo_alloc;
	msp->ms_usable_end = smo->smo_objsize;

	weight = msp->ms_usable_space;

	if (txg != 0) {
		space_map_t *freed_map =
		    &msp->ms_freemap[TXG_CLEAN(txg) & TXG_MASK];

		/* XXX -- we'll need a call to picker_fini here */

		/* If we're empty, don't bother sticking around */
		if (msp->ms_usable_space == 0) {
			space_map_vacate(&msp->ms_map, NULL, NULL);
			msp->ms_map_incore = 0;
			ASSERT3U(freed_map->sm_space, ==, 0);
			weight = 0;
		} else {
			/* Add the freed blocks to the available space map */
			if (msp->ms_map_incore)
				space_map_merge(freed_map, &msp->ms_map);
			else
				space_map_vacate(freed_map, NULL, NULL);
			weight += msp->ms_map.sm_size;
		}

		if (msp->ms_last_alloc == txg)
			/* Safe to use for allocation now */
			msp->ms_last_alloc = 0;

		*dirty = 0;
	}

	mutex_exit(&msp->ms_lock);

	metaslab_group_sort(msp->ms_group, msp, weight);
}

/*
 * The first-fit block picker.  No picker_init or picker_fini,
 * this is just an experiment to see how it feels to separate out
 * the block selection policy from the map updates.
 * Note: the 'cursor' argument is a form of PPD.
 */
static uint64_t
metaslab_pick_block(space_map_t *sm, uint64_t size, uint64_t *cursor)
{
	avl_tree_t *t = &sm->sm_root;
	uint64_t align = size & -size;
	space_seg_t *ss, ssearch;
	avl_index_t where;
	int tried_once = 0;

again:
	ssearch.ss_start = *cursor;
	ssearch.ss_end = *cursor + size;

	ss = avl_find(t, &ssearch, &where);
	if (ss == NULL)
		ss = avl_nearest(t, where, AVL_AFTER);

	while (ss != NULL) {
		uint64_t offset = P2ROUNDUP(ss->ss_start, align);

		if (offset + size <= ss->ss_end) {
			*cursor = offset + size;
			return (offset);
		}
		ss = AVL_NEXT(t, ss);
	}

	/* If we couldn't find a block after cursor, search again */
	if (tried_once == 0) {
		tried_once = 1;
		*cursor = 0;
		goto again;
	}

	return (-1ULL);
}

static uint64_t
metaslab_getblock(metaslab_t *msp, uint64_t size, uint64_t txg)
{
	space_map_t *sm = &msp->ms_map;
	vdev_t *vd = msp->ms_group->mg_vd;
	uint64_t offset;

	ASSERT(MUTEX_HELD(&msp->ms_lock));
	ASSERT(msp->ms_map_incore);
	ASSERT(sm->sm_space != 0);
	ASSERT(P2PHASE(size, 1ULL << vd->vdev_ashift) == 0);

	offset = metaslab_pick_block(sm, size,
	    &msp->ms_map_cursor[highbit(size & -size) - vd->vdev_ashift - 1]);
	if (offset != -1ULL) {
		space_map_remove(sm, offset, size);
		space_map_add(&msp->ms_allocmap[txg & TXG_MASK], offset, size);
	}
	return (offset);
}

/*
 * Intent log support: upon opening the pool after a crash, notify the SPA
 * of blocks that the intent log has allocated for immediate write, but
 * which are still considered free by the SPA because the last transaction
 * group didn't commit yet.
 */
int
metaslab_claim(spa_t *spa, dva_t *dva, uint64_t txg)
{
	uint64_t vdev = DVA_GET_VDEV(dva);
	uint64_t offset = DVA_GET_OFFSET(dva);
	uint64_t size = DVA_GET_ASIZE(dva);
	objset_t *os = spa->spa_meta_objset;
	vdev_t *vd;
	metaslab_t *msp;
	space_map_t *sm;
	space_map_obj_t *smo;
	int error;

	if ((vd = vdev_lookup_top(spa, vdev)) == NULL)
		return (ENXIO);

	if ((offset >> vd->vdev_ms_shift) >= vd->vdev_ms_count)
		return (ENXIO);

	msp = vd->vdev_ms[offset >> vd->vdev_ms_shift];
	sm = &msp->ms_map;
	smo = msp->ms_smo;

	if (DVA_GET_GANG(dva))
		size = vdev_psize_to_asize(vd, SPA_GANGBLOCKSIZE);

	mutex_enter(&msp->ms_lock);

	if (msp->ms_map_incore == 0) {
		error = space_map_load(sm, smo, SM_FREE, os,
		    msp->ms_usable_end, sm->sm_size - msp->ms_usable_space);
		ASSERT(error == 0);
		if (error) {
			mutex_exit(&msp->ms_lock);
			return (error);
		}
		msp->ms_map_incore = 1;
		/* XXX -- we'll need a call to picker_init here */
		bzero(msp->ms_map_cursor, sizeof (msp->ms_map_cursor));
	}

	space_map_remove(sm, offset, size);
	space_map_add(&msp->ms_allocmap[txg & TXG_MASK], offset, size);

	if ((msp->ms_dirty[txg & TXG_MASK] & MSD_ALLOC) == 0) {
		msp->ms_dirty[txg & TXG_MASK] |= MSD_ALLOC;
		msp->ms_last_alloc = txg;
		vdev_dirty(vd, VDD_ALLOC, txg);
		(void) txg_list_add(&vd->vdev_ms_list, msp, txg);
	}

	mutex_exit(&msp->ms_lock);

	return (0);
}

static int
metaslab_usable(metaslab_t *msp, uint64_t size, uint64_t txg)
{
	/*
	 * Enforce segregation across transaction groups.
	 */
	/* XXX -- We should probably not assume we know what ms_weight means */
	if (msp->ms_last_alloc == txg)
		return (msp->ms_map.sm_space >= size && msp->ms_weight >= size);

	if (msp->ms_last_alloc != 0)
		return (0);

	if (msp->ms_map.sm_space >= size && msp->ms_weight >= size)
		return (1);

	/* XXX -- the weight test should be in terms of MINFREE */
	return (msp->ms_usable_space >= size && msp->ms_weight >= size);
}

static metaslab_t *
metaslab_pick(metaslab_group_t *mg, uint64_t size, uint64_t txg)
{
	metaslab_t *msp;
	avl_tree_t *t = &mg->mg_metaslab_tree;

	mutex_enter(&mg->mg_lock);
	for (msp = avl_first(t); msp != NULL; msp = AVL_NEXT(t, msp))
		if (metaslab_usable(msp, size, txg))
			break;
	mutex_exit(&mg->mg_lock);

	return (msp);
}

static metaslab_t *
metaslab_group_alloc(spa_t *spa, metaslab_group_t *mg, uint64_t size,
    uint64_t *offp, uint64_t txg)
{
	metaslab_t *msp;
	int error;

	while ((msp = metaslab_pick(mg, size, txg)) != NULL) {
		space_map_obj_t *smo = msp->ms_smo;
		mutex_enter(&msp->ms_lock);
		if (!metaslab_usable(msp, size, txg)) {
			mutex_exit(&msp->ms_lock);
			continue;
		}
		if (msp->ms_map_incore == 0) {
			error = space_map_load(&msp->ms_map, smo, SM_FREE,
			    spa->spa_meta_objset, msp->ms_usable_end,
			    msp->ms_map.sm_size - msp->ms_usable_space);
			ASSERT(error == 0);
			if (error) {
				mutex_exit(&msp->ms_lock);
				metaslab_group_sort(mg, msp, 0);
				continue;
			}
			msp->ms_map_incore = 1;
			/* XXX -- we'll need a call to picker_init here */
			bzero(msp->ms_map_cursor, sizeof (msp->ms_map_cursor));
		}
		*offp = metaslab_getblock(msp, size, txg);
		if (*offp != -1ULL) {
			if ((msp->ms_dirty[txg & TXG_MASK] & MSD_ALLOC) == 0) {
				vdev_t *vd = mg->mg_vd;
				msp->ms_dirty[txg & TXG_MASK] |= MSD_ALLOC;
				msp->ms_last_alloc = txg;
				vdev_dirty(vd, VDD_ALLOC, txg);
				(void) txg_list_add(&vd->vdev_ms_list,
				    msp, txg);
			}
			mutex_exit(&msp->ms_lock);
			return (msp);
		}
		mutex_exit(&msp->ms_lock);
		metaslab_group_sort(msp->ms_group, msp, size - 1);
	}

	return (NULL);
}

/*
 * Allocate a block for the specified i/o.
 */
int
metaslab_alloc(spa_t *spa, uint64_t psize, dva_t *dva, uint64_t txg)
{
	metaslab_t *msp;
	metaslab_group_t *mg, *rotor;
	metaslab_class_t *mc;
	vdev_t *vd;
	uint64_t offset = -1ULL;
	uint64_t asize;

	mc = spa_metaslab_class_select(spa);

	/*
	 * Start at the rotor and loop through all mgs until we find something.
	 * Note that there's no locking on mc_rotor or mc_allocated because
	 * nothing actually breaks if we miss a few updates -- we just won't
	 * allocate quite as evenly.  It all balances out over time.
	 */
	mg = rotor = mc->mc_rotor;
	do {
		vd = mg->mg_vd;
		asize = vdev_psize_to_asize(vd, psize);
		ASSERT(P2PHASE(asize, 1ULL << vd->vdev_ashift) == 0);

		msp = metaslab_group_alloc(spa, mg, asize, &offset, txg);
		if (msp != NULL) {
			ASSERT(offset != -1ULL);

			/*
			 * If we've just selected this metaslab group,
			 * figure out whether the corresponding vdev is
			 * over- or under-used relative to the pool,
			 * and set an allocation bias to even it out.
			 */
			if (mc->mc_allocated == 0) {
				vdev_stat_t *vs = &vd->vdev_stat;
				uint64_t alloc, space;
				int64_t vu, su;

				alloc = spa_get_alloc(spa);
				space = spa_get_space(spa);

				/*
				 * Determine percent used in units of 0..1024.
				 * (This is just to avoid floating point.)
				 */
				vu = (vs->vs_alloc << 10) / (vs->vs_space + 1);
				su = (alloc << 10) / (space + 1);

				/*
				 * Bias by at most +/- 25% of the aliquot.
				 */
				mg->mg_bias = ((su - vu) *
				    (int64_t)mg->mg_aliquot) / (1024 * 4);

				dprintf("bias = %lld\n", mg->mg_bias);
			}

			if (atomic_add_64_nv(&mc->mc_allocated, asize) >=
			    mg->mg_aliquot + mg->mg_bias) {
				mc->mc_rotor = mg->mg_next;
				mc->mc_allocated = 0;
			}

			DVA_SET_VDEV(dva, vd->vdev_id);
			DVA_SET_OFFSET(dva, offset);
			DVA_SET_GANG(dva, 0);
			DVA_SET_ASIZE(dva, asize);

			return (0);
		}
		mc->mc_rotor = mg->mg_next;
		mc->mc_allocated = 0;
	} while ((mg = mg->mg_next) != rotor);

	dprintf("spa=%p, psize=%llu, txg=%llu: no\n", spa, psize, txg);

	DVA_SET_VDEV(dva, 0);
	DVA_SET_OFFSET(dva, 0);
	DVA_SET_GANG(dva, 0);

	return (ENOSPC);
}

/*
 * Free the block represented by DVA in the context of the specified
 * transaction group.
 */
void
metaslab_free(spa_t *spa, dva_t *dva, uint64_t txg)
{
	uint64_t vdev = DVA_GET_VDEV(dva);
	uint64_t offset = DVA_GET_OFFSET(dva);
	uint64_t size = DVA_GET_ASIZE(dva);
	vdev_t *vd;
	metaslab_t *msp;

	if (txg > spa_freeze_txg(spa))
		return;

	if ((vd = vdev_lookup_top(spa, vdev)) == NULL) {
		cmn_err(CE_WARN, "metaslab_free(): bad vdev %llu",
		    (u_longlong_t)vdev);
		ASSERT(0);
		return;
	}

	if ((offset >> vd->vdev_ms_shift) >= vd->vdev_ms_count) {
		cmn_err(CE_WARN, "metaslab_free(): bad offset %llu",
		    (u_longlong_t)offset);
		ASSERT(0);
		return;
	}

	msp = vd->vdev_ms[offset >> vd->vdev_ms_shift];

	if (DVA_GET_GANG(dva))
		size = vdev_psize_to_asize(vd, SPA_GANGBLOCKSIZE);

	mutex_enter(&msp->ms_lock);

	if ((msp->ms_dirty[txg & TXG_MASK] & MSD_FREE) == 0) {
		msp->ms_dirty[txg & TXG_MASK] |= MSD_FREE;
		vdev_dirty(vd, VDD_FREE, txg);
		(void) txg_list_add(&vd->vdev_ms_list, msp, txg);
	}

	space_map_add(&msp->ms_freemap[txg & TXG_MASK], offset, size);

	mutex_exit(&msp->ms_lock);
}
