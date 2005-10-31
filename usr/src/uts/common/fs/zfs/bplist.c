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

#include <sys/bplist.h>
#include <sys/zfs_context.h>

static void
bplist_hold(bplist_t *bpl)
{
	ASSERT(MUTEX_HELD(&bpl->bpl_lock));
	if (bpl->bpl_dbuf == NULL) {
		bpl->bpl_dbuf = dmu_bonus_hold_tag(bpl->bpl_mos,
		    bpl->bpl_object, bpl);
		dmu_buf_read(bpl->bpl_dbuf);
		bpl->bpl_phys = bpl->bpl_dbuf->db_data;
	}
}

uint64_t
bplist_create(objset_t *mos, int blocksize, dmu_tx_t *tx)
{
	uint64_t obj;

	obj = dmu_object_alloc(mos, DMU_OT_BPLIST, blocksize,
	    DMU_OT_BPLIST_HDR, sizeof (bplist_phys_t), tx);

	return (obj);
}

void
bplist_destroy(objset_t *mos, uint64_t object, dmu_tx_t *tx)
{
	VERIFY(dmu_object_free(mos, object, tx) == 0);
}

void
bplist_open(bplist_t *bpl, objset_t *mos, uint64_t object)
{
	dmu_object_info_t doi;

	VERIFY(dmu_object_info(mos, object, &doi) == 0);

	mutex_enter(&bpl->bpl_lock);

	ASSERT(bpl->bpl_dbuf == NULL);
	ASSERT(bpl->bpl_phys == NULL);
	ASSERT(bpl->bpl_cached_dbuf == NULL);
	ASSERT(bpl->bpl_queue == NULL);
	ASSERT(object != 0);

	bpl->bpl_mos = mos;
	bpl->bpl_object = object;
	bpl->bpl_blockshift = highbit(doi.doi_data_block_size - 1);
	bpl->bpl_bpshift = bpl->bpl_blockshift - SPA_BLKPTRSHIFT;

	mutex_exit(&bpl->bpl_lock);
}

void
bplist_close(bplist_t *bpl)
{
	mutex_enter(&bpl->bpl_lock);

	ASSERT(bpl->bpl_queue == NULL);

	if (bpl->bpl_cached_dbuf) {
		dmu_buf_rele(bpl->bpl_cached_dbuf);
		bpl->bpl_cached_dbuf = NULL;
	}
	if (bpl->bpl_dbuf) {
		dmu_buf_rele_tag(bpl->bpl_dbuf, bpl);
		bpl->bpl_dbuf = NULL;
		bpl->bpl_phys = NULL;
	}

	mutex_exit(&bpl->bpl_lock);
}

boolean_t
bplist_empty(bplist_t *bpl)
{
	boolean_t rv;

	if (bpl->bpl_object == 0)
		return (B_TRUE);

	mutex_enter(&bpl->bpl_lock);
	bplist_hold(bpl);
	rv = (bpl->bpl_phys->bpl_entries == 0);
	mutex_exit(&bpl->bpl_lock);

	return (rv);
}

int
bplist_iterate(bplist_t *bpl, uint64_t *itorp, blkptr_t *bp)
{
	uint64_t blk, off;
	blkptr_t *bparray;
	dmu_buf_t *db;

	mutex_enter(&bpl->bpl_lock);
	bplist_hold(bpl);

	if (*itorp >= bpl->bpl_phys->bpl_entries) {
		mutex_exit(&bpl->bpl_lock);
		return (ENOENT);
	}

	blk = *itorp >> bpl->bpl_bpshift;
	off = P2PHASE(*itorp, 1ULL << bpl->bpl_bpshift);
	db = bpl->bpl_cached_dbuf;

	if (db == NULL || db->db_offset != (blk << bpl->bpl_blockshift)) {
		if (db != NULL)
			dmu_buf_rele(db);
		bpl->bpl_cached_dbuf = db = dmu_buf_hold(bpl->bpl_mos,
		    bpl->bpl_object, blk << bpl->bpl_blockshift);
	}

	ASSERT3U(db->db_size, ==, 1ULL << bpl->bpl_blockshift);

	dmu_buf_read(db);
	bparray = db->db_data;
	*bp = bparray[off];
	(*itorp)++;
	mutex_exit(&bpl->bpl_lock);
	return (0);
}

void
bplist_enqueue(bplist_t *bpl, blkptr_t *bp, dmu_tx_t *tx)
{
	uint64_t blk, off;
	blkptr_t *bparray;
	dmu_buf_t *db;

	ASSERT(!BP_IS_HOLE(bp));
	mutex_enter(&bpl->bpl_lock);
	bplist_hold(bpl);

	blk = bpl->bpl_phys->bpl_entries >> bpl->bpl_bpshift;
	off = P2PHASE(bpl->bpl_phys->bpl_entries, 1ULL << bpl->bpl_bpshift);
	db = bpl->bpl_cached_dbuf;

	if (db == NULL || db->db_offset != (blk << bpl->bpl_blockshift)) {
		if (db != NULL)
			dmu_buf_rele(db);
		bpl->bpl_cached_dbuf = db = dmu_buf_hold(bpl->bpl_mos,
		    bpl->bpl_object, blk << bpl->bpl_blockshift);
	}

	ASSERT3U(db->db_size, ==, 1ULL << bpl->bpl_blockshift);

	dmu_buf_will_dirty(db, tx);
	bparray = db->db_data;
	bparray[off] = *bp;

	/* We never need the fill count. */
	bparray[off].blk_fill = 0;

	/* The bplist will compress better if we can leave off the checksum */
	bzero(&bparray[off].blk_cksum, sizeof (bparray[off].blk_cksum));

	dmu_buf_will_dirty(bpl->bpl_dbuf, tx);
	bpl->bpl_phys->bpl_entries++;
	bpl->bpl_phys->bpl_bytes += BP_GET_ASIZE(bp);
	mutex_exit(&bpl->bpl_lock);
}

/*
 * Deferred entry; will be written later by bplist_sync().
 */
void
bplist_enqueue_deferred(bplist_t *bpl, blkptr_t *bp)
{
	bplist_q_t *bpq = kmem_alloc(sizeof (*bpq), KM_SLEEP);

	ASSERT(!BP_IS_HOLE(bp));
	mutex_enter(&bpl->bpl_lock);
	bpq->bpq_blk = *bp;
	bpq->bpq_next = bpl->bpl_queue;
	bpl->bpl_queue = bpq;
	mutex_exit(&bpl->bpl_lock);
}

void
bplist_sync(bplist_t *bpl, dmu_tx_t *tx)
{
	bplist_q_t *bpq;

	mutex_enter(&bpl->bpl_lock);
	while ((bpq = bpl->bpl_queue) != NULL) {
		bpl->bpl_queue = bpq->bpq_next;
		mutex_exit(&bpl->bpl_lock);
		bplist_enqueue(bpl, &bpq->bpq_blk, tx);
		kmem_free(bpq, sizeof (*bpq));
		mutex_enter(&bpl->bpl_lock);
	}
	mutex_exit(&bpl->bpl_lock);
}

void
bplist_vacate(bplist_t *bpl, dmu_tx_t *tx)
{
	mutex_enter(&bpl->bpl_lock);
	ASSERT3P(bpl->bpl_queue, ==, NULL);
	bplist_hold(bpl);
	dmu_buf_will_dirty(bpl->bpl_dbuf, tx);
	dmu_free_range(bpl->bpl_mos, bpl->bpl_object, 0, -1ULL, tx);
	bpl->bpl_phys->bpl_entries = 0;
	bpl->bpl_phys->bpl_bytes = 0;
	mutex_exit(&bpl->bpl_lock);
}
