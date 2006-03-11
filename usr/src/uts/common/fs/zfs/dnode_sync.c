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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/zfs_context.h>
#include <sys/dbuf.h>
#include <sys/dnode.h>
#include <sys/dmu.h>
#include <sys/dmu_tx.h>
#include <sys/dmu_objset.h>
#include <sys/dsl_dataset.h>
#include <sys/spa.h>
#include <sys/zio.h>

static void
dnode_increase_indirection(dnode_t *dn, dmu_tx_t *tx)
{
	dmu_buf_impl_t *db;
	int i;
	uint64_t txg = tx->tx_txg;

	ASSERT(dn->dn_phys->dn_type != DMU_OT_NONE);
	ASSERT(RW_WRITE_HELD(&dn->dn_struct_rwlock));
	/* this dnode can't be paged out because it's dirty */

	db = dbuf_hold_level(dn, dn->dn_phys->dn_nlevels, 0, FTAG);
	ASSERT(db != NULL);
	for (i = 0; i < dn->dn_phys->dn_nblkptr; i++)
		if (!BP_IS_HOLE(&dn->dn_phys->dn_blkptr[i]))
			break;
	if (i != dn->dn_phys->dn_nblkptr) {
		ASSERT(list_link_active(&db->db_dirty_node[txg&TXG_MASK]));

		(void) dbuf_read(db, NULL,
		    DB_RF_HAVESTRUCT | DB_RF_MUST_SUCCEED);
		arc_release(db->db_buf, db);
		/* copy dnode's block pointers to new indirect block */
		ASSERT3U(sizeof (blkptr_t) * dn->dn_phys->dn_nblkptr, <=,
		    db->db.db_size);
		bcopy(dn->dn_phys->dn_blkptr, db->db.db_data,
		    sizeof (blkptr_t) * dn->dn_phys->dn_nblkptr);
	}

	dn->dn_phys->dn_nlevels += 1;
	dprintf("os=%p obj=%llu, increase to %d\n",
		dn->dn_objset, dn->dn_object,
		dn->dn_phys->dn_nlevels);

	/* set dbuf's parent pointers to new indirect buf */
	for (i = 0; i < dn->dn_phys->dn_nblkptr; i++) {
		dmu_buf_impl_t *child =
		    dbuf_find(dn, dn->dn_phys->dn_nlevels-2, i);
		if (child == NULL)
			continue;
		if (child->db_dnode == NULL) {
			mutex_exit(&child->db_mtx);
			continue;
		}

		if (child->db_parent == NULL ||
		    child->db_parent == dn->dn_dbuf) {
			dprintf_dbuf_bp(child, child->db_blkptr,
			    "changing db_blkptr to new indirect %s", "");
			child->db_parent = db;
			dbuf_add_ref(db, child);
			if (db->db.db_data) {
				child->db_blkptr =
				    (blkptr_t *)db->db.db_data + i;
			} else {
				child->db_blkptr = NULL;
			}
			dprintf_dbuf_bp(child, child->db_blkptr,
			    "changed db_blkptr to new indirect %s", "");
		}
		ASSERT3P(child->db_parent, ==, db);

		mutex_exit(&child->db_mtx);
	}

	bzero(dn->dn_phys->dn_blkptr,
		sizeof (blkptr_t) * dn->dn_phys->dn_nblkptr);

	dbuf_rele(db, FTAG);
}

static void
free_blocks(dnode_t *dn, blkptr_t *bp, int num, dmu_tx_t *tx)
{
	objset_impl_t *os = dn->dn_objset;
	uint64_t bytesfreed = 0;
	int i;

	dprintf("os=%p obj=%llx num=%d\n", os, dn->dn_object, num);

	for (i = 0; i < num; i++, bp++) {
		if (BP_IS_HOLE(bp))
			continue;

		bytesfreed += BP_GET_ASIZE(bp);
		ASSERT3U(bytesfreed >> DEV_BSHIFT, <=, dn->dn_phys->dn_secphys);
		dsl_dataset_block_kill(os->os_dsl_dataset, bp, tx);
	}
	dnode_diduse_space(dn, -bytesfreed);
}

#ifdef ZFS_DEBUG
static void
free_verify(dmu_buf_impl_t *db, uint64_t start, uint64_t end, dmu_tx_t *tx)
{
	int off, num;
	int i, err, epbs;
	uint64_t txg = tx->tx_txg;

	epbs = db->db_dnode->dn_phys->dn_indblkshift - SPA_BLKPTRSHIFT;
	off = start - (db->db_blkid * 1<<epbs);
	num = end - start + 1;

	ASSERT3U(off, >=, 0);
	ASSERT3U(num, >=, 0);
	ASSERT3U(db->db_level, >, 0);
	ASSERT3U(db->db.db_size, ==, 1<<db->db_dnode->dn_phys->dn_indblkshift);
	ASSERT3U(off+num, <=, db->db.db_size >> SPA_BLKPTRSHIFT);
	ASSERT(db->db_blkptr != NULL);

	for (i = off; i < off+num; i++) {
		uint64_t *buf;
		int j;
		dmu_buf_impl_t *child;

		ASSERT(db->db_level == 1);

		rw_enter(&db->db_dnode->dn_struct_rwlock, RW_READER);
		err = dbuf_hold_impl(db->db_dnode, db->db_level-1,
			(db->db_blkid << epbs) + i, TRUE, FTAG, &child);
		rw_exit(&db->db_dnode->dn_struct_rwlock);
		if (err == ENOENT)
			continue;
		ASSERT(err == 0);
		ASSERT(child->db_level == 0);
		ASSERT(!list_link_active(&child->db_dirty_node[txg&TXG_MASK]));

		/* db_data_old better be zeroed */
		if (child->db_d.db_data_old[txg & TXG_MASK]) {
			buf = ((arc_buf_t *)child->db_d.db_data_old
			    [txg & TXG_MASK])->b_data;
			for (j = 0; j < child->db.db_size >> 3; j++) {
				if (buf[j] != 0) {
					panic("freed data not zero: "
					    "child=%p i=%d off=%d num=%d\n",
					    child, i, off, num);
				}
			}
		}

		/*
		 * db_data better be zeroed unless it's dirty in a
		 * future txg.
		 */
		mutex_enter(&child->db_mtx);
		buf = child->db.db_data;
		if (buf != NULL && child->db_state != DB_FILL &&
		    !list_link_active(&child->db_dirty_node
			[(txg+1) & TXG_MASK]) &&
		    !list_link_active(&child->db_dirty_node
			[(txg+2) & TXG_MASK])) {
			for (j = 0; j < child->db.db_size >> 3; j++) {
				if (buf[j] != 0) {
					panic("freed data not zero: "
					    "child=%p i=%d off=%d num=%d\n",
					    child, i, off, num);
				}
			}
		}
		mutex_exit(&child->db_mtx);

		dbuf_rele(child, FTAG);
	}
}
#endif

static int
free_children(dmu_buf_impl_t *db, uint64_t blkid, uint64_t nblks, int trunc,
    dmu_tx_t *tx)
{
	dnode_t *dn = db->db_dnode;
	blkptr_t *bp;
	dmu_buf_impl_t *subdb;
	uint64_t start, end, dbstart, dbend, i;
	int epbs, shift, err;
	int txgoff = tx->tx_txg & TXG_MASK;
	int all = TRUE;

	(void) dbuf_read(db, NULL, DB_RF_MUST_SUCCEED);
	arc_release(db->db_buf, db);
	bp = (blkptr_t *)db->db.db_data;

	epbs = db->db_dnode->dn_phys->dn_indblkshift - SPA_BLKPTRSHIFT;
	shift = (db->db_level - 1) * epbs;
	dbstart = db->db_blkid << epbs;
	start = blkid >> shift;
	if (dbstart < start) {
		bp += start - dbstart;
		all = FALSE;
	} else {
		start = dbstart;
	}
	dbend = ((db->db_blkid + 1) << epbs) - 1;
	end = (blkid + nblks - 1) >> shift;
	if (dbend <= end)
		end = dbend;
	else if (all)
		all = trunc;
	ASSERT3U(start, <=, end);

	if (db->db_level == 1) {
		FREE_VERIFY(db, start, end, tx);
		free_blocks(dn, bp, end-start+1, tx);
		ASSERT(all || list_link_active(&db->db_dirty_node[txgoff]));
		return (all);
	}

	for (i = start; i <= end; i++, bp++) {
		if (BP_IS_HOLE(bp))
			continue;
		rw_enter(&dn->dn_struct_rwlock, RW_READER);
		err = dbuf_hold_impl(dn, db->db_level-1, i, TRUE, FTAG, &subdb);
		ASSERT3U(err, ==, 0);
		rw_exit(&dn->dn_struct_rwlock);

		if (free_children(subdb, blkid, nblks, trunc, tx)) {
			ASSERT3P(subdb->db_blkptr, ==, bp);
			free_blocks(dn, bp, 1, tx);
		} else {
			all = FALSE;
		}
		dbuf_rele(subdb, FTAG);
	}
#ifdef ZFS_DEBUG
	bp -= (end-start)+1;
	for (i = start; i <= end; i++, bp++) {
		if (i == start && blkid != 0)
			continue;
		else if (i == end && !trunc)
			continue;
		ASSERT3U(bp->blk_birth, ==, 0);
	}
#endif
	ASSERT(all || list_link_active(&db->db_dirty_node[txgoff]));
	return (all);
}

/*
 * free_range: Traverse the indicated range of the provided file
 * and "free" all the blocks contained there.
 */
static void
dnode_sync_free_range(dnode_t *dn, uint64_t blkid, uint64_t nblks, dmu_tx_t *tx)
{
	blkptr_t *bp = dn->dn_phys->dn_blkptr;
	dmu_buf_impl_t *db;
	int trunc, start, end, shift, i, err;
	int dnlevel = dn->dn_phys->dn_nlevels;

	if (blkid > dn->dn_phys->dn_maxblkid)
		return;

	ASSERT(dn->dn_phys->dn_maxblkid < UINT64_MAX);
	trunc = blkid + nblks > dn->dn_phys->dn_maxblkid;
	if (trunc)
		nblks = dn->dn_phys->dn_maxblkid - blkid + 1;

	/* There are no indirect blocks in the object */
	if (dnlevel == 1) {
		if (blkid >= dn->dn_phys->dn_nblkptr) {
			/* this range was never made persistent */
			return;
		}
		ASSERT3U(blkid + nblks, <=, dn->dn_phys->dn_nblkptr);
		free_blocks(dn, bp + blkid, nblks, tx);
		if (trunc) {
			uint64_t off = (dn->dn_phys->dn_maxblkid + 1) *
			    (dn->dn_phys->dn_datablkszsec << SPA_MINBLOCKSHIFT);
			dn->dn_phys->dn_maxblkid = (blkid ? blkid - 1 : 0);
			ASSERT(off < dn->dn_phys->dn_maxblkid ||
			    dn->dn_phys->dn_maxblkid == 0 ||
			    dnode_next_offset(dn, FALSE, &off, 1, 1) == ESRCH);
		}
		return;
	}

	shift = (dnlevel - 1) * (dn->dn_phys->dn_indblkshift - SPA_BLKPTRSHIFT);
	start = blkid >> shift;
	ASSERT(start < dn->dn_phys->dn_nblkptr);
	end = (blkid + nblks - 1) >> shift;
	bp += start;
	for (i = start; i <= end; i++, bp++) {
		if (BP_IS_HOLE(bp))
			continue;
		rw_enter(&dn->dn_struct_rwlock, RW_READER);
		err = dbuf_hold_impl(dn, dnlevel-1, i, TRUE, FTAG, &db);
		ASSERT3U(err, ==, 0);
		rw_exit(&dn->dn_struct_rwlock);

		if (free_children(db, blkid, nblks, trunc, tx)) {
			ASSERT3P(db->db_blkptr, ==, bp);
			free_blocks(dn, bp, 1, tx);
		}
		dbuf_rele(db, FTAG);
	}
	if (trunc) {
		uint64_t off = (dn->dn_phys->dn_maxblkid + 1) *
		    (dn->dn_phys->dn_datablkszsec << SPA_MINBLOCKSHIFT);
		dn->dn_phys->dn_maxblkid = (blkid ? blkid - 1 : 0);
		ASSERT(off < dn->dn_phys->dn_maxblkid ||
		    dn->dn_phys->dn_maxblkid == 0 ||
		    dnode_next_offset(dn, FALSE, &off, 1, 1) == ESRCH);
	}
}

/*
 * Try to kick all the dnodes dbufs out of the cache...
 */
void
dnode_evict_dbufs(dnode_t *dn)
{
	int progress;
	int pass = 0;

	do {
		dmu_buf_impl_t *db, *db_next;
		int evicting = FALSE;

		progress = FALSE;
		mutex_enter(&dn->dn_dbufs_mtx);
		for (db = list_head(&dn->dn_dbufs); db; db = db_next) {
			/* dbuf_clear() may remove db from this list */
			db_next = list_next(&dn->dn_dbufs, db);

			mutex_enter(&db->db_mtx);
			if (db->db_state == DB_EVICTING) {
				progress = TRUE;
				evicting = TRUE;
				mutex_exit(&db->db_mtx);
			} else if (refcount_is_zero(&db->db_holds)) {
				progress = TRUE;
				ASSERT(!arc_released(db->db_buf));
				dbuf_clear(db); /* exits db_mtx for us */
			} else {
				mutex_exit(&db->db_mtx);
			}

		}
		/*
		 * NB: we need to drop dn_dbufs_mtx between passes so
		 * that any DB_EVICTING dbufs can make progress.
		 * Ideally, we would have some cv we could wait on, but
		 * since we don't, just wait a bit to give the other
		 * thread a chance to run.
		 */
		mutex_exit(&dn->dn_dbufs_mtx);
		if (evicting)
			delay(1);
		pass++;
		ASSERT(pass < 100); /* sanity check */
	} while (progress);

	/*
	 * This function works fine even if it can't evict everything,
	 * but all of our callers need this assertion, so let's put it
	 * here (for now).  Perhaps in the future there will be a try vs
	 * doall flag.
	 */
	if (list_head(&dn->dn_dbufs) != NULL) {
		panic("dangling dbufs (dn=%p, dbuf=%p)\n",
		    dn, list_head(&dn->dn_dbufs));
	}

	rw_enter(&dn->dn_struct_rwlock, RW_WRITER);
	if (dn->dn_bonus && refcount_is_zero(&dn->dn_bonus->db_holds)) {
		mutex_enter(&dn->dn_bonus->db_mtx);
		dbuf_evict(dn->dn_bonus);
		dn->dn_bonus = NULL;
	}
	rw_exit(&dn->dn_struct_rwlock);

}

static int
dnode_sync_free(dnode_t *dn, dmu_tx_t *tx)
{
	dmu_buf_impl_t *db;
	int txgoff = tx->tx_txg & TXG_MASK;

	ASSERT(dmu_tx_is_syncing(tx));

	/* Undirty all buffers */
	while (db = list_head(&dn->dn_dirty_dbufs[txgoff])) {
		mutex_enter(&db->db_mtx);
		/* XXX - use dbuf_undirty()? */
		list_remove(&dn->dn_dirty_dbufs[txgoff], db);
		if (db->db_level == 0) {
			ASSERT(db->db_blkid == DB_BONUS_BLKID ||
			    db->db_d.db_data_old[txgoff] == db->db_buf);
			if (db->db_d.db_overridden_by[txgoff])
				dbuf_unoverride(db, tx->tx_txg);
			db->db_d.db_data_old[txgoff] = NULL;
		}
		db->db_dirtycnt -= 1;
		mutex_exit(&db->db_mtx);
		dbuf_rele(db, (void *)(uintptr_t)tx->tx_txg);
	}

	dnode_evict_dbufs(dn);
	ASSERT3P(list_head(&dn->dn_dbufs), ==, NULL);

	/*
	 * XXX - It would be nice to assert this, but we may still
	 * have residual holds from async evictions from the arc...
	 *
	 * ASSERT3U(refcount_count(&dn->dn_holds), ==, 1);
	 */

	/* Undirty next bits */
	dn->dn_next_nlevels[txgoff] = 0;
	dn->dn_next_indblkshift[txgoff] = 0;
	dn->dn_next_blksz[txgoff] = 0;

	/* free up all the blocks in the file. */
	dnode_sync_free_range(dn, 0, dn->dn_phys->dn_maxblkid+1, tx);
	ASSERT3U(dn->dn_phys->dn_secphys, ==, 0);

	/* ASSERT(blkptrs are zero); */
	ASSERT(dn->dn_phys->dn_type != DMU_OT_NONE);
	ASSERT(dn->dn_type != DMU_OT_NONE);

	ASSERT(dn->dn_free_txg > 0);
	if (dn->dn_allocated_txg != dn->dn_free_txg)
		dbuf_will_dirty(dn->dn_dbuf, tx);
	bzero(dn->dn_phys, sizeof (dnode_phys_t));

	mutex_enter(&dn->dn_mtx);
	dn->dn_type = DMU_OT_NONE;
	dn->dn_maxblkid = 0;
	dn->dn_allocated_txg = 0;
	mutex_exit(&dn->dn_mtx);

	ASSERT(dn->dn_object != DMU_META_DNODE_OBJECT);

	dnode_rele(dn, (void *)(uintptr_t)tx->tx_txg);
	/*
	 * Now that we've released our hold, the dnode may
	 * be evicted, so we musn't access it.
	 */
	return (1);
}

/*
 * Write out the dnode's dirty buffers at the specified level.
 * This may create more dirty buffers at the next level up.
 *
 * NOTE: The dnode is kept in memory by being dirty.  Once the
 * dirty bit is cleared, it may be evicted.  Beware of this!
 */
int
dnode_sync(dnode_t *dn, int level, zio_t *zio, dmu_tx_t *tx)
{
	free_range_t *rp;
	int txgoff = tx->tx_txg & TXG_MASK;
	dnode_phys_t *dnp = dn->dn_phys;

	ASSERT(dmu_tx_is_syncing(tx));
	ASSERT(dnp->dn_type != DMU_OT_NONE || dn->dn_allocated_txg);
	DNODE_VERIFY(dn);

	/*
	 * Make sure the dbuf for the dn_phys is released before we modify it.
	 */
	if (dn->dn_dbuf)
		arc_release(dn->dn_dbuf->db_buf, dn->dn_dbuf);

	mutex_enter(&dn->dn_mtx);
	if (dn->dn_allocated_txg == tx->tx_txg) {
		/* The dnode is newly allocated or reallocated */
		if (dnp->dn_type == DMU_OT_NONE) {
			/* this is a first alloc, not a realloc */
			/* XXX shouldn't the phys already be zeroed? */
			bzero(dnp, DNODE_CORE_SIZE);
			dnp->dn_datablkszsec = dn->dn_datablkszsec;
			dnp->dn_indblkshift = dn->dn_indblkshift;
			dnp->dn_nlevels = 1;
		}

		if (dn->dn_nblkptr > dnp->dn_nblkptr) {
			/* zero the new blkptrs we are gaining */
			bzero(dnp->dn_blkptr + dnp->dn_nblkptr,
			    sizeof (blkptr_t) *
			    (dn->dn_nblkptr - dnp->dn_nblkptr));
		}
		dnp->dn_type = dn->dn_type;
		dnp->dn_bonustype = dn->dn_bonustype;
		dnp->dn_bonuslen = dn->dn_bonuslen;
		dnp->dn_nblkptr = dn->dn_nblkptr;
	}

	if (dn->dn_next_blksz[txgoff]) {
		ASSERT(P2PHASE(dn->dn_next_blksz[txgoff],
		    SPA_MINBLOCKSIZE) == 0);
		dnp->dn_datablkszsec =
		    dn->dn_next_blksz[txgoff] >> SPA_MINBLOCKSHIFT;
		dn->dn_next_blksz[txgoff] = 0;
	}

	if (dn->dn_next_indblkshift[txgoff]) {
		ASSERT(dnp->dn_nlevels == 1);
		dnp->dn_indblkshift = dn->dn_next_indblkshift[txgoff];
		dn->dn_next_indblkshift[txgoff] = 0;
	}

	/*
	 * Just take the live (open-context) values for checksum and compress.
	 * Strictly speaking it's a future leak, but nothing bad happens if we
	 * start using the new checksum or compress algorithm a little early.
	 */
	dnp->dn_checksum = dn->dn_checksum;
	dnp->dn_compress = dn->dn_compress;

	mutex_exit(&dn->dn_mtx);

	/* process all the "freed" ranges in the file */
	if (dn->dn_free_txg == 0 || dn->dn_free_txg > tx->tx_txg) {
		for (rp = avl_last(&dn->dn_ranges[txgoff]); rp != NULL;
		    rp = AVL_PREV(&dn->dn_ranges[txgoff], rp))
			dnode_sync_free_range(dn,
			    rp->fr_blkid, rp->fr_nblks, tx);
	}
	mutex_enter(&dn->dn_mtx);
	for (rp = avl_first(&dn->dn_ranges[txgoff]); rp; ) {
		free_range_t *last = rp;
		rp = AVL_NEXT(&dn->dn_ranges[txgoff], rp);
		avl_remove(&dn->dn_ranges[txgoff], last);
		kmem_free(last, sizeof (free_range_t));
	}
	mutex_exit(&dn->dn_mtx);

	if (dn->dn_free_txg > 0 && dn->dn_free_txg <= tx->tx_txg) {
		ASSERT3U(level, ==, 0);
		return (dnode_sync_free(dn, tx));
	}

	if (dn->dn_next_nlevels[txgoff]) {
		int new_lvl = dn->dn_next_nlevels[txgoff];

		rw_enter(&dn->dn_struct_rwlock, RW_WRITER);
		while (new_lvl > dnp->dn_nlevels)
			dnode_increase_indirection(dn, tx);
		rw_exit(&dn->dn_struct_rwlock);
		dn->dn_next_nlevels[txgoff] = 0;
	}

	if (level == dnp->dn_nlevels) {
		uint64_t off = (dn->dn_phys->dn_maxblkid + 1) *
		    (dn->dn_phys->dn_datablkszsec << SPA_MINBLOCKSHIFT);

		/* we've already synced out all data and indirect blocks */
		/* there are no more dirty dbufs under this dnode */
		ASSERT3P(list_head(&dn->dn_dirty_dbufs[txgoff]), ==, NULL);
		ASSERT(dn->dn_free_txg == 0 || dn->dn_free_txg >= tx->tx_txg);

		/* XXX this is expensive. remove once 6343073 is closed. */
		/* NB: the "off < maxblkid" is to catch overflow */
		/*
		 * NB: if blocksize is changing, we could get confused,
		 * so only bother if there are multiple blocks and thus
		 * it can't be changing.
		 */
		if (!(off < dn->dn_phys->dn_maxblkid ||
		    dn->dn_phys->dn_maxblkid == 0 ||
		    dnode_next_offset(dn, FALSE, &off, 1, 1) == ESRCH))
			panic("data after EOF: off=%llu\n", (u_longlong_t)off);

		if (dn->dn_object != DMU_META_DNODE_OBJECT) {
			dbuf_will_dirty(dn->dn_dbuf, tx);
			dnode_rele(dn, (void *)(uintptr_t)tx->tx_txg);
		}

		/*
		 * Now that we've dropped the reference, the dnode may
		 * be evicted, so we musn't access it.
		 */
		return (1);
	} else {
		dmu_buf_impl_t *db, *db_next;
		list_t *list = &dn->dn_dirty_dbufs[txgoff];
		/*
		 * Iterate over the list, removing and sync'ing dbufs
		 * which are on the level we want, and leaving others.
		 */
		for (db = list_head(list); db; db = db_next) {
			db_next = list_next(list, db);
			if (db->db_level == level) {
				list_remove(list, db);
				dbuf_sync(db, zio, tx);
			}
		}
		return (0);
	}
}
