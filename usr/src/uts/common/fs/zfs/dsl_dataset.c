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

#include <sys/dmu_objset.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_dir.h>
#include <sys/dmu_traverse.h>
#include <sys/dmu_tx.h>
#include <sys/arc.h>
#include <sys/zio.h>
#include <sys/zap.h>
#include <sys/unique.h>
#include <sys/zfs_context.h>

#define	DOS_REF_MAX	(1ULL << 62)

#define	DSL_DEADLIST_BLOCKSIZE	SPA_MAXBLOCKSIZE

#define	BP_GET_UCSIZE(bp) \
	((BP_GET_LEVEL(bp) > 0 || dmu_ot[BP_GET_TYPE(bp)].ot_metadata) ? \
	BP_GET_PSIZE(bp) : BP_GET_LSIZE(bp));

/*
 * We use weighted reference counts to express the various forms of exclusion
 * between different open modes.  A STANDARD open is 1 point, an EXCLUSIVE open
 * is DOS_REF_MAX, and a PRIMARY open is little more than half of an EXCLUSIVE.
 * This makes the exclusion logic simple: the total refcnt for all opens cannot
 * exceed DOS_REF_MAX.  For example, EXCLUSIVE opens are exclusive because their
 * weight (DOS_REF_MAX) consumes the entire refcnt space.  PRIMARY opens consume
 * just over half of the refcnt space, so there can't be more than one, but it
 * can peacefully coexist with any number of STANDARD opens.
 */
static uint64_t ds_refcnt_weight[DS_MODE_LEVELS] = {
	0,			/* DOS_MODE_NONE - invalid		*/
	1,			/* DOS_MODE_STANDARD - unlimited number	*/
	(DOS_REF_MAX >> 1) + 1,	/* DOS_MODE_PRIMARY - only one of these	*/
	DOS_REF_MAX		/* DOS_MODE_EXCLUSIVE - no other opens	*/
};


void
dsl_dataset_block_born(dsl_dataset_t *ds, blkptr_t *bp, dmu_tx_t *tx)
{
	int used = BP_GET_ASIZE(bp);
	int compressed = BP_GET_PSIZE(bp);
	int uncompressed = BP_GET_UCSIZE(bp);

	dprintf_bp(bp, "born, ds=%p\n", ds);

	ASSERT(dmu_tx_is_syncing(tx));
	/* It could have been compressed away to nothing */
	if (BP_IS_HOLE(bp))
		return;
	ASSERT(BP_GET_TYPE(bp) != DMU_OT_NONE);
	ASSERT3U(BP_GET_TYPE(bp), <, DMU_OT_NUMTYPES);
	if (ds == NULL) {
		/*
		 * Account for the meta-objset space in its placeholder
		 * dsl_dir.
		 */
		ASSERT3U(compressed, ==, uncompressed); /* it's all metadata */
		dsl_dir_diduse_space(tx->tx_pool->dp_mos_dir,
		    used, compressed, uncompressed, tx);
		dsl_dir_dirty(tx->tx_pool->dp_mos_dir, tx);
		return;
	}
	dmu_buf_will_dirty(ds->ds_dbuf, tx);
	mutex_enter(&ds->ds_lock);
	ds->ds_phys->ds_used_bytes += used;
	ds->ds_phys->ds_compressed_bytes += compressed;
	ds->ds_phys->ds_uncompressed_bytes += uncompressed;
	ds->ds_phys->ds_unique_bytes += used;
	mutex_exit(&ds->ds_lock);
	dsl_dir_diduse_space(ds->ds_dir,
	    used, compressed, uncompressed, tx);
}

void
dsl_dataset_block_kill(dsl_dataset_t *ds, blkptr_t *bp, dmu_tx_t *tx)
{
	int used = BP_GET_ASIZE(bp);
	int compressed = BP_GET_PSIZE(bp);
	int uncompressed = BP_GET_UCSIZE(bp);

	ASSERT(dmu_tx_is_syncing(tx));
	if (BP_IS_HOLE(bp))
		return;

	ASSERT(used > 0);
	if (ds == NULL) {
		/*
		 * Account for the meta-objset space in its placeholder
		 * dataset.
		 */
		/* XXX this can fail, what do we do when it does? */
		(void) arc_free(NULL, tx->tx_pool->dp_spa,
		    tx->tx_txg, bp, NULL, NULL, ARC_WAIT);
		bzero(bp, sizeof (blkptr_t));

		dsl_dir_diduse_space(tx->tx_pool->dp_mos_dir,
		    -used, -compressed, -uncompressed, tx);
		dsl_dir_dirty(tx->tx_pool->dp_mos_dir, tx);
		return;
	}
	ASSERT3P(tx->tx_pool, ==, ds->ds_dir->dd_pool);

	dmu_buf_will_dirty(ds->ds_dbuf, tx);

	if (bp->blk_birth > ds->ds_phys->ds_prev_snap_txg) {
		dprintf_bp(bp, "freeing: %s", "");
		/* XXX check return code? */
		(void) arc_free(NULL, tx->tx_pool->dp_spa,
		    tx->tx_txg, bp, NULL, NULL, ARC_WAIT);

		mutex_enter(&ds->ds_lock);
		/* XXX unique_bytes is not accurate for head datasets */
		/* ASSERT3U(ds->ds_phys->ds_unique_bytes, >=, used); */
		ds->ds_phys->ds_unique_bytes -= used;
		mutex_exit(&ds->ds_lock);
		dsl_dir_diduse_space(ds->ds_dir,
		    -used, -compressed, -uncompressed, tx);
	} else {
		dprintf_bp(bp, "putting on dead list: %s", "");
		VERIFY(0 == bplist_enqueue(&ds->ds_deadlist, bp, tx));
		/* if (bp->blk_birth > prev prev snap txg) prev unique += bs */
		if (ds->ds_phys->ds_prev_snap_obj != 0) {
			ASSERT3U(ds->ds_prev->ds_object, ==,
			    ds->ds_phys->ds_prev_snap_obj);
			ASSERT(ds->ds_prev->ds_phys->ds_num_children > 0);
			if (ds->ds_prev->ds_phys->ds_next_snap_obj ==
			    ds->ds_object &&
			    bp->blk_birth >
			    ds->ds_prev->ds_phys->ds_prev_snap_txg) {
				dmu_buf_will_dirty(ds->ds_prev->ds_dbuf, tx);
				mutex_enter(&ds->ds_prev->ds_lock);
				ds->ds_prev->ds_phys->ds_unique_bytes +=
				    used;
				mutex_exit(&ds->ds_prev->ds_lock);
			}
		}
	}
	bzero(bp, sizeof (blkptr_t));
	mutex_enter(&ds->ds_lock);
	ASSERT3U(ds->ds_phys->ds_used_bytes, >=, used);
	ds->ds_phys->ds_used_bytes -= used;
	ASSERT3U(ds->ds_phys->ds_compressed_bytes, >=, compressed);
	ds->ds_phys->ds_compressed_bytes -= compressed;
	ASSERT3U(ds->ds_phys->ds_uncompressed_bytes, >=, uncompressed);
	ds->ds_phys->ds_uncompressed_bytes -= uncompressed;
	mutex_exit(&ds->ds_lock);
}

uint64_t
dsl_dataset_prev_snap_txg(dsl_dataset_t *ds)
{
	uint64_t txg;
	dsl_dir_t *dd;

	if (ds == NULL)
		return (0);
	/*
	 * The snapshot creation could fail, but that would cause an
	 * incorrect FALSE return, which would only result in an
	 * overestimation of the amount of space that an operation would
	 * consume, which is OK.
	 *
	 * There's also a small window where we could miss a pending
	 * snapshot, because we could set the sync task in the quiescing
	 * phase.  So this should only be used as a guess.
	 */
	dd = ds->ds_dir;
	mutex_enter(&dd->dd_lock);
	if (dd->dd_sync_func == dsl_dataset_snapshot_sync)
		txg = dd->dd_sync_txg;
	else
		txg = ds->ds_phys->ds_prev_snap_txg;
	mutex_exit(&dd->dd_lock);

	return (txg);
}

int
dsl_dataset_block_freeable(dsl_dataset_t *ds, uint64_t blk_birth)
{
	return (blk_birth > dsl_dataset_prev_snap_txg(ds));
}

/* ARGSUSED */
static void
dsl_dataset_evict(dmu_buf_t *db, void *dsv)
{
	dsl_dataset_t *ds = dsv;
	dsl_pool_t *dp = ds->ds_dir->dd_pool;

	/* open_refcount == DOS_REF_MAX when deleting */
	ASSERT(ds->ds_open_refcount == 0 ||
	    ds->ds_open_refcount == DOS_REF_MAX);

	dprintf_ds(ds, "evicting %s\n", "");

	unique_remove(ds->ds_phys->ds_fsid_guid);

	if (ds->ds_user_ptr != NULL)
		ds->ds_user_evict_func(ds, ds->ds_user_ptr);

	if (ds->ds_prev) {
		dsl_dataset_close(ds->ds_prev, DS_MODE_NONE, ds);
		ds->ds_prev = NULL;
	}

	bplist_close(&ds->ds_deadlist);
	dsl_dir_close(ds->ds_dir, ds);

	if (list_link_active(&ds->ds_synced_link))
		list_remove(&dp->dp_synced_objsets, ds);

	kmem_free(ds, sizeof (dsl_dataset_t));
}

static int
dsl_dataset_get_snapname(dsl_dataset_t *ds)
{
	dsl_dataset_phys_t *headphys;
	int err;
	dmu_buf_t *headdbuf;
	dsl_pool_t *dp = ds->ds_dir->dd_pool;
	objset_t *mos = dp->dp_meta_objset;

	if (ds->ds_snapname[0])
		return (0);
	if (ds->ds_phys->ds_next_snap_obj == 0)
		return (0);

	err = dmu_bonus_hold(mos, ds->ds_dir->dd_phys->dd_head_dataset_obj,
	    FTAG, &headdbuf);
	if (err)
		return (err);
	headphys = headdbuf->db_data;
	err = zap_value_search(dp->dp_meta_objset,
	    headphys->ds_snapnames_zapobj, ds->ds_object, ds->ds_snapname);
	dmu_buf_rele(headdbuf, FTAG);
	return (err);
}

int
dsl_dataset_open_obj(dsl_pool_t *dp, uint64_t dsobj, const char *snapname,
    int mode, void *tag, dsl_dataset_t **dsp)
{
	uint64_t weight = ds_refcnt_weight[DS_MODE_LEVEL(mode)];
	objset_t *mos = dp->dp_meta_objset;
	dmu_buf_t *dbuf;
	dsl_dataset_t *ds;
	int err;

	ASSERT(RW_LOCK_HELD(&dp->dp_config_rwlock) ||
	    dsl_pool_sync_context(dp));

	err = dmu_bonus_hold(mos, dsobj, tag, &dbuf);
	if (err)
		return (err);
	ds = dmu_buf_get_user(dbuf);
	if (ds == NULL) {
		dsl_dataset_t *winner;

		ds = kmem_zalloc(sizeof (dsl_dataset_t), KM_SLEEP);
		ds->ds_dbuf = dbuf;
		ds->ds_object = dsobj;
		ds->ds_phys = dbuf->db_data;

		err = bplist_open(&ds->ds_deadlist,
		    mos, ds->ds_phys->ds_deadlist_obj);
		if (err == 0) {
			err = dsl_dir_open_obj(dp,
			    ds->ds_phys->ds_dir_obj, NULL, ds, &ds->ds_dir);
		}
		if (err) {
			/*
			 * we don't really need to close the blist if we
			 * just opened it.
			 */
			kmem_free(ds, sizeof (dsl_dataset_t));
			dmu_buf_rele(dbuf, tag);
			return (err);
		}

		if (ds->ds_dir->dd_phys->dd_head_dataset_obj == dsobj) {
			ds->ds_snapname[0] = '\0';
			if (ds->ds_phys->ds_prev_snap_obj) {
				err = dsl_dataset_open_obj(dp,
				    ds->ds_phys->ds_prev_snap_obj, NULL,
				    DS_MODE_NONE, ds, &ds->ds_prev);
			}
		} else {
			if (snapname) {
#ifdef ZFS_DEBUG
				dsl_dataset_phys_t *headphys;
				dmu_buf_t *headdbuf;
				err = dmu_bonus_hold(mos,
				    ds->ds_dir->dd_phys->dd_head_dataset_obj,
				    FTAG, &headdbuf);
				if (err == 0) {
					headphys = headdbuf->db_data;
					uint64_t foundobj;
					err = zap_lookup(dp->dp_meta_objset,
					    headphys->ds_snapnames_zapobj,
					    snapname, sizeof (foundobj), 1,
					    &foundobj);
					ASSERT3U(foundobj, ==, dsobj);
					dmu_buf_rele(headdbuf, FTAG);
				}
#endif
				(void) strcat(ds->ds_snapname, snapname);
			} else if (zfs_flags & ZFS_DEBUG_SNAPNAMES) {
				err = dsl_dataset_get_snapname(ds);
			}
		}

		if (err == 0) {
			winner = dmu_buf_set_user_ie(dbuf, ds, &ds->ds_phys,
			    dsl_dataset_evict);
		}
		if (err || winner) {
			bplist_close(&ds->ds_deadlist);
			if (ds->ds_prev) {
				dsl_dataset_close(ds->ds_prev,
				    DS_MODE_NONE, ds);
			}
			dsl_dir_close(ds->ds_dir, ds);
			kmem_free(ds, sizeof (dsl_dataset_t));
			if (err) {
				dmu_buf_rele(dbuf, tag);
				return (err);
			}
			ds = winner;
		} else {
			uint64_t new =
			    unique_insert(ds->ds_phys->ds_fsid_guid);
			if (new != ds->ds_phys->ds_fsid_guid) {
				/* XXX it won't necessarily be synced... */
				ds->ds_phys->ds_fsid_guid = new;
			}
		}
	}
	ASSERT3P(ds->ds_dbuf, ==, dbuf);
	ASSERT3P(ds->ds_phys, ==, dbuf->db_data);

	mutex_enter(&ds->ds_lock);
	if ((DS_MODE_LEVEL(mode) == DS_MODE_PRIMARY &&
	    ds->ds_phys->ds_restoring && !DS_MODE_IS_RESTORE(mode)) ||
	    (ds->ds_open_refcount + weight > DOS_REF_MAX)) {
		mutex_exit(&ds->ds_lock);
		dsl_dataset_close(ds, DS_MODE_NONE, tag);
		return (EBUSY);
	}
	ds->ds_open_refcount += weight;
	mutex_exit(&ds->ds_lock);

	*dsp = ds;
	return (0);
}

int
dsl_dataset_open_spa(spa_t *spa, const char *name, int mode,
    void *tag, dsl_dataset_t **dsp)
{
	dsl_dir_t *dd;
	dsl_pool_t *dp;
	const char *tail;
	uint64_t obj;
	dsl_dataset_t *ds = NULL;
	int err = 0;

	err = dsl_dir_open_spa(spa, name, FTAG, &dd, &tail);
	if (err)
		return (err);

	dp = dd->dd_pool;
	obj = dd->dd_phys->dd_head_dataset_obj;
	rw_enter(&dp->dp_config_rwlock, RW_READER);
	if (obj == 0) {
		/* A dataset with no associated objset */
		err = ENOENT;
		goto out;
	}

	if (tail != NULL) {
		objset_t *mos = dp->dp_meta_objset;

		err = dsl_dataset_open_obj(dp, obj, NULL,
		    DS_MODE_NONE, tag, &ds);
		if (err)
			goto out;
		obj = ds->ds_phys->ds_snapnames_zapobj;
		dsl_dataset_close(ds, DS_MODE_NONE, tag);
		ds = NULL;

		if (tail[0] != '@') {
			err = ENOENT;
			goto out;
		}
		tail++;

		/* Look for a snapshot */
		if (!DS_MODE_IS_READONLY(mode)) {
			err = EROFS;
			goto out;
		}
		dprintf("looking for snapshot '%s'\n", tail);
		err = zap_lookup(mos, obj, tail, 8, 1, &obj);
		if (err)
			goto out;
	}
	err = dsl_dataset_open_obj(dp, obj, tail, mode, tag, &ds);

out:
	rw_exit(&dp->dp_config_rwlock);
	dsl_dir_close(dd, FTAG);

	ASSERT3U((err == 0), ==, (ds != NULL));
	/* ASSERT(ds == NULL || strcmp(name, ds->ds_name) == 0); */

	*dsp = ds;
	return (err);
}

int
dsl_dataset_open(const char *name, int mode, void *tag, dsl_dataset_t **dsp)
{
	return (dsl_dataset_open_spa(NULL, name, mode, tag, dsp));
}

void
dsl_dataset_name(dsl_dataset_t *ds, char *name)
{
	if (ds == NULL) {
		(void) strcpy(name, "mos");
	} else {
		dsl_dir_name(ds->ds_dir, name);
		VERIFY(0 == dsl_dataset_get_snapname(ds));
		if (ds->ds_snapname[0]) {
			(void) strcat(name, "@");
			if (!MUTEX_HELD(&ds->ds_lock)) {
				/*
				 * We use a "recursive" mutex so that we
				 * can call dprintf_ds() with ds_lock held.
				 */
				mutex_enter(&ds->ds_lock);
				(void) strcat(name, ds->ds_snapname);
				mutex_exit(&ds->ds_lock);
			} else {
				(void) strcat(name, ds->ds_snapname);
			}
		}
	}
}

void
dsl_dataset_close(dsl_dataset_t *ds, int mode, void *tag)
{
	uint64_t weight = ds_refcnt_weight[DS_MODE_LEVEL(mode)];
	mutex_enter(&ds->ds_lock);
	ASSERT3U(ds->ds_open_refcount, >=, weight);
	ds->ds_open_refcount -= weight;
	dprintf_ds(ds, "closing mode %u refcount now 0x%llx\n",
	    mode, ds->ds_open_refcount);
	mutex_exit(&ds->ds_lock);

	dmu_buf_rele(ds->ds_dbuf, tag);
}

void
dsl_dataset_create_root(dsl_pool_t *dp, uint64_t *ddobjp, dmu_tx_t *tx)
{
	objset_t *mos = dp->dp_meta_objset;
	dmu_buf_t *dbuf;
	dsl_dataset_phys_t *dsphys;
	dsl_dataset_t *ds;
	uint64_t dsobj;
	dsl_dir_t *dd;

	dsl_dir_create_root(mos, ddobjp, tx);
	VERIFY(0 == dsl_dir_open_obj(dp, *ddobjp, NULL, FTAG, &dd));

	dsobj = dmu_object_alloc(mos, DMU_OT_DSL_DATASET, 0,
	    DMU_OT_DSL_DATASET, sizeof (dsl_dataset_phys_t), tx);
	VERIFY(0 == dmu_bonus_hold(mos, dsobj, FTAG, &dbuf));
	dmu_buf_will_dirty(dbuf, tx);
	dsphys = dbuf->db_data;
	dsphys->ds_dir_obj = dd->dd_object;
	dsphys->ds_fsid_guid = unique_create();
	unique_remove(dsphys->ds_fsid_guid); /* it isn't open yet */
	(void) random_get_pseudo_bytes((void*)&dsphys->ds_guid,
	    sizeof (dsphys->ds_guid));
	dsphys->ds_snapnames_zapobj =
	    zap_create(mos, DMU_OT_DSL_DS_SNAP_MAP, DMU_OT_NONE, 0, tx);
	dsphys->ds_creation_time = gethrestime_sec();
	dsphys->ds_creation_txg = tx->tx_txg;
	dsphys->ds_deadlist_obj =
	    bplist_create(mos, DSL_DEADLIST_BLOCKSIZE, tx);
	dmu_buf_rele(dbuf, FTAG);

	dmu_buf_will_dirty(dd->dd_dbuf, tx);
	dd->dd_phys->dd_head_dataset_obj = dsobj;
	dsl_dir_close(dd, FTAG);

	VERIFY(0 ==
	    dsl_dataset_open_obj(dp, dsobj, NULL, DS_MODE_NONE, FTAG, &ds));
	(void) dmu_objset_create_impl(dp->dp_spa, ds, DMU_OST_ZFS, tx);
	dsl_dataset_close(ds, DS_MODE_NONE, FTAG);
}

int
dsl_dataset_create_sync(dsl_dir_t *pds, const char *fullname,
    const char *lastname, dsl_dataset_t *clone_parent, dmu_tx_t *tx)
{
	int err;
	dsl_pool_t *dp = pds->dd_pool;
	dmu_buf_t *dbuf;
	dsl_dataset_phys_t *dsphys;
	uint64_t dsobj;
	objset_t *mos = dp->dp_meta_objset;
	dsl_dir_t *dd;

	if (clone_parent != NULL) {
		/*
		 * You can't clone across pools.
		 */
		if (clone_parent->ds_dir->dd_pool != dp)
			return (EXDEV);

		/*
		 * You can only clone snapshots, not the head datasets.
		 */
		if (clone_parent->ds_phys->ds_num_children == 0)
			return (EINVAL);
	}

	ASSERT(lastname[0] != '@');
	ASSERT(dmu_tx_is_syncing(tx));

	err = dsl_dir_create_sync(pds, lastname, tx);
	if (err)
		return (err);
	VERIFY(0 == dsl_dir_open_spa(dp->dp_spa, fullname, FTAG, &dd, NULL));

	/* This is the point of no (unsuccessful) return */

	dsobj = dmu_object_alloc(mos, DMU_OT_DSL_DATASET, 0,
	    DMU_OT_DSL_DATASET, sizeof (dsl_dataset_phys_t), tx);
	VERIFY(0 == dmu_bonus_hold(mos, dsobj, FTAG, &dbuf));
	dmu_buf_will_dirty(dbuf, tx);
	dsphys = dbuf->db_data;
	dsphys->ds_dir_obj = dd->dd_object;
	dsphys->ds_fsid_guid = unique_create();
	unique_remove(dsphys->ds_fsid_guid); /* it isn't open yet */
	(void) random_get_pseudo_bytes((void*)&dsphys->ds_guid,
	    sizeof (dsphys->ds_guid));
	dsphys->ds_snapnames_zapobj =
	    zap_create(mos, DMU_OT_DSL_DS_SNAP_MAP, DMU_OT_NONE, 0, tx);
	dsphys->ds_creation_time = gethrestime_sec();
	dsphys->ds_creation_txg = tx->tx_txg;
	dsphys->ds_deadlist_obj =
	    bplist_create(mos, DSL_DEADLIST_BLOCKSIZE, tx);
	if (clone_parent) {
		dsphys->ds_prev_snap_obj = clone_parent->ds_object;
		dsphys->ds_prev_snap_txg =
		    clone_parent->ds_phys->ds_creation_txg;
		dsphys->ds_used_bytes =
		    clone_parent->ds_phys->ds_used_bytes;
		dsphys->ds_compressed_bytes =
		    clone_parent->ds_phys->ds_compressed_bytes;
		dsphys->ds_uncompressed_bytes =
		    clone_parent->ds_phys->ds_uncompressed_bytes;
		dsphys->ds_bp = clone_parent->ds_phys->ds_bp;

		dmu_buf_will_dirty(clone_parent->ds_dbuf, tx);
		clone_parent->ds_phys->ds_num_children++;

		dmu_buf_will_dirty(dd->dd_dbuf, tx);
		dd->dd_phys->dd_clone_parent_obj = clone_parent->ds_object;
	}
	dmu_buf_rele(dbuf, FTAG);

	dmu_buf_will_dirty(dd->dd_dbuf, tx);
	dd->dd_phys->dd_head_dataset_obj = dsobj;
	dsl_dir_close(dd, FTAG);

	return (0);
}


int
dsl_dataset_destroy(const char *name)
{
	int err;
	dsl_pool_t *dp;
	dsl_dir_t *dd;
	const char *tail;

	err = dsl_dir_open(name, FTAG, &dd, &tail);
	if (err)
		return (err);

	dp = dd->dd_pool;
	if (tail != NULL) {
		if (tail[0] != '@') {
			dsl_dir_close(dd, FTAG);
			return (ENOENT);
		}
		tail++;
		/* Just blow away the snapshot */
		do {
			txg_wait_synced(dp, 0);
			err = dsl_dir_sync_task(dd,
			    dsl_dataset_destroy_sync, (void*)tail, 0);
		} while (err == EAGAIN);
		dsl_dir_close(dd, FTAG);
	} else {
		char buf[MAXNAMELEN];
		char *cp;

		dsl_dir_t *pds;
		if (dd->dd_phys->dd_parent_obj == 0) {
			dsl_dir_close(dd, FTAG);
			return (EINVAL);
		}
		/*
		 * Make sure it's not dirty before we destroy it.
		 */
		txg_wait_synced(dd->dd_pool, 0);
		/*
		 * Blow away the dsl_dir + head dataset.
		 * dsl_dir_destroy_sync() will call
		 * dsl_dataset_destroy_sync() to destroy the head dataset.
		 */
		rw_enter(&dp->dp_config_rwlock, RW_READER);
		err = dsl_dir_open_obj(dd->dd_pool,
		    dd->dd_phys->dd_parent_obj, NULL, FTAG, &pds);
		dsl_dir_close(dd, FTAG);
		rw_exit(&dp->dp_config_rwlock);
		if (err)
			return (err);

		(void) strcpy(buf, name);
		cp = strrchr(buf, '/') + 1;
		ASSERT(cp[0] != '\0');
		do {
			txg_wait_synced(dp, 0);
			err = dsl_dir_sync_task(pds,
			    dsl_dir_destroy_sync, cp, 0);
		} while (err == EAGAIN);
		dsl_dir_close(pds, FTAG);
	}

	return (err);
}

int
dsl_dataset_rollback(const char *name)
{
	int err;
	dsl_dir_t *dd;
	const char *tail;

	err = dsl_dir_open(name, FTAG, &dd, &tail);
	if (err)
		return (err);

	if (tail != NULL) {
		dsl_dir_close(dd, FTAG);
		return (EINVAL);
	}
	do {
		txg_wait_synced(dd->dd_pool, 0);
		err = dsl_dir_sync_task(dd,
		    dsl_dataset_rollback_sync, NULL, 0);
	} while (err == EAGAIN);
	dsl_dir_close(dd, FTAG);

	return (err);
}

void *
dsl_dataset_set_user_ptr(dsl_dataset_t *ds,
    void *p, dsl_dataset_evict_func_t func)
{
	void *old;

	mutex_enter(&ds->ds_lock);
	old = ds->ds_user_ptr;
	if (old == NULL) {
		ds->ds_user_ptr = p;
		ds->ds_user_evict_func = func;
	}
	mutex_exit(&ds->ds_lock);
	return (old);
}

void *
dsl_dataset_get_user_ptr(dsl_dataset_t *ds)
{
	return (ds->ds_user_ptr);
}


void
dsl_dataset_get_blkptr(dsl_dataset_t *ds, blkptr_t *bp)
{
	*bp = ds->ds_phys->ds_bp;
}

void
dsl_dataset_set_blkptr(dsl_dataset_t *ds, blkptr_t *bp, dmu_tx_t *tx)
{
	ASSERT(dmu_tx_is_syncing(tx));
	/* If it's the meta-objset, set dp_meta_rootbp */
	if (ds == NULL) {
		tx->tx_pool->dp_meta_rootbp = *bp;
	} else {
		dmu_buf_will_dirty(ds->ds_dbuf, tx);
		ds->ds_phys->ds_bp = *bp;
	}
}

spa_t *
dsl_dataset_get_spa(dsl_dataset_t *ds)
{
	return (ds->ds_dir->dd_pool->dp_spa);
}

void
dsl_dataset_dirty(dsl_dataset_t *ds, dmu_tx_t *tx)
{
	dsl_pool_t *dp;

	if (ds == NULL) /* this is the meta-objset */
		return;

	ASSERT(ds->ds_user_ptr != NULL);
	ASSERT(ds->ds_phys->ds_next_snap_obj == 0);

	dp = ds->ds_dir->dd_pool;

	if (txg_list_add(&dp->dp_dirty_datasets, ds, tx->tx_txg) == 0) {
		/* up the hold count until we can be written out */
		dmu_buf_add_ref(ds->ds_dbuf, ds);
	}
}

struct killarg {
	uint64_t *usedp;
	uint64_t *compressedp;
	uint64_t *uncompressedp;
	zio_t *zio;
	dmu_tx_t *tx;
};

static int
kill_blkptr(traverse_blk_cache_t *bc, spa_t *spa, void *arg)
{
	struct killarg *ka = arg;
	blkptr_t *bp = &bc->bc_blkptr;

	ASSERT3U(bc->bc_errno, ==, 0);

	/*
	 * Since this callback is not called concurrently, no lock is
	 * needed on the accounting values.
	 */
	*ka->usedp += BP_GET_ASIZE(bp);
	*ka->compressedp += BP_GET_PSIZE(bp);
	*ka->uncompressedp += BP_GET_UCSIZE(bp);
	/* XXX check for EIO? */
	(void) arc_free(ka->zio, spa, ka->tx->tx_txg, bp, NULL, NULL,
	    ARC_NOWAIT);
	return (0);
}

/* ARGSUSED */
int
dsl_dataset_rollback_sync(dsl_dir_t *dd, void *arg, dmu_tx_t *tx)
{
	objset_t *mos = dd->dd_pool->dp_meta_objset;
	dsl_dataset_t *ds;
	int err;

	if (dd->dd_phys->dd_head_dataset_obj == 0)
		return (EINVAL);
	err = dsl_dataset_open_obj(dd->dd_pool,
	    dd->dd_phys->dd_head_dataset_obj, NULL, DS_MODE_NONE, FTAG, &ds);
	if (err)
		return (err);

	if (ds->ds_phys->ds_prev_snap_txg == 0) {
		/*
		 * There's no previous snapshot.  I suppose we could
		 * roll it back to being empty (and re-initialize the
		 * upper (ZPL) layer).  But for now there's no way to do
		 * this via the user interface.
		 */
		dsl_dataset_close(ds, DS_MODE_NONE, FTAG);
		return (EINVAL);
	}

	mutex_enter(&ds->ds_lock);
	if (ds->ds_open_refcount > 0) {
		mutex_exit(&ds->ds_lock);
		dsl_dataset_close(ds, DS_MODE_NONE, FTAG);
		return (EBUSY);
	}

	/*
	 * If we made changes this txg, traverse_dsl_dataset won't find
	 * them.  Try again.
	 */
	if (ds->ds_phys->ds_bp.blk_birth >= tx->tx_txg) {
		mutex_exit(&ds->ds_lock);
		dsl_dataset_close(ds, DS_MODE_NONE, FTAG);
		return (EAGAIN);
	}

	/* THE POINT OF NO (unsuccessful) RETURN */
	ds->ds_open_refcount = DOS_REF_MAX;
	mutex_exit(&ds->ds_lock);

	dmu_buf_will_dirty(ds->ds_dbuf, tx);

	/* Zero out the deadlist. */
	dprintf("old deadlist obj = %llx\n", ds->ds_phys->ds_deadlist_obj);
	bplist_close(&ds->ds_deadlist);
	bplist_destroy(mos, ds->ds_phys->ds_deadlist_obj, tx);
	ds->ds_phys->ds_deadlist_obj =
	    bplist_create(mos, DSL_DEADLIST_BLOCKSIZE, tx);
	VERIFY(0 == bplist_open(&ds->ds_deadlist, mos,
	    ds->ds_phys->ds_deadlist_obj));
	dprintf("new deadlist obj = %llx\n", ds->ds_phys->ds_deadlist_obj);

	{
		/* Free blkptrs that we gave birth to */
		zio_t *zio;
		uint64_t used = 0, compressed = 0, uncompressed = 0;
		struct killarg ka;

		zio = zio_root(tx->tx_pool->dp_spa, NULL, NULL,
		    ZIO_FLAG_MUSTSUCCEED);
		ka.usedp = &used;
		ka.compressedp = &compressed;
		ka.uncompressedp = &uncompressed;
		ka.zio = zio;
		ka.tx = tx;
		(void) traverse_dsl_dataset(ds, ds->ds_phys->ds_prev_snap_txg,
		    ADVANCE_POST, kill_blkptr, &ka);
		(void) zio_wait(zio);

		dsl_dir_diduse_space(dd,
		    -used, -compressed, -uncompressed, tx);
	}

	/* Change our contents to that of the prev snapshot (finally!) */
	ASSERT3U(ds->ds_prev->ds_object, ==, ds->ds_phys->ds_prev_snap_obj);
	ds->ds_phys->ds_bp = ds->ds_prev->ds_phys->ds_bp;
	ds->ds_phys->ds_used_bytes = ds->ds_prev->ds_phys->ds_used_bytes;
	ds->ds_phys->ds_compressed_bytes =
	    ds->ds_prev->ds_phys->ds_compressed_bytes;
	ds->ds_phys->ds_uncompressed_bytes =
	    ds->ds_prev->ds_phys->ds_uncompressed_bytes;
	ds->ds_phys->ds_restoring = ds->ds_prev->ds_phys->ds_restoring;
	ds->ds_phys->ds_unique_bytes = 0;

	dmu_buf_will_dirty(ds->ds_prev->ds_dbuf, tx);
	ds->ds_prev->ds_phys->ds_unique_bytes = 0;

	dprintf("new deadlist obj = %llx\n", ds->ds_phys->ds_deadlist_obj);
	ds->ds_open_refcount = 0;
	dsl_dataset_close(ds, DS_MODE_NONE, FTAG);

	return (0);
}

int
dsl_dataset_destroy_sync(dsl_dir_t *dd, void *arg, dmu_tx_t *tx)
{
	const char *snapname = arg;
	uint64_t used = 0, compressed = 0, uncompressed = 0;
	blkptr_t bp;
	zio_t *zio;
	int err;
	int after_branch_point = FALSE;
	int drop_lock = FALSE;
	dsl_pool_t *dp = dd->dd_pool;
	objset_t *mos = dp->dp_meta_objset;
	dsl_dataset_t *ds, *ds_prev = NULL;
	uint64_t obj;

	if (dd->dd_phys->dd_head_dataset_obj == 0)
		return (EINVAL);

	if (!RW_WRITE_HELD(&dp->dp_config_rwlock)) {
		rw_enter(&dp->dp_config_rwlock, RW_WRITER);
		drop_lock = TRUE;
	}

	err = dsl_dataset_open_obj(dd->dd_pool,
	    dd->dd_phys->dd_head_dataset_obj, NULL,
	    snapname ? DS_MODE_NONE : DS_MODE_EXCLUSIVE, FTAG, &ds);

	if (err == 0 && snapname) {
		err = zap_lookup(mos, ds->ds_phys->ds_snapnames_zapobj,
		    snapname, 8, 1, &obj);
		dsl_dataset_close(ds, DS_MODE_NONE, FTAG);
		if (err == 0) {
			err = dsl_dataset_open_obj(dd->dd_pool, obj, NULL,
			    DS_MODE_EXCLUSIVE, FTAG, &ds);
		}
	}
	if (err) {
		if (drop_lock)
			rw_exit(&dp->dp_config_rwlock);
		return (err);
	}

	obj = ds->ds_object;

	/* Can't delete a branch point. */
	if (ds->ds_phys->ds_num_children > 1) {
		dsl_dataset_close(ds, DS_MODE_EXCLUSIVE, FTAG);
		if (drop_lock)
			rw_exit(&dp->dp_config_rwlock);
		return (EINVAL);
	}

	/*
	 * Can't delete a head dataset if there are snapshots of it.
	 * (Except if the only snapshots are from the branch we cloned
	 * from.)
	 */
	if (ds->ds_prev != NULL &&
	    ds->ds_prev->ds_phys->ds_next_snap_obj == obj) {
		dsl_dataset_close(ds, DS_MODE_EXCLUSIVE, FTAG);
		if (drop_lock)
			rw_exit(&dp->dp_config_rwlock);
		return (EINVAL);
	}

	/*
	 * If we made changes this txg, traverse_dsl_dataset won't find
	 * them.  Try again.
	 */
	if (ds->ds_phys->ds_bp.blk_birth >= tx->tx_txg) {
		dsl_dataset_close(ds, DS_MODE_NONE, FTAG);
		if (drop_lock)
			rw_exit(&dp->dp_config_rwlock);
		return (EAGAIN);
	}

	if (ds->ds_phys->ds_prev_snap_obj != 0) {
		if (ds->ds_prev) {
			ds_prev = ds->ds_prev;
		} else {
			err = dsl_dataset_open_obj(dd->dd_pool,
			    ds->ds_phys->ds_prev_snap_obj, NULL,
			    DS_MODE_NONE, FTAG, &ds_prev);
			if (err) {
				dsl_dataset_close(ds, DS_MODE_NONE, FTAG);
				if (drop_lock)
					rw_exit(&dp->dp_config_rwlock);
				return (err);
			}
		}
		after_branch_point =
		    (ds_prev->ds_phys->ds_next_snap_obj != obj);

		dmu_buf_will_dirty(ds_prev->ds_dbuf, tx);
		if (after_branch_point &&
		    ds->ds_phys->ds_next_snap_obj == 0) {
			/* This clone is toast. */
			ASSERT(ds_prev->ds_phys->ds_num_children > 1);
			ds_prev->ds_phys->ds_num_children--;
		} else if (!after_branch_point) {
			ds_prev->ds_phys->ds_next_snap_obj =
			    ds->ds_phys->ds_next_snap_obj;
		}
	}

	/* THE POINT OF NO (unsuccessful) RETURN */

	ASSERT3P(tx->tx_pool, ==, dd->dd_pool);
	zio = zio_root(dp->dp_spa, NULL, NULL, ZIO_FLAG_MUSTSUCCEED);

	if (ds->ds_phys->ds_next_snap_obj != 0) {
		dsl_dataset_t *ds_next;
		uint64_t itor = 0;

		spa_scrub_restart(dp->dp_spa, tx->tx_txg);

		VERIFY(0 == dsl_dataset_open_obj(dd->dd_pool,
		    ds->ds_phys->ds_next_snap_obj, NULL,
		    DS_MODE_NONE, FTAG, &ds_next));
		ASSERT3U(ds_next->ds_phys->ds_prev_snap_obj, ==, obj);

		dmu_buf_will_dirty(ds_next->ds_dbuf, tx);
		ds_next->ds_phys->ds_prev_snap_obj =
		    ds->ds_phys->ds_prev_snap_obj;
		ds_next->ds_phys->ds_prev_snap_txg =
		    ds->ds_phys->ds_prev_snap_txg;
		ASSERT3U(ds->ds_phys->ds_prev_snap_txg, ==,
		    ds_prev ? ds_prev->ds_phys->ds_creation_txg : 0);

		/*
		 * Transfer to our deadlist (which will become next's
		 * new deadlist) any entries from next's current
		 * deadlist which were born before prev, and free the
		 * other entries.
		 *
		 * XXX we're doing this long task with the config lock held
		 */
		while (bplist_iterate(&ds_next->ds_deadlist, &itor,
		    &bp) == 0) {
			if (bp.blk_birth <= ds->ds_phys->ds_prev_snap_txg) {
				VERIFY(0 == bplist_enqueue(&ds->ds_deadlist,
				    &bp, tx));
				if (ds_prev && !after_branch_point &&
				    bp.blk_birth >
				    ds_prev->ds_phys->ds_prev_snap_txg) {
					ds_prev->ds_phys->ds_unique_bytes +=
					    BP_GET_ASIZE(&bp);
				}
			} else {
				used += BP_GET_ASIZE(&bp);
				compressed += BP_GET_PSIZE(&bp);
				uncompressed += BP_GET_UCSIZE(&bp);
				/* XXX check return value? */
				(void) arc_free(zio, dp->dp_spa, tx->tx_txg,
				    &bp, NULL, NULL, ARC_NOWAIT);
			}
		}

		/* free next's deadlist */
		bplist_close(&ds_next->ds_deadlist);
		bplist_destroy(mos, ds_next->ds_phys->ds_deadlist_obj, tx);

		/* set next's deadlist to our deadlist */
		ds_next->ds_phys->ds_deadlist_obj =
		    ds->ds_phys->ds_deadlist_obj;
		VERIFY(0 == bplist_open(&ds_next->ds_deadlist, mos,
		    ds_next->ds_phys->ds_deadlist_obj));
		ds->ds_phys->ds_deadlist_obj = 0;

		if (ds_next->ds_phys->ds_next_snap_obj != 0) {
			/*
			 * Update next's unique to include blocks which
			 * were previously shared by only this snapshot
			 * and it.  Those blocks will be born after the
			 * prev snap and before this snap, and will have
			 * died after the next snap and before the one
			 * after that (ie. be on the snap after next's
			 * deadlist).
			 *
			 * XXX we're doing this long task with the
			 * config lock held
			 */
			dsl_dataset_t *ds_after_next;

			VERIFY(0 == dsl_dataset_open_obj(dd->dd_pool,
			    ds_next->ds_phys->ds_next_snap_obj, NULL,
			    DS_MODE_NONE, FTAG, &ds_after_next));
			itor = 0;
			while (bplist_iterate(&ds_after_next->ds_deadlist,
			    &itor, &bp) == 0) {
				if (bp.blk_birth >
				    ds->ds_phys->ds_prev_snap_txg &&
				    bp.blk_birth <=
				    ds->ds_phys->ds_creation_txg) {
					ds_next->ds_phys->ds_unique_bytes +=
					    BP_GET_ASIZE(&bp);
				}
			}

			dsl_dataset_close(ds_after_next, DS_MODE_NONE, FTAG);
			ASSERT3P(ds_next->ds_prev, ==, NULL);
		} else {
			/*
			 * It would be nice to update the head dataset's
			 * unique.  To do so we would have to traverse
			 * it for blocks born after ds_prev, which is
			 * pretty expensive just to maintain something
			 * for debugging purposes.
			 */
			ASSERT3P(ds_next->ds_prev, ==, ds);
			dsl_dataset_close(ds_next->ds_prev, DS_MODE_NONE,
			    ds_next);
			if (ds_prev) {
				VERIFY(0 == dsl_dataset_open_obj(dd->dd_pool,
				    ds->ds_phys->ds_prev_snap_obj, NULL,
				    DS_MODE_NONE, ds_next, &ds_next->ds_prev));
			} else {
				ds_next->ds_prev = NULL;
			}
		}
		dsl_dataset_close(ds_next, DS_MODE_NONE, FTAG);

		/*
		 * NB: unique_bytes is not accurate for head objsets
		 * because we don't update it when we delete the most
		 * recent snapshot -- see above comment.
		 */
		ASSERT3U(used, ==, ds->ds_phys->ds_unique_bytes);
	} else {
		/*
		 * There's no next snapshot, so this is a head dataset.
		 * Destroy the deadlist.  Unless it's a clone, the
		 * deadlist should be empty.  (If it's a clone, it's
		 * safe to ignore the deadlist contents.)
		 */
		struct killarg ka;

		ASSERT(after_branch_point || bplist_empty(&ds->ds_deadlist));
		bplist_close(&ds->ds_deadlist);
		bplist_destroy(mos, ds->ds_phys->ds_deadlist_obj, tx);
		ds->ds_phys->ds_deadlist_obj = 0;

		/*
		 * Free everything that we point to (that's born after
		 * the previous snapshot, if we are a clone)
		 *
		 * XXX we're doing this long task with the config lock held
		 */
		ka.usedp = &used;
		ka.compressedp = &compressed;
		ka.uncompressedp = &uncompressed;
		ka.zio = zio;
		ka.tx = tx;
		err = traverse_dsl_dataset(ds, ds->ds_phys->ds_prev_snap_txg,
		    ADVANCE_POST, kill_blkptr, &ka);
		ASSERT3U(err, ==, 0);
	}

	err = zio_wait(zio);
	ASSERT3U(err, ==, 0);

	dsl_dir_diduse_space(dd, -used, -compressed, -uncompressed, tx);

	if (ds->ds_phys->ds_snapnames_zapobj) {
		err = zap_destroy(mos, ds->ds_phys->ds_snapnames_zapobj, tx);
		ASSERT(err == 0);
	}

	if (dd->dd_phys->dd_head_dataset_obj == ds->ds_object) {
		/* Erase the link in the dataset */
		dmu_buf_will_dirty(dd->dd_dbuf, tx);
		dd->dd_phys->dd_head_dataset_obj = 0;
		/*
		 * dsl_dir_sync_destroy() called us, they'll destroy
		 * the dataset.
		 */
	} else {
		/* remove from snapshot namespace */
		dsl_dataset_t *ds_head;
		VERIFY(0 == dsl_dataset_open_obj(dd->dd_pool,
		    dd->dd_phys->dd_head_dataset_obj, NULL,
		    DS_MODE_NONE, FTAG, &ds_head));
#ifdef ZFS_DEBUG
		{
			uint64_t val;
			err = zap_lookup(mos,
			    ds_head->ds_phys->ds_snapnames_zapobj,
			    snapname, 8, 1, &val);
			ASSERT3U(err, ==, 0);
			ASSERT3U(val, ==, obj);
		}
#endif
		err = zap_remove(mos, ds_head->ds_phys->ds_snapnames_zapobj,
		    snapname, tx);
		ASSERT(err == 0);
		dsl_dataset_close(ds_head, DS_MODE_NONE, FTAG);
	}

	if (ds_prev && ds->ds_prev != ds_prev)
		dsl_dataset_close(ds_prev, DS_MODE_NONE, FTAG);

	err = dmu_object_free(mos, obj, tx);
	ASSERT(err == 0);

	/*
	 * Close the objset with mode NONE, thus leaving it with
	 * DOS_REF_MAX set, so that noone can access it.
	 */
	dsl_dataset_close(ds, DS_MODE_NONE, FTAG);

	if (drop_lock)
		rw_exit(&dp->dp_config_rwlock);
	return (0);
}

int
dsl_dataset_snapshot_sync(dsl_dir_t *dd, void *arg, dmu_tx_t *tx)
{
	const char *snapname = arg;
	dsl_pool_t *dp = dd->dd_pool;
	dmu_buf_t *dbuf;
	dsl_dataset_phys_t *dsphys;
	uint64_t dsobj, value;
	objset_t *mos = dp->dp_meta_objset;
	dsl_dataset_t *ds;
	int err;

	ASSERT(dmu_tx_is_syncing(tx));

	if (dd->dd_phys->dd_head_dataset_obj == 0)
		return (EINVAL);
	err = dsl_dataset_open_obj(dp, dd->dd_phys->dd_head_dataset_obj, NULL,
	    DS_MODE_NONE, FTAG, &ds);
	if (err)
		return (err);

	err = zap_lookup(mos, ds->ds_phys->ds_snapnames_zapobj,
	    snapname, 8, 1, &value);
	if (err == 0) {
		dsl_dataset_close(ds, DS_MODE_NONE, FTAG);
		return (EEXIST);
	}
	ASSERT(err == ENOENT);

	/* The point of no (unsuccessful) return */

	dprintf_dd(dd, "taking snapshot %s in txg %llu\n",
	    snapname, tx->tx_txg);

	spa_scrub_restart(dp->dp_spa, tx->tx_txg);

	rw_enter(&dp->dp_config_rwlock, RW_WRITER);

	dsobj = dmu_object_alloc(mos, DMU_OT_DSL_DATASET, 0,
	    DMU_OT_DSL_DATASET, sizeof (dsl_dataset_phys_t), tx);
	VERIFY(0 == dmu_bonus_hold(mos, dsobj, FTAG, &dbuf));
	dmu_buf_will_dirty(dbuf, tx);
	dsphys = dbuf->db_data;
	dsphys->ds_dir_obj = dd->dd_object;
	dsphys->ds_fsid_guid = unique_create();
	unique_remove(dsphys->ds_fsid_guid); /* it isn't open yet */
	(void) random_get_pseudo_bytes((void*)&dsphys->ds_guid,
	    sizeof (dsphys->ds_guid));
	dsphys->ds_prev_snap_obj = ds->ds_phys->ds_prev_snap_obj;
	dsphys->ds_prev_snap_txg = ds->ds_phys->ds_prev_snap_txg;
	dsphys->ds_next_snap_obj = ds->ds_object;
	dsphys->ds_num_children = 1;
	dsphys->ds_creation_time = gethrestime_sec();
	dsphys->ds_creation_txg = tx->tx_txg;
	dsphys->ds_deadlist_obj = ds->ds_phys->ds_deadlist_obj;
	dsphys->ds_used_bytes = ds->ds_phys->ds_used_bytes;
	dsphys->ds_compressed_bytes = ds->ds_phys->ds_compressed_bytes;
	dsphys->ds_uncompressed_bytes = ds->ds_phys->ds_uncompressed_bytes;
	dsphys->ds_restoring = ds->ds_phys->ds_restoring;
	dsphys->ds_bp = ds->ds_phys->ds_bp;
	dmu_buf_rele(dbuf, FTAG);

	if (ds->ds_phys->ds_prev_snap_obj != 0) {
		dsl_dataset_t *ds_prev;

		VERIFY(0 == dsl_dataset_open_obj(dp,
		    ds->ds_phys->ds_prev_snap_obj, NULL,
		    DS_MODE_NONE, FTAG, &ds_prev));
		ASSERT(ds_prev->ds_phys->ds_next_snap_obj ==
		    ds->ds_object ||
		    ds_prev->ds_phys->ds_num_children > 1);
		if (ds_prev->ds_phys->ds_next_snap_obj == ds->ds_object) {
			dmu_buf_will_dirty(ds_prev->ds_dbuf, tx);
			ASSERT3U(ds->ds_phys->ds_prev_snap_txg, ==,
			    ds_prev->ds_phys->ds_creation_txg);
			ds_prev->ds_phys->ds_next_snap_obj = dsobj;
		}
		dsl_dataset_close(ds_prev, DS_MODE_NONE, FTAG);
	} else {
		ASSERT3U(ds->ds_phys->ds_prev_snap_txg, ==, 0);
	}

	bplist_close(&ds->ds_deadlist);
	dmu_buf_will_dirty(ds->ds_dbuf, tx);
	ASSERT3U(ds->ds_phys->ds_prev_snap_txg, <, dsphys->ds_creation_txg);
	ds->ds_phys->ds_prev_snap_obj = dsobj;
	ds->ds_phys->ds_prev_snap_txg = dsphys->ds_creation_txg;
	ds->ds_phys->ds_unique_bytes = 0;
	ds->ds_phys->ds_deadlist_obj =
	    bplist_create(mos, DSL_DEADLIST_BLOCKSIZE, tx);
	VERIFY(0 == bplist_open(&ds->ds_deadlist, mos,
	    ds->ds_phys->ds_deadlist_obj));

	dprintf("snap '%s' -> obj %llu\n", snapname, dsobj);
	err = zap_add(mos, ds->ds_phys->ds_snapnames_zapobj,
	    snapname, 8, 1, &dsobj, tx);
	ASSERT(err == 0);

	if (ds->ds_prev)
		dsl_dataset_close(ds->ds_prev, DS_MODE_NONE, ds);
	VERIFY(0 == dsl_dataset_open_obj(dp,
	    ds->ds_phys->ds_prev_snap_obj, snapname,
	    DS_MODE_NONE, ds, &ds->ds_prev));

	rw_exit(&dp->dp_config_rwlock);
	dsl_dataset_close(ds, DS_MODE_NONE, FTAG);

	return (0);
}

void
dsl_dataset_sync(dsl_dataset_t *ds, dmu_tx_t *tx)
{
	ASSERT(dmu_tx_is_syncing(tx));
	ASSERT(ds->ds_user_ptr != NULL);
	ASSERT(ds->ds_phys->ds_next_snap_obj == 0);

	dmu_objset_sync(ds->ds_user_ptr, tx);
	dsl_dir_dirty(ds->ds_dir, tx);
	bplist_close(&ds->ds_deadlist);

	dmu_buf_rele(ds->ds_dbuf, ds);
}

void
dsl_dataset_stats(dsl_dataset_t *ds, dmu_objset_stats_t *dds)
{
	/* fill in properties crap */
	dsl_dir_stats(ds->ds_dir, dds);

	if (ds->ds_phys->ds_num_children != 0) {
		dds->dds_is_snapshot = TRUE;
		dds->dds_num_clones = ds->ds_phys->ds_num_children - 1;
	}

	dds->dds_last_txg = ds->ds_phys->ds_bp.blk_birth;

	dds->dds_objects_used = ds->ds_phys->ds_bp.blk_fill;
	dds->dds_objects_avail = DN_MAX_OBJECT - dds->dds_objects_used;

	/* We override the dataset's creation time... they should be the same */
	dds->dds_creation_time = ds->ds_phys->ds_creation_time;
	dds->dds_creation_txg = ds->ds_phys->ds_creation_txg;
	dds->dds_space_refd = ds->ds_phys->ds_used_bytes;
	dds->dds_fsid_guid = ds->ds_phys->ds_fsid_guid;

	if (ds->ds_phys->ds_next_snap_obj) {
		/*
		 * This is a snapshot; override the dd's space used with
		 * our unique space
		 */
		dds->dds_space_used = ds->ds_phys->ds_unique_bytes;
		dds->dds_compressed_bytes =
		    ds->ds_phys->ds_compressed_bytes;
		dds->dds_uncompressed_bytes =
		    ds->ds_phys->ds_uncompressed_bytes;
	}
}

dsl_pool_t *
dsl_dataset_pool(dsl_dataset_t *ds)
{
	return (ds->ds_dir->dd_pool);
}

struct osrenamearg {
	const char *oldname;
	const char *newname;
};

static int
dsl_dataset_snapshot_rename_sync(dsl_dir_t *dd, void *arg, dmu_tx_t *tx)
{
	struct osrenamearg *ora = arg;
	objset_t *mos = dd->dd_pool->dp_meta_objset;
	dsl_dir_t *nds;
	const char *tail;
	int err;
	dsl_dataset_t *snds, *fsds;
	uint64_t val;

	err = dsl_dataset_open_spa(dd->dd_pool->dp_spa, ora->oldname,
	    DS_MODE_READONLY | DS_MODE_STANDARD, FTAG, &snds);
	if (err)
		return (err);

	if (snds->ds_dir != dd) {
		dsl_dataset_close(snds, DS_MODE_STANDARD, FTAG);
		return (EINVAL);
	}

	/* better be changing a snapshot */
	if (snds->ds_phys->ds_next_snap_obj == 0) {
		dsl_dataset_close(snds, DS_MODE_STANDARD, FTAG);
		return (EINVAL);
	}

	/* new fs better exist */
	err = dsl_dir_open_spa(dd->dd_pool->dp_spa, ora->newname,
	    FTAG, &nds, &tail);
	if (err) {
		dsl_dataset_close(snds, DS_MODE_STANDARD, FTAG);
		return (err);
	}

	dsl_dir_close(nds, FTAG);

	/* new name better be in same fs */
	if (nds != dd) {
		dsl_dataset_close(snds, DS_MODE_STANDARD, FTAG);
		return (EINVAL);
	}

	/* new name better be a snapshot */
	if (tail == NULL || tail[0] != '@') {
		dsl_dataset_close(snds, DS_MODE_STANDARD, FTAG);
		return (EINVAL);
	}

	tail++;

	err = dsl_dataset_open_obj(dd->dd_pool,
	    dd->dd_phys->dd_head_dataset_obj, NULL, DS_MODE_NONE, FTAG, &fsds);
	if (err) {
		dsl_dataset_close(snds, DS_MODE_STANDARD, FTAG);
		return (err);
	}

	/* new name better not be in use */
	err = zap_lookup(mos, fsds->ds_phys->ds_snapnames_zapobj,
	    tail, 8, 1, &val);
	if (err != ENOENT) {
		if (err == 0)
			err = EEXIST;
		dsl_dataset_close(fsds, DS_MODE_NONE, FTAG);
		dsl_dataset_close(snds, DS_MODE_STANDARD, FTAG);
		return (EEXIST);
	}

	/* The point of no (unsuccessful) return */

	rw_enter(&dd->dd_pool->dp_config_rwlock, RW_WRITER);
	VERIFY(0 == dsl_dataset_get_snapname(snds));
	err = zap_remove(mos, fsds->ds_phys->ds_snapnames_zapobj,
	    snds->ds_snapname, tx);
	ASSERT3U(err, ==, 0);
	mutex_enter(&snds->ds_lock);
	(void) strcpy(snds->ds_snapname, tail);
	mutex_exit(&snds->ds_lock);
	err = zap_add(mos, fsds->ds_phys->ds_snapnames_zapobj,
	    snds->ds_snapname, 8, 1, &snds->ds_object, tx);
	ASSERT3U(err, ==, 0);
	rw_exit(&dd->dd_pool->dp_config_rwlock);

	dsl_dataset_close(fsds, DS_MODE_NONE, FTAG);
	dsl_dataset_close(snds, DS_MODE_STANDARD, FTAG);
	return (0);
}

#pragma weak dmu_objset_rename = dsl_dataset_rename
int
dsl_dataset_rename(const char *osname, const char *newname)
{
	dsl_dir_t *dd;
	const char *tail;
	struct osrenamearg ora;
	int err;

	err = dsl_dir_open(osname, FTAG, &dd, &tail);
	if (err)
		return (err);
	if (tail == NULL) {
		err = dsl_dir_sync_task(dd,
		    dsl_dir_rename_sync, (void*)newname, 1<<12);
		dsl_dir_close(dd, FTAG);
		return (err);
	}
	if (tail[0] != '@') {
		/* the name ended in a nonexistant component */
		dsl_dir_close(dd, FTAG);
		return (ENOENT);
	}

	ora.oldname = osname;
	ora.newname = newname;

	err = dsl_dir_sync_task(dd,
	    dsl_dataset_snapshot_rename_sync, &ora, 1<<12);
	dsl_dir_close(dd, FTAG);
	return (err);
}
