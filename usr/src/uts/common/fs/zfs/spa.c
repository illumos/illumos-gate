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

/*
 * This file contains all the routines used when modifying on-disk SPA state.
 * This includes opening, importing, destroying, exporting a pool, and syncing a
 * pool.
 */

#include <sys/zfs_context.h>
#include <sys/fm/fs/zfs.h>
#include <sys/spa_impl.h>
#include <sys/zio.h>
#include <sys/zio_checksum.h>
#include <sys/zio_compress.h>
#include <sys/dmu.h>
#include <sys/dmu_tx.h>
#include <sys/zap.h>
#include <sys/zil.h>
#include <sys/vdev_impl.h>
#include <sys/metaslab.h>
#include <sys/uberblock_impl.h>
#include <sys/txg.h>
#include <sys/avl.h>
#include <sys/dmu_traverse.h>
#include <sys/unique.h>
#include <sys/dsl_pool.h>
#include <sys/dsl_dir.h>
#include <sys/dsl_prop.h>
#include <sys/fs/zfs.h>
#include <sys/callb.h>

static uint32_t spa_active_count;

/*
 * ==========================================================================
 * SPA state manipulation (open/create/destroy/import/export)
 * ==========================================================================
 */

static int
spa_error_entry_compare(const void *a, const void *b)
{
	spa_error_entry_t *sa = (spa_error_entry_t *)a;
	spa_error_entry_t *sb = (spa_error_entry_t *)b;
	int ret;

	ret = bcmp(&sa->se_bookmark, &sb->se_bookmark,
	    sizeof (zbookmark_t));

	if (ret < 0)
		return (-1);
	else if (ret > 0)
		return (1);
	else
		return (0);
}

/*
 * Utility function which retrieves copies of the current logs and
 * re-initializes them in the process.
 */
void
spa_get_errlists(spa_t *spa, avl_tree_t *last, avl_tree_t *scrub)
{
	ASSERT(MUTEX_HELD(&spa->spa_errlist_lock));

	bcopy(&spa->spa_errlist_last, last, sizeof (avl_tree_t));
	bcopy(&spa->spa_errlist_scrub, scrub, sizeof (avl_tree_t));

	avl_create(&spa->spa_errlist_scrub,
	    spa_error_entry_compare, sizeof (spa_error_entry_t),
	    offsetof(spa_error_entry_t, se_avl));
	avl_create(&spa->spa_errlist_last,
	    spa_error_entry_compare, sizeof (spa_error_entry_t),
	    offsetof(spa_error_entry_t, se_avl));
}

/*
 * Activate an uninitialized pool.
 */
static void
spa_activate(spa_t *spa)
{
	int t;

	ASSERT(spa->spa_state == POOL_STATE_UNINITIALIZED);

	spa->spa_state = POOL_STATE_ACTIVE;

	spa->spa_normal_class = metaslab_class_create();

	for (t = 0; t < ZIO_TYPES; t++) {
		spa->spa_zio_issue_taskq[t] = taskq_create("spa_zio_issue",
		    8, maxclsyspri, 50, INT_MAX,
		    TASKQ_PREPOPULATE);
		spa->spa_zio_intr_taskq[t] = taskq_create("spa_zio_intr",
		    8, maxclsyspri, 50, INT_MAX,
		    TASKQ_PREPOPULATE);
	}

	rw_init(&spa->spa_traverse_lock, NULL, RW_DEFAULT, NULL);

	list_create(&spa->spa_dirty_list, sizeof (vdev_t),
	    offsetof(vdev_t, vdev_dirty_node));

	txg_list_create(&spa->spa_vdev_txg_list,
	    offsetof(struct vdev, vdev_txg_node));

	avl_create(&spa->spa_errlist_scrub,
	    spa_error_entry_compare, sizeof (spa_error_entry_t),
	    offsetof(spa_error_entry_t, se_avl));
	avl_create(&spa->spa_errlist_last,
	    spa_error_entry_compare, sizeof (spa_error_entry_t),
	    offsetof(spa_error_entry_t, se_avl));
}

/*
 * Opposite of spa_activate().
 */
static void
spa_deactivate(spa_t *spa)
{
	int t;

	ASSERT(spa->spa_sync_on == B_FALSE);
	ASSERT(spa->spa_dsl_pool == NULL);
	ASSERT(spa->spa_root_vdev == NULL);

	ASSERT(spa->spa_state != POOL_STATE_UNINITIALIZED);

	txg_list_destroy(&spa->spa_vdev_txg_list);

	list_destroy(&spa->spa_dirty_list);

	rw_destroy(&spa->spa_traverse_lock);

	for (t = 0; t < ZIO_TYPES; t++) {
		taskq_destroy(spa->spa_zio_issue_taskq[t]);
		taskq_destroy(spa->spa_zio_intr_taskq[t]);
		spa->spa_zio_issue_taskq[t] = NULL;
		spa->spa_zio_intr_taskq[t] = NULL;
	}

	metaslab_class_destroy(spa->spa_normal_class);
	spa->spa_normal_class = NULL;

	/*
	 * If this was part of an import or the open otherwise failed, we may
	 * still have errors left in the queues.  Empty them just in case.
	 */
	spa_errlog_drain(spa);

	avl_destroy(&spa->spa_errlist_scrub);
	avl_destroy(&spa->spa_errlist_last);

	spa->spa_state = POOL_STATE_UNINITIALIZED;
}

/*
 * Verify a pool configuration, and construct the vdev tree appropriately.  This
 * will create all the necessary vdevs in the appropriate layout, with each vdev
 * in the CLOSED state.  This will prep the pool before open/creation/import.
 * All vdev validation is done by the vdev_alloc() routine.
 */
static vdev_t *
spa_config_parse(spa_t *spa, nvlist_t *nv, vdev_t *parent, uint_t id, int atype)
{
	nvlist_t **child;
	uint_t c, children;
	vdev_t *vd;

	if ((vd = vdev_alloc(spa, nv, parent, id, atype)) == NULL)
		return (NULL);

	if (vd->vdev_ops->vdev_op_leaf)
		return (vd);

	if (nvlist_lookup_nvlist_array(nv, ZPOOL_CONFIG_CHILDREN,
	    &child, &children) != 0) {
		vdev_free(vd);
		return (NULL);
	}

	for (c = 0; c < children; c++) {
		if (spa_config_parse(spa, child[c], vd, c, atype) == NULL) {
			vdev_free(vd);
			return (NULL);
		}
	}

	return (vd);
}

/*
 * Opposite of spa_load().
 */
static void
spa_unload(spa_t *spa)
{
	/*
	 * Stop async tasks.
	 */
	spa_async_suspend(spa);

	/*
	 * Stop syncing.
	 */
	if (spa->spa_sync_on) {
		txg_sync_stop(spa->spa_dsl_pool);
		spa->spa_sync_on = B_FALSE;
	}

	/*
	 * Wait for any outstanding prefetch I/O to complete.
	 */
	spa_config_enter(spa, RW_WRITER, FTAG);
	spa_config_exit(spa, FTAG);

	/*
	 * Close the dsl pool.
	 */
	if (spa->spa_dsl_pool) {
		dsl_pool_close(spa->spa_dsl_pool);
		spa->spa_dsl_pool = NULL;
	}

	/*
	 * Close all vdevs.
	 */
	if (spa->spa_root_vdev)
		vdev_free(spa->spa_root_vdev);
	ASSERT(spa->spa_root_vdev == NULL);

	spa->spa_async_suspended = 0;
}

/*
 * Load an existing storage pool, using the pool's builtin spa_config as a
 * source of configuration information.
 */
static int
spa_load(spa_t *spa, nvlist_t *config, spa_load_state_t state, int mosconfig)
{
	int error = 0;
	uint64_t config_cache_txg = spa->spa_config_txg;
	nvlist_t *nvroot = NULL;
	vdev_t *rvd;
	uberblock_t *ub = &spa->spa_uberblock;
	uint64_t pool_guid;
	zio_t *zio;

	spa->spa_load_state = state;
	if (nvlist_lookup_nvlist(config, ZPOOL_CONFIG_VDEV_TREE, &nvroot) ||
	    nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_GUID, &pool_guid)) {
		error = EINVAL;
		goto out;
	}

	(void) nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_TXG,
	    &spa->spa_config_txg);

	if ((spa->spa_load_state == SPA_LOAD_IMPORT ||
	    spa->spa_load_state == SPA_LOAD_TRYIMPORT) &&
	    spa_guid_exists(pool_guid, 0)) {
		error = EEXIST;
		goto out;
	}

	/*
	 * Parse the configuration into a vdev tree.
	 */
	spa_config_enter(spa, RW_WRITER, FTAG);
	rvd = spa_config_parse(spa, nvroot, NULL, 0, VDEV_ALLOC_LOAD);
	spa_config_exit(spa, FTAG);

	if (rvd == NULL) {
		error = EINVAL;
		goto out;
	}

	ASSERT(spa->spa_root_vdev == rvd);
	ASSERT(spa_guid(spa) == pool_guid);

	/*
	 * Try to open all vdevs, loading each label in the process.
	 */
	if (vdev_open(rvd) != 0) {
		error = ENXIO;
		goto out;
	}

	/*
	 * Find the best uberblock.
	 */
	bzero(ub, sizeof (uberblock_t));

	zio = zio_root(spa, NULL, NULL,
	    ZIO_FLAG_CANFAIL | ZIO_FLAG_SPECULATIVE);
	vdev_uberblock_load(zio, rvd, ub);
	error = zio_wait(zio);

	/*
	 * If we weren't able to find a single valid uberblock, return failure.
	 */
	if (ub->ub_txg == 0) {
		error = ENXIO;
		goto out;
	}

	/*
	 * If the pool is newer than the code, we can't open it.
	 */
	if (ub->ub_version > UBERBLOCK_VERSION) {
		error = ENOTSUP;
		goto out;
	}

	/*
	 * If the vdev guid sum doesn't match the uberblock, we have an
	 * incomplete configuration.
	 */
	if (rvd->vdev_guid_sum != ub->ub_guid_sum && mosconfig) {
		vdev_set_state(rvd, B_TRUE, VDEV_STATE_CANT_OPEN,
		    VDEV_AUX_BAD_GUID_SUM);
		error = ENXIO;
		goto out;
	}

	/*
	 * Initialize internal SPA structures.
	 */
	spa->spa_state = POOL_STATE_ACTIVE;
	spa->spa_ubsync = spa->spa_uberblock;
	spa->spa_first_txg = spa_last_synced_txg(spa) + 1;
	error = dsl_pool_open(spa, spa->spa_first_txg, &spa->spa_dsl_pool);
	if (error) {
		vdev_set_state(rvd, B_TRUE, VDEV_STATE_CANT_OPEN,
		    VDEV_AUX_CORRUPT_DATA);
		goto out;
	}
	spa->spa_meta_objset = spa->spa_dsl_pool->dp_meta_objset;

	if (zap_lookup(spa->spa_meta_objset,
	    DMU_POOL_DIRECTORY_OBJECT, DMU_POOL_CONFIG,
	    sizeof (uint64_t), 1, &spa->spa_config_object) != 0) {
		vdev_set_state(rvd, B_TRUE, VDEV_STATE_CANT_OPEN,
		    VDEV_AUX_CORRUPT_DATA);
		error = EIO;
		goto out;
	}

	if (!mosconfig) {
		dmu_buf_t *db;
		char *packed = NULL;
		size_t nvsize = 0;
		nvlist_t *newconfig = NULL;

		VERIFY(0 == dmu_bonus_hold(spa->spa_meta_objset,
		    spa->spa_config_object, FTAG, &db));
		nvsize = *(uint64_t *)db->db_data;
		dmu_buf_rele(db, FTAG);

		packed = kmem_alloc(nvsize, KM_SLEEP);
		error = dmu_read(spa->spa_meta_objset,
		    spa->spa_config_object, 0, nvsize, packed);
		if (error == 0)
			error = nvlist_unpack(packed, nvsize, &newconfig, 0);
		kmem_free(packed, nvsize);

		if (error) {
			vdev_set_state(rvd, B_TRUE, VDEV_STATE_CANT_OPEN,
			    VDEV_AUX_CORRUPT_DATA);
			error = EIO;
			goto out;
		}

		spa_config_set(spa, newconfig);

		spa_unload(spa);
		spa_deactivate(spa);
		spa_activate(spa);

		return (spa_load(spa, newconfig, state, B_TRUE));
	}

	if (zap_lookup(spa->spa_meta_objset,
	    DMU_POOL_DIRECTORY_OBJECT, DMU_POOL_SYNC_BPLIST,
	    sizeof (uint64_t), 1, &spa->spa_sync_bplist_obj) != 0) {
		vdev_set_state(rvd, B_TRUE, VDEV_STATE_CANT_OPEN,
		    VDEV_AUX_CORRUPT_DATA);
		error = EIO;
		goto out;
	}

	/*
	 * Load the persistent error log.  If we have an older pool, this will
	 * not be present.
	 */
	error = zap_lookup(spa->spa_meta_objset,
	    DMU_POOL_DIRECTORY_OBJECT, DMU_POOL_ERRLOG_LAST,
	    sizeof (uint64_t), 1, &spa->spa_errlog_last);
	if (error != 0 &&error != ENOENT) {
		vdev_set_state(rvd, B_TRUE, VDEV_STATE_CANT_OPEN,
		    VDEV_AUX_CORRUPT_DATA);
		error = EIO;
		goto out;
	}

	error = zap_lookup(spa->spa_meta_objset,
	    DMU_POOL_DIRECTORY_OBJECT, DMU_POOL_ERRLOG_SCRUB,
	    sizeof (uint64_t), 1, &spa->spa_errlog_scrub);
	if (error != 0 && error != ENOENT) {
		vdev_set_state(rvd, B_TRUE, VDEV_STATE_CANT_OPEN,
		    VDEV_AUX_CORRUPT_DATA);
		error = EIO;
		goto out;
	}

	/*
	 * Load the vdev state for all top level vdevs.  We need to grab the
	 * config lock because all label I/O is done with the
	 * ZIO_FLAG_CONFIG_HELD flag.
	 */
	spa_config_enter(spa, RW_READER, FTAG);
	if ((error = vdev_load(rvd)) != 0) {
		spa_config_exit(spa, FTAG);
		goto out;
	}
	spa_config_exit(spa, FTAG);

	/*
	 * Propagate the leaf DTLs we just loaded all the way up the tree.
	 */
	spa_config_enter(spa, RW_WRITER, FTAG);
	vdev_dtl_reassess(rvd, 0, 0, B_FALSE);
	spa_config_exit(spa, FTAG);

	/*
	 * Check the state of the root vdev.  If it can't be opened, it
	 * indicates one or more toplevel vdevs are faulted.
	 */
	if (rvd->vdev_state <= VDEV_STATE_CANT_OPEN) {
		error = ENXIO;
		goto out;
	}

	/*
	 * Claim log blocks that haven't been committed yet, and update all
	 * top-level vdevs to sync any config changes found in vdev_load().
	 * This must all happen in a single txg.
	 */
	if ((spa_mode & FWRITE) && state != SPA_LOAD_TRYIMPORT) {
		int c;
		dmu_tx_t *tx;

		spa_config_enter(spa, RW_WRITER, FTAG);
		vdev_config_dirty(rvd);
		spa_config_exit(spa, FTAG);

		tx = dmu_tx_create_assigned(spa_get_dsl(spa),
		    spa_first_txg(spa));
		dmu_objset_find(spa->spa_name, zil_claim, tx, 0);
		dmu_tx_commit(tx);

		spa->spa_sync_on = B_TRUE;
		txg_sync_start(spa->spa_dsl_pool);

		/*
		 * Wait for all claims to sync.
		 */
		txg_wait_synced(spa->spa_dsl_pool, 0);

		/*
		 * If the config cache is stale relative to the mosconfig,
		 * sync the config cache.
		 */
		if (config_cache_txg != spa->spa_config_txg) {
			uint64_t txg;
			spa_config_enter(spa, RW_WRITER, FTAG);
			txg = spa_last_synced_txg(spa) + 1;
			spa_config_set(spa,
			    spa_config_generate(spa, rvd, txg, 0));
			spa_config_exit(spa, FTAG);
			txg_wait_synced(spa->spa_dsl_pool, txg);
			spa_config_sync();
		}

		/*
		 * If we have top-level vdevs that were added but have
		 * not yet been prepared for allocation, do that now.
		 * (It's safe now because the config cache is up to date,
		 * so it will be able to translate the new DVAs.)
		 * See comments in spa_vdev_add() for full details.
		 */
		for (c = 0; c < rvd->vdev_children; c++) {
			vdev_t *tvd = rvd->vdev_child[c];
			if (tvd->vdev_ms_array == 0) {
				uint64_t txg;
				ASSERT(tvd->vdev_ms_shift == 0);
				spa_config_enter(spa, RW_WRITER, FTAG);
				txg = spa_last_synced_txg(spa) + 1;
				vdev_init(tvd, txg);
				vdev_config_dirty(tvd);
				spa_config_set(spa,
				    spa_config_generate(spa, rvd, txg, 0));
				spa_config_exit(spa, FTAG);
				txg_wait_synced(spa->spa_dsl_pool, txg);
				ASSERT(tvd->vdev_ms_shift != 0);
				ASSERT(tvd->vdev_ms_array != 0);
				spa_config_sync();
			}
		}
	}

	error = 0;
out:
	if (error)
		zfs_ereport_post(FM_EREPORT_ZFS_POOL, spa, NULL, NULL, 0, 0);
	spa->spa_load_state = SPA_LOAD_NONE;
	spa->spa_ena = 0;

	return (error);
}

/*
 * Pool Open/Import
 *
 * The import case is identical to an open except that the configuration is sent
 * down from userland, instead of grabbed from the configuration cache.  For the
 * case of an open, the pool configuration will exist in the
 * POOL_STATE_UNITIALIZED state.
 *
 * The stats information (gen/count/ustats) is used to gather vdev statistics at
 * the same time open the pool, without having to keep around the spa_t in some
 * ambiguous state.
 */
static int
spa_open_common(const char *pool, spa_t **spapp, void *tag, nvlist_t **config)
{
	spa_t *spa;
	int error;
	int loaded = B_FALSE;
	int locked = B_FALSE;

	*spapp = NULL;

	/*
	 * As disgusting as this is, we need to support recursive calls to this
	 * function because dsl_dir_open() is called during spa_load(), and ends
	 * up calling spa_open() again.  The real fix is to figure out how to
	 * avoid dsl_dir_open() calling this in the first place.
	 */
	if (mutex_owner(&spa_namespace_lock) != curthread) {
		mutex_enter(&spa_namespace_lock);
		locked = B_TRUE;
	}

	if ((spa = spa_lookup(pool)) == NULL) {
		if (locked)
			mutex_exit(&spa_namespace_lock);
		return (ENOENT);
	}
	if (spa->spa_state == POOL_STATE_UNINITIALIZED) {

		spa_activate(spa);

		error = spa_load(spa, spa->spa_config,
		    SPA_LOAD_OPEN, B_FALSE);

		if (error == EBADF) {
			/*
			 * If vdev_load() returns EBADF, it indicates that one
			 * of the vdevs indicates that the pool has been
			 * exported or destroyed.  If this is the case, the
			 * config cache is out of sync and we should remove the
			 * pool from the namespace.
			 */
			spa_unload(spa);
			spa_deactivate(spa);
			spa_remove(spa);
			spa_config_sync();
			if (locked)
				mutex_exit(&spa_namespace_lock);
			return (ENOENT);
		}

		if (error) {
			/*
			 * We can't open the pool, but we still have useful
			 * information: the state of each vdev after the
			 * attempted vdev_open().  Return this to the user.
			 */
			if (config != NULL && spa->spa_root_vdev != NULL)
				*config = spa_config_generate(spa, NULL, -1ULL,
				    B_TRUE);
			spa_unload(spa);
			spa_deactivate(spa);
			spa->spa_last_open_failed = B_TRUE;
			if (locked)
				mutex_exit(&spa_namespace_lock);
			*spapp = NULL;
			return (error);
		} else {
			zfs_post_ok(spa, NULL);
			spa->spa_last_open_failed = B_FALSE;
		}

		loaded = B_TRUE;
	}

	spa_open_ref(spa, tag);
	if (locked)
		mutex_exit(&spa_namespace_lock);

	*spapp = spa;

	if (config != NULL) {
		spa_config_enter(spa, RW_READER, FTAG);
		*config = spa_config_generate(spa, NULL, -1ULL, B_TRUE);
		spa_config_exit(spa, FTAG);
	}

	/*
	 * If we just loaded the pool, resilver anything that's out of date.
	 */
	if (loaded && (spa_mode & FWRITE))
		VERIFY(spa_scrub(spa, POOL_SCRUB_RESILVER, B_TRUE) == 0);

	return (0);
}

int
spa_open(const char *name, spa_t **spapp, void *tag)
{
	return (spa_open_common(name, spapp, tag, NULL));
}

/*
 * Lookup the given spa_t, incrementing the inject count in the process,
 * preventing it from being exported or destroyed.
 */
spa_t *
spa_inject_addref(char *name)
{
	spa_t *spa;

	mutex_enter(&spa_namespace_lock);
	if ((spa = spa_lookup(name)) == NULL) {
		mutex_exit(&spa_namespace_lock);
		return (NULL);
	}
	spa->spa_inject_ref++;
	mutex_exit(&spa_namespace_lock);

	return (spa);
}

void
spa_inject_delref(spa_t *spa)
{
	mutex_enter(&spa_namespace_lock);
	spa->spa_inject_ref--;
	mutex_exit(&spa_namespace_lock);
}

int
spa_get_stats(const char *name, nvlist_t **config, char *altroot, size_t buflen)
{
	int error;
	spa_t *spa;

	*config = NULL;
	error = spa_open_common(name, &spa, FTAG, config);

	if (spa && *config != NULL)
		VERIFY(nvlist_add_uint64(*config, ZPOOL_CONFIG_ERRCOUNT,
		    spa_get_errlog_size(spa)) == 0);

	/*
	 * We want to get the alternate root even for faulted pools, so we cheat
	 * and call spa_lookup() directly.
	 */
	if (altroot) {
		if (spa == NULL) {
			mutex_enter(&spa_namespace_lock);
			spa = spa_lookup(name);
			if (spa)
				spa_altroot(spa, altroot, buflen);
			else
				altroot[0] = '\0';
			spa = NULL;
			mutex_exit(&spa_namespace_lock);
		} else {
			spa_altroot(spa, altroot, buflen);
		}
	}

	if (spa != NULL)
		spa_close(spa, FTAG);

	return (error);
}

/*
 * Pool Creation
 */
int
spa_create(const char *pool, nvlist_t *nvroot, char *altroot)
{
	spa_t *spa;
	dsl_pool_t *dp;
	dmu_tx_t *tx;
	int error;
	uint64_t txg = TXG_INITIAL;

	/*
	 * If this pool already exists, return failure.
	 */
	mutex_enter(&spa_namespace_lock);
	if (spa_lookup(pool) != NULL) {
		mutex_exit(&spa_namespace_lock);
		return (EEXIST);
	}
	spa = spa_add(pool);

	/*
	 * Allocate a new spa_t structure.
	 */
	spa_activate(spa);

	if (altroot != NULL) {
		spa->spa_root = spa_strdup(altroot);
		atomic_add_32(&spa_active_count, 1);
	}

	spa->spa_uberblock.ub_txg = txg - 1;
	spa->spa_ubsync = spa->spa_uberblock;

	error = spa_vdev_add(spa, nvroot);

	if (error) {
		spa_unload(spa);
		spa_deactivate(spa);
		spa_remove(spa);
		mutex_exit(&spa_namespace_lock);
		return (error);
	}

	spa->spa_dsl_pool = dp = dsl_pool_create(spa, txg);
	spa->spa_meta_objset = dp->dp_meta_objset;

	tx = dmu_tx_create_assigned(dp, txg);

	/*
	 * Create the pool config object.
	 */
	spa->spa_config_object = dmu_object_alloc(spa->spa_meta_objset,
	    DMU_OT_PACKED_NVLIST, 1 << 14,
	    DMU_OT_PACKED_NVLIST_SIZE, sizeof (uint64_t), tx);

	if (zap_add(spa->spa_meta_objset,
	    DMU_POOL_DIRECTORY_OBJECT, DMU_POOL_CONFIG,
	    sizeof (uint64_t), 1, &spa->spa_config_object, tx) != 0) {
		cmn_err(CE_PANIC, "failed to add pool config");
	}

	/*
	 * Create the deferred-free bplist object.  Turn off compression
	 * because sync-to-convergence takes longer if the blocksize
	 * keeps changing.
	 */
	spa->spa_sync_bplist_obj = bplist_create(spa->spa_meta_objset,
	    1 << 14, tx);
	dmu_object_set_compress(spa->spa_meta_objset, spa->spa_sync_bplist_obj,
	    ZIO_COMPRESS_OFF, tx);

	if (zap_add(spa->spa_meta_objset,
	    DMU_POOL_DIRECTORY_OBJECT, DMU_POOL_SYNC_BPLIST,
	    sizeof (uint64_t), 1, &spa->spa_sync_bplist_obj, tx) != 0) {
		cmn_err(CE_PANIC, "failed to add bplist");
	}

	dmu_tx_commit(tx);

	spa->spa_sync_on = B_TRUE;
	txg_sync_start(spa->spa_dsl_pool);

	/*
	 * We explicitly wait for the first transaction to complete so that our
	 * bean counters are appropriately updated.
	 */
	txg_wait_synced(spa->spa_dsl_pool, txg);

	spa_config_sync();

	mutex_exit(&spa_namespace_lock);

	return (0);
}

/*
 * Import the given pool into the system.  We set up the necessary spa_t and
 * then call spa_load() to do the dirty work.
 */
int
spa_import(const char *pool, nvlist_t *config, char *altroot)
{
	spa_t *spa;
	int error;

	if (!(spa_mode & FWRITE))
		return (EROFS);

	/*
	 * If a pool with this name exists, return failure.
	 */
	mutex_enter(&spa_namespace_lock);
	if (spa_lookup(pool) != NULL) {
		mutex_exit(&spa_namespace_lock);
		return (EEXIST);
	}

	/*
	 * Create an initialize the spa structure
	 */
	spa = spa_add(pool);
	spa_activate(spa);

	/*
	 * Set the alternate root, if there is one.
	 */
	if (altroot != NULL) {
		spa->spa_root = spa_strdup(altroot);
		atomic_add_32(&spa_active_count, 1);
	}

	/*
	 * Pass off the heavy lifting to spa_load().  We pass TRUE for mosconfig
	 * so that we don't try to open the pool if the config is damaged.
	 * Note: on success, spa_load() will update and sync the config cache.
	 */
	error = spa_load(spa, config, SPA_LOAD_IMPORT, B_TRUE);

	if (error) {
		spa_unload(spa);
		spa_deactivate(spa);
		spa_remove(spa);
		mutex_exit(&spa_namespace_lock);
		return (error);
	}

	mutex_exit(&spa_namespace_lock);

	/*
	 * Resilver anything that's out of date.
	 */
	if (spa_mode & FWRITE)
		VERIFY(spa_scrub(spa, POOL_SCRUB_RESILVER, B_TRUE) == 0);

	return (0);
}

/*
 * This (illegal) pool name is used when temporarily importing a spa_t in order
 * to get the vdev stats associated with the imported devices.
 */
#define	TRYIMPORT_NAME	"$import"

nvlist_t *
spa_tryimport(nvlist_t *tryconfig)
{
	nvlist_t *config = NULL;
	char *poolname;
	spa_t *spa;
	uint64_t state;

	if (nvlist_lookup_string(tryconfig, ZPOOL_CONFIG_POOL_NAME, &poolname))
		return (NULL);

	if (nvlist_lookup_uint64(tryconfig, ZPOOL_CONFIG_POOL_STATE, &state))
		return (NULL);

	mutex_enter(&spa_namespace_lock);
	spa = spa_add(TRYIMPORT_NAME);

	ASSERT(spa->spa_state == POOL_STATE_UNINITIALIZED);

	/*
	 * Initialize the spa_t structure.
	 */
	spa_activate(spa);

	/*
	 * Pass off the heavy lifting to spa_load().  We pass TRUE for mosconfig
	 * so we don't try to open the pool if the config is damaged.
	 */
	(void) spa_load(spa, tryconfig, SPA_LOAD_TRYIMPORT, B_TRUE);

	/*
	 * If 'tryconfig' was at least parsable, return the current config.
	 */
	if (spa->spa_root_vdev != NULL) {
		config = spa_config_generate(spa, NULL, -1ULL, B_TRUE);
		VERIFY(nvlist_add_string(config, ZPOOL_CONFIG_POOL_NAME,
		    poolname) == 0);
		VERIFY(nvlist_add_uint64(config, ZPOOL_CONFIG_POOL_STATE,
		    state) == 0);
	}

	spa_unload(spa);
	spa_deactivate(spa);
	spa_remove(spa);
	mutex_exit(&spa_namespace_lock);

	return (config);
}

/*
 * Pool export/destroy
 *
 * The act of destroying or exporting a pool is very simple.  We make sure there
 * is no more pending I/O and any references to the pool are gone.  Then, we
 * update the pool state and sync all the labels to disk, removing the
 * configuration from the cache afterwards.
 */
static int
spa_export_common(char *pool, int new_state)
{
	spa_t *spa;

	if (!(spa_mode & FWRITE))
		return (EROFS);

	mutex_enter(&spa_namespace_lock);
	if ((spa = spa_lookup(pool)) == NULL) {
		mutex_exit(&spa_namespace_lock);
		return (ENOENT);
	}

	/*
	 * Put a hold on the pool, drop the namespace lock, stop async tasks,
	 * reacquire the namespace lock, and see if we can export.
	 */
	spa_open_ref(spa, FTAG);
	mutex_exit(&spa_namespace_lock);
	spa_async_suspend(spa);
	mutex_enter(&spa_namespace_lock);
	spa_close(spa, FTAG);

	/*
	 * The pool will be in core if it's openable,
	 * in which case we can modify its state.
	 */
	if (spa->spa_state != POOL_STATE_UNINITIALIZED && spa->spa_sync_on) {
		/*
		 * Objsets may be open only because they're dirty, so we
		 * have to force it to sync before checking spa_refcnt.
		 */
		spa_scrub_suspend(spa);
		txg_wait_synced(spa->spa_dsl_pool, 0);

		/*
		 * A pool cannot be exported or destroyed if there are active
		 * references.  If we are resetting a pool, allow references by
		 * fault injection handlers.
		 */
		if (!spa_refcount_zero(spa) ||
		    (spa->spa_inject_ref != 0 &&
		    new_state != POOL_STATE_UNINITIALIZED)) {
			spa_scrub_resume(spa);
			spa_async_resume(spa);
			mutex_exit(&spa_namespace_lock);
			return (EBUSY);
		}

		spa_scrub_resume(spa);
		VERIFY(spa_scrub(spa, POOL_SCRUB_NONE, B_TRUE) == 0);

		if (spa->spa_root != NULL)
			atomic_add_32(&spa_active_count, -1);

		/*
		 * We want this to be reflected on every label,
		 * so mark them all dirty.  spa_unload() will do the
		 * final sync that pushes these changes out.
		 */
		if (new_state != POOL_STATE_UNINITIALIZED) {
			spa_config_enter(spa, RW_WRITER, FTAG);
			spa->spa_state = new_state;
			vdev_config_dirty(spa->spa_root_vdev);
			spa_config_exit(spa, FTAG);
		}
	}

	if (spa->spa_state != POOL_STATE_UNINITIALIZED) {
		spa_unload(spa);
		spa_deactivate(spa);
	}

	if (new_state != POOL_STATE_UNINITIALIZED) {
		spa_remove(spa);
		spa_config_sync();
	}
	mutex_exit(&spa_namespace_lock);

	return (0);
}

/*
 * Destroy a storage pool.
 */
int
spa_destroy(char *pool)
{
	return (spa_export_common(pool, POOL_STATE_DESTROYED));
}

/*
 * Export a storage pool.
 */
int
spa_export(char *pool)
{
	return (spa_export_common(pool, POOL_STATE_EXPORTED));
}

/*
 * Similar to spa_export(), this unloads the spa_t without actually removing it
 * from the namespace in any way.
 */
int
spa_reset(char *pool)
{
	return (spa_export_common(pool, POOL_STATE_UNINITIALIZED));
}


/*
 * ==========================================================================
 * Device manipulation
 * ==========================================================================
 */

/*
 * Add capacity to a storage pool.
 */
int
spa_vdev_add(spa_t *spa, nvlist_t *nvroot)
{
	uint64_t txg;
	int c, c0, children, error;
	vdev_t *rvd = spa->spa_root_vdev;
	vdev_t *vd, *tvd;

	txg = spa_vdev_enter(spa);

	vd = spa_config_parse(spa, nvroot, NULL, 0, VDEV_ALLOC_ADD);

	if (vd == NULL)
		return (spa_vdev_exit(spa, vd, txg, EINVAL));

	if (rvd == NULL) {			/* spa_create() */
		rvd = vd;
		c0 = 0;
	} else {
		c0 = rvd->vdev_children;
	}

	ASSERT(spa->spa_root_vdev == rvd);

	if ((error = vdev_create(vd, txg)) != 0)
		return (spa_vdev_exit(spa, vd, txg, error));

	children = vd->vdev_children;

	/*
	 * Transfer each new top-level vdev from vd to rvd.
	 */
	for (c = 0; c < children; c++) {
		tvd = vd->vdev_child[c];
		if (vd != rvd) {
			vdev_remove_child(vd, tvd);
			tvd->vdev_id = c0 + c;
			vdev_add_child(rvd, tvd);
		}
		vdev_config_dirty(tvd);
	}

	/*
	 * We have to be careful when adding new vdevs to an existing pool.
	 * If other threads start allocating from these vdevs before we
	 * sync the config cache, and we lose power, then upon reboot we may
	 * fail to open the pool because there are DVAs that the config cache
	 * can't translate.  Therefore, we first add the vdevs without
	 * initializing metaslabs; sync the config cache (via spa_vdev_exit());
	 * initialize the metaslabs; and sync the config cache again.
	 *
	 * spa_load() checks for added-but-not-initialized vdevs, so that
	 * if we lose power at any point in this sequence, the remaining
	 * steps will be completed the next time we load the pool.
	 */
	if (vd != rvd) {
		(void) spa_vdev_exit(spa, vd, txg, 0);
		txg = spa_vdev_enter(spa);
		vd = NULL;
	}

	/*
	 * Now that the config is safely on disk, we can use the new space.
	 */
	for (c = 0; c < children; c++) {
		tvd = rvd->vdev_child[c0 + c];
		ASSERT(tvd->vdev_ms_array == 0);
		vdev_init(tvd, txg);
		vdev_config_dirty(tvd);
	}

	return (spa_vdev_exit(spa, vd, txg, 0));
}

/*
 * Attach a device to a mirror.  The arguments are the path to any device
 * in the mirror, and the nvroot for the new device.  If the path specifies
 * a device that is not mirrored, we automatically insert the mirror vdev.
 *
 * If 'replacing' is specified, the new device is intended to replace the
 * existing device; in this case the two devices are made into their own
 * mirror using the 'replacing' vdev, which is functionally idendical to
 * the mirror vdev (it actually reuses all the same ops) but has a few
 * extra rules: you can't attach to it after it's been created, and upon
 * completion of resilvering, the first disk (the one being replaced)
 * is automatically detached.
 */
int
spa_vdev_attach(spa_t *spa, uint64_t guid, nvlist_t *nvroot, int replacing)
{
	uint64_t txg, open_txg;
	int error;
	vdev_t *rvd = spa->spa_root_vdev;
	vdev_t *oldvd, *newvd, *newrootvd, *pvd, *tvd;
	vdev_ops_t *pvops = replacing ? &vdev_replacing_ops : &vdev_mirror_ops;

	txg = spa_vdev_enter(spa);

	oldvd = vdev_lookup_by_guid(rvd, guid);

	if (oldvd == NULL)
		return (spa_vdev_exit(spa, NULL, txg, ENODEV));

	if (!oldvd->vdev_ops->vdev_op_leaf)
		return (spa_vdev_exit(spa, NULL, txg, ENOTSUP));

	pvd = oldvd->vdev_parent;

	/*
	 * The parent must be a mirror or the root, unless we're replacing;
	 * in that case, the parent can be anything but another replacing vdev.
	 */
	if (pvd->vdev_ops != &vdev_mirror_ops &&
	    pvd->vdev_ops != &vdev_root_ops &&
	    (!replacing || pvd->vdev_ops == &vdev_replacing_ops))
		return (spa_vdev_exit(spa, NULL, txg, ENOTSUP));

	newrootvd = spa_config_parse(spa, nvroot, NULL, 0, VDEV_ALLOC_ADD);

	if (newrootvd == NULL || newrootvd->vdev_children != 1)
		return (spa_vdev_exit(spa, newrootvd, txg, EINVAL));

	newvd = newrootvd->vdev_child[0];

	if (!newvd->vdev_ops->vdev_op_leaf)
		return (spa_vdev_exit(spa, newrootvd, txg, EINVAL));

	if ((error = vdev_create(newrootvd, txg)) != 0)
		return (spa_vdev_exit(spa, newrootvd, txg, error));

	/*
	 * Compare the new device size with the replaceable/attachable
	 * device size.
	 */
	if (newvd->vdev_psize < vdev_get_rsize(oldvd))
		return (spa_vdev_exit(spa, newrootvd, txg, EOVERFLOW));

	if (newvd->vdev_ashift != oldvd->vdev_ashift && oldvd->vdev_ashift != 0)
		return (spa_vdev_exit(spa, newrootvd, txg, EDOM));

	/*
	 * If this is an in-place replacement, update oldvd's path and devid
	 * to make it distinguishable from newvd, and unopenable from now on.
	 */
	if (strcmp(oldvd->vdev_path, newvd->vdev_path) == 0) {
		spa_strfree(oldvd->vdev_path);
		oldvd->vdev_path = kmem_alloc(strlen(newvd->vdev_path) + 5,
		    KM_SLEEP);
		(void) sprintf(oldvd->vdev_path, "%s/%s",
		    newvd->vdev_path, "old");
		if (oldvd->vdev_devid != NULL) {
			spa_strfree(oldvd->vdev_devid);
			oldvd->vdev_devid = NULL;
		}
	}

	/*
	 * If the parent is not a mirror, or if we're replacing,
	 * insert the new mirror/replacing vdev above oldvd.
	 */
	if (pvd->vdev_ops != pvops)
		pvd = vdev_add_parent(oldvd, pvops);

	ASSERT(pvd->vdev_top->vdev_parent == rvd);
	ASSERT(pvd->vdev_ops == pvops);
	ASSERT(oldvd->vdev_parent == pvd);

	/*
	 * Extract the new device from its root and add it to pvd.
	 */
	vdev_remove_child(newrootvd, newvd);
	newvd->vdev_id = pvd->vdev_children;
	vdev_add_child(pvd, newvd);

	/*
	 * If newvd is smaller than oldvd, but larger than its rsize,
	 * the addition of newvd may have decreased our parent's asize.
	 */
	pvd->vdev_asize = MIN(pvd->vdev_asize, newvd->vdev_asize);

	tvd = newvd->vdev_top;
	ASSERT(pvd->vdev_top == tvd);
	ASSERT(tvd->vdev_parent == rvd);

	vdev_config_dirty(tvd);

	/*
	 * Set newvd's DTL to [TXG_INITIAL, open_txg].  It will propagate
	 * upward when spa_vdev_exit() calls vdev_dtl_reassess().
	 */
	open_txg = txg + TXG_CONCURRENT_STATES - 1;

	mutex_enter(&newvd->vdev_dtl_lock);
	space_map_add(&newvd->vdev_dtl_map, TXG_INITIAL,
	    open_txg - TXG_INITIAL + 1);
	mutex_exit(&newvd->vdev_dtl_lock);

	dprintf("attached %s in txg %llu\n", newvd->vdev_path, txg);

	/*
	 * Mark newvd's DTL dirty in this txg.
	 */
	vdev_dirty(tvd, VDD_DTL, txg);
	(void) txg_list_add(&tvd->vdev_dtl_list, newvd, txg);

	(void) spa_vdev_exit(spa, newrootvd, open_txg, 0);

	/*
	 * Kick off a resilver to update newvd.
	 */
	VERIFY(spa_scrub(spa, POOL_SCRUB_RESILVER, B_TRUE) == 0);

	return (0);
}

/*
 * Detach a device from a mirror or replacing vdev.
 * If 'replace_done' is specified, only detach if the parent
 * is a replacing vdev.
 */
int
spa_vdev_detach(spa_t *spa, uint64_t guid, int replace_done)
{
	uint64_t txg;
	int c, t, error;
	vdev_t *rvd = spa->spa_root_vdev;
	vdev_t *vd, *pvd, *cvd, *tvd;

	txg = spa_vdev_enter(spa);

	vd = vdev_lookup_by_guid(rvd, guid);

	if (vd == NULL)
		return (spa_vdev_exit(spa, NULL, txg, ENODEV));

	if (!vd->vdev_ops->vdev_op_leaf)
		return (spa_vdev_exit(spa, NULL, txg, ENOTSUP));

	pvd = vd->vdev_parent;

	/*
	 * If replace_done is specified, only remove this device if it's
	 * the first child of a replacing vdev.
	 */
	if (replace_done &&
	    (vd->vdev_id != 0 || pvd->vdev_ops != &vdev_replacing_ops))
		return (spa_vdev_exit(spa, NULL, txg, ENOTSUP));

	/*
	 * Only mirror and replacing vdevs support detach.
	 */
	if (pvd->vdev_ops != &vdev_replacing_ops &&
	    pvd->vdev_ops != &vdev_mirror_ops)
		return (spa_vdev_exit(spa, NULL, txg, ENOTSUP));

	/*
	 * If there's only one replica, you can't detach it.
	 */
	if (pvd->vdev_children <= 1)
		return (spa_vdev_exit(spa, NULL, txg, EBUSY));

	/*
	 * If all siblings have non-empty DTLs, this device may have the only
	 * valid copy of the data, which means we cannot safely detach it.
	 *
	 * XXX -- as in the vdev_offline() case, we really want a more
	 * precise DTL check.
	 */
	for (c = 0; c < pvd->vdev_children; c++) {
		uint64_t dirty;

		cvd = pvd->vdev_child[c];
		if (cvd == vd)
			continue;
		if (vdev_is_dead(cvd))
			continue;
		mutex_enter(&cvd->vdev_dtl_lock);
		dirty = cvd->vdev_dtl_map.sm_space |
		    cvd->vdev_dtl_scrub.sm_space;
		mutex_exit(&cvd->vdev_dtl_lock);
		if (!dirty)
			break;
	}
	if (c == pvd->vdev_children)
		return (spa_vdev_exit(spa, NULL, txg, EBUSY));

	/*
	 * Erase the disk labels so the disk can be used for other things.
	 * This must be done after all other error cases are handled,
	 * but before we disembowel vd (so we can still do I/O to it).
	 * But if we can't do it, don't treat the error as fatal --
	 * it may be that the unwritability of the disk is the reason
	 * it's being detached!
	 */
	error = vdev_label_init(vd, 0);
	if (error)
		dprintf("unable to erase labels on %s\n", vdev_description(vd));

	/*
	 * Remove vd from its parent and compact the parent's children.
	 */
	vdev_remove_child(pvd, vd);
	vdev_compact_children(pvd);

	/*
	 * Remember one of the remaining children so we can get tvd below.
	 */
	cvd = pvd->vdev_child[0];

	/*
	 * If the parent mirror/replacing vdev only has one child,
	 * the parent is no longer needed.  Remove it from the tree.
	 */
	if (pvd->vdev_children == 1)
		vdev_remove_parent(cvd);

	/*
	 * We don't set tvd until now because the parent we just removed
	 * may have been the previous top-level vdev.
	 */
	tvd = cvd->vdev_top;
	ASSERT(tvd->vdev_parent == rvd);

	/*
	 * Reopen this top-level vdev to reassess health after detach.
	 */
	vdev_reopen(tvd);

	/*
	 * If the device we just detached was smaller than the others,
	 * it may be possible to add metaslabs (i.e. grow the pool).  We ignore
	 * the error here because the detach still succeeded - we just weren't
	 * able to reinitialize the metaslabs.  This pool is in for a world of
	 * hurt, in any case.
	 */
	(void) vdev_metaslab_init(tvd, txg);

	vdev_config_dirty(tvd);

	/*
	 * Mark vd's DTL as dirty in this txg.
	 * vdev_dtl_sync() will see that vd->vdev_detached is set
	 * and free vd's DTL object in syncing context.
	 * But first make sure we're not on any *other* txg's DTL list,
	 * to prevent vd from being accessed after it's freed.
	 */
	vdev_dirty(tvd, VDD_DTL, txg);
	vd->vdev_detached = B_TRUE;
	for (t = 0; t < TXG_SIZE; t++)
		(void) txg_list_remove_this(&tvd->vdev_dtl_list, vd, t);
	(void) txg_list_add(&tvd->vdev_dtl_list, vd, txg);

	dprintf("detached %s in txg %llu\n", vd->vdev_path, txg);

	return (spa_vdev_exit(spa, vd, txg, 0));
}

/*
 * Find any device that's done replacing, so we can detach it.
 */
static vdev_t *
spa_vdev_replace_done_hunt(vdev_t *vd)
{
	vdev_t *newvd, *oldvd;
	int c;

	for (c = 0; c < vd->vdev_children; c++) {
		oldvd = spa_vdev_replace_done_hunt(vd->vdev_child[c]);
		if (oldvd != NULL)
			return (oldvd);
	}

	if (vd->vdev_ops == &vdev_replacing_ops && vd->vdev_children == 2) {
		oldvd = vd->vdev_child[0];
		newvd = vd->vdev_child[1];

		mutex_enter(&newvd->vdev_dtl_lock);
		if (newvd->vdev_dtl_map.sm_space == 0 &&
		    newvd->vdev_dtl_scrub.sm_space == 0) {
			mutex_exit(&newvd->vdev_dtl_lock);
			return (oldvd);
		}
		mutex_exit(&newvd->vdev_dtl_lock);
	}

	return (NULL);
}

static void
spa_vdev_replace_done(spa_t *spa)
{
	vdev_t *vd;
	uint64_t guid;

	spa_config_enter(spa, RW_READER, FTAG);

	while ((vd = spa_vdev_replace_done_hunt(spa->spa_root_vdev)) != NULL) {
		guid = vd->vdev_guid;
		spa_config_exit(spa, FTAG);
		if (spa_vdev_detach(spa, guid, B_TRUE) != 0)
			return;
		spa_config_enter(spa, RW_READER, FTAG);
	}

	spa_config_exit(spa, FTAG);
}

/*
 * Update the stored path for this vdev.  Dirty the vdev configuration, relying
 * on spa_vdev_enter/exit() to synchronize the labels and cache.
 */
int
spa_vdev_setpath(spa_t *spa, uint64_t guid, const char *newpath)
{
	vdev_t *rvd, *vd;
	uint64_t txg;

	rvd = spa->spa_root_vdev;

	txg = spa_vdev_enter(spa);

	if ((vd = vdev_lookup_by_guid(rvd, guid)) == NULL)
		return (spa_vdev_exit(spa, NULL, txg, ENOENT));

	if (!vd->vdev_ops->vdev_op_leaf)
		return (spa_vdev_exit(spa, NULL, txg, ENOTSUP));

	spa_strfree(vd->vdev_path);
	vd->vdev_path = spa_strdup(newpath);

	vdev_config_dirty(vd->vdev_top);

	return (spa_vdev_exit(spa, NULL, txg, 0));
}

/*
 * ==========================================================================
 * SPA Scrubbing
 * ==========================================================================
 */

void
spa_scrub_throttle(spa_t *spa, int direction)
{
	mutex_enter(&spa->spa_scrub_lock);
	spa->spa_scrub_throttled += direction;
	ASSERT(spa->spa_scrub_throttled >= 0);
	if (spa->spa_scrub_throttled == 0)
		cv_broadcast(&spa->spa_scrub_io_cv);
	mutex_exit(&spa->spa_scrub_lock);
}

static void
spa_scrub_io_done(zio_t *zio)
{
	spa_t *spa = zio->io_spa;

	zio_buf_free(zio->io_data, zio->io_size);

	mutex_enter(&spa->spa_scrub_lock);
	if (zio->io_error && !(zio->io_flags & ZIO_FLAG_SPECULATIVE)) {
		vdev_t *vd = zio->io_vd;
		spa->spa_scrub_errors++;
		mutex_enter(&vd->vdev_stat_lock);
		vd->vdev_stat.vs_scrub_errors++;
		mutex_exit(&vd->vdev_stat_lock);
	}
	if (--spa->spa_scrub_inflight == 0) {
		cv_broadcast(&spa->spa_scrub_io_cv);
		ASSERT(spa->spa_scrub_throttled == 0);
	}
	mutex_exit(&spa->spa_scrub_lock);
}

static void
spa_scrub_io_start(spa_t *spa, blkptr_t *bp, int priority, int flags,
    zbookmark_t *zb)
{
	size_t size = BP_GET_LSIZE(bp);
	void *data = zio_buf_alloc(size);

	mutex_enter(&spa->spa_scrub_lock);
	spa->spa_scrub_inflight++;
	mutex_exit(&spa->spa_scrub_lock);

	if (zb->zb_level == -1 && BP_GET_TYPE(bp) != DMU_OT_OBJSET)
		flags |= ZIO_FLAG_SPECULATIVE;	/* intent log block */

	flags |= ZIO_FLAG_CANFAIL;

	zio_nowait(zio_read(NULL, spa, bp, data, size,
	    spa_scrub_io_done, NULL, priority, flags, zb));
}

/* ARGSUSED */
static int
spa_scrub_cb(traverse_blk_cache_t *bc, spa_t *spa, void *a)
{
	blkptr_t *bp = &bc->bc_blkptr;
	vdev_t *vd = vdev_lookup_top(spa, DVA_GET_VDEV(&bp->blk_dva[0]));

	if (bc->bc_errno || vd == NULL) {
		/*
		 * We can't scrub this block, but we can continue to scrub
		 * the rest of the pool.  Note the error and move along.
		 */
		mutex_enter(&spa->spa_scrub_lock);
		spa->spa_scrub_errors++;
		mutex_exit(&spa->spa_scrub_lock);

		if (vd != NULL) {
			mutex_enter(&vd->vdev_stat_lock);
			vd->vdev_stat.vs_scrub_errors++;
			mutex_exit(&vd->vdev_stat_lock);
		}

		return (ERESTART);
	}

	ASSERT(bp->blk_birth < spa->spa_scrub_maxtxg);

	/*
	 * Keep track of how much data we've examined so that
	 * zpool(1M) status can make useful progress reports.
	 */
	mutex_enter(&vd->vdev_stat_lock);
	vd->vdev_stat.vs_scrub_examined += BP_GET_ASIZE(bp);
	mutex_exit(&vd->vdev_stat_lock);

	if (spa->spa_scrub_type == POOL_SCRUB_RESILVER) {
		if (DVA_GET_GANG(&bp->blk_dva[0])) {
			/*
			 * Gang members may be spread across multiple vdevs,
			 * so the best we can do is look at the pool-wide DTL.
			 * XXX -- it would be better to change our allocation
			 * policy to ensure that this can't happen.
			 */
			vd = spa->spa_root_vdev;
		}
		if (vdev_dtl_contains(&vd->vdev_dtl_map, bp->blk_birth, 1)) {
			spa_scrub_io_start(spa, bp, ZIO_PRIORITY_RESILVER,
			    ZIO_FLAG_RESILVER, &bc->bc_bookmark);
		}
	} else {
		spa_scrub_io_start(spa, bp, ZIO_PRIORITY_SCRUB,
		    ZIO_FLAG_SCRUB, &bc->bc_bookmark);
	}

	return (0);
}

static void
spa_scrub_thread(spa_t *spa)
{
	callb_cpr_t cprinfo;
	traverse_handle_t *th = spa->spa_scrub_th;
	vdev_t *rvd = spa->spa_root_vdev;
	pool_scrub_type_t scrub_type = spa->spa_scrub_type;
	int error = 0;
	boolean_t complete;

	CALLB_CPR_INIT(&cprinfo, &spa->spa_scrub_lock, callb_generic_cpr, FTAG);

	/*
	 * If we're restarting due to a snapshot create/delete,
	 * wait for that to complete.
	 */
	txg_wait_synced(spa_get_dsl(spa), 0);

	dprintf("start %s mintxg=%llu maxtxg=%llu\n",
	    scrub_type == POOL_SCRUB_RESILVER ? "resilver" : "scrub",
	    spa->spa_scrub_mintxg, spa->spa_scrub_maxtxg);

	spa_config_enter(spa, RW_WRITER, FTAG);
	vdev_reopen(rvd);		/* purge all vdev caches */
	vdev_config_dirty(rvd);		/* rewrite all disk labels */
	vdev_scrub_stat_update(rvd, scrub_type, B_FALSE);
	spa_config_exit(spa, FTAG);

	mutex_enter(&spa->spa_scrub_lock);
	spa->spa_scrub_errors = 0;
	spa->spa_scrub_active = 1;
	ASSERT(spa->spa_scrub_inflight == 0);
	ASSERT(spa->spa_scrub_throttled == 0);

	while (!spa->spa_scrub_stop) {
		CALLB_CPR_SAFE_BEGIN(&cprinfo);
		while (spa->spa_scrub_suspended) {
			spa->spa_scrub_active = 0;
			cv_broadcast(&spa->spa_scrub_cv);
			cv_wait(&spa->spa_scrub_cv, &spa->spa_scrub_lock);
			spa->spa_scrub_active = 1;
		}
		CALLB_CPR_SAFE_END(&cprinfo, &spa->spa_scrub_lock);

		if (spa->spa_scrub_restart_txg != 0)
			break;

		mutex_exit(&spa->spa_scrub_lock);
		error = traverse_more(th);
		mutex_enter(&spa->spa_scrub_lock);
		if (error != EAGAIN)
			break;

		while (spa->spa_scrub_throttled > 0)
			cv_wait(&spa->spa_scrub_io_cv, &spa->spa_scrub_lock);
	}

	while (spa->spa_scrub_inflight)
		cv_wait(&spa->spa_scrub_io_cv, &spa->spa_scrub_lock);

	spa->spa_scrub_active = 0;
	cv_broadcast(&spa->spa_scrub_cv);

	mutex_exit(&spa->spa_scrub_lock);

	spa_config_enter(spa, RW_WRITER, FTAG);

	mutex_enter(&spa->spa_scrub_lock);

	/*
	 * Note: we check spa_scrub_restart_txg under both spa_scrub_lock
	 * AND the spa config lock to synchronize with any config changes
	 * that revise the DTLs under spa_vdev_enter() / spa_vdev_exit().
	 */
	if (spa->spa_scrub_restart_txg != 0)
		error = ERESTART;

	if (spa->spa_scrub_stop)
		error = EINTR;

	/*
	 * Even if there were uncorrectable errors, we consider the scrub
	 * completed.  The downside is that if there is a transient error during
	 * a resilver, we won't resilver the data properly to the target.  But
	 * if the damage is permanent (more likely) we will resilver forever,
	 * which isn't really acceptable.  Since there is enough information for
	 * the user to know what has failed and why, this seems like a more
	 * tractable approach.
	 */
	complete = (error == 0);

	dprintf("end %s to maxtxg=%llu %s, traverse=%d, %llu errors, stop=%u\n",
	    scrub_type == POOL_SCRUB_RESILVER ? "resilver" : "scrub",
	    spa->spa_scrub_maxtxg, complete ? "done" : "FAILED",
	    error, spa->spa_scrub_errors, spa->spa_scrub_stop);

	mutex_exit(&spa->spa_scrub_lock);

	/*
	 * If the scrub/resilver completed, update all DTLs to reflect this.
	 * Whether it succeeded or not, vacate all temporary scrub DTLs.
	 */
	vdev_dtl_reassess(rvd, spa_last_synced_txg(spa) + 1,
	    complete ? spa->spa_scrub_maxtxg : 0, B_TRUE);
	vdev_scrub_stat_update(rvd, POOL_SCRUB_NONE, complete);
	spa_errlog_rotate(spa);

	spa_config_exit(spa, FTAG);

	mutex_enter(&spa->spa_scrub_lock);

	/*
	 * We may have finished replacing a device.
	 * Let the async thread assess this and handle the detach.
	 */
	spa_async_request(spa, SPA_ASYNC_REPLACE_DONE);

	/*
	 * If we were told to restart, our final act is to start a new scrub.
	 */
	if (error == ERESTART)
		spa_async_request(spa, scrub_type == POOL_SCRUB_RESILVER ?
		    SPA_ASYNC_RESILVER : SPA_ASYNC_SCRUB);

	spa->spa_scrub_type = POOL_SCRUB_NONE;
	spa->spa_scrub_active = 0;
	spa->spa_scrub_thread = NULL;
	cv_broadcast(&spa->spa_scrub_cv);
	CALLB_CPR_EXIT(&cprinfo);	/* drops &spa->spa_scrub_lock */
	thread_exit();
}

void
spa_scrub_suspend(spa_t *spa)
{
	mutex_enter(&spa->spa_scrub_lock);
	spa->spa_scrub_suspended++;
	while (spa->spa_scrub_active) {
		cv_broadcast(&spa->spa_scrub_cv);
		cv_wait(&spa->spa_scrub_cv, &spa->spa_scrub_lock);
	}
	while (spa->spa_scrub_inflight)
		cv_wait(&spa->spa_scrub_io_cv, &spa->spa_scrub_lock);
	mutex_exit(&spa->spa_scrub_lock);
}

void
spa_scrub_resume(spa_t *spa)
{
	mutex_enter(&spa->spa_scrub_lock);
	ASSERT(spa->spa_scrub_suspended != 0);
	if (--spa->spa_scrub_suspended == 0)
		cv_broadcast(&spa->spa_scrub_cv);
	mutex_exit(&spa->spa_scrub_lock);
}

void
spa_scrub_restart(spa_t *spa, uint64_t txg)
{
	/*
	 * Something happened (e.g. snapshot create/delete) that means
	 * we must restart any in-progress scrubs.  The itinerary will
	 * fix this properly.
	 */
	mutex_enter(&spa->spa_scrub_lock);
	spa->spa_scrub_restart_txg = txg;
	mutex_exit(&spa->spa_scrub_lock);
}

int
spa_scrub(spa_t *spa, pool_scrub_type_t type, boolean_t force)
{
	space_seg_t *ss;
	uint64_t mintxg, maxtxg;
	vdev_t *rvd = spa->spa_root_vdev;
	int advance = ADVANCE_PRE | ADVANCE_ZIL;

	if ((uint_t)type >= POOL_SCRUB_TYPES)
		return (ENOTSUP);

	mutex_enter(&spa->spa_scrub_lock);

	/*
	 * If there's a scrub or resilver already in progress, stop it.
	 */
	while (spa->spa_scrub_thread != NULL) {
		/*
		 * Don't stop a resilver unless forced.
		 */
		if (spa->spa_scrub_type == POOL_SCRUB_RESILVER && !force) {
			mutex_exit(&spa->spa_scrub_lock);
			return (EBUSY);
		}
		spa->spa_scrub_stop = 1;
		cv_broadcast(&spa->spa_scrub_cv);
		cv_wait(&spa->spa_scrub_cv, &spa->spa_scrub_lock);
	}

	/*
	 * Terminate the previous traverse.
	 */
	if (spa->spa_scrub_th != NULL) {
		traverse_fini(spa->spa_scrub_th);
		spa->spa_scrub_th = NULL;
	}

	if (rvd == NULL) {
		ASSERT(spa->spa_scrub_stop == 0);
		ASSERT(spa->spa_scrub_type == type);
		ASSERT(spa->spa_scrub_restart_txg == 0);
		mutex_exit(&spa->spa_scrub_lock);
		return (0);
	}

	mintxg = TXG_INITIAL - 1;
	maxtxg = spa_last_synced_txg(spa) + 1;

	mutex_enter(&rvd->vdev_dtl_lock);

	if (rvd->vdev_dtl_map.sm_space == 0) {
		/*
		 * The pool-wide DTL is empty.
		 * If this is a resilver, there's nothing to do.
		 */
		if (type == POOL_SCRUB_RESILVER)
			type = POOL_SCRUB_NONE;
	} else {
		/*
		 * The pool-wide DTL is non-empty.
		 * If this is a normal scrub, upgrade to a resilver instead.
		 */
		if (type == POOL_SCRUB_EVERYTHING)
			type = POOL_SCRUB_RESILVER;
	}

	if (type == POOL_SCRUB_RESILVER) {
		/*
		 * Determine the resilvering boundaries.
		 *
		 * Note: (mintxg, maxtxg) is an open interval,
		 * i.e. mintxg and maxtxg themselves are not included.
		 *
		 * Note: for maxtxg, we MIN with spa_last_synced_txg(spa) + 1
		 * so we don't claim to resilver a txg that's still changing.
		 */
		ss = avl_first(&rvd->vdev_dtl_map.sm_root);
		mintxg = ss->ss_start - 1;
		ss = avl_last(&rvd->vdev_dtl_map.sm_root);
		maxtxg = MIN(ss->ss_end, maxtxg);

		advance |= ADVANCE_PRUNE;
	}

	mutex_exit(&rvd->vdev_dtl_lock);

	spa->spa_scrub_stop = 0;
	spa->spa_scrub_type = type;
	spa->spa_scrub_restart_txg = 0;

	if (type != POOL_SCRUB_NONE) {
		spa->spa_scrub_mintxg = mintxg;
		spa->spa_scrub_maxtxg = maxtxg;
		spa->spa_scrub_th = traverse_init(spa, spa_scrub_cb, NULL,
		    advance, ZIO_FLAG_CANFAIL);
		traverse_add_pool(spa->spa_scrub_th, mintxg, maxtxg);
		spa->spa_scrub_thread = thread_create(NULL, 0,
		    spa_scrub_thread, spa, 0, &p0, TS_RUN, minclsyspri);
	}

	mutex_exit(&spa->spa_scrub_lock);

	return (0);
}

/*
 * ==========================================================================
 * SPA async task processing
 * ==========================================================================
 */

static void
spa_async_reopen(spa_t *spa)
{
	vdev_t *rvd = spa->spa_root_vdev;
	vdev_t *tvd;
	int c;

	spa_config_enter(spa, RW_WRITER, FTAG);

	for (c = 0; c < rvd->vdev_children; c++) {
		tvd = rvd->vdev_child[c];
		if (tvd->vdev_reopen_wanted) {
			tvd->vdev_reopen_wanted = 0;
			vdev_reopen(tvd);
		}
	}

	spa_config_exit(spa, FTAG);
}

static void
spa_async_thread(spa_t *spa)
{
	int tasks;

	ASSERT(spa->spa_sync_on);

	mutex_enter(&spa->spa_async_lock);
	tasks = spa->spa_async_tasks;
	spa->spa_async_tasks = 0;
	mutex_exit(&spa->spa_async_lock);

	/*
	 * See if any devices need to be reopened.
	 */
	if (tasks & SPA_ASYNC_REOPEN)
		spa_async_reopen(spa);

	/*
	 * If any devices are done replacing, detach them.
	 */
	if (tasks & SPA_ASYNC_REPLACE_DONE)
		spa_vdev_replace_done(spa);

	/*
	 * Kick off a scrub.
	 */
	if (tasks & SPA_ASYNC_SCRUB)
		VERIFY(spa_scrub(spa, POOL_SCRUB_EVERYTHING, B_TRUE) == 0);

	/*
	 * Kick off a resilver.
	 */
	if (tasks & SPA_ASYNC_RESILVER)
		VERIFY(spa_scrub(spa, POOL_SCRUB_RESILVER, B_TRUE) == 0);

	/*
	 * Let the world know that we're done.
	 */
	mutex_enter(&spa->spa_async_lock);
	spa->spa_async_thread = NULL;
	cv_broadcast(&spa->spa_async_cv);
	mutex_exit(&spa->spa_async_lock);
	thread_exit();
}

void
spa_async_suspend(spa_t *spa)
{
	mutex_enter(&spa->spa_async_lock);
	spa->spa_async_suspended++;
	while (spa->spa_async_thread != NULL)
		cv_wait(&spa->spa_async_cv, &spa->spa_async_lock);
	mutex_exit(&spa->spa_async_lock);
}

void
spa_async_resume(spa_t *spa)
{
	mutex_enter(&spa->spa_async_lock);
	ASSERT(spa->spa_async_suspended != 0);
	spa->spa_async_suspended--;
	mutex_exit(&spa->spa_async_lock);
}

static void
spa_async_dispatch(spa_t *spa)
{
	mutex_enter(&spa->spa_async_lock);
	if (spa->spa_async_tasks && !spa->spa_async_suspended &&
	    spa->spa_async_thread == NULL)
		spa->spa_async_thread = thread_create(NULL, 0,
		    spa_async_thread, spa, 0, &p0, TS_RUN, maxclsyspri);
	mutex_exit(&spa->spa_async_lock);
}

void
spa_async_request(spa_t *spa, int task)
{
	mutex_enter(&spa->spa_async_lock);
	spa->spa_async_tasks |= task;
	mutex_exit(&spa->spa_async_lock);
}

/*
 * ==========================================================================
 * SPA syncing routines
 * ==========================================================================
 */

static void
spa_sync_deferred_frees(spa_t *spa, uint64_t txg)
{
	bplist_t *bpl = &spa->spa_sync_bplist;
	dmu_tx_t *tx;
	blkptr_t blk;
	uint64_t itor = 0;
	zio_t *zio;
	int error;
	uint8_t c = 1;

	zio = zio_root(spa, NULL, NULL, ZIO_FLAG_CONFIG_HELD);

	while (bplist_iterate(bpl, &itor, &blk) == 0)
		zio_nowait(zio_free(zio, spa, txg, &blk, NULL, NULL));

	error = zio_wait(zio);
	ASSERT3U(error, ==, 0);

	tx = dmu_tx_create_assigned(spa->spa_dsl_pool, txg);
	bplist_vacate(bpl, tx);

	/*
	 * Pre-dirty the first block so we sync to convergence faster.
	 * (Usually only the first block is needed.)
	 */
	dmu_write(spa->spa_meta_objset, spa->spa_sync_bplist_obj, 0, 1, &c, tx);
	dmu_tx_commit(tx);
}

static void
spa_sync_config_object(spa_t *spa, dmu_tx_t *tx)
{
	nvlist_t *config;
	char *packed = NULL;
	size_t nvsize = 0;
	dmu_buf_t *db;

	if (list_is_empty(&spa->spa_dirty_list))
		return;

	config = spa_config_generate(spa, NULL, dmu_tx_get_txg(tx), B_FALSE);

	spa_config_set(spa, config);

	VERIFY(nvlist_size(config, &nvsize, NV_ENCODE_XDR) == 0);

	packed = kmem_alloc(nvsize, KM_SLEEP);

	VERIFY(nvlist_pack(config, &packed, &nvsize, NV_ENCODE_XDR,
	    KM_SLEEP) == 0);

	dmu_write(spa->spa_meta_objset, spa->spa_config_object, 0, nvsize,
	    packed, tx);

	kmem_free(packed, nvsize);

	VERIFY(0 == dmu_bonus_hold(spa->spa_meta_objset,
	    spa->spa_config_object, FTAG, &db));
	dmu_buf_will_dirty(db, tx);
	*(uint64_t *)db->db_data = nvsize;
	dmu_buf_rele(db, FTAG);
}

/*
 * Sync the specified transaction group.  New blocks may be dirtied as
 * part of the process, so we iterate until it converges.
 */
void
spa_sync(spa_t *spa, uint64_t txg)
{
	dsl_pool_t *dp = spa->spa_dsl_pool;
	objset_t *mos = spa->spa_meta_objset;
	bplist_t *bpl = &spa->spa_sync_bplist;
	vdev_t *vd;
	dmu_tx_t *tx;
	int dirty_vdevs;

	/*
	 * Lock out configuration changes.
	 */
	spa_config_enter(spa, RW_READER, FTAG);

	spa->spa_syncing_txg = txg;
	spa->spa_sync_pass = 0;

	VERIFY(0 == bplist_open(bpl, mos, spa->spa_sync_bplist_obj));

	/*
	 * If anything has changed in this txg, push the deferred frees
	 * from the previous txg.  If not, leave them alone so that we
	 * don't generate work on an otherwise idle system.
	 */
	if (!txg_list_empty(&dp->dp_dirty_datasets, txg) ||
	    !txg_list_empty(&dp->dp_dirty_dirs, txg))
		spa_sync_deferred_frees(spa, txg);

	/*
	 * Iterate to convergence.
	 */
	do {
		spa->spa_sync_pass++;

		tx = dmu_tx_create_assigned(dp, txg);
		spa_sync_config_object(spa, tx);
		dmu_tx_commit(tx);

		spa_errlog_sync(spa, txg);

		dsl_pool_sync(dp, txg);

		dirty_vdevs = 0;
		while (vd = txg_list_remove(&spa->spa_vdev_txg_list, txg)) {
			vdev_sync(vd, txg);
			dirty_vdevs++;
		}

		tx = dmu_tx_create_assigned(dp, txg);
		bplist_sync(bpl, tx);
		dmu_tx_commit(tx);

	} while (dirty_vdevs);

	bplist_close(bpl);

	dprintf("txg %llu passes %d\n", txg, spa->spa_sync_pass);

	/*
	 * Rewrite the vdev configuration (which includes the uberblock)
	 * to commit the transaction group.
	 */
	VERIFY(0 == spa_sync_labels(spa, txg));

	/*
	 * Make a stable copy of the fully synced uberblock.
	 * We use this as the root for pool traversals.
	 */
	spa->spa_traverse_wanted = 1;	/* tells traverse_more() to stop */

	spa_scrub_suspend(spa);		/* stop scrubbing and finish I/Os */

	rw_enter(&spa->spa_traverse_lock, RW_WRITER);
	spa->spa_traverse_wanted = 0;
	spa->spa_ubsync = spa->spa_uberblock;
	rw_exit(&spa->spa_traverse_lock);

	spa_scrub_resume(spa);		/* resume scrub with new ubsync */

	/*
	 * Clean up the ZIL records for the synced txg.
	 */
	dsl_pool_zil_clean(dp);

	/*
	 * Update usable space statistics.
	 */
	while (vd = txg_list_remove(&spa->spa_vdev_txg_list, TXG_CLEAN(txg)))
		vdev_sync_done(vd, txg);

	/*
	 * It had better be the case that we didn't dirty anything
	 * since spa_sync_labels().
	 */
	ASSERT(txg_list_empty(&dp->dp_dirty_datasets, txg));
	ASSERT(txg_list_empty(&dp->dp_dirty_dirs, txg));
	ASSERT(txg_list_empty(&spa->spa_vdev_txg_list, txg));
	ASSERT(bpl->bpl_queue == NULL);

	spa_config_exit(spa, FTAG);

	/*
	 * If any async tasks have been requested, kick them off.
	 */
	spa_async_dispatch(spa);
}

/*
 * Sync all pools.  We don't want to hold the namespace lock across these
 * operations, so we take a reference on the spa_t and drop the lock during the
 * sync.
 */
void
spa_sync_allpools(void)
{
	spa_t *spa = NULL;
	mutex_enter(&spa_namespace_lock);
	while ((spa = spa_next(spa)) != NULL) {
		if (spa_state(spa) != POOL_STATE_ACTIVE)
			continue;
		spa_open_ref(spa, FTAG);
		mutex_exit(&spa_namespace_lock);
		txg_wait_synced(spa_get_dsl(spa), 0);
		mutex_enter(&spa_namespace_lock);
		spa_close(spa, FTAG);
	}
	mutex_exit(&spa_namespace_lock);
}

/*
 * ==========================================================================
 * Miscellaneous routines
 * ==========================================================================
 */

int
spa_busy(void)
{
	return (spa_active_count != 0);
}

/*
 * Remove all pools in the system.
 */
void
spa_evict_all(void)
{
	spa_t *spa;

	/*
	 * Remove all cached state.  All pools should be closed now,
	 * so every spa in the AVL tree should be unreferenced.
	 */
	mutex_enter(&spa_namespace_lock);
	while ((spa = spa_next(NULL)) != NULL) {
		/*
		 * Stop async tasks.  The async thread may need to detach
		 * a device that's been replaced, which requires grabbing
		 * spa_namespace_lock, so we must drop it here.
		 */
		spa_open_ref(spa, FTAG);
		mutex_exit(&spa_namespace_lock);
		spa_async_suspend(spa);
		VERIFY(spa_scrub(spa, POOL_SCRUB_NONE, B_TRUE) == 0);
		mutex_enter(&spa_namespace_lock);
		spa_close(spa, FTAG);

		if (spa->spa_state != POOL_STATE_UNINITIALIZED) {
			spa_unload(spa);
			spa_deactivate(spa);
		}
		spa_remove(spa);
	}
	mutex_exit(&spa_namespace_lock);
}

vdev_t *
spa_lookup_by_guid(spa_t *spa, uint64_t guid)
{
	return (vdev_lookup_by_guid(spa->spa_root_vdev, guid));
}
