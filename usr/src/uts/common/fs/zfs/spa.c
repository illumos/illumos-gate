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

/*
 * This file contains all the routines used when modifying on-disk SPA state.
 * This includes opening, importing, destroying, exporting a pool, and syncing a
 * pool.
 */

#include <sys/zfs_context.h>
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

	spa->spa_vdev_retry_taskq = taskq_create("spa_vdev_retry",
	    4, maxclsyspri, 50, INT_MAX, TASKQ_PREPOPULATE);

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

	taskq_destroy(spa->spa_vdev_retry_taskq);
	spa->spa_vdev_retry_taskq = NULL;

	metaslab_class_destroy(spa->spa_normal_class);
	spa->spa_normal_class = NULL;

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
	 * Stop syncing.
	 */
	if (spa->spa_sync_on) {
		txg_sync_stop(spa->spa_dsl_pool);
		spa->spa_sync_on = B_FALSE;
	}

	/*
	 * Wait for any outstanding prefetch I/O to complete.
	 */
	spa_config_enter(spa, RW_WRITER);
	spa_config_exit(spa);

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
	if (spa->spa_root_vdev) {
		vdev_free(spa->spa_root_vdev);
		spa->spa_root_vdev = NULL;
	}
}

/*
 * Load an existing storage pool, using the pool's builtin spa_config as a
 * source of configuration information.  The 'readonly' flag will prevent us
 * from writing any updated state to disk, and can be use when testing a pool
 * for import.
 */
static int
spa_load(spa_t *spa, nvlist_t *config, int readonly, int import, int mosconfig)
{
	int error = 0;
	nvlist_t *nvroot = NULL;
	vdev_t *rvd;
	uberblock_t *ub = &spa->spa_uberblock;
	uint64_t pool_guid;
	zio_t *zio;

	if (nvlist_lookup_nvlist(config, ZPOOL_CONFIG_VDEV_TREE, &nvroot) ||
	    nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_GUID, &pool_guid))
		return (EINVAL);

	(void) nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_TXG,
	    &spa->spa_config_txg);

	if (import && spa_guid_exists(pool_guid, 0))
		return (EEXIST);

	/*
	 * Parse the configuration into a vdev tree.
	 */
	spa_config_enter(spa, RW_WRITER);
	rvd = spa_config_parse(spa, nvroot, NULL, 0, VDEV_ALLOC_LOAD);
	spa_config_exit(spa);

	if (rvd == NULL)
		return (EINVAL);

	spa->spa_root_vdev = rvd;
	ASSERT(spa_guid(spa) == pool_guid);

	/*
	 * Try to open all vdevs, loading each label in the process.
	 */
	if (vdev_open(rvd) != 0)
		return (ENXIO);

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
		dprintf("ub_txg is zero\n");
		return (ENXIO);
	}

	/*
	 * If the vdev guid sum doesn't match the uberblock, we have an
	 * incomplete configuration.
	 */
	if (rvd->vdev_guid_sum != ub->ub_guid_sum && mosconfig) {
		rvd->vdev_state = VDEV_STATE_CANT_OPEN;
		rvd->vdev_stat.vs_aux = VDEV_AUX_BAD_GUID_SUM;
		dprintf("vdev_guid_sum %llx != ub_guid_sum %llx\n",
		    rvd->vdev_guid_sum, ub->ub_guid_sum);
		return (ENXIO);
	}

	/*
	 * Initialize internal SPA structures.
	 */
	spa->spa_state = POOL_STATE_ACTIVE;
	spa->spa_ubsync = spa->spa_uberblock;
	spa->spa_first_txg = spa_last_synced_txg(spa) + 1;
	spa->spa_dsl_pool = dsl_pool_open(spa, spa->spa_first_txg);
	spa->spa_meta_objset = spa->spa_dsl_pool->dp_meta_objset;

	VERIFY(zap_lookup(spa->spa_meta_objset,
	    DMU_POOL_DIRECTORY_OBJECT, DMU_POOL_CONFIG,
	    sizeof (uint64_t), 1, &spa->spa_config_object) == 0);

	if (!mosconfig) {
		dmu_buf_t *db;
		char *packed = NULL;
		size_t nvsize = 0;
		nvlist_t *newconfig = NULL;

		db = dmu_bonus_hold(spa->spa_meta_objset,
		    spa->spa_config_object);
		dmu_buf_read(db);
		nvsize = *(uint64_t *)db->db_data;
		dmu_buf_rele(db);

		packed = kmem_alloc(nvsize, KM_SLEEP);
		error = dmu_read_canfail(spa->spa_meta_objset,
		    spa->spa_config_object, 0, nvsize, packed);
		if (error == 0)
			error = nvlist_unpack(packed, nvsize, &newconfig, 0);
		kmem_free(packed, nvsize);

		if (error)
			return (ENXIO);

		spa_config_set(spa, newconfig);

		spa_unload(spa);
		spa_deactivate(spa);
		spa_activate(spa);

		return (spa_load(spa, newconfig, readonly, import, B_TRUE));
	}

	VERIFY(zap_lookup(spa->spa_meta_objset,
	    DMU_POOL_DIRECTORY_OBJECT, DMU_POOL_SYNC_BPLIST,
	    sizeof (uint64_t), 1, &spa->spa_sync_bplist_obj) == 0);

	/*
	 * Load the vdev state for all top level vdevs.
	 */
	if ((error = vdev_load(rvd, import)) != 0)
		return (error);

	/*
	 * Propagate the leaf DTLs we just loaded all the way up the tree.
	 */
	spa_config_enter(spa, RW_WRITER);
	vdev_dtl_reassess(rvd, 0, 0, B_FALSE);
	spa_config_exit(spa);

	/*
	 * Check the state of the root vdev.  If it can't be opened, it
	 * indicates one or more toplevel vdevs are faulted.
	 */
	if (rvd->vdev_state <= VDEV_STATE_CANT_OPEN)
		return (ENXIO);

	/*
	 * Claim log blocks that haven't been committed yet, and update all
	 * top-level vdevs to sync any config changes found in vdev_load().
	 * This must all happen in a single txg.
	 */
	if ((spa_mode & FWRITE) && !readonly) {
		dmu_tx_t *tx = dmu_tx_create_assigned(spa_get_dsl(spa),
		    spa_first_txg(spa));
		dmu_objset_find(spa->spa_name, zil_claim, tx, 0);
		vdev_config_dirty(rvd);
		dmu_tx_commit(tx);

		spa->spa_sync_on = B_TRUE;
		txg_sync_start(spa->spa_dsl_pool);

		/*
		 * Wait for all claims to sync.
		 */
		txg_wait_synced(spa->spa_dsl_pool, 0);
	}

	return (0);
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
		    B_FALSE, B_FALSE, B_FALSE);

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
		} if (error) {
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
			if (locked)
				mutex_exit(&spa_namespace_lock);
			*spapp = NULL;
			return (error);
		}

		loaded = B_TRUE;
	}

	spa_open_ref(spa, tag);
	if (locked)
		mutex_exit(&spa_namespace_lock);

	*spapp = spa;

	if (config != NULL) {
		spa_config_enter(spa, RW_READER);
		*config = spa_config_generate(spa, NULL, -1ULL, B_TRUE);
		spa_config_exit(spa);
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

int
spa_get_stats(const char *name, nvlist_t **config)
{
	int error;
	spa_t *spa;

	*config = NULL;
	error = spa_open_common(name, &spa, FTAG, config);

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

	if (altroot != NULL) {
		spa->spa_root = spa_strdup(altroot);
		atomic_add_32(&spa_active_count, 1);
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

	VERIFY(zap_add(spa->spa_meta_objset,
	    DMU_POOL_DIRECTORY_OBJECT, DMU_POOL_CONFIG,
	    sizeof (uint64_t), 1, &spa->spa_config_object, tx) == 0);

	/*
	 * Create the deferred-free bplist object.  Turn off compression
	 * because sync-to-convergence takes longer if the blocksize
	 * keeps changing.
	 */
	spa->spa_sync_bplist_obj = bplist_create(spa->spa_meta_objset,
	    1 << 14, tx);
	dmu_object_set_compress(spa->spa_meta_objset, spa->spa_sync_bplist_obj,
	    ZIO_COMPRESS_OFF, tx);

	VERIFY(zap_add(spa->spa_meta_objset,
	    DMU_POOL_DIRECTORY_OBJECT, DMU_POOL_SYNC_BPLIST,
	    sizeof (uint64_t), 1, &spa->spa_sync_bplist_obj, tx) == 0);

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
	 * Pass off the heavy lifting to spa_load().  We pass TRUE for mosconfig
	 * so that we don't try to open the pool if the config is damaged.
	 */
	error = spa_load(spa, config, B_FALSE, B_TRUE, B_TRUE);

	if (error) {
		spa_unload(spa);
		spa_deactivate(spa);
		spa_remove(spa);
		mutex_exit(&spa_namespace_lock);
		return (error);
	}

	/*
	 * Set the alternate root, if there is one.
	 */
	if (altroot != NULL) {
		atomic_add_32(&spa_active_count, 1);
		spa->spa_root = spa_strdup(altroot);
	}

	/*
	 * Initialize the config based on the in-core state.
	 */
	config = spa_config_generate(spa, NULL, spa_last_synced_txg(spa), 0);

	spa_config_set(spa, config);

	/*
	 * Sync the configuration cache.
	 */
	spa_config_sync();

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
	(void) spa_load(spa, tryconfig, B_TRUE, B_TRUE, B_TRUE);

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

		if (!spa_refcount_zero(spa)) {
			spa_scrub_resume(spa);
			mutex_exit(&spa_namespace_lock);
			return (EBUSY);
		}

		/*
		 * Update the pool state.
		 */
		spa->spa_state = new_state;

		spa_scrub_resume(spa);
		VERIFY(spa_scrub(spa, POOL_SCRUB_NONE, B_TRUE) == 0);

		if (spa->spa_root != NULL)
			atomic_add_32(&spa_active_count, -1);

		/*
		 * We want this to be reflected on every label,
		 * so mark them all dirty.  spa_unload() will do the
		 * final sync that pushes these changes out.
		 */
		vdev_config_dirty(spa->spa_root_vdev);
	}

	if (spa->spa_state != POOL_STATE_UNINITIALIZED) {
		spa_unload(spa);
		spa_deactivate(spa);
	}

	spa_remove(spa);
	spa_config_sync();
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
	int c, error;
	vdev_t *rvd = spa->spa_root_vdev;
	vdev_t *vd;

	txg = spa_vdev_enter(spa);

	vd = spa_config_parse(spa, nvroot, NULL, 0, VDEV_ALLOC_ADD);

	if (vd == NULL)
		return (spa_vdev_exit(spa, vd, txg, EINVAL));

	if (rvd == NULL)			/* spa_create() */
		spa->spa_root_vdev = rvd = vd;

	if ((error = vdev_create(vd, txg)) != 0)
		return (spa_vdev_exit(spa, vd, txg, error));

	/*
	 * Transfer each top-level vdev from the temporary root
	 * to the spa's root and initialize its metaslabs.
	 */
	for (c = 0; c < vd->vdev_children; c++) {
		vdev_t *tvd = vd->vdev_child[c];
		if (vd != rvd) {
			vdev_remove_child(vd, tvd);
			tvd->vdev_id = rvd->vdev_children;
			vdev_add_child(rvd, tvd);
		}
		vdev_init(tvd, txg);
		vdev_config_dirty(tvd);
	}

	/*
	 * Update the config based on the new in-core state.
	 */
	spa_config_set(spa, spa_config_generate(spa, rvd, txg, 0));

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
spa_vdev_attach(spa_t *spa, const char *path, nvlist_t *nvroot, int replacing)
{
	uint64_t txg, open_txg;
	int error;
	vdev_t *rvd = spa->spa_root_vdev;
	vdev_t *oldvd, *newvd, *newrootvd, *pvd, *tvd;
	vdev_ops_t *pvops = replacing ? &vdev_replacing_ops : &vdev_mirror_ops;

	txg = spa_vdev_enter(spa);

	oldvd = vdev_lookup_by_path(rvd, path);

	if (oldvd == NULL)
		return (spa_vdev_exit(spa, NULL, txg, ENODEV));

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

	if (newvd->vdev_psize < oldvd->vdev_psize)
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

	tvd = newvd->vdev_top;
	ASSERT(pvd->vdev_top == tvd);
	ASSERT(tvd->vdev_parent == rvd);

	/*
	 * Update the config based on the new in-core state.
	 */
	spa_config_set(spa, spa_config_generate(spa, rvd, txg, 0));

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

	/*
	 * Mark newvd's DTL dirty in this txg.
	 */
	vdev_dirty(tvd, VDD_DTL, txg);
	(void) txg_list_add(&tvd->vdev_dtl_list, newvd, txg);

	dprintf("attached %s, replacing=%d\n", path, replacing);

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
spa_vdev_detach(spa_t *spa, const char *path, uint64_t guid, int replace_done)
{
	uint64_t txg;
	int c, t, error;
	vdev_t *rvd = spa->spa_root_vdev;
	vdev_t *vd, *pvd, *cvd, *tvd;

	txg = spa_vdev_enter(spa);

	vd = vdev_lookup_by_path(rvd, path);

	if (vd == NULL)
		return (spa_vdev_exit(spa, NULL, txg, ENODEV));

	if (guid != 0 && vd->vdev_guid != guid)
		return (spa_vdev_exit(spa, NULL, txg, ENODEV));

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
	vdev_reopen(tvd, NULL);

	/*
	 * If the device we just detached was smaller than the others,
	 * it may be possible to add metaslabs (i.e. grow the pool).
	 */
	vdev_metaslab_init(tvd, txg);

	/*
	 * Update the config based on the new in-core state.
	 */
	spa_config_set(spa, spa_config_generate(spa, rvd, txg, 0));

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

	dprintf("detached %s\n", path);

	return (spa_vdev_exit(spa, vd, txg, 0));
}

/*
 * If there are any replacing vdevs that have finished replacing, detach them.
 * We can't hold the config lock across detaches, so we lock the config,
 * build a list of candidates, unlock the config, and try each candidate.
 */
typedef struct vdev_detach_link {
	char		*vdl_path;
	uint64_t	vdl_guid;
	list_node_t	vdl_node;
} vdev_detach_link_t;

static void
spa_vdev_replace_done_make_list(list_t *l, vdev_t *vd)
{
	int c;

	for (c = 0; c < vd->vdev_children; c++)
		spa_vdev_replace_done_make_list(l, vd->vdev_child[c]);

	if (vd->vdev_ops == &vdev_replacing_ops && vd->vdev_children == 2) {
		vdev_t *cvd0 = vd->vdev_child[0];
		vdev_t *cvd1 = vd->vdev_child[1];
		vdev_detach_link_t *vdl;
		int dirty1;

		mutex_enter(&cvd1->vdev_dtl_lock);
		dirty1 = cvd1->vdev_dtl_map.sm_space |
		    cvd1->vdev_dtl_scrub.sm_space;
		mutex_exit(&cvd1->vdev_dtl_lock);

		if (!dirty1) {
			vdl = kmem_zalloc(sizeof (*vdl), KM_SLEEP);
			vdl->vdl_path = spa_strdup(cvd0->vdev_path);
			vdl->vdl_guid = cvd0->vdev_guid;
			list_insert_tail(l, vdl);
		}
	}
}

void
spa_vdev_replace_done(spa_t *spa)
{
	vdev_detach_link_t *vdl;
	list_t vdlist;

	list_create(&vdlist, sizeof (vdev_detach_link_t),
	    offsetof(vdev_detach_link_t, vdl_node));

	spa_config_enter(spa, RW_READER);
	spa_vdev_replace_done_make_list(&vdlist, spa->spa_root_vdev);
	spa_config_exit(spa);

	while ((vdl = list_head(&vdlist)) != NULL) {
		list_remove(&vdlist, vdl);
		(void) spa_vdev_detach(spa, vdl->vdl_path, vdl->vdl_guid,
		    B_TRUE);
		spa_strfree(vdl->vdl_path);
		kmem_free(vdl, sizeof (*vdl));
	}

	list_destroy(&vdlist);
}

/*
 * ==========================================================================
 * SPA Scrubbing
 * ==========================================================================
 */

static int spa_scrub_locked(spa_t *, pool_scrub_type_t, boolean_t);

static void
spa_scrub_io_done(zio_t *zio)
{
	spa_t *spa = zio->io_spa;

	zio_buf_free(zio->io_data, zio->io_size);

	mutex_enter(&spa->spa_scrub_lock);
	if (zio->io_error)
		spa->spa_scrub_errors++;
	if (--spa->spa_scrub_inflight == 0)
		cv_broadcast(&spa->spa_scrub_io_cv);
	mutex_exit(&spa->spa_scrub_lock);

	if (zio->io_error) {
		vdev_t *vd = zio->io_vd;
		mutex_enter(&vd->vdev_stat_lock);
		vd->vdev_stat.vs_scrub_errors++;
		mutex_exit(&vd->vdev_stat_lock);
	}
}

static void
spa_scrub_io_start(spa_t *spa, blkptr_t *bp, int priority, int flags)
{
	size_t size = BP_GET_LSIZE(bp);
	void *data = zio_buf_alloc(size);

	mutex_enter(&spa->spa_scrub_lock);
	spa->spa_scrub_inflight++;
	mutex_exit(&spa->spa_scrub_lock);

	zio_nowait(zio_read(NULL, spa, bp, data, size,
	    spa_scrub_io_done, NULL, priority, flags));
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
			    ZIO_FLAG_CANFAIL | ZIO_FLAG_DONT_RETRY |
			    ZIO_FLAG_RESILVER);
		}
	} else {
		spa_scrub_io_start(spa, bp, ZIO_PRIORITY_SCRUB,
		    ZIO_FLAG_CANFAIL | ZIO_FLAG_DONT_RETRY | ZIO_FLAG_SCRUB);
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

	spa_config_enter(spa, RW_WRITER);
	vdev_reopen(rvd, NULL);		/* purge all vdev caches */
	vdev_config_dirty(rvd);		/* rewrite all disk labels */
	vdev_scrub_stat_update(rvd, scrub_type, B_FALSE);
	spa_config_exit(spa);

	mutex_enter(&spa->spa_scrub_lock);
	spa->spa_scrub_errors = 0;
	spa->spa_scrub_active = 1;

	while (!spa->spa_scrub_stop) {
		CALLB_CPR_SAFE_BEGIN(&cprinfo);
		while (spa->spa_scrub_suspend) {
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
	}

	while (spa->spa_scrub_inflight)
		cv_wait(&spa->spa_scrub_io_cv, &spa->spa_scrub_lock);

	if (spa->spa_scrub_restart_txg != 0)
		error = ERESTART;

	spa->spa_scrub_active = 0;
	cv_broadcast(&spa->spa_scrub_cv);

	/*
	 * If the traverse completed, and there were no errors,
	 * then the scrub was completely successful.
	 */
	complete = (error == 0 && spa->spa_scrub_errors == 0);

	dprintf("scrub to maxtxg=%llu %s, traverse=%d, %llu errors, stop=%u\n",
	    spa->spa_scrub_maxtxg, complete ? "done" : "FAILED",
	    error, spa->spa_scrub_errors, spa->spa_scrub_stop);

	mutex_exit(&spa->spa_scrub_lock);

	/*
	 * If the scrub/resilver completed, update all DTLs to reflect this.
	 * Whether it succeeded or not, vacate all temporary scrub DTLs.
	 */
	spa_config_enter(spa, RW_WRITER);
	vdev_dtl_reassess(rvd, spa_last_synced_txg(spa) + 1,
	    complete ? spa->spa_scrub_maxtxg : 0, B_TRUE);
	spa_config_exit(spa);

	spa_vdev_replace_done(spa);

	spa_config_enter(spa, RW_READER);
	vdev_scrub_stat_update(rvd, POOL_SCRUB_NONE, complete);
	spa_config_exit(spa);

	mutex_enter(&spa->spa_scrub_lock);

	spa->spa_scrub_type = POOL_SCRUB_NONE;
	spa->spa_scrub_active = 0;
	spa->spa_scrub_thread = NULL;

	cv_broadcast(&spa->spa_scrub_cv);

	/*
	 * If we were told to restart, our final act is to start a new scrub.
	 */
	if (error == ERESTART)
		VERIFY(spa_scrub_locked(spa, scrub_type, B_TRUE) == 0);

	CALLB_CPR_EXIT(&cprinfo);	/* drops &spa->spa_scrub_lock */
	thread_exit();
}

void
spa_scrub_suspend(spa_t *spa)
{
	mutex_enter(&spa->spa_scrub_lock);
	spa->spa_scrub_suspend++;
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
	ASSERT(spa->spa_scrub_suspend != 0);
	if (--spa->spa_scrub_suspend == 0)
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

static int
spa_scrub_locked(spa_t *spa, pool_scrub_type_t type, boolean_t force)
{
	space_seg_t *ss;
	uint64_t mintxg, maxtxg;
	vdev_t *rvd = spa->spa_root_vdev;
	int advance = 0;

	if ((uint_t)type >= POOL_SCRUB_TYPES)
		return (ENOTSUP);

	/*
	 * If there's a scrub or resilver already in progress, stop it.
	 */
	while (spa->spa_scrub_thread != NULL) {
		/*
		 * Don't stop a resilver unless forced.
		 */
		if (spa->spa_scrub_type == POOL_SCRUB_RESILVER && !force)
			return (EBUSY);

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

	spa->spa_scrub_stop = 0;
	spa->spa_scrub_type = type;
	spa->spa_scrub_restart_txg = 0;

	mintxg = TXG_INITIAL - 1;
	maxtxg = spa_last_synced_txg(spa) + 1;

	switch (type) {

	case POOL_SCRUB_NONE:
		break;

	case POOL_SCRUB_RESILVER:
		/*
		 * Determine the resilvering boundaries.
		 *
		 * Note: (mintxg, maxtxg) is an open interval,
		 * i.e. mintxg and maxtxg themselves are not included.
		 *
		 * Note: for maxtxg, we MIN with spa_last_synced_txg(spa) + 1
		 * so we don't claim to resilver a txg that's still changing.
		 */
		mutex_enter(&rvd->vdev_dtl_lock);
		ss = avl_first(&rvd->vdev_dtl_map.sm_root);
		mintxg = ss ? ss->ss_start - 1 : 0;
		ss = avl_last(&rvd->vdev_dtl_map.sm_root);
		maxtxg = ss ? ss->ss_end : 0;
		maxtxg = MIN(maxtxg, spa_last_synced_txg(spa) + 1);
		mutex_exit(&rvd->vdev_dtl_lock);

		advance = ADVANCE_PRE | ADVANCE_PRUNE;
		break;

	case POOL_SCRUB_EVERYTHING:
		/*
		 * A scrub is like a resilver, but not pruned by DTL.
		 */
		advance = ADVANCE_PRE;
		break;
	}

	if (mintxg != 0 && maxtxg != 0 && type != POOL_SCRUB_NONE) {
		spa->spa_scrub_maxtxg = maxtxg;
		spa->spa_scrub_th = traverse_init(spa, spa_scrub_cb, NULL,
		    advance, ZIO_FLAG_CANFAIL);
		traverse_add_pool(spa->spa_scrub_th, mintxg, maxtxg);
		spa->spa_scrub_thread = thread_create(NULL, 0,
		    spa_scrub_thread, spa, 0, &p0, TS_RUN, minclsyspri);
	}

	return (0);
}

int
spa_scrub(spa_t *spa, pool_scrub_type_t type, boolean_t force)
{
	int error;
	traverse_handle_t *th;

	mutex_enter(&spa->spa_scrub_lock);
	error = spa_scrub_locked(spa, type, force);
	th = spa->spa_scrub_th;
	mutex_exit(&spa->spa_scrub_lock);

	if (th == NULL && type != POOL_SCRUB_NONE)
		spa_vdev_replace_done(spa);

	return (error);
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

	VERIFY(nvlist_pack(config, &packed, &nvsize, NV_ENCODE_XDR, 0) == 0);

	dmu_write(spa->spa_meta_objset, spa->spa_config_object, 0, nvsize,
	    packed, tx);

	kmem_free(packed, nvsize);

	db = dmu_bonus_hold(spa->spa_meta_objset, spa->spa_config_object);
	dmu_buf_will_dirty(db, tx);
	*(uint64_t *)db->db_data = nvsize;
	dmu_buf_rele(db);
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
	vdev_t *rvd = spa->spa_root_vdev;
	vdev_t *vd;
	dmu_tx_t *tx;
	int dirty_vdevs;

	/*
	 * Lock out configuration changes.
	 */
	spa_config_enter(spa, RW_READER);

	spa->spa_syncing_txg = txg;
	spa->spa_sync_pass = 0;

	bplist_open(bpl, mos, spa->spa_sync_bplist_obj);

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
	while (spa_sync_labels(spa, txg)) {
		dprintf("waiting for devices to heal\n");
		delay(hz);
		vdev_reopen(rvd, NULL);
	}

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

	spa_config_exit(spa);
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
		 * Stop all scrub and resilver activity.  spa_scrub() needs to
		 * wait for the scrub thread, which may do a detach and sync the
		 * configs, which needs spa_namespace_lock.  Drop the lock while
		 * maintaining a hold on the spa_t.
		 */
		spa_open_ref(spa, FTAG);
		mutex_exit(&spa_namespace_lock);
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
