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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2012 by Delphix. All rights reserved.
 * Copyright (c) 2012 Joyent, Inc. All rights reserved.
 */

#include <sys/dmu.h>
#include <sys/dmu_objset.h>
#include <sys/dmu_tx.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_dir.h>
#include <sys/dsl_prop.h>
#include <sys/dsl_synctask.h>
#include <sys/dsl_deleg.h>
#include <sys/spa.h>
#include <sys/metaslab.h>
#include <sys/zap.h>
#include <sys/zio.h>
#include <sys/arc.h>
#include <sys/sunddi.h>
#include <sys/zfs_zone.h>
#include <sys/zfeature.h>
#include <sys/policy.h>
#include <sys/zfs_znode.h>
#include "zfs_namecheck.h"
#include "zfs_prop.h"

/*
 * Filesystem and Snapshot Limits
 * ------------------------------
 *
 * These limits are used to restrict the number of filesystems and/or snapshots
 * that can be created at a given level in the tree or below. A typical
 * use-case is with a delegated dataset where the administrator wants to ensure
 * that a user within the zone is not creating too many additional filesystems
 * or snapshots, even though they're not exceeding their space quota.
 *
 * The count of filesystems and snapshots is stored in the dsl_dir_phys_t which
 * impacts the on-disk format. As such, this capability is controlled by a
 * feature flag and must be enabled to be used. Once enabled, the feature is
 * not active until the first limit is set. At that point, future operations to
 * create/destroy filesystems or snapshots will validate and update the counts.
 *
 * Because the on-disk counts will be uninitialized (0) before the feature is
 * active, the counts are updated when a limit is first set on an uninitialized
 * node (The filesystem/snapshot counts on a node includes all of the nested
 * filesystems/snapshots, plus the node itself. Thus, a new leaf node has a
 * filesystem count of 1 and a snapshot count of 0. A filesystem count of 0 on
 * a node indicates uninitialized counts on that node.) When setting a limit on
 * an uninitialized node, the code starts at the filesystem with the new limit
 * and descends into all sub-filesystems and updates the counts to be accurate.
 * In practice this is lightweight since a limit is typically set when the
 * filesystem is created and thus has no children. Once valid, changing the
 * limit value won't require a re-traversal since the counts are already valid.
 * When recursively fixing the counts, if a node with a limit is encountered
 * during the descent, the counts are known to be valid and there is no need to
 * descend into that filesystem's children. The counts on filesystems above the
 * one with the new limit will still be uninitialized (0), unless a limit is
 * eventually set on one of those filesystems. The counts are always recursively
 * updated when a limit is set on a dataset, unless there is already a limit.
 * When a new limit value is set on a filesystem with an existing limit, it is
 * possible for the new limit to be less than the current count at that level
 * since a user who can change the limit is also allowed to exceed the limit.
 *
 * Once the feature is active, then whenever a filesystem or snapshot is
 * created, the code recurses up the tree, validating the new count against the
 * limit at each initialized level. In practice, most levels will not have a
 * limit set. If there is a limit at any initialized level up the tree, the
 * check must pass or the creation will fail. Likewise, when a filesystem or
 * snapshot is destroyed, the counts are recursively adjusted all the way up
 * the initizized nodes in the tree. Renaming a filesystem into different point
 * in the tree will first validate, then update the counts on each branch up to
 * the common ancestor. A receive will also validate the counts and then update
 * them.
 *
 * An exception to the above behavior is that the limit is not enforced if the
 * user has permission to modify the limit. This is primarily so that
 * recursive snapshots in the global zone always work. We want to prevent a
 * denial-of-service in which a lower level delegated dataset could max out its
 * limit and thus block recursive snapshots from being taken in the global zone.
 * Because of this, it is possible for the snapshot count to be over the limit
 * and snapshots taken in the global zone could cause a lower level dataset to
 * hit or exceed its limit. The administrator taking the global zone recursive
 * snapshot should be aware of this side-effect and behave accordingly.
 * For consistency, the filesystem limit is also not enforced if the user can
 * modify the limit.
 *
 * The filesystem limit is validated by dsl_dir_fscount_check() and updated by
 * dsl_dir_fscount_adjust(). The snapshot limit is validated by
 * dsl_snapcount_check() and updated by dsl_snapcount_adjust().
 * A new limit value is validated in dsl_dir_validate_fs_ss_limit() and the
 * filesystem counts are adjusted, if necessary, by dsl_dir_set_fs_ss_count().
 *
 * There is a special case when we receive a filesystem that already exists. In
 * this case a temporary clone name of %X is created (see dmu_recv_begin). We
 * never update the filesystem counts for temporary clones.
 */

static uint64_t dsl_dir_space_towrite(dsl_dir_t *dd);
static void dsl_dir_set_reservation_sync_impl(dsl_dir_t *dd,
    uint64_t value, dmu_tx_t *tx);

extern dsl_syncfunc_t dsl_prop_set_sync;

/* ARGSUSED */
static void
dsl_dir_evict(dmu_buf_t *db, void *arg)
{
	dsl_dir_t *dd = arg;
	dsl_pool_t *dp = dd->dd_pool;
	int t;

	for (t = 0; t < TXG_SIZE; t++) {
		ASSERT(!txg_list_member(&dp->dp_dirty_dirs, dd, t));
		ASSERT(dd->dd_tempreserved[t] == 0);
		ASSERT(dd->dd_space_towrite[t] == 0);
	}

	if (dd->dd_parent)
		dsl_dir_close(dd->dd_parent, dd);

	spa_close(dd->dd_pool->dp_spa, dd);

	/*
	 * The props callback list should have been cleaned up by
	 * objset_evict().
	 */
	list_destroy(&dd->dd_prop_cbs);
	mutex_destroy(&dd->dd_lock);
	kmem_free(dd, sizeof (dsl_dir_t));
}

int
dsl_dir_open_obj(dsl_pool_t *dp, uint64_t ddobj,
    const char *tail, void *tag, dsl_dir_t **ddp)
{
	dmu_buf_t *dbuf;
	dsl_dir_t *dd;
	int err;

	ASSERT(RW_LOCK_HELD(&dp->dp_config_rwlock) ||
	    dsl_pool_sync_context(dp));

	err = dmu_bonus_hold(dp->dp_meta_objset, ddobj, tag, &dbuf);
	if (err)
		return (err);
	dd = dmu_buf_get_user(dbuf);
#ifdef ZFS_DEBUG
	{
		dmu_object_info_t doi;
		dmu_object_info_from_db(dbuf, &doi);
		ASSERT3U(doi.doi_type, ==, DMU_OT_DSL_DIR);
		ASSERT3U(doi.doi_bonus_size, >=, sizeof (dsl_dir_phys_t));
	}
#endif
	if (dd == NULL) {
		dsl_dir_t *winner;

		dd = kmem_zalloc(sizeof (dsl_dir_t), KM_SLEEP);
		dd->dd_object = ddobj;
		dd->dd_dbuf = dbuf;
		dd->dd_pool = dp;
		dd->dd_phys = dbuf->db_data;
		mutex_init(&dd->dd_lock, NULL, MUTEX_DEFAULT, NULL);

		list_create(&dd->dd_prop_cbs, sizeof (dsl_prop_cb_record_t),
		    offsetof(dsl_prop_cb_record_t, cbr_node));

		dsl_dir_snap_cmtime_update(dd);

		if (dd->dd_phys->dd_parent_obj) {
			err = dsl_dir_open_obj(dp, dd->dd_phys->dd_parent_obj,
			    NULL, dd, &dd->dd_parent);
			if (err)
				goto errout;
			if (tail) {
#ifdef ZFS_DEBUG
				uint64_t foundobj;

				err = zap_lookup(dp->dp_meta_objset,
				    dd->dd_parent->dd_phys->dd_child_dir_zapobj,
				    tail, sizeof (foundobj), 1, &foundobj);
				ASSERT(err || foundobj == ddobj);
#endif
				(void) strcpy(dd->dd_myname, tail);
			} else {
				err = zap_value_search(dp->dp_meta_objset,
				    dd->dd_parent->dd_phys->dd_child_dir_zapobj,
				    ddobj, 0, dd->dd_myname);
			}
			if (err)
				goto errout;
		} else {
			(void) strcpy(dd->dd_myname, spa_name(dp->dp_spa));
		}

		if (dsl_dir_is_clone(dd)) {
			dmu_buf_t *origin_bonus;
			dsl_dataset_phys_t *origin_phys;

			/*
			 * We can't open the origin dataset, because
			 * that would require opening this dsl_dir.
			 * Just look at its phys directly instead.
			 */
			err = dmu_bonus_hold(dp->dp_meta_objset,
			    dd->dd_phys->dd_origin_obj, FTAG, &origin_bonus);
			if (err)
				goto errout;
			origin_phys = origin_bonus->db_data;
			dd->dd_origin_txg =
			    origin_phys->ds_creation_txg;
			dmu_buf_rele(origin_bonus, FTAG);
		}

		winner = dmu_buf_set_user_ie(dbuf, dd, &dd->dd_phys,
		    dsl_dir_evict);
		if (winner) {
			if (dd->dd_parent)
				dsl_dir_close(dd->dd_parent, dd);
			mutex_destroy(&dd->dd_lock);
			kmem_free(dd, sizeof (dsl_dir_t));
			dd = winner;
		} else {
			spa_open_ref(dp->dp_spa, dd);
		}
	}

	/*
	 * The dsl_dir_t has both open-to-close and instantiate-to-evict
	 * holds on the spa.  We need the open-to-close holds because
	 * otherwise the spa_refcnt wouldn't change when we open a
	 * dir which the spa also has open, so we could incorrectly
	 * think it was OK to unload/export/destroy the pool.  We need
	 * the instantiate-to-evict hold because the dsl_dir_t has a
	 * pointer to the dd_pool, which has a pointer to the spa_t.
	 */
	spa_open_ref(dp->dp_spa, tag);
	ASSERT3P(dd->dd_pool, ==, dp);
	ASSERT3U(dd->dd_object, ==, ddobj);
	ASSERT3P(dd->dd_dbuf, ==, dbuf);
	*ddp = dd;
	return (0);

errout:
	if (dd->dd_parent)
		dsl_dir_close(dd->dd_parent, dd);
	mutex_destroy(&dd->dd_lock);
	kmem_free(dd, sizeof (dsl_dir_t));
	dmu_buf_rele(dbuf, tag);
	return (err);
}

void
dsl_dir_close(dsl_dir_t *dd, void *tag)
{
	dprintf_dd(dd, "%s\n", "");
	spa_close(dd->dd_pool->dp_spa, tag);
	dmu_buf_rele(dd->dd_dbuf, tag);
}

/* buf must be long enough (MAXNAMELEN + strlen(MOS_DIR_NAME) + 1 should do) */
void
dsl_dir_name(dsl_dir_t *dd, char *buf)
{
	if (dd->dd_parent) {
		dsl_dir_name(dd->dd_parent, buf);
		(void) strcat(buf, "/");
	} else {
		buf[0] = '\0';
	}
	if (!MUTEX_HELD(&dd->dd_lock)) {
		/*
		 * recursive mutex so that we can use
		 * dprintf_dd() with dd_lock held
		 */
		mutex_enter(&dd->dd_lock);
		(void) strcat(buf, dd->dd_myname);
		mutex_exit(&dd->dd_lock);
	} else {
		(void) strcat(buf, dd->dd_myname);
	}
}

/* Calculate name length, avoiding all the strcat calls of dsl_dir_name */
int
dsl_dir_namelen(dsl_dir_t *dd)
{
	int result = 0;

	if (dd->dd_parent) {
		/* parent's name + 1 for the "/" */
		result = dsl_dir_namelen(dd->dd_parent) + 1;
	}

	if (!MUTEX_HELD(&dd->dd_lock)) {
		/* see dsl_dir_name */
		mutex_enter(&dd->dd_lock);
		result += strlen(dd->dd_myname);
		mutex_exit(&dd->dd_lock);
	} else {
		result += strlen(dd->dd_myname);
	}

	return (result);
}

static int
getcomponent(const char *path, char *component, const char **nextp)
{
	char *p;
	if ((path == NULL) || (path[0] == '\0'))
		return (ENOENT);
	/* This would be a good place to reserve some namespace... */
	p = strpbrk(path, "/@");
	if (p && (p[1] == '/' || p[1] == '@')) {
		/* two separators in a row */
		return (EINVAL);
	}
	if (p == NULL || p == path) {
		/*
		 * if the first thing is an @ or /, it had better be an
		 * @ and it had better not have any more ats or slashes,
		 * and it had better have something after the @.
		 */
		if (p != NULL &&
		    (p[0] != '@' || strpbrk(path+1, "/@") || p[1] == '\0'))
			return (EINVAL);
		if (strlen(path) >= MAXNAMELEN)
			return (ENAMETOOLONG);
		(void) strcpy(component, path);
		p = NULL;
	} else if (p[0] == '/') {
		if (p-path >= MAXNAMELEN)
			return (ENAMETOOLONG);
		(void) strncpy(component, path, p - path);
		component[p-path] = '\0';
		p++;
	} else if (p[0] == '@') {
		/*
		 * if the next separator is an @, there better not be
		 * any more slashes.
		 */
		if (strchr(path, '/'))
			return (EINVAL);
		if (p-path >= MAXNAMELEN)
			return (ENAMETOOLONG);
		(void) strncpy(component, path, p - path);
		component[p-path] = '\0';
	} else {
		ASSERT(!"invalid p");
	}
	*nextp = p;
	return (0);
}

/*
 * same as dsl_open_dir, ignore the first component of name and use the
 * spa instead
 */
int
dsl_dir_open_spa(spa_t *spa, const char *name, void *tag,
    dsl_dir_t **ddp, const char **tailp)
{
	char buf[MAXNAMELEN];
	const char *next, *nextnext = NULL;
	int err;
	dsl_dir_t *dd;
	dsl_pool_t *dp;
	uint64_t ddobj;
	int openedspa = FALSE;

	dprintf("%s\n", name);

	err = getcomponent(name, buf, &next);
	if (err)
		return (err);
	if (spa == NULL) {
		err = spa_open(buf, &spa, FTAG);
		if (err) {
			dprintf("spa_open(%s) failed\n", buf);
			return (err);
		}
		openedspa = TRUE;

		/* XXX this assertion belongs in spa_open */
		ASSERT(!dsl_pool_sync_context(spa_get_dsl(spa)));
	}

	dp = spa_get_dsl(spa);

	rw_enter(&dp->dp_config_rwlock, RW_READER);
	err = dsl_dir_open_obj(dp, dp->dp_root_dir_obj, NULL, tag, &dd);
	if (err) {
		rw_exit(&dp->dp_config_rwlock);
		if (openedspa)
			spa_close(spa, FTAG);
		return (err);
	}

	while (next != NULL) {
		dsl_dir_t *child_ds;
		err = getcomponent(next, buf, &nextnext);
		if (err)
			break;
		ASSERT(next[0] != '\0');
		if (next[0] == '@')
			break;
		dprintf("looking up %s in obj%lld\n",
		    buf, dd->dd_phys->dd_child_dir_zapobj);

		err = zap_lookup(dp->dp_meta_objset,
		    dd->dd_phys->dd_child_dir_zapobj,
		    buf, sizeof (ddobj), 1, &ddobj);
		if (err) {
			if (err == ENOENT)
				err = 0;
			break;
		}

		err = dsl_dir_open_obj(dp, ddobj, buf, tag, &child_ds);
		if (err)
			break;
		dsl_dir_close(dd, tag);
		dd = child_ds;
		next = nextnext;
	}
	rw_exit(&dp->dp_config_rwlock);

	if (err) {
		dsl_dir_close(dd, tag);
		if (openedspa)
			spa_close(spa, FTAG);
		return (err);
	}

	/*
	 * It's an error if there's more than one component left, or
	 * tailp==NULL and there's any component left.
	 */
	if (next != NULL &&
	    (tailp == NULL || (nextnext && nextnext[0] != '\0'))) {
		/* bad path name */
		dsl_dir_close(dd, tag);
		dprintf("next=%p (%s) tail=%p\n", next, next?next:"", tailp);
		err = ENOENT;
	}
	if (tailp)
		*tailp = next;
	if (openedspa)
		spa_close(spa, FTAG);
	*ddp = dd;
	return (err);
}

/*
 * Return the dsl_dir_t, and possibly the last component which couldn't
 * be found in *tail.  Return NULL if the path is bogus, or if
 * tail==NULL and we couldn't parse the whole name.  (*tail)[0] == '@'
 * means that the last component is a snapshot.
 */
int
dsl_dir_open(const char *name, void *tag, dsl_dir_t **ddp, const char **tailp)
{
	return (dsl_dir_open_spa(NULL, name, tag, ddp, tailp));
}

/*
 * Check if the counts are already valid for this filesystem and its
 * descendants. The counts on this filesystem, and those below, may be
 * uninitialized due to either the use of a pre-existing pool which did not
 * support the filesystem/snapshot limit feature, or one in which the feature
 * had not yet been enabled.
 *
 * Recursively descend the filesystem tree and update the filesystem/snapshot
 * counts on each filesystem below, then update the cumulative count on the
 * current filesystem. If the filesystem already has a limit set on it,
 * then we know that its counts, and the counts on the filesystems below it,
 * have been updated to be correct, so we can skip this filesystem.
 */
static int
dsl_dir_set_fs_ss_count(dsl_dir_t *dd, dmu_tx_t *tx, uint64_t *fscnt,
    uint64_t *sscnt)
{
	uint64_t my_fs_cnt = 0;
	uint64_t my_ss_cnt = 0;
	uint64_t curr_ss_cnt;
	objset_t *os = dd->dd_pool->dp_meta_objset;
	zap_cursor_t *zc;
	zap_attribute_t *za;
	int err;
	int ret = 0;
	boolean_t limit_set = B_FALSE;
	uint64_t fslimit, sslimit;
	dsl_dataset_t *ds;

	ASSERT(RW_LOCK_HELD(&dd->dd_pool->dp_config_rwlock));

	err = dsl_prop_get_dd(dd, zfs_prop_to_name(ZFS_PROP_FILESYSTEM_LIMIT),
	    8, 1, &fslimit, NULL, B_FALSE);
	if (err == 0 && fslimit != UINT64_MAX)
		limit_set = B_TRUE;

	if (!limit_set) {
		err = dsl_prop_get_dd(dd,
		    zfs_prop_to_name(ZFS_PROP_SNAPSHOT_LIMIT), 8, 1, &sslimit,
		    NULL, B_FALSE);
		if (err == 0 && sslimit != UINT64_MAX)
			limit_set = B_TRUE;
	}

	/*
	 * If the dd has a limit, we know its count is already good and we
	 * don't need to recurse down any further.
	 */
	if (limit_set) {
		*fscnt = dd->dd_phys->dd_filesystem_count;
		*sscnt = dd->dd_phys->dd_snapshot_count;
		return (ret);
	}

	zc = kmem_alloc(sizeof (zap_cursor_t), KM_SLEEP);
	za = kmem_alloc(sizeof (zap_attribute_t), KM_SLEEP);

	mutex_enter(&dd->dd_lock);

	/* Iterate datasets */
	for (zap_cursor_init(zc, os, dd->dd_phys->dd_child_dir_zapobj);
	    zap_cursor_retrieve(zc, za) == 0; zap_cursor_advance(zc)) {
		dsl_dir_t *chld_dd;
		uint64_t chld_fs_cnt = 0;
		uint64_t chld_ss_cnt = 0;

		if (dsl_dir_open_obj(dd->dd_pool,
		    ZFS_DIRENT_OBJ(za->za_first_integer), NULL, FTAG,
		    &chld_dd)) {
			ret = 1;
			break;
		}

		if (dsl_dir_set_fs_ss_count(chld_dd, tx, &chld_fs_cnt,
		    &chld_ss_cnt)) {
			ret = 1;
			break;
		}

		dsl_dir_close(chld_dd, FTAG);

		my_fs_cnt += chld_fs_cnt;
		my_ss_cnt += chld_ss_cnt;
	}
	zap_cursor_fini(zc);
	kmem_free(zc, sizeof (zap_cursor_t));
	kmem_free(za, sizeof (zap_attribute_t));

	/* Count snapshots */
	if (dsl_dataset_hold_obj(dd->dd_pool, dd->dd_phys->dd_head_dataset_obj,
	    FTAG, &ds) == 0) {
		if (zap_count(os, ds->ds_phys->ds_snapnames_zapobj,
		    &curr_ss_cnt) == 0)
			my_ss_cnt += curr_ss_cnt;
		else
			ret = 1;
		dsl_dataset_rele(ds, FTAG);
	} else {
		ret = 1;
	}

	/* Add 1 for self */
	my_fs_cnt++;

	/* save updated counts */
	dmu_buf_will_dirty(dd->dd_dbuf, tx);
	dd->dd_phys->dd_filesystem_count = my_fs_cnt;
	dd->dd_phys->dd_snapshot_count = my_ss_cnt;

	mutex_exit(&dd->dd_lock);

	/* Return child dataset count plus self */
	*fscnt = my_fs_cnt;
	*sscnt = my_ss_cnt;
	return (ret);
}

/* ARGSUSED */
static int
fs_ss_limit_feat_check(void *arg1, void *arg2, dmu_tx_t *tx)
{
	return (0);
}

/* ARGSUSED */
static void
fs_ss_limit_feat_sync(void *arg1, void *arg2, dmu_tx_t *tx)
{
	spa_t *spa = arg1;
	zfeature_info_t *limit_feat =
	    &spa_feature_table[SPA_FEATURE_FS_SS_LIMIT];

	spa_feature_incr(spa, limit_feat, tx);
}

/*
 * Make sure the feature is enabled and activate it if necessary.
 * If setting a limit, ensure the on-disk counts are valid.
 *
 * We do not validate the new limit, since users who can change the limit are
 * also allowed to exceed the limit.
 *
 * Return -1 to force the zfs_set_prop_nvlist code down the default path to set
 * the value in the nvlist.
 */
int
dsl_dir_validate_fs_ss_limit(const char *ddname, uint64_t limit,
    zfs_prop_t ptype)
{
	dsl_dir_t *dd;
	dsl_dataset_t *ds;
	int err;
	dmu_tx_t *tx;
	uint64_t my_fs_cnt = 0;
	uint64_t my_ss_cnt = 0;
	uint64_t curr_limit;
	spa_t *spa;
	zfeature_info_t *limit_feat =
	    &spa_feature_table[SPA_FEATURE_FS_SS_LIMIT];

	if ((err = dsl_dataset_hold(ddname, FTAG, &ds)) != 0)
		return (err);

	spa = dsl_dataset_get_spa(ds);
	if (!spa_feature_is_enabled(spa,
	    &spa_feature_table[SPA_FEATURE_FS_SS_LIMIT])) {
		dsl_dataset_rele(ds, FTAG);
		return (ENOTSUP);
	}

	dd = ds->ds_dir;

	if ((err = dsl_prop_get_dd(dd, zfs_prop_to_name(ptype), 8, 1,
	    &curr_limit, NULL, B_FALSE)) != 0) {
		dsl_dataset_rele(ds, FTAG);
		return (err);
	}

	if (limit == UINT64_MAX) {
		/*
		 * If we had a limit, since we're now removing that limit, this
		 * is where we could decrement the feature-active counter so
		 * that the feature becomes inactive (only enabled) if we
		 * remove the last limit. However, we do not currently support
		 * deactivating the feature.
		 */
		dsl_dataset_rele(ds, FTAG);
		return (-1);
	}

	if (!spa_feature_is_active(spa, limit_feat)) {
		/*
		 * Since the feature was not active and we're now setting a
		 * limit, increment the feature-active counter so that the
		 * feature becomes active for the first time.
		 *
		 * We can't update the MOS in open context, so create a sync
		 * task.
		 */
		err = dsl_sync_task_do(dd->dd_pool, fs_ss_limit_feat_check,
		    fs_ss_limit_feat_sync, spa, (void *)1, 0);
		if (err != 0)
			return (err);
	}

	tx = dmu_tx_create_dd(dd);
	if (dmu_tx_assign(tx, TXG_WAIT)) {
		dmu_tx_abort(tx);
		dsl_dataset_rele(ds, FTAG);
		return (ENOSPC);
	}

	/*
	 * Since we are now setting a non-UINT64_MAX on the filesystem, we need
	 * to ensure the counts are correct. Descend down the tree from this
	 * point and update all of the counts to be accurate.
	 */
	err = -1;
	rw_enter(&dd->dd_pool->dp_config_rwlock, RW_READER);
	if (dsl_dir_set_fs_ss_count(dd, tx, &my_fs_cnt, &my_ss_cnt))
		err = ENOSPC;
	rw_exit(&dd->dd_pool->dp_config_rwlock);

	dmu_tx_commit(tx);
	dsl_dataset_rele(ds, FTAG);

	return (err);
}

/*
 * Used to determine if the filesystem_limit or snapshot_limit should be
 * enforced. We allow the limit to be exceeded if the user has permission to
 * write the property value. We pass in the creds that we got in the open
 * context since we will always be the GZ root in syncing context.
 *
 * We can never modify these two properties within a non-global zone. In
 * addition, the other checks are modeled on zfs_secpolicy_write_perms. We
 * can't use that function since we are already holding the dp_config_rwlock.
 * In addition, we already have the dd and dealing with snapshots is simplified.
 */
int
dsl_secpolicy_write_prop(dsl_dir_t *dd, zfs_prop_t prop, cred_t *cr)
{
	int err = 0;
	uint64_t obj;
	dsl_dataset_t *ds;
	uint64_t zoned;

#ifdef _KERNEL
	if (crgetzoneid(cr) != GLOBAL_ZONEID)
		return (EPERM);

	if (secpolicy_zfs(cr) == 0)
		return (0);
#endif

	if ((obj = dd->dd_phys->dd_head_dataset_obj) == NULL)
		return (ENOENT);

	ASSERT(RW_LOCK_HELD(&dd->dd_pool->dp_config_rwlock));

	if ((err = dsl_dataset_hold_obj(dd->dd_pool, obj, FTAG, &ds)) != 0)
		return (err);

	if (dsl_prop_get_ds(ds, "zoned", 8, 1, &zoned, NULL) || zoned) {
		/* Only root can access zoned fs's from the GZ */
		err = EPERM;
	} else {
		err = dsl_deleg_access_impl(ds, zfs_prop_to_name(prop), cr,
		    B_FALSE);
	}

	dsl_dataset_rele(ds, FTAG);
	return (err);
}

/*
 * Check if adding additional child filesystem(s) would exceed any filesystem
 * limits. Note that all filesystem limits up to the root (or the highest
 * initialized) filesystem or the given ancestor must be satisfied.
 */
int
dsl_dir_fscount_check(dsl_dir_t *dd, uint64_t cnt, dsl_dir_t *ancestor,
    cred_t *cr)
{
	uint64_t limit;
	int err = 0;

	VERIFY(RW_LOCK_HELD(&dd->dd_pool->dp_config_rwlock));

	/* If we're allowed to change the limit, don't enforce the limit. */
	if (dsl_secpolicy_write_prop(dd, ZFS_PROP_FILESYSTEM_LIMIT, cr) == 0)
		return (0);

	/*
	 * If an ancestor has been provided, stop checking the limit once we
	 * hit that dir. We need this during rename so that we don't overcount
	 * the check once we recurse up to the common ancestor.
	 */
	if (ancestor == dd)
		return (0);

	/*
	 * If we hit an uninitialized node while recursing up the tree, we can
	 * stop since we know the counts are not valid on this node and we
	 * know we won't touch this node's counts.
	 */
	if (dd->dd_phys->dd_filesystem_count == 0)
		return (0);

	err = dsl_prop_get_dd(dd, zfs_prop_to_name(ZFS_PROP_FILESYSTEM_LIMIT),
	    8, 1, &limit, NULL, B_FALSE);
	if (err != 0)
		return (err);

	/* Is there a fs limit which we've hit? */
	if ((dd->dd_phys->dd_filesystem_count + cnt) > limit)
		return (EDQUOT);

	if (dd->dd_parent != NULL)
		err = dsl_dir_fscount_check(dd->dd_parent, cnt, ancestor, cr);

	return (err);
}

/*
 * Adjust the filesystem count for the specified dsl_dir_t and all parent
 * filesystems. When a new filesystem is created, increment the count on all
 * parents, and when a filesystem is destroyed, decrement the count.
 */
void
dsl_dir_fscount_adjust(dsl_dir_t *dd, dmu_tx_t *tx, int64_t delta,
    boolean_t first)
{
	if (first) {
		VERIFY(RW_LOCK_HELD(&dd->dd_pool->dp_config_rwlock));
		VERIFY(dmu_tx_is_syncing(tx));
	}

	/*
	 * When we receive an incremental stream into a filesystem that already
	 * exists, a temporary clone is created.  We don't count this temporary
	 * clone, whose name begins with a '%'.
	 */
	if (dd->dd_myname[0] == '%')
		return;

	/*
	 * If we hit an uninitialized node while recursing up the tree, we can
	 * stop since we know the counts are not valid on this node and we
	 * know we shouldn't touch this node's counts. An uninitialized count
	 * on the node indicates that either the feature has not yet been
	 * activated or there are no limits on this part of the tree.
	 */
	if (dd->dd_phys->dd_filesystem_count == 0)
		return;

	/*
	 * On initial entry we need to check if this feature is active, but
	 * we don't want to re-check this on each recursive call. Note: the
	 * feature cannot be active if its not enabled. If the feature is not
	 * active, don't touch the on-disk count fields.
	 */
	if (first) {
		zfeature_info_t *quota_feat =
		    &spa_feature_table[SPA_FEATURE_FS_SS_LIMIT];

		if (!spa_feature_is_active(dd->dd_pool->dp_spa, quota_feat))
			return;
	}

	dmu_buf_will_dirty(dd->dd_dbuf, tx);

	mutex_enter(&dd->dd_lock);

	dd->dd_phys->dd_filesystem_count += delta;
	VERIFY(dd->dd_phys->dd_filesystem_count >= 1);	/* ourself is 1 */

	/* Roll up this additional count into our ancestors */
	if (dd->dd_parent != NULL)
		dsl_dir_fscount_adjust(dd->dd_parent, tx, delta, B_FALSE);

	mutex_exit(&dd->dd_lock);
}

uint64_t
dsl_dir_create_sync(dsl_pool_t *dp, dsl_dir_t *pds, const char *name,
    dmu_tx_t *tx)
{
	objset_t *mos = dp->dp_meta_objset;
	uint64_t ddobj;
	dsl_dir_phys_t *ddphys;
	dmu_buf_t *dbuf;
	zfeature_info_t *limit_feat =
	    &spa_feature_table[SPA_FEATURE_FS_SS_LIMIT];


	ddobj = dmu_object_alloc(mos, DMU_OT_DSL_DIR, 0,
	    DMU_OT_DSL_DIR, sizeof (dsl_dir_phys_t), tx);
	if (pds) {
		VERIFY(0 == zap_add(mos, pds->dd_phys->dd_child_dir_zapobj,
		    name, sizeof (uint64_t), 1, &ddobj, tx));
	} else {
		/* it's the root dir */
		VERIFY(0 == zap_add(mos, DMU_POOL_DIRECTORY_OBJECT,
		    DMU_POOL_ROOT_DATASET, sizeof (uint64_t), 1, &ddobj, tx));
	}
	VERIFY(0 == dmu_bonus_hold(mos, ddobj, FTAG, &dbuf));
	dmu_buf_will_dirty(dbuf, tx);
	ddphys = dbuf->db_data;

	ddphys->dd_creation_time = gethrestime_sec();
	/* Only initialize the count if the limit feature is active */
	if (spa_feature_is_active(dp->dp_spa, limit_feat))
		ddphys->dd_filesystem_count = 1;
	if (pds)
		ddphys->dd_parent_obj = pds->dd_object;
	ddphys->dd_props_zapobj = zap_create(mos,
	    DMU_OT_DSL_PROPS, DMU_OT_NONE, 0, tx);
	ddphys->dd_child_dir_zapobj = zap_create(mos,
	    DMU_OT_DSL_DIR_CHILD_MAP, DMU_OT_NONE, 0, tx);
	if (spa_version(dp->dp_spa) >= SPA_VERSION_USED_BREAKDOWN)
		ddphys->dd_flags |= DD_FLAG_USED_BREAKDOWN;
	dmu_buf_rele(dbuf, FTAG);

	return (ddobj);
}

/* ARGSUSED */
int
dsl_dir_destroy_check(void *arg1, void *arg2, dmu_tx_t *tx)
{
	dsl_dir_t *dd = arg1;
	dsl_pool_t *dp = dd->dd_pool;
	objset_t *mos = dp->dp_meta_objset;
	int err;
	uint64_t count;

	/*
	 * There should be exactly two holds, both from
	 * dsl_dataset_destroy: one on the dd directory, and one on its
	 * head ds.  If there are more holds, then a concurrent thread is
	 * performing a lookup inside this dir while we're trying to destroy
	 * it.  To minimize this possibility, we perform this check only
	 * in syncing context and fail the operation if we encounter
	 * additional holds.  The dp_config_rwlock ensures that nobody else
	 * opens it after we check.
	 */
	if (dmu_tx_is_syncing(tx) && dmu_buf_refcount(dd->dd_dbuf) > 2)
		return (EBUSY);

	err = zap_count(mos, dd->dd_phys->dd_child_dir_zapobj, &count);
	if (err)
		return (err);
	if (count != 0)
		return (EEXIST);

	return (0);
}

void
dsl_dir_destroy_sync(void *arg1, void *tag, dmu_tx_t *tx)
{
	dsl_dir_t *dd = arg1;
	objset_t *mos = dd->dd_pool->dp_meta_objset;
	uint64_t obj;
	dd_used_t t;

	ASSERT(RW_WRITE_HELD(&dd->dd_pool->dp_config_rwlock));
	ASSERT(dd->dd_phys->dd_head_dataset_obj == 0);

	/*
	 * Decrement the filesystem count for all parent filesystems.
	 *
	 * When we receive an incremental stream into a filesystem that already
	 * exists, a temporary clone is created.  We never count this temporary
	 * clone, whose name begins with a '%'.
	 */
	if (dd->dd_myname[0] != '%' && dd->dd_parent != NULL)
		dsl_dir_fscount_adjust(dd->dd_parent, tx, -1, B_TRUE);

	/*
	 * Remove our reservation. The impl() routine avoids setting the
	 * actual property, which would require the (already destroyed) ds.
	 */
	dsl_dir_set_reservation_sync_impl(dd, 0, tx);

	ASSERT0(dd->dd_phys->dd_used_bytes);
	ASSERT0(dd->dd_phys->dd_reserved);
	for (t = 0; t < DD_USED_NUM; t++)
		ASSERT0(dd->dd_phys->dd_used_breakdown[t]);

	VERIFY(0 == zap_destroy(mos, dd->dd_phys->dd_child_dir_zapobj, tx));
	VERIFY(0 == zap_destroy(mos, dd->dd_phys->dd_props_zapobj, tx));
	VERIFY(0 == dsl_deleg_destroy(mos, dd->dd_phys->dd_deleg_zapobj, tx));
	VERIFY(0 == zap_remove(mos,
	    dd->dd_parent->dd_phys->dd_child_dir_zapobj, dd->dd_myname, tx));

	obj = dd->dd_object;
	dsl_dir_close(dd, tag);
	VERIFY(0 == dmu_object_free(mos, obj, tx));
}

boolean_t
dsl_dir_is_clone(dsl_dir_t *dd)
{
	return (dd->dd_phys->dd_origin_obj &&
	    (dd->dd_pool->dp_origin_snap == NULL ||
	    dd->dd_phys->dd_origin_obj !=
	    dd->dd_pool->dp_origin_snap->ds_object));
}

void
dsl_dir_stats(dsl_dir_t *dd, nvlist_t *nv)
{
	mutex_enter(&dd->dd_lock);
	dsl_prop_nvlist_add_uint64(nv, ZFS_PROP_USED,
	    dd->dd_phys->dd_used_bytes);
	dsl_prop_nvlist_add_uint64(nv, ZFS_PROP_QUOTA, dd->dd_phys->dd_quota);
	dsl_prop_nvlist_add_uint64(nv, ZFS_PROP_RESERVATION,
	    dd->dd_phys->dd_reserved);
	dsl_prop_nvlist_add_uint64(nv, ZFS_PROP_COMPRESSRATIO,
	    dd->dd_phys->dd_compressed_bytes == 0 ? 100 :
	    (dd->dd_phys->dd_uncompressed_bytes * 100 /
	    dd->dd_phys->dd_compressed_bytes));
	if (dd->dd_phys->dd_flags & DD_FLAG_USED_BREAKDOWN) {
		dsl_prop_nvlist_add_uint64(nv, ZFS_PROP_USEDSNAP,
		    dd->dd_phys->dd_used_breakdown[DD_USED_SNAP]);
		dsl_prop_nvlist_add_uint64(nv, ZFS_PROP_USEDDS,
		    dd->dd_phys->dd_used_breakdown[DD_USED_HEAD]);
		dsl_prop_nvlist_add_uint64(nv, ZFS_PROP_USEDREFRESERV,
		    dd->dd_phys->dd_used_breakdown[DD_USED_REFRSRV]);
		dsl_prop_nvlist_add_uint64(nv, ZFS_PROP_USEDCHILD,
		    dd->dd_phys->dd_used_breakdown[DD_USED_CHILD] +
		    dd->dd_phys->dd_used_breakdown[DD_USED_CHILD_RSRV]);
	}
	mutex_exit(&dd->dd_lock);

	rw_enter(&dd->dd_pool->dp_config_rwlock, RW_READER);
	if (dsl_dir_is_clone(dd)) {
		dsl_dataset_t *ds;
		char buf[MAXNAMELEN];

		VERIFY(0 == dsl_dataset_hold_obj(dd->dd_pool,
		    dd->dd_phys->dd_origin_obj, FTAG, &ds));
		dsl_dataset_name(ds, buf);
		dsl_dataset_rele(ds, FTAG);
		dsl_prop_nvlist_add_string(nv, ZFS_PROP_ORIGIN, buf);
	}
	rw_exit(&dd->dd_pool->dp_config_rwlock);
}

void
dsl_dir_dirty(dsl_dir_t *dd, dmu_tx_t *tx)
{
	dsl_pool_t *dp = dd->dd_pool;

	ASSERT(dd->dd_phys);

	if (txg_list_add(&dp->dp_dirty_dirs, dd, tx->tx_txg) == 0) {
		/* up the hold count until we can be written out */
		dmu_buf_add_ref(dd->dd_dbuf, dd);
	}
}

static int64_t
parent_delta(dsl_dir_t *dd, uint64_t used, int64_t delta)
{
	uint64_t old_accounted = MAX(used, dd->dd_phys->dd_reserved);
	uint64_t new_accounted = MAX(used + delta, dd->dd_phys->dd_reserved);
	return (new_accounted - old_accounted);
}

void
dsl_dir_sync(dsl_dir_t *dd, dmu_tx_t *tx)
{
	ASSERT(dmu_tx_is_syncing(tx));

	mutex_enter(&dd->dd_lock);
	ASSERT0(dd->dd_tempreserved[tx->tx_txg&TXG_MASK]);
	dprintf_dd(dd, "txg=%llu towrite=%lluK\n", tx->tx_txg,
	    dd->dd_space_towrite[tx->tx_txg&TXG_MASK] / 1024);
	dd->dd_space_towrite[tx->tx_txg&TXG_MASK] = 0;
	mutex_exit(&dd->dd_lock);

	/* release the hold from dsl_dir_dirty */
	dmu_buf_rele(dd->dd_dbuf, dd);
}

static uint64_t
dsl_dir_space_towrite(dsl_dir_t *dd)
{
	uint64_t space = 0;
	int i;

	ASSERT(MUTEX_HELD(&dd->dd_lock));

	for (i = 0; i < TXG_SIZE; i++) {
		space += dd->dd_space_towrite[i&TXG_MASK];
		ASSERT3U(dd->dd_space_towrite[i&TXG_MASK], >=, 0);
	}
	return (space);
}

/*
 * How much space would dd have available if ancestor had delta applied
 * to it?  If ondiskonly is set, we're only interested in what's
 * on-disk, not estimated pending changes.
 */
uint64_t
dsl_dir_space_available(dsl_dir_t *dd,
    dsl_dir_t *ancestor, int64_t delta, int ondiskonly)
{
	uint64_t parentspace, myspace, quota, used;

	/*
	 * If there are no restrictions otherwise, assume we have
	 * unlimited space available.
	 */
	quota = UINT64_MAX;
	parentspace = UINT64_MAX;

	if (dd->dd_parent != NULL) {
		parentspace = dsl_dir_space_available(dd->dd_parent,
		    ancestor, delta, ondiskonly);
	}

	mutex_enter(&dd->dd_lock);
	if (dd->dd_phys->dd_quota != 0)
		quota = dd->dd_phys->dd_quota;
	used = dd->dd_phys->dd_used_bytes;
	if (!ondiskonly)
		used += dsl_dir_space_towrite(dd);

	if (dd->dd_parent == NULL) {
		uint64_t poolsize = dsl_pool_adjustedsize(dd->dd_pool, FALSE);
		quota = MIN(quota, poolsize);
	}

	if (dd->dd_phys->dd_reserved > used && parentspace != UINT64_MAX) {
		/*
		 * We have some space reserved, in addition to what our
		 * parent gave us.
		 */
		parentspace += dd->dd_phys->dd_reserved - used;
	}

	if (dd == ancestor) {
		ASSERT(delta <= 0);
		ASSERT(used >= -delta);
		used += delta;
		if (parentspace != UINT64_MAX)
			parentspace -= delta;
	}

	if (used > quota) {
		/* over quota */
		myspace = 0;
	} else {
		/*
		 * the lesser of the space provided by our parent and
		 * the space left in our quota
		 */
		myspace = MIN(parentspace, quota - used);
	}

	mutex_exit(&dd->dd_lock);

	return (myspace);
}

struct tempreserve {
	list_node_t tr_node;
	dsl_pool_t *tr_dp;
	dsl_dir_t *tr_ds;
	uint64_t tr_size;
};

static int
dsl_dir_tempreserve_impl(dsl_dir_t *dd, uint64_t asize, boolean_t netfree,
    boolean_t ignorequota, boolean_t checkrefquota, list_t *tr_list,
    dmu_tx_t *tx, boolean_t first)
{
	uint64_t txg = tx->tx_txg;
	uint64_t est_inflight, used_on_disk, quota, parent_rsrv;
	uint64_t deferred = 0;
	struct tempreserve *tr;
	int retval = EDQUOT;
	int txgidx = txg & TXG_MASK;
	int i;
	uint64_t ref_rsrv = 0;

	ASSERT3U(txg, !=, 0);
	ASSERT3S(asize, >, 0);

	mutex_enter(&dd->dd_lock);

	/*
	 * Check against the dsl_dir's quota.  We don't add in the delta
	 * when checking for over-quota because they get one free hit.
	 */
	est_inflight = dsl_dir_space_towrite(dd);
	for (i = 0; i < TXG_SIZE; i++)
		est_inflight += dd->dd_tempreserved[i];
	used_on_disk = dd->dd_phys->dd_used_bytes;

	/*
	 * On the first iteration, fetch the dataset's used-on-disk and
	 * refreservation values. Also, if checkrefquota is set, test if
	 * allocating this space would exceed the dataset's refquota.
	 */
	if (first && tx->tx_objset) {
		int error;
		dsl_dataset_t *ds = tx->tx_objset->os_dsl_dataset;

		error = dsl_dataset_check_quota(ds, checkrefquota,
		    asize, est_inflight, &used_on_disk, &ref_rsrv);
		if (error) {
			mutex_exit(&dd->dd_lock);
			return (error);
		}
	}

	/*
	 * If this transaction will result in a net free of space,
	 * we want to let it through.
	 */
	if (ignorequota || netfree || dd->dd_phys->dd_quota == 0)
		quota = UINT64_MAX;
	else
		quota = dd->dd_phys->dd_quota;

	/*
	 * Adjust the quota against the actual pool size at the root
	 * minus any outstanding deferred frees.
	 * To ensure that it's possible to remove files from a full
	 * pool without inducing transient overcommits, we throttle
	 * netfree transactions against a quota that is slightly larger,
	 * but still within the pool's allocation slop.  In cases where
	 * we're very close to full, this will allow a steady trickle of
	 * removes to get through.
	 */
	if (dd->dd_parent == NULL) {
		spa_t *spa = dd->dd_pool->dp_spa;
		uint64_t poolsize = dsl_pool_adjustedsize(dd->dd_pool, netfree);
		deferred = metaslab_class_get_deferred(spa_normal_class(spa));
		if (poolsize - deferred < quota) {
			quota = poolsize - deferred;
			retval = ENOSPC;
		}
	}

	/*
	 * If they are requesting more space, and our current estimate
	 * is over quota, they get to try again unless the actual
	 * on-disk is over quota and there are no pending changes (which
	 * may free up space for us).
	 */
	if (used_on_disk + est_inflight >= quota) {
		if (est_inflight > 0 || used_on_disk < quota ||
		    (retval == ENOSPC && used_on_disk < quota + deferred))
			retval = ERESTART;
		dprintf_dd(dd, "failing: used=%lluK inflight = %lluK "
		    "quota=%lluK tr=%lluK err=%d\n",
		    used_on_disk>>10, est_inflight>>10,
		    quota>>10, asize>>10, retval);
		mutex_exit(&dd->dd_lock);
		return (retval);
	}

	/* We need to up our estimated delta before dropping dd_lock */
	dd->dd_tempreserved[txgidx] += asize;

	parent_rsrv = parent_delta(dd, used_on_disk + est_inflight,
	    asize - ref_rsrv);
	mutex_exit(&dd->dd_lock);

	tr = kmem_zalloc(sizeof (struct tempreserve), KM_SLEEP);
	tr->tr_ds = dd;
	tr->tr_size = asize;
	list_insert_tail(tr_list, tr);

	/* see if it's OK with our parent */
	if (dd->dd_parent && parent_rsrv) {
		boolean_t ismos = (dd->dd_phys->dd_head_dataset_obj == 0);

		return (dsl_dir_tempreserve_impl(dd->dd_parent,
		    parent_rsrv, netfree, ismos, TRUE, tr_list, tx, FALSE));
	} else {
		return (0);
	}
}

/*
 * Reserve space in this dsl_dir, to be used in this tx's txg.
 * After the space has been dirtied (and dsl_dir_willuse_space()
 * has been called), the reservation should be canceled, using
 * dsl_dir_tempreserve_clear().
 */
int
dsl_dir_tempreserve_space(dsl_dir_t *dd, uint64_t lsize, uint64_t asize,
    uint64_t fsize, uint64_t usize, void **tr_cookiep, dmu_tx_t *tx)
{
	int err;
	list_t *tr_list;

	if (asize == 0) {
		*tr_cookiep = NULL;
		return (0);
	}

	tr_list = kmem_alloc(sizeof (list_t), KM_SLEEP);
	list_create(tr_list, sizeof (struct tempreserve),
	    offsetof(struct tempreserve, tr_node));
	ASSERT3S(asize, >, 0);
	ASSERT3S(fsize, >=, 0);

	err = arc_tempreserve_space(lsize, tx->tx_txg);
	if (err == 0) {
		struct tempreserve *tr;

		tr = kmem_zalloc(sizeof (struct tempreserve), KM_SLEEP);
		tr->tr_size = lsize;
		list_insert_tail(tr_list, tr);

		err = dsl_pool_tempreserve_space(dd->dd_pool, asize, tx);
	} else {
		if (err == EAGAIN) {
			txg_delay(dd->dd_pool, tx->tx_txg,
			    zfs_zone_txg_delay());
			err = ERESTART;
		}
		dsl_pool_memory_pressure(dd->dd_pool);
	}

	if (err == 0) {
		struct tempreserve *tr;

		tr = kmem_zalloc(sizeof (struct tempreserve), KM_SLEEP);
		tr->tr_dp = dd->dd_pool;
		tr->tr_size = asize;
		list_insert_tail(tr_list, tr);

		err = dsl_dir_tempreserve_impl(dd, asize, fsize >= asize,
		    FALSE, asize > usize, tr_list, tx, TRUE);
	}

	if (err)
		dsl_dir_tempreserve_clear(tr_list, tx);
	else
		*tr_cookiep = tr_list;

	return (err);
}

/*
 * Clear a temporary reservation that we previously made with
 * dsl_dir_tempreserve_space().
 */
void
dsl_dir_tempreserve_clear(void *tr_cookie, dmu_tx_t *tx)
{
	int txgidx = tx->tx_txg & TXG_MASK;
	list_t *tr_list = tr_cookie;
	struct tempreserve *tr;

	ASSERT3U(tx->tx_txg, !=, 0);

	if (tr_cookie == NULL)
		return;

	while (tr = list_head(tr_list)) {
		if (tr->tr_dp) {
			dsl_pool_tempreserve_clear(tr->tr_dp, tr->tr_size, tx);
		} else if (tr->tr_ds) {
			mutex_enter(&tr->tr_ds->dd_lock);
			ASSERT3U(tr->tr_ds->dd_tempreserved[txgidx], >=,
			    tr->tr_size);
			tr->tr_ds->dd_tempreserved[txgidx] -= tr->tr_size;
			mutex_exit(&tr->tr_ds->dd_lock);
		} else {
			arc_tempreserve_clear(tr->tr_size);
		}
		list_remove(tr_list, tr);
		kmem_free(tr, sizeof (struct tempreserve));
	}

	kmem_free(tr_list, sizeof (list_t));
}

static void
dsl_dir_willuse_space_impl(dsl_dir_t *dd, int64_t space, dmu_tx_t *tx)
{
	int64_t parent_space;
	uint64_t est_used;

	mutex_enter(&dd->dd_lock);
	if (space > 0)
		dd->dd_space_towrite[tx->tx_txg & TXG_MASK] += space;

	est_used = dsl_dir_space_towrite(dd) + dd->dd_phys->dd_used_bytes;
	parent_space = parent_delta(dd, est_used, space);
	mutex_exit(&dd->dd_lock);

	/* Make sure that we clean up dd_space_to* */
	dsl_dir_dirty(dd, tx);

	/* XXX this is potentially expensive and unnecessary... */
	if (parent_space && dd->dd_parent)
		dsl_dir_willuse_space_impl(dd->dd_parent, parent_space, tx);
}

/*
 * Call in open context when we think we're going to write/free space,
 * eg. when dirtying data.  Be conservative (ie. OK to write less than
 * this or free more than this, but don't write more or free less).
 */
void
dsl_dir_willuse_space(dsl_dir_t *dd, int64_t space, dmu_tx_t *tx)
{
	dsl_pool_willuse_space(dd->dd_pool, space, tx);
	dsl_dir_willuse_space_impl(dd, space, tx);
}

/* call from syncing context when we actually write/free space for this dd */
void
dsl_dir_diduse_space(dsl_dir_t *dd, dd_used_t type,
    int64_t used, int64_t compressed, int64_t uncompressed, dmu_tx_t *tx)
{
	int64_t accounted_delta;
	boolean_t needlock = !MUTEX_HELD(&dd->dd_lock);

	ASSERT(dmu_tx_is_syncing(tx));
	ASSERT(type < DD_USED_NUM);

	if (needlock)
		mutex_enter(&dd->dd_lock);
	accounted_delta = parent_delta(dd, dd->dd_phys->dd_used_bytes, used);
	ASSERT(used >= 0 || dd->dd_phys->dd_used_bytes >= -used);
	ASSERT(compressed >= 0 ||
	    dd->dd_phys->dd_compressed_bytes >= -compressed);
	ASSERT(uncompressed >= 0 ||
	    dd->dd_phys->dd_uncompressed_bytes >= -uncompressed);
	dmu_buf_will_dirty(dd->dd_dbuf, tx);
	dd->dd_phys->dd_used_bytes += used;
	dd->dd_phys->dd_uncompressed_bytes += uncompressed;
	dd->dd_phys->dd_compressed_bytes += compressed;

	if (dd->dd_phys->dd_flags & DD_FLAG_USED_BREAKDOWN) {
		ASSERT(used > 0 ||
		    dd->dd_phys->dd_used_breakdown[type] >= -used);
		dd->dd_phys->dd_used_breakdown[type] += used;
#ifdef DEBUG
		dd_used_t t;
		uint64_t u = 0;
		for (t = 0; t < DD_USED_NUM; t++)
			u += dd->dd_phys->dd_used_breakdown[t];
		ASSERT3U(u, ==, dd->dd_phys->dd_used_bytes);
#endif
	}
	if (needlock)
		mutex_exit(&dd->dd_lock);

	if (dd->dd_parent != NULL) {
		dsl_dir_diduse_space(dd->dd_parent, DD_USED_CHILD,
		    accounted_delta, compressed, uncompressed, tx);
		dsl_dir_transfer_space(dd->dd_parent,
		    used - accounted_delta,
		    DD_USED_CHILD_RSRV, DD_USED_CHILD, tx);
	}
}

void
dsl_dir_transfer_space(dsl_dir_t *dd, int64_t delta,
    dd_used_t oldtype, dd_used_t newtype, dmu_tx_t *tx)
{
	boolean_t needlock = !MUTEX_HELD(&dd->dd_lock);

	ASSERT(dmu_tx_is_syncing(tx));
	ASSERT(oldtype < DD_USED_NUM);
	ASSERT(newtype < DD_USED_NUM);

	if (delta == 0 || !(dd->dd_phys->dd_flags & DD_FLAG_USED_BREAKDOWN))
		return;

	if (needlock)
		mutex_enter(&dd->dd_lock);
	ASSERT(delta > 0 ?
	    dd->dd_phys->dd_used_breakdown[oldtype] >= delta :
	    dd->dd_phys->dd_used_breakdown[newtype] >= -delta);
	ASSERT(dd->dd_phys->dd_used_bytes >= ABS(delta));
	dmu_buf_will_dirty(dd->dd_dbuf, tx);
	dd->dd_phys->dd_used_breakdown[oldtype] -= delta;
	dd->dd_phys->dd_used_breakdown[newtype] += delta;
	if (needlock)
		mutex_exit(&dd->dd_lock);
}

static int
dsl_dir_set_quota_check(void *arg1, void *arg2, dmu_tx_t *tx)
{
	dsl_dataset_t *ds = arg1;
	dsl_dir_t *dd = ds->ds_dir;
	dsl_prop_setarg_t *psa = arg2;
	int err;
	uint64_t towrite;

	if ((err = dsl_prop_predict_sync(ds->ds_dir, psa)) != 0)
		return (err);

	if (psa->psa_effective_value == 0)
		return (0);

	mutex_enter(&dd->dd_lock);
	/*
	 * If we are doing the preliminary check in open context, and
	 * there are pending changes, then don't fail it, since the
	 * pending changes could under-estimate the amount of space to be
	 * freed up.
	 */
	towrite = dsl_dir_space_towrite(dd);
	if ((dmu_tx_is_syncing(tx) || towrite == 0) &&
	    (psa->psa_effective_value < dd->dd_phys->dd_reserved ||
	    psa->psa_effective_value < dd->dd_phys->dd_used_bytes + towrite)) {
		err = ENOSPC;
	}
	mutex_exit(&dd->dd_lock);
	return (err);
}

static void
dsl_dir_set_quota_sync(void *arg1, void *arg2, dmu_tx_t *tx)
{
	dsl_dataset_t *ds = arg1;
	dsl_dir_t *dd = ds->ds_dir;
	dsl_prop_setarg_t *psa = arg2;
	uint64_t effective_value = psa->psa_effective_value;

	dsl_prop_set_sync(ds, psa, tx);
	DSL_PROP_CHECK_PREDICTION(dd, psa);

	dmu_buf_will_dirty(dd->dd_dbuf, tx);

	mutex_enter(&dd->dd_lock);
	dd->dd_phys->dd_quota = effective_value;
	mutex_exit(&dd->dd_lock);
}

int
dsl_dir_set_quota(const char *ddname, zprop_source_t source, uint64_t quota)
{
	dsl_dir_t *dd;
	dsl_dataset_t *ds;
	dsl_prop_setarg_t psa;
	int err;

	dsl_prop_setarg_init_uint64(&psa, "quota", source, &quota);

	err = dsl_dataset_hold(ddname, FTAG, &ds);
	if (err)
		return (err);

	err = dsl_dir_open(ddname, FTAG, &dd, NULL);
	if (err) {
		dsl_dataset_rele(ds, FTAG);
		return (err);
	}

	ASSERT(ds->ds_dir == dd);

	/*
	 * If someone removes a file, then tries to set the quota, we want to
	 * make sure the file freeing takes effect.
	 */
	txg_wait_open(dd->dd_pool, 0);

	err = dsl_sync_task_do(dd->dd_pool, dsl_dir_set_quota_check,
	    dsl_dir_set_quota_sync, ds, &psa, 0);

	dsl_dir_close(dd, FTAG);
	dsl_dataset_rele(ds, FTAG);
	return (err);
}

int
dsl_dir_set_reservation_check(void *arg1, void *arg2, dmu_tx_t *tx)
{
	dsl_dataset_t *ds = arg1;
	dsl_dir_t *dd = ds->ds_dir;
	dsl_prop_setarg_t *psa = arg2;
	uint64_t effective_value;
	uint64_t used, avail;
	int err;

	if ((err = dsl_prop_predict_sync(ds->ds_dir, psa)) != 0)
		return (err);

	effective_value = psa->psa_effective_value;

	/*
	 * If we are doing the preliminary check in open context, the
	 * space estimates may be inaccurate.
	 */
	if (!dmu_tx_is_syncing(tx))
		return (0);

	mutex_enter(&dd->dd_lock);
	used = dd->dd_phys->dd_used_bytes;
	mutex_exit(&dd->dd_lock);

	if (dd->dd_parent) {
		avail = dsl_dir_space_available(dd->dd_parent,
		    NULL, 0, FALSE);
	} else {
		avail = dsl_pool_adjustedsize(dd->dd_pool, B_FALSE) - used;
	}

	if (MAX(used, effective_value) > MAX(used, dd->dd_phys->dd_reserved)) {
		uint64_t delta = MAX(used, effective_value) -
		    MAX(used, dd->dd_phys->dd_reserved);

		if (delta > avail)
			return (ENOSPC);
		if (dd->dd_phys->dd_quota > 0 &&
		    effective_value > dd->dd_phys->dd_quota)
			return (ENOSPC);
	}

	return (0);
}

static void
dsl_dir_set_reservation_sync_impl(dsl_dir_t *dd, uint64_t value, dmu_tx_t *tx)
{
	uint64_t used;
	int64_t delta;

	dmu_buf_will_dirty(dd->dd_dbuf, tx);

	mutex_enter(&dd->dd_lock);
	used = dd->dd_phys->dd_used_bytes;
	delta = MAX(used, value) - MAX(used, dd->dd_phys->dd_reserved);
	dd->dd_phys->dd_reserved = value;

	if (dd->dd_parent != NULL) {
		/* Roll up this additional usage into our ancestors */
		dsl_dir_diduse_space(dd->dd_parent, DD_USED_CHILD_RSRV,
		    delta, 0, 0, tx);
	}
	mutex_exit(&dd->dd_lock);
}


static void
dsl_dir_set_reservation_sync(void *arg1, void *arg2, dmu_tx_t *tx)
{
	dsl_dataset_t *ds = arg1;
	dsl_dir_t *dd = ds->ds_dir;
	dsl_prop_setarg_t *psa = arg2;
	uint64_t value = psa->psa_effective_value;

	dsl_prop_set_sync(ds, psa, tx);
	DSL_PROP_CHECK_PREDICTION(dd, psa);

	dsl_dir_set_reservation_sync_impl(dd, value, tx);
}

int
dsl_dir_set_reservation(const char *ddname, zprop_source_t source,
    uint64_t reservation)
{
	dsl_dir_t *dd;
	dsl_dataset_t *ds;
	dsl_prop_setarg_t psa;
	int err;

	dsl_prop_setarg_init_uint64(&psa, "reservation", source, &reservation);

	err = dsl_dataset_hold(ddname, FTAG, &ds);
	if (err)
		return (err);

	err = dsl_dir_open(ddname, FTAG, &dd, NULL);
	if (err) {
		dsl_dataset_rele(ds, FTAG);
		return (err);
	}

	ASSERT(ds->ds_dir == dd);

	err = dsl_sync_task_do(dd->dd_pool, dsl_dir_set_reservation_check,
	    dsl_dir_set_reservation_sync, ds, &psa, 0);

	dsl_dir_close(dd, FTAG);
	dsl_dataset_rele(ds, FTAG);
	return (err);
}

static dsl_dir_t *
closest_common_ancestor(dsl_dir_t *ds1, dsl_dir_t *ds2)
{
	for (; ds1; ds1 = ds1->dd_parent) {
		dsl_dir_t *dd;
		for (dd = ds2; dd; dd = dd->dd_parent) {
			if (ds1 == dd)
				return (dd);
		}
	}
	return (NULL);
}

/*
 * If delta is applied to dd, how much of that delta would be applied to
 * ancestor?  Syncing context only.
 */
static int64_t
would_change(dsl_dir_t *dd, int64_t delta, dsl_dir_t *ancestor)
{
	if (dd == ancestor)
		return (delta);

	mutex_enter(&dd->dd_lock);
	delta = parent_delta(dd, dd->dd_phys->dd_used_bytes, delta);
	mutex_exit(&dd->dd_lock);
	return (would_change(dd->dd_parent, delta, ancestor));
}

struct renamearg {
	dsl_dir_t *newparent;
	const char *mynewname;
	cred_t *cr;
};

static int
dsl_dir_rename_check(void *arg1, void *arg2, dmu_tx_t *tx)
{
	dsl_dir_t *dd = arg1;
	struct renamearg *ra = arg2;
	dsl_pool_t *dp = dd->dd_pool;
	objset_t *mos = dp->dp_meta_objset;
	int err;
	uint64_t val;

	/*
	 * There should only be one reference, from dmu_objset_rename().
	 * Fleeting holds are also possible (eg, from "zfs list" getting
	 * stats), but any that are present in open context will likely
	 * be gone by syncing context, so only fail from syncing
	 * context.
	 */
	if (dmu_tx_is_syncing(tx) && dmu_buf_refcount(dd->dd_dbuf) > 1)
		return (EBUSY);

	/* check for existing name */
	err = zap_lookup(mos, ra->newparent->dd_phys->dd_child_dir_zapobj,
	    ra->mynewname, 8, 1, &val);
	if (err == 0)
		return (EEXIST);
	if (err != ENOENT)
		return (err);

	if (ra->newparent != dd->dd_parent) {
		/* is there enough space? */
		uint64_t myspace =
		    MAX(dd->dd_phys->dd_used_bytes, dd->dd_phys->dd_reserved);

		/* no rename into our descendant */
		if (closest_common_ancestor(dd, ra->newparent) == dd)
			return (EINVAL);

		if (err = dsl_dir_transfer_possible(dd->dd_parent,
		    ra->newparent, dd, myspace, ra->cr))
			return (err);

		if (dd->dd_phys->dd_filesystem_count == 0 &&
		    dmu_tx_is_syncing(tx)) {
			uint64_t fs_cnt = 0;
			uint64_t ss_cnt = 0;

			/*
			 * Ensure this portion of the tree's counts have been
			 * initialized in case the new parent has limits set.
			 */
			err = dsl_dir_set_fs_ss_count(dd, tx, &fs_cnt, &ss_cnt);
			if (err)
				return (EIO);
		}
	}

	return (0);
}

static void
dsl_dir_rename_sync(void *arg1, void *arg2, dmu_tx_t *tx)
{
	dsl_dir_t *dd = arg1;
	struct renamearg *ra = arg2;
	dsl_pool_t *dp = dd->dd_pool;
	objset_t *mos = dp->dp_meta_objset;
	int err;
	char namebuf[MAXNAMELEN];

	ASSERT(dmu_buf_refcount(dd->dd_dbuf) <= 2);

	/* Log this before we change the name. */
	dsl_dir_name(ra->newparent, namebuf);
	spa_history_log_internal_dd(dd, "rename", tx,
	    "-> %s/%s", namebuf, ra->mynewname);

	if (ra->newparent != dd->dd_parent) {
		int cnt;

		mutex_enter(&dd->dd_lock);

		cnt = dd->dd_phys->dd_filesystem_count;
		dsl_dir_fscount_adjust(dd->dd_parent, tx, -cnt, B_TRUE);
		dsl_dir_fscount_adjust(ra->newparent, tx, cnt, B_TRUE);

		cnt = dd->dd_phys->dd_snapshot_count;
		dsl_snapcount_adjust(dd->dd_parent, tx, -cnt, B_TRUE);
		dsl_snapcount_adjust(ra->newparent, tx, cnt, B_TRUE);

		mutex_exit(&dd->dd_lock);

		dsl_dir_diduse_space(dd->dd_parent, DD_USED_CHILD,
		    -dd->dd_phys->dd_used_bytes,
		    -dd->dd_phys->dd_compressed_bytes,
		    -dd->dd_phys->dd_uncompressed_bytes, tx);
		dsl_dir_diduse_space(ra->newparent, DD_USED_CHILD,
		    dd->dd_phys->dd_used_bytes,
		    dd->dd_phys->dd_compressed_bytes,
		    dd->dd_phys->dd_uncompressed_bytes, tx);

		if (dd->dd_phys->dd_reserved > dd->dd_phys->dd_used_bytes) {
			uint64_t unused_rsrv = dd->dd_phys->dd_reserved -
			    dd->dd_phys->dd_used_bytes;

			dsl_dir_diduse_space(dd->dd_parent, DD_USED_CHILD_RSRV,
			    -unused_rsrv, 0, 0, tx);
			dsl_dir_diduse_space(ra->newparent, DD_USED_CHILD_RSRV,
			    unused_rsrv, 0, 0, tx);
		}
	}

	dmu_buf_will_dirty(dd->dd_dbuf, tx);

	/* remove from old parent zapobj */
	err = zap_remove(mos, dd->dd_parent->dd_phys->dd_child_dir_zapobj,
	    dd->dd_myname, tx);
	ASSERT0(err);

	(void) strcpy(dd->dd_myname, ra->mynewname);
	dsl_dir_close(dd->dd_parent, dd);
	dd->dd_phys->dd_parent_obj = ra->newparent->dd_object;
	VERIFY(0 == dsl_dir_open_obj(dd->dd_pool,
	    ra->newparent->dd_object, NULL, dd, &dd->dd_parent));

	/* add to new parent zapobj */
	err = zap_add(mos, ra->newparent->dd_phys->dd_child_dir_zapobj,
	    dd->dd_myname, 8, 1, &dd->dd_object, tx);
	ASSERT0(err);

}

int
dsl_dir_rename(dsl_dir_t *dd, const char *newname)
{
	struct renamearg ra;
	int err;

	/* new parent should exist */
	err = dsl_dir_open(newname, FTAG, &ra.newparent, &ra.mynewname);
	if (err)
		return (err);

	/* can't rename to different pool */
	if (dd->dd_pool != ra.newparent->dd_pool) {
		err = ENXIO;
		goto out;
	}

	/* new name should not already exist */
	if (ra.mynewname == NULL) {
		err = EEXIST;
		goto out;
	}

	ra.cr = CRED();

	err = dsl_sync_task_do(dd->dd_pool,
	    dsl_dir_rename_check, dsl_dir_rename_sync, dd, &ra, 3);

out:
	dsl_dir_close(ra.newparent, FTAG);
	return (err);
}

int
dsl_dir_transfer_possible(dsl_dir_t *sdd, dsl_dir_t *tdd, dsl_dir_t *moving_dd,
    uint64_t space, cred_t *cr)
{
	dsl_dir_t *ancestor;
	int64_t adelta;
	uint64_t avail;
	int err;

	ancestor = closest_common_ancestor(sdd, tdd);
	adelta = would_change(sdd, -space, ancestor);
	avail = dsl_dir_space_available(tdd, ancestor, adelta, FALSE);
	if (avail < space)
		return (ENOSPC);

	if (sdd != moving_dd) {
		err = dsl_dir_fscount_check(tdd,
		    moving_dd->dd_phys->dd_filesystem_count, ancestor, cr);
		if (err != 0)
			return (err);
	}
	err = dsl_snapcount_check(tdd, moving_dd->dd_phys->dd_snapshot_count,
	    ancestor, cr);
	if (err != 0)
		return (err);

	return (0);
}

timestruc_t
dsl_dir_snap_cmtime(dsl_dir_t *dd)
{
	timestruc_t t;

	mutex_enter(&dd->dd_lock);
	t = dd->dd_snap_cmtime;
	mutex_exit(&dd->dd_lock);

	return (t);
}

void
dsl_dir_snap_cmtime_update(dsl_dir_t *dd)
{
	timestruc_t t;

	gethrestime(&t);
	mutex_enter(&dd->dd_lock);
	dd->dd_snap_cmtime = t;
	mutex_exit(&dd->dd_lock);
}
