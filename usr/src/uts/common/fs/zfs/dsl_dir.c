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

#include <sys/dmu.h>
#include <sys/dmu_tx.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_dir.h>
#include <sys/dsl_prop.h>
#include <sys/spa.h>
#include <sys/zap.h>
#include <sys/zio.h>
#include <sys/arc.h>
#include "zfs_namecheck.h"

static uint64_t dsl_dir_space_accounted(dsl_dir_t *dd);
static uint64_t dsl_dir_estimated_space(dsl_dir_t *dd);
static int dsl_dir_set_reservation_sync(dsl_dir_t *dd,
    void *arg, dmu_tx_t *tx);
static uint64_t dsl_dir_space_available(dsl_dir_t *dd,
    dsl_dir_t *ancestor, int64_t delta, int ondiskonly);


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

	ASSERT3U(dd->dd_used_bytes, ==, dd->dd_phys->dd_used_bytes);

	ASSERT(dd->dd_sync_txg == 0);

	if (dd->dd_parent)
		dsl_dir_close(dd->dd_parent, dd);

	spa_close(dd->dd_pool->dp_spa, dd);

	/*
	 * The props callback list should be empty since they hold the
	 * dir open.
	 */
	list_destroy(&dd->dd_prop_cbs);
	kmem_free(dd, sizeof (dsl_dir_t));
}

dsl_dir_t *
dsl_dir_open_obj(dsl_pool_t *dp, uint64_t ddobj,
    const char *tail, void *tag)
{
	dmu_buf_t *dbuf;
	dsl_dir_t *dd;

	ASSERT(RW_LOCK_HELD(&dp->dp_config_rwlock) ||
	    dsl_pool_sync_context(dp));

	dbuf = dmu_bonus_hold_tag(dp->dp_meta_objset, ddobj, tag);
	dmu_buf_read(dbuf);
	dd = dmu_buf_get_user(dbuf);
#ifdef ZFS_DEBUG
	{
		dmu_object_info_t doi;
		dmu_object_info_from_db(dbuf, &doi);
		ASSERT3U(doi.doi_type, ==, DMU_OT_DSL_DATASET);
	}
#endif
	/* XXX assert bonus buffer size is correct */
	if (dd == NULL) {
		dsl_dir_t *winner;
		int err;

		dd = kmem_zalloc(sizeof (dsl_dir_t), KM_SLEEP);
		dd->dd_object = ddobj;
		dd->dd_dbuf = dbuf;
		dd->dd_pool = dp;
		dd->dd_phys = dbuf->db_data;
		dd->dd_used_bytes = dd->dd_phys->dd_used_bytes;

		list_create(&dd->dd_prop_cbs, sizeof (dsl_prop_cb_record_t),
		    offsetof(dsl_prop_cb_record_t, cbr_node));

		if (dd->dd_phys->dd_parent_obj) {
			dd->dd_parent = dsl_dir_open_obj(dp,
			    dd->dd_phys->dd_parent_obj, NULL, dd);
			if (tail) {
#ifdef ZFS_DEBUG
				uint64_t foundobj;

				err = zap_lookup(dp->dp_meta_objset,
				    dd->dd_parent->dd_phys->
				    dd_child_dir_zapobj,
				    tail, sizeof (foundobj), 1, &foundobj);
				ASSERT3U(err, ==, 0);
				ASSERT3U(foundobj, ==, ddobj);
#endif
				(void) strcpy(dd->dd_myname, tail);
			} else {
				err = zap_value_search(dp->dp_meta_objset,
				    dd->dd_parent->dd_phys->
				    dd_child_dir_zapobj,
				    ddobj, dd->dd_myname);
				/*
				 * The caller should be protecting this ddobj
				 * from being deleted concurrently
				 */
				ASSERT(err == 0);
			}
		} else {
			(void) strcpy(dd->dd_myname, spa_name(dp->dp_spa));
		}

		winner = dmu_buf_set_user_ie(dbuf, dd, &dd->dd_phys,
		    dsl_dir_evict);
		if (winner) {
			if (dd->dd_parent)
				dsl_dir_close(dd->dd_parent, dd);
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
	return (dd);
}

void
dsl_dir_close(dsl_dir_t *dd, void *tag)
{
	dprintf_dd(dd, "%s\n", "");
	spa_close(dd->dd_pool->dp_spa, tag);
	dmu_buf_rele_tag(dd->dd_dbuf, tag);
}

/* buf must be long enough (MAXNAMELEN should do) */
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

int
dsl_dir_is_private(dsl_dir_t *dd)
{
	int rv = FALSE;

	if (dd->dd_parent && dsl_dir_is_private(dd->dd_parent))
		rv = TRUE;
	if (dataset_name_hidden(dd->dd_myname))
		rv = TRUE;
	return (rv);
}


static int
getcomponent(const char *path, char *component, const char **nextp)
{
	char *p;
	if (path == NULL)
		return (NULL);
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
dsl_dir_t *
dsl_dir_open_spa(spa_t *spa, const char *name, void *tag, const char **tailp)
{
	char buf[MAXNAMELEN];
	const char *next, *nextnext = NULL;
	int err;
	dsl_dir_t *dd;
	dsl_pool_t *dp;
	uint64_t ddobj;
	int openedspa = FALSE;

	dprintf("%s\n", name);

	if (name == NULL)
		return (NULL);
	err = getcomponent(name, buf, &next);
	if (err)
		return (NULL);
	if (spa == NULL) {
		err = spa_open(buf, &spa, FTAG);
		if (err) {
			dprintf("spa_open(%s) failed\n", buf);
			return (NULL);
		}
		openedspa = TRUE;

		/* XXX this assertion belongs in spa_open */
		ASSERT(!dsl_pool_sync_context(spa_get_dsl(spa)));
	}

	dp = spa_get_dsl(spa);

	rw_enter(&dp->dp_config_rwlock, RW_READER);
	dd = dsl_dir_open_obj(dp, dp->dp_root_dir_obj, NULL, tag);
	while (next != NULL) {
		dsl_dir_t *child_ds;
		err = getcomponent(next, buf, &nextnext);
		if (err) {
			dsl_dir_close(dd, tag);
			rw_exit(&dp->dp_config_rwlock);
			if (openedspa)
				spa_close(spa, FTAG);
			return (NULL);
		}
		ASSERT(next[0] != '\0');
		if (next[0] == '@')
			break;
		if (dd->dd_phys->dd_child_dir_zapobj == 0)
			break;
		dprintf("looking up %s in obj%lld\n",
		    buf, dd->dd_phys->dd_child_dir_zapobj);

		err = zap_lookup(dp->dp_meta_objset,
		    dd->dd_phys->dd_child_dir_zapobj,
		    buf, sizeof (ddobj), 1, &ddobj);
		if (err == ENOENT) {
			break;
		}
		ASSERT(err == 0);

		child_ds = dsl_dir_open_obj(dp, ddobj, buf, tag);
		dsl_dir_close(dd, tag);
		dd = child_ds;
		next = nextnext;
	}
	rw_exit(&dp->dp_config_rwlock);

	/*
	 * It's an error if there's more than one component left, or
	 * tailp==NULL and there's any component left.
	 */
	if (next != NULL &&
	    (tailp == NULL || (nextnext && nextnext[0] != '\0'))) {
		/* bad path name */
		dsl_dir_close(dd, tag);
		dprintf("next=%p (%s) tail=%p\n", next, next?next:"", tailp);
		next = NULL;
		dd = NULL;
	}
	if (tailp)
		*tailp = next;
	if (openedspa)
		spa_close(spa, FTAG);
	return (dd);
}

/*
 * Return the dsl_dir_t, and possibly the last component which couldn't
 * be found in *tail.  Return NULL if the path is bogus, or if
 * tail==NULL and we couldn't parse the whole name.  (*tail)[0] == '@'
 * means that the last component is a snapshot.
 */
dsl_dir_t *
dsl_dir_open(const char *name, void *tag, const char **tailp)
{
	return (dsl_dir_open_spa(NULL, name, tag, tailp));
}

int
dsl_dir_create_sync(dsl_dir_t *pds, const char *name, dmu_tx_t *tx)
{
	objset_t *mos = pds->dd_pool->dp_meta_objset;
	uint64_t ddobj;
	dsl_dir_phys_t *dsphys;
	dmu_buf_t *dbuf;
	int err;

	ASSERT(dmu_tx_is_syncing(tx));

	if (pds->dd_phys->dd_child_dir_zapobj == 0) {
		dmu_buf_will_dirty(pds->dd_dbuf, tx);
		pds->dd_phys->dd_child_dir_zapobj = zap_create(mos,
		    DMU_OT_DSL_DIR_CHILD_MAP, DMU_OT_NONE, 0, tx);
	}

	rw_enter(&pds->dd_pool->dp_config_rwlock, RW_WRITER);
	err = zap_lookup(mos, pds->dd_phys->dd_child_dir_zapobj,
	    name, sizeof (uint64_t), 1, &ddobj);
	if (err != ENOENT) {
		rw_exit(&pds->dd_pool->dp_config_rwlock);
		return (err ? err : EEXIST);
	}

	ddobj = dmu_object_alloc(mos, DMU_OT_DSL_DATASET, 0,
	    DMU_OT_DSL_DATASET, sizeof (dsl_dir_phys_t), tx);
	err = zap_add(mos, pds->dd_phys->dd_child_dir_zapobj,
	    name, sizeof (uint64_t), 1, &ddobj, tx);
	ASSERT3U(err, ==, 0);
	dprintf("dataset_create: zap_add %s->%lld to %lld returned %d\n",
	    name, ddobj, pds->dd_phys->dd_child_dir_zapobj, err);

	dbuf = dmu_bonus_hold(mos, ddobj);
	dmu_buf_will_dirty(dbuf, tx);
	dsphys = dbuf->db_data;

	dsphys->dd_creation_time = gethrestime_sec();
	dsphys->dd_parent_obj = pds->dd_object;
	dsphys->dd_props_zapobj = zap_create(mos,
	    DMU_OT_DSL_PROPS, DMU_OT_NONE, 0, tx);
	dsphys->dd_child_dir_zapobj = zap_create(mos,
	    DMU_OT_DSL_DIR_CHILD_MAP, DMU_OT_NONE, 0, tx);
	dmu_buf_rele(dbuf);

	rw_exit(&pds->dd_pool->dp_config_rwlock);

	return (0);
}

int
dsl_dir_destroy_sync(dsl_dir_t *pds, void *arg, dmu_tx_t *tx)
{
	const char *name = arg;
	dsl_dir_t *dd = NULL;
	dsl_pool_t *dp = pds->dd_pool;
	objset_t *mos = dp->dp_meta_objset;
	uint64_t val, obj, child_zapobj, props_zapobj;
	int t, err;

	rw_enter(&dp->dp_config_rwlock, RW_WRITER);

	err = zap_lookup(mos, pds->dd_phys->dd_child_dir_zapobj, name,
	    8, 1, &obj);
	if (err)
		goto out;

	dd = dsl_dir_open_obj(dp, obj, name, FTAG);
	ASSERT3U(dd->dd_phys->dd_parent_obj, ==, pds->dd_object);

	if (dmu_buf_refcount(dd->dd_dbuf) > 1) {
		err = EBUSY;
		goto out;
	}

	for (t = 0; t < TXG_SIZE; t++) {
		/*
		 * if they were dirty, they'd also be open.
		 * dp_config_rwlock ensures that it stays that way.
		 */
		ASSERT(!txg_list_member(&dp->dp_dirty_dirs, dd, t));
	}

	child_zapobj = dd->dd_phys->dd_child_dir_zapobj;
	props_zapobj = dd->dd_phys->dd_props_zapobj;

	if (child_zapobj != 0) {
		uint64_t count;
		err = EEXIST;
		(void) zap_count(mos, child_zapobj, &count);
		if (count != 0)
			goto out;
	}

	if (dd->dd_phys->dd_head_dataset_obj != 0) {
		err = dsl_dataset_destroy_sync(dd, NULL, tx);
		if (err)
			goto out;
	}
	ASSERT(dd->dd_phys->dd_head_dataset_obj == 0);

	/* The point of no (unsuccessful) return */

	/* Make sure parent's used gets updated */
	val = 0;
	err = dsl_dir_set_reservation_sync(dd, &val, tx);
	ASSERT(err == 0);
	ASSERT3U(dd->dd_used_bytes, ==, 0);
	ASSERT3U(dd->dd_phys->dd_reserved, ==, 0);
	dsl_dir_close(dd, FTAG);
	dd = NULL;

	err = dmu_object_free(mos, obj, tx);
	ASSERT(err == 0);

	if (child_zapobj)
		err = zap_destroy(mos, child_zapobj, tx);
	ASSERT(err == 0);

	if (props_zapobj)
		err = zap_destroy(mos, props_zapobj, tx);
	ASSERT(err == 0);

	err = zap_remove(mos, pds->dd_phys->dd_child_dir_zapobj, name, tx);
	ASSERT(err == 0);

out:
	rw_exit(&dp->dp_config_rwlock);
	if (dd)
		dsl_dir_close(dd, FTAG);

	return (err);
}

void
dsl_dir_create_root(objset_t *mos, uint64_t *ddobjp, dmu_tx_t *tx)
{
	dsl_dir_phys_t *dsp;
	dmu_buf_t *dbuf;
	int error;

	*ddobjp = dmu_object_alloc(mos, DMU_OT_DSL_DATASET, 0,
	    DMU_OT_DSL_DATASET, sizeof (dsl_dir_phys_t), tx);

	error = zap_add(mos, DMU_POOL_DIRECTORY_OBJECT, DMU_POOL_ROOT_DATASET,
	    sizeof (uint64_t), 1, ddobjp, tx);
	ASSERT3U(error, ==, 0);

	dbuf = dmu_bonus_hold(mos, *ddobjp);
	dmu_buf_will_dirty(dbuf, tx);
	dsp = dbuf->db_data;

	dsp->dd_creation_time = gethrestime_sec();
	dsp->dd_props_zapobj = zap_create(mos,
	    DMU_OT_DSL_PROPS, DMU_OT_NONE, 0, tx);
	dsp->dd_child_dir_zapobj = zap_create(mos,
	    DMU_OT_DSL_DIR_CHILD_MAP, DMU_OT_NONE, 0, tx);

	dmu_buf_rele(dbuf);
}

void
dsl_dir_stats(dsl_dir_t *dd, dmu_objset_stats_t *dds)
{
	bzero(dds, sizeof (dmu_objset_stats_t));

	dds->dds_dir_obj = dd->dd_object;
	dds->dds_available = dsl_dir_space_available(dd, NULL, 0, TRUE);

	mutex_enter(&dd->dd_lock);
	dds->dds_space_used = dd->dd_used_bytes;
	dds->dds_compressed_bytes = dd->dd_phys->dd_compressed_bytes;
	dds->dds_uncompressed_bytes = dd->dd_phys->dd_uncompressed_bytes;
	dds->dds_quota = dd->dd_phys->dd_quota;
	dds->dds_reserved = dd->dd_phys->dd_reserved;
	mutex_exit(&dd->dd_lock);

	dds->dds_creation_time = dd->dd_phys->dd_creation_time;

	dds->dds_is_placeholder = (dd->dd_phys->dd_head_dataset_obj == 0);

	if (dd->dd_phys->dd_clone_parent_obj) {
		dsl_dataset_t *ds;

		rw_enter(&dd->dd_pool->dp_config_rwlock, RW_READER);
		ds = dsl_dataset_open_obj(dd->dd_pool,
		    dd->dd_phys->dd_clone_parent_obj, NULL, DS_MODE_NONE, FTAG);
		dsl_dataset_name(ds, dds->dds_clone_of);
		dds->dds_clone_of_obj = dd->dd_phys->dd_clone_parent_obj;
		dsl_dataset_close(ds, DS_MODE_NONE, FTAG);
		rw_exit(&dd->dd_pool->dp_config_rwlock);
	}

	VERIFY(dsl_prop_get_ds_integer(dd, "checksum",
	    &dds->dds_checksum, dds->dds_checksum_setpoint) == 0);

	VERIFY(dsl_prop_get_ds_integer(dd, "compression",
	    &dds->dds_compression, dds->dds_compression_setpoint) == 0);

	VERIFY(dsl_prop_get_ds_integer(dd, "zoned",
	    &dds->dds_zoned, dds->dds_zoned_setpoint) == 0);

	spa_altroot(dd->dd_pool->dp_spa, dds->dds_altroot,
	    sizeof (dds->dds_altroot));
}

int
dsl_dir_sync_task(dsl_dir_t *dd,
    int (*func)(dsl_dir_t *, void*, dmu_tx_t *), void *arg, uint64_t space)
{
	dmu_tx_t *tx;
	dsl_pool_t *dp = dd->dd_pool;
	int err = 0;
	uint64_t txg;

	dprintf_dd(dd, "func=%p space=%llu\n", func, space);

again:
	tx = dmu_tx_create_ds(dd);
	dmu_tx_hold_space(tx, space);
	err = dmu_tx_assign(tx, TXG_WAIT);
	if (err == ENOSPC || err == EDQUOT) {
		dsl_dir_t *rds;
		/*
		 * They can get their space from either this dd, or the
		 * root dd.
		 */
		for (rds = dd; rds->dd_parent; rds = rds->dd_parent)
			continue;
		dmu_tx_abort(tx);
		tx = dmu_tx_create_ds(rds);
		dmu_tx_hold_space(tx, space);
		err = dmu_tx_assign(tx, TXG_WAIT);
	}
	if (err) {
		dmu_tx_abort(tx);
		return (err);
	}

	txg = dmu_tx_get_txg(tx);
	mutex_enter(&dd->dd_lock);
	if (dd->dd_sync_txg != 0) {
		mutex_exit(&dd->dd_lock);
		dmu_tx_commit(tx);
		txg_wait_synced(dp, 0);
		goto again;
	}

	/* We're good to go */

	dd->dd_sync_txg = txg;
	dd->dd_sync_func = func;
	dd->dd_sync_arg = arg;

	mutex_exit(&dd->dd_lock);

	dsl_dir_dirty(dd, tx);
	dmu_tx_commit(tx);

	txg_wait_synced(dp, txg);

	mutex_enter(&dd->dd_lock);
	ASSERT(dd->dd_sync_txg == txg);
	ASSERT(dd->dd_sync_func == NULL);
	err = dd->dd_sync_err;
	dd->dd_sync_txg = 0;
	mutex_exit(&dd->dd_lock);

	return (err);
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
	if (dd->dd_sync_txg == tx->tx_txg && dd->dd_sync_func) {
		dd->dd_sync_err = dd->dd_sync_func(dd, dd->dd_sync_arg, tx);
		dd->dd_sync_func = NULL;
	}

	ASSERT(dmu_tx_is_syncing(tx));

	dmu_buf_will_dirty(dd->dd_dbuf, tx);

	mutex_enter(&dd->dd_lock);
	ASSERT3U(dd->dd_tempreserved[tx->tx_txg&TXG_MASK], ==, 0);
	dprintf_dd(dd, "txg=%llu towrite=%lluK\n", tx->tx_txg,
	    dd->dd_space_towrite[tx->tx_txg&TXG_MASK] / 1024);
	dd->dd_space_towrite[tx->tx_txg&TXG_MASK] = 0;
	dd->dd_phys->dd_used_bytes = dd->dd_used_bytes;
	mutex_exit(&dd->dd_lock);

	/* release the hold from dsl_dir_dirty */
	dmu_buf_remove_ref(dd->dd_dbuf, dd);
}

static uint64_t
dsl_dir_estimated_space(dsl_dir_t *dd)
{
	int64_t space;
	int i;

	ASSERT(MUTEX_HELD(&dd->dd_lock));

	space = dd->dd_used_bytes;
	ASSERT(space >= 0);
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
static uint64_t
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
	if (ondiskonly) {
		used = dd->dd_used_bytes;
	} else {
		used = dsl_dir_estimated_space(dd);
	}
	if (dd == ancestor)
		used += delta;

	if (dd->dd_parent == NULL) {
		uint64_t poolsize = dsl_pool_adjustedsize(dd->dd_pool, B_FALSE);
		quota = MIN(quota, poolsize);
	}

	if (dd->dd_phys->dd_reserved > used && parentspace != UINT64_MAX) {
		/*
		 * We have some space reserved, in addition to what our
		 * parent gave us.
		 */
		parentspace += dd->dd_phys->dd_reserved - used;
	}

	if (used > quota) {
		/* over quota */
		myspace = 0;
#ifdef ZFS_DEBUG
		{
			/*
			 * While it's OK to be a little over quota, if
			 * we think we are using more space than there
			 * is in the pool (which is already 6% more than
			 * dsl_pool_adjustedsize()), something is very
			 * wrong.
			 */
			uint64_t space = spa_get_space(dd->dd_pool->dp_spa);
			ASSERT3U(used, <=, space);
		}
#endif
	} else {
		/*
		 * the lesser of parent's space and the space
		 * left in our quota
		 */
		myspace = MIN(parentspace, quota - used);
	}

	mutex_exit(&dd->dd_lock);

	return (myspace);
}

struct tempreserve {
	list_node_t tr_node;
	dsl_dir_t *tr_ds;
	uint64_t tr_size;
};

/*
 * Reserve space in this dsl_dir, to be used in this tx's txg.
 * After the space has been dirtied (and thus
 * dsl_dir_willuse_space() has been called), the reservation should
 * be canceled, using dsl_dir_tempreserve_clear().
 */
static int
dsl_dir_tempreserve_impl(dsl_dir_t *dd,
    uint64_t asize, boolean_t netfree, list_t *tr_list, dmu_tx_t *tx)
{
	uint64_t txg = tx->tx_txg;
	uint64_t est_used, quota, parent_rsrv;
	int edquot = EDQUOT;
	int txgidx = txg & TXG_MASK;
	int i;
	struct tempreserve *tr;

	ASSERT3U(txg, !=, 0);

	mutex_enter(&dd->dd_lock);
	/*
	 * Check against the dsl_dir's quota.  We don't add in the delta
	 * when checking for over-quota because they get one free hit.
	 */
	est_used = dsl_dir_estimated_space(dd);
	for (i = 0; i < TXG_SIZE; i++)
		est_used += dd->dd_tempreserved[i];

	quota = UINT64_MAX;

	if (dd->dd_phys->dd_quota)
		quota = dd->dd_phys->dd_quota;

	/*
	 * If this transaction will result in a net free of space, we want
	 * to let it through, but we have to be careful: the space that it
	 * frees won't become available until *after* this txg syncs.
	 * Therefore, to ensure that it's possible to remove files from
	 * a full pool without inducing transient overcommits, we throttle
	 * netfree transactions against a quota that is slightly larger,
	 * but still within the pool's allocation slop.  In cases where
	 * we're very close to full, this will allow a steady trickle of
	 * removes to get through.
	 */
	if (dd->dd_parent == NULL) {
		uint64_t poolsize = dsl_pool_adjustedsize(dd->dd_pool, netfree);
		if (poolsize < quota) {
			quota = poolsize;
			edquot = ENOSPC;
		}
	} else if (netfree) {
		quota = UINT64_MAX;
	}

	/*
	 * If they are requesting more space, and our current estimate
	 * is over quota.  They get to try again unless the actual
	 * on-disk is over quota.
	 */
	if (asize > 0 && est_used > quota) {
		if (dd->dd_used_bytes < quota)
			edquot = ERESTART;
		dprintf_dd(dd, "failing: used=%lluK est_used = %lluK "
		    "quota=%lluK tr=%lluK err=%d\n",
		    dd->dd_used_bytes>>10, est_used>>10,
		    quota>>10, asize>>10, edquot);
		mutex_exit(&dd->dd_lock);
		return (edquot);
	}

	/* We need to up our estimated delta before dropping dd_lock */
	dd->dd_tempreserved[txgidx] += asize;

	parent_rsrv = parent_delta(dd, est_used, asize);
	mutex_exit(&dd->dd_lock);

	tr = kmem_alloc(sizeof (struct tempreserve), KM_SLEEP);
	tr->tr_ds = dd;
	tr->tr_size = asize;
	list_insert_tail(tr_list, tr);

	/* see if it's OK with our parent */
	if (dd->dd_parent && parent_rsrv) {
		return (dsl_dir_tempreserve_impl(dd->dd_parent,
		    parent_rsrv, netfree, tr_list, tx));
	} else {
		return (0);
	}
}

/*
 * Reserve space in this dsl_dir, to be used in this tx's txg.
 * After the space has been dirtied (and thus
 * dsl_dir_willuse_space() has been called), the reservation should
 * be canceled, using dsl_dir_tempreserve_clear().
 */
int
dsl_dir_tempreserve_space(dsl_dir_t *dd, uint64_t lsize,
    uint64_t asize, uint64_t fsize, void **tr_cookiep, dmu_tx_t *tx)
{
	int err = 0;
	list_t *tr_list;

	tr_list = kmem_alloc(sizeof (list_t), KM_SLEEP);
	list_create(tr_list, sizeof (struct tempreserve),
	    offsetof(struct tempreserve, tr_node));

	err = dsl_dir_tempreserve_impl(dd, asize, fsize >= asize,
	    tr_list, tx);

	if (err == 0) {
		struct tempreserve *tr;

		err = arc_tempreserve_space(lsize);
		if (err == 0) {
			tr = kmem_alloc(sizeof (struct tempreserve), KM_SLEEP);
			tr->tr_ds = NULL;
			tr->tr_size = lsize;
			list_insert_tail(tr_list, tr);
		}
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

	while (tr = list_head(tr_list)) {
		if (tr->tr_ds == NULL) {
			arc_tempreserve_clear(tr->tr_size);
		} else {
			mutex_enter(&tr->tr_ds->dd_lock);
			ASSERT3U(tr->tr_ds->dd_tempreserved[txgidx], >=,
			    tr->tr_size);
			tr->tr_ds->dd_tempreserved[txgidx] -= tr->tr_size;
			mutex_exit(&tr->tr_ds->dd_lock);
		}
		list_remove(tr_list, tr);
		kmem_free(tr, sizeof (struct tempreserve));
	}

	kmem_free(tr_list, sizeof (list_t));
}

/*
 * Call in open context when we think we're going to write/free space,
 * eg. when dirtying data.  Be conservative (ie. OK to write less than
 * this or free more than this, but don't write more or free less).
 */
void
dsl_dir_willuse_space(dsl_dir_t *dd, int64_t space, dmu_tx_t *tx)
{
	int64_t parent_space;
	uint64_t est_used;

	mutex_enter(&dd->dd_lock);
	if (space > 0)
		dd->dd_space_towrite[tx->tx_txg & TXG_MASK] += space;

	est_used = dsl_dir_estimated_space(dd);
	parent_space = parent_delta(dd, est_used, space);
	mutex_exit(&dd->dd_lock);

	/* Make sure that we clean up dd_space_to* */
	dsl_dir_dirty(dd, tx);

	/* XXX this is potentially expensive and unnecessary... */
	if (parent_space && dd->dd_parent)
		dsl_dir_willuse_space(dd->dd_parent, parent_space, tx);
}

/* call from syncing context when we actually write/free space for this dd */
void
dsl_dir_diduse_space(dsl_dir_t *dd,
    int64_t used, int64_t compressed, int64_t uncompressed, dmu_tx_t *tx)
{
	int64_t accounted_delta;

	ASSERT(dmu_tx_is_syncing(tx));

	dsl_dir_dirty(dd, tx);

	mutex_enter(&dd->dd_lock);
	accounted_delta = parent_delta(dd, dd->dd_used_bytes, used);
	ASSERT(used >= 0 || dd->dd_used_bytes >= -used);
	ASSERT(compressed >= 0 ||
	    dd->dd_phys->dd_compressed_bytes >= -compressed);
	ASSERT(uncompressed >= 0 ||
	    dd->dd_phys->dd_uncompressed_bytes >= -uncompressed);
	dd->dd_used_bytes += used;
	if (used > 0)
		dd->dd_space_towrite[tx->tx_txg & TXG_MASK] -= used;
	dd->dd_phys->dd_uncompressed_bytes += uncompressed;
	dd->dd_phys->dd_compressed_bytes += compressed;
	mutex_exit(&dd->dd_lock);

	if (dd->dd_parent != NULL) {
		dsl_dir_diduse_space(dd->dd_parent,
		    accounted_delta, compressed, uncompressed, tx);
	}
}

static int
dsl_dir_set_quota_sync(dsl_dir_t *dd, void *arg, dmu_tx_t *tx)
{
	uint64_t *quotap = arg;
	uint64_t new_quota = *quotap;
	int err = 0;

	dmu_buf_will_dirty(dd->dd_dbuf, tx);

	mutex_enter(&dd->dd_lock);
	if (new_quota != 0 && (new_quota < dd->dd_phys->dd_reserved ||
	    new_quota < dsl_dir_estimated_space(dd))) {
		err = ENOSPC;
	} else {
		dd->dd_phys->dd_quota = new_quota;
	}
	mutex_exit(&dd->dd_lock);
	return (err);
}

int
dsl_dir_set_quota(const char *ddname, uint64_t quota)
{
	dsl_dir_t *dd;
	int err;

	dd = dsl_dir_open(ddname, FTAG, NULL);
	if (dd == NULL)
		return (ENOENT);
	/*
	 * If someone removes a file, then tries to set the quota, we
	 * want to make sure the file freeing takes effect.
	 */
	txg_wait_open(dd->dd_pool, 0);

	err = dsl_dir_sync_task(dd, dsl_dir_set_quota_sync, &quota, 0);
	dsl_dir_close(dd, FTAG);
	return (err);
}

static int
dsl_dir_set_reservation_sync(dsl_dir_t *dd, void *arg, dmu_tx_t *tx)
{
	uint64_t *reservationp = arg;
	uint64_t new_reservation = *reservationp;
	uint64_t used, avail;
	int64_t delta;

	if (new_reservation > INT64_MAX)
		return (EOVERFLOW);

	mutex_enter(&dd->dd_lock);
	used = dd->dd_used_bytes;
	delta = MAX(used, new_reservation) -
	    MAX(used, dd->dd_phys->dd_reserved);
	mutex_exit(&dd->dd_lock);

	if (dd->dd_parent) {
		avail = dsl_dir_space_available(dd->dd_parent,
		    NULL, 0, FALSE);
	} else {
		avail = dsl_pool_adjustedsize(dd->dd_pool, B_FALSE) - used;
	}

	if (delta > 0 && delta > avail)
		return (ENOSPC);
	if (delta > 0 && dd->dd_phys->dd_quota > 0 &&
	    new_reservation > dd->dd_phys->dd_quota)
		return (ENOSPC);

	dmu_buf_will_dirty(dd->dd_dbuf, tx);
	dd->dd_phys->dd_reserved = new_reservation;

	if (dd->dd_parent != NULL) {
		/* Roll up this additional usage into our ancestors */
		dsl_dir_diduse_space(dd->dd_parent, delta, 0, 0, tx);
	}
	return (0);
}

int
dsl_dir_set_reservation(const char *ddname, uint64_t reservation)
{
	dsl_dir_t *dd;
	int err;

	dd = dsl_dir_open(ddname, FTAG, NULL);
	if (dd == NULL)
		return (ENOENT);
	err = dsl_dir_sync_task(dd,
	    dsl_dir_set_reservation_sync, &reservation, 0);
	dsl_dir_close(dd, FTAG);
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
	delta = parent_delta(dd, dd->dd_used_bytes, delta);
	mutex_exit(&dd->dd_lock);
	return (would_change(dd->dd_parent, delta, ancestor));
}

int
dsl_dir_rename_sync(dsl_dir_t *dd, void *arg, dmu_tx_t *tx)
{
	const char *newname = arg;
	dsl_pool_t *dp = dd->dd_pool;
	objset_t *mos = dp->dp_meta_objset;
	dsl_dir_t *newpds;
	const char *tail;
	int err, len;

	/* can't rename to different pool */
	len = strlen(dp->dp_root_dir->dd_myname);
	if (strncmp(dp->dp_root_dir->dd_myname, newname, len != 0) ||
	    newname[len] != '/') {
		return (ENXIO);
	}

	newpds = dsl_dir_open_spa(dp->dp_spa, newname, FTAG, &tail);

	/* new parent should exist */
	if (newpds == NULL)
		return (ENOENT);

	/* new name should not already exist */
	if (tail == NULL) {
		dsl_dir_close(newpds, FTAG);
		return (EEXIST);
	}

	rw_enter(&dp->dp_config_rwlock, RW_WRITER);

	/* There should be 2 references: the open and the dirty */
	if (dmu_buf_refcount(dd->dd_dbuf) > 2) {
		rw_exit(&dp->dp_config_rwlock);
		dsl_dir_close(newpds, FTAG);
		return (EBUSY);
	}

	if (newpds != dd->dd_parent) {
		dsl_dir_t *ancestor;
		int64_t adelta;
		uint64_t myspace, avail;

		ancestor = closest_common_ancestor(dd, newpds);

		/* no rename into our descendent */
		if (ancestor == dd) {
			dsl_dir_close(newpds, FTAG);
			rw_exit(&dp->dp_config_rwlock);
			return (EINVAL);
		}

		myspace = MAX(dd->dd_used_bytes, dd->dd_phys->dd_reserved);
		adelta = would_change(dd->dd_parent, -myspace, ancestor);
		avail = dsl_dir_space_available(newpds,
		    ancestor, adelta, FALSE);
		if (avail < myspace) {
			dsl_dir_close(newpds, FTAG);
			rw_exit(&dp->dp_config_rwlock);
			return (ENOSPC);
		}

		/* The point of no (unsuccessful) return */

		dsl_dir_diduse_space(dd->dd_parent, -myspace,
		    -dd->dd_phys->dd_compressed_bytes,
		    -dd->dd_phys->dd_uncompressed_bytes, tx);
		dsl_dir_diduse_space(newpds, myspace,
		    dd->dd_phys->dd_compressed_bytes,
		    dd->dd_phys->dd_uncompressed_bytes, tx);
	}

	/* The point of no (unsuccessful) return */

	dmu_buf_will_dirty(dd->dd_dbuf, tx);

	/* remove from old parent zapobj */
	err = zap_remove(mos, dd->dd_parent->dd_phys->dd_child_dir_zapobj,
	    dd->dd_myname, tx);
	ASSERT3U(err, ==, 0);

	(void) strcpy(dd->dd_myname, tail);
	dsl_dir_close(dd->dd_parent, dd);
	dd->dd_phys->dd_parent_obj = newpds->dd_object;
	dd->dd_parent = dsl_dir_open_obj(dd->dd_pool,
	    newpds->dd_object, NULL, dd);

	/* add to new parent zapobj */
	err = zap_add(mos, newpds->dd_phys->dd_child_dir_zapobj,
	    dd->dd_myname, 8, 1, &dd->dd_object, tx);
	ASSERT3U(err, ==, 0);

	dsl_dir_close(newpds, FTAG);
	rw_exit(&dp->dp_config_rwlock);
	return (0);
}
