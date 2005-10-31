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
#include <sys/spa.h>
#include <sys/spa_impl.h>
#include <sys/dmu.h>
#include <sys/dmu_tx.h>
#include <sys/vdev_impl.h>
#include <sys/uberblock_impl.h>
#include <sys/metaslab.h>
#include <sys/metaslab_impl.h>
#include <sys/space_map.h>
#include <sys/zio.h>
#include <sys/zap.h>
#include <sys/fs/zfs.h>

/*
 * Virtual device management.
 */

static vdev_ops_t *vdev_ops_table[] = {
	&vdev_root_ops,
	&vdev_raidz_ops,
	&vdev_mirror_ops,
	&vdev_replacing_ops,
	&vdev_disk_ops,
	&vdev_file_ops,
	&vdev_missing_ops,
	NULL
};

/*
 * Given a vdev type, return the appropriate ops vector.
 */
static vdev_ops_t *
vdev_getops(const char *type)
{
	vdev_ops_t *ops, **opspp;

	for (opspp = vdev_ops_table; (ops = *opspp) != NULL; opspp++)
		if (strcmp(ops->vdev_op_type, type) == 0)
			break;

	return (ops);
}

/*
 * Default asize function: return the MAX of psize with the asize of
 * all children.  This is what's used by anything other than RAID-Z.
 */
uint64_t
vdev_default_asize(vdev_t *vd, uint64_t psize)
{
	uint64_t asize = P2ROUNDUP(psize, 1ULL << vd->vdev_ashift);
	uint64_t csize;
	uint64_t c;

	for (c = 0; c < vd->vdev_children; c++) {
		csize = vdev_psize_to_asize(vd->vdev_child[c], psize);
		asize = MAX(asize, csize);
	}

	return (asize);
}

vdev_t *
vdev_lookup_top(spa_t *spa, uint64_t vdev)
{
	vdev_t *rvd = spa->spa_root_vdev;

	if (vdev < rvd->vdev_children)
		return (rvd->vdev_child[vdev]);

	return (NULL);
}

vdev_t *
vdev_lookup_by_path(vdev_t *vd, const char *path)
{
	int c;
	vdev_t *mvd;

	if (vd->vdev_path != NULL && strcmp(path, vd->vdev_path) == 0)
		return (vd);

	for (c = 0; c < vd->vdev_children; c++)
		if ((mvd = vdev_lookup_by_path(vd->vdev_child[c], path)) !=
		    NULL)
			return (mvd);

	return (NULL);
}

vdev_t *
vdev_lookup_by_guid(vdev_t *vd, uint64_t guid)
{
	int c;
	vdev_t *mvd;

	if (vd->vdev_children == 0 && vd->vdev_guid == guid)
		return (vd);

	for (c = 0; c < vd->vdev_children; c++)
		if ((mvd = vdev_lookup_by_guid(vd->vdev_child[c], guid)) !=
		    NULL)
			return (mvd);

	return (NULL);
}

void
vdev_add_child(vdev_t *pvd, vdev_t *cvd)
{
	size_t oldsize, newsize;
	uint64_t id = cvd->vdev_id;
	vdev_t **newchild;

	ASSERT(spa_config_held(cvd->vdev_spa, RW_WRITER));
	ASSERT(cvd->vdev_parent == NULL);

	cvd->vdev_parent = pvd;

	if (pvd == NULL)
		return;

	ASSERT(id >= pvd->vdev_children || pvd->vdev_child[id] == NULL);

	oldsize = pvd->vdev_children * sizeof (vdev_t *);
	pvd->vdev_children = MAX(pvd->vdev_children, id + 1);
	newsize = pvd->vdev_children * sizeof (vdev_t *);

	newchild = kmem_zalloc(newsize, KM_SLEEP);
	if (pvd->vdev_child != NULL) {
		bcopy(pvd->vdev_child, newchild, oldsize);
		kmem_free(pvd->vdev_child, oldsize);
	}

	pvd->vdev_child = newchild;
	pvd->vdev_child[id] = cvd;

	cvd->vdev_top = (pvd->vdev_top ? pvd->vdev_top: cvd);
	ASSERT(cvd->vdev_top->vdev_parent->vdev_parent == NULL);

	/*
	 * Walk up all ancestors to update guid sum.
	 */
	for (; pvd != NULL; pvd = pvd->vdev_parent)
		pvd->vdev_guid_sum += cvd->vdev_guid_sum;
}

void
vdev_remove_child(vdev_t *pvd, vdev_t *cvd)
{
	int c;
	uint_t id = cvd->vdev_id;

	ASSERT(cvd->vdev_parent == pvd);

	if (pvd == NULL)
		return;

	ASSERT(id < pvd->vdev_children);
	ASSERT(pvd->vdev_child[id] == cvd);

	pvd->vdev_child[id] = NULL;
	cvd->vdev_parent = NULL;

	for (c = 0; c < pvd->vdev_children; c++)
		if (pvd->vdev_child[c])
			break;

	if (c == pvd->vdev_children) {
		kmem_free(pvd->vdev_child, c * sizeof (vdev_t *));
		pvd->vdev_child = NULL;
		pvd->vdev_children = 0;
	}

	/*
	 * Walk up all ancestors to update guid sum.
	 */
	for (; pvd != NULL; pvd = pvd->vdev_parent)
		pvd->vdev_guid_sum -= cvd->vdev_guid_sum;
}

/*
 * Remove any holes in the child array.
 */
void
vdev_compact_children(vdev_t *pvd)
{
	vdev_t **newchild, *cvd;
	int oldc = pvd->vdev_children;
	int newc, c;

	ASSERT(spa_config_held(pvd->vdev_spa, RW_WRITER));

	for (c = newc = 0; c < oldc; c++)
		if (pvd->vdev_child[c])
			newc++;

	newchild = kmem_alloc(newc * sizeof (vdev_t *), KM_SLEEP);

	for (c = newc = 0; c < oldc; c++) {
		if ((cvd = pvd->vdev_child[c]) != NULL) {
			newchild[newc] = cvd;
			cvd->vdev_id = newc++;
		}
	}

	kmem_free(pvd->vdev_child, oldc * sizeof (vdev_t *));
	pvd->vdev_child = newchild;
	pvd->vdev_children = newc;
}

/*
 * Allocate and minimally initialize a vdev_t.
 */
static vdev_t *
vdev_alloc_common(spa_t *spa, uint_t id, uint64_t guid, vdev_ops_t *ops)
{
	vdev_t *vd;

	while (guid == 0)
		guid = spa_get_random(-1ULL);

	vd = kmem_zalloc(sizeof (vdev_t), KM_SLEEP);

	vd->vdev_spa = spa;
	vd->vdev_id = id;
	vd->vdev_guid = guid;
	vd->vdev_guid_sum = guid;
	vd->vdev_ops = ops;
	vd->vdev_state = VDEV_STATE_CLOSED;

	mutex_init(&vd->vdev_io_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&vd->vdev_io_cv, NULL, CV_DEFAULT, NULL);
	list_create(&vd->vdev_io_pending, sizeof (zio_t),
	    offsetof(zio_t, io_pending));
	mutex_init(&vd->vdev_dirty_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&vd->vdev_dtl_lock, NULL, MUTEX_DEFAULT, NULL);
	space_map_create(&vd->vdev_dtl_map, 0, -1ULL, 0, &vd->vdev_dtl_lock);
	space_map_create(&vd->vdev_dtl_scrub, 0, -1ULL, 0, &vd->vdev_dtl_lock);
	txg_list_create(&vd->vdev_ms_list,
	    offsetof(struct metaslab, ms_txg_node));
	txg_list_create(&vd->vdev_dtl_list,
	    offsetof(struct vdev, vdev_dtl_node));
	vd->vdev_stat.vs_timestamp = gethrtime();

	return (vd);
}

/*
 * Free a vdev_t that has been removed from service.
 */
static void
vdev_free_common(vdev_t *vd)
{
	if (vd->vdev_path)
		spa_strfree(vd->vdev_path);
	if (vd->vdev_devid)
		spa_strfree(vd->vdev_devid);

	txg_list_destroy(&vd->vdev_ms_list);
	txg_list_destroy(&vd->vdev_dtl_list);
	mutex_enter(&vd->vdev_dtl_lock);
	space_map_vacate(&vd->vdev_dtl_map, NULL, NULL);
	space_map_destroy(&vd->vdev_dtl_map);
	space_map_vacate(&vd->vdev_dtl_scrub, NULL, NULL);
	space_map_destroy(&vd->vdev_dtl_scrub);
	mutex_exit(&vd->vdev_dtl_lock);
	mutex_destroy(&vd->vdev_dtl_lock);
	mutex_destroy(&vd->vdev_dirty_lock);
	list_destroy(&vd->vdev_io_pending);
	mutex_destroy(&vd->vdev_io_lock);
	cv_destroy(&vd->vdev_io_cv);

	kmem_free(vd, sizeof (vdev_t));
}

/*
 * Allocate a new vdev.  The 'alloctype' is used to control whether we are
 * creating a new vdev or loading an existing one - the behavior is slightly
 * different for each case.
 */
vdev_t *
vdev_alloc(spa_t *spa, nvlist_t *nv, vdev_t *parent, uint_t id, int alloctype)
{
	vdev_ops_t *ops;
	char *type;
	uint64_t guid = 0;
	vdev_t *vd;

	ASSERT(spa_config_held(spa, RW_WRITER));

	if (nvlist_lookup_string(nv, ZPOOL_CONFIG_TYPE, &type) != 0)
		return (NULL);

	if ((ops = vdev_getops(type)) == NULL)
		return (NULL);

	/*
	 * If this is a load, get the vdev guid from the nvlist.
	 * Otherwise, vdev_alloc_common() will generate one for us.
	 */
	if (alloctype == VDEV_ALLOC_LOAD) {
		uint64_t label_id;

		if (nvlist_lookup_uint64(nv, ZPOOL_CONFIG_ID, &label_id) ||
		    label_id != id)
			return (NULL);

		if (nvlist_lookup_uint64(nv, ZPOOL_CONFIG_GUID, &guid) != 0)
			return (NULL);
	}

	vd = vdev_alloc_common(spa, id, guid, ops);

	if (nvlist_lookup_string(nv, ZPOOL_CONFIG_PATH, &vd->vdev_path) == 0)
		vd->vdev_path = spa_strdup(vd->vdev_path);
	if (nvlist_lookup_string(nv, ZPOOL_CONFIG_DEVID, &vd->vdev_devid) == 0)
		vd->vdev_devid = spa_strdup(vd->vdev_devid);

	/*
	 * If we're a top-level vdev, try to load the allocation parameters.
	 */
	if (parent && !parent->vdev_parent && alloctype == VDEV_ALLOC_LOAD) {
		(void) nvlist_lookup_uint64(nv, ZPOOL_CONFIG_METASLAB_ARRAY,
		    &vd->vdev_ms_array);
		(void) nvlist_lookup_uint64(nv, ZPOOL_CONFIG_METASLAB_SHIFT,
		    &vd->vdev_ms_shift);
		(void) nvlist_lookup_uint64(nv, ZPOOL_CONFIG_ASHIFT,
		    &vd->vdev_ashift);
		(void) nvlist_lookup_uint64(nv, ZPOOL_CONFIG_ASIZE,
		    &vd->vdev_asize);
	}

	/*
	 * If we're a leaf vdev, try to load the DTL object.
	 */
	if (vd->vdev_ops->vdev_op_leaf && alloctype == VDEV_ALLOC_LOAD) {
		(void) nvlist_lookup_uint64(nv, ZPOOL_CONFIG_DTL,
		    &vd->vdev_dtl.smo_object);
	}

	/*
	 * Add ourselves to the parent's list of children.
	 */
	vdev_add_child(parent, vd);

	return (vd);
}

void
vdev_free(vdev_t *vd)
{
	int c;

	/*
	 * vdev_free() implies closing the vdev first.  This is simpler than
	 * trying to ensure complicated semantics for all callers.
	 */
	vdev_close(vd);

	/*
	 * It's possible to free a vdev that's been added to the dirty
	 * list when in the middle of spa_vdev_add().  Handle that case
	 * correctly here.
	 */
	if (vd->vdev_is_dirty)
		vdev_config_clean(vd);

	/*
	 * Free all children.
	 */
	for (c = 0; c < vd->vdev_children; c++)
		vdev_free(vd->vdev_child[c]);

	ASSERT(vd->vdev_child == NULL);
	ASSERT(vd->vdev_guid_sum == vd->vdev_guid);

	/*
	 * Discard allocation state.
	 */
	if (vd == vd->vdev_top)
		vdev_metaslab_fini(vd);

	ASSERT3U(vd->vdev_stat.vs_space, ==, 0);
	ASSERT3U(vd->vdev_stat.vs_alloc, ==, 0);

	/*
	 * Remove this vdev from its parent's child list.
	 */
	vdev_remove_child(vd->vdev_parent, vd);

	ASSERT(vd->vdev_parent == NULL);

	vdev_free_common(vd);
}

/*
 * Transfer top-level vdev state from svd to tvd.
 */
static void
vdev_top_transfer(vdev_t *svd, vdev_t *tvd)
{
	spa_t *spa = svd->vdev_spa;
	metaslab_t *msp;
	vdev_t *vd;
	int t;

	ASSERT(tvd == tvd->vdev_top);

	tvd->vdev_ms_array = svd->vdev_ms_array;
	tvd->vdev_ms_shift = svd->vdev_ms_shift;
	tvd->vdev_ms_count = svd->vdev_ms_count;

	svd->vdev_ms_array = 0;
	svd->vdev_ms_shift = 0;
	svd->vdev_ms_count = 0;

	tvd->vdev_mg = svd->vdev_mg;
	tvd->vdev_mg->mg_vd = tvd;
	tvd->vdev_ms = svd->vdev_ms;
	tvd->vdev_smo = svd->vdev_smo;

	svd->vdev_mg = NULL;
	svd->vdev_ms = NULL;
	svd->vdev_smo = NULL;

	tvd->vdev_stat.vs_alloc = svd->vdev_stat.vs_alloc;
	tvd->vdev_stat.vs_space = svd->vdev_stat.vs_space;

	svd->vdev_stat.vs_alloc = 0;
	svd->vdev_stat.vs_space = 0;

	for (t = 0; t < TXG_SIZE; t++) {
		while ((msp = txg_list_remove(&svd->vdev_ms_list, t)) != NULL)
			(void) txg_list_add(&tvd->vdev_ms_list, msp, t);
		while ((vd = txg_list_remove(&svd->vdev_dtl_list, t)) != NULL)
			(void) txg_list_add(&tvd->vdev_dtl_list, vd, t);
		if (txg_list_remove_this(&spa->spa_vdev_txg_list, svd, t))
			(void) txg_list_add(&spa->spa_vdev_txg_list, tvd, t);
		tvd->vdev_dirty[t] = svd->vdev_dirty[t];
		svd->vdev_dirty[t] = 0;
	}

	if (svd->vdev_is_dirty) {
		vdev_config_clean(svd);
		vdev_config_dirty(tvd);
	}

	ASSERT(svd->vdev_io_retry == NULL);
	ASSERT(list_is_empty(&svd->vdev_io_pending));
}

static void
vdev_top_update(vdev_t *tvd, vdev_t *vd)
{
	int c;

	if (vd == NULL)
		return;

	vd->vdev_top = tvd;

	for (c = 0; c < vd->vdev_children; c++)
		vdev_top_update(tvd, vd->vdev_child[c]);
}

/*
 * Add a mirror/replacing vdev above an existing vdev.
 */
vdev_t *
vdev_add_parent(vdev_t *cvd, vdev_ops_t *ops)
{
	spa_t *spa = cvd->vdev_spa;
	vdev_t *pvd = cvd->vdev_parent;
	vdev_t *mvd;

	ASSERT(spa_config_held(spa, RW_WRITER));

	mvd = vdev_alloc_common(spa, cvd->vdev_id, 0, ops);
	vdev_remove_child(pvd, cvd);
	vdev_add_child(pvd, mvd);
	cvd->vdev_id = mvd->vdev_children;
	vdev_add_child(mvd, cvd);
	vdev_top_update(cvd->vdev_top, cvd->vdev_top);

	mvd->vdev_asize = cvd->vdev_asize;
	mvd->vdev_ashift = cvd->vdev_ashift;
	mvd->vdev_state = cvd->vdev_state;

	if (mvd == mvd->vdev_top)
		vdev_top_transfer(cvd, mvd);

	return (mvd);
}

/*
 * Remove a 1-way mirror/replacing vdev from the tree.
 */
void
vdev_remove_parent(vdev_t *cvd)
{
	vdev_t *mvd = cvd->vdev_parent;
	vdev_t *pvd = mvd->vdev_parent;

	ASSERT(spa_config_held(cvd->vdev_spa, RW_WRITER));

	ASSERT(mvd->vdev_children == 1);
	ASSERT(mvd->vdev_ops == &vdev_mirror_ops ||
	    mvd->vdev_ops == &vdev_replacing_ops);

	vdev_remove_child(mvd, cvd);
	vdev_remove_child(pvd, mvd);
	cvd->vdev_id = mvd->vdev_id;
	vdev_add_child(pvd, cvd);
	vdev_top_update(cvd->vdev_top, cvd->vdev_top);

	if (cvd == cvd->vdev_top)
		vdev_top_transfer(mvd, cvd);

	ASSERT(mvd->vdev_children == 0);
	vdev_free(mvd);
}

void
vdev_metaslab_init(vdev_t *vd, uint64_t txg)
{
	spa_t *spa = vd->vdev_spa;
	metaslab_class_t *mc = spa_metaslab_class_select(spa);
	uint64_t c;
	uint64_t oldc = vd->vdev_ms_count;
	uint64_t newc = vd->vdev_asize >> vd->vdev_ms_shift;
	space_map_obj_t *smo = vd->vdev_smo;
	metaslab_t **mspp = vd->vdev_ms;

	dprintf("%s oldc %llu newc %llu\n", vdev_description(vd), oldc, newc);

	ASSERT(oldc <= newc);

	vd->vdev_smo = kmem_zalloc(newc * sizeof (*smo), KM_SLEEP);
	vd->vdev_ms = kmem_zalloc(newc * sizeof (*mspp), KM_SLEEP);
	vd->vdev_ms_count = newc;

	if (vd->vdev_mg == NULL) {
		if (txg == 0) {
			dmu_buf_t *db;
			uint64_t *ms_array;

			ms_array = kmem_zalloc(newc * sizeof (uint64_t),
			    KM_SLEEP);

			dmu_read(spa->spa_meta_objset, vd->vdev_ms_array,
			    0, newc * sizeof (uint64_t), ms_array);

			for (c = 0; c < newc; c++) {
				if (ms_array[c] == 0)
					continue;
				db = dmu_bonus_hold(spa->spa_meta_objset,
				    ms_array[c]);
				dmu_buf_read(db);
				ASSERT3U(db->db_size, ==, sizeof (*smo));
				bcopy(db->db_data, &vd->vdev_smo[c],
				    db->db_size);
				ASSERT3U(vd->vdev_smo[c].smo_object, ==,
				    ms_array[c]);
				dmu_buf_rele(db);
			}
			kmem_free(ms_array, newc * sizeof (uint64_t));
		}
		vd->vdev_mg = metaslab_group_create(mc, vd);
	}

	for (c = 0; c < oldc; c++) {
		vd->vdev_smo[c] = smo[c];
		vd->vdev_ms[c] = mspp[c];
		mspp[c]->ms_smo = &vd->vdev_smo[c];
	}

	for (c = oldc; c < newc; c++)
		metaslab_init(vd->vdev_mg, &vd->vdev_smo[c], &vd->vdev_ms[c],
		    c << vd->vdev_ms_shift, 1ULL << vd->vdev_ms_shift, txg);

	if (oldc != 0) {
		kmem_free(smo, oldc * sizeof (*smo));
		kmem_free(mspp, oldc * sizeof (*mspp));
	}

}

void
vdev_metaslab_fini(vdev_t *vd)
{
	uint64_t m;
	uint64_t count = vd->vdev_ms_count;

	if (vd->vdev_ms != NULL) {
		for (m = 0; m < count; m++)
			metaslab_fini(vd->vdev_ms[m]);
		kmem_free(vd->vdev_ms, count * sizeof (metaslab_t *));
		vd->vdev_ms = NULL;
	}

	if (vd->vdev_smo != NULL) {
		kmem_free(vd->vdev_smo, count * sizeof (space_map_obj_t));
		vd->vdev_smo = NULL;
	}
}

/*
 * Prepare a virtual device for access.
 */
int
vdev_open(vdev_t *vd)
{
	int error;
	vdev_knob_t *vk;
	int c;
	uint64_t osize = 0;
	uint64_t asize, psize;
	uint64_t ashift = -1ULL;

	ASSERT(vd->vdev_state == VDEV_STATE_CLOSED ||
	    vd->vdev_state == VDEV_STATE_CANT_OPEN ||
	    vd->vdev_state == VDEV_STATE_OFFLINE);

	if (vd->vdev_fault_mode == VDEV_FAULT_COUNT)
		vd->vdev_fault_arg >>= 1;
	else
		vd->vdev_fault_mode = VDEV_FAULT_NONE;

	vd->vdev_stat.vs_aux = VDEV_AUX_NONE;

	for (vk = vdev_knob_next(NULL); vk != NULL; vk = vdev_knob_next(vk)) {
		uint64_t *valp = (uint64_t *)((char *)vd + vk->vk_offset);

		*valp = vk->vk_default;
		*valp = MAX(*valp, vk->vk_min);
		*valp = MIN(*valp, vk->vk_max);
	}

	if (vd->vdev_ops->vdev_op_leaf) {
		vdev_cache_init(vd);
		vdev_queue_init(vd);
		vd->vdev_cache_active = B_TRUE;
	}

	if (vd->vdev_offline) {
		ASSERT(vd->vdev_children == 0);
		dprintf("OFFLINE: %s = ENXIO\n", vdev_description(vd));
		vd->vdev_state = VDEV_STATE_OFFLINE;
		return (ENXIO);
	}

	error = vd->vdev_ops->vdev_op_open(vd, &osize, &ashift);

	dprintf("%s = %d, osize %llu, state = %d\n",
	    vdev_description(vd), error, osize, vd->vdev_state);

	if (error) {
		dprintf("%s in %s failed to open, error %d, aux %d\n",
		    vdev_description(vd),
		    vdev_description(vd->vdev_parent),
		    error,
		    vd->vdev_stat.vs_aux);

		vd->vdev_state = VDEV_STATE_CANT_OPEN;
		return (error);
	}

	vd->vdev_state = VDEV_STATE_HEALTHY;

	for (c = 0; c < vd->vdev_children; c++)
		if (vd->vdev_child[c]->vdev_state != VDEV_STATE_HEALTHY)
			vd->vdev_state = VDEV_STATE_DEGRADED;

	osize = P2ALIGN(osize, (uint64_t)sizeof (vdev_label_t));

	if (vd->vdev_children == 0) {
		if (osize < SPA_MINDEVSIZE) {
			vd->vdev_state = VDEV_STATE_CANT_OPEN;
			vd->vdev_stat.vs_aux = VDEV_AUX_TOO_SMALL;
			return (EOVERFLOW);
		}
		psize = osize;
		asize = osize - (VDEV_LABEL_START_SIZE + VDEV_LABEL_END_SIZE);
	} else {
		if (osize < SPA_MINDEVSIZE -
		    (VDEV_LABEL_START_SIZE + VDEV_LABEL_END_SIZE)) {
			vd->vdev_state = VDEV_STATE_CANT_OPEN;
			vd->vdev_stat.vs_aux = VDEV_AUX_TOO_SMALL;
			return (EOVERFLOW);
		}
		psize = 0;
		asize = osize;
	}

	vd->vdev_psize = psize;

	if (vd->vdev_asize == 0) {
		/*
		 * This is the first-ever open, so use the computed values.
		 */
		vd->vdev_asize = asize;
		vd->vdev_ashift = ashift;
	} else {
		/*
		 * Make sure the alignment requirement hasn't increased.
		 */
		if (ashift > vd->vdev_ashift) {
			dprintf("%s: ashift grew\n", vdev_description(vd));
			vd->vdev_state = VDEV_STATE_CANT_OPEN;
			vd->vdev_stat.vs_aux = VDEV_AUX_BAD_LABEL;
			return (EINVAL);
		}

		/*
		 * Make sure the device hasn't shrunk.
		 */
		if (asize < vd->vdev_asize) {
			dprintf("%s: device shrank\n", vdev_description(vd));
			vd->vdev_state = VDEV_STATE_CANT_OPEN;
			vd->vdev_stat.vs_aux = VDEV_AUX_BAD_LABEL;
			return (EINVAL);
		}

		/*
		 * If all children are healthy and the asize has increased,
		 * then we've experienced dynamic LUN growth.
		 */
		if (vd->vdev_state == VDEV_STATE_HEALTHY &&
		    asize > vd->vdev_asize) {
			dprintf("%s: device grew\n", vdev_description(vd));
			vd->vdev_asize = asize;
		}
	}

	return (0);
}

/*
 * Close a virtual device.
 */
void
vdev_close(vdev_t *vd)
{
	ASSERT3P(list_head(&vd->vdev_io_pending), ==, NULL);

	vd->vdev_ops->vdev_op_close(vd);

	if (vd->vdev_cache_active) {
		vdev_cache_fini(vd);
		vdev_queue_fini(vd);
		vd->vdev_cache_active = B_FALSE;
	}

	if (vd->vdev_offline)
		vd->vdev_state = VDEV_STATE_OFFLINE;
	else
		vd->vdev_state = VDEV_STATE_CLOSED;
}

void
vdev_reopen(vdev_t *vd, zio_t **rq)
{
	vdev_t *rvd = vd->vdev_spa->spa_root_vdev;
	int c;

	if (vd == rvd) {
		ASSERT(rq == NULL);
		for (c = 0; c < rvd->vdev_children; c++)
			vdev_reopen(rvd->vdev_child[c], NULL);
		return;
	}

	/* only valid for top-level vdevs */
	ASSERT3P(vd, ==, vd->vdev_top);

	/*
	 * vdev_state can change when spa_config_lock is held as writer,
	 * or when it's held as reader and we're doing a vdev_reopen().
	 * To handle the latter case, we grab rvd's io_lock to serialize
	 * reopens.  This ensures that there's never more than one vdev
	 * state changer active at a time.
	 */
	mutex_enter(&rvd->vdev_io_lock);

	mutex_enter(&vd->vdev_io_lock);
	while (list_head(&vd->vdev_io_pending) != NULL)
		cv_wait(&vd->vdev_io_cv, &vd->vdev_io_lock);
	vdev_close(vd);
	(void) vdev_open(vd);
	if (rq != NULL) {
		*rq = vd->vdev_io_retry;
		vd->vdev_io_retry = NULL;
	}
	mutex_exit(&vd->vdev_io_lock);

	/*
	 * Reassess root vdev's health.
	 */
	rvd->vdev_state = VDEV_STATE_HEALTHY;
	for (c = 0; c < rvd->vdev_children; c++) {
		uint64_t state = rvd->vdev_child[c]->vdev_state;
		rvd->vdev_state = MIN(rvd->vdev_state, state);
	}

	mutex_exit(&rvd->vdev_io_lock);
}

int
vdev_create(vdev_t *vd, uint64_t txg)
{
	int error;

	/*
	 * Normally, partial opens (e.g. of a mirror) are allowed.
	 * For a create, however, we want to fail the request if
	 * there are any components we can't open.
	 */
	error = vdev_open(vd);

	if (error || vd->vdev_state != VDEV_STATE_HEALTHY) {
		vdev_close(vd);
		return (error ? error : ENXIO);
	}

	/*
	 * Recursively initialize all labels.
	 */
	if ((error = vdev_label_init(vd, txg)) != 0) {
		vdev_close(vd);
		return (error);
	}

	return (0);
}

/*
 * The is the latter half of vdev_create().  It is distinct because it
 * involves initiating transactions in order to do metaslab creation.
 * For creation, we want to try to create all vdevs at once and then undo it
 * if anything fails; this is much harder if we have pending transactions.
 */
void
vdev_init(vdev_t *vd, uint64_t txg)
{
	/*
	 * Aim for roughly 200 metaslabs per vdev.
	 */
	vd->vdev_ms_shift = highbit(vd->vdev_asize / 200);
	vd->vdev_ms_shift = MAX(vd->vdev_ms_shift, SPA_MAXBLOCKSHIFT);

	/*
	 * Initialize the vdev's metaslabs.
	 */
	vdev_metaslab_init(vd, txg);
}

void
vdev_dirty(vdev_t *vd, uint8_t flags, uint64_t txg)
{
	vdev_t *tvd = vd->vdev_top;

	mutex_enter(&tvd->vdev_dirty_lock);
	if ((tvd->vdev_dirty[txg & TXG_MASK] & flags) != flags) {
		tvd->vdev_dirty[txg & TXG_MASK] |= flags;
		(void) txg_list_add(&tvd->vdev_spa->spa_vdev_txg_list,
		    tvd, txg);
	}
	mutex_exit(&tvd->vdev_dirty_lock);
}

void
vdev_dtl_dirty(space_map_t *sm, uint64_t txg, uint64_t size)
{
	mutex_enter(sm->sm_lock);
	if (!space_map_contains(sm, txg, size))
		space_map_add(sm, txg, size);
	mutex_exit(sm->sm_lock);
}

int
vdev_dtl_contains(space_map_t *sm, uint64_t txg, uint64_t size)
{
	int dirty;

	/*
	 * Quick test without the lock -- covers the common case that
	 * there are no dirty time segments.
	 */
	if (sm->sm_space == 0)
		return (0);

	mutex_enter(sm->sm_lock);
	dirty = space_map_contains(sm, txg, size);
	mutex_exit(sm->sm_lock);

	return (dirty);
}

/*
 * Reassess DTLs after a config change or scrub completion.
 */
void
vdev_dtl_reassess(vdev_t *vd, uint64_t txg, uint64_t scrub_txg, int scrub_done)
{
	int c;

	ASSERT(spa_config_held(vd->vdev_spa, RW_WRITER));

	if (vd->vdev_children == 0) {
		mutex_enter(&vd->vdev_dtl_lock);
		/*
		 * We're successfully scrubbed everything up to scrub_txg.
		 * Therefore, excise all old DTLs up to that point, then
		 * fold in the DTLs for everything we couldn't scrub.
		 */
		if (scrub_txg != 0) {
			space_map_excise(&vd->vdev_dtl_map, 0, scrub_txg);
			space_map_union(&vd->vdev_dtl_map, &vd->vdev_dtl_scrub);
		}
		if (scrub_done)
			space_map_vacate(&vd->vdev_dtl_scrub, NULL, NULL);
		mutex_exit(&vd->vdev_dtl_lock);
		if (txg != 0) {
			vdev_t *tvd = vd->vdev_top;
			vdev_dirty(tvd, VDD_DTL, txg);
			(void) txg_list_add(&tvd->vdev_dtl_list, vd, txg);
		}
		return;
	}

	mutex_enter(&vd->vdev_dtl_lock);
	space_map_vacate(&vd->vdev_dtl_map, NULL, NULL);
	space_map_vacate(&vd->vdev_dtl_scrub, NULL, NULL);
	mutex_exit(&vd->vdev_dtl_lock);

	for (c = 0; c < vd->vdev_children; c++) {
		vdev_t *cvd = vd->vdev_child[c];
		vdev_dtl_reassess(cvd, txg, scrub_txg, scrub_done);
		mutex_enter(&vd->vdev_dtl_lock);
		space_map_union(&vd->vdev_dtl_map, &cvd->vdev_dtl_map);
		space_map_union(&vd->vdev_dtl_scrub, &cvd->vdev_dtl_scrub);
		mutex_exit(&vd->vdev_dtl_lock);
	}
}

static int
vdev_dtl_load(vdev_t *vd)
{
	spa_t *spa = vd->vdev_spa;
	space_map_obj_t *smo = &vd->vdev_dtl;
	dmu_buf_t *db;
	int error;

	ASSERT(vd->vdev_children == 0);

	if (smo->smo_object == 0)
		return (0);

	db = dmu_bonus_hold(spa->spa_meta_objset, smo->smo_object);
	dmu_buf_read(db);
	ASSERT3U(db->db_size, ==, sizeof (*smo));
	bcopy(db->db_data, smo, db->db_size);
	dmu_buf_rele(db);

	mutex_enter(&vd->vdev_dtl_lock);
	error = space_map_load(&vd->vdev_dtl_map, smo, SM_ALLOC,
	    spa->spa_meta_objset, smo->smo_objsize, smo->smo_alloc);
	mutex_exit(&vd->vdev_dtl_lock);

	return (error);
}

void
vdev_dtl_sync(vdev_t *vd, uint64_t txg)
{
	spa_t *spa = vd->vdev_spa;
	space_map_obj_t *smo = &vd->vdev_dtl;
	space_map_t *sm = &vd->vdev_dtl_map;
	space_map_t smsync;
	kmutex_t smlock;
	avl_tree_t *t = &sm->sm_root;
	space_seg_t *ss;
	dmu_buf_t *db;
	dmu_tx_t *tx;

	dprintf("%s in txg %llu pass %d\n",
	    vdev_description(vd), (u_longlong_t)txg, spa_sync_pass(spa));

	tx = dmu_tx_create_assigned(spa->spa_dsl_pool, txg);

	if (vd->vdev_detached) {
		if (smo->smo_object != 0) {
			int err = dmu_object_free(spa->spa_meta_objset,
			    smo->smo_object, tx);
			ASSERT3U(err, ==, 0);
			smo->smo_object = 0;
		}
		dmu_tx_commit(tx);
		return;
	}

	if (smo->smo_object == 0) {
		ASSERT(smo->smo_objsize == 0);
		ASSERT(smo->smo_alloc == 0);
		smo->smo_object = dmu_object_alloc(spa->spa_meta_objset,
		    DMU_OT_SPACE_MAP, 1 << SPACE_MAP_BLOCKSHIFT,
		    DMU_OT_SPACE_MAP_HEADER, sizeof (*smo), tx);
		ASSERT(smo->smo_object != 0);
		vdev_config_dirty(vd->vdev_top);
	}

	dmu_free_range(spa->spa_meta_objset, smo->smo_object,
	    0, smo->smo_objsize, tx);

	mutex_init(&smlock, NULL, MUTEX_DEFAULT, NULL);

	space_map_create(&smsync, sm->sm_start, sm->sm_size, sm->sm_shift,
	    &smlock);

	mutex_enter(&smlock);

	mutex_enter(&vd->vdev_dtl_lock);
	for (ss = avl_first(t); ss != NULL; ss = AVL_NEXT(t, ss))
		space_map_add(&smsync, ss->ss_start, ss->ss_end - ss->ss_start);
	mutex_exit(&vd->vdev_dtl_lock);

	smo->smo_objsize = 0;
	smo->smo_alloc = smsync.sm_space;

	space_map_sync(&smsync, NULL, smo, SM_ALLOC, spa->spa_meta_objset, tx);
	space_map_destroy(&smsync);

	mutex_exit(&smlock);
	mutex_destroy(&smlock);

	db = dmu_bonus_hold(spa->spa_meta_objset, smo->smo_object);
	dmu_buf_will_dirty(db, tx);
	ASSERT3U(db->db_size, ==, sizeof (*smo));
	bcopy(smo, db->db_data, db->db_size);
	dmu_buf_rele(db);

	dmu_tx_commit(tx);
}

int
vdev_load(vdev_t *vd, int import)
{
	spa_t *spa = vd->vdev_spa;
	int c, error;
	nvlist_t *label;
	uint64_t guid, state;

	dprintf("loading %s\n", vdev_description(vd));

	/*
	 * Recursively load all children.
	 */
	for (c = 0; c < vd->vdev_children; c++)
		if ((error = vdev_load(vd->vdev_child[c], import)) != 0)
			return (error);

	/*
	 * If this is a leaf vdev, make sure its agrees with its disk labels.
	 */
	if (vd->vdev_ops->vdev_op_leaf) {

		if (vdev_is_dead(vd))
			return (0);

		/*
		 * XXX state transitions don't propagate to parent here.
		 * Also, merely setting the state isn't sufficient because
		 * it's not persistent; a vdev_reopen() would make us
		 * forget all about it.
		 */
		if ((label = vdev_label_read_config(vd)) == NULL) {
			dprintf("can't load label config\n");
			vdev_set_state(vd, VDEV_STATE_CANT_OPEN,
			    VDEV_AUX_CORRUPT_DATA);
			return (0);
		}

		if (nvlist_lookup_uint64(label, ZPOOL_CONFIG_POOL_GUID,
		    &guid) != 0 || guid != spa_guid(spa)) {
			dprintf("bad or missing pool GUID (%llu)\n", guid);
			vdev_set_state(vd, VDEV_STATE_CANT_OPEN,
			    VDEV_AUX_CORRUPT_DATA);
			nvlist_free(label);
			return (0);
		}

		if (nvlist_lookup_uint64(label, ZPOOL_CONFIG_GUID, &guid) ||
		    guid != vd->vdev_guid) {
			dprintf("bad or missing vdev guid (%llu != %llu)\n",
			    guid, vd->vdev_guid);
			vdev_set_state(vd, VDEV_STATE_CANT_OPEN,
			    VDEV_AUX_CORRUPT_DATA);
			nvlist_free(label);
			return (0);
		}

		/*
		 * If we find a vdev with a matching pool guid and vdev guid,
		 * but the pool state is not active, it indicates that the user
		 * exported or destroyed the pool without affecting the config
		 * cache (if / was mounted readonly, for example).  In this
		 * case, immediately return EBADF so the caller can remove it
		 * from the config.
		 */
		if (nvlist_lookup_uint64(label, ZPOOL_CONFIG_POOL_STATE,
		    &state)) {
			dprintf("missing pool state\n");
			vdev_set_state(vd, VDEV_STATE_CANT_OPEN,
			    VDEV_AUX_CORRUPT_DATA);
			nvlist_free(label);
			return (0);
		}

		if (state != POOL_STATE_ACTIVE &&
		    (!import || state != POOL_STATE_EXPORTED)) {
			dprintf("pool state not active (%llu)\n", state);
			nvlist_free(label);
			return (EBADF);
		}

		nvlist_free(label);
	}

	/*
	 * If this is a top-level vdev, make sure its allocation parameters
	 * exist and initialize its metaslabs.
	 */
	if (vd == vd->vdev_top) {

		if (vd->vdev_ms_array == 0 ||
		    vd->vdev_ms_shift == 0 ||
		    vd->vdev_ashift == 0 ||
		    vd->vdev_asize == 0) {
			vdev_set_state(vd, VDEV_STATE_CANT_OPEN,
			    VDEV_AUX_CORRUPT_DATA);
			return (0);
		}

		vdev_metaslab_init(vd, 0);
	}

	/*
	 * If this is a leaf vdev, load its DTL.
	 */
	if (vd->vdev_ops->vdev_op_leaf) {
		error = vdev_dtl_load(vd);
		if (error) {
			dprintf("can't load DTL for %s, error %d\n",
			    vdev_description(vd), error);
			vdev_set_state(vd, VDEV_STATE_CANT_OPEN,
			    VDEV_AUX_CORRUPT_DATA);
			return (0);
		}
	}

	return (0);
}

void
vdev_sync_done(vdev_t *vd, uint64_t txg)
{
	metaslab_t *msp;

	dprintf("%s txg %llu\n", vdev_description(vd), txg);

	while (msp = txg_list_remove(&vd->vdev_ms_list, TXG_CLEAN(txg)))
		metaslab_sync_done(msp, txg);
}

void
vdev_add_sync(vdev_t *vd, uint64_t txg)
{
	spa_t *spa = vd->vdev_spa;
	dmu_tx_t *tx = dmu_tx_create_assigned(spa->spa_dsl_pool, txg);

	ASSERT(vd == vd->vdev_top);

	if (vd->vdev_ms_array == 0)
		vd->vdev_ms_array = dmu_object_alloc(spa->spa_meta_objset,
		    DMU_OT_OBJECT_ARRAY, 0, DMU_OT_NONE, 0, tx);

	ASSERT(vd->vdev_ms_array != 0);

	vdev_config_dirty(vd);

	dmu_tx_commit(tx);
}

void
vdev_sync(vdev_t *vd, uint64_t txg)
{
	spa_t *spa = vd->vdev_spa;
	vdev_t *lvd;
	metaslab_t *msp;
	uint8_t *dirtyp = &vd->vdev_dirty[txg & TXG_MASK];
	uint8_t dirty = *dirtyp;

	mutex_enter(&vd->vdev_dirty_lock);
	*dirtyp &= ~(VDD_ALLOC | VDD_FREE | VDD_ADD | VDD_DTL);
	mutex_exit(&vd->vdev_dirty_lock);

	dprintf("%s txg %llu pass %d\n",
	    vdev_description(vd), (u_longlong_t)txg, spa_sync_pass(spa));

	if (dirty & VDD_ADD)
		vdev_add_sync(vd, txg);

	while ((msp = txg_list_remove(&vd->vdev_ms_list, txg)) != NULL)
		metaslab_sync(msp, txg);

	while ((lvd = txg_list_remove(&vd->vdev_dtl_list, txg)) != NULL)
		vdev_dtl_sync(lvd, txg);

	(void) txg_list_add(&spa->spa_vdev_txg_list, vd, TXG_CLEAN(txg));
}

uint64_t
vdev_psize_to_asize(vdev_t *vd, uint64_t psize)
{
	return (vd->vdev_ops->vdev_op_asize(vd, psize));
}

void
vdev_io_start(zio_t *zio)
{
	zio->io_vd->vdev_ops->vdev_op_io_start(zio);
}

void
vdev_io_done(zio_t *zio)
{
	zio->io_vd->vdev_ops->vdev_op_io_done(zio);
}

const char *
vdev_description(vdev_t *vd)
{
	if (vd == NULL || vd->vdev_ops == NULL)
		return ("<unknown>");

	if (vd->vdev_path != NULL)
		return (vd->vdev_path);

	if (vd->vdev_parent == NULL)
		return (spa_name(vd->vdev_spa));

	return (vd->vdev_ops->vdev_op_type);
}

int
vdev_online(spa_t *spa, const char *path)
{
	vdev_t *vd;

	spa_config_enter(spa, RW_WRITER);

	if ((vd = vdev_lookup_by_path(spa->spa_root_vdev, path)) == NULL) {
		spa_config_exit(spa);
		return (ENODEV);
	}

	dprintf("ONLINE: %s\n", vdev_description(vd));

	vd->vdev_offline = B_FALSE;

	/*
	 * Clear the error counts.  The idea is that you expect to see all
	 * zeroes when everything is working, so if you've just onlined a
	 * device, you don't want to keep hearing about errors from before.
	 */
	vd->vdev_stat.vs_read_errors = 0;
	vd->vdev_stat.vs_write_errors = 0;
	vd->vdev_stat.vs_checksum_errors = 0;

	vdev_reopen(vd->vdev_top, NULL);

	spa_config_exit(spa);

	VERIFY(spa_scrub(spa, POOL_SCRUB_RESILVER, B_TRUE) == 0);

	return (0);
}

int
vdev_offline(spa_t *spa, const char *path)
{
	vdev_t *vd;

	spa_config_enter(spa, RW_WRITER);

	if ((vd = vdev_lookup_by_path(spa->spa_root_vdev, path)) == NULL) {
		spa_config_exit(spa);
		return (ENODEV);
	}

	dprintf("OFFLINE: %s\n", vdev_description(vd));

	/*
	 * If this device's top-level vdev has a non-empty DTL,
	 * don't allow the device to be offlined.
	 *
	 * XXX -- we should make this more precise by allowing the offline
	 * as long as the remaining devices don't have any DTL holes.
	 */
	if (vd->vdev_top->vdev_dtl_map.sm_space != 0) {
		spa_config_exit(spa);
		return (EBUSY);
	}

	/*
	 * Set this device to offline state and reopen its top-level vdev.
	 * If this action results in the top-level vdev becoming unusable,
	 * undo it and fail the request.
	 */
	vd->vdev_offline = B_TRUE;
	vdev_reopen(vd->vdev_top, NULL);
	if (vdev_is_dead(vd->vdev_top)) {
		vd->vdev_offline = B_FALSE;
		vdev_reopen(vd->vdev_top, NULL);
		spa_config_exit(spa);
		return (EBUSY);
	}

	spa_config_exit(spa);

	return (0);
}

int
vdev_error_setup(spa_t *spa, const char *path, int mode, int mask, uint64_t arg)
{
	vdev_t *vd;

	spa_config_enter(spa, RW_WRITER);

	if ((vd = vdev_lookup_by_path(spa->spa_root_vdev, path)) == NULL) {
		spa_config_exit(spa);
		return (ENODEV);
	}

	vd->vdev_fault_mode = mode;
	vd->vdev_fault_mask = mask;
	vd->vdev_fault_arg = arg;

	spa_config_exit(spa);

	return (0);
}

int
vdev_is_dead(vdev_t *vd)
{
	return (vd->vdev_state <= VDEV_STATE_CANT_OPEN);
}

int
vdev_error_inject(vdev_t *vd, zio_t *zio)
{
	int error = 0;

	if (vd->vdev_fault_mode == VDEV_FAULT_NONE)
		return (0);

	if (((1ULL << zio->io_type) & vd->vdev_fault_mask) == 0)
		return (0);

	switch (vd->vdev_fault_mode) {
	case VDEV_FAULT_RANDOM:
		if (spa_get_random(vd->vdev_fault_arg) == 0)
			error = EIO;
		break;

	case VDEV_FAULT_COUNT:
		if ((int64_t)--vd->vdev_fault_arg <= 0)
			vd->vdev_fault_mode = VDEV_FAULT_NONE;
		error = EIO;
		break;
	}

	if (error != 0) {
		dprintf("returning %d for type %d on %s state %d offset %llx\n",
		    error, zio->io_type, vdev_description(vd),
		    vd->vdev_state, zio->io_offset);
	}

	return (error);
}

/*
 * Get statistics for the given vdev.
 */
void
vdev_get_stats(vdev_t *vd, vdev_stat_t *vs)
{
	vdev_t *rvd = vd->vdev_spa->spa_root_vdev;
	int c, t;

	mutex_enter(&vd->vdev_stat_lock);
	bcopy(&vd->vdev_stat, vs, sizeof (*vs));
	vs->vs_timestamp = gethrtime() - vs->vs_timestamp;
	vs->vs_state = vd->vdev_state;
	mutex_exit(&vd->vdev_stat_lock);

	/*
	 * If we're getting stats on the root vdev, aggregate the I/O counts
	 * over all top-level vdevs (i.e. the direct children of the root).
	 */
	if (vd == rvd) {
		for (c = 0; c < rvd->vdev_children; c++) {
			vdev_t *cvd = rvd->vdev_child[c];
			vdev_stat_t *cvs = &cvd->vdev_stat;

			mutex_enter(&vd->vdev_stat_lock);
			for (t = 0; t < ZIO_TYPES; t++) {
				vs->vs_ops[t] += cvs->vs_ops[t];
				vs->vs_bytes[t] += cvs->vs_bytes[t];
			}
			vs->vs_read_errors += cvs->vs_read_errors;
			vs->vs_write_errors += cvs->vs_write_errors;
			vs->vs_checksum_errors += cvs->vs_checksum_errors;
			vs->vs_scrub_examined += cvs->vs_scrub_examined;
			vs->vs_scrub_errors += cvs->vs_scrub_errors;
			mutex_exit(&vd->vdev_stat_lock);
		}
	}
}

void
vdev_stat_update(zio_t *zio)
{
	vdev_t *vd = zio->io_vd;
	vdev_t *pvd;
	uint64_t txg = zio->io_txg;
	vdev_stat_t *vs = &vd->vdev_stat;
	zio_type_t type = zio->io_type;
	int flags = zio->io_flags;

	if (zio->io_error == 0) {
		if (!(flags & ZIO_FLAG_IO_BYPASS)) {
			mutex_enter(&vd->vdev_stat_lock);
			vs->vs_ops[type]++;
			vs->vs_bytes[type] += zio->io_size;
			mutex_exit(&vd->vdev_stat_lock);
		}
		if ((flags & ZIO_FLAG_IO_REPAIR) &&
		    zio->io_delegate_list == NULL) {
			mutex_enter(&vd->vdev_stat_lock);
			if (flags & (ZIO_FLAG_SCRUB | ZIO_FLAG_RESILVER))
				vs->vs_scrub_repaired += zio->io_size;
			else
				vs->vs_self_healed += zio->io_size;
			mutex_exit(&vd->vdev_stat_lock);
		}
		return;
	}

	if (flags & ZIO_FLAG_SPECULATIVE)
		return;

	if (!vdev_is_dead(vd)) {
		mutex_enter(&vd->vdev_stat_lock);
		if (type == ZIO_TYPE_READ) {
			if (zio->io_error == ECKSUM)
				vs->vs_checksum_errors++;
			else
				vs->vs_read_errors++;
		}
		if (type == ZIO_TYPE_WRITE)
			vs->vs_write_errors++;
		mutex_exit(&vd->vdev_stat_lock);
	}

	if (type == ZIO_TYPE_WRITE) {
		if (txg == 0 || vd->vdev_children != 0)
			return;
		if (flags & (ZIO_FLAG_SCRUB | ZIO_FLAG_RESILVER)) {
			ASSERT(flags & ZIO_FLAG_IO_REPAIR);
			for (pvd = vd; pvd != NULL; pvd = pvd->vdev_parent)
				vdev_dtl_dirty(&pvd->vdev_dtl_scrub, txg, 1);
		}
		if (!(flags & ZIO_FLAG_IO_REPAIR)) {
			vdev_t *tvd = vd->vdev_top;
			if (vdev_dtl_contains(&vd->vdev_dtl_map, txg, 1))
				return;
			vdev_dirty(tvd, VDD_DTL, txg);
			(void) txg_list_add(&tvd->vdev_dtl_list, vd, txg);
			for (pvd = vd; pvd != NULL; pvd = pvd->vdev_parent)
				vdev_dtl_dirty(&pvd->vdev_dtl_map, txg, 1);
		}
	}
}

void
vdev_scrub_stat_update(vdev_t *vd, pool_scrub_type_t type, boolean_t complete)
{
	int c;
	vdev_stat_t *vs = &vd->vdev_stat;

	for (c = 0; c < vd->vdev_children; c++)
		vdev_scrub_stat_update(vd->vdev_child[c], type, complete);

	mutex_enter(&vd->vdev_stat_lock);

	if (type == POOL_SCRUB_NONE) {
		/*
		 * Update completion and end time.  Leave everything else alone
		 * so we can report what happened during the previous scrub.
		 */
		vs->vs_scrub_complete = complete;
		vs->vs_scrub_end = gethrestime_sec();
	} else {
		vs->vs_scrub_type = type;
		vs->vs_scrub_complete = 0;
		vs->vs_scrub_examined = 0;
		vs->vs_scrub_repaired = 0;
		vs->vs_scrub_errors = 0;
		vs->vs_scrub_start = gethrestime_sec();
		vs->vs_scrub_end = 0;
	}

	mutex_exit(&vd->vdev_stat_lock);
}

/*
 * Report checksum errors that a vdev that didn't realize it made.
 * This can happen, for example, when RAID-Z combinatorial reconstruction
 * infers that one of its components returned bad data.
 */
void
vdev_checksum_error(zio_t *zio, vdev_t *vd)
{
	dprintf_bp(zio->io_bp, "imputed checksum error on %s: ",
	    vdev_description(vd));

	if (!(zio->io_flags & ZIO_FLAG_SPECULATIVE)) {
		mutex_enter(&vd->vdev_stat_lock);
		vd->vdev_stat.vs_checksum_errors++;
		mutex_exit(&vd->vdev_stat_lock);
	}
}

/*
 * Update the in-core space usage stats for this vdev and the root vdev.
 */
void
vdev_space_update(vdev_t *vd, uint64_t space_delta, uint64_t alloc_delta)
{
	ASSERT(vd == vd->vdev_top);

	do {
		mutex_enter(&vd->vdev_stat_lock);
		vd->vdev_stat.vs_space += space_delta;
		vd->vdev_stat.vs_alloc += alloc_delta;
		mutex_exit(&vd->vdev_stat_lock);
	} while ((vd = vd->vdev_parent) != NULL);
}

/*
 * Various knobs to tune a vdev.
 */
static vdev_knob_t vdev_knob[] = {
	{
		"cache_size",
		"size of the read-ahead cache",
		0,
		1ULL << 30,
		10ULL << 20,
		offsetof(struct vdev, vdev_cache.vc_size)
	},
	{
		"cache_bshift",
		"log2 of cache blocksize",
		SPA_MINBLOCKSHIFT,
		SPA_MAXBLOCKSHIFT,
		16,
		offsetof(struct vdev, vdev_cache.vc_bshift)
	},
	{
		"cache_max",
		"largest block size to cache",
		0,
		SPA_MAXBLOCKSIZE,
		1ULL << 14,
		offsetof(struct vdev, vdev_cache.vc_max)
	},
	{
		"min_pending",
		"minimum pending I/Os to the disk",
		1,
		10000,
		2,
		offsetof(struct vdev, vdev_queue.vq_min_pending)
	},
	{
		"max_pending",
		"maximum pending I/Os to the disk",
		1,
		10000,
		35,
		offsetof(struct vdev, vdev_queue.vq_max_pending)
	},
	{
		"agg_limit",
		"maximum size of aggregated I/Os",
		0,
		SPA_MAXBLOCKSIZE,
		SPA_MAXBLOCKSIZE,
		offsetof(struct vdev, vdev_queue.vq_agg_limit)
	},
	{
		"time_shift",
		"deadline = pri + (lbolt >> time_shift)",
		0,
		63,
		4,
		offsetof(struct vdev, vdev_queue.vq_time_shift)
	},
	{
		"ramp_rate",
		"exponential I/O issue ramp-up rate",
		1,
		10000,
		2,
		offsetof(struct vdev, vdev_queue.vq_ramp_rate)
	},
};

vdev_knob_t *
vdev_knob_next(vdev_knob_t *vk)
{
	if (vk == NULL)
		return (vdev_knob);

	if (++vk == vdev_knob + sizeof (vdev_knob) / sizeof (vdev_knob_t))
		return (NULL);

	return (vk);
}

/*
 * Mark a top-level vdev's config as dirty, placing it on the dirty list
 * so that it will be written out next time the vdev configuration is synced.
 * If the root vdev is specified (vdev_top == NULL), dirty all top-level vdevs.
 */
void
vdev_config_dirty(vdev_t *vd)
{
	spa_t *spa = vd->vdev_spa;
	vdev_t *rvd = spa->spa_root_vdev;
	int c;

	if (vd == rvd) {
		for (c = 0; c < rvd->vdev_children; c++)
			vdev_config_dirty(rvd->vdev_child[c]);
	} else {
		ASSERT(vd == vd->vdev_top);

		if (!vd->vdev_is_dirty) {
			list_insert_head(&spa->spa_dirty_list, vd);
			vd->vdev_is_dirty = B_TRUE;
		}
	}
}

void
vdev_config_clean(vdev_t *vd)
{
	ASSERT(vd->vdev_is_dirty);

	list_remove(&vd->vdev_spa->spa_dirty_list, vd);
	vd->vdev_is_dirty = B_FALSE;
}

/*
 * Set a vdev's state, updating any parent's state as well.
 */
void
vdev_set_state(vdev_t *vd, vdev_state_t state, vdev_aux_t aux)
{
	if (state == vd->vdev_state)
		return;

	vd->vdev_state = state;
	vd->vdev_stat.vs_aux = aux;

	if (vd->vdev_parent != NULL) {
		int c;
		int degraded = 0, faulted = 0;
		vdev_t *parent, *child;

		parent = vd->vdev_parent;
		for (c = 0; c < parent->vdev_children; c++) {
			child = parent->vdev_child[c];
			if (child->vdev_state <= VDEV_STATE_CANT_OPEN)
				faulted++;
			else if (child->vdev_state == VDEV_STATE_DEGRADED)
				degraded++;
		}

		vd->vdev_parent->vdev_ops->vdev_op_state_change(
		    vd->vdev_parent, faulted, degraded);
	    }
}
