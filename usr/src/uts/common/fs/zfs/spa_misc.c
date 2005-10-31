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
#include <sys/unique.h>
#include <sys/dsl_pool.h>
#include <sys/dsl_dir.h>
#include <sys/dsl_prop.h>
#include <sys/fs/zfs.h>

/*
 * SPA locking
 *
 * There are four basic locks for managing spa_t structures:
 *
 * spa_namespace_lock (global mutex)
 *
 * 	This lock must be acquired to do any of the following:
 *
 * 		- Lookup a spa_t by name
 * 		- Add or remove a spa_t from the namespace
 * 		- Increase spa_refcount from non-zero
 * 		- Check if spa_refcount is zero
 * 		- Rename a spa_t
 * 		- Held for the duration of create/destroy/import/export
 *
 * 	It does not need to handle recursion.  A create or destroy may
 * 	reference objects (files or zvols) in other pools, but by
 * 	definition they must have an existing reference, and will never need
 * 	to lookup a spa_t by name.
 *
 * spa_refcount (per-spa refcount_t protected by mutex)
 *
 * 	This reference count keep track of any active users of the spa_t.  The
 * 	spa_t cannot be destroyed or freed while this is non-zero.  Internally,
 * 	the refcount is never really 'zero' - opening a pool implicitly keeps
 * 	some references in the DMU.  Internally we check against SPA_MINREF, but
 * 	present the image of a zero/non-zero value to consumers.
 *
 * spa_config_lock (per-spa crazy rwlock)
 *
 * 	This SPA special is a recursive rwlock, capable of being acquired from
 * 	asynchronous threads.  It has protects the spa_t from config changes,
 * 	and must be held in the following circumstances:
 *
 * 		- RW_READER to perform I/O to the spa
 * 		- RW_WRITER to change the vdev config
 *
 * spa_config_cache_lock (per-spa mutex)
 *
 * 	This mutex prevents the spa_config nvlist from being updated.  No
 *      other locks are required to obtain this lock, although implicitly you
 *      must have the namespace lock or non-zero refcount to have any kind
 *      of spa_t pointer at all.
 *
 * spa_vdev_lock (global mutex)
 *
 * 	This special lock is a global mutex used to serialize attempts to
 * 	access devices through ZFS.  It makes sure that we do not try to add
 * 	a single vdev to multiple pools at the same time.  It must be held
 * 	when adding or removing a device from the pool.
 *
 *
 * The locking order is fairly straightforward:
 *
 * 		spa_namespace_lock	->	spa_refcount
 *
 * 	The namespace lock must be acquired to increase the refcount from 0
 * 	or to check if it is zero.
 *
 * 		spa_refcount 		->	spa_config_lock
 *
 * 	There must be at least one valid reference on the spa_t to acquire
 * 	the config lock.
 *
 * 		spa_vdev_lock		->	spa_config_lock
 *
 * 	There are no locks required for spa_vdev_lock, but it must be
 * 	acquired before spa_config_lock.
 *
 *
 * The spa_namespace_lock and spa_config_cache_lock can be acquired directly and
 * are globally visible.
 *
 * The namespace is manipulated using the following functions, all which require
 * the spa_namespace_lock to be held.
 *
 * 	spa_lookup()		Lookup a spa_t by name.
 *
 * 	spa_add()		Create a new spa_t in the namespace.
 *
 * 	spa_remove()		Remove a spa_t from the namespace.  This also
 * 				frees up any memory associated with the spa_t.
 *
 * 	spa_next()		Returns the next spa_t in the system, or the
 * 				first if NULL is passed.
 *
 * 	spa_evict_all()		Shutdown and remove all spa_t structures in
 * 				the system.
 *
 *
 * The spa_refcount is manipulated using the following functions:
 *
 * 	spa_open_ref()		Adds a reference to the given spa_t.  Must be
 * 				called with spa_namespace_lock held if the
 * 				refcount is currently zero.
 *
 * 	spa_close()		Remove a reference from the spa_t.  This will
 * 				not free the spa_t or remove it from the
 * 				namespace.  No locking is required.
 *
 * 	spa_refcount_zero()	Returns true if the refcount is currently
 * 				zero.  Must be called with spa_namespace_lock
 * 				held.
 *
 * The spa_config_lock is manipulated using the following functions:
 *
 * 	spa_config_enter()	Acquire the config lock as RW_READER or
 * 				RW_WRITER.  At least one reference on the spa_t
 * 				must exist.
 *
 * 	spa_config_exit()	Release the config lock.
 *
 * 	spa_config_held()	Returns true if the config lock is currently
 * 				held in the given state.
 *
 * The spa_vdev_lock, while acquired directly, is hidden by the following
 * functions, which imply additional semantics that must be followed:
 *
 * 	spa_vdev_enter()	Acquire the vdev lock and the config lock for
 * 				writing.
 *
 * 	spa_vdev_exit()		Release the config lock, wait for all I/O
 * 				to complete, release the vdev lock, and sync
 * 				the updated configs to the cache.
 *
 * The spa_name() function also requires either the spa_namespace_lock
 * or the spa_config_lock, as both are needed to do a rename.  spa_rename() is
 * also implemented within this file since is requires manipulation of the
 * namespace.
 */

static avl_tree_t spa_namespace_avl;
kmutex_t spa_namespace_lock;
static kcondvar_t spa_namespace_cv;

kmem_cache_t *spa_buffer_pool;
int spa_mode;

#ifdef ZFS_DEBUG
int zfs_flags = ~0;
#else
int zfs_flags = 0;
#endif

static kmutex_t spa_vdev_lock;

#define	SPA_MINREF	5	/* spa_refcnt for an open-but-idle pool */

/*
 * ==========================================================================
 * SPA namespace functions
 * ==========================================================================
 */

/*
 * Lookup the named spa_t in the AVL tree.  The spa_namespace_lock must be held.
 * Returns NULL if no matching spa_t is found.
 */
spa_t *
spa_lookup(const char *name)
{
	spa_t search, *spa;
	avl_index_t where;

	ASSERT(MUTEX_HELD(&spa_namespace_lock));

	search.spa_name = (char *)name;
	spa = avl_find(&spa_namespace_avl, &search, &where);

	return (spa);
}

/*
 * Create an uninitialized spa_t with the given name.  Requires
 * spa_namespace_lock.  The caller must ensure that the spa_t doesn't already
 * exist by calling spa_lookup() first.
 */
spa_t *
spa_add(const char *name)
{
	spa_t *spa;

	ASSERT(MUTEX_HELD(&spa_namespace_lock));

	spa = kmem_zalloc(sizeof (spa_t), KM_SLEEP);

	spa->spa_name = spa_strdup(name);
	spa->spa_state = POOL_STATE_UNINITIALIZED;
	spa->spa_freeze_txg = UINT64_MAX;

	refcount_create(&spa->spa_refcount);

	avl_add(&spa_namespace_avl, spa);

	return (spa);
}

/*
 * Removes a spa_t from the namespace, freeing up any memory used.  Requires
 * spa_namespace_lock.  This is called only after the spa_t has been closed and
 * deactivated.
 */
void
spa_remove(spa_t *spa)
{
	ASSERT(MUTEX_HELD(&spa_namespace_lock));
	ASSERT(spa->spa_state == POOL_STATE_UNINITIALIZED);
	ASSERT(spa->spa_scrub_thread == NULL);

	avl_remove(&spa_namespace_avl, spa);
	cv_broadcast(&spa_namespace_cv);

	if (spa->spa_root)
		spa_strfree(spa->spa_root);

	if (spa->spa_name)
		spa_strfree(spa->spa_name);

	spa_config_set(spa, NULL);

	refcount_destroy(&spa->spa_refcount);

	kmem_free(spa, sizeof (spa_t));
}

/*
 * Given a pool, return the next pool in the namespace, or NULL if there is
 * none.  If 'prev' is NULL, return the first pool.
 */
spa_t *
spa_next(spa_t *prev)
{
	ASSERT(MUTEX_HELD(&spa_namespace_lock));

	if (prev)
		return (AVL_NEXT(&spa_namespace_avl, prev));
	else
		return (avl_first(&spa_namespace_avl));
}

/*
 * ==========================================================================
 * SPA refcount functions
 * ==========================================================================
 */

/*
 * Add a reference to the given spa_t.  Must have at least one reference, or
 * have the namespace lock held.
 */
void
spa_open_ref(spa_t *spa, void *tag)
{
	ASSERT(refcount_count(&spa->spa_refcount) > SPA_MINREF ||
	    MUTEX_HELD(&spa_namespace_lock));

	(void) refcount_add(&spa->spa_refcount, tag);
}

/*
 * Remove a reference to the given spa_t.  Must have at least one reference, or
 * have the namespace lock held.
 */
void
spa_close(spa_t *spa, void *tag)
{
	ASSERT(refcount_count(&spa->spa_refcount) > SPA_MINREF ||
	    MUTEX_HELD(&spa_namespace_lock));

	(void) refcount_remove(&spa->spa_refcount, tag);
}

/*
 * Check to see if the spa refcount is zero.  Must be called with
 * spa_namespace_lock held.  We really compare against SPA_MINREF, which is the
 * number of references acquired when opening a pool
 */
boolean_t
spa_refcount_zero(spa_t *spa)
{
	ASSERT(MUTEX_HELD(&spa_namespace_lock));

	return (refcount_count(&spa->spa_refcount) == SPA_MINREF);
}

/*
 * ==========================================================================
 * SPA config locking
 * ==========================================================================
 */

/*
 * Acquire the config lock.  The config lock is a special rwlock that allows for
 * recursive enters.  Because these enters come from the same thread as well as
 * asynchronous threads working on behalf of the owner, we must unilaterally
 * allow all reads access as long at least one reader is held (even if a write
 * is requested).  This has the side effect of write starvation, but write locks
 * are extremely rare, and a solution to this problem would be significantly
 * more complex (if even possible).
 *
 * We would like to assert that the namespace lock isn't held, but this is a
 * valid use during create.
 */
void
spa_config_enter(spa_t *spa, krw_t rw)
{
	spa_config_lock_t *scl = &spa->spa_config_lock;

	mutex_enter(&scl->scl_lock);

	if (scl->scl_writer != curthread) {
		if (rw == RW_READER) {
			while (scl->scl_writer != NULL)
				cv_wait(&scl->scl_cv, &scl->scl_lock);
		} else {
			while (scl->scl_writer != NULL || scl->scl_count > 0)
				cv_wait(&scl->scl_cv, &scl->scl_lock);
			scl->scl_writer = curthread;
		}
	}

	scl->scl_count++;

	mutex_exit(&scl->scl_lock);
}

/*
 * Release the spa config lock, notifying any waiters in the process.
 */
void
spa_config_exit(spa_t *spa)
{
	spa_config_lock_t *scl = &spa->spa_config_lock;

	mutex_enter(&scl->scl_lock);

	ASSERT(scl->scl_count > 0);
	if (--scl->scl_count == 0) {
		cv_broadcast(&scl->scl_cv);
		scl->scl_writer = NULL;  /* OK in either case */
	}

	mutex_exit(&scl->scl_lock);
}

/*
 * Returns true if the config lock is held in the given manner.
 */
boolean_t
spa_config_held(spa_t *spa, krw_t rw)
{
	spa_config_lock_t *scl = &spa->spa_config_lock;
	boolean_t held;

	mutex_enter(&scl->scl_lock);
	if (rw == RW_WRITER)
		held = (scl->scl_writer == curthread);
	else
		held = (scl->scl_count != 0);
	mutex_exit(&scl->scl_lock);

	return (held);
}

/*
 * ==========================================================================
 * SPA vdev locking
 * ==========================================================================
 */

/*
 * Lock the given spa_t for the purpose of adding or removing a vdev.  This
 * grabs the global spa_vdev_lock as well as the spa config lock for writing.
 * It returns the next transaction group for the spa_t.
 */
uint64_t
spa_vdev_enter(spa_t *spa)
{
	mutex_enter(&spa_vdev_lock);

	spa_config_enter(spa, RW_WRITER);

	return (spa_last_synced_txg(spa) + 1);
}

/*
 * Unlock the spa_t after adding or removing a vdev.  Besides undoing the
 * locking of spa_vdev_enter(), we also want make sure the transactions have
 * synced to disk, and then update the global configuration cache with the new
 * information.
 */
int
spa_vdev_exit(spa_t *spa, vdev_t *vd, uint64_t txg, int error)
{
	vdev_dtl_reassess(spa->spa_root_vdev, 0, 0, B_FALSE);

	spa_config_exit(spa);

	if (vd == spa->spa_root_vdev) {		/* spa_create() */
		mutex_exit(&spa_vdev_lock);
		return (error);
	}

	/*
	 * Note: this txg_wait_synced() is important because it ensures
	 * that there won't be more than one config change per txg.
	 * This allows us to use the txg as the generation number.
	 */
	if (error == 0)
		txg_wait_synced(spa->spa_dsl_pool, txg);

	mutex_exit(&spa_vdev_lock);

	if (vd != NULL) {
		ASSERT(!vd->vdev_detached || vd->vdev_dtl.smo_object == 0);
		vdev_free(vd);
	}

	/*
	 * If we're in the middle of export or destroy, don't sync the
	 * config -- it will do that anyway, and we deadlock if we try.
	 */
	if (error == 0 && spa->spa_state == POOL_STATE_ACTIVE) {
		mutex_enter(&spa_namespace_lock);
		spa_config_sync();
		mutex_exit(&spa_namespace_lock);
	}

	return (error);
}

/*
 * ==========================================================================
 * Miscellaneous functions
 * ==========================================================================
 */

/*
 * Rename a spa_t.
 */
int
spa_rename(const char *name, const char *newname)
{
	spa_t *spa;
	int err;

	/*
	 * Lookup the spa_t and grab the config lock for writing.  We need to
	 * actually open the pool so that we can sync out the necessary labels.
	 * It's OK to call spa_open() with the namespace lock held because we
	 * alllow recursive calls for other reasons.
	 */
	mutex_enter(&spa_namespace_lock);
	if ((err = spa_open(name, &spa, FTAG)) != 0) {
		mutex_exit(&spa_namespace_lock);
		return (err);
	}

	spa_config_enter(spa, RW_WRITER);

	avl_remove(&spa_namespace_avl, spa);
	spa_strfree(spa->spa_name);
	spa->spa_name = spa_strdup(newname);
	avl_add(&spa_namespace_avl, spa);

	/*
	 * Sync all labels to disk with the new names by marking the root vdev
	 * dirty and waiting for it to sync.  It will pick up the new pool name
	 * during the sync.
	 */
	vdev_config_dirty(spa->spa_root_vdev);

	spa_config_exit(spa);

	txg_wait_synced(spa->spa_dsl_pool, 0);

	/*
	 * Sync the updated config cache.
	 */
	spa_config_set(spa,
	    spa_config_generate(spa, NULL, spa_last_synced_txg(spa), 0));
	spa_config_sync();

	spa_close(spa, FTAG);

	mutex_exit(&spa_namespace_lock);

	return (0);
}


/*
 * Determine whether a pool with given pool_guid exists.  If device_guid is
 * non-zero, determine whether the pool exists *and* contains a device with the
 * specified device_guid.
 */
boolean_t
spa_guid_exists(uint64_t pool_guid, uint64_t device_guid)
{
	spa_t *spa;
	avl_tree_t *t = &spa_namespace_avl;
	boolean_t locked = B_FALSE;

	if (mutex_owner(&spa_namespace_lock) != curthread) {
		mutex_enter(&spa_namespace_lock);
		locked = B_TRUE;
	}

	for (spa = avl_first(t); spa != NULL; spa = AVL_NEXT(t, spa)) {
		if (spa->spa_state == POOL_STATE_UNINITIALIZED)
			continue;
		if (spa->spa_root_vdev == NULL)
			continue;
		if (spa_guid(spa) == pool_guid && (device_guid == 0 ||
		    vdev_lookup_by_guid(spa->spa_root_vdev, device_guid)))
			break;
	}

	if (locked)
		mutex_exit(&spa_namespace_lock);

	return (spa != NULL);
}

char *
spa_strdup(const char *s)
{
	size_t len;
	char *new;

	len = strlen(s);
	new = kmem_alloc(len + 1, KM_SLEEP);
	bcopy(s, new, len);
	new[len] = '\0';

	return (new);
}

void
spa_strfree(char *s)
{
	kmem_free(s, strlen(s) + 1);
}

uint64_t
spa_get_random(uint64_t range)
{
	uint64_t r;

	ASSERT(range != 0);

	(void) random_get_pseudo_bytes((void *)&r, sizeof (uint64_t));

	return (r % range);
}

void
sprintf_blkptr(char *buf, blkptr_t *bp)
{
	/* XXBP - Need to see if we want all DVAs or not */
	dva_t *dva = BP_IDENTITY(bp);

	if (bp == NULL) {
		(void) sprintf(buf, "<NULL>");
		return;
	}

	if (BP_IS_HOLE(bp)) {
		(void) sprintf(buf, "<hole>");
		return;
	}

	(void) sprintf(buf, "[L%llu %s] vdev=%llu offset=%llx "
	    "size=%llxL/%llxP/%llxA %s %s %s %s",
	    (u_longlong_t)BP_GET_LEVEL(bp),
	    dmu_ot[BP_GET_TYPE(bp)].ot_name,
	    (u_longlong_t)DVA_GET_VDEV(dva),
	    (u_longlong_t)DVA_GET_OFFSET(dva),
	    (u_longlong_t)BP_GET_LSIZE(bp),
	    (u_longlong_t)BP_GET_PSIZE(bp),
	    (u_longlong_t)DVA_GET_ASIZE(dva),
	    zio_checksum_table[BP_GET_CHECKSUM(bp)].ci_name,
	    zio_compress_table[BP_GET_COMPRESS(bp)].ci_name,
	    BP_GET_BYTEORDER(bp) == 0 ? "BE" : "LE",
	    DVA_GET_GANG(dva) == 0 ? "contiguous" : "gang");

	(void) sprintf(buf + strlen(buf), " birth=%llu fill=%llu"
	    " cksum=%llx:%llx:%llx:%llx",
	    (u_longlong_t)bp->blk_birth,
	    (u_longlong_t)bp->blk_fill,
	    (u_longlong_t)bp->blk_cksum.zc_word[0],
	    (u_longlong_t)bp->blk_cksum.zc_word[1],
	    (u_longlong_t)bp->blk_cksum.zc_word[2],
	    (u_longlong_t)bp->blk_cksum.zc_word[3]);
}

void
spa_freeze(spa_t *spa)
{
	uint64_t freeze_txg = 0;

	spa_config_enter(spa, RW_WRITER);
	if (spa->spa_freeze_txg == UINT64_MAX) {
		freeze_txg = spa_last_synced_txg(spa) + TXG_SIZE;
		spa->spa_freeze_txg = freeze_txg;
	}
	spa_config_exit(spa);
	if (freeze_txg != 0)
		txg_wait_synced(spa_get_dsl(spa), freeze_txg);
}

/*
 * ==========================================================================
 * Accessor functions
 * ==========================================================================
 */

krwlock_t *
spa_traverse_rwlock(spa_t *spa)
{
	return (&spa->spa_traverse_lock);
}

int
spa_traverse_wanted(spa_t *spa)
{
	return (spa->spa_traverse_wanted);
}

dsl_pool_t *
spa_get_dsl(spa_t *spa)
{
	return (spa->spa_dsl_pool);
}

blkptr_t *
spa_get_rootblkptr(spa_t *spa)
{
	return (&spa->spa_ubsync.ub_rootbp);
}

void
spa_set_rootblkptr(spa_t *spa, const blkptr_t *bp)
{
	spa->spa_uberblock.ub_rootbp = *bp;
}

void
spa_altroot(spa_t *spa, char *buf, size_t buflen)
{
	if (spa->spa_root == NULL)
		buf[0] = '\0';
	else
		(void) strncpy(buf, spa->spa_root, buflen);
}

int
spa_sync_pass(spa_t *spa)
{
	return (spa->spa_sync_pass);
}

char *
spa_name(spa_t *spa)
{
	/*
	 * Accessing the name requires holding either the namespace lock or the
	 * config lock, both of which are required to do a rename.
	 */
	ASSERT(MUTEX_HELD(&spa_namespace_lock) ||
	    spa_config_held(spa, RW_READER) || spa_config_held(spa, RW_WRITER));

	return (spa->spa_name);
}

uint64_t
spa_guid(spa_t *spa)
{
	return (spa->spa_root_vdev->vdev_guid);
}

uint64_t
spa_last_synced_txg(spa_t *spa)
{
	return (spa->spa_ubsync.ub_txg);
}

uint64_t
spa_first_txg(spa_t *spa)
{
	return (spa->spa_first_txg);
}

int
spa_state(spa_t *spa)
{
	return (spa->spa_state);
}

uint64_t
spa_freeze_txg(spa_t *spa)
{
	return (spa->spa_freeze_txg);
}

/*
 * In the future, this may select among different metaslab classes
 * depending on the zdp.  For now, there's no such distinction.
 */
metaslab_class_t *
spa_metaslab_class_select(spa_t *spa)
{
	return (spa->spa_normal_class);
}

/*
 * Return pool-wide allocated space.
 */
uint64_t
spa_get_alloc(spa_t *spa)
{
	return (spa->spa_root_vdev->vdev_stat.vs_alloc);
}

/*
 * Return pool-wide allocated space.
 */
uint64_t
spa_get_space(spa_t *spa)
{
	return (spa->spa_root_vdev->vdev_stat.vs_space);
}

/* ARGSUSED */
uint64_t
spa_get_asize(spa_t *spa, uint64_t lsize)
{
	/*
	 * For now, the worst case is 512-byte RAID-Z blocks, in which
	 * case the space requirement is exactly 2x; so just assume that.
	 */
	return (lsize << 1);
}

/*
 * ==========================================================================
 * Initialization and Termination
 * ==========================================================================
 */

static int
spa_name_compare(const void *a1, const void *a2)
{
	const spa_t *s1 = a1;
	const spa_t *s2 = a2;
	int s;

	s = strcmp(s1->spa_name, s2->spa_name);
	if (s > 0)
		return (1);
	if (s < 0)
		return (-1);
	return (0);
}

void
spa_init(int mode)
{
	mutex_init(&spa_namespace_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&spa_namespace_cv, NULL, CV_DEFAULT, NULL);

	avl_create(&spa_namespace_avl, spa_name_compare, sizeof (spa_t),
	    offsetof(spa_t, spa_avl));

	spa_mode = mode;

	refcount_init();
	unique_init();
	zio_init();
	dmu_init();
	zil_init();
	spa_config_load();
}

void
spa_fini(void)
{
	spa_evict_all();

	zil_fini();
	dmu_fini();
	zio_fini();
	refcount_fini();

	avl_destroy(&spa_namespace_avl);

	cv_destroy(&spa_namespace_cv);
	mutex_destroy(&spa_namespace_lock);
}
