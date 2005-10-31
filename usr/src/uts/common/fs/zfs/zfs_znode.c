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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/resource.h>
#include <sys/mntent.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/unistd.h>
#include <sys/stat.h>
#include <sys/mode.h>
#include <sys/atomic.h>
#include <vm/pvn.h>
#include "fs/fs_subr.h"
#include <sys/zfs_dir.h>
#include <sys/zfs_acl.h>
#include <sys/zfs_ioctl.h>
#include <sys/zfs_znode.h>
#include <sys/zap.h>
#include <sys/dmu.h>
#include <sys/fs/zfs.h>

struct kmem_cache *znode_cache = NULL;

/*
 * Note that znodes can be on one of 2 states:
 *	ZCACHE_mru	- recently used, currently cached
 *	ZCACHE_mfu	- frequently used, currently cached
 * When there are no active references to the znode, they
 * are linked onto one of the lists in zcache.  These are the
 * only znodes that can be evicted.
 */

typedef struct zcache_state {
	list_t	list;	/* linked list of evictable znodes in state */
	uint64_t lcnt;	/* total number of znodes in the linked list */
	uint64_t cnt;	/* total number of all znodes in this state */
	uint64_t hits;
	kmutex_t mtx;
} zcache_state_t;

/* The 2 states: */
static zcache_state_t ZCACHE_mru;
static zcache_state_t ZCACHE_mfu;

static struct zcache {
	zcache_state_t	*mru;
	zcache_state_t	*mfu;
	uint64_t	p;		/* Target size of mru */
	uint64_t	c;		/* Target size of cache */
	uint64_t	c_max;		/* Maximum target cache size */

	/* performance stats */
	uint64_t	missed;
	uint64_t	evicted;
	uint64_t	skipped;
} zcache;

void zcache_kmem_reclaim(void);

#define	ZCACHE_MINTIME (hz>>4) /* 62 ms */

/*
 * Move the supplied znode to the indicated state.  The mutex
 * for the znode must be held by the caller.
 */
static void
zcache_change_state(zcache_state_t *new_state, znode_t *zp)
{
	/* ASSERT(MUTEX_HELD(hash_mtx)); */
	ASSERT(zp->z_active);

	if (zp->z_zcache_state) {
		ASSERT3U(zp->z_zcache_state->cnt, >=, 1);
		atomic_add_64(&zp->z_zcache_state->cnt, -1);
	}
	atomic_add_64(&new_state->cnt, 1);
	zp->z_zcache_state = new_state;
}

static void
zfs_zcache_evict(znode_t *zp, kmutex_t *hash_mtx)
{
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;

	ASSERT(zp->z_phys);
	ASSERT(zp->z_dbuf_held);

	zp->z_dbuf_held = 0;
	mutex_exit(&zp->z_lock);
	dmu_buf_rele(zp->z_dbuf);
	mutex_exit(hash_mtx);
	VFS_RELE(zfsvfs->z_vfs);
}

/*
 * Evict znodes from list until we've removed the specified number
 */
static void
zcache_evict_state(zcache_state_t *state, int64_t cnt, zfsvfs_t *zfsvfs)
{
	int znodes_evicted = 0;
	znode_t *zp, *zp_prev;
	kmutex_t *hash_mtx;

	ASSERT(state == zcache.mru || state == zcache.mfu);

	mutex_enter(&state->mtx);

	for (zp = list_tail(&state->list); zp; zp = zp_prev) {
		zp_prev = list_prev(&state->list, zp);
		if (zfsvfs && zp->z_zfsvfs != zfsvfs)
			continue;
		hash_mtx = ZFS_OBJ_MUTEX(zp);
		if (mutex_tryenter(hash_mtx)) {
			mutex_enter(&zp->z_lock);
			list_remove(&zp->z_zcache_state->list, zp);
			zp->z_zcache_state->lcnt -= 1;
			ASSERT3U(zp->z_zcache_state->cnt, >=, 1);
			atomic_add_64(&zp->z_zcache_state->cnt, -1);
			zp->z_zcache_state = NULL;
			zp->z_zcache_access = 0;
			/* drops z_lock and hash_mtx */
			zfs_zcache_evict(zp, hash_mtx);
			znodes_evicted += 1;
			atomic_add_64(&zcache.evicted, 1);
			if (znodes_evicted >= cnt)
				break;
		} else {
			atomic_add_64(&zcache.skipped, 1);
		}
	}
	mutex_exit(&state->mtx);

	if (znodes_evicted < cnt)
		dprintf("only evicted %lld znodes from %x",
		    (longlong_t)znodes_evicted, state);
}

static void
zcache_adjust(void)
{
	uint64_t mrucnt = zcache.mru->lcnt;
	uint64_t mfucnt = zcache.mfu->lcnt;
	uint64_t p = zcache.p;
	uint64_t c = zcache.c;

	if (mrucnt > p)
		zcache_evict_state(zcache.mru, mrucnt - p, NULL);

	if (mfucnt > 0 && mrucnt + mfucnt > c) {
		int64_t toevict = MIN(mfucnt, mrucnt + mfucnt - c);
		zcache_evict_state(zcache.mfu, toevict, NULL);
	}
}

/*
 * Flush all *evictable* data from the cache.
 * NOTE: this will not touch "active" (i.e. referenced) data.
 */
void
zfs_zcache_flush(zfsvfs_t *zfsvfs)
{
	zcache_evict_state(zcache.mru, zcache.mru->lcnt, zfsvfs);
	zcache_evict_state(zcache.mfu, zcache.mfu->lcnt, zfsvfs);
}

static void
zcache_try_grow(int64_t cnt)
{
	int64_t size;
	/*
	 * If we're almost to the current target cache size,
	 * increment the target cache size
	 */
	size = zcache.mru->lcnt + zcache.mfu->lcnt;
	if ((zcache.c - size) <= 1) {
		atomic_add_64(&zcache.c, cnt);
		if (zcache.c > zcache.c_max)
			zcache.c = zcache.c_max;
		else if (zcache.p + cnt < zcache.c)
			atomic_add_64(&zcache.p, cnt);
	}
}

/*
 * This routine is called whenever a znode is accessed.
 */
static void
zcache_access(znode_t *zp, kmutex_t *hash_mtx)
{
	ASSERT(MUTEX_HELD(hash_mtx));

	if (zp->z_zcache_state == NULL) {
		/*
		 * This znode is not in the cache.
		 * Add the new znode to the MRU state.
		 */

		zcache_try_grow(1);

		ASSERT(zp->z_zcache_access == 0);
		zp->z_zcache_access = lbolt;
		zcache_change_state(zcache.mru, zp);
		mutex_exit(hash_mtx);

		/*
		 * If we are using less than 2/3 of our total target
		 * cache size, bump up the target size for the MRU
		 * list.
		 */
		if (zcache.mru->lcnt + zcache.mfu->lcnt < zcache.c*2/3) {
			zcache.p = zcache.mru->lcnt + zcache.c/6;
		}

		zcache_adjust();

		atomic_add_64(&zcache.missed, 1);
	} else if (zp->z_zcache_state == zcache.mru) {
		/*
		 * This znode has been "accessed" only once so far,
		 * Move it to the MFU state.
		 */
		if (lbolt > zp->z_zcache_access + ZCACHE_MINTIME) {
			/*
			 * More than 125ms have passed since we
			 * instantiated this buffer.  Move it to the
			 * most frequently used state.
			 */
			zp->z_zcache_access = lbolt;
			zcache_change_state(zcache.mfu, zp);
		}
		atomic_add_64(&zcache.mru->hits, 1);
		mutex_exit(hash_mtx);
	} else {
		ASSERT(zp->z_zcache_state == zcache.mfu);
		/*
		 * This buffer has been accessed more than once.
		 * Keep it in the MFU state.
		 */
		atomic_add_64(&zcache.mfu->hits, 1);
		mutex_exit(hash_mtx);
	}
}

static void
zcache_init(void)
{
	zcache.c = 20;
	zcache.c_max = 50;

	zcache.mru = &ZCACHE_mru;
	zcache.mfu = &ZCACHE_mfu;

	list_create(&zcache.mru->list, sizeof (znode_t),
	    offsetof(znode_t, z_zcache_node));
	list_create(&zcache.mfu->list, sizeof (znode_t),
	    offsetof(znode_t, z_zcache_node));
}

static void
zcache_fini(void)
{
	zfs_zcache_flush(NULL);

	list_destroy(&zcache.mru->list);
	list_destroy(&zcache.mfu->list);
}

/*ARGSUSED*/
static void
znode_pageout_func(dmu_buf_t *dbuf, void *user_ptr)
{
	znode_t *zp = user_ptr;
	vnode_t *vp = ZTOV(zp);

	if (vp->v_count == 0) {
		vn_invalid(vp);
		zfs_znode_free(zp);
	}
}

/*ARGSUSED*/
static int
zfs_znode_cache_constructor(void *buf, void *cdrarg, int kmflags)
{
	znode_t *zp = buf;

	zp->z_vnode = vn_alloc(KM_SLEEP);
	zp->z_vnode->v_data = (caddr_t)zp;
	mutex_init(&zp->z_lock, NULL, MUTEX_DEFAULT, NULL);
	rw_init(&zp->z_map_lock, NULL, RW_DEFAULT, NULL);
	rw_init(&zp->z_grow_lock, NULL, RW_DEFAULT, NULL);
	rw_init(&zp->z_append_lock, NULL, RW_DEFAULT, NULL);
	mutex_init(&zp->z_acl_lock, NULL, MUTEX_DEFAULT, NULL);
	zp->z_dbuf_held = 0;
	zp->z_dirlocks = 0;
	return (0);
}

/*ARGSUSED*/
static void
zfs_znode_cache_destructor(void *buf, void *cdarg)
{
	znode_t *zp = buf;

	ASSERT(zp->z_dirlocks == 0);
	mutex_destroy(&zp->z_lock);
	rw_destroy(&zp->z_map_lock);
	rw_destroy(&zp->z_grow_lock);
	rw_destroy(&zp->z_append_lock);
	mutex_destroy(&zp->z_acl_lock);

	ASSERT(zp->z_dbuf_held == 0);
	ASSERT(ZTOV(zp)->v_count == 0);
	vn_free(ZTOV(zp));
}

void
zfs_znode_init(void)
{
	/*
	 * Initialize zcache
	 */
	ASSERT(znode_cache == NULL);
	znode_cache = kmem_cache_create("zfs_znode_cache",
	    sizeof (znode_t), 0, zfs_znode_cache_constructor,
	    zfs_znode_cache_destructor, NULL, NULL, NULL, 0);

	zcache_init();
}

void
zfs_znode_fini(void)
{
	zcache_fini();

	/*
	 * Cleanup vfs & vnode ops
	 */
	zfs_remove_op_tables();

	/*
	 * Cleanup zcache
	 */
	if (znode_cache)
		kmem_cache_destroy(znode_cache);
	znode_cache = NULL;
}

struct vnodeops *zfs_dvnodeops;
struct vnodeops *zfs_fvnodeops;
struct vnodeops *zfs_symvnodeops;
struct vnodeops *zfs_xdvnodeops;
struct vnodeops *zfs_evnodeops;

void
zfs_remove_op_tables()
{
	/*
	 * Remove vfs ops
	 */
	ASSERT(zfsfstype);
	(void) vfs_freevfsops_by_type(zfsfstype);
	zfsfstype = 0;

	/*
	 * Remove vnode ops
	 */
	if (zfs_dvnodeops)
		vn_freevnodeops(zfs_dvnodeops);
	if (zfs_fvnodeops)
		vn_freevnodeops(zfs_fvnodeops);
	if (zfs_symvnodeops)
		vn_freevnodeops(zfs_symvnodeops);
	if (zfs_xdvnodeops)
		vn_freevnodeops(zfs_xdvnodeops);
	if (zfs_evnodeops)
		vn_freevnodeops(zfs_evnodeops);

	zfs_dvnodeops = NULL;
	zfs_fvnodeops = NULL;
	zfs_symvnodeops = NULL;
	zfs_xdvnodeops = NULL;
	zfs_evnodeops = NULL;
}

extern const fs_operation_def_t zfs_dvnodeops_template[];
extern const fs_operation_def_t zfs_fvnodeops_template[];
extern const fs_operation_def_t zfs_xdvnodeops_template[];
extern const fs_operation_def_t zfs_symvnodeops_template[];
extern const fs_operation_def_t zfs_evnodeops_template[];

int
zfs_create_op_tables()
{
	int error;

	/*
	 * zfs_dvnodeops can be set if mod_remove() calls mod_installfs()
	 * due to a failure to remove the the 2nd modlinkage (zfs_modldrv).
	 * In this case we just return as the ops vectors are already set up.
	 */
	if (zfs_dvnodeops)
		return (0);

	error = vn_make_ops(MNTTYPE_ZFS, zfs_dvnodeops_template,
	    &zfs_dvnodeops);
	if (error)
		return (error);

	error = vn_make_ops(MNTTYPE_ZFS, zfs_fvnodeops_template,
	    &zfs_fvnodeops);
	if (error)
		return (error);

	error = vn_make_ops(MNTTYPE_ZFS, zfs_symvnodeops_template,
	    &zfs_symvnodeops);
	if (error)
		return (error);

	error = vn_make_ops(MNTTYPE_ZFS, zfs_xdvnodeops_template,
	    &zfs_xdvnodeops);
	if (error)
		return (error);

	error = vn_make_ops(MNTTYPE_ZFS, zfs_evnodeops_template,
	    &zfs_evnodeops);

	return (error);
}

/*
 * zfs_init_fs - Initialize the zfsvfs struct and the file system
 *	incore "master" object.  Verify version compatibility.
 */
int
zfs_init_fs(zfsvfs_t *zfsvfs, znode_t **zpp, cred_t *cr)
{
	extern int zfsfstype;

	objset_t	*os = zfsvfs->z_os;
	uint64_t	zoid;
	uint64_t	version = ZFS_VERSION;
	int		i, error;
	dmu_object_info_t doi;
	dmu_objset_stats_t *stats;

	*zpp = NULL;

	/*
	 * XXX - hack to auto-create the pool root filesystem at
	 * the first attempted mount.
	 */
	if (dmu_object_info(os, MASTER_NODE_OBJ, &doi) == ENOENT) {
		dmu_tx_t *tx = dmu_tx_create(os);

		dmu_tx_hold_zap(tx, DMU_NEW_OBJECT, 3); /* master node */
		dmu_tx_hold_zap(tx, DMU_NEW_OBJECT, 1); /* delete queue */
		dmu_tx_hold_bonus(tx, DMU_NEW_OBJECT); /* root node */
		error = dmu_tx_assign(tx, TXG_WAIT);
		ASSERT3U(error, ==, 0);
		zfs_create_fs(os, cr, tx);
		dmu_tx_commit(tx);
	}

	if (zap_lookup(os, MASTER_NODE_OBJ, ZFS_VERSION_OBJ, 8, 1, &version)) {
		return (EINVAL);
	} else if (version != ZFS_VERSION) {
		(void) printf("Mismatched versions:  File system "
		    "is version %lld on-disk format, which is "
		    "incompatible with this software version %lld!",
		    (u_longlong_t)version, ZFS_VERSION);
		return (ENOTSUP);
	}

	/*
	 * The fsid is 64 bits, composed of an 8-bit fs type, which
	 * separates our fsid from any other filesystem types, and a
	 * 56-bit objset unique ID.  The objset unique ID is unique to
	 * all objsets open on this system, provided by unique_create().
	 * The 8-bit fs type must be put in the low bits of fsid[1]
	 * because that's where other Solaris filesystems put it.
	 */
	stats = kmem_alloc(sizeof (dmu_objset_stats_t), KM_SLEEP);
	dmu_objset_stats(os, stats);
	ASSERT((stats->dds_fsid_guid & ~((1ULL<<56)-1)) == 0);
	zfsvfs->z_vfs->vfs_fsid.val[0] = stats->dds_fsid_guid;
	zfsvfs->z_vfs->vfs_fsid.val[1] = ((stats->dds_fsid_guid>>32) << 8) |
	    zfsfstype & 0xFF;
	kmem_free(stats, sizeof (dmu_objset_stats_t));
	stats = NULL;

	if (zap_lookup(os, MASTER_NODE_OBJ, ZFS_ROOT_OBJ, 8, 1, &zoid)) {
		return (EINVAL);
	}
	ASSERT(zoid != 0);
	zfsvfs->z_root = zoid;

	/*
	 * Create the per mount vop tables.
	 */

	/*
	 * Initialize zget mutex's
	 */
	for (i = 0; i != ZFS_OBJ_MTX_SZ; i++)
		mutex_init(&zfsvfs->z_hold_mtx[i], NULL, MUTEX_DEFAULT, NULL);

	error = zfs_zget(zfsvfs, zoid, zpp);
	if (error)
		return (error);
	ASSERT3U((*zpp)->z_id, ==, zoid);

	if (zap_lookup(os, MASTER_NODE_OBJ, ZFS_DELETE_QUEUE, 8, 1, &zoid)) {
		return (EINVAL);
	}

	zfsvfs->z_dqueue = zoid;

	/*
	 * Initialize delete head structure
	 * Thread(s) will be started/stopped via
	 * readonly_changed_cb() depending
	 * on whether this is rw/ro mount.
	 */
	list_create(&zfsvfs->z_delete_head.z_znodes,
	    sizeof (znode_t), offsetof(znode_t, z_list_node));

	return (0);
}

/*
 * Construct a new znode/vnode and intialize.
 *
 * This does not do a call to dmu_set_user() that is
 * up to the caller to do, in case you don't want to
 * return the znode
 */
znode_t *
zfs_znode_alloc(zfsvfs_t *zfsvfs, dmu_buf_t *db, uint64_t obj_num, int blksz)
{
	znode_t	*zp;
	vnode_t *vp;

	zp = kmem_cache_alloc(znode_cache, KM_SLEEP);

	ASSERT(zp->z_dirlocks == NULL);

	zp->z_phys = db->db_data;
	zp->z_zfsvfs = zfsvfs;
	zp->z_active = 1;
	zp->z_reap = 0;
	zp->z_atime_dirty = 0;
	zp->z_dbuf_held = 0;
	zp->z_mapcnt = 0;
	zp->z_last_itx = 0;
	zp->z_dbuf = db;
	zp->z_id = obj_num;
	zp->z_blksz = blksz;
	zp->z_seq = 0x7A4653;

	bzero(&zp->z_zcache_node, sizeof (list_node_t));

	mutex_enter(&zfsvfs->z_znodes_lock);
	list_insert_tail(&zfsvfs->z_all_znodes, zp);
	mutex_exit(&zfsvfs->z_znodes_lock);

	vp = ZTOV(zp);
	vn_reinit(vp);

	vp->v_vfsp = zfsvfs->z_parent->z_vfs;
	vp->v_type = IFTOVT((mode_t)zp->z_phys->zp_mode);

	switch (vp->v_type) {
	case VDIR:
		if (zp->z_phys->zp_flags & ZFS_XATTR) {
			vn_setops(vp, zfs_xdvnodeops);
			vp->v_flag |= V_XATTRDIR;
		} else
			vn_setops(vp, zfs_dvnodeops);
		break;
	case VBLK:
	case VCHR:
		vp->v_rdev = (dev_t)zp->z_phys->zp_rdev;
		/*FALLTHROUGH*/
	case VFIFO:
	case VSOCK:
	case VDOOR:
		vn_setops(vp, zfs_fvnodeops);
		break;
	case VREG:
		vp->v_flag |= VMODSORT;
		vn_setops(vp, zfs_fvnodeops);
		break;
	case VLNK:
		vn_setops(vp, zfs_symvnodeops);
		break;
	default:
		vn_setops(vp, zfs_evnodeops);
		break;
	}

	return (zp);
}

static void
zfs_znode_dmu_init(znode_t *zp)
{
	znode_t		*nzp;
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	dmu_buf_t	*db = zp->z_dbuf;

	mutex_enter(&zp->z_lock);

	nzp = dmu_buf_set_user(db, zp, &zp->z_phys, znode_pageout_func);

	/*
	 * there should be no
	 * concurrent zgets on this object.
	 */
	ASSERT3P(nzp, ==, NULL);

	/*
	 * Slap on VROOT if we are the root znode
	 */
	if (zp->z_id == zfsvfs->z_root) {
		ZTOV(zp)->v_flag |= VROOT;
	}

	zp->z_zcache_state = NULL;
	zp->z_zcache_access = 0;

	ASSERT(zp->z_dbuf_held == 0);
	zp->z_dbuf_held = 1;
	VFS_HOLD(zfsvfs->z_vfs);
	mutex_exit(&zp->z_lock);
	vn_exists(ZTOV(zp));
}

/*
 * Create a new DMU object to hold a zfs znode.
 *
 *	IN:	dzp	- parent directory for new znode
 *		vap	- file attributes for new znode
 *		tx	- dmu transaction id for zap operations
 *		cr	- credentials of caller
 *		flag	- flags:
 *			  IS_ROOT_NODE	- new object will be root
 *			  IS_XATTR	- new object is an attribute
 *			  IS_REPLAY	- intent log replay
 *
 *	OUT:	oid	- ID of created object
 *
 */
void
zfs_mknode(znode_t *dzp, vattr_t *vap, uint64_t *oid, dmu_tx_t *tx, cred_t *cr,
	uint_t flag, znode_t **zpp, int bonuslen)
{
	dmu_buf_t	*dbp;
	znode_phys_t	*pzp;
	znode_t		*zp;
	zfsvfs_t	*zfsvfs = dzp->z_zfsvfs;
	timestruc_t	now;
	uint64_t	gen;
	int		err;

	ASSERT(vap && (vap->va_mask & (AT_TYPE|AT_MODE)) == (AT_TYPE|AT_MODE));

	if (zfsvfs->z_assign >= TXG_INITIAL) {		/* ZIL replay */
		*oid = vap->va_nodeid;
		flag |= IS_REPLAY;
		now = vap->va_ctime;		/* see zfs_replay_create() */
		gen = vap->va_nblocks;		/* ditto */
	} else {
		*oid = 0;
		gethrestime(&now);
		gen = dmu_tx_get_txg(tx);
	}

	/*
	 * Create a new DMU object.
	 */
	if (vap->va_type == VDIR) {
		if (flag & IS_REPLAY) {
			err = zap_create_claim(zfsvfs->z_os, *oid,
			    DMU_OT_DIRECTORY_CONTENTS,
			    DMU_OT_ZNODE, sizeof (znode_phys_t) + bonuslen, tx);
			ASSERT3U(err, ==, 0);
		} else {
			*oid = zap_create(zfsvfs->z_os,
			    DMU_OT_DIRECTORY_CONTENTS,
			    DMU_OT_ZNODE, sizeof (znode_phys_t) + bonuslen, tx);
		}
	} else {
		if (flag & IS_REPLAY) {
			err = dmu_object_claim(zfsvfs->z_os, *oid,
			    DMU_OT_PLAIN_FILE_CONTENTS, 0,
			    DMU_OT_ZNODE, sizeof (znode_phys_t) + bonuslen, tx);
			ASSERT3U(err, ==, 0);
		} else {
			*oid = dmu_object_alloc(zfsvfs->z_os,
			    DMU_OT_PLAIN_FILE_CONTENTS, 0,
			    DMU_OT_ZNODE, sizeof (znode_phys_t) + bonuslen, tx);
		}
	}
	dbp = dmu_bonus_hold(zfsvfs->z_os, *oid);
	dmu_buf_will_dirty(dbp, tx);

	/*
	 * Initialize the znode physical data to zero.
	 */
	ASSERT(dbp->db_size >= sizeof (znode_phys_t));
	bzero(dbp->db_data, dbp->db_size);
	pzp = dbp->db_data;

	/*
	 * If this is the root, fix up the half-initialized parent pointer
	 * to reference the just-allocated physical data area.
	 */
	if (flag & IS_ROOT_NODE) {
		dzp->z_phys = pzp;
		dzp->z_id = *oid;
	}

	/*
	 * If parent is an xattr, so am I.
	 */
	if (dzp->z_phys->zp_flags & ZFS_XATTR)
		flag |= IS_XATTR;

	if (vap->va_type == VBLK || vap->va_type == VCHR) {
		pzp->zp_rdev = vap->va_rdev;
	}

	if (vap->va_type == VDIR) {
		pzp->zp_size = 2;		/* contents ("." and "..") */
		pzp->zp_links = (flag & (IS_ROOT_NODE | IS_XATTR)) ? 2 : 1;
	}

	pzp->zp_parent = dzp->z_id;
	if (flag & IS_XATTR)
		pzp->zp_flags |= ZFS_XATTR;

	pzp->zp_gen = gen;

	ZFS_TIME_ENCODE(&now, pzp->zp_crtime);
	ZFS_TIME_ENCODE(&now, pzp->zp_ctime);

	if (vap->va_mask & AT_ATIME) {
		ZFS_TIME_ENCODE(&vap->va_atime, pzp->zp_atime);
	} else {
		ZFS_TIME_ENCODE(&now, pzp->zp_atime);
	}

	if (vap->va_mask & AT_MTIME) {
		ZFS_TIME_ENCODE(&vap->va_mtime, pzp->zp_mtime);
	} else {
		ZFS_TIME_ENCODE(&now, pzp->zp_mtime);
	}

	pzp->zp_mode = MAKEIMODE(vap->va_type, vap->va_mode);
	zp = zfs_znode_alloc(zfsvfs, dbp, *oid, 0);

	zfs_perm_init(zp, dzp, flag, vap, tx, cr);

	if (zpp) {
		kmutex_t *hash_mtx = ZFS_OBJ_MUTEX(zp);

		mutex_enter(hash_mtx);
		zfs_znode_dmu_init(zp);
		zcache_access(zp, hash_mtx);
		*zpp = zp;
	} else {
		ZTOV(zp)->v_count = 0;
		dmu_buf_rele(dbp);
		zfs_znode_free(zp);
	}
}

int
zfs_zget(zfsvfs_t *zfsvfs, uint64_t obj_num, znode_t **zpp)
{
	dmu_object_info_t doi;
	dmu_buf_t	*db;
	znode_t		*zp;

	*zpp = NULL;

	ZFS_OBJ_HOLD_ENTER(zfsvfs, obj_num);

	db = dmu_bonus_hold(zfsvfs->z_os, obj_num);
	if (db == NULL) {
		ZFS_OBJ_HOLD_EXIT(zfsvfs, obj_num);
		return (ENOENT);
	}

	dmu_object_info_from_db(db, &doi);
	if (doi.doi_bonus_type != DMU_OT_ZNODE ||
	    doi.doi_bonus_size < sizeof (znode_phys_t)) {
		dmu_buf_rele(db);
		ZFS_OBJ_HOLD_EXIT(zfsvfs, obj_num);
		return (EINVAL);
	}
	dmu_buf_read(db);

	ASSERT(db->db_object == obj_num);
	ASSERT(db->db_offset == -1);
	ASSERT(db->db_data != NULL);

	zp = dmu_buf_get_user(db);

	if (zp != NULL) {
		mutex_enter(&zp->z_lock);

		ASSERT3U(zp->z_id, ==, obj_num);
		if (zp->z_reap) {
			dmu_buf_rele(db);
			mutex_exit(&zp->z_lock);
			ZFS_OBJ_HOLD_EXIT(zfsvfs, obj_num);
			return (ENOENT);
		} else if (zp->z_dbuf_held) {
			dmu_buf_rele(db);
		} else {
			zp->z_dbuf_held = 1;
			VFS_HOLD(zfsvfs->z_vfs);
		}

		if (zp->z_active == 0) {
			zp->z_active = 1;
			if (list_link_active(&zp->z_zcache_node)) {
				mutex_enter(&zp->z_zcache_state->mtx);
				list_remove(&zp->z_zcache_state->list, zp);
				zp->z_zcache_state->lcnt -= 1;
				mutex_exit(&zp->z_zcache_state->mtx);
			}
		}
		VN_HOLD(ZTOV(zp));
		mutex_exit(&zp->z_lock);
		zcache_access(zp, ZFS_OBJ_MUTEX(zp));
		*zpp = zp;
		return (0);
	}

	/*
	 * Not found create new znode/vnode
	 */
	zp = zfs_znode_alloc(zfsvfs, db, obj_num, doi.doi_data_block_size);
	ASSERT3U(zp->z_id, ==, obj_num);
	zfs_znode_dmu_init(zp);
	zcache_access(zp, ZFS_OBJ_MUTEX(zp));
	*zpp = zp;
	return (0);
}

void
zfs_znode_delete(znode_t *zp, dmu_tx_t *tx)
{
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	int error;

	ZFS_OBJ_HOLD_ENTER(zfsvfs, zp->z_id);
	if (zp->z_phys->zp_acl.z_acl_extern_obj) {
		error = dmu_object_free(zfsvfs->z_os,
		    zp->z_phys->zp_acl.z_acl_extern_obj, tx);
		ASSERT3U(error, ==, 0);
	}
	if (zp->z_zcache_state) {
		ASSERT3U(zp->z_zcache_state->cnt, >=, 1);
		atomic_add_64(&zp->z_zcache_state->cnt, -1);
	}
	error = dmu_object_free(zfsvfs->z_os, zp->z_id, tx);
	ASSERT3U(error, ==, 0);
	zp->z_dbuf_held = 0;
	ZFS_OBJ_HOLD_EXIT(zfsvfs, zp->z_id);
	dmu_buf_rele(zp->z_dbuf);
}

void
zfs_zinactive(znode_t *zp)
{
	vnode_t	*vp = ZTOV(zp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	uint64_t z_id = zp->z_id;

	ASSERT(zp->z_dbuf_held && zp->z_phys);

	/*
	 * Don't allow a zfs_zget() while were trying to release this znode
	 */
	ZFS_OBJ_HOLD_ENTER(zfsvfs, z_id);

	mutex_enter(&zp->z_lock);
	mutex_enter(&vp->v_lock);
	vp->v_count--;
	if (vp->v_count > 0 || vn_has_cached_data(vp)) {
		/*
		 * If the hold count is greater than zero, somebody has
		 * obtained a new reference on this znode while we were
		 * processing it here, so we are done.  If we still have
		 * mapped pages then we are also done, since we don't
		 * want to inactivate the znode until the pages get pushed.
		 *
		 * XXX - if vn_has_cached_data(vp) is true, but count == 0,
		 * this seems like it would leave the znode hanging with
		 * no chance to go inactive...
		 */
		mutex_exit(&vp->v_lock);
		mutex_exit(&zp->z_lock);
		ZFS_OBJ_HOLD_EXIT(zfsvfs, z_id);
		return;
	}
	mutex_exit(&vp->v_lock);
	zp->z_active = 0;

	/*
	 * If this was the last reference to a file with no links,
	 * remove the file from the file system.
	 */
	if (zp->z_reap) {
		mutex_exit(&zp->z_lock);
		ZFS_OBJ_HOLD_EXIT(zfsvfs, z_id);
		ASSERT3U(zp->z_zcache_state->cnt, >=, 1);
		atomic_add_64(&zp->z_zcache_state->cnt, -1);
		zp->z_zcache_state = NULL;
		/* XATTR files are not put on the delete queue */
		if (zp->z_phys->zp_flags & ZFS_XATTR) {
			zfs_rmnode(zp);
		} else {
			mutex_enter(&zfsvfs->z_delete_head.z_mutex);
			list_insert_tail(&zfsvfs->z_delete_head.z_znodes, zp);
			zfsvfs->z_delete_head.z_znode_count++;
			cv_broadcast(&zfsvfs->z_delete_head.z_cv);
			mutex_exit(&zfsvfs->z_delete_head.z_mutex);
		}
		VFS_RELE(zfsvfs->z_vfs);
		return;
	}

	/*
	 * If the file system for this znode is no longer mounted,
	 * evict the znode now, don't put it in the cache.
	 */
	if (zfsvfs->z_unmounted1) {
		zfs_zcache_evict(zp, ZFS_OBJ_MUTEX(zp));
		return;
	}

	/* put znode on evictable list */
	mutex_enter(&zp->z_zcache_state->mtx);
	list_insert_head(&zp->z_zcache_state->list, zp);
	zp->z_zcache_state->lcnt += 1;
	mutex_exit(&zp->z_zcache_state->mtx);
	mutex_exit(&zp->z_lock);
	ZFS_OBJ_HOLD_EXIT(zfsvfs, z_id);
}

void
zfs_znode_free(znode_t *zp)
{
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;

	mutex_enter(&zfsvfs->z_znodes_lock);
	list_remove(&zfsvfs->z_all_znodes, zp);
	mutex_exit(&zfsvfs->z_znodes_lock);

	kmem_cache_free(znode_cache, zp);
}

void
zfs_time_stamper_locked(znode_t *zp, uint_t flag, dmu_tx_t *tx)
{
	timestruc_t	now;

	ASSERT(MUTEX_HELD(&zp->z_lock));

	gethrestime(&now);

	if (tx) {
		dmu_buf_will_dirty(zp->z_dbuf, tx);
		zp->z_atime_dirty = 0;
		zp->z_seq++;
	} else {
		zp->z_atime_dirty = 1;
	}

	if (flag & AT_ATIME)
		ZFS_TIME_ENCODE(&now, zp->z_phys->zp_atime);

	if (flag & AT_MTIME)
		ZFS_TIME_ENCODE(&now, zp->z_phys->zp_mtime);

	if (flag & AT_CTIME)
		ZFS_TIME_ENCODE(&now, zp->z_phys->zp_ctime);
}

/*
 * Update the requested znode timestamps with the current time.
 * If we are in a transaction, then go ahead and mark the znode
 * dirty in the transaction so the timestamps will go to disk.
 * Otherwise, we will get pushed next time the znode is updated
 * in a transaction, or when this znode eventually goes inactive.
 *
 * Why is this OK?
 *  1 - Only the ACCESS time is ever updated outside of a transaction.
 *  2 - Multiple consecutive updates will be collapsed into a single
 *	znode update by the transaction grouping semantics of the DMU.
 */
void
zfs_time_stamper(znode_t *zp, uint_t flag, dmu_tx_t *tx)
{
	mutex_enter(&zp->z_lock);
	zfs_time_stamper_locked(zp, flag, tx);
	mutex_exit(&zp->z_lock);
}

/*
 * Grow the block size for a file.  This may involve migrating data
 * from the bonus buffer into a data block (when we grow beyond the
 * bonus buffer data area).
 *
 *	IN:	zp	- znode of file to free data in.
 *		size	- requested block size
 *		tx	- open transaction.
 *
 * 	RETURN:	0 if success
 *		error code if failure
 *
 * NOTE: this function assumes that the znode is write locked.
 */
int
zfs_grow_blocksize(znode_t *zp, uint64_t size, dmu_tx_t *tx)
{
	int		error;
	u_longlong_t	dummy;

	ASSERT(rw_write_held(&zp->z_grow_lock));

	if (size <= zp->z_blksz)
		return (0);
	/*
	 * If the file size is already greater than the current blocksize,
	 * we will not grow.  If there is more than one block in a file,
	 * the blocksize cannot change.
	 */
	if (zp->z_blksz && zp->z_phys->zp_size > zp->z_blksz)
		return (0);

	error = dmu_object_set_blocksize(zp->z_zfsvfs->z_os, zp->z_id,
	    size, 0, tx);
	if (error == ENOTSUP)
		return (0);
	ASSERT3U(error, ==, 0);

	/* What blocksize did we actually get? */
	dmu_object_size_from_db(zp->z_dbuf, &zp->z_blksz, &dummy);

	return (0);
}

/*
 * This is a dummy interface used when pvn_vplist_dirty() should *not*
 * be calling back into the fs for a putpage().  E.g.: when truncating
 * a file, the pages being "thrown away* don't need to be written out.
 */
/* ARGSUSED */
static int
zfs_no_putpage(vnode_t *vp, page_t *pp, u_offset_t *offp, size_t *lenp,
    int flags, cred_t *cr)
{
	ASSERT(0);
	return (0);
}

/*
 * Free space in a file.  Currently, this function only
 * supports freeing space at the end of the file.
 *
 *	IN:	zp	- znode of file to free data in.
 *		from	- start of section to free.
 *		len	- length of section to free (0 => to EOF).
 *		flag	- current file open mode flags.
 *		tx	- open transaction.
 *
 * 	RETURN:	0 if success
 *		error code if failure
 */
int
zfs_freesp(znode_t *zp, uint64_t from, uint64_t len, int flag, dmu_tx_t *tx,
	cred_t *cr)
{
	vnode_t *vp = ZTOV(zp);
	uint64_t size = zp->z_phys->zp_size;
	uint64_t end = from + len;
	int have_grow_lock, error;

	have_grow_lock = RW_WRITE_HELD(&zp->z_grow_lock);

	/*
	 * Nothing to do if file already at desired length.
	 */
	if (len == 0 && size == from) {
		return (0);
	}

	/*
	 * Check for any locks in the region to be freed.
	 */
	if (MANDLOCK(vp, (mode_t)zp->z_phys->zp_mode)) {
		uint64_t	start;

		if (size > from)
			start = from;
		else
			start = size;
		if (error = chklock(vp, FWRITE, start, 0, flag, NULL))
			return (error);
	}

	if (end > zp->z_blksz && (!ISP2(zp->z_blksz) ||
	    zp->z_blksz < zp->z_zfsvfs->z_max_blksz)) {
		uint64_t new_blksz;
		/*
		 * We are growing the file past the current block size.
		 */
		if (zp->z_blksz > zp->z_zfsvfs->z_max_blksz) {
			ASSERT(!ISP2(zp->z_blksz));
			new_blksz = MIN(end, SPA_MAXBLOCKSIZE);
		} else {
			new_blksz = MIN(end, zp->z_zfsvfs->z_max_blksz);
		}
		error = zfs_grow_blocksize(zp, new_blksz, tx);
		ASSERT(error == 0);
	}
	if (end > size || len == 0)
		zp->z_phys->zp_size = end;
	if (from > size)
		return (0);

	if (have_grow_lock)
		rw_downgrade(&zp->z_grow_lock);
	/*
	 * Clear any mapped pages in the truncated region.
	 */
	rw_enter(&zp->z_map_lock, RW_WRITER);
	if (vn_has_cached_data(vp)) {
		page_t *pp;
		uint64_t start = from & PAGEMASK;
		int off = from & PAGEOFFSET;

		if (off != 0 && (pp = page_lookup(vp, start, SE_SHARED))) {
			/*
			 * We need to zero a partial page.
			 */
			pagezero(pp, off, PAGESIZE - off);
			start += PAGESIZE;
			page_unlock(pp);
		}
		error = pvn_vplist_dirty(vp, start, zfs_no_putpage,
		    B_INVAL | B_TRUNC, cr);
		ASSERT(error == 0);
	}
	rw_exit(&zp->z_map_lock);

	if (!have_grow_lock)
		rw_enter(&zp->z_grow_lock, RW_READER);

	if (len == 0)
		len = -1;
	else if (end > size)
		len = size - from;
	dmu_free_range(zp->z_zfsvfs->z_os, zp->z_id, from, len, tx);

	if (!have_grow_lock)
		rw_exit(&zp->z_grow_lock);

	return (0);
}


void
zfs_create_fs(objset_t *os, cred_t *cr, dmu_tx_t *tx)
{
	zfsvfs_t	zfsvfs;
	uint64_t	moid, doid, roid = 0;
	uint64_t	version = ZFS_VERSION;
	int		error;
	znode_t		*rootzp = NULL;
	vnode_t		*vp;
	vattr_t		vattr;

	/*
	 * First attempt to create master node.
	 */
	moid = MASTER_NODE_OBJ;
	error = zap_create_claim(os, moid, DMU_OT_MASTER_NODE,
	    DMU_OT_NONE, 0, tx);
	ASSERT(error == 0);

	/*
	 * Set starting attributes.
	 */

	error = zap_update(os, moid, ZFS_VERSION_OBJ, 8, 1, &version, tx);
	ASSERT(error == 0);

	/*
	 * Create a delete queue.
	 */
	doid = zap_create(os, DMU_OT_DELETE_QUEUE, DMU_OT_NONE, 0, tx);

	error = zap_add(os, moid, ZFS_DELETE_QUEUE, 8, 1, &doid, tx);
	ASSERT(error == 0);

	/*
	 * Create root znode.  Create minimal znode/vnode/zfsvfs
	 * to allow zfs_mknode to work.
	 */
	vattr.va_mask = AT_MODE|AT_UID|AT_GID|AT_TYPE;
	vattr.va_type = VDIR;
	vattr.va_mode = S_IFDIR|0755;
	vattr.va_uid = 0;
	vattr.va_gid = 3;

	rootzp = kmem_cache_alloc(znode_cache, KM_SLEEP);
	rootzp->z_zfsvfs = &zfsvfs;
	rootzp->z_active = 1;
	rootzp->z_reap = 0;
	rootzp->z_atime_dirty = 0;
	rootzp->z_dbuf_held = 0;

	vp = ZTOV(rootzp);
	vn_reinit(vp);
	vp->v_type = VDIR;

	bzero(&zfsvfs, sizeof (zfsvfs_t));

	zfsvfs.z_os = os;
	zfsvfs.z_assign = TXG_NOWAIT;
	zfsvfs.z_parent = &zfsvfs;

	mutex_init(&zfsvfs.z_znodes_lock, NULL, MUTEX_DEFAULT, NULL);
	list_create(&zfsvfs.z_all_znodes, sizeof (znode_t),
	    offsetof(znode_t, z_link_node));

	zfs_mknode(rootzp, &vattr, &roid, tx, cr, IS_ROOT_NODE, NULL, 0);
	ASSERT3U(rootzp->z_id, ==, roid);
	error = zap_add(os, moid, ZFS_ROOT_OBJ, 8, 1, &roid, tx);
	ASSERT(error == 0);

	ZTOV(rootzp)->v_count = 0;
	kmem_cache_free(znode_cache, rootzp);
}
