/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/cred.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/t_lock.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/file.h>
#include <sys/pathname.h>
#include <sys/sysmacros.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/avl.h>
#include <sys/stat.h>
#include <sys/mode.h>

#include <fcntl.h>
#include <unistd.h>

#include "vncache.h"

kmem_cache_t *vn_cache;

/*
 * You can dump this AVL tree with mdb, i.e.
 * vncache_avl ::walk avl |::print -s1 vnode_t
 */
avl_tree_t vncache_avl;
kmutex_t vncache_lock;

/*
 * Vnode cache.
 */

/* ARGSUSED */
static int
vn_cache_constructor(void *buf, void *cdrarg, int kmflags)
{
	struct vnode *vp;

	vp = buf;
	bzero(vp, sizeof (*vp));

	mutex_init(&vp->v_lock, NULL, MUTEX_DEFAULT, NULL);
	vp->v_fd = -1;

	return (0);
}

/* ARGSUSED */
static void
vn_cache_destructor(void *buf, void *cdrarg)
{
	struct vnode *vp;

	vp = buf;

	mutex_destroy(&vp->v_lock);
}

/*
 * Used by file systems when fs-specific nodes (e.g., ufs inodes) are
 * cached by the file system and vnodes remain associated.
 */
void
vn_recycle(vnode_t *vp)
{

	ASSERT(vp->v_fd == -1);

	vp->v_rdcnt = 0;
	vp->v_wrcnt = 0;

	if (vp->v_path) {
		strfree(vp->v_path);
		vp->v_path = NULL;
	}
}


/*
 * Used to reset the vnode fields including those that are directly accessible
 * as well as those which require an accessor function.
 *
 * Does not initialize:
 *	synchronization objects: v_lock, v_vsd_lock, v_nbllock, v_cv
 *	v_data (since FS-nodes and vnodes point to each other and should
 *		be updated simultaneously)
 *	v_op (in case someone needs to make a VOP call on this object)
 */
void
vn_reinit(vnode_t *vp)
{
	vp->v_count = 1;
	vp->v_vfsp = NULL;
	vp->v_stream = NULL;
	vp->v_flag = 0;
	vp->v_type = VNON;
	vp->v_rdev = NODEV;

	vn_recycle(vp);
}

vnode_t *
vn_alloc(int kmflag)
{
	vnode_t *vp;

	vp = kmem_cache_alloc(vn_cache, kmflag);

	if (vp != NULL) {
		vn_reinit(vp);
	}

	return (vp);
}

void
vn_free(vnode_t *vp)
{

	/*
	 * Some file systems call vn_free() with v_count of zero,
	 * some with v_count of 1.  In any case, the value should
	 * never be anything else.
	 */
	ASSERT((vp->v_count == 0) || (vp->v_count == 1));
	if (vp->v_path != NULL) {
		strfree(vp->v_path);
		vp->v_path = NULL;
	}
	ASSERT(vp->v_fd != -1);
	(void) close(vp->v_fd);
	vp->v_fd = -1;

	kmem_cache_free(vn_cache, vp);
}

int
vncache_cmp(const void *v1, const void *v2)
{
	const vnode_t *vp1, *vp2;

	vp1 = v1;
	vp2 = v2;

	if (vp1->v_st_dev < vp2->v_st_dev)
		return (-1);
	if (vp1->v_st_dev > vp2->v_st_dev)
		return (+1);
	if (vp1->v_st_ino < vp2->v_st_ino)
		return (-1);
	if (vp1->v_st_ino > vp2->v_st_ino)
		return (+1);

	return (0);
}

vnode_t *
vncache_lookup(struct stat *st)
{
	vnode_t tmp_vn;
	vnode_t *vp;

	tmp_vn.v_st_dev = st->st_dev;
	tmp_vn.v_st_ino = st->st_ino;

	mutex_enter(&vncache_lock);
	vp = avl_find(&vncache_avl, &tmp_vn, NULL);
	if (vp != NULL)
		vn_hold(vp);
	mutex_exit(&vncache_lock);

	return (vp);
}

vnode_t *
vncache_enter(struct stat *st, vnode_t *dvp, char *name, int fd)
{
	vnode_t *old_vp;
	vnode_t *new_vp;
	vfs_t *vfs;
	char *vpath;
	avl_index_t	where;
	int len;

	/*
	 * Fill in v_path
	 * Note: fsop_root() calls with dvp=NULL
	 */
	len = strlen(name) + 1;
	if (dvp == NULL) {
		vpath = kmem_alloc(len, KM_SLEEP);
		(void) strlcpy(vpath, name, len);
		vfs = rootvfs;
	} else {
		/* add to length for parent path + "/" */
		len += (strlen(dvp->v_path) + 1);
		vpath = kmem_alloc(len, KM_SLEEP);
		(void) snprintf(vpath, len, "%s/%s", dvp->v_path, name);
		vfs = dvp->v_vfsp;
	}

	new_vp = vn_alloc(KM_SLEEP);
	new_vp->v_path = vpath;
	new_vp->v_fd = fd;
	new_vp->v_st_dev = st->st_dev;
	new_vp->v_st_ino = st->st_ino;
	new_vp->v_vfsp = vfs;
	new_vp->v_type = IFTOVT(st->st_mode);

	mutex_enter(&vncache_lock);
	old_vp = avl_find(&vncache_avl, new_vp, &where);
	if (old_vp != NULL)
		vn_hold(old_vp);
	else
		avl_insert(&vncache_avl, new_vp, where);
	mutex_exit(&vncache_lock);

	/* If we lost the race, free new_vp */
	if (old_vp != NULL) {
		vn_free(new_vp);
		return (old_vp);
	}

	return (new_vp);
}

/*
 * Called after a successful rename to update v_path
 */
void
vncache_renamed(vnode_t *vp, vnode_t *to_dvp, char *to_name)
{
	char *vpath;
	char *ovpath;
	int len;

	len = strlen(to_name) + 1;
	/* add to length for parent path + "/" */
	len += (strlen(to_dvp->v_path) + 1);
	vpath = kmem_alloc(len, KM_SLEEP);
	(void) snprintf(vpath, len, "%s/%s", to_dvp->v_path, to_name);

	mutex_enter(&vncache_lock);
	ovpath = vp->v_path;
	vp->v_path = vpath;
	mutex_exit(&vncache_lock);

	strfree(ovpath);
}

/*
 * Last reference to this vnode is (possibly) going away.
 * This is normally called by vn_rele() when v_count==1.
 * Note that due to lock order concerns, we have to take
 * the vncache_lock (for the avl tree) and then recheck
 * v_count, which might have gained a ref during the time
 * we did not hold vp->v_lock.
 */
void
vncache_inactive(vnode_t *vp)
{
	uint_t count;

	mutex_enter(&vncache_lock);
	mutex_enter(&vp->v_lock);

	if ((count = vp->v_count) <= 1) {
		/* This is (still) the last ref. */
		avl_remove(&vncache_avl, vp);
	}

	mutex_exit(&vp->v_lock);
	mutex_exit(&vncache_lock);

	if (count <= 1) {
		vn_free(vp);
	}
}

#pragma init(vncache_init)
int
vncache_init(void)
{
	vn_cache = kmem_cache_create("vn_cache", sizeof (struct vnode),
	    VNODE_ALIGN, vn_cache_constructor, vn_cache_destructor, NULL, NULL,
	    NULL, 0);
	avl_create(&vncache_avl,
	    vncache_cmp,
	    sizeof (vnode_t),
	    offsetof(vnode_t, v_avl_node));
	mutex_init(&vncache_lock, NULL, MUTEX_DEFAULT, NULL);
	return (0);
}

#pragma fini(vncache_fini)
void
vncache_fini(void)
{
	mutex_destroy(&vncache_lock);
	avl_destroy(&vncache_avl);
	kmem_cache_destroy(vn_cache);
}
