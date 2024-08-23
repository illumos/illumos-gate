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
 * Copyright 2024 RackTop Systems, Inc.
 */

/*
 * The SMB server supports its local file system operations using
 * kernel-style VOP_... calls.  This layer simulates creating and
 * finding vnodes for "libfksmbsrv".
 *
 * The vnodes manged here are always paired with a private struct
 * (see fakefs_node_t) to hold the details we need to find them
 * in our cache and the file descriptor used in simulations.
 *
 * The actual VOP_... and VFS_... call simulations are in other
 * files, generall named after the original kernel ones.
 * (eg. fake_vfs.c)
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

#define	VTOF(vp)	((struct fakefs_node *)(vp)->v_data)
#define	FTOV(fnp)	((fnp)->fn_vnode)

/* Private to the fake vnode impl. */
typedef struct fakefs_node {
	avl_node_t	fn_avl_node;
	vnode_t		*fn_vnode;
	dev_t		fn_st_dev;
	ino_t		fn_st_ino;
	int		fn_fd;
	int		fn_mode;
} fakefs_node_t;

typedef struct fnode_vnode {
	struct fakefs_node fn;
	struct vnode vn;
} fnode_vnode_t;

/*
 * You can dump this AVL tree with mdb, i.e.
 * fncache_avl ::walk avl |::print fakefs_node_t
 * fncache_avl ::walk avl |::print fnode_vnode_t fn vn.v_path
 */
avl_tree_t fncache_avl;
kmutex_t fncache_lock;

/*
 * Fake node / vnode cache.
 */
kmem_cache_t *fn_cache;

/* ARGSUSED */
static int
fn_cache_constructor(void *buf, void *cdrarg, int kmflags)
{
	fnode_vnode_t *fvp = buf;

	bzero(fvp, sizeof (*fvp));

	fvp->fn.fn_vnode = &fvp->vn;
	fvp->fn.fn_fd = -1;

	fvp->vn.v_data = &fvp->fn;
	mutex_init(&fvp->vn.v_lock, NULL, MUTEX_DEFAULT, NULL);

	return (0);
}

/* ARGSUSED */
static void
fn_cache_destructor(void *buf, void *cdrarg)
{
	fnode_vnode_t *fvp = buf;
	mutex_destroy(&fvp->vn.v_lock);
}

/*
 * Used by file systems when fs-specific nodes (e.g., ufs inodes) are
 * cached by the file system and vnodes remain associated.
 */
void
vn_recycle(vnode_t *vp)
{
	fakefs_node_t *fnp = VTOF(vp);

	ASSERT(fnp->fn_fd == -1);

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
	fnode_vnode_t *fvp;
	vnode_t *vp = NULL;

	fvp = kmem_cache_alloc(fn_cache, kmflag);
	if (fvp != NULL) {
		vp = &fvp->vn;
		vn_reinit(vp);
	}

	return (vp);
}

void
vn_free(vnode_t *vp)
{
	fakefs_node_t *fnp = VTOF(vp);

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
	ASSERT(fnp->fn_fd > 2);
	(void) close(fnp->fn_fd);
	fnp->fn_fd = -1;

	/*
	 * Make sure fnp points to the beginning of fnode_vnode_t,
	 * which is what we must pass to kmem_cache_free.
	 */
	CTASSERT(offsetof(fnode_vnode_t, fn) == 0);
	kmem_cache_free(fn_cache, fnp);
}

static int
fncache_cmp(const void *v1, const void *v2)
{
	const fakefs_node_t *np1 = v1;
	const fakefs_node_t *np2 = v2;

	/* The args are really fnode_vnode_t */
	CTASSERT(offsetof(fnode_vnode_t, fn) == 0);

	if (np1->fn_st_dev < np2->fn_st_dev)
		return (-1);
	if (np1->fn_st_dev > np2->fn_st_dev)
		return (+1);
	if (np1->fn_st_ino < np2->fn_st_ino)
		return (-1);
	if (np1->fn_st_ino > np2->fn_st_ino)
		return (+1);

	return (0);
}

int
vncache_cmp(const vnode_t *vp1, const vnode_t *vp2)
{
	fakefs_node_t *np1 = VTOF(vp1);
	fakefs_node_t *np2 = VTOF(vp2);
	return (fncache_cmp(np1, np2));
}

vnode_t *
vncache_lookup(struct stat *st)
{
	fakefs_node_t tmp_fn;
	fakefs_node_t *fnp;
	vnode_t *vp = NULL;

	tmp_fn.fn_st_dev = st->st_dev;
	tmp_fn.fn_st_ino = st->st_ino;

	mutex_enter(&fncache_lock);
	fnp = avl_find(&fncache_avl, &tmp_fn, NULL);
	if (fnp != NULL) {
		vp = FTOV(fnp);
		VN_HOLD(vp);
	}
	mutex_exit(&fncache_lock);

	return (vp);
}

vnode_t *
vncache_enter(struct stat *st, vnode_t *dvp, char *name, int fd)
{
	vnode_t *old_vp;
	vnode_t *new_vp;
	fakefs_node_t *old_fnp;
	fakefs_node_t *new_fnp;
	vfs_t *vfs;
	char *vpath;
	avl_index_t	where;
	int len;

	ASSERT(fd > 2);

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

	/* Note: (vp : fnp) linkage setup in constructor */
	new_vp = vn_alloc(KM_SLEEP);
	new_vp->v_path = vpath;
	new_vp->v_vfsp = vfs;
	new_vp->v_type = IFTOVT(st->st_mode);
	new_fnp = VTOF(new_vp);
	new_fnp->fn_fd = fd;
	new_fnp->fn_st_dev = st->st_dev;
	new_fnp->fn_st_ino = st->st_ino;

	old_vp = NULL;
	mutex_enter(&fncache_lock);
	old_fnp = avl_find(&fncache_avl, new_fnp, &where);
	if (old_fnp != NULL) {
		DTRACE_PROBE1(found, fakefs_node_t *, old_fnp);
		old_vp = FTOV(old_fnp);
		VN_HOLD(old_vp);
	} else {
		DTRACE_PROBE1(insert, fakefs_node_t *, new_fnp);
		avl_insert(&fncache_avl, new_fnp, where);
	}
	mutex_exit(&fncache_lock);

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

	mutex_enter(&fncache_lock);
	ovpath = vp->v_path;
	vp->v_path = vpath;
	mutex_exit(&fncache_lock);

	strfree(ovpath);
}

/*
 * Last reference to this vnode is (possibly) going away.
 * This is normally called by vn_rele() when v_count==1.
 * Note that due to lock order concerns, we have to take
 * the fncache_lock (for the avl tree) and then recheck
 * v_count, which might have gained a ref during the time
 * we did not hold vp->v_lock.
 */
void
vncache_inactive(vnode_t *vp)
{
	fakefs_node_t *fnp = VTOF(vp);
	vnode_t *xvp;
	uint_t count;

	mutex_enter(&fncache_lock);
	mutex_enter(&vp->v_lock);

	if ((count = vp->v_count) <= 1) {
		/* This is (still) the last ref. */
		DTRACE_PROBE1(remove, fakefs_node_t *, fnp);
		avl_remove(&fncache_avl, fnp);
	}

	mutex_exit(&vp->v_lock);
	mutex_exit(&fncache_lock);

	if (count > 1)
		return;

	/*
	 * See fake_lookup_xattrdir()
	 */
	xvp = vp->v_xattrdir;
	vp->v_xattrdir = NULL;
	vn_free(vp);

	if (xvp != NULL) {
		ASSERT((xvp->v_flag & V_XATTRDIR) != 0);
		VN_RELE(xvp);
	}
}

int
vncache_getfd(vnode_t *vp)
{
	fakefs_node_t *fnp = VTOF(vp);
	ASSERT(fnp->fn_fd > 2);
	return (fnp->fn_fd);
}

/*
 * See fake_lookup_xattrdir()
 * Special case vnode creation.
 */
void
vncache_setfd(vnode_t *vp, int fd)
{
	fakefs_node_t *fnp = VTOF(vp);
	ASSERT(fnp->fn_fd == -1);
	ASSERT(fd > 2);
	fnp->fn_fd = fd;
}


int
vncache_init(void)
{
	fn_cache = kmem_cache_create("fn_cache", sizeof (fnode_vnode_t),
	    VNODE_ALIGN, fn_cache_constructor, fn_cache_destructor,
	    NULL, NULL, NULL, 0);
	avl_create(&fncache_avl,
	    fncache_cmp,
	    sizeof (fnode_vnode_t),
	    offsetof(fnode_vnode_t, fn.fn_avl_node));
	mutex_init(&fncache_lock, NULL, MUTEX_DEFAULT, NULL);
	return (0);
}

void
vncache_fini(void)
{
	mutex_destroy(&fncache_lock);
	avl_destroy(&fncache_avl);
	kmem_cache_destroy(fn_cache);
}
