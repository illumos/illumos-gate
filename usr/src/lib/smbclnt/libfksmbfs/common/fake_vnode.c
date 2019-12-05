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
 * Copyright (c) 1988, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2017, Joyent, Inc.
 * Copyright (c) 2011, 2017 by Delphix. All rights reserved.
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*
 * This file contains those functions from fs/vnode.c that can be
 * used with relatively little change.  Functions that differ
 * significantly from that are in other files.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/t_lock.h>
#include <sys/errno.h>
#include <sys/cred.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/file.h>
#include <sys/pathname.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/vnode.h>
#include <sys/rwstlock.h>
#include <sys/fem.h>
#include <sys/stat.h>
#include <sys/mode.h>
#include <sys/conf.h>
#include <sys/sysmacros.h>
#include <sys/cmn_err.h>
#include <sys/systm.h>
#include <sys/kmem.h>
#include <sys/atomic.h>
#include <sys/debug.h>
#include <sys/acl.h>
#include <sys/nbmlock.h>
#include <sys/fcntl.h>
#include <sys/time.h>
#include <fs/fs_subr.h>
#include <fs/fs_reparse.h>

#include <libfksmbfs.h>

/* Determine if this vnode is a file that is read-only */
#define	ISROFILE(vp)	\
	((vp)->v_type != VCHR && (vp)->v_type != VBLK && \
	    (vp)->v_type != VFIFO && vn_is_readonly(vp))

#define	VOPSTATS_UPDATE(vp, counter) ((void)vp)
#define	VOPSTATS_UPDATE_IO(vp, counter, bytecounter, bytesval) \
	((void)vp, (void)bytesval)
#define	VOPXID_MAP_CR(vp, cr)	((void)vp)

/*
 * Excerpts from fs/vnode.c
 */

/* Global used for empty/invalid v_path */
char *vn_vpath_empty = "";

static int fs_reparse_mark(char *target, vattr_t *vap, xvattr_t *xvattr);

/*
 * Convert stat(2) formats to vnode types and vice versa.  (Knows about
 * numerical order of S_IFMT and vnode types.)
 */
enum vtype iftovt_tab[] = {
	VNON, VFIFO, VCHR, VNON, VDIR, VNON, VBLK, VNON,
	VREG, VNON, VLNK, VNON, VSOCK, VNON, VNON, VNON
};

ushort_t vttoif_tab[] = {
	0, S_IFREG, S_IFDIR, S_IFBLK, S_IFCHR, S_IFLNK, S_IFIFO,
	S_IFDOOR, 0, S_IFSOCK, S_IFPORT, 0
};

/*
 * The system vnode cache.
 */

kmem_cache_t *vn_cache;


/*
 * Vnode operations vector.
 */

static const fs_operation_trans_def_t vn_ops_table[] = {
	VOPNAME_OPEN, offsetof(struct vnodeops, vop_open),
	    fs_nosys, fs_nosys,

	VOPNAME_CLOSE, offsetof(struct vnodeops, vop_close),
	    fs_nosys, fs_nosys,

	VOPNAME_READ, offsetof(struct vnodeops, vop_read),
	    fs_nosys, fs_nosys,

	VOPNAME_WRITE, offsetof(struct vnodeops, vop_write),
	    fs_nosys, fs_nosys,

	VOPNAME_IOCTL, offsetof(struct vnodeops, vop_ioctl),
	    fs_nosys, fs_nosys,

	VOPNAME_SETFL, offsetof(struct vnodeops, vop_setfl),
	    fs_setfl, fs_nosys,

	VOPNAME_GETATTR, offsetof(struct vnodeops, vop_getattr),
	    fs_nosys, fs_nosys,

	VOPNAME_SETATTR, offsetof(struct vnodeops, vop_setattr),
	    fs_nosys, fs_nosys,

	VOPNAME_ACCESS, offsetof(struct vnodeops, vop_access),
	    fs_nosys, fs_nosys,

	VOPNAME_LOOKUP, offsetof(struct vnodeops, vop_lookup),
	    fs_nosys, fs_nosys,

	VOPNAME_CREATE, offsetof(struct vnodeops, vop_create),
	    fs_nosys, fs_nosys,

	VOPNAME_REMOVE, offsetof(struct vnodeops, vop_remove),
	    fs_nosys, fs_nosys,

	VOPNAME_LINK, offsetof(struct vnodeops, vop_link),
	    fs_nosys, fs_nosys,

	VOPNAME_RENAME, offsetof(struct vnodeops, vop_rename),
	    fs_nosys, fs_nosys,

	VOPNAME_MKDIR, offsetof(struct vnodeops, vop_mkdir),
	    fs_nosys, fs_nosys,

	VOPNAME_RMDIR, offsetof(struct vnodeops, vop_rmdir),
	    fs_nosys, fs_nosys,

	VOPNAME_READDIR, offsetof(struct vnodeops, vop_readdir),
	    fs_nosys, fs_nosys,

	VOPNAME_SYMLINK, offsetof(struct vnodeops, vop_symlink),
	    fs_nosys, fs_nosys,

	VOPNAME_READLINK, offsetof(struct vnodeops, vop_readlink),
	    fs_nosys, fs_nosys,

	VOPNAME_FSYNC, offsetof(struct vnodeops, vop_fsync),
	    fs_nosys, fs_nosys,

	VOPNAME_INACTIVE, offsetof(struct vnodeops, vop_inactive),
	    fs_nosys, fs_nosys,

	VOPNAME_FID, offsetof(struct vnodeops, vop_fid),
	    fs_nosys, fs_nosys,

	VOPNAME_RWLOCK, offsetof(struct vnodeops, vop_rwlock),
	    fs_rwlock, fs_rwlock,

	VOPNAME_RWUNLOCK, offsetof(struct vnodeops, vop_rwunlock),
	    (fs_generic_func_p)(uintptr_t)fs_rwunlock,
	    (fs_generic_func_p)(intptr_t)fs_rwunlock,	/* no errors allowed */

	VOPNAME_SEEK, offsetof(struct vnodeops, vop_seek),
	    fs_nosys, fs_nosys,

	VOPNAME_CMP, offsetof(struct vnodeops, vop_cmp),
	    fs_cmp, fs_cmp,		/* no errors allowed */

	VOPNAME_FRLOCK, offsetof(struct vnodeops, vop_frlock),
	    fs_frlock, fs_nosys,

	VOPNAME_SPACE, offsetof(struct vnodeops, vop_space),
	    fs_nosys, fs_nosys,

	VOPNAME_REALVP, offsetof(struct vnodeops, vop_realvp),
	    fs_nosys, fs_nosys,

	VOPNAME_GETPAGE, offsetof(struct vnodeops, vop_getpage),
	    fs_nosys, fs_nosys,

	VOPNAME_PUTPAGE, offsetof(struct vnodeops, vop_putpage),
	    fs_nosys, fs_nosys,

	VOPNAME_MAP, offsetof(struct vnodeops, vop_map),
	    (fs_generic_func_p) fs_nosys_map,
	    (fs_generic_func_p) fs_nosys_map,

	VOPNAME_ADDMAP, offsetof(struct vnodeops, vop_addmap),
	    (fs_generic_func_p) fs_nosys_addmap,
	    (fs_generic_func_p) fs_nosys_addmap,

	VOPNAME_DELMAP, offsetof(struct vnodeops, vop_delmap),
	    fs_nosys, fs_nosys,

	VOPNAME_POLL, offsetof(struct vnodeops, vop_poll),
	    (fs_generic_func_p) fs_poll, (fs_generic_func_p) fs_nosys_poll,

	VOPNAME_DUMP, offsetof(struct vnodeops, vop_dump),
	    fs_nosys, fs_nosys,

	VOPNAME_PATHCONF, offsetof(struct vnodeops, vop_pathconf),
	    fs_pathconf, fs_nosys,

	VOPNAME_PAGEIO, offsetof(struct vnodeops, vop_pageio),
	    fs_nosys, fs_nosys,

	VOPNAME_DUMPCTL, offsetof(struct vnodeops, vop_dumpctl),
	    fs_nosys, fs_nosys,

	VOPNAME_DISPOSE, offsetof(struct vnodeops, vop_dispose),
	    (fs_generic_func_p)(intptr_t)fs_dispose,
	    (fs_generic_func_p)(intptr_t)fs_nodispose,

	VOPNAME_SETSECATTR, offsetof(struct vnodeops, vop_setsecattr),
	    fs_nosys, fs_nosys,

	VOPNAME_GETSECATTR, offsetof(struct vnodeops, vop_getsecattr),
	    fs_fab_acl, fs_nosys,

	VOPNAME_SHRLOCK, offsetof(struct vnodeops, vop_shrlock),
	    fs_shrlock, fs_nosys,

	VOPNAME_VNEVENT, offsetof(struct vnodeops, vop_vnevent),
	    (fs_generic_func_p) fs_vnevent_nosupport,
	    (fs_generic_func_p) fs_vnevent_nosupport,

	VOPNAME_REQZCBUF, offsetof(struct vnodeops, vop_reqzcbuf),
	    fs_nosys, fs_nosys,

	VOPNAME_RETZCBUF, offsetof(struct vnodeops, vop_retzcbuf),
	    fs_nosys, fs_nosys,

	NULL, 0, NULL, NULL
};

/* Extensible attribute (xva) routines. */

/*
 * Zero out the structure, set the size of the requested/returned bitmaps,
 * set AT_XVATTR in the embedded vattr_t's va_mask, and set up the pointer
 * to the returned attributes array.
 */
void
xva_init(xvattr_t *xvap)
{
	bzero(xvap, sizeof (xvattr_t));
	xvap->xva_mapsize = XVA_MAPSIZE;
	xvap->xva_magic = XVA_MAGIC;
	xvap->xva_vattr.va_mask = AT_XVATTR;
	xvap->xva_rtnattrmapp = &(xvap->xva_rtnattrmap)[0];
}

/*
 * If AT_XVATTR is set, returns a pointer to the embedded xoptattr_t
 * structure.  Otherwise, returns NULL.
 */
xoptattr_t *
xva_getxoptattr(xvattr_t *xvap)
{
	xoptattr_t *xoap = NULL;
	if (xvap->xva_vattr.va_mask & AT_XVATTR)
		xoap = &xvap->xva_xoptattrs;
	return (xoap);
}

// vska_compar
// create_vopstats_template
// new_vskstat
// vopstats_startup
// initialize_vopstats
// get_fstype_vopstats
// get_vskstat_anchor
// teardown_vopstats

/*
 * Read or write a vnode.  Called from kernel code.
 */
int
vn_rdwr(
	enum uio_rw rw,
	struct vnode *vp,
	caddr_t base,
	ssize_t len,
	offset_t offset,
	enum uio_seg seg,
	int ioflag,
	rlim64_t ulimit,	/* meaningful only if rw is UIO_WRITE */
	cred_t *cr,
	ssize_t *residp)
{
	struct uio uio;
	struct iovec iov;
	int error;
	int in_crit = 0;

	if (rw == UIO_WRITE && ISROFILE(vp))
		return (EROFS);

	if (len < 0)
		return (EIO);

	VOPXID_MAP_CR(vp, cr);

	iov.iov_base = base;
	iov.iov_len = len;
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_loffset = offset;
	uio.uio_segflg = (short)seg;
	uio.uio_resid = len;
	uio.uio_llimit = ulimit;

	/*
	 * We have to enter the critical region before calling VOP_RWLOCK
	 * to avoid a deadlock with ufs.
	 */
	if (nbl_need_check(vp)) {
		int svmand;

		nbl_start_crit(vp, RW_READER);
		in_crit = 1;
		error = nbl_svmand(vp, cr, &svmand);
		if (error != 0)
			goto done;
		if (nbl_conflict(vp, rw == UIO_WRITE ? NBL_WRITE : NBL_READ,
		    uio.uio_offset, uio.uio_resid, svmand, NULL)) {
			error = EACCES;
			goto done;
		}
	}

	(void) VOP_RWLOCK(vp,
	    rw == UIO_WRITE ? V_WRITELOCK_TRUE : V_WRITELOCK_FALSE, NULL);
	if (rw == UIO_WRITE) {
		uio.uio_fmode = FWRITE;
		uio.uio_extflg = UIO_COPY_DEFAULT;
		error = VOP_WRITE(vp, &uio, ioflag, cr, NULL);
	} else {
		uio.uio_fmode = FREAD;
		uio.uio_extflg = UIO_COPY_CACHED;
		error = VOP_READ(vp, &uio, ioflag, cr, NULL);
	}
	VOP_RWUNLOCK(vp,
	    rw == UIO_WRITE ? V_WRITELOCK_TRUE : V_WRITELOCK_FALSE, NULL);
	if (residp)
		*residp = uio.uio_resid;
	else if (uio.uio_resid)
		error = EIO;

done:
	if (in_crit)
		nbl_end_crit(vp);
	return (error);
}

/*
 * Incremend the hold on a vnode
 * (Real kernel uses a macro)
 */
void
vn_hold(struct vnode *vp)
{
	mutex_enter(&vp->v_lock);
	(vp)->v_count++;
	mutex_exit(&vp->v_lock);
}

/*
 * Release a vnode.  Call VOP_INACTIVE on last reference or
 * decrement reference count...
 */
void
vn_rele(vnode_t *vp)
{
	VERIFY(vp->v_count > 0);
	mutex_enter(&vp->v_lock);
	if (vp->v_count == 1) {
		mutex_exit(&vp->v_lock);
		VOP_INACTIVE(vp, CRED(), NULL);
		return;
	}
	VN_RELE_LOCKED(vp);
	mutex_exit(&vp->v_lock);
}

// vn_rele_dnlc
// vn_rele_stream
// vn_rele_inactive
// vn_rele_async
// vn_open, vn_openat
// vn_open_upgrade
// vn_open_downgrade
// vn_create, vn_createat
// vn_link, vn_linkat
// vn_rename, vn_renameat
// vn_remove, vn_removeat


/*
 * Utility function to compare equality of vnodes.
 * Compare the underlying real vnodes, if there are underlying vnodes.
 * This is a more thorough comparison than the VN_CMP() macro provides.
 */
int
vn_compare(vnode_t *vp1, vnode_t *vp2)
{
	vnode_t *realvp;

	if (vp1 != NULL && VOP_REALVP(vp1, &realvp, NULL) == 0)
		vp1 = realvp;
	if (vp2 != NULL && VOP_REALVP(vp2, &realvp, NULL) == 0)
		vp2 = realvp;
	return (VN_CMP(vp1, vp2));
}

// vn_vfslocks_buckets
// vn_vfslocks_getlock
// vn_vfslocks_rele

static krwlock_t vfsentry_ve_lock;

/*
 * vn_vfswlock_wait is used to implement a lock which is logically a
 * writers lock protecting the v_vfsmountedhere field.
 * vn_vfswlock_wait has been modified to be similar to vn_vfswlock,
 * except that it blocks to acquire the lock VVFSLOCK.
 *
 * traverse() and routines re-implementing part of traverse (e.g. autofs)
 * need to hold this lock. mount(), vn_rename(), vn_remove() and so on
 * need the non-blocking version of the writers lock i.e. vn_vfswlock
 */
int
vn_vfswlock_wait(vnode_t *vp)
{

	ASSERT(vp != NULL);

	rw_enter(&vfsentry_ve_lock, RW_WRITER);

	return (0);
}

int
vn_vfsrlock_wait(vnode_t *vp)
{

	ASSERT(vp != NULL);

	rw_enter(&vfsentry_ve_lock, RW_READER);

	return (0);
}

/*
 * vn_vfswlock is used to implement a lock which is logically a writers lock
 * protecting the v_vfsmountedhere field.
 */
int
vn_vfswlock(vnode_t *vp)
{

	if (vp == NULL)
		return (EBUSY);

	if (rw_tryenter(&vfsentry_ve_lock, RW_WRITER))
		return (0);

	return (EBUSY);
}

int
vn_vfsrlock(vnode_t *vp)
{

	if (vp == NULL)
		return (EBUSY);

	if (rw_tryenter(&vfsentry_ve_lock, RW_READER))
		return (0);

	return (EBUSY);
}

void
vn_vfsunlock(vnode_t *vp)
{

	rw_exit(&vfsentry_ve_lock);
}

int
vn_vfswlock_held(vnode_t *vp)
{
	int held;

	ASSERT(vp != NULL);

	held = rw_write_held(&vfsentry_ve_lock);

	return (held);
}


int
vn_make_ops(
	const char *name,			/* Name of file system */
	const fs_operation_def_t *templ,	/* Operation specification */
	vnodeops_t **actual)			/* Return the vnodeops */
{
	int unused_ops;
	int error;

	*actual = (vnodeops_t *)kmem_alloc(sizeof (vnodeops_t), KM_SLEEP);

	(*actual)->vnop_name = name;

	error = fs_build_vector(*actual, &unused_ops, vn_ops_table, templ);
	if (error) {
		kmem_free(*actual, sizeof (vnodeops_t));
	}

#if DEBUG
	if (unused_ops != 0)
		cmn_err(CE_WARN, "vn_make_ops: %s: %d operations supplied "
		    "but not used", name, unused_ops);
#endif

	return (error);
}

/*
 * Free the vnodeops created as a result of vn_make_ops()
 */
void
vn_freevnodeops(vnodeops_t *vnops)
{
	kmem_free(vnops, sizeof (vnodeops_t));
}

/*
 * Vnode cache.
 */

/* ARGSUSED */
static int
vn_cache_constructor(void *buf, void *cdrarg, int kmflags)
{
	struct vnode *vp = buf;

	bzero(vp, sizeof (*vp));
	mutex_init(&vp->v_lock, NULL, MUTEX_DEFAULT, NULL);
	rw_init(&vp->v_nbllock, NULL, RW_DEFAULT, NULL);
	vp->v_path = vn_vpath_empty;
	vp->v_fd = -1;
	vp->v_st_dev = NODEV;

	return (0);
}

/* ARGSUSED */
static void
vn_cache_destructor(void *buf, void *cdrarg)
{
	struct vnode *vp;

	vp = buf;

	rw_destroy(&vp->v_nbllock);
	mutex_destroy(&vp->v_lock);
}

void
vn_create_cache(void)
{
	vn_cache = kmem_cache_create("vn_cache", sizeof (struct vnode),
	    VNODE_ALIGN, vn_cache_constructor, vn_cache_destructor, NULL, NULL,
	    NULL, 0);
}

void
vn_destroy_cache(void)
{
	kmem_cache_destroy(vn_cache);
}

/*
 * Used by file systems when fs-specific nodes (e.g., ufs inodes) are
 * cached by the file system and vnodes remain associated.
 */
void
vn_recycle(vnode_t *vp)
{
	VERIFY(vp->v_path != NULL);

	/*
	 * XXX - This really belongs in vn_reinit(), but we have some issues
	 * with the counts.  Best to have it here for clean initialization.
	 */
	vp->v_rdcnt = 0;
	vp->v_wrcnt = 0;

	/*
	 * If FEM was in use...
	 */

	if (vp->v_path != vn_vpath_empty) {
		kmem_free(vp->v_path, strlen(vp->v_path) + 1);
		vp->v_path = vn_vpath_empty;
	}
	// vsd_free(vp);
}

/*
 * Used to reset the vnode fields including those that are directly accessible
 * as well as those which require an accessor function.
 */
void
vn_reinit(vnode_t *vp)
{
	vp->v_count = 1;
	// vp->v_count_dnlc = 0;
	vp->v_vfsp = NULL;
	vp->v_stream = NULL;
	vp->v_vfsmountedhere = NULL;
	vp->v_flag = 0;
	vp->v_type = VNON;
	vp->v_rdev = NODEV;

	vp->v_xattrdir = NULL;

	/*
	 * In a few specific instances, vn_reinit() is used to initialize
	 * locally defined vnode_t instances.  Lacking the construction offered
	 * by vn_alloc(), these vnodes require v_path initialization.
	 */
	if (vp->v_path == NULL) {
		vp->v_path = vn_vpath_empty;
	}

	/* Handles v_femhead, v_path, and the r/w/map counts */
	vn_recycle(vp);
}

vnode_t *
vn_alloc(int kmflag)
{
	vnode_t *vp;

	vp = kmem_cache_alloc(vn_cache, kmflag);

	if (vp != NULL) {
		// vp->v_femhead = NULL; /* Must be done before vn_reinit() */
		// vp->v_fopdata = NULL;
		vn_reinit(vp);
	}

	return (vp);
}

void
vn_free(vnode_t *vp)
{
	extern vnode_t *rootdir;
	ASSERT(vp != rootdir);

	/*
	 * Some file systems call vn_free() with v_count of zero,
	 * some with v_count of 1.  In any case, the value should
	 * never be anything else.
	 */
	ASSERT((vp->v_count == 0) || (vp->v_count == 1));
	VERIFY(vp->v_path != NULL);
	if (vp->v_path != vn_vpath_empty) {
		kmem_free(vp->v_path, strlen(vp->v_path) + 1);
		vp->v_path = vn_vpath_empty;
	}

	/* If FEM was in use... */

	// vsd_free(vp);
	kmem_cache_free(vn_cache, vp);
}

/*
 * vnode status changes, should define better states than 1, 0.
 */
void
vn_reclaim(vnode_t *vp)
{
	vfs_t   *vfsp = vp->v_vfsp;

	if (vfsp == NULL ||
	    vfsp->vfs_implp == NULL || vfsp->vfs_femhead == NULL) {
		return;
	}
	(void) VFS_VNSTATE(vfsp, vp, VNTRANS_RECLAIMED);
}

void
vn_idle(vnode_t *vp)
{
	vfs_t   *vfsp = vp->v_vfsp;

	if (vfsp == NULL ||
	    vfsp->vfs_implp == NULL || vfsp->vfs_femhead == NULL) {
		return;
	}
	(void) VFS_VNSTATE(vfsp, vp, VNTRANS_IDLED);
}
void
vn_exists(vnode_t *vp)
{
	vfs_t   *vfsp = vp->v_vfsp;

	if (vfsp == NULL ||
	    vfsp->vfs_implp == NULL || vfsp->vfs_femhead == NULL) {
		return;
	}
	(void) VFS_VNSTATE(vfsp, vp, VNTRANS_EXISTS);
}

void
vn_invalid(vnode_t *vp)
{
}

/* Vnode event notification */
// vnevent_support()
// vnevent_...

/*
 * Vnode accessors.
 */

int
vn_is_readonly(vnode_t *vp)
{
	return (vp->v_vfsp->vfs_flag & VFS_RDONLY);
}

int
vn_has_flocks(vnode_t *vp)
{
	return (0);
}

int
vn_has_mandatory_locks(vnode_t *vp, int mode)
{
	return (0);
}

int
vn_has_cached_data(vnode_t *vp)
{
	return (0);
}

// vn_can_change_zones

/*
 * Return nonzero if the vnode is a mount point, zero if not.
 */
int
vn_ismntpt(vnode_t *vp)
{
	return (vp->v_vfsmountedhere != NULL);
}

/* Retrieve the vfs (if any) mounted on this vnode */
vfs_t *
vn_mountedvfs(vnode_t *vp)
{
	return (vp->v_vfsmountedhere);
}

/*
 * Return nonzero if the vnode is referenced by the dnlc, zero if not.
 * (no DNLC here)
 */
int
vn_in_dnlc(vnode_t *vp)
{
	return (0);
}


/*
 * vn_has_other_opens() checks whether a particular file is opened by more than
 * just the caller and whether the open is for read and/or write.
 * This routine is for calling after the caller has already called VOP_OPEN()
 * and the caller wishes to know if they are the only one with it open for
 * the mode(s) specified.
 *
 * Vnode counts are only kept on regular files (v_type=VREG).
 */
int
vn_has_other_opens(
	vnode_t *vp,
	v_mode_t mode)
{

	ASSERT(vp != NULL);

	switch (mode) {
	case V_WRITE:
		if (vp->v_wrcnt > 1)
			return (V_TRUE);
		break;
	case V_RDORWR:
		if ((vp->v_rdcnt > 1) || (vp->v_wrcnt > 1))
			return (V_TRUE);
		break;
	case V_RDANDWR:
		if ((vp->v_rdcnt > 1) && (vp->v_wrcnt > 1))
			return (V_TRUE);
		break;
	case V_READ:
		if (vp->v_rdcnt > 1)
			return (V_TRUE);
		break;
	}

	return (V_FALSE);
}

/*
 * vn_is_opened() checks whether a particular file is opened and
 * whether the open is for read and/or write.
 *
 * Vnode counts are only kept on regular files (v_type=VREG).
 */
int
vn_is_opened(
	vnode_t *vp,
	v_mode_t mode)
{

	ASSERT(vp != NULL);

	switch (mode) {
	case V_WRITE:
		if (vp->v_wrcnt)
			return (V_TRUE);
		break;
	case V_RDANDWR:
		if (vp->v_rdcnt && vp->v_wrcnt)
			return (V_TRUE);
		break;
	case V_RDORWR:
		if (vp->v_rdcnt || vp->v_wrcnt)
			return (V_TRUE);
		break;
	case V_READ:
		if (vp->v_rdcnt)
			return (V_TRUE);
		break;
	}

	return (V_FALSE);
}

/*
 * vn_is_mapped() checks whether a particular file is mapped and whether
 * the file is mapped read and/or write.  (no mmap here)
 */
int
vn_is_mapped(
	vnode_t *vp,
	v_mode_t mode)
{
	return (V_FALSE);
}

/*
 * Set the operations vector for a vnode.
 */
void
vn_setops(vnode_t *vp, vnodeops_t *vnodeops)
{

	ASSERT(vp != NULL);
	ASSERT(vnodeops != NULL);

	vp->v_op = vnodeops;
}

/*
 * Retrieve the operations vector for a vnode
 */
vnodeops_t *
vn_getops(vnode_t *vp)
{

	ASSERT(vp != NULL);

	return (vp->v_op);
}

/*
 * Returns non-zero (1) if the vnodeops matches that of the vnode.
 * Returns zero (0) if not.
 */
int
vn_matchops(vnode_t *vp, vnodeops_t *vnodeops)
{
	return (vn_getops(vp) == vnodeops);
}

// vn_matchopval
// fs_new_caller_id

// vn_clearpath
// vn_setpath_common

/* ARGSUSED */
void
vn_updatepath(vnode_t *pvp, vnode_t *vp, const char *name)
{
}

// vn_setpath...
// vn_renamepath
// vn_copypath

// vn_vmpss_usepageio

/* VOP_XXX() macros call the corresponding fop_xxx() function */

int
fop_open(
	vnode_t **vpp,
	int mode,
	cred_t *cr,
	caller_context_t *ct)
{
	int ret;
	vnode_t *vp = *vpp;

	VN_HOLD(vp);
	/*
	 * Adding to the vnode counts before calling open
	 * avoids the need for a mutex...
	 */
	if ((*vpp)->v_type == VREG) {
		if (mode & FREAD)
			atomic_inc_32(&(*vpp)->v_rdcnt);
		if (mode & FWRITE)
			atomic_inc_32(&(*vpp)->v_wrcnt);
	}

	VOPXID_MAP_CR(vp, cr);

	ret = (*(*(vpp))->v_op->vop_open)(vpp, mode, cr, ct);

	if (ret) {
		/*
		 * Use the saved vp just in case the vnode ptr got trashed
		 * by the error.
		 */
		VOPSTATS_UPDATE(vp, open);
		if ((vp->v_type == VREG) && (mode & FREAD))
			atomic_dec_32(&vp->v_rdcnt);
		if ((vp->v_type == VREG) && (mode & FWRITE))
			atomic_dec_32(&vp->v_wrcnt);
	} else {
		/*
		 * Some filesystems will return a different vnode,
		 * but the same path was still used to open it.
		 * So if we do change the vnode and need to
		 * copy over the path, do so here, rather than special
		 * casing each filesystem. Adjust the vnode counts to
		 * reflect the vnode switch.
		 */
		VOPSTATS_UPDATE(*vpp, open);
		if (*vpp != vp && *vpp != NULL) {
			// vn_copypath(vp, *vpp);
			if (((*vpp)->v_type == VREG) && (mode & FREAD))
				atomic_inc_32(&(*vpp)->v_rdcnt);
			if ((vp->v_type == VREG) && (mode & FREAD))
				atomic_dec_32(&vp->v_rdcnt);
			if (((*vpp)->v_type == VREG) && (mode & FWRITE))
				atomic_inc_32(&(*vpp)->v_wrcnt);
			if ((vp->v_type == VREG) && (mode & FWRITE))
				atomic_dec_32(&vp->v_wrcnt);
		}
	}
	VN_RELE(vp);
	return (ret);
}

int
fop_close(
	vnode_t *vp,
	int flag,
	int count,
	offset_t offset,
	cred_t *cr,
	caller_context_t *ct)
{
	int err;

	VOPXID_MAP_CR(vp, cr);

	err = (*(vp)->v_op->vop_close)(vp, flag, count, offset, cr, ct);
	VOPSTATS_UPDATE(vp, close);
	/*
	 * Check passed in count to handle possible dups. Vnode counts are only
	 * kept on regular files
	 */
	if ((vp->v_type == VREG) && (count == 1))  {
		if (flag & FREAD) {
			ASSERT(vp->v_rdcnt > 0);
			atomic_dec_32(&vp->v_rdcnt);
		}
		if (flag & FWRITE) {
			ASSERT(vp->v_wrcnt > 0);
			atomic_dec_32(&vp->v_wrcnt);
		}
	}
	return (err);
}

int
fop_read(
	vnode_t *vp,
	uio_t *uiop,
	int ioflag,
	cred_t *cr,
	caller_context_t *ct)
{
	int	err;
	ssize_t	resid_start = uiop->uio_resid;

	VOPXID_MAP_CR(vp, cr);

	err = (*(vp)->v_op->vop_read)(vp, uiop, ioflag, cr, ct);
	VOPSTATS_UPDATE_IO(vp, read,
	    read_bytes, (resid_start - uiop->uio_resid));
	return (err);
}

int
fop_write(
	vnode_t *vp,
	uio_t *uiop,
	int ioflag,
	cred_t *cr,
	caller_context_t *ct)
{
	int	err;
	ssize_t	resid_start = uiop->uio_resid;

	VOPXID_MAP_CR(vp, cr);

	err = (*(vp)->v_op->vop_write)(vp, uiop, ioflag, cr, ct);
	VOPSTATS_UPDATE_IO(vp, write,
	    write_bytes, (resid_start - uiop->uio_resid));
	return (err);
}

int
fop_ioctl(
	vnode_t *vp,
	int cmd,
	intptr_t arg,
	int flag,
	cred_t *cr,
	int *rvalp,
	caller_context_t *ct)
{
	int	err;

	VOPXID_MAP_CR(vp, cr);

	err = (*(vp)->v_op->vop_ioctl)(vp, cmd, arg, flag, cr, rvalp, ct);
	VOPSTATS_UPDATE(vp, ioctl);
	return (err);
}

int
fop_setfl(
	vnode_t *vp,
	int oflags,
	int nflags,
	cred_t *cr,
	caller_context_t *ct)
{
	int	err;

	VOPXID_MAP_CR(vp, cr);

	err = (*(vp)->v_op->vop_setfl)(vp, oflags, nflags, cr, ct);
	VOPSTATS_UPDATE(vp, setfl);
	return (err);
}

int
fop_getattr(
	vnode_t *vp,
	vattr_t *vap,
	int flags,
	cred_t *cr,
	caller_context_t *ct)
{
	int	err;

	VOPXID_MAP_CR(vp, cr);

	/*
	 * If this file system doesn't understand the xvattr extensions
	 * then turn off the xvattr bit.
	 */
	if (vfs_has_feature(vp->v_vfsp, VFSFT_XVATTR) == 0) {
		vap->va_mask &= ~AT_XVATTR;
	}

	/*
	 * We're only allowed to skip the ACL check iff we used a 32 bit
	 * ACE mask with VOP_ACCESS() to determine permissions.
	 */
	if ((flags & ATTR_NOACLCHECK) &&
	    vfs_has_feature(vp->v_vfsp, VFSFT_ACEMASKONACCESS) == 0) {
		return (EINVAL);
	}
	err = (*(vp)->v_op->vop_getattr)(vp, vap, flags, cr, ct);
	VOPSTATS_UPDATE(vp, getattr);
	return (err);
}

int
fop_setattr(
	vnode_t *vp,
	vattr_t *vap,
	int flags,
	cred_t *cr,
	caller_context_t *ct)
{
	int	err;

	VOPXID_MAP_CR(vp, cr);

	/*
	 * If this file system doesn't understand the xvattr extensions
	 * then turn off the xvattr bit.
	 */
	if (vfs_has_feature(vp->v_vfsp, VFSFT_XVATTR) == 0) {
		vap->va_mask &= ~AT_XVATTR;
	}

	/*
	 * We're only allowed to skip the ACL check iff we used a 32 bit
	 * ACE mask with VOP_ACCESS() to determine permissions.
	 */
	if ((flags & ATTR_NOACLCHECK) &&
	    vfs_has_feature(vp->v_vfsp, VFSFT_ACEMASKONACCESS) == 0) {
		return (EINVAL);
	}
	err = (*(vp)->v_op->vop_setattr)(vp, vap, flags, cr, ct);
	VOPSTATS_UPDATE(vp, setattr);
	return (err);
}

int
fop_access(
	vnode_t *vp,
	int mode,
	int flags,
	cred_t *cr,
	caller_context_t *ct)
{
	int	err;

	if ((flags & V_ACE_MASK) &&
	    vfs_has_feature(vp->v_vfsp, VFSFT_ACEMASKONACCESS) == 0) {
		return (EINVAL);
	}

	VOPXID_MAP_CR(vp, cr);

	err = (*(vp)->v_op->vop_access)(vp, mode, flags, cr, ct);
	VOPSTATS_UPDATE(vp, access);
	return (err);
}

int
fop_lookup(
	vnode_t *dvp,
	char *nm,
	vnode_t **vpp,
	pathname_t *pnp,
	int flags,
	vnode_t *rdir,
	cred_t *cr,
	caller_context_t *ct,
	int *deflags,		/* Returned per-dirent flags */
	pathname_t *ppnp)	/* Returned case-preserved name in directory */
{
	int ret;

	/*
	 * If this file system doesn't support case-insensitive access
	 * and said access is requested, fail quickly.  It is required
	 * that if the vfs supports case-insensitive lookup, it also
	 * supports extended dirent flags.
	 */
	if (flags & FIGNORECASE &&
	    (vfs_has_feature(dvp->v_vfsp, VFSFT_CASEINSENSITIVE) == 0 &&
	    vfs_has_feature(dvp->v_vfsp, VFSFT_NOCASESENSITIVE) == 0))
		return (EINVAL);

	VOPXID_MAP_CR(dvp, cr);

	/*
	 * The real vnode.c would call xattr_dir_lookup here,
	 * which inserts the special "System Attribute" files:
	 * (SUNWattr_rw, SUNWattr_ro) into the xattr list.
	 * Here the main focus is on testing xattr support,
	 * so the system attribute stuff is ommitted.
	 */
#if 0
	if ((flags & LOOKUP_XATTR) && (flags & LOOKUP_HAVE_SYSATTR_DIR) == 0) {
		// Don't need xattr support in libfksmbfs.
		// ret = xattr_dir_lookup(dvp, vpp, flags, cr);
		ret = EINVAL;
	} else
#endif
	{
		ret = (*(dvp)->v_op->vop_lookup)
		    (dvp, nm, vpp, pnp, flags, rdir, cr, ct, deflags, ppnp);
	}
	if (ret == 0 && *vpp) {
		VOPSTATS_UPDATE(*vpp, lookup);
		vn_updatepath(dvp, *vpp, nm);
	}

	return (ret);
}

int
fop_create(
	vnode_t *dvp,
	char *name,
	vattr_t *vap,
	vcexcl_t excl,
	int mode,
	vnode_t **vpp,
	cred_t *cr,
	int flags,
	caller_context_t *ct,
	vsecattr_t *vsecp)	/* ACL to set during create */
{
	int ret;

	if (vsecp != NULL &&
	    vfs_has_feature(dvp->v_vfsp, VFSFT_ACLONCREATE) == 0) {
		return (EINVAL);
	}
	/*
	 * If this file system doesn't support case-insensitive access
	 * and said access is requested, fail quickly.
	 */
	if (flags & FIGNORECASE &&
	    (vfs_has_feature(dvp->v_vfsp, VFSFT_CASEINSENSITIVE) == 0 &&
	    vfs_has_feature(dvp->v_vfsp, VFSFT_NOCASESENSITIVE) == 0))
		return (EINVAL);

	VOPXID_MAP_CR(dvp, cr);

	ret = (*(dvp)->v_op->vop_create)
	    (dvp, name, vap, excl, mode, vpp, cr, flags, ct, vsecp);
	if (ret == 0 && *vpp) {
		VOPSTATS_UPDATE(*vpp, create);
		vn_updatepath(dvp, *vpp, name);
	}

	return (ret);
}

int
fop_remove(
	vnode_t *dvp,
	char *nm,
	cred_t *cr,
	caller_context_t *ct,
	int flags)
{
	int	err;

	/*
	 * If this file system doesn't support case-insensitive access
	 * and said access is requested, fail quickly.
	 */
	if (flags & FIGNORECASE &&
	    (vfs_has_feature(dvp->v_vfsp, VFSFT_CASEINSENSITIVE) == 0 &&
	    vfs_has_feature(dvp->v_vfsp, VFSFT_NOCASESENSITIVE) == 0))
		return (EINVAL);

	VOPXID_MAP_CR(dvp, cr);

	err = (*(dvp)->v_op->vop_remove)(dvp, nm, cr, ct, flags);
	VOPSTATS_UPDATE(dvp, remove);
	return (err);
}

int
fop_link(
	vnode_t *tdvp,
	vnode_t *svp,
	char *tnm,
	cred_t *cr,
	caller_context_t *ct,
	int flags)
{
	int	err;

	/*
	 * If the target file system doesn't support case-insensitive access
	 * and said access is requested, fail quickly.
	 */
	if (flags & FIGNORECASE &&
	    (vfs_has_feature(tdvp->v_vfsp, VFSFT_CASEINSENSITIVE) == 0 &&
	    vfs_has_feature(tdvp->v_vfsp, VFSFT_NOCASESENSITIVE) == 0))
		return (EINVAL);

	VOPXID_MAP_CR(tdvp, cr);

	err = (*(tdvp)->v_op->vop_link)(tdvp, svp, tnm, cr, ct, flags);
	VOPSTATS_UPDATE(tdvp, link);
	return (err);
}

int
fop_rename(
	vnode_t *sdvp,
	char *snm,
	vnode_t *tdvp,
	char *tnm,
	cred_t *cr,
	caller_context_t *ct,
	int flags)
{
	int	err;

	/*
	 * If the file system involved does not support
	 * case-insensitive access and said access is requested, fail
	 * quickly.
	 */
	if (flags & FIGNORECASE &&
	    ((vfs_has_feature(sdvp->v_vfsp, VFSFT_CASEINSENSITIVE) == 0 &&
	    vfs_has_feature(sdvp->v_vfsp, VFSFT_NOCASESENSITIVE) == 0)))
		return (EINVAL);

	VOPXID_MAP_CR(tdvp, cr);

	err = (*(sdvp)->v_op->vop_rename)(sdvp, snm, tdvp, tnm, cr, ct, flags);
	VOPSTATS_UPDATE(sdvp, rename);
	return (err);
}

int
fop_mkdir(
	vnode_t *dvp,
	char *dirname,
	vattr_t *vap,
	vnode_t **vpp,
	cred_t *cr,
	caller_context_t *ct,
	int flags,
	vsecattr_t *vsecp)	/* ACL to set during create */
{
	int ret;

	if (vsecp != NULL &&
	    vfs_has_feature(dvp->v_vfsp, VFSFT_ACLONCREATE) == 0) {
		return (EINVAL);
	}
	/*
	 * If this file system doesn't support case-insensitive access
	 * and said access is requested, fail quickly.
	 */
	if (flags & FIGNORECASE &&
	    (vfs_has_feature(dvp->v_vfsp, VFSFT_CASEINSENSITIVE) == 0 &&
	    vfs_has_feature(dvp->v_vfsp, VFSFT_NOCASESENSITIVE) == 0))
		return (EINVAL);

	VOPXID_MAP_CR(dvp, cr);

	ret = (*(dvp)->v_op->vop_mkdir)
	    (dvp, dirname, vap, vpp, cr, ct, flags, vsecp);
	if (ret == 0 && *vpp) {
		VOPSTATS_UPDATE(*vpp, mkdir);
		vn_updatepath(dvp, *vpp, dirname);
	}

	return (ret);
}

int
fop_rmdir(
	vnode_t *dvp,
	char *nm,
	vnode_t *cdir,
	cred_t *cr,
	caller_context_t *ct,
	int flags)
{
	int	err;

	/*
	 * If this file system doesn't support case-insensitive access
	 * and said access is requested, fail quickly.
	 */
	if (flags & FIGNORECASE &&
	    (vfs_has_feature(dvp->v_vfsp, VFSFT_CASEINSENSITIVE) == 0 &&
	    vfs_has_feature(dvp->v_vfsp, VFSFT_NOCASESENSITIVE) == 0))
		return (EINVAL);

	VOPXID_MAP_CR(dvp, cr);

	err = (*(dvp)->v_op->vop_rmdir)(dvp, nm, cdir, cr, ct, flags);
	VOPSTATS_UPDATE(dvp, rmdir);
	return (err);
}

int
fop_readdir(
	vnode_t *vp,
	uio_t *uiop,
	cred_t *cr,
	int *eofp,
	caller_context_t *ct,
	int flags)
{
	int	err;
	ssize_t	resid_start = uiop->uio_resid;

	/*
	 * If this file system doesn't support retrieving directory
	 * entry flags and said access is requested, fail quickly.
	 */
	if (flags & V_RDDIR_ENTFLAGS &&
	    vfs_has_feature(vp->v_vfsp, VFSFT_DIRENTFLAGS) == 0)
		return (EINVAL);

	VOPXID_MAP_CR(vp, cr);

	err = (*(vp)->v_op->vop_readdir)(vp, uiop, cr, eofp, ct, flags);
	VOPSTATS_UPDATE_IO(vp, readdir,
	    readdir_bytes, (resid_start - uiop->uio_resid));
	return (err);
}

int
fop_symlink(
	vnode_t *dvp,
	char *linkname,
	vattr_t *vap,
	char *target,
	cred_t *cr,
	caller_context_t *ct,
	int flags)
{
	int	err;
	xvattr_t xvattr;

	/*
	 * If this file system doesn't support case-insensitive access
	 * and said access is requested, fail quickly.
	 */
	if (flags & FIGNORECASE &&
	    (vfs_has_feature(dvp->v_vfsp, VFSFT_CASEINSENSITIVE) == 0 &&
	    vfs_has_feature(dvp->v_vfsp, VFSFT_NOCASESENSITIVE) == 0))
		return (EINVAL);

	VOPXID_MAP_CR(dvp, cr);

	/* check for reparse point */
	if ((vfs_has_feature(dvp->v_vfsp, VFSFT_REPARSE)) &&
	    (strncmp(target, FS_REPARSE_TAG_STR,
	    strlen(FS_REPARSE_TAG_STR)) == 0)) {
		if (!fs_reparse_mark(target, vap, &xvattr))
			vap = (vattr_t *)&xvattr;
	}

	err = (*(dvp)->v_op->vop_symlink)
	    (dvp, linkname, vap, target, cr, ct, flags);
	VOPSTATS_UPDATE(dvp, symlink);
	return (err);
}

int
fop_readlink(
	vnode_t *vp,
	uio_t *uiop,
	cred_t *cr,
	caller_context_t *ct)
{
	int	err;

	VOPXID_MAP_CR(vp, cr);

	err = (*(vp)->v_op->vop_readlink)(vp, uiop, cr, ct);
	VOPSTATS_UPDATE(vp, readlink);
	return (err);
}

int
fop_fsync(
	vnode_t *vp,
	int syncflag,
	cred_t *cr,
	caller_context_t *ct)
{
	int	err;

	VOPXID_MAP_CR(vp, cr);

	err = (*(vp)->v_op->vop_fsync)(vp, syncflag, cr, ct);
	VOPSTATS_UPDATE(vp, fsync);
	return (err);
}

void
fop_inactive(
	vnode_t *vp,
	cred_t *cr,
	caller_context_t *ct)
{
	/* Need to update stats before vop call since we may lose the vnode */
	VOPSTATS_UPDATE(vp, inactive);

	VOPXID_MAP_CR(vp, cr);

	(*(vp)->v_op->vop_inactive)(vp, cr, ct);
}

int
fop_fid(
	vnode_t *vp,
	fid_t *fidp,
	caller_context_t *ct)
{
	int	err;

	err = (*(vp)->v_op->vop_fid)(vp, fidp, ct);
	VOPSTATS_UPDATE(vp, fid);
	return (err);
}

int
fop_rwlock(
	vnode_t *vp,
	int write_lock,
	caller_context_t *ct)
{
	int	ret;

	ret = ((*(vp)->v_op->vop_rwlock)(vp, write_lock, ct));
	VOPSTATS_UPDATE(vp, rwlock);
	return (ret);
}

void
fop_rwunlock(
	vnode_t *vp,
	int write_lock,
	caller_context_t *ct)
{
	(*(vp)->v_op->vop_rwunlock)(vp, write_lock, ct);
	VOPSTATS_UPDATE(vp, rwunlock);
}

int
fop_seek(
	vnode_t *vp,
	offset_t ooff,
	offset_t *noffp,
	caller_context_t *ct)
{
	int	err;

	err = (*(vp)->v_op->vop_seek)(vp, ooff, noffp, ct);
	VOPSTATS_UPDATE(vp, seek);
	return (err);
}

int
fop_cmp(
	vnode_t *vp1,
	vnode_t *vp2,
	caller_context_t *ct)
{
	int	err;

	err = (*(vp1)->v_op->vop_cmp)(vp1, vp2, ct);
	VOPSTATS_UPDATE(vp1, cmp);
	return (err);
}

int
fop_frlock(
	vnode_t *vp,
	int cmd,
	flock64_t *bfp,
	int flag,
	offset_t offset,
	struct flk_callback *flk_cbp,
	cred_t *cr,
	caller_context_t *ct)
{
	int	err;

	VOPXID_MAP_CR(vp, cr);

	err = (*(vp)->v_op->vop_frlock)
	    (vp, cmd, bfp, flag, offset, flk_cbp, cr, ct);
	VOPSTATS_UPDATE(vp, frlock);
	return (err);
}

int
fop_space(
	vnode_t *vp,
	int cmd,
	flock64_t *bfp,
	int flag,
	offset_t offset,
	cred_t *cr,
	caller_context_t *ct)
{
	int	err;

	VOPXID_MAP_CR(vp, cr);

	err = (*(vp)->v_op->vop_space)(vp, cmd, bfp, flag, offset, cr, ct);
	VOPSTATS_UPDATE(vp, space);
	return (err);
}

int
fop_realvp(
	vnode_t *vp,
	vnode_t **vpp,
	caller_context_t *ct)
{
	int	err;

	err = (*(vp)->v_op->vop_realvp)(vp, vpp, ct);
	VOPSTATS_UPDATE(vp, realvp);
	return (err);
}

int
fop_getpage(
	vnode_t *vp,
	offset_t off,
	size_t len,
	uint_t *protp,
	page_t **plarr,
	size_t plsz,
	struct seg *seg,
	caddr_t addr,
	enum seg_rw rw,
	cred_t *cr,
	caller_context_t *ct)
{
	int	err;

	VOPXID_MAP_CR(vp, cr);

	err = (*(vp)->v_op->vop_getpage)
	    (vp, off, len, protp, plarr, plsz, seg, addr, rw, cr, ct);
	VOPSTATS_UPDATE(vp, getpage);
	return (err);
}

int
fop_putpage(
	vnode_t *vp,
	offset_t off,
	size_t len,
	int flags,
	cred_t *cr,
	caller_context_t *ct)
{
	int	err;

	VOPXID_MAP_CR(vp, cr);

	err = (*(vp)->v_op->vop_putpage)(vp, off, len, flags, cr, ct);
	VOPSTATS_UPDATE(vp, putpage);
	return (err);
}

int
fop_map(
	vnode_t *vp,
	offset_t off,
	struct as *as,
	caddr_t *addrp,
	size_t len,
	uchar_t prot,
	uchar_t maxprot,
	uint_t flags,
	cred_t *cr,
	caller_context_t *ct)
{
	int	err;

	VOPXID_MAP_CR(vp, cr);

	err = (*(vp)->v_op->vop_map)
	    (vp, off, as, addrp, len, prot, maxprot, flags, cr, ct);
	VOPSTATS_UPDATE(vp, map);
	return (err);
}

int
fop_addmap(
	vnode_t *vp,
	offset_t off,
	struct as *as,
	caddr_t addr,
	size_t len,
	uchar_t prot,
	uchar_t maxprot,
	uint_t flags,
	cred_t *cr,
	caller_context_t *ct)
{
	int error;

	VOPXID_MAP_CR(vp, cr);

	error = (*(vp)->v_op->vop_addmap)
	    (vp, off, as, addr, len, prot, maxprot, flags, cr, ct);

	VOPSTATS_UPDATE(vp, addmap);
	return (error);
}

int
fop_delmap(
	vnode_t *vp,
	offset_t off,
	struct as *as,
	caddr_t addr,
	size_t len,
	uint_t prot,
	uint_t maxprot,
	uint_t flags,
	cred_t *cr,
	caller_context_t *ct)
{
	int error;

	VOPXID_MAP_CR(vp, cr);

	error = (*(vp)->v_op->vop_delmap)
	    (vp, off, as, addr, len, prot, maxprot, flags, cr, ct);

	VOPSTATS_UPDATE(vp, delmap);
	return (error);
}


int
fop_poll(
	vnode_t *vp,
	short events,
	int anyyet,
	short *reventsp,
	struct pollhead **phpp,
	caller_context_t *ct)
{
	int	err;

	err = (*(vp)->v_op->vop_poll)(vp, events, anyyet, reventsp, phpp, ct);
	VOPSTATS_UPDATE(vp, poll);
	return (err);
}

int
fop_dump(
	vnode_t *vp,
	caddr_t addr,
	offset_t lbdn,
	offset_t dblks,
	caller_context_t *ct)
{
	int	err;

	/* ensure lbdn and dblks can be passed safely to bdev_dump */
	if ((lbdn != (daddr_t)lbdn) || (dblks != (int)dblks))
		return (EIO);

	err = (*(vp)->v_op->vop_dump)(vp, addr, lbdn, dblks, ct);
	VOPSTATS_UPDATE(vp, dump);
	return (err);
}

int
fop_pathconf(
	vnode_t *vp,
	int cmd,
	ulong_t *valp,
	cred_t *cr,
	caller_context_t *ct)
{
	int	err;

	VOPXID_MAP_CR(vp, cr);

	err = (*(vp)->v_op->vop_pathconf)(vp, cmd, valp, cr, ct);
	VOPSTATS_UPDATE(vp, pathconf);
	return (err);
}

int
fop_pageio(
	vnode_t *vp,
	struct page *pp,
	u_offset_t io_off,
	size_t io_len,
	int flags,
	cred_t *cr,
	caller_context_t *ct)
{
	int	err;

	VOPXID_MAP_CR(vp, cr);

	err = (*(vp)->v_op->vop_pageio)(vp, pp, io_off, io_len, flags, cr, ct);
	VOPSTATS_UPDATE(vp, pageio);
	return (err);
}

int
fop_dumpctl(
	vnode_t *vp,
	int action,
	offset_t *blkp,
	caller_context_t *ct)
{
	int	err;
	err = (*(vp)->v_op->vop_dumpctl)(vp, action, blkp, ct);
	VOPSTATS_UPDATE(vp, dumpctl);
	return (err);
}

void
fop_dispose(
	vnode_t *vp,
	page_t *pp,
	int flag,
	int dn,
	cred_t *cr,
	caller_context_t *ct)
{
	/* Must do stats first since it's possible to lose the vnode */
	VOPSTATS_UPDATE(vp, dispose);

	VOPXID_MAP_CR(vp, cr);

	(*(vp)->v_op->vop_dispose)(vp, pp, flag, dn, cr, ct);
}

int
fop_setsecattr(
	vnode_t *vp,
	vsecattr_t *vsap,
	int flag,
	cred_t *cr,
	caller_context_t *ct)
{
	int	err;

	VOPXID_MAP_CR(vp, cr);

	/*
	 * We're only allowed to skip the ACL check iff we used a 32 bit
	 * ACE mask with VOP_ACCESS() to determine permissions.
	 */
	if ((flag & ATTR_NOACLCHECK) &&
	    vfs_has_feature(vp->v_vfsp, VFSFT_ACEMASKONACCESS) == 0) {
		return (EINVAL);
	}
	err = (*(vp)->v_op->vop_setsecattr) (vp, vsap, flag, cr, ct);
	VOPSTATS_UPDATE(vp, setsecattr);
	return (err);
}

int
fop_getsecattr(
	vnode_t *vp,
	vsecattr_t *vsap,
	int flag,
	cred_t *cr,
	caller_context_t *ct)
{
	int	err;

	/*
	 * We're only allowed to skip the ACL check iff we used a 32 bit
	 * ACE mask with VOP_ACCESS() to determine permissions.
	 */
	if ((flag & ATTR_NOACLCHECK) &&
	    vfs_has_feature(vp->v_vfsp, VFSFT_ACEMASKONACCESS) == 0) {
		return (EINVAL);
	}

	VOPXID_MAP_CR(vp, cr);

	err = (*(vp)->v_op->vop_getsecattr) (vp, vsap, flag, cr, ct);
	VOPSTATS_UPDATE(vp, getsecattr);
	return (err);
}

int
fop_shrlock(
	vnode_t *vp,
	int cmd,
	struct shrlock *shr,
	int flag,
	cred_t *cr,
	caller_context_t *ct)
{
	int	err;

	VOPXID_MAP_CR(vp, cr);

	err = (*(vp)->v_op->vop_shrlock)(vp, cmd, shr, flag, cr, ct);
	VOPSTATS_UPDATE(vp, shrlock);
	return (err);
}

int
fop_vnevent(vnode_t *vp, vnevent_t vnevent, vnode_t *dvp, char *fnm,
    caller_context_t *ct)
{
	int	err;

	err = (*(vp)->v_op->vop_vnevent)(vp, vnevent, dvp, fnm, ct);
	VOPSTATS_UPDATE(vp, vnevent);
	return (err);
}

// fop_reqzcbuf
// fop_retzcbuf

// vsd_defaultdestructor
// vsd_create, vsd_destroy
// vsd_get, vsd_set
// vsd_free, vsd_realloc

static int
fs_reparse_mark(char *target, vattr_t *vap, xvattr_t *xvattr)
{
	return (-1);
}

/*
 * Function to check whether a symlink is a reparse point.
 * Return B_TRUE if it is a reparse point, else return B_FALSE
 */
boolean_t
vn_is_reparse(vnode_t *vp, cred_t *cr, caller_context_t *ct)
{
	xvattr_t xvattr;
	xoptattr_t *xoap;

	if ((vp->v_type != VLNK) ||
	    !(vfs_has_feature(vp->v_vfsp, VFSFT_XVATTR)))
		return (B_FALSE);

	xva_init(&xvattr);
	xoap = xva_getxoptattr(&xvattr);
	ASSERT(xoap);
	XVA_SET_REQ(&xvattr, XAT_REPARSE);

	if (VOP_GETATTR(vp, &xvattr.xva_vattr, 0, cr, ct))
		return (B_FALSE);

	if ((!(xvattr.xva_vattr.va_mask & AT_XVATTR)) ||
	    (!(XVA_ISSET_RTN(&xvattr, XAT_REPARSE))))
		return (B_FALSE);

	return (xoap->xoa_reparse ? B_TRUE : B_FALSE);
}
