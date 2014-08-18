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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * lxprvfsops.c: vfs operations for /lxprocfs.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/cmn_err.h>
#include <sys/cred.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/var.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/vnode.h>
#include <sys/mode.h>
#include <sys/signal.h>
#include <sys/user.h>
#include <sys/mount.h>
#include <sys/bitmap.h>
#include <sys/kmem.h>
#include <sys/policy.h>
#include <sys/modctl.h>
#include <sys/sunddi.h>
#include <sys/sunldi.h>
#include <sys/lx_impl.h>

#include "lx_proc.h"

/* Module level parameters */
static int	lxprocfstype;
static dev_t	lxprocdev;
static kmutex_t	lxpr_mount_lock;

int nproc_highbit;	/* highbit(v.v_nproc) */

static int lxpr_mount(vfs_t *, vnode_t *, mounta_t *, cred_t *);
static int lxpr_unmount(vfs_t *, int, cred_t *);
static int lxpr_root(vfs_t *, vnode_t **);
static int lxpr_statvfs(vfs_t *, statvfs64_t *);
static int lxpr_init(int, char *);

static vfsdef_t vfw = {
	VFSDEF_VERSION,
	"lx_proc",
	lxpr_init,
	VSW_ZMOUNT,
	NULL
};

/*
 * Module linkage information for the kernel.
 */
extern struct mod_ops mod_fsops;

static struct modlfs modlfs = {
	&mod_fsops, "lx brand procfs", &vfw
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlfs, NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	int retval;

	/*
	 * attempt to unload the module
	 */
	if ((retval = mod_remove(&modlinkage)) != 0)
		goto done;

	/*
	 * destroy lxpr_node cache
	 */
	lxpr_fininodecache();

	/*
	 * clean out the vfsops and vnodeops
	 */
	(void) vfs_freevfsops_by_type(lxprocfstype);
	vn_freevnodeops(lxpr_vnodeops);

	mutex_destroy(&lxpr_mount_lock);
done:
	return (retval);
}

static int
lxpr_init(int fstype, char *name)
{
	static const fs_operation_def_t lxpr_vfsops_template[] = {
		VFSNAME_MOUNT,		{ .vfs_mount = lxpr_mount },
		VFSNAME_UNMOUNT,	{ .vfs_unmount = lxpr_unmount },
		VFSNAME_ROOT,		{ .vfs_root = lxpr_root },
		VFSNAME_STATVFS,	{ .vfs_statvfs = lxpr_statvfs },
		NULL,			NULL
	};
	extern const fs_operation_def_t lxpr_vnodeops_template[];
	int error;
	major_t dev;

	nproc_highbit = highbit(v.v_proc);
	lxprocfstype = fstype;
	ASSERT(lxprocfstype != 0);

	mutex_init(&lxpr_mount_lock, NULL, MUTEX_DEFAULT, NULL);

	/*
	 * Associate VFS ops vector with this fstype.
	 */
	error = vfs_setfsops(fstype, lxpr_vfsops_template, NULL);
	if (error != 0) {
		cmn_err(CE_WARN, "lxpr_init: bad vfs ops template");
		return (error);
	}

	/*
	 * Set up vnode ops vector too.
	 */
	error = vn_make_ops(name, lxpr_vnodeops_template, &lxpr_vnodeops);
	if (error != 0) {
		(void) vfs_freevfsops_by_type(fstype);
		cmn_err(CE_WARN, "lxpr_init: bad vnode ops template");
		return (error);
	}

	/*
	 * Assign a unique "device" number (used by stat(2)).
	 */
	if ((dev = getudev()) == (major_t)-1) {
		cmn_err(CE_WARN, "lxpr_init: can't get unique device number");
		dev = 0;
	}

	/*
	 * Make the pseudo device
	 */
	lxprocdev = makedevice(dev, 0);

	/*
	 * Initialise cache for lxpr_nodes
	 */
	lxpr_initnodecache();

	return (0);
}

static int
lxpr_mount(vfs_t *vfsp, vnode_t *mvp, mounta_t *uap, cred_t *cr)
{
	lxpr_mnt_t *lxpr_mnt;
	zone_t *zone = curproc->p_zone;
	ldi_ident_t li;
	int err;

	/*
	 * must be root to mount
	 */
	if (secpolicy_fs_mount(cr, mvp, vfsp) != 0)
		return (EPERM);

	/*
	 * mount point must be a directory
	 */
	if (mvp->v_type != VDIR)
		return (ENOTDIR);

	if (zone == global_zone) {
		zone_t *mntzone;

		mntzone = zone_find_by_path(refstr_value(vfsp->vfs_mntpt));
		zone_rele(mntzone);
		if (zone != mntzone)
			return (EBUSY);
	}

	/*
	 * Having the resource be anything but "lxproc" doesn't make sense
	 */
	vfs_setresource(vfsp, "lxproc", 0);

	lxpr_mnt = kmem_alloc(sizeof (*lxpr_mnt), KM_SLEEP);

	if ((err = ldi_ident_from_mod(&modlinkage, &li)) != 0) {
		kmem_free(lxpr_mnt, sizeof (*lxpr_mnt));
		return (err);
	}

	lxpr_mnt->lxprm_li = li;

	mutex_enter(&lxpr_mount_lock);

	/*
	 * Ensure we don't allow overlaying mounts
	 */
	mutex_enter(&mvp->v_lock);
	if ((uap->flags & MS_OVERLAY) == 0 &&
	    (mvp->v_count > 1 || (mvp->v_flag & VROOT))) {
		mutex_exit(&mvp->v_lock);
		mutex_exit(&lxpr_mount_lock);
		kmem_free(lxpr_mnt, sizeof ((*lxpr_mnt)));
		return (EBUSY);
	}
	mutex_exit(&mvp->v_lock);

	/*
	 * allocate the first vnode
	 */
	zone_hold(lxpr_mnt->lxprm_zone = zone);

	/* Arbitrarily set the parent vnode to the mounted over directory */
	lxpr_mnt->lxprm_node = lxpr_getnode(mvp, LXPR_PROCDIR, NULL, 0);

	/* Correctly set the fs for the root node */
	lxpr_mnt->lxprm_node->lxpr_vnode->v_vfsp = vfsp;

	vfs_make_fsid(&vfsp->vfs_fsid, lxprocdev, lxprocfstype);
	vfsp->vfs_bsize = DEV_BSIZE;
	vfsp->vfs_fstype = lxprocfstype;
	vfsp->vfs_data = (caddr_t)lxpr_mnt;
	vfsp->vfs_dev = lxprocdev;

	mutex_exit(&lxpr_mount_lock);

	return (0);
}

static int
lxpr_unmount(vfs_t *vfsp, int flag, cred_t *cr)
{
	lxpr_mnt_t *lxpr_mnt = (lxpr_mnt_t *)vfsp->vfs_data;
	vnode_t *vp;
	int count;

	ASSERT(lxpr_mnt != NULL);
	vp = LXPTOV(lxpr_mnt->lxprm_node);

	mutex_enter(&lxpr_mount_lock);

	/*
	 * must be root to unmount
	 */
	if (secpolicy_fs_unmount(cr, vfsp) != 0) {
		mutex_exit(&lxpr_mount_lock);
		return (EPERM);
	}

	/*
	 * forced unmount is not supported by this file system
	 */
	if (flag & MS_FORCE) {
		mutex_exit(&lxpr_mount_lock);
		return (ENOTSUP);
	}

	/*
	 * Ensure that no vnodes are in use on this mount point.
	 */
	mutex_enter(&vp->v_lock);
	count = vp->v_count;
	mutex_exit(&vp->v_lock);
	if (count > 1) {
		mutex_exit(&lxpr_mount_lock);
		return (EBUSY);
	}


	/*
	 * purge the dnlc cache for vnode entries
	 * associated with this file system
	 */
	count = dnlc_purge_vfsp(vfsp, 0);

	/*
	 * free up the lxprnode
	 */
	lxpr_freenode(lxpr_mnt->lxprm_node);
	zone_rele(lxpr_mnt->lxprm_zone);
	kmem_free(lxpr_mnt, sizeof (*lxpr_mnt));

	mutex_exit(&lxpr_mount_lock);

	return (0);
}

static int
lxpr_root(vfs_t *vfsp, vnode_t **vpp)
{
	lxpr_node_t *lxpnp = ((lxpr_mnt_t *)vfsp->vfs_data)->lxprm_node;
	vnode_t *vp = LXPTOV(lxpnp);

	VN_HOLD(vp);
	*vpp = vp;
	return (0);
}

static int
lxpr_statvfs(vfs_t *vfsp, statvfs64_t *sp)
{
	int n;
	dev32_t d32;
	extern uint_t nproc;

	n = v.v_proc - nproc;

	bzero((caddr_t)sp, sizeof (*sp));
	sp->f_bsize	= DEV_BSIZE;
	sp->f_frsize	= DEV_BSIZE;
	sp->f_blocks	= (fsblkcnt64_t)0;
	sp->f_bfree	= (fsblkcnt64_t)0;
	sp->f_bavail	= (fsblkcnt64_t)0;
	sp->f_files	= (fsfilcnt64_t)v.v_proc + 2;
	sp->f_ffree	= (fsfilcnt64_t)n;
	sp->f_favail	= (fsfilcnt64_t)n;
	(void) cmpldev(&d32, vfsp->vfs_dev);
	sp->f_fsid	= d32;
	/* It is guaranteed that vsw_name will fit in f_basetype */
	(void) strcpy(sp->f_basetype, vfssw[lxprocfstype].vsw_name);
	sp->f_flag = vf_to_stf(vfsp->vfs_flag);
	sp->f_namemax = 64;		/* quite arbitrary */
	bzero(sp->f_fstr, sizeof (sp->f_fstr));

	/* We know f_fstr is 32 chars */
	(void) strcpy(sp->f_fstr, "/proc");
	(void) strcpy(&sp->f_fstr[6], "/proc");

	return (0);
}
