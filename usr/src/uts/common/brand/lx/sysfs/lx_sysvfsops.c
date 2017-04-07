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
 * Copyright 2017 Joyent, Inc.
 */

/*
 * lxsysvfsops.c: vfs operations for lx sysfs.
 *
 * sysfs has a close relationship with the lx getdents(2) syscall. This is
 * necessary so that the getdents code can populate the 'd_type' entries
 * during a sysfs readdir operation. The glibc code which accesses sysfs
 * (specifically the 'cpu' subtree) expects dirents to have the d_type field
 * populated. One problematic consumer is java, which becomes unstable if it
 * gets the incorrect data from glibc. When sysfs loads, it populates the
 * lx_sysfs_vfs_type and lx_sysfs_vtype variables defined in lx_getdents.c.
 * The getdents code can then call into sysfs to determine the d_type for any
 * given inode directory entry.
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

#include "lx_sysfs.h"

/* Module level parameters */
static int	lxsysfstype;
static dev_t	lxsysdev;
static kmutex_t	lxsys_mount_lock;

extern int	lx_sysfs_vfs_type;
extern int	(*lx_sysfs_vtype)(ino_t);

static int lxsys_mount(vfs_t *, vnode_t *, mounta_t *, cred_t *);
static int lxsys_unmount(vfs_t *, int, cred_t *);
static int lxsys_root(vfs_t *, vnode_t **);
static int lxsys_statvfs(vfs_t *, statvfs64_t *);
static int lxsys_init(int, char *);

static vfsdef_t vfw = {
	VFSDEF_VERSION,
	"lx_sysfs",
	lxsys_init,
	VSW_ZMOUNT,
	NULL
};

/*
 * Module linkage information for the kernel.
 */
extern struct mod_ops mod_fsops;

static struct modlfs modlfs = {
	&mod_fsops, "lx brand sysfs", &vfw
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

	lx_sysfs_vfs_type = 0;
	lx_sysfs_vtype = NULL;

	/*
	 * destroy lxsys_node cache
	 */
	lxsys_fininodecache();

	/*
	 * clean out the vfsops and vnodeops
	 */
	(void) vfs_freevfsops_by_type(lxsysfstype);
	vn_freevnodeops(lxsys_vnodeops);

	mutex_destroy(&lxsys_mount_lock);
done:
	return (retval);
}

static int
lxsys_init(int fstype, char *name)
{
	static const fs_operation_def_t lxsys_vfsops_template[] = {
		VFSNAME_MOUNT,		{ .vfs_mount = lxsys_mount },
		VFSNAME_UNMOUNT,	{ .vfs_unmount = lxsys_unmount },
		VFSNAME_ROOT,		{ .vfs_root = lxsys_root },
		VFSNAME_STATVFS,	{ .vfs_statvfs = lxsys_statvfs },
		NULL,			NULL
	};
	extern const fs_operation_def_t lxsys_vnodeops_template[];
	int error;
	major_t dev;

	lx_sysfs_vtype = lxsys_ino_get_type;
	lx_sysfs_vfs_type = lxsysfstype = fstype;
	ASSERT(lxsysfstype != 0);

	mutex_init(&lxsys_mount_lock, NULL, MUTEX_DEFAULT, NULL);

	/*
	 * Associate VFS ops vector with this fstype.
	 */
	error = vfs_setfsops(fstype, lxsys_vfsops_template, NULL);
	if (error != 0) {
		cmn_err(CE_WARN, "lxsys_init: bad vfs ops template");
		return (error);
	}

	/*
	 * Set up vnode ops vector too.
	 */
	error = vn_make_ops(name, lxsys_vnodeops_template, &lxsys_vnodeops);
	if (error != 0) {
		(void) vfs_freevfsops_by_type(fstype);
		cmn_err(CE_WARN, "lxsys_init: bad vnode ops template");
		return (error);
	}

	/*
	 * Assign a unique "device" number (used by stat(2)).
	 */
	if ((dev = getudev()) == (major_t)-1) {
		cmn_err(CE_WARN, "lxsys_init: can't get unique device number");
		dev = 0;
	}

	/*
	 * Make the pseudo device
	 */
	lxsysdev = makedevice(dev, 0);

	/*
	 * Initialise cache for lxsys_nodes
	 */
	lxsys_initnodecache();

	return (0);
}

static int
lxsys_mount(vfs_t *vfsp, vnode_t *mvp, mounta_t *uap, cred_t *cr)
{
	lxsys_mnt_t *lxsys_mnt;
	zone_t *zone = curproc->p_zone;

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
	 * Having the resource be anything but "lxsys" doesn't make sense
	 */
	vfs_setresource(vfsp, "lxsys", 0);

	lxsys_mnt = kmem_alloc(sizeof (*lxsys_mnt), KM_SLEEP);

	mutex_enter(&lxsys_mount_lock);

	/*
	 * Ensure we don't allow overlaying mounts
	 */
	mutex_enter(&mvp->v_lock);
	if ((uap->flags & MS_OVERLAY) == 0 &&
	    (mvp->v_count > 1 || (mvp->v_flag & VROOT))) {
		mutex_exit(&mvp->v_lock);
		mutex_exit(&lxsys_mount_lock);
		kmem_free(lxsys_mnt, sizeof ((*lxsys_mnt)));
		return (EBUSY);
	}
	mutex_exit(&mvp->v_lock);


	mutex_init(&lxsys_mnt->lxsysm_lock, NULL, MUTEX_DEFAULT, NULL);
	zone_hold(lxsys_mnt->lxsysm_zone = zone);

	/* Arbitrarily set the parent vnode to the mounted over directory */
	lxsys_mnt->lxsysm_node = lxsys_getnode(mvp, LXSYS_STATIC,
	    LXSYS_INST_ROOT, 0);
	lxsys_mnt->lxsysm_node->lxsys_next = NULL;

	/* Correctly set the fs for the root node */
	lxsys_mnt->lxsysm_node->lxsys_vnode->v_vfsp = vfsp;

	vfs_make_fsid(&vfsp->vfs_fsid, lxsysdev, lxsysfstype);
	vfsp->vfs_bsize = DEV_BSIZE;
	vfsp->vfs_fstype = lxsysfstype;
	vfsp->vfs_data = (caddr_t)lxsys_mnt;
	vfsp->vfs_dev = lxsysdev;

	mutex_exit(&lxsys_mount_lock);

	return (0);
}

static int
lxsys_unmount(vfs_t *vfsp, int flag, cred_t *cr)
{
	lxsys_mnt_t *lxsys_mnt = (lxsys_mnt_t *)vfsp->vfs_data;
	lxsys_node_t *lnp;
	vnode_t *vp;
	int count;

	VERIFY(lxsys_mnt != NULL);

	mutex_enter(&lxsys_mount_lock);

	/* must be root to unmount */
	if (secpolicy_fs_unmount(cr, vfsp) != 0) {
		mutex_exit(&lxsys_mount_lock);
		return (EPERM);
	}

	/* forced unmount is not supported by this fs */
	if (flag & MS_FORCE) {
		mutex_exit(&lxsys_mount_lock);
		return (ENOTSUP);
	}

	/* Ensure that no vnodes are in use on this mount point. */
	lnp = lxsys_mnt->lxsysm_node;
	vp = LXSTOV(lnp);
	mutex_enter(&vp->v_lock);
	count = vp->v_count;
	mutex_exit(&vp->v_lock);
	if (count > 1) {
		mutex_exit(&lxsys_mount_lock);
		return (EBUSY);
	}

	/*
	 * If there are no references to the root vnode the list of persistent
	 * static vnodes should be empty
	 */
	VERIFY(lnp->lxsys_next == NULL);

	(void) dnlc_purge_vfsp(vfsp, 0);

	lxsys_mnt->lxsysm_node = NULL;
	lxsys_freenode(lnp);
	zone_rele(lxsys_mnt->lxsysm_zone);
	vfsp->vfs_data = NULL;
	kmem_free(lxsys_mnt, sizeof (*lxsys_mnt));

	mutex_exit(&lxsys_mount_lock);

	return (0);
}

static int
lxsys_root(vfs_t *vfsp, vnode_t **vpp)
{
	lxsys_mnt_t *lxsm = (lxsys_mnt_t *)vfsp->vfs_data;
	vnode_t *vp;

	VERIFY(lxsm != NULL);
	VERIFY(lxsm->lxsysm_node != NULL);

	vp = LXSTOV(lxsm->lxsysm_node);
	VN_HOLD(vp);
	*vpp = vp;

	return (0);
}

static int
lxsys_statvfs(vfs_t *vfsp, statvfs64_t *sp)
{
	dev32_t d32;

	bzero((caddr_t)sp, sizeof (*sp));
	sp->f_bsize	= DEV_BSIZE;
	sp->f_frsize	= DEV_BSIZE;
	sp->f_blocks	= (fsblkcnt64_t)0;
	sp->f_bfree	= (fsblkcnt64_t)0;
	sp->f_bavail	= (fsblkcnt64_t)0;
	sp->f_files	= (fsfilcnt64_t)3;
	sp->f_ffree	= (fsfilcnt64_t)0;	/* none */
	sp->f_favail	= (fsfilcnt64_t)0;	/* none */
	(void) cmpldev(&d32, vfsp->vfs_dev);
	sp->f_fsid	= d32;
	/* It is guaranteed that vsw_name will fit in f_basetype */
	(void) strcpy(sp->f_basetype, vfssw[lxsysfstype].vsw_name);
	sp->f_flag = vf_to_stf(vfsp->vfs_flag);
	sp->f_namemax = 64;		/* quite arbitrary */
	bzero(sp->f_fstr, sizeof (sp->f_fstr));

	/* We know f_fstr is 32 chars */
	(void) strcpy(sp->f_fstr, "/sys");
	(void) strcpy(&sp->f_fstr[6], "/sys");

	return (0);
}
