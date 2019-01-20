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
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/


#include <sys/types.h>
#include <sys/param.h>
#include <sys/cmn_err.h>
#include <sys/cred.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/proc.h>
#include <sys/procfs.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/zone.h>
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
#include <fs/fs_subr.h>
#include <fs/proc/prdata.h>

/*
 * This is the loadable module wrapper.
 */
#include <sys/modctl.h>

static int prinit();

static mntopts_t proc_mntopts = {
	.mo_count = 0,
	.mo_list = NULL
};

static vfsdef_t vfw = {
	VFSDEF_VERSION,
	"proc",
	prinit,
	VSW_HASPROTO|VSW_STATS|VSW_XID|VSW_ZMOUNT,
	&proc_mntopts
};

/*
 * Module linkage information for the kernel.
 */
extern struct mod_ops mod_fsops;

static struct modlfs modlfs = {
	&mod_fsops, "filesystem for proc", &vfw
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

/*
 * N.B.
 * No _fini routine. The module cannot be unloaded once loaded.
 * The NO_UNLOAD_STUB in modstubs.s must change if this module
 * is ever modified to become unloadable.
 */

int		nproc_highbit;		/* highbit(v.v_nproc) */

static int	procfstype;
static major_t	procfs_major;
static minor_t	procfs_minor;
static kmutex_t	procfs_minor_lock;

static kmutex_t	pr_mount_lock;

/*
 * /proc VFS operations vector.
 */
static int	prmount(), prunmount(), prroot(), prstatvfs();

static void
prinitrootnode(prnode_t *pnp, vfs_t *vfsp)
{
	struct vnode *vp;

	bzero((caddr_t)pnp, sizeof (*pnp));
	pnp->pr_vnode = vp = vn_alloc(KM_SLEEP);

	mutex_init(&pnp->pr_mutex, NULL, MUTEX_DEFAULT, NULL);
	vp->v_flag = VROOT|VNOCACHE|VNOMAP|VNOSWAP|VNOMOUNT;
	VN_SET_VFS_TYPE_DEV(vp, vfsp, VDIR, 0);
	vn_setops(vp, prvnodeops);
	vp->v_data = (caddr_t)pnp;
	pnp->pr_type = PR_PROCDIR;
	pnp->pr_mode = 0555;	/* read-search by everyone */
	vn_exists(vp);
}

static int
prinit(int fstype, char *name)
{
	static const fs_operation_def_t pr_vfsops_template[] = {
		VFSNAME_MOUNT,		{ .vfs_mount = prmount },
		VFSNAME_UNMOUNT,	{ .vfs_unmount = prunmount },
		VFSNAME_ROOT,		{ .vfs_root = prroot },
		VFSNAME_STATVFS,	{ .vfs_statvfs = prstatvfs },
		NULL,			NULL
	};
	extern const fs_operation_def_t pr_vnodeops_template[];
	int error;

	nproc_highbit = highbit(v.v_proc);
	procfstype = fstype;
	ASSERT(procfstype != 0);
	/*
	 * Associate VFS ops vector with this fstype.
	 */
	error = vfs_setfsops(fstype, pr_vfsops_template, NULL);
	if (error != 0) {
		cmn_err(CE_WARN, "prinit: bad vfs ops template");
		return (error);
	}

	/*
	 * Set up vnode ops vector too.
	 */

	error = vn_make_ops(name, pr_vnodeops_template, &prvnodeops);
	if (error != 0) {
		(void) vfs_freevfsops_by_type(fstype);
		cmn_err(CE_WARN, "prinit: bad vnode ops template");
		return (error);
	}

	/*
	 * Assign a unique "device" number (used by stat(2)).
	 */
	if ((procfs_major = getudev()) == (major_t)-1) {
		cmn_err(CE_WARN, "prinit: can't get unique device number");
		procfs_major = 0;
	}
	mutex_init(&pr_mount_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&procfs_minor_lock, NULL, MUTEX_DEFAULT, NULL);

	return (0);
}

/* ARGSUSED */
static int
prmount(struct vfs *vfsp, struct vnode *mvp,
    struct mounta *uap, struct cred *cr)
{
	prnode_t *pnp;
	zone_t *zone = curproc->p_zone;

	if (secpolicy_fs_mount(cr, mvp, vfsp) != 0)
		return (EPERM);

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
	 * Having the resource be anything but "proc" doesn't make sense
	 */
	vfs_setresource(vfsp, "proc", 0);

	pnp = kmem_alloc(sizeof (*pnp), KM_SLEEP);
	mutex_enter(&pr_mount_lock);

	mutex_enter(&mvp->v_lock);
	if ((uap->flags & MS_OVERLAY) == 0 &&
	    (mvp->v_count > 1 || (mvp->v_flag & VROOT))) {
		mutex_exit(&mvp->v_lock);
		mutex_exit(&pr_mount_lock);
		kmem_free(pnp, sizeof (*pnp));
		return (EBUSY);
	}
	mutex_exit(&mvp->v_lock);

	prinitrootnode(pnp, vfsp);
	vfsp->vfs_fstype = procfstype;
	vfsp->vfs_data = (caddr_t)pnp;
	vfsp->vfs_bsize = DEV_BSIZE;
	/*
	 * find an available minor device number for this mount
	 */
	mutex_enter(&procfs_minor_lock);
	do {
		vfsp->vfs_dev = makedevice(procfs_major, procfs_minor);
		procfs_minor = (procfs_minor + 1) & L_MAXMIN32;
	} while (vfs_devismounted(vfsp->vfs_dev));
	mutex_exit(&procfs_minor_lock);
	vfs_make_fsid(&vfsp->vfs_fsid, vfsp->vfs_dev, procfstype);

	mutex_exit(&pr_mount_lock);
	return (0);
}

/* ARGSUSED */
static int
prunmount(struct vfs *vfsp, int flag, struct cred *cr)
{
	prnode_t *pnp = (prnode_t *)vfsp->vfs_data;
	vnode_t *vp = PTOV(pnp);

	mutex_enter(&pr_mount_lock);
	if (secpolicy_fs_unmount(cr, vfsp) != 0) {
		mutex_exit(&pr_mount_lock);
		return (EPERM);
	}

	/*
	 * forced unmount is not supported by this file system
	 * and thus, ENOTSUP, is being returned.
	 */
	if (flag & MS_FORCE) {
		mutex_exit(&pr_mount_lock);
		return (ENOTSUP);
	}

	/*
	 * Ensure that no /proc vnodes are in use on this mount point.
	 */
	mutex_enter(&vp->v_lock);
	if (vp->v_count > 1) {
		mutex_exit(&vp->v_lock);
		mutex_exit(&pr_mount_lock);
		return (EBUSY);
	}

	mutex_exit(&vp->v_lock);
	mutex_exit(&pr_mount_lock);
	vn_invalid(vp);
	vn_free(vp);
	kmem_free(pnp, sizeof (*pnp));
	return (0);
}

/* ARGSUSED */
static int
prroot(struct vfs *vfsp, struct vnode **vpp)
{
	vnode_t *vp = PTOV((prnode_t *)vfsp->vfs_data);

	VN_HOLD(vp);
	*vpp = vp;
	return (0);
}

static int
prstatvfs(struct vfs *vfsp, struct statvfs64 *sp)
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
	(void) strcpy(sp->f_basetype, vfssw[procfstype].vsw_name);
	sp->f_flag = vf_to_stf(vfsp->vfs_flag);
	sp->f_namemax = 64;		/* quite arbitrary */
	bzero(sp->f_fstr, sizeof (sp->f_fstr));
	(void) strcpy(sp->f_fstr, "/proc");
	(void) strcpy(&sp->f_fstr[6], "/proc");
	return (0);
}
