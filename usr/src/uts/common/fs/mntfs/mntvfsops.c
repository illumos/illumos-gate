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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 */

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
#include <sys/fs/mntdata.h>
#include <sys/zone.h>

/*
 * This is the loadable module wrapper.
 */
#include <sys/modctl.h>

static int mntinit(int, char *);

static mntopts_t mnt_mntopts = {
	0,
	NULL
};

static vfsdef_t vfw = {
	VFSDEF_VERSION,
	"mntfs",
	mntinit,
	VSW_HASPROTO|VSW_STATS|VSW_ZMOUNT,
	&mnt_mntopts
};

/*
 * Module linkage information for the kernel.
 */
extern struct mod_ops mod_fsops;

static struct modlfs modlfs = {
	&mod_fsops, "mount information file system", &vfw
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

extern int	mntfstype;
static major_t	mnt_major;
static minor_t	mnt_minor;
static kmutex_t	mnt_minor_lock;

/*
 * /mnttab VFS operations vector.
 */
static int	mntmount(), mntunmount(), mntroot(), mntstatvfs();

static void
mntinitrootnode(mntnode_t *mnp)
{
	struct vnode *vp;

	bzero((caddr_t)mnp, sizeof (*mnp));

	mnp->mnt_vnode = vn_alloc(KM_SLEEP);

	vp = MTOV(mnp);

	vp->v_flag = VROOT|VNOCACHE|VNOMAP|VNOSWAP|VNOMOUNT;
	vn_setops(vp, mntvnodeops);
	vp->v_type = VREG;
	vp->v_data = (caddr_t)mnp;
}

static int
mntinit(int fstype, char *name)
{
	static const fs_operation_def_t mnt_vfsops_template[] = {
		VFSNAME_MOUNT,		{ .vfs_mount = mntmount },
		VFSNAME_UNMOUNT,	{ .vfs_unmount = mntunmount },
		VFSNAME_ROOT,		{ .vfs_root = mntroot },
		VFSNAME_STATVFS,	{ .vfs_statvfs = mntstatvfs },
		NULL,			NULL
	};
	extern const fs_operation_def_t mnt_vnodeops_template[];
	int error;

	mntfstype = fstype;
	ASSERT(mntfstype != 0);
	/*
	 * Associate VFS ops vector with this fstype.
	 */
	error = vfs_setfsops(fstype, mnt_vfsops_template, NULL);
	if (error != 0) {
		cmn_err(CE_WARN, "mntinit: bad vfs ops template");
		return (error);
	}

	/* Vnode ops too. */

	error = vn_make_ops(name, mnt_vnodeops_template, &mntvnodeops);
	if (error != 0) {
		(void) vfs_freevfsops_by_type(fstype);
		cmn_err(CE_WARN, "mntinit: bad vnode ops template");
		return (error);
	}

	/*
	 * Assign a unique "device" number (used by stat(2)).
	 */
	if ((mnt_major = getudev()) == (major_t)-1) {
		cmn_err(CE_WARN, "mntinit: can't get unique device number");
		mnt_major = 0;
	}
	mutex_init(&mnt_minor_lock, NULL, MUTEX_DEFAULT, NULL);

	return (0);
}

/* ARGSUSED */
static int
mntmount(struct vfs *vfsp, struct vnode *mvp,
	struct mounta *uap, struct cred *cr)
{
	mntdata_t *mnt;
	mntnode_t *mnp;
	zone_t *zone = curproc->p_zone;

	if (secpolicy_fs_mount(cr, mvp, vfsp) != 0)
		return (EPERM);

	/*
	 * You can only mount mnttab in your current zone.
	 */
	if (zone == global_zone) {
		zone_t *mntzone;

		mntzone = zone_find_by_path(refstr_value(vfsp->vfs_mntpt));
		ASSERT(mntzone != NULL);
		zone_rele(mntzone);
		if (mntzone != zone)
			return (EBUSY);
	}

	/*
	 * Having the resource be anything but "mnttab" doesn't make sense
	 */
	vfs_setresource(vfsp, "mnttab", 0);

	mnt = kmem_zalloc(sizeof (*mnt), KM_SLEEP);
	mutex_enter(&mvp->v_lock);
	if ((uap->flags & MS_OVERLAY) == 0 &&
	    (mvp->v_count > 1 || (mvp->v_flag & VROOT))) {
		mutex_exit(&mvp->v_lock);
		kmem_free(mnt, sizeof (*mnt));
		return (EBUSY);
	}
	mutex_exit(&mvp->v_lock);

	zone_init_ref(&mnt->mnt_zone_ref);
	zone_hold_ref(zone, &mnt->mnt_zone_ref, ZONE_REF_MNTFS);
	mnp = &mnt->mnt_node;

	vfsp->vfs_fstype = mntfstype;
	vfsp->vfs_data = (caddr_t)mnt;
	/*
	 * find an available minor device number for this mount.
	 */
	mutex_enter(&mnt_minor_lock);
	do {
		mnt_minor = (mnt_minor + 1) & L_MAXMIN32;
		vfsp->vfs_dev = makedevice(mnt_major, mnt_minor);
	} while (vfs_devismounted(vfsp->vfs_dev));
	mutex_exit(&mnt_minor_lock);
	vfs_make_fsid(&vfsp->vfs_fsid, vfsp->vfs_dev, mntfstype);
	vfsp->vfs_bsize = DEV_BSIZE;
	mntinitrootnode(mnp);
	MTOV(mnp)->v_vfsp = vfsp;
	mnp->mnt_mountvp = mvp;
	vn_exists(MTOV(mnp));
	return (0);
}

/* ARGSUSED */
static int
mntunmount(struct vfs *vfsp, int flag, struct cred *cr)
{
	mntdata_t *mnt = (mntdata_t *)vfsp->vfs_data;
	vnode_t *vp = MTOV(&mnt->mnt_node);

	if (secpolicy_fs_unmount(cr, vfsp) != 0)
		return (EPERM);

	/*
	 * Ensure that no /mnttab vnodes are in use on this mount point.
	 */
	mutex_enter(&vp->v_lock);
	if (vp->v_count > 1 || mnt->mnt_nopen > 0) {
		mutex_exit(&vp->v_lock);
		return (EBUSY);
	}

	mutex_exit(&vp->v_lock);
	zone_rele_ref(&mnt->mnt_zone_ref, ZONE_REF_MNTFS);
	vn_invalid(vp);
	vn_free(vp);
	kmem_free(mnt, sizeof (*mnt));
	return (0);
}

/* ARGSUSED */
static int
mntroot(struct vfs *vfsp, struct vnode **vpp)
{
	mntnode_t *mnp = &((mntdata_t *)vfsp->vfs_data)->mnt_node;
	struct vnode *vp = MTOV(mnp);

	VN_HOLD(vp);
	*vpp = vp;
	return (0);
}

static int
mntstatvfs(struct vfs *vfsp, struct statvfs64 *sp)
{
	dev32_t d32;

	bzero((caddr_t)sp, sizeof (*sp));
	sp->f_bsize	= DEV_BSIZE;
	sp->f_frsize	= DEV_BSIZE;
	sp->f_blocks	= (fsblkcnt64_t)0;
	sp->f_bfree	= (fsblkcnt64_t)0;
	sp->f_bavail	= (fsblkcnt64_t)0;
	sp->f_files	= (fsfilcnt64_t)1;
	sp->f_ffree	= (fsfilcnt64_t)0;
	sp->f_favail	= (fsfilcnt64_t)0;
	(void) cmpldev(&d32, vfsp->vfs_dev);
	sp->f_fsid	= d32;
	(void) strcpy(sp->f_basetype, vfssw[mntfstype].vsw_name);
	sp->f_flag = vf_to_stf(vfsp->vfs_flag);
	sp->f_namemax = 64;		/* quite arbitrary */
	bzero(sp->f_fstr, sizeof (sp->f_fstr));
	(void) strcpy(sp->f_fstr, "/mnttab");
	(void) strcpy(&sp->f_fstr[8], "/mnttab");
	return (0);
}
