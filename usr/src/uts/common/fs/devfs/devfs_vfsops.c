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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This is the device filesystem.
 *
 * It is a combination of a namer to drive autoconfiguration,
 * plus the access methods for the device drivers of the system.
 *
 * The prototype is fairly dependent on specfs for the latter part
 * of its implementation, though a final version would integrate the two.
 */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/kmem.h>
#include <sys/time.h>
#include <sys/pathname.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/vnode.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <sys/cmn_err.h>
#include <sys/cred.h>
#include <sys/statvfs.h>
#include <sys/mount.h>
#include <sys/debug.h>
#include <sys/modctl.h>
#include <fs/fs_subr.h>
#include <sys/fs/dv_node.h>
#include <sys/fs/snode.h>
#include <sys/sunndi.h>
#include <sys/policy.h>
#include <sys/sunmdi.h>

/*
 * devfs vfs operations.
 */
static int devfs_mount(struct vfs *, struct vnode *, struct mounta *,
    struct cred *);
static int devfs_unmount(struct vfs *, int, struct cred *);
static int devfs_root(struct vfs *, struct vnode **);
static int devfs_statvfs(struct vfs *, struct statvfs64 *);
static int devfs_mountroot(struct vfs *, enum whymountroot);

static int devfsinit(int, char *);

static vfsdef_t devfs_vfssw = {
	VFSDEF_VERSION,
	"devfs",	/* type name string */
	devfsinit,	/* init routine */
	0,		/* flags */
	NULL		/* mount options table prototype */
};

static kmutex_t devfs_lock;	/* protects global data */
static int devfstype;		/* fstype */
static dev_t devfsdev;		/* the fictious 'device' we live on */
static struct devfs_data *devfs_mntinfo;	/* linked list of instances */

/*
 * Module linkage information
 */
static struct modlfs modlfs = {
	&mod_fsops, "devices filesystem", &devfs_vfssw
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlfs, NULL
};

int
_init(void)
{
	int e;

	mutex_init(&devfs_lock, "devfs lock", MUTEX_DEFAULT, NULL);
	dv_node_cache_init();
	if ((e = mod_install(&modlinkage)) != 0) {
		dv_node_cache_fini();
		mutex_destroy(&devfs_lock);
		return (e);
	}
	dcmn_err(("devfs loaded\n"));
	return (0);
}

int
_fini(void)
{
	return (EBUSY);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*ARGSUSED1*/
static int
devfsinit(int fstype, char *name)
{
	static const fs_operation_def_t devfs_vfsops_template[] = {
		VFSNAME_MOUNT,		{ .vfs_mount = devfs_mount },
		VFSNAME_UNMOUNT,	{ .vfs_unmount = devfs_unmount },
		VFSNAME_ROOT,		{ .vfs_root = devfs_root },
		VFSNAME_STATVFS,	{ .vfs_statvfs = devfs_statvfs },
		VFSNAME_SYNC,		{ .vfs_sync = fs_sync },
		VFSNAME_MOUNTROOT,	{ .vfs_mountroot = devfs_mountroot },
		NULL,			NULL
	};
	int error;
	int dev;
	extern major_t getudev(void);	/* gack - what a function */

	devfstype = fstype;
	/*
	 * Associate VFS ops vector with this fstype
	 */
	error = vfs_setfsops(fstype, devfs_vfsops_template, NULL);
	if (error != 0) {
		cmn_err(CE_WARN, "devfsinit: bad vfs ops template");
		return (error);
	}

	error = vn_make_ops("dev fs", dv_vnodeops_template, &dv_vnodeops);
	if (error != 0) {
		(void) vfs_freevfsops_by_type(fstype);
		cmn_err(CE_WARN, "devfsinit: bad vnode ops template");
		return (error);
	}

	/*
	 * Invent a dev_t (sigh).
	 */
	if ((dev = getudev()) == DDI_MAJOR_T_NONE) {
		cmn_err(CE_NOTE, "%s: can't get unique dev", devfs_vfssw.name);
		dev = 0;
	}
	devfsdev = makedevice(dev, 0);

	return (0);
}

/*
 * The name of the mount point and the name of the attribute
 * filesystem are passed down from userland for now.
 */
static int
devfs_mount(struct vfs *vfsp, struct vnode *mvp, struct mounta *uap,
    struct cred *cr)
{
	struct devfs_data *devfs_data;
	struct vnode *avp;
	struct dv_node *dv;
	struct vattr va;

	dcmn_err(("devfs_mount\n"));

	if (secpolicy_fs_mount(cr, mvp, vfsp) != 0)
		return (EPERM);

	/*
	 * check that the mount point is sane
	 */
	if (mvp->v_type != VDIR)
		return (ENOTDIR);

	ASSERT(uap->flags & MS_SYSSPACE);
	/*
	 * Devfs can only be mounted from kernel during boot.
	 * avp is the existing /devices, the same as the mount point.
	 */
	avp = mvp;

	/*
	 * Create and initialize the vfs-private data.
	 * This includes a hand-crafted root vnode (we build
	 * this here mostly so that traverse() doesn't sleep
	 * in VFS_ROOT()).
	 */
	mutex_enter(&devfs_lock);
	ASSERT(devfs_mntinfo == NULL);
	dv = dv_mkroot(vfsp, devfsdev);
	dv->dv_attrvp = avp;		/* attribute root vp */

	ASSERT(dv == dv->dv_dotdot);

	devfs_data = kmem_zalloc(sizeof (struct devfs_data), KM_SLEEP);
	devfs_data->devfs_vfsp = vfsp;
	devfs_data->devfs_root = dv;

	vfsp->vfs_data = (caddr_t)devfs_data;
	vfsp->vfs_fstype = devfstype;
	vfsp->vfs_dev = devfsdev;
	vfsp->vfs_bsize = DEV_BSIZE;
	vfsp->vfs_mtime = ddi_get_time();
	vfs_make_fsid(&vfsp->vfs_fsid, vfsp->vfs_dev, devfstype);

	/* We're there. */
	devfs_mntinfo = devfs_data;
	mutex_exit(&devfs_lock);

	va.va_mask = AT_ATIME|AT_MTIME;
	gethrestime(&va.va_atime);
	gethrestime(&va.va_mtime);
	(void) VOP_SETATTR(DVTOV(dv), &va, 0, cr, NULL);
	return (0);
}


/*
 * We never unmount devfs in a real production system.
 */
/*ARGSUSED*/
static int
devfs_unmount(struct vfs *vfsp, int flag, struct cred *cr)
{
	return (EBUSY);
}

/*
 * return root vnode for given vfs
 */
static int
devfs_root(struct vfs *vfsp, struct vnode **vpp)
{
	dcmn_err(("devfs_root\n"));
	*vpp = DVTOV(VFSTODVFS(vfsp)->devfs_root);
	VN_HOLD(*vpp);
	return (0);
}

/*
 * return 'generic superblock' information to userland.
 *
 * not much that we can usefully admit to here
 */
static int
devfs_statvfs(struct vfs *vfsp, struct statvfs64 *sbp)
{
	extern kmem_cache_t *dv_node_cache;

	dev32_t d32;

	dcmn_err(("devfs_statvfs\n"));
	bzero(sbp, sizeof (*sbp));
	sbp->f_frsize = sbp->f_bsize = vfsp->vfs_bsize;
	/*
	 * We could compute the number of devfsnodes here .. but since
	 * it's dynamic anyway, it's not clear how useful this is.
	 */
	sbp->f_files = kmem_cache_stat(dv_node_cache, "alloc");

	/* no illusions that free/avail files is relevant to devfs */
	sbp->f_ffree = 0;
	sbp->f_favail = 0;

	/* no illusions that blocks are relevant to devfs */
	sbp->f_bfree = 0;
	sbp->f_bavail = 0;
	sbp->f_blocks = 0;

	(void) cmpldev(&d32, vfsp->vfs_dev);
	sbp->f_fsid = d32;
	(void) strcpy(sbp->f_basetype, vfssw[devfstype].vsw_name);
	sbp->f_flag = vf_to_stf(vfsp->vfs_flag);
	sbp->f_namemax = MAXNAMELEN - 1;
	(void) strcpy(sbp->f_fstr, "devices");

	return (0);
}

/*
 * devfs always mount after root is mounted, so this should never
 * be invoked.
 */
/*ARGSUSED*/
static int
devfs_mountroot(struct vfs *vfsp, enum whymountroot why)
{
	dcmn_err(("devfs_mountroot\n"));

	return (EINVAL);
}

struct dv_node *
devfs_dip_to_dvnode(dev_info_t *dip)
{
	char *dirpath;
	struct vnode *dirvp;

	ASSERT(dip != NULL);

	/* no-op if devfs not mounted yet */
	if (devfs_mntinfo == NULL)
		return (NULL);

	/*
	 * The lookupname below only looks up cached dv_nodes
	 * because devfs_clean_key is set in thread specific data.
	 */
	dirpath = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	(void) ddi_pathname(dip, dirpath);
	if (devfs_lookupname(dirpath, NULLVPP, &dirvp)) {
		dcmn_err(("directory %s not found\n", dirpath));
		kmem_free(dirpath, MAXPATHLEN);
		return (NULL);
	}

	kmem_free(dirpath, MAXPATHLEN);
	return (VTODV(dirvp));
}

/*
 * If DV_CLEAN_FORCE devfs_clean is issued with a dip that is not the root
 * and not a vHCI we also need to clean any vHCI branches because they
 * may contain pHCI nodes. A detach_node() of a pHCI will fail if its
 * mdi_devi_offline() fails, and the mdi_devi_offline() of the last
 * pHCI will fail unless an ndi_devi_offline() of the Client nodes under
 * the vHCI is successful - which requires a clean vHCI branch to removed
 * the devi_refs associated with devfs vnodes.
 */
static int
devfs_clean_vhci(dev_info_t *dip, void *args)
{
	struct dv_node	*dvp;
	uint_t		flags = (uint_t)(uintptr_t)args;

	(void) tsd_set(devfs_clean_key, (void *)1);
	dvp = devfs_dip_to_dvnode(dip);
	if (dvp) {
		(void) dv_cleandir(dvp, NULL, flags);
		VN_RELE(DVTOV(dvp));
	}
	(void) tsd_set(devfs_clean_key, NULL);
	return (DDI_WALK_CONTINUE);
}

/*
 * devfs_clean()
 *
 * Destroy unreferenced dv_node's and detach devices.
 *
 * devfs_clean will try its best to clean up unused nodes. It is
 * no longer valid to assume that just because devfs_clean fails,
 * the device is not removable. This is because device contracts
 * can result in userland processes releasing a device during the
 * device offline process in the kernel. Thus it is no longer
 * correct to fail an offline just because devfs_clean finds
 * referenced dv_nodes. To enforce this, devfs_clean() always
 * returns success i.e. 0.
 *
 * devfs_clean() may return before removing all possible nodes if
 * we cannot acquire locks in areas of the code where potential for
 * deadlock exists (see comments in dv_find() and dv_cleandir() for
 * examples of this).
 *
 * devfs caches unreferenced dv_node to speed by the performance
 * of ls, find, etc. devfs_clean() is invoked to cleanup cached
 * dv_nodes to reclaim memory as well as to facilitate device
 * removal (dv_node reference devinfo nodes, which prevents driver
 * detach).
 *
 * If a shell parks in a /devices directory, the dv_node will be
 * held, preventing the corresponding device to be detached.
 * This would be a denial of service against DR. To prevent this,
 * DR code calls devfs_clean() with the DV_CLEAN_FORCE flag.
 * The dv_cleandir() implementation does the right thing to ensure
 * successful DR.
 */
int
devfs_clean(dev_info_t *dip, char *devnm, uint_t flags)
{
	struct dv_node		*dvp;

	dcmn_err(("devfs_unconfigure: dip = 0x%p, flags = 0x%x",
	    (void *)dip, flags));

	/* avoid recursion back into the device tree */
	(void) tsd_set(devfs_clean_key, (void *)1);
	dvp = devfs_dip_to_dvnode(dip);
	if (dvp == NULL) {
		(void) tsd_set(devfs_clean_key, NULL);
		return (0);
	}

	(void) dv_cleandir(dvp, devnm, flags);
	(void) tsd_set(devfs_clean_key, NULL);
	VN_RELE(DVTOV(dvp));

	/*
	 * If we are doing a DV_CLEAN_FORCE, and we did not start at the
	 * root, and we did not start at a vHCI node then clean vHCI
	 * branches too.  Failure to clean vHCI branch does not cause EBUSY.
	 *
	 * Also, to accommodate nexus callers that clean 'self' to DR 'child'
	 * (like pcihp) we clean vHCIs even when dv_cleandir() of dip branch
	 * above fails - this prevents a busy DR 'child' sibling from causing
	 * the DR of 'child' to fail because a vHCI branch was not cleaned.
	 */
	if ((flags & DV_CLEAN_FORCE) && (dip != ddi_root_node()) &&
	    (mdi_component_is_vhci(dip, NULL) != MDI_SUCCESS)) {
		/*
		 * NOTE: for backport the following is recommended
		 * 	(void) devfs_clean_vhci(scsi_vhci_dip,
		 *	    (void *)(uintptr_t)flags);
		 */
		mdi_walk_vhcis(devfs_clean_vhci, (void *)(uintptr_t)flags);
	}

	return (0);
}

/*
 * lookup a devfs relative pathname, returning held vnodes for the final
 * component and the containing directory (if requested).
 *
 * NOTE: We can't use lookupname because this would use the current
 *	processes credentials (CRED) in the call lookuppnvp instead
 *	of kcred.  It also does not give you the flexibility so
 * 	specify the directory to start the resolution in (devicesdir).
 */
int
devfs_lookupname(
	char	*pathname,		/* user pathname */
	vnode_t **dirvpp,		/* ret for ptr to parent dir vnode */
	vnode_t **compvpp)		/* ret for ptr to component vnode */
{
	struct pathname	pn;
	int		error;

	ASSERT(devicesdir);		/* devfs must be initialized */
	ASSERT(pathname);		/* must have some path */

	if (error = pn_get(pathname, UIO_SYSSPACE, &pn))
		return (error);

	/* make the path relative to /devices. */
	pn_skipslash(&pn);
	if (pn_pathleft(&pn) == 0) {
		/* all we had was "\0" or "/" (which skipslash skiped) */
		if (dirvpp)
			*dirvpp = NULL;
		if (compvpp) {
			VN_HOLD(devicesdir);
			*compvpp = devicesdir;
		}
	} else {
		/*
		 * Use devfs lookup to resolve pathname to the vnode for
		 * the device via relative lookup in devfs. Extra holds for
		 * using devicesdir as directory we are searching and for
		 * being our root without being == rootdir.
		 */
		VN_HOLD(devicesdir);
		VN_HOLD(devicesdir);
		error = lookuppnvp(&pn, NULL, FOLLOW, dirvpp, compvpp,
		    devicesdir, devicesdir, kcred);
	}
	pn_free(&pn);

	return (error);
}

/*
 * Given a devfs path (without the /devices prefix), walk
 * the dv_node sub-tree rooted at the path.
 */
int
devfs_walk(
	char		*path,
	void		(*callback)(struct dv_node *, void *),
	void		*arg)
{
	char *dirpath, *devnm;
	struct vnode	*dirvp;

	ASSERT(path && callback);

	if (*path != '/' || devfs_mntinfo == NULL)
		return (ENXIO);

	dcmn_err(("devfs_walk: path = %s", path));

	dirpath = kmem_alloc(MAXPATHLEN, KM_SLEEP);

	(void) snprintf(dirpath, MAXPATHLEN, "/devices%s", path);

	devnm = strrchr(dirpath, '/');

	ASSERT(devnm);

	*devnm++ = '\0';

	if (lookupname(dirpath, UIO_SYSSPACE, 0, NULL, &dirvp)) {
		dcmn_err(("directory %s not found\n", dirpath));
		kmem_free(dirpath, MAXPATHLEN);
		return (ENXIO);
	}

	/*
	 * if path == "/", visit the root dv_node
	 */
	if (*devnm == '\0') {
		callback(VTODV(dirvp), arg);
		devnm = NULL;
	}

	dv_walk(VTODV(dirvp), devnm, callback, arg);

	VN_RELE(dirvp);

	kmem_free(dirpath, MAXPATHLEN);

	return (0);
}

int
devfs_devpolicy(vnode_t *vp, devplcy_t **dpp)
{
	struct vnode *rvp;
	struct dv_node *dvp;
	int rval = -1;

	/* fail if devfs not mounted yet */
	if (devfs_mntinfo == NULL)
		return (rval);

	if (VOP_REALVP(vp, &rvp, NULL) == 0 && vn_matchops(rvp, dv_vnodeops)) {
		dvp = VTODV(rvp);
		rw_enter(&dvp->dv_contents, RW_READER);
		if (dvp->dv_priv) {
			dphold(dvp->dv_priv);
			*dpp = dvp->dv_priv;
			rval = 0;
		}
		rw_exit(&dvp->dv_contents);
	}
	return (rval);
}
