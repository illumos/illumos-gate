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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2015 Joyent, Inc.  All rights reserved.
 */

/*
 * This is the /dev (hence, the sdev_ prefix) filesystem.
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
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <sys/cmn_err.h>
#include <sys/cred.h>
#include <sys/statvfs.h>
#include <sys/policy.h>
#include <sys/mount.h>
#include <sys/debug.h>
#include <sys/modctl.h>
#include <sys/mkdev.h>
#include <fs/fs_subr.h>
#include <sys/fs/sdev_impl.h>
#include <sys/fs/snode.h>
#include <sys/fs/dv_node.h>
#include <sys/sunndi.h>
#include <sys/mntent.h>
#include <sys/disp.h>

/*
 * /dev vfs operations.
 */

/*
 * globals
 */
struct sdev_data *sdev_origins; /* mount info for origins under /dev */
kmutex_t sdev_lock; /* used for mount/unmount/rename synchronization */
taskq_t *sdev_taskq = NULL;

/*
 * static
 */
static major_t devmajor;	/* the fictitious major we live on */
static major_t devminor;	/* the fictitious minor of this instance */
static struct sdev_data *sdev_mntinfo = NULL;	/* linked list of instances */

/* LINTED E_STATIC_UNUSED */		/* useful for debugging */
static struct vnode *sdev_stale_attrvp; /* stale root attrvp after remount */

static int sdev_mount(struct vfs *, struct vnode *, struct mounta *,
    struct cred *);
static int sdev_unmount(struct vfs *, int, struct cred *);
static int sdev_root(struct vfs *, struct vnode **);
static int sdev_statvfs(struct vfs *, struct statvfs64 *);
static void sdev_insert_mntinfo(struct sdev_data *);
static int devinit(int, char *);

static vfsdef_t sdev_vfssw = {
	VFSDEF_VERSION,
	"dev",		/* type name string */
	devinit,	/* init routine */
	VSW_CANREMOUNT,	/* flags */
	NULL		/* mount options table prototype */
};


/*
 * Module linkage information
 */
static struct modlfs modlfs = {
	&mod_fsops, "/dev filesystem", &sdev_vfssw
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlfs, NULL
};

int
_init(void)
{
	int e;

	mutex_init(&sdev_lock, NULL, MUTEX_DEFAULT, NULL);
	sdev_node_cache_init();
	sdev_devfsadm_lockinit();
	if ((e = mod_install(&modlinkage)) != 0) {
		sdev_devfsadm_lockdestroy();
		sdev_node_cache_fini();
		mutex_destroy(&sdev_lock);
		return (e);
	}
	return (0);
}

/*
 * dev module remained loaded for the global /dev instance
 */
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

/*ARGSUSED*/
static int
devinit(int fstype, char *name)
{
	static const fs_operation_def_t dev_vfsops_tbl[] = {
		VFSNAME_MOUNT,		{ .vfs_mount = sdev_mount },
		VFSNAME_UNMOUNT,	{ .vfs_unmount = sdev_unmount },
		VFSNAME_ROOT, 		{ .vfs_root = sdev_root },
		VFSNAME_STATVFS,	{ .vfs_statvfs = sdev_statvfs },
		NULL,			NULL
	};

	int	error;
	extern major_t getudev(void);

	devtype = fstype;

	error = vfs_setfsops(fstype, dev_vfsops_tbl, NULL);
	if (error != 0) {
		cmn_err(CE_WARN, "devinit: bad vfs ops tbl");
		return (error);
	}

	error = vn_make_ops("dev", sdev_vnodeops_tbl, &sdev_vnodeops);
	if (error != 0) {
		(void) vfs_freevfsops_by_type(fstype);
		cmn_err(CE_WARN, "devinit: bad vnode ops tbl");
		return (error);
	}

	if ((devmajor = getudev()) == (major_t)-1) {
		cmn_err(CE_WARN, "%s: can't get unique dev", sdev_vfssw.name);
		return (1);
	}

	/* initialize negative cache */
	sdev_ncache_init();

	return (0);
}

/*
 * Both mount point and backing store directory name are
 * passed in from userland
 */
static int
sdev_mount(struct vfs *vfsp, struct vnode *mvp, struct mounta *uap,
    struct cred *cr)
{
	struct sdev_data *sdev_data;
	struct vnode *avp;
	struct sdev_node *dv;
	struct sdev_mountargs *args = NULL;
	int	error = 0;
	dev_t	devdev;

	/*
	 * security check
	 */
	if ((secpolicy_fs_mount(cr, mvp, vfsp) != 0) ||
	    (secpolicy_sys_devices(cr) != 0))
		return (EPERM);

	/*
	 * Sanity check the mount point
	 */
	if (mvp->v_type != VDIR)
		return (ENOTDIR);

	/*
	 * Sanity Check for overlay mount.
	 */
	mutex_enter(&mvp->v_lock);
	if ((uap->flags & MS_OVERLAY) == 0 &&
	    (uap->flags & MS_REMOUNT) == 0 &&
	    (mvp->v_count > 1 || (mvp->v_flag & VROOT))) {
		mutex_exit(&mvp->v_lock);
		return (EBUSY);
	}
	mutex_exit(&mvp->v_lock);

	args = kmem_zalloc(sizeof (*args), KM_SLEEP);

	if ((uap->flags & MS_DATA) &&
	    (uap->datalen != 0 && uap->dataptr != NULL)) {
		/* copy in the arguments */
		if (error = sdev_copyin_mountargs(uap, args))
			goto cleanup;
	}

	/*
	 * Sanity check the backing store
	 */
	if (args->sdev_attrdir) {
		/* user supplied an attribute store */
		if (error = lookupname((char *)(uintptr_t)args->sdev_attrdir,
		    UIO_USERSPACE, FOLLOW, NULLVPP, &avp)) {
			cmn_err(CE_NOTE, "/dev fs: lookup on attribute "
			    "directory %s failed",
			    (char *)(uintptr_t)args->sdev_attrdir);
			goto cleanup;
		}

		if (avp->v_type != VDIR) {
			VN_RELE(avp);
			error = ENOTDIR;
			goto cleanup;
		}
	} else {
		/* use mountp as the attribute store */
		avp = mvp;
		VN_HOLD(avp);
	}

	mutex_enter(&sdev_lock);

	/*
	 * Check that the taskq has been created. We can't do this in our
	 * _init or devinit because they run too early for ddi_taskq_create.
	 */
	if (sdev_taskq == NULL) {
		sdev_taskq = taskq_create("sdev", 1, minclsyspri, 1, 1, 0);
		if (sdev_taskq == NULL) {
			error = ENOMEM;
			mutex_exit(&sdev_lock);
			VN_RELE(avp);
			goto cleanup;
		}
	}

	/*
	 * handling installation
	 */
	if (uap->flags & MS_REMOUNT) {
		sdev_data = (struct sdev_data *)vfsp->vfs_data;
		ASSERT(sdev_data);

		dv = sdev_data->sdev_root;
		ASSERT(dv == dv->sdev_dotdot);

		/*
		 * mark all existing sdev_nodes (except root node) stale
		 */
		sdev_stale(dv);

		/* Reset previous mountargs */
		if (sdev_data->sdev_mountargs) {
			kmem_free(sdev_data->sdev_mountargs,
			    sizeof (struct sdev_mountargs));
		}
		sdev_data->sdev_mountargs = args;
		args = NULL;		/* so it won't be freed below */

		sdev_stale_attrvp = dv->sdev_attrvp;
		dv->sdev_attrvp = avp;
		vfsp->vfs_mtime = ddi_get_time();

		mutex_exit(&sdev_lock);
		goto cleanup;				/* we're done */
	}

	/*
	 * Create and initialize the vfs-private data.
	 */
	devdev = makedevice(devmajor, devminor);
	while (vfs_devismounted(devdev)) {
		devminor = (devminor + 1) & MAXMIN32;

		/*
		 * All the minor numbers are used up.
		 */
		if (devminor == 0) {
			mutex_exit(&sdev_lock);
			VN_RELE(avp);
			error = ENODEV;
			goto cleanup;
		}

		devdev = makedevice(devmajor, devminor);
	}

	dv = sdev_mkroot(vfsp, devdev, mvp, avp, cr);
	sdev_data = kmem_zalloc(sizeof (struct sdev_data), KM_SLEEP);
	vfsp->vfs_dev = devdev;
	vfsp->vfs_data = (caddr_t)sdev_data;
	vfsp->vfs_fstype = devtype;
	vfsp->vfs_bsize = DEV_BSIZE;
	vfsp->vfs_mtime = ddi_get_time();
	vfs_make_fsid(&vfsp->vfs_fsid, vfsp->vfs_dev, devtype);

	ASSERT(dv == dv->sdev_dotdot);

	sdev_data->sdev_vfsp = vfsp;
	sdev_data->sdev_root = dv;
	sdev_data->sdev_mountargs = args;

	/* get acl flavor from attribute dir */
	if (VOP_PATHCONF(avp, _PC_ACL_ENABLED, &sdev_data->sdev_acl_flavor,
	    kcred, NULL) != 0 || sdev_data->sdev_acl_flavor == 0)
		sdev_data->sdev_acl_flavor = _ACL_ACLENT_ENABLED;

	args = NULL;			/* so it won't be freed below */
	sdev_insert_mntinfo(sdev_data);
	mutex_exit(&sdev_lock);

	if (!SDEV_IS_GLOBAL(dv)) {
		ASSERT(sdev_origins);
		dv->sdev_flags &= ~SDEV_GLOBAL;
		dv->sdev_origin = sdev_origins->sdev_root;
	} else {
		sdev_ncache_setup();
		rw_enter(&dv->sdev_contents, RW_WRITER);
		sdev_filldir_dynamic(dv);
		rw_exit(&dv->sdev_contents);
	}

	sdev_update_timestamps(dv->sdev_attrvp,
	    cr, AT_CTIME|AT_MTIME|AT_ATIME);

cleanup:
	if (args)
		kmem_free(args, sizeof (*args));
	return (error);
}

/*
 * unmounting the non-global /dev instances, e.g. when deleting a Kevlar zone.
 */
static int
sdev_unmount(struct vfs *vfsp, int flag, struct cred *cr)
{
	struct sdev_node *dv;
	int error;
	struct sdev_data *sdev_data, *prev, *next;

	/*
	 * enforce the security policies
	 */
	if ((secpolicy_fs_unmount(cr, vfsp) != 0) ||
	    (secpolicy_sys_devices(cr) != 0))
		return (EPERM);

	if (flag & MS_FORCE)
		return (ENOTSUP);

	mutex_enter(&sdev_lock);
	dv = VFSTOSDEVFS(vfsp)->sdev_root;
	ASSERT(dv == dv->sdev_dotdot);
	if (SDEVTOV(dv)->v_count > 1) {
		mutex_exit(&sdev_lock);
		return (EBUSY);
	}

	/*
	 * global instance remains mounted
	 */
	if (SDEV_IS_GLOBAL(dv)) {
		mutex_exit(&sdev_lock);
		return (EBUSY);
	}
	mutex_exit(&sdev_lock);

	/* verify the v_count */
	if ((error = sdev_cleandir(dv, NULL, 0)) != 0) {
		return (error);
	}
	ASSERT(SDEVTOV(dv)->v_count == 1);

	/* release hold on root node and destroy it */
	SDEV_RELE(dv);
	dv->sdev_nlink -= 2;
	sdev_nodedestroy(dv, 0);

	sdev_data = (struct sdev_data *)vfsp->vfs_data;
	vfsp->vfs_data = (caddr_t)0;

	/*
	 * XXX separate it into sdev_delete_mntinfo() if useful
	 */
	mutex_enter(&sdev_lock);
	prev = sdev_data->sdev_prev;
	next = sdev_data->sdev_next;
	if (prev)
		prev->sdev_next = next;
	else
		sdev_mntinfo = next;
	if (next)
		next->sdev_prev = prev;
	mutex_exit(&sdev_lock);

	if (sdev_data->sdev_mountargs) {
		kmem_free(sdev_data->sdev_mountargs,
		    sizeof (struct sdev_mountargs));
	}
	kmem_free(sdev_data, sizeof (struct sdev_data));
	return (0);
}

/*
 * return root vnode for given vfs
 */
static int
sdev_root(struct vfs *vfsp, struct vnode **vpp)
{
	*vpp = SDEVTOV(VFSTOSDEVFS(vfsp)->sdev_root);
	VN_HOLD(*vpp);
	return (0);
}

/*
 * return 'generic superblock' information to userland.
 *
 * not much that we can usefully admit to here
 */
static int
sdev_statvfs(struct vfs *vfsp, struct statvfs64 *sbp)
{
	dev32_t d32;

	bzero(sbp, sizeof (*sbp));
	sbp->f_frsize = sbp->f_bsize = vfsp->vfs_bsize;
	sbp->f_files = kmem_cache_stat(sdev_node_cache, "alloc");

	/* no illusions that free/avail files is relevant to dev */
	sbp->f_ffree = 0;
	sbp->f_favail = 0;

	/* no illusions that blocks are relevant to devfs */
	sbp->f_bfree = 0;
	sbp->f_bavail = 0;
	sbp->f_blocks = 0;

	(void) cmpldev(&d32, vfsp->vfs_dev);
	sbp->f_fsid = d32;
	(void) strcpy(sbp->f_basetype, vfssw[devtype].vsw_name);
	sbp->f_flag = vf_to_stf(vfsp->vfs_flag);
	sbp->f_namemax = MAXNAMELEN - 1;
	(void) strcpy(sbp->f_fstr, "dev");

	return (0);
}

static void
sdev_insert_mntinfo(struct sdev_data *data)
{
	ASSERT(mutex_owned(&sdev_lock));
	data->sdev_next = sdev_mntinfo;
	data->sdev_prev = NULL;
	if (sdev_mntinfo) {
		sdev_mntinfo->sdev_prev = data;
	} else {
		sdev_origins = data;
	}
	sdev_mntinfo = data;
}

struct sdev_data *
sdev_find_mntinfo(char *mntpt)
{
	struct sdev_data *mntinfo;

	mutex_enter(&sdev_lock);
	mntinfo = sdev_mntinfo;
	while (mntinfo) {
		if (strcmp(mntpt, mntinfo->sdev_root->sdev_name) == 0) {
			SDEVTOV(mntinfo->sdev_root)->v_count++;
			break;
		}
		mntinfo = mntinfo->sdev_next;
	}
	mutex_exit(&sdev_lock);
	return (mntinfo);
}

void
sdev_mntinfo_rele(struct sdev_data *mntinfo)
{
	mutex_enter(&sdev_lock);
	SDEVTOV(mntinfo->sdev_root)->v_count--;
	mutex_exit(&sdev_lock);
}
