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
 * Copyright 2016 Joyent, Inc.
 */

/*
 * The lx devfs (lxd) file system is used within lx branded zones to provide
 * the Linux view of /dev.
 *
 * In the past, the Linux /dev was simply a lofs mount pointing at /native/dev.
 * lxd now provides the Linux /dev.
 *
 * The lxd file system is a hybrid of lofs and tmpfs. It supports a "back" file
 * system which is the special device and corresponds to the special device in
 * a lofs mount. As with lofs, all files in the special device are accessible
 * through the lxd mount. Because the zone's devfs is not directly modifiable
 * within the zone (also mknod(2) is not generally allowed within a zone) it is
 * impossible to create files in devfs. For lx, in some cases it's useful to be
 * able to make new symlinks or new directories under /dev. lxd implements
 * these operations by creating "files" in memory in the same way as tmpfs
 * does. Within lxd these are referred to as "front" files. For operations such
 * as lookup or readdir, lxd provides a merged view of both the front and back
 * files. lxd does not support regular front files or simple I/O (read/write)
 * to front files, since there is no need for that. For back files, all
 * operations are simply passed through to the real vnode, as is done with
 * lofs. Front files are not allowed to mask back files.
 *
 * The Linux /dev is now a lxd mount with the special file (i.e. the back
 * file system) as /native/dev.
 *
 * In addition, lx has a need for some illumos/Linux translation for the
 * various *stat(2) system calls when used on a device. This translation can
 * be centralized within lxd's getattr vnode entry point.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
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
#include <sys/systm.h>
#include <sys/mntent.h>
#include <sys/policy.h>
#include <sys/sdt.h>
#include <sys/ddi.h>
#include <sys/lx_brand.h>
#include <sys/lx_ptm.h>
#include <sys/lx_impl.h>

#include "lxd.h"

/* Module level parameters */
static int	lxd_fstype;
static dev_t	lxd_dev;

/*
 * lxd_mountcount is used to prevent module unloads while there is still
 * state from a former mount hanging around. The filesystem module must not be
 * allowed to go away before the last VFS_FREEVFS() call has been made. Since
 * this is just an atomic counter, there's no need for locking.
 */
static uint32_t lxd_mountcount;

/*
 * lxd_minfree is the minimum amount of swap space that lx devfs leaves for
 * the rest of the zone.
 */
size_t lxd_minfree = 0;

/*
 * LXDMINFREE -- the value from which lxd_minfree is derived -- should be
 * configured to a value that is roughly the smallest practical value for
 * memory + swap minus the largest reasonable size for lxd in such
 * a configuration. As of this writing, the smallest practical memory + swap
 * configuration is 128MB, and it seems reasonable to allow lxd to consume
 * no more than ~10% of this, yielding a LXDMINFREE of 12MB.
 */
#define	LXDMINFREE	12 * 1024 * 1024	/* 12 Megabytes */

extern pgcnt_t swapfs_minfree;

extern int lxd_symlink(vnode_t *, char *, struct vattr *, char *, cred_t *,
    caller_context_t *, int);
extern int stat64(char *, struct stat64 *);

/*
 * lxd vfs operations.
 */
static int lxd_init(int, char *);
static int lxd_mount(vfs_t *, vnode_t *, struct mounta *, cred_t *);
static int lxd_unmount(vfs_t *, int, cred_t *);
static int lxd_root(vfs_t *, vnode_t **);
static int lxd_statvfs(vfs_t *, statvfs64_t *);
static void lxd_freevfs(vfs_t *vfsp);

/*
 * Loadable module wrapper
 */
#include <sys/modctl.h>

static vfsdef_t vfw = {
	VFSDEF_VERSION,
	"lx_devfs",
	lxd_init,
	VSW_ZMOUNT,
	NULL
};

/*
 * Module linkage information
 */
static struct modlfs modlfs = {
	&mod_fsops, "lx brand devfs", &vfw
};

static struct modlinkage modlinkage = {
	MODREV_1, &modlfs, NULL
};

/*
 * Definitions and translators for devt's.
 */
static void lxd_pts_devt_translator(dev_t, dev_t *);
static void lxd_ptm_devt_translator(dev_t, dev_t *);

#define	LX_PTS_MAJOR_MIN	136
#define	LX_PTS_MAJOR_MAX	143

#define	LX_PTM_MAJOR		5
#define	LX_PTM_MINOR		2

static kmutex_t			lxd_xlate_lock;
static boolean_t		lxd_xlate_initialized = B_FALSE;

static lxd_minor_translator_t lxd_mtranslator_mm[] = {
	{ "/dev/null",		0, 1, 3 },
	{ "/dev/zero",		0, 1, 5 },
	{ NULL,			0, 0, 0 }
};
static lxd_minor_translator_t lxd_mtranslator_random[] = {
	{ "/dev/random",	0, 1, 8 },
	{ "/dev/urandom",	0, 1, 9 },
	{ NULL,			0, 0, 0 }
};
static lxd_minor_translator_t lxd_mtranslator_sy[] = {
	{ "/dev/tty",		0, 5, 0 },
	{ NULL,			0, 0, 0 }
};
static lxd_minor_translator_t lxd_mtranslator_zcons[] = {
	{ "/dev/console",	0, 5, 1 },
	{ NULL,			0, 0, 0 }
};
lxd_devt_translator_t lxd_devt_translators[] = {
	{ "mm",		0, DTT_LIST,	(uintptr_t)&lxd_mtranslator_mm },
	{ "random",	0, DTT_LIST,	(uintptr_t)&lxd_mtranslator_random },
	{ "sy",		0, DTT_LIST,	(uintptr_t)&lxd_mtranslator_sy },
	{ "zcons",	0, DTT_LIST,	(uintptr_t)&lxd_mtranslator_zcons },
	{ LX_PTM_DRV,	0, DTT_CUSTOM,	(uintptr_t)lxd_ptm_devt_translator },
	{ "pts",	0, DTT_CUSTOM,	(uintptr_t)lxd_pts_devt_translator },
	{ NULL,		0, DTT_INVALID,	NULL }
};

int
_init()
{
	return (mod_install(&modlinkage));
}

int
_fini()
{
	int error;

	if (lxd_mountcount > 0)
		return (EBUSY);

	if ((error = mod_remove(&modlinkage)) != 0)
		return (error);

	/*
	 * Tear down the operations vectors
	 */
	(void) vfs_freevfsops_by_type(lxd_fstype);
	vn_freevnodeops(lxd_vnodeops);
	mutex_destroy(&lxd_xlate_lock);
	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * Initialize global locks, etc. Called when loading lxd module.
 */
static int
lxd_init(int fstype, char *name)
{
	static const fs_operation_def_t lxd_vfsops_template[] = {
		VFSNAME_MOUNT,		{ .vfs_mount = lxd_mount },
		VFSNAME_UNMOUNT,	{ .vfs_unmount = lxd_unmount },
		VFSNAME_ROOT,		{ .vfs_root = lxd_root },
		VFSNAME_STATVFS,	{ .vfs_statvfs = lxd_statvfs },
		VFSNAME_FREEVFS,	{ .vfs_freevfs = lxd_freevfs },
		NULL,			NULL
	};
	extern const struct fs_operation_def lxd_vnodeops_template[];
	int error;
	major_t dev;

	lxd_fstype = fstype;
	ASSERT(lxd_fstype != 0);

	error = vfs_setfsops(fstype, lxd_vfsops_template, NULL);
	if (error != 0) {
		cmn_err(CE_WARN, "lxd_init: bad vfs ops template");
		return (error);
	}

	error = vn_make_ops(name, lxd_vnodeops_template, &lxd_vnodeops);
	if (error != 0) {
		(void) vfs_freevfsops_by_type(fstype);
		cmn_err(CE_WARN, "lxd_init: bad vnode ops template");
		return (error);
	}

	/*
	 * lxd_minfree doesn't need to be some function of configured
	 * swap space since it really is an absolute limit of swap space
	 * which still allows other processes to execute.
	 */
	if (lxd_minfree == 0) {
		/* Set if not patched */
		lxd_minfree = btopr(LXDMINFREE);
	}

	if ((dev = getudev()) == (major_t)-1) {
		cmn_err(CE_WARN, "lxd_init: Can't get unique device number.");
		dev = 0;
	}

	/*
	 * Make the pseudo device
	 */
	lxd_dev = makedevice(dev, 0);

	mutex_init(&lxd_xlate_lock, NULL, MUTEX_DEFAULT, NULL);

	return (0);
}

/*
 * Initialize device translator mapping table.
 *
 * Note that we cannot do this in lxd_init since that can lead to a recursive
 * rw_enter while we're doing lookupnameat (via sdev_lookup/prof_make_maps/
 * devi_attach_node/modload). Thus we do it in the mount path and keep track
 * so that we only initialize the table once.
 */
static void
lxd_xlate_init()
{
	int i;

	mutex_enter(&lxd_xlate_lock);
	if (lxd_xlate_initialized) {
		mutex_exit(&lxd_xlate_lock);
		return;
	}

	for (i = 0; lxd_devt_translators[i].lxd_xl_driver != NULL; i++) {
		lxd_minor_translator_t	*mt;
		int j;

		lxd_devt_translators[i].lxd_xl_major =
		    mod_name_to_major(lxd_devt_translators[i].lxd_xl_driver);

		/* if this translator doesn't use a list mapping we're done. */
		if (lxd_devt_translators[i].lxd_xl_type != DTT_LIST)
			continue;

		/* for each device listed, lookup the minor node number */
		mt = lxd_devt_translators[i].xl_list;
		for (j = 0; mt[j].lxd_mt_path != NULL; j++) {
			vnode_t *vp;
			struct vattr va;
			char *tpath;
			char tnm[MAXPATHLEN];

			/*
			 * The attach might be triggered in either the global
			 * zone or in a non-global zone, so we may need to
			 * adjust the path if we're in a NGZ.
			 */
			if (curproc->p_zone->zone_id == GLOBAL_ZONEUNIQID) {
				tpath = mt[j].lxd_mt_path;
			} else {
				(void) snprintf(tnm, sizeof (tnm), "/native%s",
				    mt[j].lxd_mt_path);
				tpath = tnm;
			}

			if (lookupnameat(tpath, UIO_SYSSPACE, FOLLOW, NULL,
			    &vp, NULL) != 0) {
				mt[j].lxd_mt_minor = -1;
				continue;
			}

			va.va_mask = AT_RDEV;
			if (VOP_GETATTR(vp, &va, 0, kcred, NULL) != 0) {
				va.va_rdev = NODEV;
			} else {
				ASSERT(getmajor(va.va_rdev) ==
				    lxd_devt_translators[i].lxd_xl_major);
				ASSERT(mt[j].lxd_mt_lx_minor < LX_MINORMASK);
			}

			mt[j].lxd_mt_minor = getminor(va.va_rdev);

			VN_RELE(vp);
		}
	}

	lxd_xlate_initialized = B_TRUE;
	mutex_exit(&lxd_xlate_lock);
}

static int
lxd_mount(vfs_t *vfsp, vnode_t *mvp, struct mounta *uap, cred_t *cr)
{
	lxd_mnt_t *lxdm = NULL;
	struct lxd_node *ldn;
	struct pathname dpn;
	int error;
	int i;
	int nodev;
	struct vattr rattr;
	vnode_t *realrootvp;
	vnode_t *tvp;
	lx_zone_data_t *lxzdata;
	lx_virt_disk_t *vd;
	vattr_t vattr;

	nodev = vfs_optionisset(vfsp, MNTOPT_NODEVICES, NULL);

	if ((error = secpolicy_fs_mount(cr, mvp, vfsp)) != 0)
		return (error);

	if (mvp->v_type != VDIR)
		return (ENOTDIR);

	lxd_xlate_init();

	/*
	 * This is the same behavior as with lofs.
	 * Loopback devices which get "nodevices" added can be done without
	 * "nodevices" set because we cannot import devices into a zone
	 * with loopback.  Note that we have all zone privileges when
	 * this happens; if not, we'd have gotten "nosuid".
	 */
	if (!nodev && vfs_optionisset(vfsp, MNTOPT_NODEVICES, NULL))
		vfs_setmntopt(vfsp, MNTOPT_DEVICES, NULL, VFS_NODISPLAY);

	/*
	 * Only allow mounting within lx zones.
	 */
	if (curproc->p_zone->zone_brand != &lx_brand)
		return (EINVAL);

	/*
	 * Ensure we don't allow overlaying mounts
	 */
	mutex_enter(&mvp->v_lock);
	if ((uap->flags & MS_OVERLAY) == 0 &&
	    (mvp->v_count > 1 || (mvp->v_flag & VROOT))) {
		mutex_exit(&mvp->v_lock);
		return (EBUSY);
	}
	mutex_exit(&mvp->v_lock);

	/* lxd doesn't support read-only mounts */
	if (vfs_optionisset(vfsp, MNTOPT_RO, NULL)) {
		error = EINVAL;
		goto out;
	}

	error = pn_get(uap->dir,
	    (uap->flags & MS_SYSSPACE) ? UIO_SYSSPACE : UIO_USERSPACE, &dpn);
	if (error != 0)
		goto out;

	/*
	 * Find real root
	 */
	if ((error = lookupname(uap->spec, (uap->flags & MS_SYSSPACE) ?
	    UIO_SYSSPACE : UIO_USERSPACE, FOLLOW, NULLVPP, &realrootvp))) {
		pn_free(&dpn);
		return (error);
	}

	if ((error = VOP_ACCESS(realrootvp, 0, 0, cr, NULL)) != 0) {
		pn_free(&dpn);
		VN_RELE(realrootvp);
		return (error);
	}

	/* If realroot is not a devfs, error out */
	if (strcmp(realrootvp->v_op->vnop_name, "dev") != 0) {
		pn_free(&dpn);
		VN_RELE(realrootvp);
		return (EINVAL);
	}

	lxdm = kmem_zalloc(sizeof (*lxdm), KM_SLEEP);

	/* init but don't bother entering the mutex (not on mount list yet) */
	mutex_init(&lxdm->lxdm_contents, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&lxdm->lxdm_renamelck, NULL, MUTEX_DEFAULT, NULL);

	/* Initialize the hash table mutexes */
	for (i = 0; i < LXD_HASH_SZ; i++) {
		mutex_init(&lxdm->lxdm_hash_mutex[i], NULL, MUTEX_DEFAULT,
		    NULL);
	}

	lxdm->lxdm_vfsp = vfsp;
	lxdm->lxdm_gen = 1;	/* start inode counter at 1 */

	vfsp->vfs_data = (caddr_t)lxdm;
	vfsp->vfs_fstype = lxd_fstype;
	vfsp->vfs_dev = lxd_dev;
	vfsp->vfs_bsize = PAGESIZE;
	vfsp->vfs_flag |= VFS_NOTRUNC;
	vfs_make_fsid(&vfsp->vfs_fsid, lxd_dev, lxd_fstype);
	lxdm->lxdm_mntpath = kmem_zalloc(dpn.pn_pathlen + 1, KM_SLEEP);
	(void) strcpy(lxdm->lxdm_mntpath, dpn.pn_path);

	/* allocate and initialize root lxd_node structure */
	bzero(&rattr, sizeof (struct vattr));
	rattr.va_mode = (mode_t)(S_IFDIR | 0755);
	rattr.va_type = VDIR;
	rattr.va_rdev = 0;

	tvp = lxd_make_back_node(realrootvp, lxdm);
	ldn = VTOLDN(tvp);

	rw_enter(&ldn->lxdn_rwlock, RW_WRITER);
	LDNTOV(ldn)->v_flag |= VROOT;

	/*
	 * initialize linked list of lxd_nodes so that the back pointer of
	 * the root lxd_node always points to the last one on the list
	 * and the forward pointer of the last node is null
	 */
	ldn->lxdn_prev = ldn;
	ldn->lxdn_next = NULL;
	ldn->lxdn_nlink = 0;
	lxdm->lxdm_rootnode = ldn;

	ldn->lxdn_nodeid = lxdm->lxdm_gen++;
	lxd_dirinit(ldn, ldn, cr);

	rw_exit(&ldn->lxdn_rwlock);

	pn_free(&dpn);
	error = 0;
	atomic_inc_32(&lxd_mountcount);

	lxzdata = ztolxzd(curproc->p_zone);
	ASSERT(lxzdata->lxzd_vdisks != NULL);

	vattr.va_mask = AT_TYPE | AT_MODE;
	vattr.va_type = VLNK;
	vattr.va_mode = 0777;

	vd = list_head(lxzdata->lxzd_vdisks);
	while (vd != NULL) {
		/* only create links for actual zvols */
		if (vd->lxvd_type == LXVD_ZVOL) {
			char lnknm[MAXPATHLEN];

			(void) snprintf(lnknm, sizeof (lnknm),
			    "./zvol/dsk/%s", vd->lxvd_real_name);
			(void) lxd_symlink(LDNTOV(ldn), vd->lxvd_name, &vattr,
			    lnknm, cr, NULL, 0);
		}

		vd = list_next(lxzdata->lxzd_vdisks, vd);
	}

out:
	if (error == 0)
		vfs_set_feature(vfsp, VFSFT_SYSATTR_VIEWS);

	return (error);
}

static int
lxd_unmount(struct vfs *vfsp, int flag, struct cred *cr)
{
	lxd_mnt_t *lxdm = (lxd_mnt_t *)VFSTOLXDM(vfsp);
	lxd_node_t *ldn, *cancel;
	struct vnode	*vp;
	int error;
	uint_t cnt;

	if ((error = secpolicy_fs_unmount(cr, vfsp)) != 0)
		return (error);

	mutex_enter(&lxdm->lxdm_contents);

	/*
	 * In the normal unmount case only the root node would have a reference
	 * count.
	 *
	 * With lxdm_contents held, nothing can be added or removed.
	 * If we find a previously referenced node, undo the holds we have
	 * placed and fail EBUSY.
	 */
	ldn = lxdm->lxdm_rootnode;

	vp = LDNTOV(ldn);
	mutex_enter(&vp->v_lock);

	if (flag & MS_FORCE) {
		mutex_exit(&vp->v_lock);
		mutex_exit(&lxdm->lxdm_contents);
		return (EINVAL);
	}

	cnt = vp->v_count;
	if (cnt > 1) {
		mutex_exit(&vp->v_lock);
		mutex_exit(&lxdm->lxdm_contents);
		return (EBUSY);
	}

	mutex_exit(&vp->v_lock);

	/*
	 * Check for open files. An open file causes everything to unwind.
	 */
	for (ldn = ldn->lxdn_next; ldn; ldn = ldn->lxdn_next) {
		vp = LDNTOV(ldn);
		mutex_enter(&vp->v_lock);
		cnt = vp->v_count;
		if (cnt > 0) {
			/* An open file; unwind the holds we've been adding. */
			mutex_exit(&vp->v_lock);
			cancel = lxdm->lxdm_rootnode->lxdn_next;
			while (cancel != ldn) {
				vp = LDNTOV(cancel);
				ASSERT(vp->v_count > 0);
				VN_RELE(vp);
				cancel = cancel->lxdn_next;
			}
			mutex_exit(&lxdm->lxdm_contents);
			return (EBUSY);
		} else {
			/*
			 * It may seem incorrect for us to have a vnode with
			 * a count of 0, but this is modeled on tmpfs and works
			 * the same way. See lxd_front_inactive. There we allow
			 * the v_count to go to 0 but rely on the link count to
			 * keep the vnode alive. Since we now want to cleanup
			 * these vnodes we manually add a VN_HOLD so that the
			 * VN_RELEs that occur in the lxd_freevfs() cleanup
			 * will take us down the lxd_inactive code path. We
			 * can directly add a VN_HOLD since we have the lock.
			 */
			vp->v_count++;
			mutex_exit(&vp->v_lock);
		}
	}

	/*
	 * We can drop the mutex now because
	 * no one can find this mount anymore
	 */
	vfsp->vfs_flag |= VFS_UNMOUNTED;
	mutex_exit(&lxdm->lxdm_contents);

	return (0);
}

/*
 * Implementation of VFS_FREEVFS(). This is called by the vfs framework after
 * umount and the last VFS_RELE, to trigger the release of any resources still
 * associated with the given vfs_t. This is normally called immediately after
 * lxd_unmount.
 */
void
lxd_freevfs(vfs_t *vfsp)
{
	lxd_mnt_t *lxdm = (lxd_mnt_t *)VFSTOLXDM(vfsp);
	lxd_node_t *ldn;
	struct vnode *vp;

	/*
	 * Free all kmemalloc'd and anonalloc'd memory associated with
	 * this filesystem.  To do this, we go through the file list twice,
	 * once to remove all the directory entries, and then to remove
	 * all the pseudo files.
	 */

	/*
	 * Now that we are tearing ourselves down we need to remove the
	 * UNMOUNTED flag. If we don't, we'll later hit a VN_RELE when we remove
	 * files from the system causing us to have a negative value. Doing this
	 * seems a bit better than trying to set a flag on the lxd_mnt_t that
	 * says we're tearing down.
	 */
	vfsp->vfs_flag &= ~VFS_UNMOUNTED;

	/*
	 * Remove all directory entries (this doesn't remove top-level dirs).
	 */
	for (ldn = lxdm->lxdm_rootnode; ldn; ldn = ldn->lxdn_next) {
		rw_enter(&ldn->lxdn_rwlock, RW_WRITER);
		if (ldn->lxdn_vnode->v_type == VDIR)
			lxd_dirtrunc(ldn);
		rw_exit(&ldn->lxdn_rwlock);
	}

	ASSERT(lxdm->lxdm_rootnode != NULL);

	/*
	 * All links are gone, v_count is keeping nodes in place.
	 * VN_RELE should make the node disappear, unless somebody
	 * is holding pages against it.  Nap and retry until it disappears.
	 *
	 * We re-acquire the lock to prevent others who have a HOLD on a
	 * lxd_node from blowing it away (in lxd_inactive) while we're trying
	 * to get to it here. Once we have a HOLD on it we know it'll stick
	 * around.
	 */
	mutex_enter(&lxdm->lxdm_contents);

	/*
	 * Remove all the files (except the rootnode) backwards.
	 */
	while ((ldn = lxdm->lxdm_rootnode->lxdn_prev) != lxdm->lxdm_rootnode) {
		mutex_exit(&lxdm->lxdm_contents);
		/*
		 * All nodes will be released here. Note we handled the link
		 * count above.
		 */
		vp = LDNTOV(ldn);
		ASSERT(vp->v_type == VLNK || vp->v_type == VDIR ||
		    vp->v_type == VSOCK);
		VN_RELE(vp);
		mutex_enter(&lxdm->lxdm_contents);
		/*
		 * It's still there after the RELE. Someone else like pageout
		 * has a hold on it so wait a bit and then try again - we know
		 * they'll give it up soon.
		 */
		if (ldn == lxdm->lxdm_rootnode->lxdn_prev) {
			VN_HOLD(vp);
			mutex_exit(&lxdm->lxdm_contents);
			delay(hz / 4);
			mutex_enter(&lxdm->lxdm_contents);
		}
	}
	mutex_exit(&lxdm->lxdm_contents);

	ASSERT(lxdm->lxdm_back_refcnt == 1);
	ASSERT(lxdm->lxdm_dent_refcnt == 0);

	VN_RELE(LDNTOV(lxdm->lxdm_rootnode));

	ASSERT(lxdm->lxdm_mntpath != NULL);
	kmem_free(lxdm->lxdm_mntpath, strlen(lxdm->lxdm_mntpath) + 1);

	mutex_destroy(&lxdm->lxdm_contents);
	mutex_destroy(&lxdm->lxdm_renamelck);
	kmem_free(lxdm, sizeof (lxd_mnt_t));

	/* Allow _fini() to succeed now */
	atomic_dec_32(&lxd_mountcount);
}

/*
 * return root lxdnode for given vnode
 */
static int
lxd_root(struct vfs *vfsp, struct vnode **vpp)
{
	lxd_mnt_t *lxdm = (lxd_mnt_t *)VFSTOLXDM(vfsp);
	lxd_node_t *ldn = lxdm->lxdm_rootnode;
	struct vnode *vp;

	ASSERT(ldn != NULL);

	vp = LDNTOV(ldn);
	VN_HOLD(vp);
	*vpp = vp;
	return (0);
}

static int
lxd_statvfs(struct vfs *vfsp, statvfs64_t *sbp)
{
	lxd_mnt_t *lxdm = (lxd_mnt_t *)VFSTOLXDM(vfsp);
	ulong_t	blocks;
	dev32_t d32;
	zoneid_t eff_zid;
	struct zone *zp;

	zp = lxdm->lxdm_vfsp->vfs_zone;

	if (zp == NULL)
		eff_zid = GLOBAL_ZONEUNIQID;
	else
		eff_zid = zp->zone_id;

	sbp->f_bsize = PAGESIZE;
	sbp->f_frsize = PAGESIZE;

	/*
	 * Find the amount of available physical and memory swap
	 */
	mutex_enter(&anoninfo_lock);
	ASSERT(k_anoninfo.ani_max >= k_anoninfo.ani_phys_resv);
	blocks = (ulong_t)CURRENT_TOTAL_AVAILABLE_SWAP;
	mutex_exit(&anoninfo_lock);

	if (blocks > lxd_minfree)
		sbp->f_bfree = blocks - lxd_minfree;
	else
		sbp->f_bfree = 0;

	sbp->f_bavail = sbp->f_bfree;

	/*
	 * Total number of blocks is just what's available
	 */
	sbp->f_blocks = (fsblkcnt64_t)(sbp->f_bfree);

	if (eff_zid != GLOBAL_ZONEUNIQID &&
	    zp->zone_max_swap_ctl != UINT64_MAX) {
		/*
		 * If the fs is used by a zone with a swap cap,
		 * then report the capped size.
		 */
		rctl_qty_t cap, used;
		pgcnt_t pgcap, pgused;

		mutex_enter(&zp->zone_mem_lock);
		cap = zp->zone_max_swap_ctl;
		used = zp->zone_max_swap;
		mutex_exit(&zp->zone_mem_lock);

		pgcap = btop(cap);
		pgused = btop(used);

		sbp->f_bfree = MIN(pgcap - pgused, sbp->f_bfree);
		sbp->f_bavail = sbp->f_bfree;
		sbp->f_blocks = MIN(pgcap, sbp->f_blocks);
	}

	/*
	 * The maximum number of files available is approximately the number
	 * of lxd_nodes we can allocate from the remaining kernel memory
	 * available to lxdevfs in this zone.  This is fairly inaccurate since
	 * it doesn't take into account the names stored in the directory
	 * entries.
	 */
	sbp->f_ffree = sbp->f_files = ptob(availrmem) /
	    (sizeof (lxd_node_t) + sizeof (lxd_dirent_t));
	sbp->f_favail = (fsfilcnt64_t)(sbp->f_ffree);
	(void) cmpldev(&d32, vfsp->vfs_dev);
	sbp->f_fsid = d32;
	(void) strcpy(sbp->f_basetype, vfssw[lxd_fstype].vsw_name);
	(void) strncpy(sbp->f_fstr, lxdm->lxdm_mntpath, sizeof (sbp->f_fstr));
	/* ensure null termination */
	sbp->f_fstr[sizeof (sbp->f_fstr) - 1] = '\0';
	sbp->f_flag = vf_to_stf(vfsp->vfs_flag);
	sbp->f_namemax = MAXNAMELEN - 1;
	return (0);
}

static void
lxd_pts_devt_translator(dev_t dev, dev_t *jdev)
{
	minor_t	min = getminor(dev);
	int	lx_maj, lx_min;

	/*
	 * Linux uses a range of major numbers for pts devices to address the
	 * relatively small minor number space (8 bits).
	 */

	lx_maj = LX_PTS_MAJOR_MIN + (min / LX_MINORMASK);
	lx_min = min % LX_MINORMASK;
	if (lx_maj > LX_PTS_MAJOR_MAX) {
		/*
		 * The major is outside the acceptable range but there's little
		 * we can presently do about it short of overhauling the
		 * translation logic.
		 */
		lx_unsupported("pts major out of translation range");
	}

	*jdev = LX_MAKEDEVICE(lx_maj, lx_min);
}

static void
lxd_ptm_devt_translator(dev_t dev, dev_t *jdev)
{
	*jdev = LX_MAKEDEVICE(LX_PTM_MAJOR, LX_PTM_MINOR);
}
