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
 * Copyright (c) 1990, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2015 Joyent, Inc.
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
#include <sys/debug.h>
#include <sys/systm.h>
#include <sys/mntent.h>
#include <fs/fs_subr.h>
#include <vm/page.h>
#include <vm/anon.h>
#include <sys/model.h>
#include <sys/policy.h>

#include <sys/fs/swapnode.h>
#include <sys/fs/tmp.h>
#include <sys/fs/tmpnode.h>

static int tmpfsfstype;

/*
 * tmpfs vfs operations.
 */
static int tmpfsinit(int, char *);
static int tmp_mount(struct vfs *, struct vnode *,
	struct mounta *, struct cred *);
static int tmp_unmount(struct vfs *, int, struct cred *);
static int tmp_root(struct vfs *, struct vnode **);
static int tmp_statvfs(struct vfs *, struct statvfs64 *);
static int tmp_vget(struct vfs *, struct vnode **, struct fid *);

/*
 * Loadable module wrapper
 */
#include <sys/modctl.h>

static mntopts_t tmpfs_proto_opttbl;

static vfsdef_t vfw = {
	VFSDEF_VERSION,
	"tmpfs",
	tmpfsinit,
	VSW_HASPROTO|VSW_CANREMOUNT|VSW_STATS|VSW_ZMOUNT,
	&tmpfs_proto_opttbl
};

/*
 * in-kernel mnttab options
 */
static char *xattr_cancel[] = { MNTOPT_NOXATTR, NULL };
static char *noxattr_cancel[] = { MNTOPT_XATTR, NULL };

static mntopt_t tmpfs_options[] = {
	/* Option name		Cancel Opt	Arg	Flags		Data */
	{ MNTOPT_XATTR,		xattr_cancel,	NULL,	MO_DEFAULT,	NULL},
	{ MNTOPT_NOXATTR,	noxattr_cancel,	NULL,	NULL,		NULL},
	{ "size",		NULL,		"0",	MO_HASVALUE,	NULL},
	{ "mode",		NULL,		NULL,	MO_HASVALUE,	NULL}
};


static mntopts_t tmpfs_proto_opttbl = {
	sizeof (tmpfs_options) / sizeof (mntopt_t),
	tmpfs_options
};

/*
 * Module linkage information
 */
static struct modlfs modlfs = {
	&mod_fsops, "filesystem for tmpfs", &vfw
};

static struct modlinkage modlinkage = {
	MODREV_1, &modlfs, NULL
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

	error = mod_remove(&modlinkage);
	if (error)
		return (error);
	/*
	 * Tear down the operations vectors
	 */
	(void) vfs_freevfsops_by_type(tmpfsfstype);
	vn_freevnodeops(tmp_vnodeops);
	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * The following are patchable variables limiting the amount of system
 * resources tmpfs can use.
 *
 * tmpfs_maxkmem limits the amount of kernel kmem_alloc memory
 * tmpfs can use for it's data structures (e.g. tmpnodes, directory entries)
 * It is not determined by setting a hard limit but rather as a percentage of
 * physical memory which is determined when tmpfs is first used in the system.
 *
 * tmpfs_minfree is the minimum amount of swap space that tmpfs leaves for
 * the rest of the system.  In other words, if the amount of free swap space
 * in the system (i.e. anoninfo.ani_free) drops below tmpfs_minfree, tmpfs
 * anon allocations will fail.
 *
 * There is also a per mount limit on the amount of swap space
 * (tmount.tm_anonmax) settable via a mount option.
 */
size_t tmpfs_maxkmem = 0;
size_t tmpfs_minfree = 0;
size_t tmp_kmemspace;		/* bytes of kernel heap used by all tmpfs */

static major_t tmpfs_major;
static minor_t tmpfs_minor;
static kmutex_t	tmpfs_minor_lock;

/*
 * initialize global tmpfs locks and such
 * called when loading tmpfs module
 */
static int
tmpfsinit(int fstype, char *name)
{
	static const fs_operation_def_t tmp_vfsops_template[] = {
		VFSNAME_MOUNT,		{ .vfs_mount = tmp_mount },
		VFSNAME_UNMOUNT,	{ .vfs_unmount = tmp_unmount },
		VFSNAME_ROOT,		{ .vfs_root = tmp_root },
		VFSNAME_STATVFS,	{ .vfs_statvfs = tmp_statvfs },
		VFSNAME_VGET,		{ .vfs_vget = tmp_vget },
		NULL,			NULL
	};
	int error;
	extern  void    tmpfs_hash_init();

	tmpfs_hash_init();
	tmpfsfstype = fstype;
	ASSERT(tmpfsfstype != 0);

	error = vfs_setfsops(fstype, tmp_vfsops_template, NULL);
	if (error != 0) {
		cmn_err(CE_WARN, "tmpfsinit: bad vfs ops template");
		return (error);
	}

	error = vn_make_ops(name, tmp_vnodeops_template, &tmp_vnodeops);
	if (error != 0) {
		(void) vfs_freevfsops_by_type(fstype);
		cmn_err(CE_WARN, "tmpfsinit: bad vnode ops template");
		return (error);
	}

	/*
	 * tmpfs_minfree doesn't need to be some function of configured
	 * swap space since it really is an absolute limit of swap space
	 * which still allows other processes to execute.
	 */
	if (tmpfs_minfree == 0) {
		/*
		 * Set if not patched
		 */
		tmpfs_minfree = btopr(TMPMINFREE);
	}

	/*
	 * The maximum amount of space tmpfs can allocate is
	 * TMPMAXPROCKMEM percent of kernel memory
	 */
	if (tmpfs_maxkmem == 0)
		tmpfs_maxkmem = MAX(PAGESIZE, kmem_maxavail() / TMPMAXFRACKMEM);

	if ((tmpfs_major = getudev()) == (major_t)-1) {
		cmn_err(CE_WARN, "tmpfsinit: Can't get unique device number.");
		tmpfs_major = 0;
	}
	mutex_init(&tmpfs_minor_lock, NULL, MUTEX_DEFAULT, NULL);
	return (0);
}

static int
tmp_mount(vfs_t *vfsp, vnode_t *mvp, struct mounta *uap, cred_t *cr)
{
	struct tmount *tm = NULL;
	struct tmpnode *tp;
	struct pathname dpn;
	int error;
	pgcnt_t anonmax;
	struct vattr rattr;
	int got_attrs;
	boolean_t mode_arg = B_FALSE;
	mode_t root_mode = 0777;
	char *argstr;

	if ((error = secpolicy_fs_mount(cr, mvp, vfsp)) != 0)
		return (error);

	if (mvp->v_type != VDIR)
		return (ENOTDIR);

	mutex_enter(&mvp->v_lock);
	if ((uap->flags & MS_REMOUNT) == 0 && (uap->flags & MS_OVERLAY) == 0 &&
	    (mvp->v_count != 1 || (mvp->v_flag & VROOT))) {
		mutex_exit(&mvp->v_lock);
		return (EBUSY);
	}
	mutex_exit(&mvp->v_lock);

	/*
	 * Having the resource be anything but "swap" doesn't make sense.
	 */
	vfs_setresource(vfsp, "swap", 0);

	/*
	 * now look for options we understand...
	 */

	/* tmpfs doesn't support read-only mounts */
	if (vfs_optionisset(vfsp, MNTOPT_RO, NULL)) {
		error = EINVAL;
		goto out;
	}

	/*
	 * tm_anonmax is set according to the mount arguments
	 * if any.  Otherwise, it is set to a maximum value.
	 */
	if (vfs_optionisset(vfsp, "size", &argstr)) {
		if ((error = tmp_convnum(argstr, &anonmax)) != 0)
			goto out;
	} else {
		anonmax = ULONG_MAX;
	}

	/*
	 * The "mode" mount argument allows the operator to override the
	 * permissions of the root of the tmpfs mount.
	 */
	if (vfs_optionisset(vfsp, "mode", &argstr)) {
		if ((error = tmp_convmode(argstr, &root_mode)) != 0) {
			goto out;
		}
		mode_arg = B_TRUE;
	}

	if (error = pn_get(uap->dir,
	    (uap->flags & MS_SYSSPACE) ? UIO_SYSSPACE : UIO_USERSPACE, &dpn))
		goto out;

	if (uap->flags & MS_REMOUNT) {
		tm = (struct tmount *)VFSTOTM(vfsp);

		/*
		 * If we change the size so its less than what is currently
		 * being used, we allow that. The file system will simply be
		 * full until enough files have been removed to get below the
		 * new max.
		 */
		mutex_enter(&tm->tm_contents);
		tm->tm_anonmax = anonmax;
		mutex_exit(&tm->tm_contents);
		goto out;
	}

	if ((tm = tmp_memalloc(sizeof (struct tmount), 0)) == NULL) {
		pn_free(&dpn);
		error = ENOMEM;
		goto out;
	}

	/*
	 * find an available minor device number for this mount
	 */
	mutex_enter(&tmpfs_minor_lock);
	do {
		tmpfs_minor = (tmpfs_minor + 1) & L_MAXMIN32;
		tm->tm_dev = makedevice(tmpfs_major, tmpfs_minor);
	} while (vfs_devismounted(tm->tm_dev));
	mutex_exit(&tmpfs_minor_lock);

	/*
	 * Set but don't bother entering the mutex
	 * (tmount not on mount list yet)
	 */
	mutex_init(&tm->tm_contents, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&tm->tm_renamelck, NULL, MUTEX_DEFAULT, NULL);

	tm->tm_vfsp = vfsp;
	tm->tm_anonmax = anonmax;

	vfsp->vfs_data = (caddr_t)tm;
	vfsp->vfs_fstype = tmpfsfstype;
	vfsp->vfs_dev = tm->tm_dev;
	vfsp->vfs_bsize = PAGESIZE;
	vfsp->vfs_flag |= VFS_NOTRUNC;
	vfs_make_fsid(&vfsp->vfs_fsid, tm->tm_dev, tmpfsfstype);
	tm->tm_mntpath = tmp_memalloc(dpn.pn_pathlen + 1, TMP_MUSTHAVE);
	(void) strcpy(tm->tm_mntpath, dpn.pn_path);

	/*
	 * allocate and initialize root tmpnode structure
	 */
	bzero(&rattr, sizeof (struct vattr));
	rattr.va_mode = (mode_t)(S_IFDIR | root_mode);
	rattr.va_type = VDIR;
	rattr.va_rdev = 0;
	tp = tmp_memalloc(sizeof (struct tmpnode), TMP_MUSTHAVE);
	tmpnode_init(tm, tp, &rattr, cr);

	/*
	 * Get the mode, uid, and gid from the underlying mount point.
	 */
	rattr.va_mask = AT_MODE|AT_UID|AT_GID;	/* Hint to getattr */
	got_attrs = VOP_GETATTR(mvp, &rattr, 0, cr, NULL);

	rw_enter(&tp->tn_rwlock, RW_WRITER);
	TNTOV(tp)->v_flag |= VROOT;

	/*
	 * If the getattr succeeded, use its results.  Otherwise allow
	 * the previously set hardwired defaults to prevail.
	 */
	if (got_attrs == 0) {
		if (!mode_arg) {
			/*
			 * Only use the underlying mount point for the
			 * mode if the "mode" mount argument was not
			 * provided.
			 */
			tp->tn_mode = rattr.va_mode;
		}
		tp->tn_uid = rattr.va_uid;
		tp->tn_gid = rattr.va_gid;
	}

	/*
	 * initialize linked list of tmpnodes so that the back pointer of
	 * the root tmpnode always points to the last one on the list
	 * and the forward pointer of the last node is null
	 */
	tp->tn_back = tp;
	tp->tn_forw = NULL;
	tp->tn_nlink = 0;
	tm->tm_rootnode = tp;

	tdirinit(tp, tp);

	rw_exit(&tp->tn_rwlock);

	pn_free(&dpn);
	error = 0;

out:
	if (error == 0)
		vfs_set_feature(vfsp, VFSFT_SYSATTR_VIEWS);

	return (error);
}

static int
tmp_unmount(struct vfs *vfsp, int flag, struct cred *cr)
{
	struct tmount *tm = (struct tmount *)VFSTOTM(vfsp);
	struct tmpnode *tnp, *cancel;
	struct vnode	*vp;
	int error;

	if ((error = secpolicy_fs_unmount(cr, vfsp)) != 0)
		return (error);

	/*
	 * forced unmount is not supported by this file system
	 * and thus, ENOTSUP, is being returned.
	 */
	if (flag & MS_FORCE)
		return (ENOTSUP);

	mutex_enter(&tm->tm_contents);

	/*
	 * If there are no open files, only the root node should have
	 * a reference count.
	 * With tm_contents held, nothing can be added or removed.
	 * There may be some dirty pages.  To prevent fsflush from
	 * disrupting the unmount, put a hold on each node while scanning.
	 * If we find a previously referenced node, undo the holds we have
	 * placed and fail EBUSY.
	 */
	tnp = tm->tm_rootnode;
	if (TNTOV(tnp)->v_count > 1) {
		mutex_exit(&tm->tm_contents);
		return (EBUSY);
	}

	for (tnp = tnp->tn_forw; tnp; tnp = tnp->tn_forw) {
		if ((vp = TNTOV(tnp))->v_count > 0) {
			cancel = tm->tm_rootnode->tn_forw;
			while (cancel != tnp) {
				vp = TNTOV(cancel);
				ASSERT(vp->v_count > 0);
				VN_RELE(vp);
				cancel = cancel->tn_forw;
			}
			mutex_exit(&tm->tm_contents);
			return (EBUSY);
		}
		VN_HOLD(vp);
	}

	/*
	 * We can drop the mutex now because no one can find this mount
	 */
	mutex_exit(&tm->tm_contents);

	/*
	 * Free all kmemalloc'd and anonalloc'd memory associated with
	 * this filesystem.  To do this, we go through the file list twice,
	 * once to remove all the directory entries, and then to remove
	 * all the files.  We do this because there is useful code in
	 * tmpnode_free which assumes that the directory entry has been
	 * removed before the file.
	 */
	/*
	 * Remove all directory entries
	 */
	for (tnp = tm->tm_rootnode; tnp; tnp = tnp->tn_forw) {
		rw_enter(&tnp->tn_rwlock, RW_WRITER);
		if (tnp->tn_type == VDIR)
			tdirtrunc(tnp);
		if (tnp->tn_vnode->v_flag & V_XATTRDIR) {
			/*
			 * Account for implicit attrdir reference.
			 */
			ASSERT(tnp->tn_nlink > 0);
			DECR_COUNT(&tnp->tn_nlink, &tnp->tn_tlock);
		}
		rw_exit(&tnp->tn_rwlock);
	}

	ASSERT(tm->tm_rootnode);

	/*
	 * All links are gone, v_count is keeping nodes in place.
	 * VN_RELE should make the node disappear, unless somebody
	 * is holding pages against it.  Nap and retry until it disappears.
	 *
	 * We re-acquire the lock to prevent others who have a HOLD on
	 * a tmpnode via its pages or anon slots from blowing it away
	 * (in tmp_inactive) while we're trying to get to it here. Once
	 * we have a HOLD on it we know it'll stick around.
	 *
	 */
	mutex_enter(&tm->tm_contents);
	/*
	 * Remove all the files (except the rootnode) backwards.
	 */
	while ((tnp = tm->tm_rootnode->tn_back) != tm->tm_rootnode) {
		mutex_exit(&tm->tm_contents);
		/*
		 * Inhibit tmp_inactive from touching attribute directory
		 * as all nodes will be released here.
		 * Note we handled the link count in pass 2 above.
		 */
		rw_enter(&tnp->tn_rwlock, RW_WRITER);
		tnp->tn_xattrdp = NULL;
		rw_exit(&tnp->tn_rwlock);
		vp = TNTOV(tnp);
		VN_RELE(vp);
		mutex_enter(&tm->tm_contents);
		/*
		 * It's still there after the RELE. Someone else like pageout
		 * has a hold on it so wait a bit and then try again - we know
		 * they'll give it up soon.
		 */
		if (tnp == tm->tm_rootnode->tn_back) {
			VN_HOLD(vp);
			mutex_exit(&tm->tm_contents);
			delay(hz / 4);
			mutex_enter(&tm->tm_contents);
		}
	}
	mutex_exit(&tm->tm_contents);

	tm->tm_rootnode->tn_xattrdp = NULL;
	VN_RELE(TNTOV(tm->tm_rootnode));

	ASSERT(tm->tm_mntpath);

	tmp_memfree(tm->tm_mntpath, strlen(tm->tm_mntpath) + 1);

	ASSERT(tm->tm_anonmem == 0);

	mutex_destroy(&tm->tm_contents);
	mutex_destroy(&tm->tm_renamelck);
	tmp_memfree(tm, sizeof (struct tmount));

	return (0);
}

/*
 * return root tmpnode for given vnode
 */
static int
tmp_root(struct vfs *vfsp, struct vnode **vpp)
{
	struct tmount *tm = (struct tmount *)VFSTOTM(vfsp);
	struct tmpnode *tp = tm->tm_rootnode;
	struct vnode *vp;

	ASSERT(tp);

	vp = TNTOV(tp);
	VN_HOLD(vp);
	*vpp = vp;
	return (0);
}

static int
tmp_statvfs(struct vfs *vfsp, struct statvfs64 *sbp)
{
	struct tmount	*tm = (struct tmount *)VFSTOTM(vfsp);
	ulong_t	blocks;
	dev32_t d32;
	zoneid_t eff_zid;
	struct zone *zp;

	/*
	 * The file system may have been mounted by the global zone on
	 * behalf of the non-global zone.  In that case, the tmount zone_id
	 * will be the global zone.  We still want to show the swap cap inside
	 * the zone in this case, even though the file system was mounted by
	 * the global zone.
	 */
	if (curproc->p_zone->zone_id != GLOBAL_ZONEUNIQID)
		zp = curproc->p_zone;
	else
		zp = tm->tm_vfsp->vfs_zone;

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

	/*
	 * If tm_anonmax for this mount is less than the available swap space
	 * (minus the amount tmpfs can't use), use that instead
	 */
	if (blocks > tmpfs_minfree)
		sbp->f_bfree = MIN(blocks - tmpfs_minfree,
		    tm->tm_anonmax - tm->tm_anonmem);
	else
		sbp->f_bfree = 0;

	sbp->f_bavail = sbp->f_bfree;

	/*
	 * Total number of blocks is what's available plus what's been used
	 */
	sbp->f_blocks = (fsblkcnt64_t)(sbp->f_bfree + tm->tm_anonmem);

	if (eff_zid != GLOBAL_ZONEUNIQID &&
	    zp->zone_max_swap_ctl != UINT64_MAX) {
		/*
		 * If the fs is used by a non-global zone with a swap cap,
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
	 * of tmpnodes we can allocate from the remaining kernel memory
	 * available to tmpfs.  This is fairly inaccurate since it doesn't
	 * take into account the names stored in the directory entries.
	 */
	if (tmpfs_maxkmem > tmp_kmemspace)
		sbp->f_ffree = (tmpfs_maxkmem - tmp_kmemspace) /
		    (sizeof (struct tmpnode) + sizeof (struct tdirent));
	else
		sbp->f_ffree = 0;

	sbp->f_files = tmpfs_maxkmem /
	    (sizeof (struct tmpnode) + sizeof (struct tdirent));
	sbp->f_favail = (fsfilcnt64_t)(sbp->f_ffree);
	(void) cmpldev(&d32, vfsp->vfs_dev);
	sbp->f_fsid = d32;
	(void) strcpy(sbp->f_basetype, vfssw[tmpfsfstype].vsw_name);
	(void) strncpy(sbp->f_fstr, tm->tm_mntpath, sizeof (sbp->f_fstr));
	/*
	 * ensure null termination
	 */
	sbp->f_fstr[sizeof (sbp->f_fstr) - 1] = '\0';
	sbp->f_flag = vf_to_stf(vfsp->vfs_flag);
	sbp->f_namemax = MAXNAMELEN - 1;
	return (0);
}

static int
tmp_vget(struct vfs *vfsp, struct vnode **vpp, struct fid *fidp)
{
	struct tfid *tfid;
	struct tmount *tm = (struct tmount *)VFSTOTM(vfsp);
	struct tmpnode *tp = NULL;

	tfid = (struct tfid *)fidp;
	*vpp = NULL;

	mutex_enter(&tm->tm_contents);
	for (tp = tm->tm_rootnode; tp; tp = tp->tn_forw) {
		mutex_enter(&tp->tn_tlock);
		if (tp->tn_nodeid == tfid->tfid_ino) {
			/*
			 * If the gen numbers don't match we know the
			 * file won't be found since only one tmpnode
			 * can have this number at a time.
			 */
			if (tp->tn_gen != tfid->tfid_gen || tp->tn_nlink == 0) {
				mutex_exit(&tp->tn_tlock);
				mutex_exit(&tm->tm_contents);
				return (0);
			}
			*vpp = (struct vnode *)TNTOV(tp);

			VN_HOLD(*vpp);

			if ((tp->tn_mode & S_ISVTX) &&
			    !(tp->tn_mode & (S_IXUSR | S_IFDIR))) {
				mutex_enter(&(*vpp)->v_lock);
				(*vpp)->v_flag |= VISSWAP;
				mutex_exit(&(*vpp)->v_lock);
			}
			mutex_exit(&tp->tn_tlock);
			mutex_exit(&tm->tm_contents);
			return (0);
		}
		mutex_exit(&tp->tn_tlock);
	}
	mutex_exit(&tm->tm_contents);
	return (0);
}
