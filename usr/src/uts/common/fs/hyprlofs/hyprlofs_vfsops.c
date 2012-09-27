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
 * Copyright (c) 2012, Joyent, Inc. All rights reserved.
 */

/*
 * Hyperlofs is a hybrid file system combining features of the tmpfs(7FS) and
 * lofs(7FS) file systems.  It is modeled on code from both of these file
 * systems.
 *
 * The purpose is to create a high performance name space for files on which
 * applications will compute.  Given a large number of data files with various
 * owners, we want to construct a view onto those files such that only a subset
 * is visible to the applications and such that the view can be changed very
 * quickly as compute progresses.  Entries in the name space are not mounts and
 * thus do not appear in the mnttab.  Entries in the name space are allowed to
 * refer to files on different backing file systems.  Intermediate directories
 * in the name space exist only in-memory, ala tmpfs.  There are no leaf nodes
 * in the name space except for entries that refer to backing files ala lofs.
 *
 * The name space is managed via ioctls issued on the mounted file system and
 * is mostly read-only for the compute applications.  That is, applications
 * cannot create new files in the name space. If a file is unlinked by an
 * application, that only removes the file from the name space, the backing
 * file remains in place.  It is possible for applications to write-through to
 * the backing files if the file system is mounted read-write.
 *
 * The name space is managed via the HYPRLOFS_ADD_ENTRIES, HYPRLOFS_RM_ENTRIES,
 * and HYPRLOFS_RM_ALL ioctls on the top-level mount.
 *
 * The HYPRLOFS_ADD_ENTRIES ioctl specifies path(s) to the backing file(s) and
 * the name(s) for the file(s) in the name space.  The name(s) may be path(s)
 * which will be relative to the root of the mount and thus cannot begin with
 * a /. If the name is a path, it does not have to correspond to any backing
 * path. The intermediate directories will only exist in the name space. The
 * entry(ies) will be added to the name space.
 *
 * The HYPRLOFS_RM_ENTRIES ioctl specifies the name(s) of the file(s) in the
 * name space which should be removed.  The name(s) may be path(s) which will
 * be relative to the root of the mount and thus cannot begin with a /.  The
 * named entry(ies) will be removed.
 *
 * The HYPRLOFS_RM_ALL ioctl will remove all mappings from the name space.
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
#include <sys/fs/hyprlofs_info.h>

static int hyprlofsfstype;

/*
 * hyprlofs vfs operations.
 */
static int hyprlofsinit(int, char *);
static int hyprlofs_mount(vfs_t *, vnode_t *, struct mounta *, cred_t *);
static int hyprlofs_unmount(vfs_t *, int, cred_t *);
static int hyprlofs_root(vfs_t *, vnode_t **);
static int hyprlofs_statvfs(vfs_t *, struct statvfs64 *);
static int hyprlofs_vget(vfs_t *, vnode_t **, struct fid *);

/*
 * Loadable module wrapper
 */
#include <sys/modctl.h>

static mntopts_t hyprlofs_mntopts;

static vfsdef_t vfw = {
	VFSDEF_VERSION,
	"hyprlofs",
	hyprlofsinit,
	VSW_HASPROTO|VSW_CANREMOUNT|VSW_STATS|VSW_ZMOUNT,
	&hyprlofs_mntopts
};

static mntopts_t hyprlofs_mntopts = {
	0, NULL
};

/*
 * Module linkage information
 */
static struct modlfs modlfs = {
	&mod_fsops, "filesystem for hyprlofs", &vfw
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
	(void) vfs_freevfsops_by_type(hyprlofsfstype);
	vn_freevnodeops(hyprlofs_vnodeops);
	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * The following are patchable variables limiting the amount of system
 * resources hyprlofs can use.
 *
 * hyprlofs_maxkmem limits the amount of kernel kmem_alloc memory hyprlofs can
 * use for it's data structures (e.g. hlnodes, directory entries). It is set
 * as a percentage of physical memory which is determined when hyprlofs is
 * first used in the system.
 *
 * hyprlofs_minfree is the minimum amount of swap space that hyprlofs leaves for
 * the rest of the system. If the amount of free swap space in the system
 * (i.e. anoninfo.ani_free) drops below hyprlofs_minfree, hyprlofs anon
 * allocations will fail.
 */
size_t hyprlofs_maxkmem = 0;
size_t hyprlofs_minfree = 0;
size_t hyprlofs_kmemspace;	/* bytes of kernel heap used by all hyprlofs */

static major_t hyprlofs_major;
static minor_t hyprlofs_minor;
static kmutex_t	hyprlofs_minor_lock;

/*
 * initialize global hyprlofs locks and hashes when loading hyprlofs module
 */
static int
hyprlofsinit(int fstype, char *name)
{
	static const fs_operation_def_t hl_vfsops_template[] = {
		VFSNAME_MOUNT,		{ .vfs_mount = hyprlofs_mount },
		VFSNAME_UNMOUNT,	{ .vfs_unmount = hyprlofs_unmount },
		VFSNAME_ROOT,		{ .vfs_root = hyprlofs_root },
		VFSNAME_STATVFS,	{ .vfs_statvfs = hyprlofs_statvfs },
		VFSNAME_VGET,		{ .vfs_vget = hyprlofs_vget },
		NULL,			NULL
	};
	int error;
	extern  void    hyprlofs_hash_init();

	hyprlofs_hash_init();
	hyprlofsfstype = fstype;
	ASSERT(hyprlofsfstype != 0);

	error = vfs_setfsops(fstype, hl_vfsops_template, NULL);
	if (error != 0) {
		cmn_err(CE_WARN, "hyprlofsinit: bad vfs ops template");
		return (error);
	}

	error = vn_make_ops(name, hyprlofs_vnodeops_template,
	    &hyprlofs_vnodeops);
	if (error != 0) {
		(void) vfs_freevfsops_by_type(fstype);
		cmn_err(CE_WARN, "hyprlofsinit: bad vnode ops template");
		return (error);
	}

	/*
	 * hyprlofs_minfree is an absolute limit of swap space which still
	 * allows other processes to execute.  Set it if its not patched.
	 */
	if (hyprlofs_minfree == 0)
		hyprlofs_minfree = btopr(HYPRLOFSMINFREE);

	/*
	 * The maximum amount of space hyprlofs can allocate is
	 * HYPRLOFSMAXPROCKMEM percent of kernel memory
	 */
	if (hyprlofs_maxkmem == 0)
		hyprlofs_maxkmem =
		    MAX(PAGESIZE, kmem_maxavail() / HYPRLOFSMAXFRACKMEM);

	if ((hyprlofs_major = getudev()) == (major_t)-1) {
		cmn_err(CE_WARN,
		    "hyprlofsinit: Can't get unique device number.");
		hyprlofs_major = 0;
	}
	mutex_init(&hyprlofs_minor_lock, NULL, MUTEX_DEFAULT, NULL);
	return (0);
}

static int
hyprlofs_mount(vfs_t *vfsp, vnode_t *mvp, struct mounta *uap, cred_t *cr)
{
	hlfsmount_t *hm = NULL;
	hlnode_t *hp;
	struct pathname dpn;
	int error;
	vattr_t rattr;
	int got_attrs;

	if ((error = secpolicy_fs_mount(cr, mvp, vfsp)) != 0)
		return (error);
	if (secpolicy_hyprlofs_control(cr) != 0)
		return (EPERM);

	if (mvp->v_type != VDIR)
		return (ENOTDIR);

	if (uap->flags & MS_REMOUNT)
		return (EBUSY);

	mutex_enter(&mvp->v_lock);
	if ((uap->flags & MS_OVERLAY) == 0 &&
	    (mvp->v_count != 1 || (mvp->v_flag & VROOT))) {
		mutex_exit(&mvp->v_lock);
		return (EBUSY);
	}
	mutex_exit(&mvp->v_lock);

	/* Having the resource be anything but "swap" doesn't make sense. */
	vfs_setresource(vfsp, "swap", 0);

	if ((error = pn_get(uap->dir,
	    (uap->flags & MS_SYSSPACE) ? UIO_SYSSPACE : UIO_USERSPACE,
	    &dpn)) != 0)
		goto out;

	if ((hm = hyprlofs_memalloc(sizeof (hlfsmount_t), 0)) == NULL) {
		pn_free(&dpn);
		error = ENOMEM;
		goto out;
	}

	/* Get an available minor device number for this mount */
	mutex_enter(&hyprlofs_minor_lock);
	do {
		hyprlofs_minor = (hyprlofs_minor + 1) & L_MAXMIN32;
		hm->hlm_dev = makedevice(hyprlofs_major, hyprlofs_minor);
	} while (vfs_devismounted(hm->hlm_dev));
	mutex_exit(&hyprlofs_minor_lock);

	/*
	 * Set but don't bother entering the mutex since hlfsmount is not on
	 * the mount list yet.
	 */
	mutex_init(&hm->hlm_contents, NULL, MUTEX_DEFAULT, NULL);

	hm->hlm_vfsp = vfsp;

	vfsp->vfs_data = (caddr_t)hm;
	vfsp->vfs_fstype = hyprlofsfstype;
	vfsp->vfs_dev = hm->hlm_dev;
	vfsp->vfs_bsize = PAGESIZE;
	vfsp->vfs_flag |= VFS_NOTRUNC;
	vfs_make_fsid(&vfsp->vfs_fsid, hm->hlm_dev, hyprlofsfstype);
	hm->hlm_mntpath = hyprlofs_memalloc(dpn.pn_pathlen + 1, HL_MUSTHAVE);
	(void) strcpy(hm->hlm_mntpath, dpn.pn_path);

	/* allocate and initialize root hlnode structure */
	bzero(&rattr, sizeof (vattr_t));
	rattr.va_mode = (mode_t)(S_IFDIR | 0777);
	rattr.va_type = VDIR;
	rattr.va_rdev = 0;
	hp = hyprlofs_memalloc(sizeof (hlnode_t), HL_MUSTHAVE);
	hyprlofs_node_init(hm, hp, &rattr, cr);

	/* Get the mode, uid, and gid from the underlying mount point. */
	rattr.va_mask = AT_MODE|AT_UID|AT_GID;
	got_attrs = VOP_GETATTR(mvp, &rattr, 0, cr, NULL);

	rw_enter(&hp->hln_rwlock, RW_WRITER);
	HLNTOV(hp)->v_flag |= VROOT;

	/*
	 * If the getattr succeeded, use its results, otherwise allow the
	 * previously set defaults to prevail.
	 */
	if (got_attrs == 0) {
		hp->hln_mode = rattr.va_mode;
		hp->hln_uid = rattr.va_uid;
		hp->hln_gid = rattr.va_gid;
	}

	/*
	 * Initialize linked list of hlnodes so that the back pointer of the
	 * root hlnode always points to the last one on the list and the
	 * forward pointer of the last node is null
	 */
	hp->hln_back = hp;
	hp->hln_forw = NULL;
	hp->hln_nlink = 0;
	hm->hlm_rootnode = hp;

	hyprlofs_dirinit(hp, hp);

	rw_exit(&hp->hln_rwlock);

	pn_free(&dpn);
	error = 0;

out:
	return (error);
}

static int
hyprlofs_unmount(vfs_t *vfsp, int flag, cred_t *cr)
{
	hlfsmount_t *hm = (hlfsmount_t *)VFSTOHLM(vfsp);
	hlnode_t *hnp, *cancel;
	vnode_t	*vp;
	int error;

	if ((error = secpolicy_fs_unmount(cr, vfsp)) != 0)
		return (error);
	if (secpolicy_hyprlofs_control(cr) != 0)
		return (EPERM);

	/*
	 * forced unmount is not supported by this file system
	 * and thus, ENOTSUP, is being returned.
	 */
	if (flag & MS_FORCE)
		return (ENOTSUP);

	mutex_enter(&hm->hlm_contents);

	/*
	 * If there are no open files, only the root node should have a ref cnt.
	 * With hlm_contents held, nothing can be added or removed. There may
	 * be some dirty pages.  To prevent fsflush from disrupting the unmount,
	 * put a hold on each node while scanning. If we find a previously
	 * referenced node, undo the holds we have placed and fail EBUSY.
	 */
	hnp = hm->hlm_rootnode;
	if (HLNTOV(hnp)->v_count > 1) {
		mutex_exit(&hm->hlm_contents);
		return (EBUSY);
	}

	for (hnp = hnp->hln_forw; hnp; hnp = hnp->hln_forw) {
		if ((vp = HLNTOV(hnp))->v_count > 0) {
			cancel = hm->hlm_rootnode->hln_forw;
			while (cancel != hnp) {
				vp = HLNTOV(cancel);
				ASSERT(vp->v_count > 0);
				VN_RELE(vp);
				cancel = cancel->hln_forw;
			}
			mutex_exit(&hm->hlm_contents);
			return (EBUSY);
		}
		VN_HOLD(vp);
	}

	/* We can drop the mutex now because no one can find this mount */
	mutex_exit(&hm->hlm_contents);

	/*
	 * Free all alloc'd memory associated with this FS. To do this, we go
	 * through the file list twice, once to remove all the dir entries, and
	 * then to remove all the files.
	 */

	/* Remove all directory entries */
	for (hnp = hm->hlm_rootnode; hnp; hnp = hnp->hln_forw) {
		rw_enter(&hnp->hln_rwlock, RW_WRITER);
		if (hnp->hln_type == VDIR)
			hyprlofs_dirtrunc(hnp);
		rw_exit(&hnp->hln_rwlock);
	}

	ASSERT(hm->hlm_rootnode);

	/*
	 * All links are gone, v_count is keeping nodes in place. VN_RELE
	 * should make the node disappear, unless somebody is holding pages
	 * against it.  Wait and retry until it disappears.
	 *
	 * We re-acquire the lock to prevent others who have a HOLD on a hlnode
	 * from blowing it away (in hyprlofs_inactive) while we're trying to
	 * get to it here. Once we have a HOLD on it we know it'll stick around.
	 */
	mutex_enter(&hm->hlm_contents);

	/* Remove all the files (except the rootnode) backwards. */
	while ((hnp = hm->hlm_rootnode->hln_back) != hm->hlm_rootnode) {
		mutex_exit(&hm->hlm_contents);
		/* Note we handled the link count in pass 2 above. */
		vp = HLNTOV(hnp);
		VN_RELE(vp);
		mutex_enter(&hm->hlm_contents);
		/*
		 * It's still there after the RELE. Someone else like pageout
		 * has a hold on it so wait a bit and then try again.
		 */
		if (hnp == hm->hlm_rootnode->hln_back) {
			VN_HOLD(vp);
			mutex_exit(&hm->hlm_contents);
			delay(hz / 4);
			mutex_enter(&hm->hlm_contents);
		}
	}
	mutex_exit(&hm->hlm_contents);

	VN_RELE(HLNTOV(hm->hlm_rootnode));

	ASSERT(hm->hlm_mntpath);

	hyprlofs_memfree(hm->hlm_mntpath, strlen(hm->hlm_mntpath) + 1);

	mutex_destroy(&hm->hlm_contents);
	hyprlofs_memfree(hm, sizeof (hlfsmount_t));

	return (0);
}

/* Return root hlnode for given vnode */
static int
hyprlofs_root(vfs_t *vfsp, vnode_t **vpp)
{
	hlfsmount_t *hm = (hlfsmount_t *)VFSTOHLM(vfsp);
	hlnode_t *hp = hm->hlm_rootnode;
	vnode_t *vp;

	ASSERT(hp);

	vp = HLNTOV(hp);
	VN_HOLD(vp);
	*vpp = vp;
	return (0);
}

static int
hyprlofs_statvfs(vfs_t *vfsp, struct statvfs64 *sbp)
{
	hlfsmount_t *hm = (hlfsmount_t *)VFSTOHLM(vfsp);
	ulong_t	blocks;
	dev32_t d32;
	zoneid_t eff_zid;
	struct zone *zp;

	/*
	 * The FS may have been mounted by the GZ on behalf of the NGZ.  In
	 * that case, the hlfsmount zone_id will be the global zone.  We want
	 * to show the swap cap inside the zone in this case, even though the
	 * FS was mounted by the GZ.
	 */
	if (curproc->p_zone->zone_id != GLOBAL_ZONEUNIQID)
		zp = curproc->p_zone;
	else
		zp = hm->hlm_vfsp->vfs_zone;

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

	if (blocks > hyprlofs_minfree)
		sbp->f_bfree = blocks - hyprlofs_minfree;
	else
		sbp->f_bfree = 0;

	sbp->f_bavail = sbp->f_bfree;

	/*
	 * Total number of blocks is what's available plus what's been used
	 */
	sbp->f_blocks = (fsblkcnt64_t)(sbp->f_bfree);

	if (eff_zid != GLOBAL_ZONEUNIQID &&
	    zp->zone_max_swap_ctl != UINT64_MAX) {
		/*
		 * If the fs is used by a NGZ with a swap cap, then report the
		 * capped size.
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
	 * This is fairly inaccurate since it doesn't take into account the
	 * names stored in the directory entries.
	 */
	if (hyprlofs_maxkmem > hyprlofs_kmemspace)
		sbp->f_ffree = (hyprlofs_maxkmem - hyprlofs_kmemspace) /
		    (sizeof (hlnode_t) + sizeof (hldirent_t));
	else
		sbp->f_ffree = 0;

	sbp->f_files = hyprlofs_maxkmem /
	    (sizeof (hlnode_t) + sizeof (hldirent_t));
	sbp->f_favail = (fsfilcnt64_t)(sbp->f_ffree);
	(void) cmpldev(&d32, vfsp->vfs_dev);
	sbp->f_fsid = d32;
	(void) strcpy(sbp->f_basetype, vfssw[hyprlofsfstype].vsw_name);
	(void) strncpy(sbp->f_fstr, hm->hlm_mntpath, sizeof (sbp->f_fstr));
	/*
	 * ensure null termination
	 */
	sbp->f_fstr[sizeof (sbp->f_fstr) - 1] = '\0';
	sbp->f_flag = vf_to_stf(vfsp->vfs_flag);
	sbp->f_namemax = MAXNAMELEN - 1;
	return (0);
}

static int
hyprlofs_vget(vfs_t *vfsp, vnode_t **vpp, struct fid *fidp)
{
	hlfid_t *hfid;
	hlfsmount_t *hm = (hlfsmount_t *)VFSTOHLM(vfsp);
	hlnode_t *hp = NULL;

	hfid = (hlfid_t *)fidp;
	*vpp = NULL;

	mutex_enter(&hm->hlm_contents);
	for (hp = hm->hlm_rootnode; hp; hp = hp->hln_forw) {
		mutex_enter(&hp->hln_tlock);
		if (hp->hln_nodeid == hfid->hlfid_ino) {
			/*
			 * If the gen numbers don't match we know the file
			 * won't be found since only one hlnode can have this
			 * number at a time.
			 */
			if (hp->hln_gen != hfid->hlfid_gen ||
			    hp->hln_nlink == 0) {
				mutex_exit(&hp->hln_tlock);
				mutex_exit(&hm->hlm_contents);
				return (0);
			}
			*vpp = (vnode_t *)HLNTOV(hp);

			VN_HOLD(*vpp);

			if ((hp->hln_mode & S_ISVTX) &&
			    !(hp->hln_mode & (S_IXUSR | S_IFDIR))) {
				mutex_enter(&(*vpp)->v_lock);
				(*vpp)->v_flag |= VISSWAP;
				mutex_exit(&(*vpp)->v_lock);
			}
			mutex_exit(&hp->hln_tlock);
			mutex_exit(&hm->hlm_contents);
			return (0);
		}
		mutex_exit(&hp->hln_tlock);
	}
	mutex_exit(&hm->hlm_contents);
	return (0);
}
