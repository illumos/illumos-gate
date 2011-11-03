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
 * Copyright (c) 2011 Bayard G. Bell. All rights reserved.
 */

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/resource.h>
#include <sys/signal.h>
#include <sys/cred.h>
#include <sys/user.h>
#include <sys/buf.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/stat.h>
#include <sys/vnode.h>
#include <sys/mode.h>
#include <sys/proc.h>
#include <sys/disp.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <sys/flock.h>
#include <sys/kmem.h>
#include <sys/uio.h>
#include <sys/dnlc.h>
#include <sys/conf.h>
#include <sys/errno.h>
#include <sys/mman.h>
#include <sys/fbuf.h>
#include <sys/pathname.h>
#include <sys/debug.h>
#include <sys/vmsystm.h>
#include <sys/cmn_err.h>
#include <sys/dirent.h>
#include <sys/errno.h>
#include <sys/modctl.h>
#include <sys/statvfs.h>
#include <sys/mount.h>
#include <sys/sunddi.h>
#include <sys/bootconf.h>
#include <sys/policy.h>

#include <vm/hat.h>
#include <vm/page.h>
#include <vm/pvn.h>
#include <vm/as.h>
#include <vm/seg.h>
#include <vm/seg_map.h>
#include <vm/seg_kmem.h>
#include <vm/seg_vn.h>
#include <vm/rm.h>
#include <vm/page.h>
#include <sys/swap.h>
#include <sys/mntent.h>


#include <fs/fs_subr.h>


#include <sys/fs/udf_volume.h>
#include <sys/fs/udf_inode.h>


extern struct vnode *common_specvp(struct vnode *vp);

extern kmutex_t ud_sync_busy;
static int32_t ud_mountfs(struct vfs *,
    enum whymountroot, dev_t, char *, struct cred *, int32_t);
static struct udf_vfs *ud_validate_and_fill_superblock(dev_t,
    int32_t, uint32_t);
void ud_destroy_fsp(struct udf_vfs *);
void ud_convert_to_superblock(struct udf_vfs *,
    struct log_vol_int_desc *);
void ud_update_superblock(struct vfs *);
int32_t ud_get_last_block(dev_t, daddr_t *);
static int32_t ud_val_get_vat(struct udf_vfs *,
    dev_t, daddr_t, struct ud_map *);
int32_t ud_read_sparing_tbls(struct udf_vfs *,
    dev_t, struct ud_map *, struct pmap_typ2 *);
uint32_t ud_get_lbsize(dev_t, uint32_t *);

static int32_t udf_mount(struct vfs *,
    struct vnode *, struct mounta *, struct cred *);
static int32_t udf_unmount(struct vfs *, int, struct cred *);
static int32_t udf_root(struct vfs *, struct vnode **);
static int32_t udf_statvfs(struct vfs *, struct statvfs64 *);
static int32_t udf_sync(struct vfs *, int16_t, struct cred *);
static int32_t udf_vget(struct vfs *, struct vnode **, struct fid *);
static int32_t udf_mountroot(struct vfs *vfsp, enum whymountroot);

static int udfinit(int, char *);

static mntopts_t udfs_mntopts;

static vfsdef_t vfw = {
	VFSDEF_VERSION,
	"udfs",
	udfinit,
	VSW_HASPROTO|VSW_CANREMOUNT|VSW_STATS|VSW_CANLOFI,
	&udfs_mntopts
};

static mntopts_t udfs_mntopts = {
	0,
	NULL
};

/*
 * Module linkage information for the kernel.
 */
extern struct mod_ops mod_fsops;

static struct modlfs modlfs = {
	&mod_fsops, "filesystem for UDFS", &vfw
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlfs, NULL
};

int32_t udf_fstype = -1;

int
_init()
{
	return (mod_install(&modlinkage));
}

int
_fini()
{
	return (EBUSY);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


/* -------------------- vfs routines -------------------- */

/*
 * XXX - this appears only to be used by the VM code to handle the case where
 * UNIX is running off the mini-root.  That probably wants to be done
 * differently.
 */
struct vnode *rootvp;
#ifndef	__lint
_NOTE(SCHEME_PROTECTS_DATA("safe sharing", rootvp))
#endif
static int32_t
udf_mount(struct vfs *vfsp, struct vnode *mvp,
	struct mounta *uap, struct cred *cr)
{
	dev_t dev;
	struct vnode *lvp = NULL;
	struct vnode *svp = NULL;
	struct pathname dpn;
	int32_t error;
	enum whymountroot why;
	int oflag, aflag;

	ud_printf("udf_mount\n");

	if ((error = secpolicy_fs_mount(cr, mvp, vfsp)) != 0) {
		return (error);
	}

	if (mvp->v_type != VDIR) {
		return (ENOTDIR);
	}

	mutex_enter(&mvp->v_lock);
	if ((uap->flags & MS_REMOUNT) == 0 &&
	    (uap->flags & MS_OVERLAY) == 0 &&
	    (mvp->v_count != 1 || (mvp->v_flag & VROOT))) {
		mutex_exit(&mvp->v_lock);
		return (EBUSY);
	}
	mutex_exit(&mvp->v_lock);

	if (error = pn_get(uap->dir, UIO_USERSPACE, &dpn)) {
		return (error);
	}

	/*
	 * Resolve path name of the file being mounted.
	 */
	if (error = lookupname(uap->spec, UIO_USERSPACE, FOLLOW, NULLVPP,
	    &svp)) {
		pn_free(&dpn);
		return (error);
	}

	error = vfs_get_lofi(vfsp, &lvp);

	if (error > 0) {
		if (error == ENOENT)
			error = ENODEV;
		goto out;
	} else if (error == 0) {
		dev = lvp->v_rdev;
	} else {
		dev = svp->v_rdev;

		if (svp->v_type != VBLK) {
			error = ENOTBLK;
			goto out;
		}
	}

	/*
	 * Ensure that this device isn't already mounted,
	 * unless this is a REMOUNT request
	 */
	if (vfs_devmounting(dev, vfsp)) {
		error = EBUSY;
		goto out;
	}
	if (vfs_devismounted(dev)) {
		if (uap->flags & MS_REMOUNT) {
			why = ROOT_REMOUNT;
		} else {
			error = EBUSY;
			goto out;
		}
	} else {
		why = ROOT_INIT;
	}
	if (getmajor(dev) >= devcnt) {
		error = ENXIO;
		goto out;
	}

	/*
	 * If the device is a tape, mount it read only
	 */
	if (devopsp[getmajor(dev)]->devo_cb_ops->cb_flag & D_TAPE) {
		vfsp->vfs_flag |= VFS_RDONLY;
	}

	if (uap->flags & MS_RDONLY) {
		vfsp->vfs_flag |= VFS_RDONLY;
	}

	/*
	 * Set mount options.
	 */
	if (uap->flags & MS_RDONLY) {
		vfs_setmntopt(vfsp, MNTOPT_RO, NULL, 0);
	}
	if (uap->flags & MS_NOSUID) {
		vfs_setmntopt(vfsp, MNTOPT_NOSUID, NULL, 0);
	}

	/*
	 * Verify that the caller can open the device special file as
	 * required.  It is not until this moment that we know whether
	 * we're mounting "ro" or not.
	 */
	if ((vfsp->vfs_flag & VFS_RDONLY) != 0) {
		oflag = FREAD;
		aflag = VREAD;
	} else {
		oflag = FREAD | FWRITE;
		aflag = VREAD | VWRITE;
	}

	if (lvp == NULL &&
	    (error = secpolicy_spec_open(cr, svp, oflag)) != 0)
		goto out;

	if ((error = VOP_ACCESS(svp, aflag, 0, cr, NULL)) != 0)
		goto out;

	/*
	 * Mount the filesystem.
	 */
	error = ud_mountfs(vfsp, why, dev, dpn.pn_path, cr, 0);
out:
	VN_RELE(svp);
	if (lvp != NULL)
		VN_RELE(lvp);
	pn_free(&dpn);
	return (error);
}



/*
 * unmount the file system pointed
 * by vfsp
 */
/* ARGSUSED */
static int32_t
udf_unmount(struct vfs *vfsp, int fflag, struct cred *cr)
{
	struct udf_vfs *udf_vfsp;
	struct vnode *bvp, *rvp;
	struct ud_inode *rip;
	int32_t flag;

	ud_printf("udf_unmount\n");

	if (secpolicy_fs_unmount(cr, vfsp) != 0) {
		return (EPERM);
	}

	/*
	 * forced unmount is not supported by this file system
	 * and thus, ENOTSUP, is being returned.
	 */
	if (fflag & MS_FORCE)
		return (ENOTSUP);

	udf_vfsp = (struct udf_vfs *)vfsp->vfs_data;
	flag = !(udf_vfsp->udf_flags & UDF_FL_RDONLY);
	bvp = udf_vfsp->udf_devvp;

	rvp = udf_vfsp->udf_root;
	ASSERT(rvp != NULL);
	rip = VTOI(rvp);

	(void) ud_release_cache(udf_vfsp);


	/* Flush all inodes except root */
	if (ud_iflush(vfsp) < 0) {
		return (EBUSY);
	}

	rw_enter(&rip->i_contents, RW_WRITER);
	(void) ud_syncip(rip, B_INVAL, I_SYNC);
	rw_exit(&rip->i_contents);

	mutex_enter(&ud_sync_busy);
	if ((udf_vfsp->udf_flags & UDF_FL_RDONLY) == 0) {
		bflush(vfsp->vfs_dev);
		mutex_enter(&udf_vfsp->udf_lock);
		udf_vfsp->udf_clean = UDF_CLEAN;
		mutex_exit(&udf_vfsp->udf_lock);
		ud_update_superblock(vfsp);
	}
	mutex_exit(&ud_sync_busy);

	mutex_destroy(&udf_vfsp->udf_lock);
	mutex_destroy(&udf_vfsp->udf_rename_lck);

	ud_delcache(rip);
	ITIMES(rip);
	VN_RELE(rvp);

	ud_destroy_fsp(udf_vfsp);

	(void) VOP_PUTPAGE(bvp, (offset_t)0, (uint32_t)0, B_INVAL, cr, NULL);
	(void) VOP_CLOSE(bvp, flag, 1, (offset_t)0, cr, NULL);

	(void) bfinval(vfsp->vfs_dev, 1);
	VN_RELE(bvp);


	return (0);
}


/*
 * Get the root vp for the
 * file system
 */
static int32_t
udf_root(struct vfs *vfsp, struct vnode **vpp)
{
	struct udf_vfs *udf_vfsp;
	struct vnode *vp;

	ud_printf("udf_root\n");

	udf_vfsp = (struct udf_vfs *)vfsp->vfs_data;

	ASSERT(udf_vfsp != NULL);
	ASSERT(udf_vfsp->udf_root != NULL);

	vp = udf_vfsp->udf_root;
	VN_HOLD(vp);
	*vpp = vp;
	return (0);
}


/*
 * Get file system statistics.
 */
static int32_t
udf_statvfs(struct vfs *vfsp, struct statvfs64 *sp)
{
	struct udf_vfs *udf_vfsp;
	struct ud_part *parts;
	dev32_t d32;
	int32_t index;

	ud_printf("udf_statvfs\n");

	udf_vfsp = (struct udf_vfs *)vfsp->vfs_data;
	(void) bzero(sp, sizeof (struct statvfs64));

	mutex_enter(&udf_vfsp->udf_lock);
	sp->f_bsize = udf_vfsp->udf_lbsize;
	sp->f_frsize = udf_vfsp->udf_lbsize;
	sp->f_blocks = 0;
	sp->f_bfree = 0;
	parts = udf_vfsp->udf_parts;
	for (index = 0; index < udf_vfsp->udf_npart; index++) {
		sp->f_blocks += parts->udp_nblocks;
		sp->f_bfree += parts->udp_nfree;
		parts++;
	}
	sp->f_bavail = sp->f_bfree;

	/*
	 * Since there are no real inodes allocated
	 * we will approximate
	 * each new file will occupy :
	 * 38(over head each dent) + MAXNAMLEN / 2 + inode_size(==block size)
	 */
	sp->f_ffree = sp->f_favail =
	    (sp->f_bavail * sp->f_bsize) / (146 + sp->f_bsize);

	/*
	 * The total number of inodes is
	 * the sum of files + directories + free inodes
	 */
	sp->f_files = sp->f_ffree + udf_vfsp->udf_nfiles + udf_vfsp->udf_ndirs;
	(void) cmpldev(&d32, vfsp->vfs_dev);
	sp->f_fsid = d32;
	(void) strcpy(sp->f_basetype, vfssw[vfsp->vfs_fstype].vsw_name);
	sp->f_flag = vf_to_stf(vfsp->vfs_flag);
	sp->f_namemax = MAXNAMLEN;
	(void) strcpy(sp->f_fstr, udf_vfsp->udf_volid);

	mutex_exit(&udf_vfsp->udf_lock);

	return (0);
}


/*
 * Flush any pending I/O to file system vfsp.
 * The ud_update() routine will only flush *all* udf files.
 */
/*ARGSUSED*/
/* ARGSUSED */
static int32_t
udf_sync(struct vfs *vfsp, int16_t flag, struct cred *cr)
{
	ud_printf("udf_sync\n");

	ud_update(flag);
	return (0);
}



/* ARGSUSED */
static int32_t
udf_vget(struct vfs *vfsp,
	struct vnode **vpp, struct fid *fidp)
{
	int32_t error = 0;
	struct udf_fid *udfid;
	struct udf_vfs *udf_vfsp;
	struct ud_inode *ip;

	ud_printf("udf_vget\n");

	udf_vfsp = (struct udf_vfs *)vfsp->vfs_data;
	if (udf_vfsp == NULL) {
		*vpp = NULL;
		return (0);
	}

	udfid = (struct udf_fid *)fidp;
	if ((error = ud_iget(vfsp, udfid->udfid_prn,
	    udfid->udfid_icb_lbn, &ip, NULL, CRED())) != 0) {
		*vpp = NULL;
		return (error);
	}

	rw_enter(&ip->i_contents, RW_READER);
	if ((udfid->udfid_uinq_lo != (ip->i_uniqid & 0xffffffff)) ||
	    (udfid->udfid_prn != ip->i_icb_prn)) {
		rw_exit(&ip->i_contents);
		VN_RELE(ITOV(ip));
		*vpp = NULL;
		return (EINVAL);
	}
	rw_exit(&ip->i_contents);

	*vpp = ITOV(ip);
	return (0);
}


/*
 * Mount root file system.
 * "why" is ROOT_INIT on initial call, ROOT_REMOUNT if called to
 * remount the root file system, and ROOT_UNMOUNT if called to
 * unmount the root (e.g., as part of a system shutdown).
 *
 * XXX - this may be partially machine-dependent; it, along with the VFS_SWAPVP
 * operation, goes along with auto-configuration.  A mechanism should be
 * provided by which machine-INdependent code in the kernel can say "get me the
 * right root file system" and "get me the right initial swap area", and have
 * that done in what may well be a machine-dependent fashion.
 * Unfortunately, it is also file-system-type dependent (NFS gets it via
 * bootparams calls, UFS gets it from various and sundry machine-dependent
 * mechanisms, as SPECFS does for swap).
 */
/* ARGSUSED */
static int32_t
udf_mountroot(struct vfs *vfsp, enum whymountroot why)
{
	dev_t rootdev;
	static int32_t udf_rootdone = 0;
	struct vnode *vp = NULL;
	int32_t ovflags, error;
	ud_printf("udf_mountroot\n");

	if (why == ROOT_INIT) {
		if (udf_rootdone++) {
			return (EBUSY);
		}
		rootdev = getrootdev();
		if (rootdev == (dev_t)NODEV) {
			return (ENODEV);
		}
		vfsp->vfs_dev = rootdev;
		vfsp->vfs_flag |= VFS_RDONLY;
	} else if (why == ROOT_REMOUNT) {
		vp = ((struct udf_vfs *)vfsp->vfs_data)->udf_devvp;
		(void) dnlc_purge_vfsp(vfsp, 0);
		vp = common_specvp(vp);
		(void) VOP_PUTPAGE(vp, (offset_t)0,
		    (uint32_t)0, B_INVAL, CRED(), NULL);
		binval(vfsp->vfs_dev);

		ovflags = vfsp->vfs_flag;
		vfsp->vfs_flag &= ~VFS_RDONLY;
		vfsp->vfs_flag |= VFS_REMOUNT;
		rootdev = vfsp->vfs_dev;
	} else if (why == ROOT_UNMOUNT) {
		ud_update(0);
		vp = ((struct udf_vfs *)vfsp->vfs_data)->udf_devvp;
		(void) VOP_CLOSE(vp, FREAD|FWRITE, 1,
		    (offset_t)0, CRED(), NULL);
		return (0);
	}

	if ((error = vfs_lock(vfsp)) != 0) {
		return (error);
	}

	error = ud_mountfs(vfsp, why, rootdev, "/", CRED(), 1);
	if (error) {
		vfs_unlock(vfsp);
		if (why == ROOT_REMOUNT) {
			vfsp->vfs_flag = ovflags;
		}
		if (rootvp) {
			VN_RELE(rootvp);
			rootvp = (struct vnode *)0;
		}
		return (error);
	}

	if (why == ROOT_INIT) {
		vfs_add((struct vnode *)0, vfsp,
		    (vfsp->vfs_flag & VFS_RDONLY) ? MS_RDONLY : 0);
	}
	vfs_unlock(vfsp);
	return (0);
}


/* ------------------------- local routines ------------------------- */


static int32_t
ud_mountfs(struct vfs *vfsp,
	enum whymountroot why, dev_t dev, char *name,
	struct cred *cr, int32_t isroot)
{
	struct vnode *devvp = NULL;
	int32_t error = 0;
	int32_t needclose = 0;
	struct udf_vfs *udf_vfsp = NULL;
	struct log_vol_int_desc *lvid;
	struct ud_inode *rip = NULL;
	struct vnode *rvp = NULL;
	int32_t i, lbsize;
	uint32_t avd_loc;
	struct ud_map *map;
	int32_t	desc_len;

	ud_printf("ud_mountfs\n");

	if (why == ROOT_INIT) {
		/*
		 * Open the device.
		 */
		devvp = makespecvp(dev, VBLK);

		/*
		 * Open block device mounted on.
		 * When bio is fixed for vnodes this can all be vnode
		 * operations.
		 */
		error = VOP_OPEN(&devvp,
		    (vfsp->vfs_flag & VFS_RDONLY) ? FREAD : FREAD|FWRITE,
		    cr, NULL);
		if (error) {
			goto out;
		}
		needclose = 1;

		/*
		 * Refuse to go any further if this
		 * device is being used for swapping.
		 */
		if (IS_SWAPVP(devvp)) {
			error = EBUSY;
			goto out;
		}
	}

	/*
	 * check for dev already mounted on
	 */
	if (vfsp->vfs_flag & VFS_REMOUNT) {
		struct tag *ttag;
		int32_t index, count;
		struct buf *tpt = 0;
		caddr_t addr;


		/* cannot remount to RDONLY */
		if (vfsp->vfs_flag & VFS_RDONLY) {
			return (EINVAL);
		}

		if (vfsp->vfs_dev != dev) {
			return (EINVAL);
		}

		udf_vfsp = (struct udf_vfs *)vfsp->vfs_data;
		devvp = udf_vfsp->udf_devvp;

		/*
		 * fsck may have altered the file system; discard
		 * as much incore data as possible.  Don't flush
		 * if this is a rw to rw remount; it's just resetting
		 * the options.
		 */
		if (udf_vfsp->udf_flags & UDF_FL_RDONLY) {
			(void) dnlc_purge_vfsp(vfsp, 0);
			(void) VOP_PUTPAGE(devvp, (offset_t)0, (uint_t)0,
			    B_INVAL, CRED(), NULL);
			(void) ud_iflush(vfsp);
			bflush(dev);
			binval(dev);
		}

		/*
		 * We could read UDF1.50 and write UDF1.50 only
		 * disallow mount of any highier version
		 */
		if ((udf_vfsp->udf_miread > UDF_150) ||
		    (udf_vfsp->udf_miwrite > UDF_150)) {
			error = EINVAL;
			goto remountout;
		}

		/*
		 * read/write to read/write; all done
		 */
		if (udf_vfsp->udf_flags & UDF_FL_RW) {
			goto remountout;
		}

		/*
		 * Does the media type allow a writable mount
		 */
		if (udf_vfsp->udf_mtype != UDF_MT_OW) {
			error = EINVAL;
			goto remountout;
		}

		/*
		 * Read the metadata
		 * and check if it is possible to
		 * mount in rw mode
		 */
		tpt = ud_bread(vfsp->vfs_dev,
		    udf_vfsp->udf_iseq_loc << udf_vfsp->udf_l2d_shift,
		    udf_vfsp->udf_iseq_len);
		if (tpt->b_flags & B_ERROR) {
			error = EIO;
			goto remountout;
		}
		count = udf_vfsp->udf_iseq_len / DEV_BSIZE;
		addr = tpt->b_un.b_addr;
		for (index = 0; index < count; index ++) {
			ttag = (struct tag *)(addr + index * DEV_BSIZE);
			desc_len = udf_vfsp->udf_iseq_len - (index * DEV_BSIZE);
			if (ud_verify_tag_and_desc(ttag, UD_LOG_VOL_INT,
			    udf_vfsp->udf_iseq_loc +
			    (index >> udf_vfsp->udf_l2d_shift),
			    1, desc_len) == 0) {
				struct log_vol_int_desc *lvid;

				lvid = (struct log_vol_int_desc *)ttag;

				if (SWAP_32(lvid->lvid_int_type) !=
				    LOG_VOL_CLOSE_INT) {
					error = EINVAL;
					goto remountout;
				}

				/*
				 * Copy new data to old data
				 */
				bcopy(udf_vfsp->udf_iseq->b_un.b_addr,
				    tpt->b_un.b_addr, udf_vfsp->udf_iseq_len);
				break;
			}
		}

		udf_vfsp->udf_flags = UDF_FL_RW;

		mutex_enter(&udf_vfsp->udf_lock);
		ud_sbwrite(udf_vfsp);
		mutex_exit(&udf_vfsp->udf_lock);
remountout:
		if (tpt != NULL) {
			tpt->b_flags = B_AGE | B_STALE;
			brelse(tpt);
		}
		return (error);
	}

	ASSERT(devvp != 0);
	/*
	 * Flush back any dirty pages on the block device to
	 * try and keep the buffer cache in sync with the page
	 * cache if someone is trying to use block devices when
	 * they really should be using the raw device.
	 */
	(void) VOP_PUTPAGE(common_specvp(devvp), (offset_t)0,
	    (uint32_t)0, B_INVAL, cr, NULL);


	/*
	 * Check if the file system
	 * is a valid udfs and fill
	 * the required fields in udf_vfs
	 */
#ifndef	__lint
	_NOTE(NO_COMPETING_THREADS_NOW);
#endif

	if ((lbsize = ud_get_lbsize(dev, &avd_loc)) == 0) {
		error = EINVAL;
		goto out;
	}

	udf_vfsp = ud_validate_and_fill_superblock(dev, lbsize, avd_loc);
	if (udf_vfsp == NULL) {
		error = EINVAL;
		goto out;
	}

	/*
	 * Fill in vfs private data
	 */
	vfsp->vfs_fstype = udf_fstype;
	vfs_make_fsid(&vfsp->vfs_fsid, dev, udf_fstype);
	vfsp->vfs_data = (caddr_t)udf_vfsp;
	vfsp->vfs_dev = dev;
	vfsp->vfs_flag |= VFS_NOTRUNC;
	udf_vfsp->udf_devvp = devvp;

	udf_vfsp->udf_fsmnt = kmem_zalloc(strlen(name) + 1, KM_SLEEP);
	(void) strcpy(udf_vfsp->udf_fsmnt, name);

	udf_vfsp->udf_vfs = vfsp;
	udf_vfsp->udf_rdclustsz = udf_vfsp->udf_wrclustsz = maxphys;

	udf_vfsp->udf_mod = 0;


	lvid = udf_vfsp->udf_lvid;
	if (vfsp->vfs_flag & VFS_RDONLY) {
		/*
		 * We could read only UDF1.50
		 * disallow mount of any highier version
		 */
		if (udf_vfsp->udf_miread > UDF_150) {
			error = EINVAL;
			goto out;
		}
		udf_vfsp->udf_flags = UDF_FL_RDONLY;
		if (SWAP_32(lvid->lvid_int_type) == LOG_VOL_CLOSE_INT) {
			udf_vfsp->udf_clean = UDF_CLEAN;
		} else {
			/* Do we have a VAT at the end of the recorded media */
			map = udf_vfsp->udf_maps;
			for (i = 0; i < udf_vfsp->udf_nmaps; i++) {
				if (map->udm_flags & UDM_MAP_VPM) {
					break;
				}
				map++;
			}
			if (i == udf_vfsp->udf_nmaps) {
				error = ENOSPC;
				goto out;
			}
			udf_vfsp->udf_clean = UDF_CLEAN;
		}
	} else {
		/*
		 * We could read UDF1.50 and write UDF1.50 only
		 * disallow mount of any highier version
		 */
		if ((udf_vfsp->udf_miread > UDF_150) ||
		    (udf_vfsp->udf_miwrite > UDF_150)) {
			error = EINVAL;
			goto out;
		}
		/*
		 * Check if the media allows
		 * us to mount read/write
		 */
		if (udf_vfsp->udf_mtype != UDF_MT_OW) {
			error = EACCES;
			goto out;
		}

		/*
		 * Check if we have VAT on a writable media
		 * we cannot use the media in presence of VAT
		 * Dent RW mount.
		 */
		map = udf_vfsp->udf_maps;
		ASSERT(map != NULL);
		for (i = 0; i < udf_vfsp->udf_nmaps; i++) {
			if (map->udm_flags & UDM_MAP_VPM) {
				error = EACCES;
				goto out;
			}
			map++;
		}

		/*
		 * Check if the domain Id allows
		 * us to write
		 */
		if (udf_vfsp->udf_lvd->lvd_dom_id.reg_ids[2] & 0x3) {
			error = EACCES;
			goto out;
		}
		udf_vfsp->udf_flags = UDF_FL_RW;

		if (SWAP_32(lvid->lvid_int_type) == LOG_VOL_CLOSE_INT) {
			udf_vfsp->udf_clean = UDF_CLEAN;
		} else {
			if (isroot) {
				udf_vfsp->udf_clean = UDF_DIRTY;
			} else {
				error = ENOSPC;
				goto out;
			}
		}
	}

	mutex_init(&udf_vfsp->udf_lock, NULL, MUTEX_DEFAULT, NULL);

	mutex_init(&udf_vfsp->udf_rename_lck, NULL, MUTEX_DEFAULT, NULL);

#ifndef	__lint
	_NOTE(COMPETING_THREADS_NOW);
#endif
	if (error = ud_iget(vfsp, udf_vfsp->udf_ricb_prn,
	    udf_vfsp->udf_ricb_loc, &rip, NULL, cr)) {
		mutex_destroy(&udf_vfsp->udf_lock);
		goto out;
	}


	/*
	 * Get the root inode and
	 * initialize the root vnode
	 */
	rvp = ITOV(rip);
	mutex_enter(&rvp->v_lock);
	rvp->v_flag |= VROOT;
	mutex_exit(&rvp->v_lock);
	udf_vfsp->udf_root = rvp;


	if (why == ROOT_INIT && isroot)
		rootvp = devvp;

	ud_vfs_add(udf_vfsp);

	if (udf_vfsp->udf_flags == UDF_FL_RW) {
		udf_vfsp->udf_clean = UDF_DIRTY;
		ud_update_superblock(vfsp);
	}

	return (0);

out:
	ud_destroy_fsp(udf_vfsp);
	if (needclose) {
		(void) VOP_CLOSE(devvp, (vfsp->vfs_flag & VFS_RDONLY) ?
		    FREAD : FREAD|FWRITE, 1, (offset_t)0, cr, NULL);
		bflush(dev);
		binval(dev);
	}
	VN_RELE(devvp);

	return (error);
}


static struct udf_vfs *
ud_validate_and_fill_superblock(dev_t dev, int32_t bsize, uint32_t avd_loc)
{
	int32_t error, count, index, shift;
	uint32_t dummy, vds_loc;
	caddr_t addr;
	daddr_t blkno, lblkno;
	struct buf *secbp, *bp;
	struct tag *ttag;
	struct anch_vol_desc_ptr *avdp;
	struct file_set_desc *fsd;
	struct udf_vfs *udf_vfsp = NULL;
	struct pmap_hdr *hdr;
	struct pmap_typ1 *typ1;
	struct pmap_typ2 *typ2;
	struct ud_map *map;
	int32_t	desc_len;

	ud_printf("ud_validate_and_fill_superblock\n");

	if (bsize < DEV_BSIZE) {
		return (NULL);
	}
	shift = 0;
	while ((bsize >> shift) > DEV_BSIZE) {
		shift++;
	}

	/*
	 * Read Anchor Volume Descriptor
	 * Verify it and get the location of
	 * Main Volume Descriptor Sequence
	 */
	secbp = ud_bread(dev, avd_loc << shift, ANCHOR_VOL_DESC_LEN);
	if ((error = geterror(secbp)) != 0) {
		cmn_err(CE_NOTE, "udfs : Could not read Anchor Volume Desc %x",
		    error);
		brelse(secbp);
		return (NULL);
	}
	avdp = (struct anch_vol_desc_ptr *)secbp->b_un.b_addr;
	if (ud_verify_tag_and_desc(&avdp->avd_tag, UD_ANCH_VOL_DESC,
	    avd_loc, 1, ANCHOR_VOL_DESC_LEN) != 0) {
		brelse(secbp);
		return (NULL);
	}
	udf_vfsp = (struct udf_vfs *)
	    kmem_zalloc(sizeof (struct udf_vfs), KM_SLEEP);
	udf_vfsp->udf_mvds_loc = SWAP_32(avdp->avd_main_vdse.ext_loc);
	udf_vfsp->udf_mvds_len = SWAP_32(avdp->avd_main_vdse.ext_len);
	udf_vfsp->udf_rvds_loc = SWAP_32(avdp->avd_res_vdse.ext_loc);
	udf_vfsp->udf_rvds_len = SWAP_32(avdp->avd_res_vdse.ext_len);
	secbp->b_flags = B_AGE | B_STALE;
	brelse(secbp);

	/*
	 * Read Main Volume Descriptor Sequence
	 * and process it
	 */
	vds_loc = udf_vfsp->udf_mvds_loc;
	secbp = ud_bread(dev, vds_loc << shift,
	    udf_vfsp->udf_mvds_len);
	if ((error = geterror(secbp)) != 0) {
		brelse(secbp);
		cmn_err(CE_NOTE, "udfs : Could not read Main Volume Desc %x",
		    error);

		vds_loc = udf_vfsp->udf_rvds_loc;
		secbp = ud_bread(dev, vds_loc << shift,
		    udf_vfsp->udf_rvds_len);
		if ((error = geterror(secbp)) != 0) {
			brelse(secbp);
			cmn_err(CE_NOTE,
			"udfs : Could not read Res Volume Desc %x", error);
			return (NULL);
		}
	}

	udf_vfsp->udf_vds = ngeteblk(udf_vfsp->udf_mvds_len);
	bp = udf_vfsp->udf_vds;
	bp->b_edev = dev;
	bp->b_dev = cmpdev(dev);
	bp->b_blkno = vds_loc << shift;
	bp->b_bcount = udf_vfsp->udf_mvds_len;
	bcopy(secbp->b_un.b_addr, bp->b_un.b_addr, udf_vfsp->udf_mvds_len);
	secbp->b_flags |= B_STALE | B_AGE;
	brelse(secbp);


	count = udf_vfsp->udf_mvds_len / DEV_BSIZE;
	addr = bp->b_un.b_addr;
	for (index = 0; index < count; index ++) {
		ttag = (struct tag *)(addr + index * DEV_BSIZE);
		desc_len = udf_vfsp->udf_mvds_len - (index * DEV_BSIZE);
		if (ud_verify_tag_and_desc(ttag, UD_PRI_VOL_DESC,
		    vds_loc + (index >> shift),
		    1, desc_len) == 0) {
			if (udf_vfsp->udf_pvd == NULL) {
				udf_vfsp->udf_pvd =
				    (struct pri_vol_desc *)ttag;
			} else {
				struct pri_vol_desc *opvd, *npvd;

				opvd = udf_vfsp->udf_pvd;
				npvd = (struct pri_vol_desc *)ttag;

				if ((strncmp(opvd->pvd_vsi,
				    npvd->pvd_vsi, 128) == 0) &&
				    (strncmp(opvd->pvd_vol_id,
				    npvd->pvd_vol_id, 32) == 0) &&
				    (strncmp((caddr_t)&opvd->pvd_desc_cs,
				    (caddr_t)&npvd->pvd_desc_cs,
				    sizeof (charspec_t)) == 0)) {

					if (SWAP_32(opvd->pvd_vdsn) <
					    SWAP_32(npvd->pvd_vdsn)) {
						udf_vfsp->udf_pvd = npvd;
					}
				} else {
					goto out;
				}
			}
		} else if (ud_verify_tag_and_desc(ttag, UD_LOG_VOL_DESC,
		    vds_loc + (index >> shift),
		    1, desc_len) == 0) {
			struct log_vol_desc *lvd;

			lvd = (struct log_vol_desc *)ttag;
			if (strncmp(lvd->lvd_dom_id.reg_id,
			    UDF_DOMAIN_NAME, 23) != 0) {
				printf("Domain ID in lvd is not valid\n");
				goto out;
			}

			if (udf_vfsp->udf_lvd == NULL) {
				udf_vfsp->udf_lvd = lvd;
			} else {
				struct log_vol_desc *olvd;

				olvd = udf_vfsp->udf_lvd;
				if ((strncmp((caddr_t)&olvd->lvd_desc_cs,
				    (caddr_t)&lvd->lvd_desc_cs,
				    sizeof (charspec_t)) == 0) &&
				    (strncmp(olvd->lvd_lvid,
				    lvd->lvd_lvid, 128) == 0)) {
					if (SWAP_32(olvd->lvd_vdsn) <
					    SWAP_32(lvd->lvd_vdsn)) {
						udf_vfsp->udf_lvd = lvd;
					}
				} else {
					goto out;
				}
			}
		} else if (ud_verify_tag_and_desc(ttag, UD_PART_DESC,
		    vds_loc + (index >> shift),
		    1, desc_len) == 0) {
			int32_t i;
			struct phdr_desc *hdr;
			struct part_desc *pdesc;
			struct ud_part *pnew, *pold, *part;

			pdesc = (struct part_desc *)ttag;
			pold = udf_vfsp->udf_parts;
			for (i = 0; i < udf_vfsp->udf_npart; i++) {
				if (pold->udp_number !=
				    SWAP_16(pdesc->pd_pnum)) {
					pold++;
					continue;
				}

				if (SWAP_32(pdesc->pd_vdsn) >
				    pold->udp_seqno) {
					pold->udp_seqno =
					    SWAP_32(pdesc->pd_vdsn);
					pold->udp_access =
					    SWAP_32(pdesc->pd_acc_type);
					pold->udp_start =
					    SWAP_32(pdesc->pd_part_start);
					pold->udp_length =
					    SWAP_32(pdesc->pd_part_length);
				}
				goto loop_end;
			}
			pold = udf_vfsp->udf_parts;
			udf_vfsp->udf_npart++;
			pnew = kmem_zalloc(udf_vfsp->udf_npart *
			    sizeof (struct ud_part), KM_SLEEP);
			udf_vfsp->udf_parts = pnew;
			if (pold) {
				bcopy(pold, pnew,
				    sizeof (struct ud_part) *
				    (udf_vfsp->udf_npart - 1));
				kmem_free(pold,
				    sizeof (struct ud_part) *
				    (udf_vfsp->udf_npart - 1));
			}
			part = pnew + (udf_vfsp->udf_npart - 1);
			part->udp_number = SWAP_16(pdesc->pd_pnum);
			part->udp_seqno = SWAP_32(pdesc->pd_vdsn);
			part->udp_access = SWAP_32(pdesc->pd_acc_type);
			part->udp_start = SWAP_32(pdesc->pd_part_start);
			part->udp_length = SWAP_32(pdesc->pd_part_length);
			part->udp_last_alloc = 0;

			/*
			 * Figure out space bitmaps
			 * or space tables
			 */
			hdr = (struct phdr_desc *)pdesc->pd_pc_use;
			if (hdr->phdr_ust.sad_ext_len) {
				part->udp_flags = UDP_SPACETBLS;
				part->udp_unall_loc =
				    SWAP_32(hdr->phdr_ust.sad_ext_loc);
				part->udp_unall_len =
				    SWAP_32(hdr->phdr_ust.sad_ext_len);
				part->udp_freed_loc =
				    SWAP_32(hdr->phdr_fst.sad_ext_loc);
				part->udp_freed_len =
				    SWAP_32(hdr->phdr_fst.sad_ext_len);
			} else {
				part->udp_flags = UDP_BITMAPS;
				part->udp_unall_loc =
				    SWAP_32(hdr->phdr_usb.sad_ext_loc);
				part->udp_unall_len =
				    SWAP_32(hdr->phdr_usb.sad_ext_len);
				part->udp_freed_loc =
				    SWAP_32(hdr->phdr_fsb.sad_ext_loc);
				part->udp_freed_len =
				    SWAP_32(hdr->phdr_fsb.sad_ext_len);
			}
		} else if (ud_verify_tag_and_desc(ttag, UD_TERM_DESC,
		    vds_loc + (index >> shift),
		    1, desc_len) == 0) {

			break;
		}
loop_end:
		;
	}
	if ((udf_vfsp->udf_pvd == NULL) ||
	    (udf_vfsp->udf_lvd == NULL) ||
	    (udf_vfsp->udf_parts == NULL)) {
		goto out;
	}

	/*
	 * Process Primary Volume Descriptor
	 */
	(void) strncpy(udf_vfsp->udf_volid, udf_vfsp->udf_pvd->pvd_vol_id, 32);
	udf_vfsp->udf_volid[31] = '\0';
	udf_vfsp->udf_tsno = SWAP_16(udf_vfsp->udf_pvd->pvd_tag.tag_sno);

	/*
	 * Process Logical Volume Descriptor
	 */
	udf_vfsp->udf_lbsize =
	    SWAP_32(udf_vfsp->udf_lvd->lvd_log_bsize);
	udf_vfsp->udf_lbmask = udf_vfsp->udf_lbsize - 1;
	udf_vfsp->udf_l2d_shift = shift;
	udf_vfsp->udf_l2b_shift = shift + DEV_BSHIFT;

	/*
	 * Check if the media is in
	 * proper domain.
	 */
	if (strcmp(udf_vfsp->udf_lvd->lvd_dom_id.reg_id,
	    UDF_DOMAIN_NAME) != 0) {
		goto out;
	}

	/*
	 * AVDS offset does not match with the lbsize
	 * in the lvd
	 */
	if (udf_vfsp->udf_lbsize != bsize) {
		goto out;
	}

	udf_vfsp->udf_iseq_loc =
	    SWAP_32(udf_vfsp->udf_lvd->lvd_int_seq_ext.ext_loc);
	udf_vfsp->udf_iseq_len =
	    SWAP_32(udf_vfsp->udf_lvd->lvd_int_seq_ext.ext_len);

	udf_vfsp->udf_fsd_prn =
	    SWAP_16(udf_vfsp->udf_lvd->lvd_lvcu.lad_ext_prn);
	udf_vfsp->udf_fsd_loc =
	    SWAP_32(udf_vfsp->udf_lvd->lvd_lvcu.lad_ext_loc);
	udf_vfsp->udf_fsd_len =
	    SWAP_32(udf_vfsp->udf_lvd->lvd_lvcu.lad_ext_len);


	/*
	 * process paritions
	 */
	udf_vfsp->udf_mtype = udf_vfsp->udf_parts[0].udp_access;
	for (index = 0; index < udf_vfsp->udf_npart; index ++) {
		if (udf_vfsp->udf_parts[index].udp_access <
		    udf_vfsp->udf_mtype) {
			udf_vfsp->udf_mtype =
			    udf_vfsp->udf_parts[index].udp_access;
		}
	}
	if ((udf_vfsp->udf_mtype < UDF_MT_RO) ||
	    (udf_vfsp->udf_mtype > UDF_MT_OW)) {
		udf_vfsp->udf_mtype = UDF_MT_RO;
	}

	udf_vfsp->udf_nmaps = 0;
	hdr = (struct pmap_hdr *)udf_vfsp->udf_lvd->lvd_pmaps;
	count = SWAP_32(udf_vfsp->udf_lvd->lvd_num_pmaps);
	for (index = 0; index < count; index++) {

		if ((hdr->maph_type == MAP_TYPE1) &&
		    (hdr->maph_length == MAP_TYPE1_LEN)) {
			typ1 = (struct pmap_typ1 *)hdr;

			map = udf_vfsp->udf_maps;
			udf_vfsp->udf_maps =
			    kmem_zalloc(sizeof (struct ud_map) *
			    (udf_vfsp->udf_nmaps + 1), KM_SLEEP);
			if (map != NULL) {
				bcopy(map, udf_vfsp->udf_maps,
				    sizeof (struct ud_map) *
				    udf_vfsp->udf_nmaps);
				kmem_free(map, sizeof (struct ud_map) *
				    udf_vfsp->udf_nmaps);
			}
			map = udf_vfsp->udf_maps + udf_vfsp->udf_nmaps;
			map->udm_flags = UDM_MAP_NORM;
			map->udm_vsn = SWAP_16(typ1->map1_vsn);
			map->udm_pn = SWAP_16(typ1->map1_pn);
			udf_vfsp->udf_nmaps ++;
		} else if ((hdr->maph_type == MAP_TYPE2) &&
		    (hdr->maph_length == MAP_TYPE2_LEN)) {
			typ2 = (struct pmap_typ2 *)hdr;

			if (strncmp(typ2->map2_pti.reg_id,
			    UDF_VIRT_PART, 23) == 0) {
				/*
				 * Add this to the normal
				 * partition table so that
				 * we donot
				 */
				map = udf_vfsp->udf_maps;
				udf_vfsp->udf_maps =
				    kmem_zalloc(sizeof (struct ud_map) *
				    (udf_vfsp->udf_nmaps + 1), KM_SLEEP);
				if (map != NULL) {
					bcopy(map, udf_vfsp->udf_maps,
					    sizeof (struct ud_map) *
					    udf_vfsp->udf_nmaps);
					kmem_free(map,
					    sizeof (struct ud_map) *
					    udf_vfsp->udf_nmaps);
				}
				map = udf_vfsp->udf_maps + udf_vfsp->udf_nmaps;
				map->udm_flags = UDM_MAP_VPM;
				map->udm_vsn = SWAP_16(typ2->map2_vsn);
				map->udm_pn = SWAP_16(typ2->map2_pn);
				udf_vfsp->udf_nmaps ++;
				if (error = ud_get_last_block(dev, &lblkno)) {
					goto out;
				}
				if (error = ud_val_get_vat(udf_vfsp, dev,
				    lblkno, map)) {
					goto out;
				}
			} else if (strncmp(typ2->map2_pti.reg_id,
			    UDF_SPAR_PART, 23) == 0) {

				if (SWAP_16(typ2->map2_pl) != 32) {
					printf(
					    "Packet Length is not valid %x\n",
					    SWAP_16(typ2->map2_pl));
					goto out;
				}
				if ((typ2->map2_nst < 1) ||
				    (typ2->map2_nst > 4)) {
					goto out;
				}
				map = udf_vfsp->udf_maps;
				udf_vfsp->udf_maps =
				    kmem_zalloc(sizeof (struct ud_map) *
				    (udf_vfsp->udf_nmaps + 1),
				    KM_SLEEP);
				if (map != NULL) {
					bcopy(map, udf_vfsp->udf_maps,
					    sizeof (struct ud_map) *
					    udf_vfsp->udf_nmaps);
					kmem_free(map,
					    sizeof (struct ud_map) *
					    udf_vfsp->udf_nmaps);
				}
				map = udf_vfsp->udf_maps + udf_vfsp->udf_nmaps;
				map->udm_flags = UDM_MAP_SPM;
				map->udm_vsn = SWAP_16(typ2->map2_vsn);
				map->udm_pn = SWAP_16(typ2->map2_pn);

				udf_vfsp->udf_nmaps ++;

				if (error = ud_read_sparing_tbls(udf_vfsp,
				    dev, map, typ2)) {
					goto out;
				}
			} else {
				/*
				 * Unknown type of partition
				 * Bail out
				 */
				goto out;
			}
		} else {
			/*
			 * Unknown type of partition
			 * Bail out
			 */
			goto out;
		}
		hdr = (struct pmap_hdr *)(((uint8_t *)hdr) + hdr->maph_length);
	}


	/*
	 * Read Logical Volume Integrity Sequence
	 * and process it
	 */
	secbp = ud_bread(dev, udf_vfsp->udf_iseq_loc << shift,
	    udf_vfsp->udf_iseq_len);
	if ((error = geterror(secbp)) != 0) {
		cmn_err(CE_NOTE,
		"udfs : Could not read Logical Volume Integrity Sequence %x",
		    error);
		brelse(secbp);
		goto out;
	}
	udf_vfsp->udf_iseq = ngeteblk(udf_vfsp->udf_iseq_len);
	bp = udf_vfsp->udf_iseq;
	bp->b_edev = dev;
	bp->b_dev = cmpdev(dev);
	bp->b_blkno = udf_vfsp->udf_iseq_loc << shift;
	bp->b_bcount = udf_vfsp->udf_iseq_len;
	bcopy(secbp->b_un.b_addr, bp->b_un.b_addr, udf_vfsp->udf_iseq_len);
	secbp->b_flags |= B_STALE | B_AGE;
	brelse(secbp);

	count = udf_vfsp->udf_iseq_len / DEV_BSIZE;
	addr = bp->b_un.b_addr;
	for (index = 0; index < count; index ++) {
		ttag = (struct tag *)(addr + index * DEV_BSIZE);
		desc_len = udf_vfsp->udf_iseq_len - (index * DEV_BSIZE);
		if (ud_verify_tag_and_desc(ttag, UD_LOG_VOL_INT,
		    udf_vfsp->udf_iseq_loc + (index >> shift),
		    1, desc_len) == 0) {

			struct log_vol_int_desc *lvid;

			lvid = (struct log_vol_int_desc *)ttag;
			udf_vfsp->udf_lvid = lvid;

			if (SWAP_32(lvid->lvid_int_type) == LOG_VOL_CLOSE_INT) {
				udf_vfsp->udf_clean = UDF_CLEAN;
			} else {
				udf_vfsp->udf_clean = UDF_DIRTY;
			}

			/*
			 * update superblock with the metadata
			 */
			ud_convert_to_superblock(udf_vfsp, lvid);
			break;
		}
	}

	if (udf_vfsp->udf_lvid == NULL) {
		goto out;
	}

	if ((blkno = ud_xlate_to_daddr(udf_vfsp,
	    udf_vfsp->udf_fsd_prn, udf_vfsp->udf_fsd_loc,
	    1, &dummy)) == 0) {
		goto out;
	}
	secbp = ud_bread(dev, blkno << shift, udf_vfsp->udf_fsd_len);
	if ((error = geterror(secbp)) != 0) {
		cmn_err(CE_NOTE,
		"udfs : Could not read File Set Descriptor %x", error);
		brelse(secbp);
		goto out;
	}
	fsd = (struct file_set_desc *)secbp->b_un.b_addr;
	if (ud_verify_tag_and_desc(&fsd->fsd_tag, UD_FILE_SET_DESC,
	    udf_vfsp->udf_fsd_loc,
	    1, udf_vfsp->udf_fsd_len) != 0) {
		secbp->b_flags = B_AGE | B_STALE;
		brelse(secbp);
		goto out;
	}
	udf_vfsp->udf_ricb_prn = SWAP_16(fsd->fsd_root_icb.lad_ext_prn);
	udf_vfsp->udf_ricb_loc = SWAP_32(fsd->fsd_root_icb.lad_ext_loc);
	udf_vfsp->udf_ricb_len = SWAP_32(fsd->fsd_root_icb.lad_ext_len);
	secbp->b_flags = B_AGE | B_STALE;
	brelse(secbp);
	udf_vfsp->udf_root_blkno = ud_xlate_to_daddr(udf_vfsp,
	    udf_vfsp->udf_ricb_prn, udf_vfsp->udf_ricb_loc,
	    1, &dummy);

	return (udf_vfsp);
out:
	ud_destroy_fsp(udf_vfsp);

	return (NULL);
}

/*
 * release/free resources from one ud_map; map data was zalloc'd in
 * ud_validate_and_fill_superblock() and fields may later point to
 * valid data
 */
static void
ud_free_map(struct ud_map *map)
{
	uint32_t n;

	if (map->udm_flags & UDM_MAP_VPM) {
		if (map->udm_count) {
			kmem_free(map->udm_count,
			    map->udm_nent * sizeof (*map->udm_count));
			map->udm_count = NULL;
		}
		if (map->udm_bp) {
			for (n = 0; n < map->udm_nent; n++) {
				if (map->udm_bp[n])
					brelse(map->udm_bp[n]);
			}
			kmem_free(map->udm_bp,
			    map->udm_nent * sizeof (*map->udm_bp));
			map->udm_bp = NULL;
		}
		if (map->udm_addr) {
			kmem_free(map->udm_addr,
			    map->udm_nent * sizeof (*map->udm_addr));
			map->udm_addr = NULL;
		}
	}
	if (map->udm_flags & UDM_MAP_SPM) {
		for (n = 0; n < MAX_SPM; n++) {
			if (map->udm_sbp[n]) {
				brelse(map->udm_sbp[n]);
				map->udm_sbp[n] = NULL;
				map->udm_spaddr[n] = NULL;
			}
		}
	}
}

void
ud_destroy_fsp(struct udf_vfs *udf_vfsp)
{
	int32_t i;

	ud_printf("ud_destroy_fsp\n");
	if (udf_vfsp == NULL)
		return;

	if (udf_vfsp->udf_maps) {
		for (i = 0; i < udf_vfsp->udf_nmaps; i++)
			ud_free_map(&udf_vfsp->udf_maps[i]);

		kmem_free(udf_vfsp->udf_maps,
		    udf_vfsp->udf_nmaps * sizeof (*udf_vfsp->udf_maps));
	}

	if (udf_vfsp->udf_parts) {
		kmem_free(udf_vfsp->udf_parts,
		    udf_vfsp->udf_npart * sizeof (*udf_vfsp->udf_parts));
	}
	if (udf_vfsp->udf_iseq) {
		udf_vfsp->udf_iseq->b_flags |= (B_STALE|B_AGE);
		brelse(udf_vfsp->udf_iseq);
	}
	if (udf_vfsp->udf_vds) {
		udf_vfsp->udf_vds->b_flags |= (B_STALE|B_AGE);
		brelse(udf_vfsp->udf_vds);
	}
	if (udf_vfsp->udf_vfs)
		ud_vfs_remove(udf_vfsp);
	if (udf_vfsp->udf_fsmnt) {
		kmem_free(udf_vfsp->udf_fsmnt,
		    strlen(udf_vfsp->udf_fsmnt) + 1);
	}
	kmem_free(udf_vfsp, sizeof (*udf_vfsp));
}

void
ud_convert_to_superblock(struct udf_vfs *udf_vfsp,
	struct log_vol_int_desc *lvid)
{
	int32_t i, c;
	uint32_t *temp;
	struct ud_part *ud_part;
	struct lvid_iu *iu;

	udf_vfsp->udf_maxuniq = SWAP_64(lvid->lvid_uniqid);
	temp = lvid->lvid_fst;
	c = SWAP_32(lvid->lvid_npart);
	ud_part = udf_vfsp->udf_parts;
	for (i = 0; i < c; i++) {
		if (i >= udf_vfsp->udf_npart) {
			continue;
		}
		ud_part->udp_nfree =  SWAP_32(temp[i]);
		ud_part->udp_nblocks =  SWAP_32(temp[c + i]);
		udf_vfsp->udf_freeblks += SWAP_32(temp[i]);
		udf_vfsp->udf_totalblks += SWAP_32(temp[c + i]);
		ud_part++;
	}

	iu = (struct lvid_iu *)(temp + c * 2);
	udf_vfsp->udf_nfiles = SWAP_32(iu->lvidiu_nfiles);
	udf_vfsp->udf_ndirs = SWAP_32(iu->lvidiu_ndirs);
	udf_vfsp->udf_miread = BCD2HEX_16(SWAP_16(iu->lvidiu_mread));
	udf_vfsp->udf_miwrite = BCD2HEX_16(SWAP_16(iu->lvidiu_mwrite));
	udf_vfsp->udf_mawrite = BCD2HEX_16(SWAP_16(iu->lvidiu_maxwr));
}

void
ud_update_superblock(struct vfs *vfsp)
{
	struct udf_vfs *udf_vfsp;

	ud_printf("ud_update_superblock\n");

	udf_vfsp = (struct udf_vfs *)vfsp->vfs_data;

	mutex_enter(&udf_vfsp->udf_lock);
	ud_sbwrite(udf_vfsp);
	mutex_exit(&udf_vfsp->udf_lock);
}


#include <sys/dkio.h>
#include <sys/cdio.h>
#include <sys/vtoc.h>

/*
 * This part of the code is known
 * to work with only sparc. It needs
 * to be evluated before using it with x86
 */
int32_t
ud_get_last_block(dev_t dev, daddr_t *blkno)
{
	struct vtoc vtoc;
	struct dk_cinfo dki_info;
	int32_t rval, error;

	if ((error = cdev_ioctl(dev, DKIOCGVTOC, (intptr_t)&vtoc,
	    FKIOCTL|FREAD|FNATIVE, CRED(), &rval)) != 0) {
		cmn_err(CE_NOTE, "Could not get the vtoc information");
		return (error);
	}

	if (vtoc.v_sanity != VTOC_SANE) {
		return (EINVAL);
	}
	if ((error = cdev_ioctl(dev, DKIOCINFO, (intptr_t)&dki_info,
	    FKIOCTL|FREAD|FNATIVE, CRED(), &rval)) != 0) {
		cmn_err(CE_NOTE, "Could not get the slice information");
		return (error);
	}

	if (dki_info.dki_partition > V_NUMPAR) {
		return (EINVAL);
	}


	*blkno = vtoc.v_part[dki_info.dki_partition].p_size;

	return (0);
}

/* Search sequentially N - 2, N, N - 152, N - 150 for vat icb */
/*
 * int32_t ud_sub_blks[] = {2, 0, 152, 150};
 */
int32_t ud_sub_blks[] = {152, 150, 2, 0};
int32_t ud_sub_count = 4;

/*
 * Validate the VAT ICB
 */
static int32_t
ud_val_get_vat(struct udf_vfs *udf_vfsp, dev_t dev,
	daddr_t blkno, struct ud_map *udm)
{
	struct buf *secbp;
	struct file_entry *fe;
	int32_t end_loc, i, j, ad_type;
	struct short_ad *sad;
	struct long_ad *lad;
	uint32_t count, blk;
	struct ud_part *ud_part;
	int err = 0;

	end_loc = (blkno >> udf_vfsp->udf_l2d_shift) - 1;

	for (i = 0; i < ud_sub_count; i++) {
		udm->udm_vat_icb = end_loc - ud_sub_blks[i];

		secbp = ud_bread(dev,
		    udm->udm_vat_icb << udf_vfsp->udf_l2d_shift,
		    udf_vfsp->udf_lbsize);
		ASSERT(secbp->b_un.b_addr);

		fe = (struct file_entry *)secbp->b_un.b_addr;
		if (ud_verify_tag_and_desc(&fe->fe_tag, UD_FILE_ENTRY, 0,
		    0, 0) == 0) {
			if (ud_verify_tag_and_desc(&fe->fe_tag, UD_FILE_ENTRY,
			    SWAP_32(fe->fe_tag.tag_loc),
			    1, udf_vfsp->udf_lbsize) == 0) {
				if (fe->fe_icb_tag.itag_ftype == 0) {
					break;
				}
			}
		}
		secbp->b_flags |= B_AGE | B_STALE;
		brelse(secbp);
	}
	if (i == ud_sub_count) {
		return (EINVAL);
	}

	ad_type = SWAP_16(fe->fe_icb_tag.itag_flags) & 0x3;
	if (ad_type == ICB_FLAG_ONE_AD) {
		udm->udm_nent = 1;
	} else if (ad_type == ICB_FLAG_SHORT_AD) {
		udm->udm_nent =
		    SWAP_32(fe->fe_len_adesc) / sizeof (struct short_ad);
	} else if (ad_type == ICB_FLAG_LONG_AD) {
		udm->udm_nent =
		    SWAP_32(fe->fe_len_adesc) / sizeof (struct long_ad);
	} else {
		err = EINVAL;
		goto end;
	}

	udm->udm_count = kmem_zalloc(udm->udm_nent * sizeof (*udm->udm_count),
	    KM_SLEEP);
	udm->udm_bp = kmem_zalloc(udm->udm_nent * sizeof (*udm->udm_bp),
	    KM_SLEEP);
	udm->udm_addr = kmem_zalloc(udm->udm_nent * sizeof (*udm->udm_addr),
	    KM_SLEEP);

	if (ad_type == ICB_FLAG_ONE_AD) {
			udm->udm_count[0] = (SWAP_64(fe->fe_info_len) - 36) /
			    sizeof (uint32_t);
			udm->udm_bp[0] = secbp;
			udm->udm_addr[0] = (uint32_t *)
			    &fe->fe_spec[SWAP_32(fe->fe_len_ear)];
			return (0);
	}
	for (i = 0; i < udm->udm_nent; i++) {
		if (ad_type == ICB_FLAG_SHORT_AD) {
			sad = (struct short_ad *)
			    (fe->fe_spec + SWAP_32(fe->fe_len_ear));
			sad += i;
			count = SWAP_32(sad->sad_ext_len);
			blk = SWAP_32(sad->sad_ext_loc);
		} else {
			lad = (struct long_ad *)
			    (fe->fe_spec + SWAP_32(fe->fe_len_ear));
			lad += i;
			count = SWAP_32(lad->lad_ext_len);
			blk = SWAP_32(lad->lad_ext_loc);
			ASSERT(SWAP_16(lad->lad_ext_prn) == udm->udm_pn);
		}
		if ((count & 0x3FFFFFFF) == 0) {
			break;
		}
		if (i < udm->udm_nent - 1) {
			udm->udm_count[i] = count / 4;
		} else {
			udm->udm_count[i] = (count - 36) / 4;
		}
		ud_part = udf_vfsp->udf_parts;
		for (j = 0; j < udf_vfsp->udf_npart; j++) {
			if (udm->udm_pn == ud_part->udp_number) {
				blk = ud_part->udp_start + blk;
				break;
			}
		}
		if (j == udf_vfsp->udf_npart) {
			err = EINVAL;
			break;
		}

		count = (count + DEV_BSIZE - 1) & ~(DEV_BSIZE - 1);
		udm->udm_bp[i] = ud_bread(dev,
		    blk << udf_vfsp->udf_l2d_shift, count);
		if ((udm->udm_bp[i]->b_error != 0) ||
		    (udm->udm_bp[i]->b_resid)) {
			err = EINVAL;
			break;
		}
		udm->udm_addr[i] = (uint32_t *)udm->udm_bp[i]->b_un.b_addr;
	}

end:
	if (err)
		ud_free_map(udm);
	secbp->b_flags |= B_AGE | B_STALE;
	brelse(secbp);
	return (err);
}

int32_t
ud_read_sparing_tbls(struct udf_vfs *udf_vfsp,
	dev_t dev, struct ud_map *map, struct pmap_typ2 *typ2)
{
	int32_t index, valid = 0;
	uint32_t sz;
	struct buf *bp;
	struct stbl *stbl;

	map->udm_plen = SWAP_16(typ2->map2_pl);
	map->udm_nspm = typ2->map2_nst;
	map->udm_spsz = SWAP_32(typ2->map2_sest);
	sz = (map->udm_spsz + udf_vfsp->udf_lbmask) & ~udf_vfsp->udf_lbmask;
	if (sz == 0) {
		return (0);
	}

	for (index = 0; index < map->udm_nspm; index++) {
		map->udm_loc[index] = SWAP_32(typ2->map2_st[index]);

		bp = ud_bread(dev,
		    map->udm_loc[index] << udf_vfsp->udf_l2d_shift, sz);
		if ((bp->b_error != 0) || (bp->b_resid)) {
			brelse(bp);
			continue;
		}
		stbl = (struct stbl *)bp->b_un.b_addr;
		if (strncmp(stbl->stbl_si.reg_id, UDF_SPAR_TBL, 23) != 0) {
			printf("Sparing Identifier does not match\n");
			bp->b_flags |= B_AGE | B_STALE;
			brelse(bp);
			continue;
		}
		map->udm_sbp[index] = bp;
		map->udm_spaddr[index] = bp->b_un.b_addr;
#ifdef	UNDEF
{
	struct stbl_entry *te;
	int32_t i, tbl_len;

	te = (struct stbl_entry *)&stbl->stbl_entry;
	tbl_len = SWAP_16(stbl->stbl_len);

	printf("%x %x\n", tbl_len, SWAP_32(stbl->stbl_seqno));
	printf("%x %x\n", bp->b_un.b_addr, te);

	for (i = 0; i < tbl_len; i++) {
		printf("%x %x\n", SWAP_32(te->sent_ol), SWAP_32(te->sent_ml));
		te ++;
	}
}
#endif
		valid ++;
	}

	if (valid) {
		return (0);
	}
	return (EINVAL);
}

uint32_t
ud_get_lbsize(dev_t dev, uint32_t *loc)
{
	int32_t bsize, shift, index, end_index;
	daddr_t last_block;
	uint32_t avd_loc;
	struct buf *bp;
	struct anch_vol_desc_ptr *avdp;
	uint32_t session_offset = 0;
	int32_t rval;

	if (ud_get_last_block(dev, &last_block) != 0) {
		end_index = 1;
	} else {
		end_index = 3;
	}

	if (cdev_ioctl(dev, CDROMREADOFFSET, (intptr_t)&session_offset,
	    FKIOCTL|FREAD|FNATIVE, CRED(), &rval) != 0) {
		session_offset = 0;
	}

	for (index = 0; index < end_index; index++) {

		for (bsize = DEV_BSIZE, shift = 0;
		    bsize <= MAXBSIZE; bsize <<= 1, shift++) {

			if (index == 0) {
				avd_loc = 256;
				if (bsize <= 2048) {
					avd_loc +=
					    session_offset * 2048 / bsize;
				} else {
					avd_loc +=
					    session_offset / (bsize / 2048);
				}
			} else if (index == 1) {
				avd_loc = last_block - (1 << shift);
			} else {
				avd_loc = last_block - (256 << shift);
			}

			bp = ud_bread(dev, avd_loc << shift,
			    ANCHOR_VOL_DESC_LEN);
			if (geterror(bp) != 0) {
				brelse(bp);
				continue;
			}

			/*
			 * Verify if we have avdp here
			 */
			avdp = (struct anch_vol_desc_ptr *)bp->b_un.b_addr;
			if (ud_verify_tag_and_desc(&avdp->avd_tag,
			    UD_ANCH_VOL_DESC, avd_loc,
			    1, ANCHOR_VOL_DESC_LEN) != 0) {
				bp->b_flags |= B_AGE | B_STALE;
				brelse(bp);
				continue;
			}
			bp->b_flags |= B_AGE | B_STALE;
			brelse(bp);
			*loc = avd_loc;
			return (bsize);
		}
	}

	/*
	 * Did not find AVD at all the locations
	 */
	return (0);
}

static int
udfinit(int fstype, char *name)
{
	static const fs_operation_def_t udf_vfsops_template[] = {
		VFSNAME_MOUNT,		{ .vfs_mount = udf_mount },
		VFSNAME_UNMOUNT,	{ .vfs_unmount = udf_unmount },
		VFSNAME_ROOT,		{ .vfs_root = udf_root },
		VFSNAME_STATVFS,	{ .vfs_statvfs = udf_statvfs },
		VFSNAME_SYNC,		{ .vfs_sync = udf_sync },
		VFSNAME_VGET,		{ .vfs_vget = udf_vget },
		VFSNAME_MOUNTROOT,	{ .vfs_mountroot = udf_mountroot },
		NULL,			NULL
	};
	extern struct vnodeops *udf_vnodeops;
	extern const fs_operation_def_t udf_vnodeops_template[];
	int error;

	ud_printf("udfinit\n");

	error = vfs_setfsops(fstype, udf_vfsops_template, NULL);
	if (error != 0) {
		cmn_err(CE_WARN, "udfinit: bad vfs ops template");
		return (error);
	}

	error = vn_make_ops(name, udf_vnodeops_template, &udf_vnodeops);
	if (error != 0) {
		(void) vfs_freevfsops_by_type(fstype);
		cmn_err(CE_WARN, "udfinit: bad vnode ops template");
		return (error);
	}

	udf_fstype = fstype;

	ud_init_inodes();

	return (0);
}
