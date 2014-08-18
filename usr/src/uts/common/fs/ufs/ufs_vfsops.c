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
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bitmap.h>
#include <sys/sysmacros.h>
#include <sys/kmem.h>
#include <sys/signal.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <sys/disp.h>
#include <sys/buf.h>
#include <sys/pathname.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/atomic.h>
#include <sys/uio.h>
#include <sys/dkio.h>
#include <sys/cred.h>
#include <sys/conf.h>
#include <sys/dnlc.h>
#include <sys/kstat.h>
#include <sys/acl.h>
#include <sys/fs/ufs_fsdir.h>
#include <sys/fs/ufs_fs.h>
#include <sys/fs/ufs_inode.h>
#include <sys/fs/ufs_mount.h>
#include <sys/fs/ufs_acl.h>
#include <sys/fs/ufs_panic.h>
#include <sys/fs/ufs_bio.h>
#include <sys/fs/ufs_quota.h>
#include <sys/fs/ufs_log.h>
#undef NFS
#include <sys/statvfs.h>
#include <sys/mount.h>
#include <sys/mntent.h>
#include <sys/swap.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include "fs/fs_subr.h"
#include <sys/cmn_err.h>
#include <sys/dnlc.h>
#include <sys/fssnap_if.h>
#include <sys/sunddi.h>
#include <sys/bootconf.h>
#include <sys/policy.h>
#include <sys/zone.h>

/*
 * This is the loadable module wrapper.
 */
#include <sys/modctl.h>

int			ufsfstype;
vfsops_t		*ufs_vfsops;
static int		ufsinit(int, char *);
static int		mountfs();
extern int		highbit();
extern struct instats	ins;
extern struct vnode *common_specvp(struct vnode *vp);
extern vfs_t		EIO_vfs;

struct  dquot *dquot, *dquotNDQUOT;

/*
 * Cylinder group summary information handling tunable.
 * This defines when these deltas get logged.
 * If the number of cylinders in the file system is over the
 * tunable then we log csum updates. Otherwise the updates are only
 * done for performance on unmount. After a panic they can be
 * quickly constructed during mounting. See ufs_construct_si()
 * called from ufs_getsummaryinfo().
 *
 * This performance feature can of course be disabled by setting
 * ufs_ncg_log to 0, and fully enabled by setting it to 0xffffffff.
 */
#define	UFS_LOG_NCG_DEFAULT 10000
uint32_t ufs_ncg_log = UFS_LOG_NCG_DEFAULT;

/*
 * ufs_clean_root indicates whether the root fs went down cleanly
 */
static int ufs_clean_root = 0;

/*
 * UFS Mount options table
 */
static char *intr_cancel[] = { MNTOPT_NOINTR, NULL };
static char *nointr_cancel[] = { MNTOPT_INTR, NULL };
static char *forcedirectio_cancel[] = { MNTOPT_NOFORCEDIRECTIO, NULL };
static char *noforcedirectio_cancel[] = { MNTOPT_FORCEDIRECTIO, NULL };
static char *largefiles_cancel[] = { MNTOPT_NOLARGEFILES, NULL };
static char *nolargefiles_cancel[] = { MNTOPT_LARGEFILES, NULL };
static char *logging_cancel[] = { MNTOPT_NOLOGGING, NULL };
static char *nologging_cancel[] = { MNTOPT_LOGGING, NULL };
static char *xattr_cancel[] = { MNTOPT_NOXATTR, NULL };
static char *noxattr_cancel[] = { MNTOPT_XATTR, NULL };
static char *quota_cancel[] = { MNTOPT_NOQUOTA, NULL };
static char *noquota_cancel[] = { MNTOPT_QUOTA, NULL };
static char *dfratime_cancel[] = { MNTOPT_NODFRATIME, NULL };
static char *nodfratime_cancel[] = { MNTOPT_DFRATIME, NULL };

static mntopt_t mntopts[] = {
/*
 *	option name		cancel option	default arg	flags
 *		ufs arg flag
 */
	{ MNTOPT_INTR,		intr_cancel,	NULL,		MO_DEFAULT,
		(void *)0 },
	{ MNTOPT_NOINTR,	nointr_cancel,	NULL,		0,
		(void *)UFSMNT_NOINTR },
	{ MNTOPT_SYNCDIR,	NULL,		NULL,		0,
		(void *)UFSMNT_SYNCDIR },
	{ MNTOPT_FORCEDIRECTIO,	forcedirectio_cancel, NULL,	0,
		(void *)UFSMNT_FORCEDIRECTIO },
	{ MNTOPT_NOFORCEDIRECTIO, noforcedirectio_cancel, NULL, 0,
		(void *)UFSMNT_NOFORCEDIRECTIO },
	{ MNTOPT_NOSETSEC,	NULL,		NULL,		0,
		(void *)UFSMNT_NOSETSEC },
	{ MNTOPT_LARGEFILES,	largefiles_cancel, NULL,	MO_DEFAULT,
		(void *)UFSMNT_LARGEFILES },
	{ MNTOPT_NOLARGEFILES,	nolargefiles_cancel, NULL,	0,
		(void *)0 },
	{ MNTOPT_LOGGING,	logging_cancel, NULL,		MO_TAG,
		(void *)UFSMNT_LOGGING },
	{ MNTOPT_NOLOGGING,	nologging_cancel, NULL,
		MO_NODISPLAY|MO_DEFAULT|MO_TAG, (void *)0 },
	{ MNTOPT_QUOTA,		quota_cancel, NULL,		MO_IGNORE,
		(void *)0 },
	{ MNTOPT_NOQUOTA,	noquota_cancel,	NULL,
		MO_NODISPLAY|MO_DEFAULT, (void *)0 },
	{ MNTOPT_GLOBAL,	NULL,		NULL,		0,
		(void *)0 },
	{ MNTOPT_XATTR,	xattr_cancel,		NULL,		MO_DEFAULT,
		(void *)0 },
	{ MNTOPT_NOXATTR,	noxattr_cancel,		NULL,		0,
		(void *)0 },
	{ MNTOPT_NOATIME,	NULL,		NULL,		0,
		(void *)UFSMNT_NOATIME },
	{ MNTOPT_DFRATIME,	dfratime_cancel, NULL,		0,
		(void *)0 },
	{ MNTOPT_NODFRATIME,	nodfratime_cancel, NULL,
		MO_NODISPLAY|MO_DEFAULT, (void *)UFSMNT_NODFRATIME },
	{ MNTOPT_ONERROR,	NULL,		UFSMNT_ONERROR_PANIC_STR,
		MO_DEFAULT|MO_HASVALUE,	(void *)0 },
};

static mntopts_t ufs_mntopts = {
	sizeof (mntopts) / sizeof (mntopt_t),
	mntopts
};

static vfsdef_t vfw = {
	VFSDEF_VERSION,
	"ufs",
	ufsinit,
	VSW_HASPROTO|VSW_CANREMOUNT|VSW_STATS|VSW_CANLOFI,
	&ufs_mntopts
};

/*
 * Module linkage information for the kernel.
 */
extern struct mod_ops mod_fsops;

static struct modlfs modlfs = {
	&mod_fsops, "filesystem for ufs", &vfw
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlfs, NULL
};

/*
 * An attempt has been made to make this module unloadable.  In order to
 * test it, we need a system in which the root fs is NOT ufs.  THIS HAS NOT
 * BEEN DONE
 */

extern kstat_t *ufs_inode_kstat;
extern uint_t ufs_lockfs_key;
extern void ufs_lockfs_tsd_destructor(void *);
extern uint_t bypass_snapshot_throttle_key;

int
_init(void)
{
	/*
	 * Create an index into the per thread array so that any thread doing
	 * VOP will have a lockfs mark on it.
	 */
	tsd_create(&ufs_lockfs_key, ufs_lockfs_tsd_destructor);
	tsd_create(&bypass_snapshot_throttle_key, NULL);
	return (mod_install(&modlinkage));
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

extern struct vnode *makespecvp(dev_t dev, vtype_t type);

extern kmutex_t	ufs_scan_lock;

static int mountfs(struct vfs *, enum whymountroot, struct vnode *, char *,
		struct cred *, int, void *, int);


static int
ufs_mount(struct vfs *vfsp, struct vnode *mvp, struct mounta *uap,
	struct cred *cr)

{
	char *data = uap->dataptr;
	int datalen = uap->datalen;
	dev_t dev;
	struct vnode *lvp = NULL;
	struct vnode *svp = NULL;
	struct pathname dpn;
	int error;
	enum whymountroot why = ROOT_INIT;
	struct ufs_args args;
	int oflag, aflag;
	int fromspace = (uap->flags & MS_SYSSPACE) ?
	    UIO_SYSSPACE : UIO_USERSPACE;

	if ((error = secpolicy_fs_mount(cr, mvp, vfsp)) != 0)
		return (error);

	if (mvp->v_type != VDIR)
		return (ENOTDIR);

	mutex_enter(&mvp->v_lock);
	if ((uap->flags & MS_REMOUNT) == 0 &&
	    (uap->flags & MS_OVERLAY) == 0 &&
	    (mvp->v_count != 1 || (mvp->v_flag & VROOT))) {
		mutex_exit(&mvp->v_lock);
		return (EBUSY);
	}
	mutex_exit(&mvp->v_lock);

	/*
	 * Get arguments
	 */
	bzero(&args, sizeof (args));
	if ((uap->flags & MS_DATA) && data != NULL && datalen != 0) {
		int copy_result = 0;

		if (datalen > sizeof (args))
			return (EINVAL);
		if (uap->flags & MS_SYSSPACE)
			bcopy(data, &args, datalen);
		else
			copy_result = copyin(data, &args, datalen);
		if (copy_result)
			return (EFAULT);
		datalen = sizeof (struct ufs_args);
	} else {
		datalen = 0;
	}

	if ((vfsp->vfs_flag & VFS_RDONLY) != 0 ||
	    (uap->flags & MS_RDONLY) != 0) {
		oflag = FREAD;
		aflag = VREAD;
	} else {
		oflag = FREAD | FWRITE;
		aflag = VREAD | VWRITE;
	}

	/*
	 * Read in the mount point pathname
	 * (so we can record the directory the file system was last mounted on).
	 */
	if (error = pn_get(uap->dir, fromspace, &dpn))
		return (error);

	/*
	 * Resolve path name of special file being mounted.
	 */
	if (error = lookupname(uap->spec, fromspace, FOLLOW, NULL, &svp)) {
		pn_free(&dpn);
		return (error);
	}

	error = vfs_get_lofi(vfsp, &lvp);

	if (error > 0) {
		VN_RELE(svp);
		pn_free(&dpn);
		return (error);
	} else if (error == 0) {
		dev = lvp->v_rdev;

		if (getmajor(dev) >= devcnt) {
			error = ENXIO;
			goto out;
		}
	} else {
		dev = svp->v_rdev;

		if (svp->v_type != VBLK) {
			VN_RELE(svp);
			pn_free(&dpn);
			return (ENOTBLK);
		}

		if (getmajor(dev) >= devcnt) {
			error = ENXIO;
			goto out;
		}

		/*
		 * In SunCluster, requests to a global device are
		 * satisfied by a local device. We substitute the global
		 * pxfs node with a local spec node here.
		 */
		if (IS_PXFSVP(svp)) {
			ASSERT(lvp == NULL);
			VN_RELE(svp);
			svp = makespecvp(dev, VBLK);
		}

		if ((error = secpolicy_spec_open(cr, svp, oflag)) != 0) {
			VN_RELE(svp);
			pn_free(&dpn);
			return (error);
		}
	}

	if (uap->flags & MS_REMOUNT)
		why = ROOT_REMOUNT;

	/*
	 * Open device/file mounted on.  We need this to check whether
	 * the caller has sufficient rights to access the resource in
	 * question.  When bio is fixed for vnodes this can all be vnode
	 * operations.
	 */
	if ((error = VOP_ACCESS(svp, aflag, 0, cr, NULL)) != 0)
		goto out;

	/*
	 * Ensure that this device isn't already mounted or in progress on a
	 * mount unless this is a REMOUNT request or we are told to suppress
	 * mount checks. Global mounts require special handling.
	 */
	if ((uap->flags & MS_NOCHECK) == 0) {
		if ((uap->flags & MS_GLOBAL) == 0 &&
		    vfs_devmounting(dev, vfsp)) {
			error = EBUSY;
			goto out;
		}
		if (vfs_devismounted(dev)) {
			if ((uap->flags & MS_REMOUNT) == 0) {
				error = EBUSY;
				goto out;
			}
		}
	}

	/*
	 * If the device is a tape, mount it read only
	 */
	if (devopsp[getmajor(dev)]->devo_cb_ops->cb_flag & D_TAPE) {
		vfsp->vfs_flag |= VFS_RDONLY;
		vfs_setmntopt(vfsp, MNTOPT_RO, NULL, 0);
	}
	if (uap->flags & MS_RDONLY)
		vfsp->vfs_flag |= VFS_RDONLY;

	/*
	 * Mount the filesystem, free the device vnode on error.
	 */
	error = mountfs(vfsp, why, lvp != NULL ? lvp : svp,
	    dpn.pn_path, cr, 0, &args, datalen);

	if (error == 0) {
		vfs_set_feature(vfsp, VFSFT_SYSATTR_VIEWS);

		/*
		 * If lofi, drop our reference to the original file.
		 */
		if (lvp != NULL)
			VN_RELE(svp);
	}

out:
	pn_free(&dpn);

	if (error) {
		if (lvp != NULL)
			VN_RELE(lvp);
		if (svp != NULL)
			VN_RELE(svp);
	}
	return (error);
}

/*
 * Mount root file system.
 * "why" is ROOT_INIT on initial call ROOT_REMOUNT if called to
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
static int
ufs_mountroot(struct vfs *vfsp, enum whymountroot why)
{
	struct fs *fsp;
	int error;
	static int ufsrootdone = 0;
	dev_t rootdev;
	struct vnode *vp;
	struct vnode *devvp = 0;
	int ovflags;
	int doclkset;
	ufsvfs_t *ufsvfsp;

	if (why == ROOT_INIT) {
		if (ufsrootdone++)
			return (EBUSY);
		rootdev = getrootdev();
		if (rootdev == (dev_t)NODEV)
			return (ENODEV);
		vfsp->vfs_dev = rootdev;
		vfsp->vfs_flag |= VFS_RDONLY;
	} else if (why == ROOT_REMOUNT) {
		vp = ((struct ufsvfs *)vfsp->vfs_data)->vfs_devvp;
		(void) dnlc_purge_vfsp(vfsp, 0);
		vp = common_specvp(vp);
		(void) VOP_PUTPAGE(vp, (offset_t)0, (size_t)0, B_INVAL,
		    CRED(), NULL);
		(void) bfinval(vfsp->vfs_dev, 0);
		fsp = getfs(vfsp);

		ovflags = vfsp->vfs_flag;
		vfsp->vfs_flag &= ~VFS_RDONLY;
		vfsp->vfs_flag |= VFS_REMOUNT;
		rootdev = vfsp->vfs_dev;
	} else if (why == ROOT_UNMOUNT) {
		if (vfs_lock(vfsp) == 0) {
			(void) ufs_flush(vfsp);
			/*
			 * Mark the log as fully rolled
			 */
			ufsvfsp = (ufsvfs_t *)vfsp->vfs_data;
			fsp = ufsvfsp->vfs_fs;
			if (TRANS_ISTRANS(ufsvfsp) &&
			    !TRANS_ISERROR(ufsvfsp) &&
			    (fsp->fs_rolled == FS_NEED_ROLL)) {
				ml_unit_t *ul = ufsvfsp->vfs_log;

				error = ufs_putsummaryinfo(ul->un_dev,
				    ufsvfsp, fsp);
				if (error == 0) {
					fsp->fs_rolled = FS_ALL_ROLLED;
					UFS_BWRITE2(NULL, ufsvfsp->vfs_bufp);
				}
			}
			vfs_unlock(vfsp);
		} else {
			ufs_update(0);
		}

		vp = ((struct ufsvfs *)vfsp->vfs_data)->vfs_devvp;
		(void) VOP_CLOSE(vp, FREAD|FWRITE, 1,
		    (offset_t)0, CRED(), NULL);
		return (0);
	}
	error = vfs_lock(vfsp);
	if (error)
		return (error);

	devvp = makespecvp(rootdev, VBLK);

	/* If RO media, don't call clkset() (see below) */
	doclkset = 1;
	if (why == ROOT_INIT) {
		error = VOP_OPEN(&devvp, FREAD|FWRITE, CRED(), NULL);
		if (error == 0) {
			(void) VOP_CLOSE(devvp, FREAD|FWRITE, 1,
			    (offset_t)0, CRED(), NULL);
		} else {
			doclkset = 0;
		}
	}

	error = mountfs(vfsp, why, devvp, "/", CRED(), 1, NULL, 0);
	/*
	 * XXX - assumes root device is not indirect, because we don't set
	 * rootvp.  Is rootvp used for anything?  If so, make another arg
	 * to mountfs.
	 */
	if (error) {
		vfs_unlock(vfsp);
		if (why == ROOT_REMOUNT)
			vfsp->vfs_flag = ovflags;
		if (rootvp) {
			VN_RELE(rootvp);
			rootvp = (struct vnode *)0;
		}
		VN_RELE(devvp);
		return (error);
	}
	if (why == ROOT_INIT)
		vfs_add((struct vnode *)0, vfsp,
		    (vfsp->vfs_flag & VFS_RDONLY) ? MS_RDONLY : 0);
	vfs_unlock(vfsp);
	fsp = getfs(vfsp);
	clkset(doclkset ? fsp->fs_time : -1);
	ufsvfsp = (ufsvfs_t *)vfsp->vfs_data;
	if (ufsvfsp->vfs_log) {
		vfs_setmntopt(vfsp, MNTOPT_LOGGING, NULL, 0);
	}
	return (0);
}

static int
remountfs(struct vfs *vfsp, dev_t dev, void *raw_argsp, int args_len)
{
	struct ufsvfs *ufsvfsp = (struct ufsvfs *)vfsp->vfs_data;
	struct ulockfs *ulp = &ufsvfsp->vfs_ulockfs;
	struct buf *bp = ufsvfsp->vfs_bufp;
	struct fs *fsp = (struct fs *)bp->b_un.b_addr;
	struct fs *fspt;
	struct buf *tpt = 0;
	int error = 0;
	int flags = 0;

	if (args_len == sizeof (struct ufs_args) && raw_argsp)
		flags = ((struct ufs_args *)raw_argsp)->flags;

	/* cannot remount to RDONLY */
	if (vfsp->vfs_flag & VFS_RDONLY)
		return (ENOTSUP);

	/* whoops, wrong dev */
	if (vfsp->vfs_dev != dev)
		return (EINVAL);

	/*
	 * synchronize w/ufs ioctls
	 */
	mutex_enter(&ulp->ul_lock);
	atomic_inc_ulong(&ufs_quiesce_pend);

	/*
	 * reset options
	 */
	ufsvfsp->vfs_nointr  = flags & UFSMNT_NOINTR;
	ufsvfsp->vfs_syncdir = flags & UFSMNT_SYNCDIR;
	ufsvfsp->vfs_nosetsec = flags & UFSMNT_NOSETSEC;
	ufsvfsp->vfs_noatime = flags & UFSMNT_NOATIME;
	if ((flags & UFSMNT_NODFRATIME) || ufsvfsp->vfs_noatime)
		ufsvfsp->vfs_dfritime &= ~UFS_DFRATIME;
	else	/* dfratime, default behavior */
		ufsvfsp->vfs_dfritime |= UFS_DFRATIME;
	if (flags & UFSMNT_FORCEDIRECTIO)
		ufsvfsp->vfs_forcedirectio = 1;
	else	/* default is no direct I/O */
		ufsvfsp->vfs_forcedirectio = 0;
	ufsvfsp->vfs_iotstamp = ddi_get_lbolt();

	/*
	 * set largefiles flag in ufsvfs equal to the
	 * value passed in by the mount command. If
	 * it is "nolargefiles", and the flag is set
	 * in the superblock, the mount fails.
	 */
	if (!(flags & UFSMNT_LARGEFILES)) {  /* "nolargefiles" */
		if (fsp->fs_flags & FSLARGEFILES) {
			error = EFBIG;
			goto remounterr;
		}
		ufsvfsp->vfs_lfflags &= ~UFS_LARGEFILES;
	} else	/* "largefiles" */
		ufsvfsp->vfs_lfflags |= UFS_LARGEFILES;
	/*
	 * read/write to read/write; all done
	 */
	if (fsp->fs_ronly == 0)
		goto remounterr;

	/*
	 * fix-on-panic assumes RO->RW remount implies system-critical fs
	 * if it is shortly after boot; so, don't attempt to lock and fix
	 * (unless the user explicitly asked for another action on error)
	 * XXX UFSMNT_ONERROR_RDONLY rather than UFSMNT_ONERROR_PANIC
	 */
#define	BOOT_TIME_LIMIT	(180*hz)
	if (!(flags & UFSMNT_ONERROR_FLGMASK) &&
	    ddi_get_lbolt() < BOOT_TIME_LIMIT) {
		cmn_err(CE_WARN, "%s is required to be mounted onerror=%s",
		    ufsvfsp->vfs_fs->fs_fsmnt, UFSMNT_ONERROR_PANIC_STR);
		flags |= UFSMNT_ONERROR_PANIC;
	}

	if ((error = ufsfx_mount(ufsvfsp, flags)) != 0)
		goto remounterr;

	/*
	 * quiesce the file system
	 */
	error = ufs_quiesce(ulp);
	if (error)
		goto remounterr;

	tpt = UFS_BREAD(ufsvfsp, ufsvfsp->vfs_dev, SBLOCK, SBSIZE);
	if (tpt->b_flags & B_ERROR) {
		error = EIO;
		goto remounterr;
	}
	fspt = (struct fs *)tpt->b_un.b_addr;
	if (((fspt->fs_magic != FS_MAGIC) &&
	    (fspt->fs_magic != MTB_UFS_MAGIC)) ||
	    (fspt->fs_magic == FS_MAGIC &&
	    (fspt->fs_version != UFS_EFISTYLE4NONEFI_VERSION_2 &&
	    fspt->fs_version != UFS_VERSION_MIN)) ||
	    (fspt->fs_magic == MTB_UFS_MAGIC &&
	    (fspt->fs_version > MTB_UFS_VERSION_1 ||
	    fspt->fs_version < MTB_UFS_VERSION_MIN)) ||
	    fspt->fs_bsize > MAXBSIZE || fspt->fs_frag > MAXFRAG ||
	    fspt->fs_bsize < sizeof (struct fs) || fspt->fs_bsize < PAGESIZE) {
		tpt->b_flags |= B_STALE | B_AGE;
		error = EINVAL;
		goto remounterr;
	}

	if (ufsvfsp->vfs_log && (ufsvfsp->vfs_log->un_flags & LDL_NOROLL)) {
		ufsvfsp->vfs_log->un_flags &= ~LDL_NOROLL;
		logmap_start_roll(ufsvfsp->vfs_log);
	}

	if (TRANS_ISERROR(ufsvfsp))
		goto remounterr;
	TRANS_DOMATAMAP(ufsvfsp);

	if ((fspt->fs_state + fspt->fs_time == FSOKAY) &&
	    fspt->fs_clean == FSLOG && !TRANS_ISTRANS(ufsvfsp)) {
		ufsvfsp->vfs_log = NULL;
		ufsvfsp->vfs_domatamap = 0;
		error = ENOSPC;
		goto remounterr;
	}

	if (fspt->fs_state + fspt->fs_time == FSOKAY &&
	    (fspt->fs_clean == FSCLEAN ||
	    fspt->fs_clean == FSSTABLE ||
	    fspt->fs_clean == FSLOG)) {

		/*
		 * Ensure that ufs_getsummaryinfo doesn't reconstruct
		 * the summary info.
		 */
		error = ufs_getsummaryinfo(vfsp->vfs_dev, ufsvfsp, fspt);
		if (error)
			goto remounterr;

		/* preserve mount name */
		(void) strncpy(fspt->fs_fsmnt, fsp->fs_fsmnt, MAXMNTLEN);
		/* free the old cg space */
		kmem_free(fsp->fs_u.fs_csp, fsp->fs_cssize);
		/* switch in the new superblock */
		fspt->fs_rolled = FS_NEED_ROLL;
		bcopy(tpt->b_un.b_addr, bp->b_un.b_addr, fspt->fs_sbsize);

		fsp->fs_clean = FSSTABLE;
	} /* superblock updated in memory */
	tpt->b_flags |= B_STALE | B_AGE;
	brelse(tpt);
	tpt = 0;

	if (fsp->fs_clean != FSSTABLE) {
		error = ENOSPC;
		goto remounterr;
	}


	if (TRANS_ISTRANS(ufsvfsp)) {
		fsp->fs_clean = FSLOG;
		ufsvfsp->vfs_dio = 0;
	} else
		if (ufsvfsp->vfs_dio)
			fsp->fs_clean = FSSUSPEND;

	TRANS_MATA_MOUNT(ufsvfsp);

	fsp->fs_fmod = 0;
	fsp->fs_ronly = 0;

	atomic_dec_ulong(&ufs_quiesce_pend);
	cv_broadcast(&ulp->ul_cv);
	mutex_exit(&ulp->ul_lock);

	if (TRANS_ISTRANS(ufsvfsp)) {

		/*
		 * start the delete thread
		 */
		ufs_thread_start(&ufsvfsp->vfs_delete, ufs_thread_delete, vfsp);

		/*
		 * start the reclaim thread
		 */
		if (fsp->fs_reclaim & (FS_RECLAIM|FS_RECLAIMING)) {
			fsp->fs_reclaim &= ~FS_RECLAIM;
			fsp->fs_reclaim |=  FS_RECLAIMING;
			ufs_thread_start(&ufsvfsp->vfs_reclaim,
			    ufs_thread_reclaim, vfsp);
		}
	}

	TRANS_SBWRITE(ufsvfsp, TOP_MOUNT);

	return (0);

remounterr:
	if (tpt)
		brelse(tpt);
	atomic_dec_ulong(&ufs_quiesce_pend);
	cv_broadcast(&ulp->ul_cv);
	mutex_exit(&ulp->ul_lock);
	return (error);
}

/*
 * If the device maxtransfer size is not available, we use ufs_maxmaxphys
 * along with the system value for maxphys to determine the value for
 * maxtransfer.
 */
int ufs_maxmaxphys = (1024 * 1024);

#include <sys/ddi.h>		/* for delay(9f) */

int ufs_mount_error_delay = 20;	/* default to 20ms */
int ufs_mount_timeout = 60000;	/* default to 1 minute */

static int
mountfs(struct vfs *vfsp, enum whymountroot why, struct vnode *devvp,
	char *path, cred_t *cr, int isroot, void *raw_argsp, int args_len)
{
	dev_t dev = devvp->v_rdev;
	struct fs *fsp;
	struct ufsvfs *ufsvfsp = 0;
	struct buf *bp = 0;
	struct buf *tp = 0;
	struct dk_cinfo ci;
	int error = 0;
	size_t len;
	int needclose = 0;
	int needtrans = 0;
	struct inode *rip;
	struct vnode *rvp = NULL;
	int flags = 0;
	kmutex_t *ihm;
	int elapsed;
	int status;
	extern	int	maxphys;

	if (args_len == sizeof (struct ufs_args) && raw_argsp)
		flags = ((struct ufs_args *)raw_argsp)->flags;

	ASSERT(vfs_lock_held(vfsp));

	if (why == ROOT_INIT) {
		/*
		 * Open block device mounted on.
		 * When bio is fixed for vnodes this can all be vnode
		 * operations.
		 */
		error = VOP_OPEN(&devvp,
		    (vfsp->vfs_flag & VFS_RDONLY) ? FREAD : FREAD|FWRITE,
		    cr, NULL);
		if (error)
			goto out;
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
		error = remountfs(vfsp, dev, raw_argsp, args_len);
		if (error == 0)
			VN_RELE(devvp);
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
	    (size_t)0, B_INVAL, cr, NULL);

	/*
	 * read in superblock
	 */
	ufsvfsp = kmem_zalloc(sizeof (struct ufsvfs), KM_SLEEP);
	tp = UFS_BREAD(ufsvfsp, dev, SBLOCK, SBSIZE);
	if (tp->b_flags & B_ERROR)
		goto out;
	fsp = (struct fs *)tp->b_un.b_addr;

	if ((fsp->fs_magic != FS_MAGIC) && (fsp->fs_magic != MTB_UFS_MAGIC)) {
		cmn_err(CE_NOTE,
		    "mount: not a UFS magic number (0x%x)", fsp->fs_magic);
		error = EINVAL;
		goto out;
	}

	if ((fsp->fs_magic == FS_MAGIC) &&
	    (fsp->fs_version != UFS_EFISTYLE4NONEFI_VERSION_2 &&
	    fsp->fs_version != UFS_VERSION_MIN)) {
		cmn_err(CE_NOTE,
		    "mount: unrecognized version of UFS on-disk format: %d",
		    fsp->fs_version);
		error = EINVAL;
		goto out;
	}

	if ((fsp->fs_magic == MTB_UFS_MAGIC) &&
	    (fsp->fs_version > MTB_UFS_VERSION_1 ||
	    fsp->fs_version < MTB_UFS_VERSION_MIN)) {
		cmn_err(CE_NOTE,
		    "mount: unrecognized version of UFS on-disk format: %d",
		    fsp->fs_version);
		error = EINVAL;
		goto out;
	}

#ifndef _LP64
	if (fsp->fs_magic == MTB_UFS_MAGIC) {
		/*
		 * Find the size of the device in sectors.  If the
		 * the size in sectors is greater than INT_MAX, it's
		 * a multi-terabyte file system, which can't be
		 * mounted by a 32-bit kernel.  We can't use the
		 * fsbtodb() macro in the next line because the macro
		 * casts the intermediate values to daddr_t, which is
		 * a 32-bit quantity in a 32-bit kernel.  Here we
		 * really do need the intermediate values to be held
		 * in 64-bit quantities because we're checking for
		 * overflow of a 32-bit field.
		 */
		if ((((diskaddr_t)(fsp->fs_size)) << fsp->fs_fsbtodb)
		    > INT_MAX) {
			cmn_err(CE_NOTE,
			    "mount: multi-terabyte UFS cannot be"
			    " mounted by a 32-bit kernel");
			error = EINVAL;
			goto out;
		}

	}
#endif

	if (fsp->fs_bsize > MAXBSIZE || fsp->fs_frag > MAXFRAG ||
	    fsp->fs_bsize < sizeof (struct fs) || fsp->fs_bsize < PAGESIZE) {
		error = EINVAL;	/* also needs translation */
		goto out;
	}

	/*
	 * Allocate VFS private data.
	 */
	vfsp->vfs_bcount = 0;
	vfsp->vfs_data = (caddr_t)ufsvfsp;
	vfsp->vfs_fstype = ufsfstype;
	vfsp->vfs_dev = dev;
	vfsp->vfs_flag |= VFS_NOTRUNC;
	vfs_make_fsid(&vfsp->vfs_fsid, dev, ufsfstype);
	ufsvfsp->vfs_devvp = devvp;

	/*
	 * Cross-link with vfs and add to instance list.
	 */
	ufsvfsp->vfs_vfs = vfsp;
	ufs_vfs_add(ufsvfsp);

	ufsvfsp->vfs_dev = dev;
	ufsvfsp->vfs_bufp = tp;

	ufsvfsp->vfs_dirsize = INODESIZE + (4 * ALLOCSIZE) + fsp->fs_fsize;
	ufsvfsp->vfs_minfrags =
	    (int)((int64_t)fsp->fs_dsize * fsp->fs_minfree / 100);
	/*
	 * if mount allows largefiles, indicate so in ufsvfs
	 */
	if (flags & UFSMNT_LARGEFILES)
		ufsvfsp->vfs_lfflags |= UFS_LARGEFILES;
	/*
	 * Initialize threads
	 */
	ufs_delete_init(ufsvfsp, 1);
	ufs_thread_init(&ufsvfsp->vfs_reclaim, 0);

	/*
	 * Chicken and egg problem. The superblock may have deltas
	 * in the log.  So after the log is scanned we reread the
	 * superblock. We guarantee that the fields needed to
	 * scan the log will not be in the log.
	 */
	if (fsp->fs_logbno && fsp->fs_clean == FSLOG &&
	    (fsp->fs_state + fsp->fs_time == FSOKAY)) {
		error = lufs_snarf(ufsvfsp, fsp, (vfsp->vfs_flag & VFS_RDONLY));
		if (error) {
			/*
			 * Allow a ro mount to continue even if the
			 * log cannot be processed - yet.
			 */
			if (!(vfsp->vfs_flag & VFS_RDONLY)) {
				cmn_err(CE_WARN, "Error accessing ufs "
				    "log for %s; Please run fsck(1M)", path);
				goto out;
			}
		}
		tp->b_flags |= (B_AGE | B_STALE);
		brelse(tp);
		tp = UFS_BREAD(ufsvfsp, dev, SBLOCK, SBSIZE);
		fsp = (struct fs *)tp->b_un.b_addr;
		ufsvfsp->vfs_bufp = tp;
		if (tp->b_flags & B_ERROR)
			goto out;
	}

	/*
	 * Set logging mounted flag used by lockfs
	 */
	ufsvfsp->vfs_validfs = UT_MOUNTED;

	/*
	 * Copy the super block into a buffer in its native size.
	 * Use ngeteblk to allocate the buffer
	 */
	bp = ngeteblk(fsp->fs_bsize);
	ufsvfsp->vfs_bufp = bp;
	bp->b_edev = dev;
	bp->b_dev = cmpdev(dev);
	bp->b_blkno = SBLOCK;
	bp->b_bcount = fsp->fs_sbsize;
	bcopy(tp->b_un.b_addr, bp->b_un.b_addr, fsp->fs_sbsize);
	tp->b_flags |= B_STALE | B_AGE;
	brelse(tp);
	tp = 0;

	fsp = (struct fs *)bp->b_un.b_addr;
	/*
	 * Mount fails if superblock flag indicates presence of large
	 * files and filesystem is attempted to be mounted 'nolargefiles'.
	 * The exception is for a read only mount of root, which we
	 * always want to succeed, so fsck can fix potential problems.
	 * The assumption is that we will remount root at some point,
	 * and the remount will enforce the mount option.
	 */
	if (!(isroot & (vfsp->vfs_flag & VFS_RDONLY)) &&
	    (fsp->fs_flags & FSLARGEFILES) &&
	    !(flags & UFSMNT_LARGEFILES)) {
		error = EFBIG;
		goto out;
	}

	if (vfsp->vfs_flag & VFS_RDONLY) {
		fsp->fs_ronly = 1;
		fsp->fs_fmod = 0;
		if (((fsp->fs_state + fsp->fs_time) == FSOKAY) &&
		    ((fsp->fs_clean == FSCLEAN) ||
		    (fsp->fs_clean == FSSTABLE) ||
		    (fsp->fs_clean == FSLOG))) {
			if (isroot) {
				if (fsp->fs_clean == FSLOG) {
					if (fsp->fs_rolled == FS_ALL_ROLLED) {
						ufs_clean_root = 1;
					}
				} else {
					ufs_clean_root = 1;
				}
			}
			fsp->fs_clean = FSSTABLE;
		} else {
			fsp->fs_clean = FSBAD;
		}
	} else {

		fsp->fs_fmod = 0;
		fsp->fs_ronly = 0;

		TRANS_DOMATAMAP(ufsvfsp);

		if ((TRANS_ISERROR(ufsvfsp)) ||
		    (((fsp->fs_state + fsp->fs_time) == FSOKAY) &&
		    fsp->fs_clean == FSLOG && !TRANS_ISTRANS(ufsvfsp))) {
			ufsvfsp->vfs_log = NULL;
			ufsvfsp->vfs_domatamap = 0;
			error = ENOSPC;
			goto out;
		}

		if (((fsp->fs_state + fsp->fs_time) == FSOKAY) &&
		    (fsp->fs_clean == FSCLEAN ||
		    fsp->fs_clean == FSSTABLE ||
		    fsp->fs_clean == FSLOG))
			fsp->fs_clean = FSSTABLE;
		else {
			if (isroot) {
				/*
				 * allow root partition to be mounted even
				 * when fs_state is not ok
				 * will be fixed later by a remount root
				 */
				fsp->fs_clean = FSBAD;
				ufsvfsp->vfs_log = NULL;
				ufsvfsp->vfs_domatamap = 0;
			} else {
				error = ENOSPC;
				goto out;
			}
		}

		if (fsp->fs_clean == FSSTABLE && TRANS_ISTRANS(ufsvfsp))
			fsp->fs_clean = FSLOG;
	}
	TRANS_MATA_MOUNT(ufsvfsp);
	needtrans = 1;

	vfsp->vfs_bsize = fsp->fs_bsize;

	/*
	 * Read in summary info
	 */
	if (error = ufs_getsummaryinfo(dev, ufsvfsp, fsp))
		goto out;

	/*
	 * lastwhinetime is set to zero rather than lbolt, so that after
	 * mounting if the filesystem is found to be full, then immediately the
	 * "file system message" will be logged.
	 */
	ufsvfsp->vfs_lastwhinetime = 0L;


	mutex_init(&ufsvfsp->vfs_lock, NULL, MUTEX_DEFAULT, NULL);
	(void) copystr(path, fsp->fs_fsmnt, sizeof (fsp->fs_fsmnt) - 1, &len);
	bzero(fsp->fs_fsmnt + len, sizeof (fsp->fs_fsmnt) - len);

	/*
	 * Sanity checks for old file systems
	 */
	if (fsp->fs_postblformat == FS_42POSTBLFMT)
		ufsvfsp->vfs_nrpos = 8;
	else
		ufsvfsp->vfs_nrpos = fsp->fs_nrpos;

	/*
	 * Initialize lockfs structure to support file system locking
	 */
	bzero(&ufsvfsp->vfs_ulockfs.ul_lockfs,
	    sizeof (struct lockfs));
	ufsvfsp->vfs_ulockfs.ul_fs_lock = ULOCKFS_ULOCK;
	mutex_init(&ufsvfsp->vfs_ulockfs.ul_lock, NULL,
	    MUTEX_DEFAULT, NULL);
	cv_init(&ufsvfsp->vfs_ulockfs.ul_cv, NULL, CV_DEFAULT, NULL);

	/*
	 * We don't need to grab vfs_dqrwlock for this ufs_iget() call.
	 * We are in the process of mounting the file system so there
	 * is no need to grab the quota lock. If a quota applies to the
	 * root inode, then it will be updated when quotas are enabled.
	 *
	 * However, we have an ASSERT(RW_LOCK_HELD(&ufsvfsp->vfs_dqrwlock))
	 * in getinoquota() that we want to keep so grab it anyway.
	 */
	rw_enter(&ufsvfsp->vfs_dqrwlock, RW_READER);

	error = ufs_iget_alloced(vfsp, UFSROOTINO, &rip, cr);

	rw_exit(&ufsvfsp->vfs_dqrwlock);

	if (error)
		goto out;

	/*
	 * make sure root inode is a directory.  Returning ENOTDIR might
	 * be confused with the mount point not being a directory, so
	 * we use EIO instead.
	 */
	if ((rip->i_mode & IFMT) != IFDIR) {
		/*
		 * Mark this inode as subject for cleanup
		 * to avoid stray inodes in the cache.
		 */
		rvp = ITOV(rip);
		error = EIO;
		goto out;
	}

	rvp = ITOV(rip);
	mutex_enter(&rvp->v_lock);
	rvp->v_flag |= VROOT;
	mutex_exit(&rvp->v_lock);
	ufsvfsp->vfs_root = rvp;
	/* The buffer for the root inode does not contain a valid b_vp */
	(void) bfinval(dev, 0);

	/* options */
	ufsvfsp->vfs_nosetsec = flags & UFSMNT_NOSETSEC;
	ufsvfsp->vfs_nointr  = flags & UFSMNT_NOINTR;
	ufsvfsp->vfs_syncdir = flags & UFSMNT_SYNCDIR;
	ufsvfsp->vfs_noatime = flags & UFSMNT_NOATIME;
	if ((flags & UFSMNT_NODFRATIME) || ufsvfsp->vfs_noatime)
		ufsvfsp->vfs_dfritime &= ~UFS_DFRATIME;
	else	/* dfratime, default behavior */
		ufsvfsp->vfs_dfritime |= UFS_DFRATIME;
	if (flags & UFSMNT_FORCEDIRECTIO)
		ufsvfsp->vfs_forcedirectio = 1;
	else if (flags & UFSMNT_NOFORCEDIRECTIO)
		ufsvfsp->vfs_forcedirectio = 0;
	ufsvfsp->vfs_iotstamp = ddi_get_lbolt();

	ufsvfsp->vfs_nindiroffset = fsp->fs_nindir - 1;
	ufsvfsp->vfs_nindirshift = highbit(ufsvfsp->vfs_nindiroffset);
	ufsvfsp->vfs_ioclustsz = fsp->fs_bsize * fsp->fs_maxcontig;

	if (cdev_ioctl(dev, DKIOCINFO, (intptr_t)&ci,
	    FKIOCTL|FNATIVE|FREAD, CRED(), &status) == 0) {
		ufsvfsp->vfs_iotransz = ci.dki_maxtransfer * DEV_BSIZE;
	} else {
		ufsvfsp->vfs_iotransz = MIN(maxphys, ufs_maxmaxphys);
	}

	if (ufsvfsp->vfs_iotransz <= 0) {
		ufsvfsp->vfs_iotransz = MIN(maxphys, ufs_maxmaxphys);
	}

	/*
	 * When logging, used to reserve log space for writes and truncs
	 */
	ufsvfsp->vfs_avgbfree = fsp->fs_cstotal.cs_nbfree / fsp->fs_ncg;

	/*
	 * Determine whether to log cylinder group summary info.
	 */
	ufsvfsp->vfs_nolog_si = (fsp->fs_ncg < ufs_ncg_log);

	if (TRANS_ISTRANS(ufsvfsp)) {
		/*
		 * start the delete thread
		 */
		ufs_thread_start(&ufsvfsp->vfs_delete, ufs_thread_delete, vfsp);

		/*
		 * start reclaim thread if the filesystem was not mounted
		 * read only.
		 */
		if (!fsp->fs_ronly && (fsp->fs_reclaim &
		    (FS_RECLAIM|FS_RECLAIMING))) {
			fsp->fs_reclaim &= ~FS_RECLAIM;
			fsp->fs_reclaim |=  FS_RECLAIMING;
			ufs_thread_start(&ufsvfsp->vfs_reclaim,
			    ufs_thread_reclaim, vfsp);
		}

		/* Mark the fs as unrolled */
		fsp->fs_rolled = FS_NEED_ROLL;
	} else if (!fsp->fs_ronly && (fsp->fs_reclaim &
	    (FS_RECLAIM|FS_RECLAIMING))) {
		/*
		 * If a file system that is mounted nologging, after
		 * having previously been mounted logging, becomes
		 * unmounted whilst the reclaim thread is in the throes
		 * of reclaiming open/deleted inodes, a subsequent mount
		 * of such a file system with logging disabled could lead
		 * to inodes becoming lost.  So, start reclaim now, even
		 * though logging was disabled for the previous mount, to
		 * tidy things up.
		 */
		fsp->fs_reclaim &= ~FS_RECLAIM;
		fsp->fs_reclaim |=  FS_RECLAIMING;
		ufs_thread_start(&ufsvfsp->vfs_reclaim,
		    ufs_thread_reclaim, vfsp);
	}

	if (!fsp->fs_ronly) {
		TRANS_SBWRITE(ufsvfsp, TOP_MOUNT);
		if (error = geterror(ufsvfsp->vfs_bufp))
			goto out;
	}

	/* fix-on-panic initialization */
	if (isroot && !(flags & UFSMNT_ONERROR_FLGMASK))
		flags |= UFSMNT_ONERROR_PANIC;	/* XXX ..._RDONLY */

	if ((error = ufsfx_mount(ufsvfsp, flags)) != 0)
		goto out;

	if (why == ROOT_INIT && isroot)
		rootvp = devvp;

	return (0);
out:
	if (error == 0)
		error = EIO;
	if (rvp) {
		/* the following sequence is similar to ufs_unmount() */

		/*
		 * There's a problem that ufs_iget() puts inodes into
		 * the inode cache before it returns them.  If someone
		 * traverses that cache and gets a reference to our
		 * inode, there's a chance they'll still be using it
		 * after we've destroyed it.  This is a hard race to
		 * hit, but it's happened (putting in a medium delay
		 * here, and a large delay in ufs_scan_inodes() for
		 * inodes on the device we're bailing out on, makes
		 * the race easy to demonstrate).  The symptom is some
		 * other part of UFS faulting on bad inode contents,
		 * or when grabbing one of the locks inside the inode,
		 * etc.  The usual victim is ufs_scan_inodes() or
		 * someone called by it.
		 */

		/*
		 * First, isolate it so that no new references can be
		 * gotten via the inode cache.
		 */
		ihm = &ih_lock[INOHASH(UFSROOTINO)];
		mutex_enter(ihm);
		remque(rip);
		mutex_exit(ihm);

		/*
		 * Now wait for all outstanding references except our
		 * own to drain.  This could, in theory, take forever,
		 * so don't wait *too* long.  If we time out, mark
		 * it stale and leak it, so we don't hit the problem
		 * described above.
		 *
		 * Note that v_count is an int, which means we can read
		 * it in one operation.  Thus, there's no need to lock
		 * around our tests.
		 */
		elapsed = 0;
		while ((rvp->v_count > 1) && (elapsed < ufs_mount_timeout)) {
			delay(ufs_mount_error_delay * drv_usectohz(1000));
			elapsed += ufs_mount_error_delay;
		}

		if (rvp->v_count > 1) {
			mutex_enter(&rip->i_tlock);
			rip->i_flag |= ISTALE;
			mutex_exit(&rip->i_tlock);
			cmn_err(CE_WARN,
			    "Timed out while cleaning up after "
			    "failed mount of %s", path);
		} else {

			/*
			 * Now we're the only one with a handle left, so tear
			 * it down the rest of the way.
			 */
			if (ufs_rmidle(rip))
				VN_RELE(rvp);
			ufs_si_del(rip);
			rip->i_ufsvfs = NULL;
			rvp->v_vfsp = NULL;
			rvp->v_type = VBAD;
			VN_RELE(rvp);
		}
	}
	if (needtrans) {
		TRANS_MATA_UMOUNT(ufsvfsp);
	}
	if (ufsvfsp) {
		ufs_vfs_remove(ufsvfsp);
		ufs_thread_exit(&ufsvfsp->vfs_delete);
		ufs_thread_exit(&ufsvfsp->vfs_reclaim);
		mutex_destroy(&ufsvfsp->vfs_lock);
		if (ufsvfsp->vfs_log) {
			lufs_unsnarf(ufsvfsp);
		}
		kmem_free(ufsvfsp, sizeof (struct ufsvfs));
	}
	if (bp) {
		bp->b_flags |= (B_STALE|B_AGE);
		brelse(bp);
	}
	if (tp) {
		tp->b_flags |= (B_STALE|B_AGE);
		brelse(tp);
	}
	if (needclose) {
		(void) VOP_CLOSE(devvp, (vfsp->vfs_flag & VFS_RDONLY) ?
		    FREAD : FREAD|FWRITE, 1, (offset_t)0, cr, NULL);
		bflush(dev);
		(void) bfinval(dev, 1);
	}
	return (error);
}

/*
 * vfs operations
 */
static int
ufs_unmount(struct vfs *vfsp, int fflag, struct cred *cr)
{
	dev_t 		dev		= vfsp->vfs_dev;
	struct ufsvfs	*ufsvfsp	= (struct ufsvfs *)vfsp->vfs_data;
	struct fs	*fs		= ufsvfsp->vfs_fs;
	struct ulockfs	*ulp		= &ufsvfsp->vfs_ulockfs;
	struct vnode 	*bvp, *vp;
	struct buf	*bp;
	struct inode	*ip, *inext, *rip;
	union ihead	*ih;
	int 		error, flag, i;
	struct lockfs	lockfs;
	int		poll_events = POLLPRI;
	extern struct pollhead ufs_pollhd;
	refstr_t	*mountpoint;

	ASSERT(vfs_lock_held(vfsp));

	if (secpolicy_fs_unmount(cr, vfsp) != 0)
		return (EPERM);
	/*
	 * Forced unmount is now supported through the
	 * lockfs protocol.
	 */
	if (fflag & MS_FORCE) {
		/*
		 * Mark the filesystem as being unmounted now in
		 * case of a forcible umount before we take any
		 * locks inside UFS to prevent racing with a VFS_VGET()
		 * request. Throw these VFS_VGET() requests away for
		 * the duration of the forcible umount so they won't
		 * use stale or even freed data later on when we're done.
		 * It may happen that the VFS has had a additional hold
		 * placed on it by someone other than UFS and thus will
		 * not get freed immediately once we're done with the
		 * umount by dounmount() - use VFS_UNMOUNTED to inform
		 * users of this still-alive VFS that its corresponding
		 * filesystem being gone so they can detect that and error
		 * out.
		 */
		vfsp->vfs_flag |= VFS_UNMOUNTED;

		ufs_thread_suspend(&ufsvfsp->vfs_delete);
		mutex_enter(&ulp->ul_lock);
		/*
		 * If file system is already hard locked,
		 * unmount the file system, otherwise
		 * hard lock it before unmounting.
		 */
		if (!ULOCKFS_IS_HLOCK(ulp)) {
			atomic_inc_ulong(&ufs_quiesce_pend);
			lockfs.lf_lock = LOCKFS_HLOCK;
			lockfs.lf_flags = 0;
			lockfs.lf_key = ulp->ul_lockfs.lf_key + 1;
			lockfs.lf_comlen = 0;
			lockfs.lf_comment = NULL;
			ufs_freeze(ulp, &lockfs);
			ULOCKFS_SET_BUSY(ulp);
			LOCKFS_SET_BUSY(&ulp->ul_lockfs);
			(void) ufs_quiesce(ulp);
			(void) ufs_flush(vfsp);
			(void) ufs_thaw(vfsp, ufsvfsp, ulp);
			atomic_dec_ulong(&ufs_quiesce_pend);
			ULOCKFS_CLR_BUSY(ulp);
			LOCKFS_CLR_BUSY(&ulp->ul_lockfs);
			poll_events |= POLLERR;
			pollwakeup(&ufs_pollhd, poll_events);
		}
		ufs_thread_continue(&ufsvfsp->vfs_delete);
		mutex_exit(&ulp->ul_lock);
	}

	/* let all types of writes go through */
	ufsvfsp->vfs_iotstamp = ddi_get_lbolt();

	/* coordinate with global hlock thread */
	if (TRANS_ISTRANS(ufsvfsp) && (ufsvfsp->vfs_validfs == UT_HLOCKING)) {
		/*
		 * last possibility for a forced umount to fail hence clear
		 * VFS_UNMOUNTED if appropriate.
		 */
		if (fflag & MS_FORCE)
			vfsp->vfs_flag &= ~VFS_UNMOUNTED;
		return (EAGAIN);
	}

	ufsvfsp->vfs_validfs = UT_UNMOUNTED;

	/* kill the reclaim thread */
	ufs_thread_exit(&ufsvfsp->vfs_reclaim);

	/* suspend the delete thread */
	ufs_thread_suspend(&ufsvfsp->vfs_delete);

	/*
	 * drain the delete and idle queues
	 */
	ufs_delete_drain(vfsp, -1, 1);
	ufs_idle_drain(vfsp);

	/*
	 * use the lockfs protocol to prevent new ops from starting
	 * a forcible umount can not fail beyond this point as
	 * we hard-locked the filesystem and drained all current consumers
	 * before.
	 */
	mutex_enter(&ulp->ul_lock);

	/*
	 * if the file system is busy; return EBUSY
	 */
	if (ulp->ul_vnops_cnt || ulp->ul_falloc_cnt || ULOCKFS_IS_SLOCK(ulp)) {
		error = EBUSY;
		goto out;
	}

	/*
	 * if this is not a forced unmount (!hard/error locked), then
	 * get rid of every inode except the root and quota inodes
	 * also, commit any outstanding transactions
	 */
	if (!ULOCKFS_IS_HLOCK(ulp) && !ULOCKFS_IS_ELOCK(ulp))
		if (error = ufs_flush(vfsp))
			goto out;

	/*
	 * ignore inodes in the cache if fs is hard locked or error locked
	 */
	rip = VTOI(ufsvfsp->vfs_root);
	if (!ULOCKFS_IS_HLOCK(ulp) && !ULOCKFS_IS_ELOCK(ulp)) {
		/*
		 * Otherwise, only the quota and root inodes are in the cache.
		 *
		 * Avoid racing with ufs_update() and ufs_sync().
		 */
		mutex_enter(&ufs_scan_lock);

		for (i = 0, ih = ihead; i < inohsz; i++, ih++) {
			mutex_enter(&ih_lock[i]);
			for (ip = ih->ih_chain[0];
			    ip != (struct inode *)ih;
			    ip = ip->i_forw) {
				if (ip->i_ufsvfs != ufsvfsp)
					continue;
				if (ip == ufsvfsp->vfs_qinod)
					continue;
				if (ip == rip && ITOV(ip)->v_count == 1)
					continue;
				mutex_exit(&ih_lock[i]);
				mutex_exit(&ufs_scan_lock);
				error = EBUSY;
				goto out;
			}
			mutex_exit(&ih_lock[i]);
		}
		mutex_exit(&ufs_scan_lock);
	}

	/*
	 * if a snapshot exists and this is a forced unmount, then delete
	 * the snapshot.  Otherwise return EBUSY.  This will insure the
	 * snapshot always belongs to a valid file system.
	 */
	if (ufsvfsp->vfs_snapshot) {
		if (ULOCKFS_IS_HLOCK(ulp) || ULOCKFS_IS_ELOCK(ulp)) {
			(void) fssnap_delete(&ufsvfsp->vfs_snapshot);
		} else {
			error = EBUSY;
			goto out;
		}
	}

	/*
	 * Close the quota file and invalidate anything left in the quota
	 * cache for this file system.  Pass kcred to allow all quota
	 * manipulations.
	 */
	(void) closedq(ufsvfsp, kcred);
	invalidatedq(ufsvfsp);
	/*
	 * drain the delete and idle queues
	 */
	ufs_delete_drain(vfsp, -1, 0);
	ufs_idle_drain(vfsp);

	/*
	 * discard the inodes for this fs (including root, shadow, and quota)
	 */
	for (i = 0, ih = ihead; i < inohsz; i++, ih++) {
		mutex_enter(&ih_lock[i]);
		for (inext = 0, ip = ih->ih_chain[0];
		    ip != (struct inode *)ih;
		    ip = inext) {
			inext = ip->i_forw;
			if (ip->i_ufsvfs != ufsvfsp)
				continue;

			/*
			 * We've found the inode in the cache and as we
			 * hold the hash mutex the inode can not
			 * disappear from underneath us.
			 * We also know it must have at least a vnode
			 * reference count of 1.
			 * We perform an additional VN_HOLD so the VN_RELE
			 * in case we take the inode off the idle queue
			 * can not be the last one.
			 * It is safe to grab the writer contents lock here
			 * to prevent a race with ufs_iinactive() putting
			 * inodes into the idle queue while we operate on
			 * this inode.
			 */
			rw_enter(&ip->i_contents, RW_WRITER);

			vp = ITOV(ip);
			VN_HOLD(vp)
			remque(ip);
			if (ufs_rmidle(ip))
				VN_RELE(vp);
			ufs_si_del(ip);
			/*
			 * rip->i_ufsvfsp is needed by bflush()
			 */
			if (ip != rip)
				ip->i_ufsvfs = NULL;
			/*
			 * Set vnode's vfsops to dummy ops, which return
			 * EIO. This is needed to forced unmounts to work
			 * with lofs/nfs properly.
			 */
			if (ULOCKFS_IS_HLOCK(ulp) || ULOCKFS_IS_ELOCK(ulp))
				vp->v_vfsp = &EIO_vfs;
			else
				vp->v_vfsp = NULL;
			vp->v_type = VBAD;

			rw_exit(&ip->i_contents);

			VN_RELE(vp);
		}
		mutex_exit(&ih_lock[i]);
	}
	ufs_si_cache_flush(dev);

	/*
	 * kill the delete thread and drain the idle queue
	 */
	ufs_thread_exit(&ufsvfsp->vfs_delete);
	ufs_idle_drain(vfsp);

	bp = ufsvfsp->vfs_bufp;
	bvp = ufsvfsp->vfs_devvp;
	flag = !fs->fs_ronly;
	if (flag) {
		bflush(dev);
		if (fs->fs_clean != FSBAD) {
			if (fs->fs_clean == FSSTABLE)
				fs->fs_clean = FSCLEAN;
			fs->fs_reclaim &= ~FS_RECLAIM;
		}
		if (TRANS_ISTRANS(ufsvfsp) &&
		    !TRANS_ISERROR(ufsvfsp) &&
		    !ULOCKFS_IS_HLOCK(ulp) &&
		    (fs->fs_rolled == FS_NEED_ROLL)) {
			/*
			 * ufs_flush() above has flushed the last Moby.
			 * This is needed to ensure the following superblock
			 * update really is the last metadata update
			 */
			error = ufs_putsummaryinfo(dev, ufsvfsp, fs);
			if (error == 0) {
				fs->fs_rolled = FS_ALL_ROLLED;
			}
		}
		TRANS_SBUPDATE(ufsvfsp, vfsp, TOP_SBUPDATE_UNMOUNT);
		/*
		 * push this last transaction
		 */
		curthread->t_flag |= T_DONTBLOCK;
		TRANS_BEGIN_SYNC(ufsvfsp, TOP_COMMIT_UNMOUNT, TOP_COMMIT_SIZE,
		    error);
		if (!error)
			TRANS_END_SYNC(ufsvfsp, error, TOP_COMMIT_UNMOUNT,
			    TOP_COMMIT_SIZE);
		curthread->t_flag &= ~T_DONTBLOCK;
	}

	TRANS_MATA_UMOUNT(ufsvfsp);
	lufs_unsnarf(ufsvfsp);		/* Release the in-memory structs */
	ufsfx_unmount(ufsvfsp);		/* fix-on-panic bookkeeping */
	kmem_free(fs->fs_u.fs_csp, fs->fs_cssize);

	bp->b_flags |= B_STALE|B_AGE;
	ufsvfsp->vfs_bufp = NULL;	/* don't point at freed buf */
	brelse(bp);			/* free the superblock buf */

	(void) VOP_PUTPAGE(common_specvp(bvp), (offset_t)0, (size_t)0,
	    B_INVAL, cr, NULL);
	(void) VOP_CLOSE(bvp, flag, 1, (offset_t)0, cr, NULL);
	bflush(dev);
	(void) bfinval(dev, 1);
	VN_RELE(bvp);

	/*
	 * It is now safe to NULL out the ufsvfs pointer and discard
	 * the root inode.
	 */
	rip->i_ufsvfs = NULL;
	VN_RELE(ITOV(rip));

	/* free up lockfs comment structure, if any */
	if (ulp->ul_lockfs.lf_comlen && ulp->ul_lockfs.lf_comment)
		kmem_free(ulp->ul_lockfs.lf_comment, ulp->ul_lockfs.lf_comlen);

	/*
	 * Remove from instance list.
	 */
	ufs_vfs_remove(ufsvfsp);

	/*
	 * For a forcible unmount, threads may be asleep in
	 * ufs_lockfs_begin/ufs_check_lockfs.  These threads will need
	 * the ufsvfs structure so we don't free it, yet.  ufs_update
	 * will free it up after awhile.
	 */
	if (ULOCKFS_IS_HLOCK(ulp) || ULOCKFS_IS_ELOCK(ulp)) {
		extern kmutex_t		ufsvfs_mutex;
		extern struct ufsvfs	*ufsvfslist;

		mutex_enter(&ufsvfs_mutex);
		ufsvfsp->vfs_dontblock = 1;
		ufsvfsp->vfs_next = ufsvfslist;
		ufsvfslist = ufsvfsp;
		mutex_exit(&ufsvfs_mutex);
		/* wakeup any suspended threads */
		cv_broadcast(&ulp->ul_cv);
		mutex_exit(&ulp->ul_lock);
	} else {
		mutex_destroy(&ufsvfsp->vfs_lock);
		kmem_free(ufsvfsp, sizeof (struct ufsvfs));
	}

	/*
	 * Now mark the filesystem as unmounted since we're done with it.
	 */
	vfsp->vfs_flag |= VFS_UNMOUNTED;

	return (0);
out:
	/* open the fs to new ops */
	cv_broadcast(&ulp->ul_cv);
	mutex_exit(&ulp->ul_lock);

	if (TRANS_ISTRANS(ufsvfsp)) {
		/* allow the delete thread to continue */
		ufs_thread_continue(&ufsvfsp->vfs_delete);
		/* restart the reclaim thread */
		ufs_thread_start(&ufsvfsp->vfs_reclaim, ufs_thread_reclaim,
		    vfsp);
		/* coordinate with global hlock thread */
		ufsvfsp->vfs_validfs = UT_MOUNTED;
		/* check for trans errors during umount */
		ufs_trans_onerror();

		/*
		 * if we have a separate /usr it will never unmount
		 * when halting. In order to not re-read all the
		 * cylinder group summary info on mounting after
		 * reboot the logging of summary info is re-enabled
		 * and the super block written out.
		 */
		mountpoint = vfs_getmntpoint(vfsp);
		if ((fs->fs_si == FS_SI_OK) &&
		    (strcmp("/usr", refstr_value(mountpoint)) == 0)) {
			ufsvfsp->vfs_nolog_si = 0;
			UFS_BWRITE2(NULL, ufsvfsp->vfs_bufp);
		}
		refstr_rele(mountpoint);
	}

	return (error);
}

static int
ufs_root(struct vfs *vfsp, struct vnode **vpp)
{
	struct ufsvfs *ufsvfsp;
	struct vnode *vp;

	if (!vfsp)
		return (EIO);

	ufsvfsp = (struct ufsvfs *)vfsp->vfs_data;
	if (!ufsvfsp || !ufsvfsp->vfs_root)
		return (EIO);	/* forced unmount */

	vp = ufsvfsp->vfs_root;
	VN_HOLD(vp);
	*vpp = vp;
	return (0);
}

/*
 * Get file system statistics.
 */
static int
ufs_statvfs(struct vfs *vfsp, struct statvfs64 *sp)
{
	struct fs *fsp;
	struct ufsvfs *ufsvfsp;
	int blk, i;
	long max_avail, used;
	dev32_t d32;

	if (vfsp->vfs_flag & VFS_UNMOUNTED)
		return (EIO);

	ufsvfsp = (struct ufsvfs *)vfsp->vfs_data;
	fsp = ufsvfsp->vfs_fs;
	if ((fsp->fs_magic != FS_MAGIC) && (fsp->fs_magic != MTB_UFS_MAGIC))
		return (EINVAL);
	if (fsp->fs_magic == FS_MAGIC &&
	    (fsp->fs_version != UFS_EFISTYLE4NONEFI_VERSION_2 &&
	    fsp->fs_version != UFS_VERSION_MIN))
		return (EINVAL);
	if (fsp->fs_magic == MTB_UFS_MAGIC &&
	    (fsp->fs_version > MTB_UFS_VERSION_1 ||
	    fsp->fs_version < MTB_UFS_VERSION_MIN))
		return (EINVAL);

	/*
	 * get the basic numbers
	 */
	(void) bzero(sp, sizeof (*sp));

	sp->f_bsize = fsp->fs_bsize;
	sp->f_frsize = fsp->fs_fsize;
	sp->f_blocks = (fsblkcnt64_t)fsp->fs_dsize;
	sp->f_bfree = (fsblkcnt64_t)fsp->fs_cstotal.cs_nbfree * fsp->fs_frag +
	    fsp->fs_cstotal.cs_nffree;

	sp->f_files = (fsfilcnt64_t)fsp->fs_ncg * fsp->fs_ipg;
	sp->f_ffree = (fsfilcnt64_t)fsp->fs_cstotal.cs_nifree;

	/*
	 * Adjust the numbers based on things waiting to be deleted.
	 * modifies f_bfree and f_ffree.  Afterwards, everything we
	 * come up with will be self-consistent.  By definition, this
	 * is a point-in-time snapshot, so the fact that the delete
	 * thread's probably already invalidated the results is not a
	 * problem.  Note that if the delete thread is ever extended to
	 * non-logging ufs, this adjustment must always be made.
	 */
	if (TRANS_ISTRANS(ufsvfsp))
		ufs_delete_adjust_stats(ufsvfsp, sp);

	/*
	 * avail = MAX(max_avail - used, 0)
	 */
	max_avail = fsp->fs_dsize - ufsvfsp->vfs_minfrags;

	used = (fsp->fs_dsize - sp->f_bfree);

	if (max_avail > used)
		sp->f_bavail = (fsblkcnt64_t)max_avail - used;
	else
		sp->f_bavail = (fsblkcnt64_t)0;

	sp->f_favail = sp->f_ffree;
	(void) cmpldev(&d32, vfsp->vfs_dev);
	sp->f_fsid = d32;
	(void) strcpy(sp->f_basetype, vfssw[vfsp->vfs_fstype].vsw_name);
	sp->f_flag = vf_to_stf(vfsp->vfs_flag);

	/* keep coordinated with ufs_l_pathconf() */
	sp->f_namemax = MAXNAMLEN;

	if (fsp->fs_cpc == 0) {
		bzero(sp->f_fstr, 14);
		return (0);
	}
	blk = fsp->fs_spc * fsp->fs_cpc / NSPF(fsp);
	for (i = 0; i < blk; i += fsp->fs_frag) /* CSTYLED */
		/* void */;
	i -= fsp->fs_frag;
	blk = i / fsp->fs_frag;
	bcopy(&(fs_rotbl(fsp)[blk]), sp->f_fstr, 14);
	return (0);
}

/*
 * Flush any pending I/O to file system vfsp.
 * The ufs_update() routine will only flush *all* ufs files.
 * If vfsp is non-NULL, only sync this ufs (in preparation
 * for a umount).
 */
/*ARGSUSED*/
static int
ufs_sync(struct vfs *vfsp, short flag, struct cred *cr)
{
	struct ufsvfs *ufsvfsp;
	struct fs *fs;
	int cheap = flag & SYNC_ATTR;
	int error;

	/*
	 * SYNC_CLOSE means we're rebooting.  Toss everything
	 * on the idle queue so we don't have to slog through
	 * a bunch of uninteresting inodes over and over again.
	 */
	if (flag & SYNC_CLOSE)
		ufs_idle_drain(NULL);

	if (vfsp == NULL) {
		ufs_update(flag);
		return (0);
	}

	/* Flush a single ufs */
	if (!vfs_matchops(vfsp, ufs_vfsops) || vfs_lock(vfsp) != 0)
		return (0);

	ufsvfsp = (struct ufsvfs *)vfsp->vfs_data;
	if (!ufsvfsp)
		return (EIO);
	fs = ufsvfsp->vfs_fs;
	mutex_enter(&ufsvfsp->vfs_lock);

	if (ufsvfsp->vfs_dio &&
	    fs->fs_ronly == 0 &&
	    fs->fs_clean != FSBAD &&
	    fs->fs_clean != FSLOG) {
		/* turn off fast-io on unmount, so no fsck needed (4029401) */
		ufsvfsp->vfs_dio = 0;
		fs->fs_clean = FSACTIVE;
		fs->fs_fmod = 1;
	}

	/* Write back modified superblock */
	if (fs->fs_fmod == 0) {
		mutex_exit(&ufsvfsp->vfs_lock);
	} else {
		if (fs->fs_ronly != 0) {
			mutex_exit(&ufsvfsp->vfs_lock);
			vfs_unlock(vfsp);
			return (ufs_fault(ufsvfsp->vfs_root,
			    "fs = %s update: ro fs mod\n", fs->fs_fsmnt));
		}
		fs->fs_fmod = 0;
		mutex_exit(&ufsvfsp->vfs_lock);

		TRANS_SBUPDATE(ufsvfsp, vfsp, TOP_SBUPDATE_UPDATE);
	}
	vfs_unlock(vfsp);

	/*
	 * Avoid racing with ufs_update() and ufs_unmount().
	 *
	 */
	mutex_enter(&ufs_scan_lock);

	(void) ufs_scan_inodes(1, ufs_sync_inode,
	    (void *)(uintptr_t)cheap, ufsvfsp);

	mutex_exit(&ufs_scan_lock);

	bflush((dev_t)vfsp->vfs_dev);

	/*
	 * commit any outstanding async transactions
	 */
	curthread->t_flag |= T_DONTBLOCK;
	TRANS_BEGIN_SYNC(ufsvfsp, TOP_COMMIT_UPDATE, TOP_COMMIT_SIZE, error);
	if (!error) {
		TRANS_END_SYNC(ufsvfsp, error, TOP_COMMIT_UPDATE,
		    TOP_COMMIT_SIZE);
	}
	curthread->t_flag &= ~T_DONTBLOCK;

	return (0);
}


void
sbupdate(struct vfs *vfsp)
{
	struct ufsvfs *ufsvfsp = (struct ufsvfs *)vfsp->vfs_data;
	struct fs *fs = ufsvfsp->vfs_fs;
	struct buf *bp;
	int blks;
	caddr_t space;
	int i;
	size_t size;

	/*
	 * for ulockfs processing, limit the superblock writes
	 */
	if ((ufsvfsp->vfs_ulockfs.ul_sbowner) &&
	    (curthread != ufsvfsp->vfs_ulockfs.ul_sbowner)) {
		/* process later */
		fs->fs_fmod = 1;
		return;
	}
	ULOCKFS_SET_MOD((&ufsvfsp->vfs_ulockfs));

	if (TRANS_ISTRANS(ufsvfsp)) {
		mutex_enter(&ufsvfsp->vfs_lock);
		ufs_sbwrite(ufsvfsp);
		mutex_exit(&ufsvfsp->vfs_lock);
		return;
	}

	blks = howmany(fs->fs_cssize, fs->fs_fsize);
	space = (caddr_t)fs->fs_u.fs_csp;
	for (i = 0; i < blks; i += fs->fs_frag) {
		size = fs->fs_bsize;
		if (i + fs->fs_frag > blks)
			size = (blks - i) * fs->fs_fsize;
		bp = UFS_GETBLK(ufsvfsp, ufsvfsp->vfs_dev,
		    (daddr_t)(fsbtodb(fs, fs->fs_csaddr + i)),
		    fs->fs_bsize);
		bcopy(space, bp->b_un.b_addr, size);
		space += size;
		bp->b_bcount = size;
		UFS_BRWRITE(ufsvfsp, bp);
	}
	mutex_enter(&ufsvfsp->vfs_lock);
	ufs_sbwrite(ufsvfsp);
	mutex_exit(&ufsvfsp->vfs_lock);
}

int ufs_vget_idle_count = 2;	/* Number of inodes to idle each time */
static int
ufs_vget(struct vfs *vfsp, struct vnode **vpp, struct fid *fidp)
{
	int error = 0;
	struct ufid *ufid;
	struct inode *ip;
	struct ufsvfs *ufsvfsp = (struct ufsvfs *)vfsp->vfs_data;
	struct ulockfs *ulp;

	/*
	 * Check for unmounted filesystem.
	 */
	if (vfsp->vfs_flag & VFS_UNMOUNTED) {
		error = EIO;
		goto errout;
	}

	/*
	 * Keep the idle queue from getting too long by
	 * idling an inode before attempting to allocate another.
	 *    This operation must be performed before entering
	 *    lockfs or a transaction.
	 */
	if (ufs_idle_q.uq_ne > ufs_idle_q.uq_hiwat)
		if ((curthread->t_flag & T_DONTBLOCK) == 0) {
			ins.in_vidles.value.ul += ufs_vget_idle_count;
			ufs_idle_some(ufs_vget_idle_count);
		}

	ufid = (struct ufid *)fidp;

	if (error = ufs_lockfs_begin(ufsvfsp, &ulp, ULOCKFS_VGET_MASK))
		goto errout;

	rw_enter(&ufsvfsp->vfs_dqrwlock, RW_READER);

	error = ufs_iget(vfsp, ufid->ufid_ino, &ip, CRED());

	rw_exit(&ufsvfsp->vfs_dqrwlock);

	ufs_lockfs_end(ulp);

	if (error)
		goto errout;

	/*
	 * Check if the inode has been deleted or freed or is in transient state
	 * since the last VFS_VGET() request for it, release it and don't return
	 * it to the caller, presumably NFS, as it's no longer valid.
	 */
	if (ip->i_gen != ufid->ufid_gen || ip->i_mode == 0 ||
	    (ip->i_nlink <= 0)) {
		VN_RELE(ITOV(ip));
		error = EINVAL;
		goto errout;
	}

	*vpp = ITOV(ip);
	return (0);

errout:
	*vpp = NULL;
	return (error);
}

static int
ufsinit(int fstype, char *name)
{
	static const fs_operation_def_t ufs_vfsops_template[] = {
		VFSNAME_MOUNT,		{ .vfs_mount = ufs_mount },
		VFSNAME_UNMOUNT,	{ .vfs_unmount = ufs_unmount },
		VFSNAME_ROOT,		{ .vfs_root = ufs_root },
		VFSNAME_STATVFS,	{ .vfs_statvfs = ufs_statvfs },
		VFSNAME_SYNC,		{ .vfs_sync = ufs_sync },
		VFSNAME_VGET,		{ .vfs_vget = ufs_vget },
		VFSNAME_MOUNTROOT,	{ .vfs_mountroot = ufs_mountroot },
		NULL,			NULL
	};
	int error;

	ufsfstype = fstype;

	error = vfs_setfsops(fstype, ufs_vfsops_template, &ufs_vfsops);
	if (error != 0) {
		cmn_err(CE_WARN, "ufsinit: bad vfs ops template");
		return (error);
	}

	error = vn_make_ops(name, ufs_vnodeops_template, &ufs_vnodeops);
	if (error != 0) {
		(void) vfs_freevfsops_by_type(fstype);
		cmn_err(CE_WARN, "ufsinit: bad vnode ops template");
		return (error);
	}

	ufs_iinit();
	return (0);
}

#ifdef __sparc

/*
 * Mounting a mirrored SVM volume is only supported on ufs,
 * this is special-case boot code to support that configuration.
 * At this point, we have booted and mounted root on a
 * single component of the mirror.  Complete the boot
 * by configuring SVM and converting the root to the
 * dev_t of the mirrored root device.  This dev_t conversion
 * only works because the underlying device doesn't change.
 */
int
ufs_remountroot(struct vfs *vfsp)
{
	struct ufsvfs *ufsvfsp;
	struct ulockfs *ulp;
	dev_t new_rootdev;
	dev_t old_rootdev;
	struct vnode *old_rootvp;
	struct vnode *new_rootvp;
	int error, sberror = 0;
	struct inode	*ip;
	union ihead	*ih;
	struct buf	*bp;
	int i;

	old_rootdev = rootdev;
	old_rootvp = rootvp;

	new_rootdev = getrootdev();
	if (new_rootdev == (dev_t)NODEV) {
		return (ENODEV);
	}

	new_rootvp = makespecvp(new_rootdev, VBLK);

	error = VOP_OPEN(&new_rootvp,
	    (vfsp->vfs_flag & VFS_RDONLY) ? FREAD : FREAD|FWRITE, CRED(), NULL);
	if (error) {
		cmn_err(CE_CONT,
		    "Cannot open mirrored root device, error %d\n", error);
		return (error);
	}

	if (vfs_lock(vfsp) != 0) {
		return (EBUSY);
	}

	ufsvfsp = (struct ufsvfs *)vfsp->vfs_data;
	ulp = &ufsvfsp->vfs_ulockfs;

	mutex_enter(&ulp->ul_lock);
	atomic_inc_ulong(&ufs_quiesce_pend);

	(void) ufs_quiesce(ulp);
	(void) ufs_flush(vfsp);

	/*
	 * Convert root vfs to new dev_t, including vfs hash
	 * table and fs id.
	 */
	vfs_root_redev(vfsp, new_rootdev, ufsfstype);

	ufsvfsp->vfs_devvp = new_rootvp;
	ufsvfsp->vfs_dev = new_rootdev;

	bp = ufsvfsp->vfs_bufp;
	bp->b_edev = new_rootdev;
	bp->b_dev = cmpdev(new_rootdev);

	/*
	 * The buffer for the root inode does not contain a valid b_vp
	 */
	(void) bfinval(new_rootdev, 0);

	/*
	 * Here we hand-craft inodes with old root device
	 * references to refer to the new device instead.
	 */
	mutex_enter(&ufs_scan_lock);

	for (i = 0, ih = ihead; i < inohsz; i++, ih++) {
		mutex_enter(&ih_lock[i]);
		for (ip = ih->ih_chain[0];
		    ip != (struct inode *)ih;
		    ip = ip->i_forw) {
			if (ip->i_ufsvfs != ufsvfsp)
				continue;
			if (ip == ufsvfsp->vfs_qinod)
				continue;
			if (ip->i_dev == old_rootdev) {
				ip->i_dev = new_rootdev;
			}

			if (ip->i_devvp == old_rootvp) {
				ip->i_devvp = new_rootvp;
			}
		}
		mutex_exit(&ih_lock[i]);
	}

	mutex_exit(&ufs_scan_lock);

	/*
	 * Make Sure logging structures are using the new device
	 * if logging is enabled.  Also start any logging thread that
	 * needs to write to the device and couldn't earlier.
	 */
	if (ufsvfsp->vfs_log) {
		buf_t		*bp, *tbp;
		ml_unit_t	*ul = ufsvfsp->vfs_log;
		struct fs	*fsp = ufsvfsp->vfs_fs;

		/*
		 * Update the main logging structure.
		 */
		ul->un_dev = new_rootdev;

		/*
		 * Get a new bp for the on disk structures.
		 */
		bp = ul->un_bp;
		tbp = ngeteblk(dbtob(LS_SECTORS));
		tbp->b_edev = new_rootdev;
		tbp->b_dev = cmpdev(new_rootdev);
		tbp->b_blkno = bp->b_blkno;
		bcopy(bp->b_un.b_addr, tbp->b_un.b_addr, DEV_BSIZE);
		bcopy(bp->b_un.b_addr, tbp->b_un.b_addr + DEV_BSIZE, DEV_BSIZE);
		bp->b_flags |= (B_STALE | B_AGE);
		brelse(bp);
		ul->un_bp = tbp;

		/*
		 * Allocate new circular buffers.
		 */
		alloc_rdbuf(&ul->un_rdbuf, MAPBLOCKSIZE, MAPBLOCKSIZE);
		alloc_wrbuf(&ul->un_wrbuf, ldl_bufsize(ul));

		/*
		 * Clear the noroll bit which indicates that logging
		 * can't roll the log yet and start the logmap roll thread
		 * unless the filesystem is still read-only in which case
		 * remountfs() will do it when going to read-write.
		 */
		ASSERT(ul->un_flags & LDL_NOROLL);

		if (!fsp->fs_ronly) {
			ul->un_flags &= ~LDL_NOROLL;
			logmap_start_roll(ul);
		}

		/*
		 * Start the reclaim thread if needed.
		 */
		if (!fsp->fs_ronly && (fsp->fs_reclaim &
		    (FS_RECLAIM|FS_RECLAIMING))) {
			fsp->fs_reclaim &= ~FS_RECLAIM;
			fsp->fs_reclaim |= FS_RECLAIMING;
			ufs_thread_start(&ufsvfsp->vfs_reclaim,
			    ufs_thread_reclaim, vfsp);
			TRANS_SBWRITE(ufsvfsp, TOP_SBUPDATE_UPDATE);
			if (sberror = geterror(ufsvfsp->vfs_bufp)) {
				refstr_t	*mntpt;
				mntpt = vfs_getmntpoint(vfsp);
				cmn_err(CE_WARN,
				    "Remountroot failed to update Reclaim"
				    "state for filesystem %s "
				    "Error writing SuperBlock %d",
				    refstr_value(mntpt), error);
				refstr_rele(mntpt);
			}
		}
	}

	rootdev = new_rootdev;
	rootvp = new_rootvp;

	atomic_dec_ulong(&ufs_quiesce_pend);
	cv_broadcast(&ulp->ul_cv);
	mutex_exit(&ulp->ul_lock);

	vfs_unlock(vfsp);

	error = VOP_CLOSE(old_rootvp, FREAD, 1, (offset_t)0, CRED(), NULL);
	if (error) {
		cmn_err(CE_CONT,
		    "close of root device component failed, error %d\n",
		    error);
	}
	VN_RELE(old_rootvp);

	return (sberror ? sberror : error);
}

#endif	/* __sparc */
