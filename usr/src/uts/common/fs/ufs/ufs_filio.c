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
 * Copyright (c) 1991, 2010, Oracle and/or its affiliates. All rights reserved.
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
#include <sys/vnode.h>
#include <sys/proc.h>
#include <sys/disp.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <sys/flock.h>
#include <sys/atomic.h>
#include <sys/kmem.h>
#include <sys/uio.h>
#include <sys/conf.h>
#include <sys/mman.h>
#include <sys/pathname.h>
#include <sys/debug.h>
#include <sys/vmsystm.h>
#include <sys/cmn_err.h>
#include <sys/filio.h>
#include <sys/dnlc.h>

#include <sys/fs/ufs_filio.h>
#include <sys/fs/ufs_lockfs.h>
#include <sys/fs/ufs_fs.h>
#include <sys/fs/ufs_inode.h>
#include <sys/fs/ufs_fsdir.h>
#include <sys/fs/ufs_quota.h>
#include <sys/fs/ufs_trans.h>
#include <sys/fs/ufs_log.h>
#include <sys/dirent.h>		/* must be AFTER <sys/fs/fsdir.h>! */
#include <sys/errno.h>
#include <sys/sysinfo.h>

#include <vm/hat.h>
#include <vm/page.h>
#include <vm/pvn.h>
#include <vm/as.h>
#include <vm/seg.h>
#include <vm/seg_map.h>
#include <vm/seg_vn.h>
#include <vm/rm.h>
#include <sys/swap.h>
#include <sys/model.h>
#include <sys/policy.h>

#include "fs/fs_subr.h"

/*
 * ufs_fioio is the ufs equivalent of NFS_CNVT and is tailored to
 * metamucil's needs.  It may change at any time.
 */
/* ARGSUSED */
int
ufs_fioio(
	struct vnode	*vp,		/* any file on the fs */
	struct fioio	*fiou,		/* fioio struct in userland */
	int		flag,		/* flag from VOP_IOCTL() */
	struct cred	*cr)		/* credentials from ufs_ioctl */
{
	int		error	= 0;
	struct vnode	*vpio	= NULL;	/* vnode for inode open */
	struct inode	*ipio	= NULL;	/* inode for inode open */
	struct file	*fpio	= NULL;	/* file  for inode open */
	struct inode	*ip;		/* inode for file system */
	struct fs	*fs;		/* fs    for file system */
	STRUCT_DECL(fioio, fio);	/* copy of user's fioio struct */

	/*
	 * must be privileged
	 */
	if (secpolicy_fs_config(cr, vp->v_vfsp) != 0)
		return (EPERM);

	STRUCT_INIT(fio, flag & DATAMODEL_MASK);

	/*
	 * get user's copy of fioio struct
	 */
	if (copyin(fiou, STRUCT_BUF(fio), STRUCT_SIZE(fio)))
		return (EFAULT);

	ip = VTOI(vp);
	fs = ip->i_fs;

	/*
	 * check the inode number against the fs's inode number bounds
	 */
	if (STRUCT_FGET(fio, fio_ino) < UFSROOTINO)
		return (ESRCH);
	if (STRUCT_FGET(fio, fio_ino) >= fs->fs_ncg * fs->fs_ipg)
		return (ESRCH);

	rw_enter(&ip->i_ufsvfs->vfs_dqrwlock, RW_READER);

	/*
	 * get the inode
	 */
	error = ufs_iget(ip->i_vfs, STRUCT_FGET(fio, fio_ino), &ipio, cr);

	rw_exit(&ip->i_ufsvfs->vfs_dqrwlock);

	if (error)
		return (error);

	/*
	 * check the generation number
	 */
	rw_enter(&ipio->i_contents, RW_READER);
	if (ipio->i_gen != STRUCT_FGET(fio, fio_gen)) {
		error = ESTALE;
		rw_exit(&ipio->i_contents);
		goto errout;
	}

	/*
	 * check if the inode is free
	 */
	if (ipio->i_mode == 0) {
		error = ENOENT;
		rw_exit(&ipio->i_contents);
		goto errout;
	}
	rw_exit(&ipio->i_contents);

	/*
	 *	Adapted from copen: get a file struct
	 *	Large Files: We open this file descriptor with FOFFMAX flag
	 *	set so that it will be like a large file open.
	 */
	if (falloc(NULL, (FREAD|FOFFMAX), &fpio, STRUCT_FADDR(fio, fio_fd)))
		goto errout;

	/*
	 *	Adapted from vn_open: check access and then open the file
	 */
	vpio = ITOV(ipio);
	if (error = VOP_ACCESS(vpio, VREAD, 0, cr, NULL))
		goto errout;

	if (error = VOP_OPEN(&vpio, FREAD, cr, NULL))
		goto errout;

	/*
	 *	Adapted from copen: initialize the file struct
	 */
	fpio->f_vnode = vpio;

	/*
	 * return the fd
	 */
	if (copyout(STRUCT_BUF(fio), fiou, STRUCT_SIZE(fio))) {
		error = EFAULT;
		goto errout;
	}
	setf(STRUCT_FGET(fio, fio_fd), fpio);
	mutex_exit(&fpio->f_tlock);
	return (0);
errout:
	/*
	 * free the file struct and fd
	 */
	if (fpio) {
		setf(STRUCT_FGET(fio, fio_fd), NULL);
		unfalloc(fpio);
	}

	/*
	 * release the hold on the inode
	 */
	if (ipio)
		VN_RELE(ITOV(ipio));
	return (error);
}

/*
 * ufs_fiosatime
 *	set access time w/o altering change time.  This ioctl is tailored
 *	to metamucil's needs and may change at any time.
 */
int
ufs_fiosatime(
	struct vnode	*vp,		/* file's vnode */
	struct timeval	*tvu,		/* struct timeval in userland */
	int		flag,		/* flag from VOP_IOCTL() */
	struct cred	*cr)		/* credentials from ufs_ioctl */
{
	struct inode	*ip;		/* inode for vp */
	struct timeval32 tv;		/* copy of user's timeval */
	int now = 0;

	/*
	 * must have sufficient privileges
	 */
	if (secpolicy_fs_config(cr, vp->v_vfsp) != 0)
		return (EPERM);

	/*
	 * get user's copy of timeval struct and check values
	 * if input is NULL, will set time to now
	 */
	if (tvu == NULL) {
		now = 1;
	} else {
		if ((flag & DATAMODEL_MASK) == DATAMODEL_ILP32) {
			if (copyin(tvu, &tv, sizeof (tv)))
				return (EFAULT);
		} else {
			struct timeval tv64;

			if (copyin(tvu, &tv64, sizeof (tv64)))
				return (EFAULT);
			if (TIMEVAL_OVERFLOW(&tv64))
				return (EOVERFLOW);
			TIMEVAL_TO_TIMEVAL32(&tv, &tv64);
		}

		if (tv.tv_usec < 0 || tv.tv_usec >= 1000000)
			return (EINVAL);
	}

	/*
	 * update access time
	 */
	ip = VTOI(vp);
	rw_enter(&ip->i_contents, RW_WRITER);
	ITIMES_NOLOCK(ip);
	if (now) {
		mutex_enter(&ufs_iuniqtime_lock);
		ip->i_atime = iuniqtime;
		mutex_exit(&ufs_iuniqtime_lock);
	} else {
		ip->i_atime = tv;
	}
	ip->i_flag |= IMODACC;
	rw_exit(&ip->i_contents);

	return (0);
}

/*
 * ufs_fiogdio
 *	Get delayed-io state.  This ioctl is tailored
 *	to metamucil's needs and may change at any time.
 */
/* ARGSUSED */
int
ufs_fiogdio(
	struct vnode	*vp,		/* file's vnode */
	uint_t		*diop,		/* dio state returned here */
	int		flag,		/* flag from ufs_ioctl */
	struct cred	*cr)		/* credentials from ufs_ioctl */
{
	struct ufsvfs	*ufsvfsp	= VTOI(vp)->i_ufsvfs;

	/*
	 * forcibly unmounted
	 */
	if (ufsvfsp == NULL)
		return (EIO);

	if (suword32(diop, ufsvfsp->vfs_dio))
		return (EFAULT);
	return (0);
}

/*
 * ufs_fiosdio
 *	Set delayed-io state.  This ioctl is tailored
 *	to metamucil's needs and may change at any time.
 */
int
ufs_fiosdio(
	struct vnode	*vp,		/* file's vnode */
	uint_t		*diop,		/* dio flag */
	int		flag,		/* flag from ufs_ioctl */
	struct cred	*cr)		/* credentials from ufs_ioctl */
{
	uint_t		dio;		/* copy of user's dio */
	struct inode	*ip;		/* inode for vp */
	struct ufsvfs	*ufsvfsp;
	struct fs	*fs;
	struct ulockfs	*ulp;
	int		error = 0;

#ifdef lint
	flag = flag;
#endif

	/* check input conditions */
	if (secpolicy_fs_config(cr, vp->v_vfsp) != 0)
		return (EPERM);

	if (copyin(diop, &dio, sizeof (dio)))
		return (EFAULT);

	if (dio > 1)
		return (EINVAL);

	/* file system has been forcibly unmounted */
	if (VTOI(vp)->i_ufsvfs == NULL)
		return (EIO);

	ip = VTOI(vp);
	ufsvfsp = ip->i_ufsvfs;
	ulp = &ufsvfsp->vfs_ulockfs;

	/* logging file system; dio ignored */
	if (TRANS_ISTRANS(ufsvfsp))
		return (error);

	/* hold the mutex to prevent race with a lockfs request */
	vfs_lock_wait(vp->v_vfsp);
	mutex_enter(&ulp->ul_lock);
	atomic_inc_ulong(&ufs_quiesce_pend);

	if (ULOCKFS_IS_HLOCK(ulp)) {
		error = EIO;
		goto out;
	}

	if (ULOCKFS_IS_ELOCK(ulp)) {
		error = EBUSY;
		goto out;
	}
	/* wait for outstanding accesses to finish */
	if (error = ufs_quiesce(ulp))
		goto out;

	/* flush w/invalidate */
	if (error = ufs_flush(vp->v_vfsp))
		goto out;

	/*
	 * update dio
	 */
	mutex_enter(&ufsvfsp->vfs_lock);
	ufsvfsp->vfs_dio = dio;

	/*
	 * enable/disable clean flag processing
	 */
	fs = ip->i_fs;
	if (fs->fs_ronly == 0 &&
	    fs->fs_clean != FSBAD &&
	    fs->fs_clean != FSLOG) {
		if (dio)
			fs->fs_clean = FSSUSPEND;
		else
			fs->fs_clean = FSACTIVE;
		ufs_sbwrite(ufsvfsp);
		mutex_exit(&ufsvfsp->vfs_lock);
	} else
		mutex_exit(&ufsvfsp->vfs_lock);
out:
	/*
	 * we need this broadcast because of the ufs_quiesce call above
	 */
	atomic_dec_ulong(&ufs_quiesce_pend);
	cv_broadcast(&ulp->ul_cv);
	mutex_exit(&ulp->ul_lock);
	vfs_unlock(vp->v_vfsp);
	return (error);
}

/*
 * ufs_fioffs - ioctl handler for flushing file system
 */
/* ARGSUSED */
int
ufs_fioffs(
	struct vnode	*vp,
	char 		*vap,		/* must be NULL - reserved */
	struct cred	*cr)		/* credentials from ufs_ioctl */
{
	int error;
	struct ufsvfs	*ufsvfsp;
	struct ulockfs	*ulp;

	/* file system has been forcibly unmounted */
	ufsvfsp = VTOI(vp)->i_ufsvfs;
	if (ufsvfsp == NULL)
		return (EIO);

	ulp = &ufsvfsp->vfs_ulockfs;

	/*
	 * suspend the delete thread
	 *	this must be done outside the lockfs locking protocol
	 */
	vfs_lock_wait(vp->v_vfsp);
	ufs_thread_suspend(&ufsvfsp->vfs_delete);

	/* hold the mutex to prevent race with a lockfs request */
	mutex_enter(&ulp->ul_lock);
	atomic_inc_ulong(&ufs_quiesce_pend);

	if (ULOCKFS_IS_HLOCK(ulp)) {
		error = EIO;
		goto out;
	}
	if (ULOCKFS_IS_ELOCK(ulp)) {
		error = EBUSY;
		goto out;
	}
	/* wait for outstanding accesses to finish */
	if (error = ufs_quiesce(ulp))
		goto out;

	/*
	 * If logging, and the logmap was marked as not rollable,
	 * make it rollable now, and start the trans_roll thread and
	 * the reclaim thread.  The log at this point is safe to write to.
	 */
	if (ufsvfsp->vfs_log) {
		ml_unit_t	*ul = ufsvfsp->vfs_log;
		struct fs	*fsp = ufsvfsp->vfs_fs;
		int		err;

		if (ul->un_flags & LDL_NOROLL) {
			ul->un_flags &= ~LDL_NOROLL;
			logmap_start_roll(ul);
			if (!fsp->fs_ronly && (fsp->fs_reclaim &
			    (FS_RECLAIM|FS_RECLAIMING))) {
				fsp->fs_reclaim &= ~FS_RECLAIM;
				fsp->fs_reclaim |= FS_RECLAIMING;
				ufs_thread_start(&ufsvfsp->vfs_reclaim,
				    ufs_thread_reclaim, vp->v_vfsp);
				if (!fsp->fs_ronly) {
					TRANS_SBWRITE(ufsvfsp,
					    TOP_SBUPDATE_UPDATE);
					if (err =
					    geterror(ufsvfsp->vfs_bufp)) {
						refstr_t	*mntpt;
						mntpt = vfs_getmntpoint(
						    vp->v_vfsp);
						cmn_err(CE_NOTE,
						    "Filesystem Flush "
						    "Failed to update "
						    "Reclaim Status for "
						    " %s, Write failed to "
						    "update superblock, "
						    "error %d",
						    refstr_value(mntpt),
						    err);
						refstr_rele(mntpt);
					}
				}
			}
		}
	}

	/* synchronously flush dirty data and metadata */
	error = ufs_flush(vp->v_vfsp);

out:
	atomic_dec_ulong(&ufs_quiesce_pend);
	cv_broadcast(&ulp->ul_cv);
	mutex_exit(&ulp->ul_lock);
	vfs_unlock(vp->v_vfsp);

	/*
	 * allow the delete thread to continue
	 */
	ufs_thread_continue(&ufsvfsp->vfs_delete);
	return (error);
}

/*
 * ufs_fioisbusy
 *	Get number of references on this vnode.
 *	Contract-private interface for Legato's NetWorker product.
 */
/* ARGSUSED */
int
ufs_fioisbusy(struct vnode *vp, int *isbusy, struct cred *cr)
{
	int is_it_busy;

	/*
	 * The caller holds one reference, there may be one in the dnlc
	 * so we need to flush it.
	 */
	if (vp->v_count > 1)
		dnlc_purge_vp(vp);
	/*
	 * Since we've just flushed the dnlc and we hold a reference
	 * to this vnode, then anything but 1 means busy (this had
	 * BETTER not be zero!). Also, it's possible for someone to
	 * have this file mmap'ed with no additional reference count.
	 */
	ASSERT(vp->v_count > 0);
	if ((vp->v_count == 1) && (VTOI(vp)->i_mapcnt == 0))
		is_it_busy = 0;
	else
		is_it_busy = 1;

	if (suword32(isbusy, is_it_busy))
		return (EFAULT);
	return (0);
}

/* ARGSUSED */
int
ufs_fiodirectio(struct vnode *vp, int cmd, struct cred *cr)
{
	int		error	= 0;
	struct inode	*ip	= VTOI(vp);

	/*
	 * Acquire reader lock and set/reset direct mode
	 */
	rw_enter(&ip->i_contents, RW_READER);
	mutex_enter(&ip->i_tlock);
	if (cmd == DIRECTIO_ON)
		ip->i_flag |= IDIRECTIO;	/* enable direct mode */
	else if (cmd == DIRECTIO_OFF)
		ip->i_flag &= ~IDIRECTIO;	/* disable direct mode */
	else
		error = EINVAL;
	mutex_exit(&ip->i_tlock);
	rw_exit(&ip->i_contents);
	return (error);
}

/*
 * ufs_fiotune
 *	Allow some tunables to be set on a mounted fs
 */
int
ufs_fiotune(struct vnode *vp, struct fiotune *uftp, struct cred *cr)
{
	struct fiotune	ftp;
	struct fs	*fs;
	struct ufsvfs	*ufsvfsp;

	/*
	 * must have sufficient privileges
	 */
	if (secpolicy_fs_config(cr, vp->v_vfsp) != 0)
		return (EPERM);

	/*
	 * get user's copy
	 */
	if (copyin(uftp, &ftp, sizeof (ftp)))
		return (EFAULT);

	/*
	 * some minimal sanity checks
	 */
	if ((ftp.maxcontig <= 0) ||
	    (ftp.rotdelay != 0) ||
	    (ftp.maxbpg <= 0) ||
	    (ftp.minfree < 0) ||
	    (ftp.minfree > 99) ||
	    ((ftp.optim != FS_OPTTIME) && (ftp.optim != FS_OPTSPACE)))
		return (EINVAL);

	/*
	 * update superblock but don't write it!  If it gets out, fine.
	 */
	fs = VTOI(vp)->i_fs;

	fs->fs_maxcontig = ftp.maxcontig;
	fs->fs_rotdelay = ftp.rotdelay;
	fs->fs_maxbpg = ftp.maxbpg;
	fs->fs_minfree = ftp.minfree;
	fs->fs_optim = ftp.optim;

	/*
	 * Adjust cluster based on the new maxcontig. The cluster size
	 * can be any positive value. The check for this is done above.
	 */
	ufsvfsp = VTOI(vp)->i_ufsvfs;
	ufsvfsp->vfs_ioclustsz = fs->fs_bsize * fs->fs_maxcontig;

	/*
	 * Adjust minfrags from minfree
	 */
	ufsvfsp->vfs_minfrags = (int)((int64_t)fs->fs_dsize *
	    fs->fs_minfree / 100);

	/*
	 * Write the superblock
	 */
	if (fs->fs_ronly == 0) {
		TRANS_BEGIN_ASYNC(ufsvfsp, TOP_SBUPDATE_UPDATE,
		    TOP_SBWRITE_SIZE);
		TRANS_SBWRITE(ufsvfsp, TOP_SBUPDATE_UPDATE);
		TRANS_END_ASYNC(ufsvfsp, TOP_SBUPDATE_UPDATE, TOP_SBWRITE_SIZE);
	}

	return (0);
}

/*
 * Lseek support for finding holes (cmd == _FIO_SEEK_HOLE) and
 * data (cmd == _FIO_SEEK_DATA). "off" is an in/out parameter.
 */
int
ufs_fio_holey(vnode_t *vp, int cmd, offset_t *off)
{
	inode_t	*ip = VTOI(vp);
	u_offset_t noff = (u_offset_t)*off; /* new offset */
	u_offset_t isz;
	int error;
	boolean_t hole;

	rw_enter(&ip->i_contents, RW_READER);
	isz = ip->i_size;
	if (noff >= isz)  {
		rw_exit(&ip->i_contents);
		return (ENXIO);
	}

	/*
	 * Check for the usual case where a file has no holes.
	 * If so we can optimise to set the end of the file as the first
	 * (virtual) hole. This avoids bmap_find() searching through
	 * every block in the file for a (non-existent) hole.
	 */
	if (!bmap_has_holes(ip)) {
		rw_exit(&ip->i_contents);
		if (cmd == _FIO_SEEK_HOLE) {
			*off = isz;
			return (0);
		}
		/* *off must already point to valid data (non hole) */
		return (0);
	}

	/*
	 * Calling bmap_read() one block at a time on a 1TB file takes forever,
	 * so we use a special function to search for holes or blocks.
	 */
	if (cmd == _FIO_SEEK_HOLE)
		hole = B_TRUE;
	else
		hole = B_FALSE;
	error = bmap_find(ip, hole, &noff);
	rw_exit(&ip->i_contents);

	/* end of file? */
	if (error == ENXIO) {
		/*
		 * Handle the virtual hole at the end of file.
		 */
		if (cmd == _FIO_SEEK_HOLE) {
			*off = isz;
			return (0);
		}
		return (ENXIO);
	}
	if (noff < *off)
		return (error);
	*off = noff;
	return (error);
}

int
ufs_mark_compressed(struct vnode *vp)
{
	struct inode *ip = VTOI(vp);
	struct ufsvfs *ufsvfsp = ip->i_ufsvfs;

	if (vp->v_type != VREG)
		return (EINVAL);

	rw_enter(&ip->i_contents, RW_WRITER);
	ip->i_cflags |= ICOMPRESS;
	TRANS_INODE(ufsvfsp, ip);
	ip->i_flag |= (ICHG|ISEQ);
	ip->i_seq++;
	if (!TRANS_ISTRANS(ufsvfsp))
		ufs_iupdat(ip, I_ASYNC);
	rw_exit(&ip->i_contents);

	return (0);
}
