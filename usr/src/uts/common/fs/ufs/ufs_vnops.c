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
 * Copyright (c) 1984, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2015, Joyent, Inc.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/ksynch.h>
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
#include <sys/vnode.h>
#include <sys/proc.h>
#include <sys/disp.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <sys/flock.h>
#include <sys/atomic.h>
#include <sys/kmem.h>
#include <sys/uio.h>
#include <sys/dnlc.h>
#include <sys/conf.h>
#include <sys/mman.h>
#include <sys/pathname.h>
#include <sys/debug.h>
#include <sys/vmsystm.h>
#include <sys/cmn_err.h>
#include <sys/filio.h>
#include <sys/policy.h>

#include <sys/fs/ufs_fs.h>
#include <sys/fs/ufs_lockfs.h>
#include <sys/fs/ufs_filio.h>
#include <sys/fs/ufs_inode.h>
#include <sys/fs/ufs_fsdir.h>
#include <sys/fs/ufs_quota.h>
#include <sys/fs/ufs_log.h>
#include <sys/fs/ufs_snap.h>
#include <sys/fs/ufs_trans.h>
#include <sys/fs/ufs_panic.h>
#include <sys/fs/ufs_bio.h>
#include <sys/dirent.h>		/* must be AFTER <sys/fs/fsdir.h>! */
#include <sys/errno.h>
#include <sys/fssnap_if.h>
#include <sys/unistd.h>
#include <sys/sunddi.h>

#include <sys/filio.h>		/* _FIOIO */

#include <vm/hat.h>
#include <vm/page.h>
#include <vm/pvn.h>
#include <vm/as.h>
#include <vm/seg.h>
#include <vm/seg_map.h>
#include <vm/seg_vn.h>
#include <vm/seg_kmem.h>
#include <vm/rm.h>
#include <sys/swap.h>

#include <fs/fs_subr.h>

#include <sys/fs/decomp.h>

static struct instats ins;

static 	int ufs_getpage_ra(struct vnode *, u_offset_t, struct seg *, caddr_t);
static	int ufs_getpage_miss(struct vnode *, u_offset_t, size_t, struct seg *,
		caddr_t, struct page **, size_t, enum seg_rw, int);
static	int ufs_open(struct vnode **, int, struct cred *, caller_context_t *);
static	int ufs_close(struct vnode *, int, int, offset_t, struct cred *,
		caller_context_t *);
static	int ufs_read(struct vnode *, struct uio *, int, struct cred *,
		struct caller_context *);
static	int ufs_write(struct vnode *, struct uio *, int, struct cred *,
		struct caller_context *);
static	int ufs_ioctl(struct vnode *, int, intptr_t, int, struct cred *,
		int *, caller_context_t *);
static	int ufs_getattr(struct vnode *, struct vattr *, int, struct cred *,
		caller_context_t *);
static	int ufs_setattr(struct vnode *, struct vattr *, int, struct cred *,
		caller_context_t *);
static	int ufs_access(struct vnode *, int, int, struct cred *,
		caller_context_t *);
static	int ufs_lookup(struct vnode *, char *, struct vnode **,
		struct pathname *, int, struct vnode *, struct cred *,
		caller_context_t *, int *, pathname_t *);
static	int ufs_create(struct vnode *, char *, struct vattr *, enum vcexcl,
		int, struct vnode **, struct cred *, int,
		caller_context_t *, vsecattr_t  *);
static	int ufs_remove(struct vnode *, char *, struct cred *,
		caller_context_t *, int);
static	int ufs_link(struct vnode *, struct vnode *, char *, struct cred *,
		caller_context_t *, int);
static	int ufs_rename(struct vnode *, char *, struct vnode *, char *,
		struct cred *, caller_context_t *, int);
static	int ufs_mkdir(struct vnode *, char *, struct vattr *, struct vnode **,
		struct cred *, caller_context_t *, int, vsecattr_t *);
static	int ufs_rmdir(struct vnode *, char *, struct vnode *, struct cred *,
		caller_context_t *, int);
static	int ufs_readdir(struct vnode *, struct uio *, struct cred *, int *,
		caller_context_t *, int);
static	int ufs_symlink(struct vnode *, char *, struct vattr *, char *,
		struct cred *, caller_context_t *, int);
static	int ufs_readlink(struct vnode *, struct uio *, struct cred *,
		caller_context_t *);
static	int ufs_fsync(struct vnode *, int, struct cred *, caller_context_t *);
static	void ufs_inactive(struct vnode *, struct cred *, caller_context_t *);
static	int ufs_fid(struct vnode *, struct fid *, caller_context_t *);
static	int ufs_rwlock(struct vnode *, int, caller_context_t *);
static	void ufs_rwunlock(struct vnode *, int, caller_context_t *);
static	int ufs_seek(struct vnode *, offset_t, offset_t *, caller_context_t *);
static	int ufs_frlock(struct vnode *, int, struct flock64 *, int, offset_t,
		struct flk_callback *, struct cred *,
		caller_context_t *);
static  int ufs_space(struct vnode *, int, struct flock64 *, int, offset_t,
		cred_t *, caller_context_t *);
static	int ufs_getpage(struct vnode *, offset_t, size_t, uint_t *,
		struct page **, size_t, struct seg *, caddr_t,
		enum seg_rw, struct cred *, caller_context_t *);
static	int ufs_putpage(struct vnode *, offset_t, size_t, int, struct cred *,
		caller_context_t *);
static	int ufs_putpages(struct vnode *, offset_t, size_t, int, struct cred *);
static	int ufs_map(struct vnode *, offset_t, struct as *, caddr_t *, size_t,
		uchar_t, uchar_t, uint_t, struct cred *, caller_context_t *);
static	int ufs_addmap(struct vnode *, offset_t, struct as *, caddr_t,  size_t,
		uchar_t, uchar_t, uint_t, struct cred *, caller_context_t *);
static	int ufs_delmap(struct vnode *, offset_t, struct as *, caddr_t,  size_t,
		uint_t, uint_t, uint_t, struct cred *, caller_context_t *);
static	int ufs_poll(vnode_t *, short, int, short *, struct pollhead **,
		caller_context_t *);
static	int ufs_dump(vnode_t *, caddr_t, offset_t, offset_t,
    caller_context_t *);
static	int ufs_l_pathconf(struct vnode *, int, ulong_t *, struct cred *,
		caller_context_t *);
static	int ufs_pageio(struct vnode *, struct page *, u_offset_t, size_t, int,
		struct cred *, caller_context_t *);
static	int ufs_dumpctl(vnode_t *, int, offset_t *, caller_context_t *);
static	daddr32_t *save_dblks(struct inode *, struct ufsvfs *, daddr32_t *,
		daddr32_t *, int, int);
static	int ufs_getsecattr(struct vnode *, vsecattr_t *, int, struct cred *,
		caller_context_t *);
static	int ufs_setsecattr(struct vnode *, vsecattr_t *, int, struct cred *,
		caller_context_t *);
static	int ufs_priv_access(void *, int, struct cred *);
static	int ufs_eventlookup(struct vnode *, char *, struct cred *,
    struct vnode **);
extern int as_map_locked(struct as *, caddr_t, size_t, int ((*)()), void *);

/*
 * For lockfs: ulockfs begin/end is now inlined in the ufs_xxx functions.
 *
 * XXX - ULOCKFS in fs_pathconf and ufs_ioctl is not inlined yet.
 */
struct vnodeops *ufs_vnodeops;

/* NOTE: "not blkd" below  means that the operation isn't blocked by lockfs */
const fs_operation_def_t ufs_vnodeops_template[] = {
	VOPNAME_OPEN,		{ .vop_open = ufs_open },	/* not blkd */
	VOPNAME_CLOSE,		{ .vop_close = ufs_close },	/* not blkd */
	VOPNAME_READ,		{ .vop_read = ufs_read },
	VOPNAME_WRITE,		{ .vop_write = ufs_write },
	VOPNAME_IOCTL,		{ .vop_ioctl = ufs_ioctl },
	VOPNAME_GETATTR,	{ .vop_getattr = ufs_getattr },
	VOPNAME_SETATTR,	{ .vop_setattr = ufs_setattr },
	VOPNAME_ACCESS,		{ .vop_access = ufs_access },
	VOPNAME_LOOKUP,		{ .vop_lookup = ufs_lookup },
	VOPNAME_CREATE,		{ .vop_create = ufs_create },
	VOPNAME_REMOVE,		{ .vop_remove = ufs_remove },
	VOPNAME_LINK,		{ .vop_link = ufs_link },
	VOPNAME_RENAME,		{ .vop_rename = ufs_rename },
	VOPNAME_MKDIR,		{ .vop_mkdir = ufs_mkdir },
	VOPNAME_RMDIR,		{ .vop_rmdir = ufs_rmdir },
	VOPNAME_READDIR,	{ .vop_readdir = ufs_readdir },
	VOPNAME_SYMLINK,	{ .vop_symlink = ufs_symlink },
	VOPNAME_READLINK,	{ .vop_readlink = ufs_readlink },
	VOPNAME_FSYNC,		{ .vop_fsync = ufs_fsync },
	VOPNAME_INACTIVE,	{ .vop_inactive = ufs_inactive }, /* not blkd */
	VOPNAME_FID,		{ .vop_fid = ufs_fid },
	VOPNAME_RWLOCK,		{ .vop_rwlock = ufs_rwlock },	/* not blkd */
	VOPNAME_RWUNLOCK,	{ .vop_rwunlock = ufs_rwunlock }, /* not blkd */
	VOPNAME_SEEK,		{ .vop_seek = ufs_seek },
	VOPNAME_FRLOCK,		{ .vop_frlock = ufs_frlock },
	VOPNAME_SPACE,		{ .vop_space = ufs_space },
	VOPNAME_GETPAGE,	{ .vop_getpage = ufs_getpage },
	VOPNAME_PUTPAGE,	{ .vop_putpage = ufs_putpage },
	VOPNAME_MAP,		{ .vop_map = ufs_map },
	VOPNAME_ADDMAP,		{ .vop_addmap = ufs_addmap },	/* not blkd */
	VOPNAME_DELMAP,		{ .vop_delmap = ufs_delmap },	/* not blkd */
	VOPNAME_POLL,		{ .vop_poll = ufs_poll },	/* not blkd */
	VOPNAME_DUMP,		{ .vop_dump = ufs_dump },
	VOPNAME_PATHCONF,	{ .vop_pathconf = ufs_l_pathconf },
	VOPNAME_PAGEIO,		{ .vop_pageio = ufs_pageio },
	VOPNAME_DUMPCTL,	{ .vop_dumpctl = ufs_dumpctl },
	VOPNAME_GETSECATTR,	{ .vop_getsecattr = ufs_getsecattr },
	VOPNAME_SETSECATTR,	{ .vop_setsecattr = ufs_setsecattr },
	VOPNAME_VNEVENT,	{ .vop_vnevent = fs_vnevent_support },
	NULL,			NULL
};

#define	MAX_BACKFILE_COUNT	9999

/*
 * Created by ufs_dumpctl() to store a file's disk block info into memory.
 * Used by ufs_dump() to dump data to disk directly.
 */
struct dump {
	struct inode	*ip;		/* the file we contain */
	daddr_t		fsbs;		/* number of blocks stored */
	struct timeval32 time;		/* time stamp for the struct */
	daddr32_t 	dblk[1];	/* place holder for block info */
};

static struct dump *dump_info = NULL;

/*
 * Previously there was no special action required for ordinary files.
 * (Devices are handled through the device file system.)
 * Now we support Large Files and Large File API requires open to
 * fail if file is large.
 * We could take care to prevent data corruption
 * by doing an atomic check of size and truncate if file is opened with
 * FTRUNC flag set but traditionally this is being done by the vfs/vnode
 * layers. So taking care of truncation here is a change in the existing
 * semantics of VOP_OPEN and therefore we chose not to implement any thing
 * here. The check for the size of the file > 2GB is being done at the
 * vfs layer in routine vn_open().
 */

/* ARGSUSED */
static int
ufs_open(struct vnode **vpp, int flag, struct cred *cr, caller_context_t *ct)
{
	return (0);
}

/*ARGSUSED*/
static int
ufs_close(struct vnode *vp, int flag, int count, offset_t offset,
	struct cred *cr, caller_context_t *ct)
{
	cleanlocks(vp, ttoproc(curthread)->p_pid, 0);
	cleanshares(vp, ttoproc(curthread)->p_pid);

	/*
	 * Push partially filled cluster at last close.
	 * ``last close'' is approximated because the dnlc
	 * may have a hold on the vnode.
	 * Checking for VBAD here will also act as a forced umount check.
	 */
	if (vp->v_count <= 2 && vp->v_type != VBAD) {
		struct inode *ip = VTOI(vp);
		if (ip->i_delaylen) {
			ins.in_poc.value.ul++;
			(void) ufs_putpages(vp, ip->i_delayoff, ip->i_delaylen,
			    B_ASYNC | B_FREE, cr);
			ip->i_delaylen = 0;
		}
	}

	return (0);
}

/*ARGSUSED*/
static int
ufs_read(struct vnode *vp, struct uio *uiop, int ioflag, struct cred *cr,
	struct caller_context *ct)
{
	struct inode *ip = VTOI(vp);
	struct ufsvfs *ufsvfsp;
	struct ulockfs *ulp = NULL;
	int error = 0;
	int intrans = 0;

	ASSERT(RW_READ_HELD(&ip->i_rwlock));

	/*
	 * Mandatory locking needs to be done before ufs_lockfs_begin()
	 * and TRANS_BEGIN_SYNC() calls since mandatory locks can sleep.
	 */
	if (MANDLOCK(vp, ip->i_mode)) {
		/*
		 * ufs_getattr ends up being called by chklock
		 */
		error = chklock(vp, FREAD, uiop->uio_loffset,
		    uiop->uio_resid, uiop->uio_fmode, ct);
		if (error)
			goto out;
	}

	ufsvfsp = ip->i_ufsvfs;
	error = ufs_lockfs_begin(ufsvfsp, &ulp, ULOCKFS_READ_MASK);
	if (error)
		goto out;

	/*
	 * In the case that a directory is opened for reading as a file
	 * (eg "cat .") with the  O_RSYNC, O_SYNC and O_DSYNC flags set.
	 * The locking order had to be changed to avoid a deadlock with
	 * an update taking place on that directory at the same time.
	 */
	if ((ip->i_mode & IFMT) == IFDIR) {

		rw_enter(&ip->i_contents, RW_READER);
		error = rdip(ip, uiop, ioflag, cr);
		rw_exit(&ip->i_contents);

		if (error) {
			if (ulp)
				ufs_lockfs_end(ulp);
			goto out;
		}

		if (ulp && (ioflag & FRSYNC) && (ioflag & (FSYNC | FDSYNC)) &&
		    TRANS_ISTRANS(ufsvfsp)) {
			rw_exit(&ip->i_rwlock);
			TRANS_BEGIN_SYNC(ufsvfsp, TOP_READ_SYNC, TOP_READ_SIZE,
			    error);
			ASSERT(!error);
			TRANS_END_SYNC(ufsvfsp, error, TOP_READ_SYNC,
			    TOP_READ_SIZE);
			rw_enter(&ip->i_rwlock, RW_READER);
		}
	} else {
		/*
		 * Only transact reads to files opened for sync-read and
		 * sync-write on a file system that is not write locked.
		 *
		 * The ``not write locked'' check prevents problems with
		 * enabling/disabling logging on a busy file system.  E.g.,
		 * logging exists at the beginning of the read but does not
		 * at the end.
		 *
		 */
		if (ulp && (ioflag & FRSYNC) && (ioflag & (FSYNC | FDSYNC)) &&
		    TRANS_ISTRANS(ufsvfsp)) {
			TRANS_BEGIN_SYNC(ufsvfsp, TOP_READ_SYNC, TOP_READ_SIZE,
			    error);
			ASSERT(!error);
			intrans = 1;
		}

		rw_enter(&ip->i_contents, RW_READER);
		error = rdip(ip, uiop, ioflag, cr);
		rw_exit(&ip->i_contents);

		if (intrans) {
			TRANS_END_SYNC(ufsvfsp, error, TOP_READ_SYNC,
			    TOP_READ_SIZE);
		}
	}

	if (ulp) {
		ufs_lockfs_end(ulp);
	}
out:

	return (error);
}

extern	int	ufs_HW;		/* high water mark */
extern	int	ufs_LW;		/* low water mark */
int	ufs_WRITES = 1;		/* XXX - enable/disable */
int	ufs_throttles = 0;	/* throttling count */
int	ufs_allow_shared_writes = 1;	/* directio shared writes */

static int
ufs_check_rewrite(struct inode *ip, struct uio *uiop, int ioflag)
{
	int	shared_write;

	/*
	 * If the FDSYNC flag is set then ignore the global
	 * ufs_allow_shared_writes in this case.
	 */
	shared_write = (ioflag & FDSYNC) | ufs_allow_shared_writes;

	/*
	 * Filter to determine if this request is suitable as a
	 * concurrent rewrite. This write must not allocate blocks
	 * by extending the file or filling in holes. No use trying
	 * through FSYNC descriptors as the inode will be synchronously
	 * updated after the write. The uio structure has not yet been
	 * checked for sanity, so assume nothing.
	 */
	return (((ip->i_mode & IFMT) == IFREG) && !(ioflag & FAPPEND) &&
	    (uiop->uio_loffset >= (offset_t)0) &&
	    (uiop->uio_loffset < ip->i_size) && (uiop->uio_resid > 0) &&
	    ((ip->i_size - uiop->uio_loffset) >= uiop->uio_resid) &&
	    !(ioflag & FSYNC) && !bmap_has_holes(ip) &&
	    shared_write);
}

/*ARGSUSED*/
static int
ufs_write(struct vnode *vp, struct uio *uiop, int ioflag, cred_t *cr,
	caller_context_t *ct)
{
	struct inode *ip = VTOI(vp);
	struct ufsvfs *ufsvfsp;
	struct ulockfs *ulp;
	int retry = 1;
	int error, resv, resid = 0;
	int directio_status;
	int exclusive;
	int rewriteflg;
	long start_resid = uiop->uio_resid;

	ASSERT(RW_LOCK_HELD(&ip->i_rwlock));

retry_mandlock:
	/*
	 * Mandatory locking needs to be done before ufs_lockfs_begin()
	 * and TRANS_BEGIN_[A]SYNC() calls since mandatory locks can sleep.
	 * Check for forced unmounts normally done in ufs_lockfs_begin().
	 */
	if ((ufsvfsp = ip->i_ufsvfs) == NULL) {
		error = EIO;
		goto out;
	}
	if (MANDLOCK(vp, ip->i_mode)) {

		ASSERT(RW_WRITE_HELD(&ip->i_rwlock));

		/*
		 * ufs_getattr ends up being called by chklock
		 */
		error = chklock(vp, FWRITE, uiop->uio_loffset,
		    uiop->uio_resid, uiop->uio_fmode, ct);
		if (error)
			goto out;
	}

	/* i_rwlock can change in chklock */
	exclusive = rw_write_held(&ip->i_rwlock);
	rewriteflg = ufs_check_rewrite(ip, uiop, ioflag);

	/*
	 * Check for fast-path special case of directio re-writes.
	 */
	if ((ip->i_flag & IDIRECTIO || ufsvfsp->vfs_forcedirectio) &&
	    !exclusive && rewriteflg) {

		error = ufs_lockfs_begin(ufsvfsp, &ulp, ULOCKFS_WRITE_MASK);
		if (error)
			goto out;

		rw_enter(&ip->i_contents, RW_READER);
		error = ufs_directio_write(ip, uiop, ioflag, 1, cr,
		    &directio_status);
		if (directio_status == DIRECTIO_SUCCESS) {
			uint_t i_flag_save;

			if (start_resid != uiop->uio_resid)
				error = 0;
			/*
			 * Special treatment of access times for re-writes.
			 * If IMOD is not already set, then convert it
			 * to IMODACC for this operation. This defers
			 * entering a delta into the log until the inode
			 * is flushed. This mimics what is done for read
			 * operations and inode access time.
			 */
			mutex_enter(&ip->i_tlock);
			i_flag_save = ip->i_flag;
			ip->i_flag |= IUPD | ICHG;
			ip->i_seq++;
			ITIMES_NOLOCK(ip);
			if ((i_flag_save & IMOD) == 0) {
				ip->i_flag &= ~IMOD;
				ip->i_flag |= IMODACC;
			}
			mutex_exit(&ip->i_tlock);
			rw_exit(&ip->i_contents);
			if (ulp)
				ufs_lockfs_end(ulp);
			goto out;
		}
		rw_exit(&ip->i_contents);
		if (ulp)
			ufs_lockfs_end(ulp);
	}

	if (!exclusive && !rw_tryupgrade(&ip->i_rwlock)) {
		rw_exit(&ip->i_rwlock);
		rw_enter(&ip->i_rwlock, RW_WRITER);
		/*
		 * Mandatory locking could have been enabled
		 * after dropping the i_rwlock.
		 */
		if (MANDLOCK(vp, ip->i_mode))
			goto retry_mandlock;
	}

	error = ufs_lockfs_begin(ufsvfsp, &ulp, ULOCKFS_WRITE_MASK);
	if (error)
		goto out;

	/*
	 * Amount of log space needed for this write
	 */
	if (!rewriteflg || !(ioflag & FDSYNC))
		TRANS_WRITE_RESV(ip, uiop, ulp, &resv, &resid);

	/*
	 * Throttle writes.
	 */
	if (ufs_WRITES && (ip->i_writes > ufs_HW)) {
		mutex_enter(&ip->i_tlock);
		while (ip->i_writes > ufs_HW) {
			ufs_throttles++;
			cv_wait(&ip->i_wrcv, &ip->i_tlock);
		}
		mutex_exit(&ip->i_tlock);
	}

	/*
	 * Enter Transaction
	 *
	 * If the write is a rewrite there is no need to open a transaction
	 * if the FDSYNC flag is set and not the FSYNC.  In this case just
	 * set the IMODACC flag to modify do the update at a later time
	 * thus avoiding the overhead of the logging transaction that is
	 * not required.
	 */
	if (ioflag & (FSYNC|FDSYNC)) {
		if (ulp) {
			if (rewriteflg) {
				uint_t i_flag_save;

				rw_enter(&ip->i_contents, RW_READER);
				mutex_enter(&ip->i_tlock);
				i_flag_save = ip->i_flag;
				ip->i_flag |= IUPD | ICHG;
				ip->i_seq++;
				ITIMES_NOLOCK(ip);
				if ((i_flag_save & IMOD) == 0) {
					ip->i_flag &= ~IMOD;
					ip->i_flag |= IMODACC;
				}
				mutex_exit(&ip->i_tlock);
				rw_exit(&ip->i_contents);
			} else {
				int terr = 0;
				TRANS_BEGIN_SYNC(ufsvfsp, TOP_WRITE_SYNC, resv,
				    terr);
				ASSERT(!terr);
			}
		}
	} else {
		if (ulp)
			TRANS_BEGIN_ASYNC(ufsvfsp, TOP_WRITE, resv);
	}

	/*
	 * Write the file
	 */
	rw_enter(&ufsvfsp->vfs_dqrwlock, RW_READER);
	rw_enter(&ip->i_contents, RW_WRITER);
	if ((ioflag & FAPPEND) != 0 && (ip->i_mode & IFMT) == IFREG) {
		/*
		 * In append mode start at end of file.
		 */
		uiop->uio_loffset = ip->i_size;
	}

	/*
	 * Mild optimisation, don't call ufs_trans_write() unless we have to
	 * Also, suppress file system full messages if we will retry.
	 */
	if (retry)
		ip->i_flag |= IQUIET;
	if (resid) {
		TRANS_WRITE(ip, uiop, ioflag, error, ulp, cr, resv, resid);
	} else {
		error = wrip(ip, uiop, ioflag, cr);
	}
	ip->i_flag &= ~IQUIET;

	rw_exit(&ip->i_contents);
	rw_exit(&ufsvfsp->vfs_dqrwlock);

	/*
	 * Leave Transaction
	 */
	if (ulp) {
		if (ioflag & (FSYNC|FDSYNC)) {
			if (!rewriteflg) {
				int terr = 0;

				TRANS_END_SYNC(ufsvfsp, terr, TOP_WRITE_SYNC,
				    resv);
				if (error == 0)
					error = terr;
			}
		} else {
			TRANS_END_ASYNC(ufsvfsp, TOP_WRITE, resv);
		}
		ufs_lockfs_end(ulp);
	}
out:
	if ((error == ENOSPC) && retry && TRANS_ISTRANS(ufsvfsp)) {
		/*
		 * Any blocks tied up in pending deletes?
		 */
		ufs_delete_drain_wait(ufsvfsp, 1);
		retry = 0;
		goto retry_mandlock;
	}

	if (error == ENOSPC && (start_resid != uiop->uio_resid))
		error = 0;

	return (error);
}

/*
 * Don't cache write blocks to files with the sticky bit set.
 * Used to keep swap files from blowing the page cache on a server.
 */
int stickyhack = 1;

/*
 * Free behind hacks.  The pager is busted.
 * XXX - need to pass the information down to writedone() in a flag like B_SEQ
 * or B_FREE_IF_TIGHT_ON_MEMORY.
 */
int	freebehind = 1;
int	smallfile = 0;
u_offset_t smallfile64 = 32 * 1024;

/*
 * While we should, in most cases, cache the pages for write, we
 * may also want to cache the pages for read as long as they are
 * frequently re-usable.
 *
 * If cache_read_ahead = 1, the pages for read will go to the tail
 * of the cache list when they are released, otherwise go to the head.
 */
int	cache_read_ahead = 0;

/*
 * Freebehind exists  so that as we read  large files  sequentially we
 * don't consume most of memory with pages  from a few files. It takes
 * longer to re-read from disk multiple small files as it does reading
 * one large one sequentially.  As system  memory grows customers need
 * to retain bigger chunks   of files in  memory.   The advent of  the
 * cachelist opens up of the possibility freeing pages  to the head or
 * tail of the list.
 *
 * Not freeing a page is a bet that the page will be read again before
 * it's segmap slot is needed for something else. If we loose the bet,
 * it means some  other thread is  burdened with the  page free we did
 * not do. If we win we save a free and reclaim.
 *
 * Freeing it at the tail  vs the head of cachelist  is a bet that the
 * page will survive until the next  read.  It's also saying that this
 * page is more likely to  be re-used than a  page freed some time ago
 * and never reclaimed.
 *
 * Freebehind maintains a  range of  file offset [smallfile1; smallfile2]
 *
 *            0 < offset < smallfile1 : pages are not freed.
 *   smallfile1 < offset < smallfile2 : pages freed to tail of cachelist.
 *   smallfile2 < offset              : pages freed to head of cachelist.
 *
 * The range  is  computed  at most  once  per second  and  depends on
 * freemem  and  ncpus_online.  Both parameters  are   bounded to be
 * >= smallfile && >= smallfile64.
 *
 * smallfile1 = (free memory / ncpu) / 1000
 * smallfile2 = (free memory / ncpu) / 10
 *
 * A few examples values:
 *
 *       Free Mem (in Bytes) [smallfile1; smallfile2]  [smallfile1; smallfile2]
 *                                 ncpus_online = 4          ncpus_online = 64
 *       ------------------  -----------------------   -----------------------
 *             1G                   [256K;  25M]               [32K; 1.5M]
 *            10G                   [2.5M; 250M]              [156K; 15M]
 *           100G                    [25M; 2.5G]              [1.5M; 150M]
 *
 */

#define	SMALLFILE1_D 1000
#define	SMALLFILE2_D 10
static u_offset_t smallfile1 = 32 * 1024;
static u_offset_t smallfile2 = 32 * 1024;
static clock_t smallfile_update = 0; /* lbolt value of when to recompute */
uint_t smallfile1_d = SMALLFILE1_D;
uint_t smallfile2_d = SMALLFILE2_D;

/*
 * wrip does the real work of write requests for ufs.
 */
int
wrip(struct inode *ip, struct uio *uio, int ioflag, struct cred *cr)
{
	rlim64_t limit = uio->uio_llimit;
	u_offset_t off;
	u_offset_t old_i_size;
	struct fs *fs;
	struct vnode *vp;
	struct ufsvfs *ufsvfsp;
	caddr_t base;
	long start_resid = uio->uio_resid;	/* save starting resid */
	long premove_resid;			/* resid before uiomove() */
	uint_t flags;
	int newpage;
	int iupdat_flag, directio_status;
	int n, on, mapon;
	int error, pagecreate;
	int do_dqrwlock;		/* drop/reacquire vfs_dqrwlock */
	int32_t	iblocks;
	int	new_iblocks;

	/*
	 * ip->i_size is incremented before the uiomove
	 * is done on a write.  If the move fails (bad user
	 * address) reset ip->i_size.
	 * The better way would be to increment ip->i_size
	 * only if the uiomove succeeds.
	 */
	int i_size_changed = 0;
	o_mode_t type;
	int i_seq_needed = 0;

	vp = ITOV(ip);

	/*
	 * check for forced unmount - should not happen as
	 * the request passed the lockfs checks.
	 */
	if ((ufsvfsp = ip->i_ufsvfs) == NULL)
		return (EIO);

	fs = ip->i_fs;

	ASSERT(RW_WRITE_HELD(&ip->i_contents));

	/* check for valid filetype */
	type = ip->i_mode & IFMT;
	if ((type != IFREG) && (type != IFDIR) && (type != IFATTRDIR) &&
	    (type != IFLNK) && (type != IFSHAD)) {
		return (EIO);
	}

	/*
	 * the actual limit of UFS file size
	 * is UFS_MAXOFFSET_T
	 */
	if (limit == RLIM64_INFINITY || limit > MAXOFFSET_T)
		limit = MAXOFFSET_T;

	if (uio->uio_loffset >= limit) {
		proc_t *p = ttoproc(curthread);

		mutex_enter(&p->p_lock);
		(void) rctl_action(rctlproc_legacy[RLIMIT_FSIZE], p->p_rctls,
		    p, RCA_UNSAFE_SIGINFO);
		mutex_exit(&p->p_lock);
		return (EFBIG);
	}

	/*
	 * if largefiles are disallowed, the limit is
	 * the pre-largefiles value of 2GB
	 */
	if (ufsvfsp->vfs_lfflags & UFS_LARGEFILES)
		limit = MIN(UFS_MAXOFFSET_T, limit);
	else
		limit = MIN(MAXOFF32_T, limit);

	if (uio->uio_loffset < (offset_t)0) {
		return (EINVAL);
	}
	if (uio->uio_resid == 0) {
		return (0);
	}

	if (uio->uio_loffset >= limit)
		return (EFBIG);

	ip->i_flag |= INOACC;	/* don't update ref time in getpage */

	if (ioflag & (FSYNC|FDSYNC)) {
		ip->i_flag |= ISYNC;
		iupdat_flag = 1;
	}
	/*
	 * Try to go direct
	 */
	if (ip->i_flag & IDIRECTIO || ufsvfsp->vfs_forcedirectio) {
		uio->uio_llimit = limit;
		error = ufs_directio_write(ip, uio, ioflag, 0, cr,
		    &directio_status);
		/*
		 * If ufs_directio wrote to the file or set the flags,
		 * we need to update i_seq, but it may be deferred.
		 */
		if (start_resid != uio->uio_resid ||
		    (ip->i_flag & (ICHG|IUPD))) {
			i_seq_needed = 1;
			ip->i_flag |= ISEQ;
		}
		if (directio_status == DIRECTIO_SUCCESS)
			goto out;
	}

	/*
	 * Behavior with respect to dropping/reacquiring vfs_dqrwlock:
	 *
	 * o shadow inodes: vfs_dqrwlock is not held at all
	 * o quota updates: vfs_dqrwlock is read or write held
	 * o other updates: vfs_dqrwlock is read held
	 *
	 * The first case is the only one where we do not hold
	 * vfs_dqrwlock at all while entering wrip().
	 * We must make sure not to downgrade/drop vfs_dqrwlock if we
	 * have it as writer, i.e. if we are updating the quota inode.
	 * There is no potential deadlock scenario in this case as
	 * ufs_getpage() takes care of this and avoids reacquiring
	 * vfs_dqrwlock in that case.
	 *
	 * This check is done here since the above conditions do not change
	 * and we possibly loop below, so save a few cycles.
	 */
	if ((type == IFSHAD) ||
	    (rw_owner(&ufsvfsp->vfs_dqrwlock) == curthread)) {
		do_dqrwlock = 0;
	} else {
		do_dqrwlock = 1;
	}

	/*
	 * Large Files: We cast MAXBMASK to offset_t
	 * inorder to mask out the higher bits. Since offset_t
	 * is a signed value, the high order bit set in MAXBMASK
	 * value makes it do the right thing by having all bits 1
	 * in the higher word. May be removed for _SOLARIS64_.
	 */

	fs = ip->i_fs;
	do {
		u_offset_t uoff = uio->uio_loffset;
		off = uoff & (offset_t)MAXBMASK;
		mapon = (int)(uoff & (offset_t)MAXBOFFSET);
		on = (int)blkoff(fs, uoff);
		n = (int)MIN(fs->fs_bsize - on, uio->uio_resid);
		new_iblocks = 1;

		if (type == IFREG && uoff + n >= limit) {
			if (uoff >= limit) {
				error = EFBIG;
				goto out;
			}
			/*
			 * since uoff + n >= limit,
			 * therefore n >= limit - uoff, and n is an int
			 * so it is safe to cast it to an int
			 */
			n = (int)(limit - (rlim64_t)uoff);
		}
		if (uoff + n > ip->i_size) {
			/*
			 * We are extending the length of the file.
			 * bmap is used so that we are sure that
			 * if we need to allocate new blocks, that it
			 * is done here before we up the file size.
			 */
			error = bmap_write(ip, uoff, (int)(on + n),
			    mapon == 0, NULL, cr);
			/*
			 * bmap_write never drops i_contents so if
			 * the flags are set it changed the file.
			 */
			if (ip->i_flag & (ICHG|IUPD)) {
				i_seq_needed = 1;
				ip->i_flag |= ISEQ;
			}
			if (error)
				break;
			/*
			 * There is a window of vulnerability here.
			 * The sequence of operations: allocate file
			 * system blocks, uiomove the data into pages,
			 * and then update the size of the file in the
			 * inode, must happen atomically.  However, due
			 * to current locking constraints, this can not
			 * be done.
			 */
			ASSERT(ip->i_writer == NULL);
			ip->i_writer = curthread;
			i_size_changed = 1;
			/*
			 * If we are writing from the beginning of
			 * the mapping, we can just create the
			 * pages without having to read them.
			 */
			pagecreate = (mapon == 0);
		} else if (n == MAXBSIZE) {
			/*
			 * Going to do a whole mappings worth,
			 * so we can just create the pages w/o
			 * having to read them in.  But before
			 * we do that, we need to make sure any
			 * needed blocks are allocated first.
			 */
			iblocks = ip->i_blocks;
			error = bmap_write(ip, uoff, (int)(on + n),
			    BI_ALLOC_ONLY, NULL, cr);
			/*
			 * bmap_write never drops i_contents so if
			 * the flags are set it changed the file.
			 */
			if (ip->i_flag & (ICHG|IUPD)) {
				i_seq_needed = 1;
				ip->i_flag |= ISEQ;
			}
			if (error)
				break;
			pagecreate = 1;
			/*
			 * check if the new created page needed the
			 * allocation of new disk blocks.
			 */
			if (iblocks == ip->i_blocks)
				new_iblocks = 0; /* no new blocks allocated */
		} else {
			pagecreate = 0;
			/*
			 * In sync mode flush the indirect blocks which
			 * may have been allocated and not written on
			 * disk. In above cases bmap_write will allocate
			 * in sync mode.
			 */
			if (ioflag & (FSYNC|FDSYNC)) {
				error = ufs_indirblk_sync(ip, uoff);
				if (error)
					break;
			}
		}

		/*
		 * At this point we can enter ufs_getpage() in one
		 * of two ways:
		 * 1) segmap_getmapflt() calls ufs_getpage() when the
		 *    forcefault parameter is true (pagecreate == 0)
		 * 2) uiomove() causes a page fault.
		 *
		 * We have to drop the contents lock to prevent the VM
		 * system from trying to reacquire it in ufs_getpage()
		 * should the uiomove cause a pagefault.
		 *
		 * We have to drop the reader vfs_dqrwlock here as well.
		 */
		rw_exit(&ip->i_contents);
		if (do_dqrwlock) {
			ASSERT(RW_LOCK_HELD(&ufsvfsp->vfs_dqrwlock));
			ASSERT(!(RW_WRITE_HELD(&ufsvfsp->vfs_dqrwlock)));
			rw_exit(&ufsvfsp->vfs_dqrwlock);
		}

		newpage = 0;
		premove_resid = uio->uio_resid;

		/*
		 * Touch the page and fault it in if it is not in core
		 * before segmap_getmapflt or vpm_data_copy can lock it.
		 * This is to avoid the deadlock if the buffer is mapped
		 * to the same file through mmap which we want to write.
		 */
		uio_prefaultpages((long)n, uio);

		if (vpm_enable) {
			/*
			 * Copy data. If new pages are created, part of
			 * the page that is not written will be initizliazed
			 * with zeros.
			 */
			error = vpm_data_copy(vp, (off + mapon), (uint_t)n,
			    uio, !pagecreate, &newpage, 0, S_WRITE);
		} else {

			base = segmap_getmapflt(segkmap, vp, (off + mapon),
			    (uint_t)n, !pagecreate, S_WRITE);

			/*
			 * segmap_pagecreate() returns 1 if it calls
			 * page_create_va() to allocate any pages.
			 */

			if (pagecreate)
				newpage = segmap_pagecreate(segkmap, base,
				    (size_t)n, 0);

			error = uiomove(base + mapon, (long)n, UIO_WRITE, uio);
		}

		/*
		 * If "newpage" is set, then a new page was created and it
		 * does not contain valid data, so it needs to be initialized
		 * at this point.
		 * Otherwise the page contains old data, which was overwritten
		 * partially or as a whole in uiomove.
		 * If there is only one iovec structure within uio, then
		 * on error uiomove will not be able to update uio->uio_loffset
		 * and we would zero the whole page here!
		 *
		 * If uiomove fails because of an error, the old valid data
		 * is kept instead of filling the rest of the page with zero's.
		 */
		if (!vpm_enable && newpage &&
		    uio->uio_loffset < roundup(off + mapon + n, PAGESIZE)) {
			/*
			 * We created pages w/o initializing them completely,
			 * thus we need to zero the part that wasn't set up.
			 * This happens on most EOF write cases and if
			 * we had some sort of error during the uiomove.
			 */
			int nzero, nmoved;

			nmoved = (int)(uio->uio_loffset - (off + mapon));
			ASSERT(nmoved >= 0 && nmoved <= n);
			nzero = roundup(on + n, PAGESIZE) - nmoved;
			ASSERT(nzero > 0 && mapon + nmoved + nzero <= MAXBSIZE);
			(void) kzero(base + mapon + nmoved, (uint_t)nzero);
		}

		/*
		 * Unlock the pages allocated by page_create_va()
		 * in segmap_pagecreate()
		 */
		if (!vpm_enable && newpage)
			segmap_pageunlock(segkmap, base, (size_t)n, S_WRITE);

		/*
		 * If the size of the file changed, then update the
		 * size field in the inode now.  This can't be done
		 * before the call to segmap_pageunlock or there is
		 * a potential deadlock with callers to ufs_putpage().
		 * They will be holding i_contents and trying to lock
		 * a page, while this thread is holding a page locked
		 * and trying to acquire i_contents.
		 */
		if (i_size_changed) {
			rw_enter(&ip->i_contents, RW_WRITER);
			old_i_size = ip->i_size;
			UFS_SET_ISIZE(uoff + n, ip);
			TRANS_INODE(ufsvfsp, ip);
			/*
			 * file has grown larger than 2GB. Set flag
			 * in superblock to indicate this, if it
			 * is not already set.
			 */
			if ((ip->i_size > MAXOFF32_T) &&
			    !(fs->fs_flags & FSLARGEFILES)) {
				ASSERT(ufsvfsp->vfs_lfflags & UFS_LARGEFILES);
				mutex_enter(&ufsvfsp->vfs_lock);
				fs->fs_flags |= FSLARGEFILES;
				ufs_sbwrite(ufsvfsp);
				mutex_exit(&ufsvfsp->vfs_lock);
			}
			mutex_enter(&ip->i_tlock);
			ip->i_writer = NULL;
			cv_broadcast(&ip->i_wrcv);
			mutex_exit(&ip->i_tlock);
			rw_exit(&ip->i_contents);
		}

		if (error) {
			/*
			 * If we failed on a write, we may have already
			 * allocated file blocks as well as pages.  It's
			 * hard to undo the block allocation, but we must
			 * be sure to invalidate any pages that may have
			 * been allocated.
			 *
			 * If the page was created without initialization
			 * then we must check if it should be possible
			 * to destroy the new page and to keep the old data
			 * on the disk.
			 *
			 * It is possible to destroy the page without
			 * having to write back its contents only when
			 * - the size of the file keeps unchanged
			 * - bmap_write() did not allocate new disk blocks
			 *   it is possible to create big files using "seek" and
			 *   write to the end of the file. A "write" to a
			 *   position before the end of the file would not
			 *   change the size of the file but it would allocate
			 *   new disk blocks.
			 * - uiomove intended to overwrite the whole page.
			 * - a new page was created (newpage == 1).
			 */

			if (i_size_changed == 0 && new_iblocks == 0 &&
			    newpage) {

				/* unwind what uiomove eventually last did */
				uio->uio_resid = premove_resid;

				/*
				 * destroy the page, do not write ambiguous
				 * data to the disk.
				 */
				flags = SM_DESTROY;
			} else {
				/*
				 * write the page back to the disk, if dirty,
				 * and remove the page from the cache.
				 */
				flags = SM_INVAL;
			}

			if (vpm_enable) {
				/*
				 *  Flush pages.
				 */
				(void) vpm_sync_pages(vp, off, n, flags);
			} else {
				(void) segmap_release(segkmap, base, flags);
			}
		} else {
			flags = 0;
			/*
			 * Force write back for synchronous write cases.
			 */
			if ((ioflag & (FSYNC|FDSYNC)) || type == IFDIR) {
				/*
				 * If the sticky bit is set but the
				 * execute bit is not set, we do a
				 * synchronous write back and free
				 * the page when done.  We set up swap
				 * files to be handled this way to
				 * prevent servers from keeping around
				 * the client's swap pages too long.
				 * XXX - there ought to be a better way.
				 */
				if (IS_SWAPVP(vp)) {
					flags = SM_WRITE | SM_FREE |
					    SM_DONTNEED;
					iupdat_flag = 0;
				} else {
					flags = SM_WRITE;
				}
			} else if (n + on == MAXBSIZE || IS_SWAPVP(vp)) {
				/*
				 * Have written a whole block.
				 * Start an asynchronous write and
				 * mark the buffer to indicate that
				 * it won't be needed again soon.
				 */
				flags = SM_WRITE | SM_ASYNC | SM_DONTNEED;
			}
			if (vpm_enable) {
				/*
				 * Flush pages.
				 */
				error = vpm_sync_pages(vp, off, n, flags);
			} else {
				error = segmap_release(segkmap, base, flags);
			}
			/*
			 * If the operation failed and is synchronous,
			 * then we need to unwind what uiomove() last
			 * did so we can potentially return an error to
			 * the caller.  If this write operation was
			 * done in two pieces and the first succeeded,
			 * then we won't return an error for the second
			 * piece that failed.  However, we only want to
			 * return a resid value that reflects what was
			 * really done.
			 *
			 * Failures for non-synchronous operations can
			 * be ignored since the page subsystem will
			 * retry the operation until it succeeds or the
			 * file system is unmounted.
			 */
			if (error) {
				if ((ioflag & (FSYNC | FDSYNC)) ||
				    type == IFDIR) {
					uio->uio_resid = premove_resid;
				} else {
					error = 0;
				}
			}
		}

		/*
		 * Re-acquire contents lock.
		 * If it was dropped, reacquire reader vfs_dqrwlock as well.
		 */
		if (do_dqrwlock)
			rw_enter(&ufsvfsp->vfs_dqrwlock, RW_READER);
		rw_enter(&ip->i_contents, RW_WRITER);

		/*
		 * If the uiomove() failed or if a synchronous
		 * page push failed, fix up i_size.
		 */
		if (error) {
			if (i_size_changed) {
				/*
				 * The uiomove failed, and we
				 * allocated blocks,so get rid
				 * of them.
				 */
				(void) ufs_itrunc(ip, old_i_size, 0, cr);
			}
		} else {
			/*
			 * XXX - Can this be out of the loop?
			 */
			ip->i_flag |= IUPD | ICHG;
			/*
			 * Only do one increase of i_seq for multiple
			 * pieces.  Because we drop locks, record
			 * the fact that we changed the timestamp and
			 * are deferring the increase in case another thread
			 * pushes our timestamp update.
			 */
			i_seq_needed = 1;
			ip->i_flag |= ISEQ;
			if (i_size_changed)
				ip->i_flag |= IATTCHG;
			if ((ip->i_mode & (IEXEC | (IEXEC >> 3) |
			    (IEXEC >> 6))) != 0 &&
			    (ip->i_mode & (ISUID | ISGID)) != 0 &&
			    secpolicy_vnode_setid_retain(cr,
			    (ip->i_mode & ISUID) != 0 && ip->i_uid == 0) != 0) {
				/*
				 * Clear Set-UID & Set-GID bits on
				 * successful write if not privileged
				 * and at least one of the execute bits
				 * is set.  If we always clear Set-GID,
				 * mandatory file and record locking is
				 * unuseable.
				 */
				ip->i_mode &= ~(ISUID | ISGID);
			}
		}
		/*
		 * In the case the FDSYNC flag is set and this is a
		 * "rewrite" we won't log a delta.
		 * The FSYNC flag overrides all cases.
		 */
		if (!ufs_check_rewrite(ip, uio, ioflag) || !(ioflag & FDSYNC)) {
			TRANS_INODE(ufsvfsp, ip);
		}
	} while (error == 0 && uio->uio_resid > 0 && n != 0);

out:
	/*
	 * Make sure i_seq is increased at least once per write
	 */
	if (i_seq_needed) {
		ip->i_seq++;
		ip->i_flag &= ~ISEQ;	/* no longer deferred */
	}

	/*
	 * Inode is updated according to this table -
	 *
	 *   FSYNC	  FDSYNC(posix.4)
	 *   --------------------------
	 *   always@	  IATTCHG|IBDWRITE
	 *
	 * @ - 	If we are doing synchronous write the only time we should
	 *	not be sync'ing the ip here is if we have the stickyhack
	 *	activated, the file is marked with the sticky bit and
	 *	no exec bit, the file length has not been changed and
	 *	no new blocks have been allocated during this write.
	 */

	if ((ip->i_flag & ISYNC) != 0) {
		/*
		 * we have eliminated nosync
		 */
		if ((ip->i_flag & (IATTCHG|IBDWRITE)) ||
		    ((ioflag & FSYNC) && iupdat_flag)) {
			ufs_iupdat(ip, 1);
		}
	}

	/*
	 * If we've already done a partial-write, terminate
	 * the write but return no error unless the error is ENOSPC
	 * because the caller can detect this and free resources and
	 * try again.
	 */
	if ((start_resid != uio->uio_resid) && (error != ENOSPC))
		error = 0;

	ip->i_flag &= ~(INOACC | ISYNC);
	ITIMES_NOLOCK(ip);
	return (error);
}

/*
 * rdip does the real work of read requests for ufs.
 */
int
rdip(struct inode *ip, struct uio *uio, int ioflag, cred_t *cr)
{
	u_offset_t off;
	caddr_t base;
	struct fs *fs;
	struct ufsvfs *ufsvfsp;
	struct vnode *vp;
	long oresid = uio->uio_resid;
	u_offset_t n, on, mapon;
	int error = 0;
	int doupdate = 1;
	uint_t flags;
	int dofree, directio_status;
	krw_t rwtype;
	o_mode_t type;
	clock_t	now;

	vp = ITOV(ip);

	ASSERT(RW_LOCK_HELD(&ip->i_contents));

	ufsvfsp = ip->i_ufsvfs;

	if (ufsvfsp == NULL)
		return (EIO);

	fs = ufsvfsp->vfs_fs;

	/* check for valid filetype */
	type = ip->i_mode & IFMT;
	if ((type != IFREG) && (type != IFDIR) && (type != IFATTRDIR) &&
	    (type != IFLNK) && (type != IFSHAD)) {
		return (EIO);
	}

	if (uio->uio_loffset > UFS_MAXOFFSET_T) {
		error = 0;
		goto out;
	}
	if (uio->uio_loffset < (offset_t)0) {
		return (EINVAL);
	}
	if (uio->uio_resid == 0) {
		return (0);
	}

	if (!ULOCKFS_IS_NOIACC(ITOUL(ip)) && (fs->fs_ronly == 0) &&
	    (!ufsvfsp->vfs_noatime)) {
		mutex_enter(&ip->i_tlock);
		ip->i_flag |= IACC;
		mutex_exit(&ip->i_tlock);
	}
	/*
	 * Try to go direct
	 */
	if (ip->i_flag & IDIRECTIO || ufsvfsp->vfs_forcedirectio) {
		error = ufs_directio_read(ip, uio, cr, &directio_status);
		if (directio_status == DIRECTIO_SUCCESS)
			goto out;
	}

	rwtype = (rw_write_held(&ip->i_contents)?RW_WRITER:RW_READER);

	do {
		offset_t diff;
		u_offset_t uoff = uio->uio_loffset;
		off = uoff & (offset_t)MAXBMASK;
		mapon = (u_offset_t)(uoff & (offset_t)MAXBOFFSET);
		on = (u_offset_t)blkoff(fs, uoff);
		n = MIN((u_offset_t)fs->fs_bsize - on,
		    (u_offset_t)uio->uio_resid);

		diff = ip->i_size - uoff;

		if (diff <= (offset_t)0) {
			error = 0;
			goto out;
		}
		if (diff < (offset_t)n)
			n = (int)diff;

		/*
		 * We update smallfile2 and smallfile1 at most every second.
		 */
		now = ddi_get_lbolt();
		if (now >= smallfile_update) {
			uint64_t percpufreeb;
			if (smallfile1_d == 0) smallfile1_d = SMALLFILE1_D;
			if (smallfile2_d == 0) smallfile2_d = SMALLFILE2_D;
			percpufreeb = ptob((uint64_t)freemem) / ncpus_online;
			smallfile1 = percpufreeb / smallfile1_d;
			smallfile2 = percpufreeb / smallfile2_d;
			smallfile1 = MAX(smallfile1, smallfile);
			smallfile1 = MAX(smallfile1, smallfile64);
			smallfile2 = MAX(smallfile1, smallfile2);
			smallfile_update = now + hz;
		}

		dofree = freebehind &&
		    ip->i_nextr == (off & PAGEMASK) && off > smallfile1;

		/*
		 * At this point we can enter ufs_getpage() in one of two
		 * ways:
		 * 1) segmap_getmapflt() calls ufs_getpage() when the
		 *    forcefault parameter is true (value of 1 is passed)
		 * 2) uiomove() causes a page fault.
		 *
		 * We cannot hold onto an i_contents reader lock without
		 * risking deadlock in ufs_getpage() so drop a reader lock.
		 * The ufs_getpage() dolock logic already allows for a
		 * thread holding i_contents as writer to work properly
		 * so we keep a writer lock.
		 */
		if (rwtype == RW_READER)
			rw_exit(&ip->i_contents);

		if (vpm_enable) {
			/*
			 * Copy data.
			 */
			error = vpm_data_copy(vp, (off + mapon), (uint_t)n,
			    uio, 1, NULL, 0, S_READ);
		} else {
			base = segmap_getmapflt(segkmap, vp, (off + mapon),
			    (uint_t)n, 1, S_READ);
			error = uiomove(base + mapon, (long)n, UIO_READ, uio);
		}

		flags = 0;
		if (!error) {
			/*
			 * If  reading sequential  we won't need  this
			 * buffer again  soon.  For  offsets in  range
			 * [smallfile1,  smallfile2] release the pages
			 * at   the  tail  of the   cache list, larger
			 * offsets are released at the head.
			 */
			if (dofree) {
				flags = SM_FREE | SM_ASYNC;
				if ((cache_read_ahead == 0) &&
				    (off > smallfile2))
					flags |=  SM_DONTNEED;
			}
			/*
			 * In POSIX SYNC (FSYNC and FDSYNC) read mode,
			 * we want to make sure that the page which has
			 * been read, is written on disk if it is dirty.
			 * And corresponding indirect blocks should also
			 * be flushed out.
			 */
			if ((ioflag & FRSYNC) && (ioflag & (FSYNC|FDSYNC))) {
				flags &= ~SM_ASYNC;
				flags |= SM_WRITE;
			}
			if (vpm_enable) {
				error = vpm_sync_pages(vp, off, n, flags);
			} else {
				error = segmap_release(segkmap, base, flags);
			}
		} else {
			if (vpm_enable) {
				(void) vpm_sync_pages(vp, off, n, flags);
			} else {
				(void) segmap_release(segkmap, base, flags);
			}
		}

		if (rwtype == RW_READER)
			rw_enter(&ip->i_contents, rwtype);
	} while (error == 0 && uio->uio_resid > 0 && n != 0);
out:
	/*
	 * Inode is updated according to this table if FRSYNC is set.
	 *
	 *   FSYNC	  FDSYNC(posix.4)
	 *   --------------------------
	 *   always	  IATTCHG|IBDWRITE
	 */
	/*
	 * The inode is not updated if we're logging and the inode is a
	 * directory with FRSYNC, FSYNC and FDSYNC flags set.
	 */
	if (ioflag & FRSYNC) {
		if (TRANS_ISTRANS(ufsvfsp) && ((ip->i_mode & IFMT) == IFDIR)) {
			doupdate = 0;
		}
		if (doupdate) {
			if ((ioflag & FSYNC) ||
			    ((ioflag & FDSYNC) &&
			    (ip->i_flag & (IATTCHG|IBDWRITE)))) {
				ufs_iupdat(ip, 1);
			}
		}
	}
	/*
	 * If we've already done a partial read, terminate
	 * the read but return no error.
	 */
	if (oresid != uio->uio_resid)
		error = 0;
	ITIMES(ip);

	return (error);
}

/* ARGSUSED */
static int
ufs_ioctl(
	struct vnode	*vp,
	int		cmd,
	intptr_t	arg,
	int		flag,
	struct cred	*cr,
	int		*rvalp,
	caller_context_t *ct)
{
	struct lockfs	lockfs, lockfs_out;
	struct ufsvfs	*ufsvfsp = VTOI(vp)->i_ufsvfs;
	char		*comment, *original_comment;
	struct fs	*fs;
	struct ulockfs	*ulp;
	offset_t	off;
	extern int	maxphys;
	int		error;
	int		issync;
	int		trans_size;


	/*
	 * forcibly unmounted
	 */
	if (ufsvfsp == NULL || vp->v_vfsp == NULL ||
	    vp->v_vfsp->vfs_flag & VFS_UNMOUNTED)
		return (EIO);
	fs = ufsvfsp->vfs_fs;

	if (cmd == Q_QUOTACTL) {
		error = ufs_lockfs_begin(ufsvfsp, &ulp, ULOCKFS_QUOTA_MASK);
		if (error)
			return (error);

		if (ulp) {
			TRANS_BEGIN_ASYNC(ufsvfsp, TOP_QUOTA,
			    TOP_SETQUOTA_SIZE(fs));
		}

		error = quotactl(vp, arg, flag, cr);

		if (ulp) {
			TRANS_END_ASYNC(ufsvfsp, TOP_QUOTA,
			    TOP_SETQUOTA_SIZE(fs));
			ufs_lockfs_end(ulp);
		}
		return (error);
	}

	switch (cmd) {
		case _FIOLFS:
			/*
			 * file system locking
			 */
			if (secpolicy_fs_config(cr, ufsvfsp->vfs_vfs) != 0)
				return (EPERM);

			if ((flag & DATAMODEL_MASK) == DATAMODEL_NATIVE) {
				if (copyin((caddr_t)arg, &lockfs,
				    sizeof (struct lockfs)))
					return (EFAULT);
			}
#ifdef _SYSCALL32_IMPL
			else {
				struct lockfs32	lockfs32;
				/* Translate ILP32 lockfs to LP64 lockfs */
				if (copyin((caddr_t)arg, &lockfs32,
				    sizeof (struct lockfs32)))
					return (EFAULT);
				lockfs.lf_lock = (ulong_t)lockfs32.lf_lock;
				lockfs.lf_flags = (ulong_t)lockfs32.lf_flags;
				lockfs.lf_key = (ulong_t)lockfs32.lf_key;
				lockfs.lf_comlen = (ulong_t)lockfs32.lf_comlen;
				lockfs.lf_comment =
				    (caddr_t)(uintptr_t)lockfs32.lf_comment;
			}
#endif /* _SYSCALL32_IMPL */

			if (lockfs.lf_comlen) {
				if (lockfs.lf_comlen > LOCKFS_MAXCOMMENTLEN)
					return (ENAMETOOLONG);
				comment =
				    kmem_alloc(lockfs.lf_comlen, KM_SLEEP);
				if (copyin(lockfs.lf_comment, comment,
				    lockfs.lf_comlen)) {
					kmem_free(comment, lockfs.lf_comlen);
					return (EFAULT);
				}
				original_comment = lockfs.lf_comment;
				lockfs.lf_comment = comment;
			}
			if ((error = ufs_fiolfs(vp, &lockfs, 0)) == 0) {
				lockfs.lf_comment = original_comment;

				if ((flag & DATAMODEL_MASK) ==
				    DATAMODEL_NATIVE) {
					(void) copyout(&lockfs, (caddr_t)arg,
					    sizeof (struct lockfs));
				}
#ifdef _SYSCALL32_IMPL
				else {
					struct lockfs32	lockfs32;
					/* Translate LP64 to ILP32 lockfs */
					lockfs32.lf_lock =
					    (uint32_t)lockfs.lf_lock;
					lockfs32.lf_flags =
					    (uint32_t)lockfs.lf_flags;
					lockfs32.lf_key =
					    (uint32_t)lockfs.lf_key;
					lockfs32.lf_comlen =
					    (uint32_t)lockfs.lf_comlen;
					lockfs32.lf_comment =
					    (uint32_t)(uintptr_t)
					    lockfs.lf_comment;
					(void) copyout(&lockfs32, (caddr_t)arg,
					    sizeof (struct lockfs32));
				}
#endif /* _SYSCALL32_IMPL */

			} else {
				if (lockfs.lf_comlen)
					kmem_free(comment, lockfs.lf_comlen);
			}
			return (error);

		case _FIOLFSS:
			/*
			 * get file system locking status
			 */

			if ((flag & DATAMODEL_MASK) == DATAMODEL_NATIVE) {
				if (copyin((caddr_t)arg, &lockfs,
				    sizeof (struct lockfs)))
					return (EFAULT);
			}
#ifdef _SYSCALL32_IMPL
			else {
				struct lockfs32	lockfs32;
				/* Translate ILP32 lockfs to LP64 lockfs */
				if (copyin((caddr_t)arg, &lockfs32,
				    sizeof (struct lockfs32)))
					return (EFAULT);
				lockfs.lf_lock = (ulong_t)lockfs32.lf_lock;
				lockfs.lf_flags = (ulong_t)lockfs32.lf_flags;
				lockfs.lf_key = (ulong_t)lockfs32.lf_key;
				lockfs.lf_comlen = (ulong_t)lockfs32.lf_comlen;
				lockfs.lf_comment =
				    (caddr_t)(uintptr_t)lockfs32.lf_comment;
			}
#endif /* _SYSCALL32_IMPL */

			if (error =  ufs_fiolfss(vp, &lockfs_out))
				return (error);
			lockfs.lf_lock = lockfs_out.lf_lock;
			lockfs.lf_key = lockfs_out.lf_key;
			lockfs.lf_flags = lockfs_out.lf_flags;
			lockfs.lf_comlen = MIN(lockfs.lf_comlen,
			    lockfs_out.lf_comlen);

			if ((flag & DATAMODEL_MASK) == DATAMODEL_NATIVE) {
				if (copyout(&lockfs, (caddr_t)arg,
				    sizeof (struct lockfs)))
					return (EFAULT);
			}
#ifdef _SYSCALL32_IMPL
			else {
				/* Translate LP64 to ILP32 lockfs */
				struct lockfs32	lockfs32;
				lockfs32.lf_lock = (uint32_t)lockfs.lf_lock;
				lockfs32.lf_flags = (uint32_t)lockfs.lf_flags;
				lockfs32.lf_key = (uint32_t)lockfs.lf_key;
				lockfs32.lf_comlen = (uint32_t)lockfs.lf_comlen;
				lockfs32.lf_comment =
				    (uint32_t)(uintptr_t)lockfs.lf_comment;
				if (copyout(&lockfs32, (caddr_t)arg,
				    sizeof (struct lockfs32)))
					return (EFAULT);
			}
#endif /* _SYSCALL32_IMPL */

			if (lockfs.lf_comlen &&
			    lockfs.lf_comment && lockfs_out.lf_comment)
				if (copyout(lockfs_out.lf_comment,
				    lockfs.lf_comment, lockfs.lf_comlen))
					return (EFAULT);
			return (0);

		case _FIOSATIME:
			/*
			 * set access time
			 */

			/*
			 * if mounted w/o atime, return quietly.
			 * I briefly thought about returning ENOSYS, but
			 * figured that most apps would consider this fatal
			 * but the idea is to make this as seamless as poss.
			 */
			if (ufsvfsp->vfs_noatime)
				return (0);

			error = ufs_lockfs_begin(ufsvfsp, &ulp,
			    ULOCKFS_SETATTR_MASK);
			if (error)
				return (error);

			if (ulp) {
				trans_size = (int)TOP_SETATTR_SIZE(VTOI(vp));
				TRANS_BEGIN_CSYNC(ufsvfsp, issync,
				    TOP_SETATTR, trans_size);
			}

			error = ufs_fiosatime(vp, (struct timeval *)arg,
			    flag, cr);

			if (ulp) {
				TRANS_END_CSYNC(ufsvfsp, error, issync,
				    TOP_SETATTR, trans_size);
				ufs_lockfs_end(ulp);
			}
			return (error);

		case _FIOSDIO:
			/*
			 * set delayed-io
			 */
			return (ufs_fiosdio(vp, (uint_t *)arg, flag, cr));

		case _FIOGDIO:
			/*
			 * get delayed-io
			 */
			return (ufs_fiogdio(vp, (uint_t *)arg, flag, cr));

		case _FIOIO:
			/*
			 * inode open
			 */
			error = ufs_lockfs_begin(ufsvfsp, &ulp,
			    ULOCKFS_VGET_MASK);
			if (error)
				return (error);

			error = ufs_fioio(vp, (struct fioio *)arg, flag, cr);

			if (ulp) {
				ufs_lockfs_end(ulp);
			}
			return (error);

		case _FIOFFS:
			/*
			 * file system flush (push w/invalidate)
			 */
			if ((caddr_t)arg != NULL)
				return (EINVAL);
			return (ufs_fioffs(vp, NULL, cr));

		case _FIOISBUSY:
			/*
			 * Contract-private interface for Legato
			 * Purge this vnode from the DNLC and decide
			 * if this vnode is busy (*arg == 1) or not
			 * (*arg == 0)
			 */
			if (secpolicy_fs_config(cr, ufsvfsp->vfs_vfs) != 0)
				return (EPERM);
			error = ufs_fioisbusy(vp, (int *)arg, cr);
			return (error);

		case _FIODIRECTIO:
			return (ufs_fiodirectio(vp, (int)arg, cr));

		case _FIOTUNE:
			/*
			 * Tune the file system (aka setting fs attributes)
			 */
			error = ufs_lockfs_begin(ufsvfsp, &ulp,
			    ULOCKFS_SETATTR_MASK);
			if (error)
				return (error);

			error = ufs_fiotune(vp, (struct fiotune *)arg, cr);

			if (ulp)
				ufs_lockfs_end(ulp);
			return (error);

		case _FIOLOGENABLE:
			if (secpolicy_fs_config(cr, ufsvfsp->vfs_vfs) != 0)
				return (EPERM);
			return (ufs_fiologenable(vp, (void *)arg, cr, flag));

		case _FIOLOGDISABLE:
			if (secpolicy_fs_config(cr, ufsvfsp->vfs_vfs) != 0)
				return (EPERM);
			return (ufs_fiologdisable(vp, (void *)arg, cr, flag));

		case _FIOISLOG:
			return (ufs_fioislog(vp, (void *)arg, cr, flag));

		case _FIOSNAPSHOTCREATE_MULTI:
		{
			struct fiosnapcreate_multi	fc, *fcp;
			size_t	fcm_size;

			if (copyin((void *)arg, &fc, sizeof (fc)))
				return (EFAULT);
			if (fc.backfilecount > MAX_BACKFILE_COUNT)
				return (EINVAL);
			fcm_size = sizeof (struct fiosnapcreate_multi) +
			    (fc.backfilecount - 1) * sizeof (int);
			fcp = (struct fiosnapcreate_multi *)
			    kmem_alloc(fcm_size, KM_SLEEP);
			if (copyin((void *)arg, fcp, fcm_size)) {
				kmem_free(fcp, fcm_size);
				return (EFAULT);
			}
			error = ufs_snap_create(vp, fcp, cr);
			/*
			 * Do copyout even if there is an error because
			 * the details of error is stored in fcp.
			 */
			if (copyout(fcp, (void *)arg, fcm_size))
				error = EFAULT;
			kmem_free(fcp, fcm_size);
			return (error);
		}

		case _FIOSNAPSHOTDELETE:
		{
			struct fiosnapdelete	fc;

			if (copyin((void *)arg, &fc, sizeof (fc)))
				return (EFAULT);
			error = ufs_snap_delete(vp, &fc, cr);
			if (!error && copyout(&fc, (void *)arg, sizeof (fc)))
				error = EFAULT;
			return (error);
		}

		case _FIOGETSUPERBLOCK:
			if (copyout(fs, (void *)arg, SBSIZE))
				return (EFAULT);
			return (0);

		case _FIOGETMAXPHYS:
			if (copyout(&maxphys, (void *)arg, sizeof (maxphys)))
				return (EFAULT);
			return (0);

		/*
		 * The following 3 ioctls are for TSufs support
		 * although could potentially be used elsewhere
		 */
		case _FIO_SET_LUFS_DEBUG:
			if (secpolicy_fs_config(cr, ufsvfsp->vfs_vfs) != 0)
				return (EPERM);
			lufs_debug = (uint32_t)arg;
			return (0);

		case _FIO_SET_LUFS_ERROR:
			if (secpolicy_fs_config(cr, ufsvfsp->vfs_vfs) != 0)
				return (EPERM);
			TRANS_SETERROR(ufsvfsp);
			return (0);

		case _FIO_GET_TOP_STATS:
		{
			fio_lufs_stats_t *ls;
			ml_unit_t *ul = ufsvfsp->vfs_log;

			ls = kmem_zalloc(sizeof (*ls), KM_SLEEP);
			ls->ls_debug = ul->un_debug; /* return debug value */
			/* Copy stucture if statistics are being kept */
			if (ul->un_logmap->mtm_tops) {
				ls->ls_topstats = *(ul->un_logmap->mtm_tops);
			}
			error = 0;
			if (copyout(ls, (void *)arg, sizeof (*ls)))
				error = EFAULT;
			kmem_free(ls, sizeof (*ls));
			return (error);
		}

		case _FIO_SEEK_DATA:
		case _FIO_SEEK_HOLE:
			if (ddi_copyin((void *)arg, &off, sizeof (off), flag))
				return (EFAULT);
			/* offset paramater is in/out */
			error = ufs_fio_holey(vp, cmd, &off);
			if (error)
				return (error);
			if (ddi_copyout(&off, (void *)arg, sizeof (off), flag))
				return (EFAULT);
			return (0);

		case _FIO_COMPRESSED:
		{
			/*
			 * This is a project private ufs ioctl() to mark
			 * the inode as that belonging to a compressed
			 * file. This is used to mark individual
			 * compressed files in a miniroot archive.
			 * The files compressed in this manner are
			 * automatically decompressed by the dcfs filesystem
			 * (via an interception in ufs_lookup - see decompvp())
			 * which is layered on top of ufs on a system running
			 * from the archive. See uts/common/fs/dcfs for details.
			 * This ioctl only marks the file as compressed - the
			 * actual compression is done by fiocompress (a
			 * userland utility) which invokes this ioctl().
			 */
			struct inode *ip = VTOI(vp);

			error = ufs_lockfs_begin(ufsvfsp, &ulp,
			    ULOCKFS_SETATTR_MASK);
			if (error)
				return (error);

			if (ulp) {
				TRANS_BEGIN_ASYNC(ufsvfsp, TOP_IUPDAT,
				    TOP_IUPDAT_SIZE(ip));
			}

			error = ufs_mark_compressed(vp);

			if (ulp) {
				TRANS_END_ASYNC(ufsvfsp, TOP_IUPDAT,
				    TOP_IUPDAT_SIZE(ip));
				ufs_lockfs_end(ulp);
			}

			return (error);

		}

		default:
			return (ENOTTY);
	}
}


/* ARGSUSED */
static int
ufs_getattr(struct vnode *vp, struct vattr *vap, int flags,
	struct cred *cr, caller_context_t *ct)
{
	struct inode *ip = VTOI(vp);
	struct ufsvfs *ufsvfsp;
	int err;

	if (vap->va_mask == AT_SIZE) {
		/*
		 * for performance, if only the size is requested don't bother
		 * with anything else.
		 */
		UFS_GET_ISIZE(&vap->va_size, ip);
		return (0);
	}

	/*
	 * inlined lockfs checks
	 */
	ufsvfsp = ip->i_ufsvfs;
	if ((ufsvfsp == NULL) || ULOCKFS_IS_HLOCK(&ufsvfsp->vfs_ulockfs)) {
		err = EIO;
		goto out;
	}

	rw_enter(&ip->i_contents, RW_READER);
	/*
	 * Return all the attributes.  This should be refined so
	 * that it only returns what's asked for.
	 */

	/*
	 * Copy from inode table.
	 */
	vap->va_type = vp->v_type;
	vap->va_mode = ip->i_mode & MODEMASK;
	/*
	 * If there is an ACL and there is a mask entry, then do the
	 * extra work that completes the equivalent of an acltomode(3)
	 * call.  According to POSIX P1003.1e, the acl mask should be
	 * returned in the group permissions field.
	 *
	 * - start with the original permission and mode bits (from above)
	 * - clear the group owner bits
	 * - add in the mask bits.
	 */
	if (ip->i_ufs_acl && ip->i_ufs_acl->aclass.acl_ismask) {
		vap->va_mode &= ~((VREAD | VWRITE | VEXEC) >> 3);
		vap->va_mode |=
		    (ip->i_ufs_acl->aclass.acl_maskbits & PERMMASK) << 3;
	}
	vap->va_uid = ip->i_uid;
	vap->va_gid = ip->i_gid;
	vap->va_fsid = ip->i_dev;
	vap->va_nodeid = (ino64_t)ip->i_number;
	vap->va_nlink = ip->i_nlink;
	vap->va_size = ip->i_size;
	if (vp->v_type == VCHR || vp->v_type == VBLK)
		vap->va_rdev = ip->i_rdev;
	else
		vap->va_rdev = 0;	/* not a b/c spec. */
	mutex_enter(&ip->i_tlock);
	ITIMES_NOLOCK(ip);	/* mark correct time in inode */
	vap->va_seq = ip->i_seq;
	vap->va_atime.tv_sec = (time_t)ip->i_atime.tv_sec;
	vap->va_atime.tv_nsec = ip->i_atime.tv_usec*1000;
	vap->va_mtime.tv_sec = (time_t)ip->i_mtime.tv_sec;
	vap->va_mtime.tv_nsec = ip->i_mtime.tv_usec*1000;
	vap->va_ctime.tv_sec = (time_t)ip->i_ctime.tv_sec;
	vap->va_ctime.tv_nsec = ip->i_ctime.tv_usec*1000;
	mutex_exit(&ip->i_tlock);

	switch (ip->i_mode & IFMT) {

	case IFBLK:
		vap->va_blksize = MAXBSIZE;		/* was BLKDEV_IOSIZE */
		break;

	case IFCHR:
		vap->va_blksize = MAXBSIZE;
		break;

	default:
		vap->va_blksize = ip->i_fs->fs_bsize;
		break;
	}
	vap->va_nblocks = (fsblkcnt64_t)ip->i_blocks;
	rw_exit(&ip->i_contents);
	err = 0;

out:
	return (err);
}

/*
 * Special wrapper to provide a callback for secpolicy_vnode_setattr().
 * The i_contents lock is already held by the caller and we need to
 * declare the inode as 'void *' argument.
 */
static int
ufs_priv_access(void *vip, int mode, struct cred *cr)
{
	struct inode *ip = vip;

	return (ufs_iaccess(ip, mode, cr, 0));
}

/*ARGSUSED4*/
static int
ufs_setattr(
	struct vnode *vp,
	struct vattr *vap,
	int flags,
	struct cred *cr,
	caller_context_t *ct)
{
	struct inode *ip = VTOI(vp);
	struct ufsvfs *ufsvfsp = ip->i_ufsvfs;
	struct fs *fs;
	struct ulockfs *ulp;
	char *errmsg1;
	char *errmsg2;
	long blocks;
	long int mask = vap->va_mask;
	size_t len1, len2;
	int issync;
	int trans_size;
	int dotrans;
	int dorwlock;
	int error;
	int owner_change;
	int dodqlock;
	timestruc_t now;
	vattr_t oldva;
	int retry = 1;
	int indeadlock;

	/*
	 * Cannot set these attributes.
	 */
	if ((mask & AT_NOSET) || (mask & AT_XVATTR))
		return (EINVAL);

	/*
	 * check for forced unmount
	 */
	if (ufsvfsp == NULL)
		return (EIO);

	fs = ufsvfsp->vfs_fs;
	if (fs->fs_ronly != 0)
		return (EROFS);

again:
	errmsg1 = NULL;
	errmsg2 = NULL;
	dotrans = 0;
	dorwlock = 0;
	dodqlock = 0;

	error = ufs_lockfs_begin(ufsvfsp, &ulp, ULOCKFS_SETATTR_MASK);
	if (error)
		goto out;

	/*
	 * Acquire i_rwlock before TRANS_BEGIN_CSYNC() if this is a file.
	 * This follows the protocol for read()/write().
	 */
	if (vp->v_type != VDIR) {
		/*
		 * ufs_tryirwlock uses rw_tryenter and checks for SLOCK to
		 * avoid i_rwlock, ufs_lockfs_begin deadlock. If deadlock
		 * possible, retries the operation.
		 */
		ufs_tryirwlock(&ip->i_rwlock, RW_WRITER, retry_file);
		if (indeadlock) {
			if (ulp)
				ufs_lockfs_end(ulp);
			goto again;
		}
		dorwlock = 1;
	}

	/*
	 * Truncate file.  Must have write permission and not be a directory.
	 */
	if (mask & AT_SIZE) {
		rw_enter(&ip->i_contents, RW_WRITER);
		if (vp->v_type == VDIR) {
			error = EISDIR;
			goto update_inode;
		}
		if (error = ufs_iaccess(ip, IWRITE, cr, 0))
			goto update_inode;

		rw_exit(&ip->i_contents);
		error = TRANS_ITRUNC(ip, vap->va_size, 0, cr);
		if (error) {
			rw_enter(&ip->i_contents, RW_WRITER);
			goto update_inode;
		}

		if (error == 0 && vap->va_size)
			vnevent_truncate(vp, ct);
	}

	if (ulp) {
		trans_size = (int)TOP_SETATTR_SIZE(ip);
		TRANS_BEGIN_CSYNC(ufsvfsp, issync, TOP_SETATTR, trans_size);
		++dotrans;
	}

	/*
	 * Acquire i_rwlock after TRANS_BEGIN_CSYNC() if this is a directory.
	 * This follows the protocol established by
	 * ufs_link/create/remove/rename/mkdir/rmdir/symlink.
	 */
	if (vp->v_type == VDIR) {
		ufs_tryirwlock_trans(&ip->i_rwlock, RW_WRITER, TOP_SETATTR,
		    retry_dir);
		if (indeadlock)
			goto again;
		dorwlock = 1;
	}

	/*
	 * Grab quota lock if we are changing the file's owner.
	 */
	if (mask & AT_UID) {
		rw_enter(&ufsvfsp->vfs_dqrwlock, RW_READER);
		dodqlock = 1;
	}
	rw_enter(&ip->i_contents, RW_WRITER);

	oldva.va_mode = ip->i_mode;
	oldva.va_uid = ip->i_uid;
	oldva.va_gid = ip->i_gid;

	vap->va_mask &= ~AT_SIZE;

	error = secpolicy_vnode_setattr(cr, vp, vap, &oldva, flags,
	    ufs_priv_access, ip);
	if (error)
		goto update_inode;

	mask = vap->va_mask;

	/*
	 * Change file access modes.
	 */
	if (mask & AT_MODE) {
		ip->i_mode = (ip->i_mode & IFMT) | (vap->va_mode & ~IFMT);
		TRANS_INODE(ufsvfsp, ip);
		ip->i_flag |= ICHG;
		if (stickyhack) {
			mutex_enter(&vp->v_lock);
			if ((ip->i_mode & (ISVTX | IEXEC | IFDIR)) == ISVTX)
				vp->v_flag |= VSWAPLIKE;
			else
				vp->v_flag &= ~VSWAPLIKE;
			mutex_exit(&vp->v_lock);
		}
	}
	if (mask & (AT_UID|AT_GID)) {
		if (mask & AT_UID) {
			/*
			 * Don't change ownership of the quota inode.
			 */
			if (ufsvfsp->vfs_qinod == ip) {
				ASSERT(ufsvfsp->vfs_qflags & MQ_ENABLED);
				error = EINVAL;
				goto update_inode;
			}

			/*
			 * No real ownership change.
			 */
			if (ip->i_uid == vap->va_uid) {
				blocks = 0;
				owner_change = 0;
			}
			/*
			 * Remove the blocks and the file, from the old user's
			 * quota.
			 */
			else {
				blocks = ip->i_blocks;
				owner_change = 1;

				(void) chkdq(ip, -blocks, /* force */ 1, cr,
				    (char **)NULL, (size_t *)NULL);
				(void) chkiq(ufsvfsp, /* change */ -1, ip,
				    (uid_t)ip->i_uid, /* force */ 1, cr,
				    (char **)NULL, (size_t *)NULL);
				dqrele(ip->i_dquot);
			}

			ip->i_uid = vap->va_uid;

			/*
			 * There is a real ownership change.
			 */
			if (owner_change) {
				/*
				 * Add the blocks and the file to the new
				 * user's quota.
				 */
				ip->i_dquot = getinoquota(ip);
				(void) chkdq(ip, blocks, /* force */ 1, cr,
				    &errmsg1, &len1);
				(void) chkiq(ufsvfsp, /* change */ 1,
				    (struct inode *)NULL, (uid_t)ip->i_uid,
				    /* force */ 1, cr, &errmsg2, &len2);
			}
		}
		if (mask & AT_GID) {
			ip->i_gid = vap->va_gid;
		}
		TRANS_INODE(ufsvfsp, ip);
		ip->i_flag |= ICHG;
	}
	/*
	 * Change file access or modified times.
	 */
	if (mask & (AT_ATIME|AT_MTIME)) {
		/* Check that the time value is within ufs range */
		if (((mask & AT_ATIME) && TIMESPEC_OVERFLOW(&vap->va_atime)) ||
		    ((mask & AT_MTIME) && TIMESPEC_OVERFLOW(&vap->va_mtime))) {
			error = EOVERFLOW;
			goto update_inode;
		}

		/*
		 * if the "noaccess" mount option is set and only atime
		 * update is requested, do nothing. No error is returned.
		 */
		if ((ufsvfsp->vfs_noatime) &&
		    ((mask & (AT_ATIME|AT_MTIME)) == AT_ATIME))
			goto skip_atime;

		if (mask & AT_ATIME) {
			ip->i_atime.tv_sec = vap->va_atime.tv_sec;
			ip->i_atime.tv_usec = vap->va_atime.tv_nsec / 1000;
			ip->i_flag &= ~IACC;
		}
		if (mask & AT_MTIME) {
			ip->i_mtime.tv_sec = vap->va_mtime.tv_sec;
			ip->i_mtime.tv_usec = vap->va_mtime.tv_nsec / 1000;
			gethrestime(&now);
			if (now.tv_sec > TIME32_MAX) {
				/*
				 * In 2038, ctime sticks forever..
				 */
				ip->i_ctime.tv_sec = TIME32_MAX;
				ip->i_ctime.tv_usec = 0;
			} else {
				ip->i_ctime.tv_sec = now.tv_sec;
				ip->i_ctime.tv_usec = now.tv_nsec / 1000;
			}
			ip->i_flag &= ~(IUPD|ICHG);
			ip->i_flag |= IMODTIME;
		}
		TRANS_INODE(ufsvfsp, ip);
		ip->i_flag |= IMOD;
	}

skip_atime:
	/*
	 * The presence of a shadow inode may indicate an ACL, but does
	 * not imply an ACL.  Future FSD types should be handled here too
	 * and check for the presence of the attribute-specific data
	 * before referencing it.
	 */
	if (ip->i_shadow) {
		/*
		 * XXX if ufs_iupdat is changed to sandbagged write fix
		 * ufs_acl_setattr to push ip to keep acls consistent
		 *
		 * Suppress out of inodes messages if we will retry.
		 */
		if (retry)
			ip->i_flag |= IQUIET;
		error = ufs_acl_setattr(ip, vap, cr);
		ip->i_flag &= ~IQUIET;
	}

update_inode:
	/*
	 * Setattr always increases the sequence number
	 */
	ip->i_seq++;

	/*
	 * if nfsd and not logging; push synchronously
	 */
	if ((curthread->t_flag & T_DONTPEND) && !TRANS_ISTRANS(ufsvfsp)) {
		ufs_iupdat(ip, 1);
	} else {
		ITIMES_NOLOCK(ip);
	}

	rw_exit(&ip->i_contents);
	if (dodqlock) {
		rw_exit(&ufsvfsp->vfs_dqrwlock);
	}
	if (dorwlock)
		rw_exit(&ip->i_rwlock);

	if (ulp) {
		if (dotrans) {
			int terr = 0;
			TRANS_END_CSYNC(ufsvfsp, terr, issync, TOP_SETATTR,
			    trans_size);
			if (error == 0)
				error = terr;
		}
		ufs_lockfs_end(ulp);
	}
out:
	/*
	 * If out of inodes or blocks, see if we can free something
	 * up from the delete queue.
	 */
	if ((error == ENOSPC) && retry && TRANS_ISTRANS(ufsvfsp)) {
		ufs_delete_drain_wait(ufsvfsp, 1);
		retry = 0;
		if (errmsg1 != NULL)
			kmem_free(errmsg1, len1);
		if (errmsg2 != NULL)
			kmem_free(errmsg2, len2);
		goto again;
	}
	if (errmsg1 != NULL) {
		uprintf(errmsg1);
		kmem_free(errmsg1, len1);
	}
	if (errmsg2 != NULL) {
		uprintf(errmsg2);
		kmem_free(errmsg2, len2);
	}
	return (error);
}

/*ARGSUSED*/
static int
ufs_access(struct vnode *vp, int mode, int flags, struct cred *cr,
	caller_context_t *ct)
{
	struct inode *ip = VTOI(vp);

	if (ip->i_ufsvfs == NULL)
		return (EIO);

	/*
	 * The ufs_iaccess function wants to be called with
	 * mode bits expressed as "ufs specific" bits.
	 * I.e., VWRITE|VREAD|VEXEC do not make sense to
	 * ufs_iaccess() but IWRITE|IREAD|IEXEC do.
	 * But since they're the same we just pass the vnode mode
	 * bit but just verify that assumption at compile time.
	 */
#if IWRITE != VWRITE || IREAD != VREAD || IEXEC != VEXEC
#error "ufs_access needs to map Vmodes to Imodes"
#endif
	return (ufs_iaccess(ip, mode, cr, 1));
}

/* ARGSUSED */
static int
ufs_readlink(struct vnode *vp, struct uio *uiop, struct cred *cr,
	caller_context_t *ct)
{
	struct inode *ip = VTOI(vp);
	struct ufsvfs *ufsvfsp;
	struct ulockfs *ulp;
	int error;
	int fastsymlink;

	if (vp->v_type != VLNK) {
		error = EINVAL;
		goto nolockout;
	}

	/*
	 * If the symbolic link is empty there is nothing to read.
	 * Fast-track these empty symbolic links
	 */
	if (ip->i_size == 0) {
		error = 0;
		goto nolockout;
	}

	ufsvfsp = ip->i_ufsvfs;
	error = ufs_lockfs_begin(ufsvfsp, &ulp, ULOCKFS_READLINK_MASK);
	if (error)
		goto nolockout;
	/*
	 * The ip->i_rwlock protects the data blocks used for FASTSYMLINK
	 */
again:
	fastsymlink = 0;
	if (ip->i_flag & IFASTSYMLNK) {
		rw_enter(&ip->i_rwlock, RW_READER);
		rw_enter(&ip->i_contents, RW_READER);
		if (ip->i_flag & IFASTSYMLNK) {
			if (!ULOCKFS_IS_NOIACC(ITOUL(ip)) &&
			    (ip->i_fs->fs_ronly == 0) &&
			    (!ufsvfsp->vfs_noatime)) {
				mutex_enter(&ip->i_tlock);
				ip->i_flag |= IACC;
				mutex_exit(&ip->i_tlock);
			}
			error = uiomove((caddr_t)&ip->i_db[1],
			    MIN(ip->i_size, uiop->uio_resid),
			    UIO_READ, uiop);
			ITIMES(ip);
			++fastsymlink;
		}
		rw_exit(&ip->i_contents);
		rw_exit(&ip->i_rwlock);
	}
	if (!fastsymlink) {
		ssize_t size;	/* number of bytes read  */
		caddr_t basep;	/* pointer to input data */
		ino_t ino;
		long  igen;
		struct uio tuio;	/* temp uio struct */
		struct uio *tuiop;
		iovec_t tiov;		/* temp iovec struct */
		char kbuf[FSL_SIZE];	/* buffer to hold fast symlink */
		int tflag = 0;		/* flag to indicate temp vars used */

		ino = ip->i_number;
		igen = ip->i_gen;
		size = uiop->uio_resid;
		basep = uiop->uio_iov->iov_base;
		tuiop = uiop;

		rw_enter(&ip->i_rwlock, RW_WRITER);
		rw_enter(&ip->i_contents, RW_WRITER);
		if (ip->i_flag & IFASTSYMLNK) {
			rw_exit(&ip->i_contents);
			rw_exit(&ip->i_rwlock);
			goto again;
		}

		/* can this be a fast symlink and is it a user buffer? */
		if (ip->i_size <= FSL_SIZE &&
		    (uiop->uio_segflg == UIO_USERSPACE ||
		    uiop->uio_segflg == UIO_USERISPACE)) {

			bzero(&tuio, sizeof (struct uio));
			/*
			 * setup a kernel buffer to read link into.  this
			 * is to fix a race condition where the user buffer
			 * got corrupted before copying it into the inode.
			 */
			size = ip->i_size;
			tiov.iov_len = size;
			tiov.iov_base = kbuf;
			tuio.uio_iov = &tiov;
			tuio.uio_iovcnt = 1;
			tuio.uio_offset = uiop->uio_offset;
			tuio.uio_segflg = UIO_SYSSPACE;
			tuio.uio_fmode = uiop->uio_fmode;
			tuio.uio_extflg = uiop->uio_extflg;
			tuio.uio_limit = uiop->uio_limit;
			tuio.uio_resid = size;

			basep = tuio.uio_iov->iov_base;
			tuiop = &tuio;
			tflag = 1;
		}

		error = rdip(ip, tuiop, 0, cr);
		if (!(error == 0 && ip->i_number == ino && ip->i_gen == igen)) {
			rw_exit(&ip->i_contents);
			rw_exit(&ip->i_rwlock);
			goto out;
		}

		if (tflag == 0)
			size -= uiop->uio_resid;

		if ((tflag == 0 && ip->i_size <= FSL_SIZE &&
		    ip->i_size == size) || (tflag == 1 &&
		    tuio.uio_resid == 0)) {
			error = kcopy(basep, &ip->i_db[1], ip->i_size);
			if (error == 0) {
				ip->i_flag |= IFASTSYMLNK;
				/*
				 * free page
				 */
				(void) VOP_PUTPAGE(ITOV(ip),
				    (offset_t)0, PAGESIZE,
				    (B_DONTNEED | B_FREE | B_FORCE | B_ASYNC),
				    cr, ct);
			} else {
				int i;
				/* error, clear garbage left behind */
				for (i = 1; i < NDADDR; i++)
					ip->i_db[i] = 0;
				for (i = 0; i < NIADDR; i++)
					ip->i_ib[i] = 0;
			}
		}
		if (tflag == 1) {
			/* now, copy it into the user buffer */
			error = uiomove((caddr_t)kbuf,
			    MIN(size, uiop->uio_resid),
			    UIO_READ, uiop);
		}
		rw_exit(&ip->i_contents);
		rw_exit(&ip->i_rwlock);
	}
out:
	if (ulp) {
		ufs_lockfs_end(ulp);
	}
nolockout:
	return (error);
}

/* ARGSUSED */
static int
ufs_fsync(struct vnode *vp, int syncflag, struct cred *cr,
	caller_context_t *ct)
{
	struct inode *ip = VTOI(vp);
	struct ufsvfs *ufsvfsp = ip->i_ufsvfs;
	struct ulockfs *ulp;
	int error;

	error = ufs_lockfs_begin(ufsvfsp, &ulp, ULOCKFS_FSYNC_MASK);
	if (error)
		return (error);

	if (TRANS_ISTRANS(ufsvfsp)) {
		/*
		 * First push out any data pages
		 */
		if (vn_has_cached_data(vp) && !(syncflag & FNODSYNC) &&
		    (vp->v_type != VCHR) && !(IS_SWAPVP(vp))) {
			error = VOP_PUTPAGE(vp, (offset_t)0, (size_t)0,
			    0, CRED(), ct);
			if (error)
				goto out;
		}

		/*
		 * Delta any delayed inode times updates
		 * and push inode to log.
		 * All other inode deltas will have already been delta'd
		 * and will be pushed during the commit.
		 */
		if (!(syncflag & FDSYNC) &&
		    ((ip->i_flag & (IMOD|IMODACC)) == IMODACC)) {
			if (ulp) {
				TRANS_BEGIN_ASYNC(ufsvfsp, TOP_FSYNC,
				    TOP_SYNCIP_SIZE);
			}
			rw_enter(&ip->i_contents, RW_READER);
			mutex_enter(&ip->i_tlock);
			ip->i_flag &= ~IMODTIME;
			mutex_exit(&ip->i_tlock);
			ufs_iupdat(ip, I_SYNC);
			rw_exit(&ip->i_contents);
			if (ulp) {
				TRANS_END_ASYNC(ufsvfsp, TOP_FSYNC,
				    TOP_SYNCIP_SIZE);
			}
		}

		/*
		 * Commit the Moby transaction
		 *
		 * Deltas have already been made so we just need to
		 * commit them with a synchronous transaction.
		 * TRANS_BEGIN_SYNC() will return an error
		 * if there are no deltas to commit, for an
		 * empty transaction.
		 */
		if (ulp) {
			TRANS_BEGIN_SYNC(ufsvfsp, TOP_FSYNC, TOP_COMMIT_SIZE,
			    error);
			if (error) {
				error = 0; /* commit wasn't needed */
				goto out;
			}
			TRANS_END_SYNC(ufsvfsp, error, TOP_FSYNC,
			    TOP_COMMIT_SIZE);
		}
	} else {	/* not logging */
		if (!(IS_SWAPVP(vp)))
			if (syncflag & FNODSYNC) {
				/* Just update the inode only */
				TRANS_IUPDAT(ip, 1);
				error = 0;
			} else if (syncflag & FDSYNC)
				/* Do data-synchronous writes */
				error = TRANS_SYNCIP(ip, 0, I_DSYNC, TOP_FSYNC);
			else
				/* Do synchronous writes */
				error = TRANS_SYNCIP(ip, 0, I_SYNC, TOP_FSYNC);

		rw_enter(&ip->i_contents, RW_WRITER);
		if (!error)
			error = ufs_sync_indir(ip);
		rw_exit(&ip->i_contents);
	}
out:
	if (ulp) {
		ufs_lockfs_end(ulp);
	}
	return (error);
}

/*ARGSUSED*/
static void
ufs_inactive(struct vnode *vp, struct cred *cr, caller_context_t *ct)
{
	ufs_iinactive(VTOI(vp));
}

/*
 * Unix file system operations having to do with directory manipulation.
 */
int ufs_lookup_idle_count = 2;	/* Number of inodes to idle each time */
/* ARGSUSED */
static int
ufs_lookup(struct vnode *dvp, char *nm, struct vnode **vpp,
	struct pathname *pnp, int flags, struct vnode *rdir, struct cred *cr,
	caller_context_t *ct, int *direntflags, pathname_t *realpnp)
{
	struct inode *ip;
	struct inode *sip;
	struct inode *xip;
	struct ufsvfs *ufsvfsp;
	struct ulockfs *ulp;
	struct vnode *vp;
	int error;

	/*
	 * Check flags for type of lookup (regular file or attribute file)
	 */

	ip = VTOI(dvp);

	if (flags & LOOKUP_XATTR) {

		/*
		 * If not mounted with XATTR support then return EINVAL
		 */

		if (!(ip->i_ufsvfs->vfs_vfs->vfs_flag & VFS_XATTR))
			return (EINVAL);
		/*
		 * We don't allow recursive attributes...
		 * Maybe someday we will.
		 */
		if ((ip->i_cflags & IXATTR)) {
			return (EINVAL);
		}

		if ((vp = dnlc_lookup(dvp, XATTR_DIR_NAME)) == NULL) {
			error = ufs_xattr_getattrdir(dvp, &sip, flags, cr);
			if (error) {
				*vpp = NULL;
				goto out;
			}

			vp = ITOV(sip);
			dnlc_update(dvp, XATTR_DIR_NAME, vp);
		}

		/*
		 * Check accessibility of directory.
		 */
		if (vp == DNLC_NO_VNODE) {
			VN_RELE(vp);
			error = ENOENT;
			goto out;
		}
		if ((error = ufs_iaccess(VTOI(vp), IEXEC, cr, 1)) != 0) {
			VN_RELE(vp);
			goto out;
		}

		*vpp = vp;
		return (0);
	}

	/*
	 * Check for a null component, which we should treat as
	 * looking at dvp from within it's parent, so we don't
	 * need a call to ufs_iaccess(), as it has already been
	 * done.
	 */
	if (nm[0] == 0) {
		VN_HOLD(dvp);
		error = 0;
		*vpp = dvp;
		goto out;
	}

	/*
	 * Check for "." ie itself. this is a quick check and
	 * avoids adding "." into the dnlc (which have been seen
	 * to occupy >10% of the cache).
	 */
	if ((nm[0] == '.') && (nm[1] == 0)) {
		/*
		 * Don't return without checking accessibility
		 * of the directory. We only need the lock if
		 * we are going to return it.
		 */
		if ((error = ufs_iaccess(ip, IEXEC, cr, 1)) == 0) {
			VN_HOLD(dvp);
			*vpp = dvp;
		}
		goto out;
	}

	/*
	 * Fast path: Check the directory name lookup cache.
	 */
	if (vp = dnlc_lookup(dvp, nm)) {
		/*
		 * Check accessibility of directory.
		 */
		if ((error = ufs_iaccess(ip, IEXEC, cr, 1)) != 0) {
			VN_RELE(vp);
			goto out;
		}
		if (vp == DNLC_NO_VNODE) {
			VN_RELE(vp);
			error = ENOENT;
			goto out;
		}
		xip = VTOI(vp);
		ulp = NULL;
		goto fastpath;
	}

	/*
	 * Keep the idle queue from getting too long by
	 * idling two inodes before attempting to allocate another.
	 *    This operation must be performed before entering
	 *    lockfs or a transaction.
	 */
	if (ufs_idle_q.uq_ne > ufs_idle_q.uq_hiwat)
		if ((curthread->t_flag & T_DONTBLOCK) == 0) {
			ins.in_lidles.value.ul += ufs_lookup_idle_count;
			ufs_idle_some(ufs_lookup_idle_count);
		}

retry_lookup:
	/*
	 * Check accessibility of directory.
	 */
	if (error = ufs_diraccess(ip, IEXEC, cr))
		goto out;

	ufsvfsp = ip->i_ufsvfs;
	error = ufs_lockfs_begin(ufsvfsp, &ulp, ULOCKFS_LOOKUP_MASK);
	if (error)
		goto out;

	error = ufs_dirlook(ip, nm, &xip, cr, 1, 0);

fastpath:
	if (error == 0) {
		ip = xip;
		*vpp = ITOV(ip);

		/*
		 * If vnode is a device return special vnode instead.
		 */
		if (IS_DEVVP(*vpp)) {
			struct vnode *newvp;

			newvp = specvp(*vpp, (*vpp)->v_rdev, (*vpp)->v_type,
			    cr);
			VN_RELE(*vpp);
			if (newvp == NULL)
				error = ENOSYS;
			else
				*vpp = newvp;
		} else if (ip->i_cflags & ICOMPRESS) {
			struct vnode *newvp;

			/*
			 * Compressed file, substitute dcfs vnode
			 */
			newvp = decompvp(*vpp, cr, ct);
			VN_RELE(*vpp);
			if (newvp == NULL)
				error = ENOSYS;
			else
				*vpp = newvp;
		}
	}
	if (ulp) {
		ufs_lockfs_end(ulp);
	}

	if (error == EAGAIN)
		goto retry_lookup;

out:
	return (error);
}

/*ARGSUSED*/
static int
ufs_create(struct vnode *dvp, char *name, struct vattr *vap, enum vcexcl excl,
	int mode, struct vnode **vpp, struct cred *cr, int flag,
	caller_context_t *ct, vsecattr_t *vsecp)
{
	struct inode *ip;
	struct inode *xip;
	struct inode *dip;
	struct vnode *xvp;
	struct ufsvfs *ufsvfsp;
	struct ulockfs *ulp;
	int error;
	int issync;
	int truncflag;
	int trans_size;
	int noentry;
	int defer_dip_seq_update = 0;	/* need to defer update of dip->i_seq */
	int retry = 1;
	int indeadlock;

again:
	ip = VTOI(dvp);
	ufsvfsp = ip->i_ufsvfs;
	truncflag = 0;

	error = ufs_lockfs_begin(ufsvfsp, &ulp, ULOCKFS_CREATE_MASK);
	if (error)
		goto out;

	if (ulp) {
		trans_size = (int)TOP_CREATE_SIZE(ip);
		TRANS_BEGIN_CSYNC(ufsvfsp, issync, TOP_CREATE, trans_size);
	}

	if ((vap->va_mode & VSVTX) && secpolicy_vnode_stky_modify(cr) != 0)
		vap->va_mode &= ~VSVTX;

	if (*name == '\0') {
		/*
		 * Null component name refers to the directory itself.
		 */
		VN_HOLD(dvp);
		/*
		 * Even though this is an error case, we need to grab the
		 * quota lock since the error handling code below is common.
		 */
		rw_enter(&ufsvfsp->vfs_dqrwlock, RW_READER);
		rw_enter(&ip->i_contents, RW_WRITER);
		error = EEXIST;
	} else {
		xip = NULL;
		noentry = 0;
		/*
		 * ufs_tryirwlock_trans uses rw_tryenter and checks for SLOCK
		 * to avoid i_rwlock, ufs_lockfs_begin deadlock. If deadlock
		 * possible, retries the operation.
		 */
		ufs_tryirwlock_trans(&ip->i_rwlock, RW_WRITER, TOP_CREATE,
		    retry_dir);
		if (indeadlock)
			goto again;

		xvp = dnlc_lookup(dvp, name);
		if (xvp == DNLC_NO_VNODE) {
			noentry = 1;
			VN_RELE(xvp);
			xvp = NULL;
		}
		if (xvp) {
			rw_exit(&ip->i_rwlock);
			if (error = ufs_iaccess(ip, IEXEC, cr, 1)) {
				VN_RELE(xvp);
			} else {
				error = EEXIST;
				xip = VTOI(xvp);
			}
		} else {
			/*
			 * Suppress file system full message if we will retry
			 */
			error = ufs_direnter_cm(ip, name, DE_CREATE,
			    vap, &xip, cr, (noentry | (retry ? IQUIET : 0)));
			if (error == EAGAIN) {
				if (ulp) {
					TRANS_END_CSYNC(ufsvfsp, error, issync,
					    TOP_CREATE, trans_size);
					ufs_lockfs_end(ulp);
				}
				goto again;
			}
			rw_exit(&ip->i_rwlock);
		}
		ip = xip;
		if (ip != NULL) {
			rw_enter(&ufsvfsp->vfs_dqrwlock, RW_READER);
			rw_enter(&ip->i_contents, RW_WRITER);
		}
	}

	/*
	 * If the file already exists and this is a non-exclusive create,
	 * check permissions and allow access for non-directories.
	 * Read-only create of an existing directory is also allowed.
	 * We fail an exclusive create of anything which already exists.
	 */
	if (error == EEXIST) {
		dip = VTOI(dvp);
		if (excl == NONEXCL) {
			if ((((ip->i_mode & IFMT) == IFDIR) ||
			    ((ip->i_mode & IFMT) == IFATTRDIR)) &&
			    (mode & IWRITE))
				error = EISDIR;
			else if (mode)
				error = ufs_iaccess(ip, mode, cr, 0);
			else
				error = 0;
		}
		if (error) {
			rw_exit(&ip->i_contents);
			rw_exit(&ufsvfsp->vfs_dqrwlock);
			VN_RELE(ITOV(ip));
			goto unlock;
		}
		/*
		 * If the error EEXIST was set, then i_seq can not
		 * have been updated. The sequence number interface
		 * is defined such that a non-error VOP_CREATE must
		 * increase the dir va_seq it by at least one. If we
		 * have cleared the error, increase i_seq. Note that
		 * we are increasing the dir i_seq and in rare cases
		 * ip may actually be from the dvp, so we already have
		 * the locks and it will not be subject to truncation.
		 * In case we have to update i_seq of the parent
		 * directory dip, we have to defer it till we have
		 * released our locks on ip due to lock ordering requirements.
		 */
		if (ip != dip)
			defer_dip_seq_update = 1;
		else
			ip->i_seq++;

		if (((ip->i_mode & IFMT) == IFREG) &&
		    (vap->va_mask & AT_SIZE) && vap->va_size == 0) {
			/*
			 * Truncate regular files, if requested by caller.
			 * Grab i_rwlock to make sure no one else is
			 * currently writing to the file (we promised
			 * bmap we would do this).
			 * Must get the locks in the correct order.
			 */
			if (ip->i_size == 0) {
				ip->i_flag |= ICHG | IUPD;
				ip->i_seq++;
				TRANS_INODE(ufsvfsp, ip);
			} else {
				/*
				 * Large Files: Why this check here?
				 * Though we do it in vn_create() we really
				 * want to guarantee that we do not destroy
				 * Large file data by atomically checking
				 * the size while holding the contents
				 * lock.
				 */
				if (flag && !(flag & FOFFMAX) &&
				    ((ip->i_mode & IFMT) == IFREG) &&
				    (ip->i_size > (offset_t)MAXOFF32_T)) {
					rw_exit(&ip->i_contents);
					rw_exit(&ufsvfsp->vfs_dqrwlock);
					error = EOVERFLOW;
					goto unlock;
				}
				if (TRANS_ISTRANS(ufsvfsp))
					truncflag++;
				else {
					rw_exit(&ip->i_contents);
					rw_exit(&ufsvfsp->vfs_dqrwlock);
					ufs_tryirwlock_trans(&ip->i_rwlock,
					    RW_WRITER, TOP_CREATE,
					    retry_file);
					if (indeadlock) {
						VN_RELE(ITOV(ip));
						goto again;
					}
					rw_enter(&ufsvfsp->vfs_dqrwlock,
					    RW_READER);
					rw_enter(&ip->i_contents, RW_WRITER);
					(void) ufs_itrunc(ip, (u_offset_t)0, 0,
					    cr);
					rw_exit(&ip->i_rwlock);
				}

			}
			if (error == 0) {
				vnevent_create(ITOV(ip), ct);
			}
		}
	}

	if (error) {
		if (ip != NULL) {
			rw_exit(&ufsvfsp->vfs_dqrwlock);
			rw_exit(&ip->i_contents);
		}
		goto unlock;
	}

	*vpp = ITOV(ip);
	ITIMES(ip);
	rw_exit(&ip->i_contents);
	rw_exit(&ufsvfsp->vfs_dqrwlock);

	/*
	 * If vnode is a device return special vnode instead.
	 */
	if (!error && IS_DEVVP(*vpp)) {
		struct vnode *newvp;

		newvp = specvp(*vpp, (*vpp)->v_rdev, (*vpp)->v_type, cr);
		VN_RELE(*vpp);
		if (newvp == NULL) {
			error = ENOSYS;
			goto unlock;
		}
		truncflag = 0;
		*vpp = newvp;
	}
unlock:

	/*
	 * Do the deferred update of the parent directory's sequence
	 * number now.
	 */
	if (defer_dip_seq_update == 1) {
		rw_enter(&dip->i_contents, RW_READER);
		mutex_enter(&dip->i_tlock);
		dip->i_seq++;
		mutex_exit(&dip->i_tlock);
		rw_exit(&dip->i_contents);
	}

	if (ulp) {
		int terr = 0;

		TRANS_END_CSYNC(ufsvfsp, terr, issync, TOP_CREATE,
		    trans_size);

		/*
		 * If we haven't had a more interesting failure
		 * already, then anything that might've happened
		 * here should be reported.
		 */
		if (error == 0)
			error = terr;
	}

	if (!error && truncflag) {
		ufs_tryirwlock(&ip->i_rwlock, RW_WRITER, retry_trunc);
		if (indeadlock) {
			if (ulp)
				ufs_lockfs_end(ulp);
			VN_RELE(ITOV(ip));
			goto again;
		}
		(void) TRANS_ITRUNC(ip, (u_offset_t)0, 0, cr);
		rw_exit(&ip->i_rwlock);
	}

	if (ulp)
		ufs_lockfs_end(ulp);

	/*
	 * If no inodes available, try to free one up out of the
	 * pending delete queue.
	 */
	if ((error == ENOSPC) && retry && TRANS_ISTRANS(ufsvfsp)) {
		ufs_delete_drain_wait(ufsvfsp, 1);
		retry = 0;
		goto again;
	}

out:
	return (error);
}

extern int ufs_idle_max;
/*ARGSUSED*/
static int
ufs_remove(struct vnode *vp, char *nm, struct cred *cr,
	caller_context_t *ct, int flags)
{
	struct inode *ip = VTOI(vp);
	struct ufsvfs *ufsvfsp	= ip->i_ufsvfs;
	struct ulockfs *ulp;
	vnode_t *rmvp = NULL;	/* Vnode corresponding to name being removed */
	int indeadlock;
	int error;
	int issync;
	int trans_size;

	/*
	 * don't let the delete queue get too long
	 */
	if (ufsvfsp == NULL) {
		error = EIO;
		goto out;
	}
	if (ufsvfsp->vfs_delete.uq_ne > ufs_idle_max)
		ufs_delete_drain(vp->v_vfsp, 1, 1);

	error = ufs_eventlookup(vp, nm, cr, &rmvp);
	if (rmvp != NULL) {
		/* Only send the event if there were no errors */
		if (error == 0)
			vnevent_remove(rmvp, vp, nm, ct);
		VN_RELE(rmvp);
	}

retry_remove:
	error = ufs_lockfs_begin(ufsvfsp, &ulp, ULOCKFS_REMOVE_MASK);
	if (error)
		goto out;

	if (ulp)
		TRANS_BEGIN_CSYNC(ufsvfsp, issync, TOP_REMOVE,
		    trans_size = (int)TOP_REMOVE_SIZE(VTOI(vp)));

	/*
	 * ufs_tryirwlock_trans uses rw_tryenter and checks for SLOCK
	 * to avoid i_rwlock, ufs_lockfs_begin deadlock. If deadlock
	 * possible, retries the operation.
	 */
	ufs_tryirwlock_trans(&ip->i_rwlock, RW_WRITER, TOP_REMOVE, retry);
	if (indeadlock)
		goto retry_remove;
	error = ufs_dirremove(ip, nm, (struct inode *)0, (struct vnode *)0,
	    DR_REMOVE, cr);
	rw_exit(&ip->i_rwlock);

	if (ulp) {
		TRANS_END_CSYNC(ufsvfsp, error, issync, TOP_REMOVE, trans_size);
		ufs_lockfs_end(ulp);
	}

out:
	return (error);
}

/*
 * Link a file or a directory.  Only privileged processes are allowed to
 * make links to directories.
 */
/*ARGSUSED*/
static int
ufs_link(struct vnode *tdvp, struct vnode *svp, char *tnm, struct cred *cr,
	caller_context_t *ct, int flags)
{
	struct inode *sip;
	struct inode *tdp = VTOI(tdvp);
	struct ufsvfs *ufsvfsp = tdp->i_ufsvfs;
	struct ulockfs *ulp;
	struct vnode *realvp;
	int error;
	int issync;
	int trans_size;
	int isdev;
	int indeadlock;

retry_link:
	error = ufs_lockfs_begin(ufsvfsp, &ulp, ULOCKFS_LINK_MASK);
	if (error)
		goto out;

	if (ulp)
		TRANS_BEGIN_CSYNC(ufsvfsp, issync, TOP_LINK,
		    trans_size = (int)TOP_LINK_SIZE(VTOI(tdvp)));

	if (VOP_REALVP(svp, &realvp, ct) == 0)
		svp = realvp;

	/*
	 * Make sure link for extended attributes is valid
	 * We only support hard linking of attr in ATTRDIR to ATTRDIR
	 *
	 * Make certain we don't attempt to look at a device node as
	 * a ufs inode.
	 */

	isdev = IS_DEVVP(svp);
	if (((isdev == 0) && ((VTOI(svp)->i_cflags & IXATTR) == 0) &&
	    ((tdp->i_mode & IFMT) == IFATTRDIR)) ||
	    ((isdev == 0) && (VTOI(svp)->i_cflags & IXATTR) &&
	    ((tdp->i_mode & IFMT) == IFDIR))) {
		error = EINVAL;
		goto unlock;
	}

	sip = VTOI(svp);
	if ((svp->v_type == VDIR &&
	    secpolicy_fs_linkdir(cr, ufsvfsp->vfs_vfs) != 0) ||
	    (sip->i_uid != crgetuid(cr) && secpolicy_basic_link(cr) != 0)) {
		error = EPERM;
		goto unlock;
	}

	/*
	 * ufs_tryirwlock_trans uses rw_tryenter and checks for SLOCK
	 * to avoid i_rwlock, ufs_lockfs_begin deadlock. If deadlock
	 * possible, retries the operation.
	 */
	ufs_tryirwlock_trans(&tdp->i_rwlock, RW_WRITER, TOP_LINK, retry);
	if (indeadlock)
		goto retry_link;
	error = ufs_direnter_lr(tdp, tnm, DE_LINK, (struct inode *)0,
	    sip, cr);
	rw_exit(&tdp->i_rwlock);

unlock:
	if (ulp) {
		TRANS_END_CSYNC(ufsvfsp, error, issync, TOP_LINK, trans_size);
		ufs_lockfs_end(ulp);
	}

	if (!error) {
		vnevent_link(svp, ct);
	}
out:
	return (error);
}

uint64_t ufs_rename_retry_cnt;
uint64_t ufs_rename_upgrade_retry_cnt;
uint64_t ufs_rename_dircheck_retry_cnt;
clock_t	 ufs_rename_backoff_delay = 1;

/*
 * Rename a file or directory.
 * We are given the vnode and entry string of the source and the
 * vnode and entry string of the place we want to move the source
 * to (the target). The essential operation is:
 *	unlink(target);
 *	link(source, target);
 *	unlink(source);
 * but "atomically".  Can't do full commit without saving state in
 * the inode on disk, which isn't feasible at this time.  Best we
 * can do is always guarantee that the TARGET exists.
 */

/*ARGSUSED*/
static int
ufs_rename(
	struct vnode *sdvp,		/* old (source) parent vnode */
	char *snm,			/* old (source) entry name */
	struct vnode *tdvp,		/* new (target) parent vnode */
	char *tnm,			/* new (target) entry name */
	struct cred *cr,
	caller_context_t *ct,
	int flags)
{
	struct inode *sip = NULL;	/* source inode */
	struct inode *ip = NULL;	/* check inode */
	struct inode *sdp;		/* old (source) parent inode */
	struct inode *tdp;		/* new (target) parent inode */
	struct vnode *svp = NULL;	/* source vnode */
	struct vnode *tvp = NULL;	/* target vnode, if it exists */
	struct vnode *realvp;
	struct ufsvfs *ufsvfsp;
	struct ulockfs *ulp = NULL;
	struct ufs_slot slot;
	timestruc_t now;
	int error;
	int issync;
	int trans_size;
	krwlock_t *first_lock;
	krwlock_t *second_lock;
	krwlock_t *reverse_lock;
	int serr, terr;

	sdp = VTOI(sdvp);
	slot.fbp = NULL;
	ufsvfsp = sdp->i_ufsvfs;

	if (VOP_REALVP(tdvp, &realvp, ct) == 0)
		tdvp = realvp;

	/* Must do this before taking locks in case of DNLC miss */
	terr = ufs_eventlookup(tdvp, tnm, cr, &tvp);
	serr = ufs_eventlookup(sdvp, snm, cr, &svp);

	if ((serr == 0) && ((terr == 0) || (terr == ENOENT))) {
		if (tvp != NULL)
			vnevent_pre_rename_dest(tvp, tdvp, tnm, ct);

		/*
		 * Notify the target directory of the rename event
		 * if source and target directories are not the same.
		 */
		if (sdvp != tdvp)
			vnevent_pre_rename_dest_dir(tdvp, svp, tnm, ct);

		if (svp != NULL)
			vnevent_pre_rename_src(svp, sdvp, snm, ct);
	}

	if (svp != NULL)
		VN_RELE(svp);

retry_rename:
	error = ufs_lockfs_begin(ufsvfsp, &ulp, ULOCKFS_RENAME_MASK);
	if (error)
		goto unlock;

	if (ulp)
		TRANS_BEGIN_CSYNC(ufsvfsp, issync, TOP_RENAME,
		    trans_size = (int)TOP_RENAME_SIZE(sdp));

	if (VOP_REALVP(tdvp, &realvp, ct) == 0)
		tdvp = realvp;

	tdp = VTOI(tdvp);

	/*
	 * We only allow renaming of attributes from ATTRDIR to ATTRDIR.
	 */
	if ((tdp->i_mode & IFMT) != (sdp->i_mode & IFMT)) {
		error = EINVAL;
		goto unlock;
	}

	/*
	 * Check accessibility of directory.
	 */
	if (error = ufs_diraccess(sdp, IEXEC, cr))
		goto unlock;

	/*
	 * Look up inode of file we're supposed to rename.
	 */
	gethrestime(&now);
	if (error = ufs_dirlook(sdp, snm, &sip, cr, 0, 0)) {
		if (error == EAGAIN) {
			if (ulp) {
				TRANS_END_CSYNC(ufsvfsp, error, issync,
				    TOP_RENAME, trans_size);
				ufs_lockfs_end(ulp);
			}
			goto retry_rename;
		}

		goto unlock;
	}

	/*
	 * Lock both the source and target directories (they may be
	 * the same) to provide the atomicity semantics that was
	 * previously provided by the per file system vfs_rename_lock
	 *
	 * with vfs_rename_lock removed to allow simultaneous renames
	 * within a file system, ufs_dircheckpath can deadlock while
	 * traversing back to ensure that source is not a parent directory
	 * of target parent directory. This is because we get into
	 * ufs_dircheckpath with the sdp and tdp locks held as RW_WRITER.
	 * If the tdp and sdp of the simultaneous renames happen to be
	 * in the path of each other, it can lead to a deadlock. This
	 * can be avoided by getting the locks as RW_READER here and then
	 * upgrading to RW_WRITER after completing the ufs_dircheckpath.
	 *
	 * We hold the target directory's i_rwlock after calling
	 * ufs_lockfs_begin but in many other operations (like ufs_readdir)
	 * VOP_RWLOCK is explicitly called by the filesystem independent code
	 * before calling the file system operation. In these cases the order
	 * is reversed (i.e i_rwlock is taken first and then ufs_lockfs_begin
	 * is called). This is fine as long as ufs_lockfs_begin acts as a VOP
	 * counter but with ufs_quiesce setting the SLOCK bit this becomes a
	 * synchronizing object which might lead to a deadlock. So we use
	 * rw_tryenter instead of rw_enter. If we fail to get this lock and
	 * find that SLOCK bit is set, we call ufs_lockfs_end and restart the
	 * operation.
	 */
retry:
	first_lock = &tdp->i_rwlock;
	second_lock = &sdp->i_rwlock;
retry_firstlock:
	if (!rw_tryenter(first_lock, RW_READER)) {
		/*
		 * We didn't get the lock. Check if the SLOCK is set in the
		 * ufsvfs. If yes, we might be in a deadlock. Safer to give up
		 * and wait for SLOCK to be cleared.
		 */

		if (ulp && ULOCKFS_IS_SLOCK(ulp)) {
			TRANS_END_CSYNC(ufsvfsp, error, issync, TOP_RENAME,
			    trans_size);
			ufs_lockfs_end(ulp);
			goto retry_rename;

		} else {
			/*
			 * SLOCK isn't set so this is a genuine synchronization
			 * case. Let's try again after giving them a breather.
			 */
			delay(RETRY_LOCK_DELAY);
			goto  retry_firstlock;
		}
	}
	/*
	 * Need to check if the tdp and sdp are same !!!
	 */
	if ((tdp != sdp) && (!rw_tryenter(second_lock, RW_READER))) {
		/*
		 * We didn't get the lock. Check if the SLOCK is set in the
		 * ufsvfs. If yes, we might be in a deadlock. Safer to give up
		 * and wait for SLOCK to be cleared.
		 */

		rw_exit(first_lock);
		if (ulp && ULOCKFS_IS_SLOCK(ulp)) {
			TRANS_END_CSYNC(ufsvfsp, error, issync, TOP_RENAME,
			    trans_size);
			ufs_lockfs_end(ulp);
			goto retry_rename;

		} else {
			/*
			 * So we couldn't get the second level peer lock *and*
			 * the SLOCK bit isn't set. Too bad we can be
			 * contentding with someone wanting these locks otherway
			 * round. Reverse the locks in case there is a heavy
			 * contention for the second level lock.
			 */
			reverse_lock = first_lock;
			first_lock = second_lock;
			second_lock = reverse_lock;
			ufs_rename_retry_cnt++;
			goto  retry_firstlock;
		}
	}

	if (sip == tdp) {
		error = EINVAL;
		goto errout;
	}
	/*
	 * Make sure we can delete the source entry.  This requires
	 * write permission on the containing directory.
	 * Check for sticky directories.
	 */
	rw_enter(&sdp->i_contents, RW_READER);
	rw_enter(&sip->i_contents, RW_READER);
	if ((error = ufs_iaccess(sdp, IWRITE, cr, 0)) != 0 ||
	    (error = ufs_sticky_remove_access(sdp, sip, cr)) != 0) {
		rw_exit(&sip->i_contents);
		rw_exit(&sdp->i_contents);
		goto errout;
	}

	/*
	 * If this is a rename of a directory and the parent is
	 * different (".." must be changed), then the source
	 * directory must not be in the directory hierarchy
	 * above the target, as this would orphan everything
	 * below the source directory.  Also the user must have
	 * write permission in the source so as to be able to
	 * change "..".
	 */
	if ((((sip->i_mode & IFMT) == IFDIR) ||
	    ((sip->i_mode & IFMT) == IFATTRDIR)) && sdp != tdp) {
		ino_t	inum;

		if (error = ufs_iaccess(sip, IWRITE, cr, 0)) {
			rw_exit(&sip->i_contents);
			rw_exit(&sdp->i_contents);
			goto errout;
		}
		inum = sip->i_number;
		rw_exit(&sip->i_contents);
		rw_exit(&sdp->i_contents);
		if ((error = ufs_dircheckpath(inum, tdp, sdp, cr))) {
			/*
			 * If we got EAGAIN ufs_dircheckpath detected a
			 * potential deadlock and backed out. We need
			 * to retry the operation since sdp and tdp have
			 * to be released to avoid the deadlock.
			 */
			if (error == EAGAIN) {
				rw_exit(&tdp->i_rwlock);
				if (tdp != sdp)
					rw_exit(&sdp->i_rwlock);
				delay(ufs_rename_backoff_delay);
				ufs_rename_dircheck_retry_cnt++;
				goto retry;
			}
			goto errout;
		}
	} else {
		rw_exit(&sip->i_contents);
		rw_exit(&sdp->i_contents);
	}


	/*
	 * Check for renaming '.' or '..' or alias of '.'
	 */
	if (strcmp(snm, ".") == 0 || strcmp(snm, "..") == 0 || sdp == sip) {
		error = EINVAL;
		goto errout;
	}

	/*
	 * Simultaneous renames can deadlock in ufs_dircheckpath since it
	 * tries to traverse back the file tree with both tdp and sdp held
	 * as RW_WRITER. To avoid that we have to hold the tdp and sdp locks
	 * as RW_READERS  till ufs_dircheckpath is done.
	 * Now that ufs_dircheckpath is done with, we can upgrade the locks
	 * to RW_WRITER.
	 */
	if (!rw_tryupgrade(&tdp->i_rwlock)) {
		/*
		 * The upgrade failed. We got to give away the lock
		 * as to avoid deadlocking with someone else who is
		 * waiting for writer lock. With the lock gone, we
		 * cannot be sure the checks done above will hold
		 * good when we eventually get them back as writer.
		 * So if we can't upgrade we drop the locks and retry
		 * everything again.
		 */
		rw_exit(&tdp->i_rwlock);
		if (tdp != sdp)
			rw_exit(&sdp->i_rwlock);
		delay(ufs_rename_backoff_delay);
		ufs_rename_upgrade_retry_cnt++;
		goto retry;
	}
	if (tdp != sdp) {
		if (!rw_tryupgrade(&sdp->i_rwlock)) {
			/*
			 * The upgrade failed. We got to give away the lock
			 * as to avoid deadlocking with someone else who is
			 * waiting for writer lock. With the lock gone, we
			 * cannot be sure the checks done above will hold
			 * good when we eventually get them back as writer.
			 * So if we can't upgrade we drop the locks and retry
			 * everything again.
			 */
			rw_exit(&tdp->i_rwlock);
			rw_exit(&sdp->i_rwlock);
			delay(ufs_rename_backoff_delay);
			ufs_rename_upgrade_retry_cnt++;
			goto retry;
		}
	}

	/*
	 * Now that all the locks are held check to make sure another thread
	 * didn't slip in and take out the sip.
	 */
	slot.status = NONE;
	if ((sip->i_ctime.tv_usec * 1000) > now.tv_nsec ||
	    sip->i_ctime.tv_sec > now.tv_sec) {
		rw_enter(&sdp->i_ufsvfs->vfs_dqrwlock, RW_READER);
		rw_enter(&sdp->i_contents, RW_WRITER);
		error = ufs_dircheckforname(sdp, snm, strlen(snm), &slot,
		    &ip, cr, 0);
		rw_exit(&sdp->i_contents);
		rw_exit(&sdp->i_ufsvfs->vfs_dqrwlock);
		if (error) {
			goto errout;
		}
		if (ip == NULL) {
			error = ENOENT;
			goto errout;
		} else {
			/*
			 * If the inode was found need to drop the v_count
			 * so as not to keep the filesystem from being
			 * unmounted at a later time.
			 */
			VN_RELE(ITOV(ip));
		}

		/*
		 * Release the slot.fbp that has the page mapped and
		 * locked SE_SHARED, and could be used in in
		 * ufs_direnter_lr() which needs to get the SE_EXCL lock
		 * on said page.
		 */
		if (slot.fbp) {
			fbrelse(slot.fbp, S_OTHER);
			slot.fbp = NULL;
		}
	}

	/*
	 * Link source to the target.
	 */
	if (error = ufs_direnter_lr(tdp, tnm, DE_RENAME, sdp, sip, cr)) {
		/*
		 * ESAME isn't really an error; it indicates that the
		 * operation should not be done because the source and target
		 * are the same file, but that no error should be reported.
		 */
		if (error == ESAME)
			error = 0;
		goto errout;
	}

	if (error == 0 && tvp != NULL)
		vnevent_rename_dest(tvp, tdvp, tnm, ct);

	/*
	 * Unlink the source.
	 * Remove the source entry.  ufs_dirremove() checks that the entry
	 * still reflects sip, and returns an error if it doesn't.
	 * If the entry has changed just forget about it.  Release
	 * the source inode.
	 */
	if ((error = ufs_dirremove(sdp, snm, sip, (struct vnode *)0,
	    DR_RENAME, cr)) == ENOENT)
		error = 0;

	if (error == 0) {
		vnevent_rename_src(ITOV(sip), sdvp, snm, ct);
		/*
		 * Notify the target directory of the rename event
		 * if source and target directories are not the same.
		 */
		if (sdvp != tdvp)
			vnevent_rename_dest_dir(tdvp, ct);
	}

errout:
	if (slot.fbp)
		fbrelse(slot.fbp, S_OTHER);

	rw_exit(&tdp->i_rwlock);
	if (sdp != tdp) {
		rw_exit(&sdp->i_rwlock);
	}

unlock:
	if (tvp != NULL)
		VN_RELE(tvp);
	if (sip != NULL)
		VN_RELE(ITOV(sip));

	if (ulp) {
		TRANS_END_CSYNC(ufsvfsp, error, issync, TOP_RENAME, trans_size);
		ufs_lockfs_end(ulp);
	}

	return (error);
}

/*ARGSUSED*/
static int
ufs_mkdir(struct vnode *dvp, char *dirname, struct vattr *vap,
	struct vnode **vpp, struct cred *cr, caller_context_t *ct, int flags,
	vsecattr_t *vsecp)
{
	struct inode *ip;
	struct inode *xip;
	struct ufsvfs *ufsvfsp;
	struct ulockfs *ulp;
	int error;
	int issync;
	int trans_size;
	int indeadlock;
	int retry = 1;

	ASSERT((vap->va_mask & (AT_TYPE|AT_MODE)) == (AT_TYPE|AT_MODE));

	/*
	 * Can't make directory in attr hidden dir
	 */
	if ((VTOI(dvp)->i_mode & IFMT) == IFATTRDIR)
		return (EINVAL);

again:
	ip = VTOI(dvp);
	ufsvfsp = ip->i_ufsvfs;
	error = ufs_lockfs_begin(ufsvfsp, &ulp, ULOCKFS_MKDIR_MASK);
	if (error)
		goto out;
	if (ulp)
		TRANS_BEGIN_CSYNC(ufsvfsp, issync, TOP_MKDIR,
		    trans_size = (int)TOP_MKDIR_SIZE(ip));

	/*
	 * ufs_tryirwlock_trans uses rw_tryenter and checks for SLOCK
	 * to avoid i_rwlock, ufs_lockfs_begin deadlock. If deadlock
	 * possible, retries the operation.
	 */
	ufs_tryirwlock_trans(&ip->i_rwlock, RW_WRITER, TOP_MKDIR, retry);
	if (indeadlock)
		goto again;

	error = ufs_direnter_cm(ip, dirname, DE_MKDIR, vap, &xip, cr,
	    (retry ? IQUIET : 0));
	if (error == EAGAIN) {
		if (ulp) {
			TRANS_END_CSYNC(ufsvfsp, error, issync, TOP_MKDIR,
			    trans_size);
			ufs_lockfs_end(ulp);
		}
		goto again;
	}

	rw_exit(&ip->i_rwlock);
	if (error == 0) {
		ip = xip;
		*vpp = ITOV(ip);
	} else if (error == EEXIST)
		VN_RELE(ITOV(xip));

	if (ulp) {
		int terr = 0;
		TRANS_END_CSYNC(ufsvfsp, terr, issync, TOP_MKDIR, trans_size);
		ufs_lockfs_end(ulp);
		if (error == 0)
			error = terr;
	}
out:
	if ((error == ENOSPC) && retry && TRANS_ISTRANS(ufsvfsp)) {
		ufs_delete_drain_wait(ufsvfsp, 1);
		retry = 0;
		goto again;
	}

	return (error);
}

/*ARGSUSED*/
static int
ufs_rmdir(struct vnode *vp, char *nm, struct vnode *cdir, struct cred *cr,
	caller_context_t *ct, int flags)
{
	struct inode *ip = VTOI(vp);
	struct ufsvfs *ufsvfsp = ip->i_ufsvfs;
	struct ulockfs *ulp;
	vnode_t *rmvp = NULL;	/* Vnode of removed directory */
	int error;
	int issync;
	int trans_size;
	int indeadlock;

	/*
	 * don't let the delete queue get too long
	 */
	if (ufsvfsp == NULL) {
		error = EIO;
		goto out;
	}
	if (ufsvfsp->vfs_delete.uq_ne > ufs_idle_max)
		ufs_delete_drain(vp->v_vfsp, 1, 1);

	error = ufs_eventlookup(vp, nm, cr, &rmvp);
	if (rmvp != NULL) {
		/* Only send the event if there were no errors */
		if (error == 0)
			vnevent_rmdir(rmvp, vp, nm, ct);
		VN_RELE(rmvp);
	}

retry_rmdir:
	error = ufs_lockfs_begin(ufsvfsp, &ulp, ULOCKFS_RMDIR_MASK);
	if (error)
		goto out;

	if (ulp)
		TRANS_BEGIN_CSYNC(ufsvfsp, issync, TOP_RMDIR,
		    trans_size = TOP_RMDIR_SIZE);

	/*
	 * ufs_tryirwlock_trans uses rw_tryenter and checks for SLOCK
	 * to avoid i_rwlock, ufs_lockfs_begin deadlock. If deadlock
	 * possible, retries the operation.
	 */
	ufs_tryirwlock_trans(&ip->i_rwlock, RW_WRITER, TOP_RMDIR, retry);
	if (indeadlock)
		goto retry_rmdir;
	error = ufs_dirremove(ip, nm, (struct inode *)0, cdir, DR_RMDIR, cr);

	rw_exit(&ip->i_rwlock);

	if (ulp) {
		TRANS_END_CSYNC(ufsvfsp, error, issync, TOP_RMDIR,
		    trans_size);
		ufs_lockfs_end(ulp);
	}

out:
	return (error);
}

/* ARGSUSED */
static int
ufs_readdir(
	struct vnode *vp,
	struct uio *uiop,
	struct cred *cr,
	int *eofp,
	caller_context_t *ct,
	int flags)
{
	struct iovec *iovp;
	struct inode *ip;
	struct direct *idp;
	struct dirent64 *odp;
	struct fbuf *fbp;
	struct ufsvfs *ufsvfsp;
	struct ulockfs *ulp;
	caddr_t outbuf;
	size_t bufsize;
	uint_t offset;
	uint_t bytes_wanted, total_bytes_wanted;
	int incount = 0;
	int outcount = 0;
	int error;

	ip = VTOI(vp);
	ASSERT(RW_READ_HELD(&ip->i_rwlock));

	if (uiop->uio_loffset >= MAXOFF32_T) {
		if (eofp)
			*eofp = 1;
		return (0);
	}

	/*
	 * Check if we have been called with a valid iov_len
	 * and bail out if not, otherwise we may potentially loop
	 * forever further down.
	 */
	if (uiop->uio_iov->iov_len <= 0) {
		error = EINVAL;
		goto out;
	}

	/*
	 * Large Files: When we come here we are guaranteed that
	 * uio_offset can be used safely. The high word is zero.
	 */

	ufsvfsp = ip->i_ufsvfs;
	error = ufs_lockfs_begin(ufsvfsp, &ulp, ULOCKFS_READDIR_MASK);
	if (error)
		goto out;

	iovp = uiop->uio_iov;
	total_bytes_wanted = iovp->iov_len;

	/* Large Files: directory files should not be "large" */

	ASSERT(ip->i_size <= MAXOFF32_T);

	/* Force offset to be valid (to guard against bogus lseek() values) */
	offset = (uint_t)uiop->uio_offset & ~(DIRBLKSIZ - 1);

	/* Quit if at end of file or link count of zero (posix) */
	if (offset >= (uint_t)ip->i_size || ip->i_nlink <= 0) {
		if (eofp)
			*eofp = 1;
		error = 0;
		goto unlock;
	}

	/*
	 * Get space to change directory entries into fs independent format.
	 * Do fast alloc for the most commonly used-request size (filesystem
	 * block size).
	 */
	if (uiop->uio_segflg != UIO_SYSSPACE || uiop->uio_iovcnt != 1) {
		bufsize = total_bytes_wanted;
		outbuf = kmem_alloc(bufsize, KM_SLEEP);
		odp = (struct dirent64 *)outbuf;
	} else {
		bufsize = total_bytes_wanted;
		odp = (struct dirent64 *)iovp->iov_base;
	}

nextblk:
	bytes_wanted = total_bytes_wanted;

	/* Truncate request to file size */
	if (offset + bytes_wanted > (int)ip->i_size)
		bytes_wanted = (int)(ip->i_size - offset);

	/* Comply with MAXBSIZE boundary restrictions of fbread() */
	if ((offset & MAXBOFFSET) + bytes_wanted > MAXBSIZE)
		bytes_wanted = MAXBSIZE - (offset & MAXBOFFSET);

	/*
	 * Read in the next chunk.
	 * We are still holding the i_rwlock.
	 */
	error = fbread(vp, (offset_t)offset, bytes_wanted, S_OTHER, &fbp);

	if (error)
		goto update_inode;
	if (!ULOCKFS_IS_NOIACC(ITOUL(ip)) && (ip->i_fs->fs_ronly == 0) &&
	    (!ufsvfsp->vfs_noatime)) {
		ip->i_flag |= IACC;
	}
	incount = 0;
	idp = (struct direct *)fbp->fb_addr;
	if (idp->d_ino == 0 && idp->d_reclen == 0 && idp->d_namlen == 0) {
		cmn_err(CE_WARN, "ufs_readdir: bad dir, inumber = %llu, "
		    "fs = %s\n",
		    (u_longlong_t)ip->i_number, ufsvfsp->vfs_fs->fs_fsmnt);
		fbrelse(fbp, S_OTHER);
		error = ENXIO;
		goto update_inode;
	}
	/* Transform to file-system independent format */
	while (incount < bytes_wanted) {
		/*
		 * If the current directory entry is mangled, then skip
		 * to the next block.  It would be nice to set the FSBAD
		 * flag in the super-block so that a fsck is forced on
		 * next reboot, but locking is a problem.
		 */
		if (idp->d_reclen & 0x3) {
			offset = (offset + DIRBLKSIZ) & ~(DIRBLKSIZ-1);
			break;
		}

		/* Skip to requested offset and skip empty entries */
		if (idp->d_ino != 0 && offset >= (uint_t)uiop->uio_offset) {
			ushort_t this_reclen =
			    DIRENT64_RECLEN(idp->d_namlen);
			/* Buffer too small for any entries */
			if (!outcount && this_reclen > bufsize) {
				fbrelse(fbp, S_OTHER);
				error = EINVAL;
				goto update_inode;
			}
			/* If would overrun the buffer, quit */
			if (outcount + this_reclen > bufsize) {
				break;
			}
			/* Take this entry */
			odp->d_ino = (ino64_t)idp->d_ino;
			odp->d_reclen = (ushort_t)this_reclen;
			odp->d_off = (offset_t)(offset + idp->d_reclen);

			/* use strncpy(9f) to zero out uninitialized bytes */

			ASSERT(strlen(idp->d_name) + 1 <=
			    DIRENT64_NAMELEN(this_reclen));
			(void) strncpy(odp->d_name, idp->d_name,
			    DIRENT64_NAMELEN(this_reclen));
			outcount += odp->d_reclen;
			odp = (struct dirent64 *)
			    ((intptr_t)odp + odp->d_reclen);
			ASSERT(outcount <= bufsize);
		}
		if (idp->d_reclen) {
			incount += idp->d_reclen;
			offset += idp->d_reclen;
			idp = (struct direct *)((intptr_t)idp + idp->d_reclen);
		} else {
			offset = (offset + DIRBLKSIZ) & ~(DIRBLKSIZ-1);
			break;
		}
	}
	/* Release the chunk */
	fbrelse(fbp, S_OTHER);

	/* Read whole block, but got no entries, read another if not eof */

	/*
	 * Large Files: casting i_size to int here is not a problem
	 * because directory sizes are always less than MAXOFF32_T.
	 * See assertion above.
	 */

	if (offset < (int)ip->i_size && !outcount)
		goto nextblk;

	/* Copy out the entry data */
	if (uiop->uio_segflg == UIO_SYSSPACE && uiop->uio_iovcnt == 1) {
		iovp->iov_base += outcount;
		iovp->iov_len -= outcount;
		uiop->uio_resid -= outcount;
		uiop->uio_offset = offset;
	} else if ((error = uiomove(outbuf, (long)outcount, UIO_READ,
	    uiop)) == 0)
		uiop->uio_offset = offset;
update_inode:
	ITIMES(ip);
	if (uiop->uio_segflg != UIO_SYSSPACE || uiop->uio_iovcnt != 1)
		kmem_free(outbuf, bufsize);

	if (eofp && error == 0)
		*eofp = (uiop->uio_offset >= (int)ip->i_size);
unlock:
	if (ulp) {
		ufs_lockfs_end(ulp);
	}
out:
	return (error);
}

/*ARGSUSED*/
static int
ufs_symlink(
	struct vnode *dvp,		/* ptr to parent dir vnode */
	char *linkname,			/* name of symbolic link */
	struct vattr *vap,		/* attributes */
	char *target,			/* target path */
	struct cred *cr,		/* user credentials */
	caller_context_t *ct,
	int flags)
{
	struct inode *ip, *dip = VTOI(dvp);
	struct ufsvfs *ufsvfsp = dip->i_ufsvfs;
	struct ulockfs *ulp;
	int error;
	int issync;
	int trans_size;
	int residual;
	int ioflag;
	int retry = 1;

	/*
	 * No symlinks in attrdirs at this time
	 */
	if ((VTOI(dvp)->i_mode & IFMT) == IFATTRDIR)
		return (EINVAL);

again:
	ip = (struct inode *)NULL;
	vap->va_type = VLNK;
	vap->va_rdev = 0;

	error = ufs_lockfs_begin(ufsvfsp, &ulp, ULOCKFS_SYMLINK_MASK);
	if (error)
		goto out;

	if (ulp)
		TRANS_BEGIN_CSYNC(ufsvfsp, issync, TOP_SYMLINK,
		    trans_size = (int)TOP_SYMLINK_SIZE(dip));

	/*
	 * We must create the inode before the directory entry, to avoid
	 * racing with readlink().  ufs_dirmakeinode requires that we
	 * hold the quota lock as reader, and directory locks as writer.
	 */

	rw_enter(&dip->i_rwlock, RW_WRITER);
	rw_enter(&ufsvfsp->vfs_dqrwlock, RW_READER);
	rw_enter(&dip->i_contents, RW_WRITER);

	/*
	 * Suppress any out of inodes messages if we will retry on
	 * ENOSP
	 */
	if (retry)
		dip->i_flag |= IQUIET;

	error = ufs_dirmakeinode(dip, &ip, vap, DE_SYMLINK, cr);

	dip->i_flag &= ~IQUIET;

	rw_exit(&dip->i_contents);
	rw_exit(&ufsvfsp->vfs_dqrwlock);
	rw_exit(&dip->i_rwlock);

	if (error)
		goto unlock;

	/*
	 * OK.  The inode has been created.  Write out the data of the
	 * symbolic link.  Since symbolic links are metadata, and should
	 * remain consistent across a system crash, we need to force the
	 * data out synchronously.
	 *
	 * (This is a change from the semantics in earlier releases, which
	 * only created symbolic links synchronously if the semi-documented
	 * 'syncdir' option was set, or if we were being invoked by the NFS
	 * server, which requires symbolic links to be created synchronously.)
	 *
	 * We need to pass in a pointer for the residual length; otherwise
	 * ufs_rdwri() will always return EIO if it can't write the data,
	 * even if the error was really ENOSPC or EDQUOT.
	 */

	ioflag = FWRITE | FDSYNC;
	residual = 0;

	rw_enter(&ufsvfsp->vfs_dqrwlock, RW_READER);
	rw_enter(&ip->i_contents, RW_WRITER);

	/*
	 * Suppress file system full messages if we will retry
	 */
	if (retry)
		ip->i_flag |= IQUIET;

	error = ufs_rdwri(UIO_WRITE, ioflag, ip, target, strlen(target),
	    (offset_t)0, UIO_SYSSPACE, &residual, cr);

	ip->i_flag &= ~IQUIET;

	if (error) {
		rw_exit(&ip->i_contents);
		rw_exit(&ufsvfsp->vfs_dqrwlock);
		goto remove;
	}

	/*
	 * If the link's data is small enough, we can cache it in the inode.
	 * This is a "fast symbolic link".  We don't use the first direct
	 * block because that's actually used to point at the symbolic link's
	 * contents on disk; but we know that none of the other direct or
	 * indirect blocks can be used because symbolic links are restricted
	 * to be smaller than a file system block.
	 */

	ASSERT(MAXPATHLEN <= VBSIZE(ITOV(ip)));

	if (ip->i_size > 0 && ip->i_size <= FSL_SIZE) {
		if (kcopy(target, &ip->i_db[1], ip->i_size) == 0) {
			ip->i_flag |= IFASTSYMLNK;
		} else {
			int i;
			/* error, clear garbage left behind */
			for (i = 1; i < NDADDR; i++)
				ip->i_db[i] = 0;
			for (i = 0; i < NIADDR; i++)
				ip->i_ib[i] = 0;
		}
	}

	rw_exit(&ip->i_contents);
	rw_exit(&ufsvfsp->vfs_dqrwlock);

	/*
	 * OK.  We've successfully created the symbolic link.  All that
	 * remains is to insert it into the appropriate directory.
	 */

	rw_enter(&dip->i_rwlock, RW_WRITER);
	error = ufs_direnter_lr(dip, linkname, DE_SYMLINK, NULL, ip, cr);
	rw_exit(&dip->i_rwlock);

	/*
	 * Fall through into remove-on-error code.  We're either done, or we
	 * need to remove the inode (if we couldn't insert it).
	 */

remove:
	if (error && (ip != NULL)) {
		rw_enter(&ip->i_contents, RW_WRITER);
		ip->i_nlink--;
		ip->i_flag |= ICHG;
		ip->i_seq++;
		ufs_setreclaim(ip);
		rw_exit(&ip->i_contents);
	}

unlock:
	if (ip != NULL)
		VN_RELE(ITOV(ip));

	if (ulp) {
		int terr = 0;

		TRANS_END_CSYNC(ufsvfsp, terr, issync, TOP_SYMLINK,
		    trans_size);
		ufs_lockfs_end(ulp);
		if (error == 0)
			error = terr;
	}

	/*
	 * We may have failed due to lack of an inode or of a block to
	 * store the target in.  Try flushing the delete queue to free
	 * logically-available things up and try again.
	 */
	if ((error == ENOSPC) && retry && TRANS_ISTRANS(ufsvfsp)) {
		ufs_delete_drain_wait(ufsvfsp, 1);
		retry = 0;
		goto again;
	}

out:
	return (error);
}

/*
 * Ufs specific routine used to do ufs io.
 */
int
ufs_rdwri(enum uio_rw rw, int ioflag, struct inode *ip, caddr_t base,
	ssize_t len, offset_t offset, enum uio_seg seg, int *aresid,
	struct cred *cr)
{
	struct uio auio;
	struct iovec aiov;
	int error;

	ASSERT(RW_LOCK_HELD(&ip->i_contents));

	bzero((caddr_t)&auio, sizeof (uio_t));
	bzero((caddr_t)&aiov, sizeof (iovec_t));

	aiov.iov_base = base;
	aiov.iov_len = len;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_loffset = offset;
	auio.uio_segflg = (short)seg;
	auio.uio_resid = len;

	if (rw == UIO_WRITE) {
		auio.uio_fmode = FWRITE;
		auio.uio_extflg = UIO_COPY_DEFAULT;
		auio.uio_llimit = curproc->p_fsz_ctl;
		error = wrip(ip, &auio, ioflag, cr);
	} else {
		auio.uio_fmode = FREAD;
		auio.uio_extflg = UIO_COPY_CACHED;
		auio.uio_llimit = MAXOFFSET_T;
		error = rdip(ip, &auio, ioflag, cr);
	}

	if (aresid) {
		*aresid = auio.uio_resid;
	} else if (auio.uio_resid) {
		error = EIO;
	}
	return (error);
}

/*ARGSUSED*/
static int
ufs_fid(struct vnode *vp, struct fid *fidp, caller_context_t *ct)
{
	struct ufid *ufid;
	struct inode *ip = VTOI(vp);

	if (ip->i_ufsvfs == NULL)
		return (EIO);

	if (fidp->fid_len < (sizeof (struct ufid) - sizeof (ushort_t))) {
		fidp->fid_len = sizeof (struct ufid) - sizeof (ushort_t);
		return (ENOSPC);
	}

	ufid = (struct ufid *)fidp;
	bzero((char *)ufid, sizeof (struct ufid));
	ufid->ufid_len = sizeof (struct ufid) - sizeof (ushort_t);
	ufid->ufid_ino = ip->i_number;
	ufid->ufid_gen = ip->i_gen;

	return (0);
}

/* ARGSUSED2 */
static int
ufs_rwlock(struct vnode *vp, int write_lock, caller_context_t *ctp)
{
	struct inode	*ip = VTOI(vp);
	struct ufsvfs	*ufsvfsp;
	int		forcedirectio;

	/*
	 * Read case is easy.
	 */
	if (!write_lock) {
		rw_enter(&ip->i_rwlock, RW_READER);
		return (V_WRITELOCK_FALSE);
	}

	/*
	 * Caller has requested a writer lock, but that inhibits any
	 * concurrency in the VOPs that follow. Acquire the lock shared
	 * and defer exclusive access until it is known to be needed in
	 * other VOP handlers. Some cases can be determined here.
	 */

	/*
	 * If directio is not set, there is no chance of concurrency,
	 * so just acquire the lock exclusive. Beware of a forced
	 * unmount before looking at the mount option.
	 */
	ufsvfsp = ip->i_ufsvfs;
	forcedirectio = ufsvfsp ? ufsvfsp->vfs_forcedirectio : 0;
	if (!(ip->i_flag & IDIRECTIO || forcedirectio) ||
	    !ufs_allow_shared_writes) {
		rw_enter(&ip->i_rwlock, RW_WRITER);
		return (V_WRITELOCK_TRUE);
	}

	/*
	 * Mandatory locking forces acquiring i_rwlock exclusive.
	 */
	if (MANDLOCK(vp, ip->i_mode)) {
		rw_enter(&ip->i_rwlock, RW_WRITER);
		return (V_WRITELOCK_TRUE);
	}

	/*
	 * Acquire the lock shared in case a concurrent write follows.
	 * Mandatory locking could have become enabled before the lock
	 * was acquired. Re-check and upgrade if needed.
	 */
	rw_enter(&ip->i_rwlock, RW_READER);
	if (MANDLOCK(vp, ip->i_mode)) {
		rw_exit(&ip->i_rwlock);
		rw_enter(&ip->i_rwlock, RW_WRITER);
		return (V_WRITELOCK_TRUE);
	}
	return (V_WRITELOCK_FALSE);
}

/*ARGSUSED*/
static void
ufs_rwunlock(struct vnode *vp, int write_lock, caller_context_t *ctp)
{
	struct inode	*ip = VTOI(vp);

	rw_exit(&ip->i_rwlock);
}

/* ARGSUSED */
static int
ufs_seek(struct vnode *vp, offset_t ooff, offset_t *noffp,
	caller_context_t *ct)
{
	return ((*noffp < 0 || *noffp > MAXOFFSET_T) ? EINVAL : 0);
}

/* ARGSUSED */
static int
ufs_frlock(struct vnode *vp, int cmd, struct flock64 *bfp, int flag,
	offset_t offset, struct flk_callback *flk_cbp, struct cred *cr,
	caller_context_t *ct)
{
	struct inode *ip = VTOI(vp);

	if (ip->i_ufsvfs == NULL)
		return (EIO);

	/*
	 * If file is being mapped, disallow frlock.
	 * XXX I am not holding tlock while checking i_mapcnt because the
	 * current locking strategy drops all locks before calling fs_frlock.
	 * So, mapcnt could change before we enter fs_frlock making is
	 * meaningless to have held tlock in the first place.
	 */
	if (ip->i_mapcnt > 0 && MANDLOCK(vp, ip->i_mode))
		return (EAGAIN);
	return (fs_frlock(vp, cmd, bfp, flag, offset, flk_cbp, cr, ct));
}

/* ARGSUSED */
static int
ufs_space(struct vnode *vp, int cmd, struct flock64 *bfp, int flag,
	offset_t offset, cred_t *cr, caller_context_t *ct)
{
	struct ufsvfs *ufsvfsp = VTOI(vp)->i_ufsvfs;
	struct ulockfs *ulp;
	int error;

	if ((error = convoff(vp, bfp, 0, offset)) == 0) {
		if (cmd == F_FREESP) {
			error = ufs_lockfs_begin(ufsvfsp, &ulp,
			    ULOCKFS_SPACE_MASK);
			if (error)
				return (error);
			error = ufs_freesp(vp, bfp, flag, cr);

			if (error == 0 && bfp->l_start == 0)
				vnevent_truncate(vp, ct);
		} else if (cmd == F_ALLOCSP) {
			error = ufs_lockfs_begin(ufsvfsp, &ulp,
			    ULOCKFS_FALLOCATE_MASK);
			if (error)
				return (error);
			error = ufs_allocsp(vp, bfp, cr);
		} else
			return (EINVAL); /* Command not handled here */

		if (ulp)
			ufs_lockfs_end(ulp);

	}
	return (error);
}

/*
 * Used to determine if read ahead should be done. Also used to
 * to determine when write back occurs.
 */
#define	CLUSTSZ(ip)		((ip)->i_ufsvfs->vfs_ioclustsz)

/*
 * A faster version of ufs_getpage.
 *
 * We optimize by inlining the pvn_getpages iterator, eliminating
 * calls to bmap_read if file doesn't have UFS holes, and avoiding
 * the overhead of page_exists().
 *
 * When files has UFS_HOLES and ufs_getpage is called with S_READ,
 * we set *protp to PROT_READ to avoid calling bmap_read. This approach
 * victimizes performance when a file with UFS holes is faulted
 * first in the S_READ mode, and then in the S_WRITE mode. We will get
 * two MMU faults in this case.
 *
 * XXX - the inode fields which control the sequential mode are not
 *	 protected by any mutex. The read ahead will act wild if
 *	 multiple processes will access the file concurrently and
 *	 some of them in sequential mode. One particulary bad case
 *	 is if another thread will change the value of i_nextrio between
 *	 the time this thread tests the i_nextrio value and then reads it
 *	 again to use it as the offset for the read ahead.
 */
/*ARGSUSED*/
static int
ufs_getpage(struct vnode *vp, offset_t off, size_t len, uint_t *protp,
	page_t *plarr[], size_t plsz, struct seg *seg, caddr_t addr,
	enum seg_rw rw, struct cred *cr, caller_context_t *ct)
{
	u_offset_t	uoff = (u_offset_t)off; /* type conversion */
	u_offset_t	pgoff;
	u_offset_t	eoff;
	struct inode 	*ip = VTOI(vp);
	struct ufsvfs	*ufsvfsp = ip->i_ufsvfs;
	struct fs 	*fs;
	struct ulockfs	*ulp;
	page_t		**pl;
	caddr_t		pgaddr;
	krw_t		rwtype;
	int 		err;
	int		has_holes;
	int		beyond_eof;
	int		seqmode;
	int		pgsize = PAGESIZE;
	int		dolock;
	int		do_qlock;
	int		trans_size;

	ASSERT((uoff & PAGEOFFSET) == 0);

	if (protp)
		*protp = PROT_ALL;

	/*
	 * Obey the lockfs protocol
	 */
	err = ufs_lockfs_begin_getpage(ufsvfsp, &ulp, seg,
	    rw == S_READ || rw == S_EXEC, protp);
	if (err)
		goto out;

	fs = ufsvfsp->vfs_fs;

	if (ulp && (rw == S_CREATE || rw == S_WRITE) &&
	    !(vp->v_flag & VISSWAP)) {
		/*
		 * Try to start a transaction, will return if blocking is
		 * expected to occur and the address space is not the
		 * kernel address space.
		 */
		trans_size = TOP_GETPAGE_SIZE(ip);
		if (seg->s_as != &kas) {
			TRANS_TRY_BEGIN_ASYNC(ufsvfsp, TOP_GETPAGE,
			    trans_size, err)
			if (err == EWOULDBLOCK) {
				/*
				 * Use EDEADLK here because the VM code
				 * can normally never see this error.
				 */
				err = EDEADLK;
				ufs_lockfs_end(ulp);
				goto out;
			}
		} else {
			TRANS_BEGIN_ASYNC(ufsvfsp, TOP_GETPAGE, trans_size);
		}
	}

	if (vp->v_flag & VNOMAP) {
		err = ENOSYS;
		goto unlock;
	}

	seqmode = ip->i_nextr == uoff && rw != S_CREATE;

	rwtype = RW_READER;		/* start as a reader */
	dolock = (rw_owner(&ip->i_contents) != curthread);
	/*
	 * If this thread owns the lock, i.e., this thread grabbed it
	 * as writer somewhere above, then we don't need to grab the
	 * lock as reader in this routine.
	 */
	do_qlock = (rw_owner(&ufsvfsp->vfs_dqrwlock) != curthread);

retrylock:
	if (dolock) {
		/*
		 * Grab the quota lock if we need to call
		 * bmap_write() below (with i_contents as writer).
		 */
		if (do_qlock && rwtype == RW_WRITER)
			rw_enter(&ufsvfsp->vfs_dqrwlock, RW_READER);
		rw_enter(&ip->i_contents, rwtype);
	}

	/*
	 * We may be getting called as a side effect of a bmap using
	 * fbread() when the blocks might be being allocated and the
	 * size has not yet been up'ed.  In this case we want to be
	 * able to return zero pages if we get back UFS_HOLE from
	 * calling bmap for a non write case here.  We also might have
	 * to read some frags from the disk into a page if we are
	 * extending the number of frags for a given lbn in bmap().
	 * Large Files: The read of i_size here is atomic because
	 * i_contents is held here. If dolock is zero, the lock
	 * is held in bmap routines.
	 */
	beyond_eof = uoff + len >
	    P2ROUNDUP_TYPED(ip->i_size, PAGESIZE, u_offset_t);
	if (beyond_eof && seg != segkmap) {
		if (dolock) {
			rw_exit(&ip->i_contents);
			if (do_qlock && rwtype == RW_WRITER)
				rw_exit(&ufsvfsp->vfs_dqrwlock);
		}
		err = EFAULT;
		goto unlock;
	}

	/*
	 * Must hold i_contents lock throughout the call to pvn_getpages
	 * since locked pages are returned from each call to ufs_getapage.
	 * Must *not* return locked pages and then try for contents lock
	 * due to lock ordering requirements (inode > page)
	 */

	has_holes = bmap_has_holes(ip);

	if ((rw == S_WRITE || rw == S_CREATE) && has_holes && !beyond_eof) {
		int	blk_size;
		u_offset_t offset;

		/*
		 * We must acquire the RW_WRITER lock in order to
		 * call bmap_write().
		 */
		if (dolock && rwtype == RW_READER) {
			rwtype = RW_WRITER;

			/*
			 * Grab the quota lock before
			 * upgrading i_contents, but if we can't grab it
			 * don't wait here due to lock order:
			 * vfs_dqrwlock > i_contents.
			 */
			if (do_qlock &&
			    rw_tryenter(&ufsvfsp->vfs_dqrwlock, RW_READER)
			    == 0) {
				rw_exit(&ip->i_contents);
				goto retrylock;
			}
			if (!rw_tryupgrade(&ip->i_contents)) {
				rw_exit(&ip->i_contents);
				if (do_qlock)
					rw_exit(&ufsvfsp->vfs_dqrwlock);
				goto retrylock;
			}
		}

		/*
		 * May be allocating disk blocks for holes here as
		 * a result of mmap faults. write(2) does the bmap_write
		 * in rdip/wrip, not here. We are not dealing with frags
		 * in this case.
		 */
		/*
		 * Large Files: We cast fs_bmask field to offset_t
		 * just as we do for MAXBMASK because uoff is a 64-bit
		 * data type. fs_bmask will still be a 32-bit type
		 * as we cannot change any ondisk data structures.
		 */

		offset = uoff & (offset_t)fs->fs_bmask;
		while (offset < uoff + len) {
			blk_size = (int)blksize(fs, ip, lblkno(fs, offset));
			err = bmap_write(ip, offset, blk_size,
			    BI_NORMAL, NULL, cr);
			if (ip->i_flag & (ICHG|IUPD))
				ip->i_seq++;
			if (err)
				goto update_inode;
			offset += blk_size; /* XXX - make this contig */
		}
	}

	/*
	 * Can be a reader from now on.
	 */
	if (dolock && rwtype == RW_WRITER) {
		rw_downgrade(&ip->i_contents);
		/*
		 * We can release vfs_dqrwlock early so do it, but make
		 * sure we don't try to release it again at the bottom.
		 */
		if (do_qlock) {
			rw_exit(&ufsvfsp->vfs_dqrwlock);
			do_qlock = 0;
		}
	}

	/*
	 * We remove PROT_WRITE in cases when the file has UFS holes
	 * because we don't  want to call bmap_read() to check each
	 * page if it is backed with a disk block.
	 */
	if (protp && has_holes && rw != S_WRITE && rw != S_CREATE)
		*protp &= ~PROT_WRITE;

	err = 0;

	/*
	 * The loop looks up pages in the range [off, off + len).
	 * For each page, we first check if we should initiate an asynchronous
	 * read ahead before we call page_lookup (we may sleep in page_lookup
	 * for a previously initiated disk read).
	 */
	eoff = (uoff + len);
	for (pgoff = uoff, pgaddr = addr, pl = plarr;
	    pgoff < eoff; /* empty */) {
		page_t	*pp;
		u_offset_t	nextrio;
		se_t	se;
		int retval;

		se = ((rw == S_CREATE || rw == S_OTHER) ? SE_EXCL : SE_SHARED);

		/* Handle async getpage (faultahead) */
		if (plarr == NULL) {
			ip->i_nextrio = pgoff;
			(void) ufs_getpage_ra(vp, pgoff, seg, pgaddr);
			pgoff += pgsize;
			pgaddr += pgsize;
			continue;
		}
		/*
		 * Check if we should initiate read ahead of next cluster.
		 * We call page_exists only when we need to confirm that
		 * we have the current page before we initiate the read ahead.
		 */
		nextrio = ip->i_nextrio;
		if (seqmode &&
		    pgoff + CLUSTSZ(ip) >= nextrio && pgoff <= nextrio &&
		    nextrio < ip->i_size && page_exists(vp, pgoff)) {
			retval = ufs_getpage_ra(vp, pgoff, seg, pgaddr);
			/*
			 * We always read ahead the next cluster of data
			 * starting from i_nextrio. If the page (vp,nextrio)
			 * is actually in core at this point, the routine
			 * ufs_getpage_ra() will stop pre-fetching data
			 * until we read that page in a synchronized manner
			 * through ufs_getpage_miss(). So, we should increase
			 * i_nextrio if the page (vp, nextrio) exists.
			 */
			if ((retval == 0) && page_exists(vp, nextrio)) {
				ip->i_nextrio = nextrio + pgsize;
			}
		}

		if ((pp = page_lookup(vp, pgoff, se)) != NULL) {
			/*
			 * We found the page in the page cache.
			 */
			*pl++ = pp;
			pgoff += pgsize;
			pgaddr += pgsize;
			len -= pgsize;
			plsz -= pgsize;
		} else  {
			/*
			 * We have to create the page, or read it from disk.
			 */
			if (err = ufs_getpage_miss(vp, pgoff, len, seg, pgaddr,
			    pl, plsz, rw, seqmode))
				goto error;

			while (*pl != NULL) {
				pl++;
				pgoff += pgsize;
				pgaddr += pgsize;
				len -= pgsize;
				plsz -= pgsize;
			}
		}
	}

	/*
	 * Return pages up to plsz if they are in the page cache.
	 * We cannot return pages if there is a chance that they are
	 * backed with a UFS hole and rw is S_WRITE or S_CREATE.
	 */
	if (plarr && !(has_holes && (rw == S_WRITE || rw == S_CREATE))) {

		ASSERT((protp == NULL) ||
		    !(has_holes && (*protp & PROT_WRITE)));

		eoff = pgoff + plsz;
		while (pgoff < eoff) {
			page_t		*pp;

			if ((pp = page_lookup_nowait(vp, pgoff,
			    SE_SHARED)) == NULL)
				break;

			*pl++ = pp;
			pgoff += pgsize;
			plsz -= pgsize;
		}
	}

	if (plarr)
		*pl = NULL;			/* Terminate page list */
	ip->i_nextr = pgoff;

error:
	if (err && plarr) {
		/*
		 * Release any pages we have locked.
		 */
		while (pl > &plarr[0])
			page_unlock(*--pl);

		plarr[0] = NULL;
	}

update_inode:
	/*
	 * If the inode is not already marked for IACC (in rdip() for read)
	 * and the inode is not marked for no access time update (in wrip()
	 * for write) then update the inode access time and mod time now.
	 */
	if ((ip->i_flag & (IACC | INOACC)) == 0) {
		if ((rw != S_OTHER) && (ip->i_mode & IFMT) != IFDIR) {
			if (!ULOCKFS_IS_NOIACC(ITOUL(ip)) &&
			    (fs->fs_ronly == 0) &&
			    (!ufsvfsp->vfs_noatime)) {
				mutex_enter(&ip->i_tlock);
				ip->i_flag |= IACC;
				ITIMES_NOLOCK(ip);
				mutex_exit(&ip->i_tlock);
			}
		}
	}

	if (dolock) {
		rw_exit(&ip->i_contents);
		if (do_qlock && rwtype == RW_WRITER)
			rw_exit(&ufsvfsp->vfs_dqrwlock);
	}

unlock:
	if (ulp) {
		if ((rw == S_CREATE || rw == S_WRITE) &&
		    !(vp->v_flag & VISSWAP)) {
			TRANS_END_ASYNC(ufsvfsp, TOP_GETPAGE, trans_size);
		}
		ufs_lockfs_end(ulp);
	}
out:
	return (err);
}

/*
 * ufs_getpage_miss is called when ufs_getpage missed the page in the page
 * cache. The page is either read from the disk, or it's created.
 * A page is created (without disk read) if rw == S_CREATE, or if
 * the page is not backed with a real disk block (UFS hole).
 */
/* ARGSUSED */
static int
ufs_getpage_miss(struct vnode *vp, u_offset_t off, size_t len, struct seg *seg,
	caddr_t addr, page_t *pl[], size_t plsz, enum seg_rw rw, int seq)
{
	struct inode	*ip = VTOI(vp);
	page_t		*pp;
	daddr_t		bn;
	size_t		io_len;
	int		crpage = 0;
	int		err;
	int		contig;
	int		bsize = ip->i_fs->fs_bsize;

	/*
	 * Figure out whether the page can be created, or must be
	 * must be read from the disk.
	 */
	if (rw == S_CREATE)
		crpage = 1;
	else {
		contig = 0;
		if (err = bmap_read(ip, off, &bn, &contig))
			return (err);

		crpage = (bn == UFS_HOLE);

		/*
		 * If its also a fallocated block that hasn't been written to
		 * yet, we will treat it just like a UFS_HOLE and create
		 * a zero page for it
		 */
		if (ISFALLOCBLK(ip, bn))
			crpage = 1;
	}

	if (crpage) {
		if ((pp = page_create_va(vp, off, PAGESIZE, PG_WAIT, seg,
		    addr)) == NULL) {
			return (ufs_fault(vp,
			    "ufs_getpage_miss: page_create == NULL"));
		}

		if (rw != S_CREATE)
			pagezero(pp, 0, PAGESIZE);

		io_len = PAGESIZE;
	} else {
		u_offset_t	io_off;
		uint_t	xlen;
		struct buf	*bp;
		ufsvfs_t	*ufsvfsp = ip->i_ufsvfs;

		/*
		 * If access is not in sequential order, we read from disk
		 * in bsize units.
		 *
		 * We limit the size of the transfer to bsize if we are reading
		 * from the beginning of the file. Note in this situation we
		 * will hedge our bets and initiate an async read ahead of
		 * the second block.
		 */
		if (!seq || off == 0)
			contig = MIN(contig, bsize);

		pp = pvn_read_kluster(vp, off, seg, addr, &io_off,
		    &io_len, off, contig, 0);

		/*
		 * Some other thread has entered the page.
		 * ufs_getpage will retry page_lookup.
		 */
		if (pp == NULL) {
			pl[0] = NULL;
			return (0);
		}

		/*
		 * Zero part of the page which we are not
		 * going to read from the disk.
		 */
		xlen = io_len & PAGEOFFSET;
		if (xlen != 0)
			pagezero(pp->p_prev, xlen, PAGESIZE - xlen);

		bp = pageio_setup(pp, io_len, ip->i_devvp, B_READ);
		bp->b_edev = ip->i_dev;
		bp->b_dev = cmpdev(ip->i_dev);
		bp->b_blkno = bn;
		bp->b_un.b_addr = (caddr_t)0;
		bp->b_file = ip->i_vnode;
		bp->b_offset = off;

		if (ufsvfsp->vfs_log) {
			lufs_read_strategy(ufsvfsp->vfs_log, bp);
		} else if (ufsvfsp->vfs_snapshot) {
			fssnap_strategy(&ufsvfsp->vfs_snapshot, bp);
		} else {
			ufsvfsp->vfs_iotstamp = ddi_get_lbolt();
			ub.ub_getpages.value.ul++;
			(void) bdev_strategy(bp);
			lwp_stat_update(LWP_STAT_INBLK, 1);
		}

		ip->i_nextrio = off + ((io_len + PAGESIZE - 1) & PAGEMASK);

		/*
		 * If the file access is sequential, initiate read ahead
		 * of the next cluster.
		 */
		if (seq && ip->i_nextrio < ip->i_size)
			(void) ufs_getpage_ra(vp, off, seg, addr);
		err = biowait(bp);
		pageio_done(bp);

		if (err) {
			pvn_read_done(pp, B_ERROR);
			return (err);
		}
	}

	pvn_plist_init(pp, pl, plsz, off, io_len, rw);
	return (0);
}

/*
 * Read ahead a cluster from the disk. Returns the length in bytes.
 */
static int
ufs_getpage_ra(struct vnode *vp, u_offset_t off, struct seg *seg, caddr_t addr)
{
	struct inode	*ip = VTOI(vp);
	page_t		*pp;
	u_offset_t	io_off = ip->i_nextrio;
	ufsvfs_t	*ufsvfsp;
	caddr_t		addr2 = addr + (io_off - off);
	struct buf	*bp;
	daddr_t		bn;
	size_t		io_len;
	int		err;
	int		contig;
	int		xlen;
	int		bsize = ip->i_fs->fs_bsize;

	/*
	 * If the directio advisory is in effect on this file,
	 * then do not do buffered read ahead. Read ahead makes
	 * it more difficult on threads using directio as they
	 * will be forced to flush the pages from this vnode.
	 */
	if ((ufsvfsp = ip->i_ufsvfs) == NULL)
		return (0);
	if (ip->i_flag & IDIRECTIO || ufsvfsp->vfs_forcedirectio)
		return (0);

	/*
	 * Is this test needed?
	 */
	if (addr2 >= seg->s_base + seg->s_size)
		return (0);

	contig = 0;
	err = bmap_read(ip, io_off, &bn, &contig);
	/*
	 * If its a UFS_HOLE or a fallocated block, do not perform
	 * any read ahead's since there probably is nothing to read ahead
	 */
	if (err || bn == UFS_HOLE || ISFALLOCBLK(ip, bn))
		return (0);

	/*
	 * Limit the transfer size to bsize if this is the 2nd block.
	 */
	if (io_off == (u_offset_t)bsize)
		contig = MIN(contig, bsize);

	if ((pp = pvn_read_kluster(vp, io_off, seg, addr2, &io_off,
	    &io_len, io_off, contig, 1)) == NULL)
		return (0);

	/*
	 * Zero part of page which we are not going to read from disk
	 */
	if ((xlen = (io_len & PAGEOFFSET)) > 0)
		pagezero(pp->p_prev, xlen, PAGESIZE - xlen);

	ip->i_nextrio = (io_off + io_len + PAGESIZE - 1) & PAGEMASK;

	bp = pageio_setup(pp, io_len, ip->i_devvp, B_READ | B_ASYNC);
	bp->b_edev = ip->i_dev;
	bp->b_dev = cmpdev(ip->i_dev);
	bp->b_blkno = bn;
	bp->b_un.b_addr = (caddr_t)0;
	bp->b_file = ip->i_vnode;
	bp->b_offset = off;

	if (ufsvfsp->vfs_log) {
		lufs_read_strategy(ufsvfsp->vfs_log, bp);
	} else if (ufsvfsp->vfs_snapshot) {
		fssnap_strategy(&ufsvfsp->vfs_snapshot, bp);
	} else {
		ufsvfsp->vfs_iotstamp = ddi_get_lbolt();
		ub.ub_getras.value.ul++;
		(void) bdev_strategy(bp);
		lwp_stat_update(LWP_STAT_INBLK, 1);
	}

	return (io_len);
}

int	ufs_delay = 1;
/*
 * Flags are composed of {B_INVAL, B_FREE, B_DONTNEED, B_FORCE, B_ASYNC}
 *
 * LMXXX - the inode really ought to contain a pointer to one of these
 * async args.  Stuff gunk in there and just hand the whole mess off.
 * This would replace i_delaylen, i_delayoff.
 */
/*ARGSUSED*/
static int
ufs_putpage(struct vnode *vp, offset_t off, size_t len, int flags,
	struct cred *cr, caller_context_t *ct)
{
	struct inode *ip = VTOI(vp);
	int err = 0;

	if (vp->v_count == 0) {
		return (ufs_fault(vp, "ufs_putpage: bad v_count == 0"));
	}

	/*
	 * XXX - Why should this check be made here?
	 */
	if (vp->v_flag & VNOMAP) {
		err = ENOSYS;
		goto errout;
	}

	if (ip->i_ufsvfs == NULL) {
		err = EIO;
		goto errout;
	}

	if (flags & B_ASYNC) {
		if (ufs_delay && len &&
		    (flags & ~(B_ASYNC|B_DONTNEED|B_FREE)) == 0) {
			mutex_enter(&ip->i_tlock);
			/*
			 * If nobody stalled, start a new cluster.
			 */
			if (ip->i_delaylen == 0) {
				ip->i_delayoff = off;
				ip->i_delaylen = len;
				mutex_exit(&ip->i_tlock);
				goto errout;
			}
			/*
			 * If we have a full cluster or they are not contig,
			 * then push last cluster and start over.
			 */
			if (ip->i_delaylen >= CLUSTSZ(ip) ||
			    ip->i_delayoff + ip->i_delaylen != off) {
				u_offset_t doff;
				size_t dlen;

				doff = ip->i_delayoff;
				dlen = ip->i_delaylen;
				ip->i_delayoff = off;
				ip->i_delaylen = len;
				mutex_exit(&ip->i_tlock);
				err = ufs_putpages(vp, doff, dlen,
				    flags, cr);
				/* LMXXX - flags are new val, not old */
				goto errout;
			}
			/*
			 * There is something there, it's not full, and
			 * it is contig.
			 */
			ip->i_delaylen += len;
			mutex_exit(&ip->i_tlock);
			goto errout;
		}
		/*
		 * Must have weird flags or we are not clustering.
		 */
	}

	err = ufs_putpages(vp, off, len, flags, cr);

errout:
	return (err);
}

/*
 * If len == 0, do from off to EOF.
 *
 * The normal cases should be len == 0 & off == 0 (entire vp list),
 * len == MAXBSIZE (from segmap_release actions), and len == PAGESIZE
 * (from pageout).
 */
/*ARGSUSED*/
static int
ufs_putpages(
	struct vnode *vp,
	offset_t off,
	size_t len,
	int flags,
	struct cred *cr)
{
	u_offset_t io_off;
	u_offset_t eoff;
	struct inode *ip = VTOI(vp);
	page_t *pp;
	size_t io_len;
	int err = 0;
	int dolock;

	if (vp->v_count == 0)
		return (ufs_fault(vp, "ufs_putpages: v_count == 0"));
	/*
	 * Acquire the readers/write inode lock before locking
	 * any pages in this inode.
	 * The inode lock is held during i/o.
	 */
	if (len == 0) {
		mutex_enter(&ip->i_tlock);
		ip->i_delayoff = ip->i_delaylen = 0;
		mutex_exit(&ip->i_tlock);
	}
	dolock = (rw_owner(&ip->i_contents) != curthread);
	if (dolock) {
		/*
		 * Must synchronize this thread and any possible thread
		 * operating in the window of vulnerability in wrip().
		 * It is dangerous to allow both a thread doing a putpage
		 * and a thread writing, so serialize them.  The exception
		 * is when the thread in wrip() does something which causes
		 * a putpage operation.  Then, the thread must be allowed
		 * to continue.  It may encounter a bmap_read problem in
		 * ufs_putapage, but that is handled in ufs_putapage.
		 * Allow async writers to proceed, we don't want to block
		 * the pageout daemon.
		 */
		if (ip->i_writer == curthread)
			rw_enter(&ip->i_contents, RW_READER);
		else {
			for (;;) {
				rw_enter(&ip->i_contents, RW_READER);
				mutex_enter(&ip->i_tlock);
				/*
				 * If there is no thread in the critical
				 * section of wrip(), then proceed.
				 * Otherwise, wait until there isn't one.
				 */
				if (ip->i_writer == NULL) {
					mutex_exit(&ip->i_tlock);
					break;
				}
				rw_exit(&ip->i_contents);
				/*
				 * Bounce async writers when we have a writer
				 * working on this file so we don't deadlock
				 * the pageout daemon.
				 */
				if (flags & B_ASYNC) {
					mutex_exit(&ip->i_tlock);
					return (0);
				}
				cv_wait(&ip->i_wrcv, &ip->i_tlock);
				mutex_exit(&ip->i_tlock);
			}
		}
	}

	if (!vn_has_cached_data(vp)) {
		if (dolock)
			rw_exit(&ip->i_contents);
		return (0);
	}

	if (len == 0) {
		/*
		 * Search the entire vp list for pages >= off.
		 */
		err = pvn_vplist_dirty(vp, (u_offset_t)off, ufs_putapage,
		    flags, cr);
	} else {
		/*
		 * Loop over all offsets in the range looking for
		 * pages to deal with.
		 */
		if ((eoff = blkroundup(ip->i_fs, ip->i_size)) != 0)
			eoff = MIN(off + len, eoff);
		else
			eoff = off + len;

		for (io_off = off; io_off < eoff; io_off += io_len) {
			/*
			 * If we are not invalidating, synchronously
			 * freeing or writing pages, use the routine
			 * page_lookup_nowait() to prevent reclaiming
			 * them from the free list.
			 */
			if ((flags & B_INVAL) || ((flags & B_ASYNC) == 0)) {
				pp = page_lookup(vp, io_off,
				    (flags & (B_INVAL | B_FREE)) ?
				    SE_EXCL : SE_SHARED);
			} else {
				pp = page_lookup_nowait(vp, io_off,
				    (flags & B_FREE) ? SE_EXCL : SE_SHARED);
			}

			if (pp == NULL || pvn_getdirty(pp, flags) == 0)
				io_len = PAGESIZE;
			else {
				u_offset_t *io_offp = &io_off;

				err = ufs_putapage(vp, pp, io_offp, &io_len,
				    flags, cr);
				if (err != 0)
					break;
				/*
				 * "io_off" and "io_len" are returned as
				 * the range of pages we actually wrote.
				 * This allows us to skip ahead more quickly
				 * since several pages may've been dealt
				 * with by this iteration of the loop.
				 */
			}
		}
	}
	if (err == 0 && off == 0 && (len == 0 || len >= ip->i_size)) {
		/*
		 * We have just sync'ed back all the pages on
		 * the inode, turn off the IMODTIME flag.
		 */
		mutex_enter(&ip->i_tlock);
		ip->i_flag &= ~IMODTIME;
		mutex_exit(&ip->i_tlock);
	}
	if (dolock)
		rw_exit(&ip->i_contents);
	return (err);
}

static void
ufs_iodone(buf_t *bp)
{
	struct inode *ip;

	ASSERT((bp->b_pages->p_vnode != NULL) && !(bp->b_flags & B_READ));

	bp->b_iodone = NULL;

	ip = VTOI(bp->b_pages->p_vnode);

	mutex_enter(&ip->i_tlock);
	if (ip->i_writes >= ufs_LW) {
		if ((ip->i_writes -= bp->b_bcount) <= ufs_LW)
			if (ufs_WRITES)
				cv_broadcast(&ip->i_wrcv); /* wake all up */
	} else {
		ip->i_writes -= bp->b_bcount;
	}

	mutex_exit(&ip->i_tlock);
	iodone(bp);
}

/*
 * Write out a single page, possibly klustering adjacent
 * dirty pages.  The inode lock must be held.
 *
 * LMXXX - bsize < pagesize not done.
 */
/*ARGSUSED*/
int
ufs_putapage(
	struct vnode *vp,
	page_t *pp,
	u_offset_t *offp,
	size_t *lenp,		/* return values */
	int flags,
	struct cred *cr)
{
	u_offset_t io_off;
	u_offset_t off;
	struct inode *ip = VTOI(vp);
	struct ufsvfs *ufsvfsp = ip->i_ufsvfs;
	struct fs *fs;
	struct buf *bp;
	size_t io_len;
	daddr_t bn;
	int err;
	int contig;
	int dotrans;

	ASSERT(RW_LOCK_HELD(&ip->i_contents));

	if (ufsvfsp == NULL) {
		err = EIO;
		goto out_trace;
	}

	fs = ip->i_fs;
	ASSERT(fs->fs_ronly == 0);

	/*
	 * If the modified time on the inode has not already been
	 * set elsewhere (e.g. for write/setattr) we set the time now.
	 * This gives us approximate modified times for mmap'ed files
	 * which are modified via stores in the user address space.
	 */
	if ((ip->i_flag & IMODTIME) == 0) {
		mutex_enter(&ip->i_tlock);
		ip->i_flag |= IUPD;
		ip->i_seq++;
		ITIMES_NOLOCK(ip);
		mutex_exit(&ip->i_tlock);
	}

	/*
	 * Align the request to a block boundry (for old file systems),
	 * and go ask bmap() how contiguous things are for this file.
	 */
	off = pp->p_offset & (offset_t)fs->fs_bmask;	/* block align it */
	contig = 0;
	err = bmap_read(ip, off, &bn, &contig);
	if (err)
		goto out;
	if (bn == UFS_HOLE) {			/* putpage never allocates */
		/*
		 * logging device is in error mode; simply return EIO
		 */
		if (TRANS_ISERROR(ufsvfsp)) {
			err = EIO;
			goto out;
		}
		/*
		 * Oops, the thread in the window in wrip() did some
		 * sort of operation which caused a putpage in the bad
		 * range.  In this case, just return an error which will
		 * cause the software modified bit on the page to set
		 * and the page will get written out again later.
		 */
		if (ip->i_writer == curthread) {
			err = EIO;
			goto out;
		}
		/*
		 * If the pager is trying to push a page in the bad range
		 * just tell it to try again later when things are better.
		 */
		if (flags & B_ASYNC) {
			err = EAGAIN;
			goto out;
		}
		err = ufs_fault(ITOV(ip), "ufs_putapage: bn == UFS_HOLE");
		goto out;
	}

	/*
	 * If it is an fallocate'd block, reverse the negativity since
	 * we are now writing to it
	 */
	if (ISFALLOCBLK(ip, bn)) {
		err = bmap_set_bn(vp, off, dbtofsb(fs, -bn));
		if (err)
			goto out;

		bn = -bn;
	}

	/*
	 * Take the length (of contiguous bytes) passed back from bmap()
	 * and _try_ and get a set of pages covering that extent.
	 */
	pp = pvn_write_kluster(vp, pp, &io_off, &io_len, off, contig, flags);

	/*
	 * May have run out of memory and not clustered backwards.
	 * off		p_offset
	 * [  pp - 1  ][   pp   ]
	 * [	block		]
	 * We told bmap off, so we have to adjust the bn accordingly.
	 */
	if (io_off > off) {
		bn += btod(io_off - off);
		contig -= (io_off - off);
	}

	/*
	 * bmap was carefull to tell us the right size so use that.
	 * There might be unallocated frags at the end.
	 * LMXXX - bzero the end of the page?  We must be writing after EOF.
	 */
	if (io_len > contig) {
		ASSERT(io_len - contig < fs->fs_bsize);
		io_len -= (io_len - contig);
	}

	/*
	 * Handle the case where we are writing the last page after EOF.
	 *
	 * XXX - just a patch for i-mt3.
	 */
	if (io_len == 0) {
		ASSERT(pp->p_offset >=
		    (u_offset_t)(roundup(ip->i_size, PAGESIZE)));
		io_len = PAGESIZE;
	}

	bp = pageio_setup(pp, io_len, ip->i_devvp, B_WRITE | flags);

	ULOCKFS_SET_MOD(ITOUL(ip));

	bp->b_edev = ip->i_dev;
	bp->b_dev = cmpdev(ip->i_dev);
	bp->b_blkno = bn;
	bp->b_un.b_addr = (caddr_t)0;
	bp->b_file = ip->i_vnode;

	/*
	 * File contents of shadow or quota inodes are metadata, and updates
	 * to these need to be put into a logging transaction. All direct
	 * callers in UFS do that, but fsflush can come here _before_ the
	 * normal codepath. An example would be updating ACL information, for
	 * which the normal codepath would be:
	 *	ufs_si_store()
	 *	ufs_rdwri()
	 *	wrip()
	 *	segmap_release()
	 *	VOP_PUTPAGE()
	 * Here, fsflush can pick up the dirty page before segmap_release()
	 * forces it out. If that happens, there's no transaction.
	 * We therefore need to test whether a transaction exists, and if not
	 * create one - for fsflush.
	 */
	dotrans =
	    (((ip->i_mode & IFMT) == IFSHAD || ufsvfsp->vfs_qinod == ip) &&
	    ((curthread->t_flag & T_DONTBLOCK) == 0) &&
	    (TRANS_ISTRANS(ufsvfsp)));

	if (dotrans) {
		curthread->t_flag |= T_DONTBLOCK;
		TRANS_BEGIN_ASYNC(ufsvfsp, TOP_PUTPAGE, TOP_PUTPAGE_SIZE(ip));
	}
	if (TRANS_ISTRANS(ufsvfsp)) {
		if ((ip->i_mode & IFMT) == IFSHAD) {
			TRANS_BUF(ufsvfsp, 0, io_len, bp, DT_SHAD);
		} else if (ufsvfsp->vfs_qinod == ip) {
			TRANS_DELTA(ufsvfsp, ldbtob(bn), bp->b_bcount, DT_QR,
			    0, 0);
		}
	}
	if (dotrans) {
		TRANS_END_ASYNC(ufsvfsp, TOP_PUTPAGE, TOP_PUTPAGE_SIZE(ip));
		curthread->t_flag &= ~T_DONTBLOCK;
	}

	/* write throttle */

	ASSERT(bp->b_iodone == NULL);
	bp->b_iodone = (int (*)())ufs_iodone;
	mutex_enter(&ip->i_tlock);
	ip->i_writes += bp->b_bcount;
	mutex_exit(&ip->i_tlock);

	if (bp->b_flags & B_ASYNC) {
		if (ufsvfsp->vfs_log) {
			lufs_write_strategy(ufsvfsp->vfs_log, bp);
		} else if (ufsvfsp->vfs_snapshot) {
			fssnap_strategy(&ufsvfsp->vfs_snapshot, bp);
		} else {
			ufsvfsp->vfs_iotstamp = ddi_get_lbolt();
			ub.ub_putasyncs.value.ul++;
			(void) bdev_strategy(bp);
			lwp_stat_update(LWP_STAT_OUBLK, 1);
		}
	} else {
		if (ufsvfsp->vfs_log) {
			lufs_write_strategy(ufsvfsp->vfs_log, bp);
		} else if (ufsvfsp->vfs_snapshot) {
			fssnap_strategy(&ufsvfsp->vfs_snapshot, bp);
		} else {
			ufsvfsp->vfs_iotstamp = ddi_get_lbolt();
			ub.ub_putsyncs.value.ul++;
			(void) bdev_strategy(bp);
			lwp_stat_update(LWP_STAT_OUBLK, 1);
		}
		err = biowait(bp);
		pageio_done(bp);
		pvn_write_done(pp, ((err) ? B_ERROR : 0) | B_WRITE | flags);
	}

	pp = NULL;

out:
	if (err != 0 && pp != NULL)
		pvn_write_done(pp, B_ERROR | B_WRITE | flags);

	if (offp)
		*offp = io_off;
	if (lenp)
		*lenp = io_len;
out_trace:
	return (err);
}

uint64_t ufs_map_alock_retry_cnt;
uint64_t ufs_map_lockfs_retry_cnt;

/* ARGSUSED */
static int
ufs_map(struct vnode *vp,
	offset_t off,
	struct as *as,
	caddr_t *addrp,
	size_t len,
	uchar_t prot,
	uchar_t maxprot,
	uint_t flags,
	struct cred *cr,
	caller_context_t *ct)
{
	struct segvn_crargs vn_a;
	struct ufsvfs *ufsvfsp = VTOI(vp)->i_ufsvfs;
	struct ulockfs *ulp;
	int error, sig;
	k_sigset_t smask;
	caddr_t hint = *addrp;

	if (vp->v_flag & VNOMAP) {
		error = ENOSYS;
		goto out;
	}

	if (off < (offset_t)0 || (offset_t)(off + len) < (offset_t)0) {
		error = ENXIO;
		goto out;
	}

	if (vp->v_type != VREG) {
		error = ENODEV;
		goto out;
	}

retry_map:
	*addrp = hint;
	/*
	 * If file is being locked, disallow mapping.
	 */
	if (vn_has_mandatory_locks(vp, VTOI(vp)->i_mode)) {
		error = EAGAIN;
		goto out;
	}

	as_rangelock(as);
	/*
	 * Note that if we are retrying (because ufs_lockfs_trybegin failed in
	 * the previous attempt), some other thread could have grabbed
	 * the same VA range if MAP_FIXED is set. In that case, choose_addr
	 * would unmap the valid VA range, that is ok.
	 */
	error = choose_addr(as, addrp, len, off, ADDR_VACALIGN, flags);
	if (error != 0) {
		as_rangeunlock(as);
		goto out;
	}

	/*
	 * a_lock has to be acquired before entering the lockfs protocol
	 * because that is the order in which pagefault works. Also we cannot
	 * block on a_lock here because this waiting writer will prevent
	 * further readers like ufs_read from progressing and could cause
	 * deadlock between ufs_read/ufs_map/pagefault when a quiesce is
	 * pending.
	 */
	while (!AS_LOCK_TRYENTER(as, RW_WRITER)) {
		ufs_map_alock_retry_cnt++;
		delay(RETRY_LOCK_DELAY);
	}

	/*
	 * We can't hold as->a_lock and wait for lockfs to succeed because
	 * the proc tools might hang on a_lock, so call ufs_lockfs_trybegin()
	 * instead.
	 */
	if (error = ufs_lockfs_trybegin(ufsvfsp, &ulp, ULOCKFS_MAP_MASK)) {
		/*
		 * ufs_lockfs_trybegin() did not succeed. It is safer to give up
		 * as->a_lock and wait for ulp->ul_fs_lock status to change.
		 */
		ufs_map_lockfs_retry_cnt++;
		AS_LOCK_EXIT(as);
		as_rangeunlock(as);
		if (error == EIO)
			goto out;

		mutex_enter(&ulp->ul_lock);
		while (ulp->ul_fs_lock & ULOCKFS_MAP_MASK) {
			if (ULOCKFS_IS_SLOCK(ulp) || ufsvfsp->vfs_nointr) {
				cv_wait(&ulp->ul_cv, &ulp->ul_lock);
			} else {
				sigintr(&smask, 1);
				sig = cv_wait_sig(&ulp->ul_cv, &ulp->ul_lock);
				sigunintr(&smask);
				if (((ulp->ul_fs_lock & ULOCKFS_MAP_MASK) &&
				    !sig) || ufsvfsp->vfs_dontblock) {
					mutex_exit(&ulp->ul_lock);
					return (EINTR);
				}
			}
		}
		mutex_exit(&ulp->ul_lock);
		goto retry_map;
	}

	vn_a.vp = vp;
	vn_a.offset = (u_offset_t)off;
	vn_a.type = flags & MAP_TYPE;
	vn_a.prot = prot;
	vn_a.maxprot = maxprot;
	vn_a.cred = cr;
	vn_a.amp = NULL;
	vn_a.flags = flags & ~MAP_TYPE;
	vn_a.szc = 0;
	vn_a.lgrp_mem_policy_flags = 0;

	error = as_map_locked(as, *addrp, len, segvn_create, &vn_a);
	if (ulp)
		ufs_lockfs_end(ulp);
	as_rangeunlock(as);
out:
	return (error);
}

/* ARGSUSED */
static int
ufs_addmap(struct vnode *vp,
	offset_t off,
	struct as *as,
	caddr_t addr,
	size_t	len,
	uchar_t  prot,
	uchar_t  maxprot,
	uint_t    flags,
	struct cred *cr,
	caller_context_t *ct)
{
	struct inode *ip = VTOI(vp);

	if (vp->v_flag & VNOMAP) {
		return (ENOSYS);
	}

	mutex_enter(&ip->i_tlock);
	ip->i_mapcnt += btopr(len);
	mutex_exit(&ip->i_tlock);
	return (0);
}

/*ARGSUSED*/
static int
ufs_delmap(struct vnode *vp, offset_t off, struct as *as, caddr_t addr,
	size_t len, uint_t prot,  uint_t maxprot,  uint_t flags,
	struct cred *cr, caller_context_t *ct)
{
	struct inode *ip = VTOI(vp);

	if (vp->v_flag & VNOMAP) {
		return (ENOSYS);
	}

	mutex_enter(&ip->i_tlock);
	ip->i_mapcnt -= btopr(len); 	/* Count released mappings */
	ASSERT(ip->i_mapcnt >= 0);
	mutex_exit(&ip->i_tlock);
	return (0);
}
/*
 * Return the answer requested to poll() for non-device files
 */
struct pollhead ufs_pollhd;

/* ARGSUSED */
int
ufs_poll(vnode_t *vp, short ev, int any, short *revp, struct pollhead **phpp,
	caller_context_t *ct)
{
	struct ufsvfs	*ufsvfsp;

	*revp = 0;
	ufsvfsp = VTOI(vp)->i_ufsvfs;

	if (!ufsvfsp) {
		*revp = POLLHUP;
		goto out;
	}

	if (ULOCKFS_IS_HLOCK(&ufsvfsp->vfs_ulockfs) ||
	    ULOCKFS_IS_ELOCK(&ufsvfsp->vfs_ulockfs)) {
		*revp |= POLLERR;

	} else {
		if ((ev & POLLOUT) && !ufsvfsp->vfs_fs->fs_ronly &&
		    !ULOCKFS_IS_WLOCK(&ufsvfsp->vfs_ulockfs))
			*revp |= POLLOUT;

		if ((ev & POLLWRBAND) && !ufsvfsp->vfs_fs->fs_ronly &&
		    !ULOCKFS_IS_WLOCK(&ufsvfsp->vfs_ulockfs))
			*revp |= POLLWRBAND;

		if (ev & POLLIN)
			*revp |= POLLIN;

		if (ev & POLLRDNORM)
			*revp |= POLLRDNORM;

		if (ev & POLLRDBAND)
			*revp |= POLLRDBAND;
	}

	if ((ev & POLLPRI) && (*revp & (POLLERR|POLLHUP)))
		*revp |= POLLPRI;
out:
	*phpp = !any && !*revp ? &ufs_pollhd : (struct pollhead *)NULL;

	return (0);
}

/* ARGSUSED */
static int
ufs_l_pathconf(struct vnode *vp, int cmd, ulong_t *valp, struct cred *cr,
	caller_context_t *ct)
{
	struct ufsvfs	*ufsvfsp = VTOI(vp)->i_ufsvfs;
	struct ulockfs	*ulp = NULL;
	struct inode 	*sip = NULL;
	int		error;
	struct inode 	*ip = VTOI(vp);
	int		issync;

	error = ufs_lockfs_begin(ufsvfsp, &ulp, ULOCKFS_PATHCONF_MASK);
	if (error)
		return (error);

	switch (cmd) {
		/*
		 * Have to handle _PC_NAME_MAX here, because the normal way
		 * [fs_pathconf() -> VOP_STATVFS() -> ufs_statvfs()]
		 * results in a lock ordering reversal between
		 * ufs_lockfs_{begin,end}() and
		 * ufs_thread_{suspend,continue}().
		 *
		 * Keep in sync with ufs_statvfs().
		 */
	case _PC_NAME_MAX:
		*valp = MAXNAMLEN;
		break;

	case _PC_FILESIZEBITS:
		if (ufsvfsp->vfs_lfflags & UFS_LARGEFILES)
			*valp = UFS_FILESIZE_BITS;
		else
			*valp = 32;
		break;

	case _PC_XATTR_EXISTS:
		if (vp->v_vfsp->vfs_flag & VFS_XATTR) {

			error =
			    ufs_xattr_getattrdir(vp, &sip, LOOKUP_XATTR, cr);
			if (error ==  0 && sip != NULL) {
				/* Start transaction */
				if (ulp) {
					TRANS_BEGIN_CSYNC(ufsvfsp, issync,
					    TOP_RMDIR, TOP_RMDIR_SIZE);
				}
				/*
				 * Is directory empty
				 */
				rw_enter(&sip->i_rwlock, RW_WRITER);
				rw_enter(&sip->i_contents, RW_WRITER);
				if (ufs_xattrdirempty(sip,
				    sip->i_number, CRED())) {
					rw_enter(&ip->i_contents, RW_WRITER);
					ufs_unhook_shadow(ip, sip);
					rw_exit(&ip->i_contents);

					*valp = 0;

				} else
					*valp = 1;
				rw_exit(&sip->i_contents);
				rw_exit(&sip->i_rwlock);
				if (ulp) {
					TRANS_END_CSYNC(ufsvfsp, error, issync,
					    TOP_RMDIR, TOP_RMDIR_SIZE);
				}
				VN_RELE(ITOV(sip));
			} else if (error == ENOENT) {
				*valp = 0;
				error = 0;
			}
		} else {
			error = fs_pathconf(vp, cmd, valp, cr, ct);
		}
		break;

	case _PC_ACL_ENABLED:
		*valp = _ACL_ACLENT_ENABLED;
		break;

	case _PC_MIN_HOLE_SIZE:
		*valp = (ulong_t)ip->i_fs->fs_bsize;
		break;

	case _PC_SATTR_ENABLED:
	case _PC_SATTR_EXISTS:
		*valp = vfs_has_feature(vp->v_vfsp, VFSFT_SYSATTR_VIEWS) &&
		    (vp->v_type == VREG || vp->v_type == VDIR);
		break;

	case _PC_TIMESTAMP_RESOLUTION:
		/*
		 * UFS keeps only microsecond timestamp resolution.
		 * This is historical and will probably never change.
		 */
		*valp = 1000L;
		break;

	default:
		error = fs_pathconf(vp, cmd, valp, cr, ct);
		break;
	}

	if (ulp != NULL) {
		ufs_lockfs_end(ulp);
	}
	return (error);
}

int ufs_pageio_writes, ufs_pageio_reads;

/*ARGSUSED*/
static int
ufs_pageio(struct vnode *vp, page_t *pp, u_offset_t io_off, size_t io_len,
	int flags, struct cred *cr, caller_context_t *ct)
{
	struct inode *ip = VTOI(vp);
	struct ufsvfs *ufsvfsp;
	page_t *npp = NULL, *opp = NULL, *cpp = pp;
	struct buf *bp;
	daddr_t bn;
	size_t done_len = 0, cur_len = 0;
	int err = 0;
	int contig = 0;
	int dolock;
	int vmpss = 0;
	struct ulockfs *ulp;

	if ((flags & B_READ) && pp != NULL && pp->p_vnode == vp &&
	    vp->v_mpssdata != NULL) {
		vmpss = 1;
	}

	dolock = (rw_owner(&ip->i_contents) != curthread);
	/*
	 * We need a better check.  Ideally, we would use another
	 * vnodeops so that hlocked and forcibly unmounted file
	 * systems would return EIO where appropriate and w/o the
	 * need for these checks.
	 */
	if ((ufsvfsp = ip->i_ufsvfs) == NULL)
		return (EIO);

	/*
	 * For vmpss (pp can be NULL) case respect the quiesce protocol.
	 * ul_lock must be taken before locking pages so we can't use it here
	 * if pp is non NULL because segvn already locked pages
	 * SE_EXCL. Instead we rely on the fact that a forced umount or
	 * applying a filesystem lock via ufs_fiolfs() will block in the
	 * implicit call to ufs_flush() until we unlock the pages after the
	 * return to segvn. Other ufs_quiesce() callers keep ufs_quiesce_pend
	 * above 0 until they are done. We have to be careful not to increment
	 * ul_vnops_cnt here after forceful unmount hlocks the file system.
	 *
	 * If pp is NULL use ul_lock to make sure we don't increment
	 * ul_vnops_cnt after forceful unmount hlocks the file system.
	 */
	if (vmpss || pp == NULL) {
		ulp = &ufsvfsp->vfs_ulockfs;
		if (pp == NULL)
			mutex_enter(&ulp->ul_lock);
		if (ulp->ul_fs_lock & ULOCKFS_GETREAD_MASK) {
			if (pp == NULL) {
				mutex_exit(&ulp->ul_lock);
			}
			return (vmpss ? EIO : EINVAL);
		}
		atomic_inc_ulong(&ulp->ul_vnops_cnt);
		if (pp == NULL)
			mutex_exit(&ulp->ul_lock);
		if (ufs_quiesce_pend) {
			if (!atomic_dec_ulong_nv(&ulp->ul_vnops_cnt))
				cv_broadcast(&ulp->ul_cv);
			return (vmpss ? EIO : EINVAL);
		}
	}

	if (dolock) {
		/*
		 * segvn may call VOP_PAGEIO() instead of VOP_GETPAGE() to
		 * handle a fault against a segment that maps vnode pages with
		 * large mappings.  Segvn creates pages and holds them locked
		 * SE_EXCL during VOP_PAGEIO() call. In this case we have to
		 * use rw_tryenter() to avoid a potential deadlock since in
		 * lock order i_contents needs to be taken first.
		 * Segvn will retry via VOP_GETPAGE() if VOP_PAGEIO() fails.
		 */
		if (!vmpss) {
			rw_enter(&ip->i_contents, RW_READER);
		} else if (!rw_tryenter(&ip->i_contents, RW_READER)) {
			if (!atomic_dec_ulong_nv(&ulp->ul_vnops_cnt))
				cv_broadcast(&ulp->ul_cv);
			return (EDEADLK);
		}
	}

	/*
	 * Return an error to segvn because the pagefault request is beyond
	 * PAGESIZE rounded EOF.
	 */
	if (vmpss && btopr(io_off + io_len) > btopr(ip->i_size)) {
		if (dolock)
			rw_exit(&ip->i_contents);
		if (!atomic_dec_ulong_nv(&ulp->ul_vnops_cnt))
			cv_broadcast(&ulp->ul_cv);
		return (EFAULT);
	}

	if (pp == NULL) {
		if (bmap_has_holes(ip)) {
			err = ENOSYS;
		} else {
			err = EINVAL;
		}
		if (dolock)
			rw_exit(&ip->i_contents);
		if (!atomic_dec_ulong_nv(&ulp->ul_vnops_cnt))
			cv_broadcast(&ulp->ul_cv);
		return (err);
	}

	/*
	 * Break the io request into chunks, one for each contiguous
	 * stretch of disk blocks in the target file.
	 */
	while (done_len < io_len) {
		ASSERT(cpp);
		contig = 0;
		if (err = bmap_read(ip, (u_offset_t)(io_off + done_len),
		    &bn, &contig))
			break;

		if (bn == UFS_HOLE) {	/* No holey swapfiles */
			if (vmpss) {
				err = EFAULT;
				break;
			}
			err = ufs_fault(ITOV(ip), "ufs_pageio: bn == UFS_HOLE");
			break;
		}

		cur_len = MIN(io_len - done_len, contig);
		/*
		 * Zero out a page beyond EOF, when the last block of
		 * a file is a UFS fragment so that ufs_pageio() can be used
		 * instead of ufs_getpage() to handle faults against
		 * segvn segments that use large pages.
		 */
		page_list_break(&cpp, &npp, btopr(cur_len));
		if ((flags & B_READ) && (cur_len & PAGEOFFSET)) {
			size_t xlen = cur_len & PAGEOFFSET;
			pagezero(cpp->p_prev, xlen, PAGESIZE - xlen);
		}

		bp = pageio_setup(cpp, cur_len, ip->i_devvp, flags);
		ASSERT(bp != NULL);

		bp->b_edev = ip->i_dev;
		bp->b_dev = cmpdev(ip->i_dev);
		bp->b_blkno = bn;
		bp->b_un.b_addr = (caddr_t)0;
		bp->b_file = ip->i_vnode;

		ufsvfsp->vfs_iotstamp = ddi_get_lbolt();
		ub.ub_pageios.value.ul++;
		if (ufsvfsp->vfs_snapshot)
			fssnap_strategy(&(ufsvfsp->vfs_snapshot), bp);
		else
			(void) bdev_strategy(bp);

		if (flags & B_READ)
			ufs_pageio_reads++;
		else
			ufs_pageio_writes++;
		if (flags & B_READ)
			lwp_stat_update(LWP_STAT_INBLK, 1);
		else
			lwp_stat_update(LWP_STAT_OUBLK, 1);
		/*
		 * If the request is not B_ASYNC, wait for i/o to complete
		 * and re-assemble the page list to return to the caller.
		 * If it is B_ASYNC we leave the page list in pieces and
		 * cleanup() will dispose of them.
		 */
		if ((flags & B_ASYNC) == 0) {
			err = biowait(bp);
			pageio_done(bp);
			if (err)
				break;
			page_list_concat(&opp, &cpp);
		}
		cpp = npp;
		npp = NULL;
		if (flags & B_READ)
			cur_len = P2ROUNDUP_TYPED(cur_len, PAGESIZE, size_t);
		done_len += cur_len;
	}
	ASSERT(err || (cpp == NULL && npp == NULL && done_len == io_len));
	if (err) {
		if (flags & B_ASYNC) {
			/* Cleanup unprocessed parts of list */
			page_list_concat(&cpp, &npp);
			if (flags & B_READ)
				pvn_read_done(cpp, B_ERROR);
			else
				pvn_write_done(cpp, B_ERROR);
		} else {
			/* Re-assemble list and let caller clean up */
			page_list_concat(&opp, &cpp);
			page_list_concat(&opp, &npp);
		}
	}

	if (vmpss && !(ip->i_flag & IACC) && !ULOCKFS_IS_NOIACC(ulp) &&
	    ufsvfsp->vfs_fs->fs_ronly == 0 && !ufsvfsp->vfs_noatime) {
		mutex_enter(&ip->i_tlock);
		ip->i_flag |= IACC;
		ITIMES_NOLOCK(ip);
		mutex_exit(&ip->i_tlock);
	}

	if (dolock)
		rw_exit(&ip->i_contents);
	if (vmpss && !atomic_dec_ulong_nv(&ulp->ul_vnops_cnt))
		cv_broadcast(&ulp->ul_cv);
	return (err);
}

/*
 * Called when the kernel is in a frozen state to dump data
 * directly to the device. It uses a private dump data structure,
 * set up by dump_ctl, to locate the correct disk block to which to dump.
 */
/*ARGSUSED*/
static int
ufs_dump(vnode_t *vp, caddr_t addr, offset_t ldbn, offset_t dblks,
    caller_context_t *ct)
{
	u_offset_t	file_size;
	struct inode    *ip = VTOI(vp);
	struct fs	*fs = ip->i_fs;
	daddr_t		dbn, lfsbn;
	int		disk_blks = fs->fs_bsize >> DEV_BSHIFT;
	int		error = 0;
	int		ndbs, nfsbs;

	/*
	 * forced unmount case
	 */
	if (ip->i_ufsvfs == NULL)
		return (EIO);
	/*
	 * Validate the inode that it has not been modified since
	 * the dump structure is allocated.
	 */
	mutex_enter(&ip->i_tlock);
	if ((dump_info == NULL) ||
	    (dump_info->ip != ip) ||
	    (dump_info->time.tv_sec != ip->i_mtime.tv_sec) ||
	    (dump_info->time.tv_usec != ip->i_mtime.tv_usec)) {
		mutex_exit(&ip->i_tlock);
		return (-1);
	}
	mutex_exit(&ip->i_tlock);

	/*
	 * See that the file has room for this write
	 */
	UFS_GET_ISIZE(&file_size, ip);

	if (ldbtob(ldbn + dblks) > file_size)
		return (ENOSPC);

	/*
	 * Find the physical disk block numbers from the dump
	 * private data structure directly and write out the data
	 * in contiguous block lumps
	 */
	while (dblks > 0 && !error) {
		lfsbn = (daddr_t)lblkno(fs, ldbtob(ldbn));
		dbn = fsbtodb(fs, dump_info->dblk[lfsbn]) + ldbn % disk_blks;
		nfsbs = 1;
		ndbs = disk_blks - ldbn % disk_blks;
		while (ndbs < dblks && fsbtodb(fs, dump_info->dblk[lfsbn +
		    nfsbs]) == dbn + ndbs) {
			nfsbs++;
			ndbs += disk_blks;
		}
		if (ndbs > dblks)
			ndbs = dblks;
		error = bdev_dump(ip->i_dev, addr, dbn, ndbs);
		addr += ldbtob((offset_t)ndbs);
		dblks -= ndbs;
		ldbn += ndbs;
	}
	return (error);

}

/*
 * Prepare the file system before and after the dump operation.
 *
 * action = DUMP_ALLOC:
 * Preparation before dump, allocate dump private data structure
 * to hold all the direct and indirect block info for dump.
 *
 * action = DUMP_FREE:
 * Clean up after dump, deallocate the dump private data structure.
 *
 * action = DUMP_SCAN:
 * Scan dump_info for *blkp DEV_BSIZE blocks of contig fs space;
 * if found, the starting file-relative DEV_BSIZE lbn is written
 * to *bklp; that lbn is intended for use with VOP_DUMP()
 */
/*ARGSUSED*/
static int
ufs_dumpctl(vnode_t *vp, int action, offset_t *blkp, caller_context_t *ct)
{
	struct inode	*ip = VTOI(vp);
	ufsvfs_t	*ufsvfsp = ip->i_ufsvfs;
	struct fs	*fs;
	daddr32_t	*dblk, *storeblk;
	daddr32_t	*nextblk, *endblk;
	struct buf	*bp;
	int		i, entry, entries;
	int		n, ncontig;

	/*
	 * check for forced unmount
	 */
	if (ufsvfsp == NULL)
		return (EIO);

	if (action == DUMP_ALLOC) {
		/*
		 * alloc and record dump_info
		 */
		if (dump_info != NULL)
			return (EINVAL);

		ASSERT(vp->v_type == VREG);
		fs = ufsvfsp->vfs_fs;

		rw_enter(&ip->i_contents, RW_READER);

		if (bmap_has_holes(ip)) {
			rw_exit(&ip->i_contents);
			return (EFAULT);
		}

		/*
		 * calculate and allocate space needed according to i_size
		 */
		entries = (int)lblkno(fs, blkroundup(fs, ip->i_size));
		dump_info = kmem_alloc(sizeof (struct dump) +
		    (entries - 1) * sizeof (daddr32_t), KM_NOSLEEP);
		if (dump_info == NULL) {
			rw_exit(&ip->i_contents);
			return (ENOMEM);
		}

		/* Start saving the info */
		dump_info->fsbs = entries;
		dump_info->ip = ip;
		storeblk = &dump_info->dblk[0];

		/* Direct Blocks */
		for (entry = 0; entry < NDADDR && entry < entries; entry++)
			*storeblk++ = ip->i_db[entry];

		/* Indirect Blocks */
		for (i = 0; i < NIADDR; i++) {
			int error = 0;

			bp = UFS_BREAD(ufsvfsp,
			    ip->i_dev, fsbtodb(fs, ip->i_ib[i]), fs->fs_bsize);
			if (bp->b_flags & B_ERROR)
				error = EIO;
			else {
				dblk = bp->b_un.b_daddr;
				if ((storeblk = save_dblks(ip, ufsvfsp,
				    storeblk, dblk, i, entries)) == NULL)
					error = EIO;
			}

			brelse(bp);

			if (error != 0) {
				kmem_free(dump_info, sizeof (struct dump) +
				    (entries - 1) * sizeof (daddr32_t));
				rw_exit(&ip->i_contents);
				dump_info = NULL;
				return (error);
			}
		}
		/* and time stamp the information */
		mutex_enter(&ip->i_tlock);
		dump_info->time = ip->i_mtime;
		mutex_exit(&ip->i_tlock);

		rw_exit(&ip->i_contents);
	} else if (action == DUMP_FREE) {
		/*
		 * free dump_info
		 */
		if (dump_info == NULL)
			return (EINVAL);
		entries = dump_info->fsbs - 1;
		kmem_free(dump_info, sizeof (struct dump) +
		    entries * sizeof (daddr32_t));
		dump_info = NULL;
	} else if (action == DUMP_SCAN) {
		/*
		 * scan dump_info
		 */
		if (dump_info == NULL)
			return (EINVAL);

		dblk = dump_info->dblk;
		nextblk = dblk + 1;
		endblk = dblk + dump_info->fsbs - 1;
		fs = ufsvfsp->vfs_fs;
		ncontig = *blkp >> (fs->fs_bshift - DEV_BSHIFT);

		/*
		 * scan dblk[] entries; contig fs space is found when:
		 * ((current blkno + frags per block) == next blkno)
		 */
		n = 0;
		while (n < ncontig && dblk < endblk) {
			if ((*dblk + fs->fs_frag) == *nextblk)
				n++;
			else
				n = 0;
			dblk++;
			nextblk++;
		}

		/*
		 * index is where size bytes of contig space begins;
		 * conversion from index to the file's DEV_BSIZE lbn
		 * is equivalent to:  (index * fs_bsize) / DEV_BSIZE
		 */
		if (n == ncontig) {
			i = (dblk - dump_info->dblk) - ncontig;
			*blkp = i << (fs->fs_bshift - DEV_BSHIFT);
		} else
			return (EFAULT);
	}
	return (0);
}

/*
 * Recursive helper function for ufs_dumpctl().  It follows the indirect file
 * system  blocks until it reaches the the disk block addresses, which are
 * then stored into the given buffer, storeblk.
 */
static daddr32_t *
save_dblks(struct inode *ip, struct ufsvfs *ufsvfsp,  daddr32_t *storeblk,
    daddr32_t *dblk, int level, int entries)
{
	struct fs	*fs = ufsvfsp->vfs_fs;
	struct buf	*bp;
	int		i;

	if (level == 0) {
		for (i = 0; i < NINDIR(fs); i++) {
			if (storeblk - dump_info->dblk >= entries)
				break;
			*storeblk++ = dblk[i];
		}
		return (storeblk);
	}
	for (i = 0; i < NINDIR(fs); i++) {
		if (storeblk - dump_info->dblk >= entries)
			break;
		bp = UFS_BREAD(ufsvfsp,
		    ip->i_dev, fsbtodb(fs, dblk[i]), fs->fs_bsize);
		if (bp->b_flags & B_ERROR) {
			brelse(bp);
			return (NULL);
		}
		storeblk = save_dblks(ip, ufsvfsp, storeblk, bp->b_un.b_daddr,
		    level - 1, entries);
		brelse(bp);

		if (storeblk == NULL)
			return (NULL);
	}
	return (storeblk);
}

/* ARGSUSED */
static int
ufs_getsecattr(struct vnode *vp, vsecattr_t *vsap, int flag,
	struct cred *cr, caller_context_t *ct)
{
	struct inode	*ip = VTOI(vp);
	struct ulockfs	*ulp;
	struct ufsvfs	*ufsvfsp = ip->i_ufsvfs;
	ulong_t		vsa_mask = vsap->vsa_mask;
	int		err = EINVAL;

	vsa_mask &= (VSA_ACL | VSA_ACLCNT | VSA_DFACL | VSA_DFACLCNT);

	/*
	 * Only grab locks if needed - they're not needed to check vsa_mask
	 * or if the mask contains no acl flags.
	 */
	if (vsa_mask != 0) {
		if (err = ufs_lockfs_begin(ufsvfsp, &ulp,
		    ULOCKFS_GETATTR_MASK))
			return (err);

		rw_enter(&ip->i_contents, RW_READER);
		err = ufs_acl_get(ip, vsap, flag, cr);
		rw_exit(&ip->i_contents);

		if (ulp)
			ufs_lockfs_end(ulp);
	}
	return (err);
}

/* ARGSUSED */
static int
ufs_setsecattr(struct vnode *vp, vsecattr_t *vsap, int flag, struct cred *cr,
	caller_context_t *ct)
{
	struct inode	*ip = VTOI(vp);
	struct ulockfs	*ulp = NULL;
	struct ufsvfs	*ufsvfsp = VTOI(vp)->i_ufsvfs;
	ulong_t		vsa_mask = vsap->vsa_mask;
	int		err;
	int		haverwlock = 1;
	int		trans_size;
	int		donetrans = 0;
	int		retry = 1;

	ASSERT(RW_LOCK_HELD(&ip->i_rwlock));

	/* Abort now if the request is either empty or invalid. */
	vsa_mask &= (VSA_ACL | VSA_ACLCNT | VSA_DFACL | VSA_DFACLCNT);
	if ((vsa_mask == 0) ||
	    ((vsap->vsa_aclentp == NULL) &&
	    (vsap->vsa_dfaclentp == NULL))) {
		err = EINVAL;
		goto out;
	}

	/*
	 * Following convention, if this is a directory then we acquire the
	 * inode's i_rwlock after starting a UFS logging transaction;
	 * otherwise, we acquire it beforehand. Since we were called (and
	 * must therefore return) with the lock held, we will have to drop it,
	 * and later reacquire it, if operating on a directory.
	 */
	if (vp->v_type == VDIR) {
		rw_exit(&ip->i_rwlock);
		haverwlock = 0;
	} else {
		/* Upgrade the lock if required. */
		if (!rw_write_held(&ip->i_rwlock)) {
			rw_exit(&ip->i_rwlock);
			rw_enter(&ip->i_rwlock, RW_WRITER);
		}
	}

again:
	ASSERT(!(vp->v_type == VDIR && haverwlock));
	if (err = ufs_lockfs_begin(ufsvfsp, &ulp, ULOCKFS_SETATTR_MASK)) {
		ulp = NULL;
		retry = 0;
		goto out;
	}

	/*
	 * Check that the file system supports this operation. Note that
	 * ufs_lockfs_begin() will have checked that the file system had
	 * not been forcibly unmounted.
	 */
	if (ufsvfsp->vfs_fs->fs_ronly) {
		err = EROFS;
		goto out;
	}
	if (ufsvfsp->vfs_nosetsec) {
		err = ENOSYS;
		goto out;
	}

	if (ulp) {
		TRANS_BEGIN_ASYNC(ufsvfsp, TOP_SETSECATTR,
		    trans_size = TOP_SETSECATTR_SIZE(VTOI(vp)));
		donetrans = 1;
	}

	if (vp->v_type == VDIR) {
		rw_enter(&ip->i_rwlock, RW_WRITER);
		haverwlock = 1;
	}

	ASSERT(haverwlock);

	/* Do the actual work. */
	rw_enter(&ip->i_contents, RW_WRITER);
	/*
	 * Suppress out of inodes messages if we will retry.
	 */
	if (retry)
		ip->i_flag |= IQUIET;
	err = ufs_acl_set(ip, vsap, flag, cr);
	ip->i_flag &= ~IQUIET;
	rw_exit(&ip->i_contents);

out:
	if (ulp) {
		if (donetrans) {
			/*
			 * top_end_async() can eventually call
			 * top_end_sync(), which can block. We must
			 * therefore observe the lock-ordering protocol
			 * here as well.
			 */
			if (vp->v_type == VDIR) {
				rw_exit(&ip->i_rwlock);
				haverwlock = 0;
			}
			TRANS_END_ASYNC(ufsvfsp, TOP_SETSECATTR, trans_size);
		}
		ufs_lockfs_end(ulp);
	}
	/*
	 * If no inodes available, try scaring a logically-
	 * free one out of the delete queue to someplace
	 * that we can find it.
	 */
	if ((err == ENOSPC) && retry && TRANS_ISTRANS(ufsvfsp)) {
		ufs_delete_drain_wait(ufsvfsp, 1);
		retry = 0;
		if (vp->v_type == VDIR && haverwlock) {
			rw_exit(&ip->i_rwlock);
			haverwlock = 0;
		}
		goto again;
	}
	/*
	 * If we need to reacquire the lock then it is safe to do so
	 * as a reader. This is because ufs_rwunlock(), which will be
	 * called by our caller after we return, does not differentiate
	 * between shared and exclusive locks.
	 */
	if (!haverwlock) {
		ASSERT(vp->v_type == VDIR);
		rw_enter(&ip->i_rwlock, RW_READER);
	}

	return (err);
}

/*
 * Locate the vnode to be used for an event notification. As this will
 * be called prior to the name space change perform basic verification
 * that the change will be allowed.
 */

static int
ufs_eventlookup(struct vnode *dvp, char *nm, struct cred *cr,
    struct vnode **vpp)
{
	int	namlen;
	int	error;
	struct vnode	*vp;
	struct inode	*ip;
	struct inode	*xip;
	struct ufsvfs	*ufsvfsp;
	struct ulockfs	*ulp;

	ip = VTOI(dvp);
	*vpp = NULL;

	if ((namlen = strlen(nm)) == 0)
		return (EINVAL);

	if (nm[0] == '.') {
		if (namlen == 1)
			return (EINVAL);
		else if ((namlen == 2) && nm[1] == '.') {
			return (EEXIST);
		}
	}

	/*
	 * Check accessibility and write access of parent directory as we
	 * only want to post the event if we're able to make a change.
	 */
	if (error = ufs_diraccess(ip, IEXEC|IWRITE, cr))
		return (error);

	if (vp = dnlc_lookup(dvp, nm)) {
		if (vp == DNLC_NO_VNODE) {
			VN_RELE(vp);
			return (ENOENT);
		}

		*vpp = vp;
		return (0);
	}

	/*
	 * Keep the idle queue from getting too long by idling two
	 * inodes before attempting to allocate another.
	 * This operation must be performed before entering lockfs
	 * or a transaction.
	 */
	if (ufs_idle_q.uq_ne > ufs_idle_q.uq_hiwat)
		if ((curthread->t_flag & T_DONTBLOCK) == 0) {
			ins.in_lidles.value.ul += ufs_lookup_idle_count;
			ufs_idle_some(ufs_lookup_idle_count);
		}

	ufsvfsp = ip->i_ufsvfs;

retry_lookup:
	if (error = ufs_lockfs_begin(ufsvfsp, &ulp, ULOCKFS_LOOKUP_MASK))
		return (error);

	if ((error = ufs_dirlook(ip, nm, &xip, cr, 1, 1)) == 0) {
		vp = ITOV(xip);
		*vpp = vp;
	}

	if (ulp) {
		ufs_lockfs_end(ulp);
	}

	if (error == EAGAIN)
		goto retry_lookup;

	return (error);
}
