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

/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#include <sys/sysmacros.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/t_lock.h>
#include <sys/uio.h>
#include <sys/kmem.h>
#include <sys/thread.h>
#include <sys/vfs.h>
#include <sys/errno.h>
#include <sys/buf.h>
#include <sys/vnode.h>
#include <sys/fs/ufs_trans.h>
#include <sys/fs/ufs_inode.h>
#include <sys/fs/ufs_fs.h>
#include <sys/fs/ufs_fsdir.h>
#include <sys/fs/ufs_quota.h>
#include <sys/fs/ufs_panic.h>
#include <sys/fs/ufs_bio.h>
#include <sys/fs/ufs_log.h>
#include <sys/cmn_err.h>
#include <sys/file.h>
#include <sys/debug.h>


extern kmutex_t ufsvfs_mutex;
extern struct ufsvfs *ufs_instances;

/*
 * hlock any file systems w/errored logs
 */
int
ufs_trans_hlock()
{
	struct ufsvfs	*ufsvfsp;
	struct lockfs	lockfs;
	int		error;
	int		retry	= 0;

	/*
	 * find fs's that paniced or have errored logging devices
	 */
	mutex_enter(&ufsvfs_mutex);
	for (ufsvfsp = ufs_instances; ufsvfsp; ufsvfsp = ufsvfsp->vfs_next) {
		/*
		 * not mounted; continue
		 */
		if ((ufsvfsp->vfs_vfs == NULL) ||
		    (ufsvfsp->vfs_validfs == UT_UNMOUNTED))
			continue;
		/*
		 * disallow unmounts (hlock occurs below)
		 */
		if (TRANS_ISERROR(ufsvfsp))
			ufsvfsp->vfs_validfs = UT_HLOCKING;
	}
	mutex_exit(&ufsvfs_mutex);

	/*
	 * hlock the fs's that paniced or have errored logging devices
	 */
again:
	mutex_enter(&ufsvfs_mutex);
	for (ufsvfsp = ufs_instances; ufsvfsp; ufsvfsp = ufsvfsp->vfs_next)
		if (ufsvfsp->vfs_validfs == UT_HLOCKING)
			break;
	mutex_exit(&ufsvfs_mutex);
	if (ufsvfsp == NULL)
		return (retry);
	/*
	 * hlock the file system
	 */
	(void) ufs_fiolfss(ufsvfsp->vfs_root, &lockfs);
	if (!LOCKFS_IS_ELOCK(&lockfs)) {
		lockfs.lf_lock = LOCKFS_HLOCK;
		lockfs.lf_flags = 0;
		lockfs.lf_comlen = 0;
		lockfs.lf_comment = NULL;
		error = ufs_fiolfs(ufsvfsp->vfs_root, &lockfs, 0);
		/*
		 * retry after awhile; another app currently doing lockfs
		 */
		if (error == EBUSY || error == EINVAL)
			retry = 1;
	} else {
		if (ufsfx_get_failure_qlen() > 0) {
			if (mutex_tryenter(&ufs_fix.uq_mutex)) {
				ufs_fix.uq_lowat = ufs_fix.uq_ne;
				cv_broadcast(&ufs_fix.uq_cv);
				mutex_exit(&ufs_fix.uq_mutex);
			}
		}
		retry = 1;
	}

	/*
	 * allow unmounts
	 */
	ufsvfsp->vfs_validfs = UT_MOUNTED;
	goto again;
}

/*ARGSUSED*/
void
ufs_trans_onerror()
{
	mutex_enter(&ufs_hlock.uq_mutex);
	ufs_hlock.uq_ne = ufs_hlock.uq_lowat;
	cv_broadcast(&ufs_hlock.uq_cv);
	mutex_exit(&ufs_hlock.uq_mutex);
}

void
ufs_trans_sbupdate(struct ufsvfs *ufsvfsp, struct vfs *vfsp, top_t topid)
{
	if (curthread->t_flag & T_DONTBLOCK) {
		sbupdate(vfsp);
		return;
	} else {

		if (panicstr && TRANS_ISTRANS(ufsvfsp))
			return;

		curthread->t_flag |= T_DONTBLOCK;
		TRANS_BEGIN_ASYNC(ufsvfsp, topid, TOP_SBUPDATE_SIZE);
		sbupdate(vfsp);
		TRANS_END_ASYNC(ufsvfsp, topid, TOP_SBUPDATE_SIZE);
		curthread->t_flag &= ~T_DONTBLOCK;
	}
}

void
ufs_trans_iupdat(struct inode *ip, int waitfor)
{
	struct ufsvfs	*ufsvfsp;

	if (curthread->t_flag & T_DONTBLOCK) {
		rw_enter(&ip->i_contents, RW_READER);
		ufs_iupdat(ip, waitfor);
		rw_exit(&ip->i_contents);
		return;
	} else {
		ufsvfsp = ip->i_ufsvfs;

		if (panicstr && TRANS_ISTRANS(ufsvfsp))
			return;

		curthread->t_flag |= T_DONTBLOCK;
		TRANS_BEGIN_ASYNC(ufsvfsp, TOP_IUPDAT, TOP_IUPDAT_SIZE(ip));
		rw_enter(&ip->i_contents, RW_READER);
		ufs_iupdat(ip, waitfor);
		rw_exit(&ip->i_contents);
		TRANS_END_ASYNC(ufsvfsp, TOP_IUPDAT, TOP_IUPDAT_SIZE(ip));
		curthread->t_flag &= ~T_DONTBLOCK;
	}
}

void
ufs_trans_sbwrite(struct ufsvfs *ufsvfsp, top_t topid)
{
	if (curthread->t_flag & T_DONTBLOCK) {
		mutex_enter(&ufsvfsp->vfs_lock);
		ufs_sbwrite(ufsvfsp);
		mutex_exit(&ufsvfsp->vfs_lock);
		return;
	} else {

		if (panicstr && TRANS_ISTRANS(ufsvfsp))
			return;

		curthread->t_flag |= T_DONTBLOCK;
		TRANS_BEGIN_ASYNC(ufsvfsp, topid, TOP_SBWRITE_SIZE);
		mutex_enter(&ufsvfsp->vfs_lock);
		ufs_sbwrite(ufsvfsp);
		mutex_exit(&ufsvfsp->vfs_lock);
		TRANS_END_ASYNC(ufsvfsp, topid, TOP_SBWRITE_SIZE);
		curthread->t_flag &= ~T_DONTBLOCK;
	}
}

/*ARGSUSED*/
int
ufs_trans_push_si(ufsvfs_t *ufsvfsp, delta_t dtyp, int ignore)
{
	struct fs	*fs;

	fs = ufsvfsp->vfs_fs;
	mutex_enter(&ufsvfsp->vfs_lock);
	TRANS_LOG(ufsvfsp, (char *)fs->fs_u.fs_csp,
	    ldbtob(fsbtodb(fs, fs->fs_csaddr)), fs->fs_cssize,
	    (caddr_t)fs->fs_u.fs_csp, fs->fs_cssize);
	mutex_exit(&ufsvfsp->vfs_lock);
	return (0);
}

/*ARGSUSED*/
int
ufs_trans_push_buf(ufsvfs_t *ufsvfsp, delta_t dtyp, daddr_t bno)
{
	struct buf	*bp;

	bp = (struct buf *)UFS_GETBLK(ufsvfsp, ufsvfsp->vfs_dev, bno, 1);
	if (bp == NULL)
		return (ENOENT);

	if (bp->b_flags & B_DELWRI) {
		/*
		 * Do not use brwrite() here since the buffer is already
		 * marked for retry or not by the code that called
		 * TRANS_BUF().
		 */
		UFS_BWRITE(ufsvfsp, bp);
		return (0);
	}
	/*
	 * If we did not find the real buf for this block above then
	 * clear the dev so the buf won't be found by mistake
	 * for this block later.  We had to allocate at least a 1 byte
	 * buffer to keep brelse happy.
	 */
	if (bp->b_bufsize == 1) {
		bp->b_dev = (o_dev_t)NODEV;
		bp->b_edev = NODEV;
		bp->b_flags = 0;
	}
	brelse(bp);
	return (ENOENT);
}

/*ARGSUSED*/
int
ufs_trans_push_inode(ufsvfs_t *ufsvfsp, delta_t dtyp, ino_t ino)
{
	int		error;
	struct inode	*ip;

	/*
	 * Grab the quota lock (if the file system has not been forcibly
	 * unmounted).
	 */
	if (ufsvfsp)
		rw_enter(&ufsvfsp->vfs_dqrwlock, RW_READER);

	error = ufs_iget(ufsvfsp->vfs_vfs, ino, &ip, kcred);

	if (ufsvfsp)
		rw_exit(&ufsvfsp->vfs_dqrwlock);
	if (error)
		return (ENOENT);

	if (ip->i_flag & (IUPD|IACC|ICHG|IMOD|IMODACC|IATTCHG)) {
		rw_enter(&ip->i_contents, RW_READER);
		ufs_iupdat(ip, 1);
		rw_exit(&ip->i_contents);
		VN_RELE(ITOV(ip));
		return (0);
	}
	VN_RELE(ITOV(ip));
	return (ENOENT);
}

#ifdef DEBUG
/*
 *	These routines maintain the metadata map (matamap)
 */

/*
 * update the metadata map at mount
 */
static int
ufs_trans_mata_mount_scan(struct inode *ip, void *arg)
{
	/*
	 * wrong file system; keep looking
	 */
	if (ip->i_ufsvfs != (struct ufsvfs *)arg)
		return (0);

	/*
	 * load the metadata map
	 */
	rw_enter(&ip->i_contents, RW_WRITER);
	ufs_trans_mata_iget(ip);
	rw_exit(&ip->i_contents);
	return (0);
}

void
ufs_trans_mata_mount(struct ufsvfs *ufsvfsp)
{
	struct fs	*fs	= ufsvfsp->vfs_fs;
	ino_t		ino;
	int		i;

	/*
	 * put static metadata into matamap
	 *	superblock
	 *	cylinder groups
	 *	inode groups
	 *	existing inodes
	 */
	TRANS_MATAADD(ufsvfsp, ldbtob(SBLOCK), fs->fs_sbsize);

	for (ino = i = 0; i < fs->fs_ncg; ++i, ino += fs->fs_ipg) {
		TRANS_MATAADD(ufsvfsp,
		    ldbtob(fsbtodb(fs, cgtod(fs, i))), fs->fs_cgsize);
		TRANS_MATAADD(ufsvfsp,
		    ldbtob(fsbtodb(fs, itod(fs, ino))),
		    fs->fs_ipg * sizeof (struct dinode));
	}
	(void) ufs_scan_inodes(0, ufs_trans_mata_mount_scan, ufsvfsp, ufsvfsp);
}

/*
 * clear the metadata map at umount
 */
void
ufs_trans_mata_umount(struct ufsvfs *ufsvfsp)
{
	top_mataclr(ufsvfsp);
}

/*
 * summary info (may be extended during growfs test)
 */
void
ufs_trans_mata_si(struct ufsvfs *ufsvfsp, struct fs *fs)
{
	TRANS_MATAADD(ufsvfsp, ldbtob(fsbtodb(fs, fs->fs_csaddr)),
	    fs->fs_cssize);
}

/*
 * scan an allocation block (either inode or true block)
 */
static void
ufs_trans_mata_direct(
	struct inode *ip,
	daddr_t *fragsp,
	daddr32_t *blkp,
	unsigned int nblk)
{
	int		i;
	daddr_t		frag;
	ulong_t		nb;
	struct ufsvfs	*ufsvfsp	= ip->i_ufsvfs;
	struct fs	*fs		= ufsvfsp->vfs_fs;

	for (i = 0; i < nblk && *fragsp; ++i, ++blkp)
		if ((frag = *blkp) != 0) {
			if (*fragsp > fs->fs_frag) {
				nb = fs->fs_bsize;
				*fragsp -= fs->fs_frag;
			} else {
				nb = *fragsp * fs->fs_fsize;
				*fragsp = 0;
			}
			TRANS_MATAADD(ufsvfsp, ldbtob(fsbtodb(fs, frag)), nb);
		}
}

/*
 * scan an indirect allocation block (either inode or true block)
 */
static void
ufs_trans_mata_indir(
	struct inode *ip,
	daddr_t *fragsp,
	daddr_t frag,
	int level)
{
	struct ufsvfs *ufsvfsp	= ip->i_ufsvfs;
	struct fs *fs = ufsvfsp->vfs_fs;
	int ne = fs->fs_bsize / (int)sizeof (daddr32_t);
	int i;
	struct buf *bp;
	daddr32_t *blkp;
	o_mode_t ifmt = ip->i_mode & IFMT;

	bp = UFS_BREAD(ufsvfsp, ip->i_dev, fsbtodb(fs, frag), fs->fs_bsize);
	if (bp->b_flags & B_ERROR) {
		brelse(bp);
		return;
	}
	blkp = bp->b_un.b_daddr;

	if (level || (ifmt == IFDIR) || (ifmt == IFSHAD) ||
	    (ifmt == IFATTRDIR) || (ip == ip->i_ufsvfs->vfs_qinod))
		ufs_trans_mata_direct(ip, fragsp, blkp, ne);

	if (level)
		for (i = 0; i < ne && *fragsp; ++i, ++blkp)
			ufs_trans_mata_indir(ip, fragsp, *blkp, level-1);
	brelse(bp);
}

/*
 * put appropriate metadata into matamap for this inode
 */
void
ufs_trans_mata_iget(struct inode *ip)
{
	int		i;
	daddr_t		frags	= dbtofsb(ip->i_fs, ip->i_blocks);
	o_mode_t	ifmt 	= ip->i_mode & IFMT;

	if (frags && ((ifmt == IFDIR) || (ifmt == IFSHAD) ||
	    (ifmt == IFATTRDIR) || (ip == ip->i_ufsvfs->vfs_qinod)))
		ufs_trans_mata_direct(ip, &frags, &ip->i_db[0], NDADDR);

	if (frags)
		ufs_trans_mata_direct(ip, &frags, &ip->i_ib[0], NIADDR);

	for (i = 0; i < NIADDR && frags; ++i)
		if (ip->i_ib[i])
			ufs_trans_mata_indir(ip, &frags, ip->i_ib[i], i);
}

/*
 * freeing possible metadata (block of user data)
 */
void
ufs_trans_mata_free(struct ufsvfs *ufsvfsp, offset_t mof, off_t nb)
{
	top_matadel(ufsvfsp, mof, nb);

}

/*
 * allocating metadata
 */
void
ufs_trans_mata_alloc(
	struct ufsvfs *ufsvfsp,
	struct inode *ip,
	daddr_t frag,
	ulong_t nb,
	int indir)
{
	struct fs	*fs	= ufsvfsp->vfs_fs;
	o_mode_t	ifmt 	= ip->i_mode & IFMT;

	if (indir || ((ifmt == IFDIR) || (ifmt == IFSHAD) ||
	    (ifmt == IFATTRDIR) || (ip == ip->i_ufsvfs->vfs_qinod)))
		TRANS_MATAADD(ufsvfsp, ldbtob(fsbtodb(fs, frag)), nb);
}

#endif /* DEBUG */

/*
 * ufs_trans_dir is used to declare a directory delta
 */
int
ufs_trans_dir(struct inode *ip, off_t offset)
{
	daddr_t	bn;
	int	contig = 0, error;

	ASSERT(ip);
	ASSERT(RW_WRITE_HELD(&ip->i_contents));
	error = bmap_read(ip, (u_offset_t)offset, &bn, &contig);
	if (error || (bn == UFS_HOLE)) {
		cmn_err(CE_WARN, "ufs_trans_dir - could not get block"
		    " number error = %d bn = %d\n", error, (int)bn);
		if (error == 0)	/* treat UFS_HOLE as an I/O error */
			error = EIO;
		return (error);
	}
	TRANS_DELTA(ip->i_ufsvfs, ldbtob(bn), DIRBLKSIZ, DT_DIR, 0, 0);
	return (error);
}

/*ARGSUSED*/
int
ufs_trans_push_quota(ufsvfs_t *ufsvfsp, delta_t dtyp, struct dquot *dqp)
{
	/*
	 * Lock the quota subsystem (ufsvfsp can be NULL
	 * if the DQ_ERROR is set).
	 */
	if (ufsvfsp)
		rw_enter(&ufsvfsp->vfs_dqrwlock, RW_READER);
	mutex_enter(&dqp->dq_lock);

	/*
	 * If this transaction has been cancelled by closedq_scan_inode(),
	 * then bail out now.  We don't call dqput() in this case because
	 * it has already been done.
	 */
	if ((dqp->dq_flags & DQ_TRANS) == 0) {
		mutex_exit(&dqp->dq_lock);
		if (ufsvfsp)
			rw_exit(&ufsvfsp->vfs_dqrwlock);
		return (0);
	}

	if (dqp->dq_flags & DQ_ERROR) {
		/*
		 * Paranoia to make sure that there is at least one
		 * reference to the dquot struct.  We are done with
		 * the dquot (due to an error) so clear logging
		 * specific markers.
		 */
		ASSERT(dqp->dq_cnt >= 1);
		dqp->dq_flags &= ~DQ_TRANS;
		dqput(dqp);
		mutex_exit(&dqp->dq_lock);
		if (ufsvfsp)
			rw_exit(&ufsvfsp->vfs_dqrwlock);
		return (1);
	}

	if (dqp->dq_flags & (DQ_MOD | DQ_BLKS | DQ_FILES)) {
		ASSERT((dqp->dq_mof != UFS_HOLE) && (dqp->dq_mof != 0));
		TRANS_LOG(ufsvfsp, (caddr_t)&dqp->dq_dqb,
		    dqp->dq_mof, (int)sizeof (struct dqblk), NULL, 0);
		/*
		 * Paranoia to make sure that there is at least one
		 * reference to the dquot struct.  Clear the
		 * modification flag because the operation is now in
		 * the log.  Also clear the logging specific markers
		 * that were set in ufs_trans_quota().
		 */
		ASSERT(dqp->dq_cnt >= 1);
		dqp->dq_flags &= ~(DQ_MOD | DQ_TRANS);
		dqput(dqp);
	}

	/*
	 * At this point, the logging specific flag should be clear,
	 * but add paranoia just in case something has gone wrong.
	 */
	ASSERT((dqp->dq_flags & DQ_TRANS) == 0);
	mutex_exit(&dqp->dq_lock);
	if (ufsvfsp)
		rw_exit(&ufsvfsp->vfs_dqrwlock);
	return (0);
}

/*
 * ufs_trans_quota take in a uid, allocates the disk space, placing the
 * quota record into the metamap, then declares the delta.
 */
/*ARGSUSED*/
void
ufs_trans_quota(struct dquot *dqp)
{

	struct inode	*qip = dqp->dq_ufsvfsp->vfs_qinod;

	ASSERT(qip);
	ASSERT(MUTEX_HELD(&dqp->dq_lock));
	ASSERT(dqp->dq_flags & DQ_MOD);
	ASSERT(dqp->dq_mof != 0);
	ASSERT(dqp->dq_mof != UFS_HOLE);

	/*
	 * Mark this dquot to indicate that we are starting a logging
	 * file system operation for this dquot.  Also increment the
	 * reference count so that the dquot does not get reused while
	 * it is on the mapentry_t list.  DQ_TRANS is cleared and the
	 * reference count is decremented by ufs_trans_push_quota.
	 *
	 * If the file system is force-unmounted while there is a
	 * pending quota transaction, then closedq_scan_inode() will
	 * clear the DQ_TRANS flag and decrement the reference count.
	 *
	 * Since deltamap_add() drops multiple transactions to the
	 * same dq_mof and ufs_trans_push_quota() won't get called,
	 * we use DQ_TRANS to prevent repeat transactions from
	 * incrementing the reference count (or calling TRANS_DELTA()).
	 */
	if ((dqp->dq_flags & DQ_TRANS) == 0) {
		dqp->dq_flags |= DQ_TRANS;
		dqp->dq_cnt++;
		TRANS_DELTA(qip->i_ufsvfs, dqp->dq_mof, sizeof (struct dqblk),
		    DT_QR, ufs_trans_push_quota, (ulong_t)dqp);
	}
}

void
ufs_trans_dqrele(struct dquot *dqp)
{
	struct ufsvfs	*ufsvfsp = dqp->dq_ufsvfsp;

	curthread->t_flag |= T_DONTBLOCK;
	TRANS_BEGIN_ASYNC(ufsvfsp, TOP_QUOTA, TOP_QUOTA_SIZE);
	rw_enter(&ufsvfsp->vfs_dqrwlock, RW_READER);
	dqrele(dqp);
	rw_exit(&ufsvfsp->vfs_dqrwlock);
	TRANS_END_ASYNC(ufsvfsp, TOP_QUOTA, TOP_QUOTA_SIZE);
	curthread->t_flag &= ~T_DONTBLOCK;
}

int ufs_trans_max_resv = TOP_MAX_RESV;	/* will be adjusted for testing */
long ufs_trans_avgbfree = 0;		/* will be adjusted for testing */
#define	TRANS_MAX_WRITE	(1024 * 1024)
size_t ufs_trans_max_resid = TRANS_MAX_WRITE;

/*
 * Calculate the log reservation for the given write or truncate
 */
static ulong_t
ufs_log_amt(struct inode *ip, offset_t offset, ssize_t resid, int trunc)
{
	long		ncg, last2blk;
	long		niblk		= 0;
	u_offset_t	writeend, offblk;
	int		resv;
	daddr_t		nblk, maxfblk;
	long		avgbfree;
	struct ufsvfs	*ufsvfsp	= ip->i_ufsvfs;
	struct fs	*fs		= ufsvfsp->vfs_fs;
	long		fni		= NINDIR(fs);
	int		bsize		= fs->fs_bsize;

	/*
	 * Assume that the request will fit in 1 or 2 cg's,
	 * resv is the amount of log space to reserve (in bytes).
	 */
	resv = SIZECG(ip) * 2 + INODESIZE + 1024;

	/*
	 * get max position of write in fs blocks
	 */
	writeend = offset + resid;
	maxfblk = lblkno(fs, writeend);
	offblk = lblkno(fs, offset);
	/*
	 * request size in fs blocks
	 */
	nblk = lblkno(fs, blkroundup(fs, resid));
	/*
	 * Adjust for sparse files
	 */
	if (trunc)
		nblk = MIN(nblk, ip->i_blocks);

	/*
	 * Adjust avgbfree (for testing)
	 */
	avgbfree = (ufs_trans_avgbfree) ? 1 : ufsvfsp->vfs_avgbfree + 1;

	/*
	 * Calculate maximum number of blocks of triple indirect
	 * pointers to write.
	 */
	last2blk = NDADDR + fni + fni * fni;
	if (maxfblk > last2blk) {
		long nl2ptr;
		long n3blk;

		if (offblk > last2blk)
			n3blk = maxfblk - offblk;
		else
			n3blk = maxfblk - last2blk;
		niblk += roundup(n3blk * sizeof (daddr_t), bsize) / bsize + 1;
		nl2ptr = roundup(niblk, fni) / fni + 1;
		niblk += roundup(nl2ptr * sizeof (daddr_t), bsize) / bsize + 2;
		maxfblk -= n3blk;
	}
	/*
	 * calculate maximum number of blocks of double indirect
	 * pointers to write.
	 */
	if (maxfblk > NDADDR + fni) {
		long n2blk;

		if (offblk > NDADDR + fni)
			n2blk = maxfblk - offblk;
		else
			n2blk = maxfblk - NDADDR + fni;
		niblk += roundup(n2blk * sizeof (daddr_t), bsize) / bsize + 2;
		maxfblk -= n2blk;
	}
	/*
	 * Add in indirect pointer block write
	 */
	if (maxfblk > NDADDR) {
		niblk += 1;
	}
	/*
	 * Calculate deltas for indirect pointer writes
	 */
	resv += niblk * (fs->fs_bsize + sizeof (struct delta));
	/*
	 * maximum number of cg's needed for request
	 */
	ncg = nblk / avgbfree;
	if (ncg > fs->fs_ncg)
		ncg = fs->fs_ncg;

	/*
	 * maximum amount of log space needed for request
	 */
	if (ncg > 2)
		resv += (ncg - 2) * SIZECG(ip);

	return (resv);
}

/*
 * Calculate the amount of log space that needs to be reserved for this
 * trunc request.  If the amount of log space is too large, then
 * calculate the the size that the requests needs to be split into.
 */
void
ufs_trans_trunc_resv(
	struct inode *ip,
	u_offset_t length,
	int *resvp,
	u_offset_t *residp)
{
	ulong_t		resv;
	u_offset_t	size, offset, resid;
	int		nchunks, flag;

	/*
	 *    *resvp is the amount of log space to reserve (in bytes).
	 *    when nonzero, *residp is the number of bytes to truncate.
	 */
	*residp = 0;

	if (length < ip->i_size) {
		size = ip->i_size - length;
	} else {
		resv = SIZECG(ip) * 2 + INODESIZE + 1024;
		/*
		 * truncate up, doesn't really use much space,
		 * the default above should be sufficient.
		 */
		goto done;
	}

	offset = length;
	resid = size;
	nchunks = 1;
	flag = 0;

	/*
	 * If this request takes too much log space, it will be split into
	 * "nchunks". If this split is not enough, linearly increment the
	 * nchunks in the next iteration.
	 */
	for (; (resv = ufs_log_amt(ip, offset, resid, 1)) > ufs_trans_max_resv;
	    offset = length + (nchunks - 1) * resid) {
		if (!flag) {
			nchunks = roundup(resv, ufs_trans_max_resv) /
			    ufs_trans_max_resv;
			flag = 1;
		} else {
			nchunks++;
		}
		resid = size / nchunks;
	}

	if (nchunks > 1) {
		*residp = resid;
	}
done:
	*resvp = resv;
}

int
ufs_trans_itrunc(struct inode *ip, u_offset_t length, int flags, cred_t *cr)
{
	int 		err, issync, resv;
	u_offset_t	resid;
	int		do_block	= 0;
	struct ufsvfs	*ufsvfsp	= ip->i_ufsvfs;
	struct fs	*fs		= ufsvfsp->vfs_fs;

	/*
	 * Not logging; just do the trunc
	 */
	if (!TRANS_ISTRANS(ufsvfsp)) {
		rw_enter(&ufsvfsp->vfs_dqrwlock, RW_READER);
		rw_enter(&ip->i_contents, RW_WRITER);
		err = ufs_itrunc(ip, length, flags, cr);
		rw_exit(&ip->i_contents);
		rw_exit(&ufsvfsp->vfs_dqrwlock);
		return (err);
	}

	/*
	 * within the lockfs protocol but *not* part of a transaction
	 */
	do_block = curthread->t_flag & T_DONTBLOCK;
	curthread->t_flag |= T_DONTBLOCK;

	/*
	 * Trunc the file (in pieces, if necessary)
	 */
again:
	ufs_trans_trunc_resv(ip, length, &resv, &resid);
	TRANS_BEGIN_CSYNC(ufsvfsp, issync, TOP_ITRUNC, resv);
	rw_enter(&ufsvfsp->vfs_dqrwlock, RW_READER);
	rw_enter(&ip->i_contents, RW_WRITER);
	if (resid) {
		/*
		 * resid is only set if we have to truncate in chunks
		 */
		ASSERT(length + resid < ip->i_size);

		/*
		 * Partially trunc file down to desired size (length).
		 * Only retain I_FREE on the last partial trunc.
		 * Round up size to a block boundary, to ensure the truncate
		 * doesn't have to allocate blocks. This is done both for
		 * performance and to fix a bug where if the block can't be
		 * allocated then the inode delete fails, but the inode
		 * is still freed with attached blocks and non-zero size
		 * (bug 4348738).
		 */
		err = ufs_itrunc(ip, blkroundup(fs, (ip->i_size - resid)),
		    flags & ~I_FREE, cr);
		ASSERT(ip->i_size != length);
	} else
		err = ufs_itrunc(ip, length, flags, cr);
	if (!do_block)
		curthread->t_flag &= ~T_DONTBLOCK;
	rw_exit(&ip->i_contents);
	rw_exit(&ufsvfsp->vfs_dqrwlock);
	TRANS_END_CSYNC(ufsvfsp, err, issync, TOP_ITRUNC, resv);

	if ((err == 0) && resid) {
		ufsvfsp->vfs_avgbfree = fs->fs_cstotal.cs_nbfree / fs->fs_ncg;
		goto again;
	}
	return (err);
}

/*
 * Calculate the amount of log space that needs to be reserved for this
 * write request.  If the amount of log space is too large, then
 * calculate the size that the requests needs to be split into.
 * First try fixed chunks of size ufs_trans_max_resid. If that
 * is too big, iterate down to the largest size that will fit.
 * Pagein the pages in the first chunk here, so that the pagein is
 * avoided later when the transaction is open.
 */
void
ufs_trans_write_resv(
	struct inode *ip,
	struct uio *uio,
	int *resvp,
	int *residp)
{
	ulong_t		resv;
	offset_t	offset;
	ssize_t		resid;
	int		nchunks;

	*residp = 0;
	offset = uio->uio_offset;
	resid = MIN(uio->uio_resid, ufs_trans_max_resid);
	resv = ufs_log_amt(ip, offset, resid, 0);
	if (resv <= ufs_trans_max_resv) {
		uio_prefaultpages(resid, uio);
		if (resid != uio->uio_resid)
			*residp = resid;
		*resvp = resv;
		return;
	}

	resid = uio->uio_resid;
	nchunks = 1;
	for (; (resv = ufs_log_amt(ip, offset, resid, 0)) > ufs_trans_max_resv;
	    offset = uio->uio_offset + (nchunks - 1) * resid) {
		nchunks++;
		resid = uio->uio_resid / nchunks;
	}
	uio_prefaultpages(resid, uio);
	/*
	 * If this request takes too much log space, it will be split
	 */
	if (nchunks > 1)
		*residp = resid;
	*resvp = resv;
}

/*
 * Issue write request.
 *
 * Split a large request into smaller chunks.
 */
int
ufs_trans_write(
	struct inode *ip,
	struct uio *uio,
	int ioflag,
	cred_t *cr,
	int resv,
	long resid)
{
	long		realresid;
	int		err;
	struct ufsvfs	*ufsvfsp = ip->i_ufsvfs;

	/*
	 * since the write is too big and would "HOG THE LOG" it needs to
	 * be broken up and done in pieces.  NOTE, the caller will
	 * issue the EOT after the request has been completed
	 */
	realresid = uio->uio_resid;

again:
	/*
	 * Perform partial request (uiomove will update uio for us)
	 *	Request is split up into "resid" size chunks until
	 *	"realresid" bytes have been transferred.
	 */
	uio->uio_resid = MIN(resid, realresid);
	realresid -= uio->uio_resid;
	err = wrip(ip, uio, ioflag, cr);

	/*
	 * Error or request is done; caller issues final EOT
	 */
	if (err || uio->uio_resid || (realresid == 0)) {
		uio->uio_resid += realresid;
		return (err);
	}

	/*
	 * Generate EOT for this part of the request
	 */
	rw_exit(&ip->i_contents);
	rw_exit(&ufsvfsp->vfs_dqrwlock);
	if (ioflag & (FSYNC|FDSYNC)) {
		TRANS_END_SYNC(ufsvfsp, err, TOP_WRITE_SYNC, resv);
	} else {
		TRANS_END_ASYNC(ufsvfsp, TOP_WRITE, resv);
	}

	/*
	 * Make sure the input buffer is resident before starting
	 * the next transaction.
	 */
	uio_prefaultpages(MIN(resid, realresid), uio);

	/*
	 * Generate BOT for next part of the request
	 */
	if (ioflag & (FSYNC|FDSYNC)) {
		int error;
		TRANS_BEGIN_SYNC(ufsvfsp, TOP_WRITE_SYNC, resv, error);
		ASSERT(!error);
	} else {
		TRANS_BEGIN_ASYNC(ufsvfsp, TOP_WRITE, resv);
	}
	rw_enter(&ufsvfsp->vfs_dqrwlock, RW_READER);
	rw_enter(&ip->i_contents, RW_WRITER);
	/*
	 * Error during EOT (probably device error while writing commit rec)
	 */
	if (err)
		return (err);
	goto again;
}
