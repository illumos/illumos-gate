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
#include <sys/acct.h>
#include <sys/dnlc.h>
#include <sys/swap.h>

#include <sys/fs/ufs_fs.h>
#include <sys/fs/ufs_inode.h>
#include <sys/fs/ufs_fsdir.h>
#include <sys/fs/ufs_trans.h>
#include <sys/fs/ufs_panic.h>
#include <sys/fs/ufs_mount.h>
#include <sys/fs/ufs_bio.h>
#include <sys/fs/ufs_log.h>
#include <sys/fs/ufs_quota.h>
#include <sys/dirent.h>		/* must be AFTER <sys/fs/fsdir.h>! */
#include <sys/errno.h>
#include <sys/sysinfo.h>

#include <vm/hat.h>
#include <vm/pvn.h>
#include <vm/as.h>
#include <vm/seg.h>
#include <vm/seg_map.h>
#include <vm/seg_vn.h>
#include <vm/rm.h>
#include <vm/anon.h>
#include <sys/swap.h>
#include <sys/dnlc.h>

extern struct vnode *common_specvp(struct vnode *vp);

/* error lock status */
#define	UN_ERRLCK	(-1)
#define	SET_ERRLCK	1
#define	RE_ERRLCK	2
#define	NO_ERRLCK	0

/*
 * Index to be used in TSD for storing lockfs data
 */
uint_t ufs_lockfs_key;

typedef struct _ulockfs_info {
	struct _ulockfs_info *next;
	struct ulockfs *ulp;
	uint_t flags;
} ulockfs_info_t;

#define	ULOCK_INFO_FALLOCATE	0x00000001	/* fallocate thread */

/*
 * Check in TSD that whether we are already doing any VOP on this filesystem
 */
#define	IS_REC_VOP(found, head, ulp, free)		\
{							\
	ulockfs_info_t *_curr;				\
							\
	for (found = 0, free = NULL, _curr = head;	\
	    _curr != NULL; _curr = _curr->next) {	\
		if ((free == NULL) &&			\
		    (_curr->ulp == NULL))		\
			free = _curr;			\
		if (_curr->ulp == ulp) {		\
			found = 1;			\
			break;				\
		}					\
	}						\
}

/*
 * Get the lockfs data from TSD so that lockfs handles the recursive VOP
 * properly
 */
#define	SEARCH_ULOCKFSP(head, ulp, info)		\
{							\
	ulockfs_info_t *_curr;				\
							\
	for (_curr = head; _curr != NULL;		\
	    _curr = _curr->next) {			\
		if (_curr->ulp == ulp) {		\
			break;				\
		}					\
	}						\
							\
	info = _curr;					\
}

/*
 * Validate lockfs request
 */
static int
ufs_getlfd(
	struct lockfs *lockfsp,		/* new lock request */
	struct lockfs *ul_lockfsp)	/* old lock state */
{
	int	error = 0;

	/*
	 * no input flags defined
	 */
	if (lockfsp->lf_flags != 0) {
		error = EINVAL;
		goto errout;
	}

	/*
	 * check key
	 */
	if (!LOCKFS_IS_ULOCK(ul_lockfsp))
		if (lockfsp->lf_key != ul_lockfsp->lf_key) {
			error = EINVAL;
			goto errout;
	}

	lockfsp->lf_key = ul_lockfsp->lf_key + 1;

errout:
	return (error);
}

/*
 * ufs_checkaccton
 *	check if accounting is turned on on this fs
 */

int
ufs_checkaccton(struct vnode *vp)
{
	if (acct_fs_in_use(vp))
		return (EDEADLK);
	return (0);
}

/*
 * ufs_checkswapon
 *	check if local swapping is to file on this fs
 */
int
ufs_checkswapon(struct vnode *vp)
{
	struct swapinfo	*sip;

	mutex_enter(&swapinfo_lock);
	for (sip = swapinfo; sip; sip = sip->si_next)
		if (sip->si_vp->v_vfsp == vp->v_vfsp) {
			mutex_exit(&swapinfo_lock);
			return (EDEADLK);
		}
	mutex_exit(&swapinfo_lock);
	return (0);
}

/*
 * ufs_freeze
 *	pend future accesses for current lock and desired lock
 */
void
ufs_freeze(struct ulockfs *ulp, struct lockfs *lockfsp)
{
	/*
	 * set to new lock type
	 */
	ulp->ul_lockfs.lf_lock = lockfsp->lf_lock;
	ulp->ul_lockfs.lf_key = lockfsp->lf_key;
	ulp->ul_lockfs.lf_comlen = lockfsp->lf_comlen;
	ulp->ul_lockfs.lf_comment = lockfsp->lf_comment;

	ulp->ul_fs_lock = (1 << ulp->ul_lockfs.lf_lock);
}

/*
 * All callers of ufs_quiesce() atomically increment ufs_quiesce_pend before
 * starting ufs_quiesce() protocol and decrement it only when a file system no
 * longer has to be in quiescent state. This allows ufs_pageio() to detect
 * that another thread wants to quiesce a file system. See more comments in
 * ufs_pageio().
 */
ulong_t ufs_quiesce_pend = 0;

/*
 * ufs_quiesce
 *	wait for outstanding accesses to finish
 */
int
ufs_quiesce(struct ulockfs *ulp)
{
	int error = 0;
	ulockfs_info_t *head;
	ulockfs_info_t *info;
	klwp_t *lwp = ttolwp(curthread);

	head = (ulockfs_info_t *)tsd_get(ufs_lockfs_key);
	SEARCH_ULOCKFSP(head, ulp, info);

	/*
	 * We have to keep /proc away from stopping us after we applied
	 * the softlock but before we got a chance to clear it again.
	 * prstop() may pagefault and become stuck on the softlock still
	 * pending.
	 */
	if (lwp != NULL)
		lwp->lwp_nostop++;

	/*
	 * Set a softlock to suspend future ufs_vnops so that
	 * this lockfs request will not be starved
	 */
	ULOCKFS_SET_SLOCK(ulp);
	ASSERT(ufs_quiesce_pend);

	/* check if there is any outstanding ufs vnodeops calls */
	while (ulp->ul_vnops_cnt || ulp->ul_falloc_cnt) {
		/*
		 * use timed version of cv_wait_sig() to make sure we don't
		 * miss a wake up call from ufs_pageio() when it doesn't use
		 * ul_lock.
		 *
		 * when a fallocate thread comes in, the only way it returns
		 * from this function is if there are no other vnode operations
		 * going on (remember fallocate threads are tracked using
		 * ul_falloc_cnt not ul_vnops_cnt), and another fallocate thread
		 * hasn't already grabbed the fs write lock.
		 */
		if (info && (info->flags & ULOCK_INFO_FALLOCATE)) {
			if (!ulp->ul_vnops_cnt && !ULOCKFS_IS_FWLOCK(ulp))
				goto out;
		}
		if (!cv_reltimedwait_sig(&ulp->ul_cv, &ulp->ul_lock, hz,
		    TR_CLOCK_TICK)) {
			error = EINTR;
			goto out;
		}
	}

out:
	/*
	 * unlock the soft lock
	 */
	ULOCKFS_CLR_SLOCK(ulp);

	if (lwp != NULL)
		lwp->lwp_nostop--;

	return (error);
}

/*
 * ufs_flush_inode
 */
int
ufs_flush_inode(struct inode *ip, void *arg)
{
	int	error;
	int	saverror	= 0;

	/*
	 * wrong file system; keep looking
	 */
	if (ip->i_ufsvfs != (struct ufsvfs *)arg)
		return (0);

	/*
	 * asynchronously push all the dirty pages
	 */
	if (((error = TRANS_SYNCIP(ip, B_ASYNC, 0, TOP_SYNCIP_FLUSHI)) != 0) &&
	    (error != EAGAIN))
		saverror = error;
	/*
	 * wait for io and discard all mappings
	 */
	if (error = TRANS_SYNCIP(ip, B_INVAL, 0, TOP_SYNCIP_FLUSHI))
		saverror = error;

	if (ITOV(ip)->v_type == VDIR) {
		dnlc_dir_purge(&ip->i_danchor);
	}

	return (saverror);
}

/*
 * ufs_flush
 *	Flush everything that is currently dirty; this includes invalidating
 *	any mappings.
 */
int
ufs_flush(struct vfs *vfsp)
{
	int		error;
	int		saverror = 0;
	struct ufsvfs	*ufsvfsp	= (struct ufsvfs *)vfsp->vfs_data;
	struct fs	*fs		= ufsvfsp->vfs_fs;
	int		tdontblock = 0;

	ASSERT(vfs_lock_held(vfsp));

	/*
	 * purge dnlc
	 */
	(void) dnlc_purge_vfsp(vfsp, 0);

	/*
	 * drain the delete and idle threads
	 */
	ufs_delete_drain(vfsp, 0, 0);
	ufs_idle_drain(vfsp);

	/*
	 * flush and invalidate quota records
	 */
	(void) qsync(ufsvfsp);

	/*
	 * flush w/invalidate the inodes for vfsp
	 */
	if (error = ufs_scan_inodes(0, ufs_flush_inode, ufsvfsp, ufsvfsp))
		saverror = error;

	/*
	 * synchronously flush superblock and summary info
	 */
	if (fs->fs_ronly == 0 && fs->fs_fmod) {
		fs->fs_fmod = 0;
		TRANS_SBUPDATE(ufsvfsp, vfsp, TOP_SBUPDATE_FLUSH);
	}
	/*
	 * flush w/invalidate block device pages and buf cache
	 */
	if ((error = VOP_PUTPAGE(common_specvp(ufsvfsp->vfs_devvp),
	    (offset_t)0, 0, B_INVAL, CRED(), NULL)) > 0)
		saverror = error;

	(void) bflush((dev_t)vfsp->vfs_dev);
	(void) bfinval((dev_t)vfsp->vfs_dev, 0);

	/*
	 * drain the delete and idle threads again
	 */
	ufs_delete_drain(vfsp, 0, 0);
	ufs_idle_drain(vfsp);

	/*
	 * play with the clean flag
	 */
	if (saverror == 0)
		ufs_checkclean(vfsp);

	/*
	 * Flush any outstanding transactions and roll the log
	 * only if we are supposed to do, i.e. LDL_NOROLL not set.
	 * We can not simply check for fs_ronly here since fsck also may
	 * use this code to roll the log on a read-only filesystem, e.g.
	 * root during early stages of boot, if other then a sanity check is
	 * done, it will clear LDL_NOROLL before.
	 * In addition we assert that the deltamap does not contain any deltas
	 * in case LDL_NOROLL is set since this is not supposed to happen.
	 */
	if (TRANS_ISTRANS(ufsvfsp)) {
		ml_unit_t	*ul	= ufsvfsp->vfs_log;
		mt_map_t	*mtm	= ul->un_deltamap;

		if (ul->un_flags & LDL_NOROLL) {
			ASSERT(mtm->mtm_nme == 0);
		} else {
			/*
			 * Do not set T_DONTBLOCK if there is a
			 * transaction opened by caller.
			 */
			if (curthread->t_flag & T_DONTBLOCK)
				tdontblock = 1;
			else
				curthread->t_flag |= T_DONTBLOCK;

			TRANS_BEGIN_SYNC(ufsvfsp, TOP_COMMIT_FLUSH,
			    TOP_COMMIT_SIZE, error);

			if (!error) {
				TRANS_END_SYNC(ufsvfsp, saverror,
				    TOP_COMMIT_FLUSH, TOP_COMMIT_SIZE);
			}

			if (tdontblock == 0)
				curthread->t_flag &= ~T_DONTBLOCK;

			logmap_roll_dev(ufsvfsp->vfs_log);
		}
	}

	return (saverror);
}

/*
 * ufs_thaw_wlock
 *	special processing when thawing down to wlock
 */
static int
ufs_thaw_wlock(struct inode *ip, void *arg)
{
	/*
	 * wrong file system; keep looking
	 */
	if (ip->i_ufsvfs != (struct ufsvfs *)arg)
		return (0);

	/*
	 * iupdat refuses to clear flags if the fs is read only.  The fs
	 * may become read/write during the lock and we wouldn't want
	 * these inodes being written to disk.  So clear the flags.
	 */
	rw_enter(&ip->i_contents, RW_WRITER);
	ip->i_flag &= ~(IMOD|IMODACC|IACC|IUPD|ICHG|IATTCHG);
	rw_exit(&ip->i_contents);

	/*
	 * pages are mlocked -- fail wlock
	 */
	if (ITOV(ip)->v_type != VCHR && vn_has_cached_data(ITOV(ip)))
		return (EBUSY);

	return (0);
}

/*
 * ufs_thaw_hlock
 *	special processing when thawing down to hlock or elock
 */
static int
ufs_thaw_hlock(struct inode *ip, void *arg)
{
	struct vnode	*vp	= ITOV(ip);

	/*
	 * wrong file system; keep looking
	 */
	if (ip->i_ufsvfs != (struct ufsvfs *)arg)
		return (0);

	/*
	 * blow away all pages - even if they are mlocked
	 */
	do {
		(void) TRANS_SYNCIP(ip, B_INVAL | B_FORCE, 0, TOP_SYNCIP_HLOCK);
	} while ((vp->v_type != VCHR) && vn_has_cached_data(vp));
	rw_enter(&ip->i_contents, RW_WRITER);
	ip->i_flag &= ~(IMOD|IMODACC|IACC|IUPD|ICHG|IATTCHG);
	rw_exit(&ip->i_contents);

	return (0);
}

/*
 * ufs_thaw
 *	thaw file system lock down to current value
 */
int
ufs_thaw(struct vfs *vfsp, struct ufsvfs *ufsvfsp, struct ulockfs *ulp)
{
	int		error	= 0;
	int		noidel	= (int)(ulp->ul_flag & ULOCKFS_NOIDEL);

	/*
	 * if wlock or hlock or elock
	 */
	if (ULOCKFS_IS_WLOCK(ulp) || ULOCKFS_IS_HLOCK(ulp) ||
	    ULOCKFS_IS_ELOCK(ulp)) {

		/*
		 * don't keep access times
		 * don't free deleted files
		 * if superblock writes are allowed, limit them to me for now
		 */
		ulp->ul_flag |= (ULOCKFS_NOIACC|ULOCKFS_NOIDEL);
		if (ulp->ul_sbowner != (kthread_id_t)-1)
			ulp->ul_sbowner = curthread;

		/*
		 * wait for writes for deleted files and superblock updates
		 */
		(void) ufs_flush(vfsp);

		/*
		 * now make sure the quota file is up-to-date
		 *	expensive; but effective
		 */
		error = ufs_flush(vfsp);
		/*
		 * no one can write the superblock
		 */
		ulp->ul_sbowner = (kthread_id_t)-1;

		/*
		 * special processing for wlock/hlock/elock
		 */
		if (ULOCKFS_IS_WLOCK(ulp)) {
			if (error)
				goto errout;
			error = bfinval(ufsvfsp->vfs_dev, 0);
			if (error)
				goto errout;
			error = ufs_scan_inodes(0, ufs_thaw_wlock,
			    (void *)ufsvfsp, ufsvfsp);
			if (error)
				goto errout;
		}
		if (ULOCKFS_IS_HLOCK(ulp) || ULOCKFS_IS_ELOCK(ulp)) {
			error = 0;
			(void) ufs_scan_inodes(0, ufs_thaw_hlock,
			    (void *)ufsvfsp, ufsvfsp);
			(void) bfinval(ufsvfsp->vfs_dev, 1);
		}
	} else {

		/*
		 * okay to keep access times
		 * okay to free deleted files
		 * okay to write the superblock
		 */
		ulp->ul_flag &= ~(ULOCKFS_NOIACC|ULOCKFS_NOIDEL);
		ulp->ul_sbowner = NULL;

		/*
		 * flush in case deleted files are in memory
		 */
		if (noidel) {
			if (error = ufs_flush(vfsp))
				goto errout;
		}
	}

errout:
	cv_broadcast(&ulp->ul_cv);
	return (error);
}

/*
 * ufs_reconcile_fs
 *	reconcile incore superblock with ondisk superblock
 */
int
ufs_reconcile_fs(struct vfs *vfsp, struct ufsvfs *ufsvfsp, int errlck)
{
	struct fs	*mfs; 	/* in-memory superblock */
	struct fs	*dfs;	/* on-disk   superblock */
	struct buf	*bp;	/* on-disk   superblock buf */
	int		 needs_unlock;
	char		 finished_fsclean;

	mfs = ufsvfsp->vfs_fs;

	/*
	 * get the on-disk copy of the superblock
	 */
	bp = UFS_BREAD(ufsvfsp, vfsp->vfs_dev, SBLOCK, SBSIZE);
	bp->b_flags |= (B_STALE|B_AGE);
	if (bp->b_flags & B_ERROR) {
		brelse(bp);
		return (EIO);
	}
	dfs = bp->b_un.b_fs;

	/* error locks may only unlock after the fs has been made consistent */
	if (errlck == UN_ERRLCK) {
		if (dfs->fs_clean == FSFIX) {	/* being repaired */
			brelse(bp);
			return (EAGAIN);
		}
		/* repair not yet started? */
		finished_fsclean = TRANS_ISTRANS(ufsvfsp)? FSLOG: FSCLEAN;
		if (dfs->fs_clean != finished_fsclean) {
			brelse(bp);
			return (EBUSY);
		}
	}

	/*
	 * if superblock has changed too much, abort
	 */
	if ((mfs->fs_sblkno		!= dfs->fs_sblkno) ||
	    (mfs->fs_cblkno		!= dfs->fs_cblkno) ||
	    (mfs->fs_iblkno		!= dfs->fs_iblkno) ||
	    (mfs->fs_dblkno		!= dfs->fs_dblkno) ||
	    (mfs->fs_cgoffset		!= dfs->fs_cgoffset) ||
	    (mfs->fs_cgmask		!= dfs->fs_cgmask) ||
	    (mfs->fs_bsize		!= dfs->fs_bsize) ||
	    (mfs->fs_fsize		!= dfs->fs_fsize) ||
	    (mfs->fs_frag		!= dfs->fs_frag) ||
	    (mfs->fs_bmask		!= dfs->fs_bmask) ||
	    (mfs->fs_fmask		!= dfs->fs_fmask) ||
	    (mfs->fs_bshift		!= dfs->fs_bshift) ||
	    (mfs->fs_fshift		!= dfs->fs_fshift) ||
	    (mfs->fs_fragshift		!= dfs->fs_fragshift) ||
	    (mfs->fs_fsbtodb		!= dfs->fs_fsbtodb) ||
	    (mfs->fs_sbsize		!= dfs->fs_sbsize) ||
	    (mfs->fs_nindir		!= dfs->fs_nindir) ||
	    (mfs->fs_nspf		!= dfs->fs_nspf) ||
	    (mfs->fs_trackskew		!= dfs->fs_trackskew) ||
	    (mfs->fs_cgsize		!= dfs->fs_cgsize) ||
	    (mfs->fs_ntrak		!= dfs->fs_ntrak) ||
	    (mfs->fs_nsect		!= dfs->fs_nsect) ||
	    (mfs->fs_spc		!= dfs->fs_spc) ||
	    (mfs->fs_cpg		!= dfs->fs_cpg) ||
	    (mfs->fs_ipg		!= dfs->fs_ipg) ||
	    (mfs->fs_fpg		!= dfs->fs_fpg) ||
	    (mfs->fs_postblformat	!= dfs->fs_postblformat) ||
	    (mfs->fs_magic		!= dfs->fs_magic)) {
		brelse(bp);
		return (EACCES);
	}
	if (dfs->fs_clean == FSBAD || FSOKAY != dfs->fs_state + dfs->fs_time)
		if (mfs->fs_clean == FSLOG) {
			brelse(bp);
			return (EACCES);
		}

	/*
	 * get new summary info
	 */
	if (ufs_getsummaryinfo(vfsp->vfs_dev, ufsvfsp, dfs)) {
		brelse(bp);
		return (EIO);
	}

	/*
	 * release old summary info and update in-memory superblock
	 */
	kmem_free(mfs->fs_u.fs_csp, mfs->fs_cssize);
	mfs->fs_u.fs_csp = dfs->fs_u.fs_csp;	/* Only entry 0 used */

	/*
	 * update fields allowed to change
	 */
	mfs->fs_size		= dfs->fs_size;
	mfs->fs_dsize		= dfs->fs_dsize;
	mfs->fs_ncg		= dfs->fs_ncg;
	mfs->fs_minfree		= dfs->fs_minfree;
	mfs->fs_rotdelay	= dfs->fs_rotdelay;
	mfs->fs_rps		= dfs->fs_rps;
	mfs->fs_maxcontig	= dfs->fs_maxcontig;
	mfs->fs_maxbpg		= dfs->fs_maxbpg;
	mfs->fs_csmask		= dfs->fs_csmask;
	mfs->fs_csshift		= dfs->fs_csshift;
	mfs->fs_optim		= dfs->fs_optim;
	mfs->fs_csaddr		= dfs->fs_csaddr;
	mfs->fs_cssize		= dfs->fs_cssize;
	mfs->fs_ncyl		= dfs->fs_ncyl;
	mfs->fs_cstotal		= dfs->fs_cstotal;
	mfs->fs_reclaim		= dfs->fs_reclaim;

	if (mfs->fs_reclaim & (FS_RECLAIM|FS_RECLAIMING)) {
		mfs->fs_reclaim &= ~FS_RECLAIM;
		mfs->fs_reclaim |=  FS_RECLAIMING;
		ufs_thread_start(&ufsvfsp->vfs_reclaim,
		    ufs_thread_reclaim, vfsp);
	}

	/* XXX What to do about sparecon? */

	/* XXX need to copy volume label */

	/*
	 * ondisk clean flag overrides inmemory clean flag iff == FSBAD
	 * or if error-locked and ondisk is now clean
	 */
	needs_unlock = !MUTEX_HELD(&ufsvfsp->vfs_lock);
	if (needs_unlock)
		mutex_enter(&ufsvfsp->vfs_lock);

	if (errlck == UN_ERRLCK) {
		if (finished_fsclean == dfs->fs_clean)
			mfs->fs_clean = finished_fsclean;
		else
			mfs->fs_clean = FSBAD;
		mfs->fs_state = FSOKAY - dfs->fs_time;
	}

	if (FSOKAY != dfs->fs_state + dfs->fs_time ||
	    (dfs->fs_clean == FSBAD))
		mfs->fs_clean = FSBAD;

	if (needs_unlock)
		mutex_exit(&ufsvfsp->vfs_lock);

	brelse(bp);

	return (0);
}

/*
 * ufs_reconcile_inode
 *	reconcile ondisk inode with incore inode
 */
static int
ufs_reconcile_inode(struct inode *ip, void *arg)
{
	int		i;
	int		ndaddr;
	int		niaddr;
	struct dinode	*dp;		/* ondisk inode */
	struct buf	*bp	= NULL;
	uid_t		d_uid;
	gid_t		d_gid;
	int		error = 0;
	struct fs	*fs;

	/*
	 * not an inode we care about
	 */
	if (ip->i_ufsvfs != (struct ufsvfs *)arg)
		return (0);

	fs = ip->i_fs;

	/*
	 * Inode reconciliation fails: we made the filesystem quiescent
	 * and we did a ufs_flush() before calling ufs_reconcile_inode()
	 * and thus the inode should not have been changed inbetween.
	 * Any discrepancies indicate a logic error and a pretty
	 * significant run-state inconsistency we should complain about.
	 */
	if (ip->i_flag & (IMOD|IMODACC|IACC|IUPD|ICHG|IATTCHG)) {
		cmn_err(CE_WARN, "%s: Inode reconciliation failed for"
		    "inode %llu", fs->fs_fsmnt, (u_longlong_t)ip->i_number);
		return (EINVAL);
	}

	/*
	 * get the dinode
	 */
	bp = UFS_BREAD(ip->i_ufsvfs,
	    ip->i_dev, (daddr_t)fsbtodb(fs, itod(fs, ip->i_number)),
	    (int)fs->fs_bsize);
	if (bp->b_flags & B_ERROR) {
		brelse(bp);
		return (EIO);
	}
	dp  = bp->b_un.b_dino;
	dp += itoo(fs, ip->i_number);

	/*
	 * handle Sun's implementation of EFT
	 */
	d_uid = (dp->di_suid == UID_LONG) ? dp->di_uid : (uid_t)dp->di_suid;
	d_gid = (dp->di_sgid == GID_LONG) ? dp->di_gid : (uid_t)dp->di_sgid;

	rw_enter(&ip->i_contents, RW_WRITER);

	/*
	 * some fields are not allowed to change
	 */
	if ((ip->i_mode  != dp->di_mode) ||
	    (ip->i_gen   != dp->di_gen) ||
	    (ip->i_uid   != d_uid) ||
	    (ip->i_gid   != d_gid)) {
		error = EACCES;
		goto out;
	}

	/*
	 * and some are allowed to change
	 */
	ip->i_size		= dp->di_size;
	ip->i_ic.ic_flags	= dp->di_ic.ic_flags;
	ip->i_blocks		= dp->di_blocks;
	ip->i_nlink		= dp->di_nlink;
	if (ip->i_flag & IFASTSYMLNK) {
		ndaddr = 1;
		niaddr = 0;
	} else {
		ndaddr = NDADDR;
		niaddr = NIADDR;
	}
	for (i = 0; i < ndaddr; ++i)
		ip->i_db[i] = dp->di_db[i];
	for (i = 0; i < niaddr; ++i)
		ip->i_ib[i] = dp->di_ib[i];

out:
	rw_exit(&ip->i_contents);
	brelse(bp);
	return (error);
}

/*
 * ufs_reconcile
 *	reconcile ondisk superblock/inodes with any incore
 */
static int
ufs_reconcile(struct vfs *vfsp, struct ufsvfs *ufsvfsp, int errlck)
{
	int	error = 0;

	/*
	 * get rid of as much inmemory data as possible
	 */
	(void) ufs_flush(vfsp);

	/*
	 * reconcile the superblock and inodes
	 */
	if (error = ufs_reconcile_fs(vfsp, ufsvfsp, errlck))
		return (error);
	if (error = ufs_scan_inodes(0, ufs_reconcile_inode, ufsvfsp, ufsvfsp))
		return (error);
	/*
	 * allocation blocks may be incorrect; get rid of them
	 */
	(void) ufs_flush(vfsp);

	return (error);
}

/*
 * File system locking
 */
int
ufs_fiolfs(struct vnode *vp, struct lockfs *lockfsp, int from_log)
{
	return (ufs__fiolfs(vp, lockfsp, /* from_user */ 1, from_log));
}

/* kernel-internal interface, also used by fix-on-panic */
int
ufs__fiolfs(
	struct vnode *vp,
	struct lockfs *lockfsp,
	int from_user,
	int from_log)
{
	struct ulockfs	*ulp;
	struct lockfs	lfs;
	int		error;
	struct vfs	*vfsp;
	struct ufsvfs	*ufsvfsp;
	int		 errlck		= NO_ERRLCK;
	int		 poll_events	= POLLPRI;
	extern struct pollhead ufs_pollhd;
	ulockfs_info_t *head;
	ulockfs_info_t *info;
	int signal = 0;

	/* check valid lock type */
	if (!lockfsp || lockfsp->lf_lock > LOCKFS_MAXLOCK)
		return (EINVAL);

	if (!vp || !vp->v_vfsp || !vp->v_vfsp->vfs_data)
		return (EIO);

	vfsp = vp->v_vfsp;

	if (vfsp->vfs_flag & VFS_UNMOUNTED) /* has been unmounted */
		return (EIO);

	/* take the lock and check again */
	vfs_lock_wait(vfsp);
	if (vfsp->vfs_flag & VFS_UNMOUNTED) {
		vfs_unlock(vfsp);
		return (EIO);
	}

	/*
	 * Can't wlock or ro/elock fs with accounting or local swap file
	 * We need to check for this before we grab the ul_lock to avoid
	 * deadlocks with the accounting framework.
	 */
	if ((LOCKFS_IS_WLOCK(lockfsp) || LOCKFS_IS_ELOCK(lockfsp) ||
	    LOCKFS_IS_ROELOCK(lockfsp)) && !from_log) {
		if (ufs_checkaccton(vp) || ufs_checkswapon(vp)) {
			vfs_unlock(vfsp);
			return (EDEADLK);
		}
	}

	ufsvfsp = (struct ufsvfs *)vfsp->vfs_data;
	ulp = &ufsvfsp->vfs_ulockfs;
	head = (ulockfs_info_t *)tsd_get(ufs_lockfs_key);
	SEARCH_ULOCKFSP(head, ulp, info);

	/*
	 * Suspend both the reclaim thread and the delete thread.
	 * This must be done outside the lockfs locking protocol.
	 */
	ufs_thread_suspend(&ufsvfsp->vfs_reclaim);
	ufs_thread_suspend(&ufsvfsp->vfs_delete);

	mutex_enter(&ulp->ul_lock);
	atomic_inc_ulong(&ufs_quiesce_pend);

	/*
	 * Quit if there is another lockfs request in progress
	 * that is waiting for existing ufs_vnops to complete.
	 */
	if (ULOCKFS_IS_BUSY(ulp)) {
		error = EBUSY;
		goto errexit;
	}

	/* cannot ulocked or downgrade a hard-lock */
	if (ULOCKFS_IS_HLOCK(ulp)) {
		error = EIO;
		goto errexit;
	}

	/* an error lock may be unlocked or relocked, only */
	if (ULOCKFS_IS_ELOCK(ulp)) {
		if (!LOCKFS_IS_ULOCK(lockfsp) && !LOCKFS_IS_ELOCK(lockfsp)) {
			error = EBUSY;
			goto errexit;
		}
	}

	/*
	 * a read-only error lock may only be upgraded to an
	 * error lock or hard lock
	 */
	if (ULOCKFS_IS_ROELOCK(ulp)) {
		if (!LOCKFS_IS_HLOCK(lockfsp) && !LOCKFS_IS_ELOCK(lockfsp)) {
			error = EBUSY;
			goto errexit;
		}
	}

	/*
	 * until read-only error locks are fully implemented
	 * just return EINVAL
	 */
	if (LOCKFS_IS_ROELOCK(lockfsp)) {
		error = EINVAL;
		goto errexit;
	}

	/*
	 * an error lock may only be applied if the file system is
	 * unlocked or already error locked.
	 * (this is to prevent the case where a fs gets changed out from
	 * underneath a fs that is locked for backup,
	 * that is, name/delete/write-locked.)
	 */
	if ((!ULOCKFS_IS_ULOCK(ulp) && !ULOCKFS_IS_ELOCK(ulp) &&
	    !ULOCKFS_IS_ROELOCK(ulp)) &&
	    (LOCKFS_IS_ELOCK(lockfsp) || LOCKFS_IS_ROELOCK(lockfsp))) {
		error = EBUSY;
		goto errexit;
	}

	/* get and validate the input lockfs request */
	if (error = ufs_getlfd(lockfsp, &ulp->ul_lockfs))
		goto errexit;

	/*
	 * save current ulockfs struct
	 */
	bcopy(&ulp->ul_lockfs, &lfs, sizeof (struct lockfs));

	/*
	 * Freeze the file system (pend future accesses)
	 */
	ufs_freeze(ulp, lockfsp);

	/*
	 * Set locking in progress because ufs_quiesce may free the
	 * ul_lock mutex.
	 */
	ULOCKFS_SET_BUSY(ulp);
	/* update the ioctl copy */
	LOCKFS_SET_BUSY(&ulp->ul_lockfs);

	/*
	 * We  need to unset FWLOCK status before we call ufs_quiesce
	 * so that the thread doesnt get suspended. We do this only if
	 * this (fallocate) thread requested an unlock operation.
	 */
	if (info && (info->flags & ULOCK_INFO_FALLOCATE)) {
		if (!ULOCKFS_IS_WLOCK(ulp))
			ULOCKFS_CLR_FWLOCK(ulp);
	}

	/*
	 * Quiesce (wait for outstanding accesses to finish)
	 */
	if (error = ufs_quiesce(ulp)) {
		/*
		 * Interrupted due to signal. There could still be
		 * pending vnops.
		 */
		signal = 1;

		/*
		 * We do broadcast because lock-status
		 * could be reverted to old status.
		 */
		cv_broadcast(&ulp->ul_cv);
		goto errout;
	}

	/*
	 * If the fallocate thread requested a write fs lock operation
	 * then we set fwlock status in the ulp.
	 */
	if (info && (info->flags & ULOCK_INFO_FALLOCATE)) {
		if (ULOCKFS_IS_WLOCK(ulp))
			ULOCKFS_SET_FWLOCK(ulp);
	}

	/*
	 * save error lock status to pass down to reconcilation
	 * routines and for later cleanup
	 */
	if (LOCKFS_IS_ELOCK(&lfs) && ULOCKFS_IS_ULOCK(ulp))
		errlck = UN_ERRLCK;

	if (ULOCKFS_IS_ELOCK(ulp) || ULOCKFS_IS_ROELOCK(ulp)) {
		int needs_unlock;
		int needs_sbwrite;

		poll_events |= POLLERR;
		errlck = LOCKFS_IS_ELOCK(&lfs) || LOCKFS_IS_ROELOCK(&lfs) ?
		    RE_ERRLCK : SET_ERRLCK;

		needs_unlock = !MUTEX_HELD(&ufsvfsp->vfs_lock);
		if (needs_unlock)
			mutex_enter(&ufsvfsp->vfs_lock);

		/* disable delayed i/o */
		needs_sbwrite = 0;

		if (errlck == SET_ERRLCK) {
			ufsvfsp->vfs_fs->fs_clean = FSBAD;
			needs_sbwrite = 1;
		}

		needs_sbwrite |= ufsvfsp->vfs_dio;
		ufsvfsp->vfs_dio = 0;

		if (needs_unlock)
			mutex_exit(&ufsvfsp->vfs_lock);

		if (needs_sbwrite) {
			ulp->ul_sbowner = curthread;
			TRANS_SBWRITE(ufsvfsp, TOP_SBWRITE_STABLE);

			if (needs_unlock)
				mutex_enter(&ufsvfsp->vfs_lock);

			ufsvfsp->vfs_fs->fs_fmod = 0;

			if (needs_unlock)
				mutex_exit(&ufsvfsp->vfs_lock);
		}
	}

	/*
	 * reconcile superblock and inodes if was wlocked
	 */
	if (LOCKFS_IS_WLOCK(&lfs) || LOCKFS_IS_ELOCK(&lfs)) {
		if (error = ufs_reconcile(vfsp, ufsvfsp, errlck))
			goto errout;
		/*
		 * in case the fs grew; reset the metadata map for logging tests
		 */
		TRANS_MATA_UMOUNT(ufsvfsp);
		TRANS_MATA_MOUNT(ufsvfsp);
		TRANS_MATA_SI(ufsvfsp, ufsvfsp->vfs_fs);
	}

	/*
	 * At least everything *currently* dirty goes out.
	 */

	if ((error = ufs_flush(vfsp)) != 0 && !ULOCKFS_IS_HLOCK(ulp) &&
	    !ULOCKFS_IS_ELOCK(ulp))
		goto errout;

	/*
	 * thaw file system and wakeup pended processes
	 */
	if (error = ufs_thaw(vfsp, ufsvfsp, ulp))
		if (!ULOCKFS_IS_HLOCK(ulp) && !ULOCKFS_IS_ELOCK(ulp))
			goto errout;

	/*
	 * reset modified flag if not already write locked
	 */
	if (!LOCKFS_IS_WLOCK(&lfs))
		ULOCKFS_CLR_MOD(ulp);

	/*
	 * idle the lock struct
	 */
	ULOCKFS_CLR_BUSY(ulp);
	/* update the ioctl copy */
	LOCKFS_CLR_BUSY(&ulp->ul_lockfs);

	/*
	 * free current comment
	 */
	if (lfs.lf_comment && lfs.lf_comlen != 0) {
		kmem_free(lfs.lf_comment, lfs.lf_comlen);
		lfs.lf_comment = NULL;
		lfs.lf_comlen = 0;
	}

	/* do error lock cleanup */
	if (errlck == UN_ERRLCK)
		ufsfx_unlockfs(ufsvfsp);

	else if (errlck == RE_ERRLCK)
		ufsfx_lockfs(ufsvfsp);

	/* don't allow error lock from user to invoke panic */
	else if (from_user && errlck == SET_ERRLCK &&
	    !(ufsvfsp->vfs_fsfx.fx_flags & (UFSMNT_ONERROR_PANIC >> 4)))
		(void) ufs_fault(ufsvfsp->vfs_root,
		    ulp->ul_lockfs.lf_comment && ulp->ul_lockfs.lf_comlen > 0 ?
		    ulp->ul_lockfs.lf_comment: "user-applied error lock");

	atomic_dec_ulong(&ufs_quiesce_pend);
	mutex_exit(&ulp->ul_lock);
	vfs_unlock(vfsp);

	if (ULOCKFS_IS_HLOCK(&ufsvfsp->vfs_ulockfs))
		poll_events |= POLLERR;

	pollwakeup(&ufs_pollhd, poll_events);

	/*
	 * Allow both the delete thread and the reclaim thread to
	 * continue.
	 */
	ufs_thread_continue(&ufsvfsp->vfs_delete);
	ufs_thread_continue(&ufsvfsp->vfs_reclaim);

	return (0);

errout:
	/*
	 * Lock failed. Reset the old lock in ufsvfs if not hard locked.
	 */
	if (!LOCKFS_IS_HLOCK(&ulp->ul_lockfs)) {
		bcopy(&lfs, &ulp->ul_lockfs, sizeof (struct lockfs));
		ulp->ul_fs_lock = (1 << lfs.lf_lock);
	}

	/*
	 * Don't call ufs_thaw() when there's a signal during
	 * ufs quiesce operation as it can lead to deadlock
	 * with getpage.
	 */
	if (signal == 0)
		(void) ufs_thaw(vfsp, ufsvfsp, ulp);

	ULOCKFS_CLR_BUSY(ulp);
	LOCKFS_CLR_BUSY(&ulp->ul_lockfs);

errexit:
	atomic_dec_ulong(&ufs_quiesce_pend);
	mutex_exit(&ulp->ul_lock);
	vfs_unlock(vfsp);

	/*
	 * Allow both the delete thread and the reclaim thread to
	 * continue.
	 */
	ufs_thread_continue(&ufsvfsp->vfs_delete);
	ufs_thread_continue(&ufsvfsp->vfs_reclaim);

	return (error);
}

/*
 * fiolfss
 * 	return the current file system locking state info
 */
int
ufs_fiolfss(struct vnode *vp, struct lockfs *lockfsp)
{
	struct ulockfs	*ulp;

	if (!vp || !vp->v_vfsp || !VTOI(vp))
		return (EINVAL);

	/* file system has been forcibly unmounted */
	if (VTOI(vp)->i_ufsvfs == NULL)
		return (EIO);

	ulp = VTOUL(vp);

	if (ULOCKFS_IS_HLOCK(ulp)) {
		*lockfsp = ulp->ul_lockfs;	/* structure assignment */
		return (0);
	}

	mutex_enter(&ulp->ul_lock);

	*lockfsp = ulp->ul_lockfs;	/* structure assignment */

	if (ULOCKFS_IS_MOD(ulp))
		lockfsp->lf_flags |= LOCKFS_MOD;

	mutex_exit(&ulp->ul_lock);

	return (0);
}

/*
 * ufs_check_lockfs
 *	check whether a ufs_vnops conflicts with the file system lock
 */
int
ufs_check_lockfs(struct ufsvfs *ufsvfsp, struct ulockfs *ulp, ulong_t mask)
{
	k_sigset_t	smask;
	int		sig, slock;

	ASSERT(MUTEX_HELD(&ulp->ul_lock));

	while (ulp->ul_fs_lock & mask) {
		slock = (int)ULOCKFS_IS_SLOCK(ulp);
		if ((curthread->t_flag & T_DONTPEND) && !slock) {
			curthread->t_flag |= T_WOULDBLOCK;
			return (EAGAIN);
		}
		curthread->t_flag &= ~T_WOULDBLOCK;

		/*
		 * In the case of an onerr umount of the fs, threads could
		 * have blocked before coming into ufs_check_lockfs and
		 * need to check for the special case of ELOCK and
		 * vfs_dontblock being set which would indicate that the fs
		 * is on its way out and will not return therefore making
		 * EIO the appropriate response.
		 */
		if (ULOCKFS_IS_HLOCK(ulp) ||
		    (ULOCKFS_IS_ELOCK(ulp) && ufsvfsp->vfs_dontblock))
			return (EIO);

		/*
		 * wait for lock status to change
		 */
		if (slock || ufsvfsp->vfs_nointr) {
			cv_wait(&ulp->ul_cv, &ulp->ul_lock);
		} else {
			sigintr(&smask, 1);
			sig = cv_wait_sig(&ulp->ul_cv, &ulp->ul_lock);
			sigunintr(&smask);
			if ((!sig && (ulp->ul_fs_lock & mask)) ||
			    ufsvfsp->vfs_dontblock)
				return (EINTR);
		}
	}

	if (mask & ULOCKFS_FWLOCK) {
		atomic_inc_ulong(&ulp->ul_falloc_cnt);
		ULOCKFS_SET_FALLOC(ulp);
	} else {
		atomic_inc_ulong(&ulp->ul_vnops_cnt);
	}

	return (0);
}

/*
 * Check whether we came across the handcrafted lockfs protocol path. We can't
 * simply check for T_DONTBLOCK here as one would assume since this can also
 * falsely catch recursive VOP's going to a different filesystem, instead we
 * check if we already hold the ulockfs->ul_lock mutex.
 */
static int
ufs_lockfs_is_under_rawlockfs(struct ulockfs *ulp)
{
	return ((mutex_owner(&ulp->ul_lock) != curthread) ? 0 : 1);
}

/*
 * ufs_lockfs_begin - start the lockfs locking protocol
 */
int
ufs_lockfs_begin(struct ufsvfs *ufsvfsp, struct ulockfs **ulpp, ulong_t mask)
{
	int 		error;
	int		rec_vop;
	ushort_t	op_cnt_incremented = 0;
	ulong_t		*ctr;
	struct ulockfs *ulp;
	ulockfs_info_t	*ulockfs_info;
	ulockfs_info_t	*ulockfs_info_free;
	ulockfs_info_t	*ulockfs_info_temp;

	/*
	 * file system has been forcibly unmounted
	 */
	if (ufsvfsp == NULL)
		return (EIO);

	*ulpp = ulp = &ufsvfsp->vfs_ulockfs;

	/*
	 * Do lockfs protocol
	 */
	ulockfs_info = (ulockfs_info_t *)tsd_get(ufs_lockfs_key);
	IS_REC_VOP(rec_vop, ulockfs_info, ulp, ulockfs_info_free);

	/*
	 * Detect recursive VOP call or handcrafted internal lockfs protocol
	 * path and bail out in that case.
	 */
	if (rec_vop || ufs_lockfs_is_under_rawlockfs(ulp)) {
		*ulpp = NULL;
		return (0);
	} else {
		if (ulockfs_info_free == NULL) {
			if ((ulockfs_info_temp = (ulockfs_info_t *)
			    kmem_zalloc(sizeof (ulockfs_info_t),
			    KM_NOSLEEP)) == NULL) {
				*ulpp = NULL;
				return (ENOMEM);
			}
		}
	}

	/*
	 * First time VOP call
	 *
	 * Increment the ctr irrespective of the lockfs state. If the lockfs
	 * state is not ULOCKFS_ULOCK, we can decrement it later. However,
	 * before incrementing we need to check if there is a pending quiesce
	 * request because if we have a continuous stream of ufs_lockfs_begin
	 * requests pounding on a few cpu's then the ufs_quiesce thread might
	 * never see the value of zero for ctr - a livelock kind of scenario.
	 */
	ctr = (mask & ULOCKFS_FWLOCK) ?
	    &ulp->ul_falloc_cnt : &ulp->ul_vnops_cnt;
	if (!ULOCKFS_IS_SLOCK(ulp)) {
		atomic_inc_ulong(ctr);
		op_cnt_incremented++;
	}

	/*
	 * If the lockfs state (indicated by ul_fs_lock) is not just
	 * ULOCKFS_ULOCK, then we will be routed through ufs_check_lockfs
	 * where there is a check with an appropriate mask to selectively allow
	 * operations permitted for that kind of lockfs state.
	 *
	 * Even these selective operations should not be allowed to go through
	 * if a lockfs request is in progress because that could result in inode
	 * modifications during a quiesce and could hence result in inode
	 * reconciliation failures. ULOCKFS_SLOCK alone would not be sufficient,
	 * so make use of ufs_quiesce_pend to disallow vnode operations when a
	 * quiesce is in progress.
	 */
	if (!ULOCKFS_IS_JUSTULOCK(ulp) || ufs_quiesce_pend) {
		if (op_cnt_incremented)
			if (!atomic_dec_ulong_nv(ctr))
				cv_broadcast(&ulp->ul_cv);
		mutex_enter(&ulp->ul_lock);
		error = ufs_check_lockfs(ufsvfsp, ulp, mask);
		mutex_exit(&ulp->ul_lock);
		if (error) {
			if (ulockfs_info_free == NULL)
				kmem_free(ulockfs_info_temp,
				    sizeof (ulockfs_info_t));
			return (error);
		}
	} else {
		/*
		 * This is the common case of file system in a unlocked state.
		 *
		 * If a file system is unlocked, we would expect the ctr to have
		 * been incremented by now. But this will not be true when a
		 * quiesce is winding up - SLOCK was set when we checked before
		 * incrementing the ctr, but by the time we checked for
		 * ULOCKFS_IS_JUSTULOCK, the quiesce thread was gone. It is okay
		 * to take ul_lock and go through the slow path in this uncommon
		 * case.
		 */
		if (op_cnt_incremented == 0) {
			mutex_enter(&ulp->ul_lock);
			error = ufs_check_lockfs(ufsvfsp, ulp, mask);
			if (error) {
				mutex_exit(&ulp->ul_lock);
				if (ulockfs_info_free == NULL)
					kmem_free(ulockfs_info_temp,
					    sizeof (ulockfs_info_t));
				return (error);
			}
			if (mask & ULOCKFS_FWLOCK)
				ULOCKFS_SET_FALLOC(ulp);
			mutex_exit(&ulp->ul_lock);
		} else if (mask & ULOCKFS_FWLOCK) {
			mutex_enter(&ulp->ul_lock);
			ULOCKFS_SET_FALLOC(ulp);
			mutex_exit(&ulp->ul_lock);
		}
	}

	if (ulockfs_info_free != NULL) {
		ulockfs_info_free->ulp = ulp;
		if (mask & ULOCKFS_FWLOCK)
			ulockfs_info_free->flags |= ULOCK_INFO_FALLOCATE;
	} else {
		ulockfs_info_temp->ulp = ulp;
		ulockfs_info_temp->next = ulockfs_info;
		if (mask & ULOCKFS_FWLOCK)
			ulockfs_info_temp->flags |= ULOCK_INFO_FALLOCATE;
		ASSERT(ufs_lockfs_key != 0);
		(void) tsd_set(ufs_lockfs_key, (void *)ulockfs_info_temp);
	}

	curthread->t_flag |= T_DONTBLOCK;
	return (0);
}

/*
 * Check whether we are returning from the top level VOP.
 */
static int
ufs_lockfs_top_vop_return(ulockfs_info_t *head)
{
	ulockfs_info_t *info;
	int result = 1;

	for (info = head; info != NULL; info = info->next) {
		if (info->ulp != NULL) {
			result = 0;
			break;
		}
	}

	return (result);
}

/*
 * ufs_lockfs_end - terminate the lockfs locking protocol
 */
void
ufs_lockfs_end(struct ulockfs *ulp)
{
	ulockfs_info_t *info;
	ulockfs_info_t *head;

	/*
	 * end-of-VOP protocol
	 */
	if (ulp == NULL)
		return;

	head = (ulockfs_info_t *)tsd_get(ufs_lockfs_key);
	SEARCH_ULOCKFSP(head, ulp, info);

	/*
	 * If we're called from a first level VOP, we have to have a
	 * valid ulockfs record in the TSD.
	 */
	ASSERT(info != NULL);

	/*
	 * Invalidate the ulockfs record.
	 */
	info->ulp = NULL;

	if (ufs_lockfs_top_vop_return(head))
		curthread->t_flag &= ~T_DONTBLOCK;

	/* fallocate thread */
	if (ULOCKFS_IS_FALLOC(ulp) && info->flags & ULOCK_INFO_FALLOCATE) {
		/* Clear the thread's fallocate state */
		info->flags &= ~ULOCK_INFO_FALLOCATE;
		if (!atomic_dec_ulong_nv(&ulp->ul_falloc_cnt)) {
			mutex_enter(&ulp->ul_lock);
			ULOCKFS_CLR_FALLOC(ulp);
			cv_broadcast(&ulp->ul_cv);
			mutex_exit(&ulp->ul_lock);
		}
	} else  { /* normal thread */
		if (!atomic_dec_ulong_nv(&ulp->ul_vnops_cnt))
			cv_broadcast(&ulp->ul_cv);
	}
}

/*
 * ufs_lockfs_trybegin - try to start the lockfs locking protocol without
 * blocking.
 */
int
ufs_lockfs_trybegin(struct ufsvfs *ufsvfsp, struct ulockfs **ulpp, ulong_t mask)
{
	int 		error = 0;
	int		rec_vop;
	ushort_t	op_cnt_incremented = 0;
	ulong_t		*ctr;
	struct ulockfs *ulp;
	ulockfs_info_t	*ulockfs_info;
	ulockfs_info_t	*ulockfs_info_free;
	ulockfs_info_t	*ulockfs_info_temp;

	/*
	 * file system has been forcibly unmounted
	 */
	if (ufsvfsp == NULL)
		return (EIO);

	*ulpp = ulp = &ufsvfsp->vfs_ulockfs;

	/*
	 * Do lockfs protocol
	 */
	ulockfs_info = (ulockfs_info_t *)tsd_get(ufs_lockfs_key);
	IS_REC_VOP(rec_vop, ulockfs_info, ulp, ulockfs_info_free);

	/*
	 * Detect recursive VOP call or handcrafted internal lockfs protocol
	 * path and bail out in that case.
	 */
	if (rec_vop || ufs_lockfs_is_under_rawlockfs(ulp)) {
		*ulpp = NULL;
		return (0);
	} else {
		if (ulockfs_info_free == NULL) {
			if ((ulockfs_info_temp = (ulockfs_info_t *)
			    kmem_zalloc(sizeof (ulockfs_info_t),
			    KM_NOSLEEP)) == NULL) {
				*ulpp = NULL;
				return (ENOMEM);
			}
		}
	}

	/*
	 * First time VOP call
	 *
	 * Increment the ctr irrespective of the lockfs state. If the lockfs
	 * state is not ULOCKFS_ULOCK, we can decrement it later. However,
	 * before incrementing we need to check if there is a pending quiesce
	 * request because if we have a continuous stream of ufs_lockfs_begin
	 * requests pounding on a few cpu's then the ufs_quiesce thread might
	 * never see the value of zero for ctr - a livelock kind of scenario.
	 */
	ctr = (mask & ULOCKFS_FWLOCK) ?
	    &ulp->ul_falloc_cnt : &ulp->ul_vnops_cnt;
	if (!ULOCKFS_IS_SLOCK(ulp)) {
		atomic_inc_ulong(ctr);
		op_cnt_incremented++;
	}

	if (!ULOCKFS_IS_JUSTULOCK(ulp) || ufs_quiesce_pend) {
		/*
		 * Non-blocking version of ufs_check_lockfs() code.
		 *
		 * If the file system is not hard locked or error locked
		 * and if ulp->ul_fs_lock allows this operation, increment
		 * the appropriate counter and proceed (For eg., In case the
		 * file system is delete locked, a mmap can still go through).
		 */
		if (op_cnt_incremented)
			if (!atomic_dec_ulong_nv(ctr))
				cv_broadcast(&ulp->ul_cv);
		mutex_enter(&ulp->ul_lock);
		if (ULOCKFS_IS_HLOCK(ulp) ||
		    (ULOCKFS_IS_ELOCK(ulp) && ufsvfsp->vfs_dontblock))
			error = EIO;
		else if (ulp->ul_fs_lock & mask)
			error = EAGAIN;

		if (error) {
			mutex_exit(&ulp->ul_lock);
			if (ulockfs_info_free == NULL)
				kmem_free(ulockfs_info_temp,
				    sizeof (ulockfs_info_t));
			return (error);
		}
		atomic_inc_ulong(ctr);
		if (mask & ULOCKFS_FWLOCK)
			ULOCKFS_SET_FALLOC(ulp);
		mutex_exit(&ulp->ul_lock);
	} else {
		/*
		 * This is the common case of file system in a unlocked state.
		 *
		 * If a file system is unlocked, we would expect the ctr to have
		 * been incremented by now. But this will not be true when a
		 * quiesce is winding up - SLOCK was set when we checked before
		 * incrementing the ctr, but by the time we checked for
		 * ULOCKFS_IS_JUSTULOCK, the quiesce thread was gone. Take
		 * ul_lock and go through the non-blocking version of
		 * ufs_check_lockfs() code.
		 */
		if (op_cnt_incremented == 0) {
			mutex_enter(&ulp->ul_lock);
			if (ULOCKFS_IS_HLOCK(ulp) ||
			    (ULOCKFS_IS_ELOCK(ulp) && ufsvfsp->vfs_dontblock))
				error = EIO;
			else if (ulp->ul_fs_lock & mask)
				error = EAGAIN;

			if (error) {
				mutex_exit(&ulp->ul_lock);
				if (ulockfs_info_free == NULL)
					kmem_free(ulockfs_info_temp,
					    sizeof (ulockfs_info_t));
				return (error);
			}
			atomic_inc_ulong(ctr);
			if (mask & ULOCKFS_FWLOCK)
				ULOCKFS_SET_FALLOC(ulp);
			mutex_exit(&ulp->ul_lock);
		} else if (mask & ULOCKFS_FWLOCK) {
			mutex_enter(&ulp->ul_lock);
			ULOCKFS_SET_FALLOC(ulp);
			mutex_exit(&ulp->ul_lock);
		}
	}

	if (ulockfs_info_free != NULL) {
		ulockfs_info_free->ulp = ulp;
		if (mask & ULOCKFS_FWLOCK)
			ulockfs_info_free->flags |= ULOCK_INFO_FALLOCATE;
	} else {
		ulockfs_info_temp->ulp = ulp;
		ulockfs_info_temp->next = ulockfs_info;
		if (mask & ULOCKFS_FWLOCK)
			ulockfs_info_temp->flags |= ULOCK_INFO_FALLOCATE;
		ASSERT(ufs_lockfs_key != 0);
		(void) tsd_set(ufs_lockfs_key, (void *)ulockfs_info_temp);
	}

	curthread->t_flag |= T_DONTBLOCK;
	return (0);
}

/*
 * specialized version of ufs_lockfs_begin() called by ufs_getpage().
 */
int
ufs_lockfs_begin_getpage(
	struct ufsvfs	*ufsvfsp,
	struct ulockfs	**ulpp,
	struct seg	*seg,
	int		read_access,
	uint_t		*protp)
{
	ulong_t			mask;
	int 			error;
	int			rec_vop;
	struct ulockfs		*ulp;
	ulockfs_info_t		*ulockfs_info;
	ulockfs_info_t		*ulockfs_info_free;
	ulockfs_info_t		*ulockfs_info_temp;

	/*
	 * file system has been forcibly unmounted
	 */
	if (ufsvfsp == NULL)
		return (EIO);

	*ulpp = ulp = &ufsvfsp->vfs_ulockfs;

	/*
	 * Do lockfs protocol
	 */
	ulockfs_info = (ulockfs_info_t *)tsd_get(ufs_lockfs_key);
	IS_REC_VOP(rec_vop, ulockfs_info, ulp, ulockfs_info_free);

	/*
	 * Detect recursive VOP call or handcrafted internal lockfs protocol
	 * path and bail out in that case.
	 */
	if (rec_vop || ufs_lockfs_is_under_rawlockfs(ulp)) {
		*ulpp = NULL;
		return (0);
	} else {
		if (ulockfs_info_free == NULL) {
			if ((ulockfs_info_temp = (ulockfs_info_t *)
			    kmem_zalloc(sizeof (ulockfs_info_t),
			    KM_NOSLEEP)) == NULL) {
				*ulpp = NULL;
				return (ENOMEM);
			}
		}
	}

	/*
	 * First time VOP call
	 */
	atomic_inc_ulong(&ulp->ul_vnops_cnt);
	if (!ULOCKFS_IS_JUSTULOCK(ulp) || ufs_quiesce_pend) {
		if (!atomic_dec_ulong_nv(&ulp->ul_vnops_cnt))
			cv_broadcast(&ulp->ul_cv);
		mutex_enter(&ulp->ul_lock);
		if (seg->s_ops == &segvn_ops &&
		    ((struct segvn_data *)seg->s_data)->type != MAP_SHARED) {
			mask = (ulong_t)ULOCKFS_GETREAD_MASK;
		} else if (protp && read_access) {
			/*
			 * Restrict the mapping to readonly.
			 * Writes to this mapping will cause
			 * another fault which will then
			 * be suspended if fs is write locked
			 */
			*protp &= ~PROT_WRITE;
			mask = (ulong_t)ULOCKFS_GETREAD_MASK;
		} else
			mask = (ulong_t)ULOCKFS_GETWRITE_MASK;

		/*
		 * will sleep if this fs is locked against this VOP
		 */
		error = ufs_check_lockfs(ufsvfsp, ulp, mask);
		mutex_exit(&ulp->ul_lock);
		if (error) {
			if (ulockfs_info_free == NULL)
				kmem_free(ulockfs_info_temp,
				    sizeof (ulockfs_info_t));
			return (error);
		}
	}

	if (ulockfs_info_free != NULL) {
		ulockfs_info_free->ulp = ulp;
	} else {
		ulockfs_info_temp->ulp = ulp;
		ulockfs_info_temp->next = ulockfs_info;
		ASSERT(ufs_lockfs_key != 0);
		(void) tsd_set(ufs_lockfs_key, (void *)ulockfs_info_temp);
	}

	curthread->t_flag |= T_DONTBLOCK;
	return (0);
}

void
ufs_lockfs_tsd_destructor(void *head)
{
	ulockfs_info_t *curr = (ulockfs_info_t *)head;
	ulockfs_info_t *temp;

	for (; curr != NULL; ) {
		/*
		 * The TSD destructor is being called when the thread exits
		 * (via thread_exit()). At that time it must have cleaned up
		 * all VOPs via ufs_lockfs_end() and there must not be a
		 * valid ulockfs record exist while a thread is exiting.
		 */
		temp = curr;
		curr = curr->next;
		ASSERT(temp->ulp == NULL);
		kmem_free(temp, sizeof (ulockfs_info_t));
	}
}
