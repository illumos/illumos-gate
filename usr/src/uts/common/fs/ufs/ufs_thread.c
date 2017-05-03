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

/*	copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 2017 by Delphix. All rights reserved.
 */

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/buf.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/user.h>
#include <sys/callb.h>
#include <sys/cpuvar.h>
#include <sys/fs/ufs_inode.h>
#include <sys/fs/ufs_log.h>
#include <sys/fs/ufs_trans.h>
#include <sys/fs/ufs_acl.h>
#include <sys/fs/ufs_bio.h>
#include <sys/fs/ufs_fsdir.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/sysmacros.h>
#include <vm/pvn.h>

extern pri_t			minclsyspri;
extern int			hash2ints();
extern struct kmem_cache	*inode_cache;	/* cache of free inodes */
extern int			ufs_idle_waiters;
extern struct instats		ins;

static void ufs_attr_purge(struct inode *);

/*
 * initialize a thread's queue struct
 */
void
ufs_thread_init(struct ufs_q *uq, int lowat)
{
	bzero((caddr_t)uq, sizeof (*uq));
	cv_init(&uq->uq_cv, NULL, CV_DEFAULT, NULL);
	mutex_init(&uq->uq_mutex, NULL, MUTEX_DEFAULT, NULL);
	uq->uq_lowat = lowat;
	uq->uq_hiwat = 2 * lowat;
	uq->uq_threadp = NULL;
}

/*
 * start a thread for a queue (assumes success)
 */
void
ufs_thread_start(struct ufs_q *uq, void (*func)(), struct vfs *vfsp)
{
	mutex_enter(&uq->uq_mutex);
	if (uq->uq_threadp == NULL) {
		uq->uq_threadp = thread_create(NULL, 0, func, vfsp, 0, &p0,
		    TS_RUN, minclsyspri);
		uq->uq_flags = 0;
	}
	mutex_exit(&uq->uq_mutex);
}

/*
 * wait for the thread to exit
 */
void
ufs_thread_exit(struct ufs_q *uq)
{
	kt_did_t ufs_thread_did = 0;

	mutex_enter(&uq->uq_mutex);
	uq->uq_flags &= ~(UQ_SUSPEND | UQ_SUSPENDED);
	if (uq->uq_threadp != NULL) {
		ufs_thread_did = uq->uq_threadp->t_did;
		uq->uq_flags |= (UQ_EXIT|UQ_WAIT);
		cv_broadcast(&uq->uq_cv);
	}
	mutex_exit(&uq->uq_mutex);

	/*
	 * It's safe to call thread_join() with an already-gone
	 * t_did, but we have to obtain it before the kernel
	 * thread structure is freed. We do so above under the
	 * protection of the uq_mutex when we're sure the thread
	 * still exists and it's save to de-reference it.
	 * We also have to check if ufs_thread_did is != 0
	 * before calling thread_join() since thread 0 in the system
	 * gets a t_did of 0.
	 */
	if (ufs_thread_did)
		thread_join(ufs_thread_did);
}

/*
 * wait for a thread to suspend itself on the caller's behalf
 *	the caller is responsible for continuing the thread
 */
void
ufs_thread_suspend(struct ufs_q *uq)
{
	mutex_enter(&uq->uq_mutex);
	if (uq->uq_threadp != NULL) {
		/*
		 * wait while another thread is suspending this thread.
		 * no need to do a cv_broadcast(), as whoever suspended
		 * the thread must continue it at some point.
		 */
		while ((uq->uq_flags & UQ_SUSPEND) &&
		    (uq->uq_threadp != NULL)) {
			/*
			 * We can't use cv_signal() because if our
			 * signal doesn't happen to hit the desired
			 * thread but instead some other waiter like
			 * ourselves, we'll wait forever for a
			 * response.  Well, at least an indeterminate
			 * amount of time until we just happen to get
			 * lucky from whomever did get signalled doing
			 * a cv_signal() of their own.  This is an
			 * unfortunate performance lossage.
			 */
			uq->uq_flags |= UQ_WAIT;
			cv_wait(&uq->uq_cv, &uq->uq_mutex);
		}

		uq->uq_flags |= (UQ_SUSPEND | UQ_WAIT);

		/*
		 * wait for the thread to suspend itself
		 */
		if ((uq->uq_flags & UQ_SUSPENDED) == 0 &&
		    (uq->uq_threadp != NULL)) {
			cv_broadcast(&uq->uq_cv);
		}

		while (((uq->uq_flags & UQ_SUSPENDED) == 0) &&
		    (uq->uq_threadp != NULL)) {
			cv_wait(&uq->uq_cv, &uq->uq_mutex);
		}
	}
	mutex_exit(&uq->uq_mutex);
}

/*
 * allow a thread to continue from a ufs_thread_suspend()
 *	This thread must be the same as the thread that called
 *	ufs_thread_suspend.
 */
void
ufs_thread_continue(struct ufs_q *uq)
{
	mutex_enter(&uq->uq_mutex);
	uq->uq_flags &= ~(UQ_SUSPEND | UQ_SUSPENDED);
	cv_broadcast(&uq->uq_cv);
	mutex_exit(&uq->uq_mutex);
}

/*
 * some common code for managing a threads execution
 *	uq is locked at entry and return
 *	may sleep
 *	may exit
 */
/*
 * Kind of a hack passing in the callb_cpr_t * here.
 * It should really be part of the ufs_q structure.
 * I did not put it in there because we are already in beta
 * and I was concerned that changing ufs_inode.h to include
 * callb.h might break something.
 */
int
ufs_thread_run(struct ufs_q *uq, callb_cpr_t *cprinfop)
{
again:
	ASSERT(uq->uq_ne >= 0);

	if (uq->uq_flags & UQ_SUSPEND) {
		uq->uq_flags |= UQ_SUSPENDED;
	} else if (uq->uq_flags & UQ_EXIT) {
		/*
		 * exiting; empty the queue (may infinite loop)
		 */
		if (uq->uq_ne)
			return (uq->uq_ne);
		uq->uq_threadp = NULL;
		if (uq->uq_flags & UQ_WAIT) {
			cv_broadcast(&uq->uq_cv);
		}
		uq->uq_flags &= ~(UQ_EXIT | UQ_WAIT);
		CALLB_CPR_EXIT(cprinfop);
		thread_exit();
	} else if (uq->uq_ne >= uq->uq_lowat) {
		/*
		 * process a block of entries until below high water mark
		 */
		return (uq->uq_ne - (uq->uq_lowat >> 1));
	}
	if (uq->uq_flags & UQ_WAIT) {
		uq->uq_flags &= ~UQ_WAIT;
		cv_broadcast(&uq->uq_cv);
	}
	CALLB_CPR_SAFE_BEGIN(cprinfop);
	cv_wait(&uq->uq_cv, &uq->uq_mutex);
	CALLB_CPR_SAFE_END(cprinfop, &uq->uq_mutex);
	goto again;
}

/*
 * DELETE INODE
 * The following routines implement the protocol for freeing the resources
 * held by an idle and deleted inode.
 */
void
ufs_delete(struct ufsvfs *ufsvfsp, struct inode *ip, int dolockfs)
{
	ushort_t	mode;
	struct vnode	*vp	= ITOV(ip);
	struct ulockfs	*ulp;
	int		trans_size;
	int		dorwlock = ((ip->i_mode & IFMT) == IFREG);
	int		issync;
	int		err;
	struct inode	*dp;
	struct ufs_q    *delq = &ufsvfsp->vfs_delete;
	struct ufs_delq_info *delq_info = &ufsvfsp->vfs_delete_info;

	/*
	 * Ignore if deletes are not allowed (wlock/hlock)
	 */
	if (ULOCKFS_IS_NOIDEL(ITOUL(ip))) {
		mutex_enter(&delq->uq_mutex);
		delq_info->delq_unreclaimed_blocks -= ip->i_blocks;
		delq_info->delq_unreclaimed_files--;
		mutex_exit(&delq->uq_mutex);
		VN_RELE(vp);
		return;
	}

	if ((vp->v_count > 1) || (ip->i_mode == 0)) {
		mutex_enter(&delq->uq_mutex);
		delq_info->delq_unreclaimed_blocks -= ip->i_blocks;
		delq_info->delq_unreclaimed_files--;
		mutex_exit(&delq->uq_mutex);
		VN_RELE(vp);
		return;
	}
	/*
	 * If we are called as part of setting a fs lock, then only
	 * do part of the lockfs protocol.  In other words, don't hang.
	 */
	if (dolockfs) {
		if (ufs_lockfs_begin(ufsvfsp, &ulp, ULOCKFS_DELETE_MASK))
			return;
	} else {
		/*
		 * check for recursive VOP call
		 */
		if (curthread->t_flag & T_DONTBLOCK) {
			ulp = NULL;
		} else {
			ulp = &ufsvfsp->vfs_ulockfs;
			curthread->t_flag |= T_DONTBLOCK;
		}
	}

	/*
	 * Hold rwlock to synchronize with (nfs) writes
	 */
	if (dorwlock)
		rw_enter(&ip->i_rwlock, RW_WRITER);

	/*
	 * Delete the attribute directory.
	 */
	if (ip->i_oeftflag != 0) {
		TRANS_BEGIN_CSYNC(ufsvfsp, issync, TOP_REMOVE,
		    trans_size = (int)TOP_REMOVE_SIZE(ip));
		rw_enter(&ip->i_contents, RW_WRITER);
		err = ufs_iget(ip->i_vfs, ip->i_oeftflag,
		    &dp, CRED());
		if (err == 0) {
			rw_enter(&dp->i_rwlock, RW_WRITER);
			rw_enter(&dp->i_contents, RW_WRITER);
			dp->i_flag |= IUPD|ICHG;
			dp->i_seq++;
			TRANS_INODE(dp->i_ufsvfs, dp);
			dp->i_nlink -= 2;
			ufs_setreclaim(dp);
			/*
			 * Should get rid of any negative cache entries that
			 * might be lingering, as well as ``.'' and
			 * ``..''.  If we don't, the VN_RELE() below
			 * won't actually put dp on the delete queue
			 * and it'll hang out until someone forces it
			 * (lockfs -f, umount, ...).  The only reliable
			 * way of doing this at the moment is to call
			 * dnlc_purge_vp(ITOV(dp)), which is unacceptably
			 * slow, so we'll just note the problem in this
			 * comment for now.
			 */
			dnlc_remove(ITOV(dp), ".");
			dnlc_remove(ITOV(dp), "..");
			ITIMES_NOLOCK(dp);
			if (!TRANS_ISTRANS(ufsvfsp)) {
				ufs_iupdat(dp, I_SYNC);
			}
			rw_exit(&dp->i_contents);
			rw_exit(&dp->i_rwlock);
			VN_RELE(ITOV(dp));
		}
		/*
		 * Clear out attribute pointer
		 */
		ip->i_oeftflag = 0;
		rw_exit(&ip->i_contents);
		TRANS_END_CSYNC(ufsvfsp, err, issync,
		    TOP_REMOVE, trans_size);
		dnlc_remove(ITOV(ip), XATTR_DIR_NAME);
	}

	if ((ip->i_mode & IFMT) == IFATTRDIR) {
		ufs_attr_purge(ip);
	}

	(void) TRANS_ITRUNC(ip, (u_offset_t)0, I_FREE | I_ACCT, CRED());

	/*
	 * the inode's space has been freed; now free the inode
	 */
	if (ulp) {
		trans_size = TOP_IFREE_SIZE(ip);
		TRANS_BEGIN_ASYNC(ufsvfsp, TOP_IFREE, trans_size);
	}
	rw_enter(&ufsvfsp->vfs_dqrwlock, RW_READER);
	rw_enter(&ip->i_contents, RW_WRITER);
	TRANS_INODE(ufsvfsp, ip);
	mode = ip->i_mode;
	ip->i_mode = 0;
	ip->i_rdev = 0;
	ip->i_ordev = 0;
	ip->i_flag |= IMOD;
	if (ip->i_ufs_acl) {
		(void) ufs_si_free(ip->i_ufs_acl, vp->v_vfsp, CRED());
		ip->i_ufs_acl = NULL;
		ip->i_shadow = 0;
	}

	/*
	 * This inode is torn down but still retains it's identity
	 * (inode number).  It could get recycled soon so it's best
	 * to clean up the vnode just in case.
	 */
	mutex_enter(&vp->v_lock);
	vn_recycle(vp);
	mutex_exit(&vp->v_lock);

	/*
	 * free the inode
	 */
	ufs_ifree(ip, ip->i_number, mode);
	/*
	 * release quota resources; can't fail
	 */
	(void) chkiq((struct ufsvfs *)vp->v_vfsp->vfs_data,
	    /* change */ -1, ip, (uid_t)ip->i_uid, 0, CRED(),
	    (char **)NULL, (size_t *)NULL);
	dqrele(ip->i_dquot);
	ip->i_dquot = NULL;
	ip->i_flag &= ~(IDEL | IDIRECTIO);
	ip->i_cflags = 0;
	if (!TRANS_ISTRANS(ufsvfsp)) {
		ufs_iupdat(ip, I_SYNC);
	} else {
		mutex_enter(&delq->uq_mutex);
		delq_info->delq_unreclaimed_files--;
		mutex_exit(&delq->uq_mutex);
	}
	rw_exit(&ip->i_contents);
	rw_exit(&ufsvfsp->vfs_dqrwlock);
	if (dorwlock)
		rw_exit(&ip->i_rwlock);
	VN_RELE(vp);

	/*
	 * End of transaction
	 */
	if (ulp) {
		TRANS_END_ASYNC(ufsvfsp, TOP_IFREE, trans_size);
		if (dolockfs)
			ufs_lockfs_end(ulp);
		else
			curthread->t_flag &= ~T_DONTBLOCK;
	}
}

/*
 * Create the delete thread and init the delq_info for this fs
 */
void
ufs_delete_init(struct ufsvfs *ufsvfsp, int lowat)
{
	struct ufs_delq_info *delq_info = &ufsvfsp->vfs_delete_info;

	ufs_thread_init(&ufsvfsp->vfs_delete, lowat);
	(void) memset((void *)delq_info, 0, sizeof (*delq_info));
}

/*
 * thread that frees up deleted inodes
 */
void
ufs_thread_delete(struct vfs *vfsp)
{
	struct ufsvfs	*ufsvfsp = (struct ufsvfs *)vfsp->vfs_data;
	struct ufs_q	*uq = &ufsvfsp->vfs_delete;
	struct inode	*ip;
	long		ne;
	callb_cpr_t	cprinfo;

	CALLB_CPR_INIT(&cprinfo, &uq->uq_mutex, callb_generic_cpr,
	    "ufsdelete");

	mutex_enter(&uq->uq_mutex);
again:
	/*
	 * Sleep until there is work to do.  Only do one entry at
	 * a time, to reduce the wait time for checking for a suspend
	 * request.  The ?: is for pedantic portability.
	 */
	ne = ufs_thread_run(uq, &cprinfo) ? 1 : 0;

	/*
	 * process an entry, if there are any
	 */
	if (ne && (ip = uq->uq_ihead)) {
		/*
		 * process first entry on queue.  Assumed conditions are:
		 *	ip is held (v_count >= 1)
		 *	ip is referenced (i_flag & IREF)
		 *	ip is free (i_nlink <= 0)
		 */
		if ((uq->uq_ihead = ip->i_freef) == ip)
			uq->uq_ihead = NULL;
		ip->i_freef->i_freeb = ip->i_freeb;
		ip->i_freeb->i_freef = ip->i_freef;
		ip->i_freef = ip;
		ip->i_freeb = ip;
		uq->uq_ne--;
		mutex_exit(&uq->uq_mutex);
		ufs_delete(ufsvfsp, ip, 1);
		mutex_enter(&uq->uq_mutex);
	}
	goto again;
}

/*
 * drain ne entries off the delete queue.  As new queue entries may
 * be added while we're working, ne is interpreted as follows:
 *
 * ne > 0   => remove up to ne entries
 * ne == 0  => remove all entries currently on the queue
 * ne == -1 => remove entries until the queue is empty
 */
void
ufs_delete_drain(struct vfs *vfsp, int ne, int dolockfs)
{
	struct ufsvfs	*ufsvfsp = (struct ufsvfs *)vfsp->vfs_data;
	struct ufs_q	*uq;
	struct inode	*ip;
	int		drain_cnt = 0;
	int		done;

	/*
	 * if forcibly unmounted; ignore
	 */
	if (ufsvfsp == NULL)
		return;

	uq = &ufsvfsp->vfs_delete;
	mutex_enter(&uq->uq_mutex);
	if (ne == 0)
		drain_cnt = uq->uq_ne;
	else if (ne > 0)
		drain_cnt = ne;

	/*
	 * process up to ne entries
	 */

	done = 0;
	while (!done && (ip = uq->uq_ihead)) {
		if (ne != -1)
			drain_cnt--;
		if (ne != -1 && drain_cnt == 0)
			done = 1;
		if ((uq->uq_ihead = ip->i_freef) == ip)
			uq->uq_ihead = NULL;
		ip->i_freef->i_freeb = ip->i_freeb;
		ip->i_freeb->i_freef = ip->i_freef;
		ip->i_freef = ip;
		ip->i_freeb = ip;
		uq->uq_ne--;
		mutex_exit(&uq->uq_mutex);
		ufs_delete(ufsvfsp, ip, dolockfs);
		mutex_enter(&uq->uq_mutex);
	}
	mutex_exit(&uq->uq_mutex);
}

void
ufs_sync_with_thread(struct ufs_q *uq)
{
	mutex_enter(&uq->uq_mutex);

	/*
	 * Wake up delete thread to free up space.
	 */
	if ((uq->uq_flags & UQ_WAIT) == 0) {
		uq->uq_flags |= UQ_WAIT;
		cv_broadcast(&uq->uq_cv);
	}

	while ((uq->uq_threadp != NULL) && (uq->uq_flags & UQ_WAIT)) {
		cv_wait(&uq->uq_cv, &uq->uq_mutex);
	}

	mutex_exit(&uq->uq_mutex);
}

/*
 * Get rid of everything that's currently in the delete queue,
 * plus whatever the delete thread is working on at the moment.
 *
 * This ability is required for providing true POSIX semantics
 * regarding close(2), unlink(2), etc, even when logging is enabled.
 * The standard requires that the released space be immediately
 * observable (statvfs(2)) and allocatable (e.g., write(2)).
 */
void
ufs_delete_drain_wait(struct ufsvfs *ufsvfsp, int dolockfs)
{
	struct ufs_q *uq = &ufsvfsp->vfs_delete;
	int	error;
	struct ufs_q    *delq = &ufsvfsp->vfs_delete;
	struct ufs_delq_info *delq_info = &ufsvfsp->vfs_delete_info;

	/*
	 * If there is something on delq or delete thread
	 * working on delq.
	 */
	mutex_enter(&delq->uq_mutex);
	if (delq_info->delq_unreclaimed_files > 0) {
		mutex_exit(&delq->uq_mutex);
		(void) ufs_delete_drain(ufsvfsp->vfs_vfs, 0, dolockfs);
		ufs_sync_with_thread(uq);
	} else {
		ASSERT(delq_info->delq_unreclaimed_files == 0);
		mutex_exit(&delq->uq_mutex);
		return;
	}

	/*
	 * Commit any outstanding transactions to make sure
	 * any canceled freed blocks are available for allocation.
	 */
	curthread->t_flag |= T_DONTBLOCK;
	TRANS_BEGIN_SYNC(ufsvfsp, TOP_COMMIT_UPDATE, TOP_COMMIT_SIZE, error);
	if (!error) {
		TRANS_END_SYNC(ufsvfsp, error, TOP_COMMIT_UPDATE,
		    TOP_COMMIT_SIZE);
	}
	curthread->t_flag &= ~T_DONTBLOCK;
}

/*
 * Adjust the resource usage in a struct statvfs based on
 * what's in the delete queue.
 *
 * We do not consider the impact of ACLs or extended attributes
 * that may be deleted as a side-effect of deleting a file.
 * Those are metadata, and their sizes aren't reflected in the
 * sizes returned by stat(), so this is not a problem.
 */
void
ufs_delete_adjust_stats(struct ufsvfs *ufsvfsp, struct statvfs64 *sp)
{
	struct ufs_q *uq = &ufsvfsp->vfs_delete;
	struct ufs_delq_info *delq_info = &ufsvfsp->vfs_delete_info;

	mutex_enter(&uq->uq_mutex);
	/*
	 * The blocks accounted for in the delete queue info are
	 * counted in DEV_BSIZE chunks, but ufs_statvfs counts in
	 * filesystem fragments, so a conversion is required here.
	 */
	sp->f_bfree += dbtofsb(ufsvfsp->vfs_fs,
	    delq_info->delq_unreclaimed_blocks);
	sp->f_ffree += delq_info->delq_unreclaimed_files;
	mutex_exit(&uq->uq_mutex);
}

/*
 * IDLE INODE
 * The following routines implement the protocol for maintaining an
 * LRU list of idle inodes and for moving the idle inodes to the
 * reuse list when the number of allocated inodes exceeds the user
 * tunable high-water mark (ufs_ninode).
 */

/*
 * clean an idle inode and move it to the reuse list
 */
static void
ufs_idle_free(struct inode *ip)
{
	int			pages;
	int			hno;
	kmutex_t		*ihm;
	struct ufsvfs		*ufsvfsp	= ip->i_ufsvfs;
	struct vnode		*vp		= ITOV(ip);
	int			vn_has_data, vn_modified;

	/*
	 * inode is held
	 */

	/*
	 * remember `pages' for stats below
	 */
	pages = (ip->i_mode && vn_has_cached_data(vp) && vp->v_type != VCHR);

	/*
	 * start the dirty pages to disk and then invalidate them
	 * unless the inode is invalid (ISTALE)
	 */
	if ((ip->i_flag & ISTALE) == 0) {
		(void) TRANS_SYNCIP(ip, B_ASYNC, I_ASYNC, TOP_SYNCIP_FREE);
		(void) TRANS_SYNCIP(ip,
		    (TRANS_ISERROR(ufsvfsp)) ? B_INVAL | B_FORCE : B_INVAL,
		    I_ASYNC, TOP_SYNCIP_FREE);
	}

	/*
	 * wait for any current ufs_iget to finish and block future ufs_igets
	 */
	ASSERT(ip->i_number != 0);
	hno = INOHASH(ip->i_number);
	ihm = &ih_lock[hno];
	mutex_enter(ihm);

	/*
	 * It must be guaranteed that v_count >= 2, otherwise
	 * something must be wrong with this vnode already.
	 * That is why we use VN_RELE_LOCKED() instead of VN_RELE().
	 * Acquire the vnode lock in case another thread is in
	 * VN_RELE().
	 */
	mutex_enter(&vp->v_lock);

	VERIFY3U(vp->v_count, >=, 2);

	VN_RELE_LOCKED(vp);

	vn_has_data = (vp->v_type != VCHR && vn_has_cached_data(vp));
	vn_modified = (ip->i_flag & (IMOD|IMODACC|IACC|ICHG|IUPD|IATTCHG));

	if (vp->v_count != 1 ||
	    ((vn_has_data || vn_modified) &&
	    ((ip->i_flag & ISTALE) == 0))) {
		/*
		 * Another thread has referenced this inode while
		 * we are trying  to free  it.  Call VN_RELE() to
		 * release our reference, if v_count > 1  data is
		 * present  or one of the modified etc. flags was
		 * set, whereby ISTALE wasn't set.
		 * If we'd proceed with ISTALE set here, we might
		 * get ourselves into a deadlock situation.
		 */
		mutex_exit(&vp->v_lock);
		mutex_exit(ihm);
		VN_RELE(vp);
	} else {
		/*
		 * The inode is currently unreferenced and can not
		 * acquire further references because it has no pages
		 * and the hash is locked.  Inodes acquire references
		 * via the hash list or via their pages.
		 */

		mutex_exit(&vp->v_lock);

		/*
		 * remove it from the cache
		 */
		remque(ip);
		mutex_exit(ihm);
		/*
		 * Stale inodes have no valid ufsvfs
		 */
		if ((ip->i_flag & ISTALE) == 0 && ip->i_dquot) {
			TRANS_DQRELE(ufsvfsp, ip->i_dquot);
			ip->i_dquot = NULL;
		}
		if ((ip->i_flag & ISTALE) &&
		    vn_has_data) {
			/*
			 * ISTALE inodes may have data
			 * and  this data needs  to be
			 * cleaned up.
			 */
			(void) pvn_vplist_dirty(vp, (u_offset_t)0,
			    ufs_putapage, B_INVAL | B_TRUNC,
			    (struct cred *)NULL);
		}
		ufs_si_del(ip);
		if (pages) {
			CPU_STATS_ADDQ(CPU, sys, ufsipage, 1);
		} else {
			CPU_STATS_ADDQ(CPU, sys, ufsinopage, 1);
		}
		ASSERT((vp->v_type == VCHR) || !vn_has_cached_data(vp));

		/*
		 * We had better not have a vnode reference count > 1
		 * at this point, if we do then something is broken as
		 * this inode/vnode acquired a reference underneath of us.
		 */
		ASSERT(vp->v_count == 1);

		ufs_free_inode(ip);
	}
}

/*
 * this thread processes the global idle queue
 */
iqhead_t *ufs_junk_iq;
iqhead_t *ufs_useful_iq;
int ufs_njunk_iq = 0;
int ufs_nuseful_iq = 0;
int ufs_niqhash;
int ufs_iqhashmask;
struct ufs_q	ufs_idle_q;

void
ufs_thread_idle(void)
{
	callb_cpr_t cprinfo;
	int i;
	int ne;

	ufs_niqhash = (ufs_idle_q.uq_lowat >> 1) / IQHASHQLEN;
	ufs_niqhash = 1 << highbit(ufs_niqhash); /* round up to power of 2 */
	ufs_iqhashmask = ufs_niqhash - 1;
	ufs_junk_iq = kmem_alloc(ufs_niqhash * sizeof (*ufs_junk_iq),
	    KM_SLEEP);
	ufs_useful_iq = kmem_alloc(ufs_niqhash * sizeof (*ufs_useful_iq),
	    KM_SLEEP);

	/* Initialize hash queue headers */
	for (i = 0; i < ufs_niqhash; i++) {
		ufs_junk_iq[i].i_freef = (inode_t *)&ufs_junk_iq[i];
		ufs_junk_iq[i].i_freeb = (inode_t *)&ufs_junk_iq[i];
		ufs_useful_iq[i].i_freef = (inode_t *)&ufs_useful_iq[i];
		ufs_useful_iq[i].i_freeb = (inode_t *)&ufs_useful_iq[i];
	}

	CALLB_CPR_INIT(&cprinfo, &ufs_idle_q.uq_mutex, callb_generic_cpr,
	    "ufsidle");
again:
	/*
	 * Whenever the idle thread is awakened, it repeatedly gives
	 * back half of the idle queue until the idle queue falls
	 * below lowat.
	 */
	mutex_enter(&ufs_idle_q.uq_mutex);
	if (ufs_idle_q.uq_ne < ufs_idle_q.uq_lowat) {
		CALLB_CPR_SAFE_BEGIN(&cprinfo);
		cv_wait(&ufs_idle_q.uq_cv, &ufs_idle_q.uq_mutex);
		CALLB_CPR_SAFE_END(&cprinfo, &ufs_idle_q.uq_mutex);
	}
	mutex_exit(&ufs_idle_q.uq_mutex);

	/*
	 * Give back 1/2 of the idle queue
	 */
	ne = ufs_idle_q.uq_ne >> 1;
	ins.in_tidles.value.ul += ne;
	ufs_idle_some(ne);
	goto again;
}

/*
 * Reclaim callback for ufs inode cache.
 * Invoked by the kernel memory allocator when memory gets tight.
 */
/*ARGSUSED*/
void
ufs_inode_cache_reclaim(void *cdrarg)
{
	/*
	 * If we are low on memory and the idle queue is over its
	 * halfway mark, then free 50% of the idle q
	 *
	 * We don't free all of the idle inodes because the inodes
	 * for popular NFS files may have been kicked from the dnlc.
	 * The inodes for these files will end up on the idle queue
	 * after every NFS access.
	 *
	 * If we repeatedly push them from the idle queue then
	 * NFS users may be unhappy as an extra buf cache operation
	 * is incurred for every NFS operation to these files.
	 *
	 * It's not common, but I have seen it happen.
	 *
	 */
	if (ufs_idle_q.uq_ne < (ufs_idle_q.uq_lowat >> 1))
		return;
	mutex_enter(&ufs_idle_q.uq_mutex);
	cv_broadcast(&ufs_idle_q.uq_cv);
	mutex_exit(&ufs_idle_q.uq_mutex);
}

/*
 * Free up some idle inodes
 */
void
ufs_idle_some(int ne)
{
	int i;
	struct inode *ip;
	struct vnode *vp;
	static int junk_rotor = 0;
	static int useful_rotor = 0;

	for (i = 0; i < ne; ++i) {
		mutex_enter(&ufs_idle_q.uq_mutex);

		if (ufs_njunk_iq) {
			while (ufs_junk_iq[junk_rotor].i_freef ==
			    (inode_t *)&ufs_junk_iq[junk_rotor]) {
				junk_rotor = IQNEXT(junk_rotor);
			}
			ip = ufs_junk_iq[junk_rotor].i_freef;
			ASSERT(ip->i_flag & IJUNKIQ);
		} else if (ufs_nuseful_iq) {
			while (ufs_useful_iq[useful_rotor].i_freef ==
			    (inode_t *)&ufs_useful_iq[useful_rotor]) {
				useful_rotor = IQNEXT(useful_rotor);
			}
			ip = ufs_useful_iq[useful_rotor].i_freef;
			ASSERT(!(ip->i_flag & IJUNKIQ));
		} else {
			mutex_exit(&ufs_idle_q.uq_mutex);
			return;
		}

		/*
		 * emulate ufs_iget
		 */
		vp = ITOV(ip);
		VN_HOLD(vp);
		mutex_exit(&ufs_idle_q.uq_mutex);
		rw_enter(&ip->i_contents, RW_WRITER);
		/*
		 * VN_RELE should not be called if
		 * ufs_rmidle returns true, as it will
		 * effectively be done in ufs_idle_free.
		 */
		if (ufs_rmidle(ip)) {
			rw_exit(&ip->i_contents);
			ufs_idle_free(ip);
		} else {
			rw_exit(&ip->i_contents);
			VN_RELE(vp);
		}
	}
}

/*
 * drain entries for vfsp from the idle queue
 * vfsp == NULL means drain the entire thing
 */
void
ufs_idle_drain(struct vfs *vfsp)
{
	struct inode	*ip, *nip;
	struct inode	*ianchor = NULL;
	int		i;

	mutex_enter(&ufs_idle_q.uq_mutex);
	if (ufs_njunk_iq) {
		/* for each hash q */
		for (i = 0; i < ufs_niqhash; i++) {
			/* search down the hash q */
			for (ip = ufs_junk_iq[i].i_freef;
			    ip != (inode_t *)&ufs_junk_iq[i];
			    ip = ip->i_freef) {
				if (ip->i_vfs == vfsp || vfsp == NULL) {
					/* found a matching entry */
					VN_HOLD(ITOV(ip));
					mutex_exit(&ufs_idle_q.uq_mutex);
					rw_enter(&ip->i_contents, RW_WRITER);
					/*
					 * See comments in ufs_idle_some()
					 * as we will call ufs_idle_free()
					 * after scanning both queues.
					 */
					if (ufs_rmidle(ip)) {
						rw_exit(&ip->i_contents);
						ip->i_freef = ianchor;
						ianchor = ip;
					} else {
						rw_exit(&ip->i_contents);
						VN_RELE(ITOV(ip));
					}
					/* restart this hash q */
					ip = (inode_t *)&ufs_junk_iq[i];
					mutex_enter(&ufs_idle_q.uq_mutex);
				}
			}
		}
	}
	if (ufs_nuseful_iq) {
		/* for each hash q */
		for (i = 0; i < ufs_niqhash; i++) {
			/* search down the hash q */
			for (ip = ufs_useful_iq[i].i_freef;
			    ip != (inode_t *)&ufs_useful_iq[i];
			    ip = ip->i_freef) {
				if (ip->i_vfs == vfsp || vfsp == NULL) {
					/* found a matching entry */
					VN_HOLD(ITOV(ip));
					mutex_exit(&ufs_idle_q.uq_mutex);
					rw_enter(&ip->i_contents, RW_WRITER);
					/*
					 * See comments in ufs_idle_some()
					 * as we will call ufs_idle_free()
					 * after scanning both queues.
					 */
					if (ufs_rmidle(ip)) {
						rw_exit(&ip->i_contents);
						ip->i_freef = ianchor;
						ianchor = ip;
					} else {
						rw_exit(&ip->i_contents);
						VN_RELE(ITOV(ip));
					}
					/* restart this hash q */
					ip = (inode_t *)&ufs_useful_iq[i];
					mutex_enter(&ufs_idle_q.uq_mutex);
				}
			}
		}
	}

	mutex_exit(&ufs_idle_q.uq_mutex);
	/* no more matching entries, release those we have found (if any) */
	for (ip = ianchor; ip; ip = nip) {
		nip = ip->i_freef;
		ip->i_freef = ip;
		ufs_idle_free(ip);
	}
}

/*
 * RECLAIM DELETED INODES
 * The following thread scans the file system once looking for deleted files
 */
void
ufs_thread_reclaim(struct vfs *vfsp)
{
	struct ufsvfs		*ufsvfsp = (struct ufsvfs *)vfsp->vfs_data;
	struct ufs_q		*uq	= &ufsvfsp->vfs_reclaim;
	struct fs		*fs	= ufsvfsp->vfs_fs;
	struct buf		*bp	= 0;
	int			err	= 0;
	daddr_t			bno;
	ino_t			ino;
	struct dinode		*dp;
	struct inode		*ip;
	callb_cpr_t		cprinfo;

	CALLB_CPR_INIT(&cprinfo, &uq->uq_mutex, callb_generic_cpr,
	    "ufsreclaim");

	/*
	 * mount decided that we don't need a reclaim thread
	 */
	if ((fs->fs_reclaim & FS_RECLAIMING) == 0)
		err++;

	/*
	 * don't reclaim if readonly
	 */
	if (fs->fs_ronly)
		err++;

	for (ino = 0; ino < (fs->fs_ncg * fs->fs_ipg) && !err; ++ino) {

		/*
		 * Check whether we are the target of another
		 * thread having called ufs_thread_exit() or
		 * ufs_thread_suspend().
		 */
		mutex_enter(&uq->uq_mutex);
again:
		if (uq->uq_flags & UQ_EXIT) {
			err++;
			mutex_exit(&uq->uq_mutex);
			break;
		} else if (uq->uq_flags & UQ_SUSPEND) {
			uq->uq_flags |= UQ_SUSPENDED;
			/*
			 * Release the buf before we cv_wait()
			 * otherwise we may deadlock with the
			 * thread that called ufs_thread_suspend().
			 */
			if (bp) {
				brelse(bp);
				bp = 0;
			}
			if (uq->uq_flags & UQ_WAIT) {
				uq->uq_flags &= ~UQ_WAIT;
				cv_broadcast(&uq->uq_cv);
			}
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			cv_wait(&uq->uq_cv, &uq->uq_mutex);
			CALLB_CPR_SAFE_END(&cprinfo, &uq->uq_mutex);
			goto again;
		}
		mutex_exit(&uq->uq_mutex);

		/*
		 * if we don't already have the buf; get it
		 */
		bno = fsbtodb(fs, itod(fs, ino));
		if ((bp == 0) || (bp->b_blkno != bno)) {
			if (bp)
				brelse(bp);
			bp = UFS_BREAD(ufsvfsp,
			    ufsvfsp->vfs_dev, bno, fs->fs_bsize);
			bp->b_flags |= B_AGE;
		}
		if (bp->b_flags & B_ERROR) {
			err++;
			continue;
		}
		/*
		 * nlink <= 0 and mode != 0 means deleted
		 */
		dp = (struct dinode *)bp->b_un.b_addr + itoo(fs, ino);
		if ((dp->di_nlink <= 0) && (dp->di_mode != 0)) {
			/*
			 * can't hold the buf (deadlock)
			 */
			brelse(bp);
			bp = 0;
			rw_enter(&ufsvfsp->vfs_dqrwlock, RW_READER);
			/*
			 * iget/iput sequence will put inode on ifree
			 * thread queue if it is idle.  This is a nop
			 * for busy (open, deleted) inodes
			 */
			if (ufs_iget(vfsp, ino, &ip, CRED()))
				err++;
			else
				VN_RELE(ITOV(ip));
			rw_exit(&ufsvfsp->vfs_dqrwlock);
		}
	}

	if (bp)
		brelse(bp);
	if (!err) {
		/*
		 * reset the reclaiming-bit
		 */
		mutex_enter(&ufsvfsp->vfs_lock);
		fs->fs_reclaim &= ~FS_RECLAIMING;
		mutex_exit(&ufsvfsp->vfs_lock);
		TRANS_SBWRITE(ufsvfsp, TOP_SBWRITE_RECLAIM);
	}

	/*
	 * exit the reclaim thread
	 */
	mutex_enter(&uq->uq_mutex);
	uq->uq_threadp = NULL;
	uq->uq_flags &= ~UQ_WAIT;
	cv_broadcast(&uq->uq_cv);
	CALLB_CPR_EXIT(&cprinfo);
	thread_exit();
}
/*
 * HLOCK FILE SYSTEM
 *	hlock the file system's whose logs have device errors
 */
struct ufs_q	ufs_hlock;
/*ARGSUSED*/
void
ufs_thread_hlock(void *ignore)
{
	int		retry;
	callb_cpr_t	cprinfo;

	CALLB_CPR_INIT(&cprinfo, &ufs_hlock.uq_mutex, callb_generic_cpr,
	    "ufshlock");

	for (;;) {
		/*
		 * sleep until there is work to do
		 */
		mutex_enter(&ufs_hlock.uq_mutex);
		(void) ufs_thread_run(&ufs_hlock, &cprinfo);
		ufs_hlock.uq_ne = 0;
		mutex_exit(&ufs_hlock.uq_mutex);
		/*
		 * hlock the error'ed fs's
		 *	retry after a bit if another app is doing lockfs stuff
		 */
		do {
			retry = ufs_trans_hlock();
			if (retry) {
				mutex_enter(&ufs_hlock.uq_mutex);
				CALLB_CPR_SAFE_BEGIN(&cprinfo);
				(void) cv_reltimedwait(&ufs_hlock.uq_cv,
				    &ufs_hlock.uq_mutex, hz, TR_CLOCK_TICK);
				CALLB_CPR_SAFE_END(&cprinfo,
				    &ufs_hlock.uq_mutex);
				mutex_exit(&ufs_hlock.uq_mutex);
			}
		} while (retry);
	}
}

static void
ufs_attr_purge(struct inode *dp)
{
	int	err;
	int	error;
	off_t 	dirsize;			/* size of the directory */
	off_t 	offset;	/* offset in the directory */
	int entryoffsetinblk;		/* offset of ep in fbp's buffer */
	struct inode *tp;
	struct fbuf *fbp;	/* pointer to directory block */
	struct direct *ep;	/* directory entry */
	int trans_size;
	int issync;
	struct ufsvfs	*ufsvfsp = dp->i_ufsvfs;

	rw_enter(&ufsvfsp->vfs_dqrwlock, RW_READER);

	fbp = NULL;
	dirsize = roundup(dp->i_size, DIRBLKSIZ);
	offset = 0;
	entryoffsetinblk = 0;

	/*
	 * Purge directory cache
	 */

	dnlc_dir_purge(&dp->i_danchor);

	while (offset < dirsize) {
		/*
		 * If offset is on a block boundary,
		 * read the next directory block.
		 * Release previous if it exists.
		 */
		if (blkoff(dp->i_fs, offset) == 0) {
			if (fbp != NULL) {
				fbrelse(fbp, S_OTHER);
			}

			err = blkatoff(dp, offset, (char **)0, &fbp);
			if (err) {
				goto out;
			}
			entryoffsetinblk = 0;
		}
		ep = (struct direct *)(fbp->fb_addr + entryoffsetinblk);
		if (ep->d_ino == 0 || (ep->d_name[0] == '.' &&
		    ep->d_name[1] == '\0') ||
		    (ep->d_name[0] == '.' && ep->d_name[1] == '.' &&
		    ep->d_name[2] == '\0')) {

			entryoffsetinblk += ep->d_reclen;

		} else {

			if ((err = ufs_iget(dp->i_vfs, ep->d_ino,
			    &tp, CRED())) != 0) {
				goto out;
			}

			TRANS_BEGIN_CSYNC(ufsvfsp, issync, TOP_REMOVE,
			    trans_size = (int)TOP_REMOVE_SIZE(tp));

			/*
			 * Delete inode.
			 */

			dnlc_remove(ITOV(dp), ep->d_name);

			rw_enter(&tp->i_contents, RW_WRITER);
			tp->i_flag |= ICHG;
			tp->i_seq++;
			TRANS_INODE(tp->i_ufsvfs, tp);
			tp->i_nlink--;
			ufs_setreclaim(tp);
			ITIMES_NOLOCK(tp);
			rw_exit(&tp->i_contents);

			VN_RELE(ITOV(tp));
			entryoffsetinblk += ep->d_reclen;
			TRANS_END_CSYNC(ufsvfsp, error,
			    issync, TOP_REMOVE, trans_size);

		}
		offset += ep->d_reclen;
	}

	if (fbp) {
		fbrelse(fbp, S_OTHER);
	}

out:
	rw_exit(&ufsvfsp->vfs_dqrwlock);
}
