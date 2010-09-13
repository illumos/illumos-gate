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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
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


#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Code pertaining to management of the in-core data structures.
 */
#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/signal.h>
#include <sys/errno.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/uio.h>
#include <sys/buf.h>
#include <sys/fs/ufs_fs.h>
#include <sys/fs/ufs_inode.h>
#include <sys/fs/ufs_quota.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/file.h>
#include <sys/fs/ufs_panic.h>
#include <sys/var.h>


/*
 * Dquot in core hash chain headers
 */
struct	dqhead	dqhead[NDQHASH];

static kmutex_t dq_cachelock;
static kmutex_t dq_freelock;

krwlock_t dq_rwlock;

/*
 * Dquot free list.
 */
struct dquot dqfreelist;

#define	dqinsheadfree(DQP) { \
	mutex_enter(&dq_freelock); \
	(DQP)->dq_freef = dqfreelist.dq_freef; \
	(DQP)->dq_freeb = &dqfreelist; \
	dqfreelist.dq_freef->dq_freeb = (DQP); \
	dqfreelist.dq_freef = (DQP); \
	mutex_exit(&dq_freelock); \
}

#define	dqinstailfree(DQP) { \
	mutex_enter(&dq_freelock); \
	(DQP)->dq_freeb = dqfreelist.dq_freeb; \
	(DQP)->dq_freef = &dqfreelist; \
	dqfreelist.dq_freeb->dq_freef = (DQP); \
	dqfreelist.dq_freeb = (DQP); \
	mutex_exit(&dq_freelock); \
}

/* (clear pointers to make sure we don't use them; catch problems early) */
#define	dqremfree(DQP) { \
	(DQP)->dq_freeb->dq_freef = (DQP)->dq_freef; \
	(DQP)->dq_freef->dq_freeb = (DQP)->dq_freeb; \
	(DQP)->dq_freef = (DQP)->dq_freeb = NULL; \
}

typedef	struct dquot *DQptr;

/*
 * Initialize quota sub-system init lock.
 */
void
qtinit()
{
	rw_init(&dq_rwlock, NULL, RW_DEFAULT, NULL);
}

/*
 * qtinit2 allocated space for the quota structures.  Only do this if
 * if quotas are going to be used so that we can save the space if quotas
 * aren't used.
 */
void
qtinit2(void)
{
	register struct dqhead *dhp;
	register struct dquot *dqp;

	ASSERT(RW_WRITE_HELD(&dq_rwlock));

	if (ndquot == 0)
		ndquot = ((maxusers * NMOUNT) / 4) + v.v_proc;

	dquot = kmem_zalloc(ndquot * sizeof (struct dquot), KM_SLEEP);
	dquotNDQUOT = dquot + ndquot;

	/*
	 * Initialize the cache between the in-core structures
	 * and the per-file system quota files on disk.
	 */
	for (dhp = &dqhead[0]; dhp < &dqhead[NDQHASH]; dhp++) {
		dhp->dqh_forw = dhp->dqh_back = (DQptr)dhp;
	}
	dqfreelist.dq_freef = dqfreelist.dq_freeb = (DQptr)&dqfreelist;
	for (dqp = dquot; dqp < dquotNDQUOT; dqp++) {
		mutex_init(&dqp->dq_lock, NULL, MUTEX_DEFAULT, NULL);
		dqp->dq_forw = dqp->dq_back = dqp;
		dqinsheadfree(dqp);
	}
}

/*
 * Obtain the user's on-disk quota limit for file system specified.
 * dqpp is returned locked.
 */
int
getdiskquota(
	uid_t uid,
	struct ufsvfs *ufsvfsp,
	int force,			/* don't do enable checks */
	struct dquot **dqpp)		/* resulting dquot ptr */
{
	struct dquot *dqp;
	struct dqhead *dhp;
	struct inode *qip;
	int error;
	extern struct cred *kcred;
	daddr_t	bn;
	int contig;
	int err;

	ASSERT(RW_LOCK_HELD(&ufsvfsp->vfs_dqrwlock));

	dhp = &dqhead[DQHASH(uid, ufsvfsp)];
loop:
	/*
	 * Check for quotas enabled.
	 */
	if ((ufsvfsp->vfs_qflags & MQ_ENABLED) == 0 && !force)
		return (ESRCH);
	qip = ufsvfsp->vfs_qinod;
	if (!qip)
		return (ufs_fault(ufsvfsp->vfs_root, "getdiskquota: NULL qip"));
	/*
	 * Check the cache first.
	 */
	mutex_enter(&dq_cachelock);
	for (dqp = dhp->dqh_forw; dqp != (DQptr)dhp; dqp = dqp->dq_forw) {
		if (dqp->dq_uid != uid || dqp->dq_ufsvfsp != ufsvfsp)
			continue;
		mutex_exit(&dq_cachelock);
		mutex_enter(&dqp->dq_lock);
		/*
		 * I may have slept in the mutex_enter.  Make sure this is
		 * still the one I want.
		 */
		if (dqp->dq_uid != uid || dqp->dq_ufsvfsp != ufsvfsp) {
			mutex_exit(&dqp->dq_lock);
			goto loop;
		}
		if (dqp->dq_flags & DQ_ERROR) {
			mutex_exit(&dqp->dq_lock);
			return (EINVAL);
		}
		/*
		 * Cache hit with no references.
		 * Take the structure off the free list.
		 */
		if (dqp->dq_cnt == 0) {
			mutex_enter(&dq_freelock);
			dqremfree(dqp);
			mutex_exit(&dq_freelock);
		}
		dqp->dq_cnt++;
		mutex_exit(&dqp->dq_lock);
		*dqpp = dqp;
		return (0);
	}
	/*
	 * Not in cache.
	 * Get dquot at head of free list.
	 */
	mutex_enter(&dq_freelock);
	if ((dqp = dqfreelist.dq_freef) == &dqfreelist) {
		mutex_exit(&dq_freelock);
		mutex_exit(&dq_cachelock);
		cmn_err(CE_WARN, "dquot table full");
		return (EUSERS);
	}

	if (dqp->dq_cnt != 0 || dqp->dq_flags != 0) {
		panic("getdiskquota: dqp->dq_cnt: "
		    "%ld != 0 || dqp->dq_flags: 0x%x != 0 (%s)",
		    dqp->dq_cnt, dqp->dq_flags, qip->i_fs->fs_fsmnt);
		/*NOTREACHED*/
	}
	/*
	 * Take it off the free list, and off the hash chain it was on.
	 * Then put it on the new hash chain.
	 */
	dqremfree(dqp);
	mutex_exit(&dq_freelock);
	remque(dqp);
	dqp->dq_cnt = 1;
	dqp->dq_uid = uid;
	dqp->dq_ufsvfsp = ufsvfsp;
	dqp->dq_mof = UFS_HOLE;
	mutex_enter(&dqp->dq_lock);
	insque(dqp, dhp);
	mutex_exit(&dq_cachelock);
	/*
	 * Check the uid in case it's too large to fit into the 2Gbyte
	 * 'quotas' file (higher than 67 million or so).
	 */

	/*
	 * Large Files: i_size need to be accessed atomically now.
	 */
	rw_enter(&qip->i_contents, RW_READER);
	if (uid <= MAXUID && dqoff(uid) >= 0 && dqoff(uid) < qip->i_size) {
		/*
		 * Read quota info off disk.
		 */
		error = ufs_rdwri(UIO_READ, FREAD, qip, (caddr_t)&dqp->dq_dqb,
		    sizeof (struct dqblk), dqoff(uid), UIO_SYSSPACE,
		    (int *)NULL, kcred);
		/*
		 * We must set the dq_mof even if not we are not logging in case
		 * we are later remount to logging.
		 */
		err = bmap_read(qip, dqoff(uid), &bn, &contig);
		rw_exit(&qip->i_contents);
		if ((bn != UFS_HOLE) && !err) {
			dqp->dq_mof = ldbtob(bn) +
			    (offset_t)(dqoff(uid) & (DEV_BSIZE - 1));
		} else {
			dqp->dq_mof = UFS_HOLE;
		}
		if (error) {
			/*
			 * I/O error in reading quota file.
			 * Put dquot on a private, unfindable hash list,
			 * put dquot at the head of the free list and
			 * reflect the problem to caller.
			 */
			dqp->dq_flags = DQ_ERROR;
			/*
			 * I must exit the dq_lock so that I can acquire the
			 * dq_cachelock.  If another thread finds dqp before
			 * I remove it from the cache it will see the
			 * DQ_ERROR and just return EIO.
			 */
			mutex_exit(&dqp->dq_lock);
			mutex_enter(&dq_cachelock);
			mutex_enter(&dqp->dq_lock);
			remque(dqp);
			mutex_exit(&dqp->dq_lock);
			mutex_exit(&dq_cachelock);
			/*
			 * Don't bother reacquiring dq_lock because the dq is
			 * not on the freelist or in the cache so only I have
			 * access to it.
			 */
			dqp->dq_cnt = 0;
			dqp->dq_ufsvfsp = NULL;
			dqp->dq_forw = dqp;
			dqp->dq_back = dqp;
			dqp->dq_mof = UFS_HOLE;
			dqp->dq_flags = 0;
			dqinsheadfree(dqp);
			return (EIO);
		}
	} else {
		rw_exit(&qip->i_contents);	/* done with i_size */
		bzero(&dqp->dq_dqb, sizeof (struct dqblk));
		dqp->dq_mof = UFS_HOLE;
	}
	mutex_exit(&dqp->dq_lock);
	*dqpp = dqp;
	return (0);
}

/*
 * Release dquot.
 */
void
dqput(dqp)
	register struct dquot *dqp;
{

	ASSERT(dqp->dq_ufsvfsp == NULL ||
		RW_LOCK_HELD(&dqp->dq_ufsvfsp->vfs_dqrwlock));
	ASSERT(MUTEX_HELD(&dqp->dq_lock));
	if (dqp->dq_cnt == 0) {
		(void) ufs_fault(
			dqp->dq_ufsvfsp && dqp->dq_ufsvfsp->vfs_root?
			dqp->dq_ufsvfsp->vfs_root: NULL,
						    "dqput: dqp->dq_cnt == 0");
		return;
	}
	if (--dqp->dq_cnt == 0) {
		if (dqp->dq_flags & DQ_MOD)
			dqupdate(dqp);
		/*
		 * DQ_MOD was cleared by dqupdate().
		 * DQ_ERROR shouldn't be set if this dquot was being used.
		 * DQ_FILES/DQ_BLKS don't matter at this point.
		 */
		dqp->dq_flags = 0;
		if (dqp->dq_ufsvfsp == NULL ||
		    dqp->dq_ufsvfsp->vfs_qflags == 0) {
			/* quotas are disabled, discard this dquot struct */
			dqinval(dqp);
		} else
			dqinstailfree(dqp);
	}
}

/*
 * Update on disk quota info.
 */
void
dqupdate(dqp)
	register struct dquot *dqp;
{
	register struct inode *qip;
	extern struct cred *kcred;
	struct ufsvfs	*ufsvfsp;
	int		newtrans	= 0;
	struct vnode	*vfs_root;

	ASSERT(MUTEX_HELD(&dqp->dq_lock));

	if (!dqp->dq_ufsvfsp) {
		(void) ufs_fault(NULL, "dqupdate: NULL dq_ufsvfsp");
		return;
	}
	vfs_root = dqp->dq_ufsvfsp->vfs_root;
	if (!vfs_root) {
		(void) ufs_fault(NULL, "dqupdate: NULL vfs_root");
		return;
	}
	/*
	 * I don't need to hold dq_rwlock when looking at vfs_qinod here
	 * because vfs_qinod is only cleared by closedq after it has called
	 * dqput on all dq's.  Since I am holding dq_lock on this dq, closedq
	 * will have to wait until I am done before it can call dqput on
	 * this dq so vfs_qinod will not change value until after I return.
	 */
	qip = dqp->dq_ufsvfsp->vfs_qinod;
	if (!qip) {
		(void) ufs_fault(vfs_root, "dqupdate: NULL vfs_qinod");
		return;
	}
	ufsvfsp = qip->i_ufsvfs;
	if (!ufsvfsp) {
		(void) ufs_fault(vfs_root,
				    "dqupdate: NULL vfs_qinod->i_ufsvfs");
		return;
	}
	if (ufsvfsp != dqp->dq_ufsvfsp) {
		(void) ufs_fault(vfs_root,
			    "dqupdate: vfs_qinod->i_ufsvfs != dqp->dq_ufsvfsp");
		return;
	}
	if (!(dqp->dq_flags & DQ_MOD)) {
		(void) ufs_fault(vfs_root,
				    "dqupdate: !(dqp->dq_flags & DQ_MOD)");
		return;
	}

	if (!(curthread->t_flag & T_DONTBLOCK)) {
		newtrans++;
		curthread->t_flag |= T_DONTBLOCK;
		TRANS_BEGIN_ASYNC(ufsvfsp, TOP_QUOTA, TOP_QUOTA_SIZE);
	}
	if (TRANS_ISTRANS(ufsvfsp)) {
		TRANS_DELTA(ufsvfsp, dqp->dq_mof, sizeof (struct dqblk),
		    DT_QR, 0, 0);
		TRANS_LOG(ufsvfsp, (caddr_t)&dqp->dq_dqb, dqp->dq_mof,
		    (int)(sizeof (struct dqblk)), NULL, 0);
	} else {
		/*
		 * Locknest gets very confused when I lock the quota inode.
		 * It thinks that qip and ip (the inode that caused the
		 * quota routines to get called) are the same inode.
		 */
		rw_enter(&qip->i_contents, RW_WRITER);
		/*
		 * refuse to push if offset would be illegal
		 */
		if (dqoff(dqp->dq_uid) >= 0) {
			(void) ufs_rdwri(UIO_WRITE, FWRITE, qip,
					(caddr_t)&dqp->dq_dqb,
					sizeof (struct dqblk),
					dqoff(dqp->dq_uid), UIO_SYSSPACE,
					(int *)NULL, kcred);
		}
		rw_exit(&qip->i_contents);
	}

	dqp->dq_flags &= ~DQ_MOD;
	if (newtrans) {
		TRANS_END_ASYNC(ufsvfsp, TOP_QUOTA, TOP_QUOTA_SIZE);
		curthread->t_flag &= ~T_DONTBLOCK;
	}
}

/*
 * Invalidate a dquot.  This function is called when quotas are disabled
 * for a specific file system via closedq() or when we unmount the file
 * system and invalidate the quota cache via invalidatedq().
 *
 * Take the dquot off its hash list and put it on a private, unfindable
 * hash list (refers to itself). Also, put it at the head of the free list.
 * Note that even though dq_cnt is zero, this dquot is NOT yet on the
 * freelist.
 */
void
dqinval(dqp)
	register struct dquot *dqp;
{
	ASSERT(MUTEX_HELD(&dqp->dq_lock));
	ASSERT(dqp->dq_cnt == 0);
	ASSERT(dqp->dq_flags == 0);
	ASSERT(dqp->dq_freef == NULL && dqp->dq_freeb == NULL);
	ASSERT(dqp->dq_ufsvfsp &&
		(dqp->dq_ufsvfsp->vfs_qflags & MQ_ENABLED) == 0);

	/*
	 * To preserve lock order, we have to drop dq_lock in order to
	 * grab dq_cachelock.  To prevent someone from grabbing this
	 * dquot from the quota cache via getdiskquota() while we are
	 * "unsafe", we clear dq_ufsvfsp so it won't match anything.
	 */
	dqp->dq_ufsvfsp = NULL;
	mutex_exit(&dqp->dq_lock);
	mutex_enter(&dq_cachelock);
	mutex_enter(&dqp->dq_lock);

	/*
	 * The following paranoia is to make sure that getdiskquota()
	 * has not been broken:
	 */
	ASSERT(dqp->dq_cnt == 0);
	ASSERT(dqp->dq_flags == 0);
	ASSERT(dqp->dq_freef == NULL && dqp->dq_freeb == NULL);
	ASSERT(dqp->dq_ufsvfsp == NULL);

	/*
	 * Now we have the locks in the right order so we can do the
	 * rest of the work.
	 */
	remque(dqp);
	mutex_exit(&dq_cachelock);
	dqp->dq_forw = dqp;
	dqp->dq_back = dqp;
	dqinsheadfree(dqp);
}

/*
 * Invalidate all quota information records for the specified file system.
 */
void
invalidatedq(ufsvfsp)
	register struct ufsvfs *ufsvfsp;
{
	register struct dquot *dqp;


	/*
	 * If quotas are not initialized, then there is nothing to do.
	 */
	rw_enter(&dq_rwlock, RW_READER);
	if (!quotas_initialized) {
		rw_exit(&dq_rwlock);
		return;
	}
	rw_exit(&dq_rwlock);


	rw_enter(&ufsvfsp->vfs_dqrwlock, RW_WRITER);

	ASSERT((ufsvfsp->vfs_qflags & MQ_ENABLED) == 0);

	/*
	 * Invalidate all the quota info records for this file system
	 * that are in the quota cache:
	 */
	for (dqp = dquot; dqp < dquotNDQUOT; dqp++) {
		/*
		 * If someone else has it, then ignore it. For the target
		 * file system, this is okay for three reasons:
		 *
		 * 1) This routine is called after closedq() so the quota
		 *    sub-system is disabled for this file system.
		 * 2) We have made the quota sub-system quiescent for
		 *    this file system.
		 * 3) We are in the process of unmounting this file
		 *    system so the quota sub-system can't be enabled
		 *    for it.
		 */
		if (!mutex_tryenter(&dqp->dq_lock)) {
			continue;
		}


		/*
		 * At this point, any quota info records that are
		 * associated with the target file system, should have a
		 * reference count of zero and be on the free list.
		 * Why? Because these quota info records went to a zero
		 * dq_cnt (via dqput()) before the file system was
		 * unmounted and are waiting to be found in the quota
		 * cache and reused (via getdiskquota()). The exception
		 * is when a quota transaction is sitting in the deltamap,
		 * indicated by DQ_TRANS being set in dq_flags.
		 * This causes a reference to be held on the quota
		 * information record and it will only be cleared once
		 * the transaction has reached the log. If we find
		 * any of these - we ignore them and let logging do
		 * the right thing.
		 */
		if (dqp->dq_ufsvfsp == ufsvfsp) {
			ASSERT(dqp->dq_cnt == 0 || (dqp->dq_cnt == 1 &&
			    (dqp->dq_flags & DQ_TRANS)));

			/* Cope with those orphaned dquots. */
			if (dqp->dq_cnt == 1 && (dqp->dq_flags & DQ_TRANS)) {
				mutex_exit(&dqp->dq_lock);
				continue;
			}

			ASSERT(dqp->dq_cnt == 0);
			ASSERT(dqp->dq_freef && dqp->dq_freeb);

			/*
			 * Take the quota info record off the free list
			 * so dqinval() can do its job (and put it on the
			 * front of the free list).
			 */
			mutex_enter(&dq_freelock);
			dqremfree(dqp);
			mutex_exit(&dq_freelock);
			dqinval(dqp);
		}

		mutex_exit(&dqp->dq_lock);
	}
	rw_exit(&ufsvfsp->vfs_dqrwlock);
}
