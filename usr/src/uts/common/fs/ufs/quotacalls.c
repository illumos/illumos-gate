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
 * Quota system calls.
 */
#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/systm.h>
#include <sys/signal.h>
#include <sys/cred.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/uio.h>
#include <sys/buf.h>
#include <sys/file.h>
#include <sys/fs/ufs_inode.h>
#include <sys/fs/ufs_fs.h>
#include <sys/fs/ufs_quota.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/pathname.h>
#include <sys/mntent.h>
#include <sys/policy.h>

static int opendq();
static int setquota();
static int getquota();
static int quotasync();

/*
 * Quota sub-system init flag.
 */
int quotas_initialized = 0;

/*
 * Sys call to allow users to find out
 * their current position wrt quota's
 * and to allow privileged users to alter it.
 */

/*ARGSUSED*/
int
quotactl(struct vnode *vp, intptr_t arg, int flag, struct cred *cr)
{
	struct quotctl quot;
	struct ufsvfs *ufsvfsp;
	int error = 0;

	if ((flag & DATAMODEL_MASK) == DATAMODEL_NATIVE) {
		if (copyin((caddr_t)arg, &quot, sizeof (struct quotctl)))
			return (EFAULT);
	}
#ifdef _SYSCALL32_IMPL
	else {
		/* quotctl struct from ILP32 callers */
		struct quotctl32 quot32;
		if (copyin((caddr_t)arg, &quot32, sizeof (struct quotctl32)))
			return (EFAULT);
		quot.op = quot32.op;
		quot.uid = quot32.uid;
		quot.addr = (caddr_t)(uintptr_t)quot32.addr;
	}
#endif /* _SYSCALL32_IMPL */

	if (quot.uid < 0)
		quot.uid = crgetruid(cr);
	if (quot.op == Q_SYNC && vp == NULL) {
		ufsvfsp = NULL;
	} else if (quot.op != Q_ALLSYNC) {
		ufsvfsp = (struct ufsvfs *)(vp->v_vfsp->vfs_data);
	}
	switch (quot.op) {

	case Q_QUOTAON:
		rw_enter(&dq_rwlock, RW_WRITER);
		if (quotas_initialized == 0) {
			qtinit2();
			quotas_initialized = 1;
		}
		rw_exit(&dq_rwlock);
		error = opendq(ufsvfsp, vp, cr);
		break;

	case Q_QUOTAOFF:
		error = closedq(ufsvfsp, cr);
		if (!error) {
			invalidatedq(ufsvfsp);
		}
		break;

	case Q_SETQUOTA:
	case Q_SETQLIM:
		error = setquota(quot.op, (uid_t)quot.uid, ufsvfsp,
		    quot.addr, cr);
		break;

	case Q_GETQUOTA:
		error = getquota((uid_t)quot.uid, ufsvfsp, (caddr_t)quot.addr,
		    cr);
		break;

	case Q_SYNC:
		error = qsync(ufsvfsp);
		break;

	case Q_ALLSYNC:
		(void) qsync(NULL);
		break;

	default:
		error = EINVAL;
		break;
	}
	return (error);
}

static int
opendq_scan_inode(struct inode *ip, void *arg)
{
	struct ufsvfs *ufsvfsp = ip->i_ufsvfs;

	/*
	 * wrong file system or this is the quota inode; keep looking
	 */
	if (ufsvfsp != (struct ufsvfs *)arg || ip == ip->i_ufsvfs->vfs_qinod) {
		return (0);
	}

	ASSERT(RW_WRITE_HELD(&ufsvfsp->vfs_dqrwlock));
	rw_enter(&ip->i_contents, RW_WRITER);
	/*
	 * This inode is in the cache (by definition), is still valid,
	 * and is not a shadow inode or extended attribute directory inode,
	 * but does not have a quota so get the quota information.
	 */
	if (ip->i_mode && (ip->i_mode & IFMT) != IFSHAD &&
	    (ip->i_mode & IFMT) != IFATTRDIR && ip->i_dquot == NULL) {
		ip->i_dquot = getinoquota(ip);
	}
	rw_exit(&ip->i_contents);

	return (0);
}

/*
 * Set the quota file up for a particular file system.
 * Called as the result of a quotaon (Q_QUOTAON) ioctl.
 */
static int
opendq(
	struct ufsvfs *ufsvfsp,
	struct vnode *vp,		/* quota file */
	struct cred *cr)
{
	struct inode *qip;
	struct dquot *dqp;
	int error;
	int quotaon = 0;

	if (secpolicy_fs_quota(cr, ufsvfsp->vfs_vfs) != 0)
		return (EPERM);

	VN_HOLD(vp);

	/*
	 * Check to be sure its a regular file.
	 */
	if (vp->v_type != VREG) {
		VN_RELE(vp);
		return (EACCES);
	}

	rw_enter(&ufsvfsp->vfs_dqrwlock, RW_WRITER);

	/*
	 * We have vfs_dqrwlock as writer, so if quotas are disabled,
	 * then vfs_qinod should be NULL or we have a race somewhere.
	 */
	ASSERT((ufsvfsp->vfs_qflags & MQ_ENABLED) || (ufsvfsp->vfs_qinod == 0));

	if ((ufsvfsp->vfs_qflags & MQ_ENABLED) != 0) {
		/*
		 * Quotas are already enabled on this file system.
		 *
		 * If the "quotas" file was replaced (different inode)
		 * while quotas were enabled we don't want to re-enable
		 * them with a new "quotas" file. Simply print a warning
		 * message to the console, release the new vnode, and
		 * return.
		 * XXX - The right way to fix this is to return EBUSY
		 * for the ioctl() issued by 'quotaon'.
		 */
		if (VTOI(vp) != ufsvfsp->vfs_qinod) {
			cmn_err(CE_WARN, "Previous quota file still in use."
			    " Disable quotas on %s before enabling.\n",
			    VTOI(vp)->i_fs->fs_fsmnt);
			VN_RELE(vp);
			rw_exit(&ufsvfsp->vfs_dqrwlock);
			return (0);
		}
		(void) quotasync(ufsvfsp, /* do_lock */ 0);
		/* remove extra hold on quota file */
		VN_RELE(vp);
		quotaon++;
		qip = ufsvfsp->vfs_qinod;
	} else {
		int qlen;

		ufsvfsp->vfs_qinod = VTOI(vp);
		qip = ufsvfsp->vfs_qinod;
		/*
		 * Force the file to have no partially allocated blocks
		 * to prevent a realloc from changing the location of
		 * the data. We must do this even if not logging in
		 * case we later remount to logging.
		 */
		qlen = qip->i_fs->fs_bsize * NDADDR;

		/*
		 * Largefiles: i_size needs to be atomically accessed now.
		 */
		rw_enter(&qip->i_contents, RW_WRITER);
		if (qip->i_size < qlen) {
			if (ufs_itrunc(qip, (u_offset_t)qlen, (int)0, cr) != 0)
				cmn_err(CE_WARN, "opendq failed to remove frags"
				    " from quota file\n");
			rw_exit(&qip->i_contents);
			(void) VOP_PUTPAGE(vp, (offset_t)0, (size_t)qip->i_size,
			    B_INVAL, kcred, NULL);
		} else {
			rw_exit(&qip->i_contents);
		}
		TRANS_MATA_IGET(ufsvfsp, qip);
	}

	/*
	 * The file system time limits are in the dquot for uid 0.
	 * The time limits set the relative time the other users
	 * can be over quota for this file system.
	 * If it is zero a default is used (see quota.h).
	 */
	error = getdiskquota((uid_t)0, ufsvfsp, 1, &dqp);
	if (error == 0) {
		mutex_enter(&dqp->dq_lock);
		ufsvfsp->vfs_btimelimit =
		    (dqp->dq_btimelimit? dqp->dq_btimelimit: DQ_BTIMELIMIT);
		ufsvfsp->vfs_ftimelimit =
		    (dqp->dq_ftimelimit? dqp->dq_ftimelimit: DQ_FTIMELIMIT);

		ufsvfsp->vfs_qflags = MQ_ENABLED;	/* enable quotas */
		vfs_setmntopt(ufsvfsp->vfs_vfs, MNTOPT_QUOTA, NULL, 0);
		dqput(dqp);
		mutex_exit(&dqp->dq_lock);
	} else if (!quotaon) {
		/*
		 * Some sort of I/O error on the quota file, and quotas were
		 * not already on when we got here so clean up.
		 */
		ufsvfsp->vfs_qflags = 0;
		ufsvfsp->vfs_qinod = NULL;
		VN_RELE(ITOV(qip));
	}

	/*
	 * If quotas are enabled update all valid inodes in the
	 * cache with quota information.
	 */
	if (ufsvfsp->vfs_qflags & MQ_ENABLED) {
		(void) ufs_scan_inodes(0, opendq_scan_inode, ufsvfsp, ufsvfsp);
	}

	rw_exit(&ufsvfsp->vfs_dqrwlock);
	return (error);
}

static int
closedq_scan_inode(struct inode *ip, void *arg)
{
	struct dquot *dqp;
	struct ufsvfs *ufsvfsp = ip->i_ufsvfs;

	/*
	 * wrong file system; keep looking
	 */
	if (ufsvfsp != (struct ufsvfs *)arg)
		return (0);

	ASSERT(RW_WRITE_HELD(&ufsvfsp->vfs_dqrwlock));
	rw_enter(&ip->i_contents, RW_WRITER);

	/*
	 * Shadow inodes and extended attribute directories
	 * do not have quota info records.
	 */
	if ((dqp = ip->i_dquot) != NULL) {
		ASSERT((ip->i_mode & IFMT) != IFSHAD);
		ASSERT((ip->i_mode & IFMT) != IFATTRDIR);
		ip->i_dquot = NULL;
		mutex_enter(&dqp->dq_lock);
		dqput(dqp);

		/*
		 * If we have a pending logging file system quota
		 * transaction, then cancel it.  Clear the flag to
		 * prevent ufs_trans_push_quota() from trying to
		 * deal with this transaction just in case it is
		 * waiting for the mutex.  We decrement the counter
		 * since the transaction won't be needing the quota
		 * info record anymore.
		 */
		if (dqp->dq_flags & DQ_TRANS) {
			dqp->dq_flags &= ~DQ_TRANS;
			dqput(dqp);
		}
		mutex_exit(&dqp->dq_lock);
	}
	rw_exit(&ip->i_contents);

	return (0);
}

/*
 * Close off disk quotas for a file system.
 */
int
closedq(struct ufsvfs *ufsvfsp, struct cred *cr)
{
	struct inode *qip;

	if (secpolicy_fs_quota(cr, ufsvfsp->vfs_vfs) != 0)
		return (EPERM);

	rw_enter(&ufsvfsp->vfs_dqrwlock, RW_WRITER);

	/*
	 * Quotas are not enabled on this file system so there is
	 * nothing more to do.
	 */
	if ((ufsvfsp->vfs_qflags & MQ_ENABLED) == 0) {
		rw_exit(&ufsvfsp->vfs_dqrwlock);
		return (0);
	}

	/*
	 * At this point, the quota subsystem is quiescent on this file
	 * system so we can do all the work necessary to dismantle the
	 * quota stuff.
	 */
	qip = ufsvfsp->vfs_qinod;
	if (!qip)
		return (ufs_fault(ufsvfsp->vfs_root, "closedq: NULL qip"));

	ufsvfsp->vfs_qflags = 0;	/* disable quotas */
	vfs_setmntopt(ufsvfsp->vfs_vfs, MNTOPT_NOQUOTA, NULL, 0);

	/*
	 * ufs_scan_inodes() depends on vfs_qinod, so we can't
	 * clear it until afterwards.
	 */
	(void) ufs_scan_inodes(0, closedq_scan_inode, ufsvfsp, ufsvfsp);

	ufsvfsp->vfs_qinod = NULL;
	rw_exit(&ufsvfsp->vfs_dqrwlock);

	/*
	 * Sync and release the quota file inode. Since we have a private
	 * pointer to the quota inode and vfs_qinod is now clear we do not
	 * need to hold vfs_dqrwlock.
	 */
	(void) TRANS_SYNCIP(qip, 0, I_SYNC, TOP_SYNCIP_CLOSEDQ);
	VN_RELE(ITOV(qip));
	return (0);
}

/*
 * Private data between setquota() and setquota_scan_inode().
 */
struct setquota_data {
#define	SQD_TYPE_NONE		0
#define	SQD_TYPE_LIMIT		1
#define	SQD_TYPE_NO_LIMIT	2
	int sqd_type;
	struct ufsvfs *sqd_ufsvfsp;
	uid_t sqd_uid;
};

static int
setquota_scan_inode(struct inode *ip, void *arg)
{
	struct setquota_data *sqdp = (struct setquota_data *)arg;
	struct ufsvfs *ufsvfsp = ip->i_ufsvfs;

	/*
	 * wrong file system; keep looking
	 */
	if (ufsvfsp != sqdp->sqd_ufsvfsp)
		return (0);

	ASSERT(RW_WRITE_HELD(&ufsvfsp->vfs_dqrwlock));

	/*
	 * The file system does not have quotas enabled or this is the
	 * file system's quota inode; keep looking.
	 */
	if ((ufsvfsp->vfs_qflags & MQ_ENABLED) == 0 ||
	    ip == ufsvfsp->vfs_qinod) {
		return (0);
	}

	rw_enter(&ip->i_contents, RW_WRITER);
	/*
	 * This inode is in the cache (by definition), is still valid,
	 * is not a shadow inode or extended attribute directory inode
	 * and has the right uid.
	 */
	if (ip->i_mode && (ip->i_mode & IFMT) != IFSHAD &&
	    (ip->i_mode & IFMT) != IFATTRDIR && ip->i_uid == sqdp->sqd_uid) {
		/*
		 * Transition is "no limit" to "at least one limit":
		 */
		if (sqdp->sqd_type == SQD_TYPE_LIMIT &&
		    ip->i_dquot == NULL) {
			ip->i_dquot = getinoquota(ip);
		}
		/*
		 * Transition is "at least one limit" to "no limit":
		 */
		else if (sqdp->sqd_type == SQD_TYPE_NO_LIMIT && ip->i_dquot) {
			mutex_enter(&ip->i_dquot->dq_lock);
			dqput(ip->i_dquot);
			mutex_exit(&ip->i_dquot->dq_lock);
			ip->i_dquot = NULL;
		}
	}
	rw_exit(&ip->i_contents);

	return (0);
}

/*
 * Set various fields of the dqblk according to the command.
 * Q_SETQUOTA - assign an entire dqblk structure.
 * Q_SETQLIM - assign a dqblk structure except for the usage.
 */
static int
setquota(int cmd, uid_t uid, struct ufsvfs *ufsvfsp,
    caddr_t addr, struct cred *cr)
{
	struct dquot *dqp;
	struct inode	*qip;
	struct dquot *xdqp;
	struct dqblk newlim;
	int error;
	int scan_type = SQD_TYPE_NONE;
	daddr_t bn;
	int contig;

	if (secpolicy_fs_quota(cr, ufsvfsp->vfs_vfs) != 0)
		return (EPERM);

	rw_enter(&ufsvfsp->vfs_dqrwlock, RW_WRITER);

	/*
	 * Quotas are not enabled on this file system so there is
	 * nothing more to do.
	 */
	if ((ufsvfsp->vfs_qflags & MQ_ENABLED) == 0) {
		rw_exit(&ufsvfsp->vfs_dqrwlock);
		return (ESRCH);
	}

	/*
	 * At this point, the quota subsystem is quiescent on this file
	 * system so we can do all the work necessary to modify the quota
	 * information for this user.
	 */

	if (copyin(addr, (caddr_t)&newlim, sizeof (struct dqblk)) != 0) {
		rw_exit(&ufsvfsp->vfs_dqrwlock);
		return (EFAULT);
	}
	error = getdiskquota(uid, ufsvfsp, 0, &xdqp);
	if (error) {
		rw_exit(&ufsvfsp->vfs_dqrwlock);
		return (error);
	}
	dqp = xdqp;
	/*
	 * Don't change disk usage on Q_SETQLIM
	 */
	mutex_enter(&dqp->dq_lock);
	if (cmd == Q_SETQLIM) {
		newlim.dqb_curblocks = dqp->dq_curblocks;
		newlim.dqb_curfiles = dqp->dq_curfiles;
	}
	if (uid == 0) {
		/*
		 * Timelimits for uid 0 set the relative time
		 * the other users can be over quota for this file system.
		 * If it is zero a default is used (see quota.h).
		 */
		ufsvfsp->vfs_btimelimit =
		    newlim.dqb_btimelimit? newlim.dqb_btimelimit: DQ_BTIMELIMIT;
		ufsvfsp->vfs_ftimelimit =
		    newlim.dqb_ftimelimit? newlim.dqb_ftimelimit: DQ_FTIMELIMIT;
	} else {
		if (newlim.dqb_bsoftlimit &&
		    newlim.dqb_curblocks >= newlim.dqb_bsoftlimit) {
			if (dqp->dq_bsoftlimit == 0 ||
			    dqp->dq_curblocks < dqp->dq_bsoftlimit) {
				/* If we're suddenly over the limit(s),	*/
				/* start the timer(s)			*/
				newlim.dqb_btimelimit =
				    (uint32_t)gethrestime_sec() +
				    ufsvfsp->vfs_btimelimit;
				dqp->dq_flags &= ~DQ_BLKS;
			} else {
				/* If we're currently over the soft	*/
				/* limit and were previously over the	*/
				/* soft limit then preserve the old	*/
				/* time limit but make sure the DQ_BLKS	*/
				/* flag is set since we must have been	*/
				/* previously warned.			*/
				newlim.dqb_btimelimit = dqp->dq_btimelimit;
				dqp->dq_flags |= DQ_BLKS;
			}
		} else {
			/* Either no quota or under quota, clear time limit */
			newlim.dqb_btimelimit = 0;
			dqp->dq_flags &= ~DQ_BLKS;
		}

		if (newlim.dqb_fsoftlimit &&
		    newlim.dqb_curfiles >= newlim.dqb_fsoftlimit) {
			if (dqp->dq_fsoftlimit == 0 ||
			    dqp->dq_curfiles < dqp->dq_fsoftlimit) {
				/* If we're suddenly over the limit(s),	*/
				/* start the timer(s)			*/
				newlim.dqb_ftimelimit =
				    (uint32_t)gethrestime_sec() +
				    ufsvfsp->vfs_ftimelimit;
				dqp->dq_flags &= ~DQ_FILES;
			} else {
				/* If we're currently over the soft	*/
				/* limit and were previously over the	*/
				/* soft limit then preserve the old	*/
				/* time limit but make sure the		*/
				/* DQ_FILES flag is set since we must	*/
				/* have been previously warned.		*/
				newlim.dqb_ftimelimit = dqp->dq_ftimelimit;
				dqp->dq_flags |= DQ_FILES;
			}
		} else {
			/* Either no quota or under quota, clear time limit */
			newlim.dqb_ftimelimit = 0;
			dqp->dq_flags &= ~DQ_FILES;
		}
	}

	/*
	 * If there was previously no limit and there is now at least
	 * one limit, then any inodes in the cache have NULL d_iquot
	 * fields (getinoquota() returns NULL when there are no limits).
	 */
	if ((dqp->dq_fhardlimit == 0 && dqp->dq_fsoftlimit == 0 &&
	    dqp->dq_bhardlimit == 0 && dqp->dq_bsoftlimit == 0) &&
	    (newlim.dqb_fhardlimit || newlim.dqb_fsoftlimit ||
	    newlim.dqb_bhardlimit || newlim.dqb_bsoftlimit)) {
		scan_type = SQD_TYPE_LIMIT;
	}

	/*
	 * If there was previously at least one limit and there is now
	 * no limit, then any inodes in the cache have non-NULL d_iquot
	 * fields need to be reset to NULL.
	 */
	else if ((dqp->dq_fhardlimit || dqp->dq_fsoftlimit ||
	    dqp->dq_bhardlimit || dqp->dq_bsoftlimit) &&
	    (newlim.dqb_fhardlimit == 0 && newlim.dqb_fsoftlimit == 0 &&
	    newlim.dqb_bhardlimit == 0 && newlim.dqb_bsoftlimit == 0)) {
		scan_type = SQD_TYPE_NO_LIMIT;
	}

	dqp->dq_dqb = newlim;
	dqp->dq_flags |= DQ_MOD;

	/*
	 *  push the new quota to disk now.  If this is a trans device
	 *  then force the page out with ufs_putpage so it will be deltaed
	 *  by ufs_startio.
	 */
	qip = ufsvfsp->vfs_qinod;
	rw_enter(&qip->i_contents, RW_WRITER);
	(void) ufs_rdwri(UIO_WRITE, FWRITE | FSYNC, qip, (caddr_t)&dqp->dq_dqb,
	    sizeof (struct dqblk), dqoff(uid), UIO_SYSSPACE,
	    (int *)NULL, kcred);
	rw_exit(&qip->i_contents);

	(void) VOP_PUTPAGE(ITOV(qip), dqoff(dqp->dq_uid) & ~qip->i_fs->fs_bmask,
	    qip->i_fs->fs_bsize, B_INVAL, kcred, NULL);

	/*
	 * We must set the dq_mof even if not we are not logging in case
	 * we are later remount to logging.
	 */
	contig = 0;
	rw_enter(&qip->i_contents, RW_WRITER);
	error = bmap_read(qip, dqoff(dqp->dq_uid), &bn, &contig);
	rw_exit(&qip->i_contents);
	if (error || (bn == UFS_HOLE)) {
		dqp->dq_mof = UFS_HOLE;
	} else {
		dqp->dq_mof = ldbtob(bn) +
		    (offset_t)((dqoff(dqp->dq_uid)) & (DEV_BSIZE - 1));
	}

	dqp->dq_flags &= ~DQ_MOD;
	dqput(dqp);
	mutex_exit(&dqp->dq_lock);
	if (scan_type) {
		struct setquota_data sqd;

		sqd.sqd_type = scan_type;
		sqd.sqd_ufsvfsp = ufsvfsp;
		sqd.sqd_uid = uid;
		(void) ufs_scan_inodes(0, setquota_scan_inode, &sqd, ufsvfsp);
	}
	rw_exit(&ufsvfsp->vfs_dqrwlock);
	return (0);
}

/*
 * Q_GETQUOTA - return current values in a dqblk structure.
 */
static int
getquota(uid_t uid, struct ufsvfs *ufsvfsp, caddr_t addr, cred_t *cr)
{
	struct dquot *dqp;
	struct dquot *xdqp;
	struct dqblk dqb;
	int error = 0;

	if (uid != crgetruid(cr) &&
	    secpolicy_fs_quota(cr, ufsvfsp->vfs_vfs) != 0)
		return (EPERM);
	rw_enter(&ufsvfsp->vfs_dqrwlock, RW_READER);
	if ((ufsvfsp->vfs_qflags & MQ_ENABLED) == 0) {
		rw_exit(&ufsvfsp->vfs_dqrwlock);
		return (ESRCH);
	}
	error = getdiskquota(uid, ufsvfsp, 0, &xdqp);
	if (error) {
		rw_exit(&ufsvfsp->vfs_dqrwlock);
		return (error);
	}
	dqp = xdqp;
	mutex_enter(&dqp->dq_lock);
	if (dqp->dq_fhardlimit == 0 && dqp->dq_fsoftlimit == 0 &&
	    dqp->dq_bhardlimit == 0 && dqp->dq_bsoftlimit == 0) {
		error = ESRCH;
	} else {
		bcopy(&dqp->dq_dqb, &dqb, sizeof (struct dqblk));
	}
	dqput(dqp);
	mutex_exit(&dqp->dq_lock);
	rw_exit(&ufsvfsp->vfs_dqrwlock);
	if (error == 0 && copyout(&dqb, addr, sizeof (struct dqblk)) != 0)
		error = EFAULT;
	return (error);
}

/*
 * Q_SYNC - sync quota files to disk.
 */
int
qsync(struct ufsvfs *ufsvfsp)
{
	return (quotasync(ufsvfsp, /* do_lock */ 1));
}

/*
 * Sync quota information records to disk for the specified file system
 * or all file systems with quotas if ufsvfsp == NULL.  Grabs a reader
 * lock on vfs_dqrwlock if it is needed.
 *
 * Currently, if ufsvfsp is NULL, then do_lock is always true, but the
 * routine is coded to account for either do_lock value.  This seemed
 * to be the safer thing to do.
 */
int
quotasync(struct ufsvfs *ufsvfsp, int do_lock)
{
	struct dquot *dqp;

	rw_enter(&dq_rwlock, RW_READER);
	if (!quotas_initialized) {
		rw_exit(&dq_rwlock);
		return (ESRCH);
	}
	rw_exit(&dq_rwlock);

	/*
	 * The operation applies to a specific file system only.
	 */
	if (ufsvfsp) {
		if (do_lock) {
			rw_enter(&ufsvfsp->vfs_dqrwlock, RW_READER);
		}

		/*
		 * Quotas are not enabled on this file system so bail.
		 */
		if ((ufsvfsp->vfs_qflags & MQ_ENABLED) == 0) {
			if (do_lock) {
				rw_exit(&ufsvfsp->vfs_dqrwlock);
			}
			return (ESRCH);
		}

		/*
		 * This operation is a no-op on a logging file system because
		 * quota information is treated as metadata and is in the log.
		 * This code path treats quota information as user data which
		 * is not necessary on a logging file system.
		 */
		if (TRANS_ISTRANS(ufsvfsp)) {
			if (do_lock) {
				rw_exit(&ufsvfsp->vfs_dqrwlock);
			}
			return (0);
		}

		/*
		 * Try to sync all the quota info records for this
		 * file system:
		 */
		for (dqp = dquot; dqp < dquotNDQUOT; dqp++) {
			/*
			 * If someone else has it, then ignore it.
			 */
			if (!mutex_tryenter(&dqp->dq_lock)) {
				continue;
			}

			/*
			 * The quota info record is for this file system
			 * and it has changes.
			 */
			if (dqp->dq_ufsvfsp == ufsvfsp &&
			    (dqp->dq_flags & DQ_MOD)) {
				ASSERT(ufsvfsp->vfs_qflags & MQ_ENABLED);
				dqupdate(dqp);
			}

			mutex_exit(&dqp->dq_lock);
		}
		if (do_lock) {
			rw_exit(&ufsvfsp->vfs_dqrwlock);
		}

		return (0);
	}

	/*
	 * Try to sync all the quota info records for *all* file systems
	 * for which quotas are enabled.
	 */
	for (dqp = dquot; dqp < dquotNDQUOT; dqp++) {
		/*
		 * If someone else has it, then ignore it.
		 */
		if (!mutex_tryenter(&dqp->dq_lock)) {
			continue;
		}

		ufsvfsp = dqp->dq_ufsvfsp;	/* shorthand */

		/*
		 * This quota info record has no changes or is
		 * not a valid quota info record yet.
		 */
		if ((dqp->dq_flags & DQ_MOD) == 0 || ufsvfsp == NULL) {
			mutex_exit(&dqp->dq_lock);
			continue;
		}

		/*
		 * Now we have a potential lock order problem:
		 *
		 *	vfs_dqrwlock > dq_lock
		 *
		 * so if we have to get vfs_dqrwlock, then go thru hoops
		 * to avoid deadlock.  If we cannot get the order right,
		 * then we ignore this quota info record.
		 */
		if (do_lock) {
			/*
			 * If we can't grab vfs_dqrwlock, then we don't
			 * want to wait to avoid deadlock.
			 */
			if (rw_tryenter(&ufsvfsp->vfs_dqrwlock,
			    RW_READER) == 0) {
				mutex_exit(&dqp->dq_lock);
				continue;
			}
			/*
			 * Okay, now we have both dq_lock and vfs_dqrwlock.
			 * We should not deadlock for the following reasons:
			 * - If another thread has a reader lock on
			 *   vfs_dqrwlock and is waiting for dq_lock,
			 *   there is no conflict because we can also have
			 *   a reader lock on vfs_dqrwlock.
			 * - If another thread has a writer lock on
			 *   vfs_dqrwlock and is waiting for dq_lock,
			 *   we would have failed the rw_tryenter() above
			 *   and given up dq_lock.
			 * - Since we have dq_lock another thread cannot
			 *   have it and be waiting for vfs_dqrwlock.
			 */
		}

		/*
		 * Since we got to this file system via a quota info
		 * record and we have vfs_dqrwlock this is paranoia
		 * to make sure that quotas are enabled.
		 */
		ASSERT(ufsvfsp->vfs_qflags & MQ_ENABLED);

		/*
		 * We are not logging.  See above logging file system
		 * comment.
		 */
		if (!TRANS_ISTRANS(ufsvfsp)) {
			dqupdate(dqp);
		}

		/*
		 * Since we have a private copy of dqp->dq_ufsvfsp,
		 * we can drop dq_lock now.
		 */
		mutex_exit(&dqp->dq_lock);

		if (do_lock) {
			rw_exit(&ufsvfsp->vfs_dqrwlock);
		}
	}

	return (0);
}
