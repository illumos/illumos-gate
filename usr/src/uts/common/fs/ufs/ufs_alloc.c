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

#include <sys/condvar_impl.h>
#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/debug.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/signal.h>
#include <sys/cred.h>
#include <sys/proc.h>
#include <sys/disp.h>
#include <sys/user.h>
#include <sys/buf.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/acl.h>
#include <sys/fs/ufs_fs.h>
#include <sys/fs/ufs_inode.h>
#include <sys/fs/ufs_acl.h>
#include <sys/fs/ufs_bio.h>
#include <sys/fs/ufs_quota.h>
#include <sys/kmem.h>
#include <sys/fs/ufs_trans.h>
#include <sys/fs/ufs_panic.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/sysmacros.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <sys/flock.h>
#include <fs/fs_subr.h>
#include <sys/cmn_err.h>
#include <sys/policy.h>
#include <sys/fs/ufs_log.h>

static ino_t	hashalloc();
static daddr_t	fragextend();
static daddr_t	alloccg();
static daddr_t	alloccgblk();
static ino_t	ialloccg();
static daddr_t	mapsearch();
static int	findlogstartcg();

extern int	inside[], around[];
extern uchar_t	*fragtbl[];
void delay();

/*
 * Allocate a block in the file system.
 *
 * The size of the requested block is given, which must be some
 * multiple of fs_fsize and <= fs_bsize.
 * A preference may be optionally specified. If a preference is given
 * the following hierarchy is used to allocate a block:
 *   1) allocate the requested block.
 *   2) allocate a rotationally optimal block in the same cylinder.
 *   3) allocate a block in the same cylinder group.
 *   4) quadratically rehash into other cylinder groups, until an
 *	available block is located.
 * If no block preference is given the following hierarchy is used
 * to allocate a block:
 *   1) allocate a block in the cylinder group that contains the
 *	inode for the file.
 *   2) quadratically rehash into other cylinder groups, until an
 *	available block is located.
 */
int
alloc(struct inode *ip, daddr_t bpref, int size, daddr_t *bnp, cred_t *cr)
{
	struct fs *fs;
	struct ufsvfs *ufsvfsp;
	daddr_t bno;
	int cg;
	int err;
	char *errmsg = NULL;
	size_t len;
	clock_t	now;

	ufsvfsp = ip->i_ufsvfs;
	fs = ufsvfsp->vfs_fs;
	if ((unsigned)size > fs->fs_bsize || fragoff(fs, size) != 0) {
		err = ufs_fault(ITOV(ip), "alloc: bad size, dev = 0x%lx,"
		    " bsize = %d, size = %d, fs = %s\n",
		    ip->i_dev, fs->fs_bsize, size, fs->fs_fsmnt);
		return (err);
	}
	if (size == fs->fs_bsize && fs->fs_cstotal.cs_nbfree == 0)
		goto nospace;
	if (freespace(fs, ufsvfsp) <= 0 &&
	    secpolicy_fs_minfree(cr, ufsvfsp->vfs_vfs) != 0)
		goto nospace;
	err = chkdq(ip, (long)btodb(size), 0, cr, &errmsg, &len);
	/* Note that may not have err, but may have errmsg */
	if (errmsg != NULL) {
		uprintf(errmsg);
		kmem_free(errmsg, len);
		errmsg = NULL;
	}
	if (err)
		return (err);
	if (bpref >= fs->fs_size)
		bpref = 0;
	if (bpref == 0)
		cg = (int)itog(fs, ip->i_number);
	else
		cg = dtog(fs, bpref);

	bno = (daddr_t)hashalloc(ip, cg, (long)bpref, size,
	    (ulong_t (*)())alloccg);
	if (bno > 0) {
		*bnp = bno;
		return (0);
	}

	/*
	 * hashalloc() failed because some other thread grabbed
	 * the last block so unwind the quota operation.  We can
	 * ignore the return because subtractions don't fail and
	 * size is guaranteed to be >= zero by our caller.
	 */
	(void) chkdq(ip, -(long)btodb(size), 0, cr, (char **)NULL,
	    (size_t *)NULL);

nospace:
	now = ddi_get_lbolt();
	mutex_enter(&ufsvfsp->vfs_lock);
	if ((now - ufsvfsp->vfs_lastwhinetime) > (hz << 2) &&
	    (!(TRANS_ISTRANS(ufsvfsp)) || !(ip->i_flag & IQUIET))) {
		ufsvfsp->vfs_lastwhinetime = now;
		cmn_err(CE_NOTE, "alloc: %s: file system full", fs->fs_fsmnt);
	}
	mutex_exit(&ufsvfsp->vfs_lock);
	return (ENOSPC);
}

/*
 * Reallocate a fragment to a bigger size
 *
 * The number and size of the old block is given, and a preference
 * and new size is also specified.  The allocator attempts to extend
 * the original block.  Failing that, the regular block allocator is
 * invoked to get an appropriate block.
 */
int
realloccg(struct inode *ip, daddr_t bprev, daddr_t bpref, int osize,
    int nsize, daddr_t *bnp, cred_t *cr)
{
	daddr_t bno;
	struct fs *fs;
	struct ufsvfs *ufsvfsp;
	int cg, request;
	int err;
	char *errmsg = NULL;
	size_t len;
	clock_t	now;

	ufsvfsp = ip->i_ufsvfs;
	fs = ufsvfsp->vfs_fs;
	if ((unsigned)osize > fs->fs_bsize || fragoff(fs, osize) != 0 ||
	    (unsigned)nsize > fs->fs_bsize || fragoff(fs, nsize) != 0) {
		err = ufs_fault(ITOV(ip),
		    "realloccg: bad size, dev=0x%lx, bsize=%d, "
		    "osize=%d, nsize=%d, fs=%s\n",
		    ip->i_dev, fs->fs_bsize, osize, nsize, fs->fs_fsmnt);
		return (err);
	}
	if (freespace(fs, ufsvfsp) <= 0 &&
	    secpolicy_fs_minfree(cr, ufsvfsp->vfs_vfs) != 0)
		goto nospace;
	if (bprev == 0) {
		err = ufs_fault(ITOV(ip),
		    "realloccg: bad bprev, dev = 0x%lx, bsize = %d,"
		    " bprev = %ld, fs = %s\n", ip->i_dev, fs->fs_bsize, bprev,
		    fs->fs_fsmnt);
		return (err);
	}
	err = chkdq(ip, (long)btodb(nsize - osize), 0, cr, &errmsg, &len);
	/* Note that may not have err, but may have errmsg */
	if (errmsg != NULL) {
		uprintf(errmsg);
		kmem_free(errmsg, len);
		errmsg = NULL;
	}
	if (err)
		return (err);
	cg = dtog(fs, bprev);
	bno = fragextend(ip, cg, (long)bprev, osize, nsize);
	if (bno != 0) {
		*bnp = bno;
		return (0);
	}
	if (bpref >= fs->fs_size)
		bpref = 0;

	/*
	 * When optimizing for time we allocate a full block and
	 * then only use the upper portion for this request. When
	 * this file grows again it will grow into the unused portion
	 * of the block (See fragextend() above).  This saves time
	 * because an extra disk write would be needed if the frags
	 * following the current allocation were not free. The extra
	 * disk write is needed to move the data from its current
	 * location into the newly allocated position.
	 *
	 * When optimizing for space we allocate a run of frags
	 * that is just the right size for this request.
	 */
	request = (fs->fs_optim == FS_OPTTIME) ? fs->fs_bsize : nsize;
	bno = (daddr_t)hashalloc(ip, cg, (long)bpref, request,
	    (ulong_t (*)())alloccg);
	if (bno > 0) {
		*bnp = bno;
		if (nsize < request)
			(void) free(ip, bno + numfrags(fs, nsize),
			    (off_t)(request - nsize), I_NOCANCEL);
		return (0);
	}

	/*
	 * hashalloc() failed because some other thread grabbed
	 * the last block so unwind the quota operation.  We can
	 * ignore the return because subtractions don't fail, and
	 * our caller guarantees nsize >= osize.
	 */
	(void) chkdq(ip, -(long)btodb(nsize - osize), 0, cr, (char **)NULL,
	    (size_t *)NULL);

nospace:
	now = ddi_get_lbolt();
	mutex_enter(&ufsvfsp->vfs_lock);
	if ((now - ufsvfsp->vfs_lastwhinetime) > (hz << 2) &&
	    (!(TRANS_ISTRANS(ufsvfsp)) || !(ip->i_flag & IQUIET))) {
		ufsvfsp->vfs_lastwhinetime = now;
		cmn_err(CE_NOTE,
		    "realloccg %s: file system full", fs->fs_fsmnt);
	}
	mutex_exit(&ufsvfsp->vfs_lock);
	return (ENOSPC);
}

/*
 * Allocate an inode in the file system.
 *
 * A preference may be optionally specified. If a preference is given
 * the following hierarchy is used to allocate an inode:
 *   1) allocate the requested inode.
 *   2) allocate an inode in the same cylinder group.
 *   3) quadratically rehash into other cylinder groups, until an
 *	available inode is located.
 * If no inode preference is given the following hierarchy is used
 * to allocate an inode:
 *   1) allocate an inode in cylinder group 0.
 *   2) quadratically rehash into other cylinder groups, until an
 *	available inode is located.
 */
int
ufs_ialloc(struct inode *pip,
    ino_t ipref, mode_t mode, struct inode **ipp, cred_t *cr)
{
	struct inode *ip;
	struct fs *fs;
	int cg;
	ino_t ino;
	int err;
	int nifree;
	struct ufsvfs *ufsvfsp = pip->i_ufsvfs;
	char *errmsg = NULL;
	size_t len;

	ASSERT(RW_WRITE_HELD(&pip->i_rwlock));
	fs = pip->i_fs;
loop:
	nifree = fs->fs_cstotal.cs_nifree;

	if (nifree == 0)
		goto noinodes;
	/*
	 * Shadow inodes don't count against a user's inode allocation.
	 * They are an implementation method and not a resource.
	 */
	if ((mode != IFSHAD) && (mode != IFATTRDIR)) {
		err = chkiq((struct ufsvfs *)ITOV(pip)->v_vfsp->vfs_data,
		    /* change */ 1, (struct inode *)NULL, crgetuid(cr), 0,
		    cr, &errmsg, &len);
		/*
		 * As we haven't acquired any locks yet, dump the message
		 * now.
		 */
		if (errmsg != NULL) {
			uprintf(errmsg);
			kmem_free(errmsg, len);
			errmsg = NULL;
		}
		if (err)
			return (err);
	}

	if (ipref >= (ulong_t)(fs->fs_ncg * fs->fs_ipg))
		ipref = 0;
	cg = (int)itog(fs, ipref);
	ino = (ino_t)hashalloc(pip, cg, (long)ipref, (int)mode,
	    (ulong_t (*)())ialloccg);
	if (ino == 0) {
		if ((mode != IFSHAD) && (mode != IFATTRDIR)) {
			/*
			 * We can safely ignore the return from chkiq()
			 * because deallocations can only fail if we
			 * can't get the user's quota info record off
			 * the disk due to an I/O error.  In that case,
			 * the quota subsystem is already messed up.
			 */
			(void) chkiq(ufsvfsp, /* change */ -1,
			    (struct inode *)NULL, crgetuid(cr), 0, cr,
			    (char **)NULL, (size_t *)NULL);
		}
		goto noinodes;
	}
	err = ufs_iget(pip->i_vfs, ino, ipp, cr);
	if (err) {
		if ((mode != IFSHAD) && (mode != IFATTRDIR)) {
			/*
			 * See above comment about why it is safe to ignore an
			 * error return here.
			 */
			(void) chkiq(ufsvfsp, /* change */ -1,
			    (struct inode *)NULL, crgetuid(cr), 0, cr,
			    (char **)NULL, (size_t *)NULL);
		}
		ufs_ifree(pip, ino, 0);
		return (err);
	}
	ip = *ipp;
	ASSERT(!ip->i_ufs_acl);
	ASSERT(!ip->i_dquot);
	rw_enter(&ip->i_contents, RW_WRITER);

	/*
	 * Check if we really got a free inode, if not then complain
	 * and mark the inode ISTALE so that it will be freed by the
	 * ufs idle thread eventually and will not be sent to ufs_delete().
	 */
	if (ip->i_mode || (ip->i_nlink > 0)) {
		ip->i_flag |= ISTALE;
		rw_exit(&ip->i_contents);
		VN_RELE(ITOV(ip));
		cmn_err(CE_WARN,
		    "%s: unexpected allocated inode %d, run fsck(1M)%s",
		    fs->fs_fsmnt, (int)ino,
		    (TRANS_ISTRANS(ufsvfsp) ? " -o f" : ""));
		goto loop;
	}

	/*
	 * Check the inode has no size or data blocks.
	 * This could have happened if the truncation failed when
	 * deleting the inode. It used to be possible for this to occur
	 * if a block allocation failed when iteratively truncating a
	 * large file using logging and with a full file system.
	 * This was fixed with bug fix 4348738. However, truncation may
	 * still fail on an IO error. So in all cases for safety and
	 * security we clear out the size; the blocks allocated; and
	 * pointers to the blocks. This will ultimately cause a fsck
	 * error of un-accounted for blocks, but its a fairly benign error,
	 * and possibly the correct thing to do anyway as accesssing those
	 * blocks agains may lead to more IO errors.
	 */
	if (ip->i_size || ip->i_blocks) {
		int i;

		if (ip->i_size) {
			cmn_err(CE_WARN,
			    "%s: free inode %d had size 0x%llx, run fsck(1M)%s",
			    fs->fs_fsmnt, (int)ino, ip->i_size,
			    (TRANS_ISTRANS(ufsvfsp) ? " -o f" : ""));
		}
		/*
		 * Clear any garbage left behind.
		 */
		ip->i_size = (u_offset_t)0;
		ip->i_blocks = 0;
		for (i = 0; i < NDADDR; i++)
			ip->i_db[i] = 0;
		for (i = 0; i < NIADDR; i++)
			ip->i_ib[i] = 0;
	}

	/*
	 * Initialize the link count
	 */
	ip->i_nlink = 0;

	/*
	 * Clear the old flags
	 */
	ip->i_flag &= IREF;

	/*
	 * Access times are not really defined if the fs is mounted
	 * with 'noatime'. But it can cause nfs clients to fail
	 * open() if the atime is not a legal value. Set a legal value
	 * here when the inode is allocated.
	 */
	if (ufsvfsp->vfs_noatime) {
		mutex_enter(&ufs_iuniqtime_lock);
		ip->i_atime = iuniqtime;
		mutex_exit(&ufs_iuniqtime_lock);
	}
	rw_exit(&ip->i_contents);
	return (0);
noinodes:
	if (!(TRANS_ISTRANS(ufsvfsp)) || !(pip->i_flag & IQUIET))
		cmn_err(CE_NOTE, "%s: out of inodes\n", fs->fs_fsmnt);
	return (ENOSPC);
}

/*
 * Find a cylinder group to place a directory.
 * Returns an inumber within the selected cylinder group.
 * Note, the vfs_lock is not needed as we don't require exact cg summary info.
 *
 * If the switch ufs_close_dirs is set, then the policy is to use
 * the current cg if it has more than 25% free inodes and more
 * than 25% free blocks. Otherwise the cgs are searched from
 * the beginning and the first cg with the same criteria is
 * used. If that is also null then we revert to the old algorithm.
 * This tends to cluster files at the beginning of the disk
 * until the disk gets full.
 *
 * Otherwise if ufs_close_dirs is not set then the original policy is
 * used which is to select from among those cylinder groups with
 * above the average number of free inodes, the one with the smallest
 * number of directories.
 */

int ufs_close_dirs = 1;	/* allocate directories close as possible */

ino_t
dirpref(inode_t *dp)
{
	int cg, minndir, mincg, avgifree, mininode, minbpg, ifree;
	struct fs *fs = dp->i_fs;

	cg = itog(fs, dp->i_number);
	mininode = fs->fs_ipg >> 2;
	minbpg = fs->fs_maxbpg >> 2;
	if (ufs_close_dirs &&
	    (fs->fs_cs(fs, cg).cs_nifree > mininode) &&
	    (fs->fs_cs(fs, cg).cs_nbfree > minbpg)) {
		return (dp->i_number);
	}

	avgifree = fs->fs_cstotal.cs_nifree / fs->fs_ncg;
	minndir = fs->fs_ipg;
	mincg = 0;
	for (cg = 0; cg < fs->fs_ncg; cg++) {
		ifree = fs->fs_cs(fs, cg).cs_nifree;
		if (ufs_close_dirs &&
		    (ifree > mininode) &&
		    (fs->fs_cs(fs, cg).cs_nbfree > minbpg)) {
			return ((ino_t)(fs->fs_ipg * cg));
		}
		if ((fs->fs_cs(fs, cg).cs_ndir < minndir) &&
		    (ifree >= avgifree)) {
			mincg = cg;
			minndir = fs->fs_cs(fs, cg).cs_ndir;
		}
	}
	return ((ino_t)(fs->fs_ipg * mincg));
}

/*
 * Select the desired position for the next block in a file.  The file is
 * logically divided into sections. The first section is composed of the
 * direct blocks. Each additional section contains fs_maxbpg blocks.
 *
 * If no blocks have been allocated in the first section, the policy is to
 * request a block in the same cylinder group as the inode that describes
 * the file. If no blocks have been allocated in any other section, the
 * policy is to place the section in a cylinder group with a greater than
 * average number of free blocks.  An appropriate cylinder group is found
 * by using a rotor that sweeps the cylinder groups. When a new group of
 * blocks is needed, the sweep begins in the cylinder group following the
 * cylinder group from which the previous allocation was made. The sweep
 * continues until a cylinder group with greater than the average number
 * of free blocks is found. If the allocation is for the first block in an
 * indirect block, the information on the previous allocation is unavailable;
 * here a best guess is made based upon the logical block number being
 * allocated.
 *
 * If a section is already partially allocated, the policy is to
 * contiguously allocate fs_maxcontig blocks.  The end of one of these
 * contiguous blocks and the beginning of the next is physically separated
 * so that the disk head will be in transit between them for at least
 * fs_rotdelay milliseconds.  This is to allow time for the processor to
 * schedule another I/O transfer.
 */
daddr_t
blkpref(struct inode *ip, daddr_t lbn, int indx, daddr32_t *bap)
{
	struct fs *fs;
	struct ufsvfs *ufsvfsp;
	int cg;
	int avgbfree, startcg;
	daddr_t nextblk;

	ufsvfsp = ip->i_ufsvfs;
	fs = ip->i_fs;
	if (indx % fs->fs_maxbpg == 0 || bap[indx - 1] == 0) {
		if (lbn < NDADDR) {
			cg = itog(fs, ip->i_number);
			return (fs->fs_fpg * cg + fs->fs_frag);
		}
		/*
		 * Find a cylinder with greater than average
		 * number of unused data blocks.
		 */
		if (indx == 0 || bap[indx - 1] == 0)
			startcg = itog(fs, ip->i_number) + lbn / fs->fs_maxbpg;
		else
			startcg = dtog(fs, bap[indx - 1]) + 1;
		startcg %= fs->fs_ncg;

		mutex_enter(&ufsvfsp->vfs_lock);
		avgbfree = fs->fs_cstotal.cs_nbfree / fs->fs_ncg;
		/*
		 * used for computing log space for writes/truncs
		 */
		ufsvfsp->vfs_avgbfree = avgbfree;
		for (cg = startcg; cg < fs->fs_ncg; cg++)
			if (fs->fs_cs(fs, cg).cs_nbfree >= avgbfree) {
				fs->fs_cgrotor = cg;
				mutex_exit(&ufsvfsp->vfs_lock);
				return (fs->fs_fpg * cg + fs->fs_frag);
			}
		for (cg = 0; cg <= startcg; cg++)
			if (fs->fs_cs(fs, cg).cs_nbfree >= avgbfree) {
				fs->fs_cgrotor = cg;
				mutex_exit(&ufsvfsp->vfs_lock);
				return (fs->fs_fpg * cg + fs->fs_frag);
			}
		mutex_exit(&ufsvfsp->vfs_lock);
		return (NULL);
	}
	/*
	 * One or more previous blocks have been laid out. If less
	 * than fs_maxcontig previous blocks are contiguous, the
	 * next block is requested contiguously, otherwise it is
	 * requested rotationally delayed by fs_rotdelay milliseconds.
	 */

	nextblk = bap[indx - 1];
	/*
	 * Provision for fallocate to return positive
	 * blk preference based on last allocation
	 */
	if (nextblk < 0 && nextblk != UFS_HOLE) {
		nextblk = (-bap[indx - 1]) + fs->fs_frag;
	} else {
		nextblk = bap[indx - 1] + fs->fs_frag;
	}

	if (indx > fs->fs_maxcontig && bap[indx - fs->fs_maxcontig] +
	    blkstofrags(fs, fs->fs_maxcontig) != nextblk) {
		return (nextblk);
	}
	if (fs->fs_rotdelay != 0)
		/*
		 * Here we convert ms of delay to frags as:
		 * (frags) = (ms) * (rev/sec) * (sect/rev) /
		 * 	((sect/frag) * (ms/sec))
		 * then round up to the next block.
		 */
		nextblk += roundup(fs->fs_rotdelay * fs->fs_rps * fs->fs_nsect /
		    (NSPF(fs) * 1000), fs->fs_frag);
	return (nextblk);
}

/*
 * Free a block or fragment.
 *
 * The specified block or fragment is placed back in the
 * free map. If a fragment is deallocated, a possible
 * block reassembly is checked.
 */
void
free(struct inode *ip, daddr_t bno, off_t size, int flags)
{
	struct fs *fs = ip->i_fs;
	struct ufsvfs *ufsvfsp = ip->i_ufsvfs;
	struct ufs_q *delq = &ufsvfsp->vfs_delete;
	struct ufs_delq_info *delq_info = &ufsvfsp->vfs_delete_info;
	struct cg *cgp;
	struct buf *bp;
	int cg, bmap, bbase;
	int i;
	uchar_t *blksfree;
	int *blktot;
	short *blks;
	daddr_t blkno, cylno, rpos;

	/*
	 * fallocate'd files will have negative block address.
	 * So negate it again to get original block address.
	 */
	if (bno < 0 && (bno % fs->fs_frag == 0) && bno != UFS_HOLE) {
		bno = -bno;
	}

	if ((unsigned long)size > fs->fs_bsize || fragoff(fs, size) != 0) {
		(void) ufs_fault(ITOV(ip),
		    "free: bad size, dev = 0x%lx, bsize = %d, size = %d, "
		    "fs = %s\n", ip->i_dev, fs->fs_bsize,
		    (int)size, fs->fs_fsmnt);
		return;
	}
	cg = dtog(fs, bno);
	ASSERT(!ufs_badblock(ip, bno));
	bp = UFS_BREAD(ufsvfsp, ip->i_dev, (daddr_t)fsbtodb(fs, cgtod(fs, cg)),
	    (int)fs->fs_cgsize);

	cgp = bp->b_un.b_cg;
	if (bp->b_flags & B_ERROR || !cg_chkmagic(cgp)) {
		brelse(bp);
		return;
	}

	if (!(flags & I_NOCANCEL))
		TRANS_CANCEL(ufsvfsp, ldbtob(fsbtodb(fs, bno)), size, flags);
	if (flags & (I_DIR|I_IBLK|I_SHAD|I_QUOTA)) {
		TRANS_MATA_FREE(ufsvfsp, ldbtob(fsbtodb(fs, bno)), size);
	}
	blksfree = cg_blksfree(cgp);
	blktot = cg_blktot(cgp);
	mutex_enter(&ufsvfsp->vfs_lock);
	cgp->cg_time = gethrestime_sec();
	bno = dtogd(fs, bno);
	if (size == fs->fs_bsize) {
		blkno = fragstoblks(fs, bno);
		cylno = cbtocylno(fs, bno);
		rpos = cbtorpos(ufsvfsp, bno);
		blks = cg_blks(ufsvfsp, cgp, cylno);
		if (!isclrblock(fs, blksfree, blkno)) {
			mutex_exit(&ufsvfsp->vfs_lock);
			brelse(bp);
			(void) ufs_fault(ITOV(ip), "free: freeing free block, "
			    "dev:0x%lx, block:%ld, ino:%lu, fs:%s",
			    ip->i_dev, bno, ip->i_number, fs->fs_fsmnt);
			return;
		}
		setblock(fs, blksfree, blkno);
		blks[rpos]++;
		blktot[cylno]++;
		cgp->cg_cs.cs_nbfree++;		/* Log below */
		fs->fs_cstotal.cs_nbfree++;
		fs->fs_cs(fs, cg).cs_nbfree++;
		if (TRANS_ISTRANS(ufsvfsp) && (flags & I_ACCT)) {
			mutex_enter(&delq->uq_mutex);
			delq_info->delq_unreclaimed_blocks -=
			    btodb(fs->fs_bsize);
			mutex_exit(&delq->uq_mutex);
		}
	} else {
		bbase = bno - fragnum(fs, bno);
		/*
		 * Decrement the counts associated with the old frags
		 */
		bmap = blkmap(fs, blksfree, bbase);
		fragacct(fs, bmap, cgp->cg_frsum, -1);
		/*
		 * Deallocate the fragment
		 */
		for (i = 0; i < numfrags(fs, size); i++) {
			if (isset(blksfree, bno + i)) {
				brelse(bp);
				mutex_exit(&ufsvfsp->vfs_lock);
				(void) ufs_fault(ITOV(ip),
				    "free: freeing free frag, "
				    "dev:0x%lx, blk:%ld, cg:%d, "
				    "ino:%lu, fs:%s",
				    ip->i_dev,
				    bno + i,
				    cgp->cg_cgx,
				    ip->i_number,
				    fs->fs_fsmnt);
				return;
			}
			setbit(blksfree, bno + i);
		}
		cgp->cg_cs.cs_nffree += i;
		fs->fs_cstotal.cs_nffree += i;
		fs->fs_cs(fs, cg).cs_nffree += i;
		if (TRANS_ISTRANS(ufsvfsp) && (flags & I_ACCT)) {
			mutex_enter(&delq->uq_mutex);
			delq_info->delq_unreclaimed_blocks -=
			    btodb(i * fs->fs_fsize);
			mutex_exit(&delq->uq_mutex);
		}
		/*
		 * Add back in counts associated with the new frags
		 */
		bmap = blkmap(fs, blksfree, bbase);
		fragacct(fs, bmap, cgp->cg_frsum, 1);
		/*
		 * If a complete block has been reassembled, account for it
		 */
		blkno = fragstoblks(fs, bbase);
		if (isblock(fs, blksfree, blkno)) {
			cylno = cbtocylno(fs, bbase);
			rpos = cbtorpos(ufsvfsp, bbase);
			blks = cg_blks(ufsvfsp, cgp, cylno);
			blks[rpos]++;
			blktot[cylno]++;
			cgp->cg_cs.cs_nffree -= fs->fs_frag;
			fs->fs_cstotal.cs_nffree -= fs->fs_frag;
			fs->fs_cs(fs, cg).cs_nffree -= fs->fs_frag;
			cgp->cg_cs.cs_nbfree++;
			fs->fs_cstotal.cs_nbfree++;
			fs->fs_cs(fs, cg).cs_nbfree++;
		}
	}
	fs->fs_fmod = 1;
	ufs_notclean(ufsvfsp);
	TRANS_BUF(ufsvfsp, 0, fs->fs_cgsize, bp, DT_CG);
	TRANS_SI(ufsvfsp, fs, cg);
	bdrwrite(bp);
}

/*
 * Free an inode.
 *
 * The specified inode is placed back in the free map.
 */
void
ufs_ifree(struct inode *ip, ino_t ino, mode_t mode)
{
	struct fs *fs = ip->i_fs;
	struct ufsvfs *ufsvfsp = ip->i_ufsvfs;
	struct cg *cgp;
	struct buf *bp;
	unsigned int inot;
	int cg;
	char *iused;

	if (ip->i_number == ino && ip->i_mode != 0) {
		(void) ufs_fault(ITOV(ip),
		    "ufs_ifree: illegal mode: (imode) %o, (omode) %o, ino %d, "
		    "fs = %s\n",
		    ip->i_mode, mode, (int)ip->i_number, fs->fs_fsmnt);
		return;
	}
	if (ino >= fs->fs_ipg * fs->fs_ncg) {
		(void) ufs_fault(ITOV(ip),
		    "ifree: range, dev = 0x%x, ino = %d, fs = %s\n",
		    (int)ip->i_dev, (int)ino, fs->fs_fsmnt);
		return;
	}
	cg = (int)itog(fs, ino);
	bp = UFS_BREAD(ufsvfsp, ip->i_dev, (daddr_t)fsbtodb(fs, cgtod(fs, cg)),
	    (int)fs->fs_cgsize);

	cgp = bp->b_un.b_cg;
	if (bp->b_flags & B_ERROR || !cg_chkmagic(cgp)) {
		brelse(bp);
		return;
	}
	mutex_enter(&ufsvfsp->vfs_lock);
	cgp->cg_time = gethrestime_sec();
	iused = cg_inosused(cgp);
	inot = (unsigned int)(ino % (ulong_t)fs->fs_ipg);
	if (isclr(iused, inot)) {
		mutex_exit(&ufsvfsp->vfs_lock);
		brelse(bp);
		(void) ufs_fault(ITOV(ip), "ufs_ifree: freeing free inode, "
		    "mode: (imode) %o, (omode) %o, ino:%d, "
		    "fs:%s",
		    ip->i_mode, mode, (int)ino, fs->fs_fsmnt);
		return;
	}
	clrbit(iused, inot);

	if (inot < (ulong_t)cgp->cg_irotor)
		cgp->cg_irotor = inot;
	cgp->cg_cs.cs_nifree++;
	fs->fs_cstotal.cs_nifree++;
	fs->fs_cs(fs, cg).cs_nifree++;
	if (((mode & IFMT) == IFDIR) || ((mode & IFMT) == IFATTRDIR)) {
		cgp->cg_cs.cs_ndir--;
		fs->fs_cstotal.cs_ndir--;
		fs->fs_cs(fs, cg).cs_ndir--;
	}
	fs->fs_fmod = 1;
	ufs_notclean(ufsvfsp);
	TRANS_BUF(ufsvfsp, 0, fs->fs_cgsize, bp, DT_CG);
	TRANS_SI(ufsvfsp, fs, cg);
	bdrwrite(bp);
}

/*
 * Implement the cylinder overflow algorithm.
 *
 * The policy implemented by this algorithm is:
 *   1) allocate the block in its requested cylinder group.
 *   2) quadratically rehash on the cylinder group number.
 *   3) brute force search for a free block.
 * The size parameter means size for data blocks, mode for inodes.
 */
static ino_t
hashalloc(struct inode *ip, int cg, long pref, int size, ulong_t (*allocator)())
{
	struct fs *fs;
	int i;
	long result;
	int icg = cg;

	fs = ip->i_fs;
	/*
	 * 1: preferred cylinder group
	 */
	result = (*allocator)(ip, cg, pref, size);
	if (result)
		return (result);
	/*
	 * 2: quadratic rehash
	 */
	for (i = 1; i < fs->fs_ncg; i *= 2) {
		cg += i;
		if (cg >= fs->fs_ncg)
			cg -= fs->fs_ncg;
		result = (*allocator)(ip, cg, 0, size);
		if (result)
			return (result);
	}
	/*
	 * 3: brute force search
	 * Note that we start at i == 2, since 0 was checked initially,
	 * and 1 is always checked in the quadratic rehash.
	 */
	cg = (icg + 2) % fs->fs_ncg;
	for (i = 2; i < fs->fs_ncg; i++) {
		result = (*allocator)(ip, cg, 0, size);
		if (result)
			return (result);
		cg++;
		if (cg == fs->fs_ncg)
			cg = 0;
	}
	return (NULL);
}

/*
 * Determine whether a fragment can be extended.
 *
 * Check to see if the necessary fragments are available, and
 * if they are, allocate them.
 */
static daddr_t
fragextend(struct inode *ip, int cg, long bprev, int osize, int nsize)
{
	struct ufsvfs *ufsvfsp = ip->i_ufsvfs;
	struct fs *fs = ip->i_fs;
	struct buf *bp;
	struct cg *cgp;
	uchar_t *blksfree;
	long bno;
	int frags, bbase;
	int i, j;

	if (fs->fs_cs(fs, cg).cs_nffree < numfrags(fs, nsize - osize))
		return (NULL);
	frags = numfrags(fs, nsize);
	bbase = (int)fragnum(fs, bprev);
	if (bbase > fragnum(fs, (bprev + frags - 1))) {
		/* cannot extend across a block boundary */
		return (NULL);
	}

	bp = UFS_BREAD(ufsvfsp, ip->i_dev, (daddr_t)fsbtodb(fs, cgtod(fs, cg)),
	    (int)fs->fs_cgsize);
	cgp = bp->b_un.b_cg;
	if (bp->b_flags & B_ERROR || !cg_chkmagic(cgp)) {
		brelse(bp);
		return (NULL);
	}

	blksfree = cg_blksfree(cgp);
	mutex_enter(&ufsvfsp->vfs_lock);
	bno = dtogd(fs, bprev);
	for (i = numfrags(fs, osize); i < frags; i++) {
		if (isclr(blksfree, bno + i)) {
			mutex_exit(&ufsvfsp->vfs_lock);
			brelse(bp);
			return (NULL);
		}
		if ((TRANS_ISCANCEL(ufsvfsp, ldbtob(fsbtodb(fs, bprev + i)),
		    fs->fs_fsize))) {
			mutex_exit(&ufsvfsp->vfs_lock);
			brelse(bp);
			return (NULL);
		}
	}

	cgp->cg_time = gethrestime_sec();
	/*
	 * The current fragment can be extended,
	 * deduct the count on fragment being extended into
	 * increase the count on the remaining fragment (if any)
	 * allocate the extended piece.
	 */
	for (i = frags; i < fs->fs_frag - bbase; i++)
		if (isclr(blksfree, bno + i))
			break;
	j = i - numfrags(fs, osize);
	cgp->cg_frsum[j]--;
	ASSERT(cgp->cg_frsum[j] >= 0);
	if (i != frags)
		cgp->cg_frsum[i - frags]++;
	for (i = numfrags(fs, osize); i < frags; i++) {
		clrbit(blksfree, bno + i);
		cgp->cg_cs.cs_nffree--;
		fs->fs_cs(fs, cg).cs_nffree--;
		fs->fs_cstotal.cs_nffree--;
	}
	fs->fs_fmod = 1;
	ufs_notclean(ufsvfsp);
	TRANS_BUF(ufsvfsp, 0, fs->fs_cgsize, bp, DT_CG);
	TRANS_SI(ufsvfsp, fs, cg);
	bdrwrite(bp);
	return ((daddr_t)bprev);
}

/*
 * Determine whether a block can be allocated.
 *
 * Check to see if a block of the apprpriate size
 * is available, and if it is, allocate it.
 */
static daddr_t
alloccg(struct inode *ip, int cg, daddr_t bpref, int size)
{
	struct ufsvfs *ufsvfsp = ip->i_ufsvfs;
	struct fs *fs = ip->i_fs;
	struct buf *bp;
	struct cg *cgp;
	uchar_t *blksfree;
	int bno, frags;
	int allocsiz;
	int i;

	/*
	 * Searching for space could be time expensive so do some
	 * up front checking to verify that there is actually space
	 * available (free blocks or free frags).
	 */
	if (fs->fs_cs(fs, cg).cs_nbfree == 0) {
		if (size == fs->fs_bsize)
			return (0);

		/*
		 * If there are not enough free frags then return.
		 */
		if (fs->fs_cs(fs, cg).cs_nffree < numfrags(fs, size))
			return (0);
	}

	bp = UFS_BREAD(ufsvfsp, ip->i_dev, (daddr_t)fsbtodb(fs, cgtod(fs, cg)),
	    (int)fs->fs_cgsize);

	cgp = bp->b_un.b_cg;
	if (bp->b_flags & B_ERROR || !cg_chkmagic(cgp) ||
	    (cgp->cg_cs.cs_nbfree == 0 && size == fs->fs_bsize)) {
		brelse(bp);
		return (0);
	}
	blksfree = cg_blksfree(cgp);
	mutex_enter(&ufsvfsp->vfs_lock);
	cgp->cg_time = gethrestime_sec();
	if (size == fs->fs_bsize) {
		if ((bno = alloccgblk(ufsvfsp, cgp, bpref, bp)) == 0)
			goto errout;
		fs->fs_fmod = 1;
		ufs_notclean(ufsvfsp);
		TRANS_SI(ufsvfsp, fs, cg);
		bdrwrite(bp);
		return (bno);
	}
	/*
	 * Check fragment bitmap to see if any fragments are already available.
	 * mapsearch() may fail because the fragment that fits this request
	 * might still be on the cancel list and not available for re-use yet.
	 * Look for a bigger sized fragment to allocate first before we have
	 * to give up and fragment a whole new block eventually.
	 */
	frags = numfrags(fs, size);
	allocsiz = frags;
next_size:
	for (; allocsiz < fs->fs_frag; allocsiz++)
		if (cgp->cg_frsum[allocsiz] != 0)
			break;

	if (allocsiz != fs->fs_frag) {
		bno = mapsearch(ufsvfsp, cgp, bpref, allocsiz);
		if (bno < 0 && allocsiz < (fs->fs_frag - 1)) {
			allocsiz++;
			goto next_size;
		}
	}

	if (allocsiz == fs->fs_frag || bno < 0) {
		/*
		 * No fragments were available, so a block
		 * will be allocated and hacked up.
		 */
		if (cgp->cg_cs.cs_nbfree == 0)
			goto errout;
		if ((bno = alloccgblk(ufsvfsp, cgp, bpref, bp)) == 0)
			goto errout;
		bpref = dtogd(fs, bno);
		for (i = frags; i < fs->fs_frag; i++)
			setbit(blksfree, bpref + i);
		i = fs->fs_frag - frags;
		cgp->cg_cs.cs_nffree += i;
		fs->fs_cstotal.cs_nffree += i;
		fs->fs_cs(fs, cg).cs_nffree += i;
		cgp->cg_frsum[i]++;
		fs->fs_fmod = 1;
		ufs_notclean(ufsvfsp);
		TRANS_SI(ufsvfsp, fs, cg);
		bdrwrite(bp);
		return (bno);
	}

	for (i = 0; i < frags; i++)
		clrbit(blksfree, bno + i);
	cgp->cg_cs.cs_nffree -= frags;
	fs->fs_cstotal.cs_nffree -= frags;
	fs->fs_cs(fs, cg).cs_nffree -= frags;
	cgp->cg_frsum[allocsiz]--;
	ASSERT(cgp->cg_frsum[allocsiz] >= 0);
	if (frags != allocsiz) {
		cgp->cg_frsum[allocsiz - frags]++;
	}
	fs->fs_fmod = 1;
	ufs_notclean(ufsvfsp);
	TRANS_BUF(ufsvfsp, 0, fs->fs_cgsize, bp, DT_CG);
	TRANS_SI(ufsvfsp, fs, cg);
	bdrwrite(bp);
	return (cg * fs->fs_fpg + bno);
errout:
	mutex_exit(&ufsvfsp->vfs_lock);
	brelse(bp);
	return (0);
}

/*
 * Allocate a block in a cylinder group.
 *
 * This algorithm implements the following policy:
 *   1) allocate the requested block.
 *   2) allocate a rotationally optimal block in the same cylinder.
 *   3) allocate the next available block on the block rotor for the
 *	specified cylinder group.
 * Note that this routine only allocates fs_bsize blocks; these
 * blocks may be fragmented by the routine that allocates them.
 */
static daddr_t
alloccgblk(
	struct ufsvfs *ufsvfsp,
	struct cg *cgp,
	daddr_t bpref,
	struct buf *bp)
{
	daddr_t bno;
	int cylno, pos, delta, rotbl_size;
	short *cylbp;
	int i;
	struct fs *fs;
	uchar_t *blksfree;
	daddr_t blkno, rpos, frag;
	short *blks;
	int32_t *blktot;

	ASSERT(MUTEX_HELD(&ufsvfsp->vfs_lock));
	fs = ufsvfsp->vfs_fs;
	blksfree = cg_blksfree(cgp);
	if (bpref == 0) {
		bpref = cgp->cg_rotor;
		goto norot;
	}
	bpref = blknum(fs, bpref);
	bpref = dtogd(fs, bpref);
	/*
	 * If the requested block is available, use it.
	 */
	if (isblock(fs, blksfree, (daddr_t)fragstoblks(fs, bpref))) {
		bno = bpref;
		goto gotit;
	}
	/*
	 * Check for a block available on the same cylinder.
	 */
	cylno = cbtocylno(fs, bpref);
	if (cg_blktot(cgp)[cylno] == 0)
		goto norot;
	if (fs->fs_cpc == 0) {
		/*
		 * Block layout info is not available, so just
		 * have to take any block in this cylinder.
		 */
		bpref = howmany(fs->fs_spc * cylno, NSPF(fs));
		goto norot;
	}
	/*
	 * Check the summary information to see if a block is
	 * available in the requested cylinder starting at the
	 * requested rotational position and proceeding around.
	 */
	cylbp = cg_blks(ufsvfsp, cgp, cylno);
	pos = cbtorpos(ufsvfsp, bpref);
	for (i = pos; i < ufsvfsp->vfs_nrpos; i++)
		if (cylbp[i] > 0)
			break;
	if (i == ufsvfsp->vfs_nrpos)
		for (i = 0; i < pos; i++)
			if (cylbp[i] > 0)
				break;
	if (cylbp[i] > 0) {
		/*
		 * Found a rotational position, now find the actual
		 * block.  A "panic" if none is actually there.
		 */

		/*
		 * Up to this point, "pos" has referred to the rotational
		 * position of the desired block.  From now on, it holds
		 * the offset of the current cylinder within a cylinder
		 * cycle.  (A cylinder cycle refers to a set of cylinders
		 * which are described by a single rotational table; the
		 * size of the cycle is fs_cpc.)
		 *
		 * bno is set to the block number of the first block within
		 * the current cylinder cycle.
		 */

		pos = cylno % fs->fs_cpc;
		bno = (cylno - pos) * fs->fs_spc / NSPB(fs);

		/*
		 * The blocks within a cylinder are grouped into equivalence
		 * classes according to their "rotational position."  There
		 * are two tables used to determine these classes.
		 *
		 * The positional offset table (fs_postbl) has an entry for
		 * each rotational position of each cylinder in a cylinder
		 * cycle.  This entry contains the relative block number
		 * (counting from the start of the cylinder cycle) of the
		 * first block in the equivalence class for that position
		 * and that cylinder.  Positions for which no blocks exist
		 * are indicated by a -1.
		 *
		 * The rotational delta table (fs_rotbl) has an entry for
		 * each block in a cylinder cycle.  This entry contains
		 * the offset from that block to the next block in the
		 * same equivalence class.  The last block in the class
		 * is indicated by a zero in the table.
		 *
		 * The following code, then, walks through all of the blocks
		 * in the cylinder (cylno) which we're allocating within
		 * which are in the equivalence class for the rotational
		 * position (i) which we're allocating within.
		 */

		if (fs_postbl(ufsvfsp, pos)[i] == -1) {
			(void) ufs_fault(ufsvfsp->vfs_root,
			    "alloccgblk: cyl groups corrupted, pos = %d, "
			    "i = %d, fs = %s\n", pos, i, fs->fs_fsmnt);
			return (0);
		}

		/*
		 * There is one entry in the rotational table for each block
		 * in the cylinder cycle.  These are whole blocks, not frags.
		 */

		rotbl_size = (fs->fs_cpc * fs->fs_spc) >>
		    (fs->fs_fragshift + fs->fs_fsbtodb);

		/*
		 * As we start, "i" is the rotational position within which
		 * we're searching.  After the next line, it will be a block
		 * number (relative to the start of the cylinder cycle)
		 * within the equivalence class of that rotational position.
		 */

		i = fs_postbl(ufsvfsp, pos)[i];

		for (;;) {
			if (isblock(fs, blksfree, (daddr_t)(bno + i))) {
				bno = blkstofrags(fs, (bno + i));
				goto gotit;
			}
			delta = fs_rotbl(fs)[i];
			if (delta <= 0 ||		/* End of chain, or */
			    delta + i > rotbl_size)	/* end of table? */
				break;			/* If so, panic. */
			i += delta;
		}
		(void) ufs_fault(ufsvfsp->vfs_root,
		    "alloccgblk: can't find blk in cyl, pos:%d, i:%d, "
		    "fs:%s bno: %x\n", pos, i, fs->fs_fsmnt, (int)bno);
		return (0);
	}
norot:
	/*
	 * No blocks in the requested cylinder, so take
	 * next available one in this cylinder group.
	 */
	bno = mapsearch(ufsvfsp, cgp, bpref, (int)fs->fs_frag);
	if (bno < 0)
		return (0);
	cgp->cg_rotor = bno;
gotit:
	blkno = fragstoblks(fs, bno);
	frag = (cgp->cg_cgx * fs->fs_fpg) + bno;
	if (TRANS_ISCANCEL(ufsvfsp, ldbtob(fsbtodb(fs, frag)), fs->fs_bsize))
		goto norot;
	clrblock(fs, blksfree, (long)blkno);
	/*
	 * the other cg/sb/si fields are TRANS'ed by the caller
	 */
	cgp->cg_cs.cs_nbfree--;
	fs->fs_cstotal.cs_nbfree--;
	fs->fs_cs(fs, cgp->cg_cgx).cs_nbfree--;
	cylno = cbtocylno(fs, bno);
	blks = cg_blks(ufsvfsp, cgp, cylno);
	rpos = cbtorpos(ufsvfsp, bno);
	blktot = cg_blktot(cgp);
	blks[rpos]--;
	blktot[cylno]--;
	TRANS_BUF(ufsvfsp, 0, fs->fs_cgsize, bp, DT_CG);
	fs->fs_fmod = 1;
	return (frag);
}

/*
 * Determine whether an inode can be allocated.
 *
 * Check to see if an inode is available, and if it is,
 * allocate it using the following policy:
 *   1) allocate the requested inode.
 *   2) allocate the next available inode after the requested
 *	inode in the specified cylinder group.
 */
static ino_t
ialloccg(struct inode *ip, int cg, daddr_t ipref, int mode)
{
	struct ufsvfs *ufsvfsp = ip->i_ufsvfs;
	struct fs *fs = ip->i_fs;
	struct cg *cgp;
	struct buf *bp;
	int start, len, loc, map, i;
	char *iused;

	if (fs->fs_cs(fs, cg).cs_nifree == 0)
		return (0);
	bp = UFS_BREAD(ufsvfsp, ip->i_dev, (daddr_t)fsbtodb(fs, cgtod(fs, cg)),
	    (int)fs->fs_cgsize);

	cgp = bp->b_un.b_cg;
	if (bp->b_flags & B_ERROR || !cg_chkmagic(cgp) ||
	    cgp->cg_cs.cs_nifree == 0) {
		brelse(bp);
		return (0);
	}
	iused = cg_inosused(cgp);
	mutex_enter(&ufsvfsp->vfs_lock);
	/*
	 * While we are waiting for the mutex, someone may have taken
	 * the last available inode.  Need to recheck.
	 */
	if (cgp->cg_cs.cs_nifree == 0) {
		mutex_exit(&ufsvfsp->vfs_lock);
		brelse(bp);
		return (0);
	}

	cgp->cg_time = gethrestime_sec();
	if (ipref) {
		ipref %= fs->fs_ipg;
		if (isclr(iused, ipref))
			goto gotit;
	}
	start = cgp->cg_irotor / NBBY;
	len = howmany(fs->fs_ipg - cgp->cg_irotor, NBBY);
	loc = skpc(0xff, (uint_t)len, &iused[start]);
	if (loc == 0) {
		len = start + 1;
		start = 0;
		loc = skpc(0xff, (uint_t)len, &iused[0]);
		if (loc == 0) {
			mutex_exit(&ufsvfsp->vfs_lock);
			(void) ufs_fault(ITOV(ip),
			    "ialloccg: map corrupted, cg = %d, irotor = %d, "
			    "fs = %s\n", cg, (int)cgp->cg_irotor, fs->fs_fsmnt);
			return (0);
		}
	}
	i = start + len - loc;
	map = iused[i];
	ipref = i * NBBY;
	for (i = 1; i < (1 << NBBY); i <<= 1, ipref++) {
		if ((map & i) == 0) {
			cgp->cg_irotor = ipref;
			goto gotit;
		}
	}

	mutex_exit(&ufsvfsp->vfs_lock);
	(void) ufs_fault(ITOV(ip), "ialloccg: block not in mapfs = %s",
	    fs->fs_fsmnt);
	return (0);
gotit:
	setbit(iused, ipref);
	cgp->cg_cs.cs_nifree--;
	fs->fs_cstotal.cs_nifree--;
	fs->fs_cs(fs, cg).cs_nifree--;
	if (((mode & IFMT) == IFDIR) || ((mode & IFMT) == IFATTRDIR)) {
		cgp->cg_cs.cs_ndir++;
		fs->fs_cstotal.cs_ndir++;
		fs->fs_cs(fs, cg).cs_ndir++;
	}
	fs->fs_fmod = 1;
	ufs_notclean(ufsvfsp);
	TRANS_BUF(ufsvfsp, 0, fs->fs_cgsize, bp, DT_CG);
	TRANS_SI(ufsvfsp, fs, cg);
	bdrwrite(bp);
	return (cg * fs->fs_ipg + ipref);
}

/*
 * Find a block of the specified size in the specified cylinder group.
 *
 * It is a panic if a request is made to find a block if none are
 * available.
 */
static daddr_t
mapsearch(struct ufsvfs *ufsvfsp, struct cg *cgp, daddr_t bpref,
	int allocsiz)
{
	struct fs *fs	= ufsvfsp->vfs_fs;
	daddr_t bno, cfrag;
	int start, len, loc, i, last, first, secondtime;
	int blk, field, subfield, pos;
	int gotit;

	/*
	 * ufsvfs->vfs_lock is held when calling this.
	 */
	/*
	 * Find the fragment by searching through the
	 * free block map for an appropriate bit pattern.
	 */
	if (bpref)
		start = dtogd(fs, bpref) / NBBY;
	else
		start = cgp->cg_frotor / NBBY;
	/*
	 * the following loop performs two scans -- the first scan
	 * searches the bottom half of the array for a match and the
	 * second scan searches the top half of the array.  The loops
	 * have been merged just to make things difficult.
	 */
	first = start;
	last = howmany(fs->fs_fpg, NBBY);
	secondtime = 0;
	cfrag = cgp->cg_cgx * fs->fs_fpg;
	while (first < last) {
		len = last - first;
		/*
		 * search the array for a match
		 */
		loc = scanc((unsigned)len, (uchar_t *)&cg_blksfree(cgp)[first],
		    (uchar_t *)fragtbl[fs->fs_frag],
		    (int)(1 << (allocsiz - 1 + (fs->fs_frag % NBBY))));
		/*
		 * match found
		 */
		if (loc) {
			bno = (last - loc) * NBBY;

			/*
			 * Found the byte in the map, sift
			 * through the bits to find the selected frag
			 */
			cgp->cg_frotor = bno;
			gotit = 0;
			for (i = bno + NBBY; bno < i; bno += fs->fs_frag) {
				blk = blkmap(fs, cg_blksfree(cgp), bno);
				blk <<= 1;
				field = around[allocsiz];
				subfield = inside[allocsiz];
				for (pos = 0;
				    pos <= fs->fs_frag - allocsiz;
				    pos++) {
					if ((blk & field) == subfield) {
						gotit++;
						break;
					}
					field <<= 1;
					subfield <<= 1;
				}
				if (gotit)
					break;
			}
			bno += pos;

			/*
			 * success if block is *not* being converted from
			 * metadata into userdata (harpy).  If so, ignore.
			 */
			if (!TRANS_ISCANCEL(ufsvfsp,
			    ldbtob(fsbtodb(fs, (cfrag+bno))),
			    allocsiz * fs->fs_fsize))
				return (bno);

			/*
			 * keep looking -- this block is being converted
			 */
			first = (last - loc) + 1;
			loc = 0;
			if (first < last)
				continue;
		}
		/*
		 * no usable matches in bottom half -- now search the top half
		 */
		if (secondtime)
			/*
			 * no usable matches in top half -- all done
			 */
			break;
		secondtime = 1;
		last = start + 1;
		first = 0;
	}
	/*
	 * no usable matches
	 */
	return ((daddr_t)-1);
}

#define	UFSNADDR (NDADDR + NIADDR)	/* NADDR applies to (obsolete) S5FS */
#define	IB(i)	(NDADDR + (i))	/* index of i'th indirect block ptr */
#define	SINGLE	0		/* single indirect block ptr */
#define	DOUBLE	1		/* double indirect block ptr */
#define	TRIPLE	2		/* triple indirect block ptr */

/*
 * Acquire a write lock, and keep trying till we get it
 */
static int
allocsp_wlockfs(struct vnode *vp, struct lockfs *lf)
{
	int err = 0;

lockagain:
	do {
		err = ufs_fiolfss(vp, lf);
		if (err)
			return (err);
	} while (!LOCKFS_IS_ULOCK(lf));

	lf->lf_lock = LOCKFS_WLOCK;
	lf->lf_flags = 0;
	lf->lf_comment = NULL;
	err = ufs__fiolfs(vp, lf, 1, 0);

	if (err == EBUSY || err == EINVAL)
		goto lockagain;

	return (err);
}

/*
 * Release the write lock
 */
static int
allocsp_unlockfs(struct vnode *vp, struct lockfs *lf)
{
	int err = 0;

	lf->lf_lock = LOCKFS_ULOCK;
	lf->lf_flags = 0;
	err = ufs__fiolfs(vp, lf, 1, 0);
	return (err);
}

struct allocsp_undo {
	daddr_t offset;
	daddr_t blk;
	struct allocsp_undo *next;
};

/*
 * ufs_allocsp() can be used to pre-allocate blocks for a file on a given
 * file system. For direct blocks, the blocks are allocated from the offset
 * requested to the block boundary, then any full blocks are allocated,
 * and finally any remainder.
 * For indirect blocks the blocks are not initialized and are
 * only marked as allocated. These addresses are then stored as negative
 * block numbers in the inode to imply special handling. UFS has been modified
 * where necessary to understand this new notion.
 * Successfully fallocated files will have IFALLOCATE cflag set in the inode.
 */
int
ufs_allocsp(struct vnode *vp, struct flock64 *lp, cred_t *cr)
{
	struct lockfs lf;
	int berr, err, resv, issync;
	off_t istart, len; /* istart, special for idb */
	struct inode *ip;
	struct fs *fs;
	struct ufsvfs *ufsvfsp;
	u_offset_t resid, i, uoff;
	daddr32_t db_undo[NDADDR];	/* old direct blocks */
	struct allocsp_undo *ib_undo = NULL;	/* ib undo */
	struct allocsp_undo *undo = NULL;
	u_offset_t osz;			/* old file size */
	int chunkblks = 0;		/* # of blocks in 1 allocation */
	int cnt = 0;
	daddr_t allocblk;
	daddr_t totblks = 0;
	struct ulockfs	*ulp;
	size_t done_len;
	int nbytes, offsetn;


	ASSERT(vp->v_type == VREG);

	ip = VTOI(vp);
	fs = ip->i_fs;
	if ((ufsvfsp = ip->i_ufsvfs) == NULL) {
		err = EIO;
		goto out_allocsp;
	}

	istart = blkroundup(fs, (lp->l_start));
	len = blkroundup(fs, (lp->l_len));
	chunkblks = blkroundup(fs, ufsvfsp->vfs_iotransz) / fs->fs_bsize;
	ulp = &ufsvfsp->vfs_ulockfs;

	if (lp->l_start < 0 || lp->l_len <= 0)
		return (EINVAL);

	/* Quickly check to make sure we have space before we proceed */
	if (lblkno(fs, len) > fs->fs_cstotal.cs_nbfree) {
		if (TRANS_ISTRANS(ufsvfsp)) {
			ufs_delete_drain_wait(ufsvfsp, 1);
			if (lblkno(fs, len) > fs->fs_cstotal.cs_nbfree)
				return (ENOSPC);
		} else
			return (ENOSPC);
	}

	/*
	 * We will keep i_rwlock locked as WRITER through out the function
	 * since we don't want anyone else reading or writing to the inode
	 * while we are in the middle of fallocating the file.
	 */
	rw_enter(&ip->i_rwlock, RW_WRITER);

	/* Back up the direct block list, used for undo later if necessary */
	rw_enter(&ip->i_contents, RW_READER);
	for (i = 0; i < NDADDR; i++)
		db_undo[i] = ip->i_db[i];
	osz = ip->i_size;
	rw_exit(&ip->i_contents);

	/* Write lock the file system */
	if (err = allocsp_wlockfs(vp, &lf))
		goto exit;

	/*
	 * Allocate any direct blocks now.
	 * Blocks are allocated from the offset requested to the block
	 * boundary, then any full blocks are allocated, and finally any
	 * remainder.
	 */
	if (lblkno(fs, lp->l_start) < NDADDR) {
		ufs_trans_trunc_resv(ip, ip->i_size + (NDADDR * fs->fs_bsize),
		    &resv, &resid);
		TRANS_BEGIN_CSYNC(ufsvfsp, issync, TOP_ALLOCSP, resv);

		rw_enter(&ufsvfsp->vfs_dqrwlock, RW_READER);
		rw_enter(&ip->i_contents, RW_WRITER);

		done_len = 0;
		while ((done_len < lp->l_len) &&
		    (lblkno(fs, lp->l_start + done_len) < NDADDR)) {
			uoff = (offset_t)(lp->l_start + done_len);
			offsetn = (int)blkoff(fs, uoff);
			nbytes = (int)MIN(fs->fs_bsize - offsetn,
			    lp->l_len - done_len);

			berr = bmap_write(ip, uoff, offsetn + nbytes,
			    BI_FALLOCATE, &allocblk, cr);
			/* Yikes error, quit */
			if (berr) {
				TRANS_INODE(ufsvfsp, ip);
				rw_exit(&ip->i_contents);
				rw_exit(&ufsvfsp->vfs_dqrwlock);
				TRANS_END_CSYNC(ufsvfsp, err, issync,
				    TOP_ALLOCSP, resv);
				err = allocsp_unlockfs(vp, &lf);
				goto exit;
			}

			if (allocblk) {
				totblks++;
				if ((uoff + nbytes) > ip->i_size)
					ip->i_size = (uoff + nbytes);
			}
			done_len += nbytes;
		}

		TRANS_INODE(ufsvfsp, ip);
		rw_exit(&ip->i_contents);
		rw_exit(&ufsvfsp->vfs_dqrwlock);
		TRANS_END_CSYNC(ufsvfsp, err, issync, TOP_ALLOCSP, resv);

		/* start offset for indirect allocation */
		istart =  (uoff + nbytes);
	}

	/* Break the transactions into vfs_iotransz units */
	ufs_trans_trunc_resv(ip, ip->i_size +
	    blkroundup(fs, ufsvfsp->vfs_iotransz), &resv, &resid);
	TRANS_BEGIN_CSYNC(ufsvfsp, issync, TOP_ALLOCSP, resv);

	rw_enter(&ufsvfsp->vfs_dqrwlock, RW_READER);
	rw_enter(&ip->i_contents, RW_WRITER);

	/* Now go about fallocating necessary indirect blocks */
	for (i = istart; i < (lp->l_start + lp->l_len); i += fs->fs_bsize) {
		berr = bmap_write(ip, i, fs->fs_bsize, BI_FALLOCATE,
		    &allocblk, cr);
		if (berr) {
			TRANS_INODE(ufsvfsp, ip);
			rw_exit(&ip->i_contents);
			rw_exit(&ufsvfsp->vfs_dqrwlock);
			TRANS_END_CSYNC(ufsvfsp, err, issync,
			    TOP_ALLOCSP, resv);
			err = allocsp_unlockfs(vp, &lf);
			goto exit;
		}

		/* Update the blk counter only if new block was added */
		if (allocblk) {
			/* Save undo information */
			undo = kmem_alloc(sizeof (struct allocsp_undo),
			    KM_SLEEP);
			undo->offset = i;
			undo->blk = allocblk;
			undo->next = ib_undo;
			ib_undo = undo;
			totblks++;

			if (i >= ip->i_size)
				ip->i_size += fs->fs_bsize;
		}
		cnt++;

		/* Being a good UFS citizen, let others get a share */
		if (cnt == chunkblks) {
			/*
			 * If there are waiters or the fs is hard locked,
			 * error locked, or read-only error locked,
			 * quit with EIO
			 */
			if (ULOCKFS_IS_HLOCK(ulp) || ULOCKFS_IS_ELOCK(ulp) ||
			    ULOCKFS_IS_ROELOCK(ulp)) {
				ip->i_cflags |= IFALLOCATE;
				TRANS_INODE(ufsvfsp, ip);
				rw_exit(&ip->i_contents);
				rw_exit(&ufsvfsp->vfs_dqrwlock);

				TRANS_END_CSYNC(ufsvfsp, err, issync,
				    TOP_ALLOCSP, resv);
				rw_exit(&ip->i_rwlock);
				(void) allocsp_unlockfs(vp, &lf);
				return (EIO);
			}

			TRANS_INODE(ufsvfsp, ip);
			rw_exit(&ip->i_contents);
			rw_exit(&ufsvfsp->vfs_dqrwlock);

			/* End the current transaction */
			TRANS_END_CSYNC(ufsvfsp, err, issync,
			    TOP_ALLOCSP, resv);

			if (CV_HAS_WAITERS(&ulp->ul_cv)) {
				/* Release the write lock */
				if (err = allocsp_unlockfs(vp, &lf))
					goto exit;

				/* Wake up others waiting to do operations */
				mutex_enter(&ulp->ul_lock);
				cv_broadcast(&ulp->ul_cv);
				mutex_exit(&ulp->ul_lock);

				/* Grab the write lock again */
				if (err = allocsp_wlockfs(vp, &lf))
					goto exit;
			} /* end of CV_HAS_WAITERS(&ulp->ul_cv) */

			/* Reserve more space in log for this file */
			ufs_trans_trunc_resv(ip,
			    ip->i_size + blkroundup(fs, ufsvfsp->vfs_iotransz),
			    &resv, &resid);
			TRANS_BEGIN_CSYNC(ufsvfsp, issync, TOP_ALLOCSP, resv);

			rw_enter(&ufsvfsp->vfs_dqrwlock, RW_READER);
			rw_enter(&ip->i_contents, RW_WRITER);

			cnt = 0;	/* reset cnt b/c of new transaction */
		}
	}

	if (!err && !berr)
		ip->i_cflags |= IFALLOCATE;

	/* If the file has grown then correct the file size */
	if (osz < (lp->l_start + lp->l_len))
		ip->i_size = (lp->l_start + lp->l_len);

	/* Release locks, end log transaction and unlock fs */
	TRANS_INODE(ufsvfsp, ip);
	rw_exit(&ip->i_contents);
	rw_exit(&ufsvfsp->vfs_dqrwlock);

	TRANS_END_CSYNC(ufsvfsp, err, issync, TOP_ALLOCSP, resv);
	err = allocsp_unlockfs(vp, &lf);

	/*
	 * @ exit label, we should no longer be holding the fs write lock, and
	 * all logging transactions should have been ended. We still hold
	 * ip->i_rwlock.
	 */
exit:
	/*
	 * File has grown larger than 2GB. Set flag
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

	/*
	 * Since we couldn't allocate completely, we will undo the allocations.
	 */
	if (berr) {
		ufs_trans_trunc_resv(ip, totblks * fs->fs_bsize, &resv, &resid);
		TRANS_BEGIN_CSYNC(ufsvfsp, issync, TOP_ALLOCSP, resv);

		rw_enter(&ufsvfsp->vfs_dqrwlock, RW_READER);
		rw_enter(&ip->i_contents, RW_WRITER);

		/* Direct blocks */
		for (i = 0; i < NDADDR; i++) {
			/*
			 * Only free the block if they are not same, and
			 * the old one isn't zero (the fragment was
			 * re-allocated).
			 */
			if (db_undo[i] != ip->i_db[i] && db_undo[i] == 0) {
				free(ip, ip->i_db[i], fs->fs_bsize, 0);
				ip->i_db[i] = 0;
			}
		}

		/* Undo the indirect blocks */
		while (ib_undo != NULL) {
			undo = ib_undo;
			err = bmap_set_bn(vp, undo->offset, 0);
			if (err)
				cmn_err(CE_PANIC, "ufs_allocsp(): failed to "
				    "undo allocation of block %ld",
				    undo->offset);
			free(ip, undo->blk, fs->fs_bsize, I_IBLK);
			ib_undo = undo->next;
			kmem_free(undo, sizeof (struct allocsp_undo));
		}

		ip->i_size = osz;
		TRANS_INODE(ufsvfsp, ip);

		rw_exit(&ip->i_contents);
		rw_exit(&ufsvfsp->vfs_dqrwlock);

		TRANS_END_CSYNC(ufsvfsp, err, issync, TOP_ALLOCSP, resv);

		rw_exit(&ip->i_rwlock);
		return (berr);
	}

	/*
	 * Don't forget to free the undo chain :)
	 */
	while (ib_undo != NULL) {
		undo = ib_undo;
		ib_undo = undo->next;
		kmem_free(undo, sizeof (struct allocsp_undo));
	}

	rw_exit(&ip->i_rwlock);

out_allocsp:
	return (err);
}

/*
 * Free storage space associated with the specified inode.  The portion
 * to be freed is specified by lp->l_start and lp->l_len (already
 * normalized to a "whence" of 0).
 *
 * This is an experimental facility whose continued existence is not
 * guaranteed.  Currently, we only support the special case
 * of l_len == 0, meaning free to end of file.
 *
 * Blocks are freed in reverse order.  This FILO algorithm will tend to
 * maintain a contiguous free list much longer than FIFO.
 * See also ufs_itrunc() in ufs_inode.c.
 *
 * Bug: unused bytes in the last retained block are not cleared.
 * This may result in a "hole" in the file that does not read as zeroes.
 */
/* ARGSUSED */
int
ufs_freesp(struct vnode *vp, struct flock64 *lp, int flag, cred_t *cr)
{
	int i;
	struct inode *ip = VTOI(vp);
	int error;

	ASSERT(vp->v_type == VREG);
	ASSERT(lp->l_start >= 0);	/* checked by convoff */

	if (lp->l_len != 0)
		return (EINVAL);

	rw_enter(&ip->i_contents, RW_READER);
	if (ip->i_size == (u_offset_t)lp->l_start) {
		rw_exit(&ip->i_contents);
		return (0);
	}

	/*
	 * Check if there is any active mandatory lock on the
	 * range that will be truncated/expanded.
	 */
	if (MANDLOCK(vp, ip->i_mode)) {
		offset_t save_start;

		save_start = lp->l_start;

		if (ip->i_size < lp->l_start) {
			/*
			 * "Truncate up" case: need to make sure there
			 * is no lock beyond current end-of-file. To
			 * do so, we need to set l_start to the size
			 * of the file temporarily.
			 */
			lp->l_start = ip->i_size;
		}
		lp->l_type = F_WRLCK;
		lp->l_sysid = 0;
		lp->l_pid = ttoproc(curthread)->p_pid;
		i = (flag & (FNDELAY|FNONBLOCK)) ? 0 : SLPFLCK;
		rw_exit(&ip->i_contents);
		if ((i = reclock(vp, lp, i, 0, lp->l_start, NULL)) != 0 ||
		    lp->l_type != F_UNLCK) {
			return (i ? i : EAGAIN);
		}
		rw_enter(&ip->i_contents, RW_READER);

		lp->l_start = save_start;
	}

	/*
	 * Make sure a write isn't in progress (allocating blocks)
	 * by acquiring i_rwlock (we promised ufs_bmap we wouldn't
	 * truncate while it was allocating blocks).
	 * Grab the locks in the right order.
	 */
	rw_exit(&ip->i_contents);
	rw_enter(&ip->i_rwlock, RW_WRITER);
	error = TRANS_ITRUNC(ip, (u_offset_t)lp->l_start, 0, cr);
	rw_exit(&ip->i_rwlock);
	return (error);
}

/*
 * Find a cg with as close to nb contiguous bytes as possible
 *	THIS MAY TAKE MANY DISK READS!
 *
 * Implemented in an attempt to allocate contiguous blocks for
 * writing the ufs log file to, minimizing future disk head seeking
 */
daddr_t
contigpref(ufsvfs_t *ufsvfsp, size_t nb, size_t minb)
{
	struct fs	*fs	= ufsvfsp->vfs_fs;
	daddr_t		nblk	= lblkno(fs, blkroundup(fs, nb));
	daddr_t		minblk	= lblkno(fs, blkroundup(fs, minb));
	daddr_t		savebno, curbno, cgbno;
	int		cg, cgblks, savecg, savenblk, curnblk, startcg;
	uchar_t		*blksfree;
	buf_t		*bp;
	struct cg	*cgp;

	savenblk = 0;
	savecg = 0;
	savebno = 0;

	if ((startcg = findlogstartcg(fs, nblk, minblk)) == -1)
		cg = 0;	/* Nothing suitable found */
	else
		cg = startcg;

	for (; cg < fs->fs_ncg; ++cg) {
		/*
		 * find the largest contiguous range in this cg
		 */
		bp = UFS_BREAD(ufsvfsp, ufsvfsp->vfs_dev,
		    (daddr_t)fsbtodb(fs, cgtod(fs, cg)),
		    (int)fs->fs_cgsize);
		cgp = bp->b_un.b_cg;
		if (bp->b_flags & B_ERROR || !cg_chkmagic(cgp)) {
			brelse(bp);
			continue;
		}
		blksfree = cg_blksfree(cgp);	    /* free array */
		cgblks = fragstoblks(fs, fs->fs_fpg); /* blks in free array */
		cgbno = 0;
		while (cgbno < cgblks && savenblk < nblk) {
			/* find a free block */
			for (; cgbno < cgblks; ++cgbno) {
				if (isblock(fs, blksfree, cgbno)) {
					if (startcg != -1) {
						brelse(bp);
						savecg = startcg;
						savebno = cgbno;
						goto done;
					} else
						break;
				}
			}
			curbno = cgbno;
			/* count the number of free blocks */
			for (curnblk = 0; cgbno < cgblks; ++cgbno) {
				if (!isblock(fs, blksfree, cgbno))
					break;
				if (++curnblk >= nblk)
					break;
			}
			if (curnblk > savenblk) {
				savecg = cg;
				savenblk = curnblk;
				savebno = curbno;
			}
		}
		brelse(bp);
		if (savenblk >= nblk)
			break;
	}

done:

	/* convert block offset in cg to frag offset in cg */
	savebno = blkstofrags(fs, savebno);

	/* convert frag offset in cg to frag offset in fs */
	savebno += (savecg * fs->fs_fpg);

	return (savebno);
}

/*
 * The object of this routine is to find a start point for the UFS log.
 * Ideally the space should be allocated from the smallest possible number
 * of contiguous cylinder groups. This is found by using a sliding window
 * technique. The smallest window of contiguous cylinder groups, which is
 * still able to accommodate the target, is found by moving the window
 * through the cylinder groups in a single pass. The end of the window is
 * advanced until the space is accommodated, then the start is advanced until
 * it no longer fits, the end is then advanced again and so on until the
 * final cylinder group is reached. The first suitable instance is recorded
 * and its starting cg number is returned.
 *
 * If we are not able to find a minimum amount of space, represented by
 * minblk, or to do so uses more than the available extents, then return -1.
 */

int
findlogstartcg(struct fs *fs, daddr_t requested, daddr_t minblk)
{
	int	 ncgs;		 /* number of cylinder groups */
	daddr_t target;		 /* amount of space sought */
	int	 cwidth, ctotal; /* current window width and total */
	int	 bwidth, btotal; /* best window width and total so far */
	int	 s;	/* index of the first element in the current window */
	int	 e;	/* index of the first element + the width */
			/*  (i.e. 1 + index of last element) */
	int	 bs; /* index of the first element in the best window so far */
	int	 header, max_extents;

	target = requested;
	ncgs = fs->fs_ncg;

	header = sizeof (extent_block_t) - sizeof (extent_t);
	max_extents = ((fs->fs_bsize)-header) / sizeof (extent_t);
	cwidth = ctotal = 0;
	btotal = -1;
	bwidth = ncgs;
	s = e = 0;
	while (e < ncgs) {
	/* Advance the end of the window until it accommodates the target. */
		while (ctotal < target && e < ncgs) {
			ctotal += fs->fs_cs(fs, e).cs_nbfree;
			e++;
		}

		/*
		 * Advance the start of the window until it no longer
		 * accommodates the target.
		 */
		while (ctotal >= target && s < e) {
			/* See if this is the smallest window so far. */
			cwidth = e - s;
			if (cwidth <= bwidth) {
				if (cwidth == bwidth && ctotal <= btotal)
					goto more;
				bwidth = cwidth;
				btotal = ctotal;
				bs = s;
			}
more:
			ctotal -= fs->fs_cs(fs, s).cs_nbfree;
			s++;
		}
	}

	/*
	 * If we cannot allocate the minimum required or we use too many
	 * extents to do so, return -1.
	 */
	if (btotal < minblk || bwidth > max_extents)
		bs = -1;

	return (bs);
}
