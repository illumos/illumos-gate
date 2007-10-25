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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/conf.h>
#include <sys/fssnap_if.h>
#include <sys/fs/ufs_inode.h>
#include <sys/fs/ufs_lockfs.h>
#include <sys/fs/ufs_log.h>
#include <sys/fs/ufs_trans.h>
#include <sys/cmn_err.h>
#include <vm/pvn.h>
#include <vm/seg_map.h>
#include <sys/fdbuffer.h>

#ifdef DEBUG
int evn_ufs_debug = 0;
#define	DEBUGF(args)	{ if (evn_ufs_debug) cmn_err args; }
#else
#define	DEBUGF(args)
#endif

/*
 * ufs_rdwr_data - supports reading or writing data when
 * no changes are permitted in file size or space allocation.
 *
 * Inputs:
 * fdb - The mandatory fdbuffer supports
 *	the read or write operation.
 * flags - defaults (zero value) to synchronous write
 *	B_READ - indicates read operation
 *	B_ASYNC - indicates perform operation asynchronously
 */
/*ARGSUSED*/
int
ufs_rdwr_data(
	vnode_t		*vnodep,
	u_offset_t	offset,
	size_t		len,
	fdbuffer_t	*fdbp,
	int		flags,
	cred_t		*credp)
{
	struct inode	*ip = VTOI(vnodep);
	struct fs	*fs;
	struct ufsvfs	*ufsvfsp = ip->i_ufsvfs;
	struct buf	*bp;
	krw_t		rwtype = RW_READER;
	u_offset_t	offset1 = offset;	/* Initial offset */
	size_t		iolen;
	int		curlen = 0;
	int		pplen;
	daddr_t		bn;
	int		contig = 0;
	int		error = 0;
	int		nbytes;			/* Number bytes this IO */
	int		offsetn;		/* Start point this IO */
	int		iswrite = flags & B_WRITE;
	int		io_started = 0;		/* No IO started */
	struct ulockfs	*ulp;
	uint_t		protp = PROT_ALL;

	error = ufs_lockfs_begin_getpage(ufsvfsp, &ulp, segkmap, !iswrite,
	    &protp);
	if (error) {
		if (flags & B_ASYNC) {
			fdb_ioerrdone(fdbp, error);
		}
		return (error);
	}
	fs = ufsvfsp->vfs_fs;
	iolen = len;

	DEBUGF((CE_CONT, "?ufs_rdwr: %s vp: %p pages:%p  off %llx len %lx"
	    " isize: %llx fdb: %p\n",
	    flags & B_READ ? "READ" : "WRITE", (void *)vnodep,
	    (void *)vnodep->v_pages, offset1, iolen, ip->i_size, (void *)fdbp));

	rw_enter(&ip->i_ufsvfs->vfs_dqrwlock, RW_READER);
	rw_enter(&ip->i_contents, rwtype);

	ASSERT(offset1 < ip->i_size);

	if ((offset1 + iolen) > ip->i_size) {
		iolen = ip->i_size - offset1;
	}
	while (!error && curlen < iolen) {

		contig = 0;

		if ((error = bmap_read(ip, offset1, &bn, &contig)) != 0) {
			break;
		}
		ASSERT(!(bn == UFS_HOLE && iswrite));
		if (bn == UFS_HOLE) {
			/*
			 * If the above assertion is true,
			 * then the following if statement can never be true.
			 */
			if (iswrite && (rwtype == RW_READER)) {
				rwtype = RW_WRITER;
				if (!rw_tryupgrade(&ip->i_contents)) {
					rw_exit(&ip->i_contents);
					rw_enter(&ip->i_contents, rwtype);
					continue;
				}
			}
			offsetn = blkoff(fs, offset1);
			pplen = P2ROUNDUP(len, PAGESIZE);
			nbytes = MIN((pplen - curlen),
			    (fs->fs_bsize - offsetn));
			ASSERT(nbytes > 0);

			/*
			 * We may be reading or writing.
			 */
			DEBUGF((CE_CONT, "?ufs_rdwr_data: hole %llx - %lx\n",
			    offset1, (iolen - curlen)));

			if (iswrite) {
				printf("**WARNING: ignoring hole in write\n");
				error = ENOSPC;
			} else {
				fdb_add_hole(fdbp, offset1 - offset, nbytes);
			}
			offset1 += nbytes;
			curlen += nbytes;
			continue;

		}
		ASSERT(contig > 0);
		pplen = P2ROUNDUP(len, PAGESIZE);

		contig = MIN(contig, len - curlen);
		contig = P2ROUNDUP(contig, DEV_BSIZE);

		bp = fdb_iosetup(fdbp, offset1 - offset, contig, vnodep, flags);

		bp->b_edev = ip->i_dev;
		bp->b_dev = cmpdev(ip->i_dev);
		bp->b_blkno = bn;
		bp->b_file = ip->i_vnode;
		bp->b_offset = (offset_t)offset1;

		if (ufsvfsp->vfs_snapshot) {
			fssnap_strategy(&ufsvfsp->vfs_snapshot, bp);
		} else {
			(void) bdev_strategy(bp);
		}
		io_started = 1;

		offset1 += contig;
		curlen += contig;
		if (iswrite)
			lwp_stat_update(LWP_STAT_OUBLK, 1);
		else
			lwp_stat_update(LWP_STAT_INBLK, 1);

		if ((flags & B_ASYNC) == 0) {
			error = biowait(bp);
			fdb_iodone(bp);
		}

		DEBUGF((CE_CONT, "?loop ufs_rdwr_data.. off %llx len %lx\n",
		    offset1, (iolen - curlen)));
	}

	DEBUGF((CE_CONT, "?ufs_rdwr_data: off %llx len %lx pages: %p ------\n",
	    offset1, (iolen - curlen), (void *)vnodep->v_pages));

	rw_exit(&ip->i_contents);
	rw_exit(&ip->i_ufsvfs->vfs_dqrwlock);

	if (flags & B_ASYNC) {
		/*
		 * Show that no more asynchronous IO will be added
		 */
		fdb_ioerrdone(fdbp, error);
	}
	if (ulp) {
		ufs_lockfs_end(ulp);
	}
	if (io_started && flags & B_ASYNC) {
		return (0);
	} else {
		return (error);
	}
}

/*
 * ufs_alloc_data - supports allocating space and reads or writes
 * that involve changes to file length or space allocation.
 *
 * This function is more expensive, because of the UFS log transaction,
 * so ufs_rdwr_data() should be used when space or file length changes
 * will not occur.
 *
 * Inputs:
 * fdb - A null pointer instructs this function to only allocate
 *	space for the specified offset and length.
 *	An actual fdbuffer instructs this function to perform
 *	the read or write operation.
 * flags - defaults (zero value) to synchronous write
 *	B_READ - indicates read operation
 *	B_ASYNC - indicates perform operation asynchronously
 */
int
ufs_alloc_data(
	vnode_t		*vnodep,
	u_offset_t	offset,
	size_t		*len,
	fdbuffer_t	*fdbp,
	int		flags,
	cred_t		*credp)
{
	struct inode	*ip = VTOI(vnodep);
	size_t		done_len, io_len;
	int		contig;
	u_offset_t	uoff, io_off;
	int		error = 0;		/* No error occurred */
	int		offsetn;		/* Start point this IO */
	int		nbytes;			/* Number bytes in this IO */
	daddr_t		bn;
	struct fs	*fs;
	struct ufsvfs	*ufsvfsp = ip->i_ufsvfs;
	int		i_size_changed = 0;
	u_offset_t	old_i_size;
	struct ulockfs	*ulp;
	int		trans_size;
	int		issync;			/* UFS Log transaction */
						/* synchronous when non-zero */

	int		io_started = 0;		/* No IO started */
	uint_t		protp = PROT_ALL;

	ASSERT((flags & B_WRITE) == 0);

	/*
	 * Obey the lockfs protocol
	 */
	error = ufs_lockfs_begin_getpage(ufsvfsp, &ulp, segkmap, 0, &protp);
	if (error) {
		if ((fdbp != NULL) && (flags & B_ASYNC)) {
			fdb_ioerrdone(fdbp, error);
		}
		return (error);
	}
	if (ulp) {
		/*
		 * Try to begin a UFS log transaction
		 */
		trans_size = TOP_GETPAGE_SIZE(ip);
		TRANS_TRY_BEGIN_CSYNC(ufsvfsp, issync, TOP_GETPAGE,
		    trans_size, error);
		if (error == EWOULDBLOCK) {
			ufs_lockfs_end(ulp);
			if ((fdbp != NULL) && (flags & B_ASYNC)) {
				fdb_ioerrdone(fdbp, EDEADLK);
			}
			return (EDEADLK);
		}
	}

	uoff = offset;
	io_off = offset;
	io_len = *len;
	done_len = 0;

	DEBUGF((CE_CONT, "?ufs_alloc: off %llx len %lx size %llx fdb: %p\n",
	    uoff, (io_len - done_len), ip->i_size, (void *)fdbp));

	rw_enter(&ip->i_ufsvfs->vfs_dqrwlock, RW_READER);
	rw_enter(&ip->i_contents, RW_WRITER);

	ASSERT((ip->i_mode & IFMT) == IFREG);

	fs = ip->i_fs;

	while (error == 0 && done_len < io_len) {
		uoff = (u_offset_t)(io_off + done_len);
		offsetn = (int)blkoff(fs, uoff);
		nbytes = (int)MIN(fs->fs_bsize - offsetn, io_len - done_len);

		DEBUGF((CE_CONT, "?ufs_alloc_data: offset: %llx len %x\n",
		    uoff, nbytes));

		if (uoff + nbytes > ip->i_size) {
			/*
			 * We are extending the length of the file.
			 * bmap is used so that we are sure that
			 * if we need to allocate new blocks, that it
			 * is done here before we up the file size.
			 */
			DEBUGF((CE_CONT, "?ufs_alloc_data: grow %llx -> %llx\n",
			    ip->i_size, uoff + nbytes));

			error = bmap_write(ip, uoff, (offsetn + nbytes),
			    BI_ALLOC_ONLY, NULL, credp);
			if (ip->i_flag & (ICHG|IUPD))
				ip->i_seq++;
			if (error) {
				DEBUGF((CE_CONT, "?ufs_alloc_data: grow "
				    "failed err: %d\n", error));
				break;
			}
			if (fdbp != NULL) {
				if (uoff >= ip->i_size) {
					/*
					 * Desired offset is past end of bytes
					 * in file, so we have a hole.
					 */
					fdb_add_hole(fdbp, uoff - offset,
					    nbytes);
				} else {
					int contig;
					buf_t *bp;

					error = bmap_read(ip, uoff, &bn,
					    &contig);
					if (error) {
						break;
					}

					contig = ip->i_size - uoff;
					contig = P2ROUNDUP(contig, DEV_BSIZE);

					bp = fdb_iosetup(fdbp, uoff - offset,
					    contig, vnodep, flags);

					bp->b_edev = ip->i_dev;
					bp->b_dev = cmpdev(ip->i_dev);
					bp->b_blkno = bn;
					bp->b_file = ip->i_vnode;
					bp->b_offset = (offset_t)uoff;

					if (ufsvfsp->vfs_snapshot) {
						fssnap_strategy(
						    &ufsvfsp->vfs_snapshot, bp);
					} else {
						(void) bdev_strategy(bp);
					}
					io_started = 1;

					lwp_stat_update(LWP_STAT_OUBLK, 1);

					if ((flags & B_ASYNC) == 0) {
						error = biowait(bp);
						fdb_iodone(bp);
						if (error) {
							break;
						}
					}
					if (contig > (ip->i_size - uoff)) {
						contig -= ip->i_size - uoff;

						fdb_add_hole(fdbp,
						    ip->i_size - offset,
						    contig);
					}
				}
			}

			i_size_changed = 1;
			old_i_size = ip->i_size;
			UFS_SET_ISIZE(uoff + nbytes, ip);
			TRANS_INODE(ip->i_ufsvfs, ip);
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
		} else {
			/*
			 * The file length is not being extended.
			 */
			error = bmap_read(ip, uoff, &bn, &contig);
			if (error) {
				DEBUGF((CE_CONT, "?ufs_alloc_data: "
				    "bmap_read err: %d\n", error));
				break;
			}

			if (bn != UFS_HOLE) {
				/*
				 * Did not map a hole in the file
				 */
				int	contig = P2ROUNDUP(nbytes, DEV_BSIZE);
				buf_t	*bp;

				if (fdbp != NULL) {
					bp = fdb_iosetup(fdbp, uoff - offset,
					    contig, vnodep, flags);

					bp->b_edev = ip->i_dev;
					bp->b_dev = cmpdev(ip->i_dev);
					bp->b_blkno = bn;
					bp->b_file = ip->i_vnode;
					bp->b_offset = (offset_t)uoff;

					if (ufsvfsp->vfs_snapshot) {
						fssnap_strategy(
						    &ufsvfsp->vfs_snapshot, bp);
					} else {
						(void) bdev_strategy(bp);
					}
					io_started = 1;

					lwp_stat_update(LWP_STAT_OUBLK, 1);

					if ((flags & B_ASYNC) == 0) {
						error = biowait(bp);
						fdb_iodone(bp);
						if (error) {
							break;
						}
					}
				}
			} else {
				/*
				 * We read a hole in the file.
				 * We have to allocate blocks for the hole.
				 */
				error = bmap_write(ip, uoff, (offsetn + nbytes),
				    BI_ALLOC_ONLY, NULL, credp);
				if (ip->i_flag & (ICHG|IUPD))
					ip->i_seq++;
				if (error) {
					DEBUGF((CE_CONT, "?ufs_alloc_data: fill"
					    " hole failed error: %d\n", error));
					break;
				}
				if (fdbp != NULL) {
					fdb_add_hole(fdbp, uoff - offset,
					    nbytes);
				}
			}
		}
		done_len += nbytes;
	}

	if (error) {
		if (i_size_changed) {
			/*
			 * Allocation of the blocks for the file failed.
			 * So truncate the file size back to its original size.
			 */
			(void) ufs_itrunc(ip, old_i_size, 0, credp);
		}
	}

	DEBUGF((CE_CONT, "?ufs_alloc: uoff %llx len %lx\n",
	    uoff, (io_len - done_len)));

	if ((offset + *len) < (NDADDR * fs->fs_bsize)) {
		*len = (size_t)(roundup(offset + *len, fs->fs_fsize) - offset);
	} else {
		*len = (size_t)(roundup(offset + *len, fs->fs_bsize) - offset);
	}

	/*
	 * Flush cached pages.
	 *
	 * XXX - There should be no pages involved, since the I/O was performed
	 * through the device strategy routine and the page cache was bypassed.
	 * However, testing has demonstrated that this VOP_PUTPAGE is
	 * necessary. Without this, data might not always be read back as it
	 * was written.
	 *
	 */
	(void) VOP_PUTPAGE(vnodep, 0, 0, B_INVAL, credp, NULL);

	rw_exit(&ip->i_contents);
	rw_exit(&ip->i_ufsvfs->vfs_dqrwlock);

	if ((fdbp != NULL) && (flags & B_ASYNC)) {
		/*
		 * Show that no more asynchronous IO will be added
		 */
		fdb_ioerrdone(fdbp, error);
	}
	if (ulp) {
		/*
		 * End the UFS Log transaction
		 */
		TRANS_END_CSYNC(ufsvfsp, error, issync, TOP_GETPAGE,
		    trans_size);
		ufs_lockfs_end(ulp);
	}
	if (io_started && (flags & B_ASYNC)) {
		return (0);
	} else {
		return (error);
	}
}
