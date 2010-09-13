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
 * Copyright (c) 1983, 2010, Oracle and/or its affiliates. All rights reserved.
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
#include <sys/signal.h>
#include <sys/user.h>
#include <sys/vnode.h>
#include <sys/buf.h>
#include <sys/disp.h>
#include <sys/proc.h>
#include <sys/conf.h>
#include <sys/fs/ufs_inode.h>
#include <sys/fs/ufs_fs.h>
#include <sys/fs/ufs_quota.h>
#include <sys/fs/ufs_trans.h>
#include <sys/fs/ufs_bio.h>
#include <vm/seg.h>
#include <sys/errno.h>
#include <sys/sysmacros.h>
#include <sys/vfs.h>
#include <sys/debug.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>

/*
 * This structure is used to track blocks as we allocate them, so that
 * we can free them if we encounter an error during allocation.  We
 * keep track of five pieces of information for each allocated block:
 *   - The number of the newly allocated block
 *   - The size of the block (lets us deal with fragments if we want)
 *   - The number of the block containing a pointer to it; or whether
 *     the pointer is in the inode
 *   - The offset within the block (or inode) containing a pointer to it.
 *   - A flag indicating the usage of the block.  (Logging needs to know
 *     this to avoid overwriting a data block if it was previously used
 *     for metadata.)
 */

enum ufs_owner_type {
	ufs_no_owner,		/* Owner has not yet been updated */
	ufs_inode_direct,	/* Listed in inode's direct block table */
	ufs_inode_indirect,	/* Listed in inode's indirect block table */
	ufs_indirect_block	/* Listed in an indirect block */
};

struct ufs_allocated_block {
	daddr_t this_block;	    /* Number of this block */
	off_t block_size;	    /* Size of this block, in bytes */
	enum ufs_owner_type owner;  /* Who points to this block? */
	daddr_t owner_block;	    /* Number of the owning block */
	uint_t owner_offset;	    /* Offset within that block or inode */
	int usage_flags;	    /* Usage flags, as expected by free() */
};


static int findextent(struct fs *fs, daddr32_t *sbp, int n, int *lenp,
		int maxtrans);

static void ufs_undo_allocation(inode_t *ip, int block_count,
	struct ufs_allocated_block table[], int inode_sector_adjust);

/*
 * Find the extent and the matching block number.
 *
 * bsize > PAGESIZE
 *	boff indicates that we want a page in the middle
 *	min expression is supposed to make sure no extra page[s] after EOF
 * PAGESIZE >= bsize
 *	we assume that a page is a multiple of bsize, i.e.,
 *	boff always == 0
 *
 * We always return a length that is suitable for a disk transfer.
 */
#define	DOEXTENT(fs, lbn, boff, bnp, lenp, size, tblp, n, chkfrag, maxtrans) {\
	register daddr32_t *dp = (tblp);				\
	register int _chkfrag = chkfrag; /* for lint. sigh */		\
									\
	if (*dp == 0) {							\
		*(bnp) = UFS_HOLE;					\
	} else {							\
		register int len;					\
									\
		len = findextent(fs, dp, (int)(n), lenp, maxtrans) << 	\
			(fs)->fs_bshift; 				\
		if (_chkfrag) {						\
			register u_offset_t tmp;			\
									\
			tmp = fragroundup((fs), size) -			\
			    (((u_offset_t)lbn) << fs->fs_bshift);	\
			len = (int)MIN(tmp, len);			\
		}							\
		len -= (boff);						\
		if (len <= 0) {						\
			*(bnp) = UFS_HOLE;				\
		} else {						\
			*(bnp) = fsbtodb(fs, *dp) + btodb(boff);	\
			*(lenp) = len;					\
		}							\
	}								\
}

/*
 * The maximum supported file size is actually somewhat less that 1
 * terabyte.  This is because the total number of blocks used for the
 * file and its metadata must fit into the ic_blocks field of the
 * inode, which is a signed 32-bit quantity.  The metadata allocated
 * for a file (that is, the single, double, and triple indirect blocks
 * used to reference the file blocks) is actually quite small,
 * but just to make sure, we check for overflow in the ic_blocks
 * ic_blocks fields for all files whose total block count is
 * within 1 GB of a terabyte.  VERYLARGEFILESIZE below is the number of
 * 512-byte blocks in a terabyte (2^31), minus the number of 512-byte blocks
 * in a gigabyte (2^21).  We only check for overflow in the ic_blocks
 * field if the number of blocks currently allocated to the file is
 * greater than VERYLARGEFILESIZE.
 *
 * Note that file "size" is the not the same as file "length".  A
 * file's "size" is the number of blocks allocated to it.  A file's
 * "length" is the maximum offset in the file.  A UFS FILE can have a
 * length of a terabyte, but the size is limited to somewhat less than
 * a terabyte, as described above.
 */
#define	VERYLARGEFILESIZE	0x7FE00000

/*
 * bmap{read,write} define the structure of file system storage by mapping
 * a logical offset in a file to a physical block number on the device.
 * It should be called with a locked inode when allocation is to be
 * done (bmap_write).  Note this strangeness: bmap_write is always called from
 * getpage(), not putpage(), since getpage() is where all the allocation
 * is done.
 *
 * S_READ, S_OTHER -> bmap_read; S_WRITE -> bmap_write.
 *
 * NOTICE: the block number returned is the disk block number, not the
 * file system block number.  All the worries about block offsets and
 * page/block sizes are hidden inside of bmap.  Well, not quite,
 * unfortunately.  It's impossible to find one place to hide all this
 * mess.  There are 3 cases:
 *
 * PAGESIZE < bsize
 *	In this case, the {get,put}page routines will attempt to align to
 *	a file system block boundry (XXX - maybe this is a mistake?).  Since
 *	the kluster routines may be out of memory, we don't always get all
 *	the pages we wanted.  If we called bmap first, to find out how much
 *	to kluster, we handed in the block aligned offset.  If we didn't get
 *	all the pages, we have to chop off the amount we didn't get from the
 *	amount handed back by bmap.
 *
 * PAGESIZE == bsize
 *	Life is quite pleasant here, no extra work needed, mainly because we
 *	(probably?) won't kluster backwards, just forwards.
 *
 * PAGESIZE > bsize
 *	This one has a different set of problems, specifically, we may have to
 *	do N reads to fill one page.  Let us hope that Sun will stay with small
 *	pages.
 *
 * Returns 0 on success, or a non-zero errno if an error occurs.
 *
 * TODO
 *	LMXXX - add a bmap cache.  This could be a couple of extents in the
 *	inode.  Two is nice for PAGESIZE > bsize.
 */

int
bmap_read(struct inode *ip, u_offset_t off, daddr_t *bnp, int *lenp)
{
	daddr_t lbn;
	ufsvfs_t *ufsvfsp = ip->i_ufsvfs;
	struct	fs *fs = ufsvfsp->vfs_fs;
	struct	buf *bp;
	int	i, j, boff;
	int	shft;			/* we maintain sh = 1 << shft */
	daddr_t	ob, nb, tbn;
	daddr32_t *bap;
	int	nindirshift, nindiroffset;

	ASSERT(RW_LOCK_HELD(&ip->i_contents));
	lbn = (daddr_t)lblkno(fs, off);
	boff = (int)blkoff(fs, off);
	if (lbn < 0)
		return (EFBIG);

	/*
	 * The first NDADDR blocks are direct blocks.
	 */
	if (lbn < NDADDR) {
		DOEXTENT(fs, lbn, boff, bnp, lenp,
		    ip->i_size, &ip->i_db[lbn], NDADDR - lbn, 1,
		    ufsvfsp->vfs_iotransz);
		return (0);
	}

	nindirshift = ufsvfsp->vfs_nindirshift;
	nindiroffset = ufsvfsp->vfs_nindiroffset;
	/*
	 * Determine how many levels of indirection.
	 */
	shft = 0;				/* sh = 1 */
	tbn = lbn - NDADDR;
	for (j = NIADDR; j > 0; j--) {
		longlong_t	sh;

		shft += nindirshift;		/* sh *= nindir */
		sh = 1LL << shft;
		if (tbn < sh)
			break;
		tbn -= sh;
	}
	if (j == 0)
		return (EFBIG);

	/*
	 * Fetch the first indirect block.
	 */
	nb = ip->i_ib[NIADDR - j];
	if (nb == 0) {
		*bnp = UFS_HOLE;
		return (0);
	}

	/*
	 * Fetch through the indirect blocks.
	 */
	for (; j <= NIADDR; j++) {
		ob = nb;
		bp = UFS_BREAD(ufsvfsp,
		    ip->i_dev, fsbtodb(fs, ob), fs->fs_bsize);
		if (bp->b_flags & B_ERROR) {
			brelse(bp);
			return (EIO);
		}
		bap = bp->b_un.b_daddr;

		ASSERT(!ufs_indir_badblock(ip, bap));

		shft -= nindirshift;		/* sh / nindir */
		i = (tbn >> shft) & nindiroffset; /* (tbn / sh) % nindir */
		nb = bap[i];
		if (nb == 0) {
			*bnp = UFS_HOLE;
			brelse(bp);
			return (0);
		}
		if (j != NIADDR)
			brelse(bp);
	}
	DOEXTENT(fs, lbn, boff, bnp, lenp, ip->i_size, &bap[i],
	    MIN(NINDIR(fs) - i, (daddr_t)lblkno(fs, ip->i_size - 1) - lbn + 1),
	    0, ufsvfsp->vfs_iotransz);
	brelse(bp);
	return (0);
}

/*
 * See bmap_read for general notes.
 *
 * The block must be at least size bytes and will be extended or
 * allocated as needed.  If alloc_type is of type BI_ALLOC_ONLY, then bmap
 * will not create any in-core pages that correspond to the new disk allocation.
 * If alloc_type is of BI_FALLOCATE, blocks will be stored as (-1) * block addr
 * and security is maintained b/c upon reading a negative block number pages
 * are zeroed. For all other allocation types (BI_NORMAL) the in-core pages will
 * be created and initialized as needed.
 *
 * Returns 0 on success, or a non-zero errno if an error occurs.
 */
int
bmap_write(struct inode	*ip, u_offset_t	off, int size,
    enum bi_type alloc_type, daddr_t *allocblk, struct cred *cr)
{
	struct	fs *fs;
	struct	buf *bp;
	int	i;
	struct	buf *nbp;
	int	j;
	int	shft;				/* we maintain sh = 1 << shft */
	daddr_t	ob, nb, pref, lbn, llbn, tbn;
	daddr32_t *bap;
	struct	vnode *vp = ITOV(ip);
	long	bsize = VBSIZE(vp);
	long	osize, nsize;
	int	issync, metaflag, isdirquota;
	int	err;
	dev_t	dev;
	struct	fbuf *fbp;
	int	nindirshift;
	int	nindiroffset;
	struct	ufsvfs	*ufsvfsp;
	int	added_sectors;		/* sectors added to this inode */
	int	alloced_blocks;		/* fs blocks newly allocated */
	struct  ufs_allocated_block undo_table[NIADDR+1];
	int	verylargefile = 0;

	ASSERT(RW_WRITE_HELD(&ip->i_contents));

	if (allocblk)
		*allocblk = 0;

	ufsvfsp = ip->i_ufsvfs;
	fs = ufsvfsp->vfs_bufp->b_un.b_fs;
	lbn = (daddr_t)lblkno(fs, off);
	if (lbn < 0)
		return (EFBIG);
	if (ip->i_blocks >= VERYLARGEFILESIZE)
		verylargefile = 1;
	llbn = (daddr_t)((ip->i_size) ? lblkno(fs, ip->i_size - 1) : 0);
	metaflag = isdirquota = 0;
	if (((ip->i_mode & IFMT) == IFDIR) ||
	    ((ip->i_mode & IFMT) == IFATTRDIR))
		isdirquota = metaflag = I_DIR;
	else if ((ip->i_mode & IFMT) == IFSHAD)
		metaflag = I_SHAD;
	else if (ip->i_ufsvfs->vfs_qinod == ip)
		isdirquota = metaflag = I_QUOTA;

	issync = ((ip->i_flag & ISYNC) != 0);

	if (isdirquota || issync) {
		alloc_type = BI_NORMAL;	/* make sure */
	}

	/*
	 * If the next write will extend the file into a new block,
	 * and the file is currently composed of a fragment
	 * this fragment has to be extended to be a full block.
	 */
	if (llbn < NDADDR && llbn < lbn && (ob = ip->i_db[llbn]) != 0) {
		osize = blksize(fs, ip, llbn);
		if (osize < bsize && osize > 0) {
			/*
			 * Check to see if doing this will make the file too
			 * big.  Only check if we are dealing with a very
			 * large file.
			 */
			if (verylargefile == 1) {
				if (((unsigned)ip->i_blocks +
				    btodb(bsize - osize)) > INT_MAX) {
					return (EFBIG);
				}
			}
			/*
			 * Make sure we have all needed pages setup correctly.
			 *
			 * We pass S_OTHER to fbread here because we want
			 * an exclusive lock on the page in question
			 * (see ufs_getpage). I/O to the old block location
			 * may still be in progress and we are about to free
			 * the old block. We don't want anyone else to get
			 * a hold of the old block once we free it until
			 * the I/O is complete.
			 */
			err =
			    fbread(ITOV(ip), ((offset_t)llbn << fs->fs_bshift),
			    (uint_t)bsize, S_OTHER, &fbp);
			if (err)
				return (err);
			pref = blkpref(ip, llbn, (int)llbn, &ip->i_db[0]);
			err = realloccg(ip, ob, pref, (int)osize, (int)bsize,
			    &nb, cr);
			if (err) {
				if (fbp)
					fbrelse(fbp, S_OTHER);
				return (err);
			}
			ASSERT(!ufs_badblock(ip, nb));

			/*
			 * Update the inode before releasing the
			 * lock on the page. If we released the page
			 * lock first, the data could be written to it's
			 * old address and then destroyed.
			 */
			TRANS_MATA_ALLOC(ufsvfsp, ip, nb, bsize, 0);
			ip->i_db[llbn] = nb;
			UFS_SET_ISIZE(((u_offset_t)(llbn + 1)) << fs->fs_bshift,
			    ip);
			ip->i_blocks += btodb(bsize - osize);
			ASSERT((unsigned)ip->i_blocks <= INT_MAX);
			TRANS_INODE(ufsvfsp, ip);
			ip->i_flag |= IUPD | ICHG | IATTCHG;

			/* Caller is responsible for updating i_seq */
			/*
			 * Don't check metaflag here, directories won't do this
			 *
			 */
			if (issync) {
				(void) ufs_fbiwrite(fbp, ip, nb, fs->fs_fsize);
			} else {
				ASSERT(fbp);
				fbrelse(fbp, S_WRITE);
			}

			if (nb != ob) {
				(void) free(ip, ob, (off_t)osize, metaflag);
			}
		}
	}

	/*
	 * The first NDADDR blocks are direct blocks.
	 */
	if (lbn < NDADDR) {
		nb = ip->i_db[lbn];
		if (nb == 0 ||
		    ip->i_size < ((u_offset_t)(lbn + 1)) << fs->fs_bshift) {
			if (nb != 0) {
				/* consider need to reallocate a frag */
				osize = fragroundup(fs, blkoff(fs, ip->i_size));
				nsize = fragroundup(fs, size);
				if (nsize <= osize)
					goto gotit;
				/*
				 * Check to see if doing this will make the
				 * file too big.  Only check if we are dealing
				 * with a very large file.
				 */
				if (verylargefile == 1) {
					if (((unsigned)ip->i_blocks +
					    btodb(nsize - osize)) > INT_MAX) {
						return (EFBIG);
					}
				}
				/*
				 * need to re-allocate a block or frag
				 */
				ob = nb;
				pref = blkpref(ip, lbn, (int)lbn,
				    &ip->i_db[0]);
				err = realloccg(ip, ob, pref, (int)osize,
				    (int)nsize, &nb, cr);
				if (err)
					return (err);
				if (allocblk)
					*allocblk = nb;
				ASSERT(!ufs_badblock(ip, nb));

			} else {
				/*
				 * need to allocate a block or frag
				 */
				osize = 0;
				if (ip->i_size <
				    ((u_offset_t)(lbn + 1)) << fs->fs_bshift)
					nsize = fragroundup(fs, size);
				else
					nsize = bsize;
				/*
				 * Check to see if doing this will make the
				 * file too big.  Only check if we are dealing
				 * with a very large file.
				 */
				if (verylargefile == 1) {
					if (((unsigned)ip->i_blocks +
					    btodb(nsize - osize)) > INT_MAX) {
						return (EFBIG);
					}
				}
				pref = blkpref(ip, lbn, (int)lbn, &ip->i_db[0]);
				err = alloc(ip, pref, (int)nsize, &nb, cr);
				if (err)
					return (err);
				if (allocblk)
					*allocblk = nb;
				ASSERT(!ufs_badblock(ip, nb));
				ob = nb;
			}

			/*
			 * Read old/create new zero pages
			 */
			fbp = NULL;
			if (osize == 0) {
				/*
				 * mmap S_WRITE faults always enter here
				 */
				/*
				 * We zero it if its also BI_FALLOCATE, but
				 * only for direct blocks!
				 */
				if (alloc_type == BI_NORMAL ||
				    alloc_type == BI_FALLOCATE ||
				    P2ROUNDUP_TYPED(size,
				    PAGESIZE, u_offset_t) < nsize) {
					/* fbzero doesn't cause a pagefault */
					fbzero(ITOV(ip),
					    ((offset_t)lbn << fs->fs_bshift),
					    (uint_t)nsize, &fbp);
				}
			} else {
				err = fbread(vp,
				    ((offset_t)lbn << fs->fs_bshift),
				    (uint_t)nsize, S_OTHER, &fbp);
				if (err) {
					if (nb != ob) {
						(void) free(ip, nb,
						    (off_t)nsize, metaflag);
					} else {
						(void) free(ip,
						    ob + numfrags(fs, osize),
						    (off_t)(nsize - osize),
						    metaflag);
					}
					ASSERT(nsize >= osize);
					(void) chkdq(ip,
					    -(long)btodb(nsize - osize),
					    0, cr, (char **)NULL,
					    (size_t *)NULL);
					return (err);
				}
			}
			TRANS_MATA_ALLOC(ufsvfsp, ip, nb, nsize, 0);
			ip->i_db[lbn] = nb;
			ip->i_blocks += btodb(nsize - osize);
			ASSERT((unsigned)ip->i_blocks <= INT_MAX);
			TRANS_INODE(ufsvfsp, ip);
			ip->i_flag |= IUPD | ICHG | IATTCHG;

			/* Caller is responsible for updating i_seq */

			/*
			 * Write directory and shadow blocks synchronously so
			 * that they never appear with garbage in them on the
			 * disk.
			 *
			 */
			if (isdirquota && (ip->i_size ||
			    TRANS_ISTRANS(ufsvfsp))) {
			/*
			 * XXX man not be necessary with harpy trans
			 * bug id 1130055
			 */
				(void) ufs_fbiwrite(fbp, ip, nb, fs->fs_fsize);
			} else if (fbp) {
				fbrelse(fbp, S_WRITE);
			}

			if (nb != ob)
				(void) free(ip, ob, (off_t)osize, metaflag);
		}
gotit:
		return (0);
	}

	added_sectors = alloced_blocks = 0;	/* No blocks alloced yet */

	/*
	 * Determine how many levels of indirection.
	 */
	nindirshift = ip->i_ufsvfs->vfs_nindirshift;
	nindiroffset = ip->i_ufsvfs->vfs_nindiroffset;
	pref = 0;
	shft = 0;				/* sh = 1 */
	tbn = lbn - NDADDR;
	for (j = NIADDR; j > 0; j--) {
		longlong_t	sh;

		shft += nindirshift;		/* sh *= nindir */
		sh = 1LL << shft;
		if (tbn < sh)
			break;
		tbn -= sh;
	}

	if (j == 0)
		return (EFBIG);

	/*
	 * Fetch the first indirect block.
	 */
	dev = ip->i_dev;
	nb = ip->i_ib[NIADDR - j];
	if (nb == 0) {
		/*
		 * Check to see if doing this will make the
		 * file too big.  Only check if we are dealing
		 * with a very large file.
		 */
		if (verylargefile == 1) {
			if (((unsigned)ip->i_blocks + btodb(bsize))
			    > INT_MAX) {
				return (EFBIG);
			}
		}
		/*
		 * Need to allocate an indirect block.
		 */
		pref = blkpref(ip, lbn, 0, (daddr32_t *)0);
		err = alloc(ip, pref, (int)bsize, &nb, cr);
		if (err)
			return (err);
		TRANS_MATA_ALLOC(ufsvfsp, ip, nb, bsize, 1);
		ASSERT(!ufs_badblock(ip, nb));

		/*
		 * Keep track of this allocation so we can undo it if we
		 * get an error later.
		 */

		ASSERT(alloced_blocks <= NIADDR);

		undo_table[alloced_blocks].this_block = nb;
		undo_table[alloced_blocks].block_size = bsize;
		undo_table[alloced_blocks].owner = ufs_no_owner;
		undo_table[alloced_blocks].usage_flags = metaflag | I_IBLK;

		alloced_blocks++;

		/*
		 * Write zero block synchronously so that
		 * indirect blocks never point at garbage.
		 */
		bp = UFS_GETBLK(ufsvfsp, dev, fsbtodb(fs, nb), bsize);

		clrbuf(bp);
		/* XXX Maybe special-case this? */
		TRANS_BUF(ufsvfsp, 0, bsize, bp, DT_ABZERO);
		UFS_BWRITE2(ufsvfsp, bp);
		if (bp->b_flags & B_ERROR) {
			err = geterror(bp);
			brelse(bp);
			ufs_undo_allocation(ip, alloced_blocks,
			    undo_table, added_sectors);
			return (err);
		}
		brelse(bp);

		ip->i_ib[NIADDR - j] = nb;
		added_sectors += btodb(bsize);
		ip->i_blocks += btodb(bsize);
		ASSERT((unsigned)ip->i_blocks <= INT_MAX);
		TRANS_INODE(ufsvfsp, ip);
		ip->i_flag |= IUPD | ICHG | IATTCHG;
		/* Caller is responsible for updating i_seq */

		/*
		 * Update the 'undo table' now that we've linked this block
		 * to an inode.
		 */

		undo_table[alloced_blocks-1].owner = ufs_inode_indirect;
		undo_table[alloced_blocks-1].owner_offset = NIADDR - j;

		/*
		 * In the ISYNC case, wrip will notice that the block
		 * count on the inode has changed and will be sure to
		 * ufs_iupdat the inode at the end of wrip.
		 */
	}

	/*
	 * Fetch through the indirect blocks.
	 */
	for (; j <= NIADDR; j++) {
		ob = nb;
		bp = UFS_BREAD(ufsvfsp, ip->i_dev, fsbtodb(fs, ob), bsize);

		if (bp->b_flags & B_ERROR) {
			err = geterror(bp);
			brelse(bp);
			/*
			 * Return any partial allocations.
			 *
			 * It is possible that we have not yet made any
			 * allocations at this point (if this is the first
			 * pass through the loop and we didn't have to
			 * allocate the first indirect block, above).
			 * In this case, alloced_blocks and added_sectors will
			 * be zero, and ufs_undo_allocation will do nothing.
			 */
			ufs_undo_allocation(ip, alloced_blocks,
			    undo_table, added_sectors);
			return (err);
		}
		bap = bp->b_un.b_daddr;
		shft -= nindirshift;		/* sh /= nindir */
		i = (tbn >> shft) & nindiroffset; /* (tbn / sh) % nindir */
		nb = bap[i];

		if (nb == 0) {
			/*
			 * Check to see if doing this will make the
			 * file too big.  Only check if we are dealing
			 * with a very large file.
			 */
			if (verylargefile == 1) {
				if (((unsigned)ip->i_blocks + btodb(bsize))
				    > INT_MAX) {
					brelse(bp);
					ufs_undo_allocation(ip, alloced_blocks,
					    undo_table, added_sectors);
					return (EFBIG);
				}
			}
			if (pref == 0) {
				if (j < NIADDR) {
					/* Indirect block */
					pref = blkpref(ip, lbn, 0,
					    (daddr32_t *)0);
				} else {
					/* Data block */
					pref = blkpref(ip, lbn, i, &bap[0]);
				}
			}

			/*
			 * release "bp" buf to avoid deadlock (re-bread later)
			 */
			brelse(bp);

			err = alloc(ip, pref, (int)bsize, &nb, cr);
			if (err) {
				/*
				 * Return any partial allocations.
				 */
				ufs_undo_allocation(ip, alloced_blocks,
				    undo_table, added_sectors);
				return (err);
			}

			ASSERT(!ufs_badblock(ip, nb));
			ASSERT(alloced_blocks <= NIADDR);

			if (allocblk)
				*allocblk = nb;

			undo_table[alloced_blocks].this_block = nb;
			undo_table[alloced_blocks].block_size = bsize;
			undo_table[alloced_blocks].owner = ufs_no_owner;
			undo_table[alloced_blocks].usage_flags = metaflag |
			    ((j < NIADDR) ? I_IBLK : 0);

			alloced_blocks++;

			if (j < NIADDR) {
				TRANS_MATA_ALLOC(ufsvfsp, ip, nb, bsize, 1);
				/*
				 * Write synchronously so indirect
				 * blocks never point at garbage.
				 */
				nbp = UFS_GETBLK(
				    ufsvfsp, dev, fsbtodb(fs, nb), bsize);

				clrbuf(nbp);
				/* XXX Maybe special-case this? */
				TRANS_BUF(ufsvfsp, 0, bsize, nbp, DT_ABZERO);
				UFS_BWRITE2(ufsvfsp, nbp);
				if (nbp->b_flags & B_ERROR) {
					err = geterror(nbp);
					brelse(nbp);
					/*
					 * Return any partial
					 * allocations.
					 */
					ufs_undo_allocation(ip,
					    alloced_blocks,
					    undo_table, added_sectors);
					return (err);
				}
				brelse(nbp);
			} else if (alloc_type == BI_NORMAL ||
			    P2ROUNDUP_TYPED(size,
			    PAGESIZE, u_offset_t) < bsize) {
				TRANS_MATA_ALLOC(ufsvfsp, ip, nb, bsize, 0);
				fbzero(ITOV(ip),
				    ((offset_t)lbn << fs->fs_bshift),
				    (uint_t)bsize, &fbp);

				/*
				 * Cases which we need to do a synchronous
				 * write of the zeroed data pages:
				 *
				 * 1) If we are writing a directory then we
				 * want to write synchronously so blocks in
				 * directories never contain garbage.
				 *
				 * 2) If we are filling in a hole and the
				 * indirect block is going to be synchronously
				 * written back below we need to make sure
				 * that the zeroes are written here before
				 * the indirect block is updated so that if
				 * we crash before the real data is pushed
				 * we will not end up with random data is
				 * the middle of the file.
				 *
				 * 3) If the size of the request rounded up
				 * to the system page size is smaller than
				 * the file system block size, we want to
				 * write out all the pages now so that
				 * they are not aborted before they actually
				 * make it to ufs_putpage since the length
				 * of the inode will not include the pages.
				 */

				if (isdirquota || (issync &&
				    lbn < llbn))
					(void) ufs_fbiwrite(fbp, ip, nb,
					    fs->fs_fsize);
				else
					fbrelse(fbp, S_WRITE);
			}

			/*
			 * re-acquire "bp" buf
			 */
			bp = UFS_BREAD(ufsvfsp,
			    ip->i_dev, fsbtodb(fs, ob), bsize);
			if (bp->b_flags & B_ERROR) {
				err = geterror(bp);
				brelse(bp);
				/*
				 * Return any partial allocations.
				 */
				ufs_undo_allocation(ip,
				    alloced_blocks,
				    undo_table, added_sectors);
				return (err);
			}
			bap = bp->b_un.b_daddr;
			bap[i] = nb;

			/*
			 * The magic explained: j will be equal to NIADDR
			 * when we are at the lowest level, this is where the
			 * array entries point directly to data blocks. Since
			 * we will be 'fallocate'ing we will go ahead and negate
			 * the addresses.
			 */
			if (alloc_type == BI_FALLOCATE && j == NIADDR)
				bap[i] = -bap[i];

			TRANS_BUF_ITEM_128(ufsvfsp, bap[i], bap, bp, DT_AB);
			added_sectors += btodb(bsize);
			ip->i_blocks += btodb(bsize);
			ASSERT((unsigned)ip->i_blocks <= INT_MAX);
			TRANS_INODE(ufsvfsp, ip);
			ip->i_flag |= IUPD | ICHG | IATTCHG;

			/* Caller is responsible for updating i_seq */

			undo_table[alloced_blocks-1].owner =
			    ufs_indirect_block;
			undo_table[alloced_blocks-1].owner_block = ob;
			undo_table[alloced_blocks-1].owner_offset = i;

			if (issync) {
				UFS_BWRITE2(ufsvfsp, bp);
				if (bp->b_flags & B_ERROR) {
					err = geterror(bp);
					brelse(bp);
					/*
					 * Return any partial
					 * allocations.
					 */
					ufs_undo_allocation(ip,
					    alloced_blocks,
					    undo_table, added_sectors);
					return (err);
				}
				brelse(bp);
			} else {
				bdrwrite(bp);
			}
		} else {
			brelse(bp);
		}
	}
	return (0);
}

/*
 * Return 1 if inode has unmapped blocks (UFS holes) or if another thread
 * is in the critical region of wrip().
 */
int
bmap_has_holes(struct inode *ip)
{
	struct fs *fs = ip->i_fs;
	uint_t	dblks; 			/* # of data blocks */
	uint_t	mblks;			/* # of data + metadata blocks */
	int	nindirshift;
	int	nindiroffset;
	uint_t	cnt;
	int	n, j, shft;
	uint_t nindirblks;

	int	fsbshift = fs->fs_bshift;
	int	fsboffset = (1 << fsbshift) - 1;

	/*
	 * Check for writer in critical region, if found then we
	 * cannot trust the values of i_size and i_blocks
	 * simply return true.
	 */
	if (ip->i_writer != NULL && ip->i_writer != curthread) {
		return (1);
	}

	dblks = (ip->i_size + fsboffset) >> fsbshift;
	mblks = (ldbtob((u_offset_t)ip->i_blocks) + fsboffset) >> fsbshift;

	/*
	 * File has only direct blocks.
	 */
	if (dblks <= NDADDR)
		return (mblks < dblks);
	nindirshift = ip->i_ufsvfs->vfs_nindirshift;

	nindiroffset = ip->i_ufsvfs->vfs_nindiroffset;
	nindirblks = nindiroffset + 1;

	dblks -= NDADDR;
	shft = 0;
	/*
	 * Determine how many levels of indirection.
	 */
	for (j = NIADDR; j > 0; j--) {
		longlong_t	sh;

		shft += nindirshift;	/* sh *= nindir */
		sh = 1LL << shft;
		if (dblks <= sh)
			break;
		dblks -= sh;
	}
	/* LINTED: warning: logical expression always true: op "||" */
	ASSERT(NIADDR <= 3);
	ASSERT(j <= NIADDR);
	if (j == NIADDR)	/* single level indirection */
		cnt = NDADDR + 1 + dblks;
	else if (j == NIADDR-1) /* double indirection */
		cnt = NDADDR + 1 + nindirblks +
		    1 + (dblks + nindiroffset)/nindirblks + dblks;
	else if (j == NIADDR-2) { /* triple indirection */
		n = (dblks + nindiroffset)/nindirblks;
		cnt = NDADDR + 1 + nindirblks +
		    1 + nindirblks + nindirblks*nindirblks +
		    1 + (n + nindiroffset)/nindirblks + n + dblks;
	}

	return (mblks < cnt);
}

/*
 * find some contig blocks starting at *sbp and going for min(n, max_contig)
 * return the number of blocks (not frags) found.
 * The array passed in must be at least [0..n-1].
 */
static int
findextent(struct fs *fs, daddr32_t *sbp, int n, int *lenp, int maxtransfer)
{
	register daddr_t bn, nextbn;
	register daddr32_t *bp;
	register int diff;
	int maxtransblk;

	if (n <= 0)
		return (0);
	bn = *sbp;
	if (bn == 0)
		return (0);

	diff = fs->fs_frag;
	if (*lenp) {
		n = MIN(n, lblkno(fs, *lenp));
	} else {
		/*
		 * If the user has set the value for maxcontig lower than
		 * the drive transfer size, then assume they want this
		 * to be the maximum value for the size of the data transfer.
		 */
		maxtransblk = maxtransfer >> DEV_BSHIFT;
		if (fs->fs_maxcontig < maxtransblk) {
			n = MIN(n, fs->fs_maxcontig);
		} else {
			n = MIN(n, maxtransblk);
		}
	}
	bp = sbp;
	while (--n > 0) {
		nextbn = *(bp + 1);
		if (nextbn == 0 || bn + diff != nextbn)
			break;
		bn = nextbn;
		bp++;
	}
	return ((int)(bp - sbp) + 1);
}

/*
 * Free any blocks which had been successfully allocated.  Always called
 * as a result of an error, so we don't bother returning an error code
 * from here.
 *
 * If block_count and inode_sector_adjust are both zero, we'll do nothing.
 * Thus it is safe to call this as part of error handling, whether or not
 * any blocks have been allocated.
 *
 * The ufs_inode_direct case is currently unused.
 */

static void
ufs_undo_allocation(
	inode_t *ip,
	int block_count,
	struct ufs_allocated_block table[],
	int inode_sector_adjust)
{
	int i;
	int inode_changed;
	int error_updating_pointers;
	struct ufsvfs *ufsvfsp;

	inode_changed = 0;
	error_updating_pointers = 0;

	ufsvfsp = ip->i_ufsvfs;

	/*
	 * Update pointers on disk before freeing blocks.  If we fail,
	 * some blocks may remain busy; but they will be reclaimed by
	 * an fsck.  (This is better than letting a block wind up with
	 * two owners if we successfully freed it but could not remove
	 * the pointer to it.)
	 */

	for (i = 0; i < block_count; i++) {
		switch (table[i].owner) {
		case ufs_no_owner:
			/* Nothing to do here, nobody points to us */
			break;
		case ufs_inode_direct:
			ASSERT(table[i].owner_offset < NDADDR);
			ip->i_db[table[i].owner_offset] = 0;
			inode_changed = 1;
			break;
		case ufs_inode_indirect:
			ASSERT(table[i].owner_offset < NIADDR);
			ip->i_ib[table[i].owner_offset] = 0;
			inode_changed = 1;
			break;
		case ufs_indirect_block: {
			buf_t *bp;
			daddr32_t *block_data;

			/* Read/modify/log/write. */

			ASSERT(table[i].owner_offset <
			    (VBSIZE(ITOV(ip)) / sizeof (daddr32_t)));

			bp = UFS_BREAD(ufsvfsp, ip->i_dev,
			    fsbtodb(ufsvfsp->vfs_fs, table[i].owner_block),
			    VBSIZE(ITOV(ip)));

			if (bp->b_flags & B_ERROR) {
				/* Couldn't read this block; give up. */
				error_updating_pointers = 1;
				brelse(bp);
				break;		/* out of SWITCH */
			}

			block_data = bp->b_un.b_daddr;
			block_data[table[i].owner_offset] = 0;

			/* Write a log entry which includes the zero. */
			/* It might be possible to optimize this by using */
			/* TRANS_BUF directly and zeroing only the four */
			/* bytes involved, but an attempt to do that led */
			/* to panics in the logging code.  The attempt was */
			/* TRANS_BUF(ufsvfsp,				  */
			/*    table[i].owner_offset * sizeof (daddr32_t), */
			/*    sizeof (daddr32_t),			  */
			/*    bp,					  */
			/*    DT_ABZERO);				  */

			TRANS_BUF_ITEM_128(ufsvfsp,
			    block_data[table[i].owner_offset],
			    block_data, bp, DT_AB);

			/* Now we can write the buffer itself. */

			UFS_BWRITE2(ufsvfsp, bp);

			if (bp->b_flags & B_ERROR) {
				error_updating_pointers = 1;
			}

			brelse(bp);
			break;
		}
		default:
			(void) ufs_fault(ITOV(ip),
			    "ufs_undo_allocation failure\n");
			break;
		}
	}

	/*
	 * If the inode changed, or if we need to update its block count,
	 * then do that now.  We update the inode synchronously on disk
	 * to ensure that it won't transiently point at a block we've
	 * freed (only necessary if we're not logging).
	 *
	 * NOTE: Currently ufs_iupdat() does not check for errors.  When
	 * it is fixed, we should verify that we successfully updated the
	 * inode before freeing blocks below.
	 */

	if (inode_changed || (inode_sector_adjust != 0)) {
		ip->i_blocks -= inode_sector_adjust;
		ASSERT((unsigned)ip->i_blocks <= INT_MAX);
		TRANS_INODE(ufsvfsp, ip);
		ip->i_flag |= IUPD | ICHG | IATTCHG;
		ip->i_seq++;
		if (!TRANS_ISTRANS(ufsvfsp))
			ufs_iupdat(ip, I_SYNC);
	}

	/*
	 * Now we go through and actually free the blocks, but only if we
	 * successfully removed the pointers to them.
	 */

	if (!error_updating_pointers) {
		for (i = 0; i < block_count; i++) {
			free(ip, table[i].this_block, table[i].block_size,
			    table[i].usage_flags);
		}
	}
}

/*
 * Find the next hole or data block in file starting at *off
 * Return found offset in *off, which can be less than the
 * starting offset if not block aligned.
 * This code is based on bmap_read().
 * Errors: ENXIO for end of file
 *         EIO for block read error.
 */
int
bmap_find(struct inode *ip, boolean_t hole, u_offset_t *off)
{
	ufsvfs_t *ufsvfsp = ip->i_ufsvfs;
	struct fs *fs = ufsvfsp->vfs_fs;
	buf_t *bp[NIADDR];
	int i, j;
	int shft;			/* we maintain sh = 1 << shft */
	int nindirshift, nindiroffset;
	daddr_t	ob, nb, tbn, lbn, skip;
	daddr32_t *bap;
	u_offset_t isz = (offset_t)ip->i_size;
	int32_t bs = fs->fs_bsize; /* file system block size */
	int32_t nindir = fs->fs_nindir;
	dev_t dev;
	int error = 0;
	daddr_t limits[NIADDR];

	ASSERT(*off < isz);
	ASSERT(RW_LOCK_HELD(&ip->i_contents));
	lbn = (daddr_t)lblkno(fs, *off);
	ASSERT(lbn >= 0);

	for (i = 0; i < NIADDR; i++)
		bp[i] = NULL;

	/*
	 * The first NDADDR blocks are direct blocks.
	 */
	if (lbn < NDADDR) {
		for (; lbn < NDADDR; lbn++) {
			if ((hole && (ip->i_db[lbn] == 0)) ||
			    (!hole && (ip->i_db[lbn] != 0))) {
				goto out;
			}
		}
		if ((u_offset_t)lbn << fs->fs_bshift >= isz)
			goto out;
	}

	nindir = fs->fs_nindir;
	nindirshift = ufsvfsp->vfs_nindirshift;
	nindiroffset = ufsvfsp->vfs_nindiroffset;
	dev = ip->i_dev;

	/* Set up limits array */
	for (limits[0] = NDADDR, j = 1; j  < NIADDR; j++)
		limits[j] = limits[j-1] + (1ULL << (nindirshift * j));

loop:
	/*
	 * Determine how many levels of indirection.
	 */
	shft = 0;				/* sh = 1 */
	tbn = lbn - NDADDR;
	for (j = NIADDR; j > 0; j--) {
		longlong_t sh;

		shft += nindirshift;		/* sh *= nindir */
		sh = 1LL << shft;
		if (tbn < sh)
			break;
		tbn -= sh;
	}
	if (j == 0) {
		/* must have passed end of file */
		ASSERT(((u_offset_t)lbn << fs->fs_bshift) >= isz);
		goto out;
	}

	/*
	 * Fetch the first indirect block.
	 */
	nb = ip->i_ib[NIADDR - j];
	if (nb == 0) {
		if (hole) {
			lbn = limits[NIADDR - j];
			goto out;
		} else {
			lbn = limits[NIADDR - j + 1];
			if ((u_offset_t)lbn << fs->fs_bshift >= isz)
				goto out;
			goto loop;
		}
	}

	/*
	 * Fetch through the indirect blocks.
	 */
	for (; ((j <= NIADDR) && (nb != 0)); j++) {
		ob = nb;
		/*
		 * if there's a different block at this level then release
		 * the old one and in with the new.
		 */
		if ((bp[j-1] == NULL) || bp[j-1]->b_blkno != fsbtodb(fs, ob)) {
			if (bp[j-1] != NULL)
				brelse(bp[j-1]);
			bp[j-1] = UFS_BREAD(ufsvfsp, dev, fsbtodb(fs, ob), bs);
			if (bp[j-1]->b_flags & B_ERROR) {
				error = EIO;
				goto out;
			}
		}
		bap = bp[j-1]->b_un.b_daddr;

		shft -= nindirshift;		/* sh / nindir */
		i = (tbn >> shft) & nindiroffset; /* (tbn / sh) % nindir */
		nb = bap[i];
		skip = 1LL << (nindirshift * (NIADDR - j));
	}

	/*
	 * Scan through the blocks in this array.
	 */
	for (; i < nindir; i++, lbn += skip) {
		if (hole && (bap[i] == 0))
			goto out;
		if (!hole && (bap[i] != 0)) {
			if (skip == 1) {
				/* we're at the lowest level */
				goto out;
			} else {
				goto loop;
			}
		}
	}
	if (((u_offset_t)lbn << fs->fs_bshift) < isz)
		goto loop;
out:
	for (i = 0; i < NIADDR; i++) {
		if (bp[i])
			brelse(bp[i]);
	}
	if (error == 0) {
		if (((u_offset_t)lbn << fs->fs_bshift) >= isz) {
			error = ENXIO;
		} else {
			/* success */
			*off = (u_offset_t)lbn << fs->fs_bshift;
		}
	}
	return (error);
}

/*
 * Set a particular offset in the inode list to be a certain block.
 * User is responsible for calling TRANS* functions
 */
int
bmap_set_bn(struct vnode *vp, u_offset_t off, daddr32_t bn)
{
	daddr_t lbn;
	struct inode *ip;
	ufsvfs_t *ufsvfsp;
	struct	fs *fs;
	struct	buf *bp;
	int	i, j;
	int	shft;			/* we maintain sh = 1 << shft */
	int err;
	daddr_t	ob, nb, tbn;
	daddr32_t *bap;
	int	nindirshift, nindiroffset;

	ip = VTOI(vp);
	ufsvfsp = ip->i_ufsvfs;
	fs = ufsvfsp->vfs_fs;
	lbn = (daddr_t)lblkno(fs, off);

	ASSERT(RW_LOCK_HELD(&ip->i_contents));

	if (lbn < 0)
		return (EFBIG);

	/*
	 * Take care of direct block assignment
	 */
	if (lbn < NDADDR) {
		ip->i_db[lbn] = bn;
		return (0);
	}

	nindirshift = ip->i_ufsvfs->vfs_nindirshift;
	nindiroffset = ip->i_ufsvfs->vfs_nindiroffset;
	/*
	 * Determine how many levels of indirection.
	 */
	shft = 0;				/* sh = 1 */
	tbn = lbn - NDADDR;
	for (j = NIADDR; j > 0; j--) {
		longlong_t	sh;

		shft += nindirshift;		/* sh *= nindir */
		sh = 1LL << shft;
		if (tbn < sh)
			break;
		tbn -= sh;
	}
	if (j == 0)
		return (EFBIG);

	/*
	 * Fetch the first indirect block.
	 */
	nb = ip->i_ib[NIADDR - j];
	if (nb == 0) {
		err = ufs_fault(ITOV(ip), "ufs_set_bn: nb == UFS_HOLE");
		return (err);
	}

	/*
	 * Fetch through the indirect blocks.
	 */
	for (; j <= NIADDR; j++) {
		ob = nb;
		bp = UFS_BREAD(ufsvfsp,
		    ip->i_dev, fsbtodb(fs, ob), fs->fs_bsize);
		if (bp->b_flags & B_ERROR) {
			err = geterror(bp);
			brelse(bp);
			return (err);
		}
		bap = bp->b_un.b_daddr;

		ASSERT(!ufs_indir_badblock(ip, bap));

		shft -= nindirshift;		/* sh / nindir */
		i = (tbn >> shft) & nindiroffset; /* (tbn / sh) % nindir */

		nb = bap[i];
		if (nb == 0) {
			err = ufs_fault(ITOV(ip), "ufs_set_bn: nb == UFS_HOLE");
			return (err);
		}

		if (j == NIADDR) {
			bap[i] = bn;
			bdrwrite(bp);
			return (0);
		}

		brelse(bp);
	}
	return (0);
}
