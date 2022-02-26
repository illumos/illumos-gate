/*
 * Copyright (c) 1988, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright (c) 1980, 1986, 1990 The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that: (1) source distributions retain this entire copyright
 * notice and comment, and (2) distributions including binaries display
 * the following acknowledgement:  ``This product includes software
 * developed by the University of California, Berkeley and its contributors''
 * in the documentation or other materials provided with the distribution
 * and in all advertising materials mentioning features or use of this
 * software. Neither the name of the University nor the names of its
 * contributors may be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <limits.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/mntent.h>
#include <sys/vnode.h>
#include <sys/fs/ufs_inode.h>
#include <sys/fs/ufs_fs.h>
#define	_KERNEL
#include <sys/fs/ufs_fsdir.h>
#undef _KERNEL
#include <pwd.h>
#include "fsck.h"

uint_t largefile_count = 0;
fsck_ino_t lastino;
struct bufarea cgblk;
struct inoinfo **aclphead, **aclpsort;
struct dinode zino;

static int get_indir_offsets(int, daddr_t, int *, int *);
static int clearanentry(struct inodesc *);
static void pdinode(struct dinode *);
static void inoflush(void);
static void mark_delayed_inodes(fsck_ino_t, daddr32_t);
static int iblock(struct inodesc *, int, u_offset_t, enum cki_action);
static struct inoinfo *search_cache(struct inoinfo *, fsck_ino_t);
static int ckinode_common(struct dinode *, struct inodesc *, enum cki_action);
static int lookup_dotdot_ino(fsck_ino_t);

/*
 * ckinode() essentially traverses the blocklist of the provided
 * inode.  For each block either the caller-supplied callback (id_func
 * in the provided struct inodesc) or dirscan() is invoked.  Which is
 * chosen is controlled by what type of traversal was requested
 * (id_type) - if it was for an ADDR or ACL, use the callback,
 * otherwise it is assumed to be DATA (i.e., a directory) whose
 * contents need to be scanned.
 *
 * Note that a directory inode can get passed in with a type of ADDR;
 * the type field is orthogonal to the IFMT value.  This is so that
 * the file aspects (no duplicate blocks, etc) of a directory can be
 * verified just like is done for any other file, or the actual
 * contents can be scanned so that connectivity and such can be
 * investigated.
 *
 * The traversal is controlled by flags in the return value of
 * dirscan() or the callback.  Five flags are defined, STOP, SKIP,
 * KEEPON, ALTERED, and FOUND.  Their semantics are:
 *
 *     STOP -    no further processing of this inode is desired/possible/
 *               feasible/etc.  This can mean that whatever the scan
 *               was searching for was found, or a serious
 *               inconsistency was encountered, or anything else
 *               appropriate.
 *
 *     SKIP -    something that made it impossible to continue was
 *               encountered, and the caller should go on to the next
 *               inode.  This is more for i/o failures than for
 *               logical inconsistencies.  Nothing actually looks for
 *               this.
 *
 *     KEEPON -  no more blocks of this inode need to be scanned, but
 *               nothing's wrong, so keep on going with the next
 *               inode.  It is similar to STOP, except that
 *               ckinode()'s caller will typically advance to the next
 *               inode for KEEPON, whereas it ceases scanning through
 *               the inodes completely for STOP.
 *
 *     ALTERED - a change was made to the inode.  If the caller sees
 *               this set, it should make sure to flush out the
 *               changes.  Note that any data blocks read in by the
 *               function need to be marked dirty by it directly;
 *               flushing of those will happen automatically later.
 *
 *     FOUND -   whatever was being searched for was located.
 *               Typically combined with STOP to avoid wasting time
 *               doing additional looking.
 *
 * During a traversal, some state needs to be carried around.  At the
 * least, the callback functions need to know what inode they're
 * working on, which logical block, and whether or not fixing problems
 * when they're encountered is desired.  Rather than try to guess what
 * else might be needed (and thus end up passing way more arguments
 * than is reasonable), all the possibilities have been bundled in
 * struct inodesc.  About half of the fields are specific to directory
 * traversals, and the rest are pretty much generic to any traversal.
 *
 * The general fields are:
 *
 *     id_fix        What to do when an error is found.  Generally, this
 *                   is set to DONTKNOW before a traversal.  If a
 *                   problem is encountered, it is changed to either FIX
 *                   or NOFIX by the dofix() query function.  If id_fix
 *                   has already been set to FIX when dofix() is called, then
 *                   it includes the ALTERED flag (see above) in its return
 *                   value; the net effect is that the inode's buffer
 *                   will get marked dirty and written to disk at some
 *                   point.  If id_fix is DONTKNOW, then dofix() will
 *                   query the user.  If it is NOFIX, then dofix()
 *                   essentially does nothing.  A few routines set NOFIX
 *                   as the initial value, as they are performing a best-
 *                   effort informational task, rather than an actual
 *                   repair operation.
 *
 *     id_func       This is the function that will be called for every
 *                   logical block in the file (assuming id_type is not
 *                   DATA).  The logical block may represent a hole, so
 *                   the callback needs to be prepared to handle that
 *                   case.  Its return value is a combination of the flags
 *                   described above (SKIP, ALTERED, etc).
 *
 *     id_number     The inode number whose block list or data is being
 *                   scanned.
 *
 *     id_parent     When id_type is DATA, this is the inode number for
 *                   the parent of id_number.  Otherwise, it is
 *                   available for use as an extra parameter or return
 *                   value between the callback and ckinode()'s caller.
 *                   Which, if either, of those is left completely up to
 *                   the two routines involved, so nothing can generally
 *                   be assumed about the id_parent value for non-DATA
 *                   traversals.
 *
 *     id_lbn        This is the current logical block (not fragment)
 *                   number being visited by the traversal.
 *
 *     id_blkno      This is the physical block corresponding to id_lbn.
 *
 *     id_numfrags   This defines how large a block is being processed in
 *                   this particular invocation of the callback.
 *                   Usually, it will be the same as sblock.fs_frag.
 *                   However, if a direct block is being processed and
 *                   it is less than a full filesystem block,
 *                   id_numfrags will indicate just how many fragments
 *                   (starting from id_lbn) are actually part of the
 *                   file.
 *
 *     id_truncto    The pass 4 callback is used in several places to
 *                   free the blocks of a file (the `FILE HAS PROBLEM
 *                   FOO; CLEAR?' scenario).  This has been generalized
 *                   to allow truncating a file to a particular length
 *                   rather than always completely discarding it.  If
 *                   id_truncto is -1, then the entire file is released,
 *                   otherwise it is logical block number to truncate
 *                   to.  This generalized interface was motivated by a
 *                   desire to be able to discard everything after a
 *                   hole in a directory, rather than the entire
 *                   directory.
 *
 *     id_type       Selects the type of traversal.  DATA for dirscan(),
 *                   ADDR or ACL for using the provided callback.
 *
 * There are several more fields used just for dirscan() traversals:
 *
 *     id_filesize   The number of bytes in the overall directory left to
 *                   process.
 *
 *     id_loc        Byte position within the directory block.  Should always
 *                   point to the start of a directory entry.
 *
 *     id_entryno    Which logical directory entry is being processed (0
 *                   is `.', 1 is `..', 2 and on are normal entries).
 *                   This field is primarily used to enable special
 *                   checks when looking at the first two entries.
 *
 *                   The exception (there's always an exception in fsck)
 *                   is that in pass 1, it tracks how many fragments are
 *                   being used by a particular inode.
 *
 *     id_firsthole  The first logical block number that was found to
 *                   be zero.  As directories are not supposed to have
 *                   holes, this marks where a directory should be
 *                   truncated down to.  A value of -1 indicates that
 *                   no holes were found.
 *
 *     id_dirp       A pointer to the in-memory copy of the current
 *                   directory entry (as identified by id_loc).
 *
 *     id_name       This is a directory entry name to either create
 *                   (callback is mkentry) or locate (callback is
 *                   chgino, findino, or findname).
 */
int
ckinode(struct dinode *dp, struct inodesc *idesc, enum cki_action action)
{
	struct inodesc cleardesc;
	mode_t	mode;

	if (idesc->id_filesize == 0)
		idesc->id_filesize = (offset_t)dp->di_size;

	/*
	 * Our caller should be filtering out completely-free inodes
	 * (mode == zero), so we'll work on the assumption that what
	 * we're given has some basic validity.
	 *
	 * The kernel is inconsistent about MAXPATHLEN including the
	 * trailing \0, so allow the more-generous length for symlinks.
	 */
	mode = dp->di_mode & IFMT;
	if (mode == IFBLK || mode == IFCHR)
		return (KEEPON);
	if (mode == IFLNK && dp->di_size > MAXPATHLEN) {
		pwarn("I=%d  Symlink longer than supported maximum\n",
		    idesc->id_number);
		init_inodesc(&cleardesc);
		cleardesc.id_type = ADDR;
		cleardesc.id_number = idesc->id_number;
		cleardesc.id_fix = DONTKNOW;
		clri(&cleardesc, "BAD", CLRI_VERBOSE, CLRI_NOP_CORRUPT);
		return (STOP);
	}
	return (ckinode_common(dp, idesc, action));
}

/*
 * This was split out from ckinode() to allow it to be used
 * without having to pass in kludge flags to suppress the
 * wrong-for-deletion initialization and irrelevant checks.
 * This feature is no longer needed, but is being kept in case
 * the need comes back.
 */
static int
ckinode_common(struct dinode *dp, struct inodesc *idesc,
	enum cki_action action)
{
	offset_t offset;
	struct dinode dino;
	daddr_t ndb;
	int indir_data_blks, last_indir_blk;
	int ret, i, frags;

	(void) memmove(&dino, dp, sizeof (struct dinode));
	ndb = howmany(dino.di_size, (u_offset_t)sblock.fs_bsize);

	for (i = 0; i < NDADDR; i++) {
		idesc->id_lbn++;
		offset = blkoff(&sblock, dino.di_size);
		if ((--ndb == 0) && (offset != 0)) {
			idesc->id_numfrags =
			    numfrags(&sblock, fragroundup(&sblock, offset));
		} else {
			idesc->id_numfrags = sblock.fs_frag;
		}
		if (dino.di_db[i] == 0) {
			if ((ndb > 0) && (idesc->id_firsthole < 0)) {
				idesc->id_firsthole = i;
			}
			continue;
		}
		idesc->id_blkno = dino.di_db[i];
		if (idesc->id_type == ADDR || idesc->id_type == ACL)
			ret = (*idesc->id_func)(idesc);
		else
			ret = dirscan(idesc);

		/*
		 * Need to clear the entry, now that we're done with
		 * it.  We depend on freeblk() ignoring a request to
		 * free already-free fragments to handle the problem of
		 * a partial block.
		 */
		if ((action == CKI_TRUNCATE) &&
		    (idesc->id_truncto >= 0) &&
		    (idesc->id_lbn >= idesc->id_truncto)) {
			dp = ginode(idesc->id_number);
			/*
			 * The (int) cast is safe, in that if di_size won't
			 * fit, it'll be a multiple of any legal fs_frag,
			 * thus giving a zero result.  That value, in turn
			 * means we're doing an entire block.
			 */
			frags = howmany((int)dp->di_size, sblock.fs_fsize) %
			    sblock.fs_frag;
			if (frags == 0)
				frags = sblock.fs_frag;
			freeblk(idesc->id_number, dp->di_db[i],
			    frags);
			dp = ginode(idesc->id_number);
			dp->di_db[i] = 0;
			inodirty();
			ret |= ALTERED;
		}

		if (ret & STOP)
			return (ret);
	}

#ifdef lint
	/*
	 * Cure a lint complaint of ``possible use before set''.
	 * Apparently it can't quite figure out the switch statement.
	 */
	indir_data_blks = 0;
#endif
	/*
	 * indir_data_blks contains the number of data blocks in all
	 * the previous levels for this iteration.  E.g., for the
	 * single indirect case (i = 0, di_ib[i] != 0), NDADDR's worth
	 * of blocks have already been covered by the direct blocks
	 * (di_db[]).  At the triple indirect level (i = NIADDR - 1),
	 * it is all of the number of data blocks that were covered
	 * by the second indirect, single indirect, and direct block
	 * levels.
	 */
	idesc->id_numfrags = sblock.fs_frag;
	ndb = howmany(dino.di_size, (u_offset_t)sblock.fs_bsize);
	for (i = 0; i < NIADDR; i++) {
		(void) get_indir_offsets(i, ndb, &indir_data_blks,
		    &last_indir_blk);
		if (dino.di_ib[i] != 0) {
			/*
			 * We'll only clear di_ib[i] if the first entry (and
			 * therefore all of them) is to be cleared, since we
			 * only go through this code on the first entry of
			 * each level of indirection.  The +1 is to account
			 * for the fact that we don't modify id_lbn until
			 * we actually start processing on a data block.
			 */
			idesc->id_blkno = dino.di_ib[i];
			ret = iblock(idesc, i + 1,
			    (u_offset_t)howmany(dino.di_size,
			    (u_offset_t)sblock.fs_bsize) - indir_data_blks,
			    action);
			if ((action == CKI_TRUNCATE) &&
			    (idesc->id_truncto <= indir_data_blks) &&
			    ((idesc->id_lbn + 1) >= indir_data_blks) &&
			    ((idesc->id_lbn + 1) <= last_indir_blk)) {
				dp = ginode(idesc->id_number);
				if (dp->di_ib[i] != 0) {
					freeblk(idesc->id_number, dp->di_ib[i],
					    sblock.fs_frag);
				}
			}
			if (ret & STOP)
				return (ret);
		} else {
			/*
			 * Need to know which of the file's logical blocks
			 * reside in the missing indirect block.  However, the
			 * precise location is only needed for truncating
			 * directories, and level-of-indirection precision is
			 * sufficient for that.
			 */
			if ((indir_data_blks < ndb) &&
			    (idesc->id_firsthole < 0)) {
				idesc->id_firsthole = indir_data_blks;
			}
		}
	}
	return (KEEPON);
}

static int
get_indir_offsets(int ilevel_wanted, daddr_t ndb, int *data_blks,
	int *last_blk)
{
	int ndb_ilevel = -1;
	int ilevel;
	int dblks, lblk;

	for (ilevel = 0; ilevel < NIADDR; ilevel++) {
		switch (ilevel) {
		case 0:	/* SINGLE */
			dblks = NDADDR;
			lblk = dblks + NINDIR(&sblock) - 1;
			break;
		case 1:	/* DOUBLE */
			dblks = NDADDR + NINDIR(&sblock);
			lblk = dblks + (NINDIR(&sblock) * NINDIR(&sblock)) - 1;
			break;
		case 2:	/* TRIPLE */
			dblks = NDADDR + NINDIR(&sblock) +
			    (NINDIR(&sblock) * NINDIR(&sblock));
			lblk = dblks + (NINDIR(&sblock) * NINDIR(&sblock) *
			    NINDIR(&sblock)) - 1;
			break;
		default:
			exitstat = EXERRFATAL;
			/*
			 * Translate from zero-based array to
			 * one-based human-style counting.
			 */
			errexit("panic: indirection level %d not 1, 2, or 3",
			    ilevel + 1);
			/* NOTREACHED */
		}

		if (dblks < ndb && ndb <= lblk)
			ndb_ilevel = ilevel;

		if (ilevel == ilevel_wanted) {
			if (data_blks != NULL)
				*data_blks = dblks;
			if (last_blk != NULL)
				*last_blk = lblk;
		}
	}

	return (ndb_ilevel);
}

static int
iblock(struct inodesc *idesc, int ilevel, u_offset_t iblks,
	enum cki_action action)
{
	struct bufarea *bp;
	int i, n;
	int (*func)(struct inodesc *) = NULL;
	u_offset_t fsbperindirb;
	daddr32_t last_lbn;
	int nif;
	char buf[BUFSIZ];

	n = KEEPON;

	switch (idesc->id_type) {
	case ADDR:
		func = idesc->id_func;
		if (((n = (*func)(idesc)) & KEEPON) == 0)
				return (n);
		break;
	case ACL:
		func = idesc->id_func;
		break;
	case DATA:
		func = dirscan;
		break;
	default:
		errexit("unknown inodesc type %d in iblock()", idesc->id_type);
		/* NOTREACHED */
	}
	if (chkrange(idesc->id_blkno, idesc->id_numfrags)) {
		return ((idesc->id_type == ACL) ? STOP : SKIP);
	}

	bp = getdatablk(idesc->id_blkno, (size_t)sblock.fs_bsize);
	if (bp->b_errs != 0) {
		brelse(bp);
		return (SKIP);
	}

	ilevel--;
	/*
	 * Trivia note: the BSD fsck has the number of bytes remaining
	 * as the third argument to iblock(), so the equivalent of
	 * fsbperindirb starts at fs_bsize instead of one.  We're
	 * working in units of filesystem blocks here, not bytes or
	 * fragments.
	 */
	for (fsbperindirb = 1, i = 0; i < ilevel; i++) {
		fsbperindirb *= (u_offset_t)NINDIR(&sblock);
	}
	/*
	 * nif indicates the next "free" pointer (as an array index) in this
	 * indirect block, based on counting the blocks remaining in the
	 * file after subtracting all previously processed blocks.
	 * This figure is based on the size field of the inode.
	 *
	 * Note that in normal operation, nif may initially be calculated
	 * as larger than the number of pointers in this block (as when
	 * there are more indirect blocks following); if that is
	 * the case, nif is limited to the max number of pointers per
	 * indirect block.
	 *
	 * Also note that if an inode is inconsistent (has more blocks
	 * allocated to it than the size field would indicate), the sweep
	 * through any indirect blocks directly pointed at by the inode
	 * continues. Since the block offset of any data blocks referenced
	 * by these indirect blocks is greater than the size of the file,
	 * the index nif may be computed as a negative value.
	 * In this case, we reset nif to indicate that all pointers in
	 * this retrieval block should be zeroed and the resulting
	 * unreferenced data and/or retrieval blocks will be recovered
	 * through garbage collection later.
	 */
	nif = (offset_t)howmany(iblks, fsbperindirb);
	if (nif > NINDIR(&sblock))
		nif = NINDIR(&sblock);
	else if (nif < 0)
		nif = 0;
	/*
	 * first pass: all "free" retrieval pointers (from [nif] thru
	 *	the end of the indirect block) should be zero. (This
	 *	assertion does not hold for directories, which may be
	 *	truncated without releasing their allocated space)
	 */
	if (nif < NINDIR(&sblock) && (idesc->id_func == pass1check ||
	    idesc->id_func == pass3bcheck)) {
		for (i = nif; i < NINDIR(&sblock); i++) {
			if (bp->b_un.b_indir[i] == 0)
				continue;
			(void) sprintf(buf, "PARTIALLY TRUNCATED INODE I=%lu",
			    (ulong_t)idesc->id_number);
			if (preen) {
				pfatal(buf);
			} else if (dofix(idesc, buf)) {
				freeblk(idesc->id_number,
				    bp->b_un.b_indir[i],
				    sblock.fs_frag);
				bp->b_un.b_indir[i] = 0;
				dirty(bp);
			}
		}
		flush(fswritefd, bp);
	}
	/*
	 * second pass: all retrieval pointers referring to blocks within
	 *	a valid range [0..filesize] (both indirect and data blocks)
	 *	are examined in the same manner as ckinode() checks the
	 *	direct blocks in the inode.  Sweep through from
	 *	the first pointer in this retrieval block to [nif-1].
	 */
	last_lbn = howmany(idesc->id_filesize, sblock.fs_bsize);
	for (i = 0; i < nif; i++) {
		if (ilevel == 0)
			idesc->id_lbn++;
		if (bp->b_un.b_indir[i] != 0) {
			idesc->id_blkno = bp->b_un.b_indir[i];
			if (ilevel > 0) {
				n = iblock(idesc, ilevel, iblks, action);
				/*
				 * Each iteration decreases "remaining block
				 * count" by the number of blocks accessible
				 * by a pointer at this indirect block level.
				 */
				iblks -= fsbperindirb;
			} else {
				/*
				 * If we're truncating, func will discard
				 * the data block for us.
				 */
				n = (*func)(idesc);
			}

			if ((action == CKI_TRUNCATE) &&
			    (idesc->id_truncto >= 0) &&
			    (idesc->id_lbn >= idesc->id_truncto)) {
				freeblk(idesc->id_number,  bp->b_un.b_indir[i],
				    sblock.fs_frag);
			}

			/*
			 * Note that truncation never gets STOP back
			 * under normal circumstances.  Abnormal would
			 * be a bad acl short-circuit in iblock() or
			 * an out-of-range failure in pass4check().
			 * We still want to keep going when truncating
			 * under those circumstances, since the whole
			 * point of truncating is to get rid of all
			 * that.
			 */
			if ((n & STOP) && (action != CKI_TRUNCATE)) {
				brelse(bp);
				return (n);
			}
		} else {
			if ((idesc->id_lbn < last_lbn) &&
			    (idesc->id_firsthole < 0)) {
				idesc->id_firsthole = idesc->id_lbn;
			}
			if (idesc->id_type == DATA) {
				/*
				 * No point in continuing in the indirect
				 * blocks of a directory, since they'll just
				 * get freed anyway.
				 */
				brelse(bp);
				return ((n & ~KEEPON) | STOP);
			}
		}
	}

	brelse(bp);
	return (KEEPON);
}

/*
 * Check that a block is a legal block number.
 * Return 0 if in range, 1 if out of range.
 */
int
chkrange(daddr32_t blk, int cnt)
{
	int c;

	if (cnt <= 0 || blk <= 0 || ((unsigned)blk >= (unsigned)maxfsblock) ||
	    ((cnt - 1) > (maxfsblock - blk))) {
		if (debug)
			(void) printf(
			    "Bad fragment range: should be 1 <= %d..%d < %d\n",
			    blk, blk + cnt, maxfsblock);
		return (1);
	}
	if ((cnt > sblock.fs_frag) ||
	    ((fragnum(&sblock, blk) + cnt) > sblock.fs_frag)) {
		if (debug)
			(void) printf("Bad fragment size: size %d\n", cnt);
		return (1);
	}
	c = dtog(&sblock, blk);
	if (blk < cgdmin(&sblock, c)) {
		if ((unsigned)(blk + cnt) > (unsigned)cgsblock(&sblock, c)) {
			if (debug)
				(void) printf(
	    "Bad fragment position: %d..%d spans start of cg metadata\n",
				    blk, blk + cnt);
			return (1);
		}
	} else {
		if ((unsigned)(blk + cnt) > (unsigned)cgbase(&sblock, c+1)) {
			if (debug)
				(void) printf(
				    "Bad frag pos: %d..%d crosses end of cg\n",
				    blk, blk + cnt);
			return (1);
		}
	}
	return (0);
}

/*
 * General purpose interface for reading inodes.
 */

/*
 * Note that any call to ginode() can potentially invalidate any
 * dinode pointers previously acquired from it.  To avoid pain,
 * make sure to always call inodirty() immediately after modifying
 * an inode, if there's any chance of ginode() being called after
 * that.  Also, always call ginode() right before you need to access
 * an inode, so that there won't be any surprises from functions
 * called between the previous ginode() invocation and the dinode
 * use.
 *
 * Despite all that, we aren't doing the amount of i/o that's implied,
 * as we use the buffer cache that getdatablk() and friends maintain.
 */
static fsck_ino_t startinum = -1;

struct dinode *
ginode(fsck_ino_t inum)
{
	daddr32_t iblk;
	struct dinode *dp;

	if (inum < UFSROOTINO || inum > maxino) {
		errexit("bad inode number %d to ginode\n", inum);
	}
	if (startinum == -1 ||
	    pbp == NULL ||
	    inum < startinum ||
	    inum >= (fsck_ino_t)(startinum + (fsck_ino_t)INOPB(&sblock))) {
		iblk = itod(&sblock, inum);
		if (pbp != NULL) {
			brelse(pbp);
		}
		/*
		 * We don't check for errors here, because we can't
		 * tell our caller about it, and the zeros that will
		 * be in the buffer are just as good as anything we
		 * could fake.
		 */
		pbp = getdatablk(iblk, (size_t)sblock.fs_bsize);
		startinum =
		    (fsck_ino_t)((inum / INOPB(&sblock)) * INOPB(&sblock));
	}
	dp = &pbp->b_un.b_dinode[inum % INOPB(&sblock)];
	if (dp->di_suid != UID_LONG)
		dp->di_uid = dp->di_suid;
	if (dp->di_sgid != GID_LONG)
		dp->di_gid = dp->di_sgid;
	return (dp);
}

/*
 * Special purpose version of ginode used to optimize first pass
 * over all the inodes in numerical order.  It bypasses the buffer
 * system used by ginode(), etc in favour of reading the bulk of a
 * cg's inodes at one time.
 */
static fsck_ino_t nextino, lastinum;
static int64_t readcnt, readpercg, fullcnt, inobufsize;
static int64_t partialcnt, partialsize;
static size_t lastsize;
static struct dinode *inodebuf;
static diskaddr_t currentdblk;
static struct dinode *currentinode;

struct dinode *
getnextinode(fsck_ino_t inum)
{
	size_t size;
	diskaddr_t dblk;
	static struct dinode *dp;

	if (inum != nextino++ || inum > maxino)
		errexit("bad inode number %d to nextinode\n", inum);

	/*
	 * Will always go into the if() the first time we're called,
	 * so dp will always be valid.
	 */
	if (inum >= lastinum) {
		readcnt++;
		dblk = fsbtodb(&sblock, itod(&sblock, lastinum));
		currentdblk = dblk;
		if (readcnt % readpercg == 0) {
			if (partialsize > SIZE_MAX)
				errexit(
				    "Internal error: partialsize overflow");
			size = (size_t)partialsize;
			lastinum += partialcnt;
		} else {
			if (inobufsize > SIZE_MAX)
				errexit("Internal error: inobufsize overflow");
			size = (size_t)inobufsize;
			lastinum += fullcnt;
		}
		/*
		 * If fsck_bread() returns an error, it will already have
		 * zeroed out the buffer, so we do not need to do so here.
		 */
		(void) fsck_bread(fsreadfd, (caddr_t)inodebuf, dblk, size);
		lastsize = size;
		dp = inodebuf;
	}
	currentinode = dp;
	return (dp++);
}

/*
 * Reread the current getnext() buffer.  This allows for changing inodes
 * other than the current one via ginode()/inodirty()/inoflush().
 *
 * Just reuses all the interesting variables that getnextinode() set up
 * last time it was called.  This shouldn't get called often, so we don't
 * try to figure out if the caller's actually touched an inode in the
 * range we have cached.  There could have been an arbitrary number of
 * them, after all.
 */
struct dinode *
getnextrefresh(void)
{
	if (inodebuf == NULL) {
		return (NULL);
	}

	inoflush();
	(void) fsck_bread(fsreadfd, (caddr_t)inodebuf, currentdblk, lastsize);
	return (currentinode);
}

void
resetinodebuf(void)
{
	startinum = 0;
	nextino = 0;
	lastinum = 0;
	readcnt = 0;
	inobufsize = blkroundup(&sblock, INOBUFSIZE);
	fullcnt = inobufsize / sizeof (struct dinode);
	readpercg = sblock.fs_ipg / fullcnt;
	partialcnt = sblock.fs_ipg % fullcnt;
	partialsize = partialcnt * sizeof (struct dinode);
	if (partialcnt != 0) {
		readpercg++;
	} else {
		partialcnt = fullcnt;
		partialsize = inobufsize;
	}
	if (inodebuf == NULL &&
	    (inodebuf = (struct dinode *)malloc((unsigned)inobufsize)) == NULL)
		errexit("Cannot allocate space for inode buffer\n");
	while (nextino < UFSROOTINO)
		(void) getnextinode(nextino);
}

void
freeinodebuf(void)
{
	if (inodebuf != NULL) {
		free((void *)inodebuf);
	}
	inodebuf = NULL;
}

/*
 * Routines to maintain information about directory inodes.
 * This is built during the first pass and used during the
 * second and third passes.
 *
 * Enter inodes into the cache.
 */
void
cacheino(struct dinode *dp, fsck_ino_t inum)
{
	struct inoinfo *inp;
	struct inoinfo **inpp;
	uint_t blks;

	blks = NDADDR + NIADDR;
	inp = (struct inoinfo *)
	    malloc(sizeof (*inp) + (blks - 1) * sizeof (daddr32_t));
	if (inp == NULL)
		errexit("Cannot increase directory list\n");
	init_inoinfo(inp, dp, inum); /* doesn't touch i_nextlist or i_number */
	inpp = &inphead[inum % numdirs];
	inp->i_nextlist = *inpp;
	*inpp = inp;
	inp->i_number = inum;
	if (inplast == listmax) {
		listmax += 100;
		inpsort = (struct inoinfo **)realloc((void *)inpsort,
		    (unsigned)listmax * sizeof (struct inoinfo *));
		if (inpsort == NULL)
			errexit("cannot increase directory list");
	}
	inpsort[inplast++] = inp;
}

/*
 * Look up an inode cache structure.
 */
struct inoinfo *
getinoinfo(fsck_ino_t inum)
{
	struct inoinfo *inp;

	inp = search_cache(inphead[inum % numdirs], inum);
	return (inp);
}

/*
 * Determine whether inode is in cache.
 */
int
inocached(fsck_ino_t inum)
{
	return (search_cache(inphead[inum % numdirs], inum) != NULL);
}

/*
 * Clean up all the inode cache structure.
 */
void
inocleanup(void)
{
	struct inoinfo **inpp;

	if (inphead == NULL)
		return;
	for (inpp = &inpsort[inplast - 1]; inpp >= inpsort; inpp--) {
		free((void *)(*inpp));
	}
	free((void *)inphead);
	free((void *)inpsort);
	inphead = inpsort = NULL;
}

/*
 * Routines to maintain information about acl inodes.
 * This is built during the first pass and used during the
 * second and third passes.
 *
 * Enter acl inodes into the cache.
 */
void
cacheacl(struct dinode *dp, fsck_ino_t inum)
{
	struct inoinfo *aclp;
	struct inoinfo **aclpp;
	uint_t blks;

	blks = NDADDR + NIADDR;
	aclp = (struct inoinfo *)
	    malloc(sizeof (*aclp) + (blks - 1) * sizeof (daddr32_t));
	if (aclp == NULL)
		return;
	aclpp = &aclphead[inum % numacls];
	aclp->i_nextlist = *aclpp;
	*aclpp = aclp;
	aclp->i_number = inum;
	aclp->i_isize = (offset_t)dp->di_size;
	aclp->i_blkssize = (size_t)(blks * sizeof (daddr32_t));
	(void) memmove(&aclp->i_blks[0], &dp->di_db[0], aclp->i_blkssize);
	if (aclplast == aclmax) {
		aclmax += 100;
		aclpsort = (struct inoinfo **)realloc((char *)aclpsort,
		    (unsigned)aclmax * sizeof (struct inoinfo *));
		if (aclpsort == NULL)
			errexit("cannot increase acl list");
	}
	aclpsort[aclplast++] = aclp;
}


/*
 * Generic cache search function.
 * ROOT is the first entry in a hash chain (the caller is expected
 * to have done the initial bucket lookup).  KEY is what's being
 * searched for.
 *
 * Returns a pointer to the entry if it is found, NULL otherwise.
 */
static struct inoinfo *
search_cache(struct inoinfo *element, fsck_ino_t key)
{
	while (element != NULL) {
		if (element->i_number == key)
			break;
		element = element->i_nextlist;
	}

	return (element);
}

void
inodirty(void)
{
	dirty(pbp);
}

static void
inoflush(void)
{
	if (pbp != NULL)
		flush(fswritefd, pbp);
}

/*
 * Interactive wrapper for freeino(), for those times when we're
 * not sure if we should throw something away.
 */
void
clri(struct inodesc *idesc, char *type, int verbose, int corrupting)
{
	int need_parent;
	struct dinode *dp;

	if (statemap[idesc->id_number] == USTATE)
		return;

	dp = ginode(idesc->id_number);
	if (verbose == CLRI_VERBOSE) {
		pwarn("%s %s", type, file_id(idesc->id_number, dp->di_mode));
		pinode(idesc->id_number);
	}
	if (preen || (reply("CLEAR") == 1)) {
		need_parent = (corrupting == CLRI_NOP_OK) ?
		    TI_NOPARENT : TI_PARENT;
		freeino(idesc->id_number, need_parent);
		if (preen)
			(void) printf(" (CLEARED)\n");
		remove_orphan_dir(idesc->id_number);
	} else if (corrupting == CLRI_NOP_CORRUPT) {
		iscorrupt = 1;
	}
	(void) printf("\n");
}

/*
 * Find the directory entry for the inode noted in id_parent (which is
 * not necessarily the parent of anything, we're just using a convenient
 * field.
 */
int
findname(struct inodesc *idesc)
{
	struct direct *dirp = idesc->id_dirp;

	if (dirp->d_ino != idesc->id_parent)
		return (KEEPON);
	(void) memmove(idesc->id_name, dirp->d_name,
	    MIN(dirp->d_namlen, MAXNAMLEN) + 1);
	return (STOP|FOUND);
}

/*
 * Find the inode number associated with the given name.
 */
int
findino(struct inodesc *idesc)
{
	struct direct *dirp = idesc->id_dirp;

	if (dirp->d_ino == 0)
		return (KEEPON);
	if (strcmp(dirp->d_name, idesc->id_name) == 0 &&
	    dirp->d_ino >= UFSROOTINO && dirp->d_ino <= maxino) {
		idesc->id_parent = dirp->d_ino;
		return (STOP|FOUND);
	}
	return (KEEPON);
}

int
cleardirentry(fsck_ino_t parentdir, fsck_ino_t target)
{
	struct inodesc idesc;
	struct dinode *dp;

	dp = ginode(parentdir);
	init_inodesc(&idesc);
	idesc.id_func = clearanentry;
	idesc.id_parent = target;
	idesc.id_type = DATA;
	idesc.id_fix = NOFIX;
	return (ckinode(dp, &idesc, CKI_TRAVERSE));
}

static int
clearanentry(struct inodesc *idesc)
{
	struct direct *dirp = idesc->id_dirp;

	if (dirp->d_ino != idesc->id_parent || idesc->id_entryno < 2) {
		idesc->id_entryno++;
		return (KEEPON);
	}
	dirp->d_ino = 0;
	return (STOP|FOUND|ALTERED);
}

void
pinode(fsck_ino_t ino)
{
	struct dinode *dp;

	(void) printf(" I=%lu ", (ulong_t)ino);
	if (ino < UFSROOTINO || ino > maxino)
		return;
	dp = ginode(ino);
	pdinode(dp);
}

static void
pdinode(struct dinode *dp)
{
	char *p;
	struct passwd *pw;
	time_t t;

	(void) printf(" OWNER=");
	if ((pw = getpwuid((int)dp->di_uid)) != 0)
		(void) printf("%s ", pw->pw_name);
	else
		(void) printf("%lu ", (ulong_t)dp->di_uid);
	(void) printf("MODE=%o\n", dp->di_mode);
	if (preen)
		(void) printf("%s: ", devname);
	(void) printf("SIZE=%lld ", (longlong_t)dp->di_size);

	/* ctime() ignores LOCALE, so this is safe */
	t = (time_t)dp->di_mtime;
	p = ctime(&t);
	(void) printf("MTIME=%12.12s %4.4s ", p + 4, p + 20);
}

void
blkerror(fsck_ino_t ino, char *type, daddr32_t blk, daddr32_t lbn)
{
	pfatal("FRAGMENT %d %s I=%u LFN %d", blk, type, ino, lbn);
	(void) printf("\n");

	switch (statemap[ino] & ~INDELAYD) {

	case FSTATE:
	case FZLINK:
		statemap[ino] = FCLEAR;
		return;

	case DFOUND:
	case DSTATE:
	case DZLINK:
		statemap[ino] = DCLEAR;
		add_orphan_dir(ino);
		return;

	case SSTATE:
		statemap[ino] = SCLEAR;
		return;

	case FCLEAR:
	case DCLEAR:
	case SCLEAR:
		return;

	default:
		errexit("BAD STATE 0x%x TO BLKERR\n", statemap[ino]);
		/* NOTREACHED */
	}
}

/*
 * allocate an unused inode
 */
fsck_ino_t
allocino(fsck_ino_t request, int type)
{
	fsck_ino_t ino;
	struct dinode *dp;
	struct cg *cgp = &cgrp;
	int cg;
	time_t t;
	caddr_t err;

	if (debug && (request != 0) && (request != UFSROOTINO))
		errexit("assertion failed: allocino() asked for "
		    "inode %d instead of 0 or %d",
		    (int)request, (int)UFSROOTINO);

	/*
	 * We know that we're only going to get requests for UFSROOTINO
	 * or 0.  If UFSROOTINO is wanted, then it better be available
	 * because our caller is trying to recreate the root directory.
	 * If we're asked for 0, then which one we return doesn't matter.
	 * We know that inodes 0 and 1 are never valid to return, so we
	 * the start at the lowest-legal inode number.
	 *
	 * If we got a request for UFSROOTINO, then request != 0, and
	 * this pair of conditionals is the only place that treats
	 * UFSROOTINO specially.
	 */
	if (request == 0)
		request = UFSROOTINO;
	else if (statemap[request] != USTATE)
		return (0);

	/*
	 * Doesn't do wrapping, since we know we started at
	 * the smallest inode.
	 */
	for (ino = request; ino < maxino; ino++)
		if (statemap[ino] == USTATE)
			break;
	if (ino == maxino)
		return (0);

	/*
	 * In pass5, we'll calculate the bitmaps and counts all again from
	 * scratch and do a comparison, but for that to work the cg has
	 * to know what in-memory changes we've made to it.  If we have
	 * trouble reading the cg, cg_sanity() should kick it out so
	 * we can skip explicit i/o error checking here.
	 */
	cg = itog(&sblock, ino);
	(void) getblk(&cgblk, cgtod(&sblock, cg), (size_t)sblock.fs_cgsize);
	err = cg_sanity(cgp, cg);
	if (err != NULL) {
		pfatal("CG %d: %s\n", cg, err);
		free((void *)err);
		if (reply("REPAIR") == 0)
			errexit("Program terminated.");
		fix_cg(cgp, cg);
	}
	setbit(cg_inosused(cgp), ino % sblock.fs_ipg);
	cgp->cg_cs.cs_nifree--;
	cgdirty();

	if (lastino < ino)
		lastino = ino;

	/*
	 * Don't currently support IFATTRDIR or any of the other
	 * types, as they aren't needed.
	 */
	switch (type & IFMT) {
	case IFDIR:
		statemap[ino] = DSTATE;
		cgp->cg_cs.cs_ndir++;
		break;
	case IFREG:
	case IFLNK:
		statemap[ino] = FSTATE;
		break;
	default:
		/*
		 * Pretend nothing ever happened.  This clears the
		 * dirty flag, among other things.
		 */
		initbarea(&cgblk);
		if (debug)
			(void) printf("allocino: unknown type 0%o\n",
			    type & IFMT);
		return (0);
	}

	/*
	 * We're allocating what should be a completely-unused inode,
	 * so make sure we don't inherit anything from any previous
	 * incarnations.
	 */
	dp = ginode(ino);
	(void) memset((void *)dp, 0, sizeof (struct dinode));
	dp->di_db[0] = allocblk(1);
	if (dp->di_db[0] == 0) {
		statemap[ino] = USTATE;
		return (0);
	}
	dp->di_mode = (mode_t)type;
	(void) time(&t);
	dp->di_atime = (time32_t)t;
	dp->di_ctime = dp->di_atime;
	dp->di_mtime = dp->di_ctime;
	dp->di_size = (u_offset_t)sblock.fs_fsize;
	dp->di_blocks = btodb(sblock.fs_fsize);
	n_files++;
	inodirty();
	return (ino);
}

/*
 * Release some or all of the blocks of an inode.
 * Only truncates down.  Assumes new_length is appropriately aligned
 * to a block boundary (or a directory block boundary, if it's a
 * directory).
 *
 * If this is a directory, discard all of its contents first, so
 * we don't create a bunch of orphans that would need another fsck
 * run to clean up.
 *
 * Even if truncating to zero length, the inode remains allocated.
 */
void
truncino(fsck_ino_t ino, offset_t new_length, int update)
{
	struct inodesc idesc;
	struct inoinfo *iip;
	struct dinode *dp;
	fsck_ino_t parent;
	mode_t mode;
	caddr_t message;
	int isdir, islink;
	int ilevel, dblk;

	dp = ginode(ino);
	mode = (dp->di_mode & IFMT);
	isdir = (mode == IFDIR) || (mode == IFATTRDIR);
	islink = (mode == IFLNK);

	if (isdir) {
		/*
		 * Go with the parent we found by chasing references,
		 * if we've gotten that far.  Otherwise, use what the
		 * directory itself claims.  If there's no ``..'' entry
		 * in it, give up trying to get the link counts right.
		 */
		if (update == TI_NOPARENT) {
			parent = -1;
		} else {
			iip = getinoinfo(ino);
			if (iip != NULL) {
				parent = iip->i_parent;
			} else {
				parent = lookup_dotdot_ino(ino);
				if (parent != 0) {
					/*
					 * Make sure that the claimed
					 * parent actually has a
					 * reference to us.
					 */
					dp = ginode(parent);
					idesc.id_name = lfname;
					idesc.id_type = DATA;
					idesc.id_func = findino;
					idesc.id_number = ino;
					idesc.id_fix = DONTKNOW;
					if ((ckinode(dp, &idesc,
					    CKI_TRAVERSE) & FOUND) == 0)
						parent = 0;
				}
			}
		}

		mark_delayed_inodes(ino, numfrags(&sblock, new_length));
		if (parent > 0) {
			dp = ginode(parent);
			LINK_RANGE(message, dp->di_nlink, -1);
			if (message != NULL) {
				LINK_CLEAR(message, parent, dp->di_mode,
				    &idesc);
				if (statemap[parent] == USTATE)
					goto no_parent_update;
			}
			TRACK_LNCNTP(parent, lncntp[parent]--);
		} else if ((mode == IFDIR) && (parent == 0)) {
			/*
			 * Currently don't have a good way to
			 * handle this, so throw up our hands.
			 * However, we know that we can still
			 * do some good if we continue, so
			 * don't actually exit yet.
			 *
			 * We don't do it for attrdirs,
			 * because there aren't link counts
			 * between them and their parents.
			 */
			pwarn("Could not determine former parent of "
			    "inode %d, link counts are possibly\n"
			    "incorrect.  Please rerun fsck(8) to "
			    "correct this.\n",
			    ino);
			iscorrupt = 1;
		}
		/*
		 * ...else if it's a directory with parent == -1, then
		 * we've not gotten far enough to know connectivity,
		 * and it'll get handled automatically later.
		 */
	}

no_parent_update:
	init_inodesc(&idesc);
	idesc.id_type = ADDR;
	idesc.id_func = pass4check;
	idesc.id_number = ino;
	idesc.id_fix = DONTKNOW;
	idesc.id_truncto = howmany(new_length, sblock.fs_bsize);
	dp = ginode(ino);
	if (!islink && ckinode(dp, &idesc, CKI_TRUNCATE) & ALTERED)
		inodirty();

	/*
	 * This has to be done after ckinode(), so that all of
	 * the fragments get visited.  Note that we assume we're
	 * always truncating to a block boundary, rather than a
	 * fragment boundary.
	 */
	dp = ginode(ino);
	dp->di_size = new_length;

	/*
	 * Clear now-obsolete pointers.
	 */
	for (dblk = idesc.id_truncto + 1; dblk < NDADDR; dblk++) {
		dp->di_db[dblk] = 0;
	}

	ilevel = get_indir_offsets(-1, idesc.id_truncto, NULL, NULL);
	for (ilevel++; ilevel < NIADDR; ilevel++) {
		dp->di_ib[ilevel] = 0;
	}

	inodirty();
}

/*
 * Release an inode's resources, then release the inode itself.
 */
void
freeino(fsck_ino_t ino, int update_parent)
{
	int cg;
	struct dinode *dp;
	struct cg *cgp;

	n_files--;
	dp = ginode(ino);
	/*
	 * We need to make sure that the file is really a large file.
	 * Everything bigger than UFS_MAXOFFSET_T is treated as a file with
	 * negative size, which shall be cleared. (see verify_inode() in
	 * pass1.c)
	 */
	if (dp->di_size > (u_offset_t)MAXOFF_T &&
	    dp->di_size <= (u_offset_t)UFS_MAXOFFSET_T &&
	    ftypeok(dp) &&
	    (dp->di_mode & IFMT) != IFBLK &&
	    (dp->di_mode & IFMT) != IFCHR) {
		largefile_count--;
	}
	truncino(ino, 0, update_parent);

	dp = ginode(ino);
	if ((dp->di_mode & IFMT) == IFATTRDIR) {
		clearshadow(ino, &attrclientinfo);
		dp = ginode(ino);
	}

	clearinode(dp);
	inodirty();
	statemap[ino] = USTATE;

	/*
	 * Keep the disk in sync with us so that pass5 doesn't get
	 * upset about spurious inconsistencies.
	 */
	cg = itog(&sblock, ino);
	(void) getblk(&cgblk, (diskaddr_t)cgtod(&sblock, cg),
	    (size_t)sblock.fs_cgsize);
	cgp = cgblk.b_un.b_cg;
	clrbit(cg_inosused(cgp), ino % sblock.fs_ipg);
	cgp->cg_cs.cs_nifree += 1;
	cgdirty();
	sblock.fs_cstotal.cs_nifree += 1;
	sbdirty();
}

void
init_inoinfo(struct inoinfo *inp, struct dinode *dp, fsck_ino_t inum)
{
	inp->i_parent = ((inum == UFSROOTINO) ? UFSROOTINO : (fsck_ino_t)0);
	inp->i_dotdot = (fsck_ino_t)0;
	inp->i_isize = (offset_t)dp->di_size;
	inp->i_blkssize = (NDADDR + NIADDR) * sizeof (daddr32_t);
	inp->i_extattr = dp->di_oeftflag;
	(void) memmove((void *)&inp->i_blks[0], (void *)&dp->di_db[0],
	    inp->i_blkssize);
}

/*
 * Return the inode number in the ".." entry of the provided
 * directory inode.
 */
static int
lookup_dotdot_ino(fsck_ino_t ino)
{
	struct inodesc idesc;

	init_inodesc(&idesc);
	idesc.id_type = DATA;
	idesc.id_func = findino;
	idesc.id_name = "..";
	idesc.id_number = ino;
	idesc.id_fix = NOFIX;

	if ((ckinode(ginode(ino), &idesc, CKI_TRAVERSE) & FOUND) != 0) {
		return (idesc.id_parent);
	}

	return (0);
}

/*
 * Convenience wrapper around ckinode(findino()).
 */
int
lookup_named_ino(fsck_ino_t dir, caddr_t name)
{
	struct inodesc idesc;

	init_inodesc(&idesc);
	idesc.id_type = DATA;
	idesc.id_func = findino;
	idesc.id_name = name;
	idesc.id_number = dir;
	idesc.id_fix = NOFIX;

	if ((ckinode(ginode(dir), &idesc, CKI_TRAVERSE) & FOUND) != 0) {
		return (idesc.id_parent);
	}

	return (0);
}

/*
 * Marks inodes that are being orphaned and might need to be reconnected
 * by pass4().  The inode we're traversing is the directory whose
 * contents will be reconnected later.  id_parent is the lfn at which
 * to start looking at said contents.
 */
static int
mark_a_delayed_inode(struct inodesc *idesc)
{
	struct direct *dirp = idesc->id_dirp;

	if (idesc->id_lbn < idesc->id_parent) {
		return (KEEPON);
	}

	if (dirp->d_ino != 0 &&
	    strcmp(dirp->d_name, ".") != 0 &&
	    strcmp(dirp->d_name, "..") != 0) {
		statemap[dirp->d_ino] &= ~INFOUND;
		statemap[dirp->d_ino] |= INDELAYD;
	}

	return (KEEPON);
}

static void
mark_delayed_inodes(fsck_ino_t ino, daddr32_t first_lfn)
{
	struct dinode *dp;
	struct inodesc idelayed;

	init_inodesc(&idelayed);
	idelayed.id_number = ino;
	idelayed.id_type = DATA;
	idelayed.id_fix = NOFIX;
	idelayed.id_func = mark_a_delayed_inode;
	idelayed.id_parent = first_lfn;
	idelayed.id_entryno = 2;

	dp = ginode(ino);
	(void) ckinode(dp, &idelayed, CKI_TRAVERSE);
}

/*
 * Clear the i_oeftflag/extended attribute pointer from INO.
 */
void
clearattrref(fsck_ino_t ino)
{
	struct dinode *dp;

	dp = ginode(ino);
	if (debug) {
		if (dp->di_oeftflag == 0)
			(void) printf("clearattref: no attr to clear on %d\n",
			    ino);
	}

	dp->di_oeftflag = 0;
	inodirty();
}
