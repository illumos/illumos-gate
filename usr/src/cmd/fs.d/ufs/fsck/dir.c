/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/mntent.h>
#include <string.h>
#include <stdarg.h>
#include <sys/fs/ufs_fs.h>
#include <sys/vnode.h>
#include <sys/fs/ufs_inode.h>
#define	_KERNEL
#include <sys/fs/ufs_fsdir.h>
#undef _KERNEL
#include "fsck.h"

struct rc_queue {
	struct rc_queue	*rc_next;
	fsck_ino_t	rc_orphan;
	fsck_ino_t	rc_parent;
	caddr_t		rc_name;
};

caddr_t lfname = "lost+found";		/* name to use for l+f dir */
static int lfmode = 01700;		/* mode to use when creating l+f dir */
static struct dirtemplate emptydir = { 0, DIRBLKSIZ };
static struct dirtemplate dirhead = {
	0, 12, 1, ".", 0, DIRBLKSIZ - 12, 2, ".."
};

static void lftempname(char *, fsck_ino_t);
static int do_reconnect(fsck_ino_t, fsck_ino_t, caddr_t);
static caddr_t mkuniqname(caddr_t, caddr_t, fsck_ino_t, fsck_ino_t);
static int chgino(struct inodesc *);
static int dircheck(struct inodesc *, struct direct *);
static int expanddir(fsck_ino_t, char *);
static void freedir(fsck_ino_t, fsck_ino_t);
static struct direct *fsck_readdir(struct inodesc *);
static struct bufarea *getdirblk(daddr32_t, size_t);
static int mkentry(struct inodesc *);
static fsck_ino_t newdir(fsck_ino_t, fsck_ino_t, int, caddr_t);
static fsck_ino_t reallocdir(fsck_ino_t, fsck_ino_t, int, caddr_t);

/*
 * Propagate connected state through the tree.
 */
void
propagate(void)
{
	struct inoinfo **inpp, *inp;
	struct inoinfo **inpend;
	int change, inorphan;

	inpend = &inpsort[inplast];
	do {
		change = 0;
		for (inpp = inpsort; inpp < inpend; inpp++) {
			inp = *inpp;
			if (inp->i_parent == 0)
				continue;
			if (statemap[inp->i_parent] == DFOUND &&
			    INO_IS_DUNFOUND(inp->i_number)) {
				inorphan = statemap[inp->i_number] & INORPHAN;
				statemap[inp->i_number] = DFOUND | inorphan;
				change++;
			}
		}
	} while (change > 0);
}

/*
 * Scan each entry in a directory block.
 */
int
dirscan(struct inodesc *idesc)
{
	struct direct *dp;
	struct bufarea *bp;
	uint_t dsize, n;
	size_t blksiz;
	union {			/* keep lint happy about alignment */
		char dbuf[DIRBLKSIZ];
		struct direct dir;
	} u;

	if (idesc->id_type != DATA)
		errexit("wrong type to dirscan %d\n", idesc->id_type);
	if (idesc->id_entryno == 0 &&
	    (idesc->id_filesize & (DIRBLKSIZ - 1)) != 0)
		idesc->id_filesize = roundup(idesc->id_filesize, DIRBLKSIZ);
	blksiz = idesc->id_numfrags * sblock.fs_fsize;
	if (chkrange(idesc->id_blkno, idesc->id_numfrags)) {
		idesc->id_filesize -= (offset_t)blksiz;
		return (SKIP);
	}
	idesc->id_loc = 0;
	for (dp = fsck_readdir(idesc); dp != NULL; dp = fsck_readdir(idesc)) {
		/*
		 * If we were just passed a corrupt directory entry with
		 * d_reclen > DIRBLKSIZ, we don't want to memmove() all over
		 * our stack.  This directory gets cleaned up later.
		 */
		dsize = MIN(dp->d_reclen, sizeof (u.dbuf));
		(void) memmove((void *)u.dbuf, (void *)dp, (size_t)dsize);
		idesc->id_dirp = &u.dir;
		if ((n = (*idesc->id_func)(idesc)) & ALTERED) {
			/*
			 * We can ignore errors from getdirblk() here,
			 * as the block is still in memory thanks to
			 * buffering and fsck_readdir().  If there was
			 * an error reading it before, then all decisions
			 * leading to getting us here were based on the
			 * resulting zeros.  As such, we have nothing
			 * to worry about at this point.
			 */
			bp = getdirblk(idesc->id_blkno, blksiz);
			(void) memmove((void *)(bp->b_un.b_buf +
			    idesc->id_loc - dsize),
			    (void *)u.dbuf, (size_t)dsize);
			dirty(bp);
			sbdirty();
		}
		if (n & STOP)
			return (n);
	}
	return (idesc->id_filesize > 0 ? KEEPON : STOP);
}

/*
 * Get current entry in a directory (and peek at the next entry).
 */
static struct direct *
fsck_readdir(struct inodesc *idesc)
{
	struct direct *dp, *ndp = 0;
	struct bufarea *bp;
	ushort_t size;		/* of directory entry */
	size_t blksiz;
	int dofixret;
	int salvaged;		/* when to report SALVAGED in preen mode */
	int origloc	= idesc->id_loc;

	blksiz = idesc->id_numfrags * sblock.fs_fsize;
	/*
	 * Sanity check id_filesize and id_loc fields.  The latter
	 * has to be within the block we're looking at, as well as
	 * aligned to a four-byte boundary.  The alignment is due to
	 * a struct direct containing four-byte integers.  It's
	 * unfortunate that the four is a magic number, but there's
	 * really no good way to derive it from the ufs header files.
	 */
	if ((idesc->id_filesize <= 0) || (idesc->id_loc >= blksiz) ||
	    ((idesc->id_loc & 3) != 0))
		return (NULL);
	/*
	 * We don't have to worry about holes in the directory's
	 * block list, because that was checked for when the
	 * inode was first encountered during pass1.  We never
	 * scan a directory until after we've vetted its block list.
	 */
	/*
	 * We can ignore errors from getdirblk() here, as dircheck()
	 * will reject any entries that would have been in the bad
	 * sectors (fsck_bread() fills in zeros on failures).  The main
	 * reject keys are that d_reclen would be zero and/or that it
	 * is less than the minimal size of a directory entry.  Since
	 * entries can't span sectors, there's no worry about having
	 * a good beginning in one sector and the rest in the next,
	 * where that second sector was unreadable and therefore
	 * replaced with zeros.
	 */
	bp = getdirblk(idesc->id_blkno, blksiz);
	/* LINTED b_buf is aligned and id_loc was verified above */
	dp = (struct direct *)(bp->b_un.b_buf + idesc->id_loc);

	/*
	 * Check the current entry in the directory.
	 */
	if (dircheck(idesc, dp) == 0) {
		/*
		 * If we are in here, then either the current directory
		 * entry is bad or the next directory entry is bad.
		 */
next_is_bad:
		/*
		 * Find the amount of space left to the end of the
		 * directory block for either directory entry.
		 */
		size = DIRBLKSIZ - (idesc->id_loc & (DIRBLKSIZ - 1));

		/*
		 * Advance to the end of the directory block.
		 */
		idesc->id_loc += size;
		idesc->id_filesize -= (offset_t)size;

		/*
		 * Ask the question before we fix the in-core directory
		 * block because dofix() may reuse the buffer.
		 */
		salvaged = (idesc->id_fix == DONTKNOW);
		dofixret = dofix(idesc, "DIRECTORY CORRUPTED");

		/*
		 * If there was an error reading the block, then that
		 * same error can reasonably be expected to have occurred
		 * when it was read previously.  As such, the decision
		 * to come here was based on the results of that partially-
		 * zerod block, and so anything we change should be
		 * based on it as well.  Upshot: no need to check for
		 * errors here.
		 */
		bp = getdirblk(idesc->id_blkno, blksiz);
		/* LINTED b_buf is aligned and id_loc/origloc was verified */
		dp = (struct direct *)(bp->b_un.b_buf + origloc);

		/*
		 * This is the current directory entry and since it is
		 * corrupt we cannot trust the rest of the directory
		 * block so change the current directory entry to
		 * contain nothing and encompass the rest of the block.
		 */
		if (ndp == NULL) {
			dp->d_reclen = size;
			dp->d_ino = 0;
			dp->d_namlen = 0;
			dp->d_name[0] = '\0';
		}
		/*
		 * This is the next directory entry, i.e., we got here
		 * via a "goto next_is_bad".  That directory entry is
		 * corrupt.  However, the current directory entry is okay
		 * so if we are in fix mode, just extend its record size
		 * to encompass the rest of the block.
		 */
		else if (dofixret) {
			dp->d_reclen += size;
		}
		/*
		 * If the user said to fix the directory corruption, then
		 * mark the block as dirty.  Otherwise, our "repairs" only
		 * apply to the in-core copy so we don't hand back trash
		 * to the caller.
		 *
		 * Note: It is possible that saying "no" to a change in
		 * one part of the I/O buffer and "yes" to a later change
		 * in the same I/O buffer may still flush the change to
		 * which we said "no". This is the pathological case and
		 * no fix is planned at this time.
		 */
		if (dofixret) {
			dirty(bp);
			if (preen && salvaged)
				(void) printf(" (SALVAGED)\n");
			if (idesc->id_number == lfdir)
				lfdir = 0;
		}

		/*
		 * dp points into bp, which will get re-used at some
		 * arbitrary time in the future.  We rely on the fact
		 * that we're singled-threaded, and that we'll be done
		 * with this directory entry by the time the next one
		 * is needed.
		 */
		return (dp);
	}
	/*
	 * The current directory entry checked out so advance past it.
	 */
	idesc->id_loc += dp->d_reclen;
	idesc->id_filesize -= (offset_t)dp->d_reclen;
	/*
	 * If we are not at the directory block boundary, then peek
	 * at the next directory entry and if it is bad we can add
	 * its space to the current directory entry (compression).
	 * Again, we sanity check the id_loc and id_filesize fields
	 * since we modified them above.
	 */
	if ((idesc->id_loc & (DIRBLKSIZ - 1)) &&	/* not at start */
	    (idesc->id_loc < blksiz) &&			/* within block */
	    ((idesc->id_loc & 3) == 0) &&		/* properly aligned */
	    (idesc->id_filesize > 0)) {			/* data follows */
		/* LINTED b_buf is aligned and id_loc verified to be ok */
		ndp = (struct direct *)(bp->b_un.b_buf + idesc->id_loc);
		if (dircheck(idesc, ndp) == 0)
			goto next_is_bad;
	}

	/*
	 * See comment above about dp pointing into bp.
	 */
	return (dp);
}

/*
 * Verify that a directory entry is valid.
 * This is a superset of the checks made in the kernel.
 */
static int
dircheck(struct inodesc *idesc, struct direct *dp)
{
	size_t size;
	char *cp;
	int spaceleft;

	/*
	 * Recall that id_filesize is the number of bytes left to
	 * process in the directory.  We check id_filesize >= size
	 * instead of id_filesize >= d_reclen because all that the
	 * directory is actually required to contain is the entry
	 * itself (and it's how the kernel does the allocation).
	 *
	 * We indirectly check for d_reclen going past the end of
	 * the allocated space by comparing it against spaceleft.
	 */
	size = DIRSIZ(dp);
	spaceleft = DIRBLKSIZ - (idesc->id_loc % DIRBLKSIZ);
	if (dp->d_ino < maxino &&
	    dp->d_reclen != 0 &&
	    (int)dp->d_reclen <= spaceleft &&
	    (dp->d_reclen & 0x3) == 0 &&
	    (int)dp->d_reclen >= size &&
	    idesc->id_filesize >= (offset_t)size &&
	    dp->d_namlen <= MAXNAMLEN) {
		if (dp->d_ino == 0)
			return (1);
		for (cp = dp->d_name, size = 0; size < (size_t)dp->d_namlen;
								size++, cp++)
			if ((*cp == '\0') || (*cp == '/'))
				goto bad;
		if (*cp == '\0')
			return (1);
	}
bad:
	if (debug) {
		(void) printf("Bad dir in inode %d at lbn %d, loc %d:\n",
		    idesc->id_number, idesc->id_lbn, idesc->id_loc);
		(void) printf("    ino %d reclen %d namlen %d name `%s'\n",
		    dp->d_ino, dp->d_reclen, dp->d_namlen, dp->d_name);
	}
	return (0);
}

void
adjust(struct inodesc *idesc, int lcnt)
{
	struct dinode *dp;
	caddr_t flow;
	int saveiscorrupt;
	struct inodesc lcidesc;

	dp = ginode(idesc->id_number);
	if (dp->di_nlink == lcnt) {
		/*
		 * If we have not hit any unresolved problems, are running
		 * in preen mode, and are on a file system using logging,
		 * then just toss any partially allocated files, as they are
		 * an expected occurrence.
		 */
		if (!iscorrupt && preen && islog) {
			clri(idesc, "UNREF", CLRI_VERBOSE, CLRI_NOP_OK);
			return;
		} else {
			/*
			 * The file system can be considered clean even if
			 * a file is not linked up, but is cleared.  In
			 * other words, the kernel won't panic over it.
			 * Hence, iscorrupt should not be set when
			 * linkup is answered no, but clri is answered yes.
			 *
			 * If neither is answered yes, then we have a
			 * non-panic-inducing known corruption that the
			 * user needs to be reminded of when we exit.
			 */
			saveiscorrupt = iscorrupt;
			if (linkup(idesc->id_number, (fsck_ino_t)0,
			    NULL) == 0) {
				iscorrupt = saveiscorrupt;
				clri(idesc, "UNREF", CLRI_QUIET, CLRI_NOP_OK);
				if (statemap[idesc->id_number] != USTATE)
					iscorrupt = 1;
				return;
			}
			dp = ginode(idesc->id_number);
		}
		lcnt = lncntp[idesc->id_number];
	}

	/*
	 * It doesn't happen often, but it's possible to get a true
	 * excess of links (especially if a lot of directories got
	 * orphaned and reattached to lost+found).  Instead of wrapping
	 * around, do something semi-useful (i.e., give progress towards
	 * a less-broken filesystem) when this happens.
	 */
	LINK_RANGE(flow, dp->di_nlink, -lcnt);
	if (flow != NULL) {
		LINK_CLEAR(flow, idesc->id_number, dp->di_mode, &lcidesc);
		if (statemap[idesc->id_number] == USTATE)
			return;
	}

	dp = ginode(idesc->id_number);
	if (lcnt && dp->di_nlink != lcnt) {
		pwarn("LINK COUNT %s",
		    file_id(idesc->id_number, dp->di_mode));
		pinode(idesc->id_number);
		dp = ginode(idesc->id_number);
		(void) printf(" COUNT %d SHOULD BE %d",
		    dp->di_nlink, dp->di_nlink - lcnt);
		/*
		 * Even lost+found is subject to this, as whenever
		 * we modify it, we update both the in-memory and
		 * on-disk counts.  Thus, they should still be in
		 * sync.
		 */
		if (preen) {
			if (lcnt < 0) {
				(void) printf("\n");
				if ((dp->di_mode & IFMT) == IFSHAD)
					pwarn("LINK COUNT INCREASING");
				else
					pfatal("LINK COUNT INCREASING");
			}
		}
		if (preen || reply("ADJUST") == 1) {
			dp->di_nlink -= lcnt;
			inodirty();
			if (preen)
				(void) printf(" (ADJUSTED)\n");
		} else if (((dp->di_mode & IFMT) == IFDIR) ||
		    ((dp->di_mode & IFMT) == IFATTRDIR)) {
			/*
			 * File counts can be off relatively harmlessly,
			 * but a bad directory count can cause the
			 * kernel to lose its mind.
			 */
			iscorrupt = 1;
		}
	}
}

static int
mkentry(struct inodesc *idesc)
{
	struct direct *dirp = idesc->id_dirp;
	struct direct newent;
	int newlen, oldlen;

	newent.d_namlen = strlen(idesc->id_name);
	newlen = DIRSIZ(&newent);
	if (dirp->d_ino != 0)
		oldlen = DIRSIZ(dirp);
	else
		oldlen = 0;
	if ((int)dirp->d_reclen - oldlen < newlen)
		return (KEEPON);
	newent.d_reclen = dirp->d_reclen - (ushort_t)oldlen;
	dirp->d_reclen = (ushort_t)oldlen;

	/* LINTED dirp is aligned and DIRSIZ() forces oldlen to be aligned */
	dirp = (struct direct *)(((char *)dirp) + oldlen);
	dirp->d_ino = idesc->id_parent;	/* ino to be entered is in id_parent */
	dirp->d_reclen = newent.d_reclen;
	dirp->d_namlen = newent.d_namlen;
	(void) memmove(dirp->d_name, idesc->id_name,
	    (size_t)newent.d_namlen + 1);

	return (ALTERED|STOP);
}

static int
chgino(struct inodesc *idesc)
{
	struct direct *dirp = idesc->id_dirp;

	if (memcmp(dirp->d_name, idesc->id_name,
	    (size_t)dirp->d_namlen + 1) != 0)
		return (KEEPON);
	dirp->d_ino = idesc->id_parent;
	return (ALTERED|STOP);
}

int
linkup(fsck_ino_t orphan, fsck_ino_t parentdir, caddr_t name)
{
	int rval;
	struct dinode *dp;
	int lostdir;
	int lostshadow;
	fsck_ino_t oldlfdir;
	fsck_ino_t *intree;
	struct inodesc idesc;

	init_inodesc(&idesc);
	dp = ginode(orphan);
	lostdir = (((dp->di_mode & IFMT) == IFDIR) ||
	    ((dp->di_mode & IFMT) == IFATTRDIR));
	if (debug && lostdir && dp->di_nlink <= 0 && lncntp[orphan] == -1)
		(void) printf(
		    "old fsck would have left inode %d for reclaim thread\n",
		    orphan);
	lostshadow = (dp->di_mode & IFMT) == IFSHAD;
	pwarn("UNREF %s ", file_id(orphan, dp->di_mode));
	pinode(orphan);
	if (lostshadow || (dp->di_size == 0 && dp->di_oeftflag == 0))
		return (0);
	if (!preen && (reply("RECONNECT") == 0))
		goto noconnect;

	if (lfdir == 0) {
		dp = ginode(UFSROOTINO);
		idesc.id_name = lfname;
		idesc.id_type = DATA;
		idesc.id_func = findino;
		idesc.id_number = UFSROOTINO;
		idesc.id_fix = DONTKNOW;
		if ((ckinode(dp, &idesc, CKI_TRAVERSE) & FOUND) != 0) {
			lfdir = idesc.id_parent;
		} else {
			pwarn("NO %s DIRECTORY", lfname);
			if (preen || reply("CREATE") == 1) {
				lfdir = newdir(UFSROOTINO, (fsck_ino_t)0,
				    lfmode, lfname);
				if (lfdir != 0) {
					if (preen)
						(void) printf(" (CREATED)\n");
					else
						(void) printf("\n");
					statemap[lfdir] |= INFOUND;
					/*
					 * XXX What if we allocate an inode
					 * that's already been scanned?  Then
					 * we need to leave lnctnp[] alone.
					 */
					TRACK_LNCNTP(UFSROOTINO,
					    lncntp[UFSROOTINO]++);
				}
			}
		}
		if (lfdir == 0) {
			pfatal("SORRY. CANNOT CREATE %s DIRECTORY\n", lfname);
			pwarn("Could not reconnect inode %d\n", orphan);
			goto noconnect;
		} else {
			/*
			 * We searched for it via the namespace, so by
			 * definition it's been found.  We have to do this
			 * because it is possible that we're called before
			 * the full namespace mapping is complete (especially
			 * from pass 1, if it encounters a corrupt directory
			 * that has to be cleared).
			 */
			statemap[lfdir] |= INFOUND;
		}
	}
	dp = ginode(lfdir);
	if ((dp->di_mode & IFMT) != IFDIR) {
		pfatal("%s IS NOT A DIRECTORY", lfname);
		if (reply("REALLOCATE") == 0) {
			iscorrupt = 1;
			goto noconnect;
		}
		oldlfdir = lfdir;
		lfdir = reallocdir(UFSROOTINO, (fsck_ino_t)0, lfmode, lfname);
		if (lfdir == 0) {
			iscorrupt = 1;
			pfatal("SORRY. CANNOT CREATE %s DIRECTORY\n\n",
			    lfname);
			goto noconnect;
		}
		inodirty();
		statemap[lfdir] |= INFOUND;
		freeino(oldlfdir, TI_PARENT);
	}
	if (statemap[lfdir] != DFOUND) {
		/*
		 * Not a consistency problem of the sort that'll
		 * cause the kernel heartburn, so don't set iscorrupt.
		 */
		if (debug)
			(void) printf("lfdir %d is in state 0x%x\n",
			    lfdir, (int)statemap[lfdir]);
		lfdir = 0;
		pfatal("SORRY. %s DIRECTORY DISAPPEARED\n\n", lfname);
		pwarn("Could not reconnect inode %d\n", orphan);
		goto noconnect;
	}

	rval = do_reconnect(orphan, parentdir, name);

	return (rval);

	/*
	 * Leaving things unconnected is harmless as far as trying to
	 * use the filesystem later, so don't set iscorrupt yet (it's
	 * just lost blocks and inodes, after all).
	 *
	 * Lost directories get noted for reporting after all checks
	 * are done - they may get cleared later.
	 */
noconnect:
	if (lostdir) {
		intree = tsearch((void *)orphan, &limbo_dirs,
		    ino_t_cmp);
		if (intree == NULL)
			errexit("linkup: out of memory");
	}
	return (0);
}

/*
 * Connect an orphaned inode to lost+found.
 *
 * Returns non-zero for success, zero for failure.
 */
static int
do_reconnect(fsck_ino_t orphan, fsck_ino_t parentdir, caddr_t name)
{
	caddr_t flow_msg;
	struct dinode *dp;
	int lostdir;
	mode_t mode;
	fsck_ino_t *intree;
	struct inodesc idesc;

	dp = ginode(orphan);
	mode = dp->di_mode & IFMT;
	lostdir = (mode == IFDIR) || (mode == IFATTRDIR);

	name = mkuniqname(name, lfname, lfdir, orphan);
	if (name == NULL)
		goto noconnect;
	if (makeentry(lfdir, orphan, name) == 0) {
		pfatal("SORRY. NO SPACE IN %s DIRECTORY\n", lfname);
		pwarn("Could not reconnect inode %d\n", orphan);
		goto noconnect;
	}

	dp = ginode(orphan);
	LINK_RANGE(flow_msg, lncntp[orphan], -1);
	if (flow_msg != NULL) {
		LINK_CLEAR(flow_msg, orphan, dp->di_mode, &idesc);
		if (statemap[orphan] == USTATE)
			goto noconnect;
	}
	TRACK_LNCNTP(orphan, lncntp[orphan]--);

	/*
	 * Make sure that anything we put into the normal namespace
	 * looks like it belongs there.  Attributes can only be in
	 * attribute directories, not the normal directory lost+found.
	 */
	maybe_convert_attrdir_to_dir(orphan);

	if (lostdir) {
		/*
		 * Can't be creating a duplicate entry with makeentry(),
		 * because changeino() will succeed if ".." already
		 * exists.
		 */
		if ((changeino(orphan, "..", lfdir) & ALTERED) == 0 &&
		    parentdir != (fsck_ino_t)-1)
			(void) makeentry(orphan, lfdir, "..");
		/*
		 * If we were half-detached, don't try to get
		 * inode 0 later on.
		 */
		if (parentdir == 0)
			parentdir = -1;
		/*
		 * Fix up link counts.
		 *
		 * XXX This section is getting pretty byzantine, espcially
		 * when combined with changeino()/chgino()'s link manipulation.
		 */
		LFDIR_LINK_RANGE_RVAL(flow_msg, lncntp[lfdir], 1, &idesc, 0);
		TRACK_LNCNTP(lfdir, lncntp[lfdir]--);
		pwarn("DIR I=%lu CONNECTED. ", (long)orphan);
		reattached_dir = 1;
		if (parentdir != (fsck_ino_t)-1) {
			/*
			 * Have to clear the parent's reference.  Otherwise,
			 * if it's an orphan, then we may clear this orphan
			 * in pass 4 even though we've reconnected it.
			 *
			 * We already have the reference count
			 * allowing for a parent link, so undo the
			 * adjustment done above.  Otherwise we come
			 * out high by one.
			 */
			(void) printf("PARENT WAS I=%lu\n", (long)parentdir);
			(void) cleardirentry(parentdir, orphan);
		}
		if (!preen)
			(void) printf("\n");
	} else if (preen) {
		(void) printf(" (RECONNECTED)\n");
	}

	statemap[orphan] &= ~INDELAYD;
	return (1);

	/*
	 * Leaving things unconnected is harmless as far as trying to
	 * use the filesystem later, so don't set iscorrupt yet (it's
	 * just lost blocks and inodes, after all).
	 *
	 * Lost directories get noted for reporting after all checks
	 * are done - they may get cleared later.
	 */
noconnect:
	if (lostdir) {
		intree = tsearch((void *)orphan, &limbo_dirs,
		    ino_t_cmp);
		if (intree == NULL)
		errexit("linkup: out of memory");
	}
	return (0);
}

/*
 * fix an entry in a directory.
 */
int
changeino(fsck_ino_t dir, char *name, fsck_ino_t newnum)
{
	struct inodesc idesc;

	init_inodesc(&idesc);
	idesc.id_type = DATA;
	idesc.id_func = chgino;
	idesc.id_number = dir;
	idesc.id_fix = DONTKNOW;
	idesc.id_name = name;
	idesc.id_parent = newnum;	/* new value for name */
	return (ckinode(ginode(dir), &idesc, CKI_TRAVERSE));
}

/*
 * make an entry in a directory
 */
int
makeentry(fsck_ino_t parent, fsck_ino_t ino, char *name)
{
	int repeat;
	struct dinode *dp;
	struct inoinfo *iip;
	struct inodesc idesc;
	char pathbuf[MAXPATHLEN + 1];

	if (parent < UFSROOTINO || parent >= maxino ||
	    ino < UFSROOTINO || ino >= maxino)
		return (0);
	init_inodesc(&idesc);
	idesc.id_type = DATA;
	idesc.id_func = mkentry;
	idesc.id_number = parent;
	idesc.id_parent = ino;	/* this is the inode to enter */
	idesc.id_fix = DONTKNOW;
	idesc.id_name = name;

	repeat = 0;
again:
	dp = ginode(parent);
	if ((dp->di_size % DIRBLKSIZ) != 0) {
		dp->di_size = roundup(dp->di_size, DIRBLKSIZ);
		inodirty();

		iip = getinoinfo(ino);
		if (iip != NULL)
			iip->i_isize = dp->di_size;
	}

	if ((ckinode(dp, &idesc, CKI_TRAVERSE) & ALTERED) != 0) {
		iip = getinoinfo(ino);
		if (iip != NULL)
			iip->i_isize = dp->di_size;

		return (1);
	}

	if (repeat == 0) {
		getpathname(pathbuf, parent, parent);
		if (expanddir(parent, pathbuf) == 0)
			return (0);

		repeat = 1;
		goto again;
	}

	return (0);
}

/*
 * Attempt to expand the size of a directory
 */
static int
expanddir(fsck_ino_t ino, char *name)
{
	struct bufarea *bpback, *bp[2];
	daddr32_t nxtibn, nxtbn;
	daddr32_t newblk[2];
	struct dinode *dp;
	char *cp;
	int bc, f;
	int n;
	int allocIndir;
	int frag2blks;
	int lffragsz = 0;
	int c = 0;
	int retval = 0;

	bp[0] = bp[1] = NULL;

	dp = ginode(ino);
	if (dp->di_size == 0) {
		goto bail;
	}

	nxtbn = lblkno(&sblock, dp->di_size - 1) + 1;

	/*
	 *  Check that none of the nominally in-use direct block
	 *  addresses for the directory are bogus.
	 */
	for (bc = 0; ((nxtbn > 0) && (bc < nxtbn) && (bc < NDADDR)); bc++) {
		if (dp->di_db[bc] == 0) {
			goto bail;
		}
	}

	/*
	 * Determine our data block allocation needs.  We always need to
	 * allocate at least one data block.  We may need a second, the
	 * indirect block itself.
	 */
	allocIndir = 0;
	nxtibn = -1;
	n = 0;

	if (nxtbn <= NDADDR)  {
		/*
		 * Still in direct blocks.  Check for the unlikely
		 * case where the last block is a frag rather than
		 * a full block.  This would only happen if someone had
		 * created a file in lost+found, and then that caused
		 * the dynamic directory shrinking capabilities of ufs
		 * to kick in.
		 *
		 * Note that we test nxtbn <= NDADDR, as it's the
		 * next block (i.e., one greater than the current/
		 * actual block being examined).
		 */
		lffragsz = dp->di_size % sblock.fs_bsize;
	}

	if (nxtbn >= NDADDR && !lffragsz) {
		n = sblock.fs_bsize / sizeof (daddr32_t);
		nxtibn = nxtbn - NDADDR;
		/*
		 * Only go one level of indirection
		 */
		if (nxtibn >= n) {
			goto bail;
		}
		/*
		 * First indirect block means we need to pick up
		 * the actual indirect pointer block as well.
		 */
		if (nxtibn == 0)
			allocIndir++;
	}

	/*
	 * Allocate all the new blocks we need.
	 */
	if ((newblk[0] = allocblk(sblock.fs_frag)) == 0) {
		goto bail;
	}
	c++;
	if (allocIndir) {
		if ((newblk[1] = allocblk(sblock.fs_frag)) == 0) {
			goto bail;
		}
		c++;
	}

	/*
	 * Take care of the block that will hold new directory entries.
	 * This one is always allocated.
	 */
	bp[0] = getdirblk(newblk[0], (size_t)sblock.fs_bsize);
	if (bp[0]->b_errs) {
		goto bail;
	}

	if (lffragsz) {
		/*
		 * Preserve the partially-populated existing directory.
		 */
		bpback = getdirblk(dp->di_db[nxtbn - 1],
		    (size_t)dblksize(&sblock, dp, nxtbn - 1));
		if (!bpback->b_errs) {
			(void) memmove(bp[0]->b_un.b_buf, bpback->b_un.b_buf,
			    (size_t)lffragsz);
		}
	}

	/*
	 * Initialize the new fragments.  lffragsz is zero if this
	 * is a completely-new block.
	 */
	for (cp = &(bp[0]->b_un.b_buf[lffragsz]);
	    cp < &(bp[0]->b_un.b_buf[sblock.fs_bsize]);
	    cp += DIRBLKSIZ) {
		(void) memmove(cp, (char *)&emptydir,
		    sizeof (emptydir));
	}
	dirty(bp[0]);

	/*
	 * If we allocated the indirect block, zero it out. Otherwise
	 * read it in if we're using one.
	 */
	if (allocIndir) {
		bp[1] = getdatablk(newblk[1], (size_t)sblock.fs_bsize);
		if (bp[1]->b_errs) {
			goto bail;
		}
		(void) memset(bp[1]->b_un.b_buf, 0, sblock.fs_bsize);
		dirty(bp[1]);
	} else if (nxtibn >= 0) {
		/* Check that the indirect block pointer looks okay */
		if (dp->di_ib[0] == 0) {
			goto bail;
		}
		bp[1] = getdatablk(dp->di_ib[0], (size_t)sblock.fs_bsize);
		if (bp[1]->b_errs) {
			goto bail;
		}

		for (bc = 0; ((bc < nxtibn) && (bc < n)); bc++) {
			/* LINTED pointer cast alignment */
			if (((daddr32_t *)bp[1]->b_un.b_buf)[bc] == 0) {
				goto bail;
			}
		}
	}

	/*
	 * Since the filesystem's consistency isn't affected by
	 * whether or not we actually do the expansion, iscorrupt
	 * is left alone for any of the approval paths.
	 */
	pwarn("NO SPACE LEFT IN %s", name);
	if (!preen && (reply("EXPAND") == 0))
		goto bail;

	/*
	 * Now that everything we need is gathered up and the
	 * necessary approvals acquired, we can make our provisional
	 * changes permanent.
	 */

	if (lffragsz) {
		/*
		 * We've saved the data from the old end fragment(s) in
		 * our new block, so we can just swap the new one in.
		 * Make sure the size reflects the expansion of the
		 * final fragments/block.
		 */
		frag2blks = roundup(lffragsz, sblock.fs_fsize);
		freeblk(ino, dp->di_db[nxtbn - 1],
		    frag2blks / sblock.fs_fsize);
		frag2blks = btodb(frag2blks);
		dp->di_size -= (u_offset_t)lffragsz;
		dp->di_blocks = dp->di_blocks - frag2blks;
		dp->di_db[nxtbn - 1] = newblk[0];
		dp->di_size += (u_offset_t)sblock.fs_bsize;
		dp->di_blocks += btodb(sblock.fs_bsize);
		inodirty();
		retval = 1;
		goto done;
	}

	/*
	 * Full-block addition's much easier.  It's just an append.
	 */
	dp->di_size += (u_offset_t)sblock.fs_bsize;
	dp->di_blocks += btodb(sblock.fs_bsize);
	if (allocIndir) {
		dp->di_blocks += btodb(sblock.fs_bsize);
	}

	inodirty();
	if (nxtibn < 0) {
		/*
		 * Still in direct blocks
		 */
		dp->di_db[nxtbn] = newblk[0];
	} else {
		/*
		 * Last indirect is always going to point at the
		 * new directory buffer
		 */
		if (allocIndir)
			dp->di_ib[0] = newblk[1];
		/* LINTED pointer case alignment */
		((daddr32_t *)bp[1]->b_un.b_buf)[nxtibn] = newblk[0];
		dirty(bp[1]);
	}

	if (preen)
		(void) printf(" (EXPANDED)\n");

	retval = 1;
	goto done;

bail:
	for (f = 0; f < c; f++)
		freeblk(ino, newblk[f], sblock.fs_frag);
done:
	/*
	 * bp[0] is handled by the directory cache's auto-release.
	 */
	if (bp[1] != NULL)
		brelse(bp[1]);

	return (retval);
}

static fsck_ino_t
newdir(fsck_ino_t parent, fsck_ino_t request, int mode, caddr_t name)
{
	fsck_ino_t dino;
	char pname[BUFSIZ];

	/*
	 * This function creates a new directory and populates it with
	 * "." and "..", then links to it as NAME in PARENT.
	 */
	dino = allocdir(parent, request, mode, 1);
	if (dino != 0) {
		getpathname(pname, parent, parent);
		name = mkuniqname(name, pname, parent, dino);
		/*
		 * We don't touch numdirs, because it's just a cache of
		 * what the filesystem claimed originally and is used
		 * to calculate hash keys.
		 */
		if (makeentry(parent, dino, name) == 0) {
			freedir(dino, parent);
			dino = 0;
		}
	}

	return (dino);
}

/*
 * Replace whatever NAME refers to in PARENT with a new directory.
 * Note that if the old inode REQUEST is a directory, all of its
 * contents will be freed and reaped.
 */
static fsck_ino_t
reallocdir(fsck_ino_t parent, fsck_ino_t request, int mode, caddr_t name)
{
	int retval;
	fsck_ino_t newino;

	if ((request != 0) && (statemap[request] != USTATE))
		freeino(request, TI_PARENT);

	newino = allocdir(parent, request, mode, 0);
	if (newino != 0) {
		retval = changeino(parent, name, newino);
		if ((retval & ALTERED) == 0) {
			/*
			 * No change made, so name doesn't exist, so
			 * unwind allocation rather than leak it.
			 */
			freedir(newino, parent);
			newino = 0;
		}
	}

	return (newino);
}

/*
 * allocate a new directory
 */
fsck_ino_t
allocdir(fsck_ino_t parent, fsck_ino_t request, int mode, int update_parent)
{
	fsck_ino_t ino;
	caddr_t cp;
	caddr_t flow;
	struct dinode *dp;
	struct bufarea *bp;
	struct inoinfo *inp;
	struct inodesc idesc;
	struct dirtemplate *dirp;

	ino = allocino(request, IFDIR|mode);
	if (ino == 0)
		return (0);
	dirp = &dirhead;
	dirp->dot_ino = ino;
	dirp->dotdot_ino = parent;
	dp = ginode(ino);
	bp = getdirblk(dp->di_db[0], (size_t)sblock.fs_fsize);
	if (bp->b_errs) {
		freeino(ino, TI_PARENT);
		return (0);
	}
	(void) memmove(bp->b_un.b_buf, (void *)dirp,
	    sizeof (struct dirtemplate));
	for (cp = &bp->b_un.b_buf[DIRBLKSIZ];
	    cp < &bp->b_un.b_buf[sblock.fs_fsize];
	    cp += DIRBLKSIZ)
		(void) memmove(cp, (void *)&emptydir, sizeof (emptydir));
	dirty(bp);
	dp->di_nlink = 2;
	inodirty();
	if (!inocached(ino)) {
		cacheino(dp, ino);
	} else {
		/*
		 * re-using an old directory inode
		 */
		inp = getinoinfo(ino);
		if (inp == NULL) {
			if (debug)
				errexit("allocdir got NULL from getinoinfo "
					"for existing entry I=%d\n",
					ino);
			cacheino(dp, ino);
		} else {
			init_inoinfo(inp, dp, ino);
			inp->i_parent = parent;
			inp->i_dotdot = parent;
		}
	}

	/*
	 * Short-circuit all the dancing around below if it's the
	 * root inode.  The net effect's the same.
	 */
	if (ino == UFSROOTINO) {
		TRACK_LNCNTP(ino, lncntp[ino] = dp->di_nlink);
		return (ino);
	}

	if (!update_parent)
		return (ino);

	/*
	 * We never create attribute directories, which can have
	 * non-directory parents.  So, the parent of the directory
	 * we're creating must itself be a directory.
	 */
	if (!INO_IS_DVALID(parent)) {
		freeino(ino, TI_PARENT);
		return (0);
	}

	/*
	 * Make sure the parent can handle another link.
	 * Since we might only update one version of the
	 * count (disk versus in-memory), we have to check both.
	 */
	LINK_RANGE(flow, lncntp[parent], -1);
	if (flow == NULL)
		LINK_RANGE(flow, (int)dp->di_nlink, 1);

	if (flow != NULL) {
		LINK_CLEAR(flow, parent, dp->di_mode, &idesc);
		if (statemap[parent] == USTATE) {
				/*
				 * No parent any more, so bail out.  Callers
				 * are expected to handle this possibility.
				 * Since most just throw up their hands if
				 * we return 0, this just happens to work.
				 */
			freeino(ino, TI_PARENT);
			return (0);
		}
	}

	/*
	 * We've created a directory with two entries, "." and "..",
	 * and a link count of two ("." and one from its parent).  If
	 * the parent's not been scanned yet, which means this inode
	 * will get scanned later as well, then make our in-core count
	 * match what we pushed out to disk.  Similarly, update the
	 * parent.  On the other hand, if the parent's already been
	 * looked at (statemap[ino] == DFOUND), the discrepancy
	 * between lncntp[] and di_nlink will be noted later, with
	 * appropriate reporting and propagation, in pass2.
	 *
	 * We're explicitly skipping where the parent was DZLINK or
	 * DFOUND.  If it has zero links, it can't be gotten to, so
	 * we want a discrepancy set up that will be caught in pass2.
	 * DFOUND was discussed above.
	 *
	 * Regarding the claim of a link from the parent: we've not
	 * done anything to create such a link here.  We depend on the
	 * semantics of our callers attaching the inode we return to
	 * an existing entry in the directory or creating the entry
	 * themselves, but in either case, not modifying the link
	 * count.
	 *
	 * Note that setting lncntp[ino] to zero means that both claimed
	 * links have been ``found''.
	 */
	statemap[ino] = statemap[parent];
	if (INO_IS_DVALID(parent)) {
		TRACK_LNCNTP(ino, lncntp[ino] = 0);
		TRACK_LNCNTP(parent, lncntp[parent]--);
	}
	dp = ginode(parent);
	dp->di_nlink++;
	inodirty();
	return (ino);
}

/*
 * free a directory inode
 */
static void
freedir(fsck_ino_t ino, fsck_ino_t parent)
{
	struct inoinfo *iip;

	if (ino != parent) {
		/*
		 * Make sure that the desired parent gets a link
		 * count update from freeino()/truncino().  If
		 * we can't look it up, then it's not really a
		 * directory, so there's nothing to worry about.
		 */
		iip = getinoinfo(ino);
		if (iip != NULL)
			iip->i_parent = parent;
	}
	freeino(ino, TI_PARENT);
}

/*
 * generate a temporary name for use in the lost+found directory.
 */
static void
lftempname(char *bufp, fsck_ino_t ino)
{
	fsck_ino_t in;
	caddr_t cp;
	int namlen;

	cp = bufp + 2;
	for (in = maxino; in > 0; in /= 10)
		cp++;
	*--cp = '\0';
	/* LINTED difference will not overflow an int */
	namlen = cp - bufp;
	if ((namlen > BUFSIZ) || (namlen > MAXPATHLEN)) {
		errexit("buffer overflow in lftempname()\n");
	}

	in = ino;
	while (cp > bufp) {
		*--cp = (in % 10) + '0';
		in /= 10;
	}
	*cp = '#';
}

/*
 * Get a directory block.
 * Insure that it is held until another is requested.
 *
 * Our callers are expected to check for errors and/or be
 * prepared to handle blocks of zeros in the middle of a
 * directory.
 */
static struct bufarea *
getdirblk(daddr32_t blkno, size_t size)
{
	if (pdirbp != 0) {
		brelse(pdirbp);
	}
	pdirbp = getdatablk(blkno, size);
	return (pdirbp);
}

/*
 * Create a unique name for INODE to be created in directory PARENT.
 * Use NAME if it is provided (non-NULL) and doesn't already exist.
 * Returning NULL indicates no unique name could be generated.
 *
 * If we were given a name, and it conflicts with an existing
 * entry, use our usual temp name instead.  Without this check,
 * we could end up creating duplicate entries for multiple
 * orphaned directories in lost+found with the same name (but
 * different parents).  Of course, our usual name might already
 * be in use as well, so be paranoid.
 *
 * We could do something like keep tacking something onto the
 * end of tempname until we come up with something that's not
 * in use, but that has liabilities as well.  This is a
 * sufficiently rare case that it's not worth going that
 * overboard for.
 */
static caddr_t
mkuniqname(caddr_t name, caddr_t pname, fsck_ino_t parent, fsck_ino_t inode)
{
	fsck_ino_t oldino;
	struct dinode *dp;
	caddr_t flow_msg;
	struct inodesc idesc;
	static char tempname[BUFSIZ];

	lftempname(tempname, inode);
	if ((name != NULL) &&
	    (lookup_named_ino(parent, name) != 0)) {
		name = NULL;
	}
	if (name == NULL) {
		/*
		 * No name given, or it wasn't unique.
		 */
		name = tempname;
		if ((oldino = lookup_named_ino(parent, name)) != 0) {
			pfatal(
			    "Name ``%s'' for inode %d already exists in %s \n",
			    name, oldino, pname);
			if (reply("REMOVE OLD ENTRY") == 0) {
				if (parent == lfdir)
					pwarn(
					    "Could not reconnect inode %d\n\n",
					    inode);
				else
					pwarn(
					    "Could not create entry for %d\n\n",
					    inode);
				name = NULL;
				goto noconnect;
			}
			(void) changeino(parent, name, inode);
			LINK_RANGE(flow_msg, lncntp[oldino], 1);
			if (flow_msg != NULL) {
				/*
				 * Do a best-effort, but if we're not
				 * allowed to do the clear, the fs is
				 * corrupt in any case, so just carry on.
				 */
				dp = ginode(oldino);
				LINK_CLEAR(flow_msg, oldino, dp->di_mode,
				    &idesc);
				if (statemap[oldino] != USTATE)
					iscorrupt = 1;
			} else {
				TRACK_LNCNTP(oldino, lncntp[oldino]++);
			}
		}
	}

noconnect:
	return (name);
}
