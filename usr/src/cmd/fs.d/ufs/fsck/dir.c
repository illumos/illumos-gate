/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
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

#define	bcopy(f, t, n)    memcpy(t, f, n)
#define	bzero(s, n)	memset(s, 0, n)
#define	bcmp(s, d, n)	memcmp(s, d, n)

#define	index(s, r)	strchr(s, r)
#define	rindex(s, r)	strrchr(s, r)

#include <sys/fs/ufs_fs.h>
#include <sys/vnode.h>
#include <sys/fs/ufs_inode.h>
#define	_KERNEL
#include <sys/fs/ufs_fsdir.h>
#undef _KERNEL
#include "fsck.h"

char	*lfname = "lost+found";
int	lfmode = 01700;
struct	dirtemplate emptydir = { 0, DIRBLKSIZ };
struct	dirtemplate dirhead = { 0, 12, 1, ".", 0, DIRBLKSIZ - 12, 2, ".." };

struct direct	*fsck_readdir();
struct bufarea	*getdirblk(daddr32_t, int);

/*
 * Propagate connected state through the tree.
 */
propagate()
{
	struct inoinfo **inpp, *inp;
	struct inoinfo **inpend;
	int change;

	inpend = &inpsort[inplast];
	do {
		change = 0;
		for (inpp = inpsort; inpp < inpend; inpp++) {
			inp = *inpp;
			if (inp->i_parent == 0)
				continue;
			if (statemap[inp->i_parent] == DFOUND &&
			    statemap[inp->i_number] == DSTATE) {
				statemap[inp->i_number] = DFOUND;
				change++;
			}
		}
	} while (change > 0);
}

/*
 * Scan each entry in a directory block.
 */
dirscan(idesc)
	struct inodesc *idesc;
{
	struct direct *dp;
	struct bufarea *bp;
	int dsize, n;
	int blksiz;
	char dbuf[DIRBLKSIZ];

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
		 * d_reclen > DIRBLKSIZ so we don't bcopy() all over our stack.
		 * This directory gets cleaned up later.
		 */
		dsize = MIN(dp->d_reclen, DIRBLKSIZ);
		bcopy((char *)dp, dbuf, dsize);
		idesc->id_dirp = (struct direct *)dbuf;
		if ((n = (*idesc->id_func)(idesc)) & ALTERED) {
			bp = getdirblk(idesc->id_blkno, blksiz);
			bcopy(dbuf, bp->b_un.b_buf + idesc->id_loc - dsize,
			    dsize);
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
struct direct *
fsck_readdir(idesc)
	struct inodesc *idesc;
{
	struct direct *dp, *ndp = 0;
	struct bufarea *bp;
	int size, blksiz;
	int dofixret;
	int origloc	= idesc->id_loc;

	blksiz = idesc->id_numfrags * sblock.fs_fsize;
	/*
	 * Sanity check id_filesize and id_loc fields.
	 */
	if (idesc->id_filesize <= 0 || idesc->id_loc >= blksiz)
		return (NULL);

	bp = getdirblk(idesc->id_blkno, blksiz);
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
		dofixret = dofix(idesc, "DIRECTORY CORRUPTED");
		bp = getdirblk(idesc->id_blkno, blksiz);
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
		 * via a "goto next_is_bad".  This directory entry is
		 * corrupt.  The current directory entry is okay so, if we
		 * are in fix mode, extend just its record size to encompass
		 * the rest of the block.
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
		 * which we said "no". This is the pathalogical case and
		 * no fix is planned at this time.
		 */
		if (dofixret)
			dirty(bp);
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
	if ((idesc->id_loc & (DIRBLKSIZ - 1)) &&
	    idesc->id_loc < blksiz && idesc->id_filesize > 0) {
		ndp = (struct direct *)(bp->b_un.b_buf + idesc->id_loc);
		if (dircheck(idesc, ndp) == 0)
			goto next_is_bad;
	}

	return (dp);
}

/*
 * Verify that a directory entry is valid.
 * This is a superset of the checks made in the kernel.
 */
dircheck(idesc, dp)
	struct inodesc *idesc;
	struct direct *dp;
{
	int size;
	char *cp;
	int spaceleft;

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
		for (cp = dp->d_name, size = 0; size < (int)dp->d_namlen;
								size++, cp++)
			if ((*cp == 0) || (*cp == '/'))
				return (0);
		if (*cp == 0)
			return (1);
	}
	return (0);
}

direrror(ino, errmesg)
	ino_t ino;
	char *errmesg;
{

	fileerror(ino, ino, errmesg);
}

fileerror(cwd, ino, errmesg)
	ino_t cwd, ino;
	char *errmesg;
{
	struct dinode *dp;
	char pathbuf[MAXPATHLEN + 1];

	pwarn("%s ", errmesg);
	pinode(ino);
	printf("\n");
	getpathname(pathbuf, cwd, ino);
	if (ino < UFSROOTINO || ino > maxino) {
		pfatal("NAME=%s\n", pathbuf);
		return;
	}
	dp = ginode(ino);
	if (ftypeok(dp))
		pfatal("%s=%s\n",
		    (dp->di_mode & IFMT) == IFDIR ? "DIR" : "FILE", pathbuf);
	else
		pfatal("NAME=%s\n", pathbuf);
}

adjust(idesc, lcnt)
	struct inodesc *idesc;
	short lcnt;
{
	struct dinode *dp;

	dp = ginode(idesc->id_number);
	if (dp->di_nlink == lcnt) {
		if (linkup(idesc->id_number, (ino_t)0) == 0) {
			clri(idesc, "UNREF", 0);
			return;
		}
		lcnt = (short)lncntp[idesc->id_number];
	}
	if (lcnt && dp->di_nlink != lcnt) {
		pwarn("LINK COUNT %s",
		    (lfdir == idesc->id_number) ? lfname :
		    (dp->di_mode & IFMT) == IFDIR ? "DIR" :
		    (dp->di_mode & IFMT) == IFATTRDIR ? "ATTR DIR" :
		    (dp->di_mode & IFMT) == IFSHAD ? "ACL" : "FILE");
		pinode(idesc->id_number);
		printf(" COUNT %d SHOULD BE %d",
		    dp->di_nlink, dp->di_nlink - lcnt);
		if (preen) {
			if (lcnt < 0) {
				printf("\n");
				if ((dp->di_mode & IFMT) == IFSHAD)
					pwarn("LINK COUNT INCREASING");
				else
					pfatal("LINK COUNT INCREASING");
			}
			printf(" (ADJUSTED)\n");
		}
		if (preen || reply("ADJUST") == 1) {
			dp->di_nlink -= lcnt;
			inodirty();
		}
	}
}

mkentry(idesc)
	struct inodesc *idesc;
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
	dirp = (struct direct *)(((char *)dirp) + oldlen);
	dirp->d_ino = idesc->id_parent;	/* ino to be entered is in id_parent */
	dirp->d_reclen = newent.d_reclen;
	dirp->d_namlen = newent.d_namlen;
	bcopy(idesc->id_name, dirp->d_name, (size_t)dirp->d_namlen + 1);
	return (ALTERED|STOP);
}

chgino(idesc)
	struct inodesc *idesc;
{
	struct direct *dirp = idesc->id_dirp;

	if (bcmp(dirp->d_name, idesc->id_name, (size_t)dirp->d_namlen + 1))
		return (KEEPON);
	dirp->d_ino = idesc->id_parent;
	return (ALTERED|STOP);
}

linkup(orphan, parentdir)
	ino_t orphan;
	ino_t parentdir;
{
	struct dinode *dp;
	int lostdir;
	int lostshadow;
	int lostattrdir;
	ino_t oldlfdir;
	struct inodesc idesc;
	char tempname[BUFSIZ];
	extern int pass4check();

	bzero((char *)&idesc, sizeof (struct inodesc));
	dp = ginode(orphan);
	lostdir = (((dp->di_mode & IFMT) == IFDIR) ||
	    ((dp->di_mode & IFMT) == IFATTRDIR));
	/*
	 * reclaim thread will remove this dir at mount
	 */
	if (lostdir &&
	    (willreclaim && dp->di_nlink <= 0 && lncntp[orphan] == -1)) {
		if (parentdir && lncntp[parentdir] < 0)
			++lncntp[parentdir];
		return (0);
	}
	lostshadow = (dp->di_mode & IFMT) == IFSHAD;
	lostattrdir = (dp->di_mode & IFMT) == IFATTRDIR;
	pwarn("UNREF %s ", lostattrdir ? "ATTRDIR" : lostdir ? "DIR" :
	    lostshadow ? "ACL" : "FILE");
	pinode(orphan);
	if (lostshadow || (dp->di_size == 0 && dp->di_oeftflag == 0))
		return (0);
	if (preen)
		printf(" (RECONNECTED)\n");
	else
		if (reply("RECONNECT") == 0)
			return (0);
	if (lfdir == 0) {
		dp = ginode(UFSROOTINO);
		idesc.id_name = lfname;
		idesc.id_type = DATA;
		idesc.id_func = findino;
		idesc.id_number = UFSROOTINO;
		idesc.id_fix = DONTKNOW;
		if ((ckinode(dp, &idesc) & FOUND) != 0) {
			lfdir = idesc.id_parent;
		} else {
			pwarn("NO lost+found DIRECTORY");
			if (preen || reply("CREATE")) {
				lfdir = allocdir(UFSROOTINO, (ino_t)0, lfmode);
				if (lfdir != 0) {
					if (makeentry(UFSROOTINO, lfdir,
					    lfname) != 0) {
						if (preen)
							printf(" (CREATED)\n");
					} else {
						freedir(lfdir, UFSROOTINO);
						lfdir = 0;
						if (preen)
							printf("\n");
					}
				}
			}
		}
		if (lfdir == 0) {
			pfatal("SORRY. CANNOT CREATE lost+found DIRECTORY");
			printf("\n\n");
			return (0);
		}
	} else {	/* lost+found already created */
		idesc.id_name = lfname;
	}
	dp = ginode(lfdir);
	if ((dp->di_mode & IFMT) != IFDIR) {
		pfatal("lost+found IS NOT A DIRECTORY");
		if (reply("REALLOCATE") == 0)
			return (0);
		oldlfdir = lfdir;
		if ((lfdir = allocdir(UFSROOTINO, (ino_t)0, lfmode)) == 0) {
			pfatal("SORRY. CANNOT CREATE lost+found DIRECTORY\n\n");
			return (0);
		}
		if ((changeino(UFSROOTINO, lfname, lfdir) & ALTERED) == 0) {
			pfatal("SORRY. CANNOT CREATE lost+found DIRECTORY\n\n");
			return (0);
		}
		inodirty();
		idesc.id_type = ADDR;
		idesc.id_func = pass4check;
		idesc.id_number = oldlfdir;
		idesc.id_fix = DONTKNOW;
		lncntp[oldlfdir]++;
		adjust(&idesc, lncntp[oldlfdir]);
		lncntp[oldlfdir] = 0;
		dp = ginode(lfdir);
	}
	if (statemap[lfdir] != DFOUND) {
		pfatal("SORRY. NO lost+found DIRECTORY\n\n");
		return (0);
	}
	(void) lftempname(tempname, orphan);
	if (makeentry(lfdir, orphan, tempname) == 0) {
		pfatal("SORRY. NO SPACE IN lost+found DIRECTORY");
		printf("\n\n");
		return (0);
	}
	lncntp[orphan]--;
	if (lostdir) {
		if ((changeino(orphan, "..", lfdir) & ALTERED) == 0 &&
		    parentdir != (ino_t)-1)
			(void) makeentry(orphan, lfdir, "..");
		/*
		 * If we were half-detached, don't try to get
		 * inode 0 later on.
		 */
		if (parentdir == 0)
			parentdir = -1;
		dp = ginode(lfdir);
		dp->di_nlink++;
		inodirty();
		lncntp[lfdir]++;
		if (parentdir != lfdir && parentdir != -1) {
			dp = ginode(parentdir);
			if ((dp->di_mode & IFMT) == IFDIR)
				lncntp[parentdir]++;
		}
		pwarn("DIR I=%u CONNECTED. ", orphan);
		if (parentdir != (ino_t)-1)
			printf("PARENT WAS I=%u\n", parentdir);
		if (preen == 0)
			printf("\n");
	}
	return (1);
}

/*
 * fix an entry in a directory.
 */
changeino(dir, name, newnum)
	ino_t dir;
	char *name;
	ino_t newnum;
{
	struct inodesc idesc;

	bzero((char *)&idesc, sizeof (struct inodesc));
	idesc.id_type = DATA;
	idesc.id_func = chgino;
	idesc.id_number = dir;
	idesc.id_fix = DONTKNOW;
	idesc.id_name = name;
	idesc.id_parent = newnum;	/* new value for name */
	return (ckinode(ginode(dir), &idesc));
}

/*
 * make an entry in a directory
 */
makeentry(parent, ino, name)
	ino_t parent, ino;
	char *name;
{
	struct dinode *dp;
	struct inodesc idesc;
	char pathbuf[MAXPATHLEN + 1];

	if (parent < UFSROOTINO || parent >= maxino ||
	    ino < UFSROOTINO || ino >= maxino)
		return (0);
	bzero((char *)&idesc, sizeof (struct inodesc));
	idesc.id_type = DATA;
	idesc.id_func = mkentry;
	idesc.id_number = parent;
	idesc.id_parent = ino;	/* this is the inode to enter */
	idesc.id_fix = DONTKNOW;
	idesc.id_name = name;
	dp = ginode(parent);
	if (dp->di_size % DIRBLKSIZ) {
		dp->di_size = roundup(dp->di_size, DIRBLKSIZ);
		inodirty();
	}
	if ((ckinode(dp, &idesc) & ALTERED) != 0)
		return (1);
	getpathname(pathbuf, parent, parent);
	dp = ginode(parent);
	if (expanddir(dp, pathbuf) == 0)
		return (0);
	idesc.id_fix = DONTKNOW;
	return (ckinode(dp, &idesc) & ALTERED);
}

/*
 * Attempt to expand the size of a directory
 */
expanddir(dp, name)
	struct dinode *dp;
	char *name;
{
	struct bufarea *bpback, *bp[2];
	daddr32_t nxtibn, nxtbn;
	daddr32_t newblk[2];
	char *cp;
	int bc, n, f;
	int allocIndir;
	int frag2blks = 0;
	int lffragsz = 0;
	int c = 0;

	if (dp->di_size == 0)
		return (0);

	nxtbn = lblkno(&sblock, dp->di_size - 1) + 1;

	/*
	 *  Check that none of the direct block addresses for
	 *  the directory are bogus.
	 */
	for (bc = 0; ((nxtbn > 0) && (bc < nxtbn) && (bc < NDADDR)); bc++) {
		if (dp->di_db[bc] == 0)
			return (0);
	}

	/*
	 * Determine our data block allocation needs.  We always need to
	 * allocate at least one data block.  We may need a second, the
	 * indirect block itself.
	 */
	allocIndir = 0;
	nxtibn = -1;

	if (nxtbn <= NDADDR)  {
		/*
		 * Still in direct blocks.  Check for the unlikely
		 * case where the last block is a frag rather than
		 * a full block.  This would only happen if someone had
		 * created a file in lost+found, and then that caused
		 * the dynamic directory shrinking capabilities of ufs
		 * to kick in.
		 */
		lffragsz = dp->di_size % sblock.fs_bsize;
	}

	if (nxtbn >= NDADDR && !lffragsz) {
		n = sblock.fs_bsize/sizeof (daddr32_t);
		nxtibn = nxtbn - NDADDR;
		/*
		 * Only go one level of indirection
		 */
		if (nxtibn >= n)
			return (0);

		if (nxtibn == 0)
			allocIndir++;
	}

	/*
	 * Allocate all the new blocks we need.
	 */
	if ((newblk[0] = allocblk(sblock.fs_frag)) == 0)
		goto bail;
	c++;
	if (allocIndir) {
		if ((newblk[1] = allocblk(sblock.fs_frag)) == 0)
			goto bail;
		c++;
	}

	/*
	 * Take care of the block that will hold new directory entries.
	 * This one is always allocated.
	 */
	bp[0] = getdirblk(newblk[0], sblock.fs_bsize);
	if (bp[0]->b_errs)
		goto bail;
	if (lffragsz) {
		bpback = getdirblk(dp->di_db[nxtbn - 1],
		    dblksize(&sblock, dp, nxtbn - 1));
		if (bpback->b_errs)
			goto bail;
		bcopy(bpback->b_un.b_buf, bp[0]->b_un.b_buf, (size_t)lffragsz);
		for (cp = &(bp[0]->b_un.b_buf[lffragsz]);
		    cp < &(bp[0]->b_un.b_buf[sblock.fs_bsize]);
		    cp += DIRBLKSIZ)
			bcopy((char *)&emptydir, cp, sizeof (emptydir));
	} else {
		for (cp = bp[0]->b_un.b_buf;
		    cp < &(bp[0]->b_un.b_buf[sblock.fs_bsize]);
		    cp += DIRBLKSIZ)
			bcopy((char *)&emptydir, cp, sizeof (emptydir));
	}
	dirty(bp[0]);

	/*
	 * If we allocated the indirect block, zero it out. Otherwise
	 * read it in if we're using one.
	 */
	if (allocIndir) {
		bp[1] = getdatablk(newblk[1], sblock.fs_bsize);
		if (bp[1]->b_errs)
			goto bail;
		bzero(bp[1]->b_un.b_buf, sblock.fs_bsize);
		dirty(bp[1]);
	} else if (nxtibn >= 0) {
		/* Check that the indirect block pointer looks okay */
		if (dp->di_ib[0] == 0)
			goto bail;

		bp[1] = getdatablk(dp->di_ib[0], sblock.fs_bsize);
		if (bp[1]->b_errs)
			goto bail;

		for (bc = 0; ((bc < nxtibn) && (bc < n)); bc++) {
			if (((daddr32_t *)bp[1]->b_un.b_buf)[bc] == 0)
				goto bail;
		}
	}

	pwarn("NO SPACE LEFT IN %s", name);
	if (preen)
		printf(" (EXPANDED)\n");
	else if (reply("EXPAND") == 0)
		goto bail;

	/*
	 * Now that everything we need is gathered up, we
	 * do the final assignments
	 */

	if (lffragsz) {
		frag2blks = roundup(lffragsz, sblock.fs_fsize);
		freeblk(dp->di_db[nxtbn - 1],
		    frag2blks / sblock.fs_fsize);
		frag2blks = btodb(frag2blks);
		dp->di_size -= (u_offset_t)lffragsz;
		dp->di_blocks = dp->di_blocks - frag2blks;
		dp->di_db[nxtbn - 1] = newblk[0];
		dp->di_size += (u_offset_t)sblock.fs_bsize;
		dp->di_blocks += btodb(sblock.fs_bsize);
		inodirty();
		return (1);
	}

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
		((daddr32_t *)bp[1]->b_un.b_buf)[nxtibn] = newblk[0];
		dirty(bp[1]);
	}
	return (1);

bail:
	for (f = 0; f < c; f++)
		freeblk(newblk[f], sblock.fs_frag);
	return (0);
}

/*
 * allocate a new directory
 */
allocdir(parent, request, mode)
	ino_t parent, request;
	int mode;
{
	ino_t ino;
	char *cp;
	struct dinode *dp;
	struct inoinfo *inp;
	struct bufarea *bp;

	ino = allocino(request, IFDIR|mode);
	if (ino == 0)
		return (0);
	dirhead.dot_ino = ino;
	dirhead.dotdot_ino = parent;
	dp = ginode(ino);
	bp = getdirblk(dp->di_db[0], sblock.fs_fsize);
	if (bp->b_errs) {
		freeino(ino);
		return (0);
	}
	bcopy((char *)&dirhead, bp->b_un.b_buf, sizeof (dirhead));
	for (cp = &bp->b_un.b_buf[DIRBLKSIZ];
	    cp < &bp->b_un.b_buf[sblock.fs_fsize];
	    cp += DIRBLKSIZ)
		bcopy((char *)&emptydir, cp, sizeof (emptydir));
	dirty(bp);
	dp->di_nlink = 2;
	inodirty();
	if (!inocached(ino)) {
		if (debug)
			printf("inode %d added to directory cache\n",
			    ino);
		cacheino(dp, ino);
	} else {
		/*
		 * re-using an old directory inode
		 */
		inp = getinoinfo(ino);
		inp->i_isize = (offset_t)dp->di_size;
		inp->i_numblks = dp->di_blocks * sizeof (daddr32_t);
		inp->i_parent = parent;
		bcopy((char *)&dp->di_db[0], (char *)&inp->i_blks[0],
		    (size_t)inp->i_numblks);
	}
	if (ino == UFSROOTINO) {
		lncntp[ino] = dp->di_nlink;
		return (ino);
	}
	if (statemap[parent] != DSTATE && statemap[parent] != DFOUND) {
		freeino(ino);
		return (0);
	}
	statemap[ino] = statemap[parent];
	if (statemap[ino] == DSTATE) {
		lncntp[ino] = dp->di_nlink;
		lncntp[parent]++;
	}
	dp = ginode(parent);
	dp->di_nlink++;
	inodirty();
	return (ino);
}

/*
 * free a directory inode
 */
freedir(ino, parent)
	ino_t ino, parent;
{
	struct dinode *dp;

	if (ino != parent) {
		dp = ginode(parent);
		dp->di_nlink--;
		inodirty();
	}
	freeino(ino);
}

/*
 * generate a temporary name for the lost+found directory.
 */
lftempname(bufp, ino)
	char *bufp;
	ino_t ino;
{
	ino_t in;
	char *cp;
	int namlen;

	cp = bufp + 2;
	for (in = maxino; in > 0; in /= 10)
		cp++;
	*--cp = 0;
	namlen = cp - bufp;
	in = ino;
	while (cp > bufp) {
		*--cp = (in % 10) + '0';
		in /= 10;
	}
	*cp = '#';
	return (namlen);
}

/*
 * Get a directory block.
 * Insure that it is held until another is requested.
 */
struct bufarea *
getdirblk(blkno, size)
	daddr32_t blkno;
	int size;
{
	if (pdirbp != 0) {
		brelse(pdirbp);
	}
	pdirbp = getdatablk(blkno, size);
	return (pdirbp);
}
