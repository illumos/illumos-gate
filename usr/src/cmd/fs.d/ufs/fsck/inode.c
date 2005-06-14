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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/mntent.h>

#include <sys/vnode.h>
#include <sys/fs/ufs_inode.h>
#include <sys/fs/ufs_fs.h>
#include <sys/fs/ufs_fsdir.h>
#include <pwd.h>
#include "fsck.h"

static ino_t startinum = 0;

extern uint_t largefile_count;

ckinode(dp, idesc)
	struct dinode *dp;
	struct inodesc *idesc;
{
	daddr32_t *ap;
	int64_t offset;
	int	n, ndb;
	int	ret;
	struct dinode dino;
	u_offset_t indir_data_blks;

	idesc->id_entryno = 0;
	idesc->id_filesize = (offset_t)dp->di_size;
	if ((dp->di_mode & IFMT) == IFBLK || (dp->di_mode & IFMT) == IFCHR)
		return (KEEPON);
	dino = *dp;
	ndb = howmany(dino.di_size, (u_offset_t)sblock.fs_bsize);
	for (ap = &dino.di_db[0]; ap < &dino.di_db[NDADDR]; ap++) {
		if (--ndb == 0 &&
				(offset = blkoff(&sblock, dino.di_size)) != 0)
			idesc->id_numfrags =
			    numfrags(&sblock, fragroundup(&sblock, offset));
		else
			idesc->id_numfrags = sblock.fs_frag;
		if (*ap == 0)
			continue;
		idesc->id_blkno = *ap;
		if (idesc->id_type == ADDR || idesc->id_type == ACL)
			ret = (*idesc->id_func)(idesc);
		else
			ret = dirscan(idesc);
		if (ret & STOP)
			return (ret);
	}
	idesc->id_numfrags = sblock.fs_frag;

	/*
	 * indir_data_blks determine the no. of data blocks
	 * in the previous levels. ie., at level 3 it
	 * is the number of data blocks at level 2, 1, and 0.
	 */

	for (ap = &dino.di_ib[0], n = 1; n <= NIADDR; ap++, n++) {
		if (n == 1) {
			/* SINGLE */
			indir_data_blks = NDADDR;
		} else if (n == 2) {
			/* DOUBLE */
			indir_data_blks = NDADDR + NINDIR(&sblock);
		} else if (n == 3) {
			/* TRIPLE */
			indir_data_blks = NDADDR + NINDIR(&sblock) +
			    (NINDIR(&sblock) * NINDIR(&sblock));
		}
		if (*ap) {
			idesc->id_blkno = *ap;
			ret = iblock(idesc, n,
			    (u_offset_t)howmany(dino.di_size,
			    (u_offset_t)sblock.fs_bsize) - indir_data_blks);
			if (ret & STOP)
				return (ret);
		} else {
			idesc->id_hasholes = 1;
		}
	}
	return (KEEPON);
}

iblock(idesc, ilevel, iblks)
	struct inodesc *idesc;
	int ilevel;
	u_offset_t iblks;
{
	daddr32_t *ap;
	daddr32_t *aplim;
	int i, n, (*func)();
	u_offset_t fsbperindirb;
	offset_t nif;
	struct bufarea *bp;
	char buf[BUFSIZ];
	extern int dirscan(), pass1check(), pass3bcheck();

	if (idesc->id_type == ADDR) {
		func = idesc->id_func;
		if (((n = (*func)(idesc)) & KEEPON) == 0)
			return (n);
	} else if (idesc->id_type == ACL) {
		func = idesc->id_func;
		if (chkrange(idesc->id_blkno, idesc->id_numfrags))
			return (STOP);
	} else { /* DATA, ie a directory */
		func = dirscan;
		if (chkrange(idesc->id_blkno, idesc->id_numfrags))
			return (SKIP);
	}
	bp = getdatablk(idesc->id_blkno, sblock.fs_bsize);
	ilevel--;
	for (fsbperindirb = 1, i = 0; i < ilevel; i++) {
		fsbperindirb *= (u_offset_t)NINDIR(&sblock);
	}
	/*
	 * nif indicates the next "free" pointer (as an array index) in this
	 * indirect block, based on counting the blocks remaining in the
	 * file after subtracting all previously processed blocks.
	 * This figure is based on the size field of the inode.
	 *
	 * Note that in normal operation, nif may initially calculated to
	 * be larger than the number of pointers in this block; if that is
	 * the case, nif is limited to the max number of pointers per
	 * indirect block.
	 *
	 * Also note that if an inode is inconsistant (has more blocks
	 * allocated to it than the size field would indicate), the sweep
	 * through any indirect blocks directly pointed at by the inode
	 * continues. Since the block offset of any data blocks referenced
	 * by these indirect blocks is greater than the size of the file,
	 * the index nif may be computed as a negative value.
	 * In this case, we reset nif to indicate that all pointers in
	 * this retrieval block should be zeroed and the resulting
	 * unreferenced data and/or retrieval blocks be recovered
	 * through garbage collection later.
	 */
	nif = (offset_t)howmany(iblks, fsbperindirb);
	if (nif > NINDIR(&sblock))
		nif = NINDIR(&sblock);
	else if (nif < 0)
		nif = 0;
	/*
	 * first pass: all "free" retrieval pointers (from [nif] thru
	 * 	the end of the indirect block) should be zero. (This
	 *	assertion does not hold for directories, which may be
	 *	truncated without releasing their allocated space)
	 */
	if ((idesc->id_func == pass1check || idesc->id_func == pass3bcheck) &&
							nif < NINDIR(&sblock)) {
		aplim = &bp->b_un.b_indir[NINDIR(&sblock)];
		for (ap = &bp->b_un.b_indir[nif];
		    ap < aplim; ap++) {
			if (*ap == 0)
				continue;
			(void) sprintf(buf, "PARTIALLY TRUNCATED INODE I=%d",
				idesc->id_number);
			if (dofix(idesc, buf)) {
				*ap = 0;
				dirty(bp);
			}
		}
		flush(fswritefd, bp);
	}
	/*
	 * second pass: all retrieval pointers refering to blocks within
	 *	a valid range [0..filesize] (both indirect and data blocks)
	 *	are respectively examined the same manner as the direct blocks
	 *	in the inode are checked in chkinode().  Sweep through
	 *	the first pointer in this retrieval block to [nif-1].
	 */
	aplim = &bp->b_un.b_indir[nif];
	for (ap = bp->b_un.b_indir; ap < aplim; ap++) {
		if (*ap) {
			idesc->id_blkno = *ap;
			if (ilevel > 0) {
				n = iblock(idesc, ilevel, iblks);
				/*
				 * each iteration decrease "remaining block
				 * count" by however many blocks were accessible
				 * by a pointer at this indirect block level.
				 */
				iblks -= fsbperindirb;
			} else {
				if (!idesc->id_hasholes) {
					/*
					 * Increment logical block count here.
					 * In the case of direct blocks, it is
					 * done in pass1().
					 */
					idesc->id_llbna++;
				}
				n = (*func)(idesc);
			}
			if (n & STOP) {
				brelse(bp);
				return (n);
			}
		} else {
			idesc->id_hasholes = 1;
		}
	}
	brelse(bp);
	return (KEEPON);
}

/*
 * Check that a block is a legal block number.
 * Return 0 if in range, 1 if out of range.
 */
chkrange(blk, cnt)
	daddr32_t blk;
	int cnt;
{
	int c;

	if ((unsigned)(blk + cnt) > (unsigned)maxfsblock)
		return (1);
	c = dtog(&sblock, blk);
	if (blk < cgdmin(&sblock, c)) {
		if ((unsigned)(blk + cnt) > (unsigned)cgsblock(&sblock, c)) {
			if (debug) {
				printf("blk %d < cgdmin %d;",
				    blk, cgdmin(&sblock, c));
				printf(" blk + cnt %d > cgsbase %d\n",
				    blk + cnt, cgsblock(&sblock, c));
			}
			return (1);
		}
	} else {
		if ((unsigned)(blk + cnt) > (unsigned)cgbase(&sblock, c+1)) {
			if (debug)  {
				printf("blk %d >= cgdmin %d;",
				    blk, cgdmin(&sblock, c));
				printf(" blk + cnt %d > sblock.fs_fpg %d\n",
				    blk+cnt, sblock.fs_fpg);
			}
			return (1);
		}
	}
	return (0);
}

/*
 * General purpose interface for reading inodes.
 */
struct dinode *
ginode(inumber)
	ino_t inumber;
{
	daddr32_t iblk;
	struct dinode *dp;

	if (inumber < UFSROOTINO || inumber > maxino)
		errexit("bad inode number %d to ginode\n", inumber);
	if (startinum == 0 ||
	    inumber < startinum ||
	    inumber >= (ino_t)(startinum + (ino_t)INOPB(&sblock))) {
		iblk = itod(&sblock, inumber);
		if (pbp != 0) {
			brelse(pbp);
		}
		pbp = getdatablk(iblk, sblock.fs_bsize);
		startinum =
		    (ino_t)((inumber / INOPB(&sblock)) * INOPB(&sblock));
	}
	dp = &pbp->b_un.b_dinode[inumber % INOPB(&sblock)];
	dp->di_mode = dp->di_smode;
	if (dp->di_suid != UID_LONG) dp->di_uid = dp->di_suid;
	if (dp->di_sgid != GID_LONG) dp->di_gid = dp->di_sgid;
	return (dp);
}

/*
 * Special purpose version of ginode used to optimize first pass
 * over all the inodes in numerical order.
 */
ino_t nextino, lastinum;
int64_t readcnt, readpercg, fullcnt, inobufsize, partialcnt, partialsize;
struct dinode *inodebuf;

struct dinode *
getnextinode(inumber)
	ino_t inumber;
{
	int64_t size;
	diskaddr_t dblk;
	static struct dinode *dp;

	if (inumber != nextino++ || inumber > maxino)
		errexit("bad inode number %d to nextinode\n", inumber);
	if (inumber >= lastinum) {
		readcnt++;
		dblk = fsbtodb(&sblock, itod(&sblock, lastinum));
		if (readcnt % readpercg == 0) {
			size = partialsize;
			lastinum += partialcnt;
		} else {
			size = inobufsize;
			lastinum += fullcnt;
		}
		bread(fsreadfd, (char *)inodebuf, dblk, (long)size);
		dp = inodebuf;
	}
	return (dp++);
}

resetinodebuf()
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

freeinodebuf()
{

	if (inodebuf != NULL)
		free((char *)inodebuf);
	inodebuf = NULL;
}

/*
 * Routines to maintain information about directory inodes.
 * This is built during the first pass and used during the
 * second and third passes.
 *
 * Enter inodes into the cache.
 */
cacheino(dp, inumber)
	struct dinode *dp;
	ino_t inumber;
{
	struct inoinfo *inp;
	struct inoinfo **inpp;
	uint_t blks;

	blks = NDADDR + NIADDR;
	inp = (struct inoinfo *)
		malloc(sizeof (*inp) + (blks - 1) * sizeof (daddr32_t));
	if (inp == NULL)
		return;
	inpp = &inphead[inumber % numdirs];
	inp->i_nexthash = *inpp;
	*inpp = inp;
	inp->i_parent = (ino_t)0;
	inp->i_dotdot = (ino_t)0;
	inp->i_number = inumber;
	inp->i_isize = (offset_t)dp->di_size;
	inp->i_numblks = blks * sizeof (daddr32_t);
	inp->i_extattr = dp->di_oeftflag;
	memcpy(&inp->i_blks[0], &dp->di_db[0], inp->i_numblks);
	if (inplast == listmax) {
		listmax += 100;
		inpsort = (struct inoinfo **)realloc((char *)inpsort,
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
getinoinfo(inumber)
	ino_t inumber;
{
	struct inoinfo *inp;

	for (inp = inphead[inumber % numdirs]; inp; inp = inp->i_nexthash) {
		if (inp->i_number != inumber)
			continue;
		return (inp);
	}
	errexit("cannot find inode %d\n", inumber);
	return ((struct inoinfo *)0);
}

/*
 * Determine whether inode is in cache.
 */
inocached(inumber)
	ino_t inumber;
{
	struct inoinfo *inp;

	for (inp = inphead[inumber % numdirs]; inp; inp = inp->i_nexthash) {
		if (inp->i_number != inumber)
			continue;
		return (1);
	}
	return (0);
}

/*
 * Clean up all the inode cache structure.
 */
inocleanup()
{
	struct inoinfo **inpp;

	if (inphead == NULL)
		return;
	for (inpp = &inpsort[inplast - 1]; inpp >= inpsort; inpp--)
		free((char *)(*inpp));
	free((char *)inphead);
	free((char *)inpsort);
	inphead = inpsort = NULL;
}

/*
 * Routines to maintain information about acl inodes.
 * This is built during the first pass and used during the
 * second and third passes.
 *
 * Enter acl inodes into the cache.
 */
cacheacl(dp, inumber)
	struct dinode *dp;
	ino_t inumber;
{
	struct aclinfo *aclp;
	struct aclinfo **aclpp;
	uint_t blks;

	blks = NDADDR + NIADDR;
	aclp = (struct aclinfo *)
		malloc(sizeof (*aclp) + (blks - 1) * sizeof (daddr32_t));
	if (aclp == NULL)
		return;
	aclpp = &aclphead[inumber % numacls];
	aclp->i_nexthash = *aclpp;
	*aclpp = aclp;
	aclp->i_number = inumber;
	aclp->i_isize = (offset_t)dp->di_size;
	aclp->i_numblks = blks * sizeof (daddr32_t);
	memcpy(&aclp->i_blks[0], &dp->di_db[0], aclp->i_numblks);
	if (aclplast == aclmax) {
		aclmax += 100;
		aclpsort = (struct aclinfo **)realloc((char *)aclpsort,
		    (unsigned)aclmax * sizeof (struct aclinfo *));
		if (aclpsort == NULL)
			errexit("cannot increase acl list");
	}
	aclpsort[aclplast++] = aclp;
}

/*
 * Look up an acl inode cache structure.
 */
struct aclinfo *
getaclinfo(inum)
	ino_t inum;
{
	struct aclinfo *aclp;

	for (aclp = aclphead[inum % numacls]; aclp; aclp = aclp->i_nexthash) {
		if (aclp->i_number != inum)
			continue;
		return (aclp);
	}
	errexit("cannot find acl inode %d\n", inum);
	return ((struct aclinfo *)0);
}

/*
 * Determine whether acl inode is in cache.
 */
aclcached(inum)
	ino_t inum;
{
	struct aclinfo *aclp;

	for (aclp = aclphead[inum % numacls]; aclp; aclp = aclp->i_nexthash) {
		if (aclp->i_number != inum)
			continue;
		return (1);
	}
	return (0);
}

inodirty()
{

	dirty(pbp);
}

clri(idesc, type, flag)
	struct inodesc *idesc;
	char *type;
	int flag;
{
	struct dinode *dp;

	dp = ginode(idesc->id_number);
	if (flag == 1) {
		pwarn("%s %s", type,
		    (dp->di_mode & IFMT) == IFDIR ? "DIRECTORY" : "FILE");
		pinode(idesc->id_number);
	}
	if (preen || reply("CLEAR") == 1) {
		if (preen)
			printf(" (CLEARED)\n");
		n_files--;
		if (dp->di_size > (u_offset_t)MAXOFF_T) {
			largefile_count--;
			if (debug)
				printf("clearing file: size %d,count %d\n",
				    dp->di_size, largefile_count);
		}
		(void) ckinode(dp, idesc);
		clearinode(dp);
		statemap[idesc->id_number] = USTATE;
		inodirty();
	}
}

findname(idesc)
	struct inodesc *idesc;
{
	struct direct *dirp = idesc->id_dirp;

	if (dirp->d_ino != idesc->id_parent)
		return (KEEPON);
	memcpy(idesc->id_name, dirp->d_name,
	    MIN(dirp->d_namlen, MAXNAMLEN) + 1);
	return (STOP|FOUND);
}

findino(idesc)
	struct inodesc *idesc;
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

pinode(ino)
	ino_t ino;
{
	struct dinode *dp;
	char *p;
	struct passwd *pw;
	time_t t;

	printf(" I=%u ", ino);
	if (ino < UFSROOTINO || ino > maxino)
		return;
	dp = ginode(ino);
	printf(" OWNER=");
	if ((pw = getpwuid((int)dp->di_uid)) != 0)
		printf("%s ", pw->pw_name);
	else
		printf("%d ", dp->di_uid);
	printf("MODE=%o\n", dp->di_mode);
	if (preen)
		printf("%s: ", devname);
	printf("SIZE=%lld ", dp->di_size);
	t = (time_t)dp->di_mtime;
	p = ctime(&t);
	printf("MTIME=%12.12s %4.4s ", p + 4, p + 20);
}

blkerror(ino, type, blk)
	ino_t ino;
	char *type;
	daddr32_t blk;
{

	pfatal("%ld %s I=%u", blk, type, ino);
	printf("\n");
	switch (statemap[ino]) {

	case FSTATE:
		statemap[ino] = FCLEAR;
		return;

	case DSTATE:
		statemap[ino] = DCLEAR;
		return;

	case SSTATE:
		statemap[ino] = SCLEAR;
		return;

	case FCLEAR:
	case DCLEAR:
	case SCLEAR:
		return;

	default:
		errexit("BAD STATE %d TO BLKERR\n", statemap[ino]);
		/* NOTREACHED */
	}
}

/*
 * allocate an unused inode
 */
ino_t
allocino(request, type)
	ino_t request;
	int type;
{
	ino_t ino;
	struct dinode *dp;
	time_t t;

	if (request == 0)
		request = UFSROOTINO;
	else if (statemap[request] != USTATE)
		return (0);
	for (ino = request; ino < maxino; ino++)
		if (statemap[ino] == USTATE)
			break;
	if (ino == maxino)
		return (0);
	switch (type & IFMT) {
	case IFDIR:
		statemap[ino] = DSTATE;
		break;
	case IFREG:
	case IFLNK:
		statemap[ino] = FSTATE;
		break;
	default:
		return (0);
	}
	dp = ginode(ino);
	dp->di_db[0] = allocblk(1);
	if (dp->di_db[0] == 0) {
		statemap[ino] = USTATE;
		return (0);
	}
	dp->di_smode = dp->di_mode = type;
	time(&t);
	dp->di_atime = (time32_t)t;
	dp->di_mtime = dp->di_ctime = dp->di_atime;
	dp->di_size = (u_offset_t)sblock.fs_fsize;
	dp->di_blocks = btodb(sblock.fs_fsize);
	n_files++;
	inodirty();
	return (ino);
}

/*
 * deallocate an inode
 */
freeino(ino)
	ino_t ino;
{
	struct inodesc idesc;
	extern int pass4check();
	struct dinode *dp;

	memset(&idesc, 0, sizeof (struct inodesc));
	idesc.id_type = ADDR;
	idesc.id_func = pass4check;
	idesc.id_number = ino;
	idesc.id_fix = DONTKNOW;
	dp = ginode(ino);
	(void) ckinode(dp, &idesc);
	clearinode(dp);
	inodirty();
	statemap[ino] = USTATE;
	n_files--;
}
