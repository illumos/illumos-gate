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
#include <sys/param.h>
#include <sys/types.h>
#include <sys/mntent.h>
#include <sys/filio.h>

#define	bcopy(f, t, n)    memcpy(t, f, n)
#define	bzero(s, n)	memset(s, 0, n)
#define	bcmp(s, d, n)	memcmp(s, d, n)

#define	index(s, r)	strchr(s, r)
#define	rindex(s, r)	strrchr(s, r)

#include <sys/fs/ufs_fs.h>
#include <sys/vnode.h>
#include <sys/fs/ufs_inode.h>
#include <sys/fs/ufs_acl.h>
#define	_KERNEL
#include <sys/fs/ufs_fsdir.h>
#undef _KERNEL
#include <sys/mnttab.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/signal.h>
#include <string.h>
#include <ctype.h>
#include "fsck.h"
#include <sys/vfstab.h>
#include <sys/lockfs.h>
#include <errno.h>

int64_t	diskreads, totalreads;	/* Disk cache statistics */
offset_t	llseek();
char	*malloc();
char	*mount_point = NULL;

extern int	mflag;
extern uint_t largefile_count;

static struct bufarea *alloc_bufarea();

ftypeok(dp)
	struct dinode *dp;
{
	switch (dp->di_mode & IFMT) {

	case IFDIR:
	case IFREG:
	case IFBLK:
	case IFCHR:
	case IFLNK:
	case IFSOCK:
	case IFIFO:
	case IFSHAD:
	case IFATTRDIR:
		return (1);

	default:
		if (debug)
			printf("bad file type 0%o\n", dp->di_mode);
		return (0);
	}
}

acltypeok(dp)
	struct dinode *dp;
{
	if (CHECK_ACL_ALLOWED(dp->di_mode & IFMT))
		return (1);

	if (debug)
		printf("bad file type for acl 0%o\n", dp->di_mode);
	return (0);
}

reply(question)
	char *question;
{
	char line[80];

	if (preen)
		pfatal("INTERNAL ERROR: GOT TO reply()");

	if (mflag) {
		printf("\n");
		printf("%s: UNEXPECTED INCONSISTENCY; RUN fsck MANUALLY.\n",
			devname);
		exit(39);
	}

	printf("\n%s? ", question);
	if (nflag || fswritefd < 0) {
		printf(" no\n\n");
		iscorrupt = 1;		/* known to be corrupt */
		return (0);
	}
	if (yflag) {
		printf(" yes\n\n");
		return (1);
	}
	if (getline(stdin, line, sizeof (line)) == EOF)
		errexit("\n");
	printf("\n");
	if (line[0] == 'y' || line[0] == 'Y')
		return (1);
	else {
		iscorrupt = 1;		/* known to be corrupt */
		return (0);
	}
}

getline(fp, loc, maxlen)
	FILE *fp;
	char *loc;
{
	int n;
	char *p, *lastloc;

	p = loc;
	lastloc = &p[maxlen-1];
	while ((n = getc(fp)) != '\n') {
		if (n == EOF)
			return (EOF);
		if (!isspace(n) && p < lastloc)
			*p++ = n;
	}
	*p = 0;
	return (p - loc);
}
/*
 * Malloc buffers and set up cache.
 */
bufinit()
{
	struct bufarea *bp;
	int bufcnt, i;
	char *bufp;

	bufp = malloc((unsigned int)sblock.fs_bsize);
	if (bufp == 0)
		errexit("cannot allocate buffer pool\n");
	cgblk.b_un.b_buf = bufp;
	initbarea(&cgblk);
	bufhead.b_next = bufhead.b_prev = &bufhead;
	bufcnt = MAXBUFSPACE / sblock.fs_bsize;
	if (bufcnt < MINBUFS)
		bufcnt = MINBUFS;
	for (i = 0; i < bufcnt; i++) {
		bp = (struct bufarea *)malloc(sizeof (struct bufarea));
		bufp = malloc((unsigned int)sblock.fs_bsize);
		if (bp == NULL || bufp == NULL) {
			if (bp)
				free((char *)bp);
			if (bufp)
				free(bufp);
			if (i >= MINBUFS)
				break;
			errexit("cannot allocate buffer pool\n");
		}
		bp->b_un.b_buf = bufp;
		bp->b_prev = &bufhead;
		bp->b_next = bufhead.b_next;
		bufhead.b_next->b_prev = bp;
		bufhead.b_next = bp;
		initbarea(bp);
	}
	bufhead.b_size = i;	/* save number of buffers */
	pbp = pdirbp = NULL;
}

/*
 * Manage a cache of directory blocks.
 */
struct bufarea *
getdatablk(blkno, size)
	daddr32_t blkno;
	int size;
{
	struct bufarea *bp;

	for (bp = bufhead.b_next; bp != &bufhead; bp = bp->b_next)
		if (bp->b_bno == fsbtodb(&sblock, blkno))
			goto foundit;
	for (bp = bufhead.b_prev; bp != &bufhead; bp = bp->b_prev)
		if ((bp->b_flags & B_INUSE) == 0)
			break;
	if (bp == &bufhead) {
		bp = alloc_bufarea();
		if (bp == NULL)
			errexit("deadlocked buffer pool\n");
	}
	getblk(bp, blkno, size);
	/* fall through */
foundit:
	totalreads++;
	bp->b_cnt++;
	/*
	 * Move the buffer to head of link-list if it isn't
	 * already there.
	 */
	if (bufhead.b_next != bp) {
		bp->b_prev->b_next = bp->b_next;
		bp->b_next->b_prev = bp->b_prev;
		bp->b_prev = &bufhead;
		bp->b_next = bufhead.b_next;
		bufhead.b_next->b_prev = bp;
		bufhead.b_next = bp;
	}
	bp->b_flags |= B_INUSE;
	return (bp);
}

int
brelse(struct bufarea *bp)
{
	bp->b_cnt--;
	if (bp->b_cnt == 0) {
		bp->b_flags &= ~B_INUSE;
	}
}

struct bufarea *
getblk(bp, blk, size)
	struct bufarea *bp;
	daddr32_t blk;
	int size;
{
	diskaddr_t dblk;

	dblk = fsbtodb(&sblock, blk);
	if (bp->b_bno == dblk)
		return (bp);
	flush(fswritefd, bp);
	diskreads++;
	bp->b_errs = bread(fsreadfd, bp->b_un.b_buf, dblk, (long)size);
	bp->b_bno = dblk;
	bp->b_size = size;
	return (bp);
}

flush(fd, bp)
	int fd;
	struct bufarea *bp;
{
	int i, j;
	caddr_t sip;
	long size;

	if (!bp->b_dirty)
		return;
	if (bp->b_errs != 0)
		pfatal("WRITING ZERO'ED BLOCK %lld TO DISK\n", bp->b_bno);
	bp->b_dirty = 0;
	bp->b_errs = 0;
	bwrite(fd, bp->b_un.b_buf, bp->b_bno, (long)bp->b_size);
	if (bp != &sblk)
		return;
	sip = (caddr_t)sblock.fs_u.fs_csp;
	for (i = 0, j = 0; i < sblock.fs_cssize; i += sblock.fs_bsize, j++) {
		size = sblock.fs_cssize - i < sblock.fs_bsize ?
		    sblock.fs_cssize - i : sblock.fs_bsize;
		bwrite(fswritefd, sip,
		    fsbtodb(&sblock, sblock.fs_csaddr + j * sblock.fs_frag),
		    size);
		sip += size;
	}
}

rwerror(mesg, blk)
	char *mesg;
	diskaddr_t blk;
{

	if (preen == 0)
		printf("\n");
	pfatal("CANNOT %s: BLK %lld", mesg, blk);
	if (reply("CONTINUE") == 0)
		errexit("Program terminated\n");
}

ckfini()
{
	struct bufarea *bp, *nbp;
	int cnt = 0;

	/*
	 * Mark the filesystem bad if a re-check is required.
	 */
	if (dirholes && havesb) {
		sblock.fs_clean = FSBAD;
		sblock.fs_state = -(FSOKAY - (long)sblock.fs_time);
		sbdirty();
	}
	flush(fswritefd, &sblk);
	if (havesb && sblk.b_bno != SBOFF / dev_bsize) {
		sblk.b_bno = SBOFF / dev_bsize;
		sbdirty();
		flush(fswritefd, &sblk);
	}
	flush(fswritefd, &cgblk);
	if (cgblk.b_un.b_buf) {
		free(cgblk.b_un.b_buf);
		cgblk.b_un.b_buf = NULL;
	}
	for (bp = bufhead.b_prev; bp && bp != &bufhead; bp = nbp) {
		cnt++;
		flush(fswritefd, bp);
		nbp = bp->b_prev;
		free(bp->b_un.b_buf);
		free((char *)bp);
	}
	pbp = pdirbp = NULL;
	if (bufhead.b_size != cnt)
		errexit("Panic: lost %d buffers\n", bufhead.b_size - cnt);
	if (debug)
		printf("cache missed %d of %d (%d%%)\n",
		    diskreads, totalreads,
		    totalreads ? diskreads * 100 / totalreads : 0);
	(void) close(fsreadfd);
	(void) close(fswritefd);
}

bread(fd, buf, blk, size)
	int fd;
	char *buf;
	diskaddr_t blk;
	long size;
{
	char *cp;
	int	i;
	int errs;
	offset_t offset = ldbtob(blk);
	offset_t addr;

	if (debug && (blk < SBLOCK)) {
		char msg[256];
		sprintf(msg, "WARNING: fsck bread() passed blkno < %d (%ld)\n",
		    SBLOCK, blk);
		printf(msg);
	}
	if (llseek(fd, offset, 0) < 0) {
		rwerror("SEEK", blk);
	} else if (read(fd, buf, (int)size) == size)
		return (0);
	rwerror("READ", blk);
	if (llseek(fd, offset, 0) < 0) {
		rwerror("SEEK", blk);
	}
	errs = 0;
	bzero(buf, (size_t)size);
	pwarn("THE FOLLOWING SECTORS COULD NOT BE READ:");
	for (cp = buf, i = 0; i < btodb(size); i++, cp += DEV_BSIZE) {
		addr = ldbtob(blk + i);
		if (llseek(fd, addr, SEEK_CUR) < 0 ||
		    read(fd, cp, (int)secsize) < 0) {
			printf(" %d", blk + i);
			errs++;
		}
	}
	printf("\n");
	return (errs);
}

bwrite(fd, buf, blk, size)
	int fd;
	char *buf;
	diskaddr_t blk;
	long size;
{
	int	i;
	int n;
	char *cp;
	offset_t offset = ldbtob(blk);
	offset_t addr;

	if (fd < 0)
		return;
	if (blk < SBLOCK) {
		char msg[256];
		sprintf(msg,
		    "WARNING: Attempt to write illegal blkno %lld on %s\n",
		    blk, devname);
		if (debug)
			printf(msg);
		return;
	}
	if (llseek(fd, offset, 0) < 0) {
		rwerror("SEEK", blk);
	} else if (write(fd, buf, (int)size) == size) {
		fsmodified = 1;
		return;
	}
	rwerror("WRITE", blk);
	if (llseek(fd, offset, 0) < 0) {
		rwerror("SEEK", blk);
	}
	pwarn("THE FOLLOWING SECTORS COULD NOT BE WRITTEN:");
	for (cp = buf, i = 0; i < btodb(size); i++, cp += DEV_BSIZE) {
		n = 0;
		addr = ldbtob(blk + i);
		if (llseek(fd, addr, SEEK_CUR) < 0 ||
		    (n = write(fd, cp, DEV_BSIZE)) < 0) {
			printf(" %d", blk + i);
		} else if (n > 0) {
			fsmodified = 1;
		}

	}
	printf("\n");
}

/*
 * allocate a data block with the specified number of fragments
 */
daddr32_t
allocblk(frags)
	int frags;
{
	int i, j, k;

	if (frags <= 0 || frags > sblock.fs_frag)
		return (0);
	for (i = 0; i < maxfsblock - sblock.fs_frag; i += sblock.fs_frag) {
		for (j = 0; j <= sblock.fs_frag - frags; j++) {
			if (testbmap(i + j))
				continue;
			for (k = 1; k < frags; k++)
				if (testbmap(i + j + k))
					break;
			if (k < frags) {
				j += k;
				continue;
			}
			for (k = 0; k < frags; k++)
				setbmap(i + j + k);
			n_blks += frags;
			return (i + j);
		}
	}
	return (0);
}

/*
 * Free a previously allocated block
 */
freeblk(blkno, frags)
	daddr32_t blkno;
	int frags;
{
	struct inodesc idesc;

	idesc.id_blkno = blkno;
	idesc.id_numfrags = frags;
	pass4check(&idesc);
}

/*
 * Find a pathname
 */
getpathname(namebuf, curdir, ino)
	char *namebuf;
	ino_t curdir, ino;
{
	int len;
	char *cp;
	struct inodesc idesc;
	struct inoinfo *inp;
	extern int findname();

	if (statemap[curdir] != DSTATE && statemap[curdir] != DFOUND) {
		strcpy(namebuf, "?");
		return;
	}
	bzero((char *)&idesc, sizeof (struct inodesc));
	idesc.id_type = DATA;
	cp = &namebuf[MAXPATHLEN - 1];
	*cp = '\0';
	if (curdir != ino) {
		idesc.id_parent = curdir;
		goto namelookup;
	}
	while (ino != UFSROOTINO) {
		idesc.id_number = ino;
		idesc.id_func = findino;
		idesc.id_name = "..";
		idesc.id_fix = NOFIX;
		if ((ckinode(ginode(ino), &idesc) & FOUND) == 0) {
			inp = getinoinfo(ino);
			if (inp->i_parent == 0)
				break;
			idesc.id_parent = inp->i_parent;
		}
	namelookup:
		idesc.id_number = idesc.id_parent;
		idesc.id_parent = ino;
		idesc.id_func = findname;
		idesc.id_name = namebuf;
		idesc.id_fix = NOFIX;
		if ((ckinode(ginode(idesc.id_number), &idesc)&FOUND) == 0)
			break;
		len = strlen(namebuf);
		cp -= len;
		if (cp < &namebuf[MAXNAMLEN])
			break;
		bcopy(namebuf, cp, len);
		*--cp = '/';
		ino = idesc.id_number;
	}
	if (ino != UFSROOTINO) {
		strcpy(namebuf, "?");
		return;
	}
	bcopy(cp, namebuf, &namebuf[MAXPATHLEN] - cp);
}

void
catch()
{
	ckfini();
	exit(37);
}

/*
 * When preening, allow a single quit to signal
 * a special exit after filesystem checks complete
 * so that reboot sequence may be interrupted.
 */
void
catchquit()
{
	extern returntosingle;

	printf("returning to single-user after filesystem check\n");
	returntosingle = 1;
	(void) signal(SIGQUIT, SIG_DFL);
}

/*
 * Ignore a single quit signal; wait and flush just in case.
 * Used by child processes in preen.
 */
void
voidquit()
{

	sleep(1);
	(void) signal(SIGQUIT, SIG_IGN);
	(void) signal(SIGQUIT, SIG_DFL);
}

/*
 * determine whether an inode should be fixed.
 */
dofix(idesc, msg)
	struct inodesc *idesc;
	char *msg;
{

	switch (idesc->id_fix) {

	case DONTKNOW:
		if (idesc->id_type == DATA)
			direrror(idesc->id_number, msg);
		else
			pwarn(msg);
		if (preen) {
			printf(" (SALVAGED)\n");
			idesc->id_fix = FIX;
			return (ALTERED);
		}
		if (reply("SALVAGE") == 0) {
			idesc->id_fix = NOFIX;
			return (0);
		}
		idesc->id_fix = FIX;
		return (ALTERED);

	case FIX:
		return (ALTERED);

	case NOFIX:
		return (0);

	default:
		errexit("UNKNOWN INODESC FIX MODE %d\n", idesc->id_fix);
	}
	/* NOTREACHED */
}

/* VARARGS1 */
errexit(s1, s2, s3, s4)
	char *s1;
{
	extern void write_altsb(int);

	if (errorlocked) {
		if (havesb) {
			sblock.fs_clean = FSBAD;
			sblock.fs_state = -(FSOKAY - (long)sblock.fs_time);
			sbdirty();
			write_altsb(fswritefd);
			flush(fswritefd, &sblk);
		}
	}
	printf(s1, s2, s3, s4);
	exit(39);
}

/*
 * An unexpected inconsistency occured.
 * Die if preening, otherwise just print message and continue.
 */
/* VARARGS1 */
pfatal(s, a1, a2, a3)
	char *s;
{
	if (preen) {
		printf("%s: ", devname);
		printf(s, a1, a2, a3);
		printf("\n");
		printf("%s: UNEXPECTED INCONSISTENCY; RUN fsck MANUALLY.\n",
			devname);
		if (havesb) {
			sblock.fs_clean = FSBAD;
			sblock.fs_state = -(FSOKAY - (long)sblock.fs_time);
			sbdirty();
			flush(fswritefd, &sblk);
		}
		exit(36);
	}
	printf(s, a1, a2, a3);
}

/*
 * Pwarn just prints a message when not preening,
 * or a warning (preceded by filename) when preening.
 */
/* VARARGS1 */
pwarn(s, a1, a2, a3, a4, a5, a6)
	char *s;
{

	if (preen)
		printf("%s: ", devname);
	printf(s, a1, a2, a3, a4, a5, a6);
}

#ifndef lint
/*
 * Stub for routines from kernel.
 */
panic(s)
	char *s;
{

	pfatal("INTERNAL INCONSISTENCY:");
	errexit(s);
}
#define	CE_PANIC 3
void
cmn_err(level, s)
	int level;
	char *s;
{

	if (level == CE_PANIC) {
		pfatal("INTERNAL INCONSISTENCY:");
		errexit(s);
	}
	else
		printf(s);
}
#endif

/*
 * Check to see if unraw version of name is already mounted.
 * Since we do not believe /etc/mnttab, we stat the mount point
 * to see if it is really looks mounted.
 */
mounted(name)
	char *name;
{
	int found = 0;
	struct mnttab mnt;
	FILE *mnttab;
	struct stat64 device_stat, mount_stat;
	char *blkname, *unrawname();

	mnttab = fopen(MNTTAB, "r");
	if (mnttab == NULL) {
		return (0);
	}
	blkname = unrawname(name);
	while ((getmntent(mnttab, &mnt)) == NULL) {
		if (strcmp(mnt.mnt_fstype, MNTTYPE_UFS) != 0) {
			continue;
		}
		if (strcmp(blkname, mnt.mnt_special) == 0) {
			stat64(mnt.mnt_mountp, &mount_stat);
			stat64(mnt.mnt_special, &device_stat);
			if (device_stat.st_rdev == mount_stat.st_dev) {
				if (hasmntopt(&mnt, MNTOPT_RO) != 0)
					found = 2;	/* mounted as RO */
				else
					found = 1; 	/* mounted as R/W */
			}
			if (mount_point == NULL) {
				mount_point = strdup(mnt.mnt_mountp);
				if (mount_point == NULL) {
					printf("fsck: memory allocation"
					    " failure\n");
					exit(39);
				}
			}
			break;
		}
	}
	fclose(mnttab);
	return (found);
}

/*
 * Check to see if name corresponds to an entry in vfstab, and that the entry
 * does not have option ro.
 */
writable(name)
	char *name;
{
	int rw = 1;
	struct vfstab vfsbuf;
	FILE *vfstab;
	char *blkname, *unrawname();

	vfstab = fopen(VFSTAB, "r");
	if (vfstab == NULL) {
		printf("can't open %s\n", VFSTAB);
		return (1);
	}
	blkname = unrawname(name);
	if ((getvfsspec(vfstab, &vfsbuf, blkname) == 0) &&
	    (vfsbuf.vfs_fstype != NULL) &&
	    (strcmp(vfsbuf.vfs_fstype, MNTTYPE_UFS) == 0) &&
	    (hasvfsopt(&vfsbuf, MNTOPT_RO))) {
		rw = 0;
	}
	fclose(vfstab);
	return (rw);
}

/*
 * debugclean
 */
debugclean()
{
	char	s[256];

	if (debug == 0)
		return;

	if ((iscorrupt == 0) && (isdirty == 0))
		return;

	if ((sblock.fs_clean != FSSTABLE) && (sblock.fs_clean != FSCLEAN) &&
	    (sblock.fs_clean != FSLOG || !islog || !islogok))
		return;

	if (FSOKAY != (sblock.fs_state + sblock.fs_time) && !errorlocked)
		return;

	sprintf(s,
	    "WARNING: inconsistencies detected on `%s' filesystem %s",
	    sblock.fs_clean == FSSTABLE ? "stable" :
	    sblock.fs_clean == FSLOG ? "logging" :
	    sblock.fs_clean == FSFIX ? "being fixed" : "clean", devname);
	printf("%s\n", s);
}

/*
 * updateclean
 *	Carefully and transparently update the clean flag.
 */
updateclean()
{
	struct bufarea	cleanbuf;
	int	size;
	daddr32_t	bno;
	int	fsclean;
	int	fsreclaim;
	int	fsflags;
	int	r;
	daddr32_t	fslogbno;
	offset_t sblkoff;
	time_t t;

	/*
	 * debug stuff
	 */
	debugclean();

	/*
	 * set fsclean to its appropriate value
	 */
	fslogbno = sblock.fs_logbno;
	fsclean = sblock.fs_clean;
	fsreclaim = sblock.fs_reclaim;
	fsflags = sblock.fs_flags;
	if (FSOKAY != (sblock.fs_state + sblock.fs_time) && !errorlocked)
		fsclean = FSACTIVE;

	/* if ufs log is not okay, clear it */
	if (fslogbno && !(islog && islogok)) {
		fsclean = FSACTIVE;
		fslogbno = 0;
	}

	/*
	 * if necessary, update fs_clean and fs_state
	 */
	switch (fsclean) {

	case FSACTIVE:
		if (!iscorrupt) {
			fsclean = FSSTABLE;
			fsreclaim = 0;
		}
		break;

	case FSCLEAN:
	case FSSTABLE:
		if (iscorrupt)
			fsclean = FSACTIVE;
		else
			fsreclaim = 0;
		break;

	case FSLOG:
		if (iscorrupt)
			fsclean = FSACTIVE;
		else if (!islog) {
			fsreclaim = 0;
			fsclean = FSSTABLE;
		} else if (fflag)
			fsreclaim = 0;
		break;

	case FSFIX:
		fsreclaim = needs_reclaim;
		fsclean = FSBAD;
		if (errorlocked && !iscorrupt) {
			fsclean = islog? FSLOG: FSCLEAN;
		}
		break;

	default:
		if (iscorrupt)
			fsclean = FSACTIVE;
		else {
			fsclean = FSSTABLE;
			fsreclaim = 0;
		}
	}

	if (largefile_count > 0)
		fsflags |= FSLARGEFILES;
	else
		fsflags &= ~FSLARGEFILES;

	/*
	 * fs is unchanged, do nothing
	 */
	if (debug)
		printf("** largefile count=%d, fs.fs_flags=%x\n",
		    largefile_count, sblock.fs_flags);

	if ((!isdirty) && (fsflags == sblock.fs_flags) &&
	    (fslogbno == sblock.fs_logbno) &&
	    (sblock.fs_clean == fsclean) && (sblock.fs_reclaim == fsreclaim) &&
	    (FSOKAY == (sblock.fs_state + sblock.fs_time))) {
		if (islog && !islogok)
			(void) ioctl(fswritefd, _FIOLOGRESET, NULL);

		if (errorlocked) {
			if (!do_errorlock(LOCKFS_ULOCK))
				pwarn(
		    "updateclean(unchanged): unlock(LOCKFS_ULOCK) failed\n");
		}
		return;
	}

	/*
	 * if user allows, update superblock state
	 */
	if (!isdirty && !preen &&
	    (reply("FILE SYSTEM STATE IN SUPERBLOCK IS WRONG; FIX") == 0))
		return;

	(void) time(&t);
	sblock.fs_time = (time32_t)t;
	if (debug)
		printclean();
	sblock.fs_logbno = fslogbno;
	sblock.fs_clean = fsclean;
	sblock.fs_state = FSOKAY - (long)sblock.fs_time;
	sblock.fs_reclaim = fsreclaim;
	sblock.fs_flags = fsflags;

	/*
	 * if superblock can't be written, return
	 */
	if (fswritefd < 0)
		return;

	/*
	 * read private copy of superblock, update clean flag, and write it
	 */
	bno  = sblk.b_bno;
	size = sblk.b_size;

	sblkoff = ldbtob(bno);

	if ((cleanbuf.b_un.b_buf = malloc(size)) == NULL)
		errexit("out of memory");

	if (llseek(fsreadfd, sblkoff, 0) == -1)
		return;
	if (read(fsreadfd, cleanbuf.b_un.b_buf, (int)size) != size)
		return;

	cleanbuf.b_un.b_fs->fs_logbno  = sblock.fs_logbno;
	cleanbuf.b_un.b_fs->fs_clean   = sblock.fs_clean;
	cleanbuf.b_un.b_fs->fs_state   = sblock.fs_state;
	cleanbuf.b_un.b_fs->fs_time    = sblock.fs_time;
	cleanbuf.b_un.b_fs->fs_reclaim = sblock.fs_reclaim;
	cleanbuf.b_un.b_fs->fs_flags   = sblock.fs_flags;

	if (llseek(fswritefd, sblkoff, 0) == -1)
		return;
	if (write(fswritefd, cleanbuf.b_un.b_buf, (int)size) != size)
		return;

	/*
	 * 1208040
	 * If we had to use -b to grab an alternate superblock, then we
	 * likely had to do so because of unacceptable differences between
	 * the main and alternate superblocks.  SO, we had better update
	 * the alternate superblock as well, or we'll just fail again
	 * the next time we attempt to run fsck!
	 */
	if (bflag) {
		extern struct bufarea asblk;

		if (llseek(fswritefd, ldbtob(asblk.b_bno), 0) == -1)
			return;
		if (write(fswritefd, cleanbuf.b_un.b_buf, (int)size) != size)
			return;
	}

	if (islog && !islogok)
		(void) ioctl(fswritefd, _FIOLOGRESET, NULL);

	if (errorlocked) {
		if (!do_errorlock(LOCKFS_ULOCK))
			pwarn(
		    "updateclean(changed): unlock(LOCKFS_ULOCK) failed\n");
	}
}

/*
 * print out clean info
 */
printclean()
{
	char	*s;

	if (FSOKAY != (sblock.fs_state + sblock.fs_time) && !errorlocked)
		s = "unknown";
	else
		switch (sblock.fs_clean) {

		case FSACTIVE:
			s = "active";
			break;

		case FSCLEAN:
			s = "clean";
			break;

		case FSSTABLE:
			s = "stable";
			break;

		case FSLOG:
			s = "logging";
			break;

		case FSBAD:
			s = "is bad";
			break;

		case FSFIX:
			s = "being fixed";
			break;

		default:
			s = "unknown";
		}

	if (preen)
		pwarn("is %s.\n", s);
	else
		printf("** %s is %s.\n", devname, s);
}

/* see if all numbers */
numbers(yp)
	char	*yp;
{
	if (yp == NULL)
		return (0);
	while ('0' <= *yp && *yp <= '9')
		yp++;
	if (*yp)
		return (0);
	return (1);
}

is_errorlocked(char *fs)
{
	struct stat64	 statb;
	char 		*mountp;
	static char	*getmountp(char *);
	char		*unrawname(char *);

	mountp = NULL;

	if (!fs)
		return (0);

	if (stat64(fs, &statb) < 0)
		return (0);

	if (S_ISDIR(statb.st_mode)) {
		mountp = fs;

	} else if (S_ISBLK(statb.st_mode) || S_ISCHR(statb.st_mode)) {
		mountp = getmountp(S_ISCHR(statb.st_mode)? unrawname(fs): fs);
		if (!mountp) {
			return (0);
		}
	} else {
		return (0);
	}

	if (elock_combuf == NULL) {
		elock_combuf =
			(char *)calloc(LOCKFS_MAXCOMMENTLEN, sizeof (char));
	} else {
		elock_combuf =
			(char *)realloc(elock_combuf, LOCKFS_MAXCOMMENTLEN);
	}

	if (elock_combuf == NULL)
		return (0);

	bzero((caddr_t)elock_combuf, LOCKFS_MAXCOMMENTLEN);

	elock_mountp = strdup(mountp);

	if (mountfd < 0) {
		if ((mountfd = open64(mountp, O_RDONLY)) == -1)
			return (0);
	}

	if (!lfp) {
		lfp = (struct lockfs *)malloc(sizeof (struct lockfs));
		if (!lfp)
			return (0);
		bzero((caddr_t)lfp, sizeof (struct lockfs));
	}

	lfp->lf_comlen = LOCKFS_MAXCOMMENTLEN;
	lfp->lf_comment = elock_combuf;

	if (ioctl(mountfd, _FIOLFSS, lfp) == -1)
		return (0);

	return (LOCKFS_IS_ELOCK(lfp));
}

static char *
getmountp(char *dev) {
	FILE		*vfstab;
	struct vfstab	 vfsbuf;
	char		*mountp;
	int		 rc;

	mountp = NULL;
	if ((vfstab = fopen(VFSTAB, "r")) == NULL) {
		return (NULL);
	}
	if ((rc = getvfsspec(vfstab, &vfsbuf, dev)) == 0) {
		if (!(mountp = malloc(MAXPATHLEN)) ||
		    vfsbuf.vfs_mountp == NULL)
			return (NULL);
		strcpy(mountp, vfsbuf.vfs_mountp);
	} else if (rc == -1) {
		return (NULL);
	}
	fclose(vfstab);
	return (mountp);
}

do_errorlock(int lock_type)
{
	char		*buf;
	time_t		 now;
	struct tm	*local;
	int		 rc = 0;

	if (!elock_combuf)
		errexit("do_errorlock(%s, %d): unallocated elock_combuf\n",
			elock_mountp? elock_mountp: "<null>", lock_type);

	if (!(buf = (char *)calloc(LOCKFS_MAXCOMMENTLEN, sizeof (char))))
		errexit("Couldn't alloc memory for temp. lock status buffer\n");

	if (!lfp) {
		errexit("do_errorlock(%s, %d): lockfs status unallocated\n",
					elock_mountp, lock_type);
	}

	bcopy(elock_combuf, buf, LOCKFS_MAXCOMMENTLEN-1);

	switch (lock_type) {
	case LOCKFS_ELOCK:
		if (time(&now) != (time_t)-1) {
			if ((local = localtime(&now)) != NULL)
				sprintf(buf,
		    "%s [pid:%d fsck start:%02d/%02d/%02d %02d:%02d:%02d",
				    elock_combuf, pid,
				    local->tm_mon+1, local->tm_mday,
				    (local->tm_year % 100), local->tm_hour,
				    local->tm_min, local->tm_sec);
			else
				sprintf(buf, "%s [fsck pid %d",
							    elock_combuf, pid);

		} else {
			sprintf(buf, "%s [fsck pid %d", elock_combuf, pid);
		}
		break;

	case LOCKFS_ULOCK:
		if (time(&now) != (time_t)-1) {
			if ((local = localtime(&now)) != NULL) {
				sprintf(buf,
				    "%s, done:%02d/%02d/%02d %02d:%02d:%02d]",
				    elock_combuf,
				    local->tm_mon+1, local->tm_mday,
				    (local->tm_year % 100), local->tm_hour,
				    local->tm_min, local->tm_sec);
			} else {
				sprintf(buf, "%s]", elock_combuf);
			}
		} else {
			sprintf(buf, "%s]", elock_combuf);
		}
		if ((rc = ioctl(mountfd, _FIOLFSS, lfp)) == -1) {
			goto out;
		}
		break;

	default:
		break;
	}

	bcopy(buf, elock_combuf, LOCKFS_MAXCOMMENTLEN-1);

	lfp->lf_lock	= lock_type;
	lfp->lf_comlen	= LOCKFS_MAXCOMMENTLEN;
	lfp->lf_comment	= elock_combuf;
	lfp->lf_flags	= 0;
	errno		= 0;

	if ((rc = ioctl(mountfd, _FIOLFS, lfp)) == -1) {
		if (errno == EINVAL) {
			pwarn("Another fsck active?\n");
			iscorrupt = 0;	/* don't go away mad, just go away */
		} else {
			pwarn(
			"do_errorlock(lock_type:%d, %s) failed: errno:%d\n",
						lock_type, elock_combuf, errno);
		}
	}
out:
	if (buf)
		free(buf);

	return (rc != -1);
}

/*
 * Shadow inode support.  To `register' a shadow with a client is to note
 * that an inode (the `client') refers to the shadow.  See fsck.h for more
 * on how the shadowclientinfo and shadowclients structures are used.
 */

static struct shadowclients *
newshadowclient(struct shadowclients *prev)
{
	struct shadowclients *rc;

	rc = (struct shadowclients *)malloc(sizeof (*rc));
	if (rc == NULL)
		errexit("newshadowclient: cannot malloc (1)");

	rc->next = prev;
	rc->nclients = 0;

	rc->client = (ino_t *)
	    malloc(sizeof (ino_t) * maxshadowclients);
	if (rc->client == NULL)
		errexit("newshadowclient: cannot malloc (2)");

	return (rc);
}

void
registershadowclient(ino_t shadow, ino_t client, struct shadowclientinfo **info)
{
	struct shadowclientinfo *sci;
	struct shadowclients *scc;

	for (sci = *info; sci; sci = sci->next)
		if (sci->shadow == shadow)
			break;
	if (sci == NULL) {
		sci = (struct shadowclientinfo *)malloc(sizeof (*sci));
		if (sci == NULL)
			errexit("registershadowclient: cannot malloc");
		sci->next = *info;
		*info = sci;
		sci->shadow = shadow;
		sci->totalClients = 0;
		sci->clients = newshadowclient(NULL);
	}

	sci->totalClients++;
	scc = sci->clients;
	if (scc->nclients >= maxshadowclients) {
		scc = newshadowclient(sci->clients);
		sci->clients = scc;
	}

	scc->client[scc->nclients++] = client;
}

/*
 * Allocate more buffer as need arises but allocate one at a time.
 * This is done to make sure that fsck does not exit with error if it
 * needs more buffer to complete it's task.
 */
static struct bufarea *
alloc_bufarea()
{
	struct bufarea *bp;
	char *bufp;

	bp = (struct bufarea *)malloc(sizeof (struct bufarea));
	bufp = malloc((unsigned int)sblock.fs_bsize);
	if (bp == NULL || bufp == NULL) {
		if (bp)
			free((char *)bp);
		if (bufp)
			free(bufp);
		return (NULL);
	}
	bp->b_un.b_buf = bufp;
	bp->b_prev = &bufhead;
	bp->b_next = bufhead.b_next;
	bufhead.b_next->b_prev = bp;
	bufhead.b_next = bp;
	initbarea(bp);
	bufhead.b_size++;
	return (bp);
}
