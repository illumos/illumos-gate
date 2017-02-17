/*
 * Copyright (c) 1990, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2016 by Delphix. All rights reserved.
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <libadm.h>
#include <note.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/mntent.h>
#include <sys/filio.h>
#include <sys/fs/ufs_fs.h>
#include <sys/vnode.h>
#include <sys/fs/ufs_acl.h>
#include <sys/fs/ufs_inode.h>
#include <sys/fs/ufs_log.h>
#define	_KERNEL
#include <sys/fs/ufs_fsdir.h>
#undef _KERNEL
#include <sys/mnttab.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <ctype.h>
#include <sys/vfstab.h>
#include <sys/lockfs.h>
#include <errno.h>
#include <sys/cmn_err.h>
#include <sys/dkio.h>
#include <sys/vtoc.h>
#include <sys/efi_partition.h>
#include <fslib.h>
#include <inttypes.h>
#include "fsck.h"

caddr_t mount_point = NULL;

static int64_t diskreads, totalreads;	/* Disk cache statistics */

static int log_checksum(int32_t *, int32_t *, int);
static void vdirerror(fsck_ino_t, caddr_t, va_list);
static struct mnttab *search_mnttab(caddr_t, caddr_t, caddr_t, size_t);
static struct vfstab *search_vfstab(caddr_t, caddr_t, caddr_t, size_t);
static void vpwarn(caddr_t, va_list);
static int getaline(FILE *, caddr_t, int);
static struct bufarea *alloc_bufarea(void);
static void rwerror(caddr_t, diskaddr_t, int rval);
static void debugclean(void);
static void report_io_prob(caddr_t, diskaddr_t, size_t, ssize_t);
static void freelogblk(daddr32_t);
static void verrexit(caddr_t, va_list);
static void vpfatal(caddr_t, va_list);
static diskaddr_t get_device_size(int, caddr_t);
static diskaddr_t brute_force_get_device_size(int);
static void cg_constants(int, daddr32_t *, daddr32_t *, daddr32_t *,
	    daddr32_t *, daddr32_t *, daddr32_t *);

int
ftypeok(struct dinode *dp)
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
			(void) printf("bad file type 0%o\n", dp->di_mode);
		return (0);
	}
}

int
acltypeok(struct dinode *dp)
{
	if (CHECK_ACL_ALLOWED(dp->di_mode & IFMT))
		return (1);

	if (debug)
		(void) printf("bad file type for acl I=%d: 0%o\n",
		    dp->di_shadow, dp->di_mode);
	return (0);
}

NOTE(PRINTFLIKE(1))
int
reply(caddr_t fmt, ...)
{
	va_list ap;
	char line[80];

	if (preen)
		pfatal("INTERNAL ERROR: GOT TO reply() in preen mode");

	if (mflag) {
		/*
		 * We don't know what's going on, so don't potentially
		 * make things worse by having errexit() write stuff
		 * out to disk.
		 */
		(void) printf(
		    "\n%s: UNEXPECTED INCONSISTENCY; RUN fsck MANUALLY.\n",
		    devname);
		exit(EXERRFATAL);
	}

	va_start(ap, fmt);
	(void) putchar('\n');
	(void) vprintf(fmt, ap);
	(void) putchar('?');
	(void) putchar(' ');
	va_end(ap);

	if (nflag || fswritefd < 0) {
		(void) printf(" no\n\n");
		return (0);
	}
	if (yflag) {
		(void) printf(" yes\n\n");
		return (1);
	}
	(void) fflush(stdout);
	if (getaline(stdin, line, sizeof (line)) == EOF)
		errexit("\n");
	(void) printf("\n");
	if (line[0] == 'y' || line[0] == 'Y') {
		return (1);
	} else {
		return (0);
	}
}

int
getaline(FILE *fp, caddr_t loc, int maxlen)
{
	int n;
	caddr_t p, lastloc;

	p = loc;
	lastloc = &p[maxlen-1];
	while ((n = getc(fp)) != '\n') {
		if (n == EOF)
			return (EOF);
		if (!isspace(n) && p < lastloc)
			*p++ = (char)n;
	}
	*p = '\0';
	/* LINTED pointer difference won't overflow */
	return (p - loc);
}

/*
 * Malloc buffers and set up cache.
 */
void
bufinit(void)
{
	struct bufarea *bp;
	int bufcnt, i;
	caddr_t bufp;

	bufp = malloc((size_t)sblock.fs_bsize);
	if (bufp == NULL)
		goto nomem;
	initbarea(&cgblk);
	cgblk.b_un.b_buf = bufp;
	bufhead.b_next = bufhead.b_prev = &bufhead;
	bufcnt = MAXBUFSPACE / sblock.fs_bsize;
	if (bufcnt < MINBUFS)
		bufcnt = MINBUFS;
	for (i = 0; i < bufcnt; i++) {
		bp = (struct bufarea *)malloc(sizeof (struct bufarea));
		if (bp == NULL) {
			if (i >= MINBUFS)
				goto noalloc;
			goto nomem;
		}

		bufp = malloc((size_t)sblock.fs_bsize);
		if (bufp == NULL) {
			free((void *)bp);
			if (i >= MINBUFS)
				goto noalloc;
			goto nomem;
		}
		initbarea(bp);
		bp->b_un.b_buf = bufp;
		bp->b_prev = &bufhead;
		bp->b_next = bufhead.b_next;
		bufhead.b_next->b_prev = bp;
		bufhead.b_next = bp;
	}
noalloc:
	bufhead.b_size = i;	/* save number of buffers */
	pbp = pdirbp = NULL;
	return;

nomem:
	errexit("cannot allocate buffer pool\n");
	/* NOTREACHED */
}

/*
 * Undo a bufinit().
 */
void
unbufinit(void)
{
	int cnt;
	struct bufarea *bp, *nbp;

	cnt = 0;
	for (bp = bufhead.b_prev; bp != NULL && bp != &bufhead; bp = nbp) {
		cnt++;
		flush(fswritefd, bp);
		nbp = bp->b_prev;
		/*
		 * We're discarding the entire chain, so this isn't
		 * technically necessary.  However, it doesn't hurt
		 * and lint's data flow analysis is much happier
		 * (this prevents it from thinking there's a chance
		 * of our using memory elsewhere after it's been released).
		 */
		nbp->b_next = bp->b_next;
		bp->b_next->b_prev = nbp;
		free((void *)bp->b_un.b_buf);
		free((void *)bp);
	}

	if (bufhead.b_size != cnt)
		errexit("Panic: cache lost %d buffers\n",
		    bufhead.b_size - cnt);
}

/*
 * Manage a cache of directory blocks.
 */
struct bufarea *
getdatablk(daddr32_t blkno, size_t size)
{
	struct bufarea *bp;

	for (bp = bufhead.b_next; bp != &bufhead; bp = bp->b_next)
		if (bp->b_bno == fsbtodb(&sblock, blkno)) {
			goto foundit;
		}
	for (bp = bufhead.b_prev; bp != &bufhead; bp = bp->b_prev)
		if ((bp->b_flags & B_INUSE) == 0)
			break;
	if (bp == &bufhead) {
		bp = alloc_bufarea();
		if (bp == NULL) {
			errexit("deadlocked buffer pool\n");
			/* NOTREACHED */
		}
	}
	/*
	 * We're at the same logical level as getblk(), so if there
	 * are any errors, we'll let our caller handle them.
	 */
	diskreads++;
	(void) getblk(bp, blkno, size);

foundit:
	totalreads++;
	bp->b_cnt++;
	/*
	 * Move the buffer to head of linked list if it isn't
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

void
brelse(struct bufarea *bp)
{
	bp->b_cnt--;
	if (bp->b_cnt == 0) {
		bp->b_flags &= ~B_INUSE;
	}
}

struct bufarea *
getblk(struct bufarea *bp, daddr32_t blk, size_t size)
{
	diskaddr_t dblk;

	dblk = fsbtodb(&sblock, blk);
	if (bp->b_bno == dblk)
		return (bp);
	flush(fswritefd, bp);
	bp->b_errs = fsck_bread(fsreadfd, bp->b_un.b_buf, dblk, size);
	bp->b_bno = dblk;
	bp->b_size = size;
	return (bp);
}

void
flush(int fd, struct bufarea *bp)
{
	int i, j;
	caddr_t sip;
	long size;

	if (!bp->b_dirty)
		return;

	/*
	 * It's not our buf, so if there are errors, let whoever
	 * acquired it deal with the actual problem.
	 */
	if (bp->b_errs != 0)
		pfatal("WRITING ZERO'ED BLOCK %lld TO DISK\n", bp->b_bno);
	bp->b_dirty = 0;
	bp->b_errs = 0;
	bwrite(fd, bp->b_un.b_buf, bp->b_bno, (long)bp->b_size);
	if (bp != &sblk) {
		return;
	}

	/*
	 * We're flushing the superblock, so make sure all the
	 * ancillary bits go out as well.
	 */
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

static void
rwerror(caddr_t mesg, diskaddr_t blk, int rval)
{
	int olderr = errno;

	if (!preen)
		(void) printf("\n");

	if (rval == -1)
		pfatal("CANNOT %s: DISK BLOCK %lld: %s",
		    mesg, blk, strerror(olderr));
	else
		pfatal("CANNOT %s: DISK BLOCK %lld", mesg, blk);

	if (reply("CONTINUE") == 0) {
		exitstat = EXERRFATAL;
		errexit("Program terminated\n");
	}
}

void
ckfini(void)
{
	int64_t percentage;

	if (fswritefd < 0)
		return;

	flush(fswritefd, &sblk);
	/*
	 * Were we using a backup superblock?
	 */
	if (havesb && sblk.b_bno != SBOFF / dev_bsize) {
		if (preen || reply("UPDATE STANDARD SUPERBLOCK") == 1) {
			sblk.b_bno = SBOFF / dev_bsize;
			sbdirty();
			flush(fswritefd, &sblk);
		}
	}
	flush(fswritefd, &cgblk);
	if (cgblk.b_un.b_buf != NULL) {
		free((void *)cgblk.b_un.b_buf);
		cgblk.b_un.b_buf = NULL;
	}
	unbufinit();
	pbp = NULL;
	pdirbp = NULL;
	if (debug) {
		/*
		 * Note that we only count cache-related reads.
		 * Anything that called fsck_bread() or getblk()
		 * directly are explicitly not cached, so they're not
		 * included here.
		 */
		if (totalreads != 0)
			percentage = diskreads * 100 / totalreads;
		else
			percentage = 0;

		(void) printf("cache missed %lld of %lld reads (%lld%%)\n",
		    (longlong_t)diskreads, (longlong_t)totalreads,
		    (longlong_t)percentage);
	}

	(void) close(fsreadfd);
	(void) close(fswritefd);
	fsreadfd = -1;
	fswritefd = -1;
}

int
fsck_bread(int fd, caddr_t buf, diskaddr_t blk, size_t size)
{
	caddr_t cp;
	int i;
	int errs;
	offset_t offset = ldbtob(blk);
	offset_t addr;

	/*
	 * In our universe, nothing exists before the superblock, so
	 * just pretend it's always zeros.  This is the complement of
	 * bwrite()'s ignoring write requests into that space.
	 */
	if (blk < SBLOCK) {
		if (debug)
			(void) printf(
			    "WARNING: fsck_bread() passed blkno < %d (%lld)\n",
			    SBLOCK, (longlong_t)blk);
		(void) memset(buf, 0, (size_t)size);
		return (1);
	}

	if (llseek(fd, offset, SEEK_SET) < 0) {
		rwerror("SEEK", blk, -1);
	}

	if ((i = read(fd, buf, size)) == size) {
		return (0);
	}
	rwerror("READ", blk, i);
	if (llseek(fd, offset, SEEK_SET) < 0) {
		rwerror("SEEK", blk, -1);
	}
	errs = 0;
	(void) memset(buf, 0, (size_t)size);
	pwarn("THE FOLLOWING SECTORS COULD NOT BE READ:");
	for (cp = buf, i = 0; i < btodb(size); i++, cp += DEV_BSIZE) {
		addr = ldbtob(blk + i);
		if (llseek(fd, addr, SEEK_SET) < 0 ||
		    read(fd, cp, (int)secsize) < 0) {
			iscorrupt = 1;
			(void) printf(" %llu", blk + (u_longlong_t)i);
			errs++;
		}
	}
	(void) printf("\n");
	return (errs);
}

void
bwrite(int fd, caddr_t buf, diskaddr_t blk, int64_t size)
{
	int i;
	int n;
	caddr_t cp;
	offset_t offset = ldbtob(blk);
	offset_t addr;

	if (fd < 0)
		return;
	if (blk < SBLOCK) {
		if (debug)
			(void) printf(
		    "WARNING: Attempt to write illegal blkno %lld on %s\n",
			    (longlong_t)blk, devname);
		return;
	}
	if (llseek(fd, offset, SEEK_SET) < 0) {
		rwerror("SEEK", blk, -1);
	}
	if ((i = write(fd, buf, (int)size)) == size) {
		fsmodified = 1;
		return;
	}
	rwerror("WRITE", blk, i);
	if (llseek(fd, offset, SEEK_SET) < 0) {
		rwerror("SEEK", blk, -1);
	}
	pwarn("THE FOLLOWING SECTORS COULD NOT BE WRITTEN:");
	for (cp = buf, i = 0; i < btodb(size); i++, cp += DEV_BSIZE) {
		n = 0;
		addr = ldbtob(blk + i);
		if (llseek(fd, addr, SEEK_SET) < 0 ||
		    (n = write(fd, cp, DEV_BSIZE)) < 0) {
			iscorrupt = 1;
			(void) printf(" %llu", blk + (u_longlong_t)i);
		} else if (n > 0) {
			fsmodified = 1;
		}

	}
	(void) printf("\n");
}

/*
 * Allocates the specified number of contiguous fragments.
 */
daddr32_t
allocblk(int wantedfrags)
{
	int block, leadfrag, tailfrag;
	daddr32_t selected;
	size_t size;
	struct bufarea *bp;

	/*
	 * It's arguable whether we should just fail, or instead
	 * error out here.  Since we should only ever be asked for
	 * a single fragment or an entire block (i.e., sblock.fs_frag),
	 * we'll fail out because anything else means somebody
	 * changed code without considering all of the ramifications.
	 */
	if (wantedfrags <= 0 || wantedfrags > sblock.fs_frag) {
		exitstat = EXERRFATAL;
		errexit("allocblk() asked for %d frags.  "
		    "Legal range is 1 to %d",
		    wantedfrags, sblock.fs_frag);
	}

	/*
	 * For each filesystem block, look at every possible starting
	 * offset within the block such that we can get the number of
	 * contiguous fragments that we need.  This is a drastically
	 * simplified version of the kernel's mapsearch() and alloc*().
	 * It's also correspondingly slower.
	 */
	for (block = 0; block < maxfsblock - sblock.fs_frag;
	    block += sblock.fs_frag) {
		for (leadfrag = 0; leadfrag <= sblock.fs_frag - wantedfrags;
		    leadfrag++) {
			/*
			 * Is first fragment of candidate run available?
			 */
			if (testbmap(block + leadfrag))
				continue;
			/*
			 * Are the rest of them available?
			 */
			for (tailfrag = 1; tailfrag < wantedfrags; tailfrag++)
				if (testbmap(block + leadfrag + tailfrag))
					break;
			if (tailfrag < wantedfrags) {
				/*
				 * No, skip the known-unusable run.
				 */
				leadfrag += tailfrag;
				continue;
			}
			/*
			 * Found what we need, so claim them.
			 */
			for (tailfrag = 0; tailfrag < wantedfrags; tailfrag++)
				setbmap(block + leadfrag + tailfrag);
			n_blks += wantedfrags;
			size = wantedfrags * sblock.fs_fsize;
			selected = block + leadfrag;
			bp = getdatablk(selected, size);
			(void) memset((void *)bp->b_un.b_buf, 0, size);
			dirty(bp);
			brelse(bp);
			if (debug)
				(void) printf(
		    "allocblk: selected %d (in block %d), frags %d, size %d\n",
				    selected, selected % sblock.fs_bsize,
				    wantedfrags, (int)size);
			return (selected);
		}
	}
	return (0);
}

/*
 * Free a previously allocated block
 */
void
freeblk(fsck_ino_t ino, daddr32_t blkno, int frags)
{
	struct inodesc idesc;

	if (debug)
		(void) printf("debug: freeing %d fragments starting at %d\n",
		    frags, blkno);

	init_inodesc(&idesc);

	idesc.id_number = ino;
	idesc.id_blkno = blkno;
	idesc.id_numfrags = frags;
	idesc.id_truncto = -1;

	/*
	 * Nothing in the return status has any relevance to how
	 * we're using pass4check(), so just ignore it.
	 */
	(void) pass4check(&idesc);
}

/*
 * Fill NAMEBUF with a path starting in CURDIR for INO.  Assumes
 * that the given buffer is at least MAXPATHLEN + 1 characters.
 */
void
getpathname(caddr_t namebuf, fsck_ino_t curdir, fsck_ino_t ino)
{
	int len;
	caddr_t cp;
	struct dinode *dp;
	struct inodesc idesc;
	struct inoinfo *inp;

	if (debug)
		(void) printf("debug: getpathname(curdir %d, ino %d)\n",
		    curdir, ino);

	if ((curdir == 0) || (!INO_IS_DVALID(curdir))) {
		(void) strcpy(namebuf, "?");
		return;
	}

	if ((curdir == UFSROOTINO) && (ino == UFSROOTINO)) {
		(void) strcpy(namebuf, "/");
		return;
	}

	init_inodesc(&idesc);
	idesc.id_type = DATA;
	cp = &namebuf[MAXPATHLEN - 1];
	*cp = '\0';

	/*
	 * In the case of extended attributes, our
	 * parent won't necessarily be a directory, so just
	 * return what we've found with a prefix indicating
	 * that it's an XATTR.  Presumably our caller will
	 * know what's going on and do something useful, like
	 * work out the path of the parent and then combine
	 * the two names.
	 *
	 * Can't use strcpy(), etc, because we've probably
	 * already got some name information in the buffer and
	 * the usual trailing \0 would lose it.
	 */
	dp = ginode(curdir);
	if ((dp->di_mode & IFMT) == IFATTRDIR) {
		idesc.id_number = curdir;
		idesc.id_parent = ino;
		idesc.id_func = findname;
		idesc.id_name = namebuf;
		idesc.id_fix = NOFIX;
		if ((ckinode(dp, &idesc, CKI_TRAVERSE) & FOUND) == 0) {
			*cp-- = '?';
		}

		len = sizeof (XATTR_DIR_NAME) - 1;
		cp -= len;
		(void) memmove(cp, XATTR_DIR_NAME, len);
		goto attrname;
	}

	/*
	 * If curdir == ino, need to get a handle on .. so we
	 * can search it for ino's name.  Otherwise, just search
	 * the given directory for ino.  Repeat until out of space
	 * or a full path has been built.
	 */
	if (curdir != ino) {
		idesc.id_parent = curdir;
		goto namelookup;
	}
	while (ino != UFSROOTINO && ino != 0) {
		idesc.id_number = ino;
		idesc.id_func = findino;
		idesc.id_name = "..";
		idesc.id_fix = NOFIX;
		if ((ckinode(ginode(ino), &idesc, CKI_TRAVERSE) & FOUND) == 0) {
			inp = getinoinfo(ino);
			if ((inp == NULL) || (inp->i_parent == 0)) {
				break;
			}
			idesc.id_parent = inp->i_parent;
		}

		/*
		 * To get this far, id_parent must have the inode
		 * number for `..' in it.  By definition, that's got
		 * to be a directory, so search it for the inode of
		 * interest.
		 */
namelookup:
		idesc.id_number = idesc.id_parent;
		idesc.id_parent = ino;
		idesc.id_func = findname;
		idesc.id_name = namebuf;
		idesc.id_fix = NOFIX;
		if ((ckinode(ginode(idesc.id_number),
		    &idesc, CKI_TRAVERSE) & FOUND) == 0) {
			break;
		}
		/*
		 * Prepend to what we've accumulated so far.  If
		 * there's not enough room for even one more path element
		 * (of the worst-case length), then bail out.
		 */
		len = strlen(namebuf);
		cp -= len;
		if (cp < &namebuf[MAXNAMLEN])
			break;
		(void) memmove(cp, namebuf, len);
		*--cp = '/';

		/*
		 * Corner case for a looped-to-itself directory.
		 */
		if (ino == idesc.id_number)
			break;

		/*
		 * Climb one level of the hierarchy.  In other words,
		 * the current .. becomes the inode to search for and
		 * its parent becomes the directory to search in.
		 */
		ino = idesc.id_number;
	}

	/*
	 * If we hit a discontinuity in the hierarchy, indicate it by
	 * prefixing the path so far with `?'.  Otherwise, the first
	 * character will be `/' as a side-effect of the *--cp above.
	 *
	 * The special case is to handle the situation where we're
	 * trying to look something up in UFSROOTINO, but didn't find
	 * it.
	 */
	if (ino != UFSROOTINO || cp == &namebuf[MAXPATHLEN - 1]) {
		if (cp > namebuf)
			cp--;
		*cp = '?';
	}

	/*
	 * The invariants being used for buffer integrity are:
	 * - namebuf[] is terminated with \0 before anything else
	 * - cp is always <= the last element of namebuf[]
	 * - the new path element is always stored at the
	 *   beginning of namebuf[], and is no more than MAXNAMLEN-1
	 *   characters
	 * - cp is is decremented by the number of characters in
	 *   the new path element
	 * - if, after the above accounting for the new element's
	 *   size, there is no longer enough room at the beginning of
	 *   namebuf[] for a full-sized path element and a slash,
	 *   terminate the loop.  cp is in the range
	 *   &namebuf[0]..&namebuf[MAXNAMLEN - 1]
	 */
attrname:
	/* LINTED per the above discussion */
	(void) memmove(namebuf, cp, &namebuf[MAXPATHLEN] - cp);
}

/* ARGSUSED */
void
catch(int dummy)
{
	ckfini();
	exit(EXSIGNAL);
}

/*
 * When preening, allow a single quit to signal
 * a special exit after filesystem checks complete
 * so that reboot sequence may be interrupted.
 */
/* ARGSUSED */
void
catchquit(int dummy)
{
	(void) printf("returning to single-user after filesystem check\n");
	interrupted = 1;
	(void) signal(SIGQUIT, SIG_DFL);
}


/*
 * determine whether an inode should be fixed.
 */
NOTE(PRINTFLIKE(2))
int
dofix(struct inodesc *idesc, caddr_t msg, ...)
{
	int rval = 0;
	va_list ap;

	va_start(ap, msg);

	switch (idesc->id_fix) {

	case DONTKNOW:
		if (idesc->id_type == DATA)
			vdirerror(idesc->id_number, msg, ap);
		else
			vpwarn(msg, ap);
		if (preen) {
			idesc->id_fix = FIX;
			rval = ALTERED;
			break;
		}
		if (reply("SALVAGE") == 0) {
			idesc->id_fix = NOFIX;
			break;
		}
		idesc->id_fix = FIX;
		rval = ALTERED;
		break;

	case FIX:
		rval = ALTERED;
		break;

	case NOFIX:
		break;

	default:
		errexit("UNKNOWN INODESC FIX MODE %d\n", (int)idesc->id_fix);
	}

	va_end(ap);
	return (rval);
}

NOTE(PRINTFLIKE(1))
void
errexit(caddr_t fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	verrexit(fmt, ap);
	/* NOTREACHED */
}

NOTE(PRINTFLIKE(1))
static void
verrexit(caddr_t fmt, va_list ap)
{
	static int recursing = 0;

	if (!recursing) {
		recursing = 1;
		if (errorlocked || iscorrupt) {
			if (havesb && fswritefd >= 0) {
				sblock.fs_clean = FSBAD;
				sblock.fs_state = FSOKAY - (long)sblock.fs_time;
				sblock.fs_state = -sblock.fs_state;
				sbdirty();
				write_altsb(fswritefd);
				flush(fswritefd, &sblk);
			}
		}
		ckfini();
		recursing = 0;
	}
	(void) vprintf(fmt, ap);
	if (fmt[strlen(fmt) - 1] != '\n')
		(void) putchar('\n');
	exit((exitstat != 0) ? exitstat : EXERRFATAL);
}

/*
 * An unexpected inconsistency occured.
 * Die if preening, otherwise just print message and continue.
 */
NOTE(PRINTFLIKE(1))
void
pfatal(caddr_t fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vpfatal(fmt, ap);
	va_end(ap);
}

NOTE(PRINTFLIKE(1))
static void
vpfatal(caddr_t fmt, va_list ap)
{
	if (preen) {
		if (*fmt != '\0') {
			(void) printf("%s: ", devname);
			(void) vprintf(fmt, ap);
			(void) printf("\n");
		}
		(void) printf(
		    "%s: UNEXPECTED INCONSISTENCY; RUN fsck MANUALLY.\n",
		    devname);
		if (havesb && fswritefd >= 0) {
			sblock.fs_clean = FSBAD;
			sblock.fs_state = -(FSOKAY - (long)sblock.fs_time);
			sbdirty();
			flush(fswritefd, &sblk);
		}
		/*
		 * We're exiting, it doesn't really matter that our
		 * caller doesn't get to call va_end().
		 */
		if (exitstat == 0)
			exitstat = EXFNDERRS;
		exit(exitstat);
	}
	if (*fmt != '\0') {
		(void) vprintf(fmt, ap);
	}
}

/*
 * Pwarn just prints a message when not preening,
 * or a warning (preceded by filename) when preening.
 */
NOTE(PRINTFLIKE(1))
void
pwarn(caddr_t fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vpwarn(fmt, ap);
	va_end(ap);
}

NOTE(PRINTFLIKE(1))
static void
vpwarn(caddr_t fmt, va_list ap)
{
	if (*fmt != '\0') {
		if (preen)
			(void) printf("%s: ", devname);
		(void) vprintf(fmt, ap);
	}
}

/*
 * Like sprintf(), except the buffer is dynamically allocated
 * and returned, instead of being passed in.  A pointer to the
 * buffer is stored in *RET, and FMT is the usual format string.
 * The number of characters in *RET (excluding the trailing \0,
 * to be consistent with the other *printf() routines) is returned.
 *
 * Solaris doesn't have asprintf(3C) yet, unfortunately.
 */
NOTE(PRINTFLIKE(2))
int
fsck_asprintf(caddr_t *ret, caddr_t fmt, ...)
{
	int len;
	caddr_t buffer;
	va_list ap;

	va_start(ap, fmt);
	len = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);

	buffer = malloc((len + 1) * sizeof (char));
	if (buffer == NULL) {
		errexit("Out of memory in asprintf\n");
		/* NOTREACHED */
	}

	va_start(ap, fmt);
	(void) vsnprintf(buffer, len + 1, fmt, ap);
	va_end(ap);

	*ret = buffer;
	return (len);
}

/*
 * So we can take advantage of kernel routines in ufs_subr.c.
 */
/* PRINTFLIKE2 */
void
cmn_err(int level, caddr_t fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (level == CE_PANIC) {
		(void) printf("INTERNAL INCONSISTENCY:");
		verrexit(fmt, ap);
	} else {
		(void) vprintf(fmt, ap);
	}
	va_end(ap);
}

/*
 * Check to see if unraw version of name is already mounted.
 * Updates devstr with the device name if devstr is not NULL
 * and str_size is positive.
 */
int
mounted(caddr_t name, caddr_t devstr, size_t str_size)
{
	int found;
	struct mnttab *mntent;

	mntent = search_mnttab(NULL, unrawname(name), devstr, str_size);
	if (mntent == NULL)
		return (M_NOMNT);

	/*
	 * It's mounted.  With or without write access?
	 */
	if (hasmntopt(mntent, MNTOPT_RO) != 0)
		found = M_RO;	/* mounted as RO */
	else
		found = M_RW; 	/* mounted as R/W */

	if (mount_point == NULL) {
		mount_point = strdup(mntent->mnt_mountp);
		if (mount_point == NULL) {
			errexit("fsck: memory allocation failure: %s",
			    strerror(errno));
			/* NOTREACHED */
		}

		if (devstr != NULL && str_size > 0)
			(void) strlcpy(devstr, mntent->mnt_special, str_size);
	}

	return (found);
}

/*
 * Check to see if name corresponds to an entry in vfstab, and that the entry
 * does not have option ro.
 */
int
writable(caddr_t name)
{
	int rw = 1;
	struct vfstab vfsbuf, vfskey;
	FILE *vfstab;

	vfstab = fopen(VFSTAB, "r");
	if (vfstab == NULL) {
		(void) printf("can't open %s\n", VFSTAB);
		return (1);
	}
	(void) memset((void *)&vfskey, 0, sizeof (vfskey));
	vfsnull(&vfskey);
	vfskey.vfs_special = unrawname(name);
	vfskey.vfs_fstype = MNTTYPE_UFS;
	if ((getvfsany(vfstab, &vfsbuf, &vfskey) == 0) &&
	    (hasvfsopt(&vfsbuf, MNTOPT_RO))) {
		rw = 0;
	}
	(void) fclose(vfstab);
	return (rw);
}

/*
 * debugclean
 */
static void
debugclean(void)
{
	if (!debug)
		return;

	if ((iscorrupt == 0) && (isdirty == 0))
		return;

	if ((sblock.fs_clean == FSSTABLE) || (sblock.fs_clean == FSCLEAN) ||
	    (sblock.fs_clean == FSLOG && islog && islogok) ||
	    ((FSOKAY == (sblock.fs_state + sblock.fs_time)) && !errorlocked))
		return;

	(void) printf("WARNING: inconsistencies detected on %s filesystem %s\n",
	    sblock.fs_clean == FSSTABLE ? "stable" :
	    sblock.fs_clean == FSLOG ? "logging" :
	    sblock.fs_clean == FSFIX ? "being fixed" : "clean",
	    devname);
}

/*
 * updateclean
 *	Carefully and transparently update the clean flag.
 *
 * `iscorrupt' has to be in its final state before this is called.
 */
int
updateclean(void)
{
	int freedlog = 0;
	struct bufarea cleanbuf;
	size_t size;
	ssize_t io_res;
	diskaddr_t bno;
	char fsclean;
	int fsreclaim;
	char fsflags;
	int flags_ok = 1;
	daddr32_t fslogbno;
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
	if (FSOKAY != (sblock.fs_state + sblock.fs_time) && !errorlocked) {
		fsclean = FSACTIVE;
	}
	/*
	 * If ufs log is not okay, note that we need to clear it.
	 */
	examinelog(NULL);
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
		if (iscorrupt) {
			fsclean = FSACTIVE;
		} else {
			fsreclaim = 0;
		}
		break;

	case FSLOG:
		if (iscorrupt) {
			fsclean = FSACTIVE;
		} else if (!islog || fslogbno == 0) {
			fsclean = FSSTABLE;
			fsreclaim = 0;
		} else if (fflag) {
			fsreclaim = 0;
		}
		break;

	case FSFIX:
		fsclean = FSBAD;
		if (errorlocked && !iscorrupt) {
			fsclean = islog ? FSLOG : FSCLEAN;
		}
		break;

	default:
		if (iscorrupt) {
			fsclean = FSACTIVE;
		} else {
			fsclean = FSSTABLE;
			fsreclaim = 0;
		}
	}

	if (largefile_count > 0)
		fsflags |= FSLARGEFILES;
	else
		fsflags &= ~FSLARGEFILES;

	/*
	 * There can be two discrepencies here.  A) The superblock
	 * shows no largefiles but we found some while scanning.
	 * B) The superblock indicates the presence of largefiles,
	 * but none are present.  Note that if preening, the superblock
	 * is silently corrected.
	 */
	if ((fsflags == FSLARGEFILES && sblock.fs_flags != FSLARGEFILES) ||
	    (fsflags != FSLARGEFILES && sblock.fs_flags == FSLARGEFILES))
		flags_ok = 0;

	if (debug)
		(void) printf(
		    "** largefile count=%d, fs.fs_flags=%x, flags_ok %d\n",
		    largefile_count, sblock.fs_flags, flags_ok);

	/*
	 * If fs is unchanged, do nothing.
	 */
	if ((!isdirty) && (flags_ok) &&
	    (fslogbno == sblock.fs_logbno) &&
	    (sblock.fs_clean == fsclean) &&
	    (sblock.fs_reclaim == fsreclaim) &&
	    (FSOKAY == (sblock.fs_state + sblock.fs_time))) {
		if (errorlocked) {
			if (!do_errorlock(LOCKFS_ULOCK))
				pwarn(
		    "updateclean(unchanged): unlock(LOCKFS_ULOCK) failed\n");
		}
		return (freedlog);
	}

	/*
	 * if user allows, update superblock state
	 */
	if (debug) {
		(void) printf(
	    "superblock: flags 0x%x logbno %d clean %d reclaim %d state 0x%x\n",
		    sblock.fs_flags, sblock.fs_logbno,
		    sblock.fs_clean, sblock.fs_reclaim,
		    sblock.fs_state + sblock.fs_time);
		(void) printf(
	    "calculated: flags 0x%x logbno %d clean %d reclaim %d state 0x%x\n",
		    fsflags, fslogbno, fsclean, fsreclaim, FSOKAY);
	}
	if (!isdirty && !preen && !rerun &&
	    (reply("FILE SYSTEM STATE IN SUPERBLOCK IS WRONG; FIX") == 0))
		return (freedlog);

	(void) time(&t);
	sblock.fs_time = (time32_t)t;
	if (debug)
		printclean();

	if (sblock.fs_logbno != fslogbno) {
		examinelog(&freelogblk);
		freedlog++;
	}

	sblock.fs_logbno = fslogbno;
	sblock.fs_clean = fsclean;
	sblock.fs_state = FSOKAY - (long)sblock.fs_time;
	sblock.fs_reclaim = fsreclaim;
	sblock.fs_flags = fsflags;

	/*
	 * if superblock can't be written, return
	 */
	if (fswritefd < 0)
		return (freedlog);

	/*
	 * Read private copy of superblock, update clean flag, and write it.
	 */
	bno  = sblk.b_bno;
	size = sblk.b_size;

	sblkoff = ldbtob(bno);

	if ((cleanbuf.b_un.b_buf = malloc(size)) == NULL)
		errexit("out of memory");
	if (llseek(fsreadfd, sblkoff, SEEK_SET) == -1) {
		(void) printf("COULD NOT SEEK TO SUPERBLOCK AT %lld: %s\n",
		    (longlong_t)bno, strerror(errno));
		goto out;
	}

	if ((io_res = read(fsreadfd, cleanbuf.b_un.b_buf, size)) != size) {
		report_io_prob("READ FROM", bno, size, io_res);
		goto out;
	}

	cleanbuf.b_un.b_fs->fs_logbno  = sblock.fs_logbno;
	cleanbuf.b_un.b_fs->fs_clean   = sblock.fs_clean;
	cleanbuf.b_un.b_fs->fs_state   = sblock.fs_state;
	cleanbuf.b_un.b_fs->fs_time    = sblock.fs_time;
	cleanbuf.b_un.b_fs->fs_reclaim = sblock.fs_reclaim;
	cleanbuf.b_un.b_fs->fs_flags   = sblock.fs_flags;

	if (llseek(fswritefd, sblkoff, SEEK_SET) == -1) {
		(void) printf("COULD NOT SEEK TO SUPERBLOCK AT %lld: %s\n",
		    (longlong_t)bno, strerror(errno));
		goto out;
	}

	if ((io_res = write(fswritefd, cleanbuf.b_un.b_buf, size)) != size) {
		report_io_prob("WRITE TO", bno, size, io_res);
		goto out;
	}

	/*
	 * 1208040
	 * If we had to use -b to grab an alternate superblock, then we
	 * likely had to do so because of unacceptable differences between
	 * the main and alternate superblocks.  So, we had better update
	 * the alternate superblock as well, or we'll just fail again
	 * the next time we attempt to run fsck!
	 */
	if (bflag != 0) {
		write_altsb(fswritefd);
	}

	if (errorlocked) {
		if (!do_errorlock(LOCKFS_ULOCK))
			pwarn(
		    "updateclean(changed): unlock(LOCKFS_ULOCK) failed\n");
	}

out:
	if (cleanbuf.b_un.b_buf != NULL) {
		free((void *)cleanbuf.b_un.b_buf);
	}

	return (freedlog);
}

static void
report_io_prob(caddr_t what, diskaddr_t bno, size_t expected, ssize_t failure)
{
	if (failure < 0)
		(void) printf("COULD NOT %s SUPERBLOCK AT %d: %s\n",
		    what, (int)bno, strerror(errno));
	else if (failure == 0)
		(void) printf("COULD NOT %s SUPERBLOCK AT %d: EOF\n",
		    what, (int)bno);
	else
		(void) printf("SHORT %s SUPERBLOCK AT %d: %u out of %u bytes\n",
		    what, (int)bno, (unsigned)failure, (unsigned)expected);
}

/*
 * print out clean info
 */
void
printclean(void)
{
	caddr_t s;

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
		(void) printf("** %s is %s.\n", devname, s);
}

int
is_errorlocked(caddr_t fs)
{
	int		retval;
	struct stat64	statb;
	caddr_t		mountp;
	struct mnttab	*mntent;

	retval = 0;

	if (!fs)
		return (0);

	if (stat64(fs, &statb) < 0)
		return (0);

	if (S_ISDIR(statb.st_mode)) {
		mountp = fs;
	} else if (S_ISBLK(statb.st_mode) || S_ISCHR(statb.st_mode)) {
		mntent = search_mnttab(NULL, fs, NULL, 0);
		if (mntent == NULL)
			return (0);
		mountp = mntent->mnt_mountp;
		if (mountp == NULL) /* theoretically a can't-happen */
			return (0);
	} else {
		return (0);
	}

	/*
	 * From here on, must `goto out' to avoid memory leakage.
	 */

	if (elock_combuf == NULL)
		elock_combuf =
		    (caddr_t)calloc(LOCKFS_MAXCOMMENTLEN, sizeof (char));
	else
		elock_combuf =
		    (caddr_t)realloc(elock_combuf, LOCKFS_MAXCOMMENTLEN);

	if (elock_combuf == NULL)
		goto out;

	(void) memset((void *)elock_combuf, 0, LOCKFS_MAXCOMMENTLEN);

	if (elock_mountp != NULL) {
		free(elock_mountp);
	}

	elock_mountp = strdup(mountp);
	if (elock_mountp == NULL)
		goto out;

	if (mountfd < 0) {
		if ((mountfd = open64(mountp, O_RDONLY)) == -1)
			goto out;
	}

	if (lfp == NULL) {
		lfp = (struct lockfs *)malloc(sizeof (struct lockfs));
		if (lfp == NULL)
			goto out;
		(void) memset((void *)lfp, 0, sizeof (struct lockfs));
	}

	lfp->lf_comlen = LOCKFS_MAXCOMMENTLEN;
	lfp->lf_comment = elock_combuf;

	if (ioctl(mountfd, _FIOLFSS, lfp) == -1)
		goto out;

	/*
	 * lint believes that the ioctl() (or any other function
	 * taking lfp as an arg) could free lfp.  This is not the
	 * case, however.
	 */
	retval = LOCKFS_IS_ELOCK(lfp);

out:
	return (retval);
}

/*
 * Given a name which is known to be a directory, see if it appears
 * in the vfstab.  If so, return the entry's block (special) device
 * field via devstr.
 */
int
check_vfstab(caddr_t name, caddr_t devstr, size_t str_size)
{
	return (NULL != search_vfstab(name, NULL, devstr, str_size));
}

/*
 * Given a name which is known to be a directory, see if it appears
 * in the mnttab.  If so, return the entry's block (special) device
 * field via devstr.
 */
int
check_mnttab(caddr_t name, caddr_t devstr, size_t str_size)
{
	return (NULL != search_mnttab(name, NULL, devstr, str_size));
}

/*
 * Search for mount point and/or special device in the given file.
 * The first matching entry is returned.
 *
 * If an entry is found and str_size is greater than zero, then
 * up to size_str bytes of the special device name from the entry
 * are copied to devstr.
 */

#define	SEARCH_TAB_BODY(st_type, st_file, st_mount, st_special, \
			st_nuller, st_init, st_searcher) \
	{ \
		FILE *fp; \
		struct st_type *retval = NULL; \
		struct st_type key; \
		static struct st_type buffer; \
		\
		/* LINTED ``assigned value never used'' */ \
		st_nuller(&key); \
		key.st_mount = mountp; \
		key.st_special = special; \
		st_init; \
		\
		if ((fp = fopen(st_file, "r")) == NULL) \
			return (NULL); \
		\
		if (st_searcher(fp, &buffer, &key) == 0) { \
			retval = &buffer; \
			if (devstr != NULL && str_size > 0 && \
			    buffer.st_special != NULL) { \
				(void) strlcpy(devstr, buffer.st_special, \
				    str_size); \
			} \
		} \
		(void) fclose(fp); \
		return (retval); \
	}

static struct vfstab *
search_vfstab(caddr_t mountp, caddr_t special, caddr_t devstr, size_t str_size)
SEARCH_TAB_BODY(vfstab, VFSTAB, vfs_mountp, vfs_special, vfsnull,
		(retval = retval), getvfsany)

static struct mnttab *
search_mnttab(caddr_t mountp, caddr_t special, caddr_t devstr, size_t str_size)
SEARCH_TAB_BODY(mnttab, MNTTAB, mnt_mountp, mnt_special, mntnull,
		(key.mnt_fstype = MNTTYPE_UFS), getmntany)

int
do_errorlock(int lock_type)
{
	caddr_t	   buf;
	time_t	   now;
	struct tm *local;
	int	   rc;

	if (elock_combuf == NULL)
		errexit("do_errorlock(%s, %d): unallocated elock_combuf\n",
		    elock_mountp ? elock_mountp : "<null>",
		    lock_type);

	if ((buf = (caddr_t)calloc(LOCKFS_MAXCOMMENTLEN, sizeof (char))) ==
	    NULL) {
		errexit("Couldn't alloc memory for temp. lock status buffer\n");
	}
	if (lfp == NULL) {
		errexit("do_errorlock(%s, %d): lockfs status unallocated\n",
		    elock_mountp, lock_type);
	}

	(void) memmove((void *)buf, (void *)elock_combuf,
	    LOCKFS_MAXCOMMENTLEN-1);

	switch (lock_type) {
	case LOCKFS_ELOCK:
		/*
		 * Note that if it is error-locked, we won't get an
		 * error back if we try to error-lock it again.
		 */
		if (time(&now) != (time_t)-1) {
			if ((local = localtime(&now)) != NULL)
				(void) snprintf(buf, LOCKFS_MAXCOMMENTLEN,
		    "%s [pid:%d fsck start:%02d/%02d/%02d %02d:%02d:%02d",
				    elock_combuf, (int)pid,
				    local->tm_mon + 1, local->tm_mday,
				    (local->tm_year % 100), local->tm_hour,
				    local->tm_min, local->tm_sec);
			else
				(void) snprintf(buf, LOCKFS_MAXCOMMENTLEN,
				    "%s [fsck pid %d", elock_combuf, pid);

		} else {
			(void) snprintf(buf, LOCKFS_MAXCOMMENTLEN,
			    "%s [fsck pid %d", elock_combuf, pid);
		}
		break;

	case LOCKFS_ULOCK:
		if (time(&now) != (time_t)-1) {
			if ((local = localtime(&now)) != NULL) {
				(void) snprintf(buf, LOCKFS_MAXCOMMENTLEN,
				    "%s, done:%02d/%02d/%02d %02d:%02d:%02d]",
				    elock_combuf,
				    local->tm_mon + 1, local->tm_mday,
				    (local->tm_year % 100), local->tm_hour,
				    local->tm_min, local->tm_sec);
			} else {
				(void) snprintf(buf, LOCKFS_MAXCOMMENTLEN,
				    "%s]", elock_combuf);
			}
		} else {
			(void) snprintf(buf, LOCKFS_MAXCOMMENTLEN,
			    "%s]", elock_combuf);
		}
		if ((rc = ioctl(mountfd, _FIOLFSS, lfp)) == -1) {
			pwarn("do_errorlock: unlock failed: %s\n",
			    strerror(errno));
			goto out;
		}
		break;

	default:
		break;
	}

	(void) memmove((void *)elock_combuf, (void *)buf,
	    LOCKFS_MAXCOMMENTLEN - 1);

	lfp->lf_lock = lock_type;
	lfp->lf_comlen = LOCKFS_MAXCOMMENTLEN;
	lfp->lf_comment = elock_combuf;
	lfp->lf_flags = 0;
	errno = 0;

	if ((rc = ioctl(mountfd, _FIOLFS, lfp)) == -1) {
		if (errno == EINVAL) {
			pwarn("Another fsck active?\n");
			iscorrupt = 0;	/* don't go away mad, just go away */
		} else {
			pwarn("do_errorlock(lock_type:%d, %s) failed: %s\n",
			    lock_type, elock_combuf, strerror(errno));
		}
	}
out:
	if (buf != NULL) {
		free((void *)buf);
	}

	return (rc != -1);
}

/*
 * Shadow inode support.  To register a shadow with a client is to note
 * that an inode (the client) refers to the shadow.
 */

static struct shadowclients *
newshadowclient(struct shadowclients *prev)
{
	struct shadowclients *rc;

	rc = (struct shadowclients *)malloc(sizeof (*rc));
	if (rc == NULL)
		errexit("newshadowclient: cannot malloc shadow client");
	rc->next = prev;
	rc->nclients = 0;

	rc->client = (fsck_ino_t *)malloc(sizeof (fsck_ino_t) *
	    maxshadowclients);
	if (rc->client == NULL)
		errexit("newshadowclient: cannot malloc client array");
	return (rc);
}

void
registershadowclient(fsck_ino_t shadow, fsck_ino_t client,
	struct shadowclientinfo **info)
{
	struct shadowclientinfo *sci;
	struct shadowclients *scc;

	/*
	 * Already have a record for this shadow?
	 */
	for (sci = *info; sci != NULL; sci = sci->next)
		if (sci->shadow == shadow)
			break;
	if (sci == NULL) {
		/*
		 * It's a new shadow, add it to the list
		 */
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
 * Locate and discard a shadow.
 */
void
clearshadow(fsck_ino_t shadow, struct shadowclientinfo **info)
{
	struct shadowclientinfo *sci, *prev;

	/*
	 * Do we have a record for this shadow?
	 */
	prev = NULL;
	for (sci = *info; sci != NULL; sci = sci->next) {
		if (sci->shadow == shadow)
			break;
		prev = sci;
	}

	if (sci != NULL) {
		/*
		 * First, pull it off the list, since we know there
		 * shouldn't be any future references to this one.
		 */
		if (prev == NULL)
			*info = sci->next;
		else
			prev->next = sci->next;
		deshadow(sci, clearattrref);
	}
}

/*
 * Discard all memory used to track clients of a shadow.
 */
void
deshadow(struct shadowclientinfo *sci, void (*cb)(fsck_ino_t))
{
	struct shadowclients *clients, *discard;
	int idx;

	clients = sci->clients;
	while (clients != NULL) {
		discard = clients;
		clients = clients->next;
		if (discard->client != NULL) {
			if (cb != NULL) {
				for (idx = 0; idx < discard->nclients; idx++)
					(*cb)(discard->client[idx]);
			}
			free((void *)discard->client);
		}
		free((void *)discard);
	}

	free((void *)sci);
}

/*
 * Allocate more buffer as need arises but allocate one at a time.
 * This is done to make sure that fsck does not exit with error if it
 * needs more buffer to complete its task.
 */
static struct bufarea *
alloc_bufarea(void)
{
	struct bufarea *newbp;
	caddr_t bufp;

	bufp = malloc((unsigned int)sblock.fs_bsize);
	if (bufp == NULL)
		return (NULL);

	newbp = (struct bufarea *)malloc(sizeof (struct bufarea));
	if (newbp == NULL) {
		free((void *)bufp);
		return (NULL);
	}

	initbarea(newbp);
	newbp->b_un.b_buf = bufp;
	newbp->b_prev = &bufhead;
	newbp->b_next = bufhead.b_next;
	bufhead.b_next->b_prev = newbp;
	bufhead.b_next = newbp;
	bufhead.b_size++;
	return (newbp);
}

/*
 * We length-limit in both unrawname() and rawname() to avoid
 * overflowing our arrays or those of our naive, trusting callers.
 */

caddr_t
unrawname(caddr_t name)
{
	caddr_t dp;
	static char fullname[MAXPATHLEN + 1];

	if ((dp = getfullblkname(name)) == NULL)
		return ("");

	(void) strlcpy(fullname, dp, sizeof (fullname));
	/*
	 * Not reporting under debug, as the allocation isn't
	 * reported by getfullblkname.  The idea is that we
	 * produce balanced alloc/free instances.
	 */
	free(dp);

	return (fullname);
}

caddr_t
rawname(caddr_t name)
{
	caddr_t dp;
	static char fullname[MAXPATHLEN + 1];

	if ((dp = getfullrawname(name)) == NULL)
		return ("");

	(void) strlcpy(fullname, dp, sizeof (fullname));
	/*
	 * Not reporting under debug, as the allocation isn't
	 * reported by getfullblkname.  The idea is that we
	 * produce balanced alloc/free instances.
	 */
	free(dp);

	return (fullname);
}

/*
 * Make sure that a cg header looks at least moderately reasonable.
 * We want to be able to trust the contents enough to be able to use
 * the standard accessor macros.  So, besides looking at the obvious
 * such as the magic number, we verify that the offset field values
 * are properly aligned and not too big or small.
 *
 * Returns a NULL pointer if the cg is sane enough for our needs, else
 * a dynamically-allocated string describing all of its faults.
 */
#define	Append_Error(full, full_len, addition, addition_len) \
	if (full == NULL) { \
		full = addition; \
		full_len = addition_len; \
	} else { \
		/* lint doesn't think realloc() understands NULLs */ \
		full = realloc(full, full_len + addition_len + 1); \
		if (full == NULL) { \
			errexit("Out of memory in cg_sanity"); \
			/* NOTREACHED */ \
		} \
		(void) strcpy(full + full_len, addition); \
		full_len += addition_len; \
		free(addition); \
	}

caddr_t
cg_sanity(struct cg *cgp, int cgno)
{
	caddr_t full_err;
	caddr_t this_err = NULL;
	int full_len, this_len;
	daddr32_t ndblk;
	daddr32_t exp_btotoff, exp_boff, exp_iusedoff;
	daddr32_t exp_freeoff, exp_nextfreeoff;

	cg_constants(cgno, &exp_btotoff, &exp_boff, &exp_iusedoff,
	    &exp_freeoff, &exp_nextfreeoff, &ndblk);

	full_err = NULL;
	full_len = 0;

	if (!cg_chkmagic(cgp)) {
		this_len = fsck_asprintf(&this_err,
		    "BAD CG MAGIC NUMBER (0x%x should be 0x%x)\n",
		    cgp->cg_magic, CG_MAGIC);
		Append_Error(full_err, full_len, this_err, this_len);
	}

	if (cgp->cg_cgx != cgno) {
		this_len = fsck_asprintf(&this_err,
		    "WRONG CG NUMBER (%d should be %d)\n",
		    cgp->cg_cgx, cgno);
		Append_Error(full_err, full_len, this_err, this_len);
	}

	if ((cgp->cg_btotoff & 3) != 0) {
		this_len = fsck_asprintf(&this_err,
		    "BLOCK TOTALS OFFSET %d NOT FOUR-BYTE ALIGNED\n",
		    cgp->cg_btotoff);
		Append_Error(full_err, full_len, this_err, this_len);
	}

	if ((cgp->cg_boff & 1) != 0) {
		this_len = fsck_asprintf(&this_err,
	    "FREE BLOCK POSITIONS TABLE OFFSET %d NOT TWO-BYTE ALIGNED\n",
		    cgp->cg_boff);
		Append_Error(full_err, full_len, this_err, this_len);
	}

	if ((cgp->cg_ncyl < 1) || (cgp->cg_ncyl > sblock.fs_cpg)) {
		if (cgp->cg_ncyl < 1) {
			this_len = fsck_asprintf(&this_err,
	    "IMPOSSIBLE NUMBER OF CYLINDERS IN GROUP (%d is less than 1)\n",
			    cgp->cg_ncyl);
		} else {
			this_len = fsck_asprintf(&this_err,
	    "IMPOSSIBLE NUMBER OF CYLINDERS IN GROUP (%d is greater than %d)\n",
			    cgp->cg_ncyl, sblock.fs_cpg);
		}
		Append_Error(full_err, full_len, this_err, this_len);
	}

	if (cgp->cg_niblk != sblock.fs_ipg) {
		this_len = fsck_asprintf(&this_err,
		    "INCORRECT NUMBER OF INODES IN GROUP (%d should be %d)\n",
		    cgp->cg_niblk, sblock.fs_ipg);
		Append_Error(full_err, full_len, this_err, this_len);
	}

	if (cgp->cg_ndblk != ndblk) {
		this_len = fsck_asprintf(&this_err,
	    "INCORRECT NUMBER OF DATA BLOCKS IN GROUP (%d should be %d)\n",
		    cgp->cg_ndblk, ndblk);
		Append_Error(full_err, full_len, this_err, this_len);
	}

	if ((cgp->cg_rotor < 0) || (cgp->cg_rotor >= ndblk)) {
		this_len = fsck_asprintf(&this_err,
		    "IMPOSSIBLE BLOCK ALLOCATION ROTOR POSITION "
		    "(%d should be at least 0 and less than %d)\n",
		    cgp->cg_rotor, ndblk);
		Append_Error(full_err, full_len, this_err, this_len);
	}

	if ((cgp->cg_frotor < 0) || (cgp->cg_frotor >= ndblk)) {
		this_len = fsck_asprintf(&this_err,
		    "IMPOSSIBLE FRAGMENT ALLOCATION ROTOR POSITION "
		    "(%d should be at least 0 and less than %d)\n",
		    cgp->cg_frotor, ndblk);
		Append_Error(full_err, full_len, this_err, this_len);
	}

	if ((cgp->cg_irotor < 0) || (cgp->cg_irotor >= sblock.fs_ipg)) {
		this_len = fsck_asprintf(&this_err,
		    "IMPOSSIBLE INODE ALLOCATION ROTOR POSITION "
		    "(%d should be at least 0 and less than %d)\n",
		    cgp->cg_irotor, sblock.fs_ipg);
		Append_Error(full_err, full_len, this_err, this_len);
	}

	if (cgp->cg_btotoff != exp_btotoff) {
		this_len = fsck_asprintf(&this_err,
		    "INCORRECT BLOCK TOTALS OFFSET (%d should be %d)\n",
		    cgp->cg_btotoff, exp_btotoff);
		Append_Error(full_err, full_len, this_err, this_len);
	}

	if (cgp->cg_boff != exp_boff) {
		this_len = fsck_asprintf(&this_err,
		    "BAD FREE BLOCK POSITIONS TABLE OFFSET (%d should %d)\n",
		    cgp->cg_boff, exp_boff);
		Append_Error(full_err, full_len, this_err, this_len);
	}

	if (cgp->cg_iusedoff != exp_iusedoff) {
		this_len = fsck_asprintf(&this_err,
		    "INCORRECT USED INODE MAP OFFSET (%d should be %d)\n",
		    cgp->cg_iusedoff, exp_iusedoff);
		Append_Error(full_err, full_len, this_err, this_len);
	}

	if (cgp->cg_freeoff != exp_freeoff) {
		this_len = fsck_asprintf(&this_err,
		    "INCORRECT FREE FRAGMENT MAP OFFSET (%d should be %d)\n",
		    cgp->cg_freeoff, exp_freeoff);
		Append_Error(full_err, full_len, this_err, this_len);
	}

	if (cgp->cg_nextfreeoff != exp_nextfreeoff) {
		this_len = fsck_asprintf(&this_err,
		    "END OF HEADER POSITION INCORRECT (%d should be %d)\n",
		    cgp->cg_nextfreeoff, exp_nextfreeoff);
		Append_Error(full_err, full_len, this_err, this_len);
	}

	return (full_err);
}

#undef	Append_Error

/*
 * This is taken from mkfs, and is what is used to come up with the
 * original values for a struct cg.  This implies that, since these
 * are all constants, recalculating them now should give us the same
 * thing as what's on disk.
 */
static void
cg_constants(int cgno, daddr32_t *btotoff, daddr32_t *boff,
	daddr32_t *iusedoff, daddr32_t *freeoff, daddr32_t *nextfreeoff,
	daddr32_t *ndblk)
{
	daddr32_t cbase, dmax;
	struct cg *cgp;

	(void) getblk(&cgblk, (diskaddr_t)cgtod(&sblock, cgno),
	    (size_t)sblock.fs_cgsize);
	cgp = cgblk.b_un.b_cg;

	cbase = cgbase(&sblock, cgno);
	dmax = cbase + sblock.fs_fpg;
	if (dmax > sblock.fs_size)
		dmax = sblock.fs_size;

	/* LINTED pointer difference won't overflow */
	*btotoff = &cgp->cg_space[0] - (uchar_t *)(&cgp->cg_link);
	*boff = *btotoff + sblock.fs_cpg * sizeof (daddr32_t);
	*iusedoff = *boff + sblock.fs_cpg * sblock.fs_nrpos * sizeof (int16_t);
	*freeoff = *iusedoff + howmany(sblock.fs_ipg, NBBY);
	*nextfreeoff = *freeoff +
	    howmany(sblock.fs_cpg * sblock.fs_spc / NSPF(&sblock), NBBY);
	*ndblk = dmax - cbase;
}

/*
 * Corrects all fields in the cg that can be done with the available
 * redundant data.
 */
void
fix_cg(struct cg *cgp, int cgno)
{
	daddr32_t exp_btotoff, exp_boff, exp_iusedoff;
	daddr32_t exp_freeoff, exp_nextfreeoff;
	daddr32_t ndblk;

	cg_constants(cgno, &exp_btotoff, &exp_boff, &exp_iusedoff,
	    &exp_freeoff, &exp_nextfreeoff, &ndblk);

	if (cgp->cg_cgx != cgno) {
		cgp->cg_cgx = cgno;
	}

	if ((cgp->cg_ncyl < 1) || (cgp->cg_ncyl > sblock.fs_cpg)) {
		if (cgno == (sblock.fs_ncg - 1)) {
			cgp->cg_ncyl = sblock.fs_ncyl -
			    (sblock.fs_cpg * cgno);
		} else {
			cgp->cg_ncyl = sblock.fs_cpg;
		}
	}

	if (cgp->cg_niblk != sblock.fs_ipg) {
		/*
		 * This is not used by the kernel, so it's pretty
		 * harmless if it's wrong.
		 */
		cgp->cg_niblk = sblock.fs_ipg;
	}

	if (cgp->cg_ndblk != ndblk) {
		cgp->cg_ndblk = ndblk;
	}

	/*
	 * For the rotors, any position's valid, so pick the one we know
	 * will always exist.
	 */
	if ((cgp->cg_rotor < 0) || (cgp->cg_rotor >= cgp->cg_ndblk)) {
		cgp->cg_rotor = 0;
	}

	if ((cgp->cg_frotor < 0) || (cgp->cg_frotor >= cgp->cg_ndblk)) {
		cgp->cg_frotor = 0;
	}

	if ((cgp->cg_irotor < 0) || (cgp->cg_irotor >= sblock.fs_ipg)) {
		cgp->cg_irotor = 0;
	}

	/*
	 * For btotoff and boff, if they're misaligned they won't
	 * match the expected values, so we're catching both cases
	 * here.  Of course, if any of these are off, it seems likely
	 * that the tables really won't be where we calculate they
	 * should be anyway.
	 */
	if (cgp->cg_btotoff != exp_btotoff) {
		cgp->cg_btotoff = exp_btotoff;
	}

	if (cgp->cg_boff != exp_boff) {
		cgp->cg_boff = exp_boff;
	}

	if (cgp->cg_iusedoff != exp_iusedoff) {
		cgp->cg_iusedoff = exp_iusedoff;
	}

	if (cgp->cg_freeoff != exp_freeoff) {
		cgp->cg_freeoff = exp_freeoff;
	}

	if (cgp->cg_nextfreeoff != exp_nextfreeoff) {
		cgp->cg_nextfreeoff = exp_nextfreeoff;
	}

	/*
	 * Reset the magic, as we've recreated this cg, also
	 * update the cg_time, as we're writing out the cg
	 */
	cgp->cg_magic = CG_MAGIC;
	cgp->cg_time = time(NULL);

	/*
	 * We know there was at least one correctable problem,
	 * or else we wouldn't have been called.  So instead of
	 * marking the buffer dirty N times above, just do it
	 * once here.
	 */
	cgdirty();
}

void
examinelog(void (*cb)(daddr32_t))
{
	struct bufarea *bp;
	extent_block_t *ebp;
	extent_t *ep;
	daddr32_t nfno, fno;
	int i;
	int j;

	/*
	 * Since ufs stores fs_logbno as blocks and MTBufs stores it as frags
	 * we need to translate accordingly using logbtodb()
	 */

	if (logbtodb(&sblock, sblock.fs_logbno) < SBLOCK) {
		if (debug) {
			(void) printf("fs_logbno < SBLOCK: %ld < %ld\n" \
			    "Aborting log examination\n", \
			    logbtodb(&sblock, sblock.fs_logbno), SBLOCK);
		}
		return;
	}

	/*
	 * Read errors will return zeros, which will cause us
	 * to do nothing harmful, so don't need to handle it.
	 */
	bp = getdatablk(logbtofrag(&sblock, sblock.fs_logbno),
	    (size_t)sblock.fs_bsize);
	ebp = (void *)bp->b_un.b_buf;

	/*
	 * Does it look like a log allocation table?
	 */
	/* LINTED pointer cast is aligned */
	if (!log_checksum(&ebp->chksum, (int32_t *)bp->b_un.b_buf,
	    sblock.fs_bsize))
		return;
	if (ebp->type != LUFS_EXTENTS || ebp->nextents == 0)
		return;

	ep = &ebp->extents[0];
	for (i = 0; i < ebp->nextents; ++i, ++ep) {
		fno = logbtofrag(&sblock, ep->pbno);
		nfno = dbtofsb(&sblock, ep->nbno);
		for (j = 0; j < nfno; ++j, ++fno) {
			/*
			 * Invoke the callback first, so that pass1 can
			 * mark the log blocks in-use.  Then, if any
			 * subsequent pass over the log shows us that a
			 * block got freed (say, it was also claimed by
			 * an inode that we cleared), we can safely declare
			 * the log bad.
			 */
			if (cb != NULL)
				(*cb)(fno);
			if (!testbmap(fno))
				islogok = 0;
		}
	}
	brelse(bp);

	if (cb != NULL) {
		fno = logbtofrag(&sblock, sblock.fs_logbno);
		for (j = 0; j < sblock.fs_frag; ++j, ++fno)
			(*cb)(fno);
	}
}

static void
freelogblk(daddr32_t frag)
{
	freeblk(sblock.fs_logbno, frag, 1);
}

caddr_t
file_id(fsck_ino_t inum, mode_t mode)
{
	static char name[MAXPATHLEN + 1];

	if (lfdir == inum) {
		return (lfname);
	}

	if ((mode & IFMT) == IFDIR) {
		(void) strcpy(name, "DIR");
	} else if ((mode & IFMT) == IFATTRDIR) {
		(void) strcpy(name, "ATTR DIR");
	} else if ((mode & IFMT) == IFSHAD) {
		(void) strcpy(name, "ACL");
	} else {
		(void) strcpy(name, "FILE");
	}

	return (name);
}

/*
 * Simple initializer for inodesc structures, so users of only a few
 * fields don't have to worry about getting the right defaults for
 * everything out.
 */
void
init_inodesc(struct inodesc *idesc)
{
	/*
	 * Most fields should be zero, just hit the special cases.
	 */
	(void) memset((void *)idesc, 0, sizeof (struct inodesc));
	idesc->id_fix = DONTKNOW;
	idesc->id_lbn = -1;
	idesc->id_truncto = -1;
	idesc->id_firsthole = -1;
}

/*
 * Compare routine for tsearch(C) to use on ino_t instances.
 */
int
ino_t_cmp(const void *left, const void *right)
{
	const fsck_ino_t lino = (const fsck_ino_t)left;
	const fsck_ino_t rino = (const fsck_ino_t)right;

	return (lino - rino);
}

int
cgisdirty(void)
{
	return (cgblk.b_dirty);
}

void
cgflush(void)
{
	flush(fswritefd, &cgblk);
}

void
dirty(struct bufarea *bp)
{
	if (fswritefd < 0) {
		/*
		 * No one should call dirty() in read only mode.
		 * But if one does, it's not fatal issue. Just warn them.
		 */
		pwarn("WON'T SET DIRTY FLAG IN READ_ONLY MODE\n");
	} else {
		(bp)->b_dirty = 1;
		isdirty = 1;
	}
}

void
initbarea(struct bufarea *bp)
{
	(bp)->b_dirty = 0;
	(bp)->b_bno = (diskaddr_t)-1LL;
	(bp)->b_flags = 0;
	(bp)->b_cnt = 0;
	(bp)->b_errs = 0;
}

/*
 * Partition-sizing routines adapted from ../newfs/newfs.c.
 * Needed because calcsb() needs to use mkfs to work out what the
 * superblock should be, and mkfs insists on being told how many
 * sectors to use.
 *
 * Error handling assumes we're never called while preening.
 *
 * XXX This should be extracted into a ../ufslib.{c,h},
 *     in the same spirit to ../../fslib.{c,h}.  Once that is
 *     done, both fsck and newfs should be modified to link
 *     against it.
 */

static int label_type;

#define	LABEL_TYPE_VTOC		1
#define	LABEL_TYPE_EFI		2
#define	LABEL_TYPE_OTHER	3

#define	MB			(1024 * 1024)
#define	SECTORS_PER_TERABYTE	(1LL << 31)
#define	FS_SIZE_UPPER_LIMIT	0x100000000000LL

diskaddr_t
getdisksize(caddr_t disk, int fd)
{
	int rpm;
	struct dk_geom g;
	struct dk_cinfo ci;
	diskaddr_t actual_size;

	/*
	 * get_device_size() determines the actual size of the
	 * device, and also the disk's attributes, such as geometry.
	 */
	actual_size = get_device_size(fd, disk);

	if (label_type == LABEL_TYPE_VTOC) {
		if (ioctl(fd, DKIOCGGEOM, &g)) {
			pwarn("%s: Unable to read Disk geometry", disk);
			return (0);
		}
		if (sblock.fs_nsect == 0)
			sblock.fs_nsect = g.dkg_nsect;
		if (sblock.fs_ntrak == 0)
			sblock.fs_ntrak = g.dkg_nhead;
		if (sblock.fs_rps == 0) {
			rpm = ((int)g.dkg_rpm <= 0) ? 3600: g.dkg_rpm;
			sblock.fs_rps = rpm / 60;
		}
	}

	if (sblock.fs_bsize == 0)
		sblock.fs_bsize = MAXBSIZE;

	/*
	 * Adjust maxcontig by the device's maxtransfer. If maxtransfer
	 * information is not available, default to the min of a MB and
	 * maxphys.
	 */
	if (sblock.fs_maxcontig == -1 && ioctl(fd, DKIOCINFO, &ci) == 0) {
		sblock.fs_maxcontig = ci.dki_maxtransfer * DEV_BSIZE;
		if (sblock.fs_maxcontig < 0) {
			int gotit, maxphys;

			gotit = fsgetmaxphys(&maxphys, NULL);

			/*
			 * If we cannot get the maxphys value, default
			 * to ufs_maxmaxphys (MB).
			 */
			if (gotit) {
				sblock.fs_maxcontig = MIN(maxphys, MB);
			} else {
				sblock.fs_maxcontig = MB;
			}
		}
		sblock.fs_maxcontig /= sblock.fs_bsize;
	}

	return (actual_size);
}

/*
 * Figure out how big the partition we're dealing with is.
 */
static diskaddr_t
get_device_size(int fd, caddr_t name)
{
	struct extvtoc vtoc;
	struct dk_gpt *efi_vtoc;
	diskaddr_t slicesize = 0;

	int index = read_extvtoc(fd, &vtoc);

	if (index >= 0) {
		label_type = LABEL_TYPE_VTOC;
	} else {
		if (index == VT_ENOTSUP || index == VT_ERROR) {
			/* it might be an EFI label */
			index = efi_alloc_and_read(fd, &efi_vtoc);
			if (index >= 0)
				label_type = LABEL_TYPE_EFI;
		}
	}

	if (index < 0) {
		/*
		 * Since both attempts to read the label failed, we're
		 * going to fall back to a brute force approach to
		 * determining the device's size:  see how far out we can
		 * perform reads on the device.
		 */

		slicesize = brute_force_get_device_size(fd);
		if (slicesize == 0) {
			switch (index) {
			case VT_ERROR:
				pwarn("%s: %s\n", name, strerror(errno));
				break;
			case VT_EIO:
				pwarn("%s: I/O error accessing VTOC", name);
				break;
			case VT_EINVAL:
				pwarn("%s: Invalid field in VTOC", name);
				break;
			default:
				pwarn("%s: unknown error %d accessing VTOC",
				    name, index);
				break;
			}
			return (0);
		} else {
			label_type = LABEL_TYPE_OTHER;
		}
	}

	if (label_type == LABEL_TYPE_EFI) {
		slicesize = efi_vtoc->efi_parts[index].p_size;
		efi_free(efi_vtoc);
	} else if (label_type == LABEL_TYPE_VTOC) {
		slicesize = vtoc.v_part[index].p_size;
	}

	return (slicesize);
}

/*
 * brute_force_get_device_size
 *
 * Determine the size of the device by seeing how far we can
 * read.  Doing an llseek( , , SEEK_END) would probably work
 * in most cases, but we've seen at least one third-party driver
 * which doesn't correctly support the SEEK_END option when the
 * the device is greater than a terabyte.
 */

static diskaddr_t
brute_force_get_device_size(int fd)
{
	diskaddr_t	min_fail = 0;
	diskaddr_t	max_succeed = 0;
	diskaddr_t	cur_db_off;
	char 		buf[DEV_BSIZE];

	/*
	 * First, see if we can read the device at all, just to
	 * eliminate errors that have nothing to do with the
	 * device's size.
	 */

	if (((llseek(fd, (offset_t)0, SEEK_SET)) == -1) ||
	    ((read(fd, buf, DEV_BSIZE)) == -1))
		return (0);  /* can't determine size */

	/*
	 * Now, go sequentially through the multiples of 4TB
	 * to find the first read that fails (this isn't strictly
	 * the most efficient way to find the actual size if the
	 * size really could be anything between 0 and 2**64 bytes.
	 * We expect the sizes to be less than 16 TB for some time,
	 * so why do a bunch of reads that are larger than that?
	 * However, this algorithm *will* work for sizes of greater
	 * than 16 TB.  We're just not optimizing for those sizes.)
	 */

	/*
	 * XXX lint uses 32-bit arithmetic for doing flow analysis.
	 * We're using > 32-bit constants here.  Therefore, its flow
	 * analysis is wrong.  For the time being, ignore complaints
	 * from it about the body of the for() being unreached.
	 */
	for (cur_db_off = SECTORS_PER_TERABYTE * 4;
	    (min_fail == 0) && (cur_db_off < FS_SIZE_UPPER_LIMIT);
	    cur_db_off += 4 * SECTORS_PER_TERABYTE) {
		if ((llseek(fd, (offset_t)(cur_db_off * DEV_BSIZE),
		    SEEK_SET) == -1) ||
		    (read(fd, buf, DEV_BSIZE) != DEV_BSIZE))
			min_fail = cur_db_off;
		else
			max_succeed = cur_db_off;
	}

	/*
	 * XXX Same lint flow analysis problem as above.
	 */
	if (min_fail == 0)
		return (0);

	/*
	 * We now know that the size of the device is less than
	 * min_fail and greater than or equal to max_succeed.  Now
	 * keep splitting the difference until the actual size in
	 * sectors in known.  We also know that the difference
	 * between max_succeed and min_fail at this time is
	 * 4 * SECTORS_PER_TERABYTE, which is a power of two, which
	 * simplifies the math below.
	 */

	while (min_fail - max_succeed > 1) {
		cur_db_off = max_succeed + (min_fail - max_succeed)/2;
		if (((llseek(fd, (offset_t)(cur_db_off * DEV_BSIZE),
		    SEEK_SET)) == -1) ||
		    ((read(fd, buf, DEV_BSIZE)) != DEV_BSIZE))
			min_fail = cur_db_off;
		else
			max_succeed = cur_db_off;
	}

	/* the size is the last successfully read sector offset plus one */
	return (max_succeed + 1);
}

static void
vfileerror(fsck_ino_t cwd, fsck_ino_t ino, caddr_t fmt, va_list ap)
{
	struct dinode *dp;
	char pathbuf[MAXPATHLEN + 1];

	vpwarn(fmt, ap);
	(void) putchar(' ');
	pinode(ino);
	(void) printf("\n");
	getpathname(pathbuf, cwd, ino);
	if (ino < UFSROOTINO || ino > maxino) {
		pfatal("NAME=%s\n", pathbuf);
		return;
	}
	dp = ginode(ino);
	if (ftypeok(dp))
		pfatal("%s=%s\n", file_id(ino, dp->di_mode), pathbuf);
	else
		pfatal("NAME=%s\n", pathbuf);
}

void
direrror(fsck_ino_t ino, caddr_t fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfileerror(ino, ino, fmt, ap);
	va_end(ap);
}

static void
vdirerror(fsck_ino_t ino, caddr_t fmt, va_list ap)
{
	vfileerror(ino, ino, fmt, ap);
}

void
fileerror(fsck_ino_t cwd, fsck_ino_t ino, caddr_t fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfileerror(cwd, ino, fmt, ap);
	va_end(ap);
}

/*
 * Adds the given inode to the orphaned-directories list, limbo_dirs.
 * Assumes that the caller has set INCLEAR in the inode's statemap[]
 * entry.
 *
 * With INCLEAR set, the inode will get ignored by passes 2 and 3,
 * meaning it's effectively an orphan.  It needs to be noted now, so
 * it will be remembered in pass 4.
 */

void
add_orphan_dir(fsck_ino_t ino)
{
	if (tsearch((void *)ino, &limbo_dirs, ino_t_cmp) == NULL)
		errexit("add_orphan_dir: out of memory");
}

/*
 * Remove an inode from the orphaned-directories list, presumably
 * because it's been cleared.
 */
void
remove_orphan_dir(fsck_ino_t ino)
{
	(void) tdelete((void *)ino, &limbo_dirs, ino_t_cmp);
}

/*
 * log_setsum() and log_checksum() are equivalent to lufs.c:setsum()
 * and lufs.c:checksum().
 */
static void
log_setsum(int32_t *sp, int32_t *lp, int nb)
{
	int32_t csum = 0;

	*sp = 0;
	nb /= sizeof (int32_t);
	while (nb--)
		csum += *lp++;
	*sp = csum;
}

static int
log_checksum(int32_t *sp, int32_t *lp, int nb)
{
	int32_t ssum = *sp;

	log_setsum(sp, lp, nb);
	if (ssum != *sp) {
		*sp = ssum;
		return (0);
	}
	return (1);
}
