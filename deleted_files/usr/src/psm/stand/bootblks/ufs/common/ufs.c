/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 1991-1994, 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* from  "@(#)boot/ufssys.c       1.1 90/03/28 SMI" */

/*
 * Basic file system reading code for standalone I/O system.
 */

#include <sys/param.h>
#include <sys/vnode.h>
#include <sys/fs/ufs_fsdir.h>
#include <sys/fs/ufs_fs.h>
#include <sys/fs/ufs_inode.h>

#include "iob.h"
#include "cbootblk.h"

/*
 *  private definitions of ufs macros from sys/fs/ufs_fs.h
 *  due to boot block size problems, these macros are coded
 *  to use the older narrow file offset type (31 bit). This
 *  saves a lot of code space. Since we will never encounter
 *  a large file here, it is safe to cast offset_t to off_t.
 */

#define	bb_fragroundup(fs, size)	/* roundup(size, fs->fs_fsize) */ \
	((off_t)((size) + (fs)->fs_fsize - 1) & (off_t)(fs)->fs_fmask)

#define	bb_blksize(fs, ip, lbn) \
	(((lbn) >= NDADDR || \
	(off_t)(ip)->i_size >= (off_t)((lbn) + 1) << (fs)->fs_bshift) \
	    ? (fs)->fs_bsize \
	    : (bb_fragroundup(fs, blkoff(fs, (off_t)(ip)->i_size))))

#define	NULL	0

static struct direct *readdir(struct iob *, int *);
static ino_t dlook(char *, struct iob *);
static int getblock(struct iob *io);

char fscompname[] = "ufsboot";

static struct iob iob[1];	/* only one open file! */

static int
openi(ino_t n, struct iob *io)
{
	struct dinode *dp;
	struct fs *fs = &io->iob_fs;

	io->i_saio.si_offset = 0;
	if (devbread(io->i_si, io->i_buf,
	    fsbtodb(fs, itod(fs, n)), fs->fs_bsize) != fs->fs_bsize)
		return (0);
	dp = (struct dinode *)io->i_buf;
	io->i_ino.i_ic = dp[itoo(fs, n)].di_ic;
	return (1);
}

static ino_t
find(char *nm, struct iob *file)
{
	char *q;
	char c;
	ino_t n;
	char pathbuf[MAXPATHLEN], *path;
	char *link;
	size_t linklen;
	int fmt = IFDIR;

	if (nm == NULL || *nm == '\0')
		return (0);
	bcopy(nm, pathbuf, strlen(nm) + 1);
root:
	path = pathbuf;
	if (openi((ino_t)UFSROOTINO, file) == 0)
		return (0);
	while (*path) {
		while (*path == '/')
			path++;
		q = path;
		while (*q != '/' && *q != '\0')
			q++;
		c = *q;
		*q = '\0';

		if ((n = dlook(path, file)) != 0) {

			*q = c;
			if (openi(n, file) == 0)
				return (0);
			switch (fmt = (file->i_ino.i_smode & IFMT)) {
			case IFREG:
			case IFDIR:
				break;

			case IFLNK:
				if (getblock(file) != 0)
					return (0);
				link = (char *)file->i_saio.si_ma;
				linklen = strlen(link);
				if (*link == '/')
					path = pathbuf;
				/*
				 * Copy unprocessed pathname up & prepend link
				 * (Yes, this bcopy handles overlapping args)
				 */
				bcopy(q, path + linklen, strlen(q) + 1);
				bcopy(link, path, linklen);
				path = pathbuf;
				goto root;
				/*NOTREACHED*/

			default:
				return (0);
			}
			if (c == '\0')
				break;
			path = q;
			continue;
		} else
			return (0);
	}

	return (fmt == IFREG ? n : 0);
}

static daddr_t
sbmap(struct iob *io, daddr_t bn)
{
	struct bnode *ip;
	int i, j, sh;
	daddr_t nb, *bap;

	/* These are the pools of buffers, iob's, etc. */

	static union {
		char	b[NIADDR+1][MAXBSIZE];
		daddr_t	*dummy;	/* force alignment */
	} b;
	static daddr_t blknos[NIADDR+1];

	ip = &io->i_ino;

	/*
	 * blocks 0..NDADDR are direct blocks
	 */
	if (bn < NDADDR)
		return (ip->i_db[bn]);

	/*
	 * addresses NIADDR have single and double indirect blocks.
	 * the first step is to determine how many levels of indirection.
	 */
	sh = 1;
	bn -= NDADDR;
	for (j = NIADDR; j > 0; j--) {
		sh *= NINDIR(&io->iob_fs);
		if (bn < sh)
			break;
		bn -= sh;
	}
	if (j == 0)
		return ((daddr_t)0);

	/*
	 * fetch the first indirect block address from the inode
	 */
	nb = ip->i_ib[NIADDR - j];
	if (nb == 0)
		return ((daddr_t)0);

	/*
	 * fetch through the indirect blocks
	 */
	for (; j <= NIADDR; j++) {
		if (blknos[j] != nb) {
			if (devbread(io->i_si, b.b[j],
			    fsbtodb(&io->iob_fs, nb),
			    io->iob_fs.fs_bsize) != io->iob_fs.fs_bsize)
				return ((daddr_t)0);
			blknos[j] = nb;
		}
		bap = (daddr_t *)b.b[j];
		sh /= NINDIR(&io->iob_fs);
		i = (bn / sh) % NINDIR(&io->iob_fs);
		nb = bap[i];
		if (nb == 0)
			return ((daddr_t)0);
	}
	return (nb);
}

static ino_t
dlook(char *s, struct iob *io)
{
	struct direct *dp;
	struct bnode *ip;
	int len, loc = 0;

	ip = &io->i_ino;
	if (s == NULL || *s == '\0')
		return (0);
	if ((ip->i_smode & IFMT) != IFDIR || ip->i_size == 0)
		return (0);
	len = strlen(s);
	for (dp = readdir(io, &loc); dp != NULL; dp = readdir(io, &loc)) {
		if (dp->d_ino == 0)
			continue;
		if (dp->d_namlen == len && strcmp(s, dp->d_name) == 0)
			return (dp->d_ino);
	}
	return (0);
}

/*
 * get next entry in a directory.
 */
static struct direct *
readdir(struct iob *io, int *loc_p)
{
	struct direct *dp;
	daddr_t lbn, d;
	int off;
	int loc = *loc_p;
	int bsize;

	for (;;) {
		if (loc >= io->i_ino.i_size)
			return (NULL);
		off = blkoff(&io->iob_fs, loc);
		if (off == 0) {
			lbn = lblkno(&io->iob_fs, loc);
			if ((d = sbmap(io, lbn)) == 0)
				return (NULL);
			bsize = bb_blksize(&io->iob_fs, &io->i_ino, lbn);
			if (devbread(io->i_si, io->i_buf,
			    fsbtodb(&io->iob_fs, d), bsize) != bsize)
				return (NULL);
		}
		dp = (struct direct *)(io->i_buf + off);
		*loc_p = (loc += dp->d_reclen);
		if (dp->d_ino == 0)
			continue;
		return (dp);
	}
}

static int
getblock(struct iob *io)
{
	struct fs *fs;
	int off, size, diff;
	daddr_t lbn;

	diff = io->i_ino.i_size - io->i_saio.si_offset;
	if (diff <= 0)
		return (-1);
	fs = &io->iob_fs;
	lbn = lblkno(fs, io->i_saio.si_offset);
	off = blkoff(fs, io->i_saio.si_offset);
	size = bb_blksize(fs, &io->i_ino, lbn);
	io->i_saio.si_cc = size;
	if (devbread(io->i_si, io->i_buf,
	    fsbtodb(fs, sbmap(io, lbn)), size) != size)
		return (-1);
	if (io->i_saio.si_offset - off + size >= io->i_ino.i_size)
		io->i_saio.si_cc = diff + off;
	io->i_saio.si_cc -= off;

	io->i_saio.si_ma = &io->i_buf[off];
	return (0);
}

int
readfile(int fd, char *buf, int count)
{
	struct iob *io = &iob[fd];
	int i, j;

	if (io->i_saio.si_offset + count > io->i_ino.i_size)
		count = io->i_ino.i_size - io->i_saio.si_offset;
	if ((i = count) <= 0)
		return (0);
	while (i > 0) {
		if (io->i_saio.si_cc <= 0) {
			if (getblock(io) == -1)
				return (0);
		}
		j = (i < io->i_saio.si_cc) ? i : io->i_saio.si_cc;
		bcopy(io->i_saio.si_ma, buf, (size_t)j);
		buf += j;
		io->i_saio.si_ma += j;
		io->i_saio.si_offset += j;
		io->i_saio.si_cc -= j;
		i -= j;
	}
	return (count);
}

/*
 * Open a file.
 */
int
openfile(char *device, char *pathname)
{
	struct iob *io = &iob[0];	/* only one open file! */

	io->i_ino.i_dev = 0;
	if ((io->i_si = devopen(device)) == NULL)
		return (-1);	/* if devopen fails, open fails */

	/* Pseudo-mount a file system; read the superblock. */

	if (devbread(io->i_si, &io->iob_fs, SBLOCK, SBSIZE) != SBSIZE)
		goto failed;
	if (io->iob_fs.fs_magic != FS_MAGIC) {
		puts("bootblk: not a UFS file system.\n");
		goto failed;
	}
	if (find(pathname, io) == 0)
		goto failed;
	io->i_saio.si_offset = io->i_saio.si_cc = 0;

	return (0);			/* only one open file! */
failed:
	(void) devclose(io->i_si);
	return (-1);
}

int
closefile(int fd)
{
	struct iob *io = &iob[fd];

	return (devclose(io->i_si));
}

/*
 * This version of seek() only performs absolute seeks (whence == 0).
 */
void
seekfile(int fd, off_t addr)
{
	struct iob *io = &iob[fd];

	io->i_saio.si_offset = addr;
	io->i_saio.si_cc = 0;
}
