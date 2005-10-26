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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * clri filsys inumber ...
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/mntent.h>

#include <sys/vnode.h>
#include <sys/fs/ufs_inode.h>
#include <sys/fs/ufs_fs.h>

#include "roll_log.h"

#define	ISIZE	(sizeof (struct dinode))
#define	NI	(MAXBSIZE/ISIZE)

static struct dinode buf[NI];

static union {
	char		dummy[SBSIZE];
	struct fs	sblk;
} sb_un;
#define	sblock sb_un.sblk

static int status;

static int read_sb(int fd, const char *dev);
static int isnumber(const char *s);

int
main(int argc, char *argv[])
{
	int		i, f;
	unsigned int	n;
	int		j;
	offset_t	off;
	int32_t		gen;
	time_t		t;
	int		sbrr;

	if (argc < 3) {
		(void) printf("ufs usage: clri filsys inumber ...\n");
		return (35);
	}
	f = open64(argv[1], 2);
	if (f < 0) {
		(void) printf("cannot open %s\n", argv[1]);
		return (35);
	}

	if ((sbrr = read_sb(f, argv[1])) != 0) {
		return (sbrr);
	}

	if ((sblock.fs_magic != FS_MAGIC) &&
	    (sblock.fs_magic != MTB_UFS_MAGIC)) {
		(void) printf("bad super block magic number\n");
		return (35);
	}

	if (sblock.fs_magic == FS_MAGIC &&
	    (sblock.fs_version != UFS_EFISTYLE4NONEFI_VERSION_2 &&
	    sblock.fs_version != UFS_VERSION_MIN)) {
		(void) printf(
		    "unrecognized version of UFS on-disk format: %d\n",
		    sblock.fs_version);
		return (35);
	}

	if (sblock.fs_magic == MTB_UFS_MAGIC &&
	    (sblock.fs_version > MTB_UFS_VERSION_1 ||
	    sblock.fs_version < MTB_UFS_VERSION_MIN)) {
		(void) printf(
		    "unrecognized version of UFS on-disk format: %d\n",
		    sblock.fs_version);
		return (35);
	}

	/* If fs is logged, roll the log. */
	if (sblock.fs_logbno) {
		switch (rl_roll_log(argv[1])) {
		case RL_SUCCESS:
			/*
			 * Reread the superblock.  Rolling the log may have
			 * changed it.
			 */
			if ((sbrr = read_sb(f, argv[1])) != 0) {
				return (sbrr);
			}
			break;
		case RL_SYSERR:
			(void) printf("Warning: Cannot roll log for %s.  %s.  "
				"Inodes will be cleared anyway.\n",
				argv[1], strerror(errno));
			break;
		default:
			(void) printf("Cannot roll log for %s.  "
				"Inodes will be cleared anyway.\n",
				argv[1]);
			break;
		}
	}

	for (i = 2; i < argc; i++) {
		if (!isnumber(argv[i])) {
			(void) printf("%s: is not a number\n", argv[i]);
			status = 1;
			continue;
		}
		n = atoi(argv[i]);
		if (n == 0) {
			(void) printf("%s: is zero\n", argv[i]);
			status = 1;
			continue;
		}
		off = fsbtodb(&sblock, itod(&sblock, n));
		off *= DEV_BSIZE;
		(void) llseek(f, off, 0);
		if (read(f, (char *)buf, sblock.fs_bsize) != sblock.fs_bsize) {
			(void) printf("%s: read error\n", argv[i]);
			status = 1;
		}
	}
	if (status)
		return (status+31);

	/*
	 * Update the time in superblock, so fsck will check this filesystem.
	 */
	(void) llseek(f, (offset_t)(SBLOCK * DEV_BSIZE), 0);
	(void) time(&t);
	sblock.fs_time = (time32_t)t;
	if (write(f, &sblock, SBSIZE) != SBSIZE) {
		(void) printf("cannot update %s\n", argv[1]);
		return (35);
	}

	for (i = 2; i < argc; i++) {
		n = atoi(argv[i]);
		(void) printf("clearing %u\n", n);
		off = fsbtodb(&sblock, itod(&sblock, n));
		off *= DEV_BSIZE;
		(void) llseek(f, off, 0);
		(void) read(f, (char *)buf, sblock.fs_bsize);
		j = itoo(&sblock, n);
		gen = buf[j].di_gen;
		memset(&buf[j], 0, ISIZE);
		buf[j].di_gen = gen + 1;
		(void) llseek(f, off, 0);
		(void) write(f, (char *)buf, sblock.fs_bsize);
	}
	if (status)
		return (status+31);
	(void) close(f);
	return (0);
}

static int
isnumber(const char *s)
{
	int c;

	while ((c = *s++) != '\0')
		if (c < '0' || c > '9')
			return (0);
	return (1);
}

static int
read_sb(int fd, const char *dev)
{
	(void) llseek(fd, (offset_t)(SBLOCK * DEV_BSIZE), 0);
	if (read(fd, &sblock, SBSIZE) != SBSIZE) {
		(void) printf("cannot read %s\n", dev);
		return (35);
	} else {
		return (0);
	}
}
