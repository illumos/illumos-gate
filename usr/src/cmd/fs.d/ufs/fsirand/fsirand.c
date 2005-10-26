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
 * fsirand installs random inode generation numbers on all the inodes on
 * device <special>, and also installs a file system ID in the superblock.
 * This helps increase the security of  file systems exported by NFS.
 */

#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <strings.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/fs/ufs_fs.h>
#include <sys/vnode.h>
#include <sys/fs/ufs_inode.h>

long fsbuf[(SBSIZE / sizeof (long))];
struct dinode dibuf[8192/sizeof (struct dinode)];

int
main(int argc, char *argv[])
{
	struct fs *fs;
	int fd;
	char *dev;
	int bno;
	struct dinode *dip;
	int inum, imax;
	int i, n;
	offset_t seekaddr;
	int bsize;
	int pflag = 0;
	struct timeval timeval;

	argv++;
	argc--;
	if (argc > 0 && strcmp(*argv, "-p") == 0) {
		pflag++;
		argv++;
		argc--;
	}
	if (argc <= 0) {
		(void) fprintf(stderr, "Usage: fsirand [-p] special\n");
		exit(1);
	}
	dev = *argv;
	fd = open64(dev, pflag ? O_RDONLY : O_RDWR);
	if (fd == -1) {
		(void) fprintf(stderr, "fsirand: Cannot open %s: %s\n", dev,
		    strerror(errno));
		exit(1);
	}
	if (llseek(fd, (offset_t)SBLOCK * DEV_BSIZE, 0) == -1) {
		(void) fprintf(stderr,
		    "fsirand: Seek to superblock failed: %s\n",
		    strerror(errno));
		exit(1);
	}
	fs = (struct fs *)fsbuf;
	if ((n = read(fd, (char *)fs, SBSIZE)) != SBSIZE) {
		(void) fprintf(stderr,
		    "fsirand: Read of superblock failed: %s\n",
		    n == -1 ? strerror(errno) : "Short read");
		exit(1);
	}
	if ((fs->fs_magic != FS_MAGIC) &&
	    (fs->fs_magic != MTB_UFS_MAGIC)) {
		(void) fprintf(stderr,
	"fsirand: Not a file system (bad magic number in superblock)\n");
		exit(1);
	}
	if (fs->fs_magic == FS_MAGIC &&
	    (fs->fs_version != UFS_EFISTYLE4NONEFI_VERSION_2 &&
	    fs->fs_version != UFS_VERSION_MIN)) {
		(void) fprintf(stderr,
	"fsirand: Unrecognized UFS format version number %d (in superblock)\n",
		    fs->fs_version);
		exit(1);
	}
	if (fs->fs_magic == MTB_UFS_MAGIC &&
	    (fs->fs_version > MTB_UFS_VERSION_1 ||
	    fs->fs_version < MTB_UFS_VERSION_MIN)) {
		(void) fprintf(stderr,
	"fsirand: Unrecognized UFS format version number %d (in superblock)\n",
		    fs->fs_version);
		exit(1);
	}
	if (pflag) {
		(void) printf("fsid: %x %x\n", fs->fs_id[0], fs->fs_id[1]);
	} else {
		n = getpid();
		(void) gettimeofday(&timeval, (struct timezone *)NULL);
		srand48((long)(timeval.tv_sec + timeval.tv_usec + n));
	}
	bsize = INOPB(fs) * sizeof (struct dinode);
	inum = 0;
	imax = fs->fs_ipg * fs->fs_ncg;
	while (inum < imax) {
		bno = itod(fs, inum);
		seekaddr = (offset_t)fsbtodb(fs, bno) * DEV_BSIZE;
		if (llseek(fd, seekaddr, 0) == -1) {
			(void) fprintf(stderr,
			    "fsirand: Seek to %ld %ld failed: %s\n",
			    ((off_t *)&seekaddr)[0], ((off_t *)&seekaddr)[1],
			    strerror(errno));
			exit(1);
		}
		n = read(fd, (char *)dibuf, bsize);
		if (n != bsize) {
			(void) fprintf(stderr,
			    "fsirand: Read of ilist block failed: %s\n",
			    n == -1 ? strerror(errno) : "Short read");
			exit(1);
		}
		for (dip = dibuf; dip < &dibuf[INOPB(fs)]; dip++) {
			if (pflag) {
				(void) printf("ino %d gen %x\n", inum,
				    dip->di_gen);
			} else {
				dip->di_gen = lrand48();
			}
			inum++;
		}
		if (!pflag) {
			if (llseek(fd, seekaddr, 0) == -1) {
				(void) fprintf(stderr,
				    "fsirand: Seek to %ld %ld failed: %s\n",
				    ((off_t *)&seekaddr)[0],
				    ((off_t *)&seekaddr)[1],
				    strerror(errno));
				exit(1);
			}
			n = write(fd, (char *)dibuf, bsize);
			if (n != bsize) {
				(void) fprintf(stderr,
				"fsirand: Write of ilist block failed: %s\n",
				    n == -1 ? strerror(errno) : "Short write");
				exit(1);
			}
		}
	}
	if (!pflag) {
		(void) gettimeofday(&timeval, (struct timezone *)NULL);
		fs->fs_id[0] = timeval.tv_sec;
		fs->fs_id[1] = timeval.tv_usec + getpid();
		if (llseek(fd, (offset_t)SBLOCK * DEV_BSIZE, 0) == -1) {
			(void) fprintf(stderr,
			    "fsirand: Seek to superblock failed: %s\n",
			    strerror(errno));
			exit(1);
		}
		if ((n = write(fd, (char *)fs, SBSIZE)) != SBSIZE) {
			(void) fprintf(stderr,
			    "fsirand: Write of superblock failed: %s\n",
			    n == -1 ? strerror(errno) : "Short write");
			exit(1);
		}
	}
	for (i = 0; i < fs->fs_ncg; i++) {
		seekaddr = (offset_t)fsbtodb(fs, cgsblock(fs, i)) * DEV_BSIZE;
		if (llseek(fd,  seekaddr, 0) == -1) {
			(void) fprintf(stderr,
			"fsirand: Seek to alternate superblock failed: %s\n",
			    strerror(errno));
			exit(1);
		}
		if (pflag) {
			if ((n = read(fd, (char *)fs, SBSIZE)) != SBSIZE) {
				(void) fprintf(stderr,
			"fsirand: Read of alternate superblock failed: %s\n",
				    n == -1 ? strerror(errno) : "Short read");
				exit(1);
			}
			if ((fs->fs_magic != FS_MAGIC) &&
			    (fs->fs_magic != MTB_UFS_MAGIC)) {
				(void) fprintf(stderr,
				    "fsirand: Not a valid file system (bad "
				    "magic number in alternate superblock)\n");
				exit(1);
			}
		} else {
			if ((n = write(fd, (char *)fs, SBSIZE)) != SBSIZE) {
				(void) fprintf(stderr,
			"fsirand: Write of alternate superblock failed: %s\n",
				    n == -1 ? strerror(errno) : "Short write");
				exit(1);
			}
		}
	}
	return (0);
}
