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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/param.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/shm.h>
#include <nsctl.h>

#include <sys/nsctl/sd_cache.h>
#include <sys/nsctl/sd_conf.h>


#define	BLK_CMP 16
#define	BYTES_CMP (BLK_CMP*512)

#define	min(a, b) ((a) > (b) ? (b) : (a))

int bflag = 0;

int
main(argc, argv)
	int argc;
	char *argv[];
{
	int fd1, fd2, curpos, r;
	nsc_size_t blocks, blocks2;
	nsc_fd_t *sdfd1, *sdfd2;
	char buf1[BYTES_CMP], buf2[BYTES_CMP];
	int count;
	int c;

	if (argc < 3) {
		(void) printf("Usage: spd_dcmp {-b} <path1> <path2> \n");
		(void) printf("Example:  spd_dcmp /dev/rdsk/7d4 "
		    "/dev/rdsk/13d9\n");
		(void) printf("Example:  spd_dcmp -b /dev/rdsk/7d4 "
		    "/dev/rdsk/13d9\n");
		(void) printf(" -b : Break on Finding the first Mismatch\n");
		exit(1);
	}

	while ((c = getopt(argc, argv, "b")) != -1) {
		switch (c) {
		case 'b':
			bflag = 1;
			break;
		}
	}
	if (bflag) {
		sdfd1 = nsc_open(argv[2], NSC_DEVICE, O_RDONLY);
	} else {
		sdfd1 = nsc_open(argv[1], NSC_DEVICE, O_RDONLY);
	}
	if (!sdfd1) {
		perror("nsc_open");
		exit(errno);
	}

	fd1 = nsc_fileno(sdfd1);
	if (fd1 < 0) {
		perror("open");
		exit(errno);
	}
	if (bflag) {
		sdfd2 = nsc_open(argv[3], NSC_DEVICE, O_RDONLY);
	} else {
		sdfd2 = nsc_open(argv[2], NSC_DEVICE, O_RDONLY);
	}
	if (!sdfd2) {
		perror("nsc_open");
		exit(errno);
	}
	fd2 = nsc_fileno(sdfd2);
	if (fd2 < 0) {
		perror("open");
		exit(errno);
	}

	r = nsc_partsize(sdfd1, &blocks);
	if (r < 0 || blocks == 0) {
		perror("can't get filesize1");
		return (1);
	}
	r = nsc_partsize(sdfd2, &blocks2);
	if (r < 0 || blocks2 == 0) {
		perror("can't get filesize2");
		return (1);
	}

	(void) printf("Size1: %d (%d MB), Size2: %d (%d MB)\n", blocks,
	    blocks >> 11, blocks2, blocks2 >> 11);

	curpos = 0;
	while (curpos < blocks) {
		r = pread(fd1, buf1, min((blocks-curpos), BLK_CMP) * 512,
		    (curpos << SCTRSHFT));
		if (r < 0) {
			perror("read");
			exit(errno);
		} else if (r == 0)
			break;

		r = pread(fd2, buf2, min((blocks-curpos), BLK_CMP) * 512,
		    (curpos << SCTRSHFT));
		if (r < 0) {
			perror("read");
			exit(errno);
		} else if (r == 0)
			break;

		if (bcmp(buf1, buf2, min((blocks-curpos), BLK_CMP) * 512)) {
			(void) printf("\nERROR: data mismatch filepos:%d bl\n",
			    curpos);
			if (bflag) {
				close(fd1);
				close(fd2);
				exit(1);
			}
		}
		curpos += min((blocks-curpos), BLK_CMP);

		if (!bflag) {
			count ++;
			if ((count % 64) == 0) {
				if (count < 3200) {
					(void) printf(".");
					fflush(stdout);
				} else {
					(void) printf(". %10d bl %7d MB\n",
					    curpos, curpos >> 11);
					fflush(stdout);
					count = 0;
				}
			}
		}
	}
	if (!bflag) {
		(void) printf(". %10d bl %7d MB\n", curpos, curpos >> 11);
	}
	close(fd1);
	close(fd2);
	exit(0);
}
