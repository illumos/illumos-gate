/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2012 Jilin Xpd <jilinxpd@gmail.com>
 * Copyright 2018 Nexenta Systems, Inc.
 * Copyright (c) 2018, Joyent, Inc.
 */

/*
 * Using mmap, make a file and padding it with random chars.
 */

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <time.h>

void
usage(void)
{
	fprintf(stderr,
	    "usage: mkfile_mmap -n <size>[b|k|m|g] -f <filename>\n");
	exit(1);
}

int
main(int argc, char **argv)
{
	char *suffix;
	char *filename = NULL;
	char *file_addr;
	char *p, *q;
	off_t offset;
	size_t filesize;
	size_t blksize;
	size_t numblks;
	size_t cnt = 1;
	size_t mul = 1;
	size_t i;
	int mret = 0;
	int c, fid;

	/*
	 * parse arguments
	 */
	while ((c = getopt(argc, argv, "n:f:")) != -1) {
		switch (c) {
		case 'n':
			cnt = (size_t)strtoul(optarg, &suffix, 0);
			if (cnt == 0)
				goto bad_n_arg;
			switch (*suffix) {
			case '\0':
			case 'b':
				mul = 1;
				break;
			case 'k':
				mul = 1024;
				break;
			case 'm':
				mul = (1024 * 1024);
				break;
			case 'g':
				mul = (1024 * 1024 * 1024);
				break;
			default:
			bad_n_arg:
				fprintf(stderr, "-n %s: invalid size\n",
				    optarg);
				return (1);
			}
			cnt = cnt * mul;
			break;

		case 'f': /* target file */
			filename = optarg;
			break;

		case ':':   /* missing optarg */
			fprintf(stderr,
			    "Option -%c requires an arg\n", optopt);
			usage();
			break;
		case '?':
			fprintf(stderr,
			    "Unrecognized option: -%c\n", optopt);
			usage();
			break;
		}
	}

	/* open test file */
	fid = open(filename, O_RDWR | O_CREAT | O_TRUNC,
	    S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH);
	if (fid == -1) {
		fprintf(stderr, "open %s error=%d\n", filename, errno);
		mret = 1;
		goto exit3;
	}

	/* extend file */
	filesize = cnt;
	if (ftruncate(fid, filesize) == -1) {
		fprintf(stderr, "ftrunc %s error=%d\n", filename, errno);
		mret = 1;
		goto exit2;
	}

#define	K 1024

	blksize = 64 * K * K;
	numblks = (filesize + blksize - 1) / blksize;
	for (i = 0; i < numblks && mret == 0; i++) {

		offset = i*blksize;
		if (offset + blksize > filesize)
			blksize = filesize - offset;

		/* map file */
		file_addr = mmap(NULL, blksize,
		    PROT_READ | PROT_WRITE, MAP_SHARED, fid, offset);
		if (file_addr == MAP_FAILED) {
			fprintf(stderr, "mmap %s error=%d\n", filename, errno);
			mret = 1;
			break;
		}

		/* tag each block (to aid debug) */
		p = file_addr;
		q = file_addr + blksize - K;
		memset(p, ' ', K);
		snprintf(p, K, "\nblk=%d\n\n", i);
		p += K;

		/* fill something into mapped addr */
		while (p < q) {
			memset(p, ' ', K);
			snprintf(p, K, "\noff=0x%x\n\n",
			    (i * blksize) + (p - file_addr));
			p += K;
		}

		/* sync mapped pages to file */
		if (msync(file_addr, blksize, MS_SYNC) == -1) {
			fprintf(stderr, "msync %s error=%d\n", filename, errno);
			mret = 1;
		}

		/* unmap file */
		if (munmap(file_addr, blksize) == -1) {
			fprintf(stderr, "unmap %s error=%d\n", filename, errno);
			mret = 1;
		}
	}

	/* close file */
exit2:
	close(fid);
exit3:
	return (mret);
}
