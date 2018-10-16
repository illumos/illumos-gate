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
 */

/*
 * use mmap to copy data from src file to des file,
 * with given flags and modes.
 * the src & des file should exist and have the same size.
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

void
usage(void)
{
	fprintf(stderr,
	    "usage: "
	    "prot_mmap -o <r|w> <r|w>"
	    " -m <r|w|s|p> <r|w|s|p>"
	    " -f <srcfile> <desfile>\n");
	exit(1);
}

int
main(int argc, char **argv)
{
	struct stat sb;
	char *src_addr, *des_addr;
	char *src_file = NULL, *des_file = NULL;
	off_t offset;
	size_t filesize;
	size_t blksize;
	size_t numblks;
	size_t i, j;
	int src_fid, des_fid;
	int mret = 0;
	int flags0 = 0, mflags0 = 0, prot0 = 0; /* flags for src file */
	int flags1 = 0, mflags1 = 0, prot1 = 0; /* flags for des file */

	/*
	 * parse arguments
	 * Not getopt because -o -m -f all have 2 optargs each.
	 */
	if (argc != 10) {
		usage();
	}
	for (i = 1; i < argc; ) {
		switch (argv[i][1]) {
			case 'o': /* options for open() */
				i++;
				for (j = 0; argv[i][j]; j++) {
					if (argv[i][j] == 'r')
						flags0 |= O_RDONLY;
					else if (argv[i][j] == 'w')
						flags0 |= O_WRONLY;
				}
				if ((flags0 & (O_RDONLY | O_WRONLY)) ==
				    (O_RDONLY | O_WRONLY))
					flags0 = O_RDWR;
				i++;
				for (j = 0; argv[i][j]; j++) {
					if (argv[i][j] == 'r')
						flags1 |= O_RDONLY;
					else if (argv[i][j] == 'w')
						flags1 |= O_WRONLY;
				}
				if ((flags1 & (O_RDONLY | O_WRONLY)) ==
				    (O_RDONLY | O_WRONLY))
					flags1 = O_RDWR;
				i++;
				break;
			case 'm': /* options for mmap() */
				i++;
				for (j = 0; argv[i][j]; j++) {
					if (argv[i][j] == 'r')
						prot0 |= PROT_READ;
					else if (argv[i][j] == 'w')
						prot0 |= PROT_WRITE;
					else if (argv[i][j] == 's')
						mflags0 |= MAP_SHARED;
					else if (argv[i][j] == 'p')
						mflags0 |= MAP_PRIVATE;
				}
				i++;
				for (j = 0; argv[i][j]; j++) {
					if (argv[i][j] == 'r')
						prot1 |= PROT_READ;
					else if (argv[i][j] == 'w')
						prot1 |= PROT_WRITE;
					else if (argv[i][j] == 's')
						mflags1 |= MAP_SHARED;
					else if (argv[i][j] == 'p')
						mflags1 |= MAP_PRIVATE;
				}
				i++;
				break;
			case 'f': /* src file and des file */
				i++;
				src_file = argv[i];
				i++;
				des_file = argv[i];
				i++;
		}
	}

	/* source file */
	src_fid = open(src_file, flags0);
	if (src_fid == -1) {
		fprintf(stderr, "open %s error=%d\n", src_file, errno);
		return (1);
	}
	/* destination file */
	des_fid = open(des_file, flags1);
	if (des_fid == -1) {
		fprintf(stderr, "open %s error=%d\n", des_file, errno);
		mret = 1;
		goto exit3;
	}

	/* get file size */
	if (fstat(src_fid, &sb) == -1) {
		fprintf(stderr, "fstat %s error=%d\n", src_file, errno);
		mret = 1;
		goto exit2;
	}
	filesize = sb.st_size;
	if (filesize < 4096) {
		fprintf(stderr, "file too small\n");
		mret = 1;
		goto exit2;
	}

	if (fstat(des_fid, &sb) == -1) {
		fprintf(stderr, "fstat %s error=%d\n", des_file, errno);
		mret = 1;
		goto exit2;
	}
	if (filesize != sb.st_size) {
		fprintf(stderr, "file sizes differ\n");
		mret = 1;
		goto exit2;
	}

	/* copy data */
	blksize = 64 * 1024 * 1024;
	numblks = (filesize + blksize - 1) / blksize;
	for (i = 0; i < numblks && mret == 0; i++) {

		offset = (i % numblks) * blksize;
		if (offset + blksize > filesize)
			blksize = filesize - offset;

		/* map file */
		src_addr = mmap(NULL, blksize, prot0, mflags0, src_fid, offset);
		if (src_addr == MAP_FAILED) {
			fprintf(stderr, "mmap %s error=%d\n", src_file, errno);
			mret = 1;
			break;
		}
		des_addr = mmap(NULL, blksize, prot1, mflags1, des_fid, offset);
		if (des_addr == MAP_FAILED) {
			fprintf(stderr, "mmap %s error=%d\n", des_file, errno);
			mret = 1;
			goto exit1;
		}

		/* cp data from src addr to des addr */
		memcpy(des_addr, src_addr, blksize);
		/* sync mapped pages to file */
		if (msync(des_addr, blksize, MS_SYNC) == -1) {
			fprintf(stderr, "msync %s error=%d\n", des_file, errno);
			mret = 1;
		}

		/* unmap file */
		if (munmap(des_addr, blksize) == -1) {
			fprintf(stderr, "munmap %s error=%d\n",
			    des_file, errno);
			mret = 1;
		}
exit1:
		if (munmap(src_addr, blksize) == -1) {
			fprintf(stderr, "munmap %s error=%d\n",
			    src_file, errno);
			mret = 1;
		}
	}

	/* close file */
exit2:
	close(des_fid);
exit3:
	close(src_fid);

	return (mret);
}
