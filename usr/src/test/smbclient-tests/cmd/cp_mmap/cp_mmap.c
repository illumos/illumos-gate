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
 * Copy a file from src to dest, using mmap to copy the data,
 * with either contiguous or discontiguous mappings.
 * (Jilin calls discontiguous "discrete" below.)
 */

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
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
	    "usage: cp_mmap -t {d|c} -f <srcfile> <desfile>\n");
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
	size_t pagesize;
	size_t len;
	size_t numblks;
	int src_fid, des_fid;
	int mret = 0;
	size_t i;
	size_t stride;
	boolean_t discrete = B_FALSE; /* discontiguous mappings */

	/*
	 * parse arguments
	 * Not getopt because -f has two optargs
	 */
	if (argc != 6)
		usage();

	for (i = 1; i < argc; ) {
		switch (argv[i][1]) {
		case 't': /* copy type */
			i++;
			discrete = (argv[i][0] == 'd');
			i++;
			break;
		case 'f': /* src file and des file */
			i++;
			src_file = argv[i];
			i++;
			des_file = argv[i];
			i++;
			break;
		default:
			usage();
			break;
		}
	}

	pagesize = sysconf(_SC_PAGESIZE); /* mmap one page each time */
	if (pagesize < 4096) {
		fprintf(stderr, "sysconf error=%d\n", errno);
		return (1);
	}
	if (discrete) {
		/*
		 * Use discontiguous mappings, and only mmap
		 * one page each time
		 */
		blksize = pagesize;
		stride = 3;
	} else {
		/* will do contiguous mmap */
		blksize = 64 * 1024 * 1024; /* mmap a block each time */
		stride = 1;
	}

	/* source file */
	src_fid = open(src_file, O_RDONLY);
	if (src_fid == -1) {
		fprintf(stderr, "open %s error=%d\n", src_file, errno);
		return (1);
	}
	/* destination file */
	des_fid = open(des_file, O_RDWR | O_CREAT | O_TRUNC,
	    S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH);
	if (des_fid == -1) {
		fprintf(stderr, "open %s error=%d\n", des_file, errno);
		mret = 1;
		goto exit3;
	}

	/* get src file size */
	if (fstat(src_fid, &sb) == -1) {
		fprintf(stderr, "fstat %s error=%d\n", src_file, errno);
		mret = 1;
		goto exit2;
	}
	filesize = sb.st_size;
	if (filesize < pagesize) {
		fprintf(stderr, "src file size < %d\n", (int)pagesize);
		mret = 1;
		goto exit2;
	}

	/* extend des file */
	if (ftruncate(des_fid, filesize) == -1) {
		fprintf(stderr, "ftrunc %s error=%d\n", des_file, errno);
		mret = 1;
		goto exit2;
	}

	/* copy data */
	numblks = (filesize + blksize - 1) / blksize;
	for (i = 0; i < stride * numblks && mret == 0; i += stride) {

		offset = (i % numblks) * blksize;
		if (offset + blksize > filesize)
			len = filesize - offset;
		else
			len = blksize;

		/* map file */
		src_addr = mmap(NULL, len, PROT_READ, MAP_SHARED,
		    src_fid, offset);
		if (src_addr == MAP_FAILED) {
			fprintf(stderr, "mmap %s error=%d\n", src_file, errno);
			mret = 1;
			break;
		}
		des_addr = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED,
		    des_fid, offset);
		if (des_addr == MAP_FAILED) {
			fprintf(stderr, "mmap %s error=%d\n", des_file, errno);
			mret = 1;
			goto exit1;
		}

		/* cp data from src addr to des addr */
		memcpy(des_addr, src_addr, len);
		/* sync mapped pages to file */
		if (msync(des_addr, len, MS_SYNC) == -1) {
			fprintf(stderr, "msync %s error=%d\n", des_file, errno);
			mret = 1;
		}

		/* unmap file */
		if (munmap(des_addr, len) == -1) {
			fprintf(stderr, "munmap %s error=%d\n",
			    des_file, errno);
			mret = 1;
		}
	exit1:
		if (munmap(src_addr, len) == -1) {
			fprintf(stderr, "munmap %s error=%d\n",
			    src_file, errno);
			mret = 1;
		}
	}

exit2:
	close(des_fid);
exit3:
	close(src_fid);

	return (mret);
}
