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
 * Test if file read/write is coherent with mmap, perform 2 tests:
 * modify file through mmap, and check the result through file read.
 * modify file through file write, and check the result through mmap.
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
	    "usage: rw_mmap -n <size>[b|k|m|g] -f <filename>\n");
	exit(1);
}

int
main(int argc, char **argv)
{
	char *suffix;
	char *filename = NULL;
	char *file_addr;
	char *p;
	size_t filesize;
	ssize_t blksize;
	size_t cnt = 1;
	size_t mul = 1;
	int c, fid;
	char *buf;

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
		return (1);
	}

	/* extend file */
	filesize = cnt;
	if (ftruncate(fid, filesize) == -1) {
		fprintf(stderr, "ftrunc %s error=%d\n", filename, errno);
		return (1);
	}

	/* map file */
	file_addr = mmap(NULL, filesize,
	    PROT_READ | PROT_WRITE, MAP_SHARED, fid, 0);
	if (file_addr == MAP_FAILED) {
		fprintf(stderr, "mmap %s error=%d\n", filename, errno);
		return (1);
	}

	blksize = 4096;
	buf = malloc(blksize);
	if (buf == NULL) {
		fprintf(stderr, "malloc failed\n");
		return (1);
	}

	/* verify fread and mmap see the same data */
	p = file_addr + 2013; /* not aligned to 4KB, on purpose */
	lseek(fid, 2013, SEEK_SET);
	while (p < file_addr + filesize) {
		blksize = read(fid, buf, blksize);
		if (blksize < 0) {
			perror(filename);
			return (1);
		}
		if (blksize == 0)
			break;
		if (memcmp(buf, p, blksize) != 0) {
			fprintf(stderr, "memcmp failed 1\n");
			return (1);
		}
		p += blksize;
	}

	/* modify file through mmap, verify fread can see the change */
	blksize = 4096;
	p = file_addr + 2013; /* not aligned to 4KB */
	lseek(fid, 2013, SEEK_SET);
	c = 'a';
	while (p < file_addr + filesize) {
		if (p + blksize > file_addr + filesize)
			blksize = file_addr + filesize - p;
		memset(p, c++, blksize);
		blksize = read(fid, buf, blksize);
		if (blksize < 0) {
			perror(filename);
			return (1);
		}
		if (blksize == 0)
			break;
		if (memcmp(buf, p, blksize) != 0) {
			fprintf(stderr, "memcmp failed 2\n");
			return (1);
		}
		p += blksize;
	}

	/* modify file through fwrite, verify mmap can see the change */
	blksize = 4096;
	p = file_addr + 2013; /* not aligned to 4KB */
	lseek(fid, 2013, SEEK_SET);
	c = 'Z';
	while (p < file_addr + filesize) {
		if (p + blksize > file_addr + filesize)
			blksize = file_addr + filesize - p;
		memset(buf, c--, blksize);
		blksize = write(fid, buf, blksize);
		if (blksize < 0) {
			perror(filename);
			return (1);
		}
		if (blksize == 0)
			break;
		if (memcmp(buf, p, blksize) != 0) {
			fprintf(stderr, "memcmp failed 3\n");
			return (1);
		}
		p += blksize;
	}

	/* sync pages to file */
	if (msync(file_addr, filesize, MS_SYNC) == -1) {
		fprintf(stderr, "msync %s error=%d\n", filename, errno);
		return (1);
	}

	/* unmap file */
	if (munmap(file_addr, filesize) == -1) {
		fprintf(stderr, "munmap %s error=%d\n", filename, errno);
		return (1);
	}

	/* close file */
	if (close(fid) == -1) {
		fprintf(stderr, "close %s error=%d\n", filename, errno);
		return (1);
	}

	return (0);
}
