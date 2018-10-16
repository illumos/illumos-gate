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
 * After close file but before munmap it, test if we can still write into
 * mapped pages and the dirty pages are eventually synced to file,
 * the result should be that we can do it as long as we dont munmap it.
 * When userland attempts to close mapped file, smbfs will keep SMB FID
 * alive if there are mapped pages(not unmapped yet), so the otW will stay
 * open until last ref. to vnode goes away.
 * This program tests if smbfs works as we said.
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

int
main(int argc, char **argv)
{
	char *file_addr;
	char *p;
	size_t filesize;
	size_t blksize;
	int fid;
	int i;
	char *c = "?#*%&";

	if (argc != 2) {
		fprintf(stderr, "\tusage:\n\tclose_wr <filename>\n");
		return (1);
	}

	/* open test file */
	fid = open(argv[1], O_RDWR | O_CREAT | O_TRUNC,
	    S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH);
	if (fid == -1) {
		fprintf(stderr, "open %s error=%d\n", argv[1], errno);
		return (1);
	}

	/* extend file */
	filesize = 64 * 1024;
	if (ftruncate(fid, filesize) == -1) {
		fprintf(stderr, "ftrunc %s error=%d\n", argv[1], errno);
		return (1);
	}

	/* map file */
	file_addr = mmap(NULL, filesize,
	    PROT_READ | PROT_WRITE, MAP_SHARED, fid, 0);
	if (file_addr == MAP_FAILED) {
		fprintf(stderr, "mmap %s error=%d\n", argv[1], errno);
		return (1);
	}

	/* erase file */
	memset(file_addr, 0, filesize);

	/* close file here! */
	if (close(fid) == -1) {
		fprintf(stderr, "close %s error=%d\n", argv[1], errno);
		return (1);
	}

	/*
	 * write somthing into mapped addr after close file,
	 * it should be ok before munmap
	 */
	blksize = filesize / 4;
	for (i = 0, p = file_addr; i < 4; i++, p += blksize) {
		memset(p, c[i], blksize);
	}

	/* sync pages to file */
	if (msync(file_addr, filesize, MS_SYNC) == -1) {
		fprintf(stderr, "msync %s error=%d\n", argv[1], errno);
		return (1);
	}

	/* unmap file */
	if (munmap(file_addr, filesize) == -1) {
		fprintf(stderr, "munmap %s error=%d\n", argv[1], errno);
		return (1);
	}

	return (0);
}
