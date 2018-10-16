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
 * It doesn't matter if the userland forgets to close the file or
 * munmap it, because smbfs will help close it(including otW close)
 * and sync the dirty pages to the file.
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
	off_t offset;
	size_t filesize;
	size_t blksize;
	int fid;
	int i;
	char *c = "?#*%&";

	if (argc != 2) {
		fprintf(stderr, "\tusage:\n\tno_close <filename>\n");
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

	/* write something into mapped addr */
	blksize = filesize / 4;
	for (i = 0, offset = 0; i < 4; i++, offset += blksize) {
		memset(file_addr + offset, c[i], blksize);
	}
	memset(file_addr + offset, c[i], filesize - offset);

	/* no msync, munmap, close */

	_exit(0);
	/* NOTREACHED */
}
