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
 * Copyright 2019 Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/dkio.h>

int
main(int argc, char **argv)
{
	int umap, fd;

	if (argc < 2) {
		fprintf(stderr, "missing disk name\n");
		exit(2);
	}

	if ((fd = open(argv[1], O_RDONLY)) == -1) {
		fprintf(stderr, "couldn't open %s: %s\n", argv[1],
		    strerror(errno));
		exit(2);
	}

	if (ioctl(fd, DKIOC_CANFREE, &umap) < 0) {
		fprintf(stderr, "ioctl failed %s: %s\n", argv[1],
		    strerror(errno));
		exit(2);
	}

	(void) close(fd);

	return (umap ? 0 : 1);
}
