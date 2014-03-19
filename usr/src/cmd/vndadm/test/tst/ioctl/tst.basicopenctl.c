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
 * Copyright (c) 2014 Joyent, Inc.  All rights reserved.
 */

/*
 * Ensure that we can do a basic open of the device for read, write, and
 * read/write.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <strings.h>
#include <unistd.h>

#define	VND_PATH	"/dev/vnd/ctl"

int
main(void)
{
	int fd;

	fd = open(VND_PATH, O_RDONLY);
	if (fd < 0) {
		(void) fprintf(stderr, "failed to open %s read only: %s\n",
		    VND_PATH, strerror(errno));
		return (1);
	}

	if (close(fd) != 0) {
		(void) fprintf(stderr, "failed to close vnd fd: %s\n",
		    strerror(errno));
		return (1);
	}

	fd = open(VND_PATH, O_RDWR);
	if (fd < 0) {
		(void) fprintf(stderr, "failed to open %s read/write: %s\n",
		    VND_PATH, strerror(errno));
		return (1);
	}

	if (close(fd) != 0) {
		(void) fprintf(stderr, "failed to close vnd fd: %s\n",
		    strerror(errno));
		return (1);
	}

	fd = open(VND_PATH, O_WRONLY);
	if (fd < 0) {
		(void) fprintf(stderr, "failed to open %s write only: %s\n",
		    VND_PATH, strerror(errno));
		return (1);
	}

	if (close(fd) != 0) {
		(void) fprintf(stderr, "failed to close vnd fd: %s\n",
		    strerror(errno));
		return (1);
	}

	return (0);
}
