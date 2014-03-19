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
 * Make sure that we can't open the vnd control device with invalid flags.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>

#define	VND_PATH	"/dev/vnd/ctl"

int
main(void)
{
	int fd;

	fd = open(VND_PATH, O_RDONLY | O_EXCL);
	if (fd != -1) {
		(void) fprintf(stderr, "somehow opened vnd O_EXCL!");
		return (1);
	}

	fd = open(VND_PATH, O_RDWR | O_EXCL);
	if (fd != -1) {
		(void) fprintf(stderr, "somehow opened vnd O_EXCL!");
		return (1);
	}

	fd = open(VND_PATH, O_WRONLY | O_EXCL);
	if (fd != -1) {
		(void) fprintf(stderr, "somehow opened vnd O_EXCL!");
		return (1);
	}

	fd = open(VND_PATH, O_RDONLY | O_NDELAY);
	if (fd != -1) {
		(void) fprintf(stderr, "somehow opened vnd O_NDELAY!");
		return (1);
	}

	fd = open(VND_PATH, O_RDWR | O_NDELAY);
	if (fd != -1) {
		(void) fprintf(stderr, "somehow opened vnd O_NDELAY!");
		return (1);
	}

	fd = open(VND_PATH, O_WRONLY | O_NDELAY);
	if (fd != -1) {
		(void) fprintf(stderr, "somehow opened vnd O_NDELAY!");
		return (1);
	}

	fd = open(VND_PATH, O_RDONLY | O_NDELAY | O_EXCL);
	if (fd != -1) {
		(void) fprintf(stderr, "somehow opened vnd O_NDELAY | O_EXCL!");
		return (1);
	}

	fd = open(VND_PATH, O_RDWR | O_NDELAY | O_EXCL);
	if (fd != -1) {
		(void) fprintf(stderr, "somehow opened vnd O_NDELAY | O_EXCL!");
		return (1);
	}

	fd = open(VND_PATH, O_WRONLY | O_NDELAY | O_EXCL);
	if (fd != -1) {
		(void) fprintf(stderr, "somehow opened vnd O_NDELAY | O_EXCL!");
		return (1);
	}

	return (0);
}
