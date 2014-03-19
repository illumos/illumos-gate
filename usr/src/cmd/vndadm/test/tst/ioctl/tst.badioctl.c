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
 * Throw a bunch of bad ioctls at us and make sure that we get ENOTTY.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <strings.h>
#include <unistd.h>
#include <stropts.h>
#include <limits.h>
#include <assert.h>

/*
 * We're including a bunch of bad header files that have ioctl numbers that we
 * know we shouldn't.
 */
#include <sys/ipd.h>
#include <sys/dtrace.h>

#define	VND_PATH	"/dev/vnd/ctl"

/*
 * A series of bad requests
 */
static int requests[] = {
	0,
	1,
	42,
	169,
	4096,
	INT_MAX,
	IPDIOC_CORRUPT,
	IPDIOC_REMOVE,
	DTRACEIOC_CONF,
	DTRACEIOC_REPLICATE,
	-1
};

int
main(void)
{
	int fd, i;

	fd = open(VND_PATH, O_RDONLY);
	if (fd < 0) {
		(void) fprintf(stderr, "failed to open %s read only: %s\n",
		    VND_PATH, strerror(errno));
		return (1);
	}

	for (i = 0; requests[i] != -1; i++) {
		int ret;
		ret = ioctl(fd, requests[i], NULL);
		assert(ret == -1);
		assert(errno == ENOTTY);
	}

	assert(close(fd) == 0);

	return (0);
}
