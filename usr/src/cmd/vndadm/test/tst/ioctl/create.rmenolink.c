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
 * Verify that unlink fails when we're not linked.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <strings.h>
#include <assert.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/vnd.h>

#define	VND_PATH	"/dev/vnd/ctl"

int
main(int argc, const char *argv[])
{
	int fd, ret;
	vnd_ioc_attach_t via;
	vnd_ioc_unlink_t viu;

	if (argc < 2) {
		(void) fprintf(stderr, "missing arguments...\n");
		return (1);
	}

	if (strlen(argv[1]) >= VND_NAMELEN) {
		(void) fprintf(stderr, "vnic name too long...\n");
		return (1);
	}

	fd = open(VND_PATH, O_RDWR);
	assert(fd > 0);

	(void) strlcpy(via.via_name, argv[1], VND_NAMELEN);
	via.via_zoneid = 0;
	via.via_errno = 0;

	ret = ioctl(fd, VND_IOC_ATTACH, &via);
	assert(ret == 0);
	assert(via.via_errno == 0);

	viu.viu_errno = 0;
	ret = ioctl(fd, VND_IOC_UNLINK, &viu);
	assert(ret == -1);
	assert(viu.viu_errno == VND_E_NOTLINKED);

	assert(close(fd) == 0);

	return (0);
}
