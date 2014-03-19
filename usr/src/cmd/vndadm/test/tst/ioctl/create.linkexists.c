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
 * Try to create two devices with the same link name.
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
	int fd, fd2, ret;
	vnd_ioc_attach_t via;
	vnd_ioc_link_t vil;
	vnd_ioc_unlink_t viu;

	if (argc < 3) {
		(void) fprintf(stderr, "missing arguments...\n");
		return (1);
	}

	if (strlen(argv[1]) >= VND_NAMELEN) {
		(void) fprintf(stderr, "vnic name too long...\n");
		return (1);
	}

	fd = open(VND_PATH, O_RDWR);
	assert(fd > 0);
	fd2 = open(VND_PATH, O_RDWR);
	assert(fd2 > 0);

	(void) strlcpy(via.via_name, argv[1], VND_NAMELEN);
	via.via_zoneid = 0;
	via.via_errno = 0;
	ret = ioctl(fd, VND_IOC_ATTACH, &via);
	assert(ret == 0);
	assert(via.via_errno == 0);

	(void) strlcpy(via.via_name, argv[2], VND_NAMELEN);
	via.via_zoneid = 0;
	via.via_errno = 0;
	ret = ioctl(fd2, VND_IOC_ATTACH, &via);
	assert(ret == 0);
	assert(via.via_errno == 0);

	(void) strlcpy(vil.vil_name, "dup", VND_NAMELEN);
	vil.vil_errno = 0;
	ret = ioctl(fd, VND_IOC_LINK, &vil);
	assert(ret == 0);
	assert(vil.vil_errno == 0);

	(void) strlcpy(vil.vil_name, "dup", VND_NAMELEN);
	vil.vil_errno = 0;
	ret = ioctl(fd2, VND_IOC_LINK, &vil);
	assert(ret == -1);
	assert(vil.vil_errno == VND_E_LINKEXISTS);

	viu.viu_errno = 0;
	ret = ioctl(fd, VND_IOC_UNLINK, &viu);
	assert(ret == 0);
	assert(viu.viu_errno == 0);

	assert(close(fd) == 0);

	return (0);
}
