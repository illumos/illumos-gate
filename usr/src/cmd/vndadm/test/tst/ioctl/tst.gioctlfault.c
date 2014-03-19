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
 * Pass pointers to arbitrary addresses and make sure we properly get EFAULT for
 * all the global ioctls.
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

#include <sys/vnd.h>

#define	VND_PATH	"/dev/vnd/ctl"

int
main(void)
{
	int fd, ret;
	vnd_ioc_attach_t *via;
	vnd_ioc_list_t *vil;
	vnd_ioc_buf_t *vib;

	fd = open(VND_PATH, O_RDWR);
	if (fd < 0) {
		(void) fprintf(stderr, "failed to open %s r/w: %s\n", VND_PATH,
		    strerror(errno));
		return (1);
	}

	via = (vnd_ioc_attach_t *)(uintptr_t)23;
	vil = (vnd_ioc_list_t *)(uintptr_t)42;
	vib = (vnd_ioc_buf_t *)(uintptr_t)169;

	ret = ioctl(fd, VND_IOC_ATTACH, NULL);
	assert(ret == -1);
	assert(errno == EFAULT);
	ret = ioctl(fd, VND_IOC_LIST, NULL);
	assert(ret == -1);
	assert(errno == EFAULT);
	ret = ioctl(fd, VND_IOC_GETMAXBUF, NULL);
	assert(ret == -1);
	assert(errno == EFAULT);

	ret = ioctl(fd, VND_IOC_ATTACH, via);
	assert(ret == -1);
	assert(errno == EFAULT);
	ret = ioctl(fd, VND_IOC_LIST, vil);
	assert(ret == -1);
	assert(errno == EFAULT);
	ret = ioctl(fd, VND_IOC_GETMAXBUF, vib);
	assert(ret == -1);
	assert(errno == EFAULT);

	assert(close(fd) == 0);

	return (0);
}
