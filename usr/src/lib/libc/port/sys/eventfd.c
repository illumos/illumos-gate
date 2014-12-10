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
 * Copyright (c) 2014, Joyent, Inc.  All rights reserved.
 */

#include <sys/eventfd.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

int
eventfd(unsigned int initval, int flags)
{
	int oflags = O_RDWR;
	uint64_t val = initval;
	int fd;

	if (flags & ~(EFD_NONBLOCK | EFD_CLOEXEC | EFD_SEMAPHORE))
		return (EINVAL);

	if (flags & EFD_NONBLOCK)
		oflags |= O_NONBLOCK;

	if (flags & EFD_CLOEXEC)
		oflags |= O_CLOEXEC;

	if ((fd = open("/dev/eventfd", oflags)) < 0)
		return (-1);

	if ((flags & EFD_SEMAPHORE) &&
	    ioctl(fd, EVENTFDIOC_SEMAPHORE, 0) != 0) {
		(void) close(fd);
		return (-1);
	}

	if (write(fd, &val, sizeof (val)) < sizeof (val)) {
		(void) close(fd);
		return (-1);
	}

	return (fd);
}

int
eventfd_read(int fd, eventfd_t *valp)
{
	return (read(fd, valp, sizeof (*valp)) < sizeof (*valp) ? -1 : 0);
}

int
eventfd_write(int fd, eventfd_t val)
{
	return (write(fd, &val, sizeof (val)) < sizeof (val) ? -1 : 0);
}
