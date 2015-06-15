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
 * Copyright 2015, Joyent, Inc.
 */

#include <sys/signalfd.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

int
signalfd(int fd, const sigset_t *mask, int flags)
{
	int origfd = fd;

	if (fd == -1) {
		int oflags = O_RDONLY;

		if (flags & ~(SFD_NONBLOCK | SFD_CLOEXEC)) {
			errno = EINVAL;
			return (-1);
		}

		if (flags & SFD_NONBLOCK)
			oflags |= O_NONBLOCK;

		if (flags & SFD_CLOEXEC)
			oflags |= O_CLOEXEC;

		if ((fd = open("/dev/signalfd", oflags)) < 0)
			return (-1);
	}

	if (ioctl(fd, SIGNALFDIOC_MASK, mask) != 0) {
		if (origfd == -1) {
			int old = errno;
			(void) close(fd);
			errno = old;
		}
		/*
		 * Trying to modify an existing sigfd so if this failed
		 * it's because it's not a valid fd or not a sigfd. ioctl
		 * returns the correct errno for these cases.
		 */
		return (-1);
	}

	return (fd);
}
