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
 * Copyright 2016 Joyent, Inc.
 */


#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <errno.h>
#include <assert.h>

int
main()
{
	int fd, flags;

	fd = epoll_create1(0);
	assert(fd >= 0);

	flags = fcntl(fd, F_GETFD);
	assert(flags != -1 && (flags & FD_CLOEXEC) == 0);
	(void) close(fd);


	fd = epoll_create1(EPOLL_CLOEXEC);
	assert(fd >= 0);

	flags = fcntl(fd, F_GETFD);
	assert(flags != -1 && (flags & FD_CLOEXEC) == FD_CLOEXEC);
	(void) close(fd);

	fd = epoll_create1(EPOLL_CLOEXEC * 3);
	assert(fd == -1 && errno == EINVAL);
	fd = epoll_create1(EPOLL_CLOEXEC * 2);
	assert(fd == -1 && errno == EINVAL);

	return (0);
}
