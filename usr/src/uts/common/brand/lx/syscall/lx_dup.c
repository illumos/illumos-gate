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

#include <sys/types.h>
#include <sys/filio.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/lx_fcntl.h>
#include <sys/lx_misc.h>

/* From usr/src/uts/common/syscall/fcntl.c */
extern int fcntl(int, int, intptr_t);

long
lx_dup(int fd)
{
	return (fcntl(fd, F_DUPFD, 0));
}

long
lx_dup2(int oldfd, int newfd)
{
	return (fcntl(oldfd, F_DUP2FD, newfd));
}

long
lx_dup3(int oldfd, int newfd, int flags)
{
	int rc;

	/* The only valid flag is O_CLOEXEC. */
	if (flags & ~LX_O_CLOEXEC)
		return (set_errno(EINVAL));

	/* Only DUP2FD_CLOEXEC returns EINVAL on the same fd's */
	if (oldfd == newfd)
		return (set_errno(EINVAL));

	rc = fcntl(oldfd, (flags == 0) ? F_DUP2FD : F_DUP2FD_CLOEXEC, newfd);
	return (rc);
}
