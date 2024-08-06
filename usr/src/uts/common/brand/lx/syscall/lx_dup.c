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
 * Copyright 2024 Oxide Computer Company
 * Copyright 2024 OmniOS Community Edition (OmniOSce) Association.
 */

#include <sys/types.h>
#include <sys/filio.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/lx_fcntl.h>
#include <sys/lx_misc.h>

/* From usr/src/uts/common/syscall/fcntl.c */
extern int fcntl(int, int, intptr_t, intptr_t);

long
lx_dup(int fd)
{
	return (fcntl(fd, F_DUPFD, 0, 0));
}

long
lx_dup2(int oldfd, int newfd)
{
	return (fcntl(oldfd, F_DUP2FD, newfd, 0));
}

long
lx_dup3(int oldfd, int newfd, int flags)
{
	int dflags = 0;

	/*
	 * dup3() only supports O_ open flags that translate into file
	 * descriptor flags in the F_GETFD sense.
	 * In the future, once Linux supports it, LX_O_CLOFORK should also
	 * be added here.
	 */
	if (flags & ~LX_O_CLOEXEC)
		return (set_errno(EINVAL));

	/*
	 * This call differs from dup2 such that it is an error when
	 * oldfd == newfd
	 */
	if (oldfd == newfd)
		return (set_errno(EINVAL));

	if ((flags & LX_O_CLOEXEC) != 0)
		dflags |= FD_CLOEXEC;

	return (fcntl(oldfd, F_DUP3FD, newfd, dflags));
}
