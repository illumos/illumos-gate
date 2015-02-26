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
 * Copyright 2015 Joyent, Inc.
 */

#include <sys/fcntl.h>
#include <sys/lx_fcntl.h>

/*
 * From "uts/common/syscall/mkdir.c":
 */
extern int mkdirat(int, char *, int);

long
lx_mkdirat(int fd, char *dname, int dmode)
{
	if (fd == LX_AT_FDCWD) {
		fd = AT_FDCWD;
	}

	return (mkdirat(fd, dname, dmode));
}

long
lx_mkdir(char *dname, int dmode)
{
	return (mkdirat(AT_FDCWD, dname, dmode));
}
