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

/*
 * Utility functions for use in both acquire-lock and runtests.
 */

#include "util.h"
#include <err.h>
#include <errno.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>


boolean_t LOG = B_FALSE;


void
flock_log(const char *format, ...)
{
	va_list ap;
	if (!LOG) {
		return;
	}

	va_start(ap, format);
	(void) vfprintf(stderr, format, ap);
	va_end(ap);
}


boolean_t
flock_nodata(int fd)
{
	struct pollfd pfd = { fd, POLLIN, 0 };
	int ret = poll(&pfd, 1, 1000);

	if (ret == -1) {
		err(EXIT_FAILURE, "poll failed");
	}

	return (ret == 0);
}


void
flock_block(int fd)
{
	char buf[1];
	int ret = 0;
	while (ret < 1) {
		ret = read(fd, buf, 1);
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			err(EXIT_FAILURE, "read failed");
		}
	}
}


void
flock_alert(int fd)
{
	int ret = 0;
	while (ret < 1) {
		ret = write(fd, "1", 1);
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			err(EXIT_FAILURE, "write failed");
		}
	}
}


lock_style_t
flock_styleenum(char *stylestr)
{
	if (strcmp(stylestr, "posix") == 0) {
		return (LSTYLE_POSIX);
	} else if (strcmp(stylestr, "ofd") == 0) {
		return (LSTYLE_OFD);
	} else if (strcmp(stylestr, "flock") == 0) {
		return (LSTYLE_FLOCK);
	} else {
		errx(EXIT_FAILURE, BAD_LOCK_MESSAGE);
		return (LSTYLE_LAST);
	}
}


char *
flock_stylestr(lock_style_t style)
{
	switch (style) {
	case LSTYLE_POSIX:
		return ("posix");
	case LSTYLE_OFD:
		return ("ofd");
	case LSTYLE_FLOCK:
		return ("flock");
	default:
		abort();
		return ("<unreachable>");
	}
}


char *
flock_stylename(lock_style_t style)
{
	switch (style) {
	case LSTYLE_POSIX:
		return ("fcntl(2) POSIX");
	case LSTYLE_OFD:
		return ("fcntl(2) OFD");
	case LSTYLE_FLOCK:
		return ("flock(3C)");
	default:
		abort();
		return ("<unreachable>");
	}
}


void
flock_reinit(struct flock *flp, int ltype)
{
	bzero(flp, sizeof (*flp));
	flp->l_type = ltype;
}


char *
flock_cmdname(int cmd)
{
	switch (cmd) {
	case F_SETLK:
		return ("F_SETLK");
	case F_OFD_SETLK:
		return ("F_OFD_SETLK");
	case F_SETLKW:
		return ("F_SETLKW");
	case F_OFD_SETLKW:
		return ("F_OFD_SETLKW");
	case F_GETLK:
		return ("F_GETLK");
	case F_OFD_GETLK:
		return ("F_OFD_GETLK");
	case F_FLOCK:
		return ("F_FLOCK");
	case F_FLOCKW:
		return ("F_FLOCKW");
	default:
		abort();
		return ("<unreachable>");
	}
}
