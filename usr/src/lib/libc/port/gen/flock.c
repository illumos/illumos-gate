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

#include <sys/feature_tests.h>

#include "lint.h"
#include <sys/types.h>
#include <sys/file.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

int
flock(int fildes, int operation)
{
	struct flock64 l;
	int op;
	int rv;

	l.l_whence = SEEK_SET;
	l.l_start = 0;
	l.l_len = 0;
	l.l_sysid = 0;
	l.l_pid = 0;

	switch (operation & ~LOCK_NB) {
	case LOCK_UN:
		if (operation & LOCK_NB) {
			errno = EINVAL;
			return (-1);
		}
		l.l_type = F_UNLCK;
		rv = fcntl(fildes, F_FLOCK, &l);
		break;
	case LOCK_EX:
	case LOCK_SH:
		l.l_type = ((operation & ~LOCK_NB) == LOCK_EX) ?
		    F_WRLCK : F_RDLCK;
		op = (operation & LOCK_NB) ? F_FLOCK : F_FLOCKW;
		rv = fcntl(fildes, op, &l);
		break;
	default:
		errno = EINVAL;
		return (-1);
	}

	return (rv);
}
