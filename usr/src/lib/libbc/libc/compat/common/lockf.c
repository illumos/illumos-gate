/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 1989 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*      Copyright (c) 1984 AT&T */
/*        All Rights Reserved   */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>

/*
 * convert lockf() into fcntl() for SystemV compatibility
 */

/* New SVR4 values */
#define SV_GETLK	5
#define SV_SETLK	6
#define SV_SETLKW	7

int
lockf(int fildes, int function, long size)
{
	struct flock ld;
	int cmd;

	cmd = SV_SETLK;		/* assume non-blocking operation */
	ld.l_type = F_WRLCK;	/* lockf() only deals with exclusive locks */
	ld.l_whence = 1;	/* lock always starts at current position */
	if (size < 0) {
		ld.l_start = size;
		ld.l_len = -size;
	} else {
		ld.l_start = 0L;
		ld.l_len = size;
	}

	switch (function) {
	case F_TEST:
		if (_syscall(SYS_fcntl, fildes, SV_GETLK, &ld) != -1) {
			if (ld.l_type == F_UNLCK) {
				ld.l_pid = ld.l_xxx;	
					/* l_pid is the last field in the 
					   SVr3 flock structure */
				return (0);
			} else
				errno = EACCES;		/* EAGAIN ?? */
		}
		return (-1);

	default:
		errno = EINVAL;
		return (-1);

			/* the rest fall thru to the fcntl() at the end */
	case F_ULOCK:
		ld.l_type = F_UNLCK;
		break;

	case F_LOCK:
		cmd = SV_SETLKW;	/* block, if not available */
		break;

	case F_TLOCK:
		break;
	}
	if (_syscall(SYS_fcntl, fildes, cmd, &ld) == -1) {
		switch (errno) {
		/* this hack is purported to be for /usr/group compatibility */
		case ENOLCK:
			errno = EDEADLK;
		}
		return(-1);
	} else {
		ld.l_pid = ld.l_xxx;	/* l_pid is the last field in the 
					   SVr3 flock structure */
		return(0);
	}
}
