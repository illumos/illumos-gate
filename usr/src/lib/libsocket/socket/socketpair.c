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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/*	  All Rights Reserved   */

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/socketvar.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>

extern int _socket_create(int, int, int, int);
extern int _so_socketpair(int *);

int _socketpair_create(int, int, int, int [2], int);

#pragma weak socketpair = _socketpair

int
_socketpair(int family, int type, int protocol, int sv[2])
{
	return (_socketpair_create(family, type, protocol, sv, SOV_DEFAULT));
}

/*
 * Used by the BCP library.
 */
int
_socketpair_bsd(int family, int type, int protocol, int sv[2])
{
	return (_socketpair_create(family, type, protocol, sv, SOV_SOCKBSD));
}

int
_socketpair_svr4(int family, int type, int protocol, int sv[2])
{
	return (_socketpair_create(family, type, protocol, sv, SOV_SOCKSTREAM));
}

int
__xnet_socketpair(int family, int type, int protocol, int sv[2])
{
	return (_socketpair_create(family, type, protocol, sv, SOV_XPG4_2));
}

int
_socketpair_create(int family, int type, int protocol, int sv[2], int version)
{
	int res;
	int fd1, fd2;

	/*
	 * Create the two sockets and pass them to _so_socketpair, which
	 * will connect them together.
	 */
	fd1 = _socket_create(family, type, protocol, version);
	if (fd1 < 0)
		return (-1);
	fd2 = _socket_create(family, type, protocol, version);
	if (fd2 < 0) {
		int error = errno;

		(void) close(fd1);
		errno = error;
		return (-1);
	}
	sv[0] = fd1;
	sv[1] = fd2;
	res = _so_socketpair(sv);
	if (res < 0) {
		int error = errno;

		(void) close(fd1);
		(void) close(fd2);
		errno = error;
		return (-1);
	}
	/*
	 * Check if kernel returned different fds in which case we close
	 * the original ones. This is the case for SOCK_STREAM where
	 * one of the original sockets is used as a listener and
	 * _so_socketpair passes out the newly accepted socket.
	 */
	if (sv[0] != fd1)
		(void) close(fd1);
	if (sv[1] != fd2)
		(void) close(fd2);
	return (res);
}
