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
 * Copyright 2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>

#include <socket_inet.h>

/*
 * Name:	socket_read
 * Description:	Use recv in non-secure sockets.
 * Scope:	private
 * Arguments:	fildes		- Socket file descriptor.
 *		buf		- Buffer to read data into.
 *		nbyte		- Number of bytes to read.
 *              read_timeout    - Timeout value in seconds.
 * Returns:	n		- Number of bytes read. -1 on error.
 */
int
socket_read(int fildes, void *buf, size_t nbyte, int read_timeout)
{
	struct pollfd pfd;

	pfd.fd = fildes;
	pfd.events = POLLIN;

	switch (poll(&pfd, 1, read_timeout * 1000)) {
	case 0:
		errno = EINTR;
		return (-1);
	case -1:
		return (-1);
	default:
		break;
	}

	return (recv(fildes, buf, nbyte, 0));
}

/*
 * Name:	socket_write
 * Description:	Use sendto for non-secure connections.
 * Scope:	private
 * Arguments:	fildes		- Socket file descriptor.
 *		buf		- Buffer containing data to be written.
 *		nbyte		- Number of bytes to write.
 *              addr            - Connection address
 * Returns:	n		- Number of bytes written. -1 on error.
 */
int
socket_write(int fildes, const void *buf, size_t nbyte,
    struct sockaddr_in *addr)
{
	return (sendto(fildes, buf, nbyte, 0, (struct sockaddr *)addr,
	    sizeof (*addr)));
}

int
socket_close(int fildes)
{
	return (close(fildes));
}
