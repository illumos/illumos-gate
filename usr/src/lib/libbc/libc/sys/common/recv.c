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
 * Copyright 1990 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/errno.h>

extern int	errno;

#define N_AGAIN 11

int	recv(s, buf, len, flags)
int	s;
char	*buf;
int	len, flags;
{
	int	a;
	if ((a = _recv(s, buf, len, flags)) == -1) {
		if (errno == N_AGAIN)
			errno = EWOULDBLOCK;
		else
			maperror(errno);
	}
	return(a);
}


int	recvfrom(s, buf, len, flags, from, fromlen)
int	s;
char	*buf;
int	len, flags;
struct sockaddr *from;
int	*fromlen;
{
	int	a;
	if ((a = _recvfrom(s, buf, len, flags, from, fromlen)) == -1) {
		if (errno == N_AGAIN)
			errno = EWOULDBLOCK;
		else
			maperror(errno);
	}
	return(a);
}


int	recvmsg(s, msg, flags)
int	s;
struct msghdr *msg;
int	flags;
{
	int	a;
	if ((a = _recvmsg(s, msg, flags)) == -1) {
		if (errno == N_AGAIN)
			errno = EWOULDBLOCK;
		else
			maperror(errno);
	}
	return(a);
}


