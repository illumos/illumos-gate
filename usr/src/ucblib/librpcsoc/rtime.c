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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * rtime - get time from remote machine
 *
 * gets time, obtaining value from host
 * on the udp/time socket.  Since timeserver returns
 * with time of day in seconds since Jan 1, 1900,  must
 * subtract seconds before Jan 1, 1970 to get
 * what unix uses.
 */

#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <errno.h>
#include <netinet/in.h>
#include <malloc.h>

#define	NYEARS	(1970 - 1900)
#define	TOFFSET ((uint_t)60*60*24*(365*NYEARS + (NYEARS/4)))

extern int _socket(int, int, int);
extern int _sendto(int, const char *, int, int,
	const struct sockaddr *, int);
extern int _recvfrom(int, char *, int, int,
	struct sockaddr *, int *);
extern int _connect(int, struct sockaddr *, int);
extern int __rpc_dtbsize();
extern ssize_t read(int, void *, size_t);
extern int close(int);
static void do_close();

int
rtime(addrp, timep, timeout)
	struct sockaddr_in *addrp;
	struct timeval *timep;
	struct timeval *timeout;
{
	int s;
	fd_set readfds;
	int res;
	uint_t thetime;
	struct sockaddr_in from;
	int fromlen;
	int type;

	if (timeout == NULL) {
		type = SOCK_STREAM;
	} else {
		type = SOCK_DGRAM;
	}
	s = _socket(AF_INET, type, 0);
	if (s < 0) {
		return (-1);
	}
	addrp->sin_family = AF_INET;
	addrp->sin_port = htons(IPPORT_TIMESERVER);
	if (type == SOCK_DGRAM) {
		res = _sendto(s, (char *)&thetime, sizeof (thetime), 0,
		    (struct sockaddr *)addrp, sizeof (*addrp));
		if (res < 0) {
			do_close(s);
			return (-1);
		}
		do {
			FD_ZERO(&readfds);
			FD_SET(s, &readfds);
			res = select(__rpc_dtbsize(), &readfds, NULL,
			    NULL, timeout);
		} while (res < 0 && errno == EINTR);
		if (res <= 0) {
			if (res == 0) {
				errno = ETIMEDOUT;
			}
			do_close(s);
			return (-1);
		}
		fromlen = sizeof (from);
		res = _recvfrom(s, (char *)&thetime, sizeof (thetime), 0,
		    (struct sockaddr *)&from, &fromlen);
		do_close(s);
		if (res < 0) {
			return (-1);
		}
	} else {
		if (_connect(s, (struct sockaddr *)addrp,
			sizeof (*addrp)) < 0) {
			do_close(s);
			return (-1);
		}
		res = read(s, (char *)&thetime, sizeof (thetime));
		do_close(s);
		if (res < 0) {
			return (-1);
		}
	}
	if (res != sizeof (thetime)) {
		errno = EIO;
		return (-1);
	}
	thetime = ntohl(thetime);

	thetime = thetime - TOFFSET;
#ifdef _ILP32
	if (thetime > INT32_MAX)
		thetime = INT32_MAX;
#endif
	timep->tv_sec = thetime;
	timep->tv_usec = 0;
	return (0);
}

static void
do_close(s)
	int s;
{
	int save;

	save = errno;
	(void) close(s);
	errno = save;
}
