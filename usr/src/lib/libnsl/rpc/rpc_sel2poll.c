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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1988 AT&T */
/* All Rights Reserved */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mt.h"
#include <sys/select.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/poll.h>
#include "rpc_mt.h"


/*
 *	Given an fd_set pointer and the number of bits to check in it,
 *	initialize the supplied pollfd array for RPC's use (RPC only
 *	polls for input events).  We return the number of pollfd slots
 *	we initialized.
 */
int
__rpc_select_to_poll(
	int	fdmax,		/* number of bits we must test */
	fd_set	*fdset,		/* source fd_set array */
	struct pollfd	*p0)	/* target pollfd array */
{
	int j;		/* loop counter */
	int n;
	struct pollfd	*p = p0;

	/*
	 * For each fd, if the appropriate bit is set convert it into
	 * the appropriate pollfd struct.
	 */
	j = ((fdmax >= FD_SETSIZE) ? FD_SETSIZE : fdmax);
	for (n = 0; n < j; n++) {
		if (FD_ISSET(n, fdset)) {
			p->fd = n;
			p->events = MASKVAL;
			p->revents = 0;
			p++;
		}
	}
	return (p - p0);
}

/*
 *	Arguments are similar to rpc_select_to_poll() except that
 *	the second argument is pointer to an array of pollfd_t
 *	which is the source array which will be compressed and
 *	copied to the target array in p0.  The size of the
 *	source argument is given by pollfdmax. The array can be
 *	sparse. The space for the target is allocated before
 *	calling this function. It should have atleast pollfdmax
 *	elements.  This function scans the source pollfd array
 *	and copies only the valid ones to the target p0.
 */
int
__rpc_compress_pollfd(int pollfdmax, pollfd_t *srcp, pollfd_t *p0)
{
	int n;
	pollfd_t *p = p0;

	for (n = 0; n < pollfdmax; n++) {
		if (POLLFD_ISSET(n, srcp)) {
			p->fd = srcp[n].fd;
			p->events = srcp[n].events;
			p->revents = 0;
			p++;
		}
	}
	return (p - p0);
}

/*
 *	Convert from timevals (used by select) to milliseconds (used by poll).
 */
int
__rpc_timeval_to_msec(struct timeval *t)
{
	int	t1, tmp;

	/*
	 * We're really returning t->tv_sec * 1000 + (t->tv_usec / 1000)
	 * but try to do so efficiently.  Note:  1000 = 1024 - 16 - 8.
	 */
	tmp = (int)t->tv_sec << 3;
	t1 = -tmp;
	t1 += t1 << 1;
	t1 += tmp << 7;
	if (t->tv_usec)
		t1 += t->tv_usec / 1000;

	return (t1);
}
