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
 * Copyright (c) 1993-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* Taken from 4.1.3 ypserv resolver code. */

/*
 * This is an example of using rpc_as.h an asynchronous polling
 * mechanism,  asynchronously polled fds are combined with the
 * service fds.  The minimum timeout is calculated, and
 * the user waits for that timeout or activity on either the
 * async pollset or the svc pollset.
 */

#include <rpc/rpc.h>
#include <errno.h>
#include <stdlib.h>
#include "rpc_as.h"
#include <stropts.h>
#include <string.h>
#include <poll.h>
#include "prnt.h"

extern int __rpc_timeval_to_msec(struct timeval *t);

/*
 * Merge two arrays of pollfd's, assumptions:
 *	Arrays are ordered so element N contains descriptor N
 *	Out array is as large as max(asize, bsize)
 */
static void
merge_pollfds(struct pollfd *out, struct pollfd *a, int asize,
				struct pollfd *b, int bsize)
{
	int i;
	int outsize;

	outsize = (asize > bsize) ? asize : bsize;

	for (i = 0; i < outsize; i++) {
		if (i < asize && a[i].fd != -1)
			out[i] = a[i];
		else if (i < bsize && b[i].fd != -1)
			out[i] = b[i];
		else
			out[i].fd = -1;
	}
}

void
svc_run_as()
{
	struct timeval  timeout;
	struct pollfd *svc_pollset = NULL;
	struct pollfd *as_pollset;
	int nfds = 0;
	int max_fds;
	int as_max_pollfd;
	int pollret = 0;

	for (;;) {
		as_max_pollfd = rpc_as_get_max_pollfd() + 1;
		as_pollset = rpc_as_get_pollset();

		max_fds = (as_max_pollfd > svc_max_pollfd) ?
				as_max_pollfd : svc_max_pollfd;
		if (nfds != max_fds) {
			svc_pollset = realloc(svc_pollset,
						sizeof (pollfd_t) * max_fds);
			nfds = max_fds;
		}

		if (nfds == 0)
			break; /* None waiting, hence return */

		/*
		 * Merge together rpc_as_get_pollset and svc_pollfd
		 */
		merge_pollfds(svc_pollset, as_pollset, as_max_pollfd,
				svc_pollfd, svc_max_pollfd);

		timeout = rpc_as_get_timeout();

		switch ((pollret = poll(svc_pollset, nfds,
					__rpc_timeval_to_msec(&timeout)))) {
		case -1:
			if (errno == EINTR) {
				continue;
			}
			prnt(P_ERR, "svc_run: - poll failed: %s\n",
				strerror(errno));
			return;
		case 0:
			rpc_as_timeout(timeout);
			break;
		default:
			rpc_as_rcvreq_poll(svc_pollset, &pollret);

			svc_getreq_poll(svc_pollset, pollret);
		}
	}
}
