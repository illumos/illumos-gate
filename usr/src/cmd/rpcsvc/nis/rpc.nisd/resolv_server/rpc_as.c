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
 * Copyright (c) 1993,1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* Taken from 4.1.3 ypserv resolver code. */

#include "rpc_as.h"
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <poll.h>
#include <string.h>

#define	CHECK_PARENT_SECS	600 /* every 10 min */

extern pid_t ppid;
extern void cleanup(int);

#define	POLLFD_EXTEND 512

static rpc_as **rpc_as_handles;
static pollfd_t *rpc_as_pollset;
static int rpc_as_max_pollfd = -1;
static int rpc_as_pollfd_allocd = 0;

pollfd_t *
rpc_as_get_pollset()
{
	return (rpc_as_pollset);
}

int
rpc_as_get_max_pollfd()
{
	return (rpc_as_max_pollfd);
}

static bool_t rpc_as_init()
{
	int i;

	if (rpc_as_handles != NULL)
		return (TRUE);

	rpc_as_handles = (rpc_as **)
			calloc(POLLFD_EXTEND, sizeof (rpc_as *));
	if (rpc_as_handles == NULL) {
		return (FALSE);
	}

	rpc_as_pollset = (pollfd_t *)calloc(POLLFD_EXTEND, sizeof (pollfd_t));
	if (rpc_as_pollset == NULL) {
		free(rpc_as_handles);
		rpc_as_handles = NULL;
		return (FALSE);
	}
	rpc_as_pollfd_allocd = POLLFD_EXTEND;

	for (i = 0; i < rpc_as_pollfd_allocd; i++) {
		rpc_as_pollset[i].fd = -1;
		rpc_as_pollset[i].events = 0;
		rpc_as_pollset[i].revents = 0;
		rpc_as_handles[i] = NULL;
	}

	return (TRUE);
}

/*
 * Activate a asynchronous handle.
 */
int
rpc_as_register(rpc_as *xprt)
{

	if ((rpc_as_handles == NULL) && (!rpc_as_init()))
		return (-1);

	if (xprt->as_fd < 0)
		return (-1); /* can't register less than zero */

	/*
	 * If the descriptor is bigger than the pollset and handles
	 * array, grow it by POLLFD_EXTEND until it is large enough.
	 */
	if (xprt->as_fd >= rpc_as_pollfd_allocd) {
		int i = rpc_as_pollfd_allocd;
		pollfd_t *ptmp;
		rpc_as **htmp;

		do {
			rpc_as_pollfd_allocd += POLLFD_EXTEND;
		} while (xprt->as_fd >= rpc_as_pollfd_allocd);

		ptmp = realloc(rpc_as_pollset,
			sizeof (pollfd_t) * rpc_as_pollfd_allocd);
		if (ptmp == NULL) {
			rpc_as_pollfd_allocd = i;
			return (-1);
		}

		htmp = realloc(rpc_as_handles,
				sizeof (rpc_as *) * rpc_as_pollfd_allocd);
		if (htmp == NULL) {
			rpc_as_pollfd_allocd = i;
			return (-1);
		}

		/*
		 * Initialize the new elements
		 */
		rpc_as_pollset = ptmp;
		rpc_as_handles = htmp;
		for (; i < rpc_as_pollfd_allocd; i++) {
			rpc_as_pollset[i].fd = -1;
			rpc_as_pollset[i].events = 0;
			rpc_as_pollset[i].revents = 0;
			rpc_as_handles[i] = NULL;
		}
	}

	rpc_as_handles[xprt->as_fd] = xprt;
	rpc_as_pollset[xprt->as_fd].fd = xprt->as_fd;
	rpc_as_pollset[xprt->as_fd].events =
				POLLIN | POLLPRI | POLLRDNORM | POLLRDBAND;
	rpc_as_pollset[xprt->as_fd].revents = 0;
	if (xprt->as_fd > rpc_as_max_pollfd)
		rpc_as_max_pollfd = xprt->as_fd;
	return (0);
}

static void
remove_pollfd(int fd)
{
	if (fd < 0 || fd > rpc_as_max_pollfd)
		return;

	/*
	 * Don't shrink handles, pollset, or rpc_as_max_pollfd for now
	 */
	rpc_as_handles[fd] = (rpc_as *)0;
	rpc_as_pollset[fd].fd = -1;
	rpc_as_pollset[fd].events = 0;
	rpc_as_pollset[fd].revents = 0;
}

/*
 * De-activate an asynchronous handle.
 */
int
rpc_as_unregister(rpc_as *xprt)
{
	if ((rpc_as_handles == NULL) && (!rpc_as_init()))
		return (-1);
	if (xprt->as_fd < 0)
		return (-1); /* can't unregister less than zero */

	if ((xprt->as_fd <= rpc_as_max_pollfd) &&
			(rpc_as_handles[xprt->as_fd] == xprt)) {
		remove_pollfd(xprt->as_fd);
		return (0);
	}
	return (-1);
}

/*
 * Check through each element of the poll set looking for returned
 * events, if found and it corresponds to an active xprt, call as_recv
 * and decrement pollretval so a later svc_getreq_poll can
 * be called.
 */
void
rpc_as_rcvreq_poll(pollfd_t *pollset, int *pollretval)
{
	int i;
	rpc_as *xprt;

	if ((rpc_as_handles == NULL) && (!rpc_as_init()))
		return;

	for (i = 0; i <= rpc_as_max_pollfd; i++) {
		pollfd_t *p = &pollset[i];
		if (p->revents) {
			/* fd has input waiting */
			if (p->revents & POLLNVAL) {
				remove_pollfd(p->fd);
				*pollretval -= 1;
				continue;
			}

			xprt = rpc_as_handles[p->fd];
			if (xprt) {
				if (xprt->as_recv)
					xprt->as_recv(xprt, p->fd);
				else
					(void) rpc_as_unregister(xprt);
				/*
				 * Clear the event
				 */
				p->revents = 0;
				*pollretval -= 1;
			}
		}
	}
}

struct timeval
rpc_as_get_timeout()
{
	int		tsecs;
	int		tusecs;
	struct timeval  now;
	struct timeval	ans;
	static struct timeval last;
	struct rpc_as   **rhd;
	int sock;

	ans.tv_sec = CHECK_PARENT_SECS; /* check parent time */
	ans.tv_usec = 0;

	if ((rpc_as_handles == NULL) && (!rpc_as_init()))
		return (ans);

	/* Calculate elapsed time */
	(void) gettimeofday(&now, (struct timezone *)0);
	if (last.tv_sec) {
		tsecs = now.tv_sec - last.tv_sec;
		tusecs = now.tv_usec - last.tv_usec;
		last = now;
	} else {
		last = now;
		tsecs = 0;
		tusecs = 0;
	}
	while (tusecs < 0)  {
		tusecs += 1000000;
		tsecs--;
	}
	if (tsecs < 0)
		tsecs = 0;

	rhd = rpc_as_handles;

	for (sock = 0; sock <= rpc_as_max_pollfd; sock++) {
		if (rhd[sock] == (struct rpc_as *)NULL)
			continue;

		if (rhd[sock]->as_timeout_flag) {

			rhd[sock]->as_timeout_remain.tv_sec -= tsecs;
			rhd[sock]->as_timeout_remain.tv_usec -= tusecs;

			while (rhd[sock]->as_timeout_remain.tv_usec < 0) {
				rhd[sock]->as_timeout_remain.tv_sec--;
				rhd[sock]->as_timeout_remain.tv_usec += 1000000;
			}
			if (rhd[sock]->as_timeout_remain.tv_sec < 0) {
				rhd[sock]->as_timeout_remain.tv_sec = 0;
				rhd[sock]->as_timeout_remain.tv_usec = 0;
			}

			if (timercmp(&(rhd[sock]->as_timeout_remain), &ans,
							< /*EMPTY*/))
				ans = rhd[sock]->as_timeout_remain;
		}
	}

	return (ans);
}

void
rpc_as_timeout(struct timeval twaited)
{

	struct rpc_as **rhd;
	int sock;

	/* ppid only set when using transient from parent (nisd) */
	if (ppid && kill(ppid, 0))
		cleanup(0);

	if ((rpc_as_handles == NULL) && (!rpc_as_init()))
		return;
	rhd = rpc_as_handles;

	for (sock = 0; sock <= rpc_as_max_pollfd; sock++) {
		if (rhd[sock] == (struct rpc_as *)NULL)
			continue;
		if (rhd[sock]->as_timeout_flag) {
			if ((timercmp(&(rhd[sock]->as_timeout_remain), &twaited,
							< /*EMPTY*/)) ||
			    (timercmp(&(rhd[sock]->as_timeout_remain), &twaited,
							== /*EMPTY*/))) {
				if (rhd[sock]->as_timeout)
					rhd[sock]->as_timeout(rhd[sock]);
				else
					(void) rpc_as_unregister(rhd[sock]);

			}
		}
	}
}
