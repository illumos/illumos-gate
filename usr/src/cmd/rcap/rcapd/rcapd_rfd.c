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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * File descriptor usage
 *
 * The number of processes that can be effectively managed is limited to less
 * than half the number of descriptors available:  one for each process's
 * psinfo, the other its pagedata.  When managing more processes, file
 * descriptors are revoked as needed, in such a way as to maximize the
 * distribution of descriptors to pagedata which will be useful in meeting a
 * cap without paging out the process's working set, while retaining some
 * benefit from caching psinfo descriptors, and leaving enough available for
 * use by external consumers, such as are needed for project enumeration or
 * configuration file reading.
 *
 * Revokable file descriptors are opened and associated with a callback
 * function which can be invoked to revoke them later.  pagedata and psinfo
 * descriptors are differentiated for the purposes of preferring pagedata over
 * psinfo, which effectively places the performance of rcapd behind the
 * importance of making good page selections.  The one exception is that one
 * psinfo descriptor is guaranteed a place at any time, for the benefit of
 * psinfo updates of a presently currently-scanned process.  Descriptors are
 * otherwise revoked in LIFO order.
 */

#include <sys/types.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <strings.h>
#include <unistd.h>
#include "rcapd_rfd.h"
#include "utils.h"

static rfd_t *tail;		/* tail of global list */

static int rfd_revoke_next(rfd_class_t);

/*
 * Return the previous rfd_t of the given class, starting at (and including)
 * the given rfd_t.
 */
static rfd_t *
rfd_find_prev_class(rfd_t *rfd, rfd_class_t class)
{
	while (rfd != NULL && rfd->rfd_class != class)
		rfd = rfd->rfd_prev;
	return (rfd);
}

/*
 * Revoke and free the given rfd_t, returning as close does.
 */
static int
rfd_revoke_fd(rfd_t *rfd)
{
	if (rfd->rfd_revoke != NULL)
		rfd->rfd_revoke(rfd);
	return (rfd_close(rfd->rfd_fd));
}

/*
 * Revoke the next file descriptor according to the above constraints.  Return
 * nonzero if there are none to revoke.
 */
static int
rfd_revoke_next(rfd_class_t class)
{
	rfd_t *rfd = NULL;

	if (tail == NULL) {
		debug("nothing to revoke\n");
		return (-1);
	}

	/*
	 * RESERVED-clsas descriptors are all equivalent and may not be revoked
	 * to satisfy another request of the same clsas.  rfd_reserve() uses
	 * this to reserve descriptors by first allocating, then closing, these
	 * descriptors.
	 */
	if (class != RFD_RESERVED)
		rfd = rfd_find_prev_class(tail, RFD_RESERVED);

	/*
	 * Next try psinfo descriptors, leaving at least one open.  Revoke the
	 * second-last psinfo descriptor, if possible.
	 */
	if (rfd == NULL) {
		rfd = rfd_find_prev_class(tail, RFD_PSINFO);
		if (rfd != NULL)
			rfd = rfd->rfd_prev_class;
	}

	/*
	 * Otherwise, revoke the last descriptor allocated, taking the same
	 * care as above that it is not reserved, if the reserved kind is
	 * sought.
	 */
	if (rfd == NULL) {
		rfd = tail;
		while (rfd != NULL && class == RFD_RESERVED && rfd->rfd_class ==
		    RFD_RESERVED)
			rfd = rfd->rfd_prev;
	}

	if (rfd != NULL)
		return (rfd_revoke_fd(rfd));

	/*
	 * Nothing but reserved-class descriptors are revocable, while a
	 * reserved- class descriptor was sought.
	 */
	return (-1);
}

/*
 * Opens a file of the given class, which can later be revoked with the given
 * callback.  Returns as open does.  The callback should reset any state that
 * this caller establishes after the open, but should not close the descriptor,
 * which will be done when the caller explicitly does so with rfd_close(), or
 * the descriptor is revoked with rfd_revoke().
 */
int
rfd_open(char *name, int revoke_ok, rfd_class_t class,
    void(*revoke)(struct rfd *), void *data, int oflag, mode_t mode)
{
	int fd;
	rfd_t *rfd;

	while ((fd = open(name, oflag, mode)) == -1 && (errno == ENFILE ||
	    errno == EMFILE)) {
		if (revoke_ok) {
			if (rfd_revoke_next(class) != 0)
				return (-1);
		} else
			break;
	}

	if (fd != -1) {
		/*
		 * Create rfd_t and link into list.
		 */
		rfd = malloc(sizeof (*rfd));
		if (rfd == NULL) {
			(void) close(fd);
			return (-1);
		}
		(void) bzero(rfd, sizeof (*rfd));
		rfd->rfd_fd = fd;
		rfd->rfd_class = class;
		rfd->rfd_revoke = revoke;
		rfd->rfd_data = data;
		if (tail != NULL)
			rfd->rfd_prev_class = rfd_find_prev_class(tail, class);
		else
			rfd->rfd_prev_class = tail;
		rfd->rfd_prev = tail;
		if (tail != NULL)
			tail->rfd_next = rfd;
		tail = rfd;
	}

	return (fd);
}

/*
 * Close a given file descriptor, and return as close() does.
 */
int
rfd_close(int fd)
{
	rfd_t *nextclass;
	rfd_t *rfdprev;
	rfd_t *rfd;
#ifdef DEBUG
	int freed = 0;
#endif /* DEBUG */

	rfd = tail;
	while (rfd != NULL) {
		rfdprev = rfd->rfd_prev;
		if (rfd->rfd_fd == fd) {
			if (rfd->rfd_prev != NULL)
				rfd->rfd_prev->rfd_next = rfd->rfd_next;
			if (rfd->rfd_next != NULL)
				rfd->rfd_next->rfd_prev = rfd->rfd_prev;
			if (tail == rfd)
				tail = rfd->rfd_prev;
			for (nextclass = rfd->rfd_next; nextclass != NULL;
			    nextclass = nextclass->rfd_next)
				if (nextclass->rfd_class == rfd->rfd_class) {
					nextclass->rfd_prev_class =
					    rfd->rfd_prev_class;
					break;
				}
			free(rfd);
#ifdef DEBUG
			freed = 1;
#endif /* DEBUG */
			break;
		}
		rfd = rfdprev;
	}
	ASSERT(freed == 1);
	return (close(fd));
}

/*
 * Makes sure at least n descriptors are available.  Returns nonzero if
 * successful.
 */
int
rfd_reserve(int n)
{
	int i;
	int fd = 0;
	rfd_t *otail = NULL;
	rfd_t *rfdnext;

	for (i = 0; i < n && fd >= 0; i++) {
		/*
		 * rfd_open() will append as many RFD_RESERVED-clsas
		 * descriptors to the current tail as are requested, revoking
		 * non-RFD_RESERVED-class descriptors until nothing else can be
		 * revoked or the reservation is met.
		 */
		fd = rfd_open("/dev/null", 1, RFD_RESERVED, NULL, NULL,
		    O_RDONLY, 0);
		if (otail == NULL)
			otail = tail;
	}

	if (fd == -1)
		debug("couldn't allocate %d descriptors\n", n);

	while (otail != NULL) {
		rfdnext = otail->rfd_next;
		(void) rfd_close(otail->rfd_fd);
		otail = rfdnext;
	}

	return (fd != -1);
}
