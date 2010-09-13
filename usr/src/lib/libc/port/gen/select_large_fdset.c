/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Emulation of select() system call using _pollsys() system call.
 *
 * Assumptions:
 *	polling for input only is most common.
 *	polling for exceptional conditions is very rare.
 *
 * Note that is it not feasible to emulate all error conditions,
 * in particular conditions that would return EFAULT are far too
 * difficult to check for in a library routine.
 *
 * This is the alternate large fd_set select.
 *
 */

/*
 * Must precede any include files
 */
#ifdef FD_SETSIZE
#undef FD_SETSIZE
#endif
#define	FD_SETSIZE 65536

#include "lint.h"
#include <values.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/poll.h>
#include <string.h>
#include <stdlib.h>
#include "libc.h"

#define	DEFAULT_POLL_SIZE 64

static struct pollfd *realloc_fds(int *, struct pollfd **, struct pollfd *);

int
pselect_large_fdset(int nfds, fd_set *in0, fd_set *out0, fd_set *ex0,
	const timespec_t *tsp, const sigset_t *sigmask)
{
	long *in, *out, *ex;
	ulong_t m;	/* bit mask */
	int j;		/* loop counter */
	ulong_t b;	/* bits to test */
	int n, rv;
	int lastj = -1;
	int nused;

	/*
	 * Rather than have a mammoth pollfd (65K) list on the stack
	 * we start with a small one and then malloc larger chunks
	 * on the heap if necessary.
	 */

	struct pollfd pfd[DEFAULT_POLL_SIZE];
	struct pollfd *p;
	struct pollfd *pfd_list;
	int nfds_on_list;

	fd_set zero;

	/*
	 * Check for invalid conditions at outset.
	 * Required for spec1170.
	 * SUSV3: We must behave as a cancellation point even if we fail early.
	 */
	if (nfds >= 0 && nfds <= FD_SETSIZE) {
		if (tsp != NULL) {
			if (tsp->tv_nsec < 0 || tsp->tv_nsec >= NANOSEC ||
			    tsp->tv_sec < 0) {
				pthread_testcancel();
				errno = EINVAL;
				return (-1);
			}
		}
	} else {
		pthread_testcancel();
		errno = EINVAL;
		return (-1);
	}

	/*
	 * If any input args are null, point them at the null array.
	 */
	(void) memset(&zero, 0, sizeof (fd_set));
	if (in0 == NULL)
		in0 = &zero;
	if (out0 == NULL)
		out0 = &zero;
	if (ex0 == NULL)
		ex0 = &zero;

	nfds_on_list = DEFAULT_POLL_SIZE;
	pfd_list = pfd;
	p = pfd_list;
	(void) memset(pfd, 0, sizeof (pfd));
	/*
	 * For each fd, if any bits are set convert them into
	 * the appropriate pollfd struct.
	 */
	in = (long *)in0->fds_bits;
	out = (long *)out0->fds_bits;
	ex = (long *)ex0->fds_bits;
	nused = 0;
	/*
	 * nused reflects the number of pollfd structs currently used
	 * less one. If realloc_fds returns NULL it is because malloc
	 * failed. We expect malloc() to have done the proper
	 * thing with errno.
	 */
	for (n = 0; n < nfds; n += NFDBITS) {
		b = (ulong_t)(*in | *out | *ex);
		for (j = 0, m = 1; b != 0; j++, b >>= 1, m <<= 1) {
			if (b & 1) {
				p->fd = n + j;
				if (p->fd < nfds) {
					p->events = 0;
					if (*in & m)
						p->events |= POLLRDNORM;
					if (*out & m)
						p->events |= POLLWRNORM;
					if (*ex & m)
						p->events |= POLLRDBAND;
					if (nused < (nfds_on_list - 1)) {
						p++;
					} else if ((p = realloc_fds(
					    &nfds_on_list, &pfd_list, pfd))
					    == NULL) {
						if (pfd_list != pfd)
							free(pfd_list);
						pthread_testcancel();
						return (-1);
					}
					nused++;
				} else
					goto done;
			}
		}
		in++;
		out++;
		ex++;
	}
done:
	/*
	 * Now do the poll.
	 */
	do {
		rv = _pollsys(pfd_list, (nfds_t)nused, tsp, sigmask);
	} while (rv < 0 && errno == EAGAIN);

	if (rv < 0) {		/* no need to set bit masks */
		if (pfd_list != pfd)
			free(pfd_list);
		return (rv);
	} else if (rv == 0) {
		/*
		 * Clear out bit masks, just in case.
		 * On the assumption that usually only
		 * one bit mask is set, use three loops.
		 */
		if (in0 != &zero) {
			in = (long *)in0->fds_bits;
			for (n = 0; n < nfds; n += NFDBITS)
				*in++ = 0;
		}
		if (out0 != &zero) {
			out = (long *)out0->fds_bits;
			for (n = 0; n < nfds; n += NFDBITS)
				*out++ = 0;
		}
		if (ex0 != &zero) {
			ex = (long *)ex0->fds_bits;
			for (n = 0; n < nfds; n += NFDBITS)
				*ex++ = 0;
		}
		if (pfd_list != pfd)
			free(pfd_list);
		return (0);
	}

	/*
	 * Check for EINVAL error case first to avoid changing any bits
	 * if we're going to return an error.
	 */
	for (p = pfd_list, j = nused; j-- > 0; p++) {
		/*
		 * select will return EBADF immediately if any fd's
		 * are bad.  poll will complete the poll on the
		 * rest of the fd's and include the error indication
		 * in the returned bits.  This is a rare case so we
		 * accept this difference and return the error after
		 * doing more work than select would've done.
		 */
		if (p->revents & POLLNVAL) {
			errno = EBADF;
			if (pfd_list != pfd)
				free(pfd_list);
			return (-1);
		}
		/*
		 * We would like to make POLLHUP available to select,
		 * checking to see if we have pending data to be read.
		 * BUT until we figure out how not to break Xsun's
		 * dependencies on select's existing features...
		 * This is what we _thought_ would work ... sigh!
		 */
		/*
		 * if ((p->revents & POLLHUP) &&
		 *	!(p->revents & (POLLRDNORM|POLLRDBAND))) {
		 *	errno = EINTR;
		 *	return (-1);
		 * }
		 */
	}

	/*
	 * Convert results of poll back into bits
	 * in the argument arrays.
	 *
	 * We assume POLLRDNORM, POLLWRNORM, and POLLRDBAND will only be set
	 * on return from poll if they were set on input, thus we don't
	 * worry about accidentally setting the corresponding bits in the
	 * zero array if the input bit masks were null.
	 *
	 * Must return number of bits set, not number of ready descriptors
	 * (as the man page says, and as poll() does).
	 */
	rv = 0;
	for (p = pfd_list; nused-- > 0; p++) {
		j = (int)(p->fd / NFDBITS);
		/* have we moved into another word of the bit mask yet? */
		if (j != lastj) {
			/* clear all output bits to start with */
			in = (long *)&in0->fds_bits[j];
			out = (long *)&out0->fds_bits[j];
			ex = (long *)&ex0->fds_bits[j];
			/*
			 * In case we made "zero" read-only (e.g., with
			 * cc -R), avoid actually storing into it.
			 */
			if (in0 != &zero)
				*in = 0;
			if (out0 != &zero)
				*out = 0;
			if (ex0 != &zero)
				*ex = 0;
			lastj = j;
		}
		if (p->revents) {
			m = 1L << (p->fd % NFDBITS);
			if (p->revents & POLLRDNORM) {
				*in |= m;
				rv++;
			}
			if (p->revents & POLLWRNORM) {
				*out |= m;
				rv++;
			}
			if (p->revents & POLLRDBAND) {
				*ex |= m;
				rv++;
			}
			/*
			 * Only set this bit on return if we asked about
			 * input conditions.
			 */
			if ((p->revents & (POLLHUP|POLLERR)) &&
			    (p->events & POLLRDNORM)) {
				if ((*in & m) == 0)
					rv++;	/* wasn't already set */
				*in |= m;
			}
			/*
			 * Only set this bit on return if we asked about
			 * output conditions.
			 */
			if ((p->revents & (POLLHUP|POLLERR)) &&
			    (p->events & POLLWRNORM)) {
				if ((*out & m) == 0)
					rv++;	/* wasn't already set */
				*out |= m;
			}
			/*
			 * Only set this bit on return if we asked about
			 * output conditions.
			 */
			if ((p->revents & (POLLHUP|POLLERR)) &&
			    (p->events & POLLRDBAND)) {
				if ((*ex & m) == 0)
					rv++;   /* wasn't already set */
				*ex |= m;
			}
		}
	}
	if (pfd_list != pfd)
		free(pfd_list);
	return (rv);
}

int
select_large_fdset(int nfds, fd_set *in0, fd_set *out0, fd_set *ex0,
	struct timeval *tv)
{
	timespec_t ts;
	timespec_t *tsp;

	if (tv == NULL)
		tsp = NULL;
	else {
		/* check timeval validity */
		if (tv->tv_usec < 0 || tv->tv_usec >= MICROSEC) {
			errno = EINVAL;
			return (-1);
		}
		/*
		 * Convert timeval to timespec.
		 * To preserve compatibility with past behavior,
		 * when select was built upon poll(2), which has a
		 * minimum non-zero timeout of 1 millisecond, force
		 * a minimum non-zero timeout of 500 microseconds.
		 */
		ts.tv_sec = tv->tv_sec;
		ts.tv_nsec = tv->tv_usec * 1000;
		if (ts.tv_nsec != 0 && ts.tv_nsec < 500000)
			ts.tv_nsec = 500000;
		tsp = &ts;
	}

	return (pselect_large_fdset(nfds, in0, out0, ex0, tsp, NULL));
}

/*
 * Reallocate buffers of pollfds for our list. We malloc a new buffer
 * and, in the case where the old buffer does not match what is passed
 * in orig, free the buffer after copying the contents.
 */
struct pollfd *
realloc_fds(int *num, struct pollfd **list_head, struct pollfd *orig)
{
	struct pollfd *b;
	int nta;
	int n2;

	n2 = *num * 2;
	nta = n2 * sizeof (struct pollfd);
	b = malloc(nta);
	if (b) {
		(void) memset(b, 0, (size_t)nta);
		(void) memcpy(b, *list_head, nta / 2);
		if (*list_head != orig)
			free(*list_head);
		*list_head = b;
		b += *num;
		*num = n2;
	}
	return (b);
}
