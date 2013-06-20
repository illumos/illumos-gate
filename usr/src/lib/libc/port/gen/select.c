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

/*
 * Emulation of select() system call using poll() system call.
 *
 * Assumptions:
 *	polling for input only is most common.
 *	polling for exceptional conditions is very rare.
 *
 * Note that is it not feasible to emulate all error conditions,
 * in particular conditions that would return EFAULT are far too
 * difficult to check for in a library routine.
 */

#pragma weak _select = select

#include "lint.h"
#include <values.h>
#include <pthread.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/poll.h>
#include <alloca.h>
#include "libc.h"

/*
 * STACK_PFD_LIM
 *
 *   The limit at which pselect allocates pollfd structures in the heap,
 *   rather than on the stack.  These limits match the historical behaviour
 *   with the * _large_fdset implementations.
 *
 * BULK_ALLOC_LIM
 *
 *   The limit below which we'll just allocate nfds pollfds, rather than
 *   counting how many we actually need.
 */
#if defined(_LP64)
#define	STACK_PFD_LIM	FD_SETSIZE
#define	BULK_ALLOC_LIM	8192
#else
#define	STACK_PFD_LIM	1024
#define	BULK_ALLOC_LIM	1024
#endif

/*
 * The previous _large_fdset implementations are, unfortunately, baked into
 * the ABI.
 */
#pragma weak select_large_fdset = select
#pragma weak pselect_large_fdset = pselect

#define	fd_set_size(nfds)	(((nfds) + (NFDBITS - 1)) / NFDBITS)

static nfds_t
fd_sets_count(int limit, fd_set *in, fd_set *out, fd_set *ex)
{
	nfds_t total = 0;

	if (limit <= 0)
		return (0);

	for (int i = 0; i < fd_set_size(limit); i++) {
		long v = (in->fds_bits[i] | out->fds_bits[i] | ex->fds_bits[i]);

		while (v != 0) {
			v &= v - 1;
			total++;
		}
	}

	return (total);
}

int
pselect(int nfds, fd_set *in0, fd_set *out0, fd_set *ex0,
    const timespec_t *tsp, const sigset_t *sigmask)
{
	long *in, *out, *ex;
	ulong_t m;	/* bit mask */
	int j;		/* loop counter */
	ulong_t b;	/* bits to test */
	int n, rv;
	struct pollfd *pfd;
	struct pollfd *p;
	int lastj = -1;
	nfds_t npfds = 0;
	boolean_t heap_pfds = B_FALSE;

	/* "zero" is read-only, it could go in the text segment */
	static fd_set zero = { 0 };

	/*
	 * Check for invalid conditions at outset.
	 * Required for spec1170.
	 * SUSV3: We must behave as a cancellation point even if we fail early.
	 */
	if (nfds < 0 || nfds > FD_SETSIZE) {
		pthread_testcancel();
		errno = EINVAL;
		return (-1);
	}

	if (tsp != NULL) {
		/* check timespec validity */
		if (tsp->tv_nsec < 0 || tsp->tv_nsec >= NANOSEC ||
		    tsp->tv_sec < 0) {
			pthread_testcancel();
			errno = EINVAL;
			return (-1);
		}
	}

	/*
	 * If any input args are null, point them at the null array.
	 */
	if (in0 == NULL)
		in0 = &zero;
	if (out0 == NULL)
		out0 = &zero;
	if (ex0 == NULL)
		ex0 = &zero;

	if (nfds <= BULK_ALLOC_LIM) {
		p = pfd = alloca(nfds * sizeof (struct pollfd));
	} else {
		npfds = fd_sets_count(nfds, in0, out0, ex0);

		if (npfds > STACK_PFD_LIM) {
			p = pfd = malloc(npfds * sizeof (struct pollfd));
			if (p == NULL)
				return (-1);
			heap_pfds = B_TRUE;
		} else {
			p = pfd = alloca(npfds * sizeof (struct pollfd));
		}
	}

	/*
	 * For each fd, if any bits are set convert them into
	 * the appropriate pollfd struct.
	 */
	in = (long *)in0->fds_bits;
	out = (long *)out0->fds_bits;
	ex = (long *)ex0->fds_bits;
	for (n = 0; n < nfds; n += NFDBITS) {
		b = (ulong_t)(*in | *out | *ex);
		for (j = 0, m = 1; b != 0; j++, b >>= 1, m <<= 1) {
			if (b & 1) {
				p->fd = n + j;
				if (p->fd >= nfds)
					goto done;
				p->events = 0;
				if (*in & m)
					p->events |= POLLRDNORM;
				if (*out & m)
					p->events |= POLLWRNORM;
				if (*ex & m)
					p->events |= POLLRDBAND;
				p++;
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
	npfds = (int)(p - pfd);
	do {
		rv = _pollsys(pfd, npfds, tsp, sigmask);
	} while (rv < 0 && errno == EAGAIN);

	if (rv < 0)		/* no need to set bit masks */
		goto out;

	if (rv == 0) {
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
		rv = 0;
		goto out;
	}

	/*
	 * Check for EINVAL error case first to avoid changing any bits
	 * if we're going to return an error.
	 */
	for (p = pfd, n = npfds; n-- > 0; p++) {
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
			rv = -1;
			goto out;
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
		 *	rv = -1;
		 *	goto out;
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
	for (p = pfd, n = npfds; n-- > 0; p++) {
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
					rv++;	/* wasn't already set */
				*ex |= m;
			}
		}
	}
out:
	if (heap_pfds)
		free(pfd);
	return (rv);
}

int
select(int nfds, fd_set *in0, fd_set *out0, fd_set *ex0, struct timeval *tv)
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

	return (pselect(nfds, in0, out0, ex0, tsp, NULL));
}
