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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/lx_misc.h>
#include <sys/lx_syscall.h>

/*
 * Linux uses different values for it clock identifiers, so we have to do basic
 * translations between the two.  Thankfully, both Linux and Solaris implement
 * the same POSIX SUSv3 clock types, so the semantics should be identical.
 */

static int ltos_clock[] = {
	CLOCK_REALTIME,
	CLOCK_MONOTONIC,
	CLOCK_PROCESS_CPUTIME_ID,
	CLOCK_THREAD_CPUTIME_ID
};

#define	LX_CLOCK_MAX	(sizeof (ltos_clock) / sizeof (ltos_clock[0]))

long
lx_clock_gettime(int clock, struct timespec *tp)
{
	struct timespec ts;

	if (clock < 0 || clock > LX_CLOCK_MAX)
		return (-EINVAL);

	if (tp == NULL)
		return (-EFAULT);

	if (clock_gettime(ltos_clock[clock], &ts) < 0)
		return (-errno);

	return ((uucopy(&ts, tp, sizeof (struct timespec)) < 0) ? -EFAULT : 0);
}

long
lx_clock_settime(int clock, struct timespec *tp)
{
	struct timespec ts;

	if (clock < 0 || clock > LX_CLOCK_MAX)
		return (-EINVAL);

	if (uucopy(tp, &ts, sizeof (struct timespec)) < 0)
		return (-EFAULT);

	return ((clock_settime(ltos_clock[clock], &ts) < 0) ? -errno : 0);
}

long
lx_clock_getres(int clock, struct timespec *tp)
{
	struct timespec ts;

	if (clock < 0 || clock > LX_CLOCK_MAX)
		return (-EINVAL);

	if (clock_getres(ltos_clock[clock], &ts) < 0)
		return (-errno);

	/* the timespec pointer is allowed to be NULL */
	if (tp == NULL)
		return (0);

	return ((uucopy(&ts, tp, sizeof (struct timespec)) < 0) ? -EFAULT : 0);
}

long
lx_clock_nanosleep(int clock, int flags, struct timespec *rqtp,
    struct timespec *rmtp)
{
	struct timespec rqt, rmt;

	if (clock < 0 || clock > LX_CLOCK_MAX)
		return (-EINVAL);

	if (uucopy(rqtp, &rqt, sizeof (struct timespec)) < 0)
		return (-EFAULT);

	/* the TIMER_RELTIME and TIMER_ABSTIME flags are the same on Linux */
	if (clock_nanosleep(ltos_clock[clock], flags, &rqt, &rmt) < 0)
		return (-errno);

	/*
	 * Only copy values to rmtp if the timer is TIMER_RELTIME and rmtp is
	 * non-NULL.
	 */
	if (((flags & TIMER_RELTIME) == TIMER_RELTIME) && (rmtp != NULL) &&
	    (uucopy(&rmt, rmtp, sizeof (struct timespec)) < 0))
		return (-EFAULT);

	return (0);
}

/*ARGSUSED*/
long
lx_adjtimex(void *tp)
{
	return (-EPERM);
}
