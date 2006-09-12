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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <errno.h>
#include <time.h>
#include <sys/lx_misc.h>

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

int
lx_clock_gettime(int clock, struct timespec *tp)
{
	if (clock < 0 || clock > LX_CLOCK_MAX)
		return (EINVAL);

	return (clock_gettime(ltos_clock[clock], tp));
}

int
lx_clock_settime(int clock, struct timespec *tp)
{
	if (clock < 0 || clock > LX_CLOCK_MAX)
		return (EINVAL);

	return (clock_settime(ltos_clock[clock], tp));
}

int
lx_clock_getres(int clock, struct timespec *tp)
{
	if (clock < 0 || clock > LX_CLOCK_MAX)
		return (EINVAL);

	return (clock_getres(ltos_clock[clock], tp));
}

int
lx_clock_nanosleep(int clock, int flags, struct timespec *rqtp,
    struct timespec *rmtp)
{
	if (clock < 0 || clock > LX_CLOCK_MAX)
		return (EINVAL);

	/* the TIMER_ABSTIME flag is the same on Linux */
	return (clock_nanosleep(ltos_clock[clock], flags, rqtp, rmtp));
}
