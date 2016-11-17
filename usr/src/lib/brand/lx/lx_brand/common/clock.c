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
 * Copyright 2016 Joyent, Inc.
 */

#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/timerfd.h>
#include <sys/lx_misc.h>
#include <sys/lx_syscall.h>
#include <lx_signum.h>

/*
 * Translating from the Linux clock types to the illumos types is a bit of a
 * mess.
 *
 * Linux uses different values for it clock identifiers, so we have to do basic
 * translations between the two.  Thankfully, both Linux and illumos implement
 * the same POSIX SUSv3 clock types, so the semantics should be identical.
 *
 * However, CLOCK_REALTIME and CLOCK_HIGHRES (CLOCK_MONOTONIC) are the only two
 * clock backends currently implemented on illumos. Functions in the kernel
 * that use the CLOCK_BACKEND macro will return an error for any clock type
 * that does not exist in the clock_backend array. These functions are
 * clock_settime, clock_gettime, clock_getres and timer_create.
 *
 * For reference, the kernel's clock_backend array looks like this:
 *
 * clock_backend[CLOCK_MAX] (6 entries)
 *    0	__CLOCK_REALTIME0		valid ptr. (obs. same as CLOCK_REALTIME)
 *    1	CLOCK_VIRTUAL			NULL
 *    2	CLOCK_THREAD_CPUTIME_ID		NULL
 *    3	CLOCK_REALTIME			valid ptr.
 *    4	CLOCK_MONOTONIC (CLOCK_HIGHRES)	valid ptr.
 *    5	CLOCK_PROCESS_CPUTIME_ID	NULL
 */

#define	CLOCK_RT_SLOT	0

#define	LX_CLOCK_REALTIME	0
#define	LX_CLOCK_MONOTONIC	1

/*
 * Limits for a minimum interval are enforced when creating timers from the
 * CLOCK_HIGHRES source. Values below this minimum will be clamped if the
 * process lacks the proc_clock_highres privilege.
 */
static int ltos_clock[] = {
	CLOCK_REALTIME,			/* LX_CLOCK_REALTIME */
	CLOCK_HIGHRES,			/* LX_CLOCK_MONOTONIC */
	CLOCK_PROCESS_CPUTIME_ID,	/* LX_CLOCK_PROCESS_CPUTIME_ID */
	CLOCK_THREAD_CPUTIME_ID,	/* LX_CLOCK_THREAD_CPUTIME_ID */
	CLOCK_HIGHRES,			/* LX_CLOCK_MONOTONIC_RAW */
	CLOCK_REALTIME,			/* LX_CLOCK_REALTIME_COARSE */
	CLOCK_HIGHRES			/* LX_CLOCK_MONOTONIC_COARSE */
};

#define	LX_CLOCK_MAX	(sizeof (ltos_clock) / sizeof (ltos_clock[0]))


long
lx_clock_nanosleep(int clock, int flags, struct timespec *rqtp,
    struct timespec *rmtp)
{
	int ret = 0;
	int err;
	struct timespec rqt, rmt;

	if (clock < 0 || clock >= LX_CLOCK_MAX)
		return (-EINVAL);

	if (uucopy(rqtp, &rqt, sizeof (struct timespec)) < 0)
		return (-EFAULT);

	/* the TIMER_RELTIME and TIMER_ABSTIME flags are the same on Linux */
	if ((err = clock_nanosleep(ltos_clock[clock], flags, &rqt, &rmt))
	    != 0) {
		if (err != EINTR)
			return (-err);
		ret = -EINTR;
		/*
		 * We fall through in case we have to pass back the remaining
		 * time.
		 */
	}

	/*
	 * Only copy values to rmtp if the timer is TIMER_RELTIME and rmtp is
	 * non-NULL.
	 */
	if (((flags & TIMER_RELTIME) == TIMER_RELTIME) && (rmtp != NULL) &&
	    (uucopy(&rmt, rmtp, sizeof (struct timespec)) < 0))
		return (-EFAULT);

	return (ret);
}

/*ARGSUSED*/
long
lx_adjtimex(void *tp)
{
	return (-EPERM);
}

long
lx_timer_settime(timer_t tid, int flags, struct itimerspec *new_val,
    struct itimerspec *old_val)
{
	return ((timer_settime(tid, flags, new_val, old_val) < 0) ? -errno : 0);
}

long
lx_timer_gettime(timer_t tid, struct itimerspec *val)
{
	return ((timer_gettime(tid, val) < 0) ? -errno : 0);
}

long
lx_timer_getoverrun(timer_t tid)
{
	int val;

	val = timer_getoverrun(tid);
	return ((val < 0) ? -errno : val);
}

long
lx_timer_delete(timer_t tid)
{
	return ((timer_delete(tid) < 0) ? -errno : 0);
}

long
lx_timerfd_create(int clockid, int flags)
{
	int r;

	/* These are the only two valid values. LTP tests for this. */
	if (clockid != LX_CLOCK_REALTIME && clockid != LX_CLOCK_MONOTONIC)
		return (-EINVAL);

	r = timerfd_create(ltos_clock[clockid], flags);
	/*
	 * As with the eventfd case, we return a slightly less jarring
	 * error condition if we cannot open /dev/timerfd.
	 */
	if (r == -1 && errno == ENOENT)
		return (-ENOTSUP);

	return (r == -1 ? -errno : r);
}

long
lx_timerfd_settime(int fd, int flags, const struct itimerspec *value,
    struct itimerspec *ovalue)
{
	int r = timerfd_settime(fd, flags, value, ovalue);

	return (r == -1 ? -errno : r);
}

long
lx_timerfd_gettime(int fd, struct itimerspec *value)
{
	int r = timerfd_gettime(fd, value);

	return (r == -1 ? -errno : r);
}
