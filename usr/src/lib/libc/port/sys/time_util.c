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
 * Copyright 2016 Joyent, Inc.
 */

#include <sys/types.h>
#include <time.h>
#include <errno.h>

/*
 * This function is blatently stolen from the kernel.
 * See the dissertation in the comments preceding the
 * hrt2ts() function in:
 *	uts/common/os/timers.c
 */
void
hrt2ts(hrtime_t hrt, timespec_t *tsp)
{
#if defined(__amd64)
	tsp->tv_sec = hrt / NANOSEC;
	tsp->tv_nsec = hrt % NANOSEC;
#else
	uint32_t sec, nsec, tmp;

	tmp = (uint32_t)(hrt >> 30);
	sec = tmp - (tmp >> 2);
	sec = tmp - (sec >> 5);
	sec = tmp + (sec >> 1);
	sec = tmp - (sec >> 6) + 7;
	sec = tmp - (sec >> 3);
	sec = tmp + (sec >> 1);
	sec = tmp + (sec >> 3);
	sec = tmp + (sec >> 4);
	tmp = (sec << 7) - sec - sec - sec;
	tmp = (tmp << 7) - tmp - tmp - tmp;
	tmp = (tmp << 7) - tmp - tmp - tmp;
	nsec = (uint32_t)hrt - (tmp << 9);
	while (nsec >= NANOSEC) {
		nsec -= NANOSEC;
		sec++;
	}
	tsp->tv_sec = (time_t)sec;
	tsp->tv_nsec = nsec;
#endif /* defined(__amd64) */
}

/*
 * Convert absolute time to relative time.
 * All *timedwait() system call traps expect relative time.
 */
void
abstime_to_reltime(clockid_t clock_id, const timespec_t *abstime,
    timespec_t *reltime)
{
	extern int __clock_gettime(clockid_t, timespec_t *);
	timespec_t now;

	(void) __clock_gettime(clock_id, &now);
	if (abstime->tv_nsec >= now.tv_nsec) {
		reltime->tv_sec = abstime->tv_sec - now.tv_sec;
		reltime->tv_nsec = abstime->tv_nsec - now.tv_nsec;
	} else {
		reltime->tv_sec = abstime->tv_sec - now.tv_sec - 1;
		reltime->tv_nsec = abstime->tv_nsec - now.tv_nsec + NANOSEC;
	}
	/*
	 * If the absolute time has already passed,
	 * just set the relative time to zero.
	 */
	if (reltime->tv_sec < 0) {
		reltime->tv_sec = 0;
		reltime->tv_nsec = 0;
	}
	/*
	 * If the specified absolute time has a bad nanoseconds value,
	 * assign it to the relative time value.  If the interface
	 * attempts to sleep, the bad value will be detected then.
	 * The SUSV3 Posix spec is very clear that such detection
	 * should not happen until an attempt to sleep is made.
	 */
	if ((ulong_t)abstime->tv_nsec >= NANOSEC)
		reltime->tv_nsec = abstime->tv_nsec;
}
