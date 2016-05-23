/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2016 Joyent, Inc.
 */

/*
 * Basic tests for timespec_get(3C).
 */

#include <time.h>
#include <limits.h>
#include <sys/debug.h>

static int
timespec_cmp(const struct timespec *ls, const struct timespec *rs)
{
	if (ls->tv_sec > rs->tv_sec)
		return (-1);
	if (ls->tv_sec < rs->tv_sec)
		return (1);
	if (ls->tv_nsec > rs->tv_nsec)
		return (-1);
	if (ls->tv_nsec > rs->tv_nsec)
		return (-1);
	if (ls->tv_nsec < rs->tv_nsec)
		return (1);

	return (0);
}

int
main(void)
{
	struct timespec ts, pre, post;

	VERIFY0(timespec_get(&ts, TIME_UTC + 1));
	VERIFY0(timespec_get(&ts, TIME_UTC - 1));
	VERIFY0(timespec_get(&ts, UINT16_MAX));

	VERIFY0(clock_gettime(CLOCK_REALTIME, &pre));
	VERIFY3S(timespec_get(&ts, TIME_UTC), ==, TIME_UTC);
	VERIFY0(clock_gettime(CLOCK_REALTIME, &post));
	VERIFY3S(timespec_cmp(&pre, &post), ==, 1);

	VERIFY3S(timespec_cmp(&pre, &ts), ==, 1);
	VERIFY3S(timespec_cmp(&ts, &post), ==, 1);

	return (0);
}
