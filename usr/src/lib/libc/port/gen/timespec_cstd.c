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
 * Copyright (c) 2015 Joyent, Inc.
 * Copyright 2025 Oxide Computer Company
 */

/*
 * Implementation of C11 and C23 timespec_*() functions. Note, the standard does
 * not have us return values of errno if there are failures for whatever reason,
 * only zero. At least we don't have to preserve errno though.
 */

#include <time.h>
#include <stdbool.h>

static bool
timespec_base_to_clock(int base, clockid_t *clock)
{
	switch (base) {
	case TIME_UTC:
		*clock = CLOCK_REALTIME;
		break;
	case TIME_MONOTONIC:
		*clock = CLOCK_HIGHRES;
		break;
	case TIME_ACTIVE:
		*clock = CLOCK_PROCESS_CPUTIME_ID;
		break;
	case TIME_THREAD_ACTIVE:
		*clock = CLOCK_THREAD_CPUTIME_ID;
		break;
	case TIME_THREAD_ACTIVE_USR:
		*clock = CLOCK_VIRTUAL;
		break;
	default:
		return (false);
	}

	return (true);
}

int
timespec_get(struct timespec *ts, int base)
{
	clockid_t clock;

	if (!timespec_base_to_clock(base, &clock))
		return (0);

	if (clock_gettime(clock, ts) != 0)
		return (0);

	return (base);
}

int
timespec_getres(struct timespec *ts, int base)
{
	clockid_t clock;

	if (!timespec_base_to_clock(base, &clock))
		return (0);

	if (clock_getres(clock, ts) != 0)
		return (0);

	return (base);
}
