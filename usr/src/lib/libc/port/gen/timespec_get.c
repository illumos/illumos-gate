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
 */

/*
 * C11 timespec_get(3C). Note the standard does not want us mucking about with
 * errno, but at least we don't have to preserve it.
 */

#include <time.h>

int
timespec_get(struct timespec *ts, int base)
{
	if (base != TIME_UTC)
		return (0);

	if (clock_gettime(CLOCK_REALTIME, ts) != 0)
		return (0);

	return (TIME_UTC);
}
