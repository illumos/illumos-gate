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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */


#include <sys/types.h>
#include <sys/time.h>
#include <sys/thread.h>
#include <sys/proc.h>

#include <sys/poll.h>

#include <time.h>

int hz = 1000;
int tick_per_msec = 0;
int msec_per_tick = 1;
int usec_per_tick = 1000;
int nsec_per_tick = 1000000;
time_t boot_time = 0;

#pragma init(_boot_time_init)
static int
_boot_time_init(void)
{
	boot_time = time(NULL);
	return (0);
}

clock_t
ddi_get_lbolt(void)
{
	hrtime_t hrt;

	hrt = gethrtime();
	return (hrt / nsec_per_tick);
}

int64_t
ddi_get_lbolt64(void)
{
	hrtime_t hrt;

	hrt = gethrtime();
	return (hrt / nsec_per_tick);
}

hrtime_t
gethrtime_unscaled(void)
{
	return (gethrtime());
}

void
gethrestime(timespec_t *ts)
{
	struct timeval tv;

	(void) gettimeofday(&tv, NULL);
	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = tv.tv_usec * 1000;
}

time_t
gethrestime_sec(void)
{
	return (time(NULL));
}

/* ARGSUSED */
void
scalehrtime(hrtime_t *t)
{
}
