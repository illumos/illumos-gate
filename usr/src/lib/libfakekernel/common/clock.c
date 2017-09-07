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
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
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

/*
 * These functions are blatently stolen from the kernel.
 * See the dissertation in the comments preceding the
 * hrt2ts() and ts2hrt() functions in:
 *	uts/common/os/timers.c
 */
void
hrt2ts(hrtime_t hrt, timespec_t *tsp)
{
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
}

hrtime_t
ts2hrt(const timestruc_t *tsp)
{
	hrtime_t hrt;

	hrt = tsp->tv_sec;
	hrt = (hrt << 7) - hrt - hrt - hrt;
	hrt = (hrt << 7) - hrt - hrt - hrt;
	hrt = (hrt << 7) - hrt - hrt - hrt;
	hrt = (hrt << 9) + tsp->tv_nsec;
	return (hrt);
}
