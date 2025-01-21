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
 * Copyright 2025 Oxide Computer Company
 */

/*
 * Basic tests for C23 timespec_getres.
 */

#include <stdlib.h>
#include <time.h>
#include <err.h>
#include <sys/sysmacros.h>
#include <limits.h>

typedef struct {
	int rc_base;
	clockid_t rc_clock;
	const char *rc_desc;
} res_cmp_t;

static const res_cmp_t resolutions[] = {
	{ TIME_UTC, CLOCK_REALTIME, "real time clock" },
	{ TIME_MONOTONIC, CLOCK_HIGHRES, "highres clock" },
	{ TIME_ACTIVE, CLOCK_PROCESS_CPUTIME_ID, "process clock" },
	{ TIME_THREAD_ACTIVE, CLOCK_THREAD_CPUTIME_ID, "thread clock" },
	{ TIME_THREAD_ACTIVE_USR, CLOCK_VIRTUAL, "thread (usr) clock" },
};

static const int bad_clocks[] = { 23, INT_MAX, INT_MIN, -42 };

int
main(void)
{
	int ret = EXIT_SUCCESS;
	for (size_t i = 0; i < ARRAY_SIZE(resolutions); i++) {
		struct timespec ts_c, ts_posix;
		int res;

		res = timespec_getres(&ts_c, resolutions[i].rc_base);
		if (res != resolutions[i].rc_base) {
			warnx("TEST FAILED: %s: timespec_getres did not "
			    "return expected base %d, got %d",
			    resolutions[i].rc_desc, resolutions[i].rc_base,
			    res);
			ret = EXIT_FAILURE;
			continue;
		}

		if (clock_getres(resolutions[i].rc_clock, &ts_posix) != 0) {
			warn("TEST FAILED: %s: clock_getres for clock %d "
			    "failed", resolutions[i].rc_desc,
			    resolutions[i].rc_clock);
			ret = EXIT_FAILURE;
			continue;
		}

		if (ts_c.tv_sec != ts_posix.tv_sec ||
		    ts_c.tv_nsec != ts_posix.tv_nsec) {
			warnx("TEST FAILED: %s: resolution mismatch: C has "
			    "0x%lx/0x%lx, posix has 0x%lx/0x%lx",
			    resolutions[i].rc_desc, ts_c.tv_sec, ts_c.tv_nsec,
			    ts_posix.tv_sec, ts_posix.tv_nsec);
			ret = EXIT_FAILURE;
			continue;
		}

		(void) printf("TEST PASSED: %s: C and POSIX resoultions "
		    "match\n", resolutions[i].rc_desc);
	}

	for (size_t i = 0; i < ARRAY_SIZE(bad_clocks); i++) {
		struct timespec ts;

		if (timespec_getres(&ts, bad_clocks[i]) != 0) {
			warnx("TEST FAILED: timespec_getres didn't fail "
			    "with bad clock (%d)", bad_clocks[i]);
			ret = EXIT_FAILURE;
		} else {
			(void) printf("TEST PASSED: timespec_getres failed "
			    "with bad clock (%d)\n", bad_clocks[i]);
		}
	}

	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests passed successfully\n");
	}

	return (ret);
}
