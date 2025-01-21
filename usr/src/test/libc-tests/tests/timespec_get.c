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
 * Copyright 2025 Oxide Computer Company
 */

/*
 * Basic tests for timespec_get(3C).
 */

#include <time.h>
#include <limits.h>
#include <err.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/sysmacros.h>

typedef struct {
	int gc_base;
	clockid_t gc_clock;
	const char *gc_desc;
} get_cmp_t;

static const get_cmp_t ts_gets[] = {
	{ TIME_UTC, CLOCK_REALTIME, "real time clock" },
	{ TIME_MONOTONIC, CLOCK_HIGHRES, "highres clock" },
	{ TIME_ACTIVE, CLOCK_PROCESS_CPUTIME_ID, "process clock" },
	{ TIME_THREAD_ACTIVE, CLOCK_THREAD_CPUTIME_ID, "thread clock" },
	{ TIME_THREAD_ACTIVE_USR, CLOCK_VIRTUAL, "thread (usr) clock" },
};

static const int bad_clocks[] = { 7777, -7777, INT16_MIN, CHAR_MAX };

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

static bool
timespec_test_one(const char *desc, int base, clockid_t clock)
{
	int ret;
	struct timespec ts, pre, post;

	if (clock_gettime(clock, &pre) != 0) {
		warn("TEST FAILED: %s: pre clock_gettime(%d) failed", desc,
		    clock);
		return (false);
	}

	if ((ret = timespec_get(&ts, base)) != base) {
		warnx("TEST FAILED: %s timespec_get did not return %d: got %d",
		    desc, base, ret);
		return (false);
	}

	if (clock_gettime(clock, &post) != 0) {
		warn("TEST FAILED: %s: post clock_gettime(%d) failed", desc,
		    clock);
		return (false);
	}

	if (timespec_cmp(&pre, &ts) != 1) {
		warnx("TEST FAILED: %s: timespec_get did not come after "
		    "pre-clock_gettime: found clock 0x%lx/0x%lx vs. timespec "
		    "0x%lx/0x%lx", desc, pre.tv_sec, pre.tv_nsec, ts.tv_sec,
		    ts.tv_nsec);
		return (false);
	}

	if (timespec_cmp(&ts, &post) != 1) {
		warnx("TEST FAILED: %s: timespec_get did not come before "
		    "post-clock_gettime: found timespec 0x%lx/0x%lx vs. clock "
		    "0x%lx/0x%lx", desc, ts.tv_sec, ts.tv_nsec, post.tv_sec,
		    post.tv_nsec);
		return (false);
	}

	(void) printf("TEST PASSED: %s: basic timespec_get works\n", desc);
	return (true);
}

int
main(void)
{
	int ret = EXIT_SUCCESS;

	for (size_t i = 0; i < ARRAY_SIZE(ts_gets); i++) {
		if (!timespec_test_one(ts_gets[i].gc_desc, ts_gets[i].gc_base,
		    ts_gets[i].gc_clock)) {
			ret = EXIT_FAILURE;
		}
	}

	for (size_t i = 0; i < ARRAY_SIZE(bad_clocks); i++) {
		struct timespec ts;

		if (timespec_getres(&ts, bad_clocks[i]) != 0) {
			warnx("TEST FAILED: timespec_get didn't fail "
			    "with bad clock (%d)", bad_clocks[i]);
			ret = EXIT_FAILURE;
		} else {
			(void) printf("TEST PASSED: timespec_get failed "
			    "with bad clock (%d)\n", bad_clocks[i]);
		}
	}

	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests passed successfully\n");
	}

	return (ret);
}
