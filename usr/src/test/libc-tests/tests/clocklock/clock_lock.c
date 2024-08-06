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
 * Copyright 2024 Oxide Computer Company
 */

/*
 * Test the various pthreads related clock based locking routines. These all
 * attempt to take some form of lock and utilize a timeout that can be specified
 * in terms of a given clock (i.e. CLOCK_REALTIME and CLOCK_HIGHRES). In
 * particular we want to cover:
 *
 *  - Invalid clock sources
 *  - Invalid timeouts ignored when acquired
 *  - Invalid timeouts caught when used
 *  - We can successfully get an ETIMEDOUT and that time has advanced at least
 *    that much
 */

#include <err.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>

#include "clock_lock.h"

/*
 * This is a generic 100ms timeout that we can use. We use it for some tests
 * that require an absolute timeout that is in the future but we don't want to
 * bother computing.
 */
const struct timespec clock_to_100ms = { 0, MSEC2NSEC(100) };

/*
 * A series of invalid clocks. The first is usable for both relative and
 * absolute operations. The others which use negative times should only fail for
 * the relative operations at this time.
 */
const struct timespec clock_to_invns = { 0, NANOSEC * 2 };
const struct timespec clock_to_invnegs = { -12345, 0 };
const struct timespec clock_to_invnegns = { 100, -0x23 };

void
clock_rel_to_abs(clockid_t clock, const struct timespec *restrict rel,
    struct timespec *restrict abs)
{
	if (clock_gettime(clock, abs) != 0) {
		err(EXIT_FAILURE, "failed to get absolute time for clock %d",
		    clock);
	}

	abs->tv_nsec += rel->tv_nsec;
	abs->tv_sec += rel->tv_sec;
	if (abs->tv_nsec > NANOSEC) {
		abs->tv_sec += abs->tv_nsec / NANOSEC;
		abs->tv_nsec %= NANOSEC;
	}
}

bool
clock_abs_after(clockid_t clock, const struct timespec *to)
{
	struct timespec now;

	if (clock_gettime(clock, &now) != 0) {
		err(EXIT_FAILURE, "failed to get absolute time for clock %d",
		    clock);
	}

	if (now.tv_sec > to->tv_sec)
		return (true);

	return (now.tv_sec == to->tv_sec && now.tv_nsec > to->tv_nsec);
}

bool
clock_rel_after(clockid_t clock, const struct timespec *start,
    const struct timespec *to)
{
	struct timespec now, absto;

	if (clock_gettime(clock, &now) != 0) {
		err(EXIT_FAILURE, "failed to get absolute time for clock %d",
		    clock);
	}

	absto.tv_nsec = start->tv_nsec + to->tv_nsec;
	absto.tv_sec = start->tv_sec + to->tv_sec;
	if (absto.tv_nsec > NANOSEC) {
		absto.tv_sec += absto.tv_nsec / NANOSEC;
		absto.tv_nsec %= NANOSEC;
	}

	if (now.tv_sec > absto.tv_sec)
		return (true);

	return (now.tv_sec == absto.tv_sec && now.tv_nsec > absto.tv_nsec);
}

typedef struct {
	const clock_test_t *cthr_test;
	void *cthr_prim;
	bool cthr_ret;
} clock_test_thr_t;

static void *
clock_test_thr(void *arg)
{
	clock_test_thr_t *thr = arg;
	thr->cthr_ret = thr->cthr_test->ct_test(thr->cthr_test,
	    thr->cthr_prim);
	return (NULL);
}

static bool
clock_test_one(const clock_test_t *test)
{
	void *prim;
	bool ret;

	test->ct_ops->lo_create(test->ct_desc, &prim);

	/*
	 * If the test requires that the lock be held in some way, then we spawn
	 * the test to run in another thread to avoid any issues with recursive
	 * actions. Otherwise we let it run locally.
	 */
	if (test->ct_enter) {
		clock_test_thr_t thr_test;
		pthread_t thr;
		int pret;

		test->ct_ops->lo_lock(prim);
		thr_test.cthr_test = test;
		thr_test.cthr_prim = prim;
		thr_test.cthr_ret = false;

		if ((pret = pthread_create(&thr, NULL, clock_test_thr,
		    &thr_test)) != 0) {
			errc(EXIT_FAILURE, pret, "TEST FAILED: %s: internal "
			    "error creating test thread", test->ct_desc);
		}

		if ((pret = pthread_join(thr, NULL)) != 0) {
			errc(EXIT_FAILURE, pret, "TEST FAILED: %s: internal "
			    "error joining test thread", test->ct_desc);
		}
		ret = thr_test.cthr_ret;
		test->ct_ops->lo_unlock(prim);
	} else {
		ret = test->ct_test(test, prim);
	}

	test->ct_ops->lo_destroy(prim);

	if (ret) {
		(void) printf("TEST PASSED: %s\n", test->ct_desc);
	}

	return (ret);
}

int
main(void)
{
	int ret = EXIT_SUCCESS;

	for (size_t i = 0; i < clock_mutex_ntests; i++) {
		if (!clock_test_one(&clock_mutex_tests[i])) {
			ret = EXIT_FAILURE;
		}
	}

	for (size_t i = 0; i < clock_rwlock_ntests; i++) {
		if (!clock_test_one(&clock_rwlock_tests[i])) {
			ret = EXIT_FAILURE;
		}
	}

	for (size_t i = 0; i < clock_sem_ntests; i++) {
		if (!clock_test_one(&clock_sem_tests[i])) {
			ret = EXIT_FAILURE;
		}
	}

	for (size_t i = 0; i < clock_cond_ntests; i++) {
		if (!clock_test_one(&clock_cond_tests[i])) {
			ret = EXIT_FAILURE;
		}
	}


	return (ret);
}
