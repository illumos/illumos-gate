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
 * mutex-specific tests
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

static void
clock_mutex_create(const char *desc, void **argp)
{
	int ret;
	pthread_mutex_t *mtx;
	pthread_mutexattr_t attr;

	mtx = calloc(1, sizeof (pthread_mutex_t));
	if (mtx == NULL) {
		err(EXIT_FAILURE, "TEST FAILED: %s: failed to allocate memory "
		    "for a mutex", desc);
	}

	if ((ret = pthread_mutexattr_init(&attr)) != 0) {
		errc(EXIT_FAILURE, ret, "TEST FAILED: %s: failed to initialize "
		    "mutex attributes", desc);
	}

	if ((ret = pthread_mutexattr_settype(&attr,
	    PTHREAD_MUTEX_ERRORCHECK)) != 0) {
		errc(EXIT_FAILURE, ret, "TEST FAILED: %s: failed to set mutex "
		    "type to error checking", desc);
	}

	if ((ret = pthread_mutex_init(mtx, &attr)) != 0) {
		errc(EXIT_FAILURE, ret, "TEST FAILED: %s: failed to create "
		    "mutex", desc);
	}

	*argp = mtx;
}

static void
clock_mutex_destroy(void *arg)
{
	VERIFY0(pthread_mutex_destroy(arg));
}

static void
clock_mutex_lock(void *arg)
{
	VERIFY0(pthread_mutex_trylock(arg));
}

static void
clock_mutex_unlock(void *arg)
{
	pthread_mutex_exit_np(arg);
}

const lock_ops_t clock_lock_mutex_ops = {
	.lo_create = clock_mutex_create,
	.lo_destroy = clock_mutex_destroy,
	.lo_lock = clock_mutex_lock,
	.lo_unlock = clock_mutex_unlock
};

static bool
clock_test_mutex_invalid_source(const clock_test_t *test, void *prim)
{
	bool ret = true;
	pthread_mutex_t *mutex = prim;
	const clockid_t clocks[] = { 0x7777, INT32_MAX, 0x23, CLOCK_VIRTUAL,
	    CLOCK_THREAD_CPUTIME_ID, CLOCK_PROCESS_CPUTIME_ID };
	int p;

	for (size_t i = 0; i < ARRAY_SIZE(clocks); i++) {
		clockid_t c = clocks[i];

		if ((p = pthread_mutex_clocklock(mutex, c, &clock_to_100ms)) !=
		    EINVAL) {
			warnx("TEST FAILED: %s: pthread_mutex_clocklock with "
			    "clock 0x%x returned %s, not EINVAL", test->ct_desc,
			    c, strerrorname_np(p));
			ret = false;
		}

		if ((p = pthread_mutex_relclocklock_np(mutex, c,
		    &clock_to_100ms)) != EINVAL) {
			warnx("TEST FAILED: %s: pthread_mutex_relclocklock_np "
			    "with clock 0x%x returned %s, not EINVAL",
			    test->ct_desc, c, strerrorname_np(p));
			ret = false;
		}
	}

	return (ret);
}

static bool
clock_test_mutex_inv_to_ign_abs(const clock_test_t *test, void *prim)
{
	bool ret = true;
	pthread_mutex_t *mutex = prim;
	int p;

	if ((p = pthread_mutex_timedlock(mutex, &clock_to_invns)) != 0) {
		warnx("TEST FAILED: %s: pthread_mutex_timedlock failed with "
		    "an invalid timeout when the lock when lock was available: "
		    "expected success, found %s", test->ct_desc,
		    strerrorname_np(p));
		ret = false;
	} else {
		test->ct_ops->lo_unlock(mutex);
	}

	if ((p = pthread_mutex_clocklock(mutex, CLOCK_MONOTONIC,
	    &clock_to_invns)) != 0) {
		warnx("TEST FAILED: %s: pthread_mutex_clocklock failed with "
		    "an invalid timeout when the lock when lock was available: "
		    "expected success, found %s", test->ct_desc,
		    strerrorname_np(p));
		ret = false;
	} else {
		test->ct_ops->lo_unlock(mutex);
	}

	return (ret);
}

static bool
clock_test_mutex_inv_to_abs(const clock_test_t *test, void *prim)
{
	bool ret = true;
	pthread_mutex_t *mutex = prim;
	int p;

	if ((p = pthread_mutex_timedlock(mutex, &clock_to_invns)) != EINVAL) {
		warnx("TEST FAILED: %s: pthread_mutex_timedlock with invalid "
		    "timeout returned %s, not EINVAL", test->ct_desc,
		    strerrorname_np(p));
		ret = false;
	}

	if ((p = pthread_mutex_clocklock(mutex, CLOCK_MONOTONIC,
	    &clock_to_invns)) != EINVAL) {
		warnx("TEST FAILED: %s: pthread_mutex_clocklock with invalid "
		    "timeout returned %s, not EINVAL", test->ct_desc,
		    strerrorname_np(p));
		ret = false;
	}

	return (ret);
}

static bool
clock_test_mutex_inv_to_ign_rel(const clock_test_t *test, void *prim)
{
	bool ret = true;
	pthread_mutex_t *mutex = prim;
	const struct timespec *specs[] = { &clock_to_invns, &clock_to_invnegs,
	    &clock_to_invnegns };
	const char *descs[] = { "too many nanoseconds", "negative seconds",
	    "negative nanoseconds" };
	int p;

	for (size_t i = 0; i < ARRAY_SIZE(specs); i++) {
		if ((p = pthread_mutex_reltimedlock_np(mutex, specs[i])) != 0) {
			warnx("TEST FAILED: %s: pthread_mutex_reltimedlock_np "
			    "failed with invalid timeout %s when the lock when "
			    "lock was available: expected success, found %s",
			    test->ct_desc, descs[i], strerrorname_np(p));
			ret = false;
		} else {
			test->ct_ops->lo_unlock(mutex);
		}

		if ((p = pthread_mutex_relclocklock_np(mutex, CLOCK_MONOTONIC,
		    specs[i])) != 0) {
			warnx("TEST FAILED: %s: pthread_mutex_relclocklock_np "
			    "failed with invalid timeout %s when the lock when "
			    "lock was available: expected success, found %s",
			    test->ct_desc, descs[i], strerrorname_np(p));
			ret = false;
		} else {
			test->ct_ops->lo_unlock(mutex);
		}
	}

	return (ret);
}

static bool
clock_test_mutex_inv_to_rel(const clock_test_t *test, void *prim)
{
	bool ret = true;
	pthread_mutex_t *mutex = prim;
	const struct timespec *specs[] = { &clock_to_invns, &clock_to_invnegs,
	    &clock_to_invnegns };
	const char *descs[] = { "too many nanoseconds", "negative seconds",
	    "negative nanoseconds" };
	int p;

	for (size_t i = 0; i < ARRAY_SIZE(specs); i++) {
		if ((p = pthread_mutex_reltimedlock_np(mutex, specs[i])) !=
		    EINVAL) {
			warnx("TEST FAILED: %s: pthread_mutex_reltimedlock_np "
			    "with invalid timeout %s returned %s, not EINVAL",
			    test->ct_desc, descs[i], strerrorname_np(p));
			ret = false;
		}

		if ((p = pthread_mutex_relclocklock_np(mutex, CLOCK_MONOTONIC,
		    specs[i])) != EINVAL) {
			warnx("TEST FAILED: %s: pthread_mutex_relclocklock_np "
			    "with invalid timeout %s returned %s, not EINVAL",
			    test->ct_desc, descs[i], strerrorname_np(p));
			ret = false;
		}
	}

	return (ret);
}

static bool
clock_test_mutex_to_abs(const clock_test_t *test, void *prim)
{
	pthread_mutex_t *mutex = prim;
	struct timespec to;
	int p;
	bool ret = true, elapse;

	clock_rel_to_abs(CLOCK_REALTIME, &clock_to_100ms, &to);
	p = pthread_mutex_timedlock(mutex, &to);
	elapse = clock_abs_after(CLOCK_REALTIME, &to);
	if (p != ETIMEDOUT) {
		warnx("TEST FAILED: %s pthread_mutex_timedlock on locked mutex "
		    "returned %s, not ETIMEDOUT", test->ct_desc,
		    strerrorname_np(p));
		ret = false;
	}
	if (!elapse) {
		warnx("TEST FAILED: %s: pthread_mutex_timedlock on locked "
		    "mutex did not block long enough!", test->ct_desc);
		ret = false;
	}

	clock_rel_to_abs(CLOCK_REALTIME, &clock_to_100ms, &to);
	p = pthread_mutex_clocklock(mutex, CLOCK_REALTIME, &to);
	elapse = clock_abs_after(CLOCK_REALTIME, &to);
	if (p != ETIMEDOUT) {
		warnx("TEST FAILED: %s: pthread_mutex_clocklock on locked "
		    "mutex with CLOCK_REALTIME returned %s, not ETIMEDOUT",
		    test->ct_desc, strerrorname_np(p));
		ret = false;
	}
	if (!elapse) {
		warnx("TEST FAILED: %s: pthread_mutex_clocklock on locked "
		    "mutex with CLOCK_REALTIME did not block long enough!",
		    test->ct_desc);
		ret = false;
	}

	clock_rel_to_abs(CLOCK_HIGHRES, &clock_to_100ms, &to);
	p = pthread_mutex_clocklock(mutex, CLOCK_HIGHRES, &to);
	elapse = clock_abs_after(CLOCK_HIGHRES, &to);
	if (p != ETIMEDOUT) {
		warnx("TEST FAILED: %s: pthread_mutex_clocklock on locked "
		    "mutex with CLOCK_HIGHRES returned %s, not ETIMEDOUT",
		    test->ct_desc, strerrorname_np(p));
		ret = false;
	}
	if (!elapse) {
		warnx("TEST FAILED: %s: pthread_mutex_clocklock on locked "
		    "mutex with CLOCK_HIGHRES did not block long enough!",
		    test->ct_desc);
		ret = false;
	}

	return (ret);
}

static bool
clock_test_mutex_to_rel(const clock_test_t *test, void *prim)
{
	pthread_mutex_t *mutex = prim;
	struct timespec start;
	int p;
	bool ret = true, elapse;

	if (clock_gettime(CLOCK_REALTIME, &start) != 0) {
		err(EXIT_FAILURE, "failed to read clock %d", CLOCK_REALTIME);
	}
	p = pthread_mutex_reltimedlock_np(mutex, &clock_to_100ms);
	elapse = clock_rel_after(CLOCK_REALTIME, &start, &clock_to_100ms);
	if (p != ETIMEDOUT) {
		warnx("TEST FAILED: %s: pthread_mutex_reltimedlock_np on "
		    "locked mutex returned %s, not ETIMEDOUT", test->ct_desc,
		    strerrorname_np(p));
		ret = false;
	}
	if (!elapse) {
		warnx("TEST FAILED: %s: pthread_mutex_reltimedlock_np on "
		    "locked mutex did not block long enough!", test->ct_desc);
		ret = false;
	}

	if (clock_gettime(CLOCK_REALTIME, &start) != 0) {
		err(EXIT_FAILURE, "failed to read clock %d", CLOCK_REALTIME);
	}
	p = pthread_mutex_relclocklock_np(mutex, CLOCK_REALTIME,
	    &clock_to_100ms);
	elapse = clock_rel_after(CLOCK_REALTIME, &start, &clock_to_100ms);
	if (p != ETIMEDOUT) {
		warnx("TEST FAILED: %s: pthread_mutex_relclocklock_np on "
		    "locked mutex with CLOCK_REALTIME returned %s, not "
		    "ETIMEDOUT", test->ct_desc, strerrorname_np(p));
		ret = false;
	}
	if (!elapse) {
		warnx("TEST FAILED: %s: pthread_mutex_relclocklock_np on "
		    "locked mutex with CLOCK_REALTIME did not block long "
		    "enough!", test->ct_desc);
		ret = false;
	}

	if (clock_gettime(CLOCK_HIGHRES, &start) != 0) {
		err(EXIT_FAILURE, "failed to read clock %d", CLOCK_HIGHRES);
	}
	p = pthread_mutex_relclocklock_np(mutex, CLOCK_HIGHRES,
	    &clock_to_100ms);
	elapse = clock_rel_after(CLOCK_HIGHRES, &start, &clock_to_100ms);
	if (p != ETIMEDOUT) {
		warnx("TEST FAILED: %s: pthread_mutex_relclocklock_np on "
		    "locked mutex with CLOCK_HIGHRES returned %s, not "
		    "ETIMEDOUT", test->ct_desc, strerrorname_np(p));
		ret = false;
	}
	if (!elapse) {
		warnx("TEST FAILED: %s: pthread_mutex_relclocklock_np on "
		    "locked mutex with CLOCK_HIGHRES did not block long "
		    "enough!", test->ct_desc);
		ret = false;
	}

	return (ret);
}

const clock_test_t clock_mutex_tests[] = { {
	.ct_desc = "mutex: invalid and unsupported clock sources",
	.ct_ops = &clock_lock_mutex_ops,
	.ct_test = clock_test_mutex_invalid_source
}, {
	.ct_desc = "mutex: invalid timeout works if lock available (absolute)",
	.ct_ops = &clock_lock_mutex_ops,
	.ct_test = clock_test_mutex_inv_to_ign_abs
}, {
	.ct_desc = "mutex: invalid timeout works if lock available (relative)",
	.ct_ops = &clock_lock_mutex_ops,
	.ct_test = clock_test_mutex_inv_to_ign_rel
}, {
	.ct_desc = "mutex: invalid timeout fails if lock taken (absolute)",
	.ct_ops = &clock_lock_mutex_ops,
	.ct_test = clock_test_mutex_inv_to_abs,
	.ct_enter = true
}, {
	.ct_desc = "mutex: invalid timeout fails if lock taken (relative)",
	.ct_ops = &clock_lock_mutex_ops,
	.ct_test = clock_test_mutex_inv_to_rel,
	.ct_enter = true
}, {
	.ct_desc = "mutex: timeout fires correctly (absolute)",
	.ct_ops = &clock_lock_mutex_ops,
	.ct_test = clock_test_mutex_to_abs,
	.ct_enter = true
}, {
	.ct_desc = "mutex: timeout fires correctly (relative)",
	.ct_ops = &clock_lock_mutex_ops,
	.ct_test = clock_test_mutex_to_rel,
	.ct_enter = true
} };

size_t clock_mutex_ntests = ARRAY_SIZE(clock_mutex_tests);
