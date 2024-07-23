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
 * rwlock-specific tests and implementation
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
clock_rwlock_create(const char *desc, void **argp)
{
	int ret;
	pthread_rwlock_t *rw;

	rw = calloc(1, sizeof (pthread_rwlock_t));
	if (rw == NULL) {
		err(EXIT_FAILURE, "TEST FAILED: %s: failed to allocate memory "
		    "for a rwlock", desc);
	}

	if ((ret = pthread_rwlock_init(rw, NULL)) != 0) {
		errc(EXIT_FAILURE, ret, "TEST FAILED: %s: failed to create "
		    "rwlock", desc);
	}

	*argp = rw;
}

static void
clock_rwlock_destroy(void *arg)
{
	VERIFY0(pthread_rwlock_destroy(arg));
}

static void
clock_rwlock_wrlock(void *arg)
{
	VERIFY0(pthread_rwlock_trywrlock(arg));
}

static void
clock_rwlock_unlock(void *arg)
{
	VERIFY0(pthread_rwlock_unlock(arg));
}

/*
 * While we have both read and write locks, we use a write lock for lo_lock()
 * here as that'll ensure that any additional readers or writers will always
 * block.
 */
const lock_ops_t clock_lock_rwlock_ops = {
	.lo_create = clock_rwlock_create,
	.lo_destroy = clock_rwlock_destroy,
	.lo_lock = clock_rwlock_wrlock,
	.lo_unlock = clock_rwlock_unlock
};

static bool
clock_test_rwlock_invalid_source(const clock_test_t *test, void *prim)
{
	bool ret = true;
	pthread_rwlock_t *rwl = prim;
	const clockid_t clocks[] = { 0x7777, INT32_MAX, 0x23, CLOCK_VIRTUAL,
	    CLOCK_THREAD_CPUTIME_ID, CLOCK_PROCESS_CPUTIME_ID };
	int p;

	for (size_t i = 0; i < ARRAY_SIZE(clocks); i++) {
		clockid_t c = clocks[i];

		if ((p = pthread_rwlock_clockrdlock(rwl, c, &clock_to_100ms)) !=
		    EINVAL) {
			warnx("TEST FAILED: %s: pthread_rwlock_clockrdlock "
			    "with clock 0x%x returned %s, not EINVAL",
			    test->ct_desc, c, strerrorname_np(p));
			ret = false;
		}

		if ((p = pthread_rwlock_relclockrdlock_np(rwl, c,
		    &clock_to_100ms)) != EINVAL) {
			warnx("TEST FAILED: %s: pthread_rwlock_relclockrdlock"
			    "_np with clock 0x%x returned %s, not EINVAL",
			    test->ct_desc, c, strerrorname_np(p));
			ret = false;
		}

		if ((p = pthread_rwlock_clockwrlock(rwl, c, &clock_to_100ms)) !=
		    EINVAL) {
			warnx("TEST FAILED: %s: pthread_rwlock_clockwrlock "
			    "with clock 0x%x returned %s, not EINVAL",
			    test->ct_desc, c, strerrorname_np(p));
			ret = false;
		}

		if ((p = pthread_rwlock_relclockwrlock_np(rwl, c,
		    &clock_to_100ms)) != EINVAL) {
			warnx("TEST FAILED: %s: pthread_rwlock_relclockwrlock"
			    "_np with clock 0x%x returned %s, not EINVAL",
			    test->ct_desc, c, strerrorname_np(p));
			ret = false;
		}

	}

	return (ret);
}

static bool
clock_test_rwlock_inv_to_ign_abs(const clock_test_t *test, void *prim)
{
	bool ret = true;
	pthread_rwlock_t *rwl = prim;
	int p;

	if ((p = pthread_rwlock_timedrdlock(rwl, &clock_to_invns)) != 0) {
		warnx("TEST FAILED: %s: pthread_rwlock_timedrdlock failed with "
		    "an invalid timeout when the lock when lock was available: "
		    "expected success, found %s", test->ct_desc,
		    strerrorname_np(p));
		ret = false;
	} else {
		test->ct_ops->lo_unlock(rwl);
	}

	if ((p = pthread_rwlock_clockrdlock(rwl, CLOCK_MONOTONIC,
	    &clock_to_invns)) != 0) {
		warnx("TEST FAILED: %s: pthread_rwlock_clockrdlock failed with "
		    "an invalid timeout when the lock when lock was available: "
		    "expected success, found %s", test->ct_desc,
		    strerrorname_np(p));
		ret = false;
	} else {
		test->ct_ops->lo_unlock(rwl);
	}

	if ((p = pthread_rwlock_timedwrlock(rwl, &clock_to_invns)) != 0) {
		warnx("TEST FAILED: %s: pthread_rwlock_timedwrlock failed with "
		    "an invalid timeout when the lock when lock was available: "
		    "expected success, found %s", test->ct_desc,
		    strerrorname_np(p));
		ret = false;
	} else {
		test->ct_ops->lo_unlock(rwl);
	}

	if ((p = pthread_rwlock_clockwrlock(rwl, CLOCK_MONOTONIC,
	    &clock_to_invns)) != 0) {
		warnx("TEST FAILED: %s: pthread_rwlock_clockwrlock failed with "
		    "an invalid timeout when the lock when lock was available: "
		    "expected success, found %s", test->ct_desc,
		    strerrorname_np(p));
		ret = false;
	} else {
		test->ct_ops->lo_unlock(rwl);
	}

	return (ret);
}

static bool
clock_test_rwlock_inv_to_abs(const clock_test_t *test, void *prim)
{
	bool ret = true;
	pthread_rwlock_t *rwl = prim;
	int p;

	if ((p = pthread_rwlock_timedrdlock(rwl, &clock_to_invns)) != EINVAL) {
		warnx("TEST FAILED: %s: pthread_rwlock_timedrdlock with "
		    "invalid timeout returned %s, not EINVAL", test->ct_desc,
		    strerrorname_np(p));
		ret = false;
	}

	if ((p = pthread_rwlock_clockrdlock(rwl, CLOCK_MONOTONIC,
	    &clock_to_invns)) != EINVAL) {
		warnx("TEST FAILED: %s: pthread_rwlock_clockrdlock with "
		    "invalid timeout returned %s, not EINVAL", test->ct_desc,
		    strerrorname_np(p));
		ret = false;
	}

	if ((p = pthread_rwlock_timedwrlock(rwl, &clock_to_invns)) != EINVAL) {
		warnx("TEST FAILED: %s: pthread_rwlock_timedwrlock with "
		    "invalid timeout returned %s, not EINVAL", test->ct_desc,
		    strerrorname_np(p));
		ret = false;
	}

	if ((p = pthread_rwlock_clockwrlock(rwl, CLOCK_MONOTONIC,
	    &clock_to_invns)) != EINVAL) {
		warnx("TEST FAILED: %s: pthread_rwlock_clockwrlock with "
		    "invalid timeout returned %s, not EINVAL", test->ct_desc,
		    strerrorname_np(p));
		ret = false;
	}

	return (ret);
}

static bool
clock_test_rwlock_inv_to_ign_rel(const clock_test_t *test, void *prim)
{
	bool ret = true;
	pthread_rwlock_t *rwl = prim;
	const struct timespec *specs[] = { &clock_to_invns, &clock_to_invnegs,
	    &clock_to_invnegns };
	const char *descs[] = { "too many nanoseconds", "negative seconds",
	    "negative nanoseconds" };
	int p;

	for (size_t i = 0; i < ARRAY_SIZE(specs); i++) {
		if ((p = pthread_rwlock_reltimedrdlock_np(rwl, specs[i])) !=
		    0) {
			warnx("TEST FAILED: %s: pthread_rwlock_reltimedrdlock"
			    "_np failed with invalid timeout %s when the lock "
			    "when lock was available: expected success, found "
			    "%s", test->ct_desc, descs[i], strerrorname_np(p));
			ret = false;
		} else {
			test->ct_ops->lo_unlock(rwl);
		}

		if ((p = pthread_rwlock_relclockrdlock_np(rwl, CLOCK_MONOTONIC,
		    specs[i])) != 0) {
			warnx("TEST FAILED: %s: pthread_rwlock_relclockrdlock"
			    "_np failed with invalid timeout %s when the lock "
			    "when lock was available: expected success, found "
			    "%s", test->ct_desc, descs[i], strerrorname_np(p));
			ret = false;
		} else {
			test->ct_ops->lo_unlock(rwl);
		}

		if ((p = pthread_rwlock_reltimedwrlock_np(rwl, specs[i])) !=
		    0) {
			warnx("TEST FAILED: %s: pthread_rwlock_reltimedwrlock"
			    "_np failed with invalid timeout %s when the lock "
			    "when lock was available: expected success, found "
			    "%s", test->ct_desc, descs[i], strerrorname_np(p));
			ret = false;
		} else {
			test->ct_ops->lo_unlock(rwl);
		}

		if ((p = pthread_rwlock_relclockwrlock_np(rwl, CLOCK_MONOTONIC,
		    specs[i])) != 0) {
			warnx("TEST FAILED: %s: pthread_rwlock_relclockwrlock"
			    "_np failed with invalid timeout %s when the lock "
			    "when lock was available: expected success, found "
			    "%s", test->ct_desc, descs[i], strerrorname_np(p));
			ret = false;
		} else {
			test->ct_ops->lo_unlock(rwl);
		}
	}

	return (ret);
}

static bool
clock_test_rwlock_inv_to_rel(const clock_test_t *test, void *prim)
{
	bool ret = true;
	pthread_rwlock_t *rwl = prim;
	const struct timespec *specs[] = { &clock_to_invns, &clock_to_invnegs,
	    &clock_to_invnegns };
	const char *descs[] = { "too many nanoseconds", "negative seconds",
	    "negative nanoseconds" };
	int p;

	for (size_t i = 0; i < ARRAY_SIZE(specs); i++) {
		if ((p = pthread_rwlock_reltimedrdlock_np(rwl, specs[i])) !=
		    EINVAL) {
			warnx("TEST FAILED: %s: pthread_rwlock_reltimedrdlock"
			    "_np with invalid timeout %s returned %s, not "
			    "EINVAL", test->ct_desc, descs[i],
			    strerrorname_np(p));
			ret = false;
		}

		if ((p = pthread_rwlock_relclockrdlock_np(rwl, CLOCK_MONOTONIC,
		    specs[i])) != EINVAL) {
			warnx("TEST FAILED: %s: pthread_rwlock_relclockrdlock"
			    "_np with invalid timeout %s returned %s, not "
			    "EINVAL", test->ct_desc, descs[i],
			    strerrorname_np(p));
			ret = false;
		}

		if ((p = pthread_rwlock_reltimedwrlock_np(rwl, specs[i])) !=
		    EINVAL) {
			warnx("TEST FAILED: %s: pthread_rwlock_reltimedwrlock"
			    "_np with invalid timeout %s returned %s, not "
			    "EINVAL", test->ct_desc, descs[i],
			    strerrorname_np(p));
			ret = false;
		}

		if ((p = pthread_rwlock_relclockwrlock_np(rwl, CLOCK_MONOTONIC,
		    specs[i])) != EINVAL) {
			warnx("TEST FAILED: %s: pthread_rwlock_relclockwrlock"
			    "_np with invalid timeout %s returned %s, not "
			    "EINVAL", test->ct_desc, descs[i],
			    strerrorname_np(p));
			ret = false;
		}
	}

	return (ret);
}

static bool
clock_test_rwlock_to_abs(const clock_test_t *test, void *prim)
{
	pthread_rwlock_t *rwl = prim;
	struct timespec to;
	int p;
	bool ret = true, elapse;

	clock_rel_to_abs(CLOCK_REALTIME, &clock_to_100ms, &to);
	p = pthread_rwlock_timedrdlock(rwl, &to);
	elapse = clock_abs_after(CLOCK_REALTIME, &to);
	if (p != ETIMEDOUT) {
		warnx("TEST FAILED: %s pthread_rwlock_timedrdlock on locked "
		    "rwlock returned %s, not ETIMEDOUT", test->ct_desc,
		    strerrorname_np(p));
		ret = false;
	}
	if (!elapse) {
		warnx("TEST FAILED: %s: pthread_rwlock_timedrdlock on locked "
		    "rwlock did not block long enough!", test->ct_desc);
		ret = false;
	}

	clock_rel_to_abs(CLOCK_REALTIME, &clock_to_100ms, &to);
	p = pthread_rwlock_clockrdlock(rwl, CLOCK_REALTIME, &to);
	elapse = clock_abs_after(CLOCK_REALTIME, &to);
	if (p != ETIMEDOUT) {
		warnx("TEST FAILED: %s: pthread_rwlock_clockrdlock on locked "
		    "rwlock with CLOCK_REALTIME returned %s, not ETIMEDOUT",
		    test->ct_desc, strerrorname_np(p));
		ret = false;
	}
	if (!elapse) {
		warnx("TEST FAILED: %s: pthread_rwlock_clockrdlock on locked "
		    "rwlock with CLOCK_REALTIME did not block long enough!",
		    test->ct_desc);
		ret = false;
	}

	clock_rel_to_abs(CLOCK_HIGHRES, &clock_to_100ms, &to);
	p = pthread_rwlock_clockrdlock(rwl, CLOCK_HIGHRES, &to);
	elapse = clock_abs_after(CLOCK_HIGHRES, &to);
	if (p != ETIMEDOUT) {
		warnx("TEST FAILED: %s: pthread_rwlock_clockrdlock on locked "
		    "rwlock with CLOCK_HIGHRES returned %s, not ETIMEDOUT",
		    test->ct_desc, strerrorname_np(p));
		ret = false;
	}
	if (!elapse) {
		warnx("TEST FAILED: %s: pthread_rwlock_clockrdlock on locked "
		    "rwlock with CLOCK_HIGHRES did not block long enough!",
		    test->ct_desc);
		ret = false;
	}

	clock_rel_to_abs(CLOCK_REALTIME, &clock_to_100ms, &to);
	p = pthread_rwlock_timedwrlock(rwl, &to);
	elapse = clock_abs_after(CLOCK_REALTIME, &to);
	if (p != ETIMEDOUT) {
		warnx("TEST FAILED: %s pthread_rwlock_timedwrlock on locked "
		    "rwlock returned %s, not ETIMEDOUT", test->ct_desc,
		    strerrorname_np(p));
		ret = false;
	}
	if (!elapse) {
		warnx("TEST FAILED: %s: pthread_rwlock_timedwrlock on locked "
		    "rwlock did not block long enough!", test->ct_desc);
		ret = false;
	}

	clock_rel_to_abs(CLOCK_REALTIME, &clock_to_100ms, &to);
	p = pthread_rwlock_clockwrlock(rwl, CLOCK_REALTIME, &to);
	elapse = clock_abs_after(CLOCK_REALTIME, &to);
	if (p != ETIMEDOUT) {
		warnx("TEST FAILED: %s: pthread_rwlock_clockwrlock on locked "
		    "rwlock with CLOCK_REALTIME returned %s, not ETIMEDOUT",
		    test->ct_desc, strerrorname_np(p));
		ret = false;
	}
	if (!elapse) {
		warnx("TEST FAILED: %s: pthread_rwlock_clockwrlock on locked "
		    "rwlock with CLOCK_REALTIME did not block long enough!",
		    test->ct_desc);
		ret = false;
	}

	clock_rel_to_abs(CLOCK_HIGHRES, &clock_to_100ms, &to);
	p = pthread_rwlock_clockwrlock(rwl, CLOCK_HIGHRES, &to);
	elapse = clock_abs_after(CLOCK_HIGHRES, &to);
	if (p != ETIMEDOUT) {
		warnx("TEST FAILED: %s: pthread_rwlock_clockwrlock on locked "
		    "rwlock with CLOCK_HIGHRES returned %s, not ETIMEDOUT",
		    test->ct_desc, strerrorname_np(p));
		ret = false;
	}
	if (!elapse) {
		warnx("TEST FAILED: %s: pthread_rwlock_clockwrlock on locked "
		    "rwlock with CLOCK_HIGHRES did not block long enough!",
		    test->ct_desc);
		ret = false;
	}


	return (ret);
}

static bool
clock_test_rwlock_to_rel(const clock_test_t *test, void *prim)
{
	pthread_rwlock_t *rwl = prim;
	struct timespec start;
	int p;
	bool ret = true, elapse;

	if (clock_gettime(CLOCK_REALTIME, &start) != 0) {
		err(EXIT_FAILURE, "failed to read clock %d", CLOCK_REALTIME);
	}
	p = pthread_rwlock_reltimedrdlock_np(rwl, &clock_to_100ms);
	elapse = clock_rel_after(CLOCK_REALTIME, &start, &clock_to_100ms);
	if (p != ETIMEDOUT) {
		warnx("TEST FAILED: %s: pthread_rwlock_reltimedrdlock_np on "
		    "locked rwlock returned %s, not ETIMEDOUT", test->ct_desc,
		    strerrorname_np(p));
		ret = false;
	}
	if (!elapse) {
		warnx("TEST FAILED: %s: pthread_rwlock_reltimedrdlock_np on "
		    "locked rwlock did not block long enough!", test->ct_desc);
		ret = false;
	}

	if (clock_gettime(CLOCK_REALTIME, &start) != 0) {
		err(EXIT_FAILURE, "failed to read clock %d", CLOCK_REALTIME);
	}
	p = pthread_rwlock_relclockrdlock_np(rwl, CLOCK_REALTIME,
	    &clock_to_100ms);
	elapse = clock_rel_after(CLOCK_REALTIME, &start, &clock_to_100ms);
	if (p != ETIMEDOUT) {
		warnx("TEST FAILED: %s: pthread_rwlock_relclockrdlock_np on "
		    "locked rwlock with CLOCK_REALTIME returned %s, not "
		    "ETIMEDOUT", test->ct_desc, strerrorname_np(p));
		ret = false;
	}
	if (!elapse) {
		warnx("TEST FAILED: %s: pthread_rwlock_relclockrdlock_np on "
		    "locked " "rwlock with CLOCK_REALTIME did not block long "
		    "enough!", test->ct_desc);
		ret = false;
	}

	if (clock_gettime(CLOCK_HIGHRES, &start) != 0) {
		err(EXIT_FAILURE, "failed to read clock %d", CLOCK_HIGHRES);
	}
	p = pthread_rwlock_relclockrdlock_np(rwl, CLOCK_HIGHRES,
	    &clock_to_100ms);
	elapse = clock_rel_after(CLOCK_HIGHRES, &start, &clock_to_100ms);
	if (p != ETIMEDOUT) {
		warnx("TEST FAILED: %s: pthread_rwlock_relclockrdlock_np on "
		    "locked rwlock with CLOCK_HIGHRES returned %s, not "
		    "ETIMEDOUT", test->ct_desc, strerrorname_np(p));
		ret = false;
	}
	if (!elapse) {
		warnx("TEST FAILED: %s: pthread_rwlock_relclockrdlock_np on "
		    "locked rwlock with CLOCK_HIGHRES did not block long "
		    "enough!", test->ct_desc);
		ret = false;
	}

	if (clock_gettime(CLOCK_REALTIME, &start) != 0) {
		err(EXIT_FAILURE, "failed to read clock %d", CLOCK_REALTIME);
	}
	p = pthread_rwlock_reltimedwrlock_np(rwl, &clock_to_100ms);
	elapse = clock_rel_after(CLOCK_REALTIME, &start, &clock_to_100ms);
	if (p != ETIMEDOUT) {
		warnx("TEST FAILED: %s: pthread_rwlock_reltimedwrlock_np on "
		    "locked rwlock returned %s, not ETIMEDOUT", test->ct_desc,
		    strerrorname_np(p));
		ret = false;
	}
	if (!elapse) {
		warnx("TEST FAILED: %s: pthread_rwlock_reltimedwrlock_np on "
		    "locked " "rwlock did not block long enough!",
		    test->ct_desc);
		ret = false;
	}

	if (clock_gettime(CLOCK_REALTIME, &start) != 0) {
		err(EXIT_FAILURE, "failed to read clock %d", CLOCK_REALTIME);
	}
	p = pthread_rwlock_relclockwrlock_np(rwl, CLOCK_REALTIME,
	    &clock_to_100ms);
	elapse = clock_rel_after(CLOCK_REALTIME, &start, &clock_to_100ms);
	if (p != ETIMEDOUT) {
		warnx("TEST FAILED: %s: pthread_rwlock_relclockwrlock_np on "
		    "locked rwlock with CLOCK_REALTIME returned %s, not "
		    "ETIMEDOUT", test->ct_desc, strerrorname_np(p));
		ret = false;
	}
	if (!elapse) {
		warnx("TEST FAILED: %s: pthread_rwlock_relclockwrlock_np on "
		    "locked " "rwlock with CLOCK_REALTIME did not block long "
		    "enough!", test->ct_desc);
		ret = false;
	}

	if (clock_gettime(CLOCK_HIGHRES, &start) != 0) {
		err(EXIT_FAILURE, "failed to read clock %d", CLOCK_HIGHRES);
	}
	p = pthread_rwlock_relclockwrlock_np(rwl, CLOCK_HIGHRES,
	    &clock_to_100ms);
	elapse = clock_rel_after(CLOCK_HIGHRES, &start, &clock_to_100ms);
	if (p != ETIMEDOUT) {
		warnx("TEST FAILED: %s: pthread_rwlock_relclockwrlock_np on "
		    "locked rwlock with CLOCK_HIGHRES returned %s, not "
		    "ETIMEDOUT", test->ct_desc, strerrorname_np(p));
		ret = false;
	}
	if (!elapse) {
		warnx("TEST FAILED: %s: pthread_rwlock_relclockwrlock_np on "
		    "locked rwlock with CLOCK_HIGHRES did not block long "
		    "enough!", test->ct_desc);
		ret = false;
	}

	return (ret);
}
const clock_test_t clock_rwlock_tests[] = { {
	.ct_desc = "rwlock: invalid and unsupported clock sources",
	.ct_ops = &clock_lock_rwlock_ops,
	.ct_test = clock_test_rwlock_invalid_source
}, {
	.ct_desc = "rwlock: invalid timeout works if lock available (absolute)",
	.ct_ops = &clock_lock_rwlock_ops,
	.ct_test = clock_test_rwlock_inv_to_ign_abs
}, {
	.ct_desc = "rwlock: invalid timeout works if lock available (relative)",
	.ct_ops = &clock_lock_rwlock_ops,
	.ct_test = clock_test_rwlock_inv_to_ign_rel
}, {
	.ct_desc = "rwlock: invalid timeout fails if lock taken (absolute)",
	.ct_ops = &clock_lock_rwlock_ops,
	.ct_test = clock_test_rwlock_inv_to_abs,
	.ct_enter = true
}, {
	.ct_desc = "rwlock: invalid timeout fails if lock taken (relative)",
	.ct_ops = &clock_lock_rwlock_ops,
	.ct_test = clock_test_rwlock_inv_to_rel,
	.ct_enter = true
}, {
	.ct_desc = "rwlock: timeout fires correctly (absolute)",
	.ct_ops = &clock_lock_rwlock_ops,
	.ct_test = clock_test_rwlock_to_abs,
	.ct_enter = true
}, {
	.ct_desc = "rwlock: timeout fires correctly (relative)",
	.ct_ops = &clock_lock_rwlock_ops,
	.ct_test = clock_test_rwlock_to_rel,
	.ct_enter = true
} };

size_t clock_rwlock_ntests = ARRAY_SIZE(clock_rwlock_tests);
