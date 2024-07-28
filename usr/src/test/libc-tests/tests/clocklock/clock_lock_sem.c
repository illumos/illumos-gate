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
 * semaphore-specific tests
 */


#include <err.h>
#include <stdlib.h>
#include <semaphore.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>

#include "clock_lock.h"

static void
clock_sem_create(const char *desc, void **argp)
{
	int ret;
	sem_t *sem;

	sem = calloc(1, sizeof (sem_t));
	if (sem == NULL) {
		err(EXIT_FAILURE, "TEST FAILED: %s: failed to allocate memory "
		    "for a semaphore", desc);
	}

	if ((ret = sem_init(sem, 0, 1)) != 0) {
		errc(EXIT_FAILURE, ret, "TEST FAILED: %s: failed to create "
		    "semaphore", desc);
	}

	*argp = sem;
}

static void
clock_sem_destroy(void *arg)
{
	VERIFY0(sem_destroy(arg));
	free(arg);
}

static void
clock_sem_lock(void *arg)
{
	VERIFY0(sem_trywait(arg));
}

static void
clock_sem_unlock(void *arg)
{
	VERIFY0(sem_post(arg));
}

const lock_ops_t clock_lock_sem_ops = {
	.lo_create = clock_sem_create,
	.lo_destroy = clock_sem_destroy,
	.lo_lock = clock_sem_lock,
	.lo_unlock = clock_sem_unlock
};

static bool
clock_test_sem_invalid_source(const clock_test_t *test, void *prim)
{
	bool ret = true;
	sem_t *sem = prim;
	const clockid_t clocks[] = { 0x7777, INT32_MAX, 0x23, CLOCK_VIRTUAL,
	    CLOCK_THREAD_CPUTIME_ID, CLOCK_PROCESS_CPUTIME_ID };

	for (size_t i = 0; i < ARRAY_SIZE(clocks); i++) {
		clockid_t c = clocks[i];

		if (sem_clockwait(sem, c, &clock_to_100ms) != -1 ||
		    errno != EINVAL) {
			warnx("TEST FAILED: %s: sem_clockwait with clock 0x%x "
			    "returned %s, not EINVAL", test->ct_desc, c,
			    strerrorname_np(errno));
			ret = false;
		}

		if (sem_relclockwait_np(sem, c, &clock_to_100ms) !=
		    -1 || errno != EINVAL) {
			warnx("TEST FAILED: %s: sem_relclockwait_np with clock "
			    "0x%x returned %s, not EINVAL", test->ct_desc, c,
			    strerrorname_np(errno));
			ret = false;
		}
	}

	return (ret);
}

static bool
clock_test_sem_inv_to_ign_abs(const clock_test_t *test, void *prim)
{
	bool ret = true;
	sem_t *sem = prim;

	if (sem_timedwait(sem, &clock_to_invns) != 0) {
		warnx("TEST FAILED: %s: sem_timedwait failed with an invalid "
		    "timeout when the lock when lock was available: expected "
		    "success, found %s", test->ct_desc, strerrorname_np(errno));
		ret = false;
	} else {
		test->ct_ops->lo_unlock(sem);
	}

	if (sem_clockwait(sem, CLOCK_MONOTONIC, &clock_to_invns) != 0) {
		warnx("TEST FAILED: %s: sem_clockwait failed with an invalid "
		    "timeout when the lock when lock was available: expected "
		    "success, found %s", test->ct_desc, strerrorname_np(errno));
		ret = false;
	} else {
		test->ct_ops->lo_unlock(sem);
	}

	return (ret);
}

static bool
clock_test_sem_inv_to_abs(const clock_test_t *test, void *prim)
{
	bool ret = true;
	sem_t *sem = prim;

	if (sem_timedwait(sem, &clock_to_invns) != -1 || errno != EINVAL) {
		warnx("TEST FAILED: %s: sem_timedwait with invalid timeout "
		    "returned %s, not EINVAL", test->ct_desc,
		    strerrorname_np(errno));
		ret = false;
	}

	if (sem_clockwait(sem, CLOCK_MONOTONIC, &clock_to_invns) != -1 ||
	    errno != EINVAL) {
		warnx("TEST FAILED: %s: sem_clockwait with invalid timeout "
		    "returned %s, not EINVAL", test->ct_desc,
		    strerrorname_np(errno));
		ret = false;
	}

	return (ret);
}

static bool
clock_test_sem_inv_to_ign_rel(const clock_test_t *test, void *prim)
{
	bool ret = true;
	sem_t *sem = prim;
	const struct timespec *specs[] = { &clock_to_invns, &clock_to_invnegs,
	    &clock_to_invnegns };
	const char *descs[] = { "too many nanoseconds", "negative seconds",
	    "negative nanoseconds" };

	for (size_t i = 0; i < ARRAY_SIZE(specs); i++) {
		if (sem_reltimedwait_np(sem, specs[i]) != 0) {
			warnx("TEST FAILED: %s: sem_reltimedwait_np "
			    "failed with invalid timeout %s when the lock when "
			    "lock was available: expected success, found %s",
			    test->ct_desc, descs[i], strerrorname_np(errno));
			ret = false;
		} else {
			test->ct_ops->lo_unlock(sem);
		}

		if (sem_relclockwait_np(sem, CLOCK_MONOTONIC, specs[i]) != 0) {
			warnx("TEST FAILED: %s: sem_relclockwait_np "
			    "failed with invalid timeout %s when the lock when "
			    "lock was available: expected success, found %s",
			    test->ct_desc, descs[i], strerrorname_np(errno));
			ret = false;
		} else {
			test->ct_ops->lo_unlock(sem);
		}
	}

	return (ret);
}

static bool
clock_test_sem_inv_to_rel(const clock_test_t *test, void *prim)
{
	bool ret = true;
	sem_t *sem = prim;
	const struct timespec *specs[] = { &clock_to_invns, &clock_to_invnegs,
	    &clock_to_invnegns };
	const char *descs[] = { "too many nanoseconds", "negative seconds",
	    "negative nanoseconds" };

	for (size_t i = 0; i < ARRAY_SIZE(specs); i++) {
		if (sem_reltimedwait_np(sem, specs[i]) != -1 ||
		    errno != EINVAL) {
			warnx("TEST FAILED: %s: sem_reltimedwait_np "
			    "with invalid timeout %s returned %s, not EINVAL",
			    test->ct_desc, descs[i], strerrorname_np(errno));
			ret = false;
		}

		if (sem_relclockwait_np(sem, CLOCK_MONOTONIC, specs[i]) != -1 ||
		    errno != EINVAL) {
			warnx("TEST FAILED: %s: sem_relclockwait_np "
			    "with invalid timeout %s returned %s, not EINVAL",
			    test->ct_desc, descs[i], strerrorname_np(errno));
			ret = false;
		}
	}

	return (ret);
}

static bool
clock_test_sem_to_abs(const clock_test_t *test, void *prim)
{
	sem_t *sem = prim;
	struct timespec to;
	int p;
	bool ret = true, elapse;

	clock_rel_to_abs(CLOCK_REALTIME, &clock_to_100ms, &to);
	p = sem_timedwait(sem, &to);
	elapse = clock_abs_after(CLOCK_REALTIME, &to);
	if (p != -1 && errno != ETIMEDOUT) {
		warnx("TEST FAILED: %s sem_timedwait on locked semaphore "
		    "returned %s, not ETIMEDOUT", test->ct_desc,
		    strerrorname_np(errno));
		ret = false;
	}
	if (!elapse) {
		warnx("TEST FAILED: %s: sem_timedwait on locked semaphore "
		    "did not block long enough!", test->ct_desc);
		ret = false;
	}

	clock_rel_to_abs(CLOCK_REALTIME, &clock_to_100ms, &to);
	p = sem_clockwait(sem, CLOCK_REALTIME, &to);
	elapse = clock_abs_after(CLOCK_REALTIME, &to);
	if (p != -1 && errno != ETIMEDOUT) {
		warnx("TEST FAILED: %s: sem_clockwait on locked semaphore "
		    "with CLOCK_REALTIME returned %s, not ETIMEDOUT",
		    test->ct_desc, strerrorname_np(errno));
		ret = false;
	}
	if (!elapse) {
		warnx("TEST FAILED: %s: sem_clockwait on locked semaphore "
		    "with CLOCK_REALTIME did not block long enough!",
		    test->ct_desc);
		ret = false;
	}

	clock_rel_to_abs(CLOCK_HIGHRES, &clock_to_100ms, &to);
	p = sem_clockwait(sem, CLOCK_HIGHRES, &to);
	elapse = clock_abs_after(CLOCK_HIGHRES, &to);
	if (p != -1 && errno != ETIMEDOUT) {
		warnx("TEST FAILED: %s: sem_clockwait on locked semaphore "
		    "with CLOCK_HIGHRES returned %s, not ETIMEDOUT",
		    test->ct_desc, strerrorname_np(errno));
		ret = false;
	}
	if (!elapse) {
		warnx("TEST FAILED: %s: sem_clockwait on locked semaphore "
		    "with CLOCK_HIGHRES did not block long enough!",
		    test->ct_desc);
		ret = false;
	}

	return (ret);
}

static bool
clock_test_sem_to_rel(const clock_test_t *test, void *prim)
{
	sem_t *sem = prim;
	struct timespec start;
	int p;
	bool ret = true, elapse;

	if (clock_gettime(CLOCK_REALTIME, &start) != 0) {
		err(EXIT_FAILURE, "failed to read clock %d", CLOCK_REALTIME);
	}
	p = sem_reltimedwait_np(sem, &clock_to_100ms);
	elapse = clock_rel_after(CLOCK_REALTIME, &start, &clock_to_100ms);
	if (p != -1 && errno != ETIMEDOUT) {
		warnx("TEST FAILED: %s: sem_reltimedwait_np on locked "
		    "sempahore returned %s, not ETIMEDOUT", test->ct_desc,
		    strerrorname_np(errno));
		ret = false;
	}
	if (!elapse) {
		warnx("TEST FAILED: %s: sem_reltimedwait_np on locked "
		    "sempahore did not block long enough!", test->ct_desc);
		ret = false;
	}

	if (clock_gettime(CLOCK_REALTIME, &start) != 0) {
		err(EXIT_FAILURE, "failed to read clock %d", CLOCK_REALTIME);
	}
	p = sem_relclockwait_np(sem, CLOCK_REALTIME,
	    &clock_to_100ms);
	elapse = clock_rel_after(CLOCK_REALTIME, &start, &clock_to_100ms);
	if (p != -1 && errno != ETIMEDOUT) {
		warnx("TEST FAILED: %s: sem_relclockwait_np on locked "
		    "semaphore with CLOCK_REALTIME returned %s, not ETIMEDOUT",
		    test->ct_desc, strerrorname_np(errno));
		ret = false;
	}
	if (!elapse) {
		warnx("TEST FAILED: %s: sem_relclockwait_np on locked "
		    "sempahore with CLOCK_REALTIME did not block long enough!",
		    test->ct_desc);
		ret = false;
	}

	if (clock_gettime(CLOCK_HIGHRES, &start) != 0) {
		err(EXIT_FAILURE, "failed to read clock %d", CLOCK_HIGHRES);
	}
	p = sem_relclockwait_np(sem, CLOCK_HIGHRES,
	    &clock_to_100ms);
	elapse = clock_rel_after(CLOCK_HIGHRES, &start, &clock_to_100ms);
	if (p != -1 && errno != ETIMEDOUT) {
		warnx("TEST FAILED: %s: sem_relclockwait_np on locked "
		    "semaphore with CLOCK_HIGHRES returned %s, not ETIMEDOUT",
		    test->ct_desc, strerrorname_np(errno));
		ret = false;
	}
	if (!elapse) {
		warnx("TEST FAILED: %s: sem_relclockwait_np on locked "
		    "semaphore with CLOCK_HIGHRES did not block long enough!",
		    test->ct_desc);
		ret = false;
	}

	return (ret);
}

const clock_test_t clock_sem_tests[] = { {
	.ct_desc = "sem: invalid and unsupported clock sources",
	.ct_ops = &clock_lock_sem_ops,
	.ct_test = clock_test_sem_invalid_source
}, {
	.ct_desc = "sem: invalid timeout works if lock available (absolute)",
	.ct_ops = &clock_lock_sem_ops,
	.ct_test = clock_test_sem_inv_to_ign_abs
}, {
	.ct_desc = "sem: invalid timeout works if lock available (relative)",
	.ct_ops = &clock_lock_sem_ops,
	.ct_test = clock_test_sem_inv_to_ign_rel
}, {
	.ct_desc = "sem: invalid timeout fails if lock taken (absolute)",
	.ct_ops = &clock_lock_sem_ops,
	.ct_test = clock_test_sem_inv_to_abs,
	.ct_enter = true
}, {
	.ct_desc = "sem: invalid timeout fails if lock taken (relative)",
	.ct_ops = &clock_lock_sem_ops,
	.ct_test = clock_test_sem_inv_to_rel,
	.ct_enter = true
}, {
	.ct_desc = "sem: timeout fires correctly (absolute)",
	.ct_ops = &clock_lock_sem_ops,
	.ct_test = clock_test_sem_to_abs,
	.ct_enter = true
}, {
	.ct_desc = "sem: timeout fires correctly (relative)",
	.ct_ops = &clock_lock_sem_ops,
	.ct_test = clock_test_sem_to_rel,
	.ct_enter = true
} };

size_t clock_sem_ntests = ARRAY_SIZE(clock_sem_tests);
