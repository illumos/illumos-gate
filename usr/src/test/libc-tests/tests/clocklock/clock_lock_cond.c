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
 * conditionn variable-specific tests
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

typedef struct {
	pthread_mutex_t cc_mutex;
	pthread_cond_t cc_cond;
} clock_cond_t;

static void
clock_cond_create(const char *desc, void **argp)
{
	int ret;
	clock_cond_t *cc;
	pthread_mutexattr_t attr;

	cc = calloc(1, sizeof (clock_cond_t));
	if (cc == NULL) {
		err(EXIT_FAILURE, "TEST FAILED: %s: failed to allocate memory "
		    "for a mutex and condition variable", desc);
	}

	if ((ret = pthread_cond_init(&cc->cc_cond, NULL)) != 0) {
		errc(EXIT_FAILURE, ret, "TEST FAILED: %s: failed to create "
		    "condition variable", desc);
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

	if ((ret = pthread_mutex_init(&cc->cc_mutex, &attr)) != 0) {
		errc(EXIT_FAILURE, ret, "TEST FAILED: %s: failed to create "
		    "mutex", desc);
	}

	*argp = cc;
}

static void
clock_cond_destroy(void *arg)
{
	clock_cond_t *cc = arg;

	VERIFY0(pthread_mutex_destroy(&cc->cc_mutex));
	VERIFY0(pthread_cond_destroy(&cc->cc_cond));
}

/*
 * Unlike the other primitives, there is no notion of a condition variable being
 * locked or unlocked. Hence there is no implementation.
 */
const lock_ops_t clock_lock_cond_ops = {
	.lo_create = clock_cond_create,
	.lo_destroy = clock_cond_destroy
};

static bool
clock_test_cond_invalid_source(const clock_test_t *test, void *arg)
{
	bool ret = true;
	clock_cond_t *cc = arg;
	pthread_mutex_t *mutex = &cc->cc_mutex;
	pthread_cond_t *cond = &cc->cc_cond;
	const clockid_t clocks[] = { 0x7777, INT32_MAX, 0x23, CLOCK_VIRTUAL,
	    CLOCK_THREAD_CPUTIME_ID, CLOCK_PROCESS_CPUTIME_ID };
	int p;

	pthread_mutex_enter_np(mutex);
	for (size_t i = 0; i < ARRAY_SIZE(clocks); i++) {
		clockid_t c = clocks[i];

		if ((p = pthread_cond_clockwait(cond, mutex, c,
		    &clock_to_100ms)) != EINVAL) {
			warnx("TEST FAILED: %s: pthread_cond_clockwait with "
			    "clock 0x%x returned %s, not EINVAL", test->ct_desc,
			    c, strerrorname_np(p));
			ret = false;
		}

		if ((p = pthread_cond_relclockwait_np(cond, mutex, c,
		    &clock_to_100ms)) != EINVAL) {
			warnx("TEST FAILED: %s: pthread_cond_relclockwait_np "
			    "with clock 0x%x returned %s, not EINVAL",
			    test->ct_desc, c, strerrorname_np(p));
			ret = false;
		}
	}
	pthread_mutex_exit_np(mutex);

	return (ret);
}

static bool
clock_test_cond_inv_to_abs(const clock_test_t *test, void *prim)
{
	bool ret = true;
	clock_cond_t *cc = prim;
	int p;

	pthread_mutex_enter_np(&cc->cc_mutex);
	if ((p = pthread_cond_timedwait(&cc->cc_cond, &cc->cc_mutex,
	    &clock_to_invns)) != EINVAL) {
		warnx("TEST FAILED: %s: pthread_cond_timedwait with invalid "
		    "timeout returned %s, not EINVAL", test->ct_desc,
		    strerrorname_np(p));
		ret = false;
	}

	if ((p = pthread_cond_clockwait(&cc->cc_cond, &cc->cc_mutex,
	    CLOCK_MONOTONIC, &clock_to_invns)) != EINVAL) {
		warnx("TEST FAILED: %s: pthread_cond_clockwait with invalid "
		    "timeout returned %s, not EINVAL", test->ct_desc,
		    strerrorname_np(p));
		ret = false;
	}
	pthread_mutex_exit_np(&cc->cc_mutex);

	return (ret);
}

static bool
clock_test_cond_inv_to_rel(const clock_test_t *test, void *prim)
{
	bool ret = true;
	clock_cond_t *cc = prim;
	const struct timespec *specs[] = { &clock_to_invns, &clock_to_invnegs,
	    &clock_to_invnegns };
	const char *descs[] = { "too many nanoseconds", "negative seconds",
	    "negative nanoseconds" };
	int p;

	pthread_mutex_enter_np(&cc->cc_mutex);
	for (size_t i = 0; i < ARRAY_SIZE(specs); i++) {
		if ((p = pthread_cond_reltimedwait_np(&cc->cc_cond,
		    &cc->cc_mutex, specs[i])) != EINVAL) {
			warnx("TEST FAILED: %s: pthread_cond_reltimedwait_np "
			    "with invalid timeout %s returned %s, not EINVAL",
			    test->ct_desc, descs[i], strerrorname_np(p));
			ret = false;
		}

		if ((p = pthread_cond_relclockwait_np(&cc->cc_cond,
		    &cc->cc_mutex, CLOCK_MONOTONIC, specs[i])) != EINVAL) {
			warnx("TEST FAILED: %s: pthread_cond_relclockwait_np "
			    "with invalid timeout %s returned %s, not EINVAL",
			    test->ct_desc, descs[i], strerrorname_np(p));
			ret = false;
		}
	}
	pthread_mutex_exit_np(&cc->cc_mutex);

	return (ret);
}

static bool
clock_test_cond_to_abs(const clock_test_t *test, void *prim)
{
	clock_cond_t *cc = prim;
	struct timespec to;
	int p;
	bool ret = true, elapse;

	pthread_mutex_enter_np(&cc->cc_mutex);
	clock_rel_to_abs(CLOCK_REALTIME, &clock_to_100ms, &to);
	p = pthread_cond_timedwait(&cc->cc_cond, &cc->cc_mutex, &to);
	elapse = clock_abs_after(CLOCK_REALTIME, &to);
	if (p != ETIMEDOUT) {
		warnx("TEST FAILED: %s pthread_cond_timedwait returned %s, not "
		    "ETIMEDOUT", test->ct_desc, strerrorname_np(p));
		ret = false;
	}
	if (!elapse) {
		warnx("TEST FAILED: %s: pthread_cond_timedwait did not block "
		    "long enough!", test->ct_desc);
		ret = false;
	}

	clock_rel_to_abs(CLOCK_REALTIME, &clock_to_100ms, &to);
	p = pthread_cond_clockwait(&cc->cc_cond, &cc->cc_mutex, CLOCK_REALTIME,
	    &to);
	elapse = clock_abs_after(CLOCK_REALTIME, &to);
	if (p != ETIMEDOUT) {
		warnx("TEST FAILED: %s: pthread_cond_clockwait with "
		    "CLOCK_REALTIME returned %s, not ETIMEDOUT", test->ct_desc,
		    strerrorname_np(p));
		ret = false;
	}
	if (!elapse) {
		warnx("TEST FAILED: %s: pthread_cond_clockwait with "
		    "CLOCK_REALTIME did not block long enough!", test->ct_desc);
		ret = false;
	}

	clock_rel_to_abs(CLOCK_HIGHRES, &clock_to_100ms, &to);
	p = pthread_cond_clockwait(&cc->cc_cond, &cc->cc_mutex, CLOCK_HIGHRES,
	    &to);
	elapse = clock_abs_after(CLOCK_HIGHRES, &to);
	if (p != ETIMEDOUT) {
		warnx("TEST FAILED: %s: pthread_cond_clockwait with "
		    "CLOCK_HIGHRES returned %s, not ETIMEDOUT", test->ct_desc,
		    strerrorname_np(p));
		ret = false;
	}
	if (!elapse) {
		warnx("TEST FAILED: %s: pthread_cond_clockwait with "
		    "CLOCK_HIGHRES did not block long enough!", test->ct_desc);
		ret = false;
	}
	pthread_mutex_exit_np(&cc->cc_mutex);

	return (ret);
}

static bool
clock_test_cond_to_rel(const clock_test_t *test, void *prim)
{
	clock_cond_t *cc = prim;
	struct timespec start;
	int p;
	bool ret = true, elapse;

	pthread_mutex_enter_np(&cc->cc_mutex);
	if (clock_gettime(CLOCK_REALTIME, &start) != 0) {
		err(EXIT_FAILURE, "failed to read clock %d", CLOCK_REALTIME);
	}
	p = pthread_cond_reltimedwait_np(&cc->cc_cond, &cc->cc_mutex,
	    &clock_to_100ms);
	elapse = clock_rel_after(CLOCK_REALTIME, &start, &clock_to_100ms);
	if (p != ETIMEDOUT) {
		warnx("TEST FAILED: %s: pthread_cond_reltimedwait_np returned "
		    "%s, not ETIMEDOUT", test->ct_desc,
		    strerrorname_np(p));
		ret = false;
	}
	if (!elapse) {
		warnx("TEST FAILED: %s: pthread_cond_reltimedwait_np did not "
		    "block long enough!", test->ct_desc);
		ret = false;
	}

	if (clock_gettime(CLOCK_REALTIME, &start) != 0) {
		err(EXIT_FAILURE, "failed to read clock %d", CLOCK_REALTIME);
	}
	p = pthread_cond_relclockwait_np(&cc->cc_cond, &cc->cc_mutex,
	    CLOCK_REALTIME, &clock_to_100ms);
	elapse = clock_rel_after(CLOCK_REALTIME, &start, &clock_to_100ms);
	if (p != ETIMEDOUT) {
		warnx("TEST FAILED: %s: pthread_cond_relclockwait_np with "
		    "CLOCK_REALTIME returned %s, not ETIMEDOUT", test->ct_desc,
		    strerrorname_np(p));
		ret = false;
	}
	if (!elapse) {
		warnx("TEST FAILED: %s: pthread_cond_relclockwait_np with "
		    "CLOCK_REALTIME did not block long enough!", test->ct_desc);
		ret = false;
	}

	if (clock_gettime(CLOCK_HIGHRES, &start) != 0) {
		err(EXIT_FAILURE, "failed to read clock %d", CLOCK_HIGHRES);
	}
	p = pthread_cond_relclockwait_np(&cc->cc_cond, &cc->cc_mutex,
	    CLOCK_HIGHRES, &clock_to_100ms);
	elapse = clock_rel_after(CLOCK_HIGHRES, &start, &clock_to_100ms);
	if (p != ETIMEDOUT) {
		warnx("TEST FAILED: %s: pthread_cond_relclockwait_np with "
		    "CLOCK_HIGHRES returned %s, not ETIMEDOUT", test->ct_desc,
		    strerrorname_np(p));
		ret = false;
	}
	if (!elapse) {
		warnx("TEST FAILED: %s: pthread_cond_relclockwait_np with "
		    "CLOCK_HIGHRES did not block long enough!", test->ct_desc);
		ret = false;
	}
	pthread_mutex_exit_np(&cc->cc_mutex);

	return (ret);
}

static bool
clock_test_cond_eperm(const clock_test_t *test, void *prim)
{
	bool ret = true;
	clock_cond_t *cc = prim;
	int p;

	if ((p = pthread_cond_timedwait(&cc->cc_cond, &cc->cc_mutex,
	    &clock_to_100ms)) != EPERM) {
		warnx("TEST FAILED: %s: pthread_cond_timedwait without held "
		    "mutex returned %s, not EPERM", test->ct_desc,
		    strerrorname_np(p));
		ret = false;
	}

	if ((p = pthread_cond_clockwait(&cc->cc_cond, &cc->cc_mutex,
	    CLOCK_MONOTONIC, &clock_to_100ms)) != EPERM) {
		warnx("TEST FAILED: %s: pthread_cond_clockwait without held "
		    "mutex returned %s, not EPERM", test->ct_desc,
		    strerrorname_np(p));
		ret = false;
	}

	if ((p = pthread_cond_reltimedwait_np(&cc->cc_cond, &cc->cc_mutex,
	    &clock_to_100ms)) != EPERM) {
		warnx("TEST FAILED: %s: pthread_cond_reltimedwait_np without "
		    "held mutex returned %s, not EPERM", test->ct_desc,
		    strerrorname_np(p));
		ret = false;
	}

	if ((p = pthread_cond_relclockwait_np(&cc->cc_cond, &cc->cc_mutex,
	    CLOCK_HIGHRES, &clock_to_100ms)) != EPERM) {
		warnx("TEST FAILED: %s: pthread_cond_relclockwait_np without "
		    "held mutex returned %s, not EPERM", test->ct_desc,
		    strerrorname_np(p));
		ret = false;
	}

	return (ret);
}

const clock_test_t clock_cond_tests[] = { {
	.ct_desc = "cond: invalid and unsupported clock sources",
	.ct_ops = &clock_lock_cond_ops,
	.ct_test = clock_test_cond_invalid_source
}, {
	.ct_desc = "cond: invalid timeout fails (absolute)",
	.ct_ops = &clock_lock_cond_ops,
	.ct_test = clock_test_cond_inv_to_abs
}, {
	.ct_desc = "cond: invalid timeout fails (relative)",
	.ct_ops = &clock_lock_cond_ops,
	.ct_test = clock_test_cond_inv_to_rel
}, {
	.ct_desc = "cond: timeout fires correctly (absolute)",
	.ct_ops = &clock_lock_cond_ops,
	.ct_test = clock_test_cond_to_abs
}, {
	.ct_desc = "cond: timeout fires correctly (relative)",
	.ct_ops = &clock_lock_cond_ops,
	.ct_test = clock_test_cond_to_rel
}, {
	.ct_desc = "cond: fails without lock",
	.ct_ops = &clock_lock_cond_ops,
	.ct_test = clock_test_cond_eperm
} };

size_t clock_cond_ntests = ARRAY_SIZE(clock_cond_tests);
