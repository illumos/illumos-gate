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
 * Test various mutex types to determine whether we properly deadlock or
 * generate an error when attempting to take the lock. Note, that the issues
 * described in 16200 only occur for a single threaded program which this does
 * not test.
 */

#include <err.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <thread.h>
#include <synch.h>
#include <stdbool.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include <libproc.h>
#include <string.h>
#include <sys/debug.h>

typedef enum {
	MUTEX_TEST_F_USE_ATTR	= 1 << 0,
	MUTEX_TEST_F_SET_TYPE	= 1 << 1,
	MUTEX_TEST_F_DEADLOCK	= 1 << 2,
	MUTEX_TEST_F_ILLUMOS	= 1 << 3
} mutex_test_flags_t;

typedef struct {
	const char *mt_desc;
	mutex_test_flags_t mt_flags;
	int mt_type;
	int mt_ret;
} mutex_test_t;

const mutex_test_t mutex_tests[] = {
	{
		.mt_desc = "pthread attr NULL",
		.mt_flags = MUTEX_TEST_F_DEADLOCK,
		.mt_ret = INT32_MIN
	}, {
		.mt_desc = "pthread attr unset",
		.mt_flags = MUTEX_TEST_F_USE_ATTR | MUTEX_TEST_F_DEADLOCK,
		.mt_ret = INT32_MIN
	}, {
		.mt_desc = "pthrad attr default",
		.mt_flags = MUTEX_TEST_F_USE_ATTR | MUTEX_TEST_F_SET_TYPE |
		    MUTEX_TEST_F_DEADLOCK,
		.mt_type = PTHREAD_MUTEX_DEFAULT,
		.mt_ret = INT32_MIN
	}, {
		.mt_desc = "pthread attr normal",
		.mt_flags = MUTEX_TEST_F_USE_ATTR | MUTEX_TEST_F_SET_TYPE |
		    MUTEX_TEST_F_DEADLOCK,
		.mt_type = PTHREAD_MUTEX_NORMAL,
		/* Set to a value that we should never see or get to */
		.mt_ret = INT32_MIN
	}, {
		.mt_desc = "pthread attr recursive",
		.mt_flags = MUTEX_TEST_F_USE_ATTR | MUTEX_TEST_F_SET_TYPE,
		.mt_type = PTHREAD_MUTEX_RECURSIVE,
		.mt_ret = 0
	}, {
		.mt_desc = "pthread attr errorcheck",
		.mt_flags = MUTEX_TEST_F_USE_ATTR | MUTEX_TEST_F_SET_TYPE,
		.mt_type = PTHREAD_MUTEX_ERRORCHECK,
		.mt_ret = EDEADLK
	}, {
		.mt_desc = "illumos USYNC_THREAD",
		.mt_flags = MUTEX_TEST_F_DEADLOCK | MUTEX_TEST_F_ILLUMOS,
		.mt_type = USYNC_THREAD,
		.mt_ret = INT32_MAX
	}, {
		.mt_desc = "illumos error check",
		.mt_flags = MUTEX_TEST_F_ILLUMOS,
		.mt_type = USYNC_THREAD | LOCK_ERRORCHECK,
		.mt_ret = EDEADLK
	}, {
		.mt_desc = "illumos recursive",
		.mt_flags = MUTEX_TEST_F_ILLUMOS,
		.mt_type = USYNC_THREAD | LOCK_RECURSIVE,
		.mt_ret = 0
	}, {
		.mt_desc = "illumos recursive error check",
		.mt_flags = MUTEX_TEST_F_ILLUMOS,
		.mt_type = USYNC_THREAD | LOCK_RECURSIVE | LOCK_ERRORCHECK,
		.mt_ret = 0
	}
};

static void *
mutex_test_thr(void *arg)
{
	int ret;
	pthread_mutexattr_t attr, *attrp = NULL;
	const mutex_test_t *test = arg;

	if ((test->mt_flags & MUTEX_TEST_F_USE_ATTR) != 0) {
		VERIFY0(pthread_mutexattr_init(&attr));
		attrp = &attr;

		if ((test->mt_flags & MUTEX_TEST_F_SET_TYPE) != 0) {
			VERIFY0(pthread_mutexattr_settype(&attr,
			    test->mt_type));
		}
	}

	if ((test->mt_flags & MUTEX_TEST_F_ILLUMOS) != 0) {
		mutex_t m;

		VERIFY0(mutex_init(&m, test->mt_type, NULL));
		VERIFY0(mutex_lock(&m));
		ret = mutex_lock(&m);
	} else {
		pthread_mutex_t pm;

		VERIFY0(pthread_mutex_init(&pm, attrp));
		VERIFY0(pthread_mutex_lock(&pm));
		ret = pthread_mutex_lock(&pm);
	}

	return ((void *)(uintptr_t)ret);
}


/*
 * Attempt to determine if a thread is still going and we should wait, if it has
 * potentially terminated, or if it is blocked in lwp_park() suggesting it has
 * been deadlocked.
 */
typedef enum {
	THR_STATE_PARKED,
	THR_STATE_DEAD,
	THR_STATE_RUNNING
} thr_state_t;

static thr_state_t
mutex_test_thr_state(thread_t thr)
{
	lwpstatus_t lwp;
	char name[SYS2STR_MAX];

	if (proc_get_lwpstatus(getpid(), (uint_t)thr, &lwp) != 0) {
		int e = errno;
		switch (e) {
		case ENOENT:
			return (THR_STATE_DEAD);
		default:
			errc(EXIT_FAILURE, e, "fatal error: got unexpected "
			    "error while trying to get lwpstatus");
		}
	}

	if ((lwp.pr_flags & PR_ASLEEP) == 0) {
		return (THR_STATE_RUNNING);
	}

	if (proc_sysname(lwp.pr_syscall, name, sizeof (name)) == 0) {
		return (THR_STATE_RUNNING);
	}

	if (strcmp(name, "lwp_park") == 0) {
		return (THR_STATE_PARKED);
	}

	return (THR_STATE_RUNNING);
}

static bool
mutex_test_run_one(const mutex_test_t *test)
{
	int err, lock;
	thread_t thr;
	thr_state_t state;
	void *val;

	err = thr_create(NULL, 0, mutex_test_thr, (void *)test, 0, &thr);
	if (err != 0) {
		errc(EXIT_FAILURE, err, "fatal test error: could not create "
		    "thread for %s", test->mt_desc);
	}

	/*
	 * Wait for the thread to deadlock or exit and then continue.
	 */
	while ((state = mutex_test_thr_state(thr)) == THR_STATE_RUNNING) {
		struct timespec sleep;

		sleep.tv_sec = 0;
		sleep.tv_nsec = MSEC2NSEC(10);
		(void) nanosleep(&sleep, NULL);
	}

	if (state == THR_STATE_PARKED) {
		if ((test->mt_flags & MUTEX_TEST_F_DEADLOCK) != 0) {
			(void) printf("TEST PASSED: %s: successfully "
			    "deadlocked\n", test->mt_desc);
			return (true);
		}

		(void) sleep(100000);

		warnx("TEST FAILED: %s: thread deadlocked, but expected return "
		    "value %d", test->mt_desc, test->mt_ret);
		return (false);
	}

	VERIFY0(thr_join(thr, NULL, &val));
	lock = (int)(uintptr_t)val;
	if ((test->mt_flags & MUTEX_TEST_F_DEADLOCK) != 0) {
		warnx("TEST FAILED: %s: expected deadlock, but mutex lock "
		    "returned %d", test->mt_desc, lock);
		return (false);
	} else if (lock != test->mt_ret) {
		warnx("TEST FAILED: %s: found return value %d, expected %d",
		    test->mt_desc, lock, test->mt_ret);
		return (false);
	} else {
		(void) printf("TEST PASSED: %s: got correct lock return value "
		    "(%d)\n", test->mt_desc, test->mt_ret);
		return (true);
	}
}

int
main(void)
{
	int ret = EXIT_SUCCESS;

	if (getenv("_THREAD_ASYNC_SAFE") != NULL) {
		errx(EXIT_FAILURE, "cannot run tests because "
		    "_THREAD_ASYNC_SAFE is set in the environment!");
	}

	for (size_t i = 0; i < ARRAY_SIZE(mutex_tests); i++) {
		if (!mutex_test_run_one(&mutex_tests[i])) {
			ret = EXIT_FAILURE;
		}
	}

	/*
	 * Ensure any lingering threads don't keep us around.
	 */
	exit(ret);
}
