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
 * The purpose of this test is to ensure that we honor several aspects of our
 * lock ordering. In particular we want to validate the following our starvation
 * properties, that is that blocking writers should take priority ahead of
 * blocking readers and that the controller lock takes priority over various
 * namespace locks. While we test all kinds of locks here, we only use the
 * controller fd here to simplify the test design.
 *
 * To do this, we utilize our blocking locks. In particular, we take a first
 * lock and then spin up threads that should all block on that. To deal with the
 * inherit race of knowing when a thread is blocked or not, we utilize libproc
 * and wait until the thread has the PR_ASLEEP flag set and that it's in an
 * ioctl system call. This ensures that the folks that are present are added in
 * the appropriate order.
 */

#include <err.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>
#include <thread.h>
#include <synch.h>
#include <strings.h>

#include "nvme_ioctl_util.h"

/*
 * Maximum number of threads that we'll spin up for locks.
 */
#define	MAX_LOCKS	10

typedef struct {
	thread_t loi_thread;
	const nvme_ioctl_lock_t *loi_lock;
} lock_order_info_t;

static mutex_t lock_mutex;
static lock_order_info_t lock_results[MAX_LOCKS];
static uint32_t lock_nextres;
static bool lock_valid;

typedef struct lock_order_test lock_order_test_t;
typedef bool (*lock_order_valif_f)(const lock_order_test_t *, uint32_t);

struct lock_order_test {
	const char *lot_desc;
	const nvme_ioctl_lock_t *lot_initlock;
	const nvme_ioctl_lock_t *lot_locks[MAX_LOCKS];
	lock_order_valif_f lot_verif;
};

static void
lock_verify_dump(void)
{
	for (size_t i = 0; i < lock_nextres; i++) {
		const nvme_ioctl_lock_t *lock = lock_results[i].loi_lock;
		const char *targ = lock->nil_ent == NVME_LOCK_E_CTRL ?
		    "controller" : "namespace";
		const char *level = lock->nil_level == NVME_LOCK_L_READ ?
		    "read" : "write";
		(void) printf("\t[%zu] = { %s, %s }\n", i, targ, level);
	}
}

/*
 * Verify that a given number of writers in the test are all found ahead of any
 * readers found in the test.
 */
static bool
lock_verify_write_before_read(const lock_order_test_t *test, uint32_t nthr)
{
	bool pass = true;
	size_t nwrite = 0;
	size_t nread = 0;

	for (size_t i = 0; i < MAX_LOCKS; i++) {
		if (test->lot_locks[i] == NULL)
			break;
		if (test->lot_locks[i]->nil_level == NVME_LOCK_L_READ) {
			nread++;
		} else {
			nwrite++;
		}
	}
	VERIFY3U(nwrite + nread, ==, nthr);

	mutex_enter(&lock_mutex);
	for (size_t i = 0; i < nthr; i++) {
		nvme_lock_level_t exp_level;
		const char *str;
		const lock_order_info_t *res = &lock_results[i];

		if (nwrite > 0) {
			exp_level = NVME_LOCK_L_WRITE;
			str = "WRITE";
			nwrite--;
		} else {
			exp_level = NVME_LOCK_L_READ;
			str = "READ";
			nread--;
		}

		if (exp_level != res->loi_lock->nil_level) {
			pass = false;
			warnx("TEST FAILED: %s: lock %zu (tid %u, ent %u, "
			    "level %u) was the wrong level, expected level %u "
			    "(%s)", test->lot_desc, i, res->loi_thread,
			    res->loi_lock->nil_ent, res->loi_lock->nil_level,
			    exp_level, str);
		}
	}
	VERIFY3U(nwrite, ==, 0);
	VERIFY3U(nread, ==, 0);

	if (!pass) {
		lock_verify_dump();
	}
	mutex_exit(&lock_mutex);

	return (pass);
}

/*
 * This verifies that all controller level locks should come in the order before
 * the namespace locks. Note, this also calls the write before read checks and
 * therefore assumes that we have an ordering that supports that.
 */
static bool
lock_verify_ctrl_before_ns(const lock_order_test_t *test, uint32_t nthr)
{
	bool pass = true;
	size_t nctrl = 0;
	size_t nns = 0;

	for (size_t i = 0; i < MAX_LOCKS; i++) {
		if (test->lot_locks[i] == NULL)
			break;
		if (test->lot_locks[i]->nil_ent == NVME_LOCK_E_CTRL) {
			nctrl++;
		} else {
			nns++;
		}
	}
	VERIFY3U(nctrl + nns, ==, nthr);

	mutex_enter(&lock_mutex);
	for (size_t i = 0; i < nthr; i++) {
		nvme_lock_ent_t exp_ent;
		const char *str;
		const lock_order_info_t *res = &lock_results[i];

		if (nctrl > 0) {
			exp_ent = NVME_LOCK_E_CTRL;
			str = "ctrl";
			nctrl--;
		} else {
			exp_ent = NVME_LOCK_E_NS;
			str = "ns";
			nns--;
		}

		if (exp_ent != res->loi_lock->nil_ent) {
			pass = false;
			warnx("TEST FAILED: %s: lock %zu (tid %u, ent %u, "
			    "level %u) was the wrong entity, expected type %u "
			    "(%s)", test->lot_desc, i, res->loi_thread,
			    res->loi_lock->nil_ent, res->loi_lock->nil_level,
			    exp_ent, str);
		}
	}

	VERIFY3U(nctrl, ==, 0);
	VERIFY3U(nns, ==, 0);

	if (!pass) {
		lock_verify_dump();
	}
	mutex_exit(&lock_mutex);

	return (pass);
}

static bool
lock_verif_ent_level(const lock_order_test_t *test, uint32_t nthr)
{
	bool pass = true;

	if (!lock_verify_ctrl_before_ns(test, nthr))
		pass = false;
	if (!lock_verify_write_before_read(test, nthr))
		pass = false;
	return (pass);
}

/*
 * The descriptions below are fashioned with the starting lock followed by what
 * order we're testing.
 */
static const lock_order_test_t lock_order_tests[] = { {
	.lot_desc = "ns(rd): pending ns writer doesn't allow more ns readers",
	.lot_initlock = &nvme_test_ns_rdlock,
	.lot_locks = { &nvme_test_ns_wrlock, &nvme_test_ns_rdlock },
	.lot_verif = lock_verify_write_before_read,
}, {
	.lot_desc = "ns(wr): pending ns writer beats waiting ns reader",
	.lot_initlock = &nvme_test_ns_wrlock,
	.lot_locks = { &nvme_test_ns_rdlock, &nvme_test_ns_wrlock },
	.lot_verif = lock_verify_write_before_read,
}, {
	.lot_desc = "ns(rd): all pend ns writers beat prior pend readers",
	.lot_initlock = &nvme_test_ns_rdlock,
	.lot_locks = { &nvme_test_ns_wrlock, &nvme_test_ns_rdlock,
	    &nvme_test_ns_rdlock, &nvme_test_ns_wrlock, &nvme_test_ns_rdlock,
	    &nvme_test_ns_wrlock },
	.lot_verif = lock_verify_write_before_read,
}, {
	.lot_desc = "ns(rd): pending ctrl writer doesn't allow more ns readers",
	.lot_initlock = &nvme_test_ns_rdlock,
	.lot_locks = { &nvme_test_ctrl_wrlock, &nvme_test_ns_rdlock,
	    &nvme_test_ns_rdlock },
	.lot_verif = lock_verify_write_before_read,
}, {
	.lot_desc = "ns(wr): pending ctrl writer beats prior pend ns readers",
	.lot_initlock = &nvme_test_ns_wrlock,
	.lot_locks = { &nvme_test_ns_rdlock, &nvme_test_ns_rdlock,
	    &nvme_test_ctrl_wrlock, &nvme_test_ns_rdlock },
	.lot_verif = lock_verify_write_before_read,
}, {
	.lot_desc = "ns(rd): pending ctrl writer doesn't allow ctrl readers",
	.lot_initlock = &nvme_test_ns_rdlock,
	.lot_locks = { &nvme_test_ctrl_wrlock, &nvme_test_ctrl_rdlock,
	    &nvme_test_ctrl_rdlock },
	.lot_verif = lock_verify_write_before_read,
}, {
	.lot_desc = "ns(rd): pending ctrl writer beats pending ns writer "
	    "and readers",
	.lot_initlock = &nvme_test_ns_rdlock,
	.lot_locks = { &nvme_test_ns_wrlock, &nvme_test_ns_rdlock,
	    &nvme_test_ctrl_wrlock, &nvme_test_ctrl_rdlock },
	.lot_verif = lock_verify_ctrl_before_ns,
}, {
	.lot_desc = "ctrl(rd): pending ctrl writer blocks ns read",
	.lot_initlock = &nvme_test_ctrl_rdlock,
	.lot_locks = { &nvme_test_ctrl_wrlock, &nvme_test_ns_rdlock,
	    &nvme_test_ns_rdlock },
	.lot_verif = lock_verif_ent_level,
}, {
	.lot_desc = "ctrl(rd): pending ctrl writer blocks ns writer",
	.lot_initlock = &nvme_test_ctrl_rdlock,
	.lot_locks = { &nvme_test_ctrl_wrlock, &nvme_test_ns_wrlock },
	.lot_verif = lock_verif_ent_level,
}, {
	.lot_desc = "ctrl(rd): pending ctrl writer blocks ctrl reader",
	.lot_initlock = &nvme_test_ctrl_rdlock,
	.lot_locks = { &nvme_test_ctrl_wrlock, &nvme_test_ctrl_rdlock },
	.lot_verif = lock_verify_write_before_read,
}, {
	.lot_desc = "ctrl(wr): ctrl writer beats all pending readers",
	.lot_initlock = &nvme_test_ctrl_wrlock,
	.lot_locks = { &nvme_test_ctrl_rdlock, &nvme_test_ctrl_rdlock,
	    &nvme_test_ns_rdlock, &nvme_test_ns_rdlock,
	    &nvme_test_ctrl_wrlock },
	.lot_verif = lock_verify_write_before_read,
}, {
	.lot_desc = "ctrl(wr): ns writer beats all pending ns readers",
	.lot_initlock = &nvme_test_ctrl_wrlock,
	.lot_locks = { &nvme_test_ns_rdlock, &nvme_test_ns_rdlock,
	    &nvme_test_ns_wrlock, &nvme_test_ns_rdlock, &nvme_test_ns_wrlock },
	.lot_verif = lock_verify_write_before_read,
} };

static void *
lock_thread(void *arg)
{
	const nvme_ioctl_lock_t *tmpl = arg;
	nvme_ioctl_lock_t lock = *tmpl;
	int ctrlfd = nvme_ioctl_test_get_fd(0);
	const char *targ = tmpl->nil_ent == NVME_LOCK_E_CTRL ?
	    "controller" : "namespace";
	const char *level = tmpl->nil_level == NVME_LOCK_L_READ ?
	    "read" : "write";

	lock.nil_flags &= ~NVME_LOCK_F_DONT_BLOCK;
	nvme_ioctl_test_lock(ctrlfd, &lock);

	mutex_enter(&lock_mutex);
	if (!lock_valid) {
		errx(EXIT_FAILURE, "TEST FAILED: thread 0x%x managed to return "
		    "with held %s %s lock before main thread unlocked: test "
		    "cannot continue", thr_self(), targ, level);
	}
	VERIFY3U(lock_nextres, <, MAX_LOCKS);
	lock_results[lock_nextres].loi_thread = thr_self();
	lock_results[lock_nextres].loi_lock = tmpl;
	lock_nextres++;
	mutex_exit(&lock_mutex);

	VERIFY0(close(ctrlfd));

	thr_exit(NULL);
}

static bool
lock_order_test(const lock_order_test_t *test)
{
	int ctrlfd;
	uint32_t nthr = 0;
	thread_t thrids[MAX_LOCKS];

	/*
	 * Ensure we have whatever lock we intend to create ahead of doing
	 * anything else.
	 */
	ctrlfd = nvme_ioctl_test_get_fd(0);
	nvme_ioctl_test_lock(ctrlfd, test->lot_initlock);

	mutex_enter(&lock_mutex);
	(void) memset(&lock_results, 0, sizeof (lock_results));
	lock_nextres = 0;
	lock_valid = false;
	mutex_exit(&lock_mutex);

	for (uint32_t i = 0; i < MAX_LOCKS; i++, nthr++) {
		int err;

		if (test->lot_locks[i] == NULL)
			break;

		err = thr_create(NULL, 0, lock_thread,
		    (void *)test->lot_locks[i], 0, &thrids[i]);
		if (err != 0) {
			errc(EXIT_FAILURE, err, "TEST FAILED: %s: cannot "
			    "continue because we failed to create thread %u",
			    test->lot_desc, i);
		}

		while (!nvme_ioctl_test_thr_blocked(thrids[i])) {
			struct timespec sleep;

			sleep.tv_sec = 0;
			sleep.tv_nsec = MSEC2NSEC(10);
			(void) nanosleep(&sleep, NULL);
		}
	}

	/*
	 * Now that all threads have been launched, close our fd to allow them
	 * to run loose and wait for them. Indicate to them that now it is okay
	 * to get the lock.
	 */
	mutex_enter(&lock_mutex);
	lock_valid = true;
	mutex_exit(&lock_mutex);
	VERIFY0(close(ctrlfd));
	for (uint32_t i = 0; i < nthr; i++) {
		int err = thr_join(thrids[i], NULL, NULL);
		if (err != 0) {
			errc(EXIT_FAILURE, err, "TEST FAILED: %s: cannot "
			    "continue because we failed to join thread %u",
			    test->lot_desc, i);
		}
	}
	mutex_enter(&lock_mutex);
	VERIFY3U(lock_nextres, ==, nthr);
	mutex_exit(&lock_mutex);

	if (test->lot_verif(test, nthr)) {
		(void) printf("TEST PASSED: %s\n", test->lot_desc);
		return (true);
	}

	return (false);
}

int
main(void)
{
	int ret = EXIT_SUCCESS;

	VERIFY0(mutex_init(&lock_mutex, USYNC_THREAD | LOCK_ERRORCHECK, NULL));

	for (size_t i = 0; i < ARRAY_SIZE(lock_order_tests); i++) {
		if (!lock_order_test(&lock_order_tests[i])) {
			ret = EXIT_FAILURE;
		}
	}

	VERIFY0(mutex_destroy(&lock_mutex));
	return (ret);
}
