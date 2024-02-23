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
 * Create a thread that blocks on a lock and then once we know it is blocked,
 * signal it. Verify that it errored out with EINTR. Once we do that, we ensure
 * we can take all four basic locks in turn to verify that our state isn't bad.
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
#include <signal.h>

#include "nvme_ioctl_util.h"

static volatile int lock_sig_ret = EXIT_SUCCESS;
static volatile uint32_t lock_sig_nsignals = 0;
static volatile thread_t lock_sig_thrid;

typedef struct {
	const char *lss_desc;
	const nvme_ioctl_lock_t *lss_lock;
} lock_sig_test_t;

static const lock_sig_test_t lock_sig_tests[] = {
	{ "controller write lock", &nvme_test_ctrl_wrlock },
	{ "controller read lock", &nvme_test_ctrl_wrlock },
	{ "namespace write lock", &nvme_test_ns_wrlock },
	{ "namespace read lock", &nvme_test_ns_wrlock }
};

static void
lock_signal_hdlr(int sig)
{
	VERIFY3U(sig, ==, SIGINFO);
	VERIFY3U(thr_self(), ==, lock_sig_thrid);
	lock_sig_nsignals++;
}

static void *
lock_signal_thr(void *arg)
{
	int fd = nvme_ioctl_test_get_fd(0);
	const lock_sig_test_t *test = arg;
	nvme_ioctl_lock_t lock = *test->lss_lock;
	sigset_t set;
	int ret;

	VERIFY0(sigemptyset(&set));
	VERIFY0(sigaddset(&set, SIGINFO));
	lock_sig_thrid = thr_self();

	if ((ret = thr_sigsetmask(SIG_UNBLOCK, &set, NULL)) != 0) {
		errc(EXIT_FAILURE, ret, "failed to unblock SIGINFO");
	}


	lock.nil_flags &= ~NVME_LOCK_F_DONT_BLOCK;
	if (ioctl(fd, NVME_IOC_LOCK, &lock) != 0) {
		err(EXIT_FAILURE, "TEST FAILED: unable to continue test "
		    "execution due to lock ioctl failure");
	}

	if (lock.nil_common.nioc_drv_err != NVME_IOCTL_E_LOCK_WAIT_SIGNAL) {
		warnx("TEST FAILED: %s: lock thread didn't error with "
		    "NVME_IOCTL_E_LOCK_WAIT_SIGNAL (%u), but found instead %u",
		    test->lss_desc, NVME_IOCTL_E_LOCK_WAIT_SIGNAL,
		    lock.nil_common.nioc_drv_err);
		lock_sig_ret = EXIT_FAILURE;
	} else {
		(void) printf("TEST PASSED: %s: thread successfully "
		    "interrupted\n", test->lss_desc);
	}

	thr_exit(NULL);
}

static void
lock_signal_one(const lock_sig_test_t *test)
{
	int fd = nvme_ioctl_test_get_fd(0);
	int ret;
	thread_t thr;

	nvme_ioctl_test_lock(fd, &nvme_test_ctrl_wrlock);
	ret = thr_create(NULL, 0, lock_signal_thr, (void *)test, 0, &thr);
	if (ret != 0) {
		errc(EXIT_FAILURE, ret, "TEST FAILED: %s: cannot continue "
		    "because we failed to create the thread to signal",
		    test->lss_desc);
	}

	while (!nvme_ioctl_test_thr_blocked(thr)) {
		struct timespec sleep;

		sleep.tv_sec = 0;
		sleep.tv_nsec = MSEC2NSEC(10);
		(void) nanosleep(&sleep, NULL);
	}

	ret = thr_kill(thr, SIGINFO);
	if (ret != 0) {
		errc(EXIT_FAILURE, ret, "TEST FAILED: %s: cannot continue "
		    "because we failed to send SIGINFO to tid %u",
		    test->lss_desc, thr);
	}

	ret = thr_join(thr, NULL, NULL);
	if (ret != 0) {
		errc(EXIT_FAILURE, ret, "TEST FAILED: %s: cannot continue "
		    "because we failed to join thread %u", test->lss_desc, thr);
	}

	VERIFY0(close(fd));
	fd = nvme_ioctl_test_get_fd(0);
	nvme_ioctl_test_lock(fd, test->lss_lock);
	(void) printf("TEST PASSED: %s: successfully grabbed follow up lock\n",
	    test->lss_desc);
	VERIFY0(close(fd));
}

int
main(void)
{
	int ret;
	sigset_t set;
	struct sigaction act;

	VERIFY0(sigfillset(&set));
	if ((ret = thr_sigsetmask(SIG_BLOCK, &set, NULL)) != 0) {
		errc(EXIT_FAILURE, ret, "failed to block signals");
	}

	act.sa_handler = lock_signal_hdlr;
	VERIFY0(sigemptyset(&act.sa_mask));
	act.sa_flags = 0;
	VERIFY0(sigaction(SIGINFO, &act, NULL));

	for (size_t i = 0; i < ARRAY_SIZE(lock_sig_tests); i++) {
		lock_signal_one(&lock_sig_tests[i]);
	}

	if (lock_sig_nsignals != ARRAY_SIZE(lock_sig_tests)) {
		lock_sig_ret = EXIT_FAILURE;
		warnx("TEST FAILED: Didn't get %zu SIGINFO handlers, instead "
		    "got %u", ARRAY_SIZE(lock_sig_tests), lock_sig_nsignals);
	} else {
		(void) printf("TEST PASSED: Successfully ran SIGINFO "
		    "handlers\n");
	}

	return (lock_sig_ret);
}
