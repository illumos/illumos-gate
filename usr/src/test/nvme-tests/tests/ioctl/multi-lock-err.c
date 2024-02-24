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
 * This tests various pieces around trying to hold multiple locks or perform
 * recursive locks. This includes:
 *
 *   o Recursively grabbing any kind of lock
 *   o Trying to take any controller lock while holding any namespace lock
 *     (controller only)
 *   o Trying to take a namespace lock while holding the controller write lock
 *     (controller only)
 *
 * This is organized as taking a given lock type and then trying all the things
 * that should fail. We currently don't test the following here because we don't
 * have tests that easily allow for determining devices with or without multiple
 * namespaces:
 *
 *   o Asking to unlock a namespace that isn't the one you have locked
 *     (controller only)
 */

#include <err.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>

#include "nvme_ioctl_util.h"

typedef struct {
	const char *rlt_desc;
	bool rlt_ctrl_only;
	const nvme_ioctl_lock_t *rlt_lock;
} rec_lock_test_t;

static const rec_lock_test_t rec_lock_tests[] = { {
	.rlt_desc = "recursive controller write lock",
	.rlt_ctrl_only = true,
	.rlt_lock = &nvme_test_ctrl_wrlock
}, {
	.rlt_desc = "recursive controller read lock",
	.rlt_ctrl_only = true,
	.rlt_lock = &nvme_test_ctrl_rdlock
}, {
	.rlt_desc = "recursive namespace write lock",
	.rlt_lock = &nvme_test_ns_wrlock
}, {
	.rlt_desc = "recursive namespace read lock",
	.rlt_lock = &nvme_test_ns_rdlock
} };

typedef struct {
	const char *nlt_desc;
	const nvme_ioctl_lock_t *nlt_lock;
	nvme_ioctl_errno_t nlt_err;
} ns_lock_test_t;

static const ns_lock_test_t ns_lock_tests[] = { {
	.nlt_desc = "take controller read lock w/ ns lock",
	.nlt_lock = &nvme_test_ctrl_rdlock,
	.nlt_err = NVME_IOCTL_E_LOCK_NO_CTRL_WITH_NS
}, {
	.nlt_desc = "take controller read lock w/ ns lock",
	.nlt_lock = &nvme_test_ctrl_wrlock,
	.nlt_err = NVME_IOCTL_E_LOCK_NO_CTRL_WITH_NS
} };

static const ns_lock_test_t ns_ctrl_tests[] = { {
	.nlt_desc = "attempt ns read lock with controller write lock",
	.nlt_lock = &nvme_test_ns_rdlock,
	.nlt_err = NVME_IOCTL_LOCK_NO_NS_WITH_CTRL_WRLOCK
}, {
	.nlt_desc = "attempt ns write lock with controller write lock",
	.nlt_lock = &nvme_test_ns_wrlock,
	.nlt_err = NVME_IOCTL_LOCK_NO_NS_WITH_CTRL_WRLOCK
} };

static bool
rec_lock_test(int fd, const rec_lock_test_t *test, bool nsfd)
{
	nvme_ioctl_lock_t lock = *test->rlt_lock;
	const char *type = nsfd ? "(ns)" : "(ctrl)";

	if (ioctl(fd, NVME_IOC_LOCK, &lock) != 0) {
		warn("TEST FAILED: %s %s: failed to issue initial lock ioctl",
		    test->rlt_desc, type);
		return (false);
	} else if (lock.nil_common.nioc_drv_err != NVME_IOCTL_E_OK) {
		warnx("TEST FAILED: %s %s: initial lock ioctl failed with "
		    "0x%x, expected success", test->rlt_desc, type,
		    lock.nil_common.nioc_drv_err);
		return (false);
	}

	lock = *test->rlt_lock;

	if (ioctl(fd, NVME_IOC_LOCK, &lock) != 0) {
		warn("TEST FAILED: %s %s: failed to issue recursive lock ioctl",
		    test->rlt_desc, type);
		return (false);
	} else if (lock.nil_common.nioc_drv_err !=
	    NVME_IOCTL_E_LOCK_ALREADY_HELD) {
		warnx("TEST FAILED: %s %s: recursive lock ioctl failed with "
		    "0x%x, expected 0x%x (NVME_IOCTL_E_LOCK_ALREADY_HELD)",
		    test->rlt_desc, type, lock.nil_common.nioc_drv_err,
		    NVME_IOCTL_E_LOCK_ALREADY_HELD);
		return (false);
	}

	return (true);
}

static bool
ns_lock_test(int fd, const ns_lock_test_t *test, bool rdlock)
{
	nvme_ioctl_lock_t lock = *test->nlt_lock;
	const char *type = rdlock ? "(ns read lock)" : "(ns write lock)";

	if (ioctl(fd, NVME_IOC_LOCK, &lock) != 0) {
		warn("TEST FAILED: %s %s: failed to issue lock ioctl",
		    test->nlt_desc, type);
		return (false);
	} else if (lock.nil_common.nioc_drv_err != test->nlt_err) {
		warnx("TEST FAILED: %s %s: recursive lock ioctl failed with "
		    "0x%x, expected 0x%x",
		    test->nlt_desc, type, lock.nil_common.nioc_drv_err,
		    test->nlt_err);
		return (false);
	} else {
		(void) printf("TEST PASSED: %s\n", test->nlt_desc);
	}

	return (true);
}

int
main(void)
{
	int ret = EXIT_SUCCESS;

	/*
	 * Recusive lock tests
	 */
	for (size_t i = 0; i < ARRAY_SIZE(rec_lock_tests); i++) {
		int fd = nvme_ioctl_test_get_fd(0);
		if (!rec_lock_test(fd, &rec_lock_tests[i], false)) {
			ret = EXIT_FAILURE;
		}
		VERIFY0(close(fd));

		if (rec_lock_tests[i].rlt_ctrl_only)
			continue;

		fd = nvme_ioctl_test_get_fd(1);
		if (!rec_lock_test(fd, &rec_lock_tests[i], true)) {
			ret = EXIT_FAILURE;
		}
		VERIFY0(close(fd));
	}

	/*
	 * Second lock attempts while holding namespace locks. We do two passes
	 * to make sure there's no difference between the read and write side.
	 * This can only happen on controller fd's.
	 */
	int fd = nvme_ioctl_test_get_fd(0);
	nvme_ioctl_test_lock(fd, &nvme_test_ns_rdlock);
	for (size_t i = 0; i < ARRAY_SIZE(ns_lock_tests); i++) {
		if (!ns_lock_test(fd, &ns_lock_tests[i], true)) {
			ret = EXIT_FAILURE;
		}
	}
	VERIFY0(close(fd));

	fd = nvme_ioctl_test_get_fd(0);
	nvme_ioctl_test_lock(fd, &nvme_test_ns_wrlock);
	for (size_t i = 0; i < ARRAY_SIZE(ns_lock_tests); i++) {
		if (!ns_lock_test(fd, &ns_lock_tests[i], false)) {
			ret = EXIT_FAILURE;
		}
	}
	VERIFY0(close(fd));

	fd = nvme_ioctl_test_get_fd(0);
	nvme_ioctl_test_lock(fd, &nvme_test_ctrl_wrlock);
	for (size_t i = 0; i < ARRAY_SIZE(ns_ctrl_tests); i++) {
		if (!ns_lock_test(fd, &ns_ctrl_tests[i], true)) {
			ret = EXIT_FAILURE;
		}
	}
	VERIFY0(close(fd));

	return (ret);
}
