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
 * The purpose of this test is to verify that multiple readers can all grab the
 * same lock. In this case, we will use a mix of namespace and controller locks,
 * but only one lock per fd. Specifically we want to ensure that all three of
 * these classes can simultaneously hold the lock:
 *
 * o Controller fd, controller lock
 * o Controller fd, namespace lock
 * o Namespace fd, namespace lock
 *
 * This also is testing that multiple instances of the same type can hold the fd
 * as well. In addition, We want to ensure that this happens regardless of
 * whomever does the first lock. In particular we want to test the following
 * orders:
 *
 * 1) All controller read locks, then all ctrl ns, then all ns
 * 2) All ns fd read locks, then all ctrl fd ns locks, then all ctrl ctrl
 * 3) All ctrl fd ns locks, then all ctrl ctrl locks, then all ns fd
 *
 * Then we repeat the above but swizzling with one fd from each.
 */

#include <err.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

#include "nvme_ioctl_util.h"

/*
 * Number of readers of each type.
 */
#define	NREADERS	10

static bool
multi_lock_one(int fd, const nvme_ioctl_lock_t *tmpl, const char *desc,
    size_t iter)
{
	nvme_ioctl_lock_t lock = *tmpl;

	if (ioctl(fd, NVME_IOC_LOCK, &lock) != 0) {
		warn("TEST FAILED: %s %zu: failed to issue lock ioctl",
		    desc, iter);
		return (false);
	} else if (lock.nil_common.nioc_drv_err != NVME_IOCTL_E_OK) {
		warnx("TEST FAILED: %s %zu: lock ioctl failed with driver "
		    "error 0x%x", desc, iter, lock.nil_common.nioc_drv_err);
		return (false);
	} else {
		return (true);
	}
}

static bool
multi_unlock_one(int fd, const nvme_ioctl_unlock_t *tmpl, const char *desc,
    size_t iter)
{
	nvme_ioctl_unlock_t unlock = *tmpl;
	if (ioctl(fd, NVME_IOC_UNLOCK, &unlock) != 0) {
		warn("TEST FAILED: %s %zu: failed to issue unlock ioctl",
		    desc, iter);
		return (false);
	} else if (unlock.niu_common.nioc_drv_err != NVME_IOCTL_E_OK) {
		warnx("TEST FAILED: %s %zu: unlock ioctl failed with driver "
		    "error 0x%x", desc, iter, unlock.niu_common.nioc_drv_err);
		return (false);
	} else {
		return (true);
	}
}

static bool
multi_unlock_all(int ctrl_ctrl[NREADERS], int ctrl_ns[NREADERS],
    int ns_ns[NREADERS])
{
	bool ret = true;
	for (uint32_t i = 0; i < NREADERS; i++) {
		if (!multi_unlock_one(ctrl_ctrl[i], &nvme_test_ctrl_unlock,
		    "ctrl fd ctrl lock", i)) {
			ret = false;
		}

		if (!multi_unlock_one(ctrl_ns[i], &nvme_test_ns_unlock,
		    "ctrl fd ns lock", i)) {
			ret = false;
		}

		if (!multi_unlock_one(ns_ns[i], &nvme_test_ns_unlock,
		    "ns fd ns lock", i)) {
			ret = false;
		}
	}

	return (ret);
}

int
main(void)
{
	int ret = EXIT_SUCCESS;
	int ctrl_ctrl[NREADERS];
	int ctrl_ns[NREADERS];
	int ns_ns[NREADERS];
	bool test;

	for (size_t i = 0; i < NREADERS; i++) {
		ctrl_ctrl[i] = nvme_ioctl_test_get_fd(0);
		ctrl_ns[i] = nvme_ioctl_test_get_fd(0);
		ns_ns[i] = nvme_ioctl_test_get_fd(1);
	}

	/*
	 * Order 1
	 */
	test = true;
	for (size_t i = 0; i < NREADERS; i++) {
		if (!multi_lock_one(ctrl_ctrl[i], &nvme_test_ctrl_rdlock,
		    "ctrl fd ctrl lock", i)) {
			test = false;
		}
	}

	for (size_t i = 0; i < NREADERS; i++) {
		if (!multi_lock_one(ctrl_ns[i], &nvme_test_ns_rdlock,
		    "ctrl fd ns lock", i)) {
			test = false;
		}
	}

	for (size_t i = 0; i < NREADERS; i++) {
		if (!multi_lock_one(ns_ns[i], &nvme_test_ns_rdlock,
		    "ns fd ns lock", i)) {
			test = false;
		}
	}

	if (test) {
		(void) printf("TEST PASSED: all read locks taken: order 1\n");
	} else {
		warnx("TEST FAILED: failed to take all read locks following "
		    "order 1");
		ret = EXIT_FAILURE;
	}
	if (!multi_unlock_all(ctrl_ctrl, ctrl_ns, ns_ns)) {
		ret = EXIT_FAILURE;
	}

	/*
	 * Order 2
	 */
	test = true;
	for (size_t i = 0; i < NREADERS; i++) {
		if (!multi_lock_one(ns_ns[i], &nvme_test_ns_rdlock,
		    "ns fd ns lock", i)) {
			test = false;
		}
	}

	for (size_t i = 0; i < NREADERS; i++) {
		if (!multi_lock_one(ctrl_ns[i], &nvme_test_ns_rdlock,
		    "ctrl fd ns lock", i)) {
			test = false;
		}
	}

	for (size_t i = 0; i < NREADERS; i++) {
		if (!multi_lock_one(ctrl_ctrl[i], &nvme_test_ctrl_rdlock,
		    "ctrl fd ctrl lock", i)) {
			test = false;
		}
	}

	if (test) {
		(void) printf("TEST PASSED: all read locks taken: order 2\n");
	} else {
		warnx("TEST FAILED: failed to take all read locks following "
		    "order 2");
		ret = EXIT_FAILURE;
	}
	if (!multi_unlock_all(ctrl_ctrl, ctrl_ns, ns_ns)) {
		ret = EXIT_FAILURE;
	}

	/*
	 * Order 3
	 */
	test = true;
	for (size_t i = 0; i < NREADERS; i++) {
		if (!multi_lock_one(ctrl_ns[i], &nvme_test_ns_rdlock,
		    "ctrl fd ns lock", i)) {
			test = false;
		}
	}

	for (size_t i = 0; i < NREADERS; i++) {
		if (!multi_lock_one(ns_ns[i], &nvme_test_ns_rdlock,
		    "ns fd ns lock", i)) {
			test = false;
		}
	}

	for (size_t i = 0; i < NREADERS; i++) {
		if (!multi_lock_one(ctrl_ctrl[i], &nvme_test_ctrl_rdlock,
		    "ctrl fd ctrl lock", i)) {
			test = false;
		}
	}

	if (test) {
		(void) printf("TEST PASSED: all read locks taken: order 3\n");
	} else {
		warnx("TEST FAILED: failed to take all read locks following "
		    "order 3");
		ret = EXIT_FAILURE;
	}
	if (!multi_unlock_all(ctrl_ctrl, ctrl_ns, ns_ns)) {
		ret = EXIT_FAILURE;
	}
	/*
	 * Swizzle 1.
	 */
	test = true;
	for (size_t i = 0; i < NREADERS; i++) {
		if (!multi_lock_one(ctrl_ctrl[i], &nvme_test_ctrl_rdlock,
		    "ctrl fd ctrl lock", i)) {
			test = false;
		}

		if (!multi_lock_one(ctrl_ns[i], &nvme_test_ns_rdlock,
		    "ctrl fd ns lock", i)) {
			test = false;
		}

		if (!multi_lock_one(ns_ns[i], &nvme_test_ns_rdlock,
		    "ns fd ns lock", i)) {
			test = false;
		}
	}

	if (test) {
		(void) printf("TEST PASSED: all read locks taken: swizzle 1\n");
	} else {
		warnx("TEST FAILED: failed to take all read locks following "
		    "swizzle 1");
		ret = EXIT_FAILURE;
	}
	if (!multi_unlock_all(ctrl_ctrl, ctrl_ns, ns_ns)) {
		ret = EXIT_FAILURE;
	}

	/*
	 * Swizzle 2.
	 */
	test = true;
	for (size_t i = 0; i < NREADERS; i++) {
		if (!multi_lock_one(ns_ns[i], &nvme_test_ns_rdlock,
		    "ns fd ns lock", i)) {
			test = false;
		}

		if (!multi_lock_one(ctrl_ns[i], &nvme_test_ns_rdlock,
		    "ctrl fd ns lock", i)) {
			test = false;
		}

		if (!multi_lock_one(ctrl_ctrl[i], &nvme_test_ctrl_rdlock,
		    "ctrl fd ctrl lock", i)) {
			test = false;
		}
	}

	if (test) {
		(void) printf("TEST PASSED: all read locks taken: swizzle 2\n");
	} else {
		warnx("TEST FAILED: failed to take all read locks following "
		    "swizzle 2");
		ret = EXIT_FAILURE;
	}
	if (!multi_unlock_all(ctrl_ctrl, ctrl_ns, ns_ns)) {
		ret = EXIT_FAILURE;
	}

	/*
	 * Swizzle 3.
	 */
	test = true;
	for (size_t i = 0; i < NREADERS; i++) {
		if (!multi_lock_one(ctrl_ns[i], &nvme_test_ns_rdlock,
		    "ctrl fd ns lock", i)) {
			test = false;
		}

		if (!multi_lock_one(ns_ns[i], &nvme_test_ns_rdlock,
		    "ns fd ns lock", i)) {
			test = false;
		}

		if (!multi_lock_one(ctrl_ctrl[i], &nvme_test_ctrl_rdlock,
		    "ctrl fd ctrl lock", i)) {
			test = false;
		}
	}

	if (test) {
		(void) printf("TEST PASSED: all read locks taken: swizzle 3\n");
	} else {
		warnx("TEST FAILED: failed to take all read locks following "
		    "swizzle 3");
		ret = EXIT_FAILURE;
	}
	if (!multi_unlock_all(ctrl_ctrl, ctrl_ns, ns_ns)) {
		ret = EXIT_FAILURE;
	}

	return (ret);
}
