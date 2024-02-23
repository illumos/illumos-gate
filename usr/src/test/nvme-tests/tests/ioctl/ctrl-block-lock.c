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
 * This test covers the following aspects of the locking behavior:
 *
 *  o A controller write lock blocks controller read/write locks
 *  o A controller write lock blocks namespace read/write locks
 *  o A controller read lock blocks controller write locks
 *  o A controller read lock does not block namespace write locks
 *  o A namespace write lock blocks namespace read/write locks
 *  o A namespace write lock blocks controller write locks, but not read locks
 *  o A namespace read lock blocks namespace write locks
 *  o A namespace read lock blocks controller write locks
 *
 * The interaction of various read locks is tested in multi-reader-lock.c.
 */

#include <err.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>

#include "nvme_ioctl_util.h"

typedef enum {
	CBF_FD_CTRL,
	CBF_FD_NS
} ctrl_block_fd_t;

/*
 * This structure describes a given test case. We expect to always succeed in
 * locking fd0 and then we will expect the return value in cbt_ret1 when we try
 * to take lock1.
 */
typedef struct {
	const char *cbt_desc;
	ctrl_block_fd_t cbt_fd0;
	ctrl_block_fd_t cbt_fd1;
	const nvme_ioctl_lock_t *cbt_lock0;
	const nvme_ioctl_lock_t *cbt_lock1;
	nvme_ioctl_errno_t cbt_ret1;
} ctrl_block_test_t;

static const ctrl_block_test_t ctrl_block_tests[] = { {
	.cbt_desc = "controller write blocks controller read",
	.cbt_fd0 = CBF_FD_CTRL,
	.cbt_fd1 = CBF_FD_CTRL,
	.cbt_lock0 = &nvme_test_ctrl_wrlock,
	.cbt_lock1 = &nvme_test_ctrl_rdlock,
	.cbt_ret1 = NVME_IOCTL_E_LOCK_WOULD_BLOCK
}, {
	.cbt_desc = "controller write blocks controller write",
	.cbt_fd0 = CBF_FD_CTRL,
	.cbt_fd1 = CBF_FD_CTRL,
	.cbt_lock0 = &nvme_test_ctrl_wrlock,
	.cbt_lock1 = &nvme_test_ctrl_wrlock,
	.cbt_ret1 = NVME_IOCTL_E_LOCK_WOULD_BLOCK
}, {
	.cbt_desc = "controller write blocks namespace read",
	.cbt_fd0 = CBF_FD_CTRL,
	.cbt_fd1 = CBF_FD_NS,
	.cbt_lock0 = &nvme_test_ctrl_wrlock,
	.cbt_lock1 = &nvme_test_ns_rdlock,
	.cbt_ret1 = NVME_IOCTL_E_LOCK_WOULD_BLOCK
}, {
	.cbt_desc = "controller write blocks namespace write",
	.cbt_fd0 = CBF_FD_CTRL,
	.cbt_fd1 = CBF_FD_NS,
	.cbt_lock0 = &nvme_test_ctrl_wrlock,
	.cbt_lock1 = &nvme_test_ns_wrlock,
	.cbt_ret1 = NVME_IOCTL_E_LOCK_WOULD_BLOCK
}, {
	.cbt_desc = "controller read blocks controller write",
	.cbt_fd0 = CBF_FD_CTRL,
	.cbt_fd1 = CBF_FD_CTRL,
	.cbt_lock0 = &nvme_test_ctrl_rdlock,
	.cbt_lock1 = &nvme_test_ctrl_wrlock,
	.cbt_ret1 = NVME_IOCTL_E_LOCK_WOULD_BLOCK
}, {
	.cbt_desc = "controller read does not block namespace write",
	.cbt_fd0 = CBF_FD_CTRL,
	.cbt_fd1 = CBF_FD_NS,
	.cbt_lock0 = &nvme_test_ctrl_rdlock,
	.cbt_lock1 = &nvme_test_ns_wrlock,
	.cbt_ret1 = NVME_IOCTL_E_OK
}, {
	.cbt_desc = "namespace write blocks namespace read",
	.cbt_fd0 = CBF_FD_NS,
	.cbt_fd1 = CBF_FD_NS,
	.cbt_lock0 = &nvme_test_ns_wrlock,
	.cbt_lock1 = &nvme_test_ns_rdlock,
	.cbt_ret1 = NVME_IOCTL_E_LOCK_WOULD_BLOCK
}, {
	.cbt_desc = "namespace write blocks namespace read",
	.cbt_fd0 = CBF_FD_NS,
	.cbt_fd1 = CBF_FD_NS,
	.cbt_lock0 = &nvme_test_ns_wrlock,
	.cbt_lock1 = &nvme_test_ns_rdlock,
	.cbt_ret1 = NVME_IOCTL_E_LOCK_WOULD_BLOCK
}, {
	.cbt_desc = "namespace write blocks namespace write",
	.cbt_fd0 = CBF_FD_NS,
	.cbt_fd1 = CBF_FD_NS,
	.cbt_lock0 = &nvme_test_ns_wrlock,
	.cbt_lock1 = &nvme_test_ns_wrlock,
	.cbt_ret1 = NVME_IOCTL_E_LOCK_WOULD_BLOCK
}, {
	.cbt_desc = "namespace write blocks controller write",
	.cbt_fd0 = CBF_FD_NS,
	.cbt_fd1 = CBF_FD_CTRL,
	.cbt_lock0 = &nvme_test_ns_wrlock,
	.cbt_lock1 = &nvme_test_ctrl_wrlock,
	.cbt_ret1 = NVME_IOCTL_E_LOCK_WOULD_BLOCK
}, {
	.cbt_desc = "namespace write does not block controller read",
	.cbt_fd0 = CBF_FD_NS,
	.cbt_fd1 = CBF_FD_CTRL,
	.cbt_lock0 = &nvme_test_ns_wrlock,
	.cbt_lock1 = &nvme_test_ctrl_rdlock,
	.cbt_ret1 = NVME_IOCTL_E_OK
}, {
	.cbt_desc = "namespace read blocks namespace write",
	.cbt_fd0 = CBF_FD_NS,
	.cbt_fd1 = CBF_FD_NS,
	.cbt_lock0 = &nvme_test_ns_rdlock,
	.cbt_lock1 = &nvme_test_ns_wrlock,
	.cbt_ret1 = NVME_IOCTL_E_LOCK_WOULD_BLOCK
}, {
	.cbt_desc = "namespace read blocks controller write",
	.cbt_fd0 = CBF_FD_NS,
	.cbt_fd1 = CBF_FD_CTRL,
	.cbt_lock0 = &nvme_test_ns_rdlock,
	.cbt_lock1 = &nvme_test_ctrl_wrlock,
	.cbt_ret1 = NVME_IOCTL_E_LOCK_WOULD_BLOCK
} };

static bool
ctrl_block_test_one(int fd0, int fd1, const ctrl_block_test_t *test)
{
	nvme_ioctl_lock_t lock0 = *test->cbt_lock0;
	nvme_ioctl_lock_t lock1 = *test->cbt_lock1;

	if (ioctl(fd0, NVME_IOC_LOCK, &lock0) != 0) {
		warn("TEST FAILED: %s: failed to issue lock ioctl for fd0",
		    test->cbt_desc);
		return (false);
	} else if (lock0.nil_common.nioc_drv_err != NVME_IOCTL_E_OK) {
		warnx("TEST FAILED: %s: fd0 lock ioctl failed with 0x%x, "
		    "expected success", test->cbt_desc,
		    lock0.nil_common.nioc_drv_err);
		return (false);
	}

	if (ioctl(fd1, NVME_IOC_LOCK, &lock1) != 0) {
		warn("TEST FAILED: %s: failed to issue lock ioctl for fd1",
		    test->cbt_desc);
		return (false);
	} else if (lock1.nil_common.nioc_drv_err != test->cbt_ret1) {
		warnx("TEST FAILED: %s: fd1 lock ioctl returned with 0x%x, "
		    "expected 0x%x", test->cbt_desc,
		    lock1.nil_common.nioc_drv_err, test->cbt_ret1);
		return (false);
	}

	(void) printf("TEST PASSED: %s\n", test->cbt_desc);
	return (true);
}

int
main(void)
{
	int ret = EXIT_SUCCESS;

	/*
	 * We purposefully open and close the fds every iteration of this loop
	 * so we don't have to explicitly issue conditional unlocks.
	 */
	for (size_t i = 0; i < ARRAY_SIZE(ctrl_block_tests); i++) {
		int fd0, fd1;

		if (ctrl_block_tests[i].cbt_fd0 == CBF_FD_CTRL) {
			fd0 = nvme_ioctl_test_get_fd(0);
		} else {
			fd0 = nvme_ioctl_test_get_fd(1);
		}

		if (ctrl_block_tests[i].cbt_fd1 == CBF_FD_CTRL) {
			fd1 = nvme_ioctl_test_get_fd(0);
		} else {
			fd1 = nvme_ioctl_test_get_fd(1);
		}

		if (!ctrl_block_test_one(fd0, fd1, &ctrl_block_tests[i])) {
			ret = EXIT_FAILURE;
		}

		VERIFY0(close(fd0));
		VERIFY0(close(fd1));
	}

	return (ret);
}
