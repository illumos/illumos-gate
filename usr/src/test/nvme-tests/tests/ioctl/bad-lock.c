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
 * Test various lock scenarios that should always result in an error. This
 * includes:
 *
 *   o Invalid unknown entities on lock and unlock
 *   o Invalid lock levels
 *   o Invalid lock flags
 *   o Namespace fds trying to do anything with the controller lock
 *
 * Then test various unlock scenarios that should always result in an error:
 *   o Asking to unlock when you don't hold a lock
 *   o Asking to unlock the wrong lock type when you hold the opposite lock
 *     (controller only)
 *   o Asking to unlock the controller lock on a ns fd
 *
 * The following aren't currently tested because we don't have tests that
 * currently distinguish between whether or not we have multiple namespaces.
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
	const char *blt_desc;
	nvme_ioctl_lock_t blt_lock;
	nvme_ioctl_errno_t blt_err;
} bad_lock_test_t;

typedef struct {
	const char *but_desc;
	nvme_ioctl_unlock_t but_unlock;
	nvme_ioctl_errno_t but_err;
} bad_unlock_test_t;

static const bad_lock_test_t bad_lock_tests_com[] = { {
	.blt_desc = "bad lock entity (1)",
	.blt_lock = { .nil_ent = 0, .nil_level = NVME_LOCK_L_READ },
	.blt_err = NVME_IOCTL_E_BAD_LOCK_ENTITY
}, {
	.blt_desc = "bad lock entity (2)",
	.blt_lock = { .nil_ent = 0x23, .nil_level = NVME_LOCK_L_READ },
	.blt_err = NVME_IOCTL_E_BAD_LOCK_ENTITY
}, {
	.blt_desc = "bad lock entity (3)",
	.blt_lock = { .nil_ent = INT32_MAX, .nil_level = NVME_LOCK_L_READ },
	.blt_err = NVME_IOCTL_E_BAD_LOCK_ENTITY
} };

static const bad_lock_test_t bad_lock_tests_ctrl[] = { {
	.blt_desc = "bad lock level (1)",
	.blt_lock = { .nil_ent = NVME_LOCK_E_CTRL, .nil_level = 0 },
	.blt_err = NVME_IOCTL_E_BAD_LOCK_LEVEL
}, {
	.blt_desc = "bad lock level (2)",
	.blt_lock = { .nil_ent = NVME_LOCK_E_CTRL, .nil_level = 7 },
	.blt_err = NVME_IOCTL_E_BAD_LOCK_LEVEL
}, {
	.blt_desc = "bad lock level (3)",
	.blt_lock = { .nil_ent = NVME_LOCK_E_CTRL, .nil_level = UINT32_MAX },
	.blt_err = NVME_IOCTL_E_BAD_LOCK_LEVEL
}, {
	.blt_desc = "bad lock level on ns (1)",
	.blt_lock = {
		.nil_common = { .nioc_nsid = 1 },
		.nil_ent = NVME_LOCK_E_NS,
		.nil_level = 0
	},
	.blt_err = NVME_IOCTL_E_BAD_LOCK_LEVEL
}, {
	.blt_desc = "bad lock level on ns (2)",
	.blt_lock = {
		.nil_common = { .nioc_nsid = 1 },
		.nil_ent = NVME_LOCK_E_NS,
		.nil_level = 7
	},
	.blt_err = NVME_IOCTL_E_BAD_LOCK_LEVEL
}, {
	.blt_desc = "bad lock level on ns (3)",
	.blt_lock = {
		.nil_common = { .nioc_nsid = 1 },
		.nil_ent = NVME_LOCK_E_NS,
		.nil_level = UINT32_MAX
	},
	.blt_err = NVME_IOCTL_E_BAD_LOCK_LEVEL
}, {
	.blt_desc = "bad lock flags (1)",
	.blt_lock = {
		.nil_ent = NVME_LOCK_E_CTRL,
		.nil_level = NVME_LOCK_L_READ,
		.nil_flags = 0x2
	},
	.blt_err = NVME_IOCTL_E_BAD_LOCK_FLAGS
}, {
	.blt_desc = "bad lock flags (2)",
	.blt_lock = {
		.nil_ent = NVME_LOCK_E_CTRL,
		.nil_level = NVME_LOCK_L_READ,
		.nil_flags = 0x23
	},
	.blt_err = NVME_IOCTL_E_BAD_LOCK_FLAGS
}, {
	.blt_desc = "bad lock flags on ns (1)",
	.blt_lock = {
		.nil_common = { .nioc_nsid = 1 },
		.nil_ent = NVME_LOCK_E_NS,
		.nil_level = NVME_LOCK_L_READ,
		.nil_flags = 0x2
	},
	.blt_err = NVME_IOCTL_E_BAD_LOCK_FLAGS
}, {
	.blt_desc = "bad lock flags on ns (2)",
	.blt_lock = {
		.nil_common = { .nioc_nsid = 1 },
		.nil_ent = NVME_LOCK_E_NS,
		.nil_level = NVME_LOCK_L_READ,
		.nil_flags = 0x23
	},
	.blt_err = NVME_IOCTL_E_BAD_LOCK_FLAGS
} };

static const bad_lock_test_t bad_lock_tests_ns[] = { {
	.blt_desc = "bad lock level (1)",
	.blt_lock = { .nil_ent = NVME_LOCK_E_NS, .nil_level = 0 },
	.blt_err = NVME_IOCTL_E_BAD_LOCK_LEVEL
}, {
	.blt_desc = "bad lock level (2)",
	.blt_lock = { .nil_ent = NVME_LOCK_E_NS, .nil_level = 7 },
	.blt_err = NVME_IOCTL_E_BAD_LOCK_LEVEL
}, {
	.blt_desc = "bad lock level (3)",
	.blt_lock = { .nil_ent = NVME_LOCK_E_NS, .nil_level = UINT32_MAX },
	.blt_err = NVME_IOCTL_E_BAD_LOCK_LEVEL
}, {
	.blt_desc = "bad lock flags (1)",
	.blt_lock = {
		.nil_ent = NVME_LOCK_E_NS,
		.nil_level = NVME_LOCK_L_READ,
		.nil_flags = 0x2
	},
	.blt_err = NVME_IOCTL_E_BAD_LOCK_FLAGS
}, {
	.blt_desc = "bad lock flags (2)",
	.blt_lock = {
		.nil_ent = NVME_LOCK_E_NS,
		.nil_level = NVME_LOCK_L_READ,
		.nil_flags = 0x23
	},
	.blt_err = NVME_IOCTL_E_BAD_LOCK_FLAGS
}, {
	.blt_desc = "ns fd cant take ctrl read lock",
	.blt_lock = {
		.nil_ent = NVME_LOCK_E_CTRL,
		.nil_level = NVME_LOCK_L_READ,
		.nil_flags = NVME_LOCK_F_DONT_BLOCK
	},
	.blt_err = NVME_IOCTL_E_NS_CANNOT_LOCK_CTRL
}, {
	.blt_desc = "ns fd cant take ctrl write lock",
	.blt_lock = {
		.nil_ent = NVME_LOCK_E_CTRL,
		.nil_level = NVME_LOCK_L_WRITE,
		.nil_flags = NVME_LOCK_F_DONT_BLOCK
	},
	.blt_err = NVME_IOCTL_E_NS_CANNOT_LOCK_CTRL
} };

static const bad_unlock_test_t bad_unlock_tests_cmn[] = { {
	.but_desc = "bad unlock entity (1)",
	.but_unlock = { .niu_ent = 0 },
	.but_err = NVME_IOCTL_E_BAD_LOCK_ENTITY
}, {
	.but_desc = "bad unlock entity (2)",
	.but_unlock = { .niu_ent = 0x23 },
	.but_err = NVME_IOCTL_E_BAD_LOCK_ENTITY
}, {
	.but_desc = "bad unlock entity (3)",
	.but_unlock = { .niu_ent = INT32_MAX },
	.but_err = NVME_IOCTL_E_BAD_LOCK_ENTITY
} };

static const bad_unlock_test_t bad_unlock_tests_ctrl[] = { {
	.but_desc = "unlock ctrl without lock",
	.but_unlock = { .niu_ent = NVME_LOCK_E_CTRL },
	.but_err = NVME_IOCTL_E_LOCK_NOT_HELD,
}, {
	.but_desc = "unlock ns without lock",
	.but_unlock = {
		.niu_common = { .nioc_nsid = 1 },
		.niu_ent = NVME_LOCK_E_NS
	},
	.but_err = NVME_IOCTL_E_LOCK_NOT_HELD
} };

static const bad_unlock_test_t bad_unlock_tests_ns[] = { {
	.but_desc = "unlock ns without lock",
	.but_unlock = { .niu_ent = NVME_LOCK_E_NS },
	.but_err = NVME_IOCTL_E_LOCK_NOT_HELD
}, {
	.but_desc = "unlock ctrl from ns fd",
	.but_unlock = { .niu_ent = NVME_LOCK_E_CTRL },
	.but_err = NVME_IOCTL_E_NS_CANNOT_UNLOCK_CTRL
} };

static const bad_unlock_test_t bad_unlock_tests_ctrl_w_ctrl[] = { {
	.but_desc = "unlock ns with control lock",
	.but_unlock = {
		.niu_common = { .nioc_nsid = 1 },
		.niu_ent = NVME_LOCK_E_NS
	},
	.but_err = NVME_IOCTL_E_LOCK_NOT_HELD
} };

static const bad_unlock_test_t bad_unlock_tests_ctrl_w_ns[] = { {
	.but_desc = "unlock ctrl with ns lock",
	.but_unlock = {
		.niu_ent = NVME_LOCK_E_CTRL
	},
	.but_err = NVME_IOCTL_E_LOCK_NOT_HELD
} };

static bool
bad_lock_test(int fd, const bad_lock_test_t *test, bool ns)
{
	nvme_ioctl_lock_t lock = test->blt_lock;
	const char *type = ns ? "(ns)" : "(ctrl)";

	if (ioctl(fd, NVME_IOC_LOCK, &lock) != 0) {
		warn("TEST FAILED: %s %s: failed to issue lock ioctl",
		    test->blt_desc, type);
		return (false);
	}

	if (lock.nil_common.nioc_drv_err != test->blt_err) {
		warnx("TEST FAILED: %s %s: lock ioctl failed with 0x%x, "
		    "expected 0x%x", test->blt_desc, type,
		    lock.nil_common.nioc_drv_err, test->blt_err);
		return (false);
	}

	(void) printf("TEST PASSED: %s %s\n", test->blt_desc, type);
	return (true);
}

static bool
bad_unlock_test(int fd, const bad_unlock_test_t *test, bool ns)
{
	nvme_ioctl_unlock_t unlock = test->but_unlock;
	const char *type = ns ? "(ns)" : "(ctrl)";

	if (ioctl(fd, NVME_IOC_UNLOCK, &unlock) != 0) {
		warn("TEST FAILED: %s %s: failed to issue unlock ioctl",
		    test->but_desc, type);
		return (false);
	}

	if (unlock.niu_common.nioc_drv_err != test->but_err) {
		warnx("TEST FAILED: %s %s: unlock ioctl failed with 0x%x, "
		    "expected 0x%x", test->but_desc, type,
		    unlock.niu_common.nioc_drv_err, test->but_err);
		return (false);
	}

	(void) printf("TEST PASSED: %s %s\n", test->but_desc, type);
	return (true);
}

int
main(void)
{
	int ret = EXIT_SUCCESS;
	int fd = nvme_ioctl_test_get_fd(0);

	for (size_t i = 0; i < ARRAY_SIZE(bad_lock_tests_com); i++) {
		if (!bad_lock_test(fd, &bad_lock_tests_com[i], false)) {
			ret = EXIT_FAILURE;
		}
	}

	for (size_t i = 0; i < ARRAY_SIZE(bad_lock_tests_ctrl); i++) {
		if (!bad_lock_test(fd, &bad_lock_tests_ctrl[i], false)) {
			ret = EXIT_FAILURE;
		}
	}

	for (size_t i = 0; i < ARRAY_SIZE(bad_unlock_tests_cmn); i++) {
		if (!bad_unlock_test(fd, &bad_unlock_tests_cmn[i], false)) {
			ret = EXIT_FAILURE;
		}
	}

	for (size_t i = 0; i < ARRAY_SIZE(bad_unlock_tests_ctrl); i++) {
		if (!bad_unlock_test(fd, &bad_unlock_tests_ctrl[i], false)) {
			ret = EXIT_FAILURE;
		}
	}

	VERIFY0(close(fd));
	fd = nvme_ioctl_test_get_fd(1);

	for (size_t i = 0; i < ARRAY_SIZE(bad_lock_tests_com); i++) {
		if (!bad_lock_test(fd, &bad_lock_tests_com[i], true)) {
			ret = EXIT_FAILURE;
		}
	}

	for (size_t i = 0; i < ARRAY_SIZE(bad_lock_tests_ns); i++) {
		if (!bad_lock_test(fd, &bad_lock_tests_ns[i], true)) {
			ret = EXIT_FAILURE;
		}
	}

	for (size_t i = 0; i < ARRAY_SIZE(bad_unlock_tests_cmn); i++) {
		if (!bad_unlock_test(fd, &bad_unlock_tests_cmn[i], true)) {
			ret = EXIT_FAILURE;
		}
	}

	for (size_t i = 0; i < ARRAY_SIZE(bad_unlock_tests_ns); i++) {
		if (!bad_unlock_test(fd, &bad_unlock_tests_ns[i], true)) {
			ret = EXIT_FAILURE;
		}
	}
	VERIFY0(close(fd));

	/*
	 * Unlock tests that require a lock to be held.
	 */
	fd = nvme_ioctl_test_get_fd(0);
	nvme_ioctl_test_lock(fd, &nvme_test_ctrl_rdlock);
	for (size_t i = 0; i < ARRAY_SIZE(bad_unlock_tests_ctrl_w_ctrl); i++) {
		if (!bad_unlock_test(fd, &bad_unlock_tests_ctrl_w_ctrl[i],
		    false)) {
			ret = EXIT_FAILURE;
		}
	}

	VERIFY0(close(fd));
	fd = nvme_ioctl_test_get_fd(0);
	nvme_ioctl_test_lock(fd, &nvme_test_ns_rdlock);
	for (size_t i = 0; i < ARRAY_SIZE(bad_unlock_tests_ctrl_w_ns); i++) {
		if (!bad_unlock_test(fd, &bad_unlock_tests_ctrl_w_ns[i],
		    false)) {
			ret = EXIT_FAILURE;
		}
	}

	VERIFY0(close(fd));

	return (ret);
}
