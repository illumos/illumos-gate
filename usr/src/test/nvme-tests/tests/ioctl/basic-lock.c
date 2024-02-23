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
 * This validates the simplest form of locking functionality:
 *
 * o On a controller fd we can take controller read and write locks.
 * o On a controller fd we can take namespace read and write locks.
 * o On a namespace fd we can take namespace read and write locks with nsid = 0
 *   to get our nsid.
 * o On a namespace fd we can specify our nsid still.
 * o A namespace fd cannot take a controller lock with either nsid.
 */

#include <err.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>

#include "nvme_ioctl_util.h"

/*
 * Loop for multiple times on each lock just to make sure this isn't a one off.
 */
#define	BASIC_LOCK_NITERS	3

typedef struct {
	const char *blt_desc;
	nvme_lock_ent_t blt_ent;
	nvme_lock_level_t blt_level;
	uint32_t blt_nsid;
} basic_lock_test_t;

static const basic_lock_test_t basic_lock_tests[] = {
	{ "ctrl fd ctrl write lock", NVME_LOCK_E_CTRL, NVME_LOCK_L_WRITE, 0 },
	{ "ctrl fd ctrl read lock", NVME_LOCK_E_CTRL, NVME_LOCK_L_READ, 0 },
	{ "ctrl fd ns write lock", NVME_LOCK_E_NS, NVME_LOCK_L_WRITE, 1 },
	{ "ctrl fd ns read lock", NVME_LOCK_E_NS, NVME_LOCK_L_READ, 1 }
};

static const basic_lock_test_t basic_ns_lock_tests[] = {
	{ "ns fd ns write lock (nsid=0)", NVME_LOCK_E_NS, NVME_LOCK_L_WRITE,
	    0 },
	{ "ns fd ns read lock (nsid=0)", NVME_LOCK_E_NS, NVME_LOCK_L_READ, 0 },
	{ "ns fd ns write lock (nsid=1)", NVME_LOCK_E_NS, NVME_LOCK_L_WRITE,
	    1 },
	{ "ns fd ns read lock (nsid=1)", NVME_LOCK_E_NS, NVME_LOCK_L_READ, 1 }
};

static const basic_lock_test_t basic_ns_ctrl_lock_tests[] = {
	{ "ns fd ctrl write lock (nsid=0)", NVME_LOCK_E_CTRL, NVME_LOCK_L_WRITE,
	    0 },
	{ "ns fd ctrl read lock (nsid=0)", NVME_LOCK_E_CTRL, NVME_LOCK_L_READ,
	    0 },
	{ "ns fd ctrl write lock (nsid=1)", NVME_LOCK_E_CTRL, NVME_LOCK_L_WRITE,
	    1 },
	{ "ns fd ctrl read lock (nsid=1)", NVME_LOCK_E_CTRL, NVME_LOCK_L_READ,
	    1 }
};


static bool
basic_lock_test(const basic_lock_test_t *test, int fd)
{
	nvme_ioctl_lock_t lock;
	nvme_ioctl_unlock_t unlock;

	(void) memset(&lock, 0, sizeof (lock));
	lock.nil_common.nioc_nsid = test->blt_nsid;
	lock.nil_ent = test->blt_ent;
	lock.nil_level = test->blt_level;
	lock.nil_flags = NVME_LOCK_F_DONT_BLOCK;

	(void) memset(&unlock, 0, sizeof (unlock));
	unlock.niu_common.nioc_nsid = test->blt_nsid;
	unlock.niu_ent = test->blt_ent;

	for (uint32_t i = 0; i < BASIC_LOCK_NITERS; i++) {
		if (ioctl(fd, NVME_IOC_LOCK, &lock) != 0) {
			warn("TEST FAILED: %s %u: failed to issue lock ioctl",
			    test->blt_desc, i);
			return (false);
		} else if (lock.nil_common.nioc_drv_err != NVME_IOCTL_E_OK) {
			warnx("TEST FAILED: %s %u: lock ioctl failed with "
			    "driver error 0x%x", test->blt_desc, i,
			    lock.nil_common.nioc_drv_err);
			return (false);
		} else {
			(void) printf("TEST PASSED: %s %u: lock acquired\n",
			    test->blt_desc, i);
		}

		if (ioctl(fd, NVME_IOC_UNLOCK, &unlock) != 0) {
			return (false);
		} else if (lock.nil_common.nioc_drv_err != NVME_IOCTL_E_OK) {
			return (false);
		} else {
			(void) printf("TEST PASSED: %s %u: lock released\n",
			    test->blt_desc, i);
		}
	}

	return (true);
}

/*
 * Verify that attempting to grab these locks fails with
 * NVME_IOCTL_E_NS_CANNOT_LOCK_CTRL. We don't bother with multiple repetitions
 * here.
 */
static bool
basic_lock_test_no_ns_ctrl(const basic_lock_test_t *test, int fd)
{
	nvme_ioctl_lock_t lock;
	bool ret = true;

	(void) memset(&lock, 0, sizeof (lock));
	lock.nil_common.nioc_nsid = test->blt_nsid;
	lock.nil_ent = test->blt_ent;
	lock.nil_level = test->blt_level;
	lock.nil_flags = NVME_LOCK_F_DONT_BLOCK;

	if (ioctl(fd, NVME_IOC_LOCK, &lock) != 0) {
		warn("TEST FAILED: %s: failed to issue lock ioctl",
		    test->blt_desc);
		return (false);
	} else if (lock.nil_common.nioc_drv_err == NVME_IOCTL_E_OK) {
		errx(EXIT_FAILURE, "TEST FAILED: %s: lock erroneously "
		    "acquired: cannot continue test", test->blt_desc);
	} else if (lock.nil_common.nioc_drv_err !=
	    NVME_IOCTL_E_NS_CANNOT_LOCK_CTRL) {
		warnx("TEST FAILED: %s: lock ioctl failed with "
		    "driver error 0x%x, expected 0x%x "
		    "(NVME_IOCTL_E_NS_CANNOT_LOCK_CTRL)", test->blt_desc,
		    lock.nil_common.nioc_drv_err,
		    NVME_IOCTL_E_NS_CANNOT_LOCK_CTRL);
		return (false);
	} else {
		(void) printf("TEST PASSED: %s: lock denied\n", test->blt_desc);
	}

	return (ret);
}

int
main(void)
{
	int fd = nvme_ioctl_test_get_fd(0);
	int ret = EXIT_SUCCESS;

	for (size_t i = 0; i < ARRAY_SIZE(basic_lock_tests); i++) {
		if (!basic_lock_test(&basic_lock_tests[i], fd)) {
			ret = EXIT_FAILURE;
		}
	}

	VERIFY0(close(fd));

	fd = nvme_ioctl_test_get_fd(1);
	for (size_t i = 0; i < ARRAY_SIZE(basic_ns_lock_tests); i++) {
		if (!basic_lock_test(&basic_ns_lock_tests[i], fd)) {
			ret = EXIT_FAILURE;
		}
	}

	for (size_t i = 0; i < ARRAY_SIZE(basic_ns_ctrl_lock_tests); i++) {
		if (!basic_lock_test_no_ns_ctrl(&basic_ns_ctrl_lock_tests[i],
		    fd)) {
			ret = EXIT_FAILURE;
		}
	}

	return (ret);
}
