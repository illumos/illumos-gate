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
 * Copyright 2025 Oxide Computer Company
 */

/*
 * This test iterates over every NVMe ioctl and tries to trigger various errors
 * that are generic across all of them. In particular:
 *
 *  - Invalid buffer (EFAULT)
 *  - Bad file descriptor mode (EBADF)
 *  - Missing privileges (EPERM)
 *
 * This is considered a destructive test as a side effect from some of these
 * would be bad. This performs all of these cases on just the controller fd at
 * this time. This test starts from the device-reset profile.
 */

#include <err.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/mman.h>
#include <priv.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>

#include "nvme_ioctl_util.h"

#if NVME_IOC_MAX != NVME_IOC_NS_DELETE
#error	"NVME_IOC_MAX has grown, update this test!"
#endif

typedef struct {
	int it_cmd;
	bool it_write;
	bool it_perm;
} ioctl_test_t;

static ioctl_test_t ioctl_tests[NVME_IOC_MAX - NVME_IOC + 1] = {
	{ NVME_IOC_CTRL_INFO, false, false },
	{ NVME_IOC_IDENTIFY, false, false },
	{ NVME_IOC_GET_LOGPAGE, false, false },
	{ NVME_IOC_GET_FEATURE, false, false },
	{ NVME_IOC_FORMAT, true, true },
	{ NVME_IOC_BD_DETACH, true, true },
	{ NVME_IOC_BD_ATTACH, true, true },
	{ NVME_IOC_FIRMWARE_DOWNLOAD, true, true },
	{ NVME_IOC_FIRMWARE_COMMIT, true, true },
	{ NVME_IOC_PASSTHRU, true, true },
	{ NVME_IOC_NS_INFO, false, false },
	{ NVME_IOC_LOCK, true, true },
	{ NVME_IOC_UNLOCK, true, false },
	{ NVME_IOC_CTRL_ATTACH, true, true },
	{ NVME_IOC_CTRL_DETACH, true, true },
	{ NVME_IOC_NS_CREATE, true, true },
	{ NVME_IOC_NS_DELETE, true, true }
};

static bool
ioctl_test_one(int fd, const ioctl_test_t *test, void *unmap, priv_set_t *basic,
    priv_set_t *cur)
{
	int altfd;
	bool ret = true;

	if (ioctl(fd, test->it_cmd, unmap) == 0) {
		warnx("TEST FAILED: ioctl %s (0x%x) with invalid buffer "
		    "incorrectly succeeded",
		    nvme_ioctl_test_cmdstr(test->it_cmd), test->it_cmd);
		ret = false;
	} else if (errno != EFAULT) {
		int e = errno;
		warnx("TEST FAILED: ioctl %s (0x%x) with invalid buffer "
		    "returned %s (0x%x), not EFAULT (0x%x)",
		    nvme_ioctl_test_cmdstr(test->it_cmd), test->it_cmd,
		    strerrorname_np(e), e, EFAULT);
		ret = false;
	} else {
		(void) printf("TEST PASSED: ioctl %s (0x%x) with invalid "
		    "buffer returned EFAULT\n",
		    nvme_ioctl_test_cmdstr(test->it_cmd), test->it_cmd);
	}

	altfd = nvme_ioctl_test_get_fd_flags(0, test->it_write ?
	    O_RDONLY : O_WRONLY);
	if (ioctl(altfd, test->it_cmd, unmap) == 0) {
		warnx("TEST FAILED: ioctl %s (0x%x) with bad fd mode "
		    "incorrectly succeeded",
		    nvme_ioctl_test_cmdstr(test->it_cmd), test->it_cmd);
		ret = false;
	} else if (errno != EBADF) {
		int e = errno;
		warnx("TEST FAILED: ioctl %s (0x%x) with bad fd mode "
		    "returned %s (0x%x), not EBADF (0x%x)",
		    nvme_ioctl_test_cmdstr(test->it_cmd), test->it_cmd,
		    strerrorname_np(e), e, EBADF);
		ret = false;
	} else {
		(void) printf("TEST PASSED: ioctl %s (0x%x) with bad fd "
		    "mode returned EBADF\n",
		    nvme_ioctl_test_cmdstr(test->it_cmd), test->it_cmd);
	}
	VERIFY0(close(altfd));

	if (setppriv(PRIV_SET, PRIV_EFFECTIVE, basic) != 0) {
		err(EXIT_FAILURE, "failed to drop privileges");
	}

	/*
	 * Some ioctls check privileges regardless of how one gets an fd to the
	 * device, others don't. Those that don't should fail with EFAULT.
	 */
	int exp = test->it_perm ? EPERM : EFAULT;
	if (ioctl(fd, test->it_cmd, unmap) == 0) {
		warnx("TEST FAILED: ioctl %s (0x%x) without privs incorrectly "
		    "succeeded", nvme_ioctl_test_cmdstr(test->it_cmd),
		    test->it_cmd);
		ret = false;
	} else if (errno != exp) {
		int e = errno;
		warnx("TEST FAILED: ioctl %s (0x%x) without privs returned "
		    "%s (0x%x), not %s (0x%x)",
		    nvme_ioctl_test_cmdstr(test->it_cmd), test->it_cmd,
		    strerrorname_np(e), e, strerrorname_np(exp), exp);
		ret = false;
	} else {
		(void) printf("TEST PASSED: ioctl %s (0x%x) without privs "
		    "returned %s\n", nvme_ioctl_test_cmdstr(test->it_cmd),
		    test->it_cmd, strerrorname_np(exp));
	}

	if (setppriv(PRIV_SET, PRIV_EFFECTIVE, cur) != 0) {
		err(EXIT_FAILURE, "failed to restore privileges");
	}

	return (ret);
}

int
main(void)
{
	int fd = nvme_ioctl_test_get_fd(0);
	int ret = EXIT_SUCCESS;
	void *unmap;
	priv_set_t *basic, *cur;

	unmap = mmap(NULL, 1024 * 1024, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1,
	    0);
	if (unmap == NULL) {
		err(EXIT_FAILURE, "failed to mmap empty buffer");
	}

	basic = priv_allocset();
	cur = priv_allocset();
	if (basic == NULL || cur == NULL) {
		err(EXIT_FAILURE, "failed to allocate privilege sets");
	}
	priv_basicset(basic);

	if (getppriv(PRIV_EFFECTIVE, cur) != 0) {
		err(EXIT_FAILURE, "failed to obtain current privilege set");
	}

	for (size_t i = 0; i < ARRAY_SIZE(ioctl_tests); i++) {
		VERIFY3S(ioctl_tests[i].it_cmd, !=, 0);
		if (!ioctl_test_one(fd, &ioctl_tests[i], unmap, basic, cur)) {
			ret = EXIT_FAILURE;
		}
	}

	VERIFY0(close(fd));

	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests passed successfully\n");
	}

	return (ret);
}
